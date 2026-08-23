//! Symlink-safe persistence for long-lived secrets and secret sidecars.

use rand_core::{OsRng, RngCore};
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

fn temporary_path(path: &Path) -> PathBuf {
    let mut random = [0u8; 16];
    OsRng.fill_bytes(&mut random);
    let token: String = random.iter().map(|b| format!("{b:02x}")).collect();
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    path.with_file_name(format!(".{name}.{token}.tmp"))
}

fn create_private(path: &Path) -> io::Result<fs::File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

fn staged(path: &Path, bytes: &[u8]) -> io::Result<PathBuf> {
    for _ in 0..16 {
        let tmp = temporary_path(path);
        match create_private(&tmp) {
            Ok(mut file) => {
                if let Err(error) = file.write_all(bytes).and_then(|_| file.sync_all()) {
                    let _ = fs::remove_file(&tmp);
                    return Err(error);
                }
                return Ok(tmp);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a private temporary file",
    ))
}

/// Atomically install a new secret without replacing an existing path.
pub fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = staged(path, bytes)?;
    let result = fs::hard_link(&tmp, path);
    let _ = fs::remove_file(&tmp);
    result
}

/// Atomically replace a mutable secret sidecar.
///
/// The random temporary is created exclusively, so an attacker cannot plant a
/// symlink at a predictable name. `rename` replaces a final symlink itself
/// rather than following it.
pub fn replace(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = staged(path, bytes)?;
    match fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = fs::remove_file(&tmp);
            Err(error)
        }
    }
}

/// Copy a regular file into a randomly named exclusive temporary and replace
/// the destination without following an existing final symlink.
pub fn replace_from(path: &Path, source: &Path) -> io::Result<u64> {
    for _ in 0..16 {
        let tmp = temporary_path(path);
        match create_private(&tmp) {
            Ok(mut output) => {
                let result = (|| {
                    let mut input = fs::File::open(source)?;
                    let bytes = io::copy(&mut input, &mut output)?;
                    output.sync_all()?;
                    fs::rename(&tmp, path)?;
                    Ok(bytes)
                })();
                if result.is_err() {
                    let _ = fs::remove_file(&tmp);
                }
                return result;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a private temporary file",
    ))
}

/// Open a secret once, then validate and harden that same file descriptor.
///
/// Comparing the pre-open path identity to the opened descriptor closes the
/// check/open race without relying on a platform-specific `O_NOFOLLOW` value.
fn open_existing(path: &Path) -> io::Result<fs::File> {
    let before = fs::symlink_metadata(path)?;
    if !before.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "secret path is not a regular file",
        ));
    }
    let file = fs::File::open(path)?;
    let opened = file.metadata()?;
    if !opened.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "secret path did not open as a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if before.dev() != opened.dev() || before.ino() != opened.ino() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "secret path changed while it was being opened",
            ));
        }
        if opened.mode() & 0o077 != 0 {
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
    }
    Ok(file)
}

/// Refuse symlinks and repair permissive Unix modes on an existing secret.
pub fn harden_existing(path: &Path) -> io::Result<()> {
    open_existing(path).map(drop)
}

/// Read a validated secret through the descriptor that was checked.
pub fn read_to_string(path: &Path) -> io::Result<String> {
    let mut file = open_existing(path)?;
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    Ok(text)
}

/// Read validated bytes through the descriptor that was checked.
///
/// This is the binary counterpart of [`read_to_string`]. Content-addressed
/// files use it too: a symlink named like a digest must not turn a later
/// verifier read into a read outside the store.
pub fn read(path: &Path) -> io::Result<Vec<u8>> {
    let mut file = open_existing(path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("cairn-secret-file-{}-{name}", std::process::id()))
    }

    #[test]
    fn new_secrets_do_not_replace_existing_files() {
        let path = scratch("no-replace");
        let _ = fs::remove_file(&path);
        write_new(&path, b"first").unwrap();
        assert_eq!(
            write_new(&path, b"second").unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(&path).unwrap(), b"first");
        fs::remove_file(path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn new_secrets_are_owner_only() {
        use std::os::unix::fs::MetadataExt;
        let path = scratch("mode");
        let _ = fs::remove_file(&path);
        write_new(&path, b"secret").unwrap();
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        fs::remove_file(path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn secret_reads_refuse_symlinks() {
        use std::os::unix::fs::symlink;
        let target = scratch("target");
        let link = scratch("link");
        let _ = fs::remove_file(&target);
        let _ = fs::remove_file(&link);
        fs::write(&target, "outside").unwrap();
        symlink(&target, &link).unwrap();
        assert_eq!(
            read_to_string(&link).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        fs::remove_file(link).unwrap();
        fs::remove_file(target).unwrap();
    }
}
