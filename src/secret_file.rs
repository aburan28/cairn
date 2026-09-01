//! Symlink-safe persistence for long-lived secrets and secret sidecars.
//!
//! [`replace_public`] lives here too although it writes nothing secret: it is
//! the same stage-`fsync`-`rename` sequence at an ordinary mode, and one copy
//! of that sequence is easier to keep right than two.

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

/// [`create_private`] at the process's ordinary creation mode.
///
/// For state that is *meant* to be read by others. A checkpoint is served by
/// `GET /checkpoint` and copied to readers; written 0600 by a daemon running
/// as one user, it is unreadable to a `cairn serve` running as another.
fn create_public(path: &Path) -> io::Result<fs::File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

fn staged_with(
    path: &Path,
    bytes: &[u8],
    create: fn(&Path) -> io::Result<fs::File>,
) -> io::Result<PathBuf> {
    for _ in 0..16 {
        let tmp = temporary_path(path);
        match create(&tmp) {
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
        "could not allocate a temporary file",
    ))
}

fn staged(path: &Path, bytes: &[u8]) -> io::Result<PathBuf> {
    staged_with(path, bytes, create_private)
}

/// Rename the staged temporary over `path`, removing it if the rename fails.
fn install(tmp: &Path, path: &Path) -> io::Result<()> {
    match fs::rename(tmp, path) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = fs::remove_file(tmp);
            Err(error)
        }
    }
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
    install(&tmp, path)
}

/// Atomically replace a file anyone may read.
///
/// [`replace`] at an ordinary mode, for state a daemon rewrites every round
/// and another process reads: the signed checkpoint, the gossip population.
/// `fs::write` in place truncates first, so a crash between the truncate and
/// the last byte leaves a torn file -- and a torn population file refuses the
/// next start, while a torn checkpoint fails verification for every reader
/// that copied it. `rename` is atomic, so a reader sees the old file or the
/// new one and never the seam; a crash leaves at most an orphaned
/// `.name.<token>.tmp` beside it, which nothing reads.
pub fn replace_public(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = staged_with(path, bytes, create_public)?;
    install(&tmp, path)
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

    #[test]
    fn public_replace_writes_and_overwrites() {
        let path = scratch("public");
        let _ = fs::remove_file(&path);
        replace_public(&path, b"first").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"first");
        replace_public(&path, b"second, longer").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"second, longer");
        // Nothing staged is left behind on the success path.
        let parent = path.parent().unwrap();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let orphans = fs::read_dir(parent)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                let n = e.file_name().to_string_lossy().to_string();
                n.starts_with(&format!(".{name}.")) && n.ends_with(".tmp")
            })
            .count();
        assert_eq!(orphans, 0);
        fs::remove_file(path).unwrap();
    }

    /// A crash between staging and rename is simulated by leaving the staged
    /// temporary where it fell. The file at `path` must be the last complete
    /// write, byte for byte -- the property `fs::write` in place does not have.
    #[test]
    fn public_replace_survives_a_crash_mid_write() {
        let path = scratch("torn");
        let _ = fs::remove_file(&path);
        replace_public(&path, b"complete checkpoint").unwrap();
        // The staged file a crash would leave: a prefix of the next write.
        let tmp = temporary_path(&path);
        fs::write(&tmp, b"partial che").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"complete checkpoint");
        // And the next writer neither trips over the orphan nor adopts it.
        replace_public(&path, b"next checkpoint").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"next checkpoint");
        assert_eq!(fs::read(&tmp).unwrap(), b"partial che");
        fs::remove_file(tmp).unwrap();
        fs::remove_file(path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn public_replace_uses_the_ordinary_mode() {
        use std::os::unix::fs::MetadataExt;
        let public = scratch("public-mode");
        let plain = scratch("plain-mode");
        let _ = fs::remove_file(&public);
        let _ = fs::remove_file(&plain);
        replace_public(&public, b"served").unwrap();
        // Compared against `fs::write` rather than a literal, so the assertion
        // holds under whatever umask the test runs with -- a umask of 077
        // makes the ordinary mode 0600 too, and that is not this helper's
        // doing.
        fs::write(&plain, b"served").unwrap();
        assert_eq!(
            fs::metadata(&public).unwrap().mode() & 0o777,
            fs::metadata(&plain).unwrap().mode() & 0o777
        );
        fs::remove_file(public).unwrap();
        fs::remove_file(plain).unwrap();
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
