//! A package on disk: a directory whose files have been checked against its
//! manifest, byte for byte.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use super::manifest::{self, FileEntry, Invalid, Manifest, Platform};
use super::MANIFEST_FILE;
use crate::canonical::Value;

/// A directory whose every listed file exists, is a regular file, and hashes
/// to its pin, and whose every runnable entry point is in the format its
/// platform runs.
#[derive(Debug, Clone)]
pub struct Package {
    pub dir: PathBuf,
    pub manifest: Manifest,
}

impl Package {
    /// Read `dir/solver.json` and hold the directory to it.
    pub fn open(dir: &Path) -> Result<Package, Invalid> {
        let path = dir.join(MANIFEST_FILE);
        let text =
            fs::read_to_string(&path).map_err(|e| Invalid(format!("{}: {e}", path.display())))?;
        let manifest = Manifest::from_json(&text)?;
        Package::at(dir, manifest)
    }

    /// Hold `dir` to a manifest that came from somewhere else: a node's
    /// answer, or a store's own copy.
    pub fn at(dir: &Path, manifest: Manifest) -> Result<Package, Invalid> {
        for (path, entry) in &manifest.files {
            verify_file(dir, path, entry)?;
        }
        for (platform, target) in &manifest.targets {
            let bytes = read_capped(&dir.join(&target.entry), manifest::MAX_FILE_BYTES)
                .map_err(|e| Invalid(format!("{}: {e}", target.entry)))?;
            platform.check_entry(&bytes).map_err(|why| {
                Invalid(format!("targets.{platform}.entry {}: {why}", target.entry))
            })?;
        }
        Ok(Package {
            dir: dir.to_path_buf(),
            manifest,
        })
    }

    pub fn id(&self) -> String {
        self.manifest.id()
    }
}

/// Check one file against its pin. A symlink is refused even when it points
/// at the right bytes: what is checked here and what the jail reads later
/// must be the same inode, and a link can be repointed in between.
pub fn verify_file(dir: &Path, path: &str, entry: &FileEntry) -> Result<(), Invalid> {
    if !manifest::valid_path(path) {
        return Err(Invalid(format!("{path:?} is not a package path")));
    }
    let full = dir.join(path);
    let meta = fs::symlink_metadata(&full).map_err(|e| Invalid(format!("{path}: {e}")))?;
    if !meta.file_type().is_file() {
        return Err(Invalid(format!("{path} is not a regular file")));
    }
    if meta.len() != entry.size {
        return Err(Invalid(format!(
            "{path} is {} bytes; solver.json says {}",
            meta.len(),
            entry.size
        )));
    }
    let bytes = read_capped(&full, entry.size).map_err(|e| Invalid(format!("{path}: {e}")))?;
    let actual = crate::blobs::address(&bytes);
    if actual != entry.hex() {
        return Err(Invalid(format!(
            "{path} hashes to {actual}; solver.json pins {}",
            entry.hex()
        )));
    }
    Ok(())
}

fn read_capped(path: &Path, cap: u64) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(cap.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > cap {
        return Err(std::io::Error::other(format!("larger than {cap} bytes")));
    }
    Ok(bytes)
}

/// Write `files` into `dir/solver.json` from what is on disk, and return the
/// manifest that results.
///
/// Every regular file under `dir` is listed, except the manifest itself and
/// anything hidden. A symlink, or a file a manifest could not name, is an
/// error rather than a skip: silently leaving out a file the solver opens
/// would publish a package that works on its author's machine only.
pub fn pack(dir: &Path) -> Result<Manifest, Invalid> {
    let path = dir.join(MANIFEST_FILE);
    let text =
        fs::read_to_string(&path).map_err(|e| Invalid(format!("{}: {e}", path.display())))?;
    let mut value =
        Value::from_json(&text).map_err(|e| Invalid(format!("{}: {e}", path.display())))?;
    let mut files = BTreeMap::new();
    walk(dir, dir, &mut files)?;
    let Value::Object(fields) = &mut value else {
        return Err(Invalid("solver.json must be a JSON object".into()));
    };
    fields.insert("files".into(), Value::Object(files));
    let manifest = Manifest::from_value(&value)?;
    let package = Package::at(dir, manifest)?;
    fs::write(&path, crate::scaffold::pretty(&value))
        .map_err(|e| Invalid(format!("{}: {e}", path.display())))?;
    Ok(package.manifest)
}

fn walk(root: &Path, dir: &Path, files: &mut BTreeMap<String, Value>) -> Result<(), Invalid> {
    let entries = fs::read_dir(dir).map_err(|e| Invalid(format!("{}: {e}", dir.display())))?;
    let mut names: Vec<_> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect();
    names.sort();
    for path in names {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.starts_with('.') || (dir == root && name == MANIFEST_FILE) {
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .ok()
            .and_then(Path::to_str)
            .map(|p| p.replace(std::path::MAIN_SEPARATOR, "/"))
            .ok_or_else(|| {
                Invalid(format!(
                    "{} has a name a manifest cannot hold",
                    path.display()
                ))
            })?;
        let meta = fs::symlink_metadata(&path).map_err(|e| Invalid(format!("{relative}: {e}")))?;
        if meta.file_type().is_symlink() {
            return Err(Invalid(format!(
                "{relative} is a symlink; copy the file into the package instead"
            )));
        }
        if meta.is_dir() {
            walk(root, &path, files)?;
            continue;
        }
        if !manifest::valid_path(&relative) {
            return Err(Invalid(format!(
                "{relative}: a package path uses letters, digits, '.', '_', '-' and '/' only"
            )));
        }
        let bytes = read_capped(&path, manifest::MAX_FILE_BYTES)
            .map_err(|e| Invalid(format!("{relative}: {e}")))?;
        files.insert(
            relative,
            Value::object([
                ("sha256", Value::string(crate::blobs::address(&bytes))),
                ("size", Value::Int(bytes.len() as i128)),
            ]),
        );
    }
    Ok(())
}

/// Copy a checked package's files into `into`, which must not exist, with
/// native entry points executable and everything else not. The manifest is
/// written beside them in canonical form, so the copy is its own proof of
/// what it is.
pub fn install(package: &Package, into: &Path) -> Result<(), Invalid> {
    let io = |e: std::io::Error| Invalid(format!("{}: {e}", into.display()));
    fs::create_dir(into).map_err(io)?;
    for (path, entry) in &package.manifest.files {
        let to = into.join(path);
        if let Some(parent) = to.parent() {
            fs::create_dir_all(parent).map_err(io)?;
        }
        fs::copy(package.dir.join(path), &to).map_err(io)?;
        set_mode(&to, executable(&package.manifest, path)).map_err(io)?;
        verify_file(into, path, entry)?;
    }
    fs::write(
        into.join(MANIFEST_FILE),
        package.manifest.to_value().canonical_bytes(),
    )
    .map_err(io)?;
    Ok(())
}

/// Whether `path` is a native target's entry point, the only files a
/// package's copy marks executable.
pub fn executable(manifest: &Manifest, path: &str) -> bool {
    manifest
        .targets
        .iter()
        .any(|(platform, target)| platform.is_native() && target.entry == path)
}

#[cfg(unix)]
pub fn set_mode(path: &Path, executable: bool) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(
        path,
        fs::Permissions::from_mode(if executable { 0o755 } else { 0o644 }),
    )
}

#[cfg(not(unix))]
pub fn set_mode(_path: &Path, _executable: bool) -> std::io::Result<()> {
    Ok(())
}

/// The platforms in `manifest` this host can run, best first.
pub fn runnable_here(manifest: &Manifest) -> Vec<Platform> {
    let mut found = Vec::new();
    if let Some(host) = Platform::host() {
        if manifest.targets.contains_key(&host) {
            found.push(host);
        }
    }
    if manifest.targets.contains_key(&Platform::Python3) {
        found.push(Platform::Python3);
    }
    found
}
