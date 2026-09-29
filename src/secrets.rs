//! Named operator secrets, kept off the log and out of agent transcripts.
//!
//! The at-rest key ([`crate::store::atrest`]) seals the ledger. These are the
//! *other* secrets an operator needs beside it: AWS keys for the ECC2K-130
//! campaign store, a Postgres URL for the distinguished-point ingester, a
//! GitHub feed URL for the status page. They live under `~/.cairn/secrets/`
//! (or `$CAIRN_SECRETS_DIR`), written through [`crate::secret_file`] so modes
//! and symlink races match every other secret file this crate owns.
//!
//! MCP may *set* a secret and may *list* names. It never returns a value —
//! agents log what they see, and a secret in a transcript is a leaked secret.
//! `cairn secret get` and `cairn secret run` exist for operators and scripts
//! that already hold the machine.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::secret_file;

/// Environment variable naming the secrets directory.
pub const SECRETS_DIR_ENV: &str = "CAIRN_SECRETS_DIR";

/// A secret name is an environment-variable spelling: `[A-Za-z_][A-Za-z0-9_]*`.
///
/// That is what `cairn secret run` exports into a child, and what the ECC2K
/// campaign scripts already read (`AWS_ACCESS_KEY_ID`, `DATABASE_URL`, …), so
/// the name *is* the binding rather than a second map.
pub fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_') && name.len() <= 128
}

/// Where named secrets live.
///
/// Outside the data directory on purpose, for the same reason the at-rest key
/// is: a backup of the store must not also be a backup of every credential
/// the operator ever set.
pub fn default_dir() -> PathBuf {
    if let Ok(explicit) = std::env::var(SECRETS_DIR_ENV) {
        if !explicit.is_empty() {
            return PathBuf::from(explicit);
        }
    }
    match home_dir() {
        Some(home) => home.join(".cairn").join("secrets"),
        None => PathBuf::from(".cairn-secrets"),
    }
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn path_for(dir: &Path, name: &str) -> Result<PathBuf, SecretsError> {
    if !valid_name(name) {
        return Err(SecretsError::BadName(name.to_string()));
    }
    Ok(dir.join(name))
}

/// Create the secrets directory with owner-only permissions where the platform
/// can express them.
pub fn prepare(dir: &Path) -> Result<(), SecretsError> {
    fs::create_dir_all(dir).map_err(|source| SecretsError::Io {
        context: format!("creating {}", dir.display()),
        source,
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

/// Write or replace a named secret.
///
/// Trailing newlines are stripped once, matching passphrase-file handling: a
/// value pasted from a file with a final newline is the value without it, and
/// an interior newline is part of the secret.
pub fn set(dir: &Path, name: &str, value: &str) -> Result<PathBuf, SecretsError> {
    prepare(dir)?;
    let path = path_for(dir, name)?;
    let trimmed = value.trim_end_matches(['\n', '\r']);
    if trimmed.is_empty() {
        return Err(SecretsError::EmptyValue);
    }
    secret_file::replace(&path, trimmed.as_bytes()).map_err(|source| SecretsError::Io {
        context: format!("writing {}", path.display()),
        source,
    })?;
    Ok(path)
}

/// Read a named secret.
pub fn get(dir: &Path, name: &str) -> Result<String, SecretsError> {
    let path = path_for(dir, name)?;
    if !path.exists() {
        return Err(SecretsError::Missing(name.to_string()));
    }
    let text = secret_file::read_to_string(&path).map_err(|source| SecretsError::Io {
        context: format!("reading {}", path.display()),
        source,
    })?;
    Ok(text.trim_end_matches(['\n', '\r']).to_string())
}

/// Delete a named secret. Missing is success: the desired state is "absent".
pub fn delete(dir: &Path, name: &str) -> Result<(), SecretsError> {
    let path = path_for(dir, name)?;
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(SecretsError::Io {
            context: format!("removing {}", path.display()),
            source,
        }),
    }
}

/// Names present in the directory, sorted. Never the values.
pub fn list(dir: &Path) -> Result<Vec<String>, SecretsError> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut names = Vec::new();
    for entry in fs::read_dir(dir).map_err(|source| SecretsError::Io {
        context: format!("listing {}", dir.display()),
        source,
    })? {
        let entry = entry.map_err(|source| SecretsError::Io {
            context: format!("listing {}", dir.display()),
            source,
        })?;
        let meta = entry.metadata().map_err(|source| SecretsError::Io {
            context: format!("listing {}", dir.display()),
            source,
        })?;
        if !meta.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue;
        }
        if valid_name(&name) {
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

/// Load every named secret as `(name, value)` for exporting into a child
/// environment. Used by `cairn secret run`.
pub fn load_all(dir: &Path, names: &[String]) -> Result<Vec<(String, String)>, SecretsError> {
    let mut out = Vec::with_capacity(names.len());
    for name in names {
        out.push((name.clone(), get(dir, name)?));
    }
    Ok(out)
}

#[derive(Debug)]
pub enum SecretsError {
    BadName(String),
    EmptyValue,
    Missing(String),
    Io { context: String, source: io::Error },
}

impl std::fmt::Display for SecretsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecretsError::BadName(name) => write!(
                f,
                "secret name {name:?} is not a valid identifier \
                 ([A-Za-z_][A-Za-z0-9_]*, at most 128 characters)"
            ),
            SecretsError::EmptyValue => write!(f, "secret value is empty"),
            SecretsError::Missing(name) => write!(f, "secret {name:?} is not set"),
            SecretsError::Io { context, source } => write!(f, "{context}: {source}"),
        }
    }
}

impl std::error::Error for SecretsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SecretsError::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "cairn-secrets-{}-{name}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn names_match_env_var_spelling() {
        assert!(valid_name("AWS_ACCESS_KEY_ID"));
        assert!(valid_name("_private"));
        assert!(valid_name("a"));
        assert!(!valid_name(""));
        assert!(!valid_name("1AWS"));
        assert!(!valid_name("aws-key"));
        assert!(!valid_name("aws.key"));
        assert!(!valid_name("../etc"));
        assert!(!valid_name("a/b"));
    }

    #[test]
    fn set_get_list_delete_round_trip() {
        let dir = scratch("round");
        set(&dir, "AWS_ACCESS_KEY_ID", "AKIAEXAMPLE\n").unwrap();
        assert_eq!(get(&dir, "AWS_ACCESS_KEY_ID").unwrap(), "AKIAEXAMPLE");
        assert_eq!(list(&dir).unwrap(), vec!["AWS_ACCESS_KEY_ID".to_string()]);
        delete(&dir, "AWS_ACCESS_KEY_ID").unwrap();
        assert!(list(&dir).unwrap().is_empty());
        assert!(matches!(
            get(&dir, "AWS_ACCESS_KEY_ID"),
            Err(SecretsError::Missing(_))
        ));
        // Missing delete is fine.
        delete(&dir, "AWS_ACCESS_KEY_ID").unwrap();
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn replace_overwrites() {
        let dir = scratch("replace");
        set(&dir, "TOKEN", "first").unwrap();
        set(&dir, "TOKEN", "second").unwrap();
        assert_eq!(get(&dir, "TOKEN").unwrap(), "second");
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn files_are_owner_only() {
        use std::os::unix::fs::MetadataExt;
        let dir = scratch("mode");
        let path = set(&dir, "DB_URL", "postgres://x").unwrap();
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        assert_eq!(fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn refuses_path_traversal_names() {
        let dir = scratch("traverse");
        assert!(matches!(
            set(&dir, "../key", "x"),
            Err(SecretsError::BadName(_))
        ));
        assert!(matches!(
            set(&dir, "a/b", "x"),
            Err(SecretsError::BadName(_))
        ));
        let _ = fs::remove_dir_all(dir);
    }
}
