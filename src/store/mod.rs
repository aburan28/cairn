//! The local store: where a node's data lives, encrypted, bounded, and copyable.
//!
//! Three things an operator needs and Stage 0 did not give them: put the data
//! where I want it, do not leave it readable on a disk that leaves my control,
//! and do not let it grow without limit.
//!
//! ```text
//! <data-dir>/
//!   log/proofwork.jsonl    the hash-linked log        PINNED       never evicted
//!   cache/blobs/           content-addressed bytes    either       see below
//!   cache/                 re-fetchable content       RECLAIMABLE  evicted under pressure
//!   tmp/                   scratch                    RECLAIMABLE  always safe to drop
//! ```
//!
//! # The one classification that matters
//!
//! [`Class::Pinned`] versus [`Class::Reclaimable`] is the whole design of the
//! quota. A size cap on a store holding the only copy of a hash-linked log is an
//! instruction to destroy evidence, and "delete the oldest thing" would
//! cheerfully eat the log, because the log *is* the oldest thing. So the log is
//! never a candidate: when the cap cannot be met without it, the store
//! **refuses** and says which pinned bytes are in the way.
//!
//! [`blobs`] is what makes that two-way split not quite enough. A blob is
//! content-addressed, so losing one is a re-download rather than a lost record
//! -- reclaimable by construction. But a blob that is this node's only copy of
//! an evaluator some posted objective pins is the difference between a node that
//! can verify and one that answers `Unavailable` for work it is paid to check,
//! which under availability sampling is a slash.
//!
//! The fix is deliberately *not* a third class. [`Store::with_pinned_blobs`]
//! moves individual blobs across the existing line, so the rule stays sayable in
//! one sentence: **a blob is reclaimable exactly when nothing needs it.** A
//! caller that never sets a pin set gets the old behaviour, which is the right
//! default for a store that is not backing a node.
//!
//! That refusal is correct and its consequence is worth stating bluntly: **a cap
//! smaller than your log stops your node; it does not prune your log.** A tool
//! that did the other thing would be worse.
//!
//! # The key is not in here by default, on purpose
//!
//! [`atrest`] encrypts what this module stores. A key file sitting inside the
//! directory you are about to copy to a cloud folder has bought you nothing, so
//! the default key location is *outside* the data directory
//! ([`Store::default_key_path`]) and [`mirror`] refuses to copy a key file it
//! finds inside one.
//!
//! # What the size cap costs, in the other module's units
//!
//! Evicting cached content is not free in a network that pays for availability.
//! [`crate::incentive`] models a node challenged to produce a Merkle path
//! against a published root: a node that evicted the content fails the challenge
//! and is slashed. The cap is therefore a *risk* setting as much as a disk
//! setting, and [`quota::Eviction`] reports what went, so the trade is visible
//! rather than silent.

pub mod atrest;
pub mod blobs;
pub mod mirror;
pub mod quota;

use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use blobs::BLOB_DIR;

/// Environment variable naming the data directory.
pub const DATA_ENV: &str = "PROOFWORK_DATA";
/// Environment variable naming the key file.
pub const KEY_ENV: &str = "PROOFWORK_KEY";

/// Subdirectory holding the log.
pub const LOG_DIR: &str = "log";
/// The log file's name inside [`LOG_DIR`].
pub const LOG_FILE: &str = "proofwork.jsonl";
/// Subdirectory holding re-fetchable content.
pub const CACHE_DIR: &str = "cache";
/// Subdirectory holding scratch files.
pub const TMP_DIR: &str = "tmp";

/// Anything that stops the store working.
#[derive(Debug)]
pub enum StoreError {
    Io {
        context: String,
        source: std::io::Error,
    },
    /// The cap cannot be met without deleting data that must not be deleted.
    ///
    /// Carries the numbers rather than a message, so a caller can decide what to
    /// do and a human can be told exactly what is in the way.
    QuotaExceeded { pinned: u64, limit: u64 },
    /// A size string that is not a size.
    BadSize(String),
    /// The store's root is a file, or otherwise unusable as a directory.
    NotADirectory(PathBuf),
    /// A blob was asked for by a name that is not a SHA-256 digest.
    NotADigest(String),
    /// A stored blob does not hash to the name it is filed under.
    ///
    /// A fact about this disk, never about the objective that asked for the
    /// bytes -- which is why callers turn it into `Unavailable` rather than a
    /// verdict that settles.
    CorruptBlob { digest: String, actual: String },
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Io { context, source } => write!(f, "{context}: {source}"),
            StoreError::QuotaExceeded { pinned, limit } => write!(
                f,
                "store limit of {} cannot hold {} of data that must not be \
                 deleted (the log and anything beside it). Raise the limit or \
                 move the store; proofwork will not prune a hash-linked log to fit",
                format_size(*limit),
                format_size(*pinned)
            ),
            StoreError::BadSize(text) => write!(
                f,
                "{text:?} is not a size; write bytes, or a number with a unit \
                 such as 20GB (10^9) or 20GiB (2^30)"
            ),
            StoreError::NotADirectory(path) => {
                write!(f, "{} is not a directory", path.display())
            }
            StoreError::NotADigest(name) => write!(
                f,
                "{name:?} is not a sha256 digest; expected 64 lowercase hex \
                 characters, optionally prefixed with \"sha256:\""
            ),
            StoreError::CorruptBlob { digest, actual } => write!(
                f,
                "blob {digest} hashes to {actual}: the stored bytes are not the \
                 bytes that name promises. Delete it and fetch it again"
            ),
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StoreError::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

fn io(context: impl Into<String>, source: std::io::Error) -> StoreError {
    StoreError::Io {
        context: context.into(),
        source,
    }
}

/// Whether content may be deleted to stay under the cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Class {
    /// Deleting it destroys something unrecoverable: the log, and anything
    /// beside it that is not a copy of something else.
    Pinned,
    /// A local copy of something that can be fetched again. Evicting it costs
    /// bandwidth and, if the network is paying for availability, possibly a
    /// slash -- but never data.
    Reclaimable,
}

/// A node's local data directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Store {
    root: PathBuf,
    limit: Option<u64>,
    /// Blobs something still needs, as canonical `sha256:` digests. Empty means
    /// "nothing is claiming any of them", which is the correct assumption for a
    /// store nobody has told about a log.
    pinned_blobs: BTreeSet<String>,
}

impl Store {
    /// A store rooted at `root`, with no size cap.
    pub fn new(root: impl Into<PathBuf>) -> Store {
        Store {
            root: root.into(),
            limit: None,
            pinned_blobs: BTreeSet::new(),
        }
    }

    /// The store named by `$PROOFWORK_DATA`, if it is set.
    ///
    /// Returns `None` rather than inventing a default. There is a perfectly good
    /// pre-existing behaviour -- a bare `proofwork.jsonl` in the working
    /// directory -- and quietly relocating an existing operator's log the first
    /// time they upgrade would be the worst possible way to introduce this.
    pub fn from_env() -> Option<Store> {
        std::env::var(DATA_ENV)
            .ok()
            .filter(|value| !value.is_empty())
            .map(Store::new)
    }

    /// Apply a size cap, in bytes.
    pub fn with_limit(mut self, limit: Option<u64>) -> Store {
        self.limit = limit;
        self
    }

    /// Declare the blobs that must survive a reclaim.
    ///
    /// A blob is [`Class::Reclaimable`] by default, because content addressing
    /// makes losing one a re-download rather than a lost record. That stops
    /// being true the moment a posted objective pins it: evicting the only local
    /// copy of an evaluator turns this node into one that answers `Unavailable`
    /// for work it is paid to check, and in a network that pays for availability
    /// that is a slash rather than an inconvenience.
    ///
    /// Digests are accepted in either spelling and stored canonically, so a
    /// caller passing an objective's bare-hex `evaluator_sha256` and one passing
    /// a prefixed id pin the same blob. Anything that is not a digest is
    /// ignored: this is a hint about what matters, and a malformed verifier spec
    /// should fail at verification with a verdict, not here with an error about
    /// disk.
    ///
    /// [`crate::node::Node::pinned_blobs`] is where a node's set comes from.
    pub fn with_pinned_blobs(
        mut self,
        digests: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Store {
        self.pinned_blobs = digests
            .into_iter()
            .filter_map(|digest| blobs::canonical_digest(digest.as_ref()).ok())
            .collect();
        self
    }

    /// The blobs this store has been told are still needed.
    pub fn pinned_blobs(&self) -> &BTreeSet<String> {
        &self.pinned_blobs
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn limit(&self) -> Option<u64> {
        self.limit
    }

    /// Where the log lives inside this store.
    pub fn log_path(&self) -> PathBuf {
        self.root.join(LOG_DIR).join(LOG_FILE)
    }

    pub fn cache_dir(&self) -> PathBuf {
        self.root.join(CACHE_DIR)
    }

    /// Where content-addressed blobs live: `<data-dir>/cache/blobs`.
    pub fn blob_dir(&self) -> PathBuf {
        self.cache_dir().join(BLOB_DIR)
    }

    pub fn tmp_dir(&self) -> PathBuf {
        self.root.join(TMP_DIR)
    }

    /// Where a key file lives when nobody says otherwise: `$PROOFWORK_KEY`, else
    /// `~/.proofwork/key`.
    ///
    /// Deliberately **not** inside the data directory. The default has to be the
    /// safe one, because the unsafe one is invisible: a key beside its
    /// ciphertext looks fine right up until the directory is synced somewhere
    /// else, and then it was never encryption at all. Falls back to
    /// `<data-dir>/key` only when there is no home directory to use, and
    /// [`mirror`] refuses to copy it when that happens.
    pub fn default_key_path(&self) -> PathBuf {
        if let Ok(explicit) = std::env::var(KEY_ENV) {
            if !explicit.is_empty() {
                return PathBuf::from(explicit);
            }
        }
        match home_dir() {
            Some(home) => home.join(".proofwork").join("key"),
            None => self.root.join("key"),
        }
    }

    /// Create the directory tree, with owner-only permissions where possible.
    pub fn prepare(&self) -> Result<(), StoreError> {
        if self.root.exists() && !self.root.is_dir() {
            return Err(StoreError::NotADirectory(self.root.clone()));
        }
        for dir in [
            self.root.clone(),
            self.root.join(LOG_DIR),
            self.cache_dir(),
            self.blob_dir(),
            self.tmp_dir(),
        ] {
            create_private_dir(&dir)?;
        }
        Ok(())
    }

    /// Classify a path inside this store.
    ///
    /// Anything not under a directory known to hold copies is [`Class::Pinned`].
    /// That default is conservative and deliberate: a file this module has never
    /// heard of is a file whose loss it cannot reason about, so it does not get
    /// to delete it.
    pub fn classify(&self, path: &Path) -> Class {
        let relative = match path.strip_prefix(&self.root) {
            Ok(relative) => relative,
            Err(_) => return Class::Pinned,
        };
        match relative.components().next() {
            Some(std::path::Component::Normal(first)) if first == CACHE_DIR || first == TMP_DIR => {
                match self.blob_digest_of(path) {
                    Some(digest) if self.pinned_blobs.contains(&digest) => Class::Pinned,
                    _ => Class::Reclaimable,
                }
            }
            _ => Class::Pinned,
        }
    }

    /// The digest a path under [`Store::blob_dir`] is filed as, if it is one.
    ///
    /// Reconstructed from the layout rather than from the file's contents:
    /// classification runs over every file in the store on every `usage` call,
    /// and re-hashing the disk to answer "may I delete this" would make the
    /// quota cost proportional to the bytes it is trying to bound. A blob whose
    /// contents no longer match its name is a corruption
    /// ([`StoreError::CorruptBlob`]) and is caught where the bytes are used, not
    /// here.
    fn blob_digest_of(&self, path: &Path) -> Option<String> {
        let relative = path.strip_prefix(self.blob_dir()).ok()?;
        let mut parts = relative.components();
        let shard = parts.next()?.as_os_str().to_str()?;
        let rest = parts.next()?.as_os_str().to_str()?;
        if parts.next().is_some() {
            return None;
        }
        blobs::canonical_digest(&format!("{shard}{rest}")).ok()
    }
}

/// One file found under a store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub path: PathBuf,
    pub bytes: u64,
    pub class: Class,
    /// Seconds since the epoch, or zero when the platform will not say.
    /// Eviction order only; never evidence of anything.
    pub modified: u64,
}

/// Every regular file under `root`, depth first.
///
/// Symlinks are recorded but never followed. A store containing a link to `/`
/// must not make `usage()` walk the whole filesystem and -- far more
/// importantly -- must not let eviction delete something outside the store.
pub fn walk(store: &Store, root: &Path) -> Result<Vec<Found>, StoreError> {
    let mut found = Vec::new();
    if !root.exists() {
        return Ok(found);
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries =
            fs::read_dir(&dir).map_err(|e| io(format!("reading {}", dir.display()), e))?;
        for entry in entries {
            let entry = entry.map_err(|e| io(format!("reading {}", dir.display()), e))?;
            let path = entry.path();
            // `symlink_metadata`, not `metadata`: the latter follows links.
            let meta = fs::symlink_metadata(&path)
                .map_err(|e| io(format!("inspecting {}", path.display()), e))?;
            if meta.is_dir() {
                stack.push(path);
                continue;
            }
            let modified = meta
                .modified()
                .ok()
                .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            found.push(Found {
                class: store.classify(&path),
                path,
                bytes: meta.len(),
                modified,
            });
        }
    }
    // Deterministic order, so a report is reproducible and a test can rely on
    // it. `read_dir` gives no ordering guarantee at all.
    found.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(found)
}

fn create_private_dir(path: &Path) -> Result<(), StoreError> {
    if path.exists() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
            .map_err(|e| io(format!("creating {}", path.display()), e))
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(path).map_err(|e| io(format!("creating {}", path.display()), e))
    }
}

fn home_dir() -> Option<PathBuf> {
    std::env::var("HOME")
        .ok()
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

/// Parse a size: bytes, or a number with a unit.
///
/// Both `GB` (10^9) and `GiB` (2^30) are accepted and they mean different
/// things. Disk vendors and operating systems have disagreed about this for
/// thirty years; a storage cap that silently picked one would be off by 7% at
/// the gigabyte and 10% at the terabyte, which is a real amount of somebody's
/// disk. Writing the unit you mean is a small price.
pub fn parse_size(text: &str) -> Result<u64, StoreError> {
    let trimmed = text.trim();
    let bad = || StoreError::BadSize(text.to_string());
    if trimmed.is_empty() {
        return Err(bad());
    }
    let split = trimmed
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(trimmed.len());
    let (number, unit) = trimmed.split_at(split);
    let unit = unit.trim();
    let multiplier: u64 = match unit.to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kb" => 1_000,
        "kib" => 1 << 10,
        "m" | "mb" => 1_000_000,
        "mib" => 1 << 20,
        "g" | "gb" => 1_000_000_000,
        "gib" => 1 << 30,
        "t" | "tb" => 1_000_000_000_000,
        "tib" => 1u64 << 40,
        _ => return Err(bad()),
    };
    // A decimal point is allowed because "1.5GB" is what people write. It is
    // parsed as a scaled integer rather than through a float: this crate does
    // not use floats for quantities anybody cares about, and a size cap is a
    // quantity somebody cares about.
    let (whole, fraction) = match number.split_once('.') {
        Some((whole, fraction)) => (whole, fraction),
        None => (number, ""),
    };
    if whole.is_empty() && fraction.is_empty() {
        return Err(bad());
    }
    let whole: u64 = if whole.is_empty() {
        0
    } else {
        whole.parse().map_err(|_| bad())?
    };
    let mut total = whole.checked_mul(multiplier).ok_or_else(bad)?;
    if !fraction.is_empty() {
        if !fraction.bytes().all(|b| b.is_ascii_digit()) {
            return Err(bad());
        }
        let digits = u32::try_from(fraction.len()).map_err(|_| bad())?;
        let scale = 10u64.checked_pow(digits).ok_or_else(bad)?;
        let numerator: u64 = fraction.parse().map_err(|_| bad())?;
        let part = numerator
            .checked_mul(multiplier)
            .ok_or_else(bad)?
            .checked_div(scale)
            .ok_or_else(bad)?;
        total = total.checked_add(part).ok_or_else(bad)?;
    }
    Ok(total)
}

/// Render a byte count for a human, in the binary units a disk reports.
pub fn format_size(bytes: u64) -> String {
    const UNITS: [(&str, u64); 4] = [
        ("TiB", 1u64 << 40),
        ("GiB", 1 << 30),
        ("MiB", 1 << 20),
        ("KiB", 1 << 10),
    ];
    for (name, scale) in UNITS {
        if bytes >= scale {
            // One decimal place, computed with integers.
            let whole = bytes / scale;
            let tenths = (bytes % scale) * 10 / scale;
            return format!("{whole}.{tenths} {name}");
        }
    }
    format!("{bytes} B")
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn scratch(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "proofwork-store-{}-{nanos}-{n}-{tag}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create scratch dir");
        path
    }

    #[test]
    fn prepare_builds_the_tree_once_and_is_idempotent() {
        let dir = scratch("prepare");
        let store = Store::new(dir.join("data"));
        store.prepare().expect("prepares");
        store.prepare().expect("is idempotent");
        assert!(store.root().is_dir());
        assert!(store.cache_dir().is_dir());
        assert!(store.tmp_dir().is_dir());
        assert_eq!(store.log_path(), store.root().join(LOG_DIR).join(LOG_FILE));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_file_where_the_root_should_be_is_refused() {
        let dir = scratch("notadir");
        let path = dir.join("blocker");
        fs::write(&path, "not a directory").expect("write");
        let store = Store::new(&path);
        assert!(matches!(
            store.prepare().expect_err("a file is not a store"),
            StoreError::NotADirectory(_)
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn classification_defaults_to_pinned_for_anything_unrecognised() {
        // The conservative default, and the one that matters: a file this
        // module has never heard of is one whose loss it cannot reason about.
        let store = Store::new("/store");
        assert_eq!(
            store.classify(Path::new("/store/cache/blob")),
            Class::Reclaimable
        );
        assert_eq!(
            store.classify(Path::new("/store/tmp/x")),
            Class::Reclaimable
        );
        assert_eq!(
            store.classify(Path::new("/store/log/proofwork.jsonl")),
            Class::Pinned
        );
        assert_eq!(store.classify(Path::new("/store/key")), Class::Pinned);
        assert_eq!(
            store.classify(Path::new("/store/something-new/file")),
            Class::Pinned,
            "an unknown directory must not be evictable"
        );
        assert_eq!(
            store.classify(Path::new("/elsewhere/cache/blob")),
            Class::Pinned,
            "outside the store entirely"
        );
        // And the near-miss: a directory whose name merely starts with "cache".
        assert_eq!(
            store.classify(Path::new("/store/cache-of-mine/blob")),
            Class::Pinned
        );
    }

    #[test]
    fn the_default_key_path_is_outside_the_data_directory() {
        // The property the whole at-rest story rests on: a key beside its
        // ciphertext is not encryption once the directory is synced.
        let store = Store::new("/store");
        let key = store.default_key_path();
        if home_dir().is_some() && std::env::var(KEY_ENV).is_err() {
            assert!(
                !key.starts_with("/store"),
                "the default key path {key:?} is inside the data directory"
            );
        }
    }

    #[test]
    fn walk_finds_every_file_and_never_follows_a_symlink() {
        let dir = scratch("walk");
        let store = Store::new(dir.join("data"));
        store.prepare().expect("prepares");
        fs::write(store.log_path(), "log").expect("write");
        fs::write(store.cache_dir().join("a"), "aaaa").expect("write");
        fs::create_dir_all(store.cache_dir().join("nested")).expect("mkdir");
        fs::write(store.cache_dir().join("nested/b"), "bb").expect("write");

        let found = walk(&store, store.root()).expect("walks");
        assert_eq!(found.len(), 3);
        let total: u64 = found.iter().map(|f| f.bytes).sum();
        assert_eq!(total, 3 + 4 + 2);
        assert_eq!(
            found
                .iter()
                .filter(|f| f.class == Class::Pinned)
                .map(|f| f.bytes)
                .sum::<u64>(),
            3,
            "only the log is pinned"
        );

        #[cfg(unix)]
        {
            // A link to a large tree outside the store must not be walked into.
            let outside = dir.join("outside");
            fs::create_dir_all(&outside).expect("mkdir");
            fs::write(outside.join("huge"), vec![0u8; 4096]).expect("write");
            std::os::unix::fs::symlink(&outside, store.cache_dir().join("link")).expect("symlink");
            let found = walk(&store, store.root()).expect("walks");
            let total: u64 = found.iter().map(|f| f.bytes).sum();
            assert!(total < 4096, "the walk followed a symlink out of the store");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn sizes_parse_with_the_unit_the_user_wrote() {
        assert_eq!(parse_size("1024").expect("bytes"), 1024);
        assert_eq!(parse_size("20GB").expect("decimal"), 20_000_000_000);
        assert_eq!(parse_size("20GiB").expect("binary"), 20 * (1 << 30));
        assert_eq!(parse_size("20gib").expect("case"), 20 * (1 << 30));
        assert_eq!(parse_size(" 5 MB ").expect("spaces"), 5_000_000);
        assert_eq!(parse_size("1.5GB").expect("fraction"), 1_500_000_000);
        assert_eq!(parse_size("0.5GiB").expect("fraction"), (1 << 30) / 2);
        // GB and GiB genuinely differ, which is why both exist.
        assert_ne!(
            parse_size("20GB").expect("size"),
            parse_size("20GiB").expect("size")
        );
    }

    #[test]
    fn a_size_that_is_not_a_size_is_refused() {
        for junk in ["", "  ", "GB", "abc", "12XB", "1.2.3GB", "1.xGB", "-5GB"] {
            assert!(
                matches!(parse_size(junk), Err(StoreError::BadSize(_))),
                "{junk:?} parsed as a size"
            );
        }
        assert!(matches!(
            parse_size("99999999999999999999TiB"),
            Err(StoreError::BadSize(_))
        ));
    }

    #[test]
    fn sizes_render_in_the_units_a_disk_reports() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(1 << 10), "1.0 KiB");
        assert_eq!(format_size(1536), "1.5 KiB");
        assert_eq!(format_size(1 << 30), "1.0 GiB");
        assert_eq!(format_size(3 * (1u64 << 40)), "3.0 TiB");
    }
}
