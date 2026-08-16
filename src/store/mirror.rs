//! Copying the store somewhere else, without ever decrypting it.
//!
//! An operator who wants their node's data on a NAS, an external disk, or a
//! cloud-synced folder is not asking for a distributed system -- they are asking
//! for a copy. This is that: a one-way, idempotent, resumable file copy that
//! knows two things a generic tool does not.
//!
//! # It never decrypts
//!
//! The mirror copies bytes. If the store is sealed, the mirror is sealed, and
//! this module never holds a key -- it has no field to put one in. That is the
//! only design under which "sync my node to Dropbox" is a sentence a security
//! reviewer can hear without flinching.
//!
//! # It refuses to carry the key
//!
//! Encryption at rest buys exactly one thing: copies that leave the machine are
//! inert. A key file copied *alongside* the ciphertext turns that back into an
//! elaborate way of storing plaintext, and it is a mistake that looks like
//! working software, because everything still opens.
//!
//! So a key file found inside the source is **skipped and reported**, never
//! copied. Not an error -- refusing to run at all would push operators toward
//! `cp -r`, which has no opinion on the matter -- but never silent either.
//! [`Report::skipped_keys`] is the line a human has to see.
//!
//! # Deleting is opt-in
//!
//! A mirror that prunes by default is a mirror that turns a mistyped source
//! path into data loss at the destination. [`Options::prune`] exists, defaults
//! to off, and only ever removes files under the destination that the source
//! no longer has.

use std::fs;
use std::path::{Path, PathBuf};

use super::{atrest, format_size, walk, Store, StoreError};

/// How to run a mirror.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Options {
    /// Remove destination files the source no longer has. Off by default.
    pub prune: bool,
    /// Report what would happen without touching the destination.
    pub dry_run: bool,
}

/// What a mirror did, or would do.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Report {
    /// Files written to the destination.
    pub copied: Vec<PathBuf>,
    /// Files already identical at the destination.
    pub unchanged: u64,
    /// Files removed from the destination, only ever with [`Options::prune`].
    pub pruned: Vec<PathBuf>,
    /// Key files found in the source and deliberately not copied.
    ///
    /// The most important field here. An empty vector means the store held no
    /// keys, which is the layout that makes the mirror safe.
    pub skipped_keys: Vec<PathBuf>,
    /// Plaintext ledger backups left by `store encrypt` and not copied.
    pub skipped_plaintext: Vec<PathBuf>,
    /// Bytes written.
    pub bytes: u64,
    /// Files whose modification time could not be carried to the destination.
    ///
    /// Not a failure -- the bytes arrived -- but each one will be recopied on
    /// the next run, so a destination filesystem that cannot hold timestamps
    /// turns an incremental mirror into a full one. Counted rather than
    /// swallowed, because "my backup takes an hour every time" is otherwise a
    /// mystery.
    pub undated: u64,
    /// True if any copied file was in the clear.
    ///
    /// Not an error: an operator may be mirroring an unencrypted store to a
    /// disk they trust, and that is their call. It is reported because the same
    /// command pointed at a cloud folder is a very different decision, and
    /// nothing else in the output would distinguish the two.
    pub plaintext: bool,
}

impl Report {
    pub fn is_empty(&self) -> bool {
        self.copied.is_empty() && self.pruned.is_empty()
    }

    /// A human-readable summary.
    pub fn summary(&self) -> String {
        let mut lines = vec![format!(
            "{} copied ({}), {} unchanged, {} pruned",
            self.copied.len(),
            format_size(self.bytes),
            self.unchanged,
            self.pruned.len()
        )];
        if !self.skipped_keys.is_empty() {
            lines.push(format!(
                "{} key file(s) NOT copied -- a key beside its ciphertext is not \
                 encryption. Keep the key somewhere the mirror does not reach:",
                self.skipped_keys.len()
            ));
            for path in &self.skipped_keys {
                lines.push(format!("  skipped {}", path.display()));
            }
        }
        if !self.skipped_plaintext.is_empty() {
            lines.push(format!(
                "{} plaintext backup(s) NOT copied -- `store encrypt` leaves the \
                 unconverted original behind, and mirroring it would undo the \
                 conversion. Delete them once you trust the sealed log:",
                self.skipped_plaintext.len()
            ));
            for path in &self.skipped_plaintext {
                lines.push(format!("  skipped {}", path.display()));
            }
        }
        if self.undated > 0 {
            lines.push(format!(
                "note: {} file(s) could not keep their modification time at the \
                 destination, so they will be copied again next run",
                self.undated
            ));
        }
        if self.plaintext {
            lines.push(String::from(
                "warning: this store is NOT encrypted, so the mirror is readable \
                 by anyone who can read the destination. Run `cairn keygen` \
                 and `cairn store encrypt` first if that is not what you want.",
            ));
        }
        lines.join("\n")
    }
}

/// Copy `store` to `destination`.
///
/// Idempotent: a file whose size and modification time match at the destination
/// is left alone, so a second run over an unchanged store copies nothing and a
/// run interrupted halfway resumes rather than restarting.
///
/// Size-and-mtime rather than a hash of every file, deliberately. Hashing a
/// hundred gigabytes to discover that nothing changed is the reason people stop
/// running their backups. The log is append-only and content-addressed, so the
/// case this heuristic could miss -- same size, same mtime, different bytes --
/// is one the ledger's own hash chain catches on the next `audit`.
pub fn mirror(store: &Store, destination: &Path, options: Options) -> Result<Report, StoreError> {
    let source = store.root();
    if !source.exists() {
        return Err(StoreError::NotADirectory(source.to_path_buf()));
    }
    if destination.exists() && !destination.is_dir() {
        return Err(StoreError::NotADirectory(destination.to_path_buf()));
    }
    // Refuse to mirror a store into itself or into its own subtree, which would
    // otherwise recurse until the disk filled.
    if destination.starts_with(source) || source.starts_with(destination) {
        return Err(StoreError::NotADirectory(destination.to_path_buf()));
    }

    let mut report = Report::default();
    let files = walk(store, source)?;

    for file in &files {
        let relative = match file.path.strip_prefix(source) {
            Ok(relative) => relative,
            // Unreachable: `walk` only yields paths under `source`. Skipped
            // rather than unwrapped, because copying a path we cannot place
            // relative to the destination is the one outcome worse than
            // skipping it.
            Err(_) => continue,
        };
        match withhold(&file.path) {
            Some(Withhold::Key) => {
                report.skipped_keys.push(file.path.clone());
                continue;
            }
            Some(Withhold::PlaintextBackup) => {
                report.skipped_plaintext.push(file.path.clone());
                continue;
            }
            None => {}
        }
        let target = destination.join(relative);
        if same_file(&file.path, &target) {
            report.unchanged = report.unchanged.saturating_add(1);
            continue;
        }
        if first_chunk(&file.path)
            .map(|head| is_plaintext_ledger(&String::from_utf8_lossy(&head)))
            .unwrap_or(false)
        {
            report.plaintext = true;
        }
        if !options.dry_run {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent).map_err(|source| StoreError::Io {
                    context: format!("creating {}", parent.display()),
                    source,
                })?;
            }
            fs::copy(&file.path, &target).map_err(|source| StoreError::Io {
                context: format!("copying {} to {}", file.path.display(), target.display()),
                source,
            })?;
            if !preserve_modified(&file.path, &target) {
                report.undated = report.undated.saturating_add(1);
            }
        }
        report.bytes = report.bytes.saturating_add(file.bytes);
        report.copied.push(target);
    }

    if options.prune {
        prune(store, source, destination, &mut report, options.dry_run)?;
    }
    Ok(report)
}

/// Remove destination files the source no longer holds.
fn prune(
    store: &Store,
    source: &Path,
    destination: &Path,
    report: &mut Report,
    dry_run: bool,
) -> Result<(), StoreError> {
    if !destination.exists() {
        return Ok(());
    }
    // Classified against a store rooted at the *destination*, so `walk`'s
    // symlink refusal applies there too -- a link planted in the destination
    // must not let a prune delete outside it.
    let mirror_store = Store::new(destination);
    for file in walk(&mirror_store, destination)? {
        let relative = match file.path.strip_prefix(destination) {
            Ok(relative) => relative,
            Err(_) => continue,
        };
        if source.join(relative).exists() {
            continue;
        }
        if !dry_run {
            match fs::remove_file(&file.path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(StoreError::Io {
                        context: format!("pruning {}", file.path.display()),
                        source: error,
                    })
                }
            }
        }
        report.pruned.push(file.path.clone());
    }
    let _ = store;
    Ok(())
}

/// Why a file was not copied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Withhold {
    /// A key file. Copying it beside its ciphertext undoes the encryption.
    Key,
    /// A plaintext ledger left behind by `store encrypt`.
    ///
    /// This one was a bug before it was a feature. `store encrypt` renames the
    /// original to `<log>.plaintext.bak` and tells the operator to delete it
    /// once satisfied -- and until they do, it sits in the data directory,
    /// unencrypted, being faithfully copied to whatever cloud folder the mirror
    /// points at. The whole conversion is undone by the backup that made it
    /// safe. So the mirror leaves it behind and says so.
    PlaintextBackup,
}

/// Should this file be withheld from the mirror?
///
/// Content, not filename, for the key case: somebody who renamed their key to
/// `notes.txt` is exactly who this has to catch. Only the first chunk is read,
/// so asking the question of a hundred-gigabyte log costs a page.
fn withhold(path: &Path) -> Option<Withhold> {
    let head = match first_chunk(path) {
        Some(head) => head,
        // A file that cannot be read cannot be confirmed safe. Withheld rather
        // than copied on the assumption it is fine.
        None => return Some(Withhold::Key),
    };
    let text = String::from_utf8_lossy(&head);
    let trimmed = text.trim_start();
    if trimmed.starts_with("pwkey1:") || trimmed.starts_with("pwkey1a:") {
        return Some(Withhold::Key);
    }
    if path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.ends_with(PLAINTEXT_BACKUP_SUFFIX))
        && is_plaintext_ledger(&text)
    {
        return Some(Withhold::PlaintextBackup);
    }
    None
}

/// Suffix `store encrypt` leaves its unconverted original under.
pub const PLAINTEXT_BACKUP_SUFFIX: &str = ".plaintext.bak";

/// Does this content look like ledger entries in the clear?
///
/// Deliberately not "is this the configured log path". A store can hold
/// plaintext ledger content under any name -- a backup, a copy someone made, an
/// export -- and the warning has to fire for all of them, because the risk is a
/// property of the bytes and not of the filename.
fn is_plaintext_ledger(text: &str) -> bool {
    let Some(line) = text.lines().find(|line| !line.trim().is_empty()) else {
        return false;
    };
    if atrest::is_sealed_line(line) {
        return false;
    }
    line.trim_start().starts_with('{') && line.contains("\"hash\"") && line.contains("\"seq\"")
}

/// At most the first 4 KiB of a file.
fn first_chunk(path: &Path) -> Option<Vec<u8>> {
    use std::io::Read as _;
    let file = fs::File::open(path).ok()?;
    let mut head = Vec::new();
    file.take(4096).read_to_end(&mut head).ok()?;
    Some(head)
}

/// Give the copy the source's modification time.
///
/// Without this the mirror is not idempotent, and the platform decides whether
/// anyone notices. `fs::copy` copies contents and permissions -- it says nothing
/// about timestamps, and on Linux it preserves none, so every destination file
/// lands with *now* as its mtime, [`same_file`] never matches, and each run
/// recopies the entire store. macOS's `copyfile` happens to carry the timestamp
/// across, which hid the bug locally and let CI find it.
///
/// Returns false if the timestamp could not be set. That is not fatal -- the
/// bytes arrived, which is what a backup is for -- but it does mean the file
/// will be recopied next time, so the count is reported rather than swallowed.
fn preserve_modified(source: &Path, target: &Path) -> bool {
    let Ok(modified) = fs::metadata(source).and_then(|meta| meta.modified()) else {
        return false;
    };
    let Ok(handle) = fs::File::options().write(true).open(target) else {
        return false;
    };
    handle
        .set_times(fs::FileTimes::new().set_modified(modified))
        .is_ok()
}

/// Same size and same modification time.
///
/// Deliberately not a content hash. Hashing a hundred gigabytes to discover
/// that nothing changed is the reason people stop running their backups, and
/// the case this misses -- same size, same mtime, different bytes -- is one the
/// ledger's own hash chain catches on the next `audit`.
fn same_file(source: &Path, target: &Path) -> bool {
    let (Ok(left), Ok(right)) = (fs::metadata(source), fs::metadata(target)) else {
        return false;
    };
    if left.len() != right.len() {
        return false;
    }
    match (left.modified(), right.modified()) {
        (Ok(a), Ok(b)) => a == b,
        // A platform that will not report mtime gets a copy every time, which
        // is slow and correct rather than fast and wrong.
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::tests::scratch;

    fn sealed_store(tag: &str) -> (PathBuf, Store) {
        let dir = scratch(tag);
        let store = Store::new(dir.join("data"));
        store.prepare().expect("prepares");
        fs::write(store.log_path(), "pwenc1:00:11\n").expect("write log");
        fs::write(store.cache_dir().join("blob"), "cached").expect("write cache");
        (dir, store)
    }

    #[test]
    fn a_mirror_copies_the_tree_and_is_idempotent() {
        let (dir, store) = sealed_store("copy");
        let destination = dir.join("mirror");
        let first = mirror(&store, &destination, Options::default()).expect("mirrors");
        assert_eq!(first.copied.len(), 2);
        assert_eq!(first.unchanged, 0);
        assert!(destination.join("log/cairn.jsonl").exists());
        assert!(destination.join("cache/blob").exists());

        let second = mirror(&store, &destination, Options::default()).expect("mirrors again");
        assert!(
            second.copied.is_empty(),
            "a second run copied {:?}",
            second.copied
        );
        assert_eq!(second.unchanged, 2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_mirror_is_ciphertext_and_the_module_never_holds_a_key() {
        let (dir, store) = sealed_store("ciphertext");
        let destination = dir.join("mirror");
        mirror(&store, &destination, Options::default()).expect("mirrors");
        let copied = fs::read_to_string(destination.join("log/cairn.jsonl")).expect("read");
        assert!(copied.starts_with("pwenc1:"));
        assert_eq!(copied, "pwenc1:00:11\n", "bytes, not a re-encryption");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_key_file_inside_the_store_is_never_copied() {
        // The guard the whole feature turns on. Copying the key beside the
        // ciphertext would make the mirror plaintext in every way that matters.
        let (dir, store) = sealed_store("keyguard");
        let key = store.root().join("key");
        fs::write(&key, format!("pwkey1:{}\n", "ab".repeat(32))).expect("write key");
        let destination = dir.join("mirror");
        let report = mirror(&store, &destination, Options::default()).expect("mirrors");

        assert_eq!(report.skipped_keys, vec![key]);
        assert!(!destination.join("key").exists(), "the key was copied");
        assert!(report.summary().contains("NOT copied"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_key_file_is_recognised_by_content_not_by_name() {
        // Renaming the key must not defeat the guard; somebody who did that is
        // exactly who it has to catch.
        let (dir, store) = sealed_store("renamedkey");
        let disguised = store.cache_dir().join("notes.txt");
        fs::write(&disguised, "pwkey1a:65536:3:1:00:11:22\n").expect("write");
        let destination = dir.join("mirror");
        let report = mirror(&store, &destination, Options::default()).expect("mirrors");
        assert_eq!(report.skipped_keys, vec![disguised]);
        assert!(!destination.join("cache/notes.txt").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_plaintext_backup_from_store_encrypt_is_never_mirrored() {
        // Regression, and the bug was mine: `store encrypt` renames the
        // original to `<log>.plaintext.bak` so it cannot destroy an operator's
        // only copy, and the mirror then dutifully copied that plaintext to
        // whatever cloud folder it was pointed at -- undoing the conversion
        // with the very file that made it safe.
        let (dir, store) = sealed_store("plaintextbak");
        let backup = store
            .root()
            .join("log")
            .join(format!("cairn.jsonl{PLAINTEXT_BACKUP_SUFFIX}"));
        fs::write(
            &backup,
            "{\"hash\":\"sha256:00\",\"kind\":\"note\",\"seq\":0}\n",
        )
        .expect("write");
        let destination = dir.join("mirror");
        let report = mirror(&store, &destination, Options::default()).expect("mirrors");

        assert_eq!(report.skipped_plaintext, vec![backup]);
        assert!(
            !destination
                .join(format!("log/cairn.jsonl{PLAINTEXT_BACKUP_SUFFIX}"))
                .exists(),
            "the plaintext backup reached the mirror"
        );
        assert!(report.summary().contains("plaintext backup"));
        // The sealed log itself still goes.
        assert!(destination.join("log/cairn.jsonl").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn plaintext_ledger_content_is_detected_by_its_bytes_not_its_path() {
        // A copy someone made by hand, under any name, still trips the warning.
        let (dir, store) = sealed_store("anyname");
        fs::write(
            store.cache_dir().join("export.json"),
            "{\"hash\":\"sha256:aa\",\"kind\":\"note\",\"seq\":0}\n",
        )
        .expect("write");
        let destination = dir.join("mirror");
        let report = mirror(&store, &destination, Options::default()).expect("mirrors");
        assert!(
            report.plaintext,
            "unencrypted ledger content went unremarked"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn mirroring_an_unencrypted_store_warns_rather_than_refusing() {
        // The operator's call, not this module's -- but never silent.
        let dir = scratch("plaintext");
        let store = Store::new(dir.join("data"));
        store.prepare().expect("prepares");
        fs::write(
            store.log_path(),
            "{\"hash\":\"sha256:00\",\"kind\":\"note\",\"seq\":0}\n",
        )
        .expect("write log");
        let destination = dir.join("mirror");
        let report = mirror(&store, &destination, Options::default()).expect("mirrors");
        assert!(report.plaintext);
        assert!(report.summary().contains("NOT encrypted"));
        assert!(destination.join("log/cairn.jsonl").exists(), "still copied");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_dry_run_touches_nothing() {
        let (dir, store) = sealed_store("dryrun");
        let destination = dir.join("mirror");
        let report = mirror(
            &store,
            &destination,
            Options {
                dry_run: true,
                ..Options::default()
            },
        )
        .expect("plans");
        assert_eq!(report.copied.len(), 2);
        assert!(!destination.exists(), "a dry run created the destination");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn pruning_is_opt_in() {
        let (dir, store) = sealed_store("prune");
        let destination = dir.join("mirror");
        mirror(&store, &destination, Options::default()).expect("mirrors");
        let stale = destination.join("cache/gone");
        fs::write(&stale, "left over").expect("write");

        let kept = mirror(&store, &destination, Options::default()).expect("mirrors");
        assert!(kept.pruned.is_empty());
        assert!(stale.exists(), "a default run deleted something");

        let pruned = mirror(
            &store,
            &destination,
            Options {
                prune: true,
                ..Options::default()
            },
        )
        .expect("prunes");
        assert_eq!(pruned.pruned, vec![stale.clone()]);
        assert!(!stale.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_destination_inside_the_source_is_refused() {
        // Otherwise the copy recurses into its own output until the disk fills.
        let (dir, store) = sealed_store("nested");
        let inside = store.root().join("mirror");
        assert!(matches!(
            mirror(&store, &inside, Options::default()).expect_err("nested"),
            StoreError::NotADirectory(_)
        ));
        assert!(matches!(
            mirror(&store, store.root(), Options::default()).expect_err("itself"),
            StoreError::NotADirectory(_)
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_destination_that_is_a_file_is_refused() {
        let (dir, store) = sealed_store("destfile");
        let blocker = dir.join("blocker");
        fs::write(&blocker, "not a directory").expect("write");
        assert!(matches!(
            mirror(&store, &blocker, Options::default()).expect_err("not a dir"),
            StoreError::NotADirectory(_)
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_copy_keeps_the_source_modification_time() {
        // Regression, and the bug was invisible on the machine it was written
        // on. `fs::copy` copies contents and permissions and says nothing about
        // timestamps: on Linux the destination lands with *now*, so `same_file`
        // never matches and every run recopies the whole store. macOS's
        // `copyfile` carries the timestamp across, which hid it locally until
        // CI ran on ubuntu.
        //
        // Asserting the timestamp directly -- rather than only asserting
        // idempotence -- is what makes this catch the bug on either platform.
        let (dir, store) = sealed_store("mtime");
        let destination = dir.join("mirror");
        let report = mirror(&store, &destination, Options::default()).expect("mirrors");
        assert_eq!(report.undated, 0, "the platform refused to set a timestamp");

        for relative in ["log/cairn.jsonl", "cache/blob"] {
            let source = store.root().join(relative);
            let target = destination.join(relative);
            let left = fs::metadata(&source)
                .expect("stat")
                .modified()
                .expect("mtime");
            let right = fs::metadata(&target)
                .expect("stat")
                .modified()
                .expect("mtime");
            assert_eq!(left, right, "{relative} did not keep its modification time");
            assert!(same_file(&source, &target));
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_changed_file_is_recopied() {
        let (dir, store) = sealed_store("changed");
        let destination = dir.join("mirror");
        mirror(&store, &destination, Options::default()).expect("mirrors");
        fs::write(store.cache_dir().join("blob"), "cached and then some").expect("write");
        let report = mirror(&store, &destination, Options::default()).expect("mirrors");
        assert_eq!(report.copied.len(), 1);
        assert_eq!(
            fs::read_to_string(destination.join("cache/blob")).expect("read"),
            "cached and then some"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
