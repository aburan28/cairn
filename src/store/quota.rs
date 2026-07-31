//! Keeping the store under a size the operator chose.
//!
//! # Why this is not a cache eviction policy
//!
//! Most disk caps are: watch a number, delete the oldest thing, repeat. That
//! algorithm applied here deletes the log, because the log is the oldest thing
//! and it only grows. It is also the one file whose loss cannot be undone by
//! fetching it again -- it *is* the record.
//!
//! So eviction only ever considers [`Class::Reclaimable`] content, and when
//! that is not enough the answer is [`StoreError::QuotaExceeded`]: a refusal,
//! naming the pinned bytes in the way. The operator raises the cap or moves the
//! store. Nothing here will prune a hash-linked log to fit inside a number.
//!
//! # Eviction order, and what it costs
//!
//! Oldest modification time first. Not least-recently-*used*: `atime` is
//! disabled or lazily updated on most modern filesystems, so a policy built on
//! it would be a policy built on a field that does not move. Modification time
//! is coarse and honest.
//!
//! What eviction costs is not disk, it is exposure. [`crate::incentive`] models
//! a node that must answer a Merkle challenge against a published root: evict
//! the content and the challenge fails, and in a network paying for
//! availability that is a slash. [`Eviction`] therefore reports every path it
//! removed rather than returning a byte count, so the decision is auditable
//! after the fact.

use std::fs;

use super::{format_size, walk, Class, Found, Store, StoreError};

/// What the store is using right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Usage {
    /// Bytes that must not be deleted.
    pub pinned: u64,
    /// Bytes that may be deleted to make room.
    pub reclaimable: u64,
    /// Files counted, both classes.
    pub files: u64,
}

impl Usage {
    pub fn total(&self) -> u64 {
        self.pinned.saturating_add(self.reclaimable)
    }

    /// Bytes still available under `limit`, or zero if the cap is already met
    /// or exceeded.
    pub fn headroom(&self, limit: u64) -> u64 {
        limit.saturating_sub(self.total())
    }

    /// True if the store is over the cap.
    pub fn over(&self, limit: u64) -> bool {
        self.total() > limit
    }
}

/// What a reclaim actually did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Eviction {
    /// Every path removed, with its size, oldest first.
    pub removed: Vec<(std::path::PathBuf, u64)>,
    /// Total bytes freed.
    pub freed: u64,
    /// Usage after the reclaim.
    pub after: Usage,
}

impl Eviction {
    pub fn is_empty(&self) -> bool {
        self.removed.is_empty()
    }
}

/// Measure the store.
pub fn usage(store: &Store) -> Result<Usage, StoreError> {
    let found = walk(store, store.root())?;
    Ok(tally(&found))
}

fn tally(found: &[Found]) -> Usage {
    let mut usage = Usage::default();
    for file in found {
        match file.class {
            Class::Pinned => usage.pinned = usage.pinned.saturating_add(file.bytes),
            Class::Reclaimable => usage.reclaimable = usage.reclaimable.saturating_add(file.bytes),
        }
        usage.files = usage.files.saturating_add(1);
    }
    usage
}

/// Free space until the store, plus `incoming` bytes, fits under its cap.
///
/// A store with no cap does nothing and says so with an empty [`Eviction`].
///
/// `incoming` is what the caller is about to write. Passing it in rather than
/// reclaiming after the fact is the difference between a store that stays under
/// its cap and one that repeatedly exceeds it and then tidies up -- which on a
/// full disk is the same as not having a cap at all.
pub fn reclaim(store: &Store, incoming: u64) -> Result<Eviction, StoreError> {
    let Some(limit) = store.limit() else {
        return Ok(Eviction::default());
    };
    let found = walk(store, store.root())?;
    let current = tally(&found);

    // The refusal, checked before anything is deleted. Deleting reclaimable
    // content and *then* discovering the pinned bytes alone bust the cap would
    // be the worst of both: data gone, cap still missed.
    let needed_pinned = current.pinned.saturating_add(incoming);
    if needed_pinned > limit {
        return Err(StoreError::QuotaExceeded {
            pinned: needed_pinned,
            limit,
        });
    }

    let target = limit.saturating_sub(incoming);
    if current.total() <= target {
        return Ok(Eviction {
            after: current,
            ..Eviction::default()
        });
    }

    let mut candidates: Vec<&Found> = found
        .iter()
        .filter(|file| file.class == Class::Reclaimable)
        .collect();
    // Oldest first; path breaks ties so the order is total and reproducible
    // rather than dependent on directory iteration.
    candidates.sort_by(|a, b| {
        a.modified
            .cmp(&b.modified)
            .then_with(|| a.path.cmp(&b.path))
    });

    let mut eviction = Eviction::default();
    let mut total = current.total();
    let mut reclaimable = current.reclaimable;
    for file in candidates {
        if total <= target {
            break;
        }
        match fs::remove_file(&file.path) {
            Ok(()) => {}
            // A file that vanished under us is a file we no longer need to
            // delete. Anything else is reported: silently failing to free space
            // would turn a cap into a suggestion.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(StoreError::Io {
                    context: format!("evicting {}", file.path.display()),
                    source: error,
                })
            }
        }
        total = total.saturating_sub(file.bytes);
        reclaimable = reclaimable.saturating_sub(file.bytes);
        eviction.freed = eviction.freed.saturating_add(file.bytes);
        eviction.removed.push((file.path.clone(), file.bytes));
    }

    eviction.after = Usage {
        pinned: current.pinned,
        reclaimable,
        files: current.files.saturating_sub(eviction.removed.len() as u64),
    };
    Ok(eviction)
}

/// A one-line summary for a report.
pub fn describe(usage: &Usage, limit: Option<u64>) -> String {
    match limit {
        Some(limit) => format!(
            "{} of {} used ({} pinned, {} reclaimable) across {} files",
            format_size(usage.total()),
            format_size(limit),
            format_size(usage.pinned),
            format_size(usage.reclaimable),
            usage.files
        ),
        None => format!(
            "{} used ({} pinned, {} reclaimable) across {} files, no limit set",
            format_size(usage.total()),
            format_size(usage.pinned),
            format_size(usage.reclaimable),
            usage.files
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::tests::scratch;
    use std::path::PathBuf;

    /// A store with a log of `log_bytes` and cache files of the given sizes,
    /// written oldest-first so eviction order is predictable.
    fn fixture(tag: &str, log_bytes: usize, cache: &[usize]) -> (PathBuf, Store) {
        let dir = scratch(tag);
        let store = Store::new(dir.join("data"));
        store.prepare().expect("prepares");
        fs::write(store.log_path(), vec![b'l'; log_bytes]).expect("write log");
        for (index, size) in cache.iter().enumerate() {
            let path = store.cache_dir().join(format!("blob-{index}"));
            fs::write(&path, vec![b'c'; *size]).expect("write cache");
            set_age(&path, 1_000_000 + index as u64);
        }
        (dir, store)
    }

    /// Force a modification time, so eviction order is a property of the test
    /// rather than of how fast the machine wrote three small files.
    fn set_age(path: &std::path::Path, secs: u64) {
        // `std::fs` cannot set mtime, and the dependency list is closed, so
        // this is the libc-free way: only unix is supported, and elsewhere the
        // ordering tests fall back to path order, which `reclaim` also defines.
        #[cfg(unix)]
        {
            use std::process::Command;
            // -t expects [[CC]YY]MMDDhhmm[.SS]; derive one from the offset so
            // successive files differ by minutes.
            let minute = secs % 60;
            let stamp = format!("2020010100{minute:02}");
            let _ = Command::new("touch")
                .arg("-t")
                .arg(&stamp)
                .arg(path)
                .status();
        }
        #[cfg(not(unix))]
        {
            let _ = (path, secs);
        }
    }

    #[test]
    fn usage_splits_pinned_from_reclaimable() {
        let (dir, store) = fixture("usage", 100, &[10, 20]);
        let usage = usage(&store).expect("measures");
        assert_eq!(usage.pinned, 100);
        assert_eq!(usage.reclaimable, 30);
        assert_eq!(usage.total(), 130);
        assert_eq!(usage.files, 3);
        assert_eq!(usage.headroom(200), 70);
        assert_eq!(usage.headroom(50), 0, "no negative headroom");
        assert!(usage.over(129));
        assert!(!usage.over(130));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_store_without_a_limit_evicts_nothing() {
        let (dir, store) = fixture("nolimit", 100, &[10, 20]);
        let eviction = reclaim(&store, 1_000_000).expect("no limit, no work");
        assert!(eviction.is_empty());
        assert_eq!(eviction.freed, 0);
        assert!(store.cache_dir().join("blob-0").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn eviction_stops_as_soon_as_the_cap_is_met() {
        // 160 bytes present against a cap of 140, so 20 must go. The policy is
        // oldest-first, not best-fit, so it walks blob-0 (10 bytes, not enough)
        // and then blob-1 (20 more, now enough) and stops -- freeing 30 rather
        // than the minimal 20, and leaving the newest blob alone.
        //
        // Freeing more than strictly necessary is the honest cost of an
        // age-ordered policy. The alternative -- picking the smallest set that
        // fits -- would evict newly written content ahead of stale content,
        // which is exactly backwards for a cache.
        let (dir, store) = fixture("partial", 100, &[10, 20, 30]);
        let store = store.with_limit(Some(140));
        let eviction = reclaim(&store, 0).expect("reclaims");
        assert_eq!(eviction.removed.len(), 2);
        assert_eq!(eviction.freed, 30);
        assert!(eviction.after.total() <= 140);
        assert_eq!(eviction.after.pinned, 100, "the log is untouched");
        assert!(store.log_path().exists());
        assert!(
            store.cache_dir().join("blob-2").exists(),
            "the newest blob should survive"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_log_is_never_evicted_and_the_shortfall_is_refused() {
        // The whole design of the quota, in one test. A cap below the size of
        // the log is a stop, not a licence to prune it.
        let (dir, store) = fixture("refuse", 1000, &[10, 20]);
        let store = store.with_limit(Some(500));
        let error = reclaim(&store, 0).expect_err("cannot fit");
        match error {
            StoreError::QuotaExceeded { pinned, limit } => {
                assert_eq!(pinned, 1000);
                assert_eq!(limit, 500);
            }
            other => panic!("expected QuotaExceeded, got {other:?}"),
        }
        // And crucially: nothing was deleted on the way to that conclusion.
        assert!(store.log_path().exists());
        assert!(store.cache_dir().join("blob-0").exists());
        assert!(store.cache_dir().join("blob-1").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn incoming_bytes_are_reserved_before_they_are_written() {
        // A cap enforced after the fact is not a cap. The store must be under
        // the limit *including* what is about to land.
        let (dir, store) = fixture("incoming", 100, &[50]);
        let store = store.with_limit(Some(200));
        // 150 present, 200 cap, 90 incoming: 40 must go, so the 50-byte blob.
        let eviction = reclaim(&store, 90).expect("reclaims");
        assert_eq!(eviction.removed.len(), 1);
        assert!(eviction.after.total() + 90 <= 200);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_incoming_write_larger_than_the_cap_is_refused_before_anything_is_deleted() {
        let (dir, store) = fixture("toobig", 100, &[50]);
        let store = store.with_limit(Some(200));
        let error = reclaim(&store, 500).expect_err("cannot fit");
        assert!(matches!(error, StoreError::QuotaExceeded { .. }));
        assert!(store.cache_dir().join("blob-0").exists(), "nothing deleted");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn eviction_reports_every_path_it_removed() {
        // Not a byte count. In a network that pays for availability, each of
        // these is a Merkle challenge that will now fail, and the operator has
        // to be able to see which.
        let (dir, store) = fixture("report", 10, &[100, 100, 100]);
        let store = store.with_limit(Some(120));
        let eviction = reclaim(&store, 0).expect("reclaims");
        assert!(eviction.removed.len() >= 2);
        for (path, bytes) in &eviction.removed {
            assert!(
                !path.exists(),
                "{} was reported but still exists",
                path.display()
            );
            assert_eq!(*bytes, 100);
        }
        assert_eq!(
            eviction.freed,
            eviction.removed.iter().map(|(_, b)| b).sum::<u64>()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_store_already_under_its_cap_is_left_alone() {
        let (dir, store) = fixture("under", 10, &[10]);
        let store = store.with_limit(Some(1_000_000));
        let eviction = reclaim(&store, 0).expect("nothing to do");
        assert!(eviction.is_empty());
        assert_eq!(eviction.after.total(), 20);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_pinned_blob_is_not_an_eviction_candidate() {
        // A blob is reclaimable exactly when nothing needs it. The one an open
        // objective pins is the difference between a node that can verify and
        // one that answers Unavailable for work it is paid to check, so it moves
        // across the existing line rather than getting a class of its own.
        use crate::store::blobs::BlobStore;

        let dir = scratch("pinned-blob");
        let store = Store::new(dir.join("data"));
        store.prepare().expect("prepares");
        fs::write(store.log_path(), vec![b'l'; 10]).expect("write log");

        let blobs = BlobStore::under(&store);
        let needed = blobs.put(&[b'n'; 100]).expect("puts");
        let spare = blobs.put(&[b's'; 100]).expect("puts");

        // Unpinned, both blobs are fair game and the cap is met by deleting.
        let loose = store.clone().with_limit(Some(120));
        assert_eq!(
            loose.classify(&blobs.path_of(&needed).expect("a digest")),
            Class::Reclaimable
        );
        assert_eq!(usage(&loose).expect("measures").pinned, 10, "just the log");

        // Pinned, the same blob is counted as pinned and survives.
        let tight = store
            .clone()
            .with_limit(Some(120))
            .with_pinned_blobs([needed.as_str()]);
        assert_eq!(
            tight.classify(&blobs.path_of(&needed).expect("a digest")),
            Class::Pinned
        );
        assert_eq!(
            tight.classify(&blobs.path_of(&spare).expect("a digest")),
            Class::Reclaimable
        );
        assert_eq!(usage(&tight).expect("measures").pinned, 110);

        let eviction = reclaim(&tight, 0).expect("reclaims");
        assert!(blobs.has(&needed), "the pinned blob survived");
        assert!(!blobs.has(&spare), "the spare paid for the cap");
        assert_eq!(eviction.freed, 100);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_cap_below_the_blobs_an_objective_needs_is_refused_rather_than_met() {
        // The same refusal the log gets, for the same reason: a store that
        // cannot hold what its objectives depend on is a store that has to stop,
        // not one that should quietly delete the thing and carry on verifying
        // nothing.
        use crate::store::blobs::BlobStore;

        let dir = scratch("pinned-refuse");
        let store = Store::new(dir.join("data"));
        store.prepare().expect("prepares");
        fs::write(store.log_path(), vec![b'l'; 10]).expect("write log");
        let blobs = BlobStore::under(&store);
        let needed = blobs.put(&[b'n'; 500]).expect("puts");

        let store = store
            .with_limit(Some(100))
            .with_pinned_blobs([needed.as_str()]);
        match reclaim(&store, 0).expect_err("cannot fit") {
            StoreError::QuotaExceeded { pinned, limit } => {
                assert_eq!(pinned, 510, "the log and the blob it cannot do without");
                assert_eq!(limit, 100);
            }
            other => panic!("expected QuotaExceeded, got {other:?}"),
        }
        assert!(blobs.has(&needed), "nothing deleted on the way to refusing");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_pin_set_naming_blobs_the_store_does_not_have_changes_nothing() {
        // Pin sets come from the log, and a log may well name an evaluator this
        // node has never fetched. That is a gap in the inventory, reported by
        // `blob ls`, and it is not the quota's business.
        use crate::store::blobs::BlobStore;

        let dir = scratch("pinned-absent");
        let store = Store::new(dir.join("data"));
        store.prepare().expect("prepares");
        fs::write(store.log_path(), vec![b'l'; 10]).expect("write log");
        let blobs = BlobStore::under(&store);
        let held = blobs.put(&[b'h'; 100]).expect("puts");
        let never_fetched = crate::canonical::digest_bytes(b"an evaluator we do not have");

        let store = store
            .with_limit(Some(50))
            .with_pinned_blobs([never_fetched.as_str(), "not-a-digest-at-all"]);
        assert_eq!(usage(&store).expect("measures").pinned, 10);
        let eviction = reclaim(&store, 0).expect("reclaims");
        assert_eq!(eviction.freed, 100);
        assert!(!blobs.has(&held));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn describe_says_whether_a_limit_is_set() {
        let usage = Usage {
            pinned: 1 << 20,
            reclaimable: 1 << 21,
            files: 4,
        };
        let capped = describe(&usage, Some(1 << 30));
        assert!(capped.contains("1.0 GiB"));
        assert!(capped.contains("3.0 MiB"));
        assert!(describe(&usage, None).contains("no limit set"));
    }
}
