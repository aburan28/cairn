//! What at-rest encryption covers, and what it deliberately does not.
//!
//! # The decision
//!
//! **[`super::atrest`] seals the log and stops there, on purpose.**
//!
//! The roadmap carried this as an open question — extend encryption past the
//! log, or decide on the record that it should not — because the asymmetry was
//! real and undecided: a node's log is unreadable without a key, and the blob
//! store sitting beside it is a directory of plainly-named files. An asymmetry
//! nobody chose is an accident waiting to be discovered by whoever loses a
//! laptop.
//!
//! The threat at-rest encryption addresses is narrow and worth restating: **a
//! copy of the data directory reaching somewhere the operator did not intend** —
//! a cloud-synced folder, a backup, a drive that gets sold. What sealing buys is
//! that the copy is inert. It has never defended against an attacker with live
//! access to a running node, because the key has to be readable for the node to
//! work.
//!
//! Against that threat:
//!
//! * **The log is sealed.** A stolen disk would otherwise yield the node's whole
//!   operating record in one readable file — every objective, claim, and
//!   settlement it holds, including records it has received and not yet passed
//!   on.
//! * **The blob store is not, and should not be.** Every byte in it, and every
//!   *name* in it, is something this node hands to any peer that asks. Blobs are
//!   pinned checker code; the name is the content address the objective itself
//!   declares; [`crate::p2p::code`] serves them on request. A stolen disk yields
//!   nothing there the network does not already give away for free.
//! * **The shard store is not, for the same reason one level down.** A shard is
//!   a linear combination of a blob the network publishes, filed under that
//!   blob's digest; holding `k` of them is holding the blob, and the blob is
//!   public. It discloses no more than the blob store beside it, and the residue
//!   below is the same residue.
//! * **The population file is not, for the same reason.** Gossiped candidates
//!   were shared with peers on purpose.
//! * **`cache/` and `tmp/` are not.** Reclaimable by construction: a local copy
//!   of something fetchable, and scratch.
//!
//! # The residue, stated rather than waved away
//!
//! The set is not the contents. An adversary holding the disk learns *which
//! objectives this node works on* without having to ask a peer and be observed
//! doing it, and that difference in cost is real.
//!
//! Closing it is possible and was rejected on the merits. Filing blobs under
//! `HMAC(key, address)` instead of `address` would hide the set while keeping
//! O(1) lookup — but it costs the property that makes the store trustworthy in
//! the first place: *the name is the hash*, so a read re-hashes and refuses
//! bytes that do not match the name they were filed under, and integrity needs
//! no second record to keep in sync. An encrypted name means an index, and an
//! index is exactly that second record. Paying for it to hide a fact any peer
//! will confirm on request is a bad trade.
//!
//! [threat-model.md](../../docs/threat-model.md) carries the residue as not
//! handled, which is where it belongs.
//!
//! # Why this is a module and not a paragraph
//!
//! A decision written only in prose decays the first time somebody adds a file.
//! [`survey`] walks a store and classifies every file as sealed, plaintext for a
//! stated reason, a key that should not be there, or **unaccounted for** — and
//! `store status` reports the last two. A new artifact written into a data
//! directory in the clear does not slip past silently: it shows up as
//! unaccounted, and whoever added it has to either seal it or put it on the list
//! above with a reason.

use std::fs;
use std::io::Read as _;
use std::path::Path;

use super::atrest;
use super::{format_size, walk, Store, StoreError, CACHE_DIR, LOG_DIR, TMP_DIR};
use crate::blobs::STORE_DIR as BLOB_DIR;
use crate::shards::store::STORE_DIR as SHARD_DIR;

/// Bytes read from the head of a file to classify it.
///
/// A page. The question is answered by the first line, and asking it of a
/// hundred-gigabyte log must not read a hundred gigabytes.
const HEAD_BYTES: usize = 4096;

/// How much of a file at-rest encryption is protecting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Exposure {
    /// Sealed: unreadable on a disk without the key.
    Sealed,
    /// Readable, and on the record as readable. The reason travels with it, so
    /// a report can say *why* rather than only *that*.
    Plaintext { reason: &'static str },
    /// A key file inside the store.
    ///
    /// The sharpest exposure there is, because it makes everything beside it
    /// readable too. [`super::mirror`] already refuses to copy one; this reports
    /// it before a mirror is ever run.
    Key,
    /// Readable and not accounted for by any decision above.
    ///
    /// The tripwire. Nothing in this crate produces one today, and a file that
    /// lands here is a file somebody added without deciding whether it should be
    /// sealed.
    Unaccounted,
}

impl Exposure {
    /// Whether this needs an operator's attention.
    pub fn is_finding(&self) -> bool {
        matches!(self, Exposure::Key | Exposure::Unaccounted)
    }
}

/// Every file in a store, classified, with byte totals.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Survey {
    /// Whether **anything** in the store is sealed.
    ///
    /// Deliberately not "is there a sealed file at [`Store::log_path`]": `--log`
    /// can put the log anywhere under the root, and a survey that only checked
    /// the default path would call an encrypting store plaintext the moment its
    /// operator moved it.
    ///
    /// A store with no key is plaintext by configuration rather than by
    /// oversight, and reporting "12 files unencrypted" at somebody who never
    /// asked for encryption is noise. When this is false every classification
    /// below is informational.
    pub sealed_log: bool,
    pub sealed_bytes: u64,
    /// Bytes readable *and accounted for* — the blobs, the cache, the scratch.
    ///
    /// Kept apart from [`Survey::finding_bytes`] rather than lumped in, because
    /// "plaintext by decision" is a claim, and a total that quietly included
    /// files nobody decided about would make that claim false in exactly the
    /// case it matters.
    pub plaintext_bytes: u64,
    /// Bytes in files nobody accounted for, plus any key found inside.
    pub finding_bytes: u64,
    /// Files needing attention, with what is wrong: keys inside the store, and
    /// anything unaccounted for.
    pub findings: Vec<(std::path::PathBuf, Exposure)>,
    /// Total files walked.
    pub files: usize,
}

impl Survey {
    /// Whether a key was found inside the store — the finding that makes every
    /// other one moot.
    pub fn holds_a_key(&self) -> bool {
        self.findings
            .iter()
            .any(|(_, what)| matches!(what, Exposure::Key))
    }

    /// A one-line summary for `store status`.
    pub fn describe(&self) -> String {
        if !self.sealed_log {
            return String::from("not encrypted (no key in use) -- run `cairn store encrypt`");
        }
        let mut line = format!(
            "log sealed ({}); {} plaintext by decision -- blobs, shards, cache, tmp",
            format_size(self.sealed_bytes),
            format_size(self.plaintext_bytes)
        );
        if !self.findings.is_empty() {
            line.push_str(&format!(
                "; {} UNACCOUNTED FOR",
                format_size(self.finding_bytes)
            ));
        }
        line
    }
}

/// Classify one path inside `store`.
///
/// `sealed_log` says whether the store is encrypting at all, because one answer
/// depends on it: a plaintext log in a store with no key is the documented
/// default, and a plaintext log in a store that *is* sealed is a conversion
/// nobody ran. [`survey`] passes `true` and relaxes afterwards, which is the
/// only way to get that right without knowing the whole walk in advance.
pub fn exposure(store: &Store, path: &Path, sealed_log: bool) -> Exposure {
    let head = read_head(path);
    let text = String::from_utf8_lossy(&head);

    // Content, not filename. Somebody who renamed their key to `notes.txt` is
    // exactly who this has to catch, and it is the same rule `mirror` applies
    // for the same reason.
    let trimmed = text.trim_start();
    if trimmed.starts_with("pwkey1:") || trimmed.starts_with("pwkey1a:") {
        return Exposure::Key;
    }
    if atrest::is_sealed_line(trimmed) {
        return Exposure::Sealed;
    }

    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    if name.ends_with(super::mirror::PLAINTEXT_BACKUP_SUFFIX) {
        return Exposure::Plaintext {
            reason: "a plaintext original left by `store encrypt`; delete it once \
                     the sealed log reads back",
        };
    }

    let Ok(relative) = path.strip_prefix(store.root()) else {
        // Outside the store entirely. Not this function's business to judge.
        return Exposure::Unaccounted;
    };
    let components: Vec<&std::ffi::OsStr> = relative
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(part) => Some(part),
            _ => None,
        })
        .collect();
    let first = components.first().map(|part| part.to_string_lossy());

    // The blob store's own path, whether it sits at the store root or under a
    // bundle root that happens to be the same directory.
    if relative.starts_with(BLOB_DIR) {
        return Exposure::Plaintext {
            reason: "pinned checker code, named by the content address the \
                     objective declares and served to any peer that asks",
        };
    }
    if relative.starts_with(SHARD_DIR) {
        return Exposure::Plaintext {
            reason: "erasure-coded shards of a blob the network publishes, filed \
                     under that blob's digest; k of them are the blob",
        };
    }

    match first.as_deref() {
        Some(CACHE_DIR) => Exposure::Plaintext {
            reason: "a local copy of something fetchable; losing it costs \
                     bandwidth, never data",
        },
        Some(TMP_DIR) => Exposure::Plaintext {
            reason: "scratch, safe to drop at any time",
        },
        Some(LOG_DIR) if !sealed_log => Exposure::Plaintext {
            reason: "the log, in a store with no key in use",
        },
        // A plaintext file under `log/` in a store that *is* sealed. Not a
        // decision anybody made -- a conversion that did not finish, or a
        // second log dropped in beside the first.
        Some(LOG_DIR) => Exposure::Unaccounted,
        _ => Exposure::Unaccounted,
    }
}

/// Walk `store` and classify everything in it.
///
/// "Is this store encrypting?" is answered by **whether anything in it is
/// sealed**, not by whether a file exists at [`Store::log_path`]. `--log` and
/// `$CAIRN_LOG` can put the log anywhere under the root, and a survey that
/// only looked at the default path would report an encrypting store as plaintext
/// the moment its operator moved the log — which is both wrong and precisely
/// backwards, since it would go quiet exactly where it should speak up.
///
/// The consequence is that classification happens under the strict reading
/// first, and the unaccounted findings are dropped afterwards if it turns out
/// nothing here was sealed at all. Key findings survive that: a key file is
/// worth reporting wherever it is, because the log it opens may live somewhere
/// this walk never reached.
pub fn survey(store: &Store) -> Result<Survey, StoreError> {
    // Classified under the strict reading first, then totalled -- because
    // whether an unaccounted file is a finding depends on something only the
    // whole walk can answer.
    let mut classified = Vec::new();
    let mut anything_sealed = false;
    for file in walk(store, store.root())? {
        let exposure = exposure(store, &file.path, true);
        anything_sealed |= exposure == Exposure::Sealed;
        classified.push((file.path, file.bytes, exposure));
    }

    let mut report = Survey {
        sealed_log: anything_sealed,
        files: classified.len(),
        ..Survey::default()
    };
    for (path, bytes, exposure) in classified {
        // Nothing here is sealed, so nothing here is an omission: an operator
        // who never ran `keygen` is not misconfigured, and telling them twelve
        // files are unencrypted is how a report becomes noise nobody reads. A
        // key still counts, wherever it is -- the log it opens may live
        // somewhere this walk never reached.
        let exposure = match exposure {
            Exposure::Unaccounted if !anything_sealed => Exposure::Plaintext {
                reason: "a store with no key in use is plaintext throughout",
            },
            other => other,
        };
        match &exposure {
            Exposure::Sealed => report.sealed_bytes = report.sealed_bytes.saturating_add(bytes),
            Exposure::Plaintext { .. } => {
                report.plaintext_bytes = report.plaintext_bytes.saturating_add(bytes)
            }
            Exposure::Key | Exposure::Unaccounted => {
                report.finding_bytes = report.finding_bytes.saturating_add(bytes)
            }
        }
        if exposure.is_finding() {
            report.findings.push((path, exposure));
        }
    }
    Ok(report)
}

/// The first [`HEAD_BYTES`] of a file, or empty if it cannot be read.
fn read_head(path: &Path) -> Vec<u8> {
    let Ok(mut handle) = fs::File::open(path) else {
        return Vec::new();
    };
    let mut buffer = vec![0u8; HEAD_BYTES];
    match handle.read(&mut buffer) {
        Ok(read) => {
            buffer.truncate(read);
            buffer
        }
        Err(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn scratch(tag: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "cairn-exposure-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&path).expect("scratch dir");
        path
    }

    /// A store shaped like a working node's: a sealed log, a blob, a coded
    /// blob's manifest and one of its shards, a cached file, and scratch.
    fn populated(tag: &str) -> (PathBuf, Store) {
        let dir = scratch(tag);
        let store = Store::new(&dir);
        store.prepare().expect("prepares");
        fs::write(store.log_path(), "pwenc1:00112233445566778899aabb:ff\n").expect("log");
        fs::write(store.cache_dir().join("peer-list.json"), b"[]").expect("cache");
        fs::write(store.tmp_dir().join("partial"), b"x").expect("tmp");
        let blobs = dir.join(BLOB_DIR);
        fs::create_dir_all(&blobs).expect("blobs");
        fs::write(blobs.join("ab".repeat(32)), b"def check(a): pass\n").expect("blob");
        let shards = dir.join(SHARD_DIR).join("cd".repeat(32));
        fs::create_dir_all(&shards).expect("shards");
        fs::write(shards.join("manifest"), b"{\"total\":4}\n").expect("manifest");
        fs::write(shards.join("001"), b"\x00\x01\x02\x03").expect("shard");
        (dir, store)
    }

    #[test]
    fn a_working_store_has_nothing_unaccounted_for() {
        // The tripwire, in its resting state. Every file a node writes today is
        // either sealed or on the list with a reason.
        let (dir, store) = populated("resting");
        let report = survey(&store).expect("surveys");
        assert!(report.sealed_log);
        assert_eq!(
            report.findings,
            Vec::new(),
            "an unaccounted file in a store this crate itself produced"
        );
        assert_eq!(report.files, 6);
        assert!(report.sealed_bytes > 0 && report.plaintext_bytes > 0);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_new_plaintext_artifact_trips_it() {
        // And the tripwire fires. This is the case the module exists for: a
        // future feature writing state into the data directory in the clear,
        // with nobody having decided that is right.
        let (dir, store) = populated("tripwire");
        let novel = dir.join("inference-receipts.json");
        fs::write(&novel, b"{\"receipts\":[]}").expect("writes");

        let report = survey(&store).expect("surveys");
        assert_eq!(
            report.findings,
            vec![(novel, Exposure::Unaccounted)],
            "a new plaintext artifact slipped past the survey"
        );
        // And its bytes are not counted as "plaintext by decision", which would
        // make that phrase false in exactly the case it matters.
        assert_eq!(report.finding_bytes, 15);
        assert!(report.describe().contains("UNACCOUNTED"));
        assert!(!report.holds_a_key());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_key_inside_the_store_is_the_sharpest_finding_and_is_found_by_content() {
        // Renaming it must not help: a key beside its ciphertext makes
        // everything beside it readable, which is the failure the whole scheme
        // turns on.
        let (dir, store) = populated("key");
        let disguised = dir.join("cache/notes.txt");
        fs::write(&disguised, format!("pwkey1:{}\n", "ab".repeat(32))).expect("writes");

        let report = survey(&store).expect("surveys");
        assert_eq!(report.findings, vec![(disguised, Exposure::Key)]);
        assert!(report.holds_a_key());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_documented_plaintext_each_carries_its_own_reason() {
        // A report that can only say *that* a file is readable sends an
        // operator looking for a problem. Saying *why* is what makes the
        // asymmetry a decision they can check rather than an alarm.
        let (dir, store) = populated("reasons");
        let reason_for = |path: PathBuf| match exposure(&store, &path, true) {
            Exposure::Plaintext { reason } => reason.to_string(),
            other => panic!("{} classified {other:?}", path.display()),
        };
        assert!(reason_for(store.cache_dir().join("peer-list.json")).contains("fetchable"));
        assert!(reason_for(store.tmp_dir().join("partial")).contains("scratch"));
        assert!(reason_for(dir.join(BLOB_DIR).join("ab".repeat(32))).contains("any peer that asks"));
        let shard = dir.join(SHARD_DIR).join("cd".repeat(32)).join("001");
        assert!(reason_for(shard).contains("k of them are the blob"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_log_moved_off_the_default_path_is_still_recognised_as_sealed() {
        // `--log` and `$CAIRN_LOG` put the log wherever the operator wants.
        // A survey that asked only about `<root>/log/cairn.jsonl` would call
        // an encrypting store plaintext the moment they moved it -- going quiet
        // exactly where it should speak up.
        let dir = scratch("moved");
        let store = Store::new(&dir);
        store.prepare().expect("prepares");
        fs::write(
            dir.join("elsewhere.jsonl"),
            "pwenc1:001122334455667788990011:ff\n",
        )
        .expect("log");

        let report = survey(&store).expect("surveys");
        assert!(
            report.sealed_log,
            "a moved sealed log was read as plaintext"
        );
        assert_eq!(report.findings, Vec::new());
        assert!(report.sealed_bytes > 0);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_unencrypted_store_is_reported_as_a_choice_rather_than_a_finding() {
        // Somebody who never ran `keygen` is not misconfigured, and telling
        // them their store is unencrypted in the language of a finding is how a
        // report becomes noise nobody reads.
        let dir = scratch("plain");
        let store = Store::new(&dir);
        store.prepare().expect("prepares");
        fs::write(store.log_path(), "{\"seq\":0}\n").expect("log");

        let report = survey(&store).expect("surveys");
        assert!(!report.sealed_log);
        assert_eq!(report.findings, Vec::new());
        assert!(report.describe().contains("store encrypt"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_plaintext_backup_is_named_as_the_leftover_it_is() {
        let (dir, store) = populated("leftover");
        let leftover = PathBuf::from(format!(
            "{}{}",
            store.log_path().display(),
            super::super::mirror::PLAINTEXT_BACKUP_SUFFIX
        ));
        fs::write(&leftover, "{\"seq\":0}\n").expect("writes");

        let report = survey(&store).expect("surveys");
        assert_eq!(
            report.findings,
            Vec::new(),
            "a known leftover is not a finding"
        );
        assert!(matches!(
            exposure(&store, &leftover, true),
            Exposure::Plaintext { reason } if reason.contains("store encrypt")
        ));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_plaintext_log_in_a_sealed_store_is_unaccounted_for() {
        // A conversion that did not finish, or a second log dropped in beside
        // the first. Either way nobody decided it, so it is not on the list.
        let (dir, store) = populated("halfconverted");
        let stray = store.log_path().with_file_name("other.jsonl");
        fs::write(&stray, "{\"seq\":0}\n").expect("writes");

        let report = survey(&store).expect("surveys");
        assert_eq!(report.findings, vec![(stray, Exposure::Unaccounted)]);
        fs::remove_dir_all(&dir).ok();
    }
}
