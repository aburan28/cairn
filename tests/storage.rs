//! End-to-end tests for the local store: encryption at rest, a chosen data
//! directory, a size cap, and an encrypted mirror.
//!
//! These go through the public API only, and every one of them is a promise the
//! docs make. The three that matter most are negative: the log is never evicted
//! to fit a cap, the key is never mirrored beside its ciphertext, and a plaintext
//! backup is never carried to a destination that exists because the data was
//! supposed to be encrypted.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use proofwork::canonical::Value;
use proofwork::ledger::{Codec, Ledger, LedgerError};
use proofwork::store::atrest::{AtRestError, Cipher};
use proofwork::store::{format_size, mirror, parse_size, quota, Store, StoreError};

fn scratch(tag: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut path = std::env::temp_dir();
    path.push(format!(
        "proofwork-storage-{}-{nanos}-{n}-{tag}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("create scratch dir");
    path
}

fn note(i: i128) -> Value {
    Value::object([("i", Value::Int(i))])
}

fn sealed(cipher: &Path) -> Codec {
    Codec::Sealed(Box::new(
        Cipher::read_key_file(cipher, None).expect("reads the key"),
    ))
}

// ---------------------------------------------------------------------------
// Encryption at rest
// ---------------------------------------------------------------------------

#[test]
fn a_node_can_be_run_entirely_out_of_a_directory_of_its_operators_choosing() {
    let dir = scratch("chosen");
    let store = Store::new(dir.join("somewhere/else/entirely"));
    store.prepare().expect("prepares");

    let key = dir.join("key-kept-elsewhere");
    Cipher::generate(&mut rand_core::OsRng)
        .write_key_file(&key, None, &mut rand_core::OsRng)
        .expect("writes a key");

    let mut ledger = Ledger::open_with(store.log_path(), sealed(&key)).expect("opens");
    for i in 0..10 {
        ledger.append("note", note(i), "t").expect("appends");
    }
    let root = ledger.root();
    drop(ledger);

    // Everything is under the chosen root and nowhere else.
    assert!(store.log_path().starts_with(store.root()));
    let reopened = Ledger::open_with(store.log_path(), sealed(&key)).expect("reopens");
    assert_eq!(reopened.len(), 10);
    assert_eq!(reopened.root(), root);
    assert!(reopened.verify_chain().is_empty());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn nothing_readable_is_left_on_disk_and_the_key_is_what_makes_it_readable() {
    let dir = scratch("atrest");
    let store = Store::new(dir.join("data"));
    store.prepare().expect("prepares");
    let key = dir.join("key");
    Cipher::generate(&mut rand_core::OsRng)
        .write_key_file(&key, None, &mut rand_core::OsRng)
        .expect("writes a key");

    let mut ledger = Ledger::open_with(store.log_path(), sealed(&key)).expect("opens");
    ledger
        .append(
            "claim",
            Value::object([("artifact", Value::string("the-secret-answer"))]),
            "t",
        )
        .expect("appends");
    drop(ledger);

    let raw = fs::read_to_string(store.log_path()).expect("read");
    assert!(!raw.contains("the-secret-answer"));
    assert!(!raw.contains("claim"));

    // Without the key the log is unreadable, and the error says why rather than
    // reporting the file as damaged.
    let error = Ledger::open(store.log_path()).expect_err("needs the key");
    assert!(matches!(error, LedgerError::Sealed { .. }), "{error:?}");

    // With it, everything is exactly as it was written.
    let opened = Ledger::open_with(store.log_path(), sealed(&key)).expect("reopens");
    assert_eq!(opened.entries()[0].kind, "claim");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_passphrase_wrapped_key_gates_the_whole_store() {
    let dir = scratch("passphrase");
    let store = Store::new(dir.join("data"));
    store.prepare().expect("prepares");
    let key = dir.join("key");
    Cipher::generate(&mut rand_core::OsRng)
        .write_key_file(&key, Some("a long passphrase"), &mut rand_core::OsRng)
        .expect("writes a wrapped key");

    assert!(Cipher::key_file_is_wrapped(&key).expect("reads"));
    assert_eq!(
        Cipher::read_key_file(&key, Some("not it")).expect_err("wrong"),
        AtRestError::Passphrase { path: key.clone() }
    );

    let cipher = Cipher::read_key_file(&key, Some("a long passphrase")).expect("opens");
    let mut ledger =
        Ledger::open_with(store.log_path(), Codec::Sealed(Box::new(cipher))).expect("opens");
    ledger.append("note", note(1), "t").expect("appends");
    assert!(ledger.is_sealed());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn encryption_changes_no_hash_no_root_and_no_audit_result() {
    // The property that keeps at-rest encryption a local decision. Two nodes
    // holding the same records agree on every id whether or not either of them
    // encrypted its disk -- so an operator can turn this on without becoming
    // undiffable against the rest of the network.
    let dir = scratch("invariant");
    let key = dir.join("key");
    Cipher::generate(&mut rand_core::OsRng)
        .write_key_file(&key, None, &mut rand_core::OsRng)
        .expect("writes a key");

    let plain_path = dir.join("plain.jsonl");
    let sealed_path = dir.join("sealed.jsonl");
    let mut plain = Ledger::open(&plain_path).expect("opens");
    let mut cipher = Ledger::open_with(&sealed_path, sealed(&key)).expect("opens");
    for i in 0..6 {
        plain.append("note", note(i), "t").expect("appends");
        cipher.append("note", note(i), "t").expect("appends");
    }

    assert_eq!(plain.root(), cipher.root());
    assert_eq!(plain.head(), cipher.head());
    assert_eq!(plain.entries(), cipher.entries());
    assert!(plain.verify_chain().is_empty());
    assert!(cipher.verify_chain().is_empty());
    let _ = fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// The size cap
// ---------------------------------------------------------------------------

#[test]
fn a_cap_evicts_cached_content_and_never_the_log() {
    let dir = scratch("cap");
    let store = Store::new(dir.join("data"));
    store.prepare().expect("prepares");
    fs::write(store.log_path(), vec![b'l'; 4096]).expect("write log");
    for index in 0..4 {
        fs::write(
            store.cache_dir().join(format!("blob-{index}")),
            vec![b'c'; 4096],
        )
        .expect("write cache");
    }

    let capped = store.clone().with_limit(Some(8192));
    let eviction = quota::reclaim(&capped, 0).expect("reclaims");
    assert!(!eviction.is_empty());
    assert!(eviction.after.total() <= 8192);
    assert_eq!(eviction.after.pinned, 4096, "the log is untouched");
    assert!(store.log_path().exists());
    // And every eviction is named, because each one is a challenge that will
    // now fail.
    for (path, _) in &eviction.removed {
        assert!(!path.exists());
        assert!(path.starts_with(store.cache_dir()));
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_cap_smaller_than_the_log_stops_the_node_rather_than_pruning_it() {
    // The single most important behaviour in this module. An operator who sets
    // a 1 GB cap on a 2 GB log has made a mistake; deleting half their
    // hash-linked log to honour it would turn that mistake into data loss.
    let dir = scratch("refuse");
    let store = Store::new(dir.join("data"));
    store.prepare().expect("prepares");
    fs::write(store.log_path(), vec![b'l'; 8192]).expect("write log");
    fs::write(store.cache_dir().join("blob"), vec![b'c'; 1024]).expect("write cache");

    let capped = store.clone().with_limit(Some(4096));
    let error = quota::reclaim(&capped, 0).expect_err("cannot fit");
    match error {
        StoreError::QuotaExceeded { pinned, limit } => {
            assert_eq!(pinned, 8192);
            assert_eq!(limit, 4096);
        }
        other => panic!("expected QuotaExceeded, got {other:?}"),
    }
    // Nothing was deleted on the way to that conclusion -- not even the cache.
    assert!(store.log_path().exists());
    assert!(store.cache_dir().join("blob").exists());
    assert_eq!(
        fs::metadata(store.log_path()).expect("stat").len(),
        8192,
        "the log was truncated"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn the_cap_is_enforced_against_what_is_about_to_be_written() {
    let dir = scratch("incoming");
    let store = Store::new(dir.join("data"));
    store.prepare().expect("prepares");
    fs::write(store.log_path(), vec![b'l'; 1024]).expect("write log");
    fs::write(store.cache_dir().join("blob"), vec![b'c'; 4096]).expect("write cache");

    let capped = store.with_limit(Some(6144));
    // Already under the cap at 5 KiB, but not with 2 KiB more coming.
    let eviction = quota::reclaim(&capped, 2048).expect("reclaims");
    assert!(!eviction.is_empty());
    assert!(eviction.after.total() + 2048 <= 6144);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn sizes_are_written_in_the_unit_the_operator_meant() {
    assert_eq!(parse_size("20GB").expect("size"), 20_000_000_000);
    assert_eq!(parse_size("20GiB").expect("size"), 21_474_836_480);
    assert!(parse_size("20 gigabytes").is_err());
    assert_eq!(format_size(21_474_836_480), "20.0 GiB");
}

// ---------------------------------------------------------------------------
// The mirror
// ---------------------------------------------------------------------------

#[test]
fn a_mirror_is_ciphertext_and_the_key_never_travels_with_it() {
    // The property the whole feature turns on. Encryption at rest buys exactly
    // one thing -- copies that leave the machine are inert -- and copying the
    // key beside them gives it straight back.
    let dir = scratch("mirror");
    let store = Store::new(dir.join("data"));
    store.prepare().expect("prepares");

    // Deliberately the unsafe layout: key inside the store.
    let key = store.root().join("key");
    Cipher::generate(&mut rand_core::OsRng)
        .write_key_file(&key, None, &mut rand_core::OsRng)
        .expect("writes a key");

    let mut ledger = Ledger::open_with(store.log_path(), sealed(&key)).expect("opens");
    ledger
        .append(
            "claim",
            Value::object([("artifact", Value::string("still-a-secret"))]),
            "t",
        )
        .expect("appends");
    drop(ledger);

    let destination = dir.join("backup");
    let report = mirror::mirror(&store, &destination, mirror::Options::default()).expect("mirrors");

    assert_eq!(report.skipped_keys, vec![key]);
    assert!(!destination.join("key").exists(), "the key was mirrored");
    let copied = fs::read_to_string(destination.join("log/proofwork.jsonl")).expect("read");
    assert!(copied.starts_with("pwenc1:"));
    assert!(!copied.contains("still-a-secret"));
    assert!(report.summary().contains("NOT copied"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_mirror_restores_into_a_working_node() {
    // The point of a backup: the copy has to be usable, with the key that was
    // deliberately kept somewhere else.
    let dir = scratch("restore");
    let store = Store::new(dir.join("data"));
    store.prepare().expect("prepares");
    let key = dir.join("key-elsewhere");
    Cipher::generate(&mut rand_core::OsRng)
        .write_key_file(&key, None, &mut rand_core::OsRng)
        .expect("writes a key");

    let mut ledger = Ledger::open_with(store.log_path(), sealed(&key)).expect("opens");
    for i in 0..5 {
        ledger.append("note", note(i), "t").expect("appends");
    }
    let root = ledger.root();
    drop(ledger);

    let destination = dir.join("backup");
    mirror::mirror(&store, &destination, mirror::Options::default()).expect("mirrors");

    let restored = Store::new(&destination);
    let reopened = Ledger::open_with(restored.log_path(), sealed(&key)).expect("opens the copy");
    assert_eq!(reopened.len(), 5);
    assert_eq!(reopened.root(), root);
    assert!(reopened.verify_chain().is_empty());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_mirror_is_idempotent_and_resumable() {
    let dir = scratch("resume");
    let store = Store::new(dir.join("data"));
    store.prepare().expect("prepares");
    fs::write(store.log_path(), "pwenc1:00:11\n").expect("write");
    for index in 0..5 {
        fs::write(store.cache_dir().join(format!("blob-{index}")), "x").expect("write");
    }
    let destination = dir.join("backup");

    let first = mirror::mirror(&store, &destination, mirror::Options::default()).expect("mirrors");
    assert_eq!(first.copied.len(), 6);
    let second = mirror::mirror(&store, &destination, mirror::Options::default()).expect("again");
    assert!(second.copied.is_empty());
    assert_eq!(second.unchanged, 6);

    // Interrupted halfway: remove two from the destination and re-run.
    fs::remove_file(destination.join("cache/blob-0")).expect("remove");
    fs::remove_file(destination.join("cache/blob-1")).expect("remove");
    let third = mirror::mirror(&store, &destination, mirror::Options::default()).expect("resumes");
    assert_eq!(third.copied.len(), 2);
    assert_eq!(third.unchanged, 4);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_mirror_never_deletes_at_the_destination_unless_asked() {
    let dir = scratch("prune");
    let store = Store::new(dir.join("data"));
    store.prepare().expect("prepares");
    fs::write(store.log_path(), "pwenc1:00:11\n").expect("write");
    let destination = dir.join("backup");
    mirror::mirror(&store, &destination, mirror::Options::default()).expect("mirrors");

    let precious = destination.join("cache/something-else");
    fs::create_dir_all(destination.join("cache")).expect("mkdir");
    fs::write(&precious, "not from this store").expect("write");

    let default_run =
        mirror::mirror(&store, &destination, mirror::Options::default()).expect("mirrors");
    assert!(default_run.pruned.is_empty());
    assert!(precious.exists(), "a default run deleted something");

    let pruned = mirror::mirror(
        &store,
        &destination,
        mirror::Options {
            prune: true,
            ..mirror::Options::default()
        },
    )
    .expect("prunes");
    assert_eq!(pruned.pruned, vec![precious.clone()]);
    assert!(!precious.exists());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn mirroring_a_store_that_was_never_encrypted_says_so() {
    let dir = scratch("warn");
    let store = Store::new(dir.join("data"));
    store.prepare().expect("prepares");
    let mut ledger = Ledger::open(store.log_path()).expect("opens");
    ledger.append("note", note(0), "t").expect("appends");
    drop(ledger);

    let destination = dir.join("backup");
    let report = mirror::mirror(&store, &destination, mirror::Options::default()).expect("mirrors");
    assert!(report.plaintext);
    assert!(report.summary().contains("NOT encrypted"));
    // Copied anyway: it is the operator's call, and refusing would push them
    // towards `cp -r`, which has no opinion at all.
    assert!(destination.join("log/proofwork.jsonl").exists());
    let _ = fs::remove_dir_all(&dir);
}
