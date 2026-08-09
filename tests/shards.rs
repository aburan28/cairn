//! End-to-end tests for erasure-coded shards.
//!
//! Through the public API only, and against the scenario the module exists for
//! rather than against its parts: several nodes each holding a slice of one
//! blob, some of them lying, and a reader with nothing but a root.
//!
//! The negative ones are the point. A liar is named rather than allowed to
//! smear one bad byte across every output byte; a proof for the wrong chunk
//! does not check; and a store that has fewer than `k` shards says so instead
//! of returning something plausible.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use proofwork::blobs::{address, BlobStore};
use proofwork::canonical::{digest_bytes, Value};
use proofwork::shards::{
    encode, reconstruct, Coding, Manifest, Shard, ShardError, ShardStore, ShardStoreError,
    DEFAULT_CHUNK_LEN, MIN_CHUNK_LEN,
};

fn scratch(tag: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut path = std::env::temp_dir();
    path.push(format!(
        "proofwork-shards-{}-{nanos}-{n}-{tag}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("create scratch dir");
    path
}

/// Deterministic pseudo-random bytes. Not zeros: a bug that silently drops a
/// shard is invisible against zeros, because a dropped shard *is* zeros.
fn bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

fn coding(data: u8, parity: u8) -> Coding {
    Coding::new(data, parity).expect("valid coding")
}

// ---------------------------------------------------------------------------
// The scenario the module exists for
// ---------------------------------------------------------------------------

#[test]
fn six_holders_of_one_blob_survive_two_of_them_going_away() {
    // (4, 2) over six machines, each holding one shard: 1.5x the blob across
    // the whole network, against the 3x replication would charge for the same
    // two tolerated losses.
    let dir = scratch("six-holders");
    let blob = bytes(300_000, 7);
    let at = address(&blob);
    let encoded = encode(&blob, coding(4, 2), MIN_CHUNK_LEN).expect("encode");

    let holders: Vec<ShardStore> = (0..6)
        .map(|index| {
            let store = ShardStore::at(dir.join(format!("node-{index}")));
            store
                .put_manifest(&at, &encoded.manifest)
                .expect("manifest");
            let shard = encoded.shards.get(index).expect("shard");
            store.put_shard(&at, shard).expect("shard");
            store
        })
        .collect();

    // Each machine holds a sixth of the blob and knows it cannot rebuild it.
    for store in &holders {
        assert_eq!(store.held(&at).len(), 1);
        assert!(matches!(
            store.reconstruct(&at),
            Err(ShardStoreError::Shards(ShardError::NotEnoughShards {
                have: 1,
                ..
            }))
        ));
    }

    // Two machines burn down. A reader collects from the remaining four.
    let collected: Vec<Shard> = holders
        .iter()
        .skip(2)
        .map(|store| {
            let index = *store.held(&at).first().expect("one shard");
            store.shard(&at, index).expect("reads")
        })
        .collect();
    let out = reconstruct(&encoded.manifest, &collected).expect("four is enough");
    assert_eq!(out.data, blob);
    assert_eq!(out.used, vec![2, 3, 4, 5]);
    assert!(out.rejected.is_empty());

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_lying_holder_is_named_and_the_blob_still_comes_back() {
    // The argument for having per-chunk commitments at all. Without the check,
    // this shard enters the linear combination and every output byte is wrong,
    // with the blob digest able to report only that *somebody* lied.
    let blob = bytes(200_000, 11);
    let encoded = encode(&blob, coding(4, 3), MIN_CHUNK_LEN).expect("encode");

    let mut offered = encoded.shards.clone();
    // Two liars, and a parity shard among them so the failure is not a data
    // shard's plain byte range. One byte each, in the middle of a chunk: the
    // subtlest version, and the one a length check would miss.
    for (index, at) in [(0usize, 40_usize), (5, 9_001)] {
        let shard = offered.get_mut(index).expect("shard");
        let byte = shard.bytes.get_mut(at).expect("in range");
        *byte ^= 0x01;
    }

    let out = reconstruct(&encoded.manifest, &offered).expect("five honest shards remain");
    assert_eq!(out.data, blob, "a liar reached the output");
    assert_eq!(out.rejected, vec![0, 5], "and was not named");
    for liar in &out.rejected {
        assert!(!out.used.contains(liar));
    }
}

#[test]
fn more_liars_than_parity_is_a_refusal_that_names_all_of_them() {
    // The honest failure. Four of seven shards are corrupt at (4, 3), so there
    // is no honest subset left -- and the answer is a refusal listing every
    // holder that lied, not a plausible byte string.
    let blob = bytes(100_000, 13);
    let encoded = encode(&blob, coding(4, 3), MIN_CHUNK_LEN).expect("encode");
    let mut offered = encoded.shards.clone();
    for index in [1usize, 2, 4, 6] {
        let shard = offered.get_mut(index).expect("shard");
        let byte = shard.bytes.get_mut(17).expect("in range");
        *byte ^= 0xff;
    }
    assert_eq!(
        reconstruct(&encoded.manifest, &offered).unwrap_err(),
        ShardError::NotEnoughShards {
            have: 3,
            need: 4,
            rejected: vec![1, 2, 4, 6]
        }
    );
}

#[test]
fn every_erasure_pattern_of_a_ten_of_fourteen_code_reconstructs() {
    // MDS is a claim about every subset, so a wide code is checked against
    // every pattern of `m` losses rather than a few. C(14, 4) = 1001.
    //
    // Small on purpose: a thousand decodes is the point and a thousand *large*
    // decodes is a test nobody runs. The shard length is what varies the
    // arithmetic, not the pattern, and the sizes are covered elsewhere.
    let blob = bytes(9_000, 17);
    let code = coding(10, 4);
    let encoded = encode(&blob, code, MIN_CHUNK_LEN).expect("encode");

    let mut patterns = 0;
    for a in 0..14u8 {
        for b in (a + 1)..14 {
            for c in (b + 1)..14 {
                for d in (c + 1)..14 {
                    let lost = [a, b, c, d];
                    let kept: Vec<Shard> = encoded
                        .shards
                        .iter()
                        .filter(|shard| !lost.contains(&shard.index))
                        .cloned()
                        .collect();
                    let out = reconstruct(&encoded.manifest, &kept)
                        .unwrap_or_else(|error| panic!("losing {lost:?}: {error}"));
                    assert_eq!(out.data, blob, "losing {lost:?}");
                    patterns += 1;
                }
            }
        }
    }
    assert_eq!(patterns, 1001);
}

// ---------------------------------------------------------------------------
// Proofs, and the reader who holds only a root
// ---------------------------------------------------------------------------

#[test]
fn a_holder_proves_one_chunk_to_a_reader_who_has_nothing_but_a_root() {
    let dir = scratch("one-root");
    let blob = bytes(150_000, 19);
    let at = address(&blob);
    let encoded = encode(&blob, coding(3, 2), MIN_CHUNK_LEN).expect("encode");

    let holder = ShardStore::at(dir.join("holder"));
    holder
        .put_manifest(&at, &encoded.manifest)
        .expect("manifest");
    let mine = encoded.shards.get(4).cloned().expect("shard 4");
    holder.put_shard(&at, &mine).expect("shard");

    // Everything the reader has. Not the manifest, not the blob, not the
    // shard: thirty-two bytes.
    let root = encoded.manifest.root();

    let held = holder.shard(&at, 4).expect("reads");
    for chunk in 0..encoded.manifest.layout().chunks() {
        let proof = encoded
            .manifest
            .prove_chunk(&held, chunk)
            .expect("in range");
        // Over the wire, and back, because a proof nobody can write down is
        // not a proof anybody can be sent.
        let wire = proof.to_value().canonical_string();
        let decoded = proofwork::shards::ChunkProof::from_value(
            &Value::from_json(&wire).expect("canonical JSON"),
        )
        .expect("decodes");
        assert!(decoded.verify(&root), "chunk {chunk}");
        // The holder's own manifest can say more: the geometry as well as the
        // membership.
        assert!(encoded.manifest.verify_chunk(&decoded), "chunk {chunk}");
    }

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_proof_does_not_travel_to_another_chunk_shard_or_blob() {
    let blob = bytes(80_000, 23);
    let encoded = encode(&blob, coding(2, 2), MIN_CHUNK_LEN).expect("encode");
    let manifest = &encoded.manifest;
    let root = manifest.root();
    let shard = encoded.shards.first().expect("shard 0");
    let proof = manifest.prove_chunk(shard, 2).expect("in range");
    assert!(proof.verify(&root));

    // Another blob's root.
    let other = encode(&bytes(80_000, 29), coding(2, 2), MIN_CHUNK_LEN).expect("encode");
    assert!(!proof.verify(&other.manifest.root()));
    assert!(!other.manifest.verify_chunk(&proof));

    // Real bytes from a different chunk of the same shard, under this path.
    let mut moved = proof.clone();
    moved.bytes = manifest
        .layout()
        .slice(&shard.bytes, 3)
        .expect("chunk 3")
        .to_vec();
    assert!(!moved.verify(&root));

    // A different shard's real proof, relabelled.
    let mut relabelled = manifest
        .prove_chunk(encoded.shards.get(1).expect("shard 1"), 2)
        .expect("in range");
    relabelled.shard = 0;
    assert!(!relabelled.verify(&root));

    // And a root that is merely a digest.
    assert!(!proof.verify(&digest_bytes(b"not a manifest root")));
}

// ---------------------------------------------------------------------------
// Against the rest of the crate
// ---------------------------------------------------------------------------

#[test]
fn a_manifest_is_checked_against_the_digest_an_objective_already_pins() {
    // What makes a manifest safe to accept from a stranger: it is not signed
    // and proves nothing on its own, so the only question worth asking is
    // whether it describes a blob the log already committed to.
    let dir = scratch("pinned");
    let code = b"def check(artifact):\n    return artifact[\"ok\"] is True\n";
    let pin = address(code); // the bare spelling `checker_sha256` uses

    let blobs = BlobStore::at(dir.join("blobs"));
    blobs.put(&pin, code).expect("stores the pinned checker");

    let encoded = encode(code, coding(2, 1), MIN_CHUNK_LEN).expect("encode");
    assert!(encoded.manifest.describes(&pin));
    assert!(encoded.manifest.describes(&format!("sha256:{pin}"))); // and the prefixed spelling

    // A manifest for anything else is refused by the same question, and by the
    // store, which will not file it under a digest it does not describe.
    let elsewhere = encode(b"something else", coding(2, 1), MIN_CHUNK_LEN).expect("encode");
    assert!(!elsewhere.manifest.describes(&pin));
    let shards = ShardStore::at(dir.join("shards"));
    assert!(matches!(
        shards.put_manifest(&pin, &elsewhere.manifest),
        Err(ShardStoreError::Mismatched { .. })
    ));

    // And the real one round-trips back to bytes identical to the blob store's.
    shards
        .put_all(&pin, &encoded.manifest, &encoded.shards)
        .expect("stores");
    assert_eq!(
        shards.reconstruct(&pin).expect("rebuilds").data,
        blobs.read(&pin).expect("reads")
    );

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_shard_directory_is_accounted_for_by_the_exposure_survey() {
    // `store::exposure` is a tripwire: anything a node writes into a data
    // directory in the clear has to be either sealed or on the list with a
    // reason. Shards are on the list, and this is what keeps that true.
    use proofwork::store::{exposure, Store};

    let dir = scratch("exposure");
    let store = Store::new(&dir);
    store.prepare().expect("prepares");
    fs::write(store.log_path(), "pwenc1:00112233445566778899aabb:ff\n").expect("sealed log");

    let blob = bytes(20_000, 31);
    let at = address(&blob);
    let encoded = encode(&blob, coding(2, 1), MIN_CHUNK_LEN).expect("encode");
    ShardStore::under(&dir)
        .put_all(&at, &encoded.manifest, &encoded.shards)
        .expect("stores");

    let report = exposure::survey(&store).expect("surveys");
    assert!(report.sealed_log);
    assert_eq!(
        report.findings,
        Vec::new(),
        "a shard store tripped the unaccounted-for check"
    );
    assert!(report.plaintext_bytes > 0);
    assert!(report.describe().contains("shards"));

    fs::remove_dir_all(&dir).ok();
}

// ---------------------------------------------------------------------------
// Shapes and refusals
// ---------------------------------------------------------------------------

#[test]
fn a_blob_of_any_size_round_trips_under_a_range_of_codings() {
    for (data, parity) in [(1u8, 1u8), (2, 3), (5, 2), (16, 4)] {
        let code = coding(data, parity);
        for (len, seed) in [(0usize, 1u64), (1, 2), (999, 3), (65_537, 4)] {
            let blob = bytes(len, seed);
            let encoded = encode(&blob, code, DEFAULT_CHUNK_LEN).expect("encode");
            assert_eq!(encoded.shards.len(), usize::from(code.shards()));
            // Every shard the same length, so one chunk geometry serves all.
            let shard_len = encoded.manifest.layout().shard_len();
            for shard in &encoded.shards {
                assert_eq!(shard.bytes.len() as u64, shard_len);
                assert!(encoded.manifest.verify_shard(shard));
            }
            // Keep the last `data` shards: the systematic path is not
            // available, so this is the one that has to invert a matrix.
            let kept: Vec<Shard> = encoded
                .shards
                .iter()
                .skip(usize::from(parity))
                .cloned()
                .collect();
            let out = reconstruct(&encoded.manifest, &kept)
                .unwrap_or_else(|error| panic!("({data},{parity}) at {len}: {error}"));
            assert_eq!(out.data, blob, "({data},{parity}) at {len} bytes");
        }
    }
}

#[test]
fn a_manifest_that_lies_about_the_blob_makes_the_reconstruction_fail_loudly() {
    // The last check in `reconstruct` is redundant against hostile shards --
    // every one was verified first -- and is kept because it is not redundant
    // against a bug in the linear algebra, which produces plausible bytes
    // rather than an error. This is the only way to reach it from outside.
    let blob = bytes(50_000, 37);
    let encoded = encode(&blob, coding(3, 2), MIN_CHUNK_LEN).expect("encode");
    let lying = Manifest::new(
        digest_bytes(b"a different blob entirely"),
        encoded.manifest.layout().total(),
        coding(3, 2),
        MIN_CHUNK_LEN,
        encoded.manifest.roots().to_vec(),
    )
    .expect("the shape is fine; the claim is not");
    assert!(matches!(
        reconstruct(&lying, &encoded.shards),
        Err(ShardError::DigestMismatch { .. })
    ));
}

#[test]
fn a_coding_that_tolerates_nothing_is_refused_rather_than_quietly_accepted() {
    // (k, 0) is plain striping. It looks exactly like a code that tolerates a
    // loss and tolerates none, so an operator who asked for erasure coding and
    // got this would find out when a disk died.
    assert_eq!(Coding::new(4, 0).unwrap_err(), ShardError::NoParityShards);
    assert_eq!(Coding::new(0, 4).unwrap_err(), ShardError::NoDataShards);
    assert!(matches!(
        Coding::new(200, 100),
        Err(ShardError::TooManyShards { .. })
    ));
}
