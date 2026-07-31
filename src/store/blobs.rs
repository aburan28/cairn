//! Content-addressed storage for the bytes an objective pins by hash.
//!
//! An objective commits to its checker by digest -- `evaluator_sha256`,
//! `checker_sha256` -- and those digests are part of the objective's id, so
//! editing a checker forks the objective rather than rescoring work already done
//! against it. That much has always been true. What was missing is anywhere to
//! *put* the bytes: the digest was only ever used to check a file the operator
//! already happened to have, at a relative path under
//! [`crate::verifiers::VerifierRegistry`]'s root.
//!
//! The consequence was narrow and awkward. Two nodes whose roots differ reach
//! different verdicts on the same claim -- one `Accept`, one `Unavailable` --
//! and while the rule that `Unavailable` never settles keeps that from being a
//! consensus failure, it means public verifiability depended on out-of-band file
//! distribution. "Anyone can re-derive every settled result from nothing but a
//! copy of the log" needed a copy of the verifier tree too.
//!
//! # The name is the hash
//!
//! Everything here follows from that. A blob is stored under its own digest, so:
//!
//! - **Verification is free and unavoidable.** [`BlobStore::get`] re-hashes what
//!   it read and refuses bytes that do not match the name they were filed under.
//!   There is no separate integrity record to keep in sync, because the filename
//!   *is* the integrity record.
//! - **Writes are idempotent.** Putting the same bytes twice is a no-op, and
//!   deliberately does not rewrite the file: modification time is what
//!   [`super::quota`] orders eviction by, so a redundant write would quietly
//!   promote a blob past older ones.
//! - **Two stores that hold the same blob hold the same bytes.** Which is what
//!   makes [`super::mirror`] a backup rather than a snapshot of one machine's
//!   idea of the truth.
//!
//! # Two decisions worth the paragraph
//!
//! **The `sha256:` prefix stays out of the filesystem.** Digests are written
//! `sha256:<64 hex>` everywhere else in this crate and that spelling is the API
//! here too, but `:` is not a portable filename character. The stored name is
//! the bare hex, so a store written on one platform is readable on another.
//!
//! **Blobs are sharded on the first byte** -- `blobs/ab/cdef...`. At the scale
//! this crate runs at today a flat directory would be fine, and that is exactly
//! why the layout has to be decided now: changing it later means moving every
//! file in every operator's store, and the cost of getting it right early is two
//! characters.
//!
//! # What this is not
//!
//! A fetch mechanism. This is where a blob lives once a node has it; nothing
//! here goes and gets one. That needs the gossip transport, which does not exist
//! -- `gossip.rs` is the merge law, not a wire protocol. Until it does, a blob
//! arrives by [`BlobStore::put`], by `proofwork blob put`, or by
//! [`super::mirror`] carrying a store that already had it.

use std::fs;
use std::path::{Path, PathBuf};

use super::{create_private_dir, io, StoreError};
use crate::canonical::{digest_bytes, DIGEST_PREFIX};

/// Subdirectory of the cache holding content-addressed blobs.
pub const BLOB_DIR: &str = "blobs";

/// Characters of hex used as the shard directory.
const SHARD: usize = 2;
/// Hex characters in a SHA-256 digest.
const HEX_LEN: usize = 64;

/// A content-addressed store: bytes filed under their own SHA-256.
///
/// Cheap to construct and holds no handles, so a caller that wants one per
/// command is not paying for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobStore {
    root: PathBuf,
}

impl BlobStore {
    /// A blob store rooted at `root`, which is the directory the shards live in.
    pub fn new(root: impl Into<PathBuf>) -> BlobStore {
        BlobStore { root: root.into() }
    }

    /// The blob store belonging to a data directory: `<data-dir>/cache/blobs`.
    ///
    /// Under `cache/` because a blob is by definition re-fetchable -- it is
    /// named by its content, so a lost blob is a re-download and never a lost
    /// record. That classification is not the whole story once an objective
    /// depends on one; see [`super::Store::with_pinned_blobs`].
    pub fn under(store: &super::Store) -> BlobStore {
        BlobStore::new(store.blob_dir())
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Create the directory, owner-only where the platform allows it.
    pub fn prepare(&self) -> Result<(), StoreError> {
        create_private_dir(&self.root)
    }

    /// Where `digest` would live, or an error if it is not a digest.
    ///
    /// Returns a path whether or not anything is there. Callers that want the
    /// question answered use [`BlobStore::has`].
    pub fn path_of(&self, digest: &str) -> Result<PathBuf, StoreError> {
        let hex = hex_of(digest)?;
        let (shard, rest) = hex.split_at(SHARD);
        Ok(self.root.join(shard).join(rest))
    }

    /// Whether this store holds `digest`.
    ///
    /// Existence only. A file that is present but corrupt answers `true` here
    /// and fails in [`BlobStore::get`], which is the right split: this is a
    /// question about the store's inventory, and the integrity check belongs on
    /// the path that is about to use the bytes.
    pub fn has(&self, digest: &str) -> bool {
        matches!(self.path_of(digest), Ok(path) if path.is_file())
    }

    /// File `bytes` under their digest and return it.
    ///
    /// Idempotent: bytes already present are left exactly as they are, mtime
    /// included.
    pub fn put(&self, bytes: &[u8]) -> Result<String, StoreError> {
        let digest = digest_bytes(bytes);
        let path = self.path_of(&digest)?;
        if path.is_file() {
            return Ok(digest);
        }
        let parent = path.parent().unwrap_or(&self.root);
        create_private_dir(parent)?;

        // Write beside the destination and rename onto it. Same directory, so
        // the rename is atomic on any filesystem worth using, and a crash
        // halfway through leaves a `.tmp-` file rather than a truncated blob
        // sitting under a digest that promises otherwise. Everything downstream
        // trusts the name, so a partially written blob is worse than no blob.
        let temporary = parent.join(format!(".tmp-{}-{}", std::process::id(), &digest[..12]));
        fs::write(&temporary, bytes)
            .map_err(|e| io(format!("writing {}", temporary.display()), e))?;
        match fs::rename(&temporary, &path) {
            Ok(()) => Ok(digest),
            Err(error) => {
                let _ = fs::remove_file(&temporary);
                Err(io(format!("filing {}", path.display()), error))
            }
        }
    }

    /// Read a file and file its contents.
    pub fn put_file(&self, source: &Path) -> Result<String, StoreError> {
        let bytes = fs::read(source).map_err(|e| io(format!("reading {}", source.display()), e))?;
        self.put(&bytes)
    }

    /// Fetch `digest`, verifying that what came back hashes to it.
    ///
    /// `Ok(None)` means the store does not have it, which is a routine answer
    /// and not an error -- the caller falls back or reports `Unavailable`.
    /// [`StoreError::CorruptBlob`] means it *did* have it and the bytes are
    /// wrong, which is a fact about this disk and never about the objective that
    /// asked for them.
    pub fn get(&self, digest: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let path = self.path_of(digest)?;
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io(format!("reading {}", path.display()), error)),
        };
        let actual = digest_bytes(&bytes);
        if actual != canonical_digest(digest)? {
            return Err(StoreError::CorruptBlob {
                digest: canonical_digest(digest)?,
                actual,
            });
        }
        Ok(Some(bytes))
    }

    /// Every blob held, as `(digest, bytes)`, in digest order.
    ///
    /// Names that are not digests are skipped rather than reported: a `.tmp-`
    /// file from an interrupted [`BlobStore::put`] is debris, and an inventory
    /// that refused to run because somebody dropped a note in the directory
    /// would be useless exactly when it is needed.
    pub fn list(&self) -> Result<Vec<(String, u64)>, StoreError> {
        let mut blobs = Vec::new();
        let shards = match fs::read_dir(&self.root) {
            Ok(shards) => shards,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(blobs),
            Err(error) => return Err(io(format!("reading {}", self.root.display()), error)),
        };
        for shard in shards {
            let shard = shard.map_err(|e| io(format!("reading {}", self.root.display()), e))?;
            if !shard.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let prefix = shard.file_name().to_string_lossy().into_owned();
            if prefix.len() != SHARD || !is_hex(&prefix) {
                continue;
            }
            let entries = fs::read_dir(shard.path())
                .map_err(|e| io(format!("reading {}", shard.path().display()), e))?;
            for entry in entries {
                let entry =
                    entry.map_err(|e| io(format!("reading {}", shard.path().display()), e))?;
                let rest = entry.file_name().to_string_lossy().into_owned();
                if rest.len() != HEX_LEN - SHARD || !is_hex(&rest) {
                    continue;
                }
                let bytes = entry.metadata().map(|m| m.len()).unwrap_or(0);
                blobs.push((format!("{DIGEST_PREFIX}{prefix}{rest}"), bytes));
            }
        }
        blobs.sort();
        Ok(blobs)
    }

    /// Re-hash everything held and return the digests whose bytes disagree.
    ///
    /// "The name is the hash" is the store's entire trust model, so it is worth
    /// being able to check rather than assume. An empty result is the good one.
    pub fn verify(&self) -> Result<Vec<String>, StoreError> {
        let mut corrupt = Vec::new();
        for (digest, _) in self.list()? {
            match self.get(&digest) {
                Ok(_) => {}
                Err(StoreError::CorruptBlob { digest, .. }) => corrupt.push(digest),
                Err(other) => return Err(other),
            }
        }
        Ok(corrupt)
    }
}

/// Accept a digest in either spelling and return the canonical, prefixed one.
///
/// Public because a pin set is a set of digests that has to compare equal
/// however its members were spelled: an objective's bare-hex `evaluator_sha256`
/// and a prefixed record id name the same blob, and a set that held both would
/// pin one and evict the other. See [`super::Store::with_pinned_blobs`].
pub fn canonical_digest(digest: &str) -> Result<String, StoreError> {
    Ok(format!("{DIGEST_PREFIX}{}", hex_of(digest)?))
}

/// The 64 hex characters of a digest, with or without the `sha256:` prefix.
///
/// Both spellings are accepted because both occur honestly: objectives write
/// `evaluator_sha256` as bare hex, while record ids and
/// [`crate::canonical::digest_bytes`] carry the prefix. Refusing one of them
/// would push a `strip_prefix` into every caller, and a caller that forgot it
/// would look up a blob that can never be there.
fn hex_of(digest: &str) -> Result<String, StoreError> {
    let hex = digest.strip_prefix(DIGEST_PREFIX).unwrap_or(digest);
    if hex.len() != HEX_LEN || !is_hex(hex) {
        return Err(StoreError::NotADigest(digest.to_string()));
    }
    Ok(hex.to_ascii_lowercase())
}

/// Lowercase hex only. Uppercase is refused rather than accepted and folded,
/// because two spellings of one digest are two filenames for one blob.
fn is_hex(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::tests::scratch;
    use crate::store::Store;

    fn store(tag: &str) -> (PathBuf, BlobStore) {
        let dir = scratch(tag);
        let blobs = BlobStore::new(dir.join("blobs"));
        blobs.prepare().expect("prepares");
        (dir, blobs)
    }

    #[test]
    fn a_blob_is_filed_under_its_own_digest() {
        let (dir, blobs) = store("put");
        let digest = blobs.put(b"print('hello')").expect("puts");
        assert_eq!(digest, digest_bytes(b"print('hello')"));
        assert!(blobs.has(&digest));
        assert_eq!(
            blobs.get(&digest).expect("gets"),
            Some(b"print('hello')".to_vec())
        );

        // Sharded on the first byte, and the `sha256:` prefix stays out of the
        // filesystem so the layout is portable.
        let hex = digest.strip_prefix(DIGEST_PREFIX).expect("prefixed");
        let path = blobs.path_of(&digest).expect("a digest");
        assert_eq!(path, blobs.root().join(&hex[..2]).join(&hex[2..]));
        assert!(!path.to_string_lossy().contains(':'));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn putting_the_same_bytes_twice_does_not_rewrite_the_file() {
        // Not merely an optimisation. `quota` evicts oldest-first by mtime, so a
        // redundant write would silently promote a blob past older ones and
        // change which content survives a reclaim.
        let (dir, blobs) = store("idempotent");
        let digest = blobs.put(b"same").expect("puts");
        let path = blobs.path_of(&digest).expect("a digest");
        let first = fs::metadata(&path).expect("metadata").modified().ok();

        let again = blobs.put(b"same").expect("puts again");
        assert_eq!(again, digest);
        let second = fs::metadata(&path).expect("metadata").modified().ok();
        assert_eq!(first, second, "an existing blob is left alone");
        assert_eq!(blobs.list().expect("lists").len(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_bytes_are_refused_rather_than_returned() {
        // The whole trust model in one test: the filename is the integrity
        // record, so tampering is detected without any second copy of anything.
        let (dir, blobs) = store("corrupt");
        let digest = blobs.put(b"honest").expect("puts");
        let path = blobs.path_of(&digest).expect("a digest");
        fs::write(&path, b"tampered").expect("overwrite");

        assert!(blobs.has(&digest), "still on disk");
        match blobs
            .get(&digest)
            .expect_err("must not hand back the bytes")
        {
            StoreError::CorruptBlob {
                digest: reported,
                actual,
            } => {
                assert_eq!(reported, digest);
                assert_eq!(actual, digest_bytes(b"tampered"));
            }
            other => panic!("expected CorruptBlob, got {other:?}"),
        }
        assert_eq!(blobs.verify().expect("verifies"), vec![digest]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_blob_is_not_an_error() {
        // The routine answer. A caller that gets `None` falls back to the path,
        // and only then reports `Unavailable` -- an absent blob is a fact about
        // this node, and turning it into an error here would push that decision
        // to the wrong layer.
        let (dir, blobs) = store("missing");
        let absent = digest_bytes(b"never stored");
        assert!(!blobs.has(&absent));
        assert_eq!(blobs.get(&absent).expect("no error"), None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn both_spellings_of_a_digest_find_the_same_blob() {
        // Objectives write `evaluator_sha256` as bare hex; ids and
        // `digest_bytes` carry the prefix. Accepting one only would mean a
        // caller that forgot to strip it looks up a blob that can never exist.
        let (dir, blobs) = store("spelling");
        let digest = blobs.put(b"either way").expect("puts");
        let bare = digest.strip_prefix(DIGEST_PREFIX).expect("prefixed");
        assert!(blobs.has(bare));
        assert_eq!(
            blobs.path_of(bare).expect("a digest"),
            blobs.path_of(&digest).expect("a digest")
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_name_that_is_not_a_digest_is_refused() {
        let (dir, blobs) = store("notadigest");
        for bad in [
            "",
            "sha256:",
            "beef",
            "sha256:not-hex-at-all-not-hex-at-all-not-hex-at-all-not-hex-at-all-xx",
            // Uppercase is refused rather than folded: two spellings of one
            // digest would be two filenames for one blob.
            "sha256:ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        ] {
            assert!(
                matches!(blobs.path_of(bad), Err(StoreError::NotADigest(_))),
                "{bad:?} should not name a blob"
            );
            assert!(!blobs.has(bad));
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_inventory_skips_debris_and_sorts() {
        let (dir, blobs) = store("list");
        let one = blobs.put(b"a").expect("puts");
        let two = blobs.put(b"bb").expect("puts");

        // Debris an interrupted `put` or a curious operator could leave behind.
        fs::write(blobs.root().join("README"), b"notes").expect("write");
        fs::create_dir_all(blobs.root().join("zz")).expect("mkdir");
        fs::write(blobs.root().join("zz").join("stray"), b"x").expect("write");
        let shard = blobs
            .path_of(&one)
            .expect("a digest")
            .parent()
            .expect("has a parent")
            .to_path_buf();
        fs::write(shard.join(".tmp-1234-abcdef012345"), b"partial").expect("write");

        let listed = blobs.list().expect("lists");
        let digests: Vec<&str> = listed.iter().map(|(d, _)| d.as_str()).collect();
        let mut expected = vec![one.as_str(), two.as_str()];
        expected.sort();
        assert_eq!(digests, expected);
        for (digest, bytes) in &listed {
            assert_eq!(*bytes, if *digest == one { 1 } else { 2 });
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_absent_store_lists_empty_rather_than_failing() {
        let dir = scratch("absent");
        let blobs = BlobStore::new(dir.join("never-created"));
        assert_eq!(blobs.list().expect("lists"), Vec::new());
        assert_eq!(blobs.verify().expect("verifies"), Vec::<String>::new());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_store_puts_its_blobs_under_the_cache() {
        // Where the bytes live decides whether the quota may delete them, so the
        // location is a contract rather than a detail.
        let dir = scratch("under");
        let store = Store::new(dir.join("data"));
        store.prepare().expect("prepares");
        let blobs = BlobStore::under(&store);
        assert_eq!(blobs.root(), store.cache_dir().join(BLOB_DIR));
        let digest = blobs.put(b"cached").expect("puts");
        assert_eq!(
            store.classify(&blobs.path_of(&digest).expect("a digest")),
            crate::store::Class::Reclaimable,
            "an unreferenced blob is a copy of something, so it may go"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn put_file_and_put_agree() {
        let (dir, blobs) = store("putfile");
        let source = dir.join("checker.py");
        fs::write(&source, b"def score(a):\n    return 0\n").expect("write");
        let from_file = blobs.put_file(&source).expect("puts");
        let from_bytes = blobs.put(b"def score(a):\n    return 0\n").expect("puts");
        assert_eq!(from_file, from_bytes);
        let _ = fs::remove_dir_all(&dir);
    }
}
