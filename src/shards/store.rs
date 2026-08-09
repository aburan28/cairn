//! Shards on disk, under the digest the log already pins.
//!
//! The layout mirrors [`crate::blobs`] one level down, because a shard is not
//! self-naming the way a blob is:
//!
//! ```text
//! .proofwork/shards/
//!   <64 hex characters of the blob's digest>/
//!     manifest      the canonical encoding of [`Manifest`], one line
//!     000, 001, …   shard bytes, filed under their index in the coding
//! ```
//!
//! # Why the directory is named for the *blob* and the files for the index
//!
//! A blob's name can be its own hash, so [`crate::blobs::BlobStore`] re-hashes
//! on read and needs no second record to keep integrity in sync. A shard cannot
//! do that: its content address would say nothing about which blob it belongs
//! to or which row of the generator matrix produced it, and a store of
//! self-named shards would need an index mapping blobs to shards — which is
//! precisely the second record `docs/storage.md` refuses to introduce.
//!
//! So the manifest plays that role, and it is not a second record in the sense
//! that matters: **it is derived from the bytes and checked against the blob
//! digest**, so a wrong one is detected rather than believed.
//! [`ShardStore::put_manifest`] refuses one that does not describe the address
//! it is being filed under, and every read of a shard re-derives the shard's
//! Merkle root and compares it to the manifest. The invariant is the same as the
//! blob store's, one indirection deeper:
//!
//! > **The store never returns bytes it has not just re-checked against a
//! > commitment.**
//!
//! # What a shard here costs, and what it protects
//!
//! Not sealed at rest, and on the record as not sealed, in the table
//! [`crate::store::exposure`] enforces. A shard is a linear combination of a
//! blob the network hands to any peer that asks; holding `k` of them is holding
//! the blob, and the blob is public. What a disk *does* disclose is the same
//! residue the blob store has — the *set* of digests this node is holding
//! content for. That is already carried as not handled in
//! `docs/threat-model.md`, and shards add no new kind of leak to it.
//!
//! Eviction is a different matter and is left strict on purpose: nothing here
//! is under `cache/`, so [`crate::store::Store::classify`] calls it pinned and
//! `store gc` will refuse rather than delete it. A shard is *not* reclaimable
//! the way a blob is — dropping a blob costs a re-download, dropping the `k`-th
//! surviving shard costs the blob.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use super::{reconstruct, Manifest, Reconstruction, Shard, ShardError};
use crate::blobs::is_address;
use crate::canonical::Value;

/// Where a shard store lives under a bundle root — beside `.proofwork/blobs`,
/// for the same reason and against the same root.
pub const STORE_DIR: &str = ".proofwork/shards";

/// The manifest's filename inside a blob's directory.
///
/// Not a content address, and deliberately not one: it is the *only* entry in
/// the directory that is not a shard index, so the two cannot collide and a
/// listing needs no second rule to tell them apart.
pub const MANIFEST_FILE: &str = "manifest";

/// Why a shard-store operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShardStoreError {
    /// Not 64 lowercase hex characters. Refused before it is allowed anywhere
    /// near a path join, exactly as in [`crate::blobs`].
    NotAnAddress { address: String },
    /// No manifest for this blob, so nothing here can be checked against
    /// anything and nothing is returned.
    NoManifest { address: String },
    /// The manifest on disk does not describe the address it is filed under.
    ///
    /// Reachable by editing the store by hand, and the answer is a refusal
    /// rather than a repair: a directory named for one blob holding a manifest
    /// for another is not a thing to guess about.
    Mismatched { address: String, digest: String },
    /// No copy of this shard.
    Absent { address: String, index: u8 },
    /// The bytes do not rebuild the root the manifest commits to. On a read the
    /// offending file is deleted first — see [`ShardStore::shard`].
    Corrupt { address: String, index: u8 },
    /// The manifest, or a shard, could not be parsed or is out of shape.
    Shards(ShardError),
    /// Filesystem trouble, as text — `io::Error` is neither `Clone` nor `Eq`.
    Io { detail: String },
}

impl fmt::Display for ShardStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ShardStoreError::NotAnAddress { address } => write!(
                f,
                "{address:?} is not a content address (64 lowercase hex characters)"
            ),
            ShardStoreError::NoManifest { address } => {
                write!(f, "no shard manifest for {address}")
            }
            ShardStoreError::Mismatched { address, digest } => {
                write!(f, "the manifest filed under {address} describes {digest}")
            }
            ShardStoreError::Absent { address, index } => {
                write!(f, "no local copy of shard {index} of {address}")
            }
            ShardStoreError::Corrupt { address, index } => write!(
                f,
                "shard {index} of {address} does not rebuild its committed root"
            ),
            ShardStoreError::Shards(error) => write!(f, "{error}"),
            ShardStoreError::Io { detail } => write!(f, "shard store: {detail}"),
        }
    }
}

impl std::error::Error for ShardStoreError {}

impl From<ShardError> for ShardStoreError {
    fn from(error: ShardError) -> ShardStoreError {
        ShardStoreError::Shards(error)
    }
}

fn io_error(error: io::Error) -> ShardStoreError {
    ShardStoreError::Io {
        detail: error.to_string(),
    }
}

/// A directory of coded blobs, one subdirectory each.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardStore {
    dir: PathBuf,
}

impl ShardStore {
    /// The store belonging to a bundle root.
    pub fn under(root: impl AsRef<Path>) -> ShardStore {
        ShardStore {
            dir: root.as_ref().join(STORE_DIR),
        }
    }

    /// A store at an explicit directory.
    pub fn at(dir: impl Into<PathBuf>) -> ShardStore {
        ShardStore { dir: dir.into() }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Where a blob's shards would live. `Err` for anything that is not an
    /// address, so a hostile pin cannot become a path outside the store.
    pub fn path_of(&self, address: &str) -> Result<PathBuf, ShardStoreError> {
        if !is_address(address) {
            return Err(ShardStoreError::NotAnAddress {
                address: address.to_string(),
            });
        }
        Ok(self.dir.join(address))
    }

    /// Every blob this store holds shards for, sorted.
    pub fn addresses(&self) -> Vec<String> {
        let mut out = Vec::new();
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return out;
        };
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if is_address(name) && entry.path().is_dir() {
                    out.push(name.to_string());
                }
            }
        }
        out.sort();
        out
    }

    pub fn is_empty(&self) -> bool {
        self.addresses().is_empty()
    }

    /// File the manifest for `address`.
    ///
    /// Refuses a manifest that does not describe the address, which is the one
    /// check that makes everything downstream meaningful: every shard read is
    /// verified against this manifest, so a manifest for the wrong blob would
    /// make the store faithfully return the wrong bytes.
    pub fn put_manifest(
        &self,
        address: &str,
        manifest: &Manifest,
    ) -> Result<PathBuf, ShardStoreError> {
        let dir = self.path_of(address)?;
        if !manifest.describes(address) {
            return Err(ShardStoreError::Mismatched {
                address: address.to_string(),
                digest: manifest.digest().to_string(),
            });
        }
        create_dir(&dir)?;
        let path = dir.join(MANIFEST_FILE);
        let mut line = manifest.to_value().canonical_string();
        line.push('\n');
        write_private(&dir, &path, line.as_bytes())?;
        Ok(path)
    }

    /// Read the manifest for `address`, checking that it describes it.
    pub fn manifest(&self, address: &str) -> Result<Manifest, ShardStoreError> {
        let path = self.path_of(address)?.join(MANIFEST_FILE);
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(ShardStoreError::NoManifest {
                    address: address.to_string(),
                })
            }
            Err(error) => return Err(io_error(error)),
        };
        let value = Value::from_json(text.trim()).map_err(|error| ShardStoreError::Io {
            detail: format!("manifest for {address} is not JSON: {error}"),
        })?;
        let manifest = Manifest::from_value(&value)?;
        if !manifest.describes(address) {
            return Err(ShardStoreError::Mismatched {
                address: address.to_string(),
                digest: manifest.digest().to_string(),
            });
        }
        Ok(manifest)
    }

    /// Store one shard, **verifying it against the manifest first**.
    ///
    /// Every path into the store goes through here, which is what makes "a
    /// shard is checked against the committed root before it is written
    /// anywhere it could be used" a property of the type rather than of each
    /// call site. Nothing that fails the check reaches disk.
    pub fn put_shard(&self, address: &str, shard: &Shard) -> Result<PathBuf, ShardStoreError> {
        let manifest = self.manifest(address)?;
        self.put_shard_against(address, &manifest, shard)
    }

    /// [`ShardStore::put_shard`] with the manifest already in hand — the same
    /// check, without re-reading and re-parsing it once per shard.
    pub fn put_shard_against(
        &self,
        address: &str,
        manifest: &Manifest,
        shard: &Shard,
    ) -> Result<PathBuf, ShardStoreError> {
        let dir = self.path_of(address)?;
        if !manifest.describes(address) {
            return Err(ShardStoreError::Mismatched {
                address: address.to_string(),
                digest: manifest.digest().to_string(),
            });
        }
        if usize::from(shard.index) >= manifest.roots().len() {
            return Err(ShardStoreError::Shards(ShardError::NoSuchShard {
                index: shard.index,
                shards: manifest.coding().shards(),
            }));
        }
        if !manifest.verify_shard(shard) {
            return Err(ShardStoreError::Corrupt {
                address: address.to_string(),
                index: shard.index,
            });
        }
        create_dir(&dir)?;
        let path = dir.join(shard_file(shard.index));
        write_private(&dir, &path, &shard.bytes)?;
        Ok(path)
    }

    /// Which shard indices are on disk for `address`, ascending.
    ///
    /// Existence only, cheap enough to call per round. A shard whose bytes have
    /// rotted is reported as held here and caught by [`ShardStore::shard`],
    /// which is the only place the bytes are used — the same split
    /// [`crate::blobs::BlobStore::holds`] makes, and for the same reason.
    pub fn held(&self, address: &str) -> Vec<u8> {
        let Ok(dir) = self.path_of(address) else {
            return Vec::new();
        };
        let Ok(entries) = fs::read_dir(dir) else {
            return Vec::new();
        };
        let mut out: Vec<u8> = entries
            .flatten()
            .filter_map(|entry| {
                let name = entry.file_name();
                let name = name.to_str()?;
                // Exactly three digits, so `07` and `007` cannot both name
                // shard seven. One spelling per shard, for the reason
                // `blobs::is_address` refuses uppercase.
                if name.len() != 3 || !name.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                name.parse::<u8>().ok()
            })
            .collect();
        out.sort_unstable();
        out
    }

    /// Read one shard, re-verifying it against the manifest.
    ///
    /// The verification is not paranoia about our own writes: the store is an
    /// ordinary directory an operator can edit, a backup can restore badly, and
    /// a disk can corrupt. A shard whose bytes no longer rebuild its committed
    /// root is deleted rather than returned — otherwise it shadows the real one
    /// forever, since [`ShardStore::held`] would go on reporting the index as
    /// present and the fetch that would replace it would never be attempted.
    /// [`crate::blobs::BlobStore::read`] makes the same choice for the same
    /// reason.
    pub fn shard(&self, address: &str, index: u8) -> Result<Shard, ShardStoreError> {
        let manifest = self.manifest(address)?;
        self.shard_against(address, &manifest, index)
    }

    /// [`ShardStore::shard`] with the manifest already in hand.
    pub fn shard_against(
        &self,
        address: &str,
        manifest: &Manifest,
        index: u8,
    ) -> Result<Shard, ShardStoreError> {
        let path = self.path_of(address)?.join(shard_file(index));
        let metadata = match fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(ShardStoreError::Absent {
                    address: address.to_string(),
                    index,
                })
            }
            Err(error) => return Err(io_error(error)),
        };
        // The declared length, before the allocation. A store entry is
        // untrusted input for the same reason a wire frame is, and the layout
        // says exactly how long this file has to be.
        if metadata.len() != manifest.layout().shard_len() {
            let _ = fs::remove_file(&path);
            return Err(ShardStoreError::Corrupt {
                address: address.to_string(),
                index,
            });
        }
        let bytes = fs::read(&path).map_err(io_error)?;
        let shard = Shard::new(index, bytes);
        if !manifest.verify_shard(&shard) {
            let _ = fs::remove_file(&path);
            return Err(ShardStoreError::Corrupt {
                address: address.to_string(),
                index,
            });
        }
        Ok(shard)
    }

    /// Rebuild the blob from whatever this store holds.
    ///
    /// A shard whose bytes have rotted is dropped rather than allowed to fail
    /// the whole attempt — that loss is exactly what the parity is for — and it
    /// is **named**, in [`Reconstruction::rejected`] on success and in
    /// [`ShardError::NotEnoughShards`] when there were not enough left. Losing
    /// that name would be the whole point of the design going missing at the
    /// last step: a caller told "3 of 4" and not *which* one rotted has to go
    /// looking for it by hand.
    ///
    /// Note that [`ShardStore::shard_against`] has already deleted the offending
    /// file by the time it is reported, so the index names a shard this node no
    /// longer has rather than one it should re-check.
    pub fn reconstruct(&self, address: &str) -> Result<Reconstruction, ShardStoreError> {
        let manifest = self.manifest(address)?;
        let mut offered = Vec::new();
        let mut rotted: Vec<u8> = Vec::new();
        for index in self.held(address) {
            match self.shard_against(address, &manifest, index) {
                Ok(shard) => offered.push(shard),
                Err(ShardStoreError::Corrupt { .. }) => rotted.push(index),
                // Removed between the listing and the read. Not misbehaviour by
                // anyone, and nothing to report.
                Err(ShardStoreError::Absent { .. }) => {}
                Err(error) => return Err(error),
            }
        }
        match reconstruct(&manifest, &offered) {
            Ok(mut out) => {
                out.rejected = merge(out.rejected, rotted);
                Ok(out)
            }
            Err(ShardError::NotEnoughShards {
                have,
                need,
                rejected,
            }) => Err(ShardStoreError::Shards(ShardError::NotEnoughShards {
                have,
                need,
                rejected: merge(rejected, rotted),
            })),
            Err(error) => Err(error.into()),
        }
    }

    /// Write a whole encoding: the manifest, then every shard given.
    ///
    /// The manifest first, on purpose. A shard cannot be written without one —
    /// [`ShardStore::put_shard_against`] has nothing to check against — so the
    /// reverse order would have to either buffer or write unchecked bytes, and
    /// the second is the rule this module exists to keep.
    pub fn put_all(
        &self,
        address: &str,
        manifest: &Manifest,
        shards: &[Shard],
    ) -> Result<usize, ShardStoreError> {
        self.put_manifest(address, manifest)?;
        let mut written = 0;
        for shard in shards {
            self.put_shard_against(address, manifest, shard)?;
            written += 1;
        }
        Ok(written)
    }

    /// Drop every shard of `address`, and the manifest with them.
    ///
    /// The manifest goes too: a manifest with no shards is a commitment to
    /// nothing, and leaving it behind would make `ls` report a blob this node
    /// cannot contribute a single byte towards.
    pub fn remove(&self, address: &str) -> Result<(), ShardStoreError> {
        let dir = self.path_of(address)?;
        match fs::remove_dir_all(&dir) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(io_error(error)),
        }
    }
}

/// Two rejection lists into one, sorted and without repeats.
fn merge(one: Vec<u8>, two: Vec<u8>) -> Vec<u8> {
    let mut all = one;
    all.extend(two);
    all.sort_unstable();
    all.dedup();
    all
}

/// A shard's filename: its index, zero-padded to three digits.
///
/// Fixed width so a directory listing sorts into coding order, and so exactly
/// one spelling names each shard.
fn shard_file(index: u8) -> String {
    format!("{index:03}")
}

#[cfg(unix)]
fn create_dir(dir: &Path) -> Result<(), ShardStoreError> {
    use std::os::unix::fs::DirBuilderExt;
    if dir.is_dir() {
        return Ok(());
    }
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(io_error)
}

#[cfg(not(unix))]
fn create_dir(dir: &Path) -> Result<(), ShardStoreError> {
    if dir.is_dir() {
        return Ok(());
    }
    fs::create_dir_all(dir).map_err(io_error)
}

/// Write with no execute bit and no group or world access, through a temporary
/// name.
///
/// The rename is what stops a crash mid-write leaving a short file under a real
/// shard index — which would read back as corruption and cost a shard that was
/// never actually lost. The temporary name carries the pid so two processes
/// sharing a root do not rename each other's partial writes into place.
fn write_private(dir: &Path, path: &Path, bytes: &[u8]) -> Result<(), ShardStoreError> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("shard");
    let staging = dir.join(format!(".{name}.{}.partial", std::process::id()));
    write_now(&staging, bytes)?;
    match fs::rename(&staging, path) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = fs::remove_file(&staging);
            Err(io_error(error))
        }
    }
}

#[cfg(unix)]
fn write_now(path: &Path, bytes: &[u8]) -> Result<(), ShardStoreError> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(io_error)?;
    file.write_all(bytes).map_err(io_error)?;
    file.sync_all().map_err(io_error)
}

#[cfg(not(unix))]
fn write_now(path: &Path, bytes: &[u8]) -> Result<(), ShardStoreError> {
    fs::write(path, bytes).map_err(io_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blobs::address;
    use crate::shards::{encode, Coding, MIN_CHUNK_LEN};

    /// A scratch directory under `target/`, so a failed run leaves evidence.
    fn scratch(name: &str) -> PathBuf {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("shard-store-tests")
            .join(name);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    fn blob(len: usize) -> Vec<u8> {
        (0..len).map(|i| ((i * 13 + 7) % 251) as u8).collect()
    }

    fn coded(len: usize) -> (Vec<u8>, String, crate::shards::Encoded) {
        let data = blob(len);
        let at = address(&data);
        let encoded =
            encode(&data, Coding::new(4, 2).expect("coding"), MIN_CHUNK_LEN).expect("encode");
        (data, at, encoded)
    }

    #[test]
    fn a_hostile_address_never_reaches_a_path_join() {
        let store = ShardStore::at(scratch("hostile"));
        for bad in ["../../../../etc/passwd", "..", "/etc/passwd", ""] {
            assert!(matches!(
                store.path_of(bad),
                Err(ShardStoreError::NotAnAddress { .. })
            ));
            assert!(store.held(bad).is_empty());
            assert!(matches!(
                store.manifest(bad),
                Err(ShardStoreError::NotAnAddress { .. })
            ));
            assert!(matches!(
                store.remove(bad),
                Err(ShardStoreError::NotAnAddress { .. })
            ));
        }
    }

    #[test]
    fn a_blob_round_trips_through_the_store() {
        let store = ShardStore::at(scratch("round-trip"));
        let (data, at, encoded) = coded(MIN_CHUNK_LEN as usize * 2 + 11);
        assert!(store.is_empty());

        assert_eq!(
            store.put_all(&at, &encoded.manifest, &encoded.shards),
            Ok(6)
        );
        assert_eq!(store.addresses(), vec![at.clone()]);
        assert_eq!(store.held(&at), vec![0, 1, 2, 3, 4, 5]);
        assert_eq!(store.manifest(&at).expect("manifest"), encoded.manifest);

        let out = store.reconstruct(&at).expect("reconstruct");
        assert_eq!(out.data, data);
        assert!(out.rejected.is_empty());

        store.remove(&at).expect("remove");
        assert!(store.is_empty());
        assert!(matches!(
            store.manifest(&at),
            Err(ShardStoreError::NoManifest { .. })
        ));
    }

    #[test]
    fn the_store_holds_a_blob_it_cannot_rebuild_without_pretending_otherwise() {
        // The point of the whole exercise: a node holds two of six shards,
        // which is a real and useful thing to hold, and says so rather than
        // failing as though the blob were absent.
        let store = ShardStore::at(scratch("partial"));
        let (_, at, encoded) = coded(MIN_CHUNK_LEN as usize * 3);
        store
            .put_manifest(&at, &encoded.manifest)
            .expect("manifest");
        for index in [1usize, 4] {
            let shard = encoded.shards.get(index).expect("shard");
            store
                .put_shard(&at, shard)
                .unwrap_or_else(|error| panic!("shard {index}: {error}"));
        }
        assert_eq!(store.held(&at), vec![1, 4]);
        assert_eq!(
            store.reconstruct(&at).unwrap_err(),
            ShardStoreError::Shards(ShardError::NotEnoughShards {
                have: 2,
                need: 4,
                rejected: vec![]
            })
        );
    }

    #[test]
    fn four_of_six_shards_still_rebuild_the_blob() {
        let store = ShardStore::at(scratch("four-of-six"));
        let (data, at, encoded) = coded(MIN_CHUNK_LEN as usize * 2 + 3);
        store
            .put_manifest(&at, &encoded.manifest)
            .expect("manifest");
        // Keep two data shards and both parity shards: the case a systematic
        // code has to solve rather than concatenate.
        for index in [2usize, 3, 4, 5] {
            let shard = encoded.shards.get(index).expect("shard");
            store.put_shard(&at, shard).expect("put");
        }
        let out = store.reconstruct(&at).expect("reconstruct");
        assert_eq!(out.data, data);
        assert_eq!(out.used, vec![2, 3, 4, 5]);
    }

    #[test]
    fn a_shard_that_does_not_match_the_manifest_never_reaches_the_disk() {
        let dir = scratch("verify-before-write");
        let store = ShardStore::at(dir.clone());
        let (_, at, encoded) = coded(MIN_CHUNK_LEN as usize);
        store
            .put_manifest(&at, &encoded.manifest)
            .expect("manifest");

        let mut lying = encoded.shards.first().cloned().expect("shard 0");
        if let Some(byte) = lying.bytes.first_mut() {
            *byte ^= 0xff;
        }
        assert_eq!(
            store.put_shard(&at, &lying),
            Err(ShardStoreError::Corrupt {
                address: at.clone(),
                index: 0
            })
        );
        assert!(store.held(&at).is_empty(), "a refused shard left a file");

        // An index the coding does not have is refused before the check.
        let stranger = Shard::new(9, vec![0u8; encoded.manifest.layout().shard_len() as usize]);
        assert_eq!(
            store.put_shard(&at, &stranger),
            Err(ShardStoreError::Shards(ShardError::NoSuchShard {
                index: 9,
                shards: 6
            }))
        );
    }

    #[test]
    fn a_rotted_shard_is_deleted_rather_than_served() {
        // Otherwise it shadows the real one forever: `held` reports the index
        // as present, so the fetch that would replace it never happens.
        let dir = scratch("rotted");
        let store = ShardStore::at(dir.clone());
        let (data, at, encoded) = coded(MIN_CHUNK_LEN as usize * 2);
        store
            .put_all(&at, &encoded.manifest, &encoded.shards)
            .expect("put all");

        let path = dir.join(&at).join("001");
        let mut rotted = fs::read(&path).expect("read");
        if let Some(byte) = rotted.get_mut(5) {
            *byte ^= 0x01;
        }
        fs::write(&path, &rotted).expect("tamper");

        assert_eq!(
            store.shard(&at, 1),
            Err(ShardStoreError::Corrupt {
                address: at.clone(),
                index: 1
            })
        );
        assert!(!store.held(&at).contains(&1), "the rotted shard survived");
        // And the blob still comes back, because that is what parity is for.
        assert_eq!(store.reconstruct(&at).expect("reconstruct").data, data);
    }

    #[test]
    fn a_truncated_shard_is_refused_against_its_declared_length() {
        let dir = scratch("truncated");
        let store = ShardStore::at(dir.clone());
        let (_, at, encoded) = coded(MIN_CHUNK_LEN as usize * 2);
        store
            .put_all(&at, &encoded.manifest, &encoded.shards)
            .expect("put all");
        fs::write(dir.join(&at).join("002"), b"short").expect("truncate");
        assert_eq!(
            store.shard(&at, 2),
            Err(ShardStoreError::Corrupt {
                address: at.clone(),
                index: 2
            })
        );
    }

    #[test]
    fn a_manifest_for_a_different_blob_is_refused_in_both_directions() {
        // The one check that makes everything downstream meaningful: every
        // shard read is verified against this manifest, so a manifest for the
        // wrong blob would make the store faithfully return the wrong bytes.
        let dir = scratch("mismatched");
        let store = ShardStore::at(dir.clone());
        let (_, at, encoded) = coded(MIN_CHUNK_LEN as usize);
        let (_, other, elsewhere) = coded(MIN_CHUNK_LEN as usize + 1);

        assert!(matches!(
            store.put_manifest(&at, &elsewhere.manifest),
            Err(ShardStoreError::Mismatched { .. })
        ));

        // And on the way out, for a store edited by hand.
        store
            .put_manifest(&at, &encoded.manifest)
            .expect("manifest");
        let mut line = elsewhere.manifest.to_value().canonical_string();
        line.push('\n');
        fs::write(dir.join(&at).join(MANIFEST_FILE), line).expect("swap");
        assert!(matches!(
            store.manifest(&at),
            Err(ShardStoreError::Mismatched { .. })
        ));
        assert_ne!(at, other);
    }

    #[test]
    fn a_shard_cannot_be_written_before_the_manifest_it_is_checked_against() {
        let store = ShardStore::at(scratch("manifest-first"));
        let (_, at, encoded) = coded(MIN_CHUNK_LEN as usize);
        assert!(matches!(
            store.put_shard(&at, encoded.shards.first().expect("shard 0")),
            Err(ShardStoreError::NoManifest { .. })
        ));
    }

    #[test]
    fn a_directory_full_of_junk_lists_no_shards() {
        // The store is an ordinary directory. Anything whose name is not three
        // digits is not a shard, whatever it contains -- and one spelling per
        // shard, so `07` is not shard seven.
        let dir = scratch("junk");
        let store = ShardStore::at(dir.clone());
        let (_, at, encoded) = coded(MIN_CHUNK_LEN as usize);
        store
            .put_manifest(&at, &encoded.manifest)
            .expect("manifest");
        let blob_dir = dir.join(&at);
        for name in ["README", "07", "0007", "00a", "-01", ""] {
            if name.is_empty() {
                continue;
            }
            fs::write(blob_dir.join(name), b"x").expect("write");
        }
        assert!(store.held(&at).is_empty());
        // And a file where a blob directory should be is not an address.
        fs::write(dir.join("f".repeat(64)), b"x").expect("write");
        assert_eq!(store.addresses(), vec![at]);
    }

    #[test]
    fn an_absent_shard_is_absent_and_not_an_io_error() {
        let store = ShardStore::at(scratch("absent"));
        let (_, at, encoded) = coded(MIN_CHUNK_LEN as usize);
        store
            .put_manifest(&at, &encoded.manifest)
            .expect("manifest");
        assert_eq!(
            store.shard(&at, 3),
            Err(ShardStoreError::Absent {
                address: at,
                index: 3
            })
        );
    }
}
