//! Erasure-coded shards, with a Merkle commitment per chunk.
//!
//! A blob split into `k` data shards and `m` parity shards, such that **any `k`
//! of the `k + m` reconstruct it**, and such that every chunk of every shard is
//! checkable on its own against a root the log already fixed.
//!
//! # What this buys, in one table
//!
//! To survive `f` holders vanishing, replication needs `f + 1` full copies.
//! Coding needs `(k + f) / k`:
//!
//! | tolerate | replication | (4, 2) coding | (8, 4) coding |
//! |---|---|---|---|
//! | 1 loss | 2.0× | 1.5× | 1.5× |
//! | 2 losses | 3.0× | 1.5× | 1.5× |
//! | 4 losses | 5.0× | — | 1.5× |
//!
//! That is the headline, and it is not the interesting half.
//!
//! # The interesting half: coding is a *downgrade* without per-chunk commitments
//!
//! Replication has a property so cheap nobody names it: **every copy is
//! self-checking.** A holder either hands you bytes that hash to the pinned
//! digest or it does not, you find out from the bytes alone, and a liar
//! implicates only itself.
//!
//! Erasure coding destroys that property. A shard is not the blob and does not
//! hash to the blob's digest; it only means something in combination with `k-1`
//! others. Feed one corrupt shard into that combination and **every** output
//! byte is wrong — the linear algebra spreads the lie across the whole
//! reconstruction. The whole-blob digest then reports that *somebody* lied,
//! which is exactly the useless answer [`crate::swarm::piece`] was written to
//! avoid during a transfer, except worse: with `n` holders and one liar there
//! are `n choose k` subsets to try, and each retry costs a full decode.
//!
//! So coding without per-chunk commitments is strictly worse than replication
//! under a Byzantine holder, and the commitments are not an optimisation on top
//! of the coding — they are the thing that makes the coding safe to use at all.
//! Hence:
//!
//! > **Nothing enters a linear combination until it has been checked against
//! > the manifest.** [`reconstruct`] verifies each shard's chunks first, drops
//! > the ones that fail, and *names* them. One liar costs its own shard and
//! > nothing else.
//!
//! # The shape
//!
//! ```text
//! blob ──split──▶ shard 0 ─┬─ chunk 0 ─▶ H ─┐
//!                          ├─ chunk 1 ─▶ H ─┼─▶ shard root 0 ─┐
//!                          └─ chunk 2 ─▶ H ─┘                 │
//!                 shard 1 ─── … ──────────────▶ shard root 1 ─┼─▶ manifest root
//!                 …                                           │
//!                 shard n-1 ─ … ──────────────▶ shard root n-1┘
//! ```
//!
//! Two levels, and the second one earns its place: a proof anchored at the
//! manifest root convinces a verifier who holds **only that root** — 32 bytes,
//! the size of something a record could one day commit to — and not the list of
//! shard roots. A verifier who already has the manifest can skip the outer hop,
//! and [`Manifest::verify_chunk`] does.
//!
//! # Three things fall out of the layout, rather than being designed in
//!
//! **A data shard's chunk is a contiguous slice of the original blob.** Shards
//! are cut as blocks, not interleaved by symbol, so chunk `c` of data shard `j`
//! is exactly `blob[j * shard_len + c * chunk_len ..]`. A reader who wants one
//! range of a large artifact fetches one chunk, checks it against the root, and
//! uses it — no decode, no other holder.
//!
//! **The manifest is `O(n)`, not `O(chunks)`.** It carries one root per shard,
//! so a 1 GiB blob at (4, 2) has a six-entry manifest. [`crate::swarm::piece`]'s
//! manifest carries one digest per piece and grows with the blob; this one does
//! not, because the per-chunk hashes are recomputed from the shard by whoever
//! holds it.
//!
//! **Sampling is `O(log)`.** Challenging a holder for one chunk costs it one
//! chunk plus `log2(chunks) + log2(n)` hashes, against a root that was fixed
//! before the challenge existed. That is the shape
//! `docs/node-incentives.md` wants for availability, applied to content instead
//! of to the log.
//!
//! # What is deliberately not here
//!
//! **No new record kind, and no field on an existing one.** A manifest is
//! derived from bytes: anyone can compute one for any content, so holding one
//! proves nothing and signing one would be signing an arithmetic fact. It is
//! connected to the network the same way a piece manifest is —
//! [`Manifest::describes`] asks whether it describes a digest the log already
//! pinned, and that question is the whole of its trust. Adding a record would
//! move canonical bytes and both implementations (`AGENTS.md`) to gain nothing.
//!
//! **No network transfer.** Shards are produced, stored, proved and
//! reconstructed here; moving one between peers is [`crate::swarm`]'s job and is
//! not wired up. Said plainly because this crate has been bitten before by a
//! subsystem tested only against itself — see `docs/storage.md` on the two bugs
//! that sat in the `swarm`/`blobs` seam. `proofwork shard` is the caller that
//! keeps this module honest until a transfer path exists.
//!
//! **No repair.** Regenerating a lost shard means reconstructing the blob and
//! re-encoding it, which is what [`reconstruct`] plus [`encode`] already do.
//! Regenerating codes that repair from less than `k` shards are a real
//! improvement and a much larger one; they are not needed to hold six shards on
//! six disks.

pub mod store;

use std::collections::BTreeSet;
use std::fmt;

use crate::canonical::{digest_bytes, merkle_proof, merkle_root, Inclusion, Value};
use crate::crypto::gf;
use crate::hex;

pub use store::{ShardStore, ShardStoreError};

// -- bounds ------------------------------------------------------------------

/// Default bytes per chunk.
///
/// The chunk is the unit of *proof*, not of transfer, so the pressure on it is
/// different from a piece length. Smaller means a cheaper challenge — a holder
/// answers with one chunk — and a deeper tree; larger means the opposite. 64 KiB
/// keeps a challenge response small enough to sit in a record and keeps a 1 GiB
/// shard under fourteen levels.
pub const DEFAULT_CHUNK_LEN: u32 = 64 * 1024;

/// Smallest chunk length a manifest may declare.
///
/// A manifest is attacker-supplied. `chunk_len = 1` is a denial of service made
/// of arithmetic: it asks a verifier to hash every byte of a shard individually
/// and build a tree with one leaf per byte.
pub const MIN_CHUNK_LEN: u32 = 4 * 1024;

/// Largest chunk length a manifest may declare.
pub const MAX_CHUNK_LEN: u32 = 4 * 1024 * 1024;

/// Largest blob this module will encode.
///
/// **A statement about memory, not about what is reasonable to store.**
/// [`encode`] is not streaming: it holds the blob and every shard at once,
/// roughly `(1 + (k + m) / k)` times the blob. At a gibibyte that is under three
/// gibibytes resident, which a laptop survives and a CI runner does not enjoy.
///
/// Raising it means making the encoder streaming first. It is checked against a
/// *declared* length wherever one exists, for the reason [`crate::blobs`] gives:
/// refusing after allocating is not a defence against a peer whose plan is to
/// make you allocate.
pub const MAX_CODED_BYTES: u64 = 1 << 30;

/// Most shards a coding may have, data and parity together.
///
/// The Cauchy construction needs `k + m` distinct elements of GF(2^8), which
/// caps it at 256; 255 is taken instead so a shard index is a `u8` with no
/// value doing double duty as a sentinel.
pub const MAX_SHARDS: u16 = 255;

/// What [`suggest_chunk_len`] aims for.
///
/// Not a bound — a preference. Beyond this the tree gets deeper without the
/// challenge getting cheaper, since a chunk's cost is its bytes and a level's
/// cost is one hash.
const TARGET_CHUNKS_PER_SHARD: u64 = 1024;

// -- errors ------------------------------------------------------------------

/// Why a coding, a manifest, or a reconstruction was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShardError {
    /// Zero data shards. There is nothing to split into no pieces.
    NoDataShards,
    /// Zero parity shards.
    ///
    /// Refused rather than accepted as "striping". A (k, 0) code tolerates no
    /// loss at all while looking exactly like one that does — an operator who
    /// asked for erasure coding and got plain striping would find out when a
    /// disk died.
    NoParityShards,
    /// More than [`MAX_SHARDS`] shards in total.
    TooManyShards { data: u8, parity: u8 },
    /// A chunk length outside [`MIN_CHUNK_LEN`]`..=`[`MAX_CHUNK_LEN`], or not a
    /// power of two.
    BadChunkLen { chunk_len: u32 },
    /// A blob above [`MAX_CODED_BYTES`].
    TooLarge { total: u64 },
    /// A manifest listing a number of shard roots its coding does not have.
    ShardCountMismatch { declared: usize, expected: usize },
    /// A shard root that is not a `sha256:` digest.
    NotADigest { index: u8 },
    /// A manifest field is missing or the wrong type.
    Malformed { field: &'static str },
    /// A shard index past the end of the coding.
    NoSuchShard { index: u8, shards: u8 },
    /// A chunk index past the end of a shard.
    NoSuchChunk { index: u32, chunks: u32 },
    /// A shard whose length is not the one the layout requires. Checked before
    /// anything is hashed.
    WrongShardLen { index: u8, expected: u64, got: u64 },
    /// Fewer verified shards than the coding needs.
    ///
    /// `have` counts shards that *passed* their chunk check, so this is the
    /// error a caller sees when enough holders lied, and `rejected` names them.
    NotEnoughShards {
        have: usize,
        need: usize,
        rejected: Vec<u8>,
    },
    /// The reconstruction did not hash to the digest the manifest names.
    ///
    /// Unreachable through hostile input alone — every shard used was checked
    /// against the manifest first — so this fires for a bug in the linear
    /// algebra, which is the class of bug that otherwise produces plausible
    /// garbage. See [`reconstruct`].
    DigestMismatch { declared: String, actual: String },
    /// An invariant this module establishes *before* relying on it was violated
    /// anyway — reachable only through a bug in this file.
    ///
    /// An error rather than a `panic!`, for the reason
    /// [`crate::crypto::shamir`] gives: a panic in a reconstruction path costs
    /// the whole operation, and a bug here should cost one attempt and a loud
    /// message.
    Invariant(&'static str),
}

impl fmt::Display for ShardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ShardError::NoDataShards => f.write_str("a coding needs at least one data shard"),
            ShardError::NoParityShards => f.write_str(
                "a coding needs at least one parity shard; zero parity tolerates no loss \
                 and only looks like erasure coding",
            ),
            ShardError::TooManyShards { data, parity } => write!(
                f,
                "{data} data + {parity} parity is more than the {MAX_SHARDS} shards \
                 GF(2^8) can index"
            ),
            ShardError::BadChunkLen { chunk_len } => write!(
                f,
                "chunk length {chunk_len} is not a power of two in \
                 {MIN_CHUNK_LEN}..={MAX_CHUNK_LEN}"
            ),
            ShardError::TooLarge { total } => write!(
                f,
                "blob of {total} bytes exceeds the {MAX_CODED_BYTES} this encoder \
                 holds in memory"
            ),
            ShardError::ShardCountMismatch { declared, expected } => write!(
                f,
                "manifest lists {declared} shard roots, the declared coding has {expected}"
            ),
            ShardError::NotADigest { index } => {
                write!(f, "shard {index} is not named by a sha256 digest")
            }
            ShardError::Malformed { field } => {
                write!(f, "manifest field {field:?} is missing or malformed")
            }
            ShardError::NoSuchShard { index, shards } => {
                write!(f, "shard {index} of a coding that has {shards}")
            }
            ShardError::NoSuchChunk { index, chunks } => {
                write!(f, "chunk {index} of a shard that has {chunks}")
            }
            ShardError::WrongShardLen {
                index,
                expected,
                got,
            } => write!(
                f,
                "shard {index} is {got} bytes, the layout requires {expected}"
            ),
            ShardError::NotEnoughShards {
                have,
                need,
                rejected,
            } => {
                write!(f, "{have} verified shard(s), {need} needed")?;
                if !rejected.is_empty() {
                    write!(f, "; {} rejected as corrupt: ", rejected.len())?;
                    for (position, index) in rejected.iter().enumerate() {
                        if position > 0 {
                            f.write_str(", ")?;
                        }
                        write!(f, "{index}")?;
                    }
                }
                Ok(())
            }
            ShardError::DigestMismatch { declared, actual } => write!(
                f,
                "reconstruction hashes to {actual}, the manifest declares {declared}"
            ),
            ShardError::Invariant(what) => write!(f, "shards internal invariant violated: {what}"),
        }
    }
}

impl std::error::Error for ShardError {}

// -- coding ------------------------------------------------------------------

/// How many data shards and how many parity shards.
///
/// `Copy` and validated on construction, so every function below can take one
/// by value and none of them re-checks the bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Coding {
    data: u8,
    parity: u8,
}

impl Coding {
    /// `data`-of-`data + parity`: any `data` shards reconstruct.
    pub fn new(data: u8, parity: u8) -> Result<Coding, ShardError> {
        if data == 0 {
            return Err(ShardError::NoDataShards);
        }
        if parity == 0 {
            return Err(ShardError::NoParityShards);
        }
        if u16::from(data) + u16::from(parity) > MAX_SHARDS {
            return Err(ShardError::TooManyShards { data, parity });
        }
        Ok(Coding { data, parity })
    }

    pub fn data(&self) -> u8 {
        self.data
    }

    pub fn parity(&self) -> u8 {
        self.parity
    }

    /// Total shards. Fits a `u8` because [`Coding::new`] bounded the sum.
    pub fn shards(&self) -> u8 {
        self.data.saturating_add(self.parity)
    }

    /// Whether `index` names a shard that carries blob bytes verbatim.
    pub fn is_data(&self, index: u8) -> bool {
        index < self.data
    }

    /// How many losses this tolerates: exactly `parity`, by the MDS property of
    /// the Cauchy construction.
    ///
    /// Not a link, because `generator_row` — where that property is argued — is
    /// private, and rustdoc refuses a public page that points at one.
    pub fn tolerates(&self) -> u8 {
        self.parity
    }
}

impl fmt::Display for Coding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({}, {})", self.data, self.parity)
    }
}

// -- layout ------------------------------------------------------------------

/// How a blob of a given size divides into shards and chunks.
///
/// Arithmetic only, like [`crate::swarm::piece::Layout`], which is what lets a
/// holder reason about a shard it does not have.
///
/// **Every shard has the same length**, including the parity shards, which is
/// what makes one chunk geometry serve all of them. The cost is up to `k - 1`
/// bytes of zero padding on the last data shard; the alternative — ragged
/// shards — would need a second geometry for the short one and a special case
/// in every proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    total: u64,
    coding: Coding,
    chunk_len: u32,
}

impl Layout {
    /// Validated constructor.
    ///
    /// A zero-length blob is a real thing — the empty file has a digest like
    /// anything else — and every shard of it has *one* chunk of length zero
    /// rather than none, for the reason [`crate::swarm::piece::Layout::new`]
    /// gives: a tree with no leaves has no root, and a shard with no root
    /// cannot be committed to or proved.
    pub fn new(total: u64, coding: Coding, chunk_len: u32) -> Result<Layout, ShardError> {
        if !(MIN_CHUNK_LEN..=MAX_CHUNK_LEN).contains(&chunk_len) || !chunk_len.is_power_of_two() {
            return Err(ShardError::BadChunkLen { chunk_len });
        }
        if total > MAX_CODED_BYTES {
            return Err(ShardError::TooLarge { total });
        }
        Ok(Layout {
            total,
            coding,
            chunk_len,
        })
    }

    pub fn total(&self) -> u64 {
        self.total
    }

    pub fn coding(&self) -> Coding {
        self.coding
    }

    pub fn chunk_len(&self) -> u32 {
        self.chunk_len
    }

    /// Bytes in every shard, data and parity alike.
    pub fn shard_len(&self) -> u64 {
        self.total.div_ceil(u64::from(self.coding.data()))
    }

    /// Bytes on disk across all holders: `shard_len * (k + m)`.
    ///
    /// The number an operator is choosing when they choose a coding, so it is
    /// computed rather than left as an exercise.
    pub fn stored_bytes(&self) -> u64 {
        self.shard_len()
            .saturating_mul(u64::from(self.coding.shards()))
    }

    /// Chunks per shard. Always at least one.
    pub fn chunks(&self) -> u32 {
        if self.shard_len() == 0 {
            return 1;
        }
        // Bounded by MAX_CODED_BYTES / MIN_CHUNK_LEN = 256Ki, so the cast is
        // exact and `Layout::new` is what makes that true.
        self.shard_len().div_ceil(u64::from(self.chunk_len)) as u32
    }

    /// Byte offset of a chunk within its shard, or `None` past the end.
    pub fn chunk_offset(&self, chunk: u32) -> Option<u64> {
        if chunk >= self.chunks() {
            return None;
        }
        Some(u64::from(chunk) * u64::from(self.chunk_len))
    }

    /// Length of a chunk: the declared length, except the last, which is short.
    pub fn chunk_bytes(&self, chunk: u32) -> Option<u32> {
        let offset = self.chunk_offset(chunk)?;
        let remaining = self.shard_len().saturating_sub(offset);
        Some(remaining.min(u64::from(self.chunk_len)) as u32)
    }

    /// The slice of a shard belonging to a chunk.
    pub fn slice<'a>(&self, shard: &'a [u8], chunk: u32) -> Option<&'a [u8]> {
        let offset = usize::try_from(self.chunk_offset(chunk)?).ok()?;
        let len = self.chunk_bytes(chunk)? as usize;
        shard.get(offset..offset.checked_add(len)?)
    }

    /// Where chunk `chunk` of data shard `shard` sits in the original blob, or
    /// `None` for a parity shard, an index past the end, or a range that is
    /// entirely padding.
    ///
    /// The property in one function: a data shard's chunk is a contiguous slice
    /// of the blob, so a reader wanting one range checks one chunk against the
    /// root and never decodes anything. The end is clamped to `total`, because
    /// the last chunk of the last data shard runs into the zero padding.
    pub fn blob_range(&self, shard: u8, chunk: u32) -> Option<(u64, u64)> {
        if !self.coding.is_data(shard) {
            return None;
        }
        let start = u64::from(shard)
            .checked_mul(self.shard_len())?
            .checked_add(self.chunk_offset(chunk)?)?;
        if start >= self.total {
            return None;
        }
        let end = start
            .checked_add(u64::from(self.chunk_bytes(chunk)?))?
            .min(self.total);
        Some((start, end))
    }
}

/// A chunk length for a blob of this size: the smallest legal power of two that
/// keeps a shard under 1024 chunks.
///
/// The target is `TARGET_CHUNKS_PER_SHARD`, which is private, so the number is
/// written out here rather than linked — a public page cannot point at it, and
/// a reader of this signature wants the number anyway.
///
/// A convenience for `proofwork shard plan`, never a rule. Two nodes choosing
/// differently produce different manifests for one blob, which is fine — a
/// manifest is checked against the blob digest, not against another manifest.
pub fn suggest_chunk_len(total: u64, coding: Coding) -> u32 {
    let shard_len = total.div_ceil(u64::from(coding.data()));
    let mut chunk_len = MIN_CHUNK_LEN;
    while chunk_len < MAX_CHUNK_LEN
        && shard_len.div_ceil(u64::from(chunk_len)) > TARGET_CHUNKS_PER_SHARD
    {
        chunk_len *= 2;
    }
    chunk_len
}

// -- the code ----------------------------------------------------------------

/// Row `index` of the generator matrix, over the `k` data shards.
///
/// The matrix is systematic: rows `0..k` are the identity, so data shard `j`
/// *is* the `j`-th block of the blob and a reader who has all `k` of them
/// concatenates rather than decoding. Rows `k..k+m` are a Cauchy matrix,
/// `C[p][j] = 1 / (x_p ⊕ y_j)` with `x_p = k + p` and `y_j = j` — two disjoint
/// sets, so no denominator is zero.
///
/// # Why Cauchy, and why the MDS property is not an assumption
///
/// "Any `k` shards reconstruct" is precisely: every `k` rows of `[I ; C]` are
/// linearly independent. Expand the determinant along the identity rows and it
/// reduces to an `r × r` submatrix of `C`, where `r` is how many parity rows
/// were chosen. Every square submatrix of a Cauchy matrix is a Cauchy matrix,
/// and a Cauchy determinant is a product of differences of distinct elements
/// over a product of the same — nonzero in any field. So the property holds for
/// all `C(n, k)` subsets by construction, not by testing a few of them.
///
/// The alternative, a Vandermonde matrix made systematic by multiplying through
/// by the inverse of its top block, is equally MDS and is where implementations
/// get it wrong: *replacing* rows of a Vandermonde with identity rows, rather
/// than transforming the whole matrix, does not preserve the property and fails
/// only for some erasure patterns. Cauchy has no version of that mistake to
/// make.
fn generator_row(coding: Coding, index: u8) -> Option<Vec<u8>> {
    let k = usize::from(coding.data());
    if index >= coding.shards() {
        return None;
    }
    if coding.is_data(index) {
        let mut row = vec![0u8; k];
        *row.get_mut(usize::from(index))? = 1;
        return Some(row);
    }
    let x = index; // = k + p, and index >= k here
    let mut row = Vec::with_capacity(k);
    for column in 0..k {
        // `column < k <= x`, so the two are distinct integers and the XOR of
        // distinct bytes is never zero -- which is the entire reason the two
        // index sets are disjoint.
        let y = u8::try_from(column).ok()?;
        row.push(gf::inv(x ^ y)?);
    }
    Some(row)
}

/// Invert a `k × k` matrix over GF(2^8) by Gauss–Jordan, or `None` if singular.
///
/// `None` is unreachable for a matrix built from distinct generator rows — that
/// is what MDS means — so a caller turns it into
/// [`ShardError::Invariant`] rather than into a user-facing failure. It is
/// reachable through *duplicate* rows, which is why [`reconstruct`] deduplicates
/// shard indices before it gets here: a peer offering shard 3 twice would
/// otherwise fill two slots of the matrix with one row.
fn invert(mut matrix: Vec<Vec<u8>>) -> Option<Vec<Vec<u8>>> {
    let size = matrix.len();
    let mut inverse: Vec<Vec<u8>> = (0..size)
        .map(|row| {
            let mut unit = vec![0u8; size];
            if let Some(slot) = unit.get_mut(row) {
                *slot = 1;
            }
            unit
        })
        .collect();

    for column in 0..size {
        let pivot = (column..size).find(|&row| {
            matrix
                .get(row)
                .and_then(|r| r.get(column))
                .is_some_and(|&value| value != 0)
        })?;
        matrix.swap(column, pivot);
        inverse.swap(column, pivot);

        let head = *matrix.get(column)?.get(column)?;
        let scale = gf::Row::of(gf::inv(head)?);
        for value in matrix.get_mut(column)?.iter_mut() {
            *value = scale.apply(*value);
        }
        for value in inverse.get_mut(column)?.iter_mut() {
            *value = scale.apply(*value);
        }

        // Cloned rather than split-borrowed. `size` is at most 255 bytes and
        // this runs `k` times per decode, so the copy is free next to the
        // per-byte work, and it keeps the elimination readable.
        let pivot_matrix = matrix.get(column)?.clone();
        let pivot_inverse = inverse.get(column)?.clone();
        for row in 0..size {
            if row == column {
                continue;
            }
            let factor = *matrix.get(row)?.get(column)?;
            if factor == 0 {
                continue;
            }
            let factor = gf::Row::of(factor);
            factor.mul_add(matrix.get_mut(row)?, &pivot_matrix);
            factor.mul_add(inverse.get_mut(row)?, &pivot_inverse);
        }
    }
    Some(inverse)
}

// -- shards ------------------------------------------------------------------

/// One shard: its index in the coding, and its bytes.
///
/// Both fields are public because a shard is a wire and disk object, and a
/// `Shard` built by hand is not validated — [`Manifest::verify_shard`] is the
/// check, and nothing downstream trusts these fields without it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shard {
    pub index: u8,
    pub bytes: Vec<u8>,
}

impl Shard {
    pub fn new(index: u8, bytes: Vec<u8>) -> Shard {
        Shard { index, bytes }
    }
}

/// What [`encode`] produces: the commitment, and the bytes it commits to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Encoded {
    pub manifest: Manifest,
    pub shards: Vec<Shard>,
}

/// Split `data` into shards and commit to every chunk of every one.
///
/// The digest in the manifest is computed here rather than taken on trust,
/// which is what makes [`Manifest::describes`] a question worth asking of a
/// manifest that arrives from somewhere else.
pub fn encode(data: &[u8], coding: Coding, chunk_len: u32) -> Result<Encoded, ShardError> {
    let layout = Layout::new(data.len() as u64, coding, chunk_len)?;
    let shard_len = usize::try_from(layout.shard_len())
        .map_err(|_| ShardError::Invariant("shard length does not fit this platform's usize"))?;

    let mut bytes: Vec<Vec<u8>> = Vec::with_capacity(usize::from(coding.shards()));
    for index in 0..coding.data() {
        // Blocks, not interleaved symbols: this is what makes a data shard's
        // chunk a contiguous slice of the blob. The tail is zero padding, and
        // `total` in the manifest is what removes it again.
        let start = usize::from(index).saturating_mul(shard_len);
        let mut shard = vec![0u8; shard_len];
        if let Some(source) = data.get(start..data.len().min(start.saturating_add(shard_len))) {
            if let Some(slot) = shard.get_mut(..source.len()) {
                slot.copy_from_slice(source);
            }
        }
        bytes.push(shard);
    }
    for index in coding.data()..coding.shards() {
        let row = generator_row(coding, index)
            .ok_or(ShardError::Invariant("no generator row for a valid index"))?;
        let mut parity = vec![0u8; shard_len];
        for (column, &coefficient) in row.iter().enumerate() {
            let source = bytes
                .get(column)
                .ok_or(ShardError::Invariant("generator row wider than the coding"))?;
            gf::Row::of(coefficient).mul_add(&mut parity, source);
        }
        bytes.push(parity);
    }

    let roots = bytes
        .iter()
        .map(|shard| shard_root(&layout, shard))
        .collect::<Result<Vec<String>, ShardError>>()?;

    let manifest = Manifest {
        digest: digest_bytes(data),
        layout,
        roots,
    };
    let shards = bytes
        .into_iter()
        .enumerate()
        .map(|(index, bytes)| {
            Ok(Shard {
                index: u8::try_from(index)
                    .map_err(|_| ShardError::Invariant("shard index above 255"))?,
                bytes,
            })
        })
        .collect::<Result<Vec<Shard>, ShardError>>()?;
    Ok(Encoded { manifest, shards })
}

/// Merkle root over one shard's chunk digests.
fn shard_root(layout: &Layout, shard: &[u8]) -> Result<String, ShardError> {
    let leaves: Vec<String> = (0..layout.chunks())
        .map(|chunk| digest_bytes(layout.slice(shard, chunk).unwrap_or(&[])))
        .collect();
    merkle_root(&leaves).ok_or(ShardError::Invariant("a shard with no chunks"))
}

// -- manifest ----------------------------------------------------------------

/// The commitment: what the blob is, how it was cut, and one Merkle root per
/// shard.
///
/// Untrusted by construction. Anyone can compute one for any bytes, so holding
/// one proves nothing and there is nothing here to sign.
/// [`Manifest::describes`] is what connects it to a digest the log already
/// fixed, and nothing should accept a manifest without asking that question
/// first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    digest: String,
    layout: Layout,
    roots: Vec<String>,
}

impl Manifest {
    /// Rebuild a manifest received from somewhere else, checking its internal
    /// shape.
    ///
    /// Says nothing about whether the roots are the *right* ones; that cannot
    /// be known until bytes arrive. What it rules out is a manifest whose
    /// numbers disagree with each other, which is the cheap half and the half
    /// that would otherwise become an allocation bug.
    pub fn new(
        digest: impl Into<String>,
        total: u64,
        coding: Coding,
        chunk_len: u32,
        roots: Vec<String>,
    ) -> Result<Manifest, ShardError> {
        let layout = Layout::new(total, coding, chunk_len)?;
        let expected = usize::from(coding.shards());
        if roots.len() != expected {
            return Err(ShardError::ShardCountMismatch {
                declared: roots.len(),
                expected,
            });
        }
        for (index, root) in roots.iter().enumerate() {
            if !is_digest(root) {
                return Err(ShardError::NotADigest {
                    index: u8::try_from(index)
                        .map_err(|_| ShardError::Invariant("shard index above 255"))?,
                });
            }
        }
        Ok(Manifest {
            digest: digest.into(),
            layout,
            roots,
        })
    }

    /// The whole-blob digest. **The ground truth**, exactly as in
    /// [`crate::swarm::piece`]: everything else here localises a lie, and this
    /// is what says a lie was told.
    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn layout(&self) -> Layout {
        self.layout
    }

    pub fn coding(&self) -> Coding {
        self.layout.coding()
    }

    pub fn roots(&self) -> &[String] {
        &self.roots
    }

    pub fn shard_root(&self, index: u8) -> Option<&str> {
        self.roots.get(usize::from(index)).map(String::as_str)
    }

    /// Merkle root over the shard roots — the top of the two-level tree, and
    /// the only thing a verifier needs in order to check a [`ChunkProof`].
    ///
    /// Uses [`crate::canonical::merkle_root`], so it inherits the promotion rule
    /// for odd nodes and with it the defence against the second-preimage attack
    /// that duplicating the last leaf enables.
    pub fn root(&self) -> String {
        // `roots` is non-empty for every constructible Coding, so the `None`
        // arm is unreachable; the digest of nothing is the honest fallback and
        // costs one line rather than an unwrap.
        merkle_root(&self.roots).unwrap_or_else(|| digest_bytes(&[]))
    }

    /// Canonical encoding, so a manifest has a content address like everything
    /// else in this crate.
    pub fn to_value(&self) -> Value {
        Value::object([
            ("chunk_len", Value::Int(i128::from(self.layout.chunk_len()))),
            ("data", Value::Int(i128::from(self.coding().data()))),
            ("digest", Value::string(&self.digest)),
            ("parity", Value::Int(i128::from(self.coding().parity()))),
            ("shards", Value::array(self.roots.iter().map(Value::string))),
            ("total", Value::Int(i128::from(self.layout.total()))),
        ])
    }

    /// The manifest's own content address.
    ///
    /// Covers the coding and the geometry as well as the roots, which is the
    /// point: the same shard bytes under a different `chunk_len` are a different
    /// tree, and two manifests that shared an id while disagreeing about that
    /// would be two readings of one name.
    pub fn id(&self) -> String {
        self.to_value().digest()
    }

    /// Decode a manifest, validating as [`Manifest::new`] does.
    pub fn from_value(value: &Value) -> Result<Manifest, ShardError> {
        let digest = value
            .get("digest")
            .and_then(Value::as_str)
            .ok_or(ShardError::Malformed { field: "digest" })?;
        let total = value
            .get("total")
            .and_then(Value::as_u64)
            .ok_or(ShardError::Malformed { field: "total" })?;
        let data = small(value, "data")?;
        let parity = small(value, "parity")?;
        let chunk_len = value
            .get("chunk_len")
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .ok_or(ShardError::Malformed { field: "chunk_len" })?;
        let roots = match value.get("shards") {
            Some(Value::Array(items)) => items
                .iter()
                .map(|item| {
                    item.as_str()
                        .map(str::to_string)
                        .ok_or(ShardError::Malformed { field: "shards" })
                })
                .collect::<Result<Vec<String>, ShardError>>()?,
            _ => return Err(ShardError::Malformed { field: "shards" }),
        };
        Manifest::new(digest, total, Coding::new(data, parity)?, chunk_len, roots)
    }

    /// Does this manifest claim to describe `digest`?
    ///
    /// The only question that matters when a manifest arrives from a stranger,
    /// because the answer connects it to something the log already fixed.
    /// Tolerant of both spellings — `sha256:`-prefixed as
    /// [`crate::canonical`] writes them, and bare as a verifier pin declares
    /// them — because the two ends of this comparison come from different
    /// halves of the crate, and a mismatch there once made every fetch fail
    /// with "no peer could be reached". See `docs/storage.md`.
    pub fn describes(&self, digest: &str) -> bool {
        let want = digest.strip_prefix("sha256:").unwrap_or(digest);
        let have = self.digest.strip_prefix("sha256:").unwrap_or(&self.digest);
        want.eq_ignore_ascii_case(have)
    }

    /// Are these the bytes of shard `shard.index`?
    ///
    /// Length first, then the tree. A shard of the wrong length is a lie that
    /// costs nothing to detect, and hashing first would let a holder make a node
    /// do work proportional to whatever it felt like sending.
    ///
    /// This is the gate [`reconstruct`] puts in front of the linear algebra. A
    /// shard that fails it never enters the combination, which is what keeps one
    /// liar from corrupting every output byte.
    pub fn verify_shard(&self, shard: &Shard) -> bool {
        let Some(expected) = self.shard_root(shard.index) else {
            return false;
        };
        if shard.bytes.len() as u64 != self.layout.shard_len() {
            return false;
        }
        match shard_root(&self.layout, &shard.bytes) {
            Ok(actual) => actual == expected,
            Err(_) => false,
        }
    }

    /// A proof that `chunk` of this shard is under [`Manifest::root`].
    ///
    /// `None` for an index out of range. The shard's bytes are not checked
    /// here — a prover proves what it holds, and a prover that holds the wrong
    /// bytes produces a proof that fails.
    pub fn prove_chunk(&self, shard: &Shard, chunk: u32) -> Option<ChunkProof> {
        if usize::from(shard.index) >= self.roots.len() {
            return None;
        }
        if shard.bytes.len() as u64 != self.layout.shard_len() {
            return None;
        }
        let leaves: Vec<String> = (0..self.layout.chunks())
            .map(|index| digest_bytes(self.layout.slice(&shard.bytes, index).unwrap_or(&[])))
            .collect();
        let within_shard = merkle_proof(&leaves, usize::try_from(chunk).ok()?)?;
        let across_shards = merkle_proof(&self.roots, usize::from(shard.index))?;
        Some(ChunkProof {
            shard: shard.index,
            chunk,
            bytes: self.layout.slice(&shard.bytes, chunk)?.to_vec(),
            shard_root: merkle_root(&leaves)?,
            within_shard,
            across_shards,
        })
    }

    /// Check a proof against this manifest.
    ///
    /// Stronger than [`ChunkProof::verify`] and the one to prefer when the
    /// manifest is in hand: it also checks the chunk's *geometry* — that the
    /// shard and chunk indices exist in this coding, that the chunk is the
    /// length this layout says it is, and that the proof's shard root is the one
    /// this manifest lists. A proof can satisfy the root alone while describing
    /// a tree of a different shape; here it cannot.
    pub fn verify_chunk(&self, proof: &ChunkProof) -> bool {
        let Some(expected_root) = self.shard_root(proof.shard) else {
            return false;
        };
        if proof.shard_root != expected_root {
            return false;
        }
        let Some(expected_len) = self.layout.chunk_bytes(proof.chunk) else {
            return false;
        };
        if proof.bytes.len() != expected_len as usize {
            return false;
        }
        if proof.within_shard.leaves != self.layout.chunks() as usize
            || proof.across_shards.leaves != self.roots.len()
        {
            return false;
        }
        proof.verify(&self.root())
    }
}

/// One chunk, and the two hops that put it under a manifest root.
///
/// Carries its bytes rather than their digest: a proof of a hash is a proof
/// about a hash, and the reason `docs/roadmap.md` records for the availability
/// answer applies here too — an answer carrying only a path can be produced by
/// somebody holding the hashes and none of the content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkProof {
    pub shard: u8,
    pub chunk: u32,
    /// The chunk itself.
    pub bytes: Vec<u8>,
    /// The root of the shard this chunk belongs to — the join between the two
    /// hops, and the leaf of the outer one.
    pub shard_root: String,
    /// Chunk digest up to [`ChunkProof::shard_root`].
    pub within_shard: Inclusion,
    /// Shard root up to the manifest root.
    pub across_shards: Inclusion,
}

impl ChunkProof {
    /// Walk both hops and report whether they arrive at `root`.
    ///
    /// **Membership only.** This convinces a verifier who holds nothing but the
    /// 32-byte root — which is the case the outer hop exists for — that these
    /// bytes are the chunk at this position of some tree with that root. It
    /// cannot check the *geometry*, because the geometry lives in the manifest:
    /// the chunk's expected length and the shard's declared root are not
    /// derivable from a root alone. A verifier holding the manifest should call
    /// [`Manifest::verify_chunk`], which checks both.
    ///
    /// The leaf is recomputed from `bytes` rather than taken from the proof,
    /// which is what keeps [`crate::canonical::Inclusion`]'s second-preimage
    /// caveat off this path: a prover cannot offer an internal node as a leaf
    /// when the verifier hashes the leaf itself.
    pub fn verify(&self, root: &str) -> bool {
        let leaf = digest_bytes(&self.bytes);
        if self.within_shard.index != self.chunk as usize
            || self.across_shards.index != usize::from(self.shard)
        {
            return false;
        }
        if !self.within_shard.verify(&leaf, &self.shard_root) {
            return false;
        }
        self.across_shards.verify(&self.shard_root, root)
    }

    /// Canonical encoding, so a proof can be written down, mailed, and checked
    /// by something that was not running when it was made.
    pub fn to_value(&self) -> Value {
        Value::object([
            (
                "across_shards",
                Value::array(self.across_shards.siblings.iter().map(Value::string)),
            ),
            ("bytes", Value::string(hex::encode(&self.bytes))),
            ("chunk", Value::Int(i128::from(self.chunk))),
            ("leaves", Value::Int(self.within_shard.leaves as i128)),
            ("shard", Value::Int(i128::from(self.shard))),
            ("shard_root", Value::string(&self.shard_root)),
            ("shards", Value::Int(self.across_shards.leaves as i128)),
            (
                "within_shard",
                Value::array(self.within_shard.siblings.iter().map(Value::string)),
            ),
        ])
    }

    /// Decode a proof.
    ///
    /// The two `leaves` counts are shape parameters, exactly as
    /// [`crate::canonical::Inclusion`] documents: they decide which levels
    /// promote, so a verifier needs them to walk the path at all. They are not a
    /// second commitment, and a count that reshapes the walk simply fails to
    /// reach the root.
    pub fn from_value(value: &Value) -> Result<ChunkProof, ShardError> {
        let shard = small(value, "shard")?;
        let chunk = value
            .get("chunk")
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .ok_or(ShardError::Malformed { field: "chunk" })?;
        let bytes = value
            .get("bytes")
            .and_then(Value::as_str)
            .and_then(unhex)
            .ok_or(ShardError::Malformed { field: "bytes" })?;
        let shard_root = value
            .get("shard_root")
            .and_then(Value::as_str)
            .filter(|text| is_digest(text))
            .ok_or(ShardError::Malformed {
                field: "shard_root",
            })?
            .to_string();
        let leaves = usize::try_from(
            value
                .get("leaves")
                .and_then(Value::as_u64)
                .ok_or(ShardError::Malformed { field: "leaves" })?,
        )
        .map_err(|_| ShardError::Malformed { field: "leaves" })?;
        let shards = usize::try_from(
            value
                .get("shards")
                .and_then(Value::as_u64)
                .ok_or(ShardError::Malformed { field: "shards" })?,
        )
        .map_err(|_| ShardError::Malformed { field: "shards" })?;
        Ok(ChunkProof {
            shard,
            chunk,
            bytes,
            shard_root,
            within_shard: Inclusion {
                index: chunk as usize,
                leaves,
                siblings: digests(value, "within_shard")?,
            },
            across_shards: Inclusion {
                index: usize::from(shard),
                leaves: shards,
                siblings: digests(value, "across_shards")?,
            },
        })
    }
}

// -- reconstruction ----------------------------------------------------------

/// What came back, and who lied on the way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reconstruction {
    /// The blob, truncated to the manifest's declared length and checked
    /// against its declared digest.
    pub data: Vec<u8>,
    /// The shard indices whose bytes went into the answer, ascending.
    pub used: Vec<u8>,
    /// The shard indices offered whose bytes did not match the manifest,
    /// ascending.
    ///
    /// **This is the output that justifies the design.** Under replication a
    /// bad copy names itself; under plain coding it does not, and this list is
    /// how it is made to. A caller with somewhere to put it — a peer scorer, a
    /// slashing rule — has provable misbehaviour attributed to a specific
    /// holder, with the root that convicts them fixed before the transfer began.
    pub rejected: Vec<u8>,
}

/// Rebuild the blob from any `k` verified shards.
///
/// The order is the whole design:
///
/// 1. **Check every offered shard against the manifest.** Wrong length, or
///    chunks that do not rebuild the shard's committed root, and it is dropped
///    and named. Nothing unchecked reaches step 3.
/// 2. **Deduplicate by index.** Two copies of shard 3 are one row of the
///    generator matrix twice, which is singular; a holder offering the same
///    shard twice must not be able to make the decode fail.
/// 3. **Recover.** All `k` data shards present is a concatenation. Otherwise
///    invert the `k × k` matrix of the chosen rows and multiply.
/// 4. **Re-hash the result** against the manifest's digest.
///
/// Step 4 is redundant against hostile input — every byte was already checked
/// under step 1 — and is kept because it is not redundant against *this file*.
/// A wrong Cauchy coefficient or a mis-eliminated pivot produces a plausible
/// byte string rather than an error, which is the same trap
/// [`crate::crypto::shamir`] documents for a short reconstruction. The check
/// costs one pass and converts a silent wrong answer into a loud one.
pub fn reconstruct(manifest: &Manifest, offered: &[Shard]) -> Result<Reconstruction, ShardError> {
    let coding = manifest.coding();
    let need = usize::from(coding.data());
    let layout = manifest.layout();

    let mut verified: Vec<&Shard> = Vec::new();
    let mut rejected: BTreeSet<u8> = BTreeSet::new();
    let mut seen: BTreeSet<u8> = BTreeSet::new();
    for shard in offered {
        if !manifest.verify_shard(shard) {
            rejected.insert(shard.index);
            continue;
        }
        // Verified *and* new. A duplicate of a good shard is not misbehaviour,
        // so it is silently ignored rather than reported as a rejection.
        if seen.insert(shard.index) {
            verified.push(shard);
        }
    }
    let rejected: Vec<u8> = rejected.into_iter().collect();

    // Data shards first, so the common partial-loss case picks the rows closest
    // to the identity and the inverse has the least work to do.
    verified.sort_by_key(|shard| (!coding.is_data(shard.index), shard.index));
    if verified.len() < need {
        return Err(ShardError::NotEnoughShards {
            have: verified.len(),
            need,
            rejected,
        });
    }
    verified.truncate(need);

    let shard_len = usize::try_from(layout.shard_len())
        .map_err(|_| ShardError::Invariant("shard length does not fit this platform's usize"))?;
    let mut recovered: Vec<Vec<u8>> = Vec::with_capacity(need);
    if verified
        .iter()
        .all(|shard| coding.is_data(shard.index) && usize::from(shard.index) < need)
        && verified.len() == need
    {
        // Every data shard is present: the code is systematic, so there is
        // nothing to solve.
        let mut ordered = verified.clone();
        ordered.sort_by_key(|shard| shard.index);
        for shard in ordered {
            recovered.push(shard.bytes.clone());
        }
    } else {
        let rows = verified
            .iter()
            .map(|shard| {
                generator_row(coding, shard.index).ok_or(ShardError::Invariant(
                    "no generator row for a verified shard",
                ))
            })
            .collect::<Result<Vec<Vec<u8>>, ShardError>>()?;
        let solution = invert(rows).ok_or(ShardError::Invariant(
            "a singular submatrix of an MDS generator",
        ))?;
        for row in solution.iter().take(need) {
            let mut out = vec![0u8; shard_len];
            for (column, &coefficient) in row.iter().enumerate() {
                if coefficient == 0 {
                    continue;
                }
                let source = verified
                    .get(column)
                    .ok_or(ShardError::Invariant("inverse wider than the shard set"))?;
                gf::Row::of(coefficient).mul_add(&mut out, &source.bytes);
            }
            recovered.push(out);
        }
    }

    let total = usize::try_from(layout.total())
        .map_err(|_| ShardError::Invariant("blob length does not fit this platform's usize"))?;
    let mut data = Vec::with_capacity(total);
    for shard in &recovered {
        data.extend_from_slice(shard);
    }
    if data.len() < total {
        return Err(ShardError::Invariant(
            "recovered shards are shorter than the declared blob",
        ));
    }
    data.truncate(total);

    let actual = digest_bytes(&data);
    if !manifest.describes(&actual) {
        return Err(ShardError::DigestMismatch {
            declared: manifest.digest().to_string(),
            actual,
        });
    }

    let mut used: Vec<u8> = verified.iter().map(|shard| shard.index).collect();
    used.sort_unstable();
    Ok(Reconstruction {
        data,
        used,
        rejected,
    })
}

// -- encoding helpers --------------------------------------------------------

/// `sha256:` followed by 64 lowercase hex characters.
fn is_digest(text: &str) -> bool {
    let Some(hex) = text.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A `u8` field, refused rather than truncated when it does not fit.
fn small(value: &Value, field: &'static str) -> Result<u8, ShardError> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .and_then(|n| u8::try_from(n).ok())
        .ok_or(ShardError::Malformed { field })
}

/// An array of `sha256:` digests.
fn digests(value: &Value, field: &'static str) -> Result<Vec<String>, ShardError> {
    match value.get(field) {
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_str()
                    .filter(|text| is_digest(text))
                    .map(str::to_string)
                    .ok_or(ShardError::Malformed { field })
            })
            .collect(),
        _ => Err(ShardError::Malformed { field }),
    }
}

/// Lowercase hex to bytes. Uppercase is refused for the reason
/// [`crate::blobs::is_address`] gives: two spellings of one string are two
/// names for one thing.
fn unhex(text: &str) -> Option<Vec<u8>> {
    fn digit(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        }
    }
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let [high, low] = pair else { return None };
        out.push((digit(*high)? << 4) | digit(*low)?);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blob(len: usize) -> Vec<u8> {
        // Not zeros: a bug that drops a shard is invisible against zeros,
        // because a dropped shard *is* zeros.
        (0..len).map(|i| ((i * 7 + i / 251) % 251) as u8).collect()
    }

    fn coding(data: u8, parity: u8) -> Coding {
        Coding::new(data, parity).expect("valid coding")
    }

    // -- the property the whole module exists for --------------------------

    #[test]
    fn every_subset_of_k_shards_reconstructs() {
        // MDS is a claim about all C(n, k) subsets, so it is checked over all
        // of them rather than over a few. (6, 3) has C(9, 6) = 84.
        let data = blob(MIN_CHUNK_LEN as usize * 2 + 91);
        let encoded = encode(&data, coding(6, 3), MIN_CHUNK_LEN).expect("encode");
        let all = &encoded.shards;
        assert_eq!(all.len(), 9);

        let mut subsets = 0;
        for mask in 0u32..(1 << 9) {
            if mask.count_ones() != 6 {
                continue;
            }
            let chosen: Vec<Shard> = (0..9)
                .filter(|i| mask & (1 << i) != 0)
                .filter_map(|i| all.get(i).cloned())
                .collect();
            let out = reconstruct(&encoded.manifest, &chosen)
                .unwrap_or_else(|error| panic!("subset {mask:b}: {error}"));
            assert_eq!(out.data, data, "subset {mask:b}");
            assert!(out.rejected.is_empty());
            subsets += 1;
        }
        assert_eq!(subsets, 84);
    }

    #[test]
    fn any_k_reconstruct_across_a_range_of_codings_and_sizes() {
        for (k, m) in [(1u8, 1u8), (2, 1), (3, 2), (4, 2), (8, 4), (2, 8)] {
            for len in [
                0,
                1,
                7,
                MIN_CHUNK_LEN as usize - 1,
                MIN_CHUNK_LEN as usize,
                MIN_CHUNK_LEN as usize * 3 + 5,
            ] {
                let data = blob(len);
                let code = coding(k, m);
                let encoded = encode(&data, code, MIN_CHUNK_LEN).expect("encode");
                // The worst case for a systematic code: keep the parity shards
                // and throw away as many data shards as the code tolerates.
                let kept: Vec<Shard> = encoded
                    .shards
                    .iter()
                    .skip(usize::from(m))
                    .take(usize::from(k))
                    .cloned()
                    .collect();
                let out = reconstruct(&encoded.manifest, &kept)
                    .unwrap_or_else(|error| panic!("({k},{m}) at {len} bytes: {error}"));
                assert_eq!(out.data, data, "({k},{m}) at {len} bytes");
            }
        }
    }

    #[test]
    fn losing_more_than_the_parity_count_is_a_refusal_and_not_a_wrong_answer() {
        let data = blob(MIN_CHUNK_LEN as usize + 3);
        let encoded = encode(&data, coding(4, 2), MIN_CHUNK_LEN).expect("encode");
        let kept: Vec<Shard> = encoded.shards.iter().take(3).cloned().collect();
        assert_eq!(
            reconstruct(&encoded.manifest, &kept).unwrap_err(),
            ShardError::NotEnoughShards {
                have: 3,
                need: 4,
                rejected: vec![]
            }
        );
    }

    // -- the reason for the Merkle half ------------------------------------

    #[test]
    fn one_corrupt_shard_is_named_and_excluded_rather_than_corrupting_the_output() {
        // The argument in the module docs, as a test. Without the per-chunk
        // check this shard enters the linear combination and every output byte
        // is wrong, with the blob digest reporting only that somebody lied.
        let data = blob(MIN_CHUNK_LEN as usize * 2 + 40);
        let encoded = encode(&data, coding(4, 2), MIN_CHUNK_LEN).expect("encode");

        let mut offered = encoded.shards.clone();
        // A liar that flips one byte in the middle of a chunk -- the subtlest
        // version, and the one a length check would miss.
        let victim = offered.get_mut(1).expect("shard 1");
        let byte = victim.bytes.get_mut(9).expect("byte 9");
        *byte ^= 0x01;

        let out = reconstruct(&encoded.manifest, &offered).expect("reconstruct");
        assert_eq!(out.data, data, "the liar did not reach the output");
        assert_eq!(out.rejected, vec![1], "and it was named");
        assert!(!out.used.contains(&1));
    }

    #[test]
    fn corruption_past_the_parity_budget_refuses_and_names_every_liar() {
        let data = blob(MIN_CHUNK_LEN as usize * 2);
        let encoded = encode(&data, coding(4, 2), MIN_CHUNK_LEN).expect("encode");
        let mut offered = encoded.shards.clone();
        for index in [0usize, 2, 5] {
            if let Some(shard) = offered.get_mut(index) {
                if let Some(byte) = shard.bytes.first_mut() {
                    *byte ^= 0xff;
                }
            }
        }
        assert_eq!(
            reconstruct(&encoded.manifest, &offered).unwrap_err(),
            ShardError::NotEnoughShards {
                have: 3,
                need: 4,
                rejected: vec![0, 2, 5]
            }
        );
    }

    #[test]
    fn a_shard_of_the_wrong_length_is_refused_before_it_is_hashed() {
        let data = blob(MIN_CHUNK_LEN as usize * 2);
        let encoded = encode(&data, coding(3, 2), MIN_CHUNK_LEN).expect("encode");
        let manifest = &encoded.manifest;
        let mut short = encoded.shards.first().cloned().expect("shard 0");
        short.bytes.truncate(4);
        assert!(!manifest.verify_shard(&short));
        let mut long = encoded.shards.first().cloned().expect("shard 0");
        long.bytes.push(0);
        assert!(!manifest.verify_shard(&long));
        // And an index that is not in the coding at all.
        let stranger = Shard::new(99, vec![0u8; manifest.layout().shard_len() as usize]);
        assert!(!manifest.verify_shard(&stranger));
    }

    #[test]
    fn a_duplicated_shard_does_not_fill_two_slots_of_the_matrix() {
        // A singular matrix is the failure this prevents: one generator row
        // twice cannot be inverted, so a holder offering the same shard four
        // times would otherwise turn a recoverable blob into an internal error.
        let data = blob(MIN_CHUNK_LEN as usize + 1);
        let encoded = encode(&data, coding(4, 2), MIN_CHUNK_LEN).expect("encode");
        let one = encoded.shards.get(2).cloned().expect("shard 2");
        let offered = vec![one.clone(), one.clone(), one.clone(), one];
        assert_eq!(
            reconstruct(&encoded.manifest, &offered).unwrap_err(),
            ShardError::NotEnoughShards {
                have: 1,
                need: 4,
                rejected: vec![]
            }
        );

        // And a duplicate alongside enough real shards is simply ignored: it is
        // not misbehaviour, so it is not reported as a rejection.
        let mut offered = encoded.shards.clone();
        offered.push(encoded.shards.first().cloned().expect("shard 0"));
        let out = reconstruct(&encoded.manifest, &offered).expect("reconstruct");
        assert_eq!(out.data, data);
        assert!(out.rejected.is_empty());
        assert_eq!(out.used.len(), 4);
    }

    // -- proofs ------------------------------------------------------------

    #[test]
    fn a_chunk_proof_verifies_against_the_root_alone() {
        let data = blob(MIN_CHUNK_LEN as usize * 5 + 17);
        let encoded = encode(&data, coding(3, 2), MIN_CHUNK_LEN).expect("encode");
        let manifest = &encoded.manifest;
        let root = manifest.root();

        for shard in &encoded.shards {
            for chunk in 0..manifest.layout().chunks() {
                let proof = manifest.prove_chunk(shard, chunk).expect("in range");
                assert!(
                    proof.verify(&root),
                    "shard {} chunk {chunk} against the root",
                    shard.index
                );
                assert!(
                    manifest.verify_chunk(&proof),
                    "shard {} chunk {chunk} against the manifest",
                    shard.index
                );
            }
        }
    }

    #[test]
    fn a_proof_for_one_chunk_does_not_verify_another() {
        let data = blob(MIN_CHUNK_LEN as usize * 4);
        let encoded = encode(&data, coding(2, 2), MIN_CHUNK_LEN).expect("encode");
        let manifest = &encoded.manifest;
        let root = manifest.root();
        let shard = encoded.shards.first().expect("shard 0");
        let mut proof = manifest.prove_chunk(shard, 0).expect("in range");

        // Real bytes from elsewhere in the same shard, under the same path.
        proof.bytes = manifest
            .layout()
            .slice(&shard.bytes, 1)
            .expect("chunk 1")
            .to_vec();
        assert!(!proof.verify(&root));
        assert!(!manifest.verify_chunk(&proof));

        // A real proof re-labelled for a different shard.
        let mut relabelled = manifest.prove_chunk(shard, 0).expect("in range");
        relabelled.shard = 1;
        assert!(!relabelled.verify(&root));
        assert!(!manifest.verify_chunk(&relabelled));

        // A real proof from another shard, offered with this shard's root.
        let other = encoded.shards.get(1).expect("shard 1");
        let mut swapped = manifest.prove_chunk(other, 0).expect("in range");
        swapped.shard_root = manifest.shard_root(0).expect("root 0").to_string();
        assert!(!swapped.verify(&root));
        assert!(!manifest.verify_chunk(&swapped));
    }

    #[test]
    fn a_truncated_or_padded_path_is_refused() {
        let data = blob(MIN_CHUNK_LEN as usize * 6);
        let encoded = encode(&data, coding(2, 1), MIN_CHUNK_LEN).expect("encode");
        let manifest = &encoded.manifest;
        let root = manifest.root();
        let shard = encoded.shards.first().expect("shard 0");
        let good = manifest.prove_chunk(shard, 1).expect("in range");
        assert!(good.verify(&root));

        let mut short = good.clone();
        short.within_shard.siblings.pop();
        assert!(!short.verify(&root));

        let mut padded = good.clone();
        padded.within_shard.siblings.push(digest_bytes(b"one more"));
        assert!(!padded.verify(&root));

        // A leaf count that genuinely reshapes the walk is refused by both
        // checks, because the path runs out of siblings.
        let mut reshaped = good.clone();
        reshaped.within_shard.leaves = 6;
        assert!(!reshaped.verify(&root));
        assert!(!manifest.verify_chunk(&reshaped));

        // A leaf count that does *not* reshape the walk is a different matter,
        // and this is the honest boundary between the two checks rather than a
        // hole in one of them. This shard has three chunks; a claim of four
        // promotes at the same levels for index 1, so the root-only check --
        // which has nothing but a root -- cannot tell them apart, exactly as
        // `canonical::Inclusion` says. The manifest knows how many chunks the
        // shard has, so it can and does.
        let mut interchangeable = good.clone();
        assert_eq!(manifest.layout().chunks(), 3);
        interchangeable.within_shard.leaves = 4;
        assert!(interchangeable.verify(&root));
        assert!(!manifest.verify_chunk(&interchangeable));
    }

    #[test]
    fn verify_chunk_catches_a_geometry_the_root_alone_cannot() {
        // The documented difference between the two checks. A one-chunk shard's
        // only leaf *is* its root, so a path of no hashes verifies against it --
        // and a manifest that says the shard has more chunks than that knows
        // better.
        let data = blob(64);
        let encoded = encode(&data, coding(2, 1), MIN_CHUNK_LEN).expect("encode");
        let manifest = &encoded.manifest;
        assert_eq!(manifest.layout().chunks(), 1);

        let shard = encoded.shards.first().expect("shard 0");
        let mut proof = manifest.prove_chunk(shard, 0).expect("in range");
        assert!(proof.verify(&manifest.root()));
        assert!(manifest.verify_chunk(&proof));

        // Same bytes, a claim about a tree of a different shape. Membership
        // still holds -- there is one leaf and it is the root -- and the
        // geometry does not.
        proof.within_shard.leaves = 2;
        assert!(!manifest.verify_chunk(&proof));
    }

    #[test]
    fn a_proof_round_trips_through_its_canonical_form() {
        let data = blob(MIN_CHUNK_LEN as usize * 3 + 8);
        let encoded = encode(&data, coding(3, 2), MIN_CHUNK_LEN).expect("encode");
        let manifest = &encoded.manifest;
        for shard in &encoded.shards {
            for chunk in 0..manifest.layout().chunks() {
                let proof = manifest.prove_chunk(shard, chunk).expect("in range");
                let decoded = ChunkProof::from_value(&proof.to_value()).expect("round trip");
                assert_eq!(decoded, proof);
                assert!(manifest.verify_chunk(&decoded));
            }
        }
        // And a malformed one is refused rather than half-decoded.
        let proof = manifest
            .prove_chunk(encoded.shards.first().expect("shard 0"), 0)
            .expect("in range");
        for field in [
            "shard",
            "chunk",
            "bytes",
            "shard_root",
            "leaves",
            "shards",
            "within_shard",
            "across_shards",
        ] {
            let mut body = proof.to_value().as_object().expect("object").clone();
            body.remove(field);
            assert!(
                ChunkProof::from_value(&Value::Object(body)).is_err(),
                "{field} must be required"
            );
        }
    }

    // -- layout ------------------------------------------------------------

    #[test]
    fn a_data_shards_chunk_is_a_contiguous_slice_of_the_blob() {
        // The range-read property. If this ever stops holding, shards are being
        // interleaved by symbol and a reader can no longer use one chunk alone.
        let data = blob(MIN_CHUNK_LEN as usize * 5 + 33);
        let encoded = encode(&data, coding(3, 2), MIN_CHUNK_LEN).expect("encode");
        let layout = encoded.manifest.layout();

        let mut covered = 0u64;
        for shard in 0..layout.coding().data() {
            for chunk in 0..layout.chunks() {
                let Some((start, end)) = layout.blob_range(shard, chunk) else {
                    continue;
                };
                let bytes = encoded
                    .shards
                    .get(usize::from(shard))
                    .and_then(|s| layout.slice(&s.bytes, chunk))
                    .expect("in range");
                let want = data
                    .get(start as usize..end as usize)
                    .expect("range inside the blob");
                assert_eq!(
                    bytes.get(..want.len()).expect("chunk covers the range"),
                    want,
                    "shard {shard} chunk {chunk}"
                );
                covered += end - start;
            }
        }
        assert_eq!(covered, data.len() as u64, "the data shards tile the blob");
        // Parity shards have no place in the blob, and neither does a chunk
        // past the end.
        assert_eq!(layout.blob_range(3, 0), None);
        assert_eq!(layout.blob_range(0, layout.chunks()), None);
    }

    #[test]
    fn every_shard_is_the_same_length_and_the_tail_is_padding() {
        let data = blob(1000);
        let encoded = encode(&data, coding(3, 2), MIN_CHUNK_LEN).expect("encode");
        let layout = encoded.manifest.layout();
        assert_eq!(layout.shard_len(), 334); // ceil(1000 / 3)
        assert_eq!(layout.stored_bytes(), 334 * 5);
        for shard in &encoded.shards {
            assert_eq!(shard.bytes.len(), 334);
        }
        // 3 * 334 = 1002, so the last data shard carries two padding bytes.
        let last = encoded.shards.get(2).expect("shard 2");
        assert_eq!(last.bytes.get(332..), Some(&[0u8, 0][..]));
        // And they do not survive the round trip.
        let out = reconstruct(&encoded.manifest, &encoded.shards).expect("reconstruct");
        assert_eq!(out.data.len(), 1000);
        assert_eq!(out.data, data);
    }

    #[test]
    fn the_empty_blob_has_one_chunk_per_shard_rather_than_none() {
        // A shard with no chunks has no root, and a shard with no root cannot
        // be committed to or proved -- so the empty blob would be permanently
        // unshardable for want of an edge case.
        let encoded = encode(&[], coding(2, 1), DEFAULT_CHUNK_LEN).expect("encode");
        let manifest = &encoded.manifest;
        assert_eq!(manifest.layout().shard_len(), 0);
        assert_eq!(manifest.layout().chunks(), 1);
        assert_eq!(manifest.layout().chunk_bytes(0), Some(0));
        assert_eq!(manifest.digest(), digest_bytes(&[]));
        for shard in &encoded.shards {
            assert!(shard.bytes.is_empty());
            assert!(manifest.verify_shard(shard));
            let proof = manifest.prove_chunk(shard, 0).expect("in range");
            assert!(proof.verify(&manifest.root()));
        }
        let out = reconstruct(manifest, &encoded.shards).expect("reconstruct");
        assert!(out.data.is_empty());
    }

    #[test]
    fn a_chunk_length_that_is_not_a_bounded_power_of_two_is_refused() {
        // A manifest is attacker-supplied, and `chunk_len = 1` asks a verifier
        // to build a tree with one leaf per byte.
        for bad in [0, 1, 1024, MIN_CHUNK_LEN - 1, MIN_CHUNK_LEN + 1, 3 * 4096] {
            assert_eq!(
                Layout::new(1_000, coding(2, 1), bad).unwrap_err(),
                ShardError::BadChunkLen { chunk_len: bad }
            );
        }
        assert!(Layout::new(1_000, coding(2, 1), MIN_CHUNK_LEN).is_ok());
        assert!(Layout::new(1_000, coding(2, 1), MAX_CHUNK_LEN).is_ok());
        assert_eq!(
            Layout::new(MAX_CODED_BYTES + 1, coding(2, 1), MIN_CHUNK_LEN).unwrap_err(),
            ShardError::TooLarge {
                total: MAX_CODED_BYTES + 1
            }
        );
    }

    #[test]
    fn a_coding_needs_data_shards_parity_shards_and_room_in_the_field() {
        assert_eq!(Coding::new(0, 2).unwrap_err(), ShardError::NoDataShards);
        // Zero parity is refused rather than accepted as striping: it tolerates
        // no loss while looking exactly like a code that does.
        assert_eq!(Coding::new(4, 0).unwrap_err(), ShardError::NoParityShards);
        assert_eq!(
            Coding::new(200, 100).unwrap_err(),
            ShardError::TooManyShards {
                data: 200,
                parity: 100
            }
        );
        let code = coding(250, 5);
        assert_eq!(code.shards(), 255);
        assert_eq!(code.tolerates(), 5);
        assert!(code.is_data(249) && !code.is_data(250));
        assert_eq!(format!("{code}"), "(250, 5)");
    }

    #[test]
    fn a_suggested_chunk_length_is_legal_and_keeps_the_tree_shallow() {
        for total in [0u64, 1, 1 << 20, 1 << 26, MAX_CODED_BYTES] {
            let code = coding(4, 2);
            let chunk_len = suggest_chunk_len(total, code);
            assert!(chunk_len.is_power_of_two());
            assert!((MIN_CHUNK_LEN..=MAX_CHUNK_LEN).contains(&chunk_len));
            let layout = Layout::new(total, code, chunk_len).expect("legal");
            assert!(
                u64::from(layout.chunks()) <= TARGET_CHUNKS_PER_SHARD || chunk_len == MAX_CHUNK_LEN,
                "{total} bytes gave {} chunks",
                layout.chunks()
            );
        }
    }

    // -- the manifest ------------------------------------------------------

    #[test]
    fn a_manifest_round_trips_and_a_malformed_one_is_refused() {
        let data = blob(MIN_CHUNK_LEN as usize * 3);
        let encoded = encode(&data, coding(3, 2), MIN_CHUNK_LEN).expect("encode");
        let manifest = &encoded.manifest;
        let decoded = Manifest::from_value(&manifest.to_value()).expect("round trip");
        assert_eq!(&decoded, manifest);
        assert_eq!(decoded.root(), manifest.root());
        assert_eq!(decoded.id(), manifest.id());

        assert_eq!(
            Manifest::new(
                manifest.digest(),
                data.len() as u64,
                coding(3, 2),
                MIN_CHUNK_LEN,
                vec![]
            )
            .unwrap_err(),
            ShardError::ShardCountMismatch {
                declared: 0,
                expected: 5
            }
        );
        assert_eq!(
            Manifest::new(
                manifest.digest(),
                data.len() as u64,
                coding(3, 2),
                MIN_CHUNK_LEN,
                vec!["not-a-digest".to_string(); 5]
            )
            .unwrap_err(),
            ShardError::NotADigest { index: 0 }
        );
        for field in ["digest", "total", "data", "parity", "chunk_len", "shards"] {
            let mut body = manifest.to_value().as_object().expect("object").clone();
            body.remove(field);
            assert!(
                Manifest::from_value(&Value::Object(body)).is_err(),
                "{field} must be required"
            );
        }
    }

    #[test]
    fn the_manifest_id_covers_the_geometry_and_not_only_the_roots() {
        // The same shard roots read under a different chunk length are a
        // different tree, so two manifests that shared an id while disagreeing
        // about that would be two readings of one name.
        let data = blob(MIN_CHUNK_LEN as usize * 8);
        let fine = encode(&data, coding(2, 1), MIN_CHUNK_LEN).expect("encode");
        let coarse = encode(&data, coding(2, 1), MIN_CHUNK_LEN * 2).expect("encode");
        assert_eq!(fine.manifest.digest(), coarse.manifest.digest());
        assert_ne!(fine.manifest.id(), coarse.manifest.id());
        assert_ne!(fine.manifest.root(), coarse.manifest.root());

        let wider = encode(&data, coding(4, 1), MIN_CHUNK_LEN).expect("encode");
        assert_ne!(fine.manifest.id(), wider.manifest.id());
    }

    #[test]
    fn a_manifest_describes_the_digest_the_log_pinned_in_either_spelling() {
        let data = blob(512);
        let encoded = encode(&data, coding(2, 1), MIN_CHUNK_LEN).expect("encode");
        let manifest = &encoded.manifest;
        assert!(manifest.describes(manifest.digest()));
        assert!(manifest.describes(&crate::blobs::address(&data)));
        assert!(!manifest.describes(&digest_bytes(b"something else")));
    }

    #[test]
    fn two_different_blobs_cannot_share_a_root() {
        let one = encode(
            &blob(MIN_CHUNK_LEN as usize * 3),
            coding(3, 2),
            MIN_CHUNK_LEN,
        )
        .expect("encode");
        let two = encode(
            &blob(MIN_CHUNK_LEN as usize * 4),
            coding(3, 2),
            MIN_CHUNK_LEN,
        )
        .expect("encode");
        assert_ne!(one.manifest.root(), two.manifest.root());
        let again = encode(
            &blob(MIN_CHUNK_LEN as usize * 3),
            coding(3, 2),
            MIN_CHUNK_LEN,
        )
        .expect("encode");
        assert_eq!(one.manifest.root(), again.manifest.root());
    }

    #[test]
    fn a_reconstruction_that_did_not_hash_right_is_an_error_and_not_a_result() {
        // Reachable only by lying to `reconstruct` about which blob the shards
        // belong to, which is exactly the case the final digest check exists to
        // convert from a plausible byte string into a loud failure.
        let data = blob(MIN_CHUNK_LEN as usize);
        let encoded = encode(&data, coding(2, 1), MIN_CHUNK_LEN).expect("encode");
        let lying = Manifest::new(
            digest_bytes(b"a different blob entirely"),
            encoded.manifest.layout().total(),
            coding(2, 1),
            MIN_CHUNK_LEN,
            encoded.manifest.roots().to_vec(),
        )
        .expect("shape is fine, the claim is not");
        assert!(matches!(
            reconstruct(&lying, &encoded.shards),
            Err(ShardError::DigestMismatch { .. })
        ));
    }

    // -- the code itself ---------------------------------------------------

    #[test]
    fn the_generator_is_systematic_and_its_parity_rows_are_cauchy() {
        let code = coding(4, 3);
        for index in 0..code.data() {
            let row = generator_row(code, index).expect("in range");
            let mut unit = vec![0u8; 4];
            if let Some(slot) = unit.get_mut(usize::from(index)) {
                *slot = 1;
            }
            assert_eq!(row, unit, "data row {index} must be a unit vector");
        }
        for index in code.data()..code.shards() {
            let row = generator_row(code, index).expect("in range");
            assert_eq!(row.len(), 4);
            // No zero coefficient: a Cauchy entry is an inverse, and an inverse
            // is never zero. A zero would mean a parity shard that ignores one
            // data shard, which is a hole in the MDS property.
            assert!(row.iter().all(|&c| c != 0), "row {index} has a zero");
            for (column, &coefficient) in row.iter().enumerate() {
                let expected = gf::inv(index ^ column as u8).expect("distinct, so non-zero");
                assert_eq!(coefficient, expected);
            }
        }
        assert_eq!(generator_row(code, 7), None);
    }

    #[test]
    fn every_k_by_k_submatrix_of_the_generator_inverts() {
        // MDS, checked directly rather than through a reconstruction: every
        // C(8, 5) = 56 choice of five rows from a (5, 3) code.
        let code = coding(5, 3);
        let rows: Vec<Vec<u8>> = (0..code.shards())
            .map(|index| generator_row(code, index).expect("in range"))
            .collect();
        let mut checked = 0;
        for mask in 0u32..(1 << 8) {
            if mask.count_ones() != 5 {
                continue;
            }
            let chosen: Vec<Vec<u8>> = (0..8)
                .filter(|i| mask & (1 << i) != 0)
                .filter_map(|i| rows.get(i).cloned())
                .collect();
            let inverse = invert(chosen.clone()).unwrap_or_else(|| panic!("singular at {mask:b}"));
            // And it really is the inverse: A * A^-1 = I.
            for (r, row) in chosen.iter().enumerate() {
                for c in 0..5 {
                    let mut acc = 0u8;
                    for (t, &coefficient) in row.iter().enumerate() {
                        let entry = inverse.get(t).and_then(|r| r.get(c)).copied().unwrap_or(0);
                        acc ^= gf::mul(coefficient, entry);
                    }
                    assert_eq!(acc, u8::from(r == c), "product at {r},{c} for {mask:b}");
                }
            }
            checked += 1;
        }
        assert_eq!(checked, 56);
    }

    #[test]
    fn a_singular_matrix_is_none_rather_than_a_wrong_inverse() {
        assert_eq!(invert(vec![vec![1, 2], vec![1, 2]]), None);
        assert_eq!(invert(vec![vec![0]]), None);
        assert_eq!(invert(vec![vec![1]]), Some(vec![vec![1]]));
    }
}
