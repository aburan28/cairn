//! Cutting a blob into verifiable pieces, and the manifest that describes them.
//!
//! A blob is named by the SHA-256 of its whole content
//! ([`crate::store::blobs`]), which is exactly the guarantee needed *after* a
//! transfer and useless *during* one. A peer feeding you 400 MB of noise is
//! indistinguishable from a peer feeding you the real thing until the last byte
//! lands and the digest comes out wrong -- at which point you know you were
//! lied to and nothing about who did the lying.
//!
//! So the blob is cut into fixed-length pieces and each piece is hashed. This is
//! the same move BitTorrent makes and it is worth being precise about what it
//! buys, because it is *not* trust:
//!
//! > **The whole-blob digest is the ground truth. Piece hashes buy blame.**
//!
//! Anyone can recompute a manifest from the bytes, so a manifest is not a
//! credential and holding one proves nothing. What it does is localise a lie: a
//! peer that sends a piece not matching the manifest has provably misbehaved on
//! *that piece*, so it can be dropped and its bytes discarded while the rest of
//! the download continues. Without piece hashes a single bad peer costs the whole
//! transfer; with them it costs one piece and its own connection.
//!
//! # The metainfo problem, which this network does not have
//!
//! BitTorrent's awkward step is that a `.torrent` must be obtained out of band
//! and trusted: the infohash is the root of trust and nothing in the protocol
//! establishes it. Here that step is already done. **The objective is the
//! metainfo** -- an objective commits to `evaluator_sha256` as part of its
//! content-addressed id, so every node that has the log already agrees on the
//! digest of every blob the network needs, with no tracker and nothing to sign.
//!
//! A manifest is therefore fetched like any other untrusted thing and checked
//! against a digest the log already fixed. [`Manifest::describes`] is that check,
//! and it is why a manifest can be accepted from a stranger.
//!
//! # Choosing a piece length
//!
//! Too small and the manifest bloats (one 71-byte digest per piece) and every
//! piece costs a round trip. Too large and a single corrupt piece wastes more
//! bandwidth than it should, rarest-first gets coarser, and a slow peer holds a
//! bigger hostage. 256 KiB is the default for the same reason BitTorrent
//! converged near there, and the bounds are enforced rather than advised: a
//! manifest is attacker-supplied, and `piece_len = 1` is a denial of service
//! made of arithmetic.

use std::fmt;

use crate::canonical::{digest_bytes, merkle_root, Value};

/// Default bytes per piece.
pub const DEFAULT_PIECE_LEN: u32 = 256 * 1024;
/// Smallest piece length a manifest may declare.
pub const MIN_PIECE_LEN: u32 = 16 * 1024;
/// Largest piece length a manifest may declare.
///
/// Also the bound the wire codec sizes its frame limit from, so raising it is
/// not a local change.
pub const MAX_PIECE_LEN: u32 = 4 * 1024 * 1024;
/// Largest blob this protocol will transfer: 64 GiB.
///
/// Not a statement about what is reasonable to store -- a statement about what
/// an attacker may claim. A peer announcing a 2^63-byte blob would otherwise get
/// a node to allocate a bitfield for it.
pub const MAX_BLOB_LEN: u64 = 64 * 1024 * 1024 * 1024;

/// A manifest that cannot be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PieceError {
    /// A piece length outside [`MIN_PIECE_LEN`]`..=`[`MAX_PIECE_LEN`], or not a
    /// power of two.
    BadPieceLen { piece_len: u32 },
    /// A blob length above [`MAX_BLOB_LEN`].
    TooLarge { total: u64 },
    /// The piece-hash count does not match the length and piece size.
    PieceCountMismatch { declared: usize, expected: usize },
    /// A piece hash that is not a `sha256:` digest.
    NotADigest { index: u32 },
    /// A manifest field is missing or the wrong type.
    Malformed { field: &'static str },
    /// A piece index past the end.
    NoSuchPiece { index: u32, pieces: u32 },
}

impl fmt::Display for PieceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PieceError::BadPieceLen { piece_len } => write!(
                f,
                "piece length {piece_len} is not a power of two in \
                 {MIN_PIECE_LEN}..={MAX_PIECE_LEN}"
            ),
            PieceError::TooLarge { total } => {
                write!(f, "blob of {total} bytes exceeds the {MAX_BLOB_LEN} bound")
            }
            PieceError::PieceCountMismatch { declared, expected } => write!(
                f,
                "manifest lists {declared} piece hashes, the declared length needs {expected}"
            ),
            PieceError::NotADigest { index } => {
                write!(f, "piece {index} is not named by a sha256 digest")
            }
            PieceError::Malformed { field } => {
                write!(f, "manifest field {field:?} is missing or malformed")
            }
            PieceError::NoSuchPiece { index, pieces } => {
                write!(f, "piece {index} of a blob that has {pieces}")
            }
        }
    }
}

impl std::error::Error for PieceError {}

/// How a blob of a given size divides into pieces.
///
/// `Copy` and arithmetic-only: every method here is a function of two numbers,
/// which is what lets a peer reason about a transfer before it has a single byte
/// of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    total: u64,
    piece_len: u32,
}

impl Layout {
    /// Validated constructor.
    ///
    /// A zero-length blob is a real thing -- the empty file has a digest like
    /// anything else -- and it has *one* piece of length zero rather than none.
    /// The alternative, a manifest with no pieces, has no Merkle root and no way
    /// to say "I have it", so the empty blob would be permanently untransferable
    /// for want of an edge case.
    pub fn new(total: u64, piece_len: u32) -> Result<Layout, PieceError> {
        if !(MIN_PIECE_LEN..=MAX_PIECE_LEN).contains(&piece_len) || !piece_len.is_power_of_two() {
            return Err(PieceError::BadPieceLen { piece_len });
        }
        if total > MAX_BLOB_LEN {
            return Err(PieceError::TooLarge { total });
        }
        Ok(Layout { total, piece_len })
    }

    pub fn total(&self) -> u64 {
        self.total
    }

    pub fn piece_len(&self) -> u32 {
        self.piece_len
    }

    /// How many pieces the blob has. Always at least one.
    pub fn pieces(&self) -> u32 {
        if self.total == 0 {
            return 1;
        }
        // Bounded by MAX_BLOB_LEN / MIN_PIECE_LEN = 4M, so the cast is safe and
        // `Layout::new` is what makes that true.
        self.total.div_ceil(u64::from(self.piece_len)) as u32
    }

    /// Byte offset of a piece, or `None` past the end.
    pub fn offset_of(&self, index: u32) -> Option<u64> {
        if index >= self.pieces() {
            return None;
        }
        Some(u64::from(index) * u64::from(self.piece_len))
    }

    /// Length of a piece: the declared length, except the last, which is short.
    pub fn len_of(&self, index: u32) -> Option<u32> {
        let offset = self.offset_of(index)?;
        let remaining = self.total.saturating_sub(offset);
        Some(remaining.min(u64::from(self.piece_len)) as u32)
    }

    /// The slice of `data` belonging to a piece.
    pub fn slice<'a>(&self, data: &'a [u8], index: u32) -> Option<&'a [u8]> {
        let offset = usize::try_from(self.offset_of(index)?).ok()?;
        let len = self.len_of(index)? as usize;
        data.get(offset..offset.checked_add(len)?)
    }
}

/// The piece hashes of one blob, and the digest they must add up to.
///
/// Untrusted by construction: this is derived from bytes, so anyone can make one
/// for any content. [`Manifest::describes`] is what connects it to a digest the
/// log already committed to, and nothing should accept a manifest without asking
/// that question first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    digest: String,
    layout: Layout,
    pieces: Vec<String>,
}

impl Manifest {
    /// Describe `data`, whose digest is computed here rather than taken on trust.
    pub fn of(data: &[u8], piece_len: u32) -> Result<Manifest, PieceError> {
        let layout = Layout::new(data.len() as u64, piece_len)?;
        let pieces = (0..layout.pieces())
            .map(|index| digest_bytes(layout.slice(data, index).unwrap_or(&[])))
            .collect();
        Ok(Manifest {
            digest: digest_bytes(data),
            layout,
            pieces,
        })
    }

    /// Rebuild a manifest received from a peer, checking its internal shape.
    ///
    /// Says nothing about whether the piece hashes are *the right ones*; that
    /// cannot be known until the bytes arrive. What it rules out is a manifest
    /// whose numbers do not agree with each other, which is the cheap half and
    /// the half that would otherwise become an allocation bug.
    pub fn new(
        digest: impl Into<String>,
        total: u64,
        piece_len: u32,
        pieces: Vec<String>,
    ) -> Result<Manifest, PieceError> {
        let layout = Layout::new(total, piece_len)?;
        let expected = layout.pieces() as usize;
        if pieces.len() != expected {
            return Err(PieceError::PieceCountMismatch {
                declared: pieces.len(),
                expected,
            });
        }
        for (index, hash) in pieces.iter().enumerate() {
            if !is_digest(hash) {
                return Err(PieceError::NotADigest {
                    index: index as u32,
                });
            }
        }
        Ok(Manifest {
            digest: digest.into(),
            layout,
            pieces,
        })
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn layout(&self) -> Layout {
        self.layout
    }

    pub fn pieces(&self) -> u32 {
        self.layout.pieces()
    }

    pub fn piece_hash(&self, index: u32) -> Option<&str> {
        self.pieces.get(index as usize).map(String::as_str)
    }

    pub fn piece_hashes(&self) -> &[String] {
        &self.pieces
    }

    /// Merkle root over the piece hashes.
    ///
    /// Uses [`crate::canonical::merkle_root`], so it inherits the promotion rule
    /// for odd nodes and with it the defence against the second-preimage attack
    /// that duplicating the last leaf enables. Two different piece sets cannot
    /// share a root, which is what makes this usable as a manifest's short name.
    pub fn root(&self) -> String {
        // `pieces` is non-empty for every constructible Layout, so the `None`
        // arm is unreachable; the digest of nothing is the honest fallback and
        // costs one line rather than an unwrap on a money-adjacent path.
        merkle_root(&self.pieces).unwrap_or_else(|| digest_bytes(&[]))
    }

    /// Does this manifest claim to describe `digest`?
    ///
    /// The only question that matters when a manifest arrives from a stranger,
    /// because the answer connects it to something the log already fixed.
    pub fn describes(&self, digest: &str) -> bool {
        let want = digest.strip_prefix("sha256:").unwrap_or(digest);
        let have = self.digest.strip_prefix("sha256:").unwrap_or(&self.digest);
        want.eq_ignore_ascii_case(have)
    }

    /// Is `bytes` the piece at `index`?
    ///
    /// Length is checked before hashing. A piece of the wrong length is a lie
    /// that costs nothing to detect, and hashing first would let a peer make a
    /// node do work proportional to whatever it felt like sending.
    pub fn verify_piece(&self, index: u32, bytes: &[u8]) -> bool {
        let Some(expected_len) = self.layout.len_of(index) else {
            return false;
        };
        if bytes.len() != expected_len as usize {
            return false;
        }
        match self.piece_hash(index) {
            Some(expected) => digest_bytes(bytes) == expected,
            None => false,
        }
    }

    /// Canonical encoding, so a manifest has a content address like every other
    /// record in this crate.
    pub fn to_value(&self) -> Value {
        Value::object([
            ("digest", Value::string(&self.digest)),
            ("total", Value::Int(self.layout.total() as i128)),
            ("piece_len", Value::Int(i128::from(self.layout.piece_len()))),
            (
                "pieces",
                Value::array(self.pieces.iter().map(Value::string)),
            ),
        ])
    }

    /// Decode a manifest, validating as [`Manifest::new`] does.
    pub fn from_value(value: &Value) -> Result<Manifest, PieceError> {
        let digest = value
            .get("digest")
            .and_then(Value::as_str)
            .ok_or(PieceError::Malformed { field: "digest" })?;
        let total = value
            .get("total")
            .and_then(Value::as_u64)
            .ok_or(PieceError::Malformed { field: "total" })?;
        let piece_len = value
            .get("piece_len")
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .ok_or(PieceError::Malformed { field: "piece_len" })?;
        let pieces = match value.get("pieces") {
            Some(Value::Array(items)) => items
                .iter()
                .map(|item| {
                    item.as_str()
                        .map(str::to_string)
                        .ok_or(PieceError::Malformed { field: "pieces" })
                })
                .collect::<Result<Vec<String>, PieceError>>()?,
            _ => return Err(PieceError::Malformed { field: "pieces" }),
        };
        Manifest::new(digest, total, piece_len, pieces)
    }
}

/// Which pieces a peer has.
///
/// A plain bitset rather than a `HashSet<u32>`: this is exchanged on every
/// connection and consulted on every scheduling decision, and at four million
/// pieces the difference is half a megabyte against tens of megabytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bitfield {
    bits: Vec<u8>,
    len: u32,
    count: u32,
}

impl Bitfield {
    /// An empty bitfield for a blob of `len` pieces.
    pub fn new(len: u32) -> Bitfield {
        Bitfield {
            bits: vec![0; (len as usize).div_ceil(8)],
            len,
            count: 0,
        }
    }

    /// A full bitfield -- what a seed announces.
    pub fn full(len: u32) -> Bitfield {
        let mut field = Bitfield::new(len);
        for index in 0..len {
            field.insert(index);
        }
        field
    }

    /// Decode a bitfield of `len` pieces from the wire.
    ///
    /// Refuses a byte count that does not match, and refuses trailing bits set
    /// past the end. That last check is not pedantry: the spare bits are the one
    /// place a peer can vary its encoding without changing its meaning, and a
    /// node that accepted them would have two byte strings for one bitfield.
    ///
    /// `len` comes from the caller, never from the wire, and that is the whole
    /// reason this is safe to accept from a stranger. A bitfield does not carry
    /// its own piece count -- the count comes from the manifest, which was
    /// checked against a digest the log already fixed. So a peer cannot use a
    /// bitfield to tell a node how much to allocate, and two adjacent lengths
    /// that happen to occupy the same number of bytes are not ambiguous here
    /// because only one of them is ever asked for.
    pub fn decode(bytes: &[u8], len: u32) -> Option<Bitfield> {
        let expected = (len as usize).div_ceil(8);
        if bytes.len() != expected {
            return None;
        }
        let spare = expected * 8 - len as usize;
        if spare > 0 {
            let last = *bytes.last()?;
            if last & ((1u16 << spare) - 1) as u8 != 0 {
                return None;
            }
        }
        let mut field = Bitfield {
            bits: bytes.to_vec(),
            len,
            count: 0,
        };
        field.count = field.bits.iter().map(|b| b.count_ones()).sum();
        Some(field)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bits
    }

    pub fn len(&self) -> u32 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// How many pieces are present.
    pub fn count(&self) -> u32 {
        self.count
    }

    pub fn is_complete(&self) -> bool {
        self.count == self.len
    }

    pub fn contains(&self, index: u32) -> bool {
        if index >= self.len {
            return false;
        }
        let (byte, bit) = locate(index);
        self.bits.get(byte).is_some_and(|b| b & bit != 0)
    }

    /// Set a bit. Returns whether it was newly set, so a caller can tell a real
    /// `have` from a repeat without a second lookup.
    pub fn insert(&mut self, index: u32) -> bool {
        if index >= self.len || self.contains(index) {
            return false;
        }
        let (byte, bit) = locate(index);
        if let Some(slot) = self.bits.get_mut(byte) {
            *slot |= bit;
            self.count += 1;
            return true;
        }
        false
    }

    /// Indices present here and absent from `other`.
    pub fn missing_from(&self, other: &Bitfield) -> Vec<u32> {
        (0..self.len)
            .filter(|index| self.contains(*index) && !other.contains(*index))
            .collect()
    }
}

/// Bit 0 is the most significant bit of byte 0, as in BitTorrent. Arbitrary, and
/// the only thing that matters is that both ends agree -- so it is stated once,
/// here, and every other reference goes through this function.
fn locate(index: u32) -> (usize, u8) {
    ((index / 8) as usize, 0x80u8 >> (index % 8))
}

fn is_digest(text: &str) -> bool {
    let hex = text.strip_prefix("sha256:").unwrap_or(text);
    hex.len() == 64
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blob(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn a_layout_covers_every_byte_exactly_once() {
        let data = blob(MIN_PIECE_LEN as usize * 3 + 17);
        let layout = Layout::new(data.len() as u64, MIN_PIECE_LEN).expect("valid");
        assert_eq!(layout.pieces(), 4);

        let mut seen = 0u64;
        let mut rebuilt = Vec::new();
        for index in 0..layout.pieces() {
            let piece = layout.slice(&data, index).expect("in range");
            assert_eq!(
                piece.len(),
                layout.len_of(index).expect("in range") as usize
            );
            assert_eq!(layout.offset_of(index).expect("in range"), seen);
            seen += piece.len() as u64;
            rebuilt.extend_from_slice(piece);
        }
        assert_eq!(seen, data.len() as u64, "pieces tile the blob");
        assert_eq!(rebuilt, data, "and reassemble it");
        assert_eq!(layout.len_of(3), Some(17), "the last piece is short");
        assert_eq!(layout.offset_of(4), None);
        assert_eq!(layout.len_of(4), None);
    }

    #[test]
    fn the_empty_blob_has_one_piece_rather_than_none() {
        // A manifest with no pieces has no Merkle root and no way to say "I have
        // it", so the empty blob would be permanently untransferable for want of
        // an edge case.
        let manifest = Manifest::of(&[], DEFAULT_PIECE_LEN).expect("valid");
        assert_eq!(manifest.pieces(), 1);
        assert_eq!(manifest.layout().len_of(0), Some(0));
        assert!(manifest.verify_piece(0, &[]));
        assert!(!manifest.verify_piece(0, b"x"));
        assert_eq!(manifest.digest(), digest_bytes(&[]));
    }

    #[test]
    fn a_piece_length_that_is_not_a_bounded_power_of_two_is_refused() {
        // A manifest is attacker-supplied and `piece_len = 1` is a denial of
        // service made of arithmetic: it would put one 71-byte digest in the
        // manifest for every byte of the blob.
        for bad in [
            0,
            1,
            1024,
            MIN_PIECE_LEN - 1,
            MIN_PIECE_LEN + 1,
            MAX_PIECE_LEN * 2,
        ] {
            assert!(
                matches!(Layout::new(1_000, bad), Err(PieceError::BadPieceLen { .. })),
                "piece_len {bad} should be refused"
            );
        }
        assert!(Layout::new(1_000, MIN_PIECE_LEN).is_ok());
        assert!(Layout::new(1_000, MAX_PIECE_LEN).is_ok());
        assert!(matches!(
            Layout::new(MAX_BLOB_LEN + 1, DEFAULT_PIECE_LEN),
            Err(PieceError::TooLarge { .. })
        ));
    }

    #[test]
    fn a_manifest_verifies_the_pieces_it_describes_and_refuses_the_rest() {
        let data = blob(MIN_PIECE_LEN as usize * 2 + 5);
        let manifest = Manifest::of(&data, MIN_PIECE_LEN).expect("valid");
        assert!(manifest.describes(manifest.digest()));
        assert!(manifest.describes(manifest.digest().trim_start_matches("sha256:")));
        assert!(!manifest.describes(&digest_bytes(b"something else")));

        for index in 0..manifest.pieces() {
            let piece = manifest.layout().slice(&data, index).expect("in range");
            assert!(manifest.verify_piece(index, piece));
            // The same bytes at the wrong index are still wrong.
            if index > 0 {
                assert!(
                    !manifest.verify_piece(index - 1, piece)
                        || piece.len() != MIN_PIECE_LEN as usize
                );
            }
        }
        assert!(!manifest.verify_piece(0, b"not the piece"));
        assert!(!manifest.verify_piece(99, &data), "no such piece");
    }

    #[test]
    fn a_wrong_length_piece_is_refused_before_it_is_hashed() {
        // Hashing first would let a peer make a node do work proportional to
        // whatever it felt like sending.
        let data = blob(MIN_PIECE_LEN as usize + 1);
        let manifest = Manifest::of(&data, MIN_PIECE_LEN).expect("valid");
        assert!(!manifest.verify_piece(0, &blob(MIN_PIECE_LEN as usize * 4)));
        assert!(!manifest.verify_piece(1, &blob(MIN_PIECE_LEN as usize)));
        assert!(manifest.verify_piece(1, &data[MIN_PIECE_LEN as usize..]));
    }

    #[test]
    fn a_manifest_round_trips_and_a_malformed_one_is_refused() {
        let data = blob(MIN_PIECE_LEN as usize * 3);
        let manifest = Manifest::of(&data, MIN_PIECE_LEN).expect("valid");
        let decoded = Manifest::from_value(&manifest.to_value()).expect("round trips");
        assert_eq!(decoded, manifest);
        assert_eq!(decoded.root(), manifest.root());

        // A piece count that does not match the declared length is the shape of
        // lie that would otherwise become an allocation bug.
        assert!(matches!(
            Manifest::new(manifest.digest(), data.len() as u64, MIN_PIECE_LEN, vec![]),
            Err(PieceError::PieceCountMismatch { .. })
        ));
        assert!(matches!(
            Manifest::new(
                manifest.digest(),
                data.len() as u64,
                MIN_PIECE_LEN,
                vec!["not-a-digest".to_string(); 3]
            ),
            Err(PieceError::NotADigest { index: 0 })
        ));
        for field in ["digest", "total", "piece_len", "pieces"] {
            let mut body = manifest.to_value().as_object().expect("object").clone();
            body.remove(field);
            assert!(
                Manifest::from_value(&Value::Object(body)).is_err(),
                "{field} must be required"
            );
        }
    }

    #[test]
    fn two_different_piece_sets_cannot_share_a_root() {
        // Inherited from `canonical::merkle_root`, which promotes an odd node
        // rather than duplicating it -- Bitcoin's CVE-2012-2459. Worth pinning
        // here because a manifest's root is what a short name for it would be.
        let three = Manifest::of(&blob(MIN_PIECE_LEN as usize * 3), MIN_PIECE_LEN).expect("valid");
        let four = Manifest::of(&blob(MIN_PIECE_LEN as usize * 4), MIN_PIECE_LEN).expect("valid");
        assert_ne!(three.root(), four.root());
        assert_eq!(
            three.root(),
            Manifest::of(&blob(MIN_PIECE_LEN as usize * 3), MIN_PIECE_LEN)
                .expect("valid")
                .root(),
            "and the root is a function of the content"
        );
    }

    #[test]
    fn a_bitfield_tracks_membership_and_counts() {
        let mut field = Bitfield::new(20);
        assert!(field.is_empty());
        assert_eq!(field.count(), 0);
        assert!(field.insert(0));
        assert!(!field.insert(0), "a repeat is not a new piece");
        assert!(field.insert(19));
        assert!(!field.insert(20), "past the end");
        assert!(field.contains(0) && field.contains(19));
        assert!(!field.contains(1) && !field.contains(20));
        assert_eq!(field.count(), 2);
        assert!(!field.is_complete());

        let full = Bitfield::full(20);
        assert!(full.is_complete());
        assert_eq!(full.count(), 20);
        assert_eq!(full.missing_from(&field).len(), 18);
        assert!(field.missing_from(&full).is_empty());
    }

    #[test]
    fn a_bitfield_round_trips_and_refuses_set_padding_bits() {
        // The spare bits are the one place a peer can vary its encoding without
        // varying its meaning. Accepting them would give one bitfield two byte
        // strings, which is exactly the kind of thing this crate refuses
        // everywhere else.
        let mut field = Bitfield::new(12);
        field.insert(0);
        field.insert(11);
        let encoded = field.as_bytes().to_vec();
        assert_eq!(encoded.len(), 2);
        assert_eq!(Bitfield::decode(&encoded, 12), Some(field));

        let mut padded = encoded.clone();
        padded[1] |= 0x01;
        assert_eq!(Bitfield::decode(&padded, 12), None, "padding bit set");
        assert_eq!(Bitfield::decode(&encoded, 17), None, "wrong byte count");
        assert_eq!(Bitfield::decode(&[], 12), None);

        // A bitfield does not carry its own length, and 13 pieces occupy the
        // same two bytes as 12. That is not an ambiguity to defend against: the
        // count comes from the manifest, which was checked against a digest the
        // log already fixed, so only one length is ever asked for.
        assert!(Bitfield::decode(&encoded, 13).is_some());
    }

    #[test]
    fn a_full_bitfield_of_a_byte_multiple_has_no_padding_to_argue_about() {
        let full = Bitfield::full(16);
        assert_eq!(full.as_bytes(), &[0xff, 0xff]);
        assert_eq!(Bitfield::decode(&[0xff, 0xff], 16), Some(full));
    }
}
