//! Which drand round an epoch is settled against.
//!
//! The primary implementation has this too. The point of writing it twice is
//! that a beacon record's `block` is a value every reader re-derives, so a
//! disagreement about the derivation is a disagreement about whether a log is
//! honest -- and the derivation has an edge (a boundary that falls between two
//! rounds) which is invisible at the network's own parameters and reachable in
//! every demo.
//!
//! So the arithmetic here is deliberately not the arithmetic there. The primary
//! rounds up; this one rounds down and then steps forward if it undershot. Both
//! must answer the same, and `scripts/interop.sh` is where that stops being an
//! intention.
//!
//! [`verify`] is the same rule twice as well, and more pointedly: it runs on
//! `bls12_381_plus` where the primary runs on `bls12_381`. A pairing is the one
//! check in this protocol where two correct-looking programs can be made to
//! disagree -- subgroup membership and non-canonical encodings are where BLS
//! libraries differ -- so using the same library in both would make agreement
//! circular exactly where it is least safe to be.
//!
//! No network. The expander below is written out over the `sha2` this crate
//! already has, independently of the primary's, and pinned to RFC 9380's own
//! vectors. See `docs/design/drand-beacon.md`.

use bls12_381_plus::elliptic_curve_013::hash2curve::{ExpandMsg, Expander};
use bls12_381_plus::elliptic_curve_013::Error;
use bls12_381_plus::{multi_miller_loop, G1Affine, G1Projective, G2Affine, G2Prepared, Gt};
use sha2::{Digest as _, Sha256};

/// quicknet. Signatures on G1, unchained, so a round is a signature over its
/// own number and needs no predecessor to check -- which is the reason this
/// chain and not drand's older `default`.
pub const CHAIN_HASH: &str = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971";

/// The group public key on G2, hex. What a reader needs to check a recorded
/// signature; unused here, since nothing here checks one.
pub const PUBLIC_KEY: &str = "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a";

/// Seconds per round.
pub const PERIOD: u64 = 3;

/// Unix time of round 1.
pub const GENESIS: u64 = 1_692_803_367;

/// The `source` a beacon from this chain carries.
pub const SOURCE: &str = "drand";

/// When `round` is published.
pub fn published_at(round: u64) -> u64 {
    GENESIS.saturating_add(round.saturating_sub(1).saturating_mul(PERIOD))
}

/// The first round published at or after `unix`.
///
/// Floor, then step forward if that landed early. The primary implementation
/// divides the other way; if these two ever disagree, one of them is letting a
/// beacon be published before the epoch it orders opened, which is a value a
/// committer already held.
pub fn round_at_or_after(unix: u64) -> u64 {
    if unix <= GENESIS {
        return 1;
    }
    let round = (unix - GENESIS) / PERIOD + 1;
    if published_at(round) < unix {
        round + 1
    } else {
        round
    }
}

/// The round epoch `epoch` names, under an epoch length of `epoch_seconds`.
pub fn round_for_epoch(epoch: u64, epoch_seconds: u64) -> u64 {
    round_at_or_after(epoch.saturating_mul(epoch_seconds))
}

/// The DST quicknet's `bls-unchained-g1-rfc9380` scheme names.
const DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

/// Does `signature` carry quicknet's signature over `round`?
///
/// `e(sig, -g2) · e(H(SHA256(round)), pk) == 1`, against [`PUBLIC_KEY`] and
/// nothing else -- no chain, no relay, no clock. Unchained is what allows it:
/// the message is the round number alone.
pub fn verify(round: u64, signature: &str) -> bool {
    if !is_signature_shaped(signature) {
        return false;
    }
    let Some(sig) = unhex(signature).and_then(|bytes| <[u8; 48]>::try_from(bytes).ok()) else {
        return false;
    };
    let Some(key) = unhex(PUBLIC_KEY).and_then(|bytes| <[u8; 96]>::try_from(bytes).ok()) else {
        return false;
    };
    // The checked constructors. `from_compressed_unchecked` skips the
    // prime-order-subgroup test, and skipping it is the classic way a BLS
    // verifier is made to accept something.
    let sig: G1Affine = match Option::from(G1Affine::from_compressed(&sig)) {
        Some(point) => point,
        None => return false,
    };
    let key: G2Affine = match Option::from(G2Affine::from_compressed(&key)) {
        Some(point) => point,
        None => return false,
    };
    let message = Sha256::digest(round.to_be_bytes());
    let hashed = G1Affine::from(G1Projective::hash::<XmdSha256>(&message, DST));
    multi_miller_loop(&[
        (&sig, &G2Prepared::from(-G2Affine::generator())),
        (&hashed, &G2Prepared::from(key)),
    ])
    .final_exponentiation()
        == Gt::IDENTITY
}

/// `expand_message_xmd` over SHA-256, RFC 9380 §5.3.1.
///
/// Written out rather than taken from `bls12_381_plus`'s `ExpandMsgXmd`, which
/// is generic over `digest` 0.10 and would mean a second SHA-256 in a crate
/// that hashes for record identity.
struct XmdSha256;

struct Okm {
    bytes: Vec<u8>,
    read: usize,
}

impl ExpandMsg<'_> for XmdSha256 {
    type Expander = Okm;

    fn expand_message(msgs: &[&[u8]], dsts: &[&[u8]], len_in_bytes: usize) -> Result<Okm, Error> {
        let bytes = expand_message_xmd(&msgs.concat(), &dsts.concat(), len_in_bytes);
        if bytes.len() == len_in_bytes {
            Ok(Okm { bytes, read: 0 })
        } else {
            Err(Error)
        }
    }
}

impl Expander for Okm {
    fn fill_bytes(&mut self, okm: &mut [u8]) {
        let taken = okm.len().min(self.bytes.len() - self.read);
        okm[..taken].copy_from_slice(&self.bytes[self.read..self.read + taken]);
        self.read += taken;
    }
}

/// The expansion, as its own function so the RFC's vectors reach it directly.
///
/// Returns an empty vector for the lengths RFC 9380 declares invalid, rather
/// than panicking: this sits in a verification path and a hostile input must
/// not be able to stop a node auditing.
pub fn expand_message_xmd(message: &[u8], dst: &[u8], len_in_bytes: usize) -> Vec<u8> {
    let hash = |parts: &[&[u8]]| -> Vec<u8> {
        let mut hasher = Sha256::new();
        for part in parts {
            hasher.update(part);
        }
        hasher.finalize().to_vec()
    };

    let ell = len_in_bytes.div_ceil(32);
    if ell > 255 || len_in_bytes > u16::MAX as usize {
        return Vec::new();
    }
    // DST' = DST ‖ len(DST), with an oversize DST hashed down first. Never
    // taken by this crate's 43-byte DST; present because a primitive with a
    // missing branch is one the next caller uses wrongly.
    let mut prime = if dst.len() > 255 {
        hash(&[b"H2C-OVERSIZE-DST-", dst])
    } else {
        dst.to_vec()
    };
    prime.push(prime.len() as u8);

    let zeros = [0u8; 64];
    let b0 = hash(&[
        &zeros,
        message,
        &(len_in_bytes as u16).to_be_bytes(),
        &[0u8],
        &prime,
    ]);
    let mut bi = hash(&[&b0, &[1u8], &prime]);

    let mut out = bi.clone();
    for i in 2..=ell {
        let xored: Vec<u8> = b0.iter().zip(bi.iter()).map(|(a, b)| a ^ b).collect();
        bi = hash(&[&xored, &[i as u8], &prime]);
        out.extend_from_slice(&bi);
    }
    out.truncate(len_in_bytes);
    out
}

/// Decode lowercase hex, or nothing.
fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in text.as_bytes().chunks_exact(2) {
        let nibble = |byte: u8| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        };
        out.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    Some(out)
}

/// 96 hex characters, lowercase: a compressed G1 point.
///
/// drand serves a `randomness` alongside every `signature`, and it is SHA-256
/// of it -- 64 characters, and a hash of the evidence rather than the evidence.
/// A record carrying it is unverifiable forever and looks fine.
pub fn is_signature_shaped(value: &str) -> bool {
    value.len() == 96
        && value
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_one_is_genesis() {
        assert_eq!(published_at(1), GENESIS);
        assert_eq!(round_at_or_after(GENESIS), 1);
        assert_eq!(round_at_or_after(0), 1);
    }

    #[test]
    fn a_real_round_lands_where_the_chain_says() {
        // Served live by api.drand.sh at round 31543729.
        assert_eq!(published_at(31_543_729), 1_787_434_551);
        assert_eq!(round_at_or_after(1_787_434_551), 31_543_729);
    }

    #[test]
    fn a_time_between_rounds_resolves_forwards() {
        for offset in 1..PERIOD {
            let between = published_at(31_543_729) + offset;
            assert_eq!(round_at_or_after(between), 31_543_730);
        }
    }

    #[test]
    fn the_default_epoch_length_lands_exactly_on_rounds() {
        // 600 and the genesis time are both divisible by 3, which is why the
        // rounding direction is invisible in production and not in a demo.
        let round = round_for_epoch(2_979_058, 600);
        assert_eq!(published_at(round), 2_979_058 * 600);
    }

    /// Real quicknet rounds, fetched from two independent relays. The same
    /// fixtures the primary implementation uses, on purpose: the point is that
    /// two different pairing libraries reach the same verdict on them.
    const ROUNDS: [(u64, &str); 3] = [
        (1, "b55e7cb2d5c613ee0b2e28d6750aabbb78c39dcc96bd9d38c2c2e12198df95571de8e8e402a0cc48871c7089a2b3af4b"),
        (30_798_012, "90973449df156e156dc8c702aa397ebe24ab3ba4f0d7f46e921ba6ab906bc07515977132dc109498c6adebe27cde6fb5"),
        (31_543_812, "a517bcc786bde26257b53b18eb3f25dc4020d2ad2e2e85339e713b046b7b84df3794c57ab9cae880f0da7b2f120b70d7"),
    ];

    #[test]
    fn real_rounds_verify_and_only_for_their_own_round() {
        for (round, signature) in ROUNDS {
            assert!(verify(round, signature), "round {round}");
            assert!(!verify(round + 1, signature), "round {round} + 1");
        }
    }

    #[test]
    fn nothing_else_verifies() {
        let (round, signature) = ROUNDS[1];
        // A real signature by the real group, over the wrong round.
        assert!(!verify(round, ROUNDS[2].1));
        // The randomness field, and 48 bytes that are not a point.
        assert!(!verify(round, &"a".repeat(64)));
        assert!(!verify(round, &"f".repeat(96)));
        assert!(!verify(round, ""));
        // One flipped character.
        let mut flipped: Vec<char> = signature.chars().collect();
        flipped[9] = if flipped[9] == 'c' { 'd' } else { 'c' };
        assert!(!verify(round, &flipped.into_iter().collect::<String>()));
    }

    /// RFC 9380 Appendix K.1 and K.2. The expander is hand-written here as it
    /// is in the primary, so it is checked against the specification rather
    /// than against the other implementation -- which would make the agreement
    /// this crate exists to test circular.
    #[test]
    fn the_expander_matches_the_rfc() {
        let dst = b"QUUX-V01-CS02-with-expander-SHA256-128";
        let hex = |bytes: Vec<u8>| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();

        assert_eq!(
            hex(expand_message_xmd(b"", dst, 0x20)),
            "68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235"
        );
        assert_eq!(
            hex(expand_message_xmd(b"abc", dst, 0x20)),
            "d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615"
        );
        // ell = 4, the only one of these that runs the chaining loop.
        assert_eq!(
            hex(expand_message_xmd(b"", dst, 0x80)),
            "af84c27ccfd45d41914fdff5df25293e221afc53d8ad2ac06d5e3e29485dadbe\
             e0d121587713a3e0dd4d5e69e93eb7cd4f5df4cd103e188cf60cb02edc3edf18\
             eda8576c412b18ffb658e3dd6ec849469b979d444cf7b26911a08e63cf31f9dc\
             c541708d3491184472c2c29bb749d4286b004ceb5ee6b9a7fa5b646c993f0ced"
        );
        // K.2: the oversize-DST branch, which nothing here takes.
        let long: Vec<u8> = [
            b"QUUX-V01-CS02-with-expander-SHA256-128-long-DST-".to_vec(),
            vec![b'1'; 208],
        ]
        .concat();
        assert_eq!(long.len(), 256);
        assert_eq!(
            hex(expand_message_xmd(b"", &long, 0x20)),
            "e8dc0c8b686b7ef2074086fbdd2f30e3f8bfbd3bdf177f73f04b97ce618a3ed3"
        );
        // Invalid lengths return nothing rather than panicking.
        assert!(expand_message_xmd(b"", dst, 256 * 32 + 1).is_empty());
    }

    #[test]
    fn shape_rejects_the_randomness_field() {
        assert!(is_signature_shaped(&"0".repeat(96)));
        assert!(!is_signature_shaped(&"0".repeat(64)));
        assert!(!is_signature_shaped(&"F".repeat(96)));
    }
}
