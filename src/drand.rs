//! The drand quicknet beacon: which round an epoch names, and what a record of
//! one has to look like.
//!
//! No network. Nothing in this module fetches anything, and that is not an
//! oversight -- `tests/cipher_policy.rs` fails the build if a TLS crate enters
//! the dependency tree, and an HTTP client is how one gets in. The fetch lives
//! in `scripts/drand-beacon.sh`, outside the binary, which is also where
//! `docs/design/chain-beacon.md` already said fetching belongs.
//!
//! # Why this exists at all
//!
//! `docs/design/chain-beacon.md` states the limit of the Ethereum beacon
//! plainly: a wrong `value` is caught by anyone holding the chain and never by
//! someone holding only the log. That is forced by the source, not by beacons.
//! `block.prevrandao` at block *N* is a fact about a chain and the only way to
//! learn it is to hold the chain; a drand round is a threshold BLS signature
//! over the round number, so checking one needs a public key and no chain at
//! all. See `docs/design/drand-beacon.md`.
//!
//! # Why quicknet and not drand's `default` chain
//!
//! `default` is **chained**: round *N* signs `H(sig(N−1) ‖ N)`, so verifying it
//! means holding its predecessor, and verifying *that* means holding the one
//! before. A chained beacon is checkable only relative to a point you already
//! trust, which is the Ethereum problem again with a different chain in it.
//! quicknet is **unchained** -- round *N* signs `H(N)` and nothing else -- so a
//! single round is self-contained, which is the whole point.
//!
//! # The pairing, and the doctrine it bends
//!
//! [`verify`] is the point of the whole exercise: `e(sig, -g2) · e(H(round), pk)
//! == 1`, one multi-Miller loop, against a key pinned in this file. It needs
//! BLS12-381, which is **the one non-post-quantum primitive in this crate**,
//! and [`crate::crypto`] spends its module docs explaining why everything else
//! is not. The distinction, argued out in `docs/design/drand-beacon.md` and
//! repeated in `Cargo.toml` because that is where the next person will look:
//! this signature covers a value that is *already public*, so there is no
//! secret with a tail for a future adversary to harvest. Forging a 2026 round
//! in 2035 changes nothing about what a 2026 epoch settled. The same argument
//! does **not** license timelock encryption over the same curve, which is why
//! that is not here.
//!
//! # One SHA-256, not two
//!
//! `bls12_381`'s own `ExpandMsgXmd` is generic over `digest` 0.9, and reaching
//! it would mean a second SHA-256 implementation in a crate that hashes for
//! record identity. So [`expand_message_xmd`] is written out here over the
//! `sha2` the rest of the crate already uses -- forty lines of RFC 9380 §5.3.1,
//! pinned to the RFC's own test vectors including the oversize-DST branch this
//! crate never takes. Same reasoning as the in-crate Shamir implementation: a
//! path that decides who gets paid should be auditable where it is used.

use core::fmt;
use std::sync::OnceLock;

use bls12_381::hash_to_curve::{ExpandMessageState, HashToCurve, InitExpandMessage};
use bls12_381::{multi_miller_loop, G1Affine, G1Projective, G2Affine, G2Prepared, Gt};
use sha2::{Digest as _, Sha256};

/// quicknet's chain hash, as drand's `/info` reports it.
///
/// Recorded here rather than read from configuration because a beacon whose
/// parameters the operator can edit is a beacon the operator chose.
pub const CHAIN_HASH: &str = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971";

/// The group public key, 96 bytes on G2, hex.
///
/// Used by [`verify`] and pinned here so verification does not ask the network
/// which key to trust -- asking the network would make the check circular.
pub const PUBLIC_KEY: &str = "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a";

/// Seconds between rounds.
pub const PERIOD_SECONDS: u64 = 3;

/// Unix time of round 1.
pub const GENESIS_TIME: u64 = 1_692_803_367;

/// What a beacon record drawn from this chain names itself.
///
/// `Node::record_beacon` matches on it to decide whether the round derivation
/// applies, so it is consensus-visible in the weak sense that a reader
/// re-deriving an audit has to spell it the same way.
pub const SOURCE: &str = "drand";

/// A compressed G1 point, hex: 48 bytes, 96 characters.
const SIGNATURE_HEX_LEN: usize = 96;

/// The round epoch `epoch` is ordered against: the first round at or **after**
/// the epoch boundary.
///
/// At or after, never at or before, and the difference is the security
/// property rather than an off-by-one. A round that landed before the boundary
/// was published before the epoch opened, so a committer in the previous epoch
/// held it while their commitment hash was still theirs to grind -- which is
/// exactly what [`crate::node::RuleViolation::BeaconOutOfEpoch`] exists to
/// stop. Rounding the other way hands it back.
///
/// The distinction is invisible at the network's own parameters, because 600
/// and 1692803367 are both divisible by 3 and so every boundary falls exactly
/// on a round. It stops being invisible under `CAIRN_EPOCH_SECONDS`, which is
/// set to seconds in every demo script in this repository.
///
/// A boundary at or before genesis clamps to round 1. Not hypothetical:
/// `CAIRN_EPOCH_SECONDS=1` puts epoch 0 in 1970.
///
/// `epoch_seconds` is passed rather than read, and callers pass the
/// environment-aware [`crate::partition::epoch_seconds`] rather than the
/// constant. That is deliberate and it has a consequence worth stating: the
/// round an epoch names moves with `CAIRN_EPOCH_SECONDS`, exactly as the epoch
/// itself does. A demo log written under a one-second epoch therefore reports
/// round mismatches when audited at the default length -- which is the same
/// thing every other epoch-derived check does, and what
/// `Node::epoch_length_report` exists to explain. The alternative, deriving the
/// round from the constant while the epoch comes from the override, would pin a
/// round to a boundary that does not exist.
pub fn round_for_epoch(epoch: u64, epoch_seconds: u64) -> u64 {
    let boundary = epoch.saturating_mul(epoch_seconds);
    if boundary <= GENESIS_TIME {
        return 1;
    }
    (boundary - GENESIS_TIME).div_ceil(PERIOD_SECONDS) + 1
}

/// Unix time at which `round` is published. The inverse of the derivation
/// above, and the thing a fetcher needs in order to wait for it.
pub fn time_of_round(round: u64) -> u64 {
    GENESIS_TIME.saturating_add(round.saturating_sub(1).saturating_mul(PERIOD_SECONDS))
}

/// Is `value` shaped like a quicknet signature?
///
/// A precondition of [`verify`] rather than a substitute for it. Kept separate
/// because it produces the *useful* error for the one mistake an operator
/// actually makes, and "does not verify" would describe that mistake correctly
/// and unhelpfully.
///
/// The shape is all this tree can check without a pairing, and it is worth
/// checking for one specific reason: drand publishes a `signature` **and** a
/// `randomness`, the second being `SHA256` of the first, and recording the
/// second is the natural mistake. It is also the one mistake that cannot be
/// detected later, because a hash of the evidence is not evidence. `randomness`
/// is 64 hex characters and a signature is 96, so the wrong field is refused at
/// the moment somebody pastes it rather than discovered by a reader who cannot
/// verify a value years afterwards.
pub fn is_signature_shaped(value: &str) -> bool {
    value.len() == SIGNATURE_HEX_LEN
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// The domain separation tag quicknet's scheme names:
/// `bls-unchained-g1-rfc9380`, signatures on G1.
///
/// Part of the message, not a parameter: change a byte and every signature
/// stops verifying, which is exactly what a domain separation tag is for.
const DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

/// Why a recorded beacon value is not the round it claims to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    /// Not 96 lowercase hex characters. See [`is_signature_shaped`].
    NotSignatureShaped,
    /// 48 bytes that are not a compressed point of the right subgroup.
    ///
    /// Separate from [`VerifyError::DoesNotVerify`] because it is a different
    /// accusation: this is not a signature at all, rather than a signature over
    /// something else. `from_compressed` does the subgroup check, which is the
    /// step whose omission is the classic BLS vulnerability.
    NotACurvePoint,
    /// A well-formed signature over some other message, or by some other key.
    DoesNotVerify,
    /// [`PUBLIC_KEY`] does not decompress.
    ///
    /// Only reachable by editing the constant in this file, and a test pins it.
    /// It is a variant rather than a panic because a verification path that can
    /// abort the process is a denial of service with extra steps.
    PinnedKeyUnusable,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::NotSignatureShaped => f.write_str(
                "not 96 lowercase hex characters, so not a quicknet signature -- drand's \
                 `randomness` field is 64 and is a hash of the evidence rather than the \
                 evidence",
            ),
            VerifyError::NotACurvePoint => f.write_str(
                "48 bytes that are not a point of the right subgroup of G1, so not a \
                 signature by anybody",
            ),
            VerifyError::DoesNotVerify => f.write_str(
                "a well-formed signature that the drand group did not produce for this \
                 round",
            ),
            VerifyError::PinnedKeyUnusable => {
                f.write_str("the pinned quicknet public key does not decompress")
            }
        }
    }
}

/// Does `signature` carry quicknet's threshold signature over `round`?
///
/// `e(sig, -g2) · e(H(SHA256(round)), pk) == 1`. Unchained is what makes this a
/// function of the round number alone: a chained beacon would need round
/// `n - 1`'s signature to build the message, and then checking any round would
/// mean holding the chain -- the very thing this source was chosen to avoid.
///
/// **Deterministic and total.** No clock, no network, no allocation beyond the
/// expander's output. Two readers holding the same log reach the same verdict,
/// which is the property that lets an audit report this at all.
pub fn verify(round: u64, signature: &str) -> Result<(), VerifyError> {
    if !is_signature_shaped(signature) {
        return Err(VerifyError::NotSignatureShaped);
    }
    let bytes: [u8; 48] = crate::hex::decode(signature)
        .ok_or(VerifyError::NotSignatureShaped)?
        .try_into()
        .map_err(|_| VerifyError::NotSignatureShaped)?;
    // `from_compressed`, never `from_compressed_unchecked`: it is the on-curve
    // and prime-order-subgroup check, and skipping it is the standard way a BLS
    // verifier is made to accept a forgery.
    let signature: G1Affine =
        Option::from(G1Affine::from_compressed(&bytes)).ok_or(VerifyError::NotACurvePoint)?;
    let key = public_key().ok_or(VerifyError::PinnedKeyUnusable)?;

    let message = Sha256::digest(round.to_be_bytes());
    let hashed = G1Affine::from(<G1Projective as HashToCurve<XmdSha256>>::hash_to_curve(
        message, DST,
    ));
    let product = multi_miller_loop(&[
        (&signature, &G2Prepared::from(-G2Affine::generator())),
        (&hashed, &G2Prepared::from(key)),
    ])
    .final_exponentiation();
    if product == Gt::identity() {
        Ok(())
    } else {
        Err(VerifyError::DoesNotVerify)
    }
}

/// [`PUBLIC_KEY`], decompressed once.
///
/// Cached because decompressing a G2 point runs a subgroup check, and an audit
/// verifies one beacon per epoch over the whole log.
fn public_key() -> Option<G2Affine> {
    static KEY: OnceLock<Option<G2Affine>> = OnceLock::new();
    *KEY.get_or_init(|| {
        let bytes: [u8; 96] = crate::hex::decode(PUBLIC_KEY)?.try_into().ok()?;
        Option::from(G2Affine::from_compressed(&bytes))
    })
}

/// `expand_message_xmd`, RFC 9380 §5.3.1, over SHA-256.
///
/// Written out rather than taken from `bls12_381::hash_to_curve::ExpandMsgXmd`,
/// which is generic over `digest` 0.9 and would put a second SHA-256 in a crate
/// that hashes for record identity. See the module docs.
pub struct XmdSha256;

/// The bytes [`XmdSha256`] produced, handed out on demand.
///
/// Computed in full up front rather than streamed. `hash_to_curve` for G1 asks
/// for 128 bytes and never more, so "streaming" would mean four SHA-256 calls
/// deferred by a state machine, and the state machine is the part that would
/// have bugs.
pub struct XmdSha256Output {
    bytes: Vec<u8>,
    read: usize,
}

impl<'x> InitExpandMessage<'x> for XmdSha256 {
    type Expander = XmdSha256Output;

    fn init_expand(message: &[u8], dst: &'x [u8], len_in_bytes: usize) -> Self::Expander {
        XmdSha256Output {
            bytes: expand_message_xmd(message, dst, len_in_bytes),
            read: 0,
        }
    }
}

impl ExpandMessageState<'_> for XmdSha256Output {
    fn read_into(&mut self, output: &mut [u8]) -> usize {
        let taken = output.len().min(self.remain());
        output[..taken].copy_from_slice(&self.bytes[self.read..self.read + taken]);
        self.read += taken;
        taken
    }

    fn remain(&self) -> usize {
        self.bytes.len() - self.read
    }
}

/// The expansion itself, exposed so the RFC's vectors can be run against it
/// directly rather than only through a curve.
///
/// Returns fewer bytes than asked for only in the cases RFC 9380 declares
/// invalid (`ell > 255`, or a length that does not fit in two bytes). Both are
/// unreachable from this crate, which asks for 128; returning short rather than
/// panicking keeps a hostile caller from aborting a verifier.
pub fn expand_message_xmd(message: &[u8], dst: &[u8], len_in_bytes: usize) -> Vec<u8> {
    /// SHA-256's output, and its block, in bytes.
    const B_IN_BYTES: usize = 32;
    const S_IN_BYTES: usize = 64;

    let ell = len_in_bytes.div_ceil(B_IN_BYTES);
    if ell > 255 || len_in_bytes > usize::from(u16::MAX) {
        return Vec::new();
    }

    // DST' = DST ‖ I2OSP(len(DST), 1), with an oversize DST hashed down first.
    // This crate's DST is 43 bytes so the branch is never taken here; it is
    // implemented because a partial primitive is one somebody reuses wrongly,
    // and it is pinned by the RFC's long-DST vector.
    let mut dst_prime = if dst.len() > 255 {
        let mut hasher = Sha256::new();
        hasher.update(b"H2C-OVERSIZE-DST-");
        hasher.update(dst);
        hasher.finalize().to_vec()
    } else {
        dst.to_vec()
    };
    let dst_len = dst_prime.len() as u8;
    dst_prime.push(dst_len);

    let mut hasher = Sha256::new();
    hasher.update([0u8; S_IN_BYTES]);
    hasher.update(message);
    hasher.update((len_in_bytes as u16).to_be_bytes());
    hasher.update([0u8]);
    hasher.update(&dst_prime);
    let b_0 = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(b_0);
    hasher.update([1u8]);
    hasher.update(&dst_prime);
    let mut b_i = hasher.finalize();

    let mut out = Vec::with_capacity(ell * B_IN_BYTES);
    out.extend_from_slice(&b_i);
    for i in 2..=ell {
        let mut strxor = [0u8; B_IN_BYTES];
        for (slot, (left, right)) in strxor.iter_mut().zip(b_0.iter().zip(b_i.iter())) {
            *slot = left ^ right;
        }
        let mut hasher = Sha256::new();
        hasher.update(strxor);
        hasher.update([i as u8]);
        hasher.update(&dst_prime);
        b_i = hasher.finalize();
        out.extend_from_slice(&b_i);
    }
    out.truncate(len_in_bytes);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pinned against the live chain: round 31543729 was served with
    /// `genesis_time` 1692803367 and `period` 3, so it is published at
    /// 1787434551. Anything that moves this derivation moves which round every
    /// epoch names, which is the value every auditor re-derives.
    #[test]
    fn round_and_time_are_inverses_at_a_real_round() {
        assert_eq!(time_of_round(31_543_729), 1_787_434_551);
        assert_eq!(time_of_round(1), GENESIS_TIME);
    }

    #[test]
    fn a_boundary_on_a_round_names_that_round() {
        let round = round_for_epoch(2_979_058, 600);
        assert_eq!(time_of_round(round), 2_979_058 * 600);
    }

    /// The at-or-after rule, at parameters where it is visible. With a
    /// one-second epoch the boundary lands between rounds two thirds of the
    /// time, and every one of those must resolve forwards.
    #[test]
    fn a_boundary_between_rounds_names_the_next_one() {
        for offset in 0..12u64 {
            let boundary = GENESIS_TIME + offset;
            let round = round_for_epoch(boundary, 1);
            assert!(
                time_of_round(round) >= boundary,
                "epoch at {boundary} named round {round}, published at {} -- before the \
                 epoch opened, so a committer in the previous epoch held it",
                time_of_round(round)
            );
            assert!(time_of_round(round) < boundary + PERIOD_SECONDS + PERIOD_SECONDS);
        }
    }

    #[test]
    fn a_boundary_before_genesis_clamps_to_the_first_round() {
        assert_eq!(round_for_epoch(0, 600), 1);
        assert_eq!(round_for_epoch(1, 1), 1);
    }

    #[test]
    fn an_absurd_epoch_does_not_panic() {
        // `overflow-checks` is on in release, so a saturating path is the
        // difference between a refusal and a node that dies on a hand-written
        // record.
        assert!(round_for_epoch(u64::MAX, u64::MAX) > 0);
        assert!(time_of_round(u64::MAX) > 0);
    }

    #[test]
    fn randomness_is_not_signature_shaped() {
        // 64 hex characters: the wrong drand field, which is the mistake this
        // check exists to catch.
        assert!(!is_signature_shaped(&"a".repeat(64)));
        assert!(is_signature_shaped(&"a".repeat(96)));
        assert!(!is_signature_shaped(&"A".repeat(96)));
        assert!(!is_signature_shaped(&"g".repeat(96)));
        assert!(!is_signature_shaped(""));
    }

    /// Round 1, and two rounds fetched live from four independent relays while
    /// this was written. Served by the network, verified here against nothing
    /// but [`PUBLIC_KEY`] -- which is the entire claim this module exists to
    /// make: no chain, no RPC, no relay, 96 bytes.
    const ROUNDS: [(u64, &str); 3] = [
        (1, "b55e7cb2d5c613ee0b2e28d6750aabbb78c39dcc96bd9d38c2c2e12198df95571de8e8e402a0cc48871c7089a2b3af4b"),
        (31_543_729, "9041fec7a1ba5398abdafd1cacd6a86563ec064b3bd8e36d7dc7ae3fe5244f1136788d106e3fd2996b8e30f2b8cf4f8b"),
        (31_543_812, "a517bcc786bde26257b53b18eb3f25dc4020d2ad2e2e85339e713b046b7b84df3794c57ab9cae880f0da7b2f120b70d7"),
    ];

    #[test]
    fn real_quicknet_rounds_verify() {
        for (round, signature) in ROUNDS {
            assert_eq!(verify(round, signature), Ok(()), "round {round}");
        }
    }

    #[test]
    fn a_signature_verifies_for_its_own_round_and_no_other() {
        // The property the whole design rests on. If a signature verified under
        // more than one round, an operator could take any published round and
        // record it against whichever epoch suited them, and the derivation
        // that makes `block` non-negotiable would buy nothing.
        for (round, signature) in ROUNDS {
            assert_eq!(
                verify(round + 1, signature),
                Err(VerifyError::DoesNotVerify)
            );
            assert_eq!(
                verify(round - 1, signature),
                Err(VerifyError::DoesNotVerify)
            );
        }
    }

    #[test]
    fn a_tampered_signature_is_refused() {
        let (round, signature) = ROUNDS[2];
        // Flip one hex digit. Either it stops being a point of the subgroup, or
        // it stays one and signs nothing -- both are refusals, and which one is
        // not the interesting part.
        let mut flipped: Vec<char> = signature.chars().collect();
        flipped[7] = if flipped[7] == 'a' { 'b' } else { 'a' };
        let flipped: String = flipped.into_iter().collect();
        assert_ne!(flipped, signature);
        assert!(matches!(
            verify(round, &flipped),
            Err(VerifyError::NotACurvePoint | VerifyError::DoesNotVerify)
        ));

        // The other round's signature: a real point, a real signature, wrong
        // message. This is the case a subgroup check would not catch.
        assert_eq!(verify(round, ROUNDS[1].1), Err(VerifyError::DoesNotVerify));
    }

    #[test]
    fn the_wrong_shape_is_named_as_such() {
        // The randomness field, and an all-zero point. Distinct errors because
        // they are distinct mistakes and only one of them is an accusation.
        assert_eq!(
            verify(1, &"a".repeat(64)),
            Err(VerifyError::NotSignatureShaped)
        );
        assert_eq!(verify(1, ""), Err(VerifyError::NotSignatureShaped));
        assert_eq!(verify(1, &"f".repeat(96)), Err(VerifyError::NotACurvePoint));
    }

    #[test]
    fn the_pinned_key_decompresses() {
        // `VerifyError::PinnedKeyUnusable` is unreachable unless somebody edits
        // the constant, and this is the check that keeps it unreachable.
        assert!(public_key().is_some());
    }

    /// RFC 9380 Appendix K.1 and K.2, `expand_message_xmd(SHA-256)`.
    ///
    /// The expander is the one piece of this module written out by hand rather
    /// than taken from a library, so it is tested against the specification's
    /// own vectors and not only end to end through a curve. K.2 is the
    /// oversize-DST branch, which this crate never takes and which would
    /// otherwise be untested code sitting in a verification path.
    #[test]
    fn the_expander_matches_the_rfc_vectors() {
        const DST_K1: &[u8] = b"QUUX-V01-CS02-with-expander-SHA256-128";
        let expect = |bytes: Vec<u8>, want: &str| assert_eq!(crate::hex::encode(&bytes), want);

        expect(
            expand_message_xmd(b"", DST_K1, 0x20),
            "68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235",
        );
        expect(
            expand_message_xmd(b"abc", DST_K1, 0x20),
            "d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615",
        );
        expect(
            expand_message_xmd(b"abcdef0123456789", DST_K1, 0x20),
            "eff31487c770a893cfb36f912fbfcbff40d5661771ca4b2cb4eafe524333f5c1",
        );
        // 128 bytes: ell = 4, so this is the only vector here that exercises
        // the b_i chaining loop, which is where an expander goes wrong.
        expect(
            expand_message_xmd(b"", DST_K1, 0x80),
            "af84c27ccfd45d41914fdff5df25293e221afc53d8ad2ac06d5e3e29485dadbe\
             e0d121587713a3e0dd4d5e69e93eb7cd4f5df4cd103e188cf60cb02edc3edf18\
             eda8576c412b18ffb658e3dd6ec849469b979d444cf7b26911a08e63cf31f9dc\
             c541708d3491184472c2c29bb749d4286b004ceb5ee6b9a7fa5b646c993f0ced",
        );

        let long = [
            b"QUUX-V01-CS02-with-expander-SHA256-128-long-DST-".to_vec(),
            vec![b'1'; 208],
        ]
        .concat();
        assert_eq!(long.len(), 256, "K.2's DST must exceed 255 bytes to be K.2");
        expect(
            expand_message_xmd(b"", &long, 0x20),
            "e8dc0c8b686b7ef2074086fbdd2f30e3f8bfbd3bdf177f73f04b97ce618a3ed3",
        );
        expect(
            expand_message_xmd(b"abc", &long, 0x20),
            "52dbf4f36cf560fca57dedec2ad924ee9c266341d8f3d6afe5171733b16bbb12",
        );
    }

    #[test]
    fn an_impossible_expansion_returns_nothing_rather_than_panicking() {
        // ell > 255. Unreachable from this crate, which asks for 128, and a
        // verifier that a hostile input can abort is a denial of service.
        assert!(expand_message_xmd(b"", b"dst", 256 * 32 + 1).is_empty());
    }

    #[test]
    fn the_pinned_key_is_the_size_the_scheme_says() {
        // bls-unchained-g1-rfc9380: public keys on G2, signatures on G1.
        assert_eq!(PUBLIC_KEY.len(), 192);
        assert_eq!(CHAIN_HASH.len(), 64);
    }
}
