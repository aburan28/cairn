//! The check that makes a version-3 sealed envelope's shares verifiable:
//! Pedersen commitments over Ristretto255, written from the protocol.
//!
//! A dealer commits to two polynomials of degree `t - 1`, `f` (whose constant
//! term is the secret) and `g`, as `C_j = a_j·G + b_j·H`. A share for seat `x`
//! is `s ‖ r` = `f(x) ‖ g(x)`, two canonical little-endian scalars, and it is
//! the dealer's exactly when `s·G + r·H` equals `Σ_j x^j·C_j`. `G` is the
//! Ristretto basepoint; `H` is SHA-512 of `"proofwork/vss/pedersen-h/v1"`
//! mapped to the group (RFC 9496's one-way map), so nobody knows `log_G H`.
//!
//! Computed here as the sum it is -- each term, then compared -- rather than
//! the primary's single multiscalar product, so the two agree because the
//! algebra does, not because they share an evaluation.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest as _, Sha512};

/// The second generator.
pub fn generator_h() -> RistrettoPoint {
    let digest = Sha512::digest(b"proofwork/vss/pedersen-h/v1");
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    RistrettoPoint::from_uniform_bytes(&wide)
}

/// A canonical scalar from 32 bytes, or `None`.
fn scalar(bytes: &[u8]) -> Option<Scalar> {
    let array: [u8; 32] = bytes.try_into().ok()?;
    Option::from(Scalar::from_canonical_bytes(array))
}

/// Commitments decoded from their 32-byte encodings, or `None` if any is not
/// the canonical encoding of a group element.
pub fn decode(commitments: &[[u8; 32]]) -> Option<Vec<RistrettoPoint>> {
    commitments
        .iter()
        .map(|bytes| CompressedRistretto(*bytes).decompress())
        .collect()
}

/// Is `share` (`s ‖ r`) the dealer's share for seat `x`?
pub fn verify(commitments: &[RistrettoPoint], x: u8, share: &[u8]) -> bool {
    if x == 0 || share.len() != 64 || commitments.is_empty() {
        return false;
    }
    let (Some(s), Some(r)) = (scalar(&share[..32]), scalar(&share[32..])) else {
        return false;
    };
    let left = RISTRETTO_BASEPOINT_POINT * s + generator_h() * r;
    let at = Scalar::from(u64::from(x));
    let mut power = Scalar::ONE;
    let mut right = RistrettoPoint::default();
    for commitment in commitments {
        right += commitment * power;
        power *= at;
    }
    left == right
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The dealing the primary derives from a seed, re-derived here from the
    /// protocol: coefficient `j` of polynomial `p` (`f` or `g`) is SHA-512 of
    /// `"proofwork/vss/dealing/v1" ‖ seed ‖ p ‖ j`, reduced. The reference
    /// never deals; this exists to pin the same bytes the primary pins, from
    /// code that was not copied from it.
    fn coefficient(seed: &[u8; 32], polynomial: u8, index: u8) -> Scalar {
        let mut hasher = Sha512::new();
        hasher.update(b"proofwork/vss/dealing/v1");
        hasher.update(seed);
        hasher.update([polynomial, index]);
        let mut wide = [0u8; 64];
        wide.copy_from_slice(&hasher.finalize());
        Scalar::from_bytes_mod_order_wide(&wide)
    }

    #[test]
    fn the_generator_and_the_primarys_pinned_dealing_agree() {
        assert_eq!(
            hex(generator_h().compress().as_bytes()),
            "b40ac19d9b1b27664ad86b8d3ed4712c56462977aa2faba67f272d913488d55d"
        );
        let seed = [0x42u8; 32];
        let f = [coefficient(&seed, b'f', 0), coefficient(&seed, b'f', 1)];
        let g = [coefficient(&seed, b'g', 0), coefficient(&seed, b'g', 1)];
        let commitments: Vec<RistrettoPoint> = f
            .iter()
            .zip(&g)
            .map(|(a, b)| RISTRETTO_BASEPOINT_POINT * a + generator_h() * b)
            .collect();
        let encoded: Vec<String> = commitments
            .iter()
            .map(|c| hex(c.compress().as_bytes()))
            .collect();
        assert_eq!(
            encoded,
            [
                "8062c406da79b2ffeb1975700cdb87c2e34f5f498be429b9aa822684af9f3167",
                "84aad19f23a1ca752632f3c72aa9d2911c6fc8a6ffe1aa1c0ef4057831d87a08",
            ]
        );
        // f(1) = a0 + a1, g(1) = b0 + b1.
        let mut share = Vec::with_capacity(64);
        share.extend_from_slice((f[0] + f[1]).as_bytes());
        share.extend_from_slice((g[0] + g[1]).as_bytes());
        assert_eq!(
            hex(&share),
            "db6c651d9e09a3dc7eb23dbb592dbed6faf2646610fb8fa07e0f477137c16e0b\
             8757eff3a23fd2f0e002abc726503e79a6b596ad1a9f18f85c02740fadd9140e"
        );
        assert!(verify(&commitments, 1, &share));
        assert!(!verify(&commitments, 2, &share));
        assert!(!verify(&commitments, 0, &share));
        let mut flipped = share.clone();
        flipped[0] ^= 1;
        assert!(!verify(&commitments, 1, &flipped));
        assert!(!verify(&commitments, 1, &share[..63]));
    }

    #[test]
    fn non_canonical_encodings_are_refused() {
        let mut point = [0u8; 32];
        point[31] = 0x80;
        assert!(decode(&[point]).is_none());
        // ℓ, the group order: the smallest non-canonical scalar.
        let mut l = [0u8; 32];
        l[..16].copy_from_slice(&[
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14,
        ]);
        l[31] = 0x10;
        assert!(scalar(&l).is_none());
    }
}
