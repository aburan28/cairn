//! Pedersen verifiable secret sharing over Ristretto255.
//!
//! # Why a sealed submission needs it
//!
//! A sealed envelope splits its content key across a committee, and until this
//! module the split was plain Shamir over GF(2^8): a share was a bare point,
//! and nothing published at commit time said which polynomial the points were
//! on. Two things followed, and both were the submitter's to exploit:
//!
//! - **The polynomial's degree was unchecked.** A dealer who split with degree
//!   `t` or more instead of `t - 1` made different `t`-subsets reconstruct
//!   different keys, so *which* members published decided what opened, and a
//!   dealer colluding with one member could choose.
//! - **A bad share could not be blamed.** A member whose share did not open
//!   could not show that the dealer sealed garbage rather than that they were
//!   lying, so a dealer could quietly disable honest seats and keep the power
//!   to open (or not) with the seats that colluded.
//!
//! Pedersen VSS answers both with one published object. The dealer commits to
//! the coefficients of two polynomials of degree `t - 1`, `f` (whose constant
//! term is the secret) and `g` (blinding):
//!
//! ```text
//!     C_j = a_j·G + b_j·H        j = 0 .. t-1
//! ```
//!
//! and a share for abscissa `x` is the pair `(s, r) = (f(x), g(x))`. Anyone can
//! check a share against the commitments alone:
//!
//! ```text
//!     s·G + r·H  ==  Σ_j x^j · C_j
//! ```
//!
//! Exactly `t` commitments are published, so every share that passes lies on
//! one polynomial of degree below `t`, and **any `t` checked shares
//! reconstruct the same secret**. The degree is bound when the envelope is
//! written, not discovered when it is opened. And because a share is checkable
//! on its own, a dealer accused of sealing garbage to a seat can be made to
//! publish that seat's share in the clear: one that checks clears the dealer
//! and restores the seat, and failing to produce one is the dealer's fault
//! alone. That protocol lives in [`crate::node`]; this module is the algebra.
//!
//! # What it rests on
//!
//! - **Hiding is information-theoretic.** `C_0 = k·G + b_0·H` with `b_0`
//!   uniform says nothing about `k`, to anyone, ever -- including an adversary
//!   who records the log today and breaks discrete logarithms later. That is
//!   the property the rest of [`super::envelope`] was rebuilt on post-quantum
//!   KEMs to keep, and Pedersen does not give it back.
//! - **Binding is discrete log in Ristretto255.** A dealer who knew `log_G H`
//!   could open the commitments to different polynomials. `H` is a hash to the
//!   group of a fixed string ([`generator_h`]), so nobody knows it. Binding is
//!   only needed while a submission is live, so a discrete-log break *later*
//!   costs nothing; one available to a dealer *at commit time* would let them
//!   equivocate, which is the honest limit of this scheme.
//!
//! # Encoding
//!
//! A commitment is a 32-byte compressed Ristretto point and must be canonical:
//! decoding refuses any other spelling, so one envelope has one encoding. A
//! scalar is its 32-byte canonical little-endian form, and a share body is
//! `s ‖ r`, [`SHARE_LEN`] bytes.

use std::sync::OnceLock;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{IsIdentity as _, VartimeMultiscalarMul as _};
use sha2::{Digest as _, Sha512};
use zeroize::{Zeroize, Zeroizing};

/// Bytes in a share body: two canonical scalars, `s ‖ r`.
pub const SHARE_LEN: usize = 64;

/// Bytes in one encoded commitment: a compressed Ristretto point.
pub const COMMITMENT_LEN: usize = 32;

/// The string `H` is hashed from. A wire constant: changing it changes every
/// commitment, so it is spelled with the protocol's original name.
const H_DOMAIN: &[u8] = b"proofwork/vss/pedersen-h/v1";

/// Domain of the dealing's coefficients, derived from the dealer's seed.
const DEALING_DOMAIN: &[u8] = b"proofwork/vss/dealing/v1";

/// The second generator, `H`: SHA-512 of `proofwork/vss/pedersen-h/v1`, mapped to
/// the group.
///
/// Hashed rather than chosen so that nobody -- this crate's authors included --
/// knows its discrete logarithm base `G`, which is the whole of the binding
/// property. `from_uniform_bytes` is the one-way map of RFC 9496 §4.3.4.
pub fn generator_h() -> RistrettoPoint {
    static H: OnceLock<RistrettoPoint> = OnceLock::new();
    *H.get_or_init(|| {
        let mut wide = [0u8; 64];
        wide.copy_from_slice(&Sha512::digest(H_DOMAIN));
        RistrettoPoint::from_uniform_bytes(&wide)
    })
}

/// One scalar of the dealing, derived from the dealer's seed: SHA-512 of the
/// domain, the seed, which polynomial and which coefficient, reduced.
fn coefficient(seed: &[u8; 32], polynomial: u8, index: u8) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(DEALING_DOMAIN);
    hasher.update(seed);
    hasher.update([polynomial, index]);
    let mut wide = Zeroizing::new([0u8; 64]);
    wide.copy_from_slice(&hasher.finalize());
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// A dealing: the two polynomials behind one set of commitments.
///
/// Derived from a 32-byte seed so that the dealer can keep the seed and
/// nothing else. That is what lets a submitter answer a complaint after the
/// fact without having stored every share -- and it is also exactly as
/// sensitive as the content key, because the seed *determines* the content
/// key. Wiped on drop.
pub struct Dealer {
    f: Vec<Scalar>,
    g: Vec<Scalar>,
}

impl Drop for Dealer {
    fn drop(&mut self) {
        self.f.zeroize();
        self.g.zeroize();
    }
}

impl Dealer {
    /// The dealing `seed` determines, with polynomials of degree
    /// `threshold - 1`. `None` for a threshold of zero, which shares nothing.
    pub fn from_seed(seed: &[u8; 32], threshold: u8) -> Option<Dealer> {
        if threshold == 0 {
            return None;
        }
        Some(Dealer {
            f: (0..threshold).map(|j| coefficient(seed, b'f', j)).collect(),
            g: (0..threshold).map(|j| coefficient(seed, b'g', j)).collect(),
        })
    }

    /// The shared secret, `f(0)`.
    pub fn secret(&self) -> Scalar {
        self.f[0]
    }

    /// `C_j = a_j·G + b_j·H`, compressed, one per coefficient.
    pub fn commitments(&self) -> Vec<[u8; COMMITMENT_LEN]> {
        let h = generator_h();
        self.f
            .iter()
            .zip(&self.g)
            .map(|(a, b)| {
                (a * RISTRETTO_BASEPOINT_POINT + b * h)
                    .compress()
                    .to_bytes()
            })
            .collect()
    }

    /// The share for abscissa `x`: `f(x) ‖ g(x)`. `None` for zero, the one
    /// abscissa that is not a share -- `f(0)` *is* the secret.
    pub fn share(&self, x: u8) -> Option<Zeroizing<[u8; SHARE_LEN]>> {
        if x == 0 {
            return None;
        }
        let at = Scalar::from(u64::from(x));
        let mut s = evaluate(&self.f, at);
        let mut r = evaluate(&self.g, at);
        let mut out = Zeroizing::new([0u8; SHARE_LEN]);
        out[..32].copy_from_slice(s.as_bytes());
        out[32..].copy_from_slice(r.as_bytes());
        s.zeroize();
        r.zeroize();
        Some(out)
    }
}

/// `Σ c_j·x^j`, by Horner.
fn evaluate(coefficients: &[Scalar], x: Scalar) -> Scalar {
    coefficients
        .iter()
        .rev()
        .fold(Scalar::ZERO, |acc, c| acc * x + c)
}

/// A share body's two scalars, if both are canonical.
pub fn share_scalars(share: &[u8]) -> Option<(Scalar, Scalar)> {
    if share.len() != SHARE_LEN {
        return None;
    }
    let mut s = [0u8; 32];
    let mut r = [0u8; 32];
    s.copy_from_slice(&share[..32]);
    r.copy_from_slice(&share[32..]);
    let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(s))?;
    let r = Option::<Scalar>::from(Scalar::from_canonical_bytes(r))?;
    Some((s, r))
}

/// A dealer's published commitments, decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commitments {
    points: Vec<RistrettoPoint>,
}

impl Commitments {
    /// Decode `encoded`, refusing an empty list and any point that is not the
    /// canonical encoding of a group element.
    pub fn decode(encoded: &[[u8; COMMITMENT_LEN]]) -> Option<Commitments> {
        if encoded.is_empty() {
            return None;
        }
        let points = encoded
            .iter()
            .map(|bytes| CompressedRistretto(*bytes).decompress())
            .collect::<Option<Vec<_>>>()?;
        Some(Commitments { points })
    }

    /// How many shares open the secret: one per committed coefficient.
    pub fn threshold(&self) -> usize {
        self.points.len()
    }

    /// Does `share` lie on the committed polynomials at `x`?
    ///
    /// `s·G + r·H − Σ x^j·C_j` must be the identity. Variable-time, which is
    /// right: everything it touches is public by the time anyone checks it.
    pub fn verify(&self, x: u8, share: &[u8]) -> bool {
        if x == 0 {
            return false;
        }
        let Some((s, r)) = share_scalars(share) else {
            return false;
        };
        let at = Scalar::from(u64::from(x));
        let mut scalars = Vec::with_capacity(self.points.len() + 2);
        let mut points = Vec::with_capacity(self.points.len() + 2);
        scalars.push(s);
        points.push(RISTRETTO_BASEPOINT_POINT);
        scalars.push(r);
        points.push(generator_h());
        let mut power = Scalar::ONE;
        for commitment in &self.points {
            scalars.push(-power);
            points.push(*commitment);
            power *= at;
        }
        RistrettoPoint::vartime_multiscalar_mul(scalars, points).is_identity()
    }
}

/// `f(0)` from shares `(x, f(x))` by Lagrange interpolation, or `None` if an
/// abscissa is zero or repeated.
///
/// Uses every share given: pass exactly the `t` to use. With checked shares
/// any `t` give the same answer, which is the point of checking them.
pub fn reconstruct(shares: &[(u8, Scalar)]) -> Option<Scalar> {
    if shares.is_empty() {
        return None;
    }
    let mut seen = [false; 256];
    for (x, _) in shares {
        if *x == 0 || seen[usize::from(*x)] {
            return None;
        }
        seen[usize::from(*x)] = true;
    }
    let mut secret = Scalar::ZERO;
    for (i, (xi, si)) in shares.iter().enumerate() {
        let xi = Scalar::from(u64::from(*xi));
        let mut numerator = Scalar::ONE;
        let mut denominator = Scalar::ONE;
        for (j, (xj, _)) in shares.iter().enumerate() {
            if i == j {
                continue;
            }
            let xj = Scalar::from(u64::from(*xj));
            numerator *= xj;
            denominator *= xj - xi;
        }
        secret += si * numerator * denominator.invert();
    }
    Some(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn dealer(seed_byte: u8, threshold: u8) -> Dealer {
        Dealer::from_seed(&[seed_byte; 32], threshold).expect("threshold > 0")
    }

    #[test]
    fn every_dealt_share_checks_and_any_t_of_them_open_the_secret() {
        let dealer = dealer(7, 3);
        let commitments = Commitments::decode(&dealer.commitments()).expect("canonical");
        assert_eq!(commitments.threshold(), 3);
        let shares: Vec<(u8, Scalar)> = (1..=5u8)
            .map(|x| {
                let share = dealer.share(x).expect("non-zero x");
                assert!(commitments.verify(x, share.as_slice()), "seat {x}");
                (x, share_scalars(share.as_slice()).expect("canonical").0)
            })
            .collect();
        for subset in [[0, 1, 2], [0, 2, 4], [1, 3, 4], [4, 3, 2]] {
            let chosen: Vec<_> = subset.iter().map(|&i| shares[i]).collect();
            assert_eq!(reconstruct(&chosen), Some(dealer.secret()));
        }
        // Below the threshold the answer is some other scalar, as Shamir's is.
        assert_ne!(reconstruct(&shares[..2]), Some(dealer.secret()));
    }

    #[test]
    fn a_share_that_is_not_on_the_committed_polynomials_does_not_check() {
        let dealer = dealer(1, 3);
        let commitments = Commitments::decode(&dealer.commitments()).expect("canonical");
        let honest = dealer.share(2).expect("x");
        // Another seat's share, a different dealing's share, a flipped bit,
        // the right share at x = 0, and the wrong length: none checks.
        assert!(!commitments.verify(3, honest.as_slice()));
        let other = super::Dealer::from_seed(&[2; 32], 3).expect("t");
        assert!(!commitments.verify(2, other.share(2).expect("x").as_slice()));
        let mut flipped = *honest;
        flipped[5] ^= 1;
        assert!(!commitments.verify(2, &flipped));
        assert!(!commitments.verify(0, honest.as_slice()));
        assert!(!commitments.verify(2, &honest[..63]));
        // A share from a polynomial of degree t — what the commitments rule
        // out — fails against commitments to only t coefficients.
        let wider = dealer_with_degree(3);
        let narrow = Commitments::decode(&wider.commitments()[..3]).expect("canonical");
        let mut failed = 0;
        for x in 1..=5u8 {
            if !narrow.verify(x, wider.share(x).expect("x").as_slice()) {
                failed += 1;
            }
        }
        assert_eq!(
            failed, 5,
            "a degree-t share passed degree-(t-1) commitments"
        );
    }

    fn dealer_with_degree(degree: u8) -> Dealer {
        Dealer::from_seed(&[9; 32], degree + 1).expect("t")
    }

    #[test]
    fn non_canonical_scalars_and_points_are_refused() {
        // The group order ℓ itself is the smallest non-canonical scalar.
        let mut l = [0u8; 32];
        l.copy_from_slice(&[
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ]);
        let mut share = [0u8; SHARE_LEN];
        share[..32].copy_from_slice(&l);
        assert_eq!(share_scalars(&share), None);
        // A point encoding with the high bit set is never canonical.
        let mut point = [0u8; 32];
        point[31] = 0x80;
        assert_eq!(Commitments::decode(&[point]), None);
        assert_eq!(Commitments::decode(&[]), None);
        // Reconstruction refuses a zero or repeated abscissa.
        assert_eq!(reconstruct(&[(0, Scalar::ONE)]), None);
        assert_eq!(reconstruct(&[(1, Scalar::ONE), (1, Scalar::ONE)]), None);
        assert_eq!(Dealer::from_seed(&[0; 32], 0).map(|d| d.secret()), None);
        assert!(dealer(3, 2).share(0).is_none());
    }

    /// Pinned bytes: `H` and one seeded dealing. The reference implementation
    /// pins the same values, so the two agree on the generator, the
    /// derivation and the encoding, not just on round trips.
    #[test]
    fn the_generator_and_a_seeded_dealing_are_pinned() {
        assert_eq!(
            hex(generator_h().compress().as_bytes()),
            PINNED_H,
            "H moved: every commitment ever written moves with it"
        );
        let dealer = dealer(0x42, 2);
        let commitments: Vec<String> = dealer.commitments().iter().map(|c| hex(c)).collect();
        assert_eq!(commitments, PINNED_COMMITMENTS);
        assert_eq!(hex(dealer.share(1).expect("x").as_slice()), PINNED_SHARE_1);
    }

    const PINNED_H: &str = "b40ac19d9b1b27664ad86b8d3ed4712c56462977aa2faba67f272d913488d55d";
    const PINNED_COMMITMENTS: [&str; 2] = [
        "8062c406da79b2ffeb1975700cdb87c2e34f5f498be429b9aa822684af9f3167",
        "84aad19f23a1ca752632f3c72aa9d2911c6fc8a6ffe1aa1c0ef4057831d87a08",
    ];
    const PINNED_SHARE_1: &str = "db6c651d9e09a3dc7eb23dbb592dbed6faf2646610fb8fa07e0f477137c16e0b8757eff3a23fd2f0e002abc726503e79a6b596ad1a9f18f85c02740fadd9140e";
}
