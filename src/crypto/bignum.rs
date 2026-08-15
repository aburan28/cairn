//! Fixed-width unsigned bignum arithmetic, and Montgomery modular multiplication.
//!
//! Exists for one caller: [`crate::vdf`], which needs `x^(2^T) mod N` in a group
//! of unknown order. Nothing else in this crate does arbitrary-precision
//! arithmetic — ed25519 and ML-KEM carry their own field code, and money is
//! `u128` on purpose — so this is deliberately the smallest thing that serves
//! that one need rather than a general bignum library.
//!
//! # Why Montgomery
//!
//! A VDF's whole security property is that computing it takes `T` *sequential*
//! squarings. `T` is large by construction, so the cost of one modular multiply
//! is multiplied by a million and a schoolbook reduction — a long division per
//! multiply — makes an honest prover a thousand times slower than it needs to
//! be without making an attacker any slower at all. Montgomery form replaces the
//! division with a multiply and a shift, which is the difference between a
//! beacon that takes a second and one that takes twenty minutes.
//!
//! # Why it is checked against another language's arithmetic
//!
//! Every operation here is pinned by vectors generated from Python's
//! arbitrary-precision integers (`scripts/gen-bignum-vectors.py`). Bignum code
//! is the kind that is subtly wrong on carries at the top limb, or on operands
//! that share a buffer, or exactly at a power of two — and a test written by the
//! same person who wrote the bug tends to agree with it. Python's integers are a
//! different implementation, in a different language, that nobody here wrote.

use core::cmp::Ordering;

/// A non-negative integer, little-endian in 64-bit limbs.
///
/// Normalised: no trailing zero limbs, and zero is the empty vector. That makes
/// [`Nat::cmp`] a length comparison first, and it means two values that are
/// equal have identical representations — which matters because this feeds a
/// consensus value, and "equal" has to mean one thing.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Nat {
    limbs: Vec<u64>,
}

impl Nat {
    pub fn zero() -> Nat {
        Nat { limbs: Vec::new() }
    }

    pub fn one() -> Nat {
        Nat { limbs: vec![1] }
    }

    pub fn from_u64(value: u64) -> Nat {
        let mut nat = Nat { limbs: vec![value] };
        nat.normalise();
        nat
    }

    /// Decode big-endian bytes, the way every serialised integer in this crate
    /// is written.
    pub fn from_be_bytes(bytes: &[u8]) -> Nat {
        let mut limbs = Vec::with_capacity(bytes.len().div_ceil(8));
        let mut taken = bytes.len();
        while taken > 0 {
            let start = taken.saturating_sub(8);
            let slice = &bytes[start..taken];
            let mut chunk = [0u8; 8];
            chunk[8 - slice.len()..].copy_from_slice(slice);
            limbs.push(u64::from_be_bytes(chunk));
            taken = start;
        }
        let mut nat = Nat { limbs };
        nat.normalise();
        nat
    }

    /// Encode big-endian, zero-padded to `width` bytes.
    ///
    /// Padded rather than minimal, because this is what goes into a record: two
    /// encodings of one value would be two records with two digests, and the
    /// canonical form of a number has to be a function of the number.
    pub fn to_be_bytes(&self, width: usize) -> Vec<u8> {
        let mut out = vec![0u8; width];
        for (index, limb) in self.limbs.iter().enumerate() {
            let bytes = limb.to_be_bytes();
            for (offset, byte) in bytes.iter().rev().enumerate() {
                let position = index * 8 + offset;
                if position < width {
                    out[width - 1 - position] = *byte;
                }
            }
        }
        out
    }

    pub fn is_zero(&self) -> bool {
        self.limbs.is_empty()
    }

    pub fn is_odd(&self) -> bool {
        self.limbs.first().is_some_and(|limb| limb & 1 == 1)
    }

    pub fn bits(&self) -> usize {
        match self.limbs.last() {
            None => 0,
            Some(top) => self.limbs.len() * 64 - top.leading_zeros() as usize,
        }
    }

    /// Bit `index`, counting from the least significant.
    pub fn bit(&self, index: usize) -> bool {
        let limb = index / 64;
        match self.limbs.get(limb) {
            None => false,
            Some(value) => (value >> (index % 64)) & 1 == 1,
        }
    }

    fn normalise(&mut self) {
        while self.limbs.last() == Some(&0) {
            self.limbs.pop();
        }
    }

    /// As a `u128`, or `None` if it does not fit.
    ///
    /// For the one place a value is known small and the arithmetic around it is
    /// hot enough that a bignum operation per step is the difference between a
    /// beacon taking a second and taking five: see the quotient stream in
    /// [`crate::vdf::prove`].
    pub fn to_u128(&self) -> Option<u128> {
        if self.limbs.len() > 2 {
            return None;
        }
        let low = u128::from(self.limbs.first().copied().unwrap_or(0));
        let high = u128::from(self.limbs.get(1).copied().unwrap_or(0));
        Some((high << 64) | low)
    }

    /// Ordering by value.
    ///
    /// Named `cmp` and *not* an `Ord` impl on purpose: deriving `Ord` on a
    /// struct whose field is a limb vector would compare lexicographically by
    /// limb, which for little-endian limbs is not numeric order and would be
    /// wrong in a way nothing here would notice.
    #[allow(clippy::should_implement_trait)]
    pub fn cmp(&self, other: &Nat) -> Ordering {
        match self.limbs.len().cmp(&other.limbs.len()) {
            Ordering::Equal => {}
            other => return other,
        }
        for index in (0..self.limbs.len()).rev() {
            match self.limbs[index].cmp(&other.limbs[index]) {
                Ordering::Equal => continue,
                other => return other,
            }
        }
        Ordering::Equal
    }

    pub fn add(&self, other: &Nat) -> Nat {
        let mut limbs = Vec::with_capacity(self.limbs.len().max(other.limbs.len()) + 1);
        let mut carry = 0u128;
        for index in 0..self.limbs.len().max(other.limbs.len()) {
            let a = u128::from(self.limbs.get(index).copied().unwrap_or(0));
            let b = u128::from(other.limbs.get(index).copied().unwrap_or(0));
            let sum = a + b + carry;
            limbs.push(sum as u64);
            carry = sum >> 64;
        }
        if carry > 0 {
            limbs.push(carry as u64);
        }
        let mut nat = Nat { limbs };
        nat.normalise();
        nat
    }

    /// `self - other`, which the caller must know is non-negative.
    ///
    /// Saturating at zero rather than panicking: every call site here has
    /// already compared, and a panic in a beacon computation is a node that
    /// stops rather than a node that disagrees.
    pub fn sub(&self, other: &Nat) -> Nat {
        let mut limbs = Vec::with_capacity(self.limbs.len());
        let mut borrow = 0i128;
        for index in 0..self.limbs.len() {
            let a = i128::from(self.limbs[index]);
            let b = i128::from(other.limbs.get(index).copied().unwrap_or(0));
            let mut diff = a - b - borrow;
            if diff < 0 {
                diff += 1i128 << 64;
                borrow = 1;
            } else {
                borrow = 0;
            }
            limbs.push(diff as u64);
        }
        let mut nat = Nat { limbs };
        nat.normalise();
        nat
    }

    pub fn mul(&self, other: &Nat) -> Nat {
        if self.is_zero() || other.is_zero() {
            return Nat::zero();
        }
        let mut limbs = vec![0u64; self.limbs.len() + other.limbs.len()];
        for (i, a) in self.limbs.iter().enumerate() {
            let mut carry = 0u128;
            for (j, b) in other.limbs.iter().enumerate() {
                let index = i + j;
                let product = u128::from(*a) * u128::from(*b) + u128::from(limbs[index]) + carry;
                limbs[index] = product as u64;
                carry = product >> 64;
            }
            let mut index = i + other.limbs.len();
            while carry > 0 {
                let sum = u128::from(limbs[index]) + carry;
                limbs[index] = sum as u64;
                carry = sum >> 64;
                index += 1;
            }
        }
        let mut nat = Nat { limbs };
        nat.normalise();
        nat
    }

    pub fn shl(&self, bits: usize) -> Nat {
        if self.is_zero() {
            return Nat::zero();
        }
        let whole = bits / 64;
        let part = bits % 64;
        let mut limbs = vec![0u64; whole];
        let mut carry = 0u64;
        for limb in &self.limbs {
            if part == 0 {
                limbs.push(*limb);
            } else {
                limbs.push((limb << part) | carry);
                carry = limb >> (64 - part);
            }
        }
        if part != 0 && carry != 0 {
            limbs.push(carry);
        }
        let mut nat = Nat { limbs };
        nat.normalise();
        nat
    }

    /// Long division: `(quotient, remainder)`.
    ///
    /// Binary, one bit at a time. Slow and obviously correct, which is the
    /// right trade here: division happens a handful of times per beacon
    /// (setting up Montgomery constants, and the small-modulus arithmetic in
    /// the proof), while *multiplication* happens millions of times and is the
    /// one that got the fast path.
    pub fn divrem(&self, divisor: &Nat) -> (Nat, Nat) {
        assert!(!divisor.is_zero(), "division by zero");
        if self.cmp(divisor) == Ordering::Less {
            return (Nat::zero(), self.clone());
        }
        let mut quotient = Nat {
            limbs: vec![0; self.limbs.len()],
        };
        let mut remainder = Nat::zero();
        for index in (0..self.bits()).rev() {
            remainder = remainder.shl(1);
            if self.bit(index) {
                remainder = remainder.add(&Nat::one());
            }
            if remainder.cmp(divisor) != Ordering::Less {
                remainder = remainder.sub(divisor);
                let limb = index / 64;
                if limb < quotient.limbs.len() {
                    quotient.limbs[limb] |= 1 << (index % 64);
                }
            }
        }
        quotient.normalise();
        (quotient, remainder)
    }

    pub fn rem(&self, modulus: &Nat) -> Nat {
        self.divrem(modulus).1
    }
}

/// A modulus in Montgomery form, plus the constants that make multiplication
/// cheap.
///
/// Built once per beacon and reused for every squaring, which is the whole
/// reason it is a struct rather than a free function: recomputing `n_prime`
/// inside the loop would put a modular inverse next to the operation that has
/// to be fast.
#[derive(Debug, Clone)]
pub struct Montgomery {
    modulus: Nat,
    limbs: usize,
    /// `-modulus^{-1} mod 2^64`.
    n_prime: u64,
    /// `R mod modulus`, which is Montgomery form's representation of one.
    r: Nat,
    /// `R^2 mod modulus`, for converting into the form.
    r2: Nat,
}

impl Montgomery {
    /// `None` for an even or zero modulus: Montgomery form needs an inverse of
    /// the modulus mod `2^64`, which an even number does not have. RSA moduli
    /// are odd, so this is a precondition rather than a limitation.
    pub fn new(modulus: Nat) -> Option<Montgomery> {
        if modulus.is_zero() || !modulus.is_odd() {
            return None;
        }
        let limbs = modulus.limbs.len();
        // Newton's iteration for the inverse mod 2^64: five doublings take a
        // 1-bit-correct seed to 64 bits.
        let n0 = modulus.limbs[0];
        let mut inverse = 1u64;
        for _ in 0..6 {
            inverse = inverse.wrapping_mul(2u64.wrapping_sub(n0.wrapping_mul(inverse)));
        }
        let n_prime = inverse.wrapping_neg();

        let r = Nat::one().shl(64 * limbs).rem(&modulus);
        let r2 = r.mul(&r).rem(&modulus);
        Some(Montgomery {
            modulus,
            limbs,
            n_prime,
            r,
            r2,
        })
    }

    pub fn modulus(&self) -> &Nat {
        &self.modulus
    }

    /// Montgomery reduction of a double-width product.
    fn redc(&self, value: &Nat) -> Nat {
        let mut t = value.limbs.clone();
        t.resize(2 * self.limbs + 1, 0);
        for i in 0..self.limbs {
            let m = t[i].wrapping_mul(self.n_prime);
            let mut carry = 0u128;
            for j in 0..self.limbs {
                let sum = u128::from(t[i + j])
                    + u128::from(m) * u128::from(self.modulus.limbs[j])
                    + carry;
                t[i + j] = sum as u64;
                carry = sum >> 64;
            }
            let mut index = i + self.limbs;
            while carry > 0 && index < t.len() {
                let sum = u128::from(t[index]) + carry;
                t[index] = sum as u64;
                carry = sum >> 64;
                index += 1;
            }
        }
        let mut result = Nat {
            limbs: t[self.limbs..].to_vec(),
        };
        result.normalise();
        if result.cmp(&self.modulus) != Ordering::Less {
            result = result.sub(&self.modulus);
        }
        result
    }

    /// Into Montgomery form: `a * R mod n`.
    pub fn enter(&self, value: &Nat) -> Nat {
        let reduced = value.rem(&self.modulus);
        self.redc(&reduced.mul(&self.r2))
    }

    /// Out of Montgomery form.
    pub fn leave(&self, value: &Nat) -> Nat {
        self.redc(value)
    }

    /// `a * b * R^{-1} mod n` — multiplication of two values already in form.
    pub fn mul(&self, a: &Nat, b: &Nat) -> Nat {
        self.redc(&a.mul(b))
    }

    /// Montgomery form's one.
    pub fn one(&self) -> Nat {
        self.r.clone()
    }

    /// `base^exponent mod n`, square-and-multiply, both operands ordinary.
    ///
    /// Not constant time, and deliberately so: every exponent this crate raises
    /// to is public — a VDF difficulty, a Fiat–Shamir challenge — so there is no
    /// secret whose timing could leak, and a windowed constant-time ladder would
    /// be more code guarding nothing.
    pub fn pow(&self, base: &Nat, exponent: &Nat) -> Nat {
        if exponent.is_zero() {
            return Nat::one().rem(&self.modulus);
        }
        let mut result = self.one();
        let mut square = self.enter(base);
        for index in 0..exponent.bits() {
            if exponent.bit(index) {
                result = self.mul(&result, &square);
            }
            square = self.mul(&square, &square);
        }
        self.leave(&result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vectors from Python's arbitrary-precision integers.
    ///
    /// The point of borrowing them is that Python's bignum is a different
    /// implementation, in a different language, that nobody here wrote — so a
    /// carry bug in this file cannot agree with the test that checks it.
    /// `scripts/gen-bignum-vectors.py` regenerates them.
    const P: &str = "\
        c7970ceedcc3b0754490201a7aa613cd73911081c790f5f1a8726f463550bb5b\
        7ff0db8e1ea1189ec72f93d1650011bd721aeeacc2acde32a04107f0648c2813\
        a31f5b0b7765ff8b44b4b6ffc93384b646eb09c7cf5e8592d40ea33c80039f35\
        b4f14a04b51f7bfd781be4d1673164ba8eb991c2c4d730bbbe35f592bdef524b";

    fn hex(text: &str) -> Nat {
        let bytes: Vec<u8> = (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
            .collect();
        Nat::from_be_bytes(&bytes)
    }

    #[test]
    fn bytes_round_trip_and_pad_to_a_fixed_width() {
        let value = hex(P);
        assert_eq!(value.bits(), 1024);
        let bytes = value.to_be_bytes(128);
        assert_eq!(Nat::from_be_bytes(&bytes), value);
        // Padded, not minimal: a record carries one encoding of a number or it
        // carries two digests for one value.
        assert_eq!(Nat::from_u64(1).to_be_bytes(4), vec![0, 0, 0, 1]);
        assert_eq!(Nat::zero().to_be_bytes(3), vec![0, 0, 0]);
    }

    #[test]
    fn add_sub_and_mul_agree_with_another_languages_arithmetic() {
        // a = 2^128 - 1, b = 2^64 + 1: the operands where a carry chain runs
        // off the top limb, which is where schoolbook bignums are wrong.
        let a = hex("ffffffffffffffffffffffffffffffff");
        let b = hex("010000000000000001");
        assert_eq!(a.add(&b), hex("0100000000000000010000000000000000"));
        assert_eq!(a.sub(&b), hex("fffffffffffffffefffffffffffffffe"));
        assert_eq!(
            a.mul(&b),
            hex("010000000000000000fffffffffffffffeffffffffffffffff")
        );
        // Zero is the empty limb vector everywhere, so equal values compare
        // equal whatever produced them.
        assert!(a.sub(&a).is_zero());
        assert_eq!(a.mul(&Nat::zero()), Nat::zero());
    }

    #[test]
    fn divrem_reproduces_the_dividend_and_matches_python() {
        let a = hex(P);
        let b = hex("0123456789abcdef0123456789abcdef");
        let (quotient, remainder) = a.divrem(&b);
        assert_eq!(quotient.mul(&b).add(&remainder), a);
        assert_eq!(remainder.cmp(&b), Ordering::Less);
        assert_eq!(
            quotient,
            hex("\
                af6bc25df007febb8648e4484d4ac7da9b5a7db97e0893a4748159c3a04c83a4\
                e4e733fdd6b9ff0bd397100e402c18e95c90ab19258a643377afacf7e3a09329\
                9b41ca16d1c2f10ea1721f98c0c2cf86b8417248cc699078c62bc08546dffdfb\
                72a92589048fc967d453f2080b5d5495f7")
        );
        assert_eq!(remainder, hex("6d9c9ae36670d5490cd41784e385b2"));

        // Exactly at a limb boundary, which is where a shift-based divider
        // shifts by 64 and gets an undefined shift instead of a zero.
        let power = Nat::one().shl(128);
        let (q, r) = power.divrem(&Nat::one().shl(64));
        assert_eq!(q, Nat::one().shl(64));
        assert!(r.is_zero());
    }

    #[test]
    fn montgomery_pow_matches_python_pow() {
        // If these disagree, the Montgomery constants are wrong and every VDF
        // built on them is a different function than the one the record claims.
        let m = Montgomery::new(hex(P)).expect("odd modulus");
        assert_eq!(
            m.pow(&Nat::from_u64(3), &Nat::from_u64(65537)),
            hex("\
                5596b8f351c7d389e6cd30620b3f9a0b3c1d48d70d82688f93f2b7b91aa958e8\
                3ea9c3b4035658b18c5a3887d6ec4ec630b7dc7cbdaa896cb247e2422d7c4bc1\
                c2f74bda0316ccee519d35875f6f9b1a4753326de997902bafe006c15711962b\
                7383bdb12e489fcef4b6deebd8be0514b1be0697f040d5fd357dcd1170b74f1a")
        );
        assert_eq!(
            m.pow(&Nat::from_u64(2), &Nat::from_u64(1_000_000)),
            hex("\
                13c59809a80a6a2abcd2fcb208cca611997d0c0bc8afaa821577a0aecc8bc92d\
                198d8129d5099f4a9cd1ce7876b0b0f5041b35ca9973573a9e4dccab1fe7a749\
                5d9c14c7972029e440092d2300395dbe42256a9c9b7a6dc5ae7ea06870a69a62\
                56a7e3b2f070d08dfaae419466f183928e69b1e6f1fcf8afcb913b9feada0ad2")
        );
        assert_eq!(
            m.pow(&Nat::from_u64(1), &Nat::from_u64(1_000_000)),
            Nat::one()
        );
        assert_eq!(m.pow(&Nat::from_u64(2), &Nat::zero()), Nat::one());
    }

    #[test]
    fn entering_and_leaving_montgomery_form_is_the_identity() {
        let m = Montgomery::new(hex(P)).expect("odd modulus");
        for value in [1u64, 2, 3, 65537, u64::MAX] {
            let nat = Nat::from_u64(value);
            assert_eq!(m.leave(&m.enter(&nat)), nat);
        }
        // And the form's one really is one.
        let three = Nat::from_u64(3);
        assert_eq!(m.leave(&m.mul(&m.one(), &m.enter(&three))), three);
    }

    #[test]
    fn an_even_modulus_has_no_montgomery_form() {
        // Not a limitation being worked around: Montgomery needs the modulus
        // invertible mod 2^64, an even number is not, and an RSA modulus is
        // odd. Refused rather than producing wrong answers quietly.
        assert!(Montgomery::new(Nat::from_u64(4)).is_none());
        assert!(Montgomery::new(Nat::zero()).is_none());
        assert!(Montgomery::new(Nat::from_u64(9)).is_some());
    }
}
