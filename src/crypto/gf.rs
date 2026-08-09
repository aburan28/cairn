//! GF(2^8), written once for two callers with opposite requirements.
//!
//! [`shamir`](super::shamir) multiplies **secret** bytes: a share is key
//! material, and the standard `EXP[LOG[a] + LOG[b]]` implementation indexes
//! memory with the secret, which is observable by anything sharing the cache.
//! [`crate::shards`] multiplies **public** bytes — a blob the network hands to
//! any peer that asks — hundreds of megabytes at a time, where a multiply per
//! byte through a masked eight-round loop is the difference between a command
//! that finishes and one that does not.
//!
//! Those are genuinely different requirements, and the usual answer is two
//! implementations. This crate has already paid for that answer once: *"the one
//! part of a DHT that is genuinely subtle is the part that must not"* drift, so
//! `swarm::dht` and `p2p::dht` became instantiations of one generic. A finite
//! field is the same shape of hazard, worse — two multiplies that disagree on
//! one of 65,536 products produce shards that reconstruct to garbage on the node
//! that used the other one, and the digest check reports only that *somebody*
//! lied.
//!
//! So there is **one** multiply here, [`mul`], and the bulk path does not
//! reimplement it — [`Row`] *calls* it, 256 times, to build a lookup table for
//! one fixed coefficient. Agreement is by construction rather than by test:
//! there is no second algorithm to agree with.
//!
//! # Which one to use
//!
//! | | indexed by | use for |
//! |---|---|---|
//! | [`mul`], [`inv`], [`pow`] | nothing | secrets: Shamir coefficients, Lagrange bases |
//! | [`Row`] | the byte being multiplied | public bulk data: erasure shards |
//!
//! **Never build a [`Row`] over a secret coefficient and never feed it secret
//! bytes.** A `Row` is a 256-byte table indexed by the plaintext byte, which is
//! exactly the cache-timing leak `mul` exists to avoid. It is safe in
//! [`crate::shards`] because every byte it touches is content the network
//! publishes; that is a property of the caller, not of this type, and nothing
//! here can check it.
//!
//! # Field
//!
//! GF(2^8) modulo the AES polynomial `x^8 + x^4 + x^3 + x + 1` (0x11b). The
//! choice of polynomial is arbitrary up to isomorphism and is therefore
//! consensus-critical in the same way an encoding is: two nodes reducing modulo
//! different primitive polynomials compute different parity bytes and would
//! disagree about what a shard is. It is stated here, once, and nothing else in
//! the crate names a reduction constant.

/// Low byte of `x^8 + x^4 + x^3 + x + 1` (0x11b) after the implicit `x^8`.
const REDUCTION: u8 = 0x1b;

/// Multiply in GF(2^8).
///
/// # What is and is not constant time
///
/// No lookup tables and no data-dependent branches: a masked Russian-peasant
/// loop with a fixed trip count of 8, using only `^`, `&`, `<<`, `>>` and
/// `wrapping_neg` — every one of which is single-cycle and operand-independent
/// on every CPU this could plausibly run on. In particular there is no `if` on
/// a secret bit and no array indexed by a secret byte.
///
/// **What is not claimed:** that the emitted machine code is constant time.
/// Rust and LLVM are permitted to turn a mask back into a branch, and nothing
/// here verifies the assembly. If constant time is load-bearing for your threat
/// model, check the disassembly; this comment is an argument about the source,
/// not a measurement of the binary.
///
/// Carry-less multiply with reduction folded into each step: shift `a` up one
/// degree per bit of `b`, and whenever that shift would have pushed a term into
/// `x^8`, subtract the modulus. Both conditionals are expressed as `0x00`/`0xff`
/// masks (`wrapping_neg` on a 0/1 value) rather than `if`.
pub const fn mul(a: u8, b: u8) -> u8 {
    let mut a = a;
    let mut b = b;
    let mut acc: u8 = 0;
    let mut step = 0;
    while step < 8 {
        // 0xff when the low bit of b is set, 0x00 otherwise.
        let add = (b & 1).wrapping_neg();
        acc ^= a & add;

        // 0xff when a is about to overflow degree 7, 0x00 otherwise.
        let overflow = ((a >> 7) & 1).wrapping_neg();
        a <<= 1; // the escaping x^8 term is dropped by the u8 width
        a ^= REDUCTION & overflow; // ...and subtracted back in here

        b >>= 1;
        step += 1;
    }
    acc
}

/// `base^exponent`, square-and-multiply over a *public* exponent.
///
/// The branch is on the exponent, which is a compile-time constant at every
/// call site, so timing depends on the exponent and not on `base`.
pub const fn pow(base: u8, exponent: u32) -> u8 {
    let mut result: u8 = 1;
    let mut squared = base;
    let mut e = exponent;
    while e > 0 {
        if e & 1 == 1 {
            result = mul(result, squared);
        }
        squared = mul(squared, squared);
        e >>= 1;
    }
    result
}

/// Multiplicative inverse, or `None` for zero.
///
/// The group has order 255, so `a^254 = a^-1` by Fermat. This is slower than a
/// table and that is the trade being made deliberately: in `shamir` it runs at
/// most `n` times per reconstruction on public share indices, and in `shards`
/// it runs `k^2` times per decode on public matrix entries. Its cost is
/// irrelevant next to the per-byte work in either caller, and a table would put
/// an inverse of a secret one careless call site away.
pub fn inv(a: u8) -> Option<u8> {
    if a == 0 {
        return None;
    }
    Some(pow(a, 254))
}

/// The 256 products of one fixed coefficient, for multiplying a lot of bytes by
/// it.
///
/// The bulk primitive is `dst ^= coefficient * src`, over whole shards, and it
/// is the only thing erasure coding does in quantity — encoding `m` parity
/// shards from `k` data shards is `k * m` of these over the shard length. A
/// [`mul`] per byte is eight masked rounds; a table lookup is one.
///
/// Built from [`mul`], not from a log/exp pair. The table is therefore a *cache*
/// of this module's own multiply rather than a second implementation of it, and
/// [`Row::of`] costs 256 multiplies once per coefficient — paid `k * m` times
/// per encode, against `k * m * shard_len` byte operations.
///
/// # The safety condition, restated because it is easy to lose
///
/// Indexed by the byte being multiplied. Feed it a secret and the secret is
/// visible to a cache-timing attacker. See the module docs.
#[derive(Clone)]
pub struct Row {
    table: [u8; 256],
}

impl Row {
    /// The multiplication table for `coefficient`.
    pub fn of(coefficient: u8) -> Row {
        let mut table = [0u8; 256];
        for (byte, slot) in table.iter_mut().enumerate() {
            // `byte` is 0..256 by construction, so the cast is exact.
            *slot = mul(coefficient, byte as u8);
        }
        Row { table }
    }

    /// `coefficient * byte`, the same answer [`mul`] gives.
    pub fn apply(&self, byte: u8) -> u8 {
        // Total by construction: the index is a `u8` and the table has 256
        // entries. The fallback keeps the function panic-free rather than
        // relying on the reader to check that.
        self.table.get(usize::from(byte)).copied().unwrap_or(0)
    }

    /// `dst ^= coefficient * src`, elementwise.
    ///
    /// Addition in a characteristic-2 field is XOR, so accumulating a linear
    /// combination is this called once per term with no carry to propagate and
    /// no order to preserve.
    ///
    /// Stops at the shorter of the two. A length mismatch is a caller bug
    /// ([`crate::shards`] holds every shard at one length), and truncating is
    /// the failure that stays inside the arithmetic instead of panicking in the
    /// middle of a reconstruction.
    pub fn mul_add(&self, dst: &mut [u8], src: &[u8]) {
        for (out, &byte) in dst.iter_mut().zip(src.iter()) {
            *out ^= self.apply(byte);
        }
    }
}

impl core::fmt::Debug for Row {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // `table[1]` is the coefficient: multiplication by one is the identity.
        // Printing the whole table would be 256 numbers nobody reads.
        write!(f, "Row({:#04x})", self.apply(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_answer_vectors() {
        // The two products every AES description uses as its worked example.
        assert_eq!(mul(0x57, 0x83), 0xc1);
        assert_eq!(mul(0x57, 0x13), 0xfe);
        assert_eq!(mul(0x02, 0x87), 0x15); // xtime with reduction
        assert_eq!(mul(0x00, 0xff), 0x00);
        assert_eq!(mul(0x01, 0xff), 0xff);
    }

    #[test]
    fn the_field_is_commutative_and_associative() {
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                assert_eq!(mul(a, b), mul(b, a), "commutativity at {a},{b}");
            }
        }
        // Associativity and distributivity over a coarse but structured sample.
        for a in (0..=255u8).step_by(7) {
            for b in (0..=255u8).step_by(11) {
                for c in (0..=255u8).step_by(13) {
                    assert_eq!(mul(mul(a, b), c), mul(a, mul(b, c)));
                    assert_eq!(mul(a, b ^ c), mul(a, b) ^ mul(a, c));
                }
            }
        }
    }

    #[test]
    fn every_non_zero_element_has_an_inverse() {
        assert_eq!(inv(0), None);
        for a in 1..=255u8 {
            let inverse = inv(a).expect("non-zero elements are invertible");
            assert_eq!(mul(a, inverse), 1, "inverse of {a}");
        }
    }

    #[test]
    fn a_row_agrees_with_mul_on_all_65536_products() {
        // The whole argument for having one field: the fast path is a cache of
        // the slow one. If this ever fails, two callers are computing in
        // different fields and a shard encoded on one node reconstructs to
        // garbage on another -- with the blob digest reporting only that
        // somebody lied, never who.
        for coefficient in 0..=255u8 {
            let row = Row::of(coefficient);
            for byte in 0..=255u8 {
                assert_eq!(
                    row.apply(byte),
                    mul(coefficient, byte),
                    "Row({coefficient}) disagrees at {byte}"
                );
            }
        }
    }

    #[test]
    fn mul_add_accumulates_a_linear_combination() {
        let a = [0x01u8, 0x02, 0x03, 0xff];
        let b = [0x10u8, 0x20, 0x30, 0x40];
        let mut acc = [0u8; 4];
        Row::of(0x02).mul_add(&mut acc, &a);
        Row::of(0x03).mul_add(&mut acc, &b);
        for i in 0..4 {
            assert_eq!(acc[i], mul(0x02, a[i]) ^ mul(0x03, b[i]));
        }

        // Adding the same term twice cancels: characteristic two, and the
        // property every decode relies on when it subtracts a known shard.
        Row::of(0x03).mul_add(&mut acc, &b);
        for i in 0..4 {
            assert_eq!(acc[i], mul(0x02, a[i]));
        }
    }

    #[test]
    fn mul_add_truncates_rather_than_panicking_on_a_length_mismatch() {
        // A caller bug, and the failure mode is chosen: truncating stays inside
        // the arithmetic where a digest check will catch it, panicking would
        // abort a reconstruction mid-way.
        let mut dst = [0xffu8; 2];
        Row::of(0x01).mul_add(&mut dst, &[0x0f]);
        assert_eq!(dst, [0xf0, 0xff]);
    }

    #[test]
    fn debug_names_the_coefficient_and_not_the_table() {
        assert_eq!(format!("{:?}", Row::of(0x1b)), "Row(0x1b)");
    }
}
