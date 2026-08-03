//! Shamir t-of-n secret sharing over GF(2^8).
//!
//! This is the load-bearing half of the sealed-submission flow in
//! `docs/censorship.md` §2. A submitter seals the artifact under a symmetric
//! key `K`, splits `K` into `n` shares, and hands share `i` to committee member
//! `i`. At the epoch boundary any `t` members publish their shares, `K` is
//! reconstructed *without the submitter*, and the artifact opens. That is the
//! whole point: the submitter can be offline, jailed, or firewalled and still
//! be paid, because nothing is required of them after commit.
//!
//! # Why this is implemented here rather than pulled in
//!
//! Reconstruction is the one path where a silent bug loses **every submission
//! in the epoch at once** — not one user's data, the whole epoch's. A wrong
//! Lagrange coefficient or a mis-reduced field product produces a key that is
//! merely wrong, the AEAD open fails, and the failure is indistinguishable from
//! a submitter having sealed garbage. There is no partial credit and no way to
//! tell the two apart after the fact, so the arithmetic is written out where a
//! reviewer can check it against the textbook line by line.
//!
//! # The caveat that matters more than the rest of this file
//!
//! **`combine` cannot detect that it was given too few shares.** With fewer
//! than `t` shares it returns a plausible-looking byte string that is not the
//! secret, and it returns it as `Ok`. This is not an oversight to be fixed
//! later; it *is* the security property. Any `t-1` shares are, by construction,
//! consistent with every possible secret — that is what "the committee cannot
//! read a submission early unless `t` members collude" means. An implementation
//! that could tell you "you are one share short" would be one that leaks
//! information about the secret to a sub-threshold set.
//!
//! The caller is therefore responsible for knowing `t` and supplying at least
//! that many shares. The system-level check is downstream and already exists:
//! reconstruct `K`, open the AEAD envelope, and re-derive the commitment. A
//! short reconstruction fails all three. Never treat a successful `combine` as
//! evidence that the reconstruction was correct.
//!
//! # Field
//!
//! GF(2^8) modulo the AES polynomial `x^8 + x^4 + x^3 + x + 1` (0x11b). Bytes
//! are shared independently, so a share is exactly as long as the secret and
//! there is no block padding or length hiding — the envelope layer, not this
//! module, is where `docs/censorship.md` §4's fixed-size-bucket mitigation
//! belongs.
//!
//! # Timing
//!
//! Read [`gf`] before assuming anything. Summary: the multiply is branch-free
//! and **table-free**, specifically so that no memory access is indexed by a
//! secret byte — the standard log/exp-table implementation leaks the secret
//! through the cache and is not used here. What is *not* claimed: that the
//! compiler preserved the branch-free form, and that the length of the secret
//! or the number and identity of the shares are hidden. They are public.

use core::fmt;

use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::canonical::Value;

// -- errors ----------------------------------------------------------------

/// Everything that can go wrong splitting, combining, or decoding a share.
///
/// Note what is absent: there is no "not enough shares" variant, and there
/// cannot be one. See the module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShamirError {
    /// Nothing to share. Sharing zero bytes would produce shares that are
    /// trivially equal, which is a confusing way to fail later.
    EmptySecret,
    /// A 0-of-n threshold is not a scheme; the secret would be recoverable
    /// from no shares at all.
    ThresholdZero,
    /// More shares are needed to reconstruct than were ever handed out, so the
    /// secret is destroyed the moment the caller drops it.
    ThresholdExceedsShares { threshold: u8, shares: u8 },
    /// `combine` was given an empty slice.
    NoShares,
    /// Share index 0 was offered. `x = 0` is where the secret lives: a "share"
    /// at index 0 *is* the plaintext secret, so accepting one would silently
    /// convert a threshold scheme into a plaintext handoff.
    IndexZero,
    /// Two shares claim the same index. Their Lagrange denominator is
    /// `x_j ^ x_i == 0`, i.e. division by zero; the interpolation is undefined
    /// and the usual cause is a duplicated committee member.
    DuplicateIndex { index: u8 },
    /// Shares of different lengths cannot come from one split.
    LengthMismatch { expected: usize, found: usize },
    /// A share carries no bytes, so it shares nothing.
    EmptyShare,
    /// The encoded form is not an object.
    NotAnObject,
    /// A required field is absent from the encoded form.
    MissingField { field: &'static str },
    /// A field is present with the wrong shape.
    InvalidField {
        field: &'static str,
        expected: &'static str,
    },
    /// An invariant this module establishes *before* using it was violated
    /// anyway — reachable only through a bug in this file, never through
    /// caller input.
    ///
    /// It is an error rather than a `panic!` on purpose. A panic in the
    /// reconstruction path aborts the reveal for every submission in the epoch,
    /// which is precisely the availability failure the sealed-submission design
    /// exists to prevent (`docs/censorship.md` §2, "it can refuse to publish
    /// shares"). A bug here should cost one reveal attempt and a loud error,
    /// not the epoch.
    Invariant(&'static str),
}

impl fmt::Display for ShamirError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ShamirError::EmptySecret => f.write_str("cannot share an empty secret"),
            ShamirError::ThresholdZero => {
                f.write_str("threshold must be at least 1; a 0-of-n scheme protects nothing")
            }
            ShamirError::ThresholdExceedsShares { threshold, shares } => write!(
                f,
                "threshold {threshold} exceeds the {shares} shares issued; the secret \
                 would be unrecoverable"
            ),
            ShamirError::NoShares => f.write_str("no shares supplied"),
            ShamirError::IndexZero => {
                f.write_str("share index 0 is the secret itself, not a share of it")
            }
            ShamirError::DuplicateIndex { index } => {
                write!(f, "share index {index} appears more than once")
            }
            ShamirError::LengthMismatch { expected, found } => write!(
                f,
                "shares must all be the same length: expected {expected} bytes, found {found}"
            ),
            ShamirError::EmptyShare => f.write_str("share carries no data"),
            ShamirError::NotAnObject => f.write_str("share: record must be an object"),
            ShamirError::MissingField { field } => {
                write!(f, "share: missing required field {field:?}")
            }
            ShamirError::InvalidField { field, expected } => {
                write!(f, "share: field {field:?} must be {expected}")
            }
            ShamirError::Invariant(what) => {
                write!(f, "shamir internal invariant violated: {what}")
            }
        }
    }
}

impl std::error::Error for ShamirError {}

// -- field -----------------------------------------------------------------

/// GF(2^8) arithmetic, branch-free and table-free.
///
/// # What is and is not constant time
///
/// [`mul`](gf::mul) uses no lookup tables and no data-dependent branches. It is
/// written as a masked Russian-peasant loop with a fixed trip count of 8, using
/// only `^`, `&`, `<<`, `>>` and `wrapping_neg` — every one of which is
/// single-cycle and operand-independent on every CPU this could plausibly run
/// on. In particular there is no `if` on a secret bit and no array indexed by a
/// secret byte, which rules out the cache-timing leak that the conventional
/// log/exp-table implementation has: `EXP[LOG[a] + LOG[b]]` indexes memory with
/// the secret and is observable by anything sharing the cache.
///
/// **What is not claimed:** that the emitted machine code is constant time.
/// Rust and LLVM are permitted to turn a mask back into a branch, and nothing
/// here verifies the assembly. If constant time is load-bearing for your threat
/// model, check the disassembly; this comment is an argument about the source,
/// not a measurement of the binary.
///
/// [`inv`](gf::inv) and [`pow`](gf::pow) branch on the bits of a *public*
/// constant exponent, never on their input. `inv` also tests its argument
/// against zero, which is fine because it is only ever called on Lagrange
/// denominators derived from share indices, and share indices are public — they
/// are published alongside the shares by construction.
mod gf {
    /// Low byte of `x^8 + x^4 + x^3 + x + 1` (0x11b) after the implicit `x^8`.
    const REDUCTION: u8 = 0x1b;

    /// Multiply in GF(2^8).
    ///
    /// Carry-less multiply with reduction folded into each step: shift `a` up
    /// one degree per bit of `b`, and whenever that shift would have pushed a
    /// term into `x^8`, subtract the modulus. Both conditionals are expressed
    /// as `0x00`/`0xff` masks (`wrapping_neg` on a 0/1 value) rather than `if`.
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
    /// The group has order 255, so `a^254 = a^-1` by Fermat. This is slower
    /// than a table and that is the trade being made deliberately; it runs at
    /// most `n` times per reconstruction on public inputs, so its cost is
    /// irrelevant next to the per-byte work.
    pub fn inv(a: u8) -> Option<u8> {
        if a == 0 {
            return None;
        }
        Some(pow(a, 254))
    }
}

// -- share -----------------------------------------------------------------

/// One share of a split secret.
///
/// `index` is the `x` coordinate the polynomials were evaluated at and must be
/// in `1..=255`; `data` is one field element per secret byte. Both fields are
/// public because a share is a wire object, but note that a `Share` built by
/// hand is not validated — [`combine`] re-checks indices, so nothing downstream
/// trusts these fields blindly.
///
/// # Secret handling
///
/// A share is key material: `t` of them are the key. It zeroizes on drop, and
/// its [`Debug`](fmt::Debug) redacts `data` — a share leaked into a log line is
/// a share leaked to whoever reads logs, and in the degenerate `t = 1` case
/// that single line *is* the secret.
///
/// Two consequences of the `Drop` impl worth knowing: a `Share` cannot be
/// destructured to move its fields out (clone what you need), and equality is
/// the derived byte-wise comparison, which short-circuits and is **not**
/// constant time. Use it for tests and deduplication, not for checking
/// attacker-supplied shares against known ones.
#[derive(Clone, PartialEq, Eq)]
pub struct Share {
    pub index: u8,
    pub data: Vec<u8>,
}

impl fmt::Debug for Share {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Share")
            .field("index", &self.index)
            .field(
                "data",
                &format_args!("<{} bytes redacted>", self.data.len()),
            )
            .finish()
    }
}

impl Zeroize for Share {
    fn zeroize(&mut self) {
        self.data.zeroize();
        self.index = 0;
    }
}

impl Drop for Share {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Share {}

impl Share {
    /// Wire form: `{"data": "<lowercase hex>", "index": <1..=255>}`.
    ///
    /// No `type` tag, unlike the records in `records.rs` — a share never
    /// appears alone on the log, only nested inside the committee's reveal
    /// record, and that record carries the tag.
    pub fn to_value(&self) -> Value {
        Value::object([
            ("index", Value::Int(i128::from(self.index))),
            ("data", Value::string(hex_encode(&self.data))),
        ])
    }

    /// Decode a share, rejecting anything that could not have come from
    /// [`split`].
    ///
    /// Hex must be lowercase. Accepting both cases would give one share two
    /// encodings, and in a system whose identities are hashes of canonical
    /// bytes (`canonical.rs`) that is how a reveal record ends up with two
    /// digests for one committee action.
    pub fn from_value(v: &Value) -> Result<Share, ShamirError> {
        if v.as_object().is_none() {
            return Err(ShamirError::NotAnObject);
        }

        const INDEX_SHAPE: &str = "an integer in 1..=255";
        let raw_index = v
            .get("index")
            .ok_or(ShamirError::MissingField { field: "index" })?;
        // `as_i128` returns None for Bool, so `true` is not index 1.
        let raw_index = raw_index.as_i128().ok_or(ShamirError::InvalidField {
            field: "index",
            expected: INDEX_SHAPE,
        })?;
        if raw_index == 0 {
            return Err(ShamirError::IndexZero);
        }
        let index = u8::try_from(raw_index).map_err(|_| ShamirError::InvalidField {
            field: "index",
            expected: INDEX_SHAPE,
        })?;

        let raw_data = v
            .get("data")
            .ok_or(ShamirError::MissingField { field: "data" })?;
        let text = raw_data.as_str().ok_or(ShamirError::InvalidField {
            field: "data",
            expected: "a lowercase hex string",
        })?;
        let data = hex_decode(text)?;
        if data.is_empty() {
            return Err(ShamirError::EmptyShare);
        }

        Ok(Share { index, data })
    }
}

// -- split -----------------------------------------------------------------

/// Polynomial coefficients above the constant term, held so that an early
/// return cannot leave them on the heap.
///
/// These are strictly more sensitive than the shares: `a_1..a_{t-1}` plus any
/// single share reconstructs the secret regardless of `t`. Capacity is reserved
/// up front so no reallocation copies them somewhere `Drop` will not reach.
struct Coefficients(Vec<Vec<u8>>);

impl Drop for Coefficients {
    fn drop(&mut self) {
        for row in self.0.iter_mut() {
            row.zeroize();
        }
    }
}

impl fmt::Debug for Coefficients {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Coefficients(<{} rows redacted>)", self.0.len())
    }
}

/// Split `secret` into `shares` shares, any `threshold` of which reconstruct it.
///
/// Each byte gets its own degree-`t-1` polynomial with that byte as the
/// constant term; share `i` is every polynomial evaluated at `x = i`, for
/// `i` in `1..=shares`.
///
/// # Why a zero leading coefficient is not rerolled
///
/// Implementations sometimes resample until `a_{t-1} != 0`, reasoning that a
/// zero leading coefficient "degrades the degree". That is backwards and it
/// **weakens** the scheme. Perfect secrecy comes from the coefficients being
/// uniform: for any `t-1` shares and any candidate secret there is exactly one
/// coefficient vector consistent with both, so the shares are independent of
/// the secret. Excluding `a_{t-1} = 0` removes one polynomial per candidate and
/// makes the share distribution depend on the secret. Uniform, including zero,
/// is the correct behaviour.
///
/// # The RNG is the whole security argument
///
/// `impl CryptoRng` asks the type system for a cryptographic generator, but the
/// marker is an assertion by the implementor, not a proof. With a predictable
/// RNG the coefficients are predictable and one share reconstructs the secret;
/// nothing here can detect that, and the shares look identical either way. Pass
/// `rand_core::OsRng` or something equally well-argued.
///
/// # Degenerate parameters
///
/// `threshold == 1` is accepted and gives every share equal to the secret
/// itself — replication, not sharing, with zero confidentiality against a
/// single committee member. It is allowed because it is occasionally what a
/// caller means, never because it is safe.
pub fn split(
    secret: &[u8],
    threshold: u8,
    shares: u8,
    mut rng: impl RngCore + CryptoRng,
) -> Result<Vec<Share>, ShamirError> {
    if secret.is_empty() {
        return Err(ShamirError::EmptySecret);
    }
    if threshold == 0 {
        return Err(ShamirError::ThresholdZero);
    }
    // `shares == 0` is caught here too, since threshold is at least 1.
    if shares < threshold {
        return Err(ShamirError::ThresholdExceedsShares { threshold, shares });
    }
    // "at most 255 shares" needs no check: `shares: u8` makes 256 unsayable,
    // in the same spirit as `Value` having no float variant.

    let degree = usize::from(threshold - 1);

    let mut coefficients = Coefficients(Vec::with_capacity(secret.len()));
    for _ in secret {
        let mut row = vec![0u8; degree];
        rng.fill_bytes(&mut row);
        coefficients.0.push(row);
    }

    let mut out = Vec::with_capacity(usize::from(shares));
    for x in 1..=shares {
        let mut data = Vec::with_capacity(secret.len());
        for (byte, row) in secret.iter().zip(coefficients.0.iter()) {
            // Horner from the top coefficient down, finishing on the secret
            // byte as the constant term. An empty row (t == 1) leaves acc at 0
            // and yields the secret byte unchanged, which is the documented
            // degenerate case rather than a special path.
            let mut acc = 0u8;
            for &coefficient in row.iter().rev() {
                acc = gf::mul(acc, x) ^ coefficient;
            }
            data.push(gf::mul(acc, x) ^ *byte);
        }
        out.push(Share { index: x, data });
    }

    Ok(out)
}

// -- combine ---------------------------------------------------------------

/// Lagrange basis coefficients evaluated at `x = 0`, one per share.
///
/// `L_i(0) = prod_{j != i} x_j / (x_j - x_i)`, and subtraction is XOR in
/// characteristic 2. Every input here is a share index, which is public, so the
/// `i == j` branch leaks nothing.
///
/// Computing the basis once and reusing it across all byte positions is not
/// just an optimisation: it keeps the per-byte inner loop to a single multiply
/// and XOR, with no branch anywhere near a secret value.
fn lagrange_at_zero(shares: &[Share]) -> Result<Vec<u8>, ShamirError> {
    let mut basis = Vec::with_capacity(shares.len());
    for (i, share_i) in shares.iter().enumerate() {
        let mut numerator: u8 = 1;
        let mut denominator: u8 = 1;
        for (j, share_j) in shares.iter().enumerate() {
            if i == j {
                continue;
            }
            numerator = gf::mul(numerator, share_j.index);
            denominator = gf::mul(denominator, share_j.index ^ share_i.index);
        }
        let inverse = gf::inv(denominator).ok_or(ShamirError::Invariant(
            "zero Lagrange denominator despite distinct non-zero indices",
        ))?;
        basis.push(gf::mul(numerator, inverse));
    }
    Ok(basis)
}

/// Reconstruct the secret by interpolating at `x = 0`.
///
/// # This function cannot tell you that you brought too few shares
///
/// Repeating the module docs because it is the one thing a caller gets wrong:
/// with fewer than `t` shares this returns `Ok` and a wrong answer. It is
/// mathematically impossible to do better — sub-threshold share sets are
/// consistent with every secret, which is exactly the confidentiality
/// guarantee. Validate downstream: reconstruct, open the AEAD envelope, and
/// check the plaintext against the commitment (`docs/censorship.md` §2). Those
/// three steps catch a short reconstruction, a corrupted share, and a submitter
/// who sealed garbage, all with the same check.
///
/// What it *does* reject is structurally impossible input: no shares at all, a
/// share at index 0 (that is the secret, not a share), duplicate indices
/// (undefined interpolation), and shares of unequal length. One share is
/// accepted, because a `1`-of-`n` split legitimately combines from one.
///
/// # The return value is a secret and does not zeroize itself
///
/// The signature is `Vec<u8>`, so the reconstructed key is left in the caller's
/// hands. Wrap it in `zeroize::Zeroizing` at the call site. Every intermediate
/// this function allocates is handled here, but the value it hands back cannot
/// be.
pub fn combine(shares: &[Share]) -> Result<Vec<u8>, ShamirError> {
    let first = shares.first().ok_or(ShamirError::NoShares)?;
    let length = first.data.len();
    if length == 0 {
        return Err(ShamirError::EmptyShare);
    }

    // 256 flags rather than a nested scan: a caller passing a large slice of
    // duplicates should not cost quadratic time, and only 255 distinct valid
    // indices exist anyway.
    let mut seen = [false; 256];
    for share in shares {
        if share.index == 0 {
            return Err(ShamirError::IndexZero);
        }
        if share.data.len() != length {
            return Err(ShamirError::LengthMismatch {
                expected: length,
                found: share.data.len(),
            });
        }
        // `usize::from(u8)` is always below 256, so this lookup is total; the
        // fallback exists only to keep the function panic-free by construction.
        let slot = seen
            .get_mut(usize::from(share.index))
            .ok_or(ShamirError::Invariant("share index outside 0..=255"))?;
        if *slot {
            return Err(ShamirError::DuplicateIndex { index: share.index });
        }
        *slot = true;
    }

    let basis = lagrange_at_zero(shares)?;
    if basis.len() != shares.len() {
        return Err(ShamirError::Invariant(
            "basis length does not match share count",
        ));
    }

    let mut secret = vec![0u8; length];
    for (share, coefficient) in shares.iter().zip(basis.iter()) {
        for (out, &y) in secret.iter_mut().zip(share.data.iter()) {
            *out ^= gf::mul(*coefficient, y);
        }
    }
    Ok(secret)
}

// -- hex -------------------------------------------------------------------

/// Lowercase hex. Written out rather than `format!("{:02x}")` per byte to avoid
/// an allocation per byte on shares that can be kilobytes long.
fn hex_encode(bytes: &[u8]) -> String {
    fn nibble(n: u8) -> char {
        match n & 0x0f {
            d @ 0..=9 => char::from(b'0' + d),
            d => char::from(b'a' + (d - 10)),
        }
    }
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for &byte in bytes {
        out.push(nibble(byte >> 4));
        out.push(nibble(byte));
    }
    out
}

fn hex_decode(text: &str) -> Result<Vec<u8>, ShamirError> {
    const SHAPE: &str = "an even-length lowercase hex string";
    fn digit(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            // Uppercase is deliberately refused: see `Share::from_value`.
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        }
    }

    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(ShamirError::InvalidField {
            field: "data",
            expected: SHAPE,
        });
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        // Slice patterns instead of indexing: `chunks_exact(2)` guarantees the
        // shape, and matching says so to the compiler rather than to a reader.
        let (high, low) = match pair {
            [high, low] => (*high, *low),
            _ => {
                return Err(ShamirError::Invariant(
                    "chunks_exact(2) yielded a short chunk",
                ))
            }
        };
        let (high, low) = match (digit(high), digit(low)) {
            (Some(h), Some(l)) => (h, l),
            _ => {
                return Err(ShamirError::InvalidField {
                    field: "data",
                    expected: SHAPE,
                })
            }
        };
        out.push((high << 4) | low);
    }
    Ok(out)
}

// -- tests -----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic splitmix64. Claims `CryptoRng` so it can be passed to
    /// `split`, which is exactly the lie the `split` docs warn about — here it
    /// buys reproducible test vectors, and nowhere else.
    struct TestRng(u64);

    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            (self.next_u64() >> 32) as u32
        }
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(8) {
                let word = self.next_u64().to_le_bytes();
                for (slot, byte) in chunk.iter_mut().zip(word.iter()) {
                    *slot = *byte;
                }
            }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }
    impl CryptoRng for TestRng {}

    /// An RNG that returns zeros. Used to demonstrate what a broken generator
    /// does to the scheme, not to test correctness.
    struct ZeroRng;
    impl RngCore for ZeroRng {
        fn next_u32(&mut self) -> u32 {
            0
        }
        fn next_u64(&mut self) -> u64 {
            0
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for slot in dest.iter_mut() {
                *slot = 0;
            }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }
    impl CryptoRng for ZeroRng {}

    fn pick(shares: &[Share], which: &[usize]) -> Vec<Share> {
        which
            .iter()
            .filter_map(|&i| shares.get(i).cloned())
            .collect()
    }

    // -- field laws --------------------------------------------------------

    #[test]
    fn field_known_answer_vectors() {
        // The two products every AES description uses as its worked example.
        assert_eq!(gf::mul(0x57, 0x83), 0xc1);
        assert_eq!(gf::mul(0x57, 0x13), 0xfe);
        assert_eq!(gf::mul(0x02, 0x87), 0x15); // xtime with reduction
        assert_eq!(gf::mul(0x00, 0xff), 0x00);
        assert_eq!(gf::mul(0x01, 0xff), 0xff);
    }

    #[test]
    fn field_is_commutative_and_associative() {
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                assert_eq!(gf::mul(a, b), gf::mul(b, a), "commutativity at {a},{b}");
            }
        }
        // Associativity and distributivity over a coarse but structured sample.
        for a in (0..=255u8).step_by(7) {
            for b in (0..=255u8).step_by(11) {
                for c in (0..=255u8).step_by(13) {
                    assert_eq!(gf::mul(gf::mul(a, b), c), gf::mul(a, gf::mul(b, c)));
                    assert_eq!(gf::mul(a, b ^ c), gf::mul(a, b) ^ gf::mul(a, c));
                }
            }
        }
    }

    #[test]
    fn every_non_zero_element_has_an_inverse() {
        assert_eq!(gf::inv(0), None);
        for a in 1..=255u8 {
            let inverse = gf::inv(a).expect("non-zero elements are invertible");
            assert_eq!(gf::mul(a, inverse), 1, "inverse of {a}");
        }
    }

    // -- round trips -------------------------------------------------------

    #[test]
    fn any_threshold_subset_reconstructs() {
        let secret = b"the answer is in the envelope";
        let shares = split(secret, 3, 5, TestRng(7)).expect("valid parameters");
        assert_eq!(shares.len(), 5);

        // Every one of the C(5,3) = 10 subsets, not a sampled few.
        let mut subsets = 0;
        for i in 0..5 {
            for j in (i + 1)..5 {
                for k in (j + 1)..5 {
                    let chosen = pick(&shares, &[i, j, k]);
                    let recovered = combine(&chosen).expect("consistent shares");
                    assert_eq!(recovered, secret, "subset {i},{j},{k}");
                    subsets += 1;
                }
            }
        }
        assert_eq!(subsets, 10);
    }

    #[test]
    fn share_indices_start_at_one() {
        let shares = split(b"x", 2, 255, TestRng(1)).expect("valid parameters");
        assert_eq!(shares.len(), 255);
        for (position, share) in shares.iter().enumerate() {
            // No share is ever handed out at x = 0, which is the secret.
            assert_ne!(share.index, 0);
            assert_eq!(usize::from(share.index), position + 1);
        }
    }

    #[test]
    fn single_byte_secret() {
        let shares = split(&[0x42], 2, 3, TestRng(99)).expect("valid parameters");
        for share in &shares {
            assert_eq!(share.data.len(), 1);
        }
        assert_eq!(combine(&pick(&shares, &[0, 2])).expect("ok"), vec![0x42]);
        assert_eq!(combine(&pick(&shares, &[1, 2])).expect("ok"), vec![0x42]);
    }

    #[test]
    fn long_secret() {
        let mut rng = TestRng(2024);
        let mut secret = vec![0u8; 4096];
        rng.fill_bytes(&mut secret);

        let shares = split(&secret, 4, 7, &mut rng).expect("valid parameters");
        for share in &shares {
            assert_eq!(share.data.len(), secret.len());
        }
        assert_eq!(combine(&pick(&shares, &[6, 0, 3, 5])).expect("ok"), secret);
    }

    #[test]
    fn threshold_equals_shares() {
        let secret = b"all five or nothing";
        let shares = split(secret, 5, 5, TestRng(11)).expect("valid parameters");
        assert_eq!(combine(&shares).expect("ok"), secret);

        // Four of five is sub-threshold, so it is garbage rather than an error.
        let four = pick(&shares, &[0, 1, 2, 3]);
        let wrong = combine(&four).expect("sub-threshold still returns Ok");
        assert_ne!(wrong, secret);
    }

    #[test]
    fn threshold_of_one_replicates_the_secret() {
        let secret = b"no confidentiality here";
        let shares = split(secret, 1, 4, TestRng(3)).expect("valid parameters");
        for share in &shares {
            // Every single share IS the secret. Documented, and dangerous.
            assert_eq!(share.data, secret);
            let single = vec![share.clone()];
            assert_eq!(combine(&single).expect("ok"), secret);
        }
    }

    #[test]
    fn large_threshold_reconstructs() {
        let secret = [0xABu8; 32];
        let shares = split(&secret, 200, 255, TestRng(5)).expect("valid parameters");
        let chosen: Vec<Share> = shares.iter().take(200).cloned().collect();
        assert_eq!(combine(&chosen).expect("ok"), secret);
    }

    #[test]
    fn works_with_a_real_csprng() {
        // The production path: proves the intended RNG type satisfies the bound.
        let secret = b"sealed until the epoch boundary";
        let shares = split(secret, 3, 5, rand_core::OsRng).expect("valid parameters");
        assert_eq!(combine(&pick(&shares, &[4, 1, 2])).expect("ok"), secret);
    }

    // -- the security property ---------------------------------------------

    #[test]
    fn sub_threshold_shares_yield_garbage_not_the_secret() {
        let secret = b"threshold three means three";
        let shares = split(secret, 3, 5, TestRng(31337)).expect("valid parameters");

        for pair in [[0, 1], [0, 4], [2, 3], [1, 3]] {
            let two = pick(&shares, &pair);
            let recovered = combine(&two).expect("combine cannot detect too-few shares");
            assert_eq!(
                recovered.len(),
                secret.len(),
                "length still leaks, as documented"
            );
            assert_ne!(
                recovered.as_slice(),
                secret.as_slice(),
                "two of three must not reconstruct"
            );
        }

        // And a single share is not the secret either, for t > 1.
        let one = pick(&shares, &[0]);
        assert_ne!(combine(&one).expect("ok").as_slice(), secret.as_slice());
    }

    #[test]
    fn a_single_share_reveals_nothing_by_itself() {
        // Two different secrets can produce the same share value under
        // different coefficients; the test is weaker than the theorem but it
        // pins the shape: share bytes are not the secret bytes.
        let secret = [0u8; 16];
        let shares = split(&secret, 2, 3, TestRng(8)).expect("valid parameters");
        for share in &shares {
            assert_ne!(share.data, secret.to_vec());
        }
    }

    #[test]
    fn a_broken_rng_silently_destroys_confidentiality() {
        // Not a correctness test -- a demonstration of the caveat in `split`'s
        // docs. With zero coefficients every share equals the secret and the
        // library has no way to notice.
        let secret = b"predictable";
        let shares = split(secret, 3, 5, ZeroRng).expect("parameters are still valid");
        for share in &shares {
            assert_eq!(share.data, secret, "a bad RNG is undetectable here");
        }
    }

    // -- rejected input ----------------------------------------------------

    #[test]
    fn split_rejects_bad_parameters() {
        assert_eq!(
            split(b"", 2, 3, TestRng(0)).unwrap_err(),
            ShamirError::EmptySecret
        );
        assert_eq!(
            split(b"x", 0, 3, TestRng(0)).unwrap_err(),
            ShamirError::ThresholdZero
        );
        assert_eq!(
            split(b"x", 4, 3, TestRng(0)).unwrap_err(),
            ShamirError::ThresholdExceedsShares {
                threshold: 4,
                shares: 3
            }
        );
        assert_eq!(
            split(b"x", 1, 0, TestRng(0)).unwrap_err(),
            ShamirError::ThresholdExceedsShares {
                threshold: 1,
                shares: 0
            }
        );
    }

    #[test]
    fn combine_rejects_no_shares() {
        assert_eq!(combine(&[]).unwrap_err(), ShamirError::NoShares);
    }

    #[test]
    fn combine_rejects_index_zero() {
        let shares = split(b"secret", 2, 3, TestRng(4)).expect("valid parameters");
        let mut forged = pick(&shares, &[0, 1]);
        if let Some(share) = forged.get_mut(0) {
            share.index = 0;
        }
        assert_eq!(combine(&forged).unwrap_err(), ShamirError::IndexZero);

        // Even alone: handing out share 0 hands out the secret.
        let solo = vec![Share {
            index: 0,
            data: vec![1, 2, 3],
        }];
        assert_eq!(combine(&solo).unwrap_err(), ShamirError::IndexZero);
    }

    #[test]
    fn combine_rejects_duplicate_indices() {
        let shares = split(b"secret", 2, 3, TestRng(4)).expect("valid parameters");
        let mut forged = pick(&shares, &[0, 1]);
        if let (Some(first), Some(second)) = (shares.first(), forged.get_mut(1)) {
            second.index = first.index;
        }
        assert_eq!(
            combine(&forged).unwrap_err(),
            ShamirError::DuplicateIndex { index: 1 }
        );

        // The exact same share twice is the same failure, not a silent success.
        let doubled = pick(&shares, &[2, 2]);
        assert_eq!(
            combine(&doubled).unwrap_err(),
            ShamirError::DuplicateIndex { index: 3 }
        );
    }

    #[test]
    fn combine_rejects_length_mismatch_and_empty_shares() {
        let shares = split(b"secret", 2, 3, TestRng(4)).expect("valid parameters");
        let mut forged = pick(&shares, &[0, 1]);
        if let Some(share) = forged.get_mut(1) {
            share.data.push(0x00);
        }
        assert_eq!(
            combine(&forged).unwrap_err(),
            ShamirError::LengthMismatch {
                expected: 6,
                found: 7
            }
        );

        let empty = vec![Share {
            index: 1,
            data: Vec::new(),
        }];
        assert_eq!(combine(&empty).unwrap_err(), ShamirError::EmptyShare);
    }

    #[test]
    fn combine_ignores_share_order() {
        let secret = b"order free";
        let shares = split(secret, 3, 5, TestRng(77)).expect("valid parameters");
        let forwards = combine(&pick(&shares, &[0, 2, 4])).expect("ok");
        let backwards = combine(&pick(&shares, &[4, 2, 0])).expect("ok");
        assert_eq!(forwards, secret);
        assert_eq!(forwards, backwards);
    }

    // -- encoding ----------------------------------------------------------

    #[test]
    fn share_value_round_trip_is_exact() {
        let shares = split(b"round trip me", 2, 3, TestRng(123)).expect("valid parameters");
        for share in &shares {
            let encoded = share.to_value();
            let decoded = Share::from_value(&encoded).expect("valid encoding");
            assert_eq!(decoded.index, share.index);
            assert_eq!(decoded.data, share.data);
            assert_eq!(decoded.to_value(), encoded);
        }
    }

    #[test]
    fn share_encodes_as_lowercase_hex() {
        let share = Share {
            index: 200,
            data: vec![0x00, 0x0f, 0xab, 0xff],
        };
        assert_eq!(
            share.to_value().canonical_string(),
            r#"{"data":"000fabff","index":200}"#
        );
    }

    #[test]
    fn from_value_rejects_malformed_encodings() {
        let good = Share {
            index: 3,
            data: vec![0xde, 0xad],
        }
        .to_value();
        assert!(Share::from_value(&good).is_ok());

        assert_eq!(
            Share::from_value(&Value::string("not an object")).unwrap_err(),
            ShamirError::NotAnObject
        );
        assert_eq!(
            Share::from_value(&Value::object([("data", Value::string("dead"))])).unwrap_err(),
            ShamirError::MissingField { field: "index" }
        );
        assert_eq!(
            Share::from_value(&Value::object([("index", Value::Int(3))])).unwrap_err(),
            ShamirError::MissingField { field: "data" }
        );
        assert_eq!(
            Share::from_value(&Value::object([
                ("index", Value::Int(0)),
                ("data", Value::string("dead")),
            ]))
            .unwrap_err(),
            ShamirError::IndexZero
        );
        assert_eq!(
            Share::from_value(&Value::object([
                ("index", Value::Int(256)),
                ("data", Value::string("dead")),
            ]))
            .unwrap_err(),
            ShamirError::InvalidField {
                field: "index",
                expected: "an integer in 1..=255"
            }
        );
        assert_eq!(
            Share::from_value(&Value::object([
                ("index", Value::Int(-1)),
                ("data", Value::string("dead")),
            ]))
            .unwrap_err(),
            ShamirError::InvalidField {
                field: "index",
                expected: "an integer in 1..=255"
            }
        );
        // A boolean is not an index, even though many encoders conflate them.
        assert_eq!(
            Share::from_value(&Value::object([
                ("index", Value::Bool(true)),
                ("data", Value::string("dead")),
            ]))
            .unwrap_err(),
            ShamirError::InvalidField {
                field: "index",
                expected: "an integer in 1..=255"
            }
        );
        assert_eq!(
            Share::from_value(&Value::object([
                ("index", Value::Int(1)),
                ("data", Value::string("")),
            ]))
            .unwrap_err(),
            ShamirError::EmptyShare
        );
        for bad in ["abc", "DEAD", "zz", "de ad", "de\u{00e9}"] {
            assert_eq!(
                Share::from_value(&Value::object([
                    ("index", Value::Int(1)),
                    ("data", Value::string(bad)),
                ]))
                .unwrap_err(),
                ShamirError::InvalidField {
                    field: "data",
                    expected: "an even-length lowercase hex string"
                },
                "input {bad:?}"
            );
        }
    }

    #[test]
    fn decoded_shares_still_reconstruct() {
        let secret = b"survives the wire";
        let shares = split(secret, 3, 4, TestRng(55)).expect("valid parameters");
        let wire: Vec<Value> = shares.iter().map(Share::to_value).collect();
        let decoded: Vec<Share> = wire
            .iter()
            .map(Share::from_value)
            .collect::<Result<_, _>>()
            .expect("valid encodings");
        assert_eq!(combine(&pick(&decoded, &[3, 0, 1])).expect("ok"), secret);
    }

    #[test]
    fn hex_round_trips_all_byte_values() {
        let all: Vec<u8> = (0..=255u8).collect();
        assert_eq!(hex_decode(&hex_encode(&all)).expect("valid hex"), all);
        assert_eq!(hex_encode(&[]), "");
    }

    // -- secret hygiene ----------------------------------------------------

    #[test]
    fn debug_does_not_print_share_data() {
        let share = Share {
            index: 9,
            data: vec![0xde, 0xad, 0xbe, 0xef],
        };
        let rendered = format!("{share:?}");
        assert!(rendered.contains("index: 9"));
        assert!(rendered.contains("redacted"));
        // Neither the hex nor the decimal rendering of the bytes may appear.
        for leaked in ["deadbeef", "222", "173", "190", "239", "["] {
            assert!(!rendered.contains(leaked), "leaked {leaked:?}: {rendered}");
        }
    }

    #[test]
    fn zeroize_clears_share_data() {
        let mut share = Share {
            index: 4,
            data: vec![0xff; 16],
        };
        share.zeroize();
        assert!(share.data.is_empty());
        assert_eq!(share.index, 0);
    }

    #[test]
    fn errors_display_without_leaking_data() {
        let rendered = format!(
            "{}",
            ShamirError::ThresholdExceedsShares {
                threshold: 4,
                shares: 3
            }
        );
        assert!(rendered.contains("threshold 4"));
        assert!(format!("{}", ShamirError::IndexZero).contains("secret"));
    }
}
