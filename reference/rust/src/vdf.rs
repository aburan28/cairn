//! The delay beacon's proof, checked independently of the primary.
//!
//! Until this module the reference verified drand beacons and not delay ones,
//! so a forged `vdf` beacon failed the primary's audit and passed this one --
//! the pattern `scripts/differential.sh` calls worse than having no second
//! implementation. Settlement consults neither, so it never forked; the audit
//! reports did.
//!
//! Written from the rules, not from the primary's code, and on a different
//! bignum: `num-bigint` here, the primary's own `crypto::bignum` there, for
//! the reason the BLS check uses a different pairing library -- two programs
//! that share an arithmetic library agree about exactly the inputs that
//! library gets wrong. The modulus is transcribed from the RSA Factoring
//! Challenge's published decimal, not copied from the primary's hex.
//!
//! The rules, all of which the primary applies:
//!
//! - `x` = SHA-256("proofwork/vdf/x1" ‖ seed) ‖ SHA-256("proofwork/vdf/x2" ‖
//!   seed), as a big-endian integer, mod N.
//! - The output `y` and witness `π` are 256-byte big-endian elements, below
//!   N and not zero (`0^l · x^r = 0` would prove every beacon).
//! - The challenge `l` is the first probable prime at or above the top 128
//!   bits of SHA-256("proofwork/vdf/challenge" ‖ x ‖ y ‖ T), with its top bit
//!   cleared and forced odd; Miller–Rabin on the first twelve primes as bases,
//!   the primary's own choice, so both draw the same prime.
//! - Accept when `π^l · x^(2^T mod l) ≡ y (mod N)`.

use num_bigint::BigUint;
use sha2::{Digest as _, Sha256};

/// RSA-2048 from the RSA Factoring Challenge, in the decimal it was published
/// in. 617 digits; nobody has published its factors.
pub const RSA_2048_DECIMAL: &str = "\
2519590847565789349402718324004839857142928212620403202777713783604366202070\
7595556264018525880784406918290641249515082189298559149176184502808489120072\
8449926873928072877767359714183472702618963750149718246911650776133798590957\
0009733045974880842840179742910064245869181719511874612151517265463228221686\
9987549182422433637259085141865462043576798423387184774447920739934236584823\
8242811981638150106748104516603773060562016196762561338441436038339044149526\
3443219011465754445417842402092461651572335077870774981712577246796292638635\
6373289912154831438167899885040445364023527381951378636564391212010397122822\
120720357";

/// Bytes an element serialises to.
pub const ELEMENT_BYTES: usize = 256;

/// The fewest squarings a delay beacon may claim; the primary's
/// `node::MIN_VDF_DIFFICULTY`.
pub const MIN_DIFFICULTY: u64 = 1 << 16;

fn modulus() -> BigUint {
    BigUint::parse_bytes(RSA_2048_DECIMAL.as_bytes(), 10).expect("the modulus is decimal")
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn element(seed: &[u8]) -> BigUint {
    let mut bytes = sha256(&[b"proofwork/vdf/x1", seed]).to_vec();
    bytes.extend_from_slice(&sha256(&[b"proofwork/vdf/x2", seed]));
    BigUint::from_bytes_be(&bytes) % modulus()
}

fn fixed(value: &BigUint) -> Vec<u8> {
    let bytes = value.to_bytes_be();
    let mut out = vec![0u8; ELEMENT_BYTES.saturating_sub(bytes.len())];
    out.extend_from_slice(&bytes);
    out
}

fn is_probable_prime(n: &BigUint) -> bool {
    const BASES: [u32; 12] = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];
    let one = BigUint::from(1u32);
    let two = BigUint::from(2u32);
    if *n < two {
        return false;
    }
    for base in BASES {
        let base = BigUint::from(base);
        if *n == base {
            return true;
        }
        if (n % &base) == BigUint::from(0u32) {
            return false;
        }
    }
    let n_minus_one = n - &one;
    let s = n_minus_one.trailing_zeros().unwrap_or(0);
    let d = &n_minus_one >> s;
    'base: for base in BASES {
        let mut x = BigUint::from(base).modpow(&d, n);
        if x == one || x == n_minus_one {
            continue;
        }
        for _ in 1..s {
            x = x.modpow(&two, n);
            if x == n_minus_one {
                continue 'base;
            }
        }
        return false;
    }
    true
}

fn challenge(x: &BigUint, y: &BigUint, difficulty: u64) -> BigUint {
    let digest = sha256(&[
        b"proofwork/vdf/challenge",
        &fixed(x),
        &fixed(y),
        &difficulty.to_be_bytes(),
    ]);
    let mut top = [0u8; 16];
    top.copy_from_slice(&digest[..16]);
    top[0] &= 0x7f;
    let mut candidate = BigUint::from_bytes_be(&top);
    if !candidate.bit(0) {
        candidate += 1u32;
    }
    while !is_probable_prime(&candidate) {
        candidate += 2u32;
    }
    candidate
}

/// Does `output`/`witness` prove `difficulty` squarings of `seed`'s element?
/// The primitive only: the floor on `difficulty` is the beacon rule's, not
/// this function's.
pub fn verify(seed: &[u8], difficulty: u64, output: &[u8], witness: &[u8]) -> bool {
    if output.len() != ELEMENT_BYTES || witness.len() != ELEMENT_BYTES {
        return false;
    }
    let n = modulus();
    let zero = BigUint::from(0u32);
    let y = BigUint::from_bytes_be(output);
    let pi = BigUint::from_bytes_be(witness);
    if y >= n || pi >= n || y == zero || pi == zero {
        return false;
    }
    let x = element(seed);
    let l = challenge(&x, &y, difficulty);
    let r = BigUint::from(2u32).modpow(&BigUint::from(difficulty), &l);
    (pi.modpow(&l, &n) * x.modpow(&r, &n)) % &n == y
}

/// The seed a delay beacon for `epoch` is computed over: the log's Merkle
/// root below the beacon, so it is not knowable before those records exist.
pub fn seed(epoch: u64, root: Option<&str>) -> Vec<u8> {
    let mut seed = b"proofwork/vdf/seed".to_vec();
    seed.extend_from_slice(&epoch.to_be_bytes());
    seed.extend_from_slice(root.unwrap_or_default().as_bytes());
    seed
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny prover, for tests only: `T` squarings and the long division
    /// for `π`, slowly but plainly.
    fn prove(seed: &[u8], difficulty: u64) -> (Vec<u8>, Vec<u8>) {
        let n = modulus();
        let x = element(seed);
        let mut y = x.clone();
        for _ in 0..difficulty {
            y = (&y * &y) % &n;
        }
        let l = challenge(&x, &y, difficulty);
        let quotient = (BigUint::from(1u32) << difficulty) / &l;
        let pi = x.modpow(&quotient, &n);
        (fixed(&y), fixed(&pi))
    }

    #[test]
    fn the_modulus_is_rsa_2048() {
        let n = modulus();
        assert_eq!(n.bits(), 2048);
        assert_eq!(RSA_2048_DECIMAL.replace('\\', "").len(), 617);
        assert!(n
            .to_string()
            .starts_with("25195908475657893494027183240048398571429282126204"));
        assert!(n.to_string().ends_with("20720357"));
    }

    #[test]
    fn an_honest_proof_verifies_and_changes_do_not() {
        let (y, pi) = prove(b"reference", 300);
        assert!(verify(b"reference", 300, &y, &pi));
        assert!(!verify(b"reference", 301, &y, &pi), "another difficulty");
        assert!(!verify(b"elsewhere", 300, &y, &pi), "another seed");
        let mut bent = y.clone();
        bent[255] ^= 1;
        assert!(!verify(b"reference", 300, &bent, &pi));
        let zero = vec![0u8; ELEMENT_BYTES];
        assert!(
            !verify(b"reference", 1 << 40, &zero, &zero),
            "zero proves nothing"
        );
        assert!(!verify(b"reference", 300, &y[1..], &pi), "wrong width");
    }

    /// A proof the *primary* produced, pinned as bytes: the reference must
    /// accept exactly it and derive exactly it. Agreement by construction
    /// within one crate proves nothing about agreement across two.
    #[test]
    fn a_proof_from_the_primary_verifies_here_byte_for_byte() {
        let unhex = |text: &str| -> Vec<u8> {
            (0..text.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
                .collect()
        };
        let output = unhex(
            "0c56a3c567b62030489207ba6335c946e4a353de7a2f04a4349ad1c84a9b032b\
af0809307790a7d3c418892c0282894abdfd0d0203a2bc1fd0fbf237631864fe\
cdd111cfae63f8c87a75db1a0994ac88a5bded9911c2994cc88d34039f4db8f6\
6abd91d95d55038e97d9099238d799b381f11bb53e3021ea266711def55152c8\
0b387dde5f799da432a4909ae7a918d1e56178dffcda3475796a64317ddb3153\
7ee02ac400c3154b24b3d453c898679bd809646f14f4402d26dce9a99096b9b2\
565a7a5f3bef3ae64cd55e5554525356b44e88a344862b6b31d217aaf76201cf\
9cb094b704418b7602fa7b2574ed258f60940903daccfc9d3a9ba1ac20e871e4",
        );
        let witness = unhex(
            "c427cae52eadeec4d8bbf2d243b819630974d4de0abcc77dfed3c72979ba0319\
d03982c8dab8b135d8bc93a30306a9090cbcc9b359c4740e8a794a8c9037f8e1\
56352fd235201648be121d351ec32ed2200f7179652f6c05af9227edd1d0f6c0\
19b78f3c8aea5ab51e80bf8bcab4a409628f377749cc166fdbe9cab89e43ecfd\
d0eac1f1668879e0d8cc6648b310291ce5e2d4a9440424ca082eea3047aef8c3\
0b6b75fc93db2c0a49790b27c23841056e3e464cb0ede472816223e6a3ea7acd\
67043aff77560106d5f140827c7ee40618fec61dedf653635e69d425ad37d6a9\
9c0e87373652e99d78ee7ca60fabc4ca188360756b075c0ce231e1d90d098868",
        );
        assert!(verify(b"cross-implementation", 300, &output, &witness));
        assert_eq!(prove(b"cross-implementation", 300), (output, witness));
    }

    #[test]
    fn miller_rabin_agrees_with_known_primes_and_composites() {
        for p in [2u64, 3, 5, 97, 7919, 1_000_000_007, (1 << 61) - 1] {
            assert!(is_probable_prime(&BigUint::from(p)), "{p}");
        }
        for c in [1u64, 4, 561, 1105, 1729, 2465, 1_000_000_007 * 3] {
            assert!(!is_probable_prime(&BigUint::from(c)), "{c}");
        }
    }
}
