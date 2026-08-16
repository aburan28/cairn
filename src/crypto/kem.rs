//! Key encapsulation: one interface, three post-quantum schemes, combined so
//! that adding one can never weaken another.
//!
//! # Why there is more than one
//!
//! Classic McEliece is the conservative choice — its problem has resisted
//! attack since 1978 — and it is the reason [`Suite::McEliece`] is mandatory in
//! every [`Bundle`]. It also has a 261,120-byte public key, which is why
//! `docs/p2p.md` had to make a peer's key a long-term cached identity rather
//! than something a handshake carries. That cost is affordable for a
//! long-lived peer and unaffordable for anything that has to ship a key inline.
//!
//! So the lattice and the newer code-based schemes are here for the cases where
//! key size is the binding constraint, and they are **additive**: a bundle is a
//! set of keys, encapsulation produces one ciphertext per suite, and the shared
//! secret is a hash over *all* legs. Recovering it requires every leg, so a
//! bundle is at least as strong as its strongest member. Concretely: if ML-KEM
//! were broken tomorrow, an attacker holding a bundle's ML-KEM secret still
//! learns nothing, because the McEliece leg's secret is also absorbed and they
//! do not have it.
//!
//! That direction matters and it is easy to get backwards. A *choice* between
//! suites is as strong as the weakest one an attacker may force; a *combination*
//! is as strong as the strongest. This module only ever combines.
//!
//! # The suites, and why these three
//!
//! | suite | family | public key | ciphertext | status |
//! |---|---|---|---|---|
//! | [`Suite::McEliece`] | code-based (binary Goppa) | 261,120 B | 96 B | mandatory in every bundle |
//! | [`Suite::MlKem768`] | module-LWE lattice | 1,184 B | 1,088 B | FIPS 203, optional |
//! | [`Suite::Hqc128`] | code-based (quasi-cyclic) | 2,241 B | 4,433 B | NIST-selected, optional, **on a release-candidate crate** |
//!
//! The three are deliberately from *two different* hardness assumptions, and
//! the two code-based ones from different code families. A bundle of McEliece
//! and ML-KEM survives a break of either lattices or Goppa codes; a bundle of
//! two lattice schemes would not, which is the whole reason not to pick the
//! cheapest two.
//!
//! ## What was considered and is not here
//!
//! Written down because "why isn't X in the list" is otherwise re-litigated
//! every time somebody reads a conference programme.
//!
//! - **Rank-metric schemes (RQC, ROLLO).** Algebraic attacks on rank syndrome
//!   decoding in 2020 broke the submitted parameter sets, and NIST dropped them
//!   from the process. Attractive key sizes; the assumption did not hold.
//! - **CSIDH.** Isogeny-based, and the only one here with genuinely small keys.
//!   Its *quantum* security is contested — the subexponential quantum attack
//!   means CSIDH-512 is nowhere near the level originally claimed, and the
//!   parameter sizes that would answer that are disputed and slow. It is also
//!   not standardised and has no maintained Rust implementation. A scheme whose
//!   parameters are an open research question does not belong on a path that
//!   decides who gets paid.
//! - **X25519.** Not post-quantum at all. It sealed committee shares until this
//!   module replaced it, and the swap is the point: a network whose transport is
//!   quantum-resistant and whose *submissions* are not has moved the weakness
//!   rather than removed it.
//!
//! # Randomness, and why every scheme is driven deterministically
//!
//! Every operation here draws its randomness from the caller's
//! `R: RngCore + CryptoRng` and feeds it to the scheme's **deterministic**
//! entry point, rather than handing the scheme an RNG of its own.
//!
//! Not an aesthetic choice. `ml-kem` and `hqc-kem` are built against
//! `rand_core 0.10`, and this crate is on `rand_core 0.6`; passing an RNG
//! across that boundary needs an adapter and a second version of the trait in
//! the public API. Driving from bytes needs neither, and it buys two things
//! worth more than the adapter: one RNG for the whole crate, so there is one
//! place entropy comes from, and a KEM layer that is reproducible from a seed,
//! so a test can pin an exact ciphertext instead of asserting round trips.
//!
//! The security argument is that these entry points are what the randomized
//! ones call: FIPS 203 `ML-KEM.Encaps_internal` takes a uniform 32-byte `m`,
//! and `encapsulate_with_rng` draws exactly that and calls it. Supplying the
//! same uniform bytes from a CSPRNG is the specified behaviour, not a shortcut
//! around it. The one hazard is supplying bytes that are *not* uniform, which
//! is why nothing here accepts a seed from a caller: every one is drawn from
//! `rng` inside this module.
//!
//! # What this module does not do
//!
//! - **No forward secrecy.** These are static keys, so a leaked secret opens
//!   every past encapsulation to it. The same trade `p2p::handshake` documents,
//!   for the same reason: an ephemeral McEliece keypair costs 243 ms and 255 KB
//!   per exchange. Rotation is the mitigation.
//! - **No sender authentication.** A KEM says nothing about who encapsulated.
//!   Signatures live in [`super::identity`].

use core::fmt;

use rand_core::{CryptoRng, RngCore};
use sha2::{Digest as _, Sha256};
use zeroize::{Zeroize, Zeroizing};

use super::envelope::Secret32;
use crate::canonical::Value;

// -- Classic McEliece ------------------------------------------------------

use classic_mceliece_rust::{
    decapsulate_boxed, encapsulate_boxed, keypair_boxed, Ciphertext as McCiphertext,
    PublicKey as McPublicKey, SecretKey as McSecretKey, CRYPTO_CIPHERTEXTBYTES as MC_CT,
    CRYPTO_PUBLICKEYBYTES as MC_PK, CRYPTO_SECRETKEYBYTES as MC_SK,
};

// -- ML-KEM ----------------------------------------------------------------

use ml_kem::array::Array;
use ml_kem::{
    Ciphertext as MlCiphertext, Decapsulate as _, DecapsulationKey, EncapsulationKey,
    KeyExport as _, MlKem768, Seed as MlSeed,
};

/// Bytes in an ML-KEM-768 encapsulation (public) key.
const ML_PK: usize = 1184;
/// Bytes in an ML-KEM-768 ciphertext.
const ML_CT: usize = 1088;
/// Bytes in the seed this module persists in place of an expanded ML-KEM
/// decapsulation key. The crate's own preferred serialization, and 64 bytes
/// rather than 2,400.
const ML_SK: usize = 64;

// -- HQC -------------------------------------------------------------------

use hqc_kem::hqc128::{
    Ciphertext as HqcCiphertext, DecapsulationKey as HqcDecapsulationKey,
    EncapsulationKey as HqcEncapsulationKey, CIPHERTEXT_SIZE as HQC_CT, MESSAGE_SIZE as HQC_M,
    PUBLIC_KEY_SIZE as HQC_PK, SECRET_KEY_SIZE as HQC_SK,
};
use hqc_kem::Hqc128;

/// Bytes in an HQC encapsulation salt. Fixed by the scheme at every level.
const HQC_SALT: usize = 16;

// -- domain separation -----------------------------------------------------

/// Domain separator for the hybrid combiner.
// Spelled `proofwork/` and not `cairn/`: this is a wire constant, not a
// brand. It is mixed into a hash or a KDF, so changing it changes the
// values every peer already computed -- the project rename left it alone
// deliberately, exactly as it left the `pwenc1:` on-disk marker alone.
const COMBINE_DOMAIN: &[u8] = b"proofwork/kem/combine/v1";

/// Bytes in every shared secret this module produces, whatever the suite.
pub const SHARED_SECRET_LEN: usize = 32;

// -- errors ----------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KemError {
    /// A key or ciphertext blob was not the length its suite requires.
    ///
    /// One variant covering keys and ciphertexts alike: the caller can act on
    /// "this blob is not what it claims to be" and cannot usefully act on
    /// which of the three it was.
    WrongLength {
        suite: Suite,
        what: &'static str,
        expected: usize,
        got: usize,
    },
    /// A blob is the right length and still not a valid key for its suite.
    ///
    /// Only ML-KEM can report this: FIPS 203 requires an encapsulation key to
    /// decode to canonical coefficients, and a non-canonical encoding is
    /// refused rather than clamped. McEliece and HQC accept any bit string of
    /// the right length as *a* key — see [`Bundle::encapsulate`] for why that
    /// costs liveness rather than secrecy.
    MalformedKey { suite: Suite },
    /// A suite name that this build does not implement.
    UnknownSuite { name: String },
    /// A bundle without its mandatory Classic McEliece key.
    ///
    /// Refused rather than allowed-and-warned. A bundle is only as strong as
    /// its strongest leg *because* every leg is absorbed, and the whole reason
    /// to accept McEliece's key size is that it is the leg nobody expects to
    /// fall. A bundle missing it is a bundle resting on lattices alone, which
    /// is not the security this network was told it has.
    McElieceRequired,
    /// Two keys in one bundle name the same suite, so encapsulation would have
    /// two legs one secret opens and the bundle would be weaker than it looks.
    DuplicateSuite { suite: Suite },
    /// An encapsulation carries a leg for a suite the bundle has no key for, or
    /// is missing one the bundle has. Both directions are the same fault: the
    /// legs and the keys must correspond exactly, or the combiner is hashing a
    /// different transcript than the sender did.
    LegMismatch,
    /// A bundle with no keys at all.
    Empty,
}

impl fmt::Display for KemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KemError::WrongLength {
                suite,
                what,
                expected,
                got,
            } => write!(f, "{suite} {what} must be {expected} bytes, got {got}"),
            KemError::MalformedKey { suite } => {
                write!(f, "{suite} public key is not a valid encoding")
            }
            KemError::UnknownSuite { name } => write!(f, "unknown KEM suite {name:?}"),
            KemError::McElieceRequired => f.write_str(
                "a key bundle must carry a Classic McEliece key; it is the leg the \
                 hybrid's security rests on",
            ),
            KemError::DuplicateSuite { suite } => {
                write!(f, "key bundle carries two {suite} keys")
            }
            KemError::LegMismatch => {
                f.write_str("encapsulation legs do not correspond to the bundle's keys")
            }
            KemError::Empty => f.write_str("key bundle is empty"),
        }
    }
}

impl std::error::Error for KemError {}

// -- suites ----------------------------------------------------------------

/// Which scheme a key, a ciphertext, or one leg of a bundle belongs to.
///
/// `Ord` is derived and the order is load bearing: a [`Bundle`] keeps its keys
/// sorted by it, so two peers that assembled the same set of keys in different
/// orders still hash the same combiner transcript. McEliece sorts first, which
/// is also the order it is read in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Suite {
    /// `mceliece348864`. Mandatory in every bundle.
    McEliece,
    /// ML-KEM-768, FIPS 203. Module-LWE.
    MlKem768,
    /// HQC-128. Quasi-cyclic codes.
    Hqc128,
}

/// Every suite this build implements, in bundle order.
pub const SUITES: [Suite; 3] = [Suite::McEliece, Suite::MlKem768, Suite::Hqc128];

impl Suite {
    /// The wire name. These strings reach records and are hashed into the
    /// combiner transcript, so they are as consensus-critical as any other
    /// encoding in this crate: renaming one changes every derived key.
    pub const fn as_str(self) -> &'static str {
        match self {
            Suite::McEliece => "mceliece348864",
            Suite::MlKem768 => "ml-kem-768",
            Suite::Hqc128 => "hqc-128",
        }
    }

    /// Parse a wire name. Unknown names are an error rather than a default:
    /// silently treating an unrecognised suite as a known one would let a peer
    /// choose which cryptography you ran.
    pub fn parse(name: &str) -> Result<Suite, KemError> {
        SUITES
            .into_iter()
            .find(|suite| suite.as_str() == name)
            .ok_or_else(|| KemError::UnknownSuite {
                name: name.to_string(),
            })
    }

    pub const fn public_key_len(self) -> usize {
        match self {
            Suite::McEliece => MC_PK,
            Suite::MlKem768 => ML_PK,
            Suite::Hqc128 => HQC_PK,
        }
    }

    /// Bytes this module persists for a secret key. For ML-KEM that is the
    /// 64-byte seed rather than the expanded key, not the expanded form.
    pub const fn secret_key_len(self) -> usize {
        match self {
            Suite::McEliece => MC_SK,
            Suite::MlKem768 => ML_SK,
            Suite::Hqc128 => HQC_SK,
        }
    }

    pub const fn ciphertext_len(self) -> usize {
        match self {
            Suite::McEliece => MC_CT,
            Suite::MlKem768 => ML_CT,
            Suite::Hqc128 => HQC_CT,
        }
    }

    /// Is this the suite a bundle may not omit?
    pub const fn is_mandatory(self) -> bool {
        matches!(self, Suite::McEliece)
    }

    /// Generate a keypair, drawing every byte of randomness from `rng`.
    ///
    /// Costs ~243 ms for McEliece and microseconds for the other two, which is
    /// why a McEliece key is a long-term identity and the others need not be.
    pub fn generate<R: RngCore + CryptoRng>(self, rng: &mut R) -> KeyPair {
        match self {
            Suite::McEliece => {
                // `keypair_boxed` wants an RNG rather than a seed and this
                // crate's `rand_core` matches it, so McEliece is the one suite
                // driven the ordinary way.
                let (public, secret) = keypair_boxed(rng);
                pair(self, public.as_array().to_vec(), secret.as_array().to_vec())
            }
            Suite::MlKem768 => {
                let mut seed = Zeroizing::new([0u8; ML_SK]);
                rng.fill_bytes(seed.as_mut_slice());
                let dk = DecapsulationKey::<MlKem768>::from_seed(MlSeed::from(*seed));
                let public = dk.encapsulation_key().to_bytes().as_slice().to_vec();
                // The seed *is* the secret key here. Persisting the expanded
                // form instead would be 2,400 bytes that must then be
                // validated on the way back in; a seed cannot be invalid,
                // because every 64-byte string expands to a key.
                pair(self, public, seed.to_vec())
            }
            Suite::Hqc128 => {
                let mut seed = Zeroizing::new([0u8; 32]);
                rng.fill_bytes(seed.as_mut_slice());
                let (ek, dk) = Hqc128::generate_key_deterministic(&seed);
                pair(self, ek.as_ref().to_vec(), dk.as_ref().to_vec())
            }
        }
    }
}

/// Assemble a keypair from raw halves a generator just produced.
fn pair(suite: Suite, public: Vec<u8>, secret: Vec<u8>) -> KeyPair {
    let public: Box<[u8]> = public.into_boxed_slice();
    KeyPair {
        public: PublicKey {
            suite,
            bytes: public.clone(),
        },
        secret: SecretKey {
            suite,
            bytes: Zeroizing::new(secret),
            public,
        },
    }
}

impl fmt::Display for Suite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// -- keys ------------------------------------------------------------------

/// A public key, tagged with the suite that can use it.
///
/// Not `Copy` and cloned rarely on purpose: a McEliece key is a quarter of a
/// megabyte, and this type exists partly so that fact is visible at the call
/// site rather than hidden in an array type.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey {
    suite: Suite,
    bytes: Box<[u8]>,
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never the key blob. Not because it is secret -- it is not -- but
        // because 261,120 bytes in a log line is a log nobody can read.
        write!(f, "PublicKey({}, {} bytes)", self.suite, self.bytes.len())
    }
}

impl PublicKey {
    /// Adopt a key blob, checking only its length.
    ///
    /// Length is all that can be checked for two of the three suites, and the
    /// consequence is worth stating: an attacker who publishes a random blob of
    /// the right length gets a key nobody can decapsulate to, which stalls
    /// their own share and nothing else. Costing yourself liveness is not an
    /// attack, and it is exactly the bound `docs/p2p.md` gives for a wrong
    /// routing answer.
    pub fn from_bytes(suite: Suite, bytes: &[u8]) -> Result<PublicKey, KemError> {
        if bytes.len() != suite.public_key_len() {
            return Err(KemError::WrongLength {
                suite,
                what: "public key",
                expected: suite.public_key_len(),
                got: bytes.len(),
            });
        }
        if suite == Suite::MlKem768 {
            // FIPS 203 §7.2 requires the modulus check, and `EncapsulationKey`
            // performs it. Doing it here rather than at encapsulate time means
            // a malformed key is refused where it enters rather than where it
            // is used, which is the only place the error is actionable.
            let array = Array::try_from(bytes).map_err(|_| KemError::MalformedKey { suite })?;
            EncapsulationKey::<MlKem768>::new(&array)
                .map_err(|_| KemError::MalformedKey { suite })?;
        }
        Ok(PublicKey {
            suite,
            bytes: bytes.to_vec().into_boxed_slice(),
        })
    }

    pub fn suite(&self) -> Suite {
        self.suite
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Encapsulate to this key alone.
    ///
    /// Prefer [`Bundle::encapsulate`]: a single leg is a single assumption, and
    /// this is here for the McEliece-only paths that predate the bundle (the
    /// transport handshake) and for testing one suite at a time.
    pub fn encapsulate<R: RngCore + CryptoRng>(&self, rng: &mut R) -> (Vec<u8>, Secret32) {
        match self.suite {
            Suite::McEliece => {
                let mut key = [0u8; MC_PK];
                key.copy_from_slice(&self.bytes);
                let pk = McPublicKey::from(&mut key);
                let (ct, shared) = encapsulate_boxed(&pk, rng);
                let secret = Secret32::new(*shared.as_array());
                (ct.as_array().to_vec(), secret)
            }
            Suite::MlKem768 => {
                // Length and encoding were checked by `from_bytes`, so both
                // conversions are infallible here.
                let array = Array::try_from(self.bytes.as_ref()).expect("length checked on entry");
                let ek = EncapsulationKey::<MlKem768>::new(&array).expect("encoding checked");
                let mut m = Zeroizing::new([0u8; 32]);
                rng.fill_bytes(m.as_mut_slice());
                let (ct, shared) = ek.encapsulate_deterministic(&Array::from(*m));
                let mut out = [0u8; SHARED_SECRET_LEN];
                out.copy_from_slice(shared.as_slice());
                (ct.as_slice().to_vec(), Secret32::new(out))
            }
            Suite::Hqc128 => {
                let ek = HqcEncapsulationKey::try_from(self.bytes.as_ref())
                    .expect("length checked on entry");
                let mut m = Zeroizing::new([0u8; HQC_M]);
                let mut salt = [0u8; HQC_SALT];
                rng.fill_bytes(m.as_mut_slice());
                rng.fill_bytes(&mut salt);
                let (ct, shared): (HqcCiphertext, _) = ek
                    .encapsulate_deterministic(m.as_slice(), &salt)
                    .expect("message length is the scheme's own constant");
                let mut out = [0u8; SHARED_SECRET_LEN];
                out.copy_from_slice(shared.as_ref());
                (ct.as_ref().to_vec(), Secret32::new(out))
            }
        }
    }
}

/// A secret key, tagged with its suite. Wiped on drop.
///
/// # Why the public half travels with it
///
/// A `mceliece348864` secret key is 6,492 bytes and its public key is 261,120:
/// the public key is *derived* from the secret, not contained in it, and
/// re-deriving it is the 243 ms keygen. So a secret key that could not name its
/// own public key would make restoring an identity from disk as expensive as
/// creating a new one, and would make `SecretBundle::id()` — which every share
/// derivation absorbs — a quarter-second operation.
///
/// Carrying it costs 255 KB of memory per held identity and is what
/// [`crate::p2p::handshake::PeerIdentity`] already does for the same reason.
/// ML-KEM and HQC could re-derive theirs cheaply; they carry it anyway, because
/// one rule for three suites is one rule to get right.
pub struct SecretKey {
    suite: Suite,
    bytes: Zeroizing<Vec<u8>>,
    public: Box<[u8]>,
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey({}, <redacted>)", self.suite)
    }
}

impl SecretKey {
    /// Restore a persisted keypair.
    ///
    /// Both halves, for every suite — see the type's documentation. Lengths are
    /// checked; that the two halves actually *match* is not, because for
    /// McEliece checking it is the keygen this constructor exists to avoid. A
    /// mismatched pair fails at the first decapsulation, which is the same
    /// failure an attacker's substituted key produces and is handled there.
    pub fn from_bytes(suite: Suite, secret: &[u8], public: &[u8]) -> Result<SecretKey, KemError> {
        if secret.len() != suite.secret_key_len() {
            return Err(KemError::WrongLength {
                suite,
                what: "secret key",
                expected: suite.secret_key_len(),
                got: secret.len(),
            });
        }
        if public.len() != suite.public_key_len() {
            return Err(KemError::WrongLength {
                suite,
                what: "public key",
                expected: suite.public_key_len(),
                got: public.len(),
            });
        }
        Ok(SecretKey {
            suite,
            bytes: Zeroizing::new(secret.to_vec()),
            public: public.to_vec().into_boxed_slice(),
        })
    }

    pub fn suite(&self) -> Suite {
        self.suite
    }

    /// Borrow the raw bytes for persistence. Named `expose` so the call site
    /// reads as an admission, matching [`Secret32::expose`].
    pub fn expose(&self) -> &[u8] {
        &self.bytes
    }

    /// The public half. Free — it was stored, not recomputed.
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            suite: self.suite,
            bytes: self.public.clone(),
        }
    }

    /// Recover the shared secret from a ciphertext.
    ///
    /// **A wrong ciphertext does not error.** All three schemes use implicit
    /// rejection: a malformed or foreign ciphertext yields a pseudorandom
    /// secret rather than a failure, which is what makes them IND-CCA2 and is
    /// deliberately not smoothed over here. The mismatch surfaces at the first
    /// AEAD tag that fails, which is where a caller can actually act on it.
    /// The only error this can return is a length one.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Secret32, KemError> {
        if ciphertext.len() != self.suite.ciphertext_len() {
            return Err(KemError::WrongLength {
                suite: self.suite,
                what: "ciphertext",
                expected: self.suite.ciphertext_len(),
                got: ciphertext.len(),
            });
        }
        let secret = match self.suite {
            Suite::McEliece => {
                let mut ct = [0u8; MC_CT];
                ct.copy_from_slice(ciphertext);
                let mut key = [0u8; MC_SK];
                key.copy_from_slice(&self.bytes);
                let sk = McSecretKey::from(Box::new(key));
                let shared = decapsulate_boxed(&McCiphertext::from(ct), &sk);
                Secret32::new(*shared.as_array())
            }
            Suite::MlKem768 => {
                let mut seed = [0u8; ML_SK];
                seed.copy_from_slice(&self.bytes);
                let dk = DecapsulationKey::<MlKem768>::from_seed(MlSeed::from(seed));
                seed.zeroize();
                let ct: MlCiphertext<MlKem768> =
                    Array::try_from(ciphertext).expect("length checked above");
                let shared = dk.decapsulate(&ct);
                let mut out = [0u8; SHARED_SECRET_LEN];
                out.copy_from_slice(shared.as_slice());
                Secret32::new(out)
            }
            Suite::Hqc128 => {
                let dk =
                    HqcDecapsulationKey::try_from(self.bytes.as_slice()).expect("length checked");
                let ct = HqcCiphertext::try_from(ciphertext).expect("length checked above");
                let shared = dk.decapsulate(&ct);
                let mut out = [0u8; SHARED_SECRET_LEN];
                out.copy_from_slice(shared.as_ref());
                Secret32::new(out)
            }
        };
        Ok(secret)
    }
}

/// A public key and the secret that opens it.
pub struct KeyPair {
    public: PublicKey,
    secret: SecretKey,
}

impl KeyPair {
    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    pub fn secret(&self) -> &SecretKey {
        &self.secret
    }

    pub fn into_parts(self) -> (PublicKey, SecretKey) {
        (self.public, self.secret)
    }
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyPair({})", self.public.suite)
    }
}

// -- bundles ---------------------------------------------------------------

/// The keys one party publishes: one per suite, Classic McEliece mandatory.
///
/// Kept sorted by [`Suite`] so that two parties assembling the same keys in
/// different orders produce the same combiner transcript. An unsorted bundle
/// would be a pair of nodes that agree on the cryptography and disagree on the
/// key, which is the worst shape this kind of bug has: everything verifies
/// locally and nothing interoperates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bundle {
    keys: Vec<PublicKey>,
}

impl Bundle {
    /// Assemble a bundle, sorting by suite and enforcing the McEliece rule.
    pub fn new(keys: impl IntoIterator<Item = PublicKey>) -> Result<Bundle, KemError> {
        let mut keys: Vec<PublicKey> = keys.into_iter().collect();
        if keys.is_empty() {
            return Err(KemError::Empty);
        }
        keys.sort_by_key(|key| key.suite);
        for pair in keys.windows(2) {
            if pair[0].suite == pair[1].suite {
                return Err(KemError::DuplicateSuite {
                    suite: pair[0].suite,
                });
            }
        }
        if !keys.iter().any(|key| key.suite.is_mandatory()) {
            return Err(KemError::McElieceRequired);
        }
        Ok(Bundle { keys })
    }

    /// A bundle holding only a Classic McEliece key.
    pub fn mceliece_only(key: PublicKey) -> Result<Bundle, KemError> {
        Bundle::new([key])
    }

    pub fn keys(&self) -> &[PublicKey] {
        &self.keys
    }

    pub fn key_for(&self, suite: Suite) -> Option<&PublicKey> {
        self.keys.iter().find(|key| key.suite == suite)
    }

    pub fn suites(&self) -> Vec<Suite> {
        self.keys.iter().map(|key| key.suite).collect()
    }

    /// The mandatory Classic McEliece key. Present by construction.
    pub fn mceliece(&self) -> &PublicKey {
        self.key_for(Suite::McEliece)
            .expect("Bundle::new refuses a bundle without one")
    }

    /// This bundle's identity: the id of its Classic McEliece key.
    ///
    /// **Deliberately not a hash of the whole bundle.** A peer's id is
    /// `sha256(McEliece public key)` everywhere in this crate — it is the
    /// Kademlia node id, it is `PeerRecord::transport`, and it is in every
    /// bootstrap file anyone has written. Deriving a bundle id over all the
    /// keys would mean a node that adds an ML-KEM key gets a new identity and
    /// silently leaves the DHT, which is a rotation nobody asked for. So the
    /// mandatory leg names the bundle and the optional legs are additive in
    /// identity exactly as they are in security.
    ///
    /// The other legs are still bound: [`Bundle::encapsulate`] absorbs every
    /// key's suite and ciphertext into the combiner, so a bundle whose optional
    /// keys were swapped derives a different secret even though its id is
    /// unchanged.
    pub fn id(&self) -> [u8; 32] {
        key_id(self.mceliece().as_bytes())
    }

    /// Encapsulate to every leg and combine.
    ///
    /// The returned secret requires **all** legs to recover, which is the
    /// property the whole module exists for: see the combiner below.
    pub fn encapsulate<R: RngCore + CryptoRng>(&self, rng: &mut R) -> (Encapsulated, Secret32) {
        let mut legs = Vec::with_capacity(self.keys.len());
        let mut secrets = Vec::with_capacity(self.keys.len());
        for key in &self.keys {
            let (ciphertext, secret) = key.encapsulate(rng);
            legs.push(Leg {
                suite: key.suite,
                ciphertext,
            });
            secrets.push(secret);
        }
        let combined = combine_legs(self.id(), &legs, &secrets);
        (Encapsulated { legs }, combined)
    }
}

/// The secret halves matching a [`Bundle`], held by whoever published it.
pub struct SecretBundle {
    keys: Vec<SecretKey>,
}

impl fmt::Debug for SecretBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretBundle")
            .field("suites", &self.suites())
            .finish()
    }
}

impl SecretBundle {
    /// Assemble, with the same suite rules as [`Bundle::new`].
    pub fn new(keys: impl IntoIterator<Item = SecretKey>) -> Result<SecretBundle, KemError> {
        let mut keys: Vec<SecretKey> = keys.into_iter().collect();
        if keys.is_empty() {
            return Err(KemError::Empty);
        }
        keys.sort_by_key(|key| key.suite);
        for pair in keys.windows(2) {
            if pair[0].suite == pair[1].suite {
                return Err(KemError::DuplicateSuite {
                    suite: pair[0].suite,
                });
            }
        }
        if !keys.iter().any(|key| key.suite.is_mandatory()) {
            return Err(KemError::McElieceRequired);
        }
        Ok(SecretBundle { keys })
    }

    /// Generate a fresh keypair for each of `suites`, plus McEliece if it was
    /// not asked for. ~243 ms, dominated by the mandatory leg.
    pub fn generate<R: RngCore + CryptoRng>(
        suites: &[Suite],
        rng: &mut R,
    ) -> (Bundle, SecretBundle) {
        let mut wanted: Vec<Suite> = suites.to_vec();
        if !wanted.contains(&Suite::McEliece) {
            wanted.push(Suite::McEliece);
        }
        wanted.sort_unstable();
        wanted.dedup();

        let mut publics = Vec::with_capacity(wanted.len());
        let mut secrets = Vec::with_capacity(wanted.len());
        for suite in wanted {
            let (public, secret) = suite.generate(rng).into_parts();
            publics.push(public);
            secrets.push(secret);
        }
        (
            Bundle::new(publics).expect("McEliece was ensured above"),
            SecretBundle::new(secrets).expect("McEliece was ensured above"),
        )
    }

    pub fn keys(&self) -> &[SecretKey] {
        &self.keys
    }

    pub fn suites(&self) -> Vec<Suite> {
        self.keys.iter().map(|key| key.suite).collect()
    }

    pub fn key_for(&self, suite: Suite) -> Option<&SecretKey> {
        self.keys.iter().find(|key| key.suite == suite)
    }

    /// The public bundle these secrets open.
    pub fn public_bundle(&self) -> Bundle {
        Bundle::new(self.keys.iter().map(SecretKey::public_key))
            .expect("a secret bundle already carries the mandatory leg")
    }

    pub fn id(&self) -> [u8; 32] {
        self.public_bundle().id()
    }

    /// Recover the combined secret from an encapsulation.
    ///
    /// Refuses a leg set that does not correspond to this bundle's keys.
    /// **This is not a tamper check** — it cannot be, because the legs travel
    /// outside any AEAD. It is the check that the combiner hashes the same
    /// transcript the sender did; a substituted ciphertext of the right suite
    /// passes here and fails at the tag, which is where implicit rejection
    /// says it should.
    pub fn decapsulate(&self, sealed: &Encapsulated) -> Result<Secret32, KemError> {
        if sealed.legs.len() != self.keys.len() {
            return Err(KemError::LegMismatch);
        }
        let mut secrets = Vec::with_capacity(self.keys.len());
        for (leg, key) in sealed.legs.iter().zip(self.keys.iter()) {
            // Both sides are sorted by suite, so a positional zip is a suite
            // match -- checked rather than assumed, because a mismatch here
            // would decapsulate one scheme's ciphertext with another's key.
            if leg.suite != key.suite {
                return Err(KemError::LegMismatch);
            }
            secrets.push(key.decapsulate(&leg.ciphertext)?);
        }
        Ok(combine_legs(self.id(), &sealed.legs, &secrets))
    }
}

/// One suite's ciphertext within an [`Encapsulated`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Leg {
    pub suite: Suite,
    pub ciphertext: Vec<u8>,
}

/// What a sender transmits: one ciphertext per leg, in suite order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Encapsulated {
    legs: Vec<Leg>,
}

impl Encapsulated {
    /// Adopt a leg list, checking suite order, uniqueness and every length.
    ///
    /// Order is checked rather than repaired: a decoder that sorted for you
    /// would accept two encodings of one encapsulation, and two encodings is
    /// two digests for one object — the disagreement `canonical.rs` exists to
    /// prevent.
    pub fn new(legs: Vec<Leg>) -> Result<Encapsulated, KemError> {
        if legs.is_empty() {
            return Err(KemError::Empty);
        }
        for pair in legs.windows(2) {
            if pair[0].suite == pair[1].suite {
                return Err(KemError::DuplicateSuite {
                    suite: pair[0].suite,
                });
            }
            if pair[0].suite > pair[1].suite {
                return Err(KemError::LegMismatch);
            }
        }
        for leg in &legs {
            if leg.ciphertext.len() != leg.suite.ciphertext_len() {
                return Err(KemError::WrongLength {
                    suite: leg.suite,
                    what: "ciphertext",
                    expected: leg.suite.ciphertext_len(),
                    got: leg.ciphertext.len(),
                });
            }
        }
        if !legs.iter().any(|leg| leg.suite.is_mandatory()) {
            return Err(KemError::McElieceRequired);
        }
        Ok(Encapsulated { legs })
    }

    pub fn legs(&self) -> &[Leg] {
        &self.legs
    }

    /// Total bytes on the wire.
    pub fn len(&self) -> usize {
        self.legs.iter().map(|leg| leg.ciphertext.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.legs.is_empty()
    }
}

// -- encoding --------------------------------------------------------------
//
// Canonical `Value` rather than `serde`, for the reason `src/canonical.rs`
// exists: a bundle reaches a record, a record's id is the digest of its bytes,
// and two spellings of one bundle would be two ids for one committee member.
// Hex rather than base64 because the canonical encoder has no byte-string type
// and base64 has too many spellings of one value.

impl Bundle {
    /// `[{"suite": ..., "public": "<hex>"}, ...]`, in suite order.
    pub fn to_value(&self) -> Value {
        Value::array(self.keys.iter().map(|key| {
            Value::object([
                ("suite", Value::string(key.suite.as_str())),
                ("public", Value::string(crate::hex::encode(key.as_bytes()))),
            ])
        }))
    }

    pub fn from_value(value: &Value) -> Result<Bundle, KemError> {
        let items = value.as_array().ok_or(KemError::LegMismatch)?;
        let mut keys = Vec::with_capacity(items.len());
        for item in items {
            keys.push(PublicKey::from_bytes(
                Suite::parse(field_str(item, "suite")?)?,
                &field_hex(item, "public")?,
            )?);
        }
        // `new` re-checks order, uniqueness and the mandatory leg, so a decoder
        // cannot admit a bundle the constructor would refuse.
        Bundle::new(keys)
    }
}

impl SecretBundle {
    /// `[{"suite": ..., "public": "<hex>", "secret": "<hex>"}, ...]`.
    ///
    /// **This carries key material.** It is the shape a node's identity file
    /// takes on disk, where `crate::store::atrest` seals it; it is never the
    /// shape anything publishes. [`SecretBundle::public_bundle`] is what gets
    /// published, and the two being different types is what stops the wrong one
    /// being handed to a writer by mistake.
    pub fn to_value(&self) -> Value {
        Value::array(self.keys.iter().map(|key| {
            Value::object([
                ("suite", Value::string(key.suite.as_str())),
                (
                    "public",
                    Value::string(crate::hex::encode(key.public_key().as_bytes())),
                ),
                ("secret", Value::string(crate::hex::encode(key.expose()))),
            ])
        }))
    }

    pub fn from_value(value: &Value) -> Result<SecretBundle, KemError> {
        let items = value.as_array().ok_or(KemError::LegMismatch)?;
        let mut keys = Vec::with_capacity(items.len());
        for item in items {
            keys.push(SecretKey::from_bytes(
                Suite::parse(field_str(item, "suite")?)?,
                &field_hex(item, "secret")?,
                &field_hex(item, "public")?,
            )?);
        }
        SecretBundle::new(keys)
    }
}

fn field_str<'a>(value: &'a Value, field: &str) -> Result<&'a str, KemError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or(KemError::LegMismatch)
}

/// Strict, lowercase-only hex. Accepting `AB` as well as `ab` would give one
/// key two spellings and therefore one committee member two ids.
///
/// `crate::hex` encodes and does not decode, and the decoder in
/// `crate::crypto::envelope` is private to it; both are a dozen lines and both
/// are lowercase-only, which is the property that has to match. Should a third
/// appear, they belong in `crate::hex` together.
fn field_hex(value: &Value, field: &str) -> Result<Vec<u8>, KemError> {
    let text = field_str(value, field)?;
    if text.len() % 2 != 0 {
        return Err(KemError::LegMismatch);
    }
    let nibble = |b: u8| -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            _ => None,
        }
    };
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = nibble(pair[0]).ok_or(KemError::LegMismatch)?;
        let lo = nibble(pair[1]).ok_or(KemError::LegMismatch)?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

// -- the combiner ----------------------------------------------------------

/// Hash every leg into one shared secret.
///
/// ```text
/// K = SHA-256( domain ‖ bundle_id ‖ (suite ‖ ciphertext ‖ secret)* )
/// ```
///
/// Three things earn their place, and the first is the whole point:
///
/// **Every leg's secret is absorbed**, so recovering `K` requires breaking
/// *all* of the schemes, not any one of them. This is what makes a bundle at
/// least as strong as its strongest member. The opposite construction — pick a
/// suite both ends support — is as strong as the weakest suite an attacker can
/// negotiate you down to, and that is a downgrade attack with extra steps.
///
/// **Every ciphertext is absorbed**, so a secret is useless outside the exact
/// encapsulation that produced it. Without this, a leg lifted from one
/// encapsulation into another would combine to the same key.
///
/// **The bundle id is absorbed**, so a set of legs re-addressed to a different
/// recipient derives a different key.
///
/// Fields are length-prefixed, so the transcript is injective: without
/// prefixes, a ciphertext ending in some bytes and a secret starting with them
/// could concatenate identically to a different pair.
fn combine_legs(bundle_id: [u8; 32], legs: &[Leg], secrets: &[Secret32]) -> Secret32 {
    let mut hasher = Sha256::new();
    absorb(&mut hasher, COMBINE_DOMAIN);
    absorb(&mut hasher, &bundle_id);
    for (leg, secret) in legs.iter().zip(secrets.iter()) {
        absorb(&mut hasher, leg.suite.as_str().as_bytes());
        absorb(&mut hasher, &leg.ciphertext);
        absorb(&mut hasher, secret.expose());
    }
    let mut out = hasher.finalize();
    let mut key = [0u8; SHARED_SECRET_LEN];
    key.copy_from_slice(&out[..]);
    Zeroize::zeroize(&mut out[..]);
    Secret32::new(key)
}

fn absorb(hasher: &mut Sha256, field: &[u8]) {
    hasher.update((field.len() as u64).to_be_bytes());
    hasher.update(field);
}

/// The 32-byte id of a Classic McEliece public key.
///
/// The one derivation, called by [`Bundle::id`] and by
/// [`crate::p2p::handshake::peer_id_of`]. The domain string still says `p2p`
/// because changing it would change every peer id in every bootstrap file and
/// every `PeerRecord::transport` ever written — the string is a wire value, not
/// a description, and renaming it for tidiness would be a hard fork for
/// cosmetics.
pub fn key_id(public: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"proofwork/p2p/peer-id/v1");
    h.update(public);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn every_suite_round_trips() {
        for suite in SUITES {
            let pair = suite.generate(&mut OsRng);
            let (ciphertext, sent) = pair.public().encapsulate(&mut OsRng);
            assert_eq!(
                ciphertext.len(),
                suite.ciphertext_len(),
                "{suite} ciphertext length"
            );
            let received = pair
                .secret()
                .decapsulate(&ciphertext)
                .expect("decapsulates");
            assert_eq!(sent.expose(), received.expose(), "{suite} shared secret");
        }
    }

    #[test]
    fn declared_sizes_match_what_the_schemes_actually_produce() {
        // The constants decide what a decoder accepts, so a crate that changed
        // a parameter set underneath us must fail here rather than at the first
        // peer that cannot be dialled.
        for suite in SUITES {
            let pair = suite.generate(&mut OsRng);
            assert_eq!(
                pair.public().as_bytes().len(),
                suite.public_key_len(),
                "{suite} public key"
            );
            assert_eq!(
                pair.secret().expose().len(),
                suite.secret_key_len(),
                "{suite} secret key"
            );
        }
    }

    #[test]
    fn a_persisted_keypair_restores_and_still_decapsulates() {
        // The round trip a node performs on every restart. It has to work
        // without a keygen: McEliece's is 243 ms and would be paid on every
        // process start and every `SecretBundle::id()`.
        for suite in SUITES {
            let pair = suite.generate(&mut OsRng);
            let restored =
                SecretKey::from_bytes(suite, pair.secret().expose(), pair.public().as_bytes())
                    .expect("restores");
            assert_eq!(restored.public_key().as_bytes(), pair.public().as_bytes());

            let (ciphertext, sent) = restored.public_key().encapsulate(&mut OsRng);
            let got = restored.decapsulate(&ciphertext).expect("decapsulates");
            assert_eq!(sent.expose(), got.expose(), "{suite}");
        }
    }

    #[test]
    fn a_bundle_needs_every_leg_to_open() {
        let (public, secret) = SecretBundle::generate(&SUITES, &mut OsRng);
        let (sealed, sent) = public.encapsulate(&mut OsRng);
        assert_eq!(sealed.legs().len(), 3);

        let received = secret.decapsulate(&sealed).expect("opens");
        assert_eq!(sent.expose(), received.expose());

        // Drop the ML-KEM leg and the combiner refuses: it is not that the
        // secret comes out wrong, it is that the transcript no longer matches
        // the bundle at all.
        let short: Vec<Leg> = sealed
            .legs()
            .iter()
            .filter(|leg| leg.suite != Suite::MlKem768)
            .cloned()
            .collect();
        let short = Encapsulated::new(short).expect("still has McEliece");
        // `Secret32` has no `PartialEq` on purpose -- comparing secrets is a
        // constant-time question -- so the error is matched rather than
        // compared through a `Result`.
        assert!(matches!(
            secret.decapsulate(&short),
            Err(KemError::LegMismatch)
        ));
    }

    /// The security claim of the whole module, stated as a test.
    #[test]
    fn breaking_one_suite_does_not_open_a_bundle() {
        let (public, secret) = SecretBundle::generate(&SUITES, &mut OsRng);
        let (sealed, real) = public.encapsulate(&mut OsRng);

        // Model a totally broken ML-KEM: the attacker holds that leg's secret
        // and therefore its shared secret, and holds every ciphertext. They
        // still cannot produce the combined key, because the McEliece and HQC
        // secrets are absorbed too and they have neither.
        let ml_secret = secret
            .key_for(Suite::MlKem768)
            .expect("bundle has one")
            .decapsulate(
                &sealed
                    .legs()
                    .iter()
                    .find(|leg| leg.suite == Suite::MlKem768)
                    .expect("leg present")
                    .ciphertext,
            )
            .expect("decapsulates");

        // Everything the attacker has, hashed the way the combiner does, with
        // zeroes standing in for the two secrets they do not hold.
        let zeros = Secret32::new([0u8; 32]);
        let forged = combine_legs(
            public.id(),
            sealed.legs(),
            &[zeros, ml_secret, Secret32::new([0u8; 32])],
        );
        assert_ne!(real.expose(), forged.expose());
    }

    #[test]
    fn a_bundle_without_mceliece_is_refused() {
        let ml = Suite::MlKem768.generate(&mut OsRng);
        let hqc = Suite::Hqc128.generate(&mut OsRng);
        assert_eq!(
            Bundle::new([ml.public().clone(), hqc.public().clone()]),
            Err(KemError::McElieceRequired)
        );
        assert_eq!(Bundle::new([]), Err(KemError::Empty));
    }

    #[test]
    fn duplicate_suites_are_refused_in_both_directions() {
        let a = Suite::McEliece.generate(&mut OsRng);
        let b = Suite::McEliece.generate(&mut OsRng);
        assert_eq!(
            Bundle::new([a.public().clone(), b.public().clone()]),
            Err(KemError::DuplicateSuite {
                suite: Suite::McEliece
            })
        );
    }

    #[test]
    fn bundles_sort_their_keys_so_assembly_order_cannot_matter() {
        let (bundle, _) = SecretBundle::generate(&SUITES, &mut OsRng);
        let forwards = bundle.keys().to_vec();
        let mut backwards = forwards.clone();
        backwards.reverse();
        let rebuilt = Bundle::new(backwards).expect("same keys");
        assert_eq!(
            rebuilt.suites(),
            vec![Suite::McEliece, Suite::MlKem768, Suite::Hqc128]
        );
        assert_eq!(rebuilt, bundle);
    }

    #[test]
    fn an_encapsulation_out_of_suite_order_is_refused_rather_than_sorted() {
        let (bundle, _) = SecretBundle::generate(&SUITES, &mut OsRng);
        let (sealed, _) = bundle.encapsulate(&mut OsRng);
        let mut reversed = sealed.legs().to_vec();
        reversed.reverse();
        assert_eq!(Encapsulated::new(reversed), Err(KemError::LegMismatch));
    }

    #[test]
    fn a_bundle_id_is_its_mceliece_key_id_and_nothing_else() {
        // Adding an optional leg must not rotate a node's identity: the id is
        // in every bootstrap file and every peer record already written.
        let mceliece = Suite::McEliece.generate(&mut OsRng);
        let alone = Bundle::mceliece_only(mceliece.public().clone()).expect("mandatory leg");
        let ml = Suite::MlKem768.generate(&mut OsRng);
        let with_lattice =
            Bundle::new([mceliece.public().clone(), ml.public().clone()]).expect("assembles");
        assert_eq!(alone.id(), with_lattice.id());
        assert_eq!(alone.id(), key_id(mceliece.public().as_bytes()));
    }

    #[test]
    fn the_same_legs_addressed_to_another_bundle_derive_a_different_secret() {
        let (a_pub, a_sec) = SecretBundle::generate(&[Suite::McEliece], &mut OsRng);
        let (b_pub, _) = SecretBundle::generate(&[Suite::McEliece], &mut OsRng);
        let (sealed, secret) = a_pub.encapsulate(&mut OsRng);
        let _ = a_sec.decapsulate(&sealed).expect("opens for a");
        // Same ciphertexts, different recipient id in the transcript.
        let elsewhere = combine_legs(
            b_pub.id(),
            sealed.legs(),
            &[a_sec
                .key_for(Suite::McEliece)
                .expect("present")
                .decapsulate(&sealed.legs()[0].ciphertext)
                .expect("decapsulates")],
        );
        assert_ne!(secret.expose(), elsewhere.expose());
    }

    #[test]
    fn wrong_lengths_are_refused_rather_than_padded() {
        for suite in SUITES {
            assert!(matches!(
                PublicKey::from_bytes(suite, &[0u8; 7]),
                Err(KemError::WrongLength { .. })
            ));
            assert!(matches!(
                SecretKey::from_bytes(suite, &[0u8; 7], &[0u8; 7]),
                Err(KemError::WrongLength { .. })
            ));
            let pair = suite.generate(&mut OsRng);
            // A right-length secret with a wrong-length public half is refused
            // too: both are checked, not just the first.
            assert!(matches!(
                SecretKey::from_bytes(suite, pair.secret().expose(), &[0u8; 7]),
                Err(KemError::WrongLength { .. })
            ));
            assert!(matches!(
                pair.secret().decapsulate(&[0u8; 3]),
                Err(KemError::WrongLength { .. })
            ));
        }
    }

    #[test]
    fn a_foreign_ciphertext_yields_a_wrong_secret_rather_than_an_error() {
        // Implicit rejection, and it is the property that makes these schemes
        // IND-CCA2. A caller that expected an error here would treat a
        // tampered ciphertext as a transport fault instead of an attack.
        for suite in SUITES {
            let mine = suite.generate(&mut OsRng);
            let theirs = suite.generate(&mut OsRng);
            let (ciphertext, sent) = theirs.public().encapsulate(&mut OsRng);
            let got = mine
                .secret()
                .decapsulate(&ciphertext)
                .expect("length is right, so no error");
            assert_ne!(sent.expose(), got.expose(), "{suite}");
        }
    }

    #[test]
    fn suite_names_round_trip_and_unknown_ones_are_refused() {
        for suite in SUITES {
            assert_eq!(Suite::parse(suite.as_str()), Ok(suite));
        }
        assert!(matches!(
            Suite::parse("csidh-512"),
            Err(KemError::UnknownSuite { .. })
        ));
        // Case matters, for the reason every hex decoder in this crate is
        // lowercase-only: two spellings of one name is two digests.
        assert!(Suite::parse("ML-KEM-768").is_err());
    }

    #[test]
    fn a_malformed_ml_kem_key_is_refused_at_the_door() {
        // FIPS 203 requires the modulus check on an encapsulation key. All-ones
        // is the right length and not a valid encoding.
        assert_eq!(
            PublicKey::from_bytes(Suite::MlKem768, &[0xffu8; ML_PK]),
            Err(KemError::MalformedKey {
                suite: Suite::MlKem768
            })
        );
    }

    #[test]
    fn debug_output_never_carries_key_material() {
        let pair = Suite::McEliece.generate(&mut OsRng);
        let secret = format!("{:?}", pair.secret());
        assert!(secret.contains("redacted"), "got {secret}");
        // A quarter-megabyte key must not reach a log line either.
        let public = format!("{:?}", pair.public());
        assert!(public.len() < 64, "got {} chars", public.len());
    }
}
