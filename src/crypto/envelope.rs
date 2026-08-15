//! Sealed submission envelopes: one AEAD over the artifact, with the content
//! key split across a threshold committee.
//!
//! # Why this exists
//!
//! Plain commit–reveal requires the submitter to act **twice** (`docs/censorship.md`
//! §1). An adversary who can neither forge nor steal your work can still take it
//! by stopping the second action: a targeted DoS, a network block, a detention, a
//! seized laptop, or a sequencer that drops your reveal until the deadline
//! passes. Your commitment sits on the log proving you had the answer first, and
//! you cannot collect.
//!
//! A sealed envelope removes the submitter from the reveal path entirely
//! (§2). The artifact is submitted encrypted at commit time; at the epoch
//! boundary `t` committee members publish their shares and *anyone* reconstructs
//! the content key. The submitter can be offline, jailed, or firewalled and still
//! be paid. Three properties fall out at once:
//!
//! - reveal-window censorship dies — nothing is required of the submitter after commit;
//! - in-flight front-running dies — nobody, sequencer included, sees the artifact
//!   while they could still act on it;
//! - selective censorship becomes visible — a sequencer that cannot see what it is
//!   dropping must include everything or censor indiscriminately, and
//!   indiscriminate censorship is detectable by everyone at once.
//!
//! # What binds what
//!
//! Confidentiality here is *not* what makes the scheme safe; **binding** is, and
//! binding is free. The commitment is already a hash of the plaintext artifact
//! ([`crate::records::commitment_hash`]), so a submitter who seals garbage is
//! caught the moment the committee opens it. This module therefore never needs to
//! prove the plaintext is "the right one" — it only has to guarantee that an
//! envelope cannot be *moved* between submissions. That is what `aad` is for:
//!
//! - it is the AEAD associated data of the payload ciphertext, so a ciphertext
//!   lifted into another submission fails its tag;
//! - it is absorbed into the key-derivation transcript of every sealed share, so
//!   a sealed share replayed into another envelope derives a different key and
//!   fails its tag.
//!
//! Callers pass the submission's commitment hash as `aad`. Storing it and not
//! feeding it to the cryptography would be theatre; both uses above are load
//! bearing and both are tested.
//!
//! # What this does not defend against
//!
//! - **`t` colluding committee members** read the artifact early and can
//!   front-run it. Rotation, diversity and a high threshold make that expensive;
//!   nothing here makes it impossible (§8).
//! - **A committee that refuses to publish shares** stalls the reveal. That is a
//!   liveness failure, not a confidentiality one, and it is why `n - t` must be
//!   large enough to absorb absentees. The fallback is submitter-initiated
//!   reveal: [`SealedEnvelope::seal_retaining_key`] plus
//!   [`SealedEnvelope::open_with_content_key`]. It reintroduces the requirement
//!   that the submitter be online, which is the whole problem — hence a
//!   fallback, not a path.
//! - **Traffic analysis.** [`SealedEnvelope::digest`] is public and the
//!   ciphertext length leaks the artifact length to within 16 bytes (§4).
//!   Padding to a size bucket is the caller's job; this module deliberately does
//!   not pad, because a padding policy chosen here would be invisible to the
//!   record layer that has to agree on it.
//! - **Structural tampering.** `threshold` and the sealed-share list travel
//!   outside every AEAD. Editing them can only make an envelope fail to open: a
//!   wrong or short share set reconstructs a wrong content key, and a wrong
//!   content key fails the payload tag. It can never produce a different
//!   plaintext.
//!
//! # How a share is sealed to a member
//!
//! By key encapsulation to the member's published [`Bundle`], never by a
//! Diffie–Hellman exchange. Until recently this was ephemeral X25519, and the
//! swap is the point rather than an implementation detail: a network whose
//! *transport* is quantum-resistant and whose *submissions* are sealed with
//! X25519 has not protected the submissions at all. An adversary who records
//! traffic today and factors later reads every artifact that was ever sealed,
//! and "later" is the only resource that attack needs.
//!
//! The bundle is McEliece plus whatever else the member published, combined so
//! that opening a share needs every leg — see [`super::kem`]. There is no
//! ephemeral key: a KEM ciphertext is itself the fresh half of the exchange,
//! and each share carries its own, so two shares to one member derive different
//! keys exactly as two ephemeral exchanges did.
//!
//! What was given up with X25519 is a *contributory* check. A low-order X25519
//! key was a real attack — a member could plant one and make their own share
//! world-readable — and the code refused it. A KEM has no equivalent: every
//! bit string of the right length is *a* key, and a member who publishes
//! garbage gets a share nobody can open, including themselves. That is a
//! liveness cost to the member who did it and no confidentiality cost to
//! anyone, so there is nothing left to refuse and no check here that pretends
//! otherwise.
//!
//! # Timing
//!
//! No secret-dependent branch or index is taken in this module. Everything that
//! touches a secret is either data-independent (`copy_from_slice`, the SHA-256
//! transcript) or delegated: [`super::kem`] for encapsulation and decapsulation,
//! `chacha20poly1305` for the constant-time Poly1305 tag comparison, and
//! [`super::shamir`] for the GF(2^8) arithmetic. The one data-dependent routine
//! here, `hex_encode`, is applied only to published bytes.

use core::fmt;

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest as _, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::kem::{Bundle, Encapsulated, KemError, Leg, SecretBundle, Suite, SUITES};
use super::shamir::{self, Share};
use crate::canonical::Value;

/// Wire type tag. Present so a record decoder cannot confuse an envelope with
/// some other object that happens to share field names.
const RECORD_TYPE: &str = "sealed_envelope";

/// Wire version. Bumped only for a change that alters how bytes are interpreted;
/// an unknown version is refused rather than guessed at.
///
/// `2` because a share stopped carrying a 32-byte X25519 ephemeral public key
/// and started carrying a list of KEM ciphertexts. A version-1 envelope is not
/// upgradable — its shares are sealed to keys of a scheme this build no longer
/// speaks — so it is refused rather than half-read. No envelope has ever been
/// written to a log (`SealedSubmission` reached no record kind until the
/// committee reveal did), so nothing in existence is orphaned by that.
const VERSION: i128 = 2;

/// Domain separator for the share key derivation.
///
/// A hash used for two purposes in one protocol is a hash used wrongly. This
/// string exists so that a share key can never collide with a digest computed
/// anywhere else in the crate, whatever the inputs.
///
/// `v2` alongside the version bump: the transcript now absorbs a bundle id and
/// a KEM encapsulation where it used to absorb two X25519 points. Leaving the
/// string at `v1` would have meant one domain covering two different
/// transcripts, which is exactly the collision the separator exists to stop.
const SHARE_KDF_DOMAIN: &[u8] = b"proofwork/censorship/envelope/share-key/v2";

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;

/// Shamir indexes are `u8` x-coordinates, so at most 255 members can hold one
/// share each.
const MAX_COMMITTEE: usize = 255;

// -- secret material -------------------------------------------------------

/// A 32-byte secret that wipes itself on drop and never prints itself.
///
/// Used for the content key and for derived share keys. Handing callers a
/// bare `[u8; 32]` would silently move the wiping obligation onto code that
/// has no reason to remember it.
pub struct Secret32([u8; KEY_LEN]);

impl Secret32 {
    fn zeroed() -> Secret32 {
        Secret32([0u8; KEY_LEN])
    }

    fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Secret32 {
        let mut bytes = [0u8; KEY_LEN];
        rng.fill_bytes(&mut bytes);
        Secret32(bytes)
    }

    /// Take ownership of key bytes the caller already has.
    ///
    /// Public because [`crate::store::atrest`] holds a key that came off disk
    /// rather than out of this module, and it should get the same zeroing and
    /// the same redacted `Debug` as every other secret here. Taking the array
    /// by value rather than by reference is the point: there is one owner, and
    /// the caller's copy is moved rather than left lying around.
    pub fn new(bytes: [u8; KEY_LEN]) -> Secret32 {
        Secret32(bytes)
    }

    /// Borrow the raw bytes. Named `expose` so that every call site reads as an
    /// admission rather than an accessor.
    pub fn expose(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl Zeroize for Secret32 {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for Secret32 {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for Secret32 {}

/// Redacted: a debug-printed key ends up in logs, and a key in a log is a key
/// that leaked.
impl fmt::Debug for Secret32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret32(<redacted>)")
    }
}

// -- errors ----------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeError {
    /// A committee of zero members can seal nothing that anyone can reopen.
    EmptyCommittee,
    /// More members than there are Shamir x-coordinates.
    CommitteeTooLarge { size: usize },
    /// `threshold` must be at least 1 and at most the committee size.
    InvalidThreshold { threshold: u8, committee: usize },
    /// Two members share a routing index, so a share cannot be addressed.
    DuplicateMemberIndex { index: u8 },
    /// Two members share a key bundle. Not a decoding problem: it means one
    /// entity silently holds two shares and the effective threshold is lower
    /// than the stated one.
    DuplicateMemberKey { index: u8 },
    /// The key encapsulation layer refused a key, a ciphertext or a bundle.
    ///
    /// Structural only — a wrong length, a suite this build does not speak, a
    /// bundle missing its mandatory McEliece leg. A *wrong* ciphertext does not
    /// arrive here, because all three schemes reject implicitly and surface as
    /// [`EnvelopeError::Authentication`] instead.
    Kem(KemError),
    /// The share splitter returned a different number of shares than there are
    /// members, so shares and members cannot be paired.
    ShareCountMismatch { shares: usize, committee: usize },
    /// The secret sharing layer failed. Text is captured rather than typed so
    /// this module does not constrain the sibling's error enum.
    Shamir(String),
    /// AEAD encryption failed. Reachable only for absurd input lengths.
    Encrypt { context: &'static str },
    /// AEAD authentication failed.
    ///
    /// For the payload this is the *only* signal that the share set was wrong:
    /// see [`SealedEnvelope::open_with_shares`].
    Authentication { context: &'static str },
    /// No sealed share carries this routing index.
    UnknownShare { index: u8 },
    /// A decrypted sealed share was empty, so it carries no Shamir index byte.
    MalformedShare { index: u8 },
    /// The reconstructed secret is not a 32-byte content key.
    ContentKeyLength { actual: usize },
    /// `open_with_shares` was handed nothing to combine.
    NoShares,
    /// Decoding: the value is not an object.
    NotAnObject,
    /// Decoding: required field absent.
    MissingField { field: &'static str },
    /// Decoding: field present with the wrong shape.
    InvalidField {
        field: &'static str,
        expected: &'static str,
    },
    /// Decoding: field is not lowercase, even-length hex.
    InvalidHex { field: &'static str },
    /// Decoding: hex field decoded to the wrong number of bytes.
    WrongLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    /// Decoding: two sealed shares claim the same routing index.
    DuplicateShareIndex { index: u8 },
    /// Decoding: a version this build cannot interpret.
    UnsupportedVersion { version: i128 },
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EnvelopeError::EmptyCommittee => f.write_str("committee must have at least one member"),
            EnvelopeError::CommitteeTooLarge { size } => write!(
                f,
                "committee of {size} exceeds the {MAX_COMMITTEE} addressable shares"
            ),
            EnvelopeError::InvalidThreshold {
                threshold,
                committee,
            } => write!(
                f,
                "threshold {threshold} must be in 1..={committee} for this committee"
            ),
            EnvelopeError::DuplicateMemberIndex { index } => {
                write!(f, "duplicate committee member index {index}")
            }
            EnvelopeError::DuplicateMemberKey { index } => write!(
                f,
                "committee member {index} reuses another member's public key; \
                 one entity would hold two shares"
            ),
            EnvelopeError::Kem(e) => write!(f, "key encapsulation: {e}"),
            EnvelopeError::ShareCountMismatch { shares, committee } => write!(
                f,
                "share splitter returned {shares} shares for {committee} members"
            ),
            EnvelopeError::Shamir(why) => write!(f, "secret sharing failed: {why}"),
            EnvelopeError::Encrypt { context } => write!(f, "{context}: AEAD encryption failed"),
            EnvelopeError::Authentication { context } => {
                write!(f, "{context}: AEAD authentication failed")
            }
            EnvelopeError::UnknownShare { index } => {
                write!(f, "envelope carries no sealed share for index {index}")
            }
            EnvelopeError::MalformedShare { index } => {
                write!(f, "sealed share {index} decrypted to an empty plaintext")
            }
            EnvelopeError::ContentKeyLength { actual } => write!(
                f,
                "reconstructed secret is {actual} bytes, expected {KEY_LEN}"
            ),
            EnvelopeError::NoShares => f.write_str("no shares supplied"),
            EnvelopeError::NotAnObject => f.write_str("sealed envelope must be an object"),
            EnvelopeError::MissingField { field } => {
                write!(f, "missing required field {field:?}")
            }
            EnvelopeError::InvalidField { field, expected } => {
                write!(f, "field {field:?} must be {expected}")
            }
            EnvelopeError::InvalidHex { field } => {
                write!(f, "field {field:?} must be lowercase hex of even length")
            }
            EnvelopeError::WrongLength {
                field,
                expected,
                actual,
            } => write!(
                f,
                "field {field:?} must decode to {expected} bytes, got {actual}"
            ),
            EnvelopeError::DuplicateShareIndex { index } => {
                write!(f, "duplicate sealed share index {index}")
            }
            EnvelopeError::UnsupportedVersion { version } => {
                write!(f, "unsupported sealed envelope version {version}")
            }
        }
    }
}

impl std::error::Error for EnvelopeError {}

// -- committee -------------------------------------------------------------

/// A committee member's public identity: a routing index and a key bundle.
///
/// `index` addresses the member within *this* envelope and has nothing to do
/// with the Shamir x-coordinate of the share they hold; the x-coordinate travels
/// sealed, inside the share ciphertext. Keeping them separate means this module
/// never has to assume how the sibling splitter numbers its shares.
///
/// No longer `Copy`, and the reason is worth stating rather than discovering at
/// a call site: a member's bundle carries a 261,120-byte McEliece key, so an
/// implicit copy per use would have been a quarter of a megabyte memcpy nobody
/// wrote down. `Clone` is explicit for exactly that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitteeMember {
    pub index: u8,
    pub keys: Bundle,
}

impl CommitteeMember {
    /// This member's 32-byte identity, which is the id of the McEliece leg of
    /// their bundle — the same value as their transport peer id and their
    /// `PeerRecord::transport`. See [`Bundle::id`].
    pub fn id(&self) -> [u8; 32] {
        self.keys.id()
    }
}

/// A committee member's private keys.
///
/// Static rather than ephemeral because a committee member must be reachable
/// across an epoch's worth of submissions with one published bundle. The cost
/// is no forward secrecy, which [`super::kem`] states plainly.
pub struct CommitteeKey {
    secrets: SecretBundle,
}

/// Redacted. This impl exists so that deriving `Debug` on a surrounding type
/// cannot accidentally add one later.
impl fmt::Debug for CommitteeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommitteeKey")
            .field("id", &hex_encode(&self.secrets.id()))
            .field("suites", &self.secrets.suites())
            .field("secrets", &"<redacted>")
            .finish()
    }
}

impl CommitteeKey {
    /// Generate a member key over `suites`. Classic McEliece is added if it was
    /// not asked for, because [`Bundle`] refuses a bundle without it.
    pub fn generate_over<R: RngCore + CryptoRng>(suites: &[Suite], rng: &mut R) -> CommitteeKey {
        let (_public, secrets) = SecretBundle::generate(suites, rng);
        CommitteeKey { secrets }
    }

    /// Generate a member key over every suite this build implements.
    ///
    /// The default because a bundle is only as strong as its *strongest* leg
    /// (the combiner absorbs all of them), so there is no security reason for a
    /// member to publish fewer — only a size reason, and a committee key is
    /// published once per epoch.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> CommitteeKey {
        CommitteeKey::generate_over(&SUITES, rng)
    }

    /// Adopt an already-assembled secret bundle, for a member whose keys are
    /// persisted elsewhere — a node reusing its transport identity, which is
    /// what [`crate::node::Node`] does for a drawn committee.
    pub fn from_secrets(secrets: SecretBundle) -> CommitteeKey {
        CommitteeKey { secrets }
    }

    pub fn secrets(&self) -> &SecretBundle {
        &self.secrets
    }

    /// Persist. **Carries key material** — see [`SecretBundle::to_value`].
    pub fn to_value(&self) -> Value {
        self.secrets.to_value()
    }

    /// Restore a persisted committee key.
    pub fn from_value(value: &Value) -> Result<CommitteeKey, EnvelopeError> {
        SecretBundle::from_value(value)
            .map(CommitteeKey::from_secrets)
            .map_err(EnvelopeError::Kem)
    }

    /// The public bundle other parties seal to.
    pub fn public(&self) -> Bundle {
        self.secrets.public_bundle()
    }

    /// This member's 32-byte identity. See [`CommitteeMember::id`].
    pub fn id(&self) -> [u8; 32] {
        self.secrets.id()
    }

    /// The public half of this key, addressed at `index`.
    pub fn member(&self, index: u8) -> CommitteeMember {
        CommitteeMember {
            index,
            keys: self.public(),
        }
    }

    /// Recover this member's Shamir share at the epoch boundary.
    ///
    /// Failure modes are deliberately indistinguishable: a share sealed to
    /// somebody else, a share lifted from another envelope, and a tampered share
    /// all surface as [`EnvelopeError::Authentication`]. There is no way to tell
    /// them apart from the ciphertext, and pretending otherwise would invent a
    /// distinction the cryptography does not support.
    pub fn open_share(&self, envelope: &SealedEnvelope, index: u8) -> Result<Share, EnvelopeError> {
        let sealed = envelope
            .sealed_share(index)
            .ok_or(EnvelopeError::UnknownShare { index })?;

        // A leg set that does not match this member's suites is a structural
        // error and says so; a leg set that matches but was sealed to somebody
        // else decapsulates to a pseudorandom secret and fails at the tag
        // below, which is where implicit rejection puts it.
        let shared = self
            .secrets
            .decapsulate(&sealed.encapsulated)
            .map_err(EnvelopeError::Kem)?;

        let key = derive_share_key(
            &shared,
            &sealed.encapsulated,
            self.id(),
            index,
            &envelope.aad,
        );
        let cipher = cipher_for(&key);
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(&Nonce::from(sealed.nonce), sealed.ciphertext.as_slice())
                .map_err(|_| EnvelopeError::Authentication {
                    context: "sealed share",
                })?,
        );

        // Layout: one Shamir x-coordinate byte, then the share body. The
        // x-coordinate is inside the AEAD rather than beside it so that a
        // relabelled share is a tag failure, not a silently wrong reconstruction.
        let (x, body) = plaintext
            .split_first()
            .ok_or(EnvelopeError::MalformedShare { index })?;
        Ok(Share {
            index: *x,
            data: body.to_vec(),
        })
    }
}

// -- sealed share ----------------------------------------------------------

/// One committee member's share, sealed to their key bundle.
///
/// `encapsulated` replaces what was a single 32-byte X25519 ephemeral public
/// key. It is larger — 96 bytes for McEliece alone, 5,617 for all three suites
/// — and that is the price of the property in [`super::kem`]: every leg must be
/// broken to open one share.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedShare {
    index: u8,
    encapsulated: Encapsulated,
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
}

impl SealedShare {
    pub fn index(&self) -> u8 {
        self.index
    }

    /// The KEM ciphertexts this share's key was derived from, one per suite.
    pub fn encapsulated(&self) -> &Encapsulated {
        &self.encapsulated
    }

    pub fn nonce(&self) -> &[u8; NONCE_LEN] {
        &self.nonce
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn to_value(&self) -> Value {
        Value::object([
            ("index", Value::Int(i128::from(self.index))),
            (
                "kem",
                Value::array(self.encapsulated.legs().iter().map(|leg| {
                    Value::object([
                        ("suite", Value::string(leg.suite.as_str())),
                        ("ciphertext", Value::string(hex_encode(&leg.ciphertext))),
                    ])
                })),
            ),
            ("nonce", Value::string(hex_encode(&self.nonce))),
            ("ciphertext", Value::string(hex_encode(&self.ciphertext))),
        ])
    }

    pub fn from_value(value: &Value) -> Result<SealedShare, EnvelopeError> {
        if value.as_object().is_none() {
            return Err(EnvelopeError::NotAnObject);
        }
        let raw = value
            .get("kem")
            .ok_or(EnvelopeError::MissingField { field: "kem" })?
            .as_array()
            .ok_or(EnvelopeError::InvalidField {
                field: "kem",
                expected: "an array",
            })?;
        let mut legs = Vec::with_capacity(raw.len());
        for item in raw {
            if item.as_object().is_none() {
                return Err(EnvelopeError::NotAnObject);
            }
            let suite = Suite::parse(field_str(item, "suite")?).map_err(EnvelopeError::Kem)?;
            legs.push(Leg {
                suite,
                ciphertext: field_hex(item, "ciphertext")?,
            });
        }
        // Suite order, uniqueness, per-suite ciphertext length and the
        // mandatory McEliece leg are all `Encapsulated`'s rules, checked in one
        // place so the decoder cannot admit a shape `seal` never produces.
        let encapsulated = Encapsulated::new(legs).map_err(EnvelopeError::Kem)?;

        Ok(SealedShare {
            index: field_u8(value, "index")?,
            encapsulated,
            nonce: field_hex_fixed::<NONCE_LEN>(value, "nonce")?,
            ciphertext: field_hex(value, "ciphertext")?,
        })
    }
}

// -- envelope --------------------------------------------------------------

/// An artifact sealed to a threshold committee.
///
/// Every field is public ciphertext or public metadata, so `Debug`, `Clone` and
/// `PartialEq` leak nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedEnvelope {
    threshold: u8,
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
    sealed_shares: Vec<SealedShare>,
    aad: String,
}

impl SealedEnvelope {
    /// Seal `payload` to `committee`, openable by any `threshold` of them.
    ///
    /// `aad` is the context this envelope is bound to — the submission's
    /// commitment hash. It is fed to the payload AEAD *and* into every share's
    /// key derivation, so neither the payload ciphertext nor an individual
    /// sealed share can be lifted into a different submission.
    ///
    /// The 96-bit nonces are random rather than counters. That is safe only
    /// because both keys are fresh: the content key is 32 bytes drawn from `rng`
    /// for this envelope alone, and each share key comes from a fresh ephemeral
    /// exchange. Neither key ever encrypts a second message, so nonce reuse
    /// across messages under one key cannot arise.
    pub fn seal<R: RngCore + CryptoRng>(
        payload: &[u8],
        aad: &str,
        committee: &[CommitteeMember],
        threshold: u8,
        rng: &mut R,
    ) -> Result<SealedEnvelope, EnvelopeError> {
        // The content key is dropped here, and wiped on the way out. A submitter
        // who wants the §2 liveness fallback must ask for it explicitly.
        SealedEnvelope::seal_retaining_key(payload, aad, committee, threshold, rng)
            .map(|(envelope, _key)| envelope)
    }

    /// [`SealedEnvelope::seal`], but the content key is returned instead of
    /// wiped.
    ///
    /// Keeping it is what makes [`SealedEnvelope::open_with_content_key`] usable,
    /// and therefore what makes the stalled-committee fallback in
    /// `docs/censorship.md` §2 real rather than aspirational. It is a separate
    /// constructor because retaining the key is a decision with a cost: the key
    /// is now a thing that can be seized from the submitter, which is the exact
    /// leverage sealing was meant to remove.
    pub fn seal_retaining_key<R: RngCore + CryptoRng>(
        payload: &[u8],
        aad: &str,
        committee: &[CommitteeMember],
        threshold: u8,
        rng: &mut R,
    ) -> Result<(SealedEnvelope, Secret32), EnvelopeError> {
        if committee.is_empty() {
            return Err(EnvelopeError::EmptyCommittee);
        }
        if committee.len() > MAX_COMMITTEE {
            return Err(EnvelopeError::CommitteeTooLarge {
                size: committee.len(),
            });
        }
        if threshold == 0 || usize::from(threshold) > committee.len() {
            return Err(EnvelopeError::InvalidThreshold {
                threshold,
                committee: committee.len(),
            });
        }
        // A duplicate index makes a share unaddressable; a duplicate key means
        // one entity holds two shares, which quietly lowers the threshold the
        // rest of the system believes it has. Both are caller bugs worth
        // refusing loudly (docs/censorship.md §2 on collusion cost).
        for (i, member) in committee.iter().enumerate() {
            for other in committee.iter().skip(i + 1) {
                if member.index == other.index {
                    return Err(EnvelopeError::DuplicateMemberIndex {
                        index: member.index,
                    });
                }
                // By id, not by bundle. The id is `sha256` of the McEliece leg,
                // so two members with the same mandatory key are the same
                // entity however their optional legs differ -- and comparing
                // whole bundles would let one entity dodge this rule by
                // publishing a second bundle that reuses its McEliece key and
                // adds an ML-KEM one. Cheaper too: 32 bytes rather than 261 KB.
                if member.id() == other.id() {
                    return Err(EnvelopeError::DuplicateMemberKey { index: other.index });
                }
            }
        }

        let content_key = Secret32::random(rng);
        let mut nonce = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce);

        let ciphertext = cipher_for(&content_key)
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: payload,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| EnvelopeError::Encrypt { context: "payload" })?;

        // `committee.len() <= MAX_COMMITTEE == u8::MAX`, checked above.
        let count = committee.len() as u8;
        let mut shares = shamir::split(content_key.expose(), threshold, count, &mut *rng)
            .map_err(|e| EnvelopeError::Shamir(format!("{e:?}")))?;
        if shares.len() != committee.len() {
            wipe_shares(&mut shares);
            return Err(EnvelopeError::ShareCountMismatch {
                shares: shares.len(),
                committee: committee.len(),
            });
        }

        let mut sealed_shares = Vec::with_capacity(committee.len());
        let mut failure = None;
        for (member, share) in committee.iter().zip(shares.iter()) {
            match seal_share(member, share, aad, rng) {
                Ok(sealed) => sealed_shares.push(sealed),
                Err(e) => {
                    failure = Some(e);
                    break;
                }
            }
        }
        // The splitter's `Share` is a plain data struct with no drop glue, so
        // wiping is this module's responsibility -- on the error path too, where
        // plaintext shares of a still-secret content key would otherwise be left
        // in freed memory.
        wipe_shares(&mut shares);
        if let Some(e) = failure {
            return Err(e);
        }

        Ok((
            SealedEnvelope {
                threshold,
                nonce,
                ciphertext,
                sealed_shares,
                aad: aad.to_string(),
            },
            content_key,
        ))
    }

    /// Reconstruct the content key from published shares and decrypt.
    ///
    /// **Shamir cannot tell you "too few shares".** Any set of points defines
    /// *some* polynomial, so combining `t-1` shares yields a perfectly
    /// well-formed 32-byte value that is simply the wrong key — this is the
    /// information-theoretic security property, not a defect. There is therefore
    /// no share count check here and there could not be a useful one: the AEAD
    /// tag is the only thing that can distinguish a correct reconstruction from
    /// a wrong one, which is why it is load-bearing rather than decorative.
    ///
    /// A failure means one of: too few shares, a corrupt or forged share, shares
    /// from a different envelope, or a tampered ciphertext. All of them are
    /// [`EnvelopeError::Authentication`] and none of them can be distinguished.
    pub fn open_with_shares(&self, shares: &[Share]) -> Result<Vec<u8>, EnvelopeError> {
        if shares.is_empty() {
            return Err(EnvelopeError::NoShares);
        }
        let combined = Zeroizing::new(
            shamir::combine(shares).map_err(|e| EnvelopeError::Shamir(format!("{e:?}")))?,
        );
        if combined.len() != KEY_LEN {
            return Err(EnvelopeError::ContentKeyLength {
                actual: combined.len(),
            });
        }
        let mut content_key = Secret32::zeroed();
        content_key.0.copy_from_slice(&combined); // length checked immediately above

        cipher_for(&content_key)
            .decrypt(
                &Nonce::from(self.nonce),
                Payload {
                    msg: &self.ciphertext,
                    aad: self.aad.as_bytes(),
                },
            )
            .map_err(|_| EnvelopeError::Authentication { context: "payload" })
    }

    /// Decrypt with a content key held directly.
    ///
    /// The submitter never lost the key, so this is the fallback for a committee
    /// that will not publish (`docs/censorship.md` §2: "a permanently stalled
    /// epoch must fall back to submitter-initiated reveal rather than losing the
    /// submission"). It restores the plain commit–reveal failure mode — the
    /// submitter must be online — which is exactly why it is the fallback and
    /// not the path.
    pub fn open_with_content_key(&self, content_key: &Secret32) -> Result<Vec<u8>, EnvelopeError> {
        cipher_for(content_key)
            .decrypt(
                &Nonce::from(self.nonce),
                Payload {
                    msg: &self.ciphertext,
                    aad: self.aad.as_bytes(),
                },
            )
            .map_err(|_| EnvelopeError::Authentication { context: "payload" })
    }

    pub fn threshold(&self) -> u8 {
        self.threshold
    }

    pub fn nonce(&self) -> &[u8; NONCE_LEN] {
        &self.nonce
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// The context this envelope is bound to, normally a commitment hash.
    pub fn aad(&self) -> &str {
        &self.aad
    }

    pub fn sealed_shares(&self) -> &[SealedShare] {
        &self.sealed_shares
    }

    pub fn sealed_share(&self, index: u8) -> Option<&SealedShare> {
        self.sealed_shares.iter().find(|s| s.index == index)
    }

    pub fn to_value(&self) -> Value {
        Value::object([
            ("type", Value::string(RECORD_TYPE)),
            ("version", Value::Int(VERSION)),
            ("threshold", Value::Int(i128::from(self.threshold))),
            ("nonce", Value::string(hex_encode(&self.nonce))),
            ("ciphertext", Value::string(hex_encode(&self.ciphertext))),
            ("aad", Value::string(self.aad.clone())),
            (
                "sealed_shares",
                Value::array(self.sealed_shares.iter().map(SealedShare::to_value)),
            ),
        ])
    }

    pub fn from_value(value: &Value) -> Result<SealedEnvelope, EnvelopeError> {
        if value.as_object().is_none() {
            return Err(EnvelopeError::NotAnObject);
        }
        match value.get("type") {
            None => return Err(EnvelopeError::MissingField { field: "type" }),
            Some(Value::String(t)) if t.as_str() == RECORD_TYPE => {}
            Some(_) => {
                return Err(EnvelopeError::InvalidField {
                    field: "type",
                    expected: "\"sealed_envelope\"",
                })
            }
        }
        let version = value
            .get("version")
            .ok_or(EnvelopeError::MissingField { field: "version" })?
            .as_i128()
            .ok_or(EnvelopeError::InvalidField {
                field: "version",
                expected: "an integer",
            })?;
        if version != VERSION {
            return Err(EnvelopeError::UnsupportedVersion { version });
        }

        let threshold = field_u8(value, "threshold")?;
        let nonce = field_hex_fixed::<NONCE_LEN>(value, "nonce")?;
        let ciphertext = field_hex(value, "ciphertext")?;
        let aad = field_str(value, "aad")?.to_string();

        let raw = value
            .get("sealed_shares")
            .ok_or(EnvelopeError::MissingField {
                field: "sealed_shares",
            })?
            .as_array()
            .ok_or(EnvelopeError::InvalidField {
                field: "sealed_shares",
                expected: "an array",
            })?;
        let mut sealed_shares = Vec::with_capacity(raw.len());
        for item in raw {
            let share = SealedShare::from_value(item)?;
            if sealed_shares
                .iter()
                .any(|s: &SealedShare| s.index == share.index)
            {
                return Err(EnvelopeError::DuplicateShareIndex { index: share.index });
            }
            sealed_shares.push(share);
        }

        // These are the same invariants `seal` enforces. A decoder that accepted
        // an envelope `seal` could not have produced would hand the rest of the
        // system a shape it never has to handle.
        if sealed_shares.is_empty() {
            return Err(EnvelopeError::EmptyCommittee);
        }
        if threshold == 0 || usize::from(threshold) > sealed_shares.len() {
            return Err(EnvelopeError::InvalidThreshold {
                threshold,
                committee: sealed_shares.len(),
            });
        }

        Ok(SealedEnvelope {
            threshold,
            nonce,
            ciphertext,
            sealed_shares,
            aad,
        })
    }

    /// Content address of the envelope as it appears on the wire.
    ///
    /// Over the canonical encoding, so it covers the sealed shares and their
    /// order. Two nodes that hold the same envelope agree on this digest; a node
    /// that reorders the share list produces a different digest for an envelope
    /// that still opens, so the digest identifies the *encoding*, not the
    /// plaintext. The commitment hash is what identifies the plaintext.
    pub fn digest(&self) -> String {
        self.to_value().digest()
    }
}

// -- internals -------------------------------------------------------------

/// Seal one Shamir share to one member.
fn seal_share<R: RngCore + CryptoRng>(
    member: &CommitteeMember,
    share: &Share,
    aad: &str,
    rng: &mut R,
) -> Result<SealedShare, EnvelopeError> {
    // A fresh encapsulation per share, which is what the ephemeral X25519
    // keypair used to buy: two shares sealed to one member derive two different
    // keys, so a nonce cannot repeat under a key and one opened share says
    // nothing about another.
    //
    // What it does *not* buy is forward secrecy. The member's bundle is
    // long-lived, so a leaked committee secret opens every share ever sealed to
    // it. That was equally true of the static X25519 side of the old exchange;
    // it is stated here rather than implied by the word "ephemeral" no longer
    // appearing.
    let (encapsulated, shared) = member.keys.encapsulate(rng);

    let key = derive_share_key(&shared, &encapsulated, member.id(), member.index, aad);

    let mut plaintext = Zeroizing::new(Vec::with_capacity(share.data.len().saturating_add(1)));
    plaintext.push(share.index);
    plaintext.extend_from_slice(&share.data);

    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    // No associated data here: `aad` is already committed to by the derived key,
    // so an envelope-mismatched share fails at the tag either way, and binding it
    // twice would only invite the two bindings to drift apart.
    let ciphertext = cipher_for(&key)
        .encrypt(&Nonce::from(nonce), plaintext.as_slice())
        .map_err(|_| EnvelopeError::Encrypt {
            context: "sealed share",
        })?;

    Ok(SealedShare {
        index: member.index,
        encapsulated,
        nonce,
        ciphertext,
    })
}

/// Derive a share-sealing key from a completed key encapsulation.
///
/// Every value that decides *which* envelope and *which* recipient this share
/// belongs to is absorbed, so a sealed share is cryptographically welded to its
/// position: replay it into another envelope (different `aad`), re-address it to
/// another member (different recipient id or index), or pair it with a
/// different encapsulation, and the derived key changes and the tag fails.
///
/// **The recipient's 32-byte id, not their key.** The id is `sha256` of the
/// McEliece leg, so it commits to that key exactly as well as the key does,
/// while a member's bundle is a quarter of a megabyte — absorbing it would put
/// a 261 KB hash on every seal and every open for no additional binding. The
/// optional legs are not absorbed here either and do not need to be: the
/// combiner inside [`Bundle::encapsulate`] already hashes every leg's suite and
/// ciphertext into `shared`, so a bundle whose ML-KEM key was swapped produces
/// a different `shared` and therefore a different key.
///
/// Fields are length-prefixed so the transcript is injective — without prefixes,
/// a recipient id ending in some bytes and an `aad` starting with them could
/// concatenate to the same string as a different pair.
fn derive_share_key(
    shared: &Secret32,
    encapsulated: &Encapsulated,
    recipient_id: [u8; 32],
    member_index: u8,
    aad: &str,
) -> Secret32 {
    let mut hasher = Sha256::new();
    absorb(&mut hasher, SHARE_KDF_DOMAIN);
    absorb(&mut hasher, shared.expose());
    for leg in encapsulated.legs() {
        absorb(&mut hasher, leg.suite.as_str().as_bytes());
        absorb(&mut hasher, &leg.ciphertext);
    }
    absorb(&mut hasher, &recipient_id);
    absorb(&mut hasher, &[member_index]);
    absorb(&mut hasher, aad.as_bytes());

    let mut out = hasher.finalize();
    let mut key = Secret32::zeroed();
    // SHA-256's output is 32 bytes by construction, so this cannot mismatch.
    key.0.copy_from_slice(&out[..]);
    Zeroize::zeroize(&mut out[..]);
    key
}

fn absorb(hasher: &mut Sha256, field: &[u8]) {
    hasher.update((field.len() as u64).to_be_bytes());
    hasher.update(field);
}

/// Build an AEAD instance, wiping the copy of the key made on the way in.
///
/// `ChaCha20Poly1305` zeroizes its own key on drop; the `GenericArray` used to
/// hand it over is the one copy nobody else wipes.
fn cipher_for(key: &Secret32) -> ChaCha20Poly1305 {
    let mut material = Key::from(*key.expose());
    let cipher = ChaCha20Poly1305::new(&material);
    Zeroize::zeroize(&mut material[..]);
    cipher
}

fn wipe_shares(shares: &mut [Share]) {
    for share in shares.iter_mut() {
        share.data.zeroize();
    }
}

// -- hex and field decoding ------------------------------------------------

/// Lowercase hex. Binary on the wire is hex because the canonical encoder has no
/// byte-string type and base64 has too many spellings of one value.
///
/// **Not constant time**: it branches per nibble. That is fine for what it is
/// used on -- nonces, ciphertexts, ephemeral and committee public keys, all of
/// which are published -- and it is why [`Secret32`] has no hex or `Display`
/// impl. Do not reach for this to print key material.
fn hex_encode(bytes: &[u8]) -> String {
    // One encoder for the whole crate, in `crate::hex`. A second copy here is a
    // second thing that could disagree about how a published byte is spelled.
    crate::hex::encode(bytes)
}

/// Strict decoder: lowercase only.
///
/// Accepting `AB` as well as `ab` would give one envelope two spellings and
/// therefore two digests, which is the disagreement `canonical.rs` exists to
/// prevent.
fn hex_decode(text: &str, field: &'static str) -> Result<Vec<u8>, EnvelopeError> {
    let mut out = Vec::with_capacity(text.len() / 2);
    let mut high: Option<u8> = None;
    for byte in text.bytes() {
        let value = hex_value(byte).ok_or(EnvelopeError::InvalidHex { field })?;
        match high.take() {
            None => high = Some(value),
            Some(h) => out.push((h << 4) | value),
        }
    }
    if high.is_some() {
        return Err(EnvelopeError::InvalidHex { field });
    }
    Ok(out)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn field_str<'a>(value: &'a Value, field: &'static str) -> Result<&'a str, EnvelopeError> {
    value
        .get(field)
        .ok_or(EnvelopeError::MissingField { field })?
        .as_str()
        .ok_or(EnvelopeError::InvalidField {
            field,
            expected: "a string",
        })
}

fn field_hex(value: &Value, field: &'static str) -> Result<Vec<u8>, EnvelopeError> {
    hex_decode(field_str(value, field)?, field)
}

fn field_hex_fixed<const N: usize>(
    value: &Value,
    field: &'static str,
) -> Result<[u8; N], EnvelopeError> {
    let bytes = field_hex(value, field)?;
    if bytes.len() != N {
        return Err(EnvelopeError::WrongLength {
            field,
            expected: N,
            actual: bytes.len(),
        });
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes); // length checked immediately above
    Ok(out)
}

fn field_u8(value: &Value, field: &'static str) -> Result<u8, EnvelopeError> {
    let raw = value
        .get(field)
        .ok_or(EnvelopeError::MissingField { field })?
        .as_i128()
        .ok_or(EnvelopeError::InvalidField {
            field,
            expected: "an integer",
        })?;
    u8::try_from(raw).map_err(|_| EnvelopeError::InvalidField {
        field,
        expected: "an integer in 0..=255",
    })
}

#[cfg(test)]
mod tests {
    /// RFC 8439 §2.8.2, against this crate's own AEAD construction.
    ///
    /// **Why a known-answer test and not another round-trip.** Every other
    /// cipher test here seals and opens in the same process with the same
    /// build, so it passes for any construction that is merely *self*-consistent
    /// — including one that has quietly changed. A sealed store and a recorded
    /// transport frame both outlive the binary that wrote them, so a cipher bump
    /// that altered the nonce handling, the AAD framing or the tag position
    /// would orphan every one of them and no test in this repository would have
    /// noticed.
    ///
    /// This is the check that noticed nothing when `chacha20poly1305` went from
    /// 0.10 to 0.11, which is the useful outcome and was not knowable before it
    /// existed.
    ///
    /// The vector is the IETF one, so it also pins the *interoperable* thing:
    /// these bytes are what any other implementation of ChaCha20-Poly1305
    /// produces, which is the property a second reader of a sealed envelope
    /// actually needs.
    #[test]
    fn the_aead_matches_the_rfc_8439_vector() {
        use chacha20poly1305::aead::{Aead, Payload};

        let key = Secret32::new([
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ]);
        let nonce: [u8; NONCE_LEN] = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];
        let aad: [u8; 12] = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let plaintext: &[u8] = b"Ladies and Gentlemen of the class of '99: If I \
could offer you only one tip for the future, sunscreen would be it.";
        // The line continuation above must not smuggle in a newline: the vector
        // is 114 bytes exactly, and a 115-byte plaintext would fail against a
        // ciphertext that is still correct.
        assert_eq!(plaintext.len(), 114, "the RFC plaintext is 114 bytes");

        let sealed = cipher_for(&key)
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .expect("the vector encrypts");

        const EXPECTED: &str = "\
d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36\
92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc\
3ff4def08e4b7a9de576d26586cec64b6116\
1ae10b594f09e26a7e902ecbd0600691";
        assert_eq!(
            hex_encode(&sealed),
            EXPECTED,
            "this crate's ChaCha20-Poly1305 no longer produces the IETF vector, \
             so every sealed envelope and every stored log written by an earlier \
             build is now unreadable"
        );

        // And the tag really is the last sixteen bytes, which is what makes the
        // ciphertext length a function of the plaintext length rather than a
        // detail of the library's framing.
        assert_eq!(sealed.len(), plaintext.len() + 16);
    }

    use super::*;
    use rand_core::OsRng;

    const AAD: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const OTHER_AAD: &str =
        "sha256:2222222222222222222222222222222222222222222222222222222222222222";

    fn committee(n: u8) -> (Vec<CommitteeKey>, Vec<CommitteeMember>) {
        let mut keys = Vec::new();
        let mut members = Vec::new();
        for index in 1..=n {
            let key = CommitteeKey::generate(&mut OsRng);
            members.push(key.member(index));
            keys.push(key);
        }
        (keys, members)
    }

    fn clone_share(share: &Share) -> Share {
        Share {
            index: share.index,
            data: share.data.clone(),
        }
    }

    /// Open every member's share. Mirrors the epoch boundary, where each member
    /// publishes independently.
    fn open_all(keys: &[CommitteeKey], envelope: &SealedEnvelope) -> Vec<Share> {
        keys.iter()
            .enumerate()
            .map(|(i, key)| {
                let index = u8::try_from(i + 1).expect("test committee fits in u8");
                key.open_share(envelope, index)
                    .expect("member opens their own share")
            })
            .collect()
    }

    #[test]
    fn round_trip_with_exactly_threshold_shares() {
        let (keys, members) = committee(5);
        let payload = b"artifact: the answer is 42";
        let envelope =
            SealedEnvelope::seal(payload, AAD, &members, 3, &mut OsRng).expect("seal succeeds");

        let shares = open_all(&keys, &envelope);
        let exactly_three: Vec<Share> = shares.iter().take(3).map(clone_share).collect();
        let opened = envelope
            .open_with_shares(&exactly_three)
            .expect("t shares reconstruct");
        assert_eq!(opened, payload);
    }

    #[test]
    fn round_trip_with_more_than_threshold_shares() {
        let (keys, members) = committee(5);
        let payload = b"artifact with every share published";
        let envelope =
            SealedEnvelope::seal(payload, AAD, &members, 3, &mut OsRng).expect("seal succeeds");

        let shares = open_all(&keys, &envelope);
        assert_eq!(shares.len(), 5);
        let opened = envelope
            .open_with_shares(&shares)
            .expect("n shares reconstruct");
        assert_eq!(opened, payload);

        // Order is not part of the reconstruction.
        let mut reversed: Vec<Share> = shares.iter().rev().map(clone_share).collect();
        reversed.truncate(4);
        assert_eq!(
            envelope
                .open_with_shares(&reversed)
                .expect("order does not matter"),
            payload
        );
    }

    /// The central adversarial case: `t-1` shares must not open the envelope,
    /// must not panic, and must not return anything the caller could mistake for
    /// a plaintext. Shamir cannot report "too few"; only the tag can.
    #[test]
    fn one_share_short_fails_authentication() {
        let (keys, members) = committee(5);
        let envelope = SealedEnvelope::seal(b"secret artifact", AAD, &members, 3, &mut OsRng)
            .expect("seal succeeds");

        let shares = open_all(&keys, &envelope);
        let two: Vec<Share> = shares.iter().take(2).map(clone_share).collect();
        match envelope.open_with_shares(&two) {
            Err(EnvelopeError::Authentication { .. }) => {}
            Err(other) => panic!("expected authentication failure, got {other:?}"),
            Ok(plaintext) => panic!("t-1 shares returned {} bytes", plaintext.len()),
        }
    }

    #[test]
    fn single_share_of_a_three_of_five_fails() {
        let (keys, members) = committee(5);
        let envelope =
            SealedEnvelope::seal(b"x", AAD, &members, 3, &mut OsRng).expect("seal succeeds");
        let shares = open_all(&keys, &envelope);
        let one: Vec<Share> = shares.iter().take(1).map(clone_share).collect();
        assert!(matches!(
            envelope.open_with_shares(&one),
            Err(EnvelopeError::Authentication { .. })
        ));
    }

    #[test]
    fn empty_share_set_is_rejected_without_panicking() {
        let (_keys, members) = committee(3);
        let envelope =
            SealedEnvelope::seal(b"x", AAD, &members, 2, &mut OsRng).expect("seal succeeds");
        assert_eq!(envelope.open_with_shares(&[]), Err(EnvelopeError::NoShares));
    }

    /// An envelope re-labelled with a different commitment must not open, even
    /// with a full share set: the payload AEAD binds `aad`.
    #[test]
    fn rewritten_aad_fails() {
        let (keys, members) = committee(3);
        let envelope =
            SealedEnvelope::seal(b"bound to one commitment", AAD, &members, 2, &mut OsRng)
                .expect("seal succeeds");
        let shares = open_all(&keys, &envelope);

        let mut moved = envelope.clone();
        moved.aad = OTHER_AAD.to_string();
        assert!(matches!(
            moved.open_with_shares(&shares),
            Err(EnvelopeError::Authentication { .. })
        ));
    }

    /// And the share layer binds it too, independently: a member asked to open
    /// their share out of a re-labelled envelope derives a different key.
    #[test]
    fn rewritten_aad_also_breaks_share_opening() {
        let (keys, members) = committee(3);
        let envelope =
            SealedEnvelope::seal(b"payload", AAD, &members, 2, &mut OsRng).expect("seal succeeds");
        let mut moved = envelope.clone();
        moved.aad = OTHER_AAD.to_string();

        let member = keys.first().expect("committee is non-empty");
        assert!(matches!(
            member.open_share(&moved, 1),
            Err(EnvelopeError::Authentication { .. })
        ));
    }

    #[test]
    fn tampered_payload_ciphertext_fails() {
        let (keys, members) = committee(3);
        let envelope = SealedEnvelope::seal(b"do not edit me", AAD, &members, 2, &mut OsRng)
            .expect("seal succeeds");
        let shares = open_all(&keys, &envelope);

        let mut tampered = envelope.clone();
        if let Some(byte) = tampered.ciphertext.first_mut() {
            *byte ^= 0x01;
        }
        assert!(matches!(
            tampered.open_with_shares(&shares),
            Err(EnvelopeError::Authentication { .. })
        ));

        // Truncation is tampering too.
        let mut truncated = envelope.clone();
        truncated.ciphertext.pop();
        assert!(matches!(
            truncated.open_with_shares(&shares),
            Err(EnvelopeError::Authentication { .. })
        ));
    }

    #[test]
    fn tampered_share_ciphertext_fails() {
        let (keys, members) = committee(3);
        let mut envelope =
            SealedEnvelope::seal(b"payload", AAD, &members, 2, &mut OsRng).expect("seal succeeds");
        if let Some(sealed) = envelope.sealed_shares.first_mut() {
            if let Some(byte) = sealed.ciphertext.first_mut() {
                *byte ^= 0xff;
            }
        }
        let member = keys.first().expect("committee is non-empty");
        assert!(matches!(
            member.open_share(&envelope, 1),
            Err(EnvelopeError::Authentication { .. })
        ));
    }

    /// A sealed share lifted out of submission A and dropped into submission B
    /// must not open. This is the replay the KDF transcript exists to stop.
    #[test]
    fn sealed_share_does_not_transplant_between_envelopes() {
        let (keys, members) = committee(3);
        let a = SealedEnvelope::seal(b"artifact A", AAD, &members, 2, &mut OsRng)
            .expect("seal A succeeds");
        let mut b = SealedEnvelope::seal(b"artifact B", OTHER_AAD, &members, 2, &mut OsRng)
            .expect("seal B succeeds");

        let lifted = a
            .sealed_share(1)
            .expect("envelope A has a share for member 1")
            .clone();
        if let Some(slot) = b.sealed_shares.first_mut() {
            *slot = lifted;
        }

        let member = keys.first().expect("committee is non-empty");
        assert!(matches!(
            member.open_share(&b, 1),
            Err(EnvelopeError::Authentication { .. })
        ));
    }

    /// Honest statement of the limit: with an *identical* `aad`, two envelopes
    /// share a share-KDF transcript, so a transplanted share does decrypt. It
    /// yields a share of the wrong content key, and the payload tag catches it.
    /// Since `aad` is the commitment hash, two distinct submissions never
    /// collide here in practice.
    #[test]
    fn transplant_under_identical_aad_is_caught_by_the_payload_tag() {
        let (keys, members) = committee(3);
        let a = SealedEnvelope::seal(b"artifact A", AAD, &members, 2, &mut OsRng)
            .expect("seal A succeeds");
        let mut b =
            SealedEnvelope::seal(b"artifact B", AAD, &members, 2, &mut OsRng).expect("seal B");

        let lifted = a.sealed_share(1).expect("share exists").clone();
        if let Some(slot) = b.sealed_shares.first_mut() {
            *slot = lifted;
        }

        let mut shares = Vec::new();
        for (i, key) in keys.iter().enumerate().take(2) {
            let index = u8::try_from(i + 1).expect("fits");
            shares.push(key.open_share(&b, index).expect("share decrypts"));
        }
        assert!(matches!(
            b.open_with_shares(&shares),
            Err(EnvelopeError::Authentication { .. })
        ));
    }

    #[test]
    fn a_member_cannot_open_another_members_share() {
        let (keys, members) = committee(4);
        let envelope =
            SealedEnvelope::seal(b"payload", AAD, &members, 2, &mut OsRng).expect("seal succeeds");

        let second = keys.get(1).expect("committee has four members");
        assert!(second.open_share(&envelope, 2).is_ok());
        for index in [1u8, 3, 4] {
            assert!(
                matches!(
                    second.open_share(&envelope, index),
                    Err(EnvelopeError::Authentication { .. })
                ),
                "member 2 must not open share {index}"
            );
        }
    }

    #[test]
    fn an_outsider_cannot_open_any_share() {
        let (_keys, members) = committee(3);
        let envelope =
            SealedEnvelope::seal(b"payload", AAD, &members, 2, &mut OsRng).expect("seal succeeds");
        let outsider = CommitteeKey::generate(&mut OsRng);
        for index in 1u8..=3 {
            assert!(matches!(
                outsider.open_share(&envelope, index),
                Err(EnvelopeError::Authentication { .. })
            ));
        }
    }

    #[test]
    fn unknown_share_index_is_reported_not_panicked() {
        let (keys, members) = committee(3);
        let envelope =
            SealedEnvelope::seal(b"payload", AAD, &members, 2, &mut OsRng).expect("seal succeeds");
        let member = keys.first().expect("committee is non-empty");
        assert_eq!(
            member.open_share(&envelope, 99),
            Err(EnvelopeError::UnknownShare { index: 99 })
        );
    }

    /// Re-addressing a sealed share to a different routing index must fail: the
    /// index is inside the KDF transcript.
    #[test]
    fn relabelled_share_index_fails() {
        let (keys, members) = committee(3);
        let mut envelope =
            SealedEnvelope::seal(b"payload", AAD, &members, 2, &mut OsRng).expect("seal succeeds");
        if let Some(sealed) = envelope.sealed_shares.first_mut() {
            sealed.index = 2;
        }
        let second = keys.get(1).expect("committee has three members");
        assert!(matches!(
            second.open_share(&envelope, 2),
            Err(EnvelopeError::Authentication { .. })
        ));
    }

    /// The §2 liveness fallback: a committee that never publishes its shares
    /// must not be able to destroy a submission.
    #[test]
    fn submitter_can_reveal_without_the_committee() {
        let (_keys, members) = committee(5);
        let payload = b"artifact the committee refuses to unseal";
        let (envelope, key) =
            SealedEnvelope::seal_retaining_key(payload, AAD, &members, 4, &mut OsRng)
                .expect("seal succeeds");

        assert_eq!(
            envelope
                .open_with_content_key(&key)
                .expect("submitter opens"),
            payload.to_vec()
        );

        let wrong = Secret32::random(&mut OsRng);
        assert!(matches!(
            envelope.open_with_content_key(&wrong),
            Err(EnvelopeError::Authentication { .. })
        ));
    }

    /// The retained key is still bound to the commitment: it cannot be used to
    /// open the same artifact re-labelled as somebody else's submission.
    #[test]
    fn retained_key_does_not_unbind_the_envelope() {
        let (_keys, members) = committee(3);
        let (envelope, key) =
            SealedEnvelope::seal_retaining_key(b"artifact", AAD, &members, 2, &mut OsRng)
                .expect("seal succeeds");
        let mut moved = envelope.clone();
        moved.aad = OTHER_AAD.to_string();
        assert!(matches!(
            moved.open_with_content_key(&key),
            Err(EnvelopeError::Authentication { .. })
        ));
    }

    /// Both reveal paths must agree; otherwise the fallback would settle a
    /// different artifact than the committee-driven reveal.
    #[test]
    fn both_reveal_paths_yield_the_same_plaintext() {
        let (keys, members) = committee(4);
        let payload = b"one artifact, two ways in";
        let (envelope, key) =
            SealedEnvelope::seal_retaining_key(payload, AAD, &members, 2, &mut OsRng)
                .expect("seal succeeds");
        let shares = open_all(&keys, &envelope);
        assert_eq!(
            envelope.open_with_shares(&shares).expect("committee opens"),
            envelope
                .open_with_content_key(&key)
                .expect("submitter opens")
        );
    }

    #[test]
    fn seal_rejects_bad_committees() {
        let (_keys, members) = committee(3);
        assert_eq!(
            SealedEnvelope::seal(b"x", AAD, &[], 1, &mut OsRng),
            Err(EnvelopeError::EmptyCommittee)
        );
        assert_eq!(
            SealedEnvelope::seal(b"x", AAD, &members, 0, &mut OsRng),
            Err(EnvelopeError::InvalidThreshold {
                threshold: 0,
                committee: 3
            })
        );
        assert_eq!(
            SealedEnvelope::seal(b"x", AAD, &members, 4, &mut OsRng),
            Err(EnvelopeError::InvalidThreshold {
                threshold: 4,
                committee: 3
            })
        );

        let mut duplicate_index = members.clone();
        if let Some(m) = duplicate_index.get_mut(1) {
            m.index = 1;
        }
        assert_eq!(
            SealedEnvelope::seal(b"x", AAD, &duplicate_index, 2, &mut OsRng),
            Err(EnvelopeError::DuplicateMemberIndex { index: 1 })
        );

        let mut duplicate_key = members.clone();
        let first_key = members.first().expect("non-empty").keys.clone();
        if let Some(m) = duplicate_key.get_mut(2) {
            m.keys = first_key;
        }
        assert_eq!(
            SealedEnvelope::seal(b"x", AAD, &duplicate_key, 2, &mut OsRng),
            Err(EnvelopeError::DuplicateMemberKey { index: 3 })
        );
    }

    /// The replacement for `low_order_member_key_is_rejected`, and the threat
    /// model changed rather than the test.
    ///
    /// Under X25519 a member could plant a low-order public key and make *their
    /// own* share readable by every observer, which lowered the effective
    /// threshold and had to be refused. A KEM has no such key: every bit string
    /// of the right length is *a* public key, and encapsulating to a random one
    /// produces a secret nobody holds -- the planter least of all.
    ///
    /// So a garbage key costs the member their own share and costs the scheme
    /// nothing, which is a liveness fault absorbed by `n - t` and not an attack.
    /// This test pins both halves of that claim.
    #[test]
    fn a_garbage_member_key_costs_only_that_member_their_share() {
        let (keys, mut members) = committee(3);
        let honest = members.clone();

        // The second member publishes a bundle whose *McEliece* leg is a blob
        // of the right length corresponding to no secret at all, keeping their
        // real ML-KEM and HQC legs. That is the sharpest version of the attack:
        // the planter still holds two of the three secrets and still cannot
        // derive the combined key, because the combiner absorbs all three.
        let mut junk = vec![0u8; Suite::McEliece.public_key_len()];
        OsRng.fill_bytes(&mut junk);
        let junk = crate::crypto::kem::PublicKey::from_bytes(Suite::McEliece, &junk)
            .expect("right length");
        let mut planted: Vec<_> = members[1]
            .keys
            .keys()
            .iter()
            .filter(|key| key.suite() != Suite::McEliece)
            .cloned()
            .collect();
        planted.push(junk);
        members[1].keys = Bundle::new(planted).expect("mandatory leg replaced, not removed");

        // Sealing still succeeds: there is nothing to refuse.
        let envelope =
            SealedEnvelope::seal(b"secret", AAD, &members, 2, &mut OsRng).expect("seals");

        // The planter cannot open their own share.
        let planted = keys[1].open_share(&envelope, members[1].index);
        assert!(
            matches!(planted, Err(EnvelopeError::Authentication { .. })),
            "got {planted:?}"
        );

        // And the other two still reach the threshold, so the submission opens.
        let shares: Vec<Share> = [0usize, 2]
            .into_iter()
            .map(|i| {
                keys[i]
                    .open_share(&envelope, honest[i].index)
                    .expect("honest member opens")
            })
            .collect();
        assert_eq!(
            envelope.open_with_shares(&shares).expect("opens"),
            b"secret".to_vec()
        );
    }

    #[test]
    fn value_round_trip_is_exact() {
        let (_keys, members) = committee(4);
        let envelope = SealedEnvelope::seal(b"round trip me", AAD, &members, 3, &mut OsRng)
            .expect("seal succeeds");
        let value = envelope.to_value();
        let decoded = SealedEnvelope::from_value(&value).expect("decodes");
        assert_eq!(decoded, envelope);
        assert_eq!(decoded.to_value(), value);
        assert_eq!(decoded.digest(), envelope.digest());
    }

    #[test]
    fn round_trip_survives_json_text() {
        let (keys, members) = committee(3);
        let payload = b"artifact carried as JSON";
        let envelope =
            SealedEnvelope::seal(payload, AAD, &members, 2, &mut OsRng).expect("seal succeeds");
        let text = envelope.to_value().canonical_string();
        let parsed = Value::from_json(&text).expect("canonical output re-parses");
        let decoded = SealedEnvelope::from_value(&parsed).expect("decodes");

        let shares = open_all(&keys, &decoded);
        assert_eq!(
            decoded.open_with_shares(&shares).expect("opens"),
            payload.to_vec()
        );
    }

    #[test]
    fn digest_changes_with_any_field() {
        let (_keys, members) = committee(3);
        let envelope =
            SealedEnvelope::seal(b"payload", AAD, &members, 2, &mut OsRng).expect("seal succeeds");
        let baseline = envelope.digest();

        let mut moved = envelope.clone();
        moved.aad = OTHER_AAD.to_string();
        assert_ne!(moved.digest(), baseline);

        let mut retimed = envelope.clone();
        retimed.threshold = 3;
        assert_ne!(retimed.digest(), baseline);
    }

    #[test]
    fn decoder_rejects_malformed_values() {
        let (_keys, members) = committee(3);
        let envelope =
            SealedEnvelope::seal(b"payload", AAD, &members, 2, &mut OsRng).expect("seal succeeds");
        let good = envelope.to_value();

        assert_eq!(
            SealedEnvelope::from_value(&Value::Int(1)),
            Err(EnvelopeError::NotAnObject)
        );

        let rebuild = |mutate: &dyn Fn(&mut std::collections::BTreeMap<String, Value>)| {
            let mut map = good
                .as_object()
                .expect("envelope encodes to an object")
                .clone();
            mutate(&mut map);
            SealedEnvelope::from_value(&Value::Object(map))
        };

        assert_eq!(
            rebuild(&|m| {
                m.remove("nonce");
            }),
            Err(EnvelopeError::MissingField { field: "nonce" })
        );
        // Both directions. `3` is a version this build predates; `1` is the
        // X25519 envelope, whose shares are sealed to a scheme this build no
        // longer speaks -- refused outright rather than partially read, because
        // half-decoding it would produce shares nothing can open and an error
        // pointing at the wrong layer.
        for version in [1, 3] {
            assert_eq!(
                rebuild(&|m| {
                    m.insert("version".into(), Value::Int(version));
                }),
                Err(EnvelopeError::UnsupportedVersion { version })
            );
        }
        assert_eq!(
            rebuild(&|m| {
                m.insert("type".into(), Value::string("commitment"));
            }),
            Err(EnvelopeError::InvalidField {
                field: "type",
                expected: "\"sealed_envelope\""
            })
        );
        assert_eq!(
            rebuild(&|m| {
                m.insert("nonce".into(), Value::string("00112233"));
            }),
            Err(EnvelopeError::WrongLength {
                field: "nonce",
                expected: NONCE_LEN,
                actual: 4
            })
        );
        assert_eq!(
            rebuild(&|m| {
                m.insert("threshold".into(), Value::Int(9));
            }),
            Err(EnvelopeError::InvalidThreshold {
                threshold: 9,
                committee: 3
            })
        );
        assert_eq!(
            rebuild(&|m| {
                m.insert("threshold".into(), Value::Int(300));
            }),
            Err(EnvelopeError::InvalidField {
                field: "threshold",
                expected: "an integer in 0..=255"
            })
        );
        assert_eq!(
            rebuild(&|m| {
                m.insert("sealed_shares".into(), Value::array([]));
            }),
            Err(EnvelopeError::EmptyCommittee)
        );

        // Duplicate routing indexes would make `sealed_share` ambiguous.
        let duplicated = {
            let mut map = good
                .as_object()
                .expect("envelope encodes to an object")
                .clone();
            let first = envelope
                .sealed_shares
                .first()
                .expect("non-empty")
                .to_value();
            map.insert("sealed_shares".into(), Value::array([first.clone(), first]));
            SealedEnvelope::from_value(&Value::Object(map))
        };
        assert_eq!(
            duplicated,
            Err(EnvelopeError::DuplicateShareIndex { index: 1 })
        );
    }

    #[test]
    fn hex_is_strict_and_lowercase() {
        assert_eq!(hex_encode(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
        assert_eq!(
            hex_decode("000fa5ff", "x").expect("decodes"),
            vec![0x00, 0x0f, 0xa5, 0xff]
        );
        // Uppercase would give one envelope two spellings and two digests.
        assert_eq!(
            hex_decode("00FF", "x"),
            Err(EnvelopeError::InvalidHex { field: "x" })
        );
        assert_eq!(
            hex_decode("abc", "x"),
            Err(EnvelopeError::InvalidHex { field: "x" })
        );
        assert_eq!(
            hex_decode("zz", "x"),
            Err(EnvelopeError::InvalidHex { field: "x" })
        );
        assert_eq!(
            hex_decode("", "x").expect("empty is empty"),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn debug_never_prints_secret_material() {
        let key = CommitteeKey::generate(&mut OsRng);
        let rendered = format!("{key:?}");
        for secret in key.secrets().keys() {
            let secret_hex = hex_encode(secret.expose());
            assert!(
                !rendered.contains(&secret_hex),
                "CommitteeKey Debug leaked a {} secret",
                secret.suite()
            );
        }
        assert!(rendered.contains("<redacted>"));

        let exported = Secret32::new([7u8; KEY_LEN]);
        let rendered = format!("{exported:?}");
        assert!(
            !rendered.contains(&hex_encode(exported.expose())),
            "Secret32 Debug leaked"
        );
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn stored_key_round_trips() {
        let key = CommitteeKey::generate(&mut OsRng);
        let restored = CommitteeKey::from_value(&key.to_value()).expect("restores");
        assert_eq!(restored.public(), key.public());
        assert_eq!(restored.id(), key.id());

        // And the restored key still opens a share sealed to the original, which
        // is the property a round trip of the *encoding* alone would not catch.
        let members = [key.member(1)];
        let envelope =
            SealedEnvelope::seal(b"still mine", AAD, &members, 1, &mut OsRng).expect("seals");
        let share = restored.open_share(&envelope, 1).expect("opens");
        assert_eq!(
            envelope.open_with_shares(&[share]).expect("opens"),
            b"still mine".to_vec()
        );
    }

    #[test]
    fn empty_payload_seals_and_opens() {
        let (keys, members) = committee(3);
        let envelope =
            SealedEnvelope::seal(b"", AAD, &members, 2, &mut OsRng).expect("seal succeeds");
        let shares = open_all(&keys, &envelope);
        assert_eq!(
            envelope.open_with_shares(&shares).expect("opens"),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn one_of_one_committee_works() {
        let (keys, members) = committee(1);
        let envelope = SealedEnvelope::seal(b"single custodian", AAD, &members, 1, &mut OsRng)
            .expect("seal succeeds");
        let shares = open_all(&keys, &envelope);
        assert_eq!(
            envelope.open_with_shares(&shares).expect("opens"),
            b"single custodian".to_vec()
        );
    }

    #[test]
    fn two_seals_of_one_payload_differ() {
        // Envelopes are randomized, so an observer cannot tell two submissions
        // carry the same artifact by comparing ciphertexts.
        let (_keys, members) = committee(3);
        let a = SealedEnvelope::seal(b"same artifact", AAD, &members, 2, &mut OsRng)
            .expect("seal succeeds");
        let b = SealedEnvelope::seal(b"same artifact", AAD, &members, 2, &mut OsRng)
            .expect("seal succeeds");
        assert_ne!(a.ciphertext(), b.ciphertext());
        assert_ne!(a.digest(), b.digest());
    }
}
