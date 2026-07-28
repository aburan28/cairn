//! Sealed submissions: commit once, and be paid even if you are never heard from
//! again.
//!
//! This is the submission-level flow of `docs/censorship.md` §2, assembled from
//! the primitives in [`crate::crypto`]. The module it exists to fix is §1:
//!
//! > Commit–reveal requires **the submitter to act twice**: commit, then reveal.
//! > An adversary who cannot forge or steal your work can still take it from you
//! > by stopping the second action — a targeted DoS, a network block, a
//! > detention, a seized laptop, or a sequencer that drops your reveal until the
//! > deadline passes.
//!
//! A [`SealedSubmission`] carries the artifact encrypted at commit time, with the
//! content key split across a threshold committee. At the epoch boundary `t`
//! members publish their shares and **anyone** calls [`open`]. The submitter is
//! not a participant in that sentence, which is the entire point: they can be
//! offline, jailed, or firewalled and still collect.
//!
//! # The nonce lives inside the envelope, and that is load bearing
//!
//! The commitment is `H(artifact ‖ submitter ‖ nonce)`. A reveal performed by the
//! committee has no way to learn the nonce unless it travels with the artifact,
//! so the sealed payload is an object carrying **both**:
//!
//! ```text
//! payload = canonical_bytes({"artifact": <artifact>, "nonce": "<nonce>"})
//! ```
//!
//! Sealing only the artifact would produce a submission that opens to a plaintext
//! nobody can check against the commitment — a mechanism that fails precisely
//! when it is needed, when the submitter is gone. The nonce is also a secret
//! before the reveal (it is what stops a guessable artifact such as `{"n": 42}`
//! being brute-forced out of the commitment), so inside the AEAD is where it
//! belongs on both counts.
//!
//! # Binding is the safety argument, and it is free
//!
//! Nothing here asks anyone to trust the submitter. The commitment is already a
//! hash of the plaintext, so [`open`] re-derives it from what actually came out of
//! the envelope and refuses a mismatch ([`SealedError::CommitmentMismatch`]). A
//! submitter who seals garbage, or seals something other than what they committed
//! to, is caught at the epoch boundary by arithmetic that costs one SHA-256. That
//! check is mandatory and has no opt-out; without it a sealed submission would be
//! an unverifiable claim about a ciphertext.
//!
//! The commitment is also the envelope's AEAD associated data, so neither the
//! payload ciphertext nor an individual sealed share can be lifted into another
//! submission ([`SealedError::EnvelopeNotBound`] and the tag failure behind it).
//!
//! # Sealing moves *when*, never *whether*
//!
//! proofwork's guarantee is that anyone can independently re-derive every settled
//! result. Once [`open`] returns, the artifact is public and anyone re-runs the
//! pinned verifier exactly as they would have in the plain flow — same artifact,
//! same commitment, same verdict path. This module changes the moment an artifact
//! becomes public. It never changes whether it becomes public, and a class that
//! did (`sealed`, §6) would need zero-knowledge verification, which is not this.
//!
//! # What is deliberately not checked here
//!
//! `submitter` is an opaque string. It is normally a pseudonym id — lowercase hex
//! of an ed25519 public key, from [`crate::crypto::identity::Identity::submitter_id`]
//! — but this module does not enforce that, because [`crate::records::commitment_hash`]
//! does not: a sealed path that refused submitter ids the plain path accepts would
//! be a second, divergent notion of a valid submission. Whether a given pseudonym
//! may submit is an authorization question for the record layer.

use core::fmt;
use core::str;

use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::canonical::{CanonicalError, Value};
use crate::crypto::envelope::{CommitteeMember, EnvelopeError, SealedEnvelope};
use crate::crypto::shamir::Share;
use crate::obj;
use crate::records::commitment_hash;

/// Wire type tag, so a decoder cannot mistake some other object with the same
/// field names for a submission.
const RECORD_TYPE: &str = "sealed_submission";

/// Wire version. Bumped only when the *interpretation* of the bytes changes —
/// including any change to the sealed payload's shape, which is not
/// self-describing and cannot be sniffed. An unknown version is refused.
const VERSION: i128 = 1;

/// The two, and only two, keys of the sealed payload.
const PAYLOAD_ARTIFACT: &str = "artifact";
const PAYLOAD_NONCE: &str = "nonce";

// -- errors ----------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealedError {
    /// The artifact is not an object. Same rule as [`crate::records::Claim`]:
    /// a verifier reads named fields rather than guessing at a bare scalar, and
    /// a sealed submission that could never become a valid claim is worth
    /// refusing before it is written to the log rather than after it is opened.
    ArtifactNotAnObject,
    /// The envelope layer failed: sealing, or an AEAD tag that did not verify.
    ///
    /// On the open path this is the *only* signal that the share set was wrong.
    /// Shamir cannot report "too few shares" — any `t-1` shares reconstruct a
    /// well-formed wrong key, which is the information-theoretic security
    /// property — so too few shares, forged shares, shares from another envelope
    /// and a tampered ciphertext all arrive here as
    /// [`EnvelopeError::Authentication`] and none can be told apart.
    Envelope(EnvelopeError),
    /// The envelope's associated data is not this submission's commitment, so
    /// the envelope was built for a different submission.
    ///
    /// The AEAD alone would not catch this: the associated data travels *with*
    /// the envelope, so an envelope moved wholesale into another submission still
    /// authenticates against its own `aad`. Comparing it to the commitment is
    /// what turns "this ciphertext is intact" into "this ciphertext is mine".
    EnvelopeNotBound { commitment: String, aad: String },
    /// The decrypted payload is not UTF-8, so it is not canonical JSON.
    PayloadNotUtf8,
    /// The decrypted payload parses, but is not the canonical encoding of what it
    /// parsed to.
    ///
    /// Refused so the payload has exactly one byte encoding. Two encodings of one
    /// payload is how two honest implementations end up disagreeing about a
    /// submission — the failure `canonical.rs` exists to prevent — and it is also
    /// where duplicate keys hide, whose resolution is a parser's choice rather
    /// than a specified one.
    PayloadNotCanonical,
    /// The decrypted payload is not valid JSON, or carries a float.
    Canonical(CanonicalError),
    /// The decrypted payload is not an object.
    PayloadNotAnObject,
    /// The decrypted payload is missing `artifact` or `nonce`. A payload without
    /// the nonce cannot be checked against the commitment by anyone but the
    /// submitter, which is the failure this whole module exists to remove.
    MissingPayloadField { field: &'static str },
    /// A payload field is present with the wrong shape.
    InvalidPayloadField {
        field: &'static str,
        expected: &'static str,
    },
    /// The payload carries a key beyond `artifact` and `nonce`.
    ///
    /// Refused because the commitment binds the artifact and the nonce and
    /// nothing else: any additional key is content that arrives with the
    /// authority of a sealed submission while being covered by no commitment at
    /// all. There is no legitimate use for that, and there is an obvious
    /// illegitimate one.
    UnexpectedPayloadField { field: String },
    /// **The submitter sealed something other than what they committed to.**
    ///
    /// The submission is invalid and, per `docs/censorship.md` §2, its bond is
    /// slashable. This is the check that makes the scheme safe without trusting
    /// the submitter; see the module docs.
    CommitmentMismatch { committed: String, sealed: String },
    /// Decoding: the value is not an object.
    NotAnObject,
    /// Decoding: a required field is absent.
    MissingField { field: &'static str },
    /// Decoding: a field is present with the wrong shape.
    InvalidField {
        field: &'static str,
        expected: &'static str,
    },
    /// Decoding: a version this build cannot interpret.
    UnsupportedVersion { version: i128 },
}

impl fmt::Display for SealedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SealedError::ArtifactNotAnObject => {
                f.write_str("sealed submission: artifact must be an object")
            }
            SealedError::Envelope(e) => write!(f, "sealed submission: {e}"),
            SealedError::EnvelopeNotBound { commitment, aad } => write!(
                f,
                "sealed submission: envelope is bound to {aad:?}, not to this \
                 submission's commitment {commitment:?}"
            ),
            SealedError::PayloadNotUtf8 => {
                f.write_str("sealed submission: decrypted payload is not UTF-8")
            }
            SealedError::PayloadNotCanonical => f.write_str(
                "sealed submission: decrypted payload is not the canonical encoding of its \
                 own contents",
            ),
            SealedError::Canonical(e) => write!(f, "sealed submission payload: {e}"),
            SealedError::PayloadNotAnObject => {
                f.write_str("sealed submission: decrypted payload must be an object")
            }
            SealedError::MissingPayloadField { field } => write!(
                f,
                "sealed submission: decrypted payload is missing {field:?}"
            ),
            SealedError::InvalidPayloadField { field, expected } => write!(
                f,
                "sealed submission: payload field {field:?} must be {expected}"
            ),
            SealedError::UnexpectedPayloadField { field } => write!(
                f,
                "sealed submission: payload carries {field:?}, which no commitment covers"
            ),
            SealedError::CommitmentMismatch { committed, sealed } => write!(
                f,
                "sealed submission: opened artifact commits to {sealed}, but the submission \
                 committed to {committed}; the submitter sealed something other than what \
                 they committed to"
            ),
            SealedError::NotAnObject => f.write_str("sealed submission must be an object"),
            SealedError::MissingField { field } => {
                write!(f, "sealed submission: missing required field {field:?}")
            }
            SealedError::InvalidField { field, expected } => {
                write!(f, "sealed submission: field {field:?} must be {expected}")
            }
            SealedError::UnsupportedVersion { version } => {
                write!(f, "unsupported sealed submission version {version}")
            }
        }
    }
}

impl std::error::Error for SealedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SealedError::Envelope(e) => Some(e),
            SealedError::Canonical(e) => Some(e),
            _ => None,
        }
    }
}

impl From<EnvelopeError> for SealedError {
    fn from(e: EnvelopeError) -> SealedError {
        SealedError::Envelope(e)
    }
}

impl From<CanonicalError> for SealedError {
    fn from(e: CanonicalError) -> SealedError {
        SealedError::Canonical(e)
    }
}

// -- submission ------------------------------------------------------------

/// An artifact committed to and sealed to a threshold committee in one action.
///
/// Every field is public: a commitment hash, a ciphertext, and metadata the log
/// needs anyway. `Debug` and `Clone` therefore leak nothing, and the secrets
/// (content key, Shamir shares, the nonce) are either inside the envelope or
/// already dropped by the time this value exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedSubmission {
    pub objective_id: String,
    /// Pseudonym id: lowercase hex of an ed25519 public key. Opaque here — see
    /// the module docs on why it is not validated.
    pub submitter: String,
    /// Byte-identical to the plain flow's [`crate::records::commitment_hash`] for
    /// the same `(objective_id, submitter, artifact, nonce)`. The two paths must
    /// produce one commitment or they are two systems.
    pub commitment: String,
    /// The artifact and its nonce, sealed to the committee.
    pub envelope: SealedEnvelope,
    /// The epoch at whose boundary the committee is expected to publish shares.
    pub epoch: u64,
    pub created_at: String,
}

impl SealedSubmission {
    /// Seal an artifact so it can be opened **without the submitter**.
    ///
    /// Nothing is required of the caller after this returns. That is the whole
    /// design: the second action plain commit–reveal demands is what a censor
    /// attacks (`docs/censorship.md` §1), so there is no second action.
    ///
    /// `nonce` should be freshly random per submission and is a **secret until
    /// the reveal**. Reusing one across submissions, or deriving it from
    /// something guessable, hands an early reader the ability to confirm a
    /// guessed artifact against the public commitment.
    ///
    /// `threshold` is `t` in `t`-of-`n`: how many committee members must publish
    /// shares for the artifact to open, where `n` is `committee.len()`. Both ends
    /// are a policy choice with teeth — a low `t` cheapens collusion and early
    /// front-running, a high `t` makes a stalled reveal more likely (§2) — and
    /// this module deliberately does not pick for the caller.
    ///
    /// The RNG must be cryptographic. A predictable one makes the content key
    /// predictable and the Shamir coefficients recoverable, and nothing
    /// downstream can detect either.
    #[allow(clippy::too_many_arguments)] // every argument is a distinct fact of
                                         // the submission; bundling them into a
                                         // struct would only move the list.
    pub fn seal<R: RngCore + CryptoRng>(
        objective_id: &str,
        submitter: &str,
        artifact: &Value,
        nonce: &str,
        epoch: u64,
        created_at: &str,
        committee: &[CommitteeMember],
        threshold: u8,
        rng: &mut R,
    ) -> Result<SealedSubmission, SealedError> {
        if artifact.as_object().is_none() {
            return Err(SealedError::ArtifactNotAnObject);
        }

        // Computed over the plaintext, exactly as the plain flow does. Sealing
        // adds a ciphertext beside the commitment; it does not change what is
        // committed to.
        let commitment = commitment_hash(objective_id, submitter, artifact, nonce);

        let payload = payload_bytes(artifact, nonce);
        // `commitment` as associated data binds this ciphertext, and every
        // sealed share's key derivation, to this submission.
        let envelope =
            SealedEnvelope::seal(payload.as_slice(), &commitment, committee, threshold, rng)?;

        Ok(SealedSubmission {
            objective_id: objective_id.to_string(),
            submitter: submitter.to_string(),
            commitment,
            envelope,
            epoch,
            created_at: created_at.to_string(),
        })
    }

    /// Content address of the submission as it appears on the wire.
    ///
    /// Over the canonical encoding, so it covers the envelope's exact bytes. Two
    /// nodes holding the same submission agree on this id; it identifies the
    /// *record*, while [`SealedSubmission::commitment`] identifies the plaintext.
    pub fn id(&self) -> String {
        self.to_value().digest()
    }

    pub fn to_value(&self) -> Value {
        Value::object([
            ("type", Value::string(RECORD_TYPE)),
            ("version", Value::Int(VERSION)),
            ("objective_id", Value::string(self.objective_id.clone())),
            ("submitter", Value::string(self.submitter.clone())),
            ("commitment", Value::string(self.commitment.clone())),
            ("envelope", self.envelope.to_value()),
            ("epoch", Value::Int(i128::from(self.epoch))),
            ("created_at", Value::string(self.created_at.clone())),
        ])
    }

    /// Decode a submission from a log payload.
    ///
    /// The envelope-to-commitment binding is checked here as well as in [`open`].
    /// Rejecting an unbound submission at the boundary means the rest of the
    /// system never holds a `SealedSubmission` whose envelope belongs to someone
    /// else; the check in `open` stays because a value can also be built by hand
    /// through the public fields, and a security check that only runs on the
    /// decode path is a security check with a bypass.
    pub fn from_value(value: &Value) -> Result<SealedSubmission, SealedError> {
        if value.as_object().is_none() {
            return Err(SealedError::NotAnObject);
        }
        match value.get("type") {
            None => return Err(SealedError::MissingField { field: "type" }),
            Some(Value::String(tag)) if tag.as_str() == RECORD_TYPE => {}
            Some(_) => {
                return Err(SealedError::InvalidField {
                    field: "type",
                    expected: "\"sealed_submission\"",
                })
            }
        }

        let version = value
            .get("version")
            .ok_or(SealedError::MissingField { field: "version" })?
            .as_i128()
            .ok_or(SealedError::InvalidField {
                field: "version",
                expected: "an integer",
            })?;
        if version != VERSION {
            return Err(SealedError::UnsupportedVersion { version });
        }

        let epoch = value
            .get("epoch")
            .ok_or(SealedError::MissingField { field: "epoch" })?
            .as_u64()
            .ok_or(SealedError::InvalidField {
                field: "epoch",
                expected: "an integer in 0..2^64",
            })?;

        let envelope = SealedEnvelope::from_value(
            value
                .get("envelope")
                .ok_or(SealedError::MissingField { field: "envelope" })?,
        )?;

        let submission = SealedSubmission {
            objective_id: field_string(value, "objective_id")?,
            submitter: field_string(value, "submitter")?,
            commitment: field_string(value, "commitment")?,
            envelope,
            epoch,
            created_at: field_string(value, "created_at")?,
        };
        submission.check_envelope_bound()?;
        Ok(submission)
    }

    /// The envelope must be sealed to *this* submission's commitment.
    fn check_envelope_bound(&self) -> Result<(), SealedError> {
        if self.envelope.aad() != self.commitment {
            return Err(SealedError::EnvelopeNotBound {
                commitment: self.commitment.clone(),
                aad: self.envelope.aad().to_string(),
            });
        }
        Ok(())
    }
}

/// What came out of a sealed submission, after the binding was checked.
///
/// Both fields are public from this moment on — the nonce appears in the
/// revealed claim, and the artifact is what anyone re-runs the verifier over.
/// There is nothing here to zeroize; that is the point of a reveal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedSubmission {
    pub artifact: Value,
    pub nonce: String,
}

/// Open a sealed submission from committee shares and **check the binding**.
///
/// Note what this function does not take: the submitter, any key of theirs, or
/// any action by them. The signature is the guarantee — a submitter who is
/// offline, jailed, or firewalled changes nothing about whether this call
/// succeeds (`docs/censorship.md` §2).
///
/// Four checks stand between a ciphertext and an accepted artifact, and the
/// order matters:
///
/// 1. the envelope is bound to this submission's commitment;
/// 2. the AEAD tag verifies, which is also the only evidence that enough correct
///    shares were supplied;
/// 3. the payload is exactly `{artifact, nonce}` in canonical form;
/// 4. **the commitment recomputed from the opened artifact, the opened nonce and
///    this submission's `objective_id` and `submitter` equals the commitment on
///    the log.**
///
/// Check 4 is what makes the scheme safe without trusting the submitter, and it
/// costs one SHA-256 because the commitment already binds the plaintext. It is
/// not optional and there is no variant of this function that skips it. A
/// failure means the submission is invalid — not that the committee erred — and
/// per §2 the submitter's bond is slashable.
///
/// Any `t` shares work and order is irrelevant. Fewer than `t` fail at check 2
/// with [`EnvelopeError::Authentication`], never with a "too few shares" error,
/// because Shamir cannot distinguish a short share set from a wrong one without
/// leaking information to a sub-threshold set.
pub fn open(
    submission: &SealedSubmission,
    shares: &[Share],
) -> Result<OpenedSubmission, SealedError> {
    submission.check_envelope_bound()?;

    // Wiped after parsing. The artifact is destined to be public, but this
    // buffer also holds the nonce, and an `embargoed` objective (§6) opens long
    // before its contents are meant to be readable. Cheap hygiene, not a
    // security claim: the parsed `Value` below carries the same bytes and is not
    // wiped, because it is the thing being published.
    let payload = Zeroizing::new(submission.envelope.open_with_shares(shares)?);

    let text = str::from_utf8(payload.as_slice()).map_err(|_| SealedError::PayloadNotUtf8)?;
    let parsed = Value::from_json(text)?;
    if parsed.canonical_bytes().as_slice() != payload.as_slice() {
        return Err(SealedError::PayloadNotCanonical);
    }

    let fields = parsed.as_object().ok_or(SealedError::PayloadNotAnObject)?;
    for key in fields.keys() {
        if key != PAYLOAD_ARTIFACT && key != PAYLOAD_NONCE {
            return Err(SealedError::UnexpectedPayloadField { field: key.clone() });
        }
    }

    let artifact = fields
        .get(PAYLOAD_ARTIFACT)
        .ok_or(SealedError::MissingPayloadField {
            field: PAYLOAD_ARTIFACT,
        })?
        .clone();
    let nonce = match fields.get(PAYLOAD_NONCE) {
        None => {
            return Err(SealedError::MissingPayloadField {
                field: PAYLOAD_NONCE,
            })
        }
        Some(Value::String(nonce)) => nonce.clone(),
        Some(_) => {
            return Err(SealedError::InvalidPayloadField {
                field: PAYLOAD_NONCE,
                expected: "a string",
            })
        }
    };

    // The binding check. `objective_id` and `submitter` come from the submission
    // on the log, so a mismatch also catches an envelope replayed under another
    // objective or another name -- all four inputs are covered by the one
    // comparison. Both sides are public digests, so a plain (non-constant-time)
    // comparison leaks nothing an observer does not already have.
    let recomputed = commitment_hash(
        &submission.objective_id,
        &submission.submitter,
        &artifact,
        &nonce,
    );
    if recomputed != submission.commitment {
        return Err(SealedError::CommitmentMismatch {
            committed: submission.commitment.clone(),
            sealed: recomputed,
        });
    }

    // Checked after the binding, so an invalid-shape artifact is reported as the
    // shape problem it is rather than being masked by a mismatch it did not
    // cause. Same rule the plain flow applies in `Claim::validate`.
    if artifact.as_object().is_none() {
        return Err(SealedError::ArtifactNotAnObject);
    }

    Ok(OpenedSubmission { artifact, nonce })
}

// -- internals -------------------------------------------------------------

/// The sealed payload: the artifact and the nonce that binds it.
///
/// Self-wiping because before the reveal the nonce is a secret — it is what
/// stops a guessable artifact being brute-forced out of the public commitment.
/// Honest limits: the caller's `nonce: &str` and the intermediate [`Value`] are
/// not wiped by this function and cannot be, since neither is owned here.
fn payload_bytes(artifact: &Value, nonce: &str) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(
        obj! {
            PAYLOAD_ARTIFACT => artifact.clone(),
            PAYLOAD_NONCE => Value::string(nonce),
        }
        .canonical_bytes(),
    )
}

fn field_string(value: &Value, field: &'static str) -> Result<String, SealedError> {
    match value.get(field) {
        None => Err(SealedError::MissingField { field }),
        Some(Value::String(text)) => Ok(text.clone()),
        Some(_) => Err(SealedError::InvalidField {
            field,
            expected: "a string",
        }),
    }
}

// -- tests -----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::digest_bytes;
    use crate::crypto::envelope::CommitteeKey;
    use crate::crypto::identity::Identity;
    use rand_core::OsRng;

    const OBJECTIVE: &str =
        "sha256:36dc4eb23ddd295b12608a6d84e2b03b48d437ce278105f93143215d260bb711";
    const SUBMITTER: &str = "alice";
    const NONCE: &str = "n1";
    const CREATED: &str = "2026-07-28T00:00:00+00:00";
    const EPOCH: u64 = 7;

    fn artifact() -> Value {
        obj! { "n" => Value::Int(42) }
    }

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

    /// Every member opens their own share, as they would at the epoch boundary.
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

    fn seal_default(members: &[CommitteeMember]) -> SealedSubmission {
        SealedSubmission::seal(
            OBJECTIVE,
            SUBMITTER,
            &artifact(),
            NONCE,
            EPOCH,
            CREATED,
            members,
            3,
            &mut OsRng,
        )
        .expect("seal succeeds")
    }

    // -- happy path --------------------------------------------------------

    #[test]
    fn threshold_shares_recover_the_exact_artifact_and_nonce() {
        let (keys, members) = committee(5);
        let submission = seal_default(&members);

        let shares = open_all(&keys, &submission.envelope);
        let exactly_three: Vec<Share> = shares.iter().take(3).map(clone_share).collect();
        let opened = open(&submission, &exactly_three).expect("t shares open the submission");

        assert_eq!(opened.artifact, artifact());
        assert_eq!(opened.nonce, NONCE);
        // And the recomputed commitment is the one on the log.
        assert_eq!(
            commitment_hash(OBJECTIVE, SUBMITTER, &opened.artifact, &opened.nonce),
            submission.commitment
        );
    }

    #[test]
    fn any_threshold_subset_opens_and_order_is_irrelevant() {
        let (keys, members) = committee(5);
        let submission = seal_default(&members);
        let shares = open_all(&keys, &submission.envelope);

        let tail: Vec<Share> = shares.iter().skip(2).map(clone_share).collect();
        assert_eq!(
            open(&submission, &tail)
                .expect("a different subset opens")
                .artifact,
            artifact()
        );

        let mut reversed: Vec<Share> = shares.iter().rev().map(clone_share).collect();
        reversed.truncate(3);
        assert_eq!(
            open(&submission, &reversed)
                .expect("order does not matter")
                .nonce,
            NONCE
        );
    }

    // -- the commitment is the plain flow's commitment ---------------------

    /// The strongest statement available: the sealed path reproduces a vector
    /// pinned against the Python reference in `conformance/vectors.json`
    /// (`records.commitment_hash_cases[0]`). If sealing ever changed what is
    /// committed to, the two flows would settle different things.
    #[test]
    fn commitment_equals_the_pinned_reference_vector() {
        let (_keys, members) = committee(3);
        let submission = SealedSubmission::seal(
            OBJECTIVE,
            SUBMITTER,
            &artifact(),
            NONCE,
            EPOCH,
            CREATED,
            &members,
            2,
            &mut OsRng,
        )
        .expect("seal succeeds");

        assert_eq!(
            submission.commitment,
            "sha256:c4b7d428439e598333b066afb7eeddb2dbdc8f1e1a914ed639885740b1d5ff5e"
        );
    }

    /// Same commitment as the plain flow's helper, and as the reference recipe
    /// rebuilt from scratch: `sha256(digest({objective_id, artifact}) | submitter
    /// | nonce)`.
    #[test]
    fn commitment_equals_the_plain_flow_for_the_same_inputs() {
        let (_keys, members) = committee(3);
        let submission = seal_default(&members);

        assert_eq!(
            submission.commitment,
            commitment_hash(OBJECTIVE, SUBMITTER, &artifact(), NONCE)
        );

        let inner = obj! {
            "artifact" => artifact(),
            "objective_id" => Value::string(OBJECTIVE),
        }
        .digest();
        let mut buf = Vec::new();
        buf.extend_from_slice(inner.as_bytes());
        buf.push(b'|');
        buf.extend_from_slice(SUBMITTER.as_bytes());
        buf.push(b'|');
        buf.extend_from_slice(NONCE.as_bytes());
        assert_eq!(submission.commitment, digest_bytes(&buf));
    }

    // -- the submitter is not needed ---------------------------------------

    /// The property the whole module exists for. The submitter's identity is
    /// dropped — jailed, seized, offline — before anyone tries to open, and the
    /// artifact still reveals from committee shares alone.
    #[test]
    fn opening_needs_only_the_shares_not_the_submitter() {
        let (keys, members) = committee(4);
        let identity = Identity::generate(&mut OsRng);
        let submitter = identity.submitter_id();

        let submission = SealedSubmission::seal(
            OBJECTIVE,
            &submitter,
            &artifact(),
            NONCE,
            EPOCH,
            CREATED,
            &members,
            3,
            &mut OsRng,
        )
        .expect("seal succeeds");

        let shares = open_all(&keys, &submission.envelope);
        drop(identity); // the submitter is gone, and their key with them

        let opened = open(&submission, &shares).expect("committee opens without the submitter");
        assert_eq!(opened.artifact, artifact());
        assert_eq!(
            commitment_hash(OBJECTIVE, &submitter, &opened.artifact, &opened.nonce),
            submission.commitment
        );
    }

    // -- adversarial: too few shares ---------------------------------------

    #[test]
    fn one_share_short_does_not_open() {
        let (keys, members) = committee(5);
        let submission = seal_default(&members);
        let shares = open_all(&keys, &submission.envelope);

        let two: Vec<Share> = shares.iter().take(2).map(clone_share).collect();
        match open(&submission, &two) {
            Err(SealedError::Envelope(EnvelopeError::Authentication { .. })) => {}
            other => panic!("t-1 shares must not open: {other:?}"),
        }
    }

    #[test]
    fn no_shares_does_not_open() {
        let (_keys, members) = committee(5);
        let submission = seal_default(&members);
        match open(&submission, &[]) {
            Err(SealedError::Envelope(EnvelopeError::NoShares)) => {}
            other => panic!("an empty share set must not open: {other:?}"),
        }
    }

    #[test]
    fn shares_from_another_submission_do_not_open() {
        let (keys_a, members_a) = committee(5);
        let (_keys_b, members_b) = committee(5);
        let a = seal_default(&members_a);
        let b = SealedSubmission::seal(
            OBJECTIVE,
            "bob",
            &artifact(),
            "n2",
            EPOCH,
            CREATED,
            &members_b,
            3,
            &mut OsRng,
        )
        .expect("seal succeeds");

        let shares_a = open_all(&keys_a, &a.envelope);
        match open(&b, &shares_a) {
            Err(SealedError::Envelope(EnvelopeError::Authentication { .. })) => {}
            other => panic!("foreign shares must not open: {other:?}"),
        }
    }

    // -- adversarial: envelope replay --------------------------------------

    /// An envelope lifted from another submission. The AEAD alone would accept
    /// it — its associated data travels with it — so the explicit binding check
    /// is what catches this.
    #[test]
    fn a_swapped_envelope_does_not_open() {
        let (keys_a, members_a) = committee(5);
        let (_keys_b, members_b) = committee(5);
        let a = seal_default(&members_a);
        let b = SealedSubmission::seal(
            OBJECTIVE,
            "bob",
            &artifact(),
            "n2",
            EPOCH,
            CREATED,
            &members_b,
            3,
            &mut OsRng,
        )
        .expect("seal succeeds");

        // Bob keeps his own commitment but serves Alice's ciphertext.
        let forged = SealedSubmission {
            envelope: a.envelope.clone(),
            ..b.clone()
        };
        let shares_a = open_all(&keys_a, &a.envelope);
        match open(&forged, &shares_a) {
            Err(SealedError::EnvelopeNotBound { .. }) => {}
            other => panic!("a swapped envelope must not open: {other:?}"),
        }

        // ...and the same swap is refused at the decoding boundary.
        match SealedSubmission::from_value(&forged.to_value()) {
            Err(SealedError::EnvelopeNotBound { .. }) => {}
            other => panic!("decoding must refuse an unbound envelope: {other:?}"),
        }
    }

    /// The thorough version of the theft: copy the victim's commitment *and*
    /// envelope, and submit under your own name. The binding check recomputes
    /// over the thief's `submitter`, so it cannot match.
    #[test]
    fn stealing_a_whole_submission_under_another_name_fails_binding() {
        let (keys, members) = committee(5);
        let victim = seal_default(&members);

        let thief = SealedSubmission {
            submitter: "mallory".to_string(),
            ..victim.clone()
        };
        let shares = open_all(&keys, &victim.envelope);
        match open(&thief, &shares) {
            Err(SealedError::CommitmentMismatch { .. }) => {}
            other => panic!("a stolen submission must not open under a new name: {other:?}"),
        }
    }

    /// The same submission replayed under a different objective. Covered by the
    /// one comparison, because `objective_id` is inside the commitment.
    #[test]
    fn replaying_under_another_objective_fails_binding() {
        let (keys, members) = committee(5);
        let original = seal_default(&members);

        let replayed = SealedSubmission {
            objective_id: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            ..original.clone()
        };
        let shares = open_all(&keys, &original.envelope);
        match open(&replayed, &shares) {
            Err(SealedError::CommitmentMismatch { .. }) => {}
            other => panic!("a replayed objective must not open: {other:?}"),
        }
    }

    // -- adversarial: a lying submitter ------------------------------------

    /// The case the binding exists for: commit to one artifact, seal another.
    /// Nothing detects this until the committee opens it, and then it is
    /// arithmetic.
    #[test]
    fn sealing_an_artifact_other_than_the_committed_one_is_detected() {
        let (keys, members) = committee(5);
        let committed = artifact();
        let smuggled = obj! { "n" => Value::Int(43) };

        let commitment = commitment_hash(OBJECTIVE, SUBMITTER, &committed, NONCE);
        let payload = payload_bytes(&smuggled, NONCE);
        let envelope =
            SealedEnvelope::seal(payload.as_slice(), &commitment, &members, 3, &mut OsRng)
                .expect("seal succeeds");
        let submission = SealedSubmission {
            objective_id: OBJECTIVE.to_string(),
            submitter: SUBMITTER.to_string(),
            commitment,
            envelope,
            epoch: EPOCH,
            created_at: CREATED.to_string(),
        };

        let shares = open_all(&keys, &submission.envelope);
        match open(&submission, &shares) {
            Err(SealedError::CommitmentMismatch { committed, sealed }) => {
                assert_ne!(committed, sealed);
            }
            other => panic!("a mis-sealed artifact must be detected: {other:?}"),
        }
    }

    /// The same attack through the nonce rather than the artifact.
    #[test]
    fn sealing_a_different_nonce_is_detected() {
        let (keys, members) = committee(5);
        let commitment = commitment_hash(OBJECTIVE, SUBMITTER, &artifact(), NONCE);
        let payload = payload_bytes(&artifact(), "a-different-nonce");
        let envelope =
            SealedEnvelope::seal(payload.as_slice(), &commitment, &members, 3, &mut OsRng)
                .expect("seal succeeds");
        let submission = SealedSubmission {
            objective_id: OBJECTIVE.to_string(),
            submitter: SUBMITTER.to_string(),
            commitment,
            envelope,
            epoch: EPOCH,
            created_at: CREATED.to_string(),
        };

        let shares = open_all(&keys, &submission.envelope);
        match open(&submission, &shares) {
            Err(SealedError::CommitmentMismatch { .. }) => {}
            other => panic!("a mis-sealed nonce must be detected: {other:?}"),
        }
    }

    // -- adversarial: payload shape ----------------------------------------

    /// Build a submission around arbitrary sealed bytes, with a commitment that
    /// is *correct* for the artifact and nonce it claims. Isolates the payload
    /// checks from the binding check.
    fn submission_with_payload(
        members: &[CommitteeMember],
        commitment_over: (&Value, &str),
        payload: &[u8],
    ) -> SealedSubmission {
        let commitment =
            commitment_hash(OBJECTIVE, SUBMITTER, commitment_over.0, commitment_over.1);
        let envelope = SealedEnvelope::seal(payload, &commitment, members, 3, &mut OsRng)
            .expect("seal succeeds");
        SealedSubmission {
            objective_id: OBJECTIVE.to_string(),
            submitter: SUBMITTER.to_string(),
            commitment,
            envelope,
            epoch: EPOCH,
            created_at: CREATED.to_string(),
        }
    }

    /// A payload without the nonce is the failure mode the design is built to
    /// avoid: it opens to something nobody but the submitter can check.
    #[test]
    fn a_payload_without_the_nonce_is_refused() {
        let (keys, members) = committee(5);
        let payload = obj! { "artifact" => artifact() }.canonical_bytes();
        let submission = submission_with_payload(&members, (&artifact(), NONCE), &payload);

        let shares = open_all(&keys, &submission.envelope);
        match open(&submission, &shares) {
            Err(SealedError::MissingPayloadField { field: "nonce" }) => {}
            other => panic!("a nonce-less payload must be refused: {other:?}"),
        }
    }

    #[test]
    fn a_non_string_nonce_is_refused() {
        let (keys, members) = committee(5);
        let payload = obj! {
            "artifact" => artifact(),
            "nonce" => Value::Int(1),
        }
        .canonical_bytes();
        let submission = submission_with_payload(&members, (&artifact(), NONCE), &payload);

        let shares = open_all(&keys, &submission.envelope);
        match open(&submission, &shares) {
            Err(SealedError::InvalidPayloadField { field: "nonce", .. }) => {}
            other => panic!("a non-string nonce must be refused: {other:?}"),
        }
    }

    /// A key no commitment covers: content smuggled in with the authority of a
    /// sealed submission.
    #[test]
    fn a_payload_with_an_extra_field_is_refused() {
        let (keys, members) = committee(5);
        let payload = obj! {
            "artifact" => artifact(),
            "nonce" => Value::string(NONCE),
            "zz_smuggled" => Value::string("uncommitted"),
        }
        .canonical_bytes();
        let submission = submission_with_payload(&members, (&artifact(), NONCE), &payload);

        let shares = open_all(&keys, &submission.envelope);
        match open(&submission, &shares) {
            Err(SealedError::UnexpectedPayloadField { field }) => {
                assert_eq!(field, "zz_smuggled");
            }
            other => panic!("an uncommitted payload field must be refused: {other:?}"),
        }
    }

    /// Valid JSON, wrong bytes: keys out of canonical order. Accepting it would
    /// give one payload two encodings.
    #[test]
    fn a_non_canonical_payload_is_refused() {
        let (keys, members) = committee(5);
        let payload = br#"{"nonce":"n1","artifact":{"n":42}}"#;
        let submission = submission_with_payload(&members, (&artifact(), NONCE), payload);

        let shares = open_all(&keys, &submission.envelope);
        match open(&submission, &shares) {
            Err(SealedError::PayloadNotCanonical) => {}
            other => panic!("a non-canonical payload must be refused: {other:?}"),
        }
    }

    #[test]
    fn a_payload_that_is_not_json_is_refused() {
        let (keys, members) = committee(5);
        let submission =
            submission_with_payload(&members, (&artifact(), NONCE), b"not json at all");

        let shares = open_all(&keys, &submission.envelope);
        match open(&submission, &shares) {
            Err(SealedError::Canonical(_)) => {}
            other => panic!("a non-JSON payload must be refused: {other:?}"),
        }
    }

    #[test]
    fn a_payload_that_is_not_utf8_is_refused() {
        let (keys, members) = committee(5);
        let submission = submission_with_payload(&members, (&artifact(), NONCE), &[0xff, 0xfe]);

        let shares = open_all(&keys, &submission.envelope);
        match open(&submission, &shares) {
            Err(SealedError::PayloadNotUtf8) => {}
            other => panic!("a non-UTF-8 payload must be refused: {other:?}"),
        }
    }

    #[test]
    fn a_non_object_artifact_is_refused_when_sealing_and_when_opening() {
        let (keys, members) = committee(5);
        let scalar = Value::Int(42);

        match SealedSubmission::seal(
            OBJECTIVE, SUBMITTER, &scalar, NONCE, EPOCH, CREATED, &members, 3, &mut OsRng,
        ) {
            Err(SealedError::ArtifactNotAnObject) => {}
            other => panic!("sealing a bare scalar must be refused: {other:?}"),
        }

        // Hand-built to reach the open path: the commitment is honest, the
        // artifact is simply not a shape a verifier can read.
        let payload = payload_bytes(&scalar, NONCE);
        let submission = submission_with_payload(&members, (&scalar, NONCE), payload.as_slice());
        let shares = open_all(&keys, &submission.envelope);
        match open(&submission, &shares) {
            Err(SealedError::ArtifactNotAnObject) => {}
            other => panic!("opening a bare scalar must be refused: {other:?}"),
        }
    }

    // -- wire form ---------------------------------------------------------

    #[test]
    fn wire_round_trip_is_exact() {
        let (keys, members) = committee(4);
        let submission = seal_default(&members);

        let decoded = SealedSubmission::from_value(&submission.to_value()).expect("round trips");
        assert_eq!(decoded, submission);
        assert_eq!(decoded.id(), submission.id());
        assert_eq!(
            decoded.to_value().canonical_bytes(),
            submission.to_value().canonical_bytes()
        );

        // And the decoded copy still opens.
        let shares = open_all(&keys, &decoded.envelope);
        assert_eq!(
            open(&decoded, &shares)
                .expect("decoded submission opens")
                .artifact,
            artifact()
        );
    }

    #[test]
    fn epoch_round_trips_at_the_boundary() {
        let (_keys, members) = committee(3);
        let submission = SealedSubmission::seal(
            OBJECTIVE,
            SUBMITTER,
            &artifact(),
            NONCE,
            u64::MAX,
            CREATED,
            &members,
            2,
            &mut OsRng,
        )
        .expect("seal succeeds");
        let decoded = SealedSubmission::from_value(&submission.to_value()).expect("round trips");
        assert_eq!(decoded.epoch, u64::MAX);
    }

    #[test]
    fn decoding_refuses_a_negative_epoch() {
        let (_keys, members) = committee(3);
        let submission = seal_default(&members);
        let mut value = submission.to_value();
        if let Value::Object(map) = &mut value {
            map.insert("epoch".to_string(), Value::Int(-1));
        }
        match SealedSubmission::from_value(&value) {
            Err(SealedError::InvalidField { field: "epoch", .. }) => {}
            other => panic!("a negative epoch must be refused: {other:?}"),
        }
    }

    #[test]
    fn decoding_refuses_an_unknown_version_and_a_wrong_type() {
        let (_keys, members) = committee(3);
        let submission = seal_default(&members);

        let mut value = submission.to_value();
        if let Value::Object(map) = &mut value {
            map.insert("version".to_string(), Value::Int(99));
        }
        match SealedSubmission::from_value(&value) {
            Err(SealedError::UnsupportedVersion { version: 99 }) => {}
            other => panic!("an unknown version must be refused: {other:?}"),
        }

        let mut value = submission.to_value();
        if let Value::Object(map) = &mut value {
            map.insert("type".to_string(), Value::string("claim"));
        }
        match SealedSubmission::from_value(&value) {
            Err(SealedError::InvalidField { field: "type", .. }) => {}
            other => panic!("a wrong type tag must be refused: {other:?}"),
        }
    }

    #[test]
    fn decoding_refuses_a_missing_field() {
        let (_keys, members) = committee(3);
        let submission = seal_default(&members);
        for field in [
            "objective_id",
            "submitter",
            "commitment",
            "envelope",
            "created_at",
            "epoch",
        ] {
            let mut value = submission.to_value();
            if let Value::Object(map) = &mut value {
                map.remove(field);
            }
            match SealedSubmission::from_value(&value) {
                Err(SealedError::MissingField { .. }) => {}
                other => panic!("a submission without {field:?} must be refused: {other:?}"),
            }
        }
    }

    #[test]
    fn the_id_covers_every_field() {
        let (_keys, members) = committee(3);
        let submission = seal_default(&members);

        let other_epoch = SealedSubmission {
            epoch: submission.epoch + 1,
            ..submission.clone()
        };
        assert_ne!(submission.id(), other_epoch.id());

        let other_time = SealedSubmission {
            created_at: "2026-07-29T00:00:00+00:00".to_string(),
            ..submission.clone()
        };
        assert_ne!(submission.id(), other_time.id());

        // Two submissions of the same artifact under different nonces are
        // different records, and neither reveals that they share an artifact.
        let another = SealedSubmission::seal(
            OBJECTIVE,
            SUBMITTER,
            &artifact(),
            "n2",
            EPOCH,
            CREATED,
            &members,
            2,
            &mut OsRng,
        )
        .expect("seal succeeds");
        assert_ne!(submission.id(), another.id());
        assert_ne!(submission.commitment, another.commitment);
    }

    /// Debug output is on the record path (logs, error reports). Nothing secret
    /// may appear there: the plaintext artifact, the nonce and the content key
    /// are all absent from a sealed submission by construction.
    #[test]
    fn debug_output_carries_no_plaintext() {
        let (_keys, members) = committee(3);
        let submission = SealedSubmission::seal(
            OBJECTIVE,
            SUBMITTER,
            &obj! { "answer" => Value::string("the-secret-artifact") },
            "the-secret-nonce",
            EPOCH,
            CREATED,
            &members,
            2,
            &mut OsRng,
        )
        .expect("seal succeeds");

        let rendered = format!("{submission:?}");
        assert!(!rendered.contains("the-secret-artifact"));
        assert!(!rendered.contains("the-secret-nonce"));
    }
}
