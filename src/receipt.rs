//! Signed submission receipts: the operator's word that a record arrived.
//!
//! # The gap this closes
//!
//! Stage 0 settles through one sequencer, and `docs/threat-model.md` names the
//! consequence its **censorship** row: an operator who dislikes a submission
//! can decline to append it, silently, and the log -- internally perfect --
//! carries no trace that anything was ever offered. Sealed submissions force a
//! censor from *targeted* to *indiscriminate* (the sequencer cannot read what
//! it drops), but nothing at this layer can force inclusion; that is the base
//! layer the roadmap's last line argues for.
//!
//! What can be built now is accountability. A receipt is the operator's
//! signed, domain-separated statement: *record `D` of kind `K` reached me at
//! time `T`*. It is signed by the same ML-DSA-65 root key that signs
//! checkpoints, so a reader who has pinned the operator's key -- which every
//! reader verifying checkpoints already has -- can hold both statements at
//! once. The two together are falsifiable in a way neither is alone: admission
//! is a pure function of the log, so if the record is *admissible* against
//! everything the operator admitted in the receipt's epoch, and the log has
//! moved past that epoch without it, the receipt-holder possesses a proof of
//! withholding that any third party can check against the published log and
//! the pinned key. Silent censorship becomes signed censorship.
//!
//! What this does **not** do, stated so nobody mistakes the strength: it does
//! not force inclusion, and an operator can refuse to issue receipts at all.
//! But a refusal to receipt is visible to the submitter at submission time --
//! the moment to walk away -- where a silent drop was visible to nobody,
//! ever. Forcing the censor to refuse *openly, before doing the work of
//! censoring,* is the honest Stage 0 defence; see `docs/censorship.md`.
//!
//! # Why the verdict is derived from the log alone
//!
//! [`standing`] never reads a clock. "The deadline passed" means *the log's
//! own entries have moved into a later epoch*, so the verdict is a pure
//! function of `(receipt, log, record)` and two readers holding the same
//! bytes reach the same one. An operator who stops appending entirely never
//! becomes provably censoring by this test -- and never advances their
//! checkpoints again either, which is its own, louder statement.

use std::fmt;
use std::path::Path;

use crate::canonical::Value;
use crate::checkpoint::{verify_ml_dsa, CheckpointError, RootKey};
use crate::ledger::Ledger;
use crate::node::Node;
use crate::partition::{epoch_of, epoch_seconds};
use crate::records::{Claim, Commitment};

// The `proofwork/` spelling is a wire constant, exactly as in `checkpoint.rs`:
// changing it changes what every already-issued receipt verifies against.
const DOMAIN: &str = "proofwork/submission-receipt/v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptError {
    Invalid(String),
    BadSignature,
    WrongSigner,
    /// The record offered for verification is not the one the receipt names.
    ///
    /// Its own variant rather than `Invalid`, because it is the one error
    /// that accuses the *verifier's inputs* rather than the receipt: handing
    /// the tool a different record would otherwise manufacture a refusal
    /// verdict for a record the operator never saw.
    RecordMismatch {
        receipted: String,
        offered: String,
    },
}

impl fmt::Display for ReceiptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReceiptError::Invalid(detail) => write!(f, "invalid receipt: {detail}"),
            ReceiptError::BadSignature => f.write_str("receipt signature does not verify"),
            ReceiptError::WrongSigner => {
                f.write_str("receipt signer does not match the pinned root key")
            }
            ReceiptError::RecordMismatch { receipted, offered } => write!(
                f,
                "the record offered ({offered}) is not the record the receipt names ({receipted})"
            ),
        }
    }
}
impl std::error::Error for ReceiptError {}

impl From<CheckpointError> for ReceiptError {
    fn from(value: CheckpointError) -> ReceiptError {
        match value {
            CheckpointError::BadSignature => ReceiptError::BadSignature,
            CheckpointError::WrongSigner => ReceiptError::WrongSigner,
            other => ReceiptError::Invalid(other.to_string()),
        }
    }
}

/// A record as the log would hold it, whatever shape it was offered in.
///
/// A submitter's JSON may omit what the canonical form carries -- `type`
/// most of all -- while a log entry's payload always carries it, so hashing
/// the offered bytes directly would mint a receipt no log entry can ever
/// match: the record would be admitted and the receipt would still read
/// "absent". Decoding and re-encoding is the one normalisation both sides
/// agree on. A payload that does not decode is returned as offered --
/// admission will refuse it in its own words, which is the verdict such a
/// receipt should reach.
fn canonical_record(kind: &str, payload: &Value) -> Value {
    match kind {
        "commitment" => Commitment::from_value(payload)
            .map(|record| record.to_value())
            .unwrap_or_else(|_| payload.clone()),
        "claim" => Claim::from_value(payload)
            .map(|record| record.to_value())
            .unwrap_or_else(|_| payload.clone()),
        _ => payload.clone(),
    }
}

/// The operator's statement of receipt: one record, one kind, one instant.
///
/// The epoch is deliberately absent -- derived from `received_at`, never
/// stored, the same rule every record obeys. A stored copy would be a second
/// place it could be wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    /// The record kind the digest was offered as: `commitment` or `claim`.
    pub kind: String,
    /// `sha256:` digest of the record's canonical log form -- the same
    /// identity `p2p::sync` deduplicates by, so presence in a log is a
    /// byte-exact question.
    pub record: String,
    /// When the record reached the operator, by the operator's clock. The
    /// deadline the receipt creates is the close of this instant's epoch,
    /// because the admission rules themselves refuse a commitment or claim
    /// drained outside its declared epoch -- an operator who receipts and
    /// then sits past the boundary has chosen the record's refusal.
    pub received_at: String,
}

impl Receipt {
    /// Build a receipt for `payload`, offered as `kind`, received now.
    pub fn for_record(
        kind: impl Into<String>,
        payload: &Value,
        received_at: impl Into<String>,
    ) -> Receipt {
        let kind = kind.into();
        Receipt {
            record: canonical_record(&kind, payload).digest(),
            kind,
            received_at: received_at.into(),
        }
    }

    /// The epoch this receipt's deadline lives in, derived from
    /// `received_at`. `None` when the timestamp does not parse.
    pub fn epoch(&self) -> Option<u64> {
        crate::time::parse_rfc3339(&self.received_at)
            .and_then(|seconds| u64::try_from(seconds).ok())
            .map(|seconds| epoch_of(seconds, epoch_seconds()))
    }

    pub fn to_value(&self) -> Value {
        Value::object([
            ("kind", Value::string(self.kind.clone())),
            ("record", Value::string(self.record.clone())),
            ("received_at", Value::string(self.received_at.clone())),
        ])
    }

    pub fn from_value(value: &Value) -> Result<Receipt, ReceiptError> {
        let field = |name: &str| -> Result<String, ReceiptError> {
            value
                .get(name)
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| ReceiptError::Invalid(name.into()))
        };
        Ok(Receipt {
            kind: field("kind")?,
            record: field("record")?,
            received_at: field("received_at")?,
        })
    }
}

/// A [`Receipt`] under the operator's root-key signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedReceipt {
    pub receipt: Receipt,
    /// ML-DSA-65 encoded public key (1952 bytes).
    pub public_key: Vec<u8>,
    /// ML-DSA-65 encoded signature (3309 bytes).
    pub signature: Vec<u8>,
}

impl SignedReceipt {
    fn signing_value(receipt: &Receipt) -> Value {
        Value::object([
            ("domain", Value::String(DOMAIN.into())),
            ("receipt", receipt.to_value()),
        ])
    }

    /// Sign `receipt` with the checkpoint root key.
    ///
    /// The *same* key on purpose: a reader holds one pinned public key per
    /// operator, and a receipt under a second key would authenticate against
    /// nothing they have. The domain string is what keeps the two statements
    /// from ever being confused for each other.
    pub fn sign(key: &RootKey, receipt: Receipt) -> SignedReceipt {
        let message = Self::signing_value(&receipt).canonical_bytes();
        SignedReceipt {
            signature: key.sign_raw(&message),
            public_key: key.public_key(),
            receipt,
        }
    }

    pub fn to_value(&self) -> Value {
        Value::object([
            ("receipt", self.receipt.to_value()),
            (
                "public_key",
                Value::string(crate::hex::encode(&self.public_key)),
            ),
            (
                "signature",
                Value::string(crate::hex::encode(&self.signature)),
            ),
        ])
    }

    pub fn from_value(value: &Value) -> Result<SignedReceipt, ReceiptError> {
        let receipt = Receipt::from_value(
            value
                .get("receipt")
                .ok_or_else(|| ReceiptError::Invalid("receipt".into()))?,
        )?;
        let hex_field = |name: &str| -> Result<Vec<u8>, ReceiptError> {
            let text = value
                .get(name)
                .and_then(Value::as_str)
                .ok_or_else(|| ReceiptError::Invalid(name.into()))?;
            crate::hex::decode(text)
                .ok_or_else(|| ReceiptError::Invalid(format!("{name} is not lowercase hex")))
        };
        let public_key = hex_field("public_key")?;
        let signature = hex_field("signature")?;
        if public_key.len() != 1952 || signature.len() != 3309 {
            return Err(ReceiptError::Invalid(
                "ML-DSA-65 key or signature length".into(),
            ));
        }
        Ok(SignedReceipt {
            receipt,
            public_key,
            signature,
        })
    }

    /// Check the signature against the key the reader has pinned.
    ///
    /// `expected_key` must come from somewhere the reader already trusts --
    /// the same out-of-band requirement `verify --from` states for
    /// checkpoints, and the same key satisfies both.
    pub fn verify(&self, expected_key: &[u8]) -> Result<(), ReceiptError> {
        if self.public_key != expected_key {
            return Err(ReceiptError::WrongSigner);
        }
        let message = Self::signing_value(&self.receipt).canonical_bytes();
        verify_ml_dsa(&self.public_key, &message, &self.signature).map_err(ReceiptError::from)
    }
}

/// What a receipt proves against a given log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Standing {
    /// The record is in the log. The receipt is discharged.
    Included { seq: u64 },
    /// The log has not yet moved past the receipt's epoch. Nothing is proven
    /// either way; check again once it has.
    Pending { deadline_epoch: u64 },
    /// The record is absent, and the log's own rules refuse it at the
    /// receipted time. The receipt is discharged: this is what an honest
    /// refusal looks like, and the reason is the rules engine's own words.
    Refused { reason: String },
    /// **Proven withholding.** The record is absent, the log has moved past
    /// the receipt's epoch, and admission at the receipted time -- against
    /// everything the operator admitted in that epoch -- succeeds. The
    /// operator signed "this reached me in epoch `epoch`" and then published
    /// a log through `log_epoch` that neither contains nor could refuse it.
    Withheld { epoch: u64, log_epoch: u64 },
    /// The record is absent past its deadline but admissibility could not be
    /// tested -- the record bytes were not supplied. Absence alone accuses
    /// nobody: the record might have been refusable.
    Undecidable { reason: String },
}

impl fmt::Display for Standing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Standing::Included { seq } => {
                write!(f, "included: the record is log entry {seq}")
            }
            Standing::Pending { deadline_epoch } => write!(
                f,
                "pending: the log has not yet moved past epoch {deadline_epoch}"
            ),
            Standing::Refused { reason } => {
                write!(f, "refused, and the refusal re-derives: {reason}")
            }
            Standing::Withheld { epoch, log_epoch } => write!(
                f,
                "WITHHELD: received in epoch {epoch}, admissible against that epoch's log, \
                 absent from a log that has reached epoch {log_epoch}"
            ),
            Standing::Undecidable { reason } => write!(f, "undecidable: {reason}"),
        }
    }
}

/// How much of an epoch must remain at receipt time for a withholding
/// verdict to stand: a tenth, and at least one second.
///
/// Without this a submitter manufactures an accusation at will: POST in the
/// final milliseconds of an epoch, and the honest operator's very next drain
/// lands across the boundary, where the epoch-binding rule itself refuses
/// the record -- admissible when receipted, absent afterwards, "proven"
/// withheld. The grace names the time an operator is actually being promised
/// to act within. A submitter who wants the proof's protection submits with
/// a tenth of an epoch to spare -- and checks, at submission time, that the
/// receipt's `received_at` is honest about the clock, because a stamp the
/// operator back-dates toward a boundary buys this exemption.
fn withholding_grace(epoch_len: u64) -> u64 {
    (epoch_len / 10).max(1)
}

/// Judge `receipt` against `ledger`.
///
/// Pass the record's payload as `record` to enable the withholding proof;
/// without it, absence past the deadline is [`Standing::Undecidable`],
/// because a record that would have been refused is not evidence of
/// anything. `verifier_root` resolves pinned verifier code exactly as a node
/// would -- an unresolvable verifier yields an `unavailable` verdict, which
/// admission records rather than refuses, so the proof does not depend on the
/// verifier's toolchain being installed here. `scratch` is a directory this
/// call may write a temporary log into.
///
/// The signature is **not** checked here -- callers verify the
/// [`SignedReceipt`] first, against a key they pinned. Splitting the two
/// keeps this function a pure question about logs, answerable even for a
/// receipt whose key the caller has yet to obtain.
pub fn standing(
    receipt: &Receipt,
    ledger: &Ledger,
    record: Option<&Value>,
    verifier_root: &Path,
    scratch: &Path,
) -> Result<Standing, ReceiptError> {
    if let Some(payload) = record {
        let offered = canonical_record(&receipt.kind, payload).digest();
        if offered != receipt.record {
            return Err(ReceiptError::RecordMismatch {
                receipted: receipt.record.clone(),
                offered,
            });
        }
    }

    if let Some(entry) = ledger
        .entries()
        .iter()
        .find(|entry| entry.kind == receipt.kind && entry.payload.digest() == receipt.record)
    {
        return Ok(Standing::Included { seq: entry.seq });
    }

    let deadline_epoch = receipt
        .epoch()
        .ok_or_else(|| ReceiptError::Invalid("received_at is not RFC 3339".into()))?;

    // The log's own notion of "now": the furthest epoch any entry was
    // admitted in. The maximum rather than the last entry, so a single
    // out-of-order stamp cannot roll the deadline backwards.
    let log_epoch = ledger
        .entries()
        .iter()
        .filter_map(|entry| {
            crate::time::parse_rfc3339(&entry.ts)
                .and_then(|seconds| u64::try_from(seconds).ok())
                .map(|seconds| epoch_of(seconds, epoch_seconds()))
        })
        .max();
    let log_epoch = match log_epoch {
        Some(epoch) if epoch > deadline_epoch => epoch,
        _ => return Ok(Standing::Pending { deadline_epoch }),
    };

    let Some(payload) = record else {
        return Ok(Standing::Undecidable {
            reason: format!(
                "absent from a log that has reached epoch {log_epoch}; supply the record \
                 bytes to test whether admission would have refused it"
            ),
        });
    };

    // Everything the operator admitted through the receipt's epoch, as a
    // positional prefix -- the chain order is the order, and stopping at the
    // first later-epoch entry keeps the reconstruction an actual prefix of
    // the published log rather than a curated subset.
    let prefix_len = ledger
        .entries()
        .iter()
        .position(|entry| {
            crate::time::parse_rfc3339(&entry.ts)
                .and_then(|seconds| u64::try_from(seconds).ok())
                .map(|seconds| epoch_of(seconds, epoch_seconds()))
                .is_none_or(|epoch| epoch > deadline_epoch)
        })
        .unwrap_or(ledger.entries().len());

    std::fs::create_dir_all(scratch)
        .map_err(|error| ReceiptError::Invalid(format!("scratch directory: {error}")))?;
    let replay_path = scratch.join(format!(
        "receipt-replay-{}.jsonl",
        receipt.record.replace("sha256:", "")
    ));
    let _ = std::fs::remove_file(&replay_path);
    let mut replay = Ledger::open(&replay_path)
        .map_err(|error| ReceiptError::Invalid(format!("scratch log: {error}")))?;
    for entry in &ledger.entries()[..prefix_len] {
        replay
            .append(&entry.kind, entry.payload.clone(), &entry.ts)
            .map_err(|error| ReceiptError::Invalid(format!("scratch log: {error}")))?;
    }
    let mut node = Node::new(replay, verifier_root);

    let admission = match receipt.kind.as_str() {
        "commitment" => Commitment::from_value(payload)
            .map_err(|error| error.to_string())
            .and_then(|commitment| {
                node.commit(&commitment, &receipt.received_at)
                    .map(|_| ())
                    .map_err(|violation| violation.to_string())
            }),
        "claim" => Claim::from_value(payload)
            .map_err(|error| error.to_string())
            .and_then(|claim| {
                // The same schema gate the HTTP path and the drain apply, so
                // this reconstruction refuses exactly what they refuse.
                crate::schema::validate_claim(&claim.to_value())
                    .map_err(|error| error.to_string())?;
                node.reveal(&claim, &receipt.received_at)
                    .map(|_| ())
                    .map_err(|violation| violation.to_string())
            }),
        other => {
            let _ = std::fs::remove_file(&replay_path);
            return Ok(Standing::Undecidable {
                reason: format!("kind {other:?} has no admission path to test against"),
            });
        }
    };
    let _ = std::fs::remove_file(&replay_path);

    Ok(match admission {
        Ok(()) => {
            // Admissible and absent -- but only an operator who was given
            // time to act can be accused. See `withholding_grace`.
            let epoch_len = epoch_seconds();
            let received = crate::time::parse_rfc3339(&receipt.received_at)
                .and_then(|seconds| u64::try_from(seconds).ok())
                .ok_or_else(|| ReceiptError::Invalid("received_at is not RFC 3339".into()))?;
            let boundary = deadline_epoch
                .saturating_add(1)
                .saturating_mul(epoch_len.max(1));
            let remaining = boundary.saturating_sub(received);
            if remaining < withholding_grace(epoch_len.max(1)) {
                Standing::Undecidable {
                    reason: format!(
                        "admissible and absent, but received {remaining}s before its epoch \
                         closed -- too late to prove the operator could still have drained \
                         it. Submit with at least a tenth of an epoch to spare for a \
                         receipt that can carry a withholding proof"
                    ),
                }
            } else {
                Standing::Withheld {
                    epoch: deadline_epoch,
                    log_epoch,
                }
            }
        }
        Err(reason) => Standing::Refused { reason },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::{commitment_hash, Objective};

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("cairn-receipt-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn fixture_objective(created_at: &str) -> Objective {
        Objective::new(
            "GOAL-receipt",
            "a fixture objective for receipt tests",
            Value::object([
                ("kind", Value::string("certificate")),
                ("checker", Value::string("checker.py")),
                ("checker_sha256", Value::string("aa".repeat(32))),
                ("entrypoint", Value::string("check")),
            ]),
            1,
            "treasury",
            created_at,
            None,
            None,
        )
        .unwrap()
    }

    #[test]
    fn a_receipt_round_trips_and_binds_its_bytes() {
        let key = RootKey::generate();
        let payload = Value::object([("x", Value::Int(1))]);
        let receipt = Receipt::for_record("commitment", &payload, "2026-08-18T00:01:00+00:00");
        let signed = SignedReceipt::sign(&key, receipt);
        signed.verify(&key.public_key()).unwrap();

        let round_trip = SignedReceipt::from_value(&signed.to_value()).unwrap();
        assert_eq!(round_trip, signed);

        let other = RootKey::generate();
        assert_eq!(
            signed.verify(&other.public_key()),
            Err(ReceiptError::WrongSigner)
        );
        let mut forged = signed.clone();
        forged.signature[0] ^= 1;
        assert_eq!(
            forged.verify(&key.public_key()),
            Err(ReceiptError::BadSignature)
        );
        let mut reworded = signed.clone();
        reworded.receipt.received_at = "2026-08-18T00:00:00+00:00".into();
        assert_eq!(
            reworded.verify(&key.public_key()),
            Err(ReceiptError::BadSignature)
        );
    }

    /// The four verdicts, on one log: pending while the epoch is open,
    /// included when the record lands, proven withholding when an admissible
    /// record is absent past its deadline, and an honest refusal re-derived
    /// when the record was never admissible.
    #[test]
    fn standing_distinguishes_withholding_from_refusal() {
        let dir = scratch("standing");
        let mut node = Node::new(Ledger::open(dir.join("log.jsonl")).unwrap(), &dir);
        let objective = fixture_objective("2026-08-18T00:00:00+00:00");
        let objective_id = node
            .post_objective(&objective, "2026-08-18T00:00:00+00:00")
            .unwrap();

        let artifact = Value::object([("answer", Value::Int(7))]);
        let hash = commitment_hash(&objective_id, "alice", &artifact, "n1");
        let commitment = Commitment::new(&objective_id, "alice", hash, "2026-08-18T00:01:00+00:00");
        let receipt = Receipt::for_record(
            "commitment",
            &commitment.to_value(),
            "2026-08-18T00:01:30+00:00",
        );

        // The log has not left the receipt's epoch: pending.
        assert!(matches!(
            standing(
                &receipt,
                node.ledger(),
                Some(&commitment.to_value()),
                &dir,
                &dir
            )
            .unwrap(),
            Standing::Pending { .. }
        ));

        // The log moves on without the record: withholding, provable because
        // admission at the receipted time succeeds.
        let later = fixture_objective("2026-08-18T00:20:00+00:00");
        node.post_objective(&later, "2026-08-18T00:20:00+00:00")
            .unwrap();
        assert!(matches!(
            standing(
                &receipt,
                node.ledger(),
                Some(&commitment.to_value()),
                &dir,
                &dir
            )
            .unwrap(),
            Standing::Withheld { .. }
        ));

        // Without the record bytes, the same absence proves nothing.
        assert!(matches!(
            standing(&receipt, node.ledger(), None, &dir, &dir).unwrap(),
            Standing::Undecidable { .. }
        ));

        // A record the rules refuse -- a commitment against an objective that
        // does not exist -- discharges its receipt with the refusal.
        let stray = Commitment::new(
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "alice",
            commitment_hash("nowhere", "alice", &artifact, "n2"),
            "2026-08-18T00:01:00+00:00",
        );
        let stray_receipt =
            Receipt::for_record("commitment", &stray.to_value(), "2026-08-18T00:01:30+00:00");
        match standing(
            &stray_receipt,
            node.ledger(),
            Some(&stray.to_value()),
            &dir,
            &dir,
        )
        .unwrap()
        {
            Standing::Refused { reason } => {
                assert!(reason.contains("unknown objective"), "reason: {reason}")
            }
            other => panic!("expected a refusal, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(dir);
    }

    /// A record that did land discharges its receipt as included, wherever
    /// the deadline stands.
    #[test]
    fn an_included_record_discharges_its_receipt() {
        let dir = scratch("included");
        let mut node = Node::new(Ledger::open(dir.join("log.jsonl")).unwrap(), &dir);
        let objective = fixture_objective("2026-08-18T00:00:00+00:00");
        let objective_id = node
            .post_objective(&objective, "2026-08-18T00:00:00+00:00")
            .unwrap();
        let artifact = Value::object([("answer", Value::Int(7))]);
        let hash = commitment_hash(&objective_id, "alice", &artifact, "n1");
        let commitment = Commitment::new(&objective_id, "alice", hash, "2026-08-18T00:01:00+00:00");
        let receipt = Receipt::for_record(
            "commitment",
            &commitment.to_value(),
            "2026-08-18T00:01:30+00:00",
        );
        node.commit(&commitment, "2026-08-18T00:01:30+00:00")
            .unwrap();
        assert!(matches!(
            standing(
                &receipt,
                node.ledger(),
                Some(&commitment.to_value()),
                &dir,
                &dir
            )
            .unwrap(),
            Standing::Included { seq: 1 }
        ));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A receipt stamped in the final moments of an epoch cannot accuse: the
    /// operator's next drain lands across the boundary, where the binding
    /// rule itself refuses the record. Without this, POSTing at 00:09:59.9
    /// manufactures a withholding proof against an honest operator.
    #[test]
    fn a_boundary_squeezed_receipt_proves_nothing() {
        let dir = scratch("grace");
        let mut node = Node::new(Ledger::open(dir.join("log.jsonl")).unwrap(), &dir);
        let objective = fixture_objective("2026-08-18T00:00:00+00:00");
        let objective_id = node
            .post_objective(&objective, "2026-08-18T00:00:00+00:00")
            .unwrap();
        let artifact = Value::object([("answer", Value::Int(7))]);
        let commitment = Commitment::new(
            &objective_id,
            "alice",
            commitment_hash(&objective_id, "alice", &artifact, "n1"),
            "2026-08-18T00:09:00+00:00",
        );
        // Ten seconds before the boundary: admissible, and no time to act.
        let receipt = Receipt::for_record(
            "commitment",
            &commitment.to_value(),
            "2026-08-18T00:09:50+00:00",
        );
        let later = fixture_objective("2026-08-18T00:20:00+00:00");
        node.post_objective(&later, "2026-08-18T00:20:00+00:00")
            .unwrap();
        match standing(
            &receipt,
            node.ledger(),
            Some(&commitment.to_value()),
            &dir,
            &dir,
        )
        .unwrap()
        {
            Standing::Undecidable { reason } => {
                assert!(reason.contains("before its epoch closed"), "{reason}")
            }
            other => panic!("a squeezed receipt must not accuse, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A submitter's minimal JSON omits `type`; the log's canonical payload
    /// carries it. The receipt must digest the canonical form, or every
    /// receipt over a hand-written record reads "absent" forever -- found by
    /// running the real binaries, not by the tests shipped with the first
    /// draft.
    #[test]
    fn a_receipt_over_a_minimal_record_matches_the_admitted_entry() {
        let dir = scratch("minimal-shape");
        let mut node = Node::new(Ledger::open(dir.join("log.jsonl")).unwrap(), &dir);
        let objective = fixture_objective("2026-08-18T00:00:00+00:00");
        let objective_id = node
            .post_objective(&objective, "2026-08-18T00:00:00+00:00")
            .unwrap();
        let artifact = Value::object([("answer", Value::Int(7))]);
        let commitment = Commitment::new(
            &objective_id,
            "alice",
            commitment_hash(&objective_id, "alice", &artifact, "n1"),
            "2026-08-18T00:01:00+00:00",
        );
        // The shape a client actually POSTs: the four fields, no `type`.
        let minimal = Value::object([
            ("objective_id", Value::string(objective_id.clone())),
            ("submitter", Value::string("alice")),
            ("hash", Value::string(commitment.hash.clone())),
            ("created_at", Value::string("2026-08-18T00:01:00+00:00")),
        ]);
        assert_ne!(
            minimal.digest(),
            commitment.to_value().digest(),
            "the fixture must exercise the two shapes actually differing"
        );
        let receipt = Receipt::for_record("commitment", &minimal, "2026-08-18T00:01:30+00:00");
        assert_eq!(receipt.record, commitment.to_value().digest());

        node.commit(&commitment, "2026-08-18T00:01:30+00:00")
            .unwrap();
        assert!(matches!(
            standing(&receipt, node.ledger(), Some(&minimal), &dir, &dir).unwrap(),
            Standing::Included { .. }
        ));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A verifier offered the wrong bytes must not manufacture a refusal.
    #[test]
    fn a_mismatched_record_is_an_error_not_a_verdict() {
        let dir = scratch("mismatch");
        let node = Node::new(Ledger::open(dir.join("log.jsonl")).unwrap(), &dir);
        let receipt = Receipt::for_record(
            "commitment",
            &Value::object([("x", Value::Int(1))]),
            "2026-08-18T00:01:00+00:00",
        );
        let other = Value::object([("x", Value::Int(2))]);
        assert!(matches!(
            standing(&receipt, node.ledger(), Some(&other), &dir, &dir),
            Err(ReceiptError::RecordMismatch { .. })
        ));
        let _ = std::fs::remove_dir_all(dir);
    }
}
