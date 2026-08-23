//! The three records the network is built from: [`Objective`], [`Commitment`],
//! [`Claim`].
//!
//! Every record is content-addressed: its id *is* the hash of its canonical
//! form. Two consequences carry most of the design's weight.
//!
//! 1. **The verifier is part of the objective's identity.** Editing an
//!    evaluator does not silently rescore work already done against it -- it
//!    produces a different objective id. There is no such thing as changing the
//!    rules of a funded objective; there is only forking it and funding the
//!    fork.
//!
//! 2. **A claim names the claims it built on.** The result is a hash-linked
//!    DAG, which is what makes automatic attribution computable (see
//!    `attribution`).
//!
//! # Optional fields are omitted, never nulled
//!
//! `deadline` and `ratchet` appear in the record only when they are set.
//! Emitting them as `null` would be a different byte string, hence a different
//! digest, hence a different objective -- every id ever issued would move. The
//! same reasoning applies to any field added later: absent and null are not
//! interchangeable in a content-addressed format.
//!
//! [`Objective::confidentiality`] is the first field added under that rule, and
//! it shows the shape the rule forces. It is not an `Option` -- every objective
//! has a class -- so the omission is keyed on the *default* instead:
//! [`Confidentiality::Public`] serialises to nothing. A field with a default
//! must therefore choose its default to be whatever every pre-existing record
//! meant by its absence, or it cannot be added at all without reissuing the
//! network's ids.
//!
//! # Validation is explicit here, unlike in the reference implementation
//!
//! Python validates inside `__post_init__`, so a record cannot exist unchecked.
//! Rust struct literals have no such hook, so the invariants live in
//! [`Objective::validate`] and [`Claim::validate`]. Both `from_value`
//! constructors and the `new` constructors run them; code that builds a record
//! by hand from untrusted input must call `validate` before trusting it. The
//! invariants that *can* be moved into the type system have been: `reward` is
//! `u64`, so "reward must be a non-negative integer" is unrepresentable rather
//! than checked, and [`canonical::Value`](crate::canonical::Value) has no float
//! variant, so no record can carry one.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::canonical::{digest_bytes, Value};

/// The `type` tag every record carries in its canonical form.
///
/// The tag is what lets a reader of the append-only log tell an objective from
/// a claim without consulting anything outside the bytes. Keeping it an enum
/// keeps the three spellings in one place instead of scattered string literals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RecordKind {
    Objective,
    Commitment,
    Claim,
    Peer,
    Undertaking,
    Availability,
    CommitteeShare,
}

impl RecordKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            RecordKind::Objective => "objective",
            RecordKind::Commitment => "commitment",
            RecordKind::Claim => "claim",
            RecordKind::Peer => "peer",
            RecordKind::Undertaking => "undertaking",
            RecordKind::Availability => "availability",
            RecordKind::CommitteeShare => "committee_share",
        }
    }
}

impl fmt::Display for RecordKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A record is structurally invalid, or a value cannot be read as one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordError {
    /// The value being decoded is not an object at all.
    NotAnObject { record: &'static str },
    /// A required field is absent. The reference implementation raises
    /// `KeyError` here; a typed error is the Rust equivalent.
    MissingField {
        record: &'static str,
        field: &'static str,
    },
    /// A field is present with the wrong shape.
    InvalidField {
        record: &'static str,
        field: &'static str,
        expected: &'static str,
    },
    /// An objective with no statement is not a question anyone can answer.
    EmptyStatement,
    /// An objective whose verifier has no `kind` cannot be routed to a checker,
    /// so its payout would be somebody's opinion.
    VerifierWithoutKind,
    /// `reward` is an integer in the smallest unit of account, and this crate
    /// carries it as `u64`. Python's bignums have no upper bound, so a record
    /// written by the reference implementation with a reward above
    /// `u64::MAX` -- or a negative one, which it rejects at construction --
    /// is refused here rather than silently truncated.
    RewardOutOfRange { reward: i128 },
    /// Citations are a set. A repeated edge would otherwise be counted twice by
    /// attribution, which is a way of paying yourself for the same input.
    DuplicateCitation { id: String },
    /// Two relations naming one target. See [`Claim::validate`] for why the key
    /// is the target rather than the `(kind, target)` pair.
    DuplicateRelation { id: String },
    /// A relation kind outside the declared set.
    ///
    /// Refused, never skipped: an implementation that ignored what another read
    /// would compute a different [`crate::knowledge::Standing`] from the same
    /// log, and neither would error.
    UnknownRelation { kind: String },
    /// `confidentiality` carried a value outside the declared classes.
    ///
    /// Refused rather than defaulted, because every wrong guess here is a
    /// disclosure decision made on the submitter's behalf.
    UnknownConfidentiality { value: String },
    /// `confidentiality: "sealed"` was requested. The class is declared in the
    /// schema so its cost is explicit, but paying for an artifact nobody may
    /// read requires a zero-knowledge proof that the pinned verifier accepts
    /// it, which is not implemented.
    ///
    /// Refused rather than silently downgraded to `embargoed`: a submitter who
    /// asked for "never revealed" and got "revealed later" would be misled
    /// about the one thing they cared about.
    SealedNotImplemented,
    /// A commitment carries an `envelope` that is not a decodable sealed
    /// envelope, or a share record carries a malformed share.
    ///
    /// Refused at the decoder rather than at open time. An envelope that cannot
    /// be decoded can never be opened, so admitting one writes a submission
    /// into the log that the committee will spend an epoch failing to reveal --
    /// and the submitter, who is the only party who could have caught it,
    /// learns about it an epoch too late.
    MalformedEnvelope { reason: String },
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecordError::NotAnObject { record } => {
                write!(f, "{record}: record must be an object")
            }
            RecordError::MissingField { record, field } => {
                write!(f, "{record}: missing required field {field:?}")
            }
            RecordError::InvalidField {
                record,
                field,
                expected,
            } => write!(f, "{record}: field {field:?} must be {expected}"),
            RecordError::EmptyStatement => f.write_str("objective needs a statement"),
            RecordError::VerifierWithoutKind => {
                f.write_str("objective needs a verifier with a 'kind'")
            }
            RecordError::RewardOutOfRange { reward } => write!(
                f,
                "reward {reward} is outside the representable range \
                 (0..=18446744073709551615 units)"
            ),
            RecordError::DuplicateCitation { id } => {
                write!(f, "duplicate citation {id:?}")
            }
            RecordError::DuplicateRelation { id } => write!(
                f,
                "two relations name the target {id:?}; a claim says one thing \
                 about any other claim"
            ),
            RecordError::UnknownRelation { kind } => write!(
                f,
                "unknown relation kind {kind:?} (expected one of: refutes, \
                 fails_to_replicate, replicates, generalizes, narrows, corrects, \
                 supersedes, conflicts_with, retracts)"
            ),
            RecordError::UnknownConfidentiality { value } => write!(
                f,
                "unknown confidentiality class {value:?} (expected \
                 \"public\", \"embargoed\", or \"sealed\")"
            ),
            RecordError::SealedNotImplemented => f.write_str(
                "confidentiality \"sealed\" requires zero-knowledge verification, \
                 which is not implemented; use \"embargoed\" for delayed disclosure",
            ),
            RecordError::MalformedEnvelope { reason } => {
                write!(f, "sealed envelope cannot be decoded: {reason}")
            }
        }
    }
}

impl std::error::Error for RecordError {}

// -- helpers ---------------------------------------------------------------

fn expect_object<'a>(value: &'a Value, record: &'static str) -> Result<&'a Value, RecordError> {
    match value {
        Value::Object(_) => Ok(value),
        _ => Err(RecordError::NotAnObject { record }),
    }
}

fn required<'a>(
    value: &'a Value,
    record: &'static str,
    field: &'static str,
) -> Result<&'a Value, RecordError> {
    value
        .get(field)
        .ok_or(RecordError::MissingField { record, field })
}

fn required_string(
    value: &Value,
    record: &'static str,
    field: &'static str,
) -> Result<String, RecordError> {
    match required(value, record, field)? {
        Value::String(s) => Ok(s.clone()),
        _ => Err(RecordError::InvalidField {
            record,
            field,
            expected: "a string",
        }),
    }
}

/// Absent and explicitly-null both read as `None`, matching the reference
/// implementation's `data.get(...)`. Note the asymmetry with output: a record
/// carrying `"deadline": null` decodes to `deadline: None` and re-encodes
/// *without* the key, so its id changes. That is the reference behaviour, and
/// it is why nothing in this crate ever writes a null optional field.
fn optional_string(
    value: &Value,
    record: &'static str,
    field: &'static str,
) -> Result<Option<String>, RecordError> {
    match value.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(RecordError::InvalidField {
            record,
            field,
            expected: "a string",
        }),
    }
}

// -- confidentiality -------------------------------------------------------

/// When an objective's settled artifacts become public.
///
/// Never *whether*. The guarantee this system exists to make is that anyone can
/// re-derive every settled result, and that requires settled artifacts to be
/// readable. A class moves the moment of disclosure; it cannot remove it. The
/// one class that would — [`Sealed`](Confidentiality::Sealed) — is refused by
/// [`Objective::validate`] rather than silently weakened.
///
/// Declared per objective rather than applied as a blanket default, because
/// each class trades away a different amount of public verifiability and the
/// funder is the only party positioned to make that trade. See
/// `docs/censorship.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Confidentiality {
    /// Revealed at epoch end. The default, and what the guarantee is written
    /// for.
    #[default]
    Public,
    /// Revealed after an embargo. Priority is timestamped immediately by the
    /// commitment while the content stays sealed.
    ///
    /// The important class, and nearly free: it is what coordinated disclosure
    /// needs, and it breaks the implication "settled result ⇒ published result"
    /// that makes an auto-publishing bounty an auto-publishing zero-day
    /// pipeline.
    Embargoed,
    /// Never revealed; settlement by zero-knowledge proof only.
    ///
    /// **Not implemented**, and refused at validation. Present in the type and
    /// the schema so the limitation is explicit rather than discovered by
    /// someone who already funded an objective.
    Sealed,
}

impl Confidentiality {
    pub fn as_str(self) -> &'static str {
        match self {
            Confidentiality::Public => "public",
            Confidentiality::Embargoed => "embargoed",
            Confidentiality::Sealed => "sealed",
        }
    }

    /// Parse a class name. Unknown values are an error, never a default —
    /// guessing here would decide disclosure on the submitter's behalf.
    pub fn parse(s: &str) -> Result<Confidentiality, RecordError> {
        match s {
            "public" => Ok(Confidentiality::Public),
            "embargoed" => Ok(Confidentiality::Embargoed),
            "sealed" => Ok(Confidentiality::Sealed),
            other => Err(RecordError::UnknownConfidentiality {
                value: other.to_string(),
            }),
        }
    }

    /// Whether artifacts under this class are readable as soon as they settle.
    pub fn reveals_at_settlement(self) -> bool {
        matches!(self, Confidentiality::Public)
    }
}

impl fmt::Display for Confidentiality {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// -- objective -------------------------------------------------------------

/// A funded, checkable question.
///
/// `reward` is an integer count of the smallest unit of account. No floats
/// anywhere near money -- and here the type system enforces it, since
/// [`Value`] cannot hold one.
///
/// The id covers the verifier and the ratchet block. That is the whole point:
/// an objective is the question *plus* the machine that settles it, so changing
/// the machine yields a different objective rather than a re-scoring of work
/// already submitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Objective {
    pub goal: String,
    pub statement: String,
    /// The pinned evaluator specification. Must be an object carrying a `kind`
    /// that some registered verifier answers to.
    pub verifier: Value,
    pub reward: u64,
    pub funder: String,
    pub created_at: String,
    pub deadline: Option<String>,
    /// Optional progressive-bounty parameters (see `frontier::Ratchet`). When
    /// present the objective pays out along an improvement curve instead of
    /// once to a single winner, which is what makes immediate publication the
    /// profitable move rather than a gift to your competitors.
    pub ratchet: Option<Value>,
    /// When settled artifacts become public. Defaults to
    /// [`Confidentiality::Public`].
    ///
    /// Omitted from the canonical form when `Public`, exactly like `deadline`
    /// and `ratchet`, so adding this field did not reissue the id of a single
    /// existing objective. The conformance vectors that predate it still pass
    /// unchanged, which is the check that this is true rather than intended.
    pub confidentiality: Confidentiality,
    /// How many epochs an [`Confidentiality::Embargoed`] artifact stays shut
    /// after its commitment's epoch closes.
    ///
    /// `None` on a public objective, and on an embargoed one it is the number
    /// the class exists to name: declaring "revealed later" without saying
    /// *how much* later is a class that means nothing an auditor can check.
    ///
    /// Omitted from the canonical form when absent, exactly like `deadline`,
    /// `ratchet` and `confidentiality`, so adding it reissued no existing id.
    /// It is *inside* the id when present, which is the point — an embargo a
    /// funder could shorten after work had started would be a promise made to
    /// the submitter and then taken back.
    pub embargo_epochs: Option<u64>,
    /// What shape of artifact the verifier expects, for a submitter who has
    /// only the record.
    ///
    /// Documentation, **not** a rule. Nothing validates an artifact against it
    /// and nothing may start: the pinned verifier is the only thing that
    /// decides what passes, and a second gate here would be a second answer to
    /// that question -- one the two implementations could disagree about, on a
    /// field the funder writes.
    ///
    /// It exists because without it an agent has no honest source for the
    /// artifact's shape. The verifier spec names a checker file and a hash,
    /// not a schema; the *statement* is attacker-authored prose. An agent that
    /// had to guess would guess from the statement, which is precisely the
    /// input the rest of this design refuses to trust.
    ///
    /// Omitted when absent, like every other optional field, so adding it
    /// moved no ids.
    pub artifact_schema: Option<Value>,
    /// Refuse submissions from anyone but a signed identity.
    ///
    /// A funder who wants an authenticated bounty could previously only *ask*
    /// for one in the statement, which is prose nothing enforces. With this
    /// set, [`Node::commit`](crate::node::Node::commit) and
    /// [`reveal`](crate::node::Node::reveal) refuse any submitter that is not
    /// key-shaped -- and a key-shaped submitter already has to carry a valid
    /// signature, so the two rules compose into "every claim here is
    /// attributable to a key nobody else holds".
    ///
    /// The cost is real and belongs to the funder: it turns away contributors
    /// who have not made an identity. That is why it is per-objective and off
    /// by default rather than a network-wide switch.
    ///
    /// `false` is omitted from the canonical form, so adding this field moved
    /// no ids -- and, as with `confidentiality`, the default had to be
    /// whatever every pre-existing objective already meant.
    pub require_signed_submitter: bool,
}

impl Objective {
    /// Build a validated objective. Prefer this to a struct literal when the
    /// inputs are not already known-good; a literal skips [`validate`].
    ///
    /// [`validate`]: Objective::validate
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        goal: impl Into<String>,
        statement: impl Into<String>,
        verifier: Value,
        reward: u64,
        funder: impl Into<String>,
        created_at: impl Into<String>,
        deadline: Option<String>,
        ratchet: Option<Value>,
    ) -> Result<Objective, RecordError> {
        let objective = Objective {
            goal: goal.into(),
            statement: statement.into(),
            verifier,
            reward,
            funder: funder.into(),
            created_at: created_at.into(),
            deadline,
            ratchet,
            confidentiality: Confidentiality::Public,
            embargo_epochs: None,
            artifact_schema: None,
            require_signed_submitter: false,
        };
        objective.validate()?;
        Ok(objective)
    }

    /// Attach an artifact-shape hint, re-validating.
    ///
    /// A builder step for the same reason [`with_confidentiality`] is one:
    /// every existing caller keeps the default, and the ones that want this
    /// say so by name.
    ///
    /// [`with_confidentiality`]: Objective::with_confidentiality
    /// Refuse anyone but a signed identity. See the field.
    pub fn requiring_signed_submitters(mut self) -> Objective {
        self.require_signed_submitter = true;
        self
    }

    pub fn with_artifact_schema(mut self, schema: Value) -> Result<Objective, RecordError> {
        self.artifact_schema = Some(schema);
        self.validate()?;
        Ok(self)
    }

    /// Set the confidentiality class, re-validating.
    ///
    /// A builder step rather than a ninth positional argument to
    /// [`new`](Objective::new): every existing caller keeps the default, and
    /// the one call site that wants something else says so by name.
    pub fn with_confidentiality(
        mut self,
        confidentiality: Confidentiality,
    ) -> Result<Objective, RecordError> {
        self.confidentiality = confidentiality;
        self.validate()?;
        Ok(self)
    }

    /// Set the embargo length, re-validating.
    ///
    /// Meaningful only on an [`Confidentiality::Embargoed`] objective;
    /// [`Objective::validate`] refuses the combinations that do not make sense
    /// rather than ignoring the field, because a length silently dropped on a
    /// public objective is a funder who thinks they asked for delay.
    pub fn with_embargo_epochs(mut self, epochs: u64) -> Result<Objective, RecordError> {
        self.embargo_epochs = Some(epochs);
        self.validate()?;
        Ok(self)
    }

    /// Declare an embargo: the class and its length, together.
    ///
    /// One step because they only mean anything together. Setting the class
    /// alone leaves an objective that says "revealed later" without saying how
    /// much later — legal, because that is the shape every embargoed objective
    /// had before the length existed, and useless, because nothing can enforce
    /// it. This is the call a funder should reach for.
    pub fn with_embargo(self, epochs: u64) -> Result<Objective, RecordError> {
        self.with_confidentiality(Confidentiality::Embargoed)?
            .with_embargo_epochs(epochs)
    }

    /// Epochs an embargoed artifact stays shut after its commitment's epoch.
    ///
    /// `0` for a public objective, which is the same answer as "no wait" and
    /// lets the share rule read one number instead of branching on the class.
    pub fn embargo(&self) -> u64 {
        match self.confidentiality {
            Confidentiality::Embargoed => self.embargo_epochs.unwrap_or(0),
            _ => 0,
        }
    }

    /// The structural invariants the reference implementation checks in
    /// `__post_init__`.
    ///
    /// "reward is a non-negative integer" is absent because `u64` already says
    /// it; the equivalent check now happens once, at the decoding boundary in
    /// [`Objective::from_value`].
    pub fn validate(&self) -> Result<(), RecordError> {
        if self.statement.trim().is_empty() {
            return Err(RecordError::EmptyStatement);
        }
        match &self.verifier {
            Value::Object(map) if map.contains_key("kind") => {}
            _ => return Err(RecordError::VerifierWithoutKind),
        }
        if let Some(ratchet) = &self.ratchet {
            if ratchet.as_object().is_none() {
                return Err(RecordError::InvalidField {
                    record: "objective",
                    field: "ratchet",
                    expected: "an object",
                });
            }
        }
        // An embargo length on an objective that is not embargoed is a funder
        // who thinks they asked for delay and did not. Refused rather than
        // ignored, for the same reason `sealed` is refused rather than
        // downgraded: silently dropping the one field somebody cared about is
        // the failure they cannot see.
        if self.embargo_epochs.is_some() && self.confidentiality != Confidentiality::Embargoed {
            return Err(RecordError::InvalidField {
                record: "objective",
                field: "embargo_epochs",
                expected: "an embargoed objective; a length has no meaning without one",
            });
        }
        // An explicit zero is `public` wearing a longer name: an artifact
        // readable in the epoch after its commitment is on the normal reveal
        // schedule. Refused so the number means what it says.
        //
        // An *absent* length is a different thing and is allowed: that is the
        // shape every embargoed objective had before this field existed, when
        // the class was a label nothing enforced. Refusing it would make old
        // logs undecodable to settle a point about new ones. So the presence
        // of the number is what turns enforcement on, exactly as the presence
        // of an issuance is what turns the supply accounting on.
        if self.embargo_epochs == Some(0) {
            return Err(RecordError::InvalidField {
                record: "objective",
                field: "embargo_epochs",
                expected: "at least one epoch; zero is what `public` already means",
            });
        }
        // Shape only. What the hint *says* is never checked -- the pinned
        // verifier decides what passes, and validating an artifact against
        // this would be a second answer to that question.
        if let Some(schema) = &self.artifact_schema {
            if schema.as_object().is_none() {
                return Err(RecordError::InvalidField {
                    record: "objective",
                    field: "artifact_schema",
                    expected: "an object",
                });
            }
        }
        // Refused, not downgraded. Paying for an artifact nobody may read needs
        // a ZK proof that the pinned verifier accepts it; quietly treating the
        // request as `embargoed` would tell a funder their result stays secret
        // when it does not.
        if self.confidentiality == Confidentiality::Sealed {
            return Err(RecordError::SealedNotImplemented);
        }
        Ok(())
    }

    /// The verifier `kind`, if the verifier is well formed. Callers route on
    /// this to find a registered checker; an objective with no answering
    /// verifier must be refused rather than posted.
    pub fn verifier_kind(&self) -> Option<&str> {
        self.verifier.get("kind").and_then(Value::as_str)
    }

    /// Canonical form. Optional fields are omitted when unset -- see the module
    /// docs for why nulling them instead would reissue every id in the network.
    pub fn to_value(&self) -> Value {
        let mut body: BTreeMap<String, Value> = BTreeMap::new();
        body.insert(
            "type".to_string(),
            Value::string(RecordKind::Objective.as_str()),
        );
        body.insert("goal".to_string(), Value::string(self.goal.clone()));
        body.insert(
            "statement".to_string(),
            Value::string(self.statement.clone()),
        );
        body.insert("verifier".to_string(), self.verifier.clone());
        // Widening u64 -> i128 is total, so no check is needed on the way out.
        // The only place reward arithmetic can fail is the way in.
        body.insert("reward".to_string(), Value::Int(i128::from(self.reward)));
        body.insert("funder".to_string(), Value::string(self.funder.clone()));
        body.insert(
            "created_at".to_string(),
            Value::string(self.created_at.clone()),
        );
        if let Some(deadline) = &self.deadline {
            body.insert("deadline".to_string(), Value::string(deadline.clone()));
        }
        if let Some(ratchet) = &self.ratchet {
            body.insert("ratchet".to_string(), ratchet.clone());
        }
        // Omitted when `Public`, for the same reason `deadline` and `ratchet`
        // are omitted when unset: emitting the default would change the digest
        // of every objective ever written, breaking the conformance vectors and
        // orphaning every claim already posted against a live bounty.
        if self.confidentiality != Confidentiality::Public {
            body.insert(
                "confidentiality".to_string(),
                Value::string(self.confidentiality.as_str()),
            );
        }
        // Inside the id when present, omitted when absent. Inside, because an
        // embargo a funder could shorten after work had started is a promise
        // made to a submitter and then taken back; omitted, because every
        // objective written before this field existed had no embargo and its
        // digest must not move.
        if let Some(epochs) = self.embargo_epochs {
            body.insert("embargo_epochs".to_string(), Value::Int(i128::from(epochs)));
        }
        // Omitted when absent, for the reason every optional field here is.
        if let Some(schema) = &self.artifact_schema {
            body.insert("artifact_schema".to_string(), schema.clone());
        }
        // Omitted when false: that is what every objective written before this
        // field existed meant, so emitting it would move every id.
        if self.require_signed_submitter {
            body.insert("require_signed_submitter".to_string(), Value::Bool(true));
        }
        Value::Object(body)
    }

    /// Content address of the whole record, verifier and ratchet included.
    pub fn id(&self) -> String {
        self.to_value().digest()
    }

    /// Decode a record. The `type` tag is not required or checked, matching the
    /// reference implementation: the log has already dispatched on entry kind
    /// by the time this runs, and the shipped `examples/*/objective.json` files
    /// carry no tag at all.
    pub fn from_value(value: &Value) -> Result<Objective, RecordError> {
        const RECORD: &str = "objective";
        let value = expect_object(value, RECORD)?;

        let raw_reward = required(value, RECORD, "reward")?;
        // `as_i128` returns None for booleans, which is what rejects Python's
        // `isinstance(reward, bool)` case -- `True` is not one unit of money.
        let reward = raw_reward.as_i128().ok_or(RecordError::InvalidField {
            record: RECORD,
            field: "reward",
            expected: "an integer unit count",
        })?;
        let reward = u64::try_from(reward).map_err(|_| RecordError::RewardOutOfRange { reward })?;

        let ratchet = match value.get("ratchet") {
            None | Some(Value::Null) => None,
            Some(other) => Some(other.clone()),
        };

        let confidentiality = match value.get("confidentiality") {
            None | Some(Value::Null) => Confidentiality::Public,
            Some(Value::String(s)) => Confidentiality::parse(s)?,
            Some(_) => {
                return Err(RecordError::InvalidField {
                    record: RECORD,
                    field: "confidentiality",
                    expected: "a string naming a confidentiality class",
                })
            }
        };

        let embargo_epochs = match value.get("embargo_epochs") {
            None | Some(Value::Null) => None,
            Some(Value::Int(epochs)) if *epochs >= 0 && *epochs <= i128::from(u64::MAX) => {
                Some(*epochs as u64)
            }
            Some(_) => {
                return Err(RecordError::InvalidField {
                    record: RECORD,
                    field: "embargo_epochs",
                    expected: "a non-negative integer number of epochs",
                })
            }
        };

        // Absent and null both mean "no hint", exactly as for `ratchet`.
        let artifact_schema = match value.get("artifact_schema") {
            None | Some(Value::Null) => None,
            Some(other) => Some(other.clone()),
        };

        let objective = Objective {
            goal: required_string(value, RECORD, "goal")?,
            statement: required_string(value, RECORD, "statement")?,
            verifier: required(value, RECORD, "verifier")?.clone(),
            reward,
            funder: required_string(value, RECORD, "funder")?,
            created_at: required_string(value, RECORD, "created_at")?,
            deadline: optional_string(value, RECORD, "deadline")?,
            ratchet,
            confidentiality,
            embargo_epochs,
            require_signed_submitter: match value.get("require_signed_submitter") {
                None | Some(Value::Null) => false,
                Some(Value::Bool(flag)) => *flag,
                // Refused rather than coerced: "1" or "yes" meaning true here
                // and false in the other implementation is a split over which
                // submissions are admissible.
                Some(_) => {
                    return Err(RecordError::InvalidField {
                        record: RECORD,
                        field: "require_signed_submitter",
                        expected: "a boolean",
                    })
                }
            },
            artifact_schema,
        };
        objective.validate()?;
        Ok(objective)
    }
}

// -- commitment ------------------------------------------------------------

/// Binding commitment to an artifact, revealed later.
///
/// Without this, a plaintext artifact is stolen by the first party who sees it
/// -- the solver does the work and someone else collects. The submitter is
/// bound into the hash so the commitment cannot be replayed by an observer
/// under their own name; the nonce keeps a guessable artifact (`{"n": 42}`)
/// from being brute-forced out of the commitment before it is revealed.
///
/// The construction is `sha256(digest({objective_id, artifact}) | submitter |
/// nonce)`, with literal `|` bytes between the three parts. The inner digest is
/// taken first so the outer input is fixed-length in its artifact component,
/// and the separators keep `("ab", "c")` from colliding with `("a", "bc")`.
/// These bytes are consensus-critical: see `commitment_hash_cases` in
/// `conformance/vectors.json`.
pub fn commitment_hash(
    objective_id: &str,
    submitter: &str,
    artifact: &Value,
    nonce: &str,
) -> String {
    let inner = Value::Object(BTreeMap::from([
        (
            "objective_id".to_string(),
            Value::string(objective_id.to_string()),
        ),
        ("artifact".to_string(), artifact.clone()),
    ]))
    .digest();

    let mut buf = Vec::with_capacity(inner.len() + submitter.len() + nonce.len() + 2);
    buf.extend_from_slice(inner.as_bytes());
    buf.push(b'|');
    buf.extend_from_slice(submitter.as_bytes());
    buf.push(b'|');
    buf.extend_from_slice(nonce.as_bytes());
    digest_bytes(&buf)
}

/// The public key a submitter name commits to, when it is one.
///
/// `submitter` has always been a free string, which means a name is worth
/// exactly nothing: anyone can submit as `alice`, and under citation flow that
/// name is being paid. This is the rule that fixes it without a registry, a
/// new record kind, or a migration.
///
/// **A submitter that is 64 lowercase hex characters is an ed25519 public key,
/// and a record carrying one must be signed by it.** Anything else is an
/// unauthenticated nickname and stays exactly as permissive as it always was.
///
/// The binding needs no state to look up because the name *is* the key, which
/// is what [`crate::crypto::identity::Identity::submitter_id`] has produced
/// all along. Two consequences worth being explicit about:
///
/// * Existing logs keep working. `alice` is not hex, so nothing is required of
///   it and no pre-existing record changes meaning. Stage 0 stays usable.
/// * A signed identity cannot be stolen. Forging a claim as
///   `8a88e3dd…` needs that key, and taking the name means taking the key.
///
/// What it does *not* do: stop anyone claiming an unsigned nickname, and stop
/// someone registering a key nobody has heard of. It makes an identity
/// unforgeable once used, which is what citation flow needs, rather than
/// making it *attributable to a person*, which nothing at this layer can do.
///
/// Lowercase only, and exactly 64 characters. Accepting mixed case would make
/// `AB…` and `ab…` two names for one key, so the same key could hold two
/// reputations and cite itself.
pub fn signed_submitter(submitter: &str) -> Option<&str> {
    let is_key = submitter.len() == 64
        && submitter
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    is_key.then_some(submitter)
}

/// Why a record's signature was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureError {
    /// The submitter names a key, and the record carries no signature.
    Missing {
        record: &'static str,
        submitter: String,
    },
    /// The submitter is not a usable key, or the signature is malformed or
    /// wrong. One variant deliberately: an attacker learns nothing from which
    /// of those it was, and a caller cannot act on the difference.
    Invalid {
        record: &'static str,
        submitter: String,
    },
}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignatureError::Missing { record, submitter } => write!(
                f,
                "{record} submitter {} is a public key, so the record must carry a \
                 signature from it; sign it or submit under a name that is not a key",
                crate::canonical::short(submitter)
            ),
            SignatureError::Invalid { record, submitter } => write!(
                f,
                "{record} signature does not verify under submitter {}",
                crate::canonical::short(submitter)
            ),
        }
    }
}

impl std::error::Error for SignatureError {}

/// The shared rule behind `Commitment::verify_signature` and `Claim`'s.
///
/// Kept in one place because the two must agree exactly: a rule enforced
/// slightly differently on commitments and claims is a rule an attacker gets
/// to choose between.
fn verify_record_signature(
    record: &'static str,
    submitter: &str,
    payload: &Value,
    signature: Option<&str>,
) -> Result<(), SignatureError> {
    use crate::crypto::identity::{verify_value, Signature, VerifyingKeyBytes};

    let Some(key_hex) = signed_submitter(submitter) else {
        // A nickname. Nothing is claimed and nothing is checked -- but a
        // signature attached to one is still refused below rather than
        // ignored, so it cannot look like authentication it is not.
        return match signature {
            None => Ok(()),
            Some(_) => Err(SignatureError::Invalid {
                record,
                submitter: submitter.to_string(),
            }),
        };
    };

    let Some(signature) = signature else {
        return Err(SignatureError::Missing {
            record,
            submitter: submitter.to_string(),
        });
    };
    let invalid = || SignatureError::Invalid {
        record,
        submitter: submitter.to_string(),
    };
    let key = VerifyingKeyBytes::from_hex(key_hex).map_err(|_| invalid())?;
    let signature = Signature::from_hex(signature).map_err(|_| invalid())?;
    verify_value(key.as_bytes(), payload, &signature).map_err(|_| invalid())
}

/// Phase 1: bind to an artifact without revealing it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commitment {
    pub objective_id: String,
    pub submitter: String,
    /// Output of [`commitment_hash`]. Opaque to the ledger until the matching
    /// [`Claim`] reproduces it — or until the epoch's committee opens
    /// [`Commitment::envelope`] without the submitter.
    pub hash: String,
    pub created_at: String,
    /// The artifact and its nonce, sealed to the epoch's committee.
    ///
    /// **Present makes this a sealed submission**, which is the only kind that
    /// can be revealed by anyone other than the submitter. Absent is plain
    /// commit–reveal, unchanged, and the submitter must come back with the
    /// artifact themselves — the failure `docs/censorship.md` §1 describes,
    /// where stopping their second action takes their bounty.
    ///
    /// Omitted from the canonical form when absent, exactly like `signature`
    /// and `Objective::confidentiality`, so adding this field moved no ids:
    /// every commitment written before it existed digests to what it always
    /// did, and no claim posted against a live bounty is orphaned.
    ///
    /// It is inside [`Commitment::signing_payload`] rather than beside it. The
    /// envelope's own `aad` is the commitment hash, so the binding already runs
    /// one way; covering it by the signature runs it the other, and means a
    /// sequencer cannot strip a submitter's envelope to force them back onto
    /// the path where censorship works.
    pub envelope: Option<crate::crypto::envelope::SealedEnvelope>,
    /// Ed25519 signature over this record, hex, or `None`.
    ///
    /// Omitted from the canonical form when absent, so adding this field moved
    /// no ids: every record written before it existed digests to exactly what
    /// it always did. See [`signed_submitter`] for when one is *required*.
    pub signature: Option<String>,
}

impl Commitment {
    pub fn new(
        objective_id: impl Into<String>,
        submitter: impl Into<String>,
        hash: impl Into<String>,
        created_at: impl Into<String>,
    ) -> Commitment {
        Commitment {
            objective_id: objective_id.into(),
            submitter: submitter.into(),
            hash: hash.into(),
            created_at: created_at.into(),
            envelope: None,
            signature: None,
        }
    }

    /// Attach a sealed envelope, making this a submission the committee can
    /// open without the submitter.
    ///
    /// Call before [`Commitment::signed_with`]: the signature covers the
    /// envelope, so attaching one afterwards invalidates it.
    pub fn sealed_with(mut self, envelope: crate::crypto::envelope::SealedEnvelope) -> Commitment {
        self.envelope = Some(envelope);
        self
    }

    pub fn to_value(&self) -> Value {
        let mut value = self.signing_payload();
        if let (Value::Object(map), Some(signature)) = (&mut value, &self.signature) {
            map.insert("signature".to_string(), Value::string(signature.clone()));
        }
        value
    }

    /// The bytes a signature covers: this record without its own signature.
    ///
    /// Excluded rather than zeroed, because a signature over a field holding
    /// that signature is not something anyone can produce. The record's `id`
    /// still covers the signature, so a signed record and its unsigned twin
    /// are different records -- which is what stops a signature being stripped
    /// without changing the id anyone cited.
    pub fn signing_payload(&self) -> Value {
        let mut value = Value::object([
            ("type", Value::string(RecordKind::Commitment.as_str())),
            ("objective_id", Value::string(self.objective_id.clone())),
            ("submitter", Value::string(self.submitter.clone())),
            ("hash", Value::string(self.hash.clone())),
            ("created_at", Value::string(self.created_at.clone())),
        ]);
        // Inserted only when present. `envelope: null` and no `envelope` key
        // are *not* interchangeable -- they are different bytes and therefore
        // different ids -- so an unsealed commitment must emit neither.
        if let (Value::Object(map), Some(envelope)) = (&mut value, &self.envelope) {
            map.insert("envelope".to_string(), envelope.to_value());
        }
        value
    }

    pub fn id(&self) -> String {
        self.to_value().digest()
    }

    /// Sign this record with `identity`, returning the signed copy.
    ///
    /// The signature covers [`Commitment::signing_payload`], so the resulting
    /// record's `id` covers the signature in turn.
    pub fn signed_with(mut self, identity: &crate::crypto::identity::Identity) -> Commitment {
        self.submitter = identity.submitter_id();
        self.signature = Some(identity.sign_value(&self.signing_payload()).to_hex());
        self
    }

    /// Check the signature this record carries, if the rules demand one.
    ///
    /// See [`signed_submitter`] for when that is. Returns `Ok(())` for a
    /// nickname-shaped submitter, which is Stage-0 behaviour unchanged.
    pub fn verify_signature(&self) -> Result<(), SignatureError> {
        verify_record_signature(
            "commitment",
            &self.submitter,
            &self.signing_payload(),
            self.signature.as_deref(),
        )
    }

    /// Decode a commitment from a log payload. The reference implementation
    /// reads these payloads as raw dicts; a typed decoder is the Rust-side
    /// equivalent and keeps the field names in one place.
    pub fn from_value(value: &Value) -> Result<Commitment, RecordError> {
        const RECORD: &str = "commitment";
        let object = expect_object(value, RECORD)?;
        let envelope = match object.get("envelope") {
            None => None,
            Some(raw) => Some(
                crate::crypto::envelope::SealedEnvelope::from_value(raw).map_err(|error| {
                    RecordError::MalformedEnvelope {
                        reason: error.to_string(),
                    }
                })?,
            ),
        };
        Ok(Commitment {
            objective_id: required_string(object, RECORD, "objective_id")?,
            submitter: required_string(object, RECORD, "submitter")?,
            hash: required_string(object, RECORD, "hash")?,
            created_at: required_string(object, RECORD, "created_at")?,
            envelope,
            signature: optional_string(object, RECORD, "signature")?,
        })
    }
}

// -- committee share -------------------------------------------------------

/// One committee member opening its share of a sealed submission's content key.
///
/// # This is the record that makes the reveal consensus-derived
///
/// `docs/censorship.md` §2 said "at the epoch boundary `t` committee members
/// publish their shares", and until this record existed there was nowhere for
/// them to publish it. The committee lived entirely in
/// [`crate::crypto::envelope`], the epoch boundary was whatever a member's
/// local clock said, and *which* peers were on the committee was whatever the
/// submitter chose to seal to. All three were unauditable: nothing in the log
/// let a reader decide whether a reveal had happened on time, or at all, or by
/// the right parties.
///
/// Putting the share on the log fixes each one with a rule a reader re-derives
/// rather than trusts, and [`crate::node::Node::check_committee_share`] is
/// where all three are enforced:
///
/// - **Who.** The committee is a beacon draw over the log's peer records
///   ([`crate::node::Node::committee_for`]), so a share is admissible only from
///   a seat the draw actually produced. Nobody issues an invitation and nobody
///   can decline to send one.
/// - **When.** A share's epoch comes from its own `created_at`, and must be
///   strictly later than the epoch of the commitment it opens — the same rule a
///   submitter-driven reveal obeys, applied to the committee. "Too early" is
///   therefore a fact about two records rather than a claim about a clock.
/// - **What.** The share is a plaintext Shamir point. It is not individually
///   checkable, and that is a property of the scheme rather than an omission —
///   see the note on verifiable secret sharing in
///   [`crate::node::Node::open_sealed`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitteeShare {
    /// The id of the commitment record whose envelope this share opens.
    pub commitment: String,
    /// Which committee seat this share is for: the routing index the draw
    /// assigned, and the index the envelope addressed the sealed share at.
    ///
    /// Derived by the checker as well as carried here, so a member cannot claim
    /// a seat that was drawn for somebody else — the field says which seat is
    /// being *answered*, and the draw says whether this identity holds it.
    pub seat: u8,
    /// The Shamir x-coordinate of the share.
    ///
    /// Not the same number as `seat`, and conflating them is the bug this
    /// separation exists to prevent: `seat` addresses a member within the
    /// envelope, `x` is the polynomial's abscissa. The envelope keeps the
    /// x-coordinate *inside* the sealed share precisely so a relabelled share
    /// is a tag failure rather than a wrong reconstruction, and republishing it
    /// here is how the combiner gets it back.
    pub x: u8,
    /// The share body, hex.
    pub share: String,
    pub created_at: String,
    /// Ed25519 public key of the publishing member, hex.
    ///
    /// The peer record's `identity`, not its `transport`: the transport id
    /// names a McEliece key, which signs nothing. The draw is over transport
    /// ids and the signature is over this, and the peer record is what ties the
    /// two together — which is exactly the job it was already doing for dialing.
    pub identity: String,
    /// Ed25519 signature over [`CommitteeShare::signing_payload`], hex.
    ///
    /// **Required.** A share record's whole purpose is to be attributable: an
    /// unsigned one is an anonymous assertion that a seat published, which
    /// anyone could write for any member and which would let a bystander stall
    /// a reveal by filling every seat with garbage.
    pub signature: Option<String>,
}

/// Longest share body a committee share may carry, in bytes before hex.
///
/// The share of a 32-byte content key is 32 bytes; the ceiling is generous
/// rather than exact so that a future envelope sealing a longer secret does not
/// need a consensus change, and bounded rather than unbounded so that a record
/// cannot be used to write a megabyte into every node's log for free.
pub const MAX_SHARE_BYTES: usize = 1024;

impl CommitteeShare {
    pub fn new(
        commitment: impl Into<String>,
        seat: u8,
        x: u8,
        share: impl Into<String>,
        created_at: impl Into<String>,
    ) -> CommitteeShare {
        CommitteeShare {
            commitment: commitment.into(),
            seat,
            x,
            share: share.into(),
            created_at: created_at.into(),
            identity: String::new(),
            signature: None,
        }
    }

    /// The bytes a signature covers: this record without its own signature.
    pub fn signing_payload(&self) -> Value {
        Value::object([
            ("type", Value::string(RecordKind::CommitteeShare.as_str())),
            ("commitment", Value::string(self.commitment.clone())),
            ("created_at", Value::string(self.created_at.clone())),
            ("identity", Value::string(self.identity.clone())),
            ("seat", Value::Int(i128::from(self.seat))),
            ("share", Value::string(self.share.clone())),
            ("x", Value::Int(i128::from(self.x))),
        ])
    }

    pub fn to_value(&self) -> Value {
        let mut value = self.signing_payload();
        if let (Value::Object(map), Some(signature)) = (&mut value, &self.signature) {
            map.insert("signature".to_string(), Value::string(signature.clone()));
        }
        value
    }

    pub fn id(&self) -> String {
        self.to_value().digest()
    }

    /// Sign with `identity`, which becomes the record's `identity` field.
    pub fn signed_with(mut self, identity: &crate::crypto::identity::Identity) -> CommitteeShare {
        self.identity = identity.submitter_id();
        self.signature = Some(identity.sign_value(&self.signing_payload()).to_hex());
        self
    }

    /// Check the signature. Always required — see the field's documentation.
    pub fn verify_signature(&self) -> Result<(), SignatureError> {
        const RECORD: &str = "committee_share";
        if signed_submitter(&self.identity).is_none() {
            return Err(SignatureError::Invalid {
                record: RECORD,
                submitter: self.identity.clone(),
            });
        }
        let Some(signature) = self.signature.as_deref() else {
            return Err(SignatureError::Missing {
                record: RECORD,
                submitter: self.identity.clone(),
            });
        };
        verify_record_signature(
            RECORD,
            &self.identity,
            &self.signing_payload(),
            Some(signature),
        )
    }

    /// The share as the secret-sharing layer wants it.
    pub fn to_share(&self) -> Result<crate::crypto::shamir::Share, RecordError> {
        Ok(crate::crypto::shamir::Share {
            index: self.x,
            data: decode_hex(&self.share).ok_or(RecordError::InvalidField {
                record: "committee_share",
                field: "share",
                expected: "lowercase hex of even length",
            })?,
        })
    }

    /// Structural rules, checked before the signature is looked at.
    pub fn validate(&self) -> Result<(), RecordError> {
        const RECORD: &str = "committee_share";
        let invalid = |field: &'static str, expected: &'static str| RecordError::InvalidField {
            record: RECORD,
            field,
            expected,
        };
        // A record id, so `sha256:` followed by 64 lowercase hex — the shape
        // `canonical::digest_bytes` produces. Checked rather than left free
        // because a share naming an id no commitment can ever have is a record
        // that will sit in the log forever being skipped, and the writer would
        // never find out why.
        let hex = self
            .commitment
            .strip_prefix(crate::canonical::DIGEST_PREFIX)
            .unwrap_or_default();
        if hex.len() != 64 || decode_hex(hex).is_none() {
            return Err(invalid(
                "commitment",
                "a commitment record id: \"sha256:\" and 64 lowercase hex characters",
            ));
        }
        if self.identity.len() != 64 || decode_hex(&self.identity).is_none() {
            return Err(invalid(
                "identity",
                "64 lowercase hex characters of an ed25519 public key",
            ));
        }
        // Zero is refused because it is the one x-coordinate that is not a
        // share: `f(0)` *is* the secret, so a share claiming to sit there is
        // either a mistake or an attempt to publish the content key itself
        // under the cover of a share record. `shamir::split` never issues it.
        if self.x == 0 {
            return Err(invalid("x", "a non-zero Shamir x-coordinate"));
        }
        let share =
            decode_hex(&self.share).ok_or(invalid("share", "lowercase hex of even length"))?;
        if share.is_empty() || share.len() > MAX_SHARE_BYTES {
            return Err(invalid(
                "share",
                "between 1 and MAX_SHARE_BYTES bytes of share body",
            ));
        }
        Ok(())
    }

    pub fn from_value(value: &Value) -> Result<CommitteeShare, RecordError> {
        const RECORD: &str = "committee_share";
        let object = expect_object(value, RECORD)?;
        let small = |field: &'static str| -> Result<u8, RecordError> {
            object
                .get(field)
                .and_then(Value::as_i128)
                .and_then(|n| u8::try_from(n).ok())
                .ok_or(RecordError::InvalidField {
                    record: RECORD,
                    field,
                    expected: "an integer in 0..=255",
                })
        };
        Ok(CommitteeShare {
            commitment: required_string(object, RECORD, "commitment")?,
            seat: small("seat")?,
            x: small("x")?,
            share: required_string(object, RECORD, "share")?,
            created_at: required_string(object, RECORD, "created_at")?,
            identity: required_string(object, RECORD, "identity")?,
            signature: optional_string(object, RECORD, "signature")?,
        })
    }
}

/// Strict, lowercase-only hex. Same rule as everywhere else in this crate:
/// accepting `AB` as well as `ab` would give one share two spellings and
/// therefore one record two ids.
fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let nibble = |b: u8| match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    };
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| Some((nibble(pair[0])? << 4) | nibble(pair[1])?))
        .collect()
}

// -- claim relations -------------------------------------------------------

/// How one claim stands to an earlier one, beyond "built on".
///
/// # Why this is not just another citation
///
/// `cites` says *I used this*, and it moves money: attribution flows value back
/// along those edges. A relation says *this is what I found about that*, and it
/// moves **nothing**. The separation is the whole security argument. If
/// declaring "I refute X" paid, refutation would be a way to bill X; if it
/// demoted X on the frontier, it would be a way to steal X's bounty. So
/// [`crate::attribution`] walks `cites` and never reads this field, settlement
/// never reads it, and the frontier never reads it. What reads it is
/// [`crate::knowledge`], which computes a *view* nobody has to agree with.
///
/// # Why these nine and not the fourteen an evidence graph usually lists
///
/// "Supports", "depends on", "uses dataset" and "uses methodology" are all
/// `cites` — a second spelling for the paying edge would mean two ways to say
/// one thing, only one of which pays, and submitters would learn which. And a
/// relation earns its place here only by having a distinct mechanical effect in
/// [`crate::knowledge::Standing`]; "reinterprets" has none, so it would be a
/// comment with a schema, which is worse than a comment.
///
/// # A relation cannot point forward, and nothing had to enforce that
///
/// A claim's id covers its relations, so naming a target requires knowing the
/// target's id, which requires the target to already exist. Self-reference is
/// impossible for the same reason: computing your own id would require it as an
/// input. This is the hash-linking doing the work a validity rule would
/// otherwise have to do — the same reason `cites` is acyclic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Relation {
    /// The target is wrong, and this claim is the demonstration.
    Refutes,
    /// This claim ran the target's procedure and did not get its result.
    /// Weaker than [`Relation::Refutes`]: a failure to reproduce is evidence
    /// against, not a disproof.
    FailsToReplicate,
    /// This claim ran the target's procedure and got its result.
    Replicates,
    /// The target's result holds more broadly than it stated.
    Generalizes,
    /// The target's result holds, but on a smaller scope than it stated.
    Narrows,
    /// The target contains an error this claim fixes; what remains still
    /// stands.
    Corrects,
    /// The target is replaced wholesale by this claim.
    Supersedes,
    /// Both cannot hold, and this claim does not settle which. Distinct from
    /// [`Relation::Refutes`], which asserts an answer.
    ConflictsWith,
    /// The submitter withdraws their own earlier claim. Only meaningful from
    /// the same submitter; see [`crate::knowledge`] for what happens when
    /// somebody points it at a claim that is not theirs.
    Retracts,
}

impl Relation {
    /// The wire spelling. Consensus-relevant: it is inside the claim's id.
    pub const fn as_str(self) -> &'static str {
        match self {
            Relation::Refutes => "refutes",
            Relation::FailsToReplicate => "fails_to_replicate",
            Relation::Replicates => "replicates",
            Relation::Generalizes => "generalizes",
            Relation::Narrows => "narrows",
            Relation::Corrects => "corrects",
            Relation::Supersedes => "supersedes",
            Relation::ConflictsWith => "conflicts_with",
            Relation::Retracts => "retracts",
        }
    }

    /// Decode a wire spelling. `None` for anything unrecognized.
    ///
    /// Refused rather than preserved-and-ignored, and this is the opposite of
    /// the choice a cryptographic envelope makes about an unknown algorithm.
    /// The reason is that an envelope's unknown suite is *inert* — an old
    /// client cannot verify it and says so — whereas an unknown relation would
    /// be read by one implementation's knowledge view and skipped by another's,
    /// so the two would report different standings for the same claim from the
    /// same log. A new relation kind is a protocol change, and should be
    /// visible as one.
    pub fn from_wire(text: &str) -> Option<Relation> {
        match text {
            "refutes" => Some(Relation::Refutes),
            "fails_to_replicate" => Some(Relation::FailsToReplicate),
            "replicates" => Some(Relation::Replicates),
            "generalizes" => Some(Relation::Generalizes),
            "narrows" => Some(Relation::Narrows),
            "corrects" => Some(Relation::Corrects),
            "supersedes" => Some(Relation::Supersedes),
            "conflicts_with" => Some(Relation::ConflictsWith),
            "retracts" => Some(Relation::Retracts),
            _ => None,
        }
    }

    /// Every kind, for schema generation and exhaustiveness tests.
    pub const ALL: [Relation; 9] = [
        Relation::Refutes,
        Relation::FailsToReplicate,
        Relation::Replicates,
        Relation::Generalizes,
        Relation::Narrows,
        Relation::Corrects,
        Relation::Supersedes,
        Relation::ConflictsWith,
        Relation::Retracts,
    ];
}

impl fmt::Display for Relation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One typed edge: what this claim says about `target`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClaimRelation {
    pub kind: Relation,
    /// The claim being spoken about.
    pub target: String,
}

impl ClaimRelation {
    pub fn new(kind: Relation, target: impl Into<String>) -> ClaimRelation {
        ClaimRelation {
            kind,
            target: target.into(),
        }
    }

    pub fn to_value(&self) -> Value {
        Value::object([
            ("kind", Value::string(self.kind.as_str())),
            ("target", Value::string(self.target.clone())),
        ])
    }

    pub fn from_value(value: &Value) -> Result<ClaimRelation, RecordError> {
        const RECORD: &str = "claim";
        let object = expect_object(value, RECORD)?;
        let kind = required_string(object, RECORD, "kind")?;
        let kind = Relation::from_wire(&kind).ok_or(RecordError::UnknownRelation { kind })?;
        let target = required_string(object, RECORD, "target")?;
        if target.is_empty() {
            return Err(RecordError::InvalidField {
                record: RECORD,
                field: "relations",
                expected: "a non-empty target claim id",
            });
        }
        // A relation is a closed two-field object, and an unknown key is
        // refused rather than ignored. Ignoring it would be worse than untidy:
        // this decoder feeds `to_value`, which emits `kind` and `target` and
        // nothing else, so a record admitted carrying a third key would be
        // *stored* under a different digest than the one it arrived with. The
        // published schema says `additionalProperties: false` here for the same
        // reason, and a decoder laxer than the schema is a second, quieter
        // answer to what a record is.
        //
        // Found by `scripts/differential.sh` on the first run after this field
        // landed: the reference implementation refused the extra key and this
        // one accepted it.
        if let Some(map) = object.as_object() {
            for key in map.keys() {
                if key != "kind" && key != "target" {
                    return Err(RecordError::InvalidField {
                        record: RECORD,
                        field: "relations",
                        expected: "an object with exactly `kind` and `target`",
                    });
                }
            }
        }
        Ok(ClaimRelation { kind, target })
    }
}

// -- claim -----------------------------------------------------------------

/// Phase 2: reveal the artifact, with the citations it builds on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    pub objective_id: String,
    pub submitter: String,
    /// The revealed work. An object, so that a verifier reads named fields
    /// rather than guessing at a bare scalar.
    pub artifact: Value,
    pub nonce: String,
    pub created_at: String,
    /// Claim ids this one builds on. A set, not a list: duplicates are refused.
    pub cites: Vec<String>,
    /// What this claim asserts *about* earlier claims — refutes, replicates,
    /// supersedes, and so on. Empty for almost every claim.
    ///
    /// Omitted from the canonical form when empty, which is the only reason
    /// this field could be added at all: every claim ever written predates it
    /// and carries none, so every existing id is unchanged and the frozen
    /// conformance vectors still pass byte-for-byte. `cites` could *not* have
    /// been added this way — it is emitted even when empty, deliberately, so
    /// that one claim cannot have two ids depending on how it was built. The
    /// difference is that `cites` was there from the start and this was not.
    ///
    /// It is inside [`Claim::signing_payload`], so a relation cannot be added
    /// to or stripped from a signed claim by anyone but its author. That is not
    /// optional: an attacker who could append `retracts` to somebody else's
    /// signed claim could withdraw their work.
    pub relations: Vec<ClaimRelation>,
    /// Ed25519 signature over this record, hex, or `None`. Omitted from the
    /// canonical form when absent, so adding it moved no ids. See
    /// [`signed_submitter`].
    pub signature: Option<String>,
}

impl Claim {
    /// Build a validated claim. Argument order matches the reference
    /// implementation's positional constructor.
    pub fn new(
        objective_id: impl Into<String>,
        submitter: impl Into<String>,
        artifact: Value,
        nonce: impl Into<String>,
        created_at: impl Into<String>,
        cites: Vec<String>,
    ) -> Result<Claim, RecordError> {
        let claim = Claim {
            objective_id: objective_id.into(),
            submitter: submitter.into(),
            artifact,
            nonce: nonce.into(),
            created_at: created_at.into(),
            cites,
            relations: Vec::new(),
            signature: None,
        };
        claim.validate()?;
        Ok(claim)
    }

    /// Attach typed relations, returning the amended claim.
    ///
    /// Separate from [`Claim::new`] rather than a tenth positional argument,
    /// because the reference implementation's constructor takes the original
    /// six and the two must stay callable the same way.
    pub fn relating(mut self, relations: Vec<ClaimRelation>) -> Result<Claim, RecordError> {
        self.relations = relations;
        self.validate()?;
        Ok(self)
    }

    /// Reject a malformed artifact, repeated citations, and a claim that says
    /// two things about one target.
    ///
    /// The duplicate-citation check is not tidiness. Attribution walks the
    /// citation DAG and splits credit across a claim's edges; the same parent
    /// listed twice would draw twice the flow, which is a way of paying
    /// yourself for one input.
    ///
    /// Relations are keyed on the **target alone**, not on `(kind, target)`, so
    /// one claim may say exactly one thing about any other claim. Allowing two
    /// would mean deciding what `refutes` *and* `replicates` on one target
    /// means, and any such table is a rule two implementations can read
    /// differently — a consensus split bought with expressiveness nobody asked
    /// for. A claim needing to say two things about one target is two claims.
    pub fn validate(&self) -> Result<(), RecordError> {
        if self.artifact.as_object().is_none() {
            return Err(RecordError::InvalidField {
                record: "claim",
                field: "artifact",
                expected: "an object",
            });
        }
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for cited in &self.cites {
            if !seen.insert(cited.as_str()) {
                return Err(RecordError::DuplicateCitation { id: cited.clone() });
            }
        }
        let mut targets: BTreeSet<&str> = BTreeSet::new();
        for relation in &self.relations {
            if relation.target.is_empty() {
                return Err(RecordError::InvalidField {
                    record: "claim",
                    field: "relations",
                    expected: "a non-empty target claim id",
                });
            }
            if !targets.insert(relation.target.as_str()) {
                return Err(RecordError::DuplicateRelation {
                    id: relation.target.clone(),
                });
            }
        }
        Ok(())
    }

    /// Canonical form. `cites` is always present, empty list included: it is
    /// not an optional field, and omitting it when empty would give the same
    /// claim two different ids depending on how it was built.
    pub fn to_value(&self) -> Value {
        let mut value = self.signing_payload();
        if let (Value::Object(map), Some(signature)) = (&mut value, &self.signature) {
            map.insert("signature".to_string(), Value::string(signature.clone()));
        }
        value
    }

    /// The bytes a signature covers: this record without its own signature.
    /// See [`Commitment::signing_payload`] for why it is excluded rather than
    /// zeroed.
    pub fn signing_payload(&self) -> Value {
        let mut value = Value::object([
            ("type", Value::string(RecordKind::Claim.as_str())),
            ("objective_id", Value::string(self.objective_id.clone())),
            ("submitter", Value::string(self.submitter.clone())),
            ("artifact", self.artifact.clone()),
            ("nonce", Value::string(self.nonce.clone())),
            ("created_at", Value::string(self.created_at.clone())),
            (
                "cites",
                Value::Array(
                    self.cites
                        .iter()
                        .map(|c| Value::String(c.clone()))
                        .collect(),
                ),
            ),
        ]);
        // Emitted only when non-empty. An empty array would be different bytes
        // from no field at all, so every id issued before relations existed
        // would move -- and with them every citation and every funded bounty
        // pointing at one.
        if !self.relations.is_empty() {
            if let Value::Object(map) = &mut value {
                map.insert(
                    "relations".to_string(),
                    Value::Array(self.relations.iter().map(ClaimRelation::to_value).collect()),
                );
            }
        }
        value
    }

    pub fn id(&self) -> String {
        self.to_value().digest()
    }

    /// Sign this record with `identity`, returning the signed copy.
    pub fn signed_with(mut self, identity: &crate::crypto::identity::Identity) -> Claim {
        self.submitter = identity.submitter_id();
        self.signature = Some(identity.sign_value(&self.signing_payload()).to_hex());
        self
    }

    /// Check the signature this record carries, if the rules demand one.
    pub fn verify_signature(&self) -> Result<(), SignatureError> {
        verify_record_signature(
            "claim",
            &self.submitter,
            &self.signing_payload(),
            self.signature.as_deref(),
        )
    }

    /// Identity of the artifact alone -- used to detect duplicate submissions.
    ///
    /// Scoped by objective, so the same artifact answering two different
    /// questions is two distinct results. Submitter and nonce are deliberately
    /// excluded: that is what makes a copied artifact recognisable as the same
    /// work no matter who reveals it.
    pub fn artifact_id(&self) -> String {
        Value::Object(BTreeMap::from([
            (
                "objective_id".to_string(),
                Value::string(self.objective_id.clone()),
            ),
            ("artifact".to_string(), self.artifact.clone()),
        ]))
        .digest()
    }

    /// The commitment this claim opens. A reveal is accepted only when this
    /// reproduces a commitment already in the log.
    pub fn commitment_hash(&self) -> String {
        commitment_hash(
            &self.objective_id,
            &self.submitter,
            &self.artifact,
            &self.nonce,
        )
    }

    /// Decode a record. Missing `cites` reads as empty; a present but non-array
    /// `cites` -- null included -- is an error, since the reference
    /// implementation cannot build a tuple from it either.
    pub fn from_value(value: &Value) -> Result<Claim, RecordError> {
        const RECORD: &str = "claim";
        let value = expect_object(value, RECORD)?;

        let cites = match value.get("cites") {
            None => Vec::new(),
            Some(Value::Array(items)) => {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    match item.as_str() {
                        Some(s) => out.push(s.to_string()),
                        None => {
                            return Err(RecordError::InvalidField {
                                record: RECORD,
                                field: "cites",
                                expected: "an array of claim ids",
                            })
                        }
                    }
                }
                out
            }
            Some(_) => {
                return Err(RecordError::InvalidField {
                    record: RECORD,
                    field: "cites",
                    expected: "an array of claim ids",
                })
            }
        };

        // Absent reads as none; present-but-not-an-array is an error, matching
        // `cites` exactly. `null` is *not* an empty list here either: a record
        // that spells "no relations" two different ways has two ids.
        let relations = match value.get("relations") {
            None => Vec::new(),
            Some(Value::Array(items)) => items
                .iter()
                .map(ClaimRelation::from_value)
                .collect::<Result<Vec<_>, _>>()?,
            Some(_) => {
                return Err(RecordError::InvalidField {
                    record: RECORD,
                    field: "relations",
                    expected: "an array of {kind, target} objects",
                })
            }
        };

        let claim = Claim {
            objective_id: required_string(value, RECORD, "objective_id")?,
            submitter: required_string(value, RECORD, "submitter")?,
            artifact: required(value, RECORD, "artifact")?.clone(),
            nonce: required_string(value, RECORD, "nonce")?,
            created_at: required_string(value, RECORD, "created_at")?,
            cites,
            relations,
            signature: optional_string(value, RECORD, "signature")?,
        };
        claim.validate()?;
        Ok(claim)
    }
}

/// A peer's permanent identity, and the transport it currently answers on.
///
/// # Why identity belongs in the log and location does not
///
/// Finding the network was a second bootstrap problem: a node needed a log
/// *and* an address list, obtained separately, and nothing tied the two
/// together. A peer's identity is permanent, so it belongs in the permanent
/// record — the same argument that puts objectives there and keeps provider
/// records out, since who *holds* a blob is a statement about right now and an
/// append-only structure has no way to say "no longer true".
///
/// An address is not permanent either, which is why this record carries a
/// [`PeerRecord::seq`]: a peer that moves appends a new record with a higher
/// one, and the highest wins. Append-only plus a sequence number is
/// last-writer-wins with an audit trail, which is strictly better than mutable
/// state for the same job.
///
/// # Two keys, and the binding between them is the point
///
/// This crate has two identity schemes and they are not interchangeable:
///
/// * **ed25519** signs. It is what a submitter name already *is* (see
///   [`signed_submitter`]), it is 32 bytes, and it is affordable in a log every
///   node replicates.
/// * **McEliece** keys the transport. It cannot sign — it is a KEM — and its
///   public key is 261,120 bytes, which is not affordable in a log at all.
///
/// So the record carries the ed25519 key as the **authority** and the McEliece
/// *peer id* — a 32-byte `sha256` of that key — as the thing being vouched for.
/// The transport key itself is fetched on demand over the wire and checked
/// against the id, which needs no trust because the id is its hash. Two hundred
/// bytes in the log instead of half a megabyte, and the expensive half is paid
/// only by nodes that actually dial.
///
/// # What a lie costs
///
/// Anyone may append a record for an identity they hold, naming any transport
/// id and any address. Doing so buys nothing: dialling that transport id
/// requires a key that hashes to it, and an impostor cannot produce one, so the
/// handshake fails. A wrong record costs a dial, never a wrong result — the
/// same bound [`crate::p2p::dht`] gives for a wrong routing answer, and for the
/// same reason.
///
/// What it cannot do is speak for somebody else's identity: the signature is
/// checked against the `identity` field, so a record is only ever a statement
/// by the key that signed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRecord {
    /// Ed25519 public key, hex. The permanent name, and the record's authority.
    pub identity: String,
    /// The transport peer id this identity vouches for: `sha256` of a McEliece
    /// public key, hex.
    pub transport: String,
    /// Where to try. A hint, superseded by any later record with a higher
    /// [`PeerRecord::seq`], and never load-bearing: an address that does not
    /// work costs a dial.
    pub addr: String,
    /// Freshness. Strictly increasing per identity; a record that does not
    /// advance it is a replay and is refused.
    pub seq: u64,
    pub created_at: String,
    /// Ed25519 signature over [`PeerRecord::signing_payload`], hex.
    ///
    /// **Required**, unlike a claim's. A claim may be posted under a nickname,
    /// because a nickname claims nothing; a peer record whose entire purpose is
    /// to authenticate an address would authenticate nothing without one.
    pub signature: Option<String>,
}

/// Longest `addr` a peer record may carry.
///
/// A generous bound on `host:port`, and a bound rather than a parse. The
/// consensus layer deliberately does **not** decide whether an address is
/// well-formed: `SocketAddr` parsing differs between languages at the edges —
/// IPv6 bracket forms, leading zeros, zone identifiers — and two
/// implementations disagreeing about whether a record is admissible is a
/// consensus split. So the rule here is length and printable ASCII, and
/// [`crate::p2p`] parses what it can and ignores the rest.
pub const MAX_PEER_ADDR: usize = 255;

impl PeerRecord {
    pub fn new(
        identity: impl Into<String>,
        transport: impl Into<String>,
        addr: impl Into<String>,
        seq: u64,
        created_at: impl Into<String>,
    ) -> PeerRecord {
        PeerRecord {
            identity: identity.into(),
            transport: transport.into(),
            addr: addr.into(),
            seq,
            created_at: created_at.into(),
            signature: None,
        }
    }

    /// The bytes a signature covers: this record without its own signature.
    pub fn signing_payload(&self) -> Value {
        Value::object([
            ("type", Value::string(RecordKind::Peer.as_str())),
            ("addr", Value::string(self.addr.clone())),
            ("created_at", Value::string(self.created_at.clone())),
            ("identity", Value::string(self.identity.clone())),
            ("seq", Value::Int(i128::from(self.seq))),
            ("transport", Value::string(self.transport.clone())),
        ])
    }

    pub fn to_value(&self) -> Value {
        let mut value = self.signing_payload();
        if let (Value::Object(map), Some(signature)) = (&mut value, &self.signature) {
            map.insert("signature".to_string(), Value::string(signature.clone()));
        }
        value
    }

    pub fn id(&self) -> String {
        self.to_value().digest()
    }

    /// Sign this record with `identity`, returning the signed copy.
    ///
    /// The signing key's public half *becomes* the `identity` field, for the
    /// reason a signed claim's submitter becomes its key: a name you sign for
    /// cannot be worn by anyone else, and a record whose name and key disagreed
    /// would be a record about somebody else.
    pub fn signed_with(mut self, identity: &crate::crypto::identity::Identity) -> PeerRecord {
        self.identity = identity.submitter_id();
        self.signature = Some(identity.sign_value(&self.signing_payload()).to_hex());
        self
    }

    /// Check the signature. Always required — see the field's documentation.
    pub fn verify_signature(&self) -> Result<(), SignatureError> {
        const RECORD: &str = "peer";
        if signed_submitter(&self.identity).is_none() {
            return Err(SignatureError::Invalid {
                record: RECORD,
                submitter: self.identity.clone(),
            });
        }
        let Some(signature) = self.signature.as_deref() else {
            return Err(SignatureError::Missing {
                record: RECORD,
                submitter: self.identity.clone(),
            });
        };
        verify_record_signature(
            RECORD,
            &self.identity,
            &self.signing_payload(),
            Some(signature),
        )
    }

    /// Structural rules, checked before the signature is looked at.
    pub fn validate(&self) -> Result<(), RecordError> {
        const RECORD: &str = "peer";
        let hex64 = |text: &str| {
            text.len() == 64
                && text
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        if !hex64(&self.identity) {
            return Err(RecordError::InvalidField {
                record: RECORD,
                field: "identity",
                expected: "64 lowercase hex characters of ed25519 public key",
            });
        }
        if !hex64(&self.transport) {
            return Err(RecordError::InvalidField {
                record: RECORD,
                field: "transport",
                expected: "64 lowercase hex characters of transport peer id",
            });
        }
        // Length and printable ASCII, never a parse. See [`MAX_PEER_ADDR`].
        if self.addr.is_empty()
            || self.addr.len() > MAX_PEER_ADDR
            || !self
                .addr
                .bytes()
                .all(|b| b.is_ascii_graphic() && b != b'"' && b != b'\\')
        {
            return Err(RecordError::InvalidField {
                record: RECORD,
                field: "addr",
                expected: "1 to 255 printable ASCII characters, no quote or backslash",
            });
        }
        Ok(())
    }

    pub fn from_value(value: &Value) -> Result<PeerRecord, RecordError> {
        const RECORD: &str = "peer";
        let value = expect_object(value, RECORD)?;
        let seq = match required(value, RECORD, "seq")? {
            // `u64` and not wider: a sequence number is a counter, and the
            // range check happens here rather than at a cast so a record from
            // an arbitrary-precision implementation is refused rather than
            // silently truncated into a *different* record.
            Value::Int(n) if *n >= 0 && *n <= i128::from(u64::MAX) => *n as u64,
            _ => {
                return Err(RecordError::InvalidField {
                    record: RECORD,
                    field: "seq",
                    expected: "an integer in [0, 2^64)",
                })
            }
        };
        let record = PeerRecord {
            identity: required_string(value, RECORD, "identity")?,
            transport: required_string(value, RECORD, "transport")?,
            addr: required_string(value, RECORD, "addr")?,
            seq,
            created_at: required_string(value, RECORD, "created_at")?,
            signature: optional_string(value, RECORD, "signature")?,
        };
        record.validate()?;
        Ok(record)
    }
}

/// A past promise to hold the log: identity `K` undertook to keep the log whose
/// Merkle root is `R` at height `H`.
///
/// # Why this is a statement about the past
///
/// An append-only log cannot say "no longer true". A record meaning *"K is
/// holding the log"* would advertise a dead node forever and get less accurate
/// the longer it ran — the same argument that keeps provider records out of the
/// log and into [`crate::dht`]'s expiring provider store. A record meaning *"K
/// undertook, at time T, to hold this"* never needs retracting, because it
/// stays true whatever K does next. What K does next is answered by a different
/// record: the sample response.
///
/// # Why the root and not a blob digest
///
/// `docs/node-incentives.md` names availability as one of the two easy services
/// — easy because *the protocol already knows the right answer*, so a node that
/// fails a challenge has proved something about itself without anyone's
/// cooperation. That oracle is the Merkle root. Undertaking to hold a bag of
/// blobs would be a promise with no oracle behind it; undertaking to hold a log
/// at a pinned root is a promise anyone can sample with
/// [`crate::ledger::Ledger::prove`].
///
/// `height` is not redundant with `root`. A Merkle path's shape depends on the
/// leaf count, so a challenger who knows only the root cannot tell a valid
/// answer from one shaped for a different tree. Both are pinned here, by the
/// signature, before any challenge exists.
///
/// # What an undertaking is worth on its own
///
/// Nothing, deliberately. Anyone may sign one for a log they have never seen —
/// the root is public. It becomes worth something only when a challenge is
/// derived against it and the answer is checked, which is why the undertaking
/// and the settlement that reads it belong to one change rather than two.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Undertaking {
    /// Ed25519 public key, hex. Who promised, and the record's authority.
    pub identity: String,
    /// `sha256:` Merkle root of the log being undertaken.
    pub root: String,
    /// How many entries that root covers. See the type docs: a challenge needs
    /// the tree's shape, not only its root.
    pub height: u64,
    /// Units staked behind this promise, and the whole of its Sybil
    /// resistance.
    ///
    /// The availability pool is split **in proportion to this**, not evenly and
    /// not by height, because a stake-weighted split is the one rule that is
    /// exactly invariant to an operator wearing forty identities instead of
    /// one: stake is conserved when it is divided, so forty promises of `S/40`
    /// earn between them exactly what one promise of `S` earns.
    /// `incentive::mechanism::SplitIdentities` proves that rather than
    /// asserting it.
    ///
    /// It has to be *scarce* or the invariance is worthless -- a number anyone
    /// can set to `u64::MAX` would look like the invariant rule and behave like
    /// the free one. So it is bounded by what the log says this identity has
    /// been paid and has not already locked: see
    /// `crate::node::Node::balances_within`.
    ///
    /// # It is not scarce yet, and the difference matters
    ///
    /// A balance comes from a settlement, a settlement comes from an objective,
    /// and `crate::node::Node::post_objective` **takes no deposit**: a funder
    /// names a reward and nothing checks it had one. So an attacker posts a
    /// bounty for an arbitrary sum against a verifier it chose, answers its own
    /// question, and stakes the proceeds -- and does it once per key.
    /// `node::tests::minting_a_bond_is_free_because_an_objective_needs_no_deposit`
    /// mints 10^12 units in four commands and audits clean afterwards, because
    /// nothing there breaks a rule; the rule is missing.
    ///
    /// So what this field buys today is *invariance*, not resistance: splitting
    /// a stake across identities is exactly neutral, which is the property a
    /// scarce stake would need and is not by itself enough. Closing it means
    /// debiting an objective's reward from its funder's own balance, which
    /// needs a genesis rule and moves both implementations. Until then, an
    /// availability pool should not carry real money.
    pub bond: u64,
    pub created_at: String,
    /// Ed25519 signature over [`Undertaking::signing_payload`], hex.
    ///
    /// **Required.** A promise nobody signed is a promise by nobody, and this
    /// record exists to be held against one identity in particular.
    pub signature: Option<String>,
}

/// Tallest log an undertaking may name.
///
/// The sample index is drawn with [`crate::partition::assign`], whose partition
/// count is a `u32` -- and reusing that function rather than writing a second
/// modular reduction is deliberate: it is pinned by `conformance/vectors.json`,
/// so both implementations agree about which entry was challenged for free, and
/// a bespoke draw here would be a new consensus surface.
///
/// So the bound is declared in the *format* and checked once, on the way in,
/// rather than discovered at settlement time when a height that does not fit
/// would have to be capped or refused with money on the table. Four billion
/// entries is far beyond anything Stage 0 contemplates; a network that reaches
/// it needs this design revisited rather than silently truncated.
pub const MAX_UNDERTAKING_HEIGHT: u64 = u32::MAX as u64;

impl Undertaking {
    pub fn new(
        identity: impl Into<String>,
        root: impl Into<String>,
        height: u64,
        bond: u64,
        created_at: impl Into<String>,
    ) -> Undertaking {
        Undertaking {
            identity: identity.into(),
            root: root.into(),
            height,
            bond,
            created_at: created_at.into(),
            signature: None,
        }
    }

    /// The bytes a signature covers: this record without its own signature.
    pub fn signing_payload(&self) -> Value {
        Value::object([
            ("type", Value::string(RecordKind::Undertaking.as_str())),
            ("bond", Value::Int(i128::from(self.bond))),
            ("created_at", Value::string(self.created_at.clone())),
            ("height", Value::Int(i128::from(self.height))),
            ("identity", Value::string(self.identity.clone())),
            ("root", Value::string(self.root.clone())),
        ])
    }

    pub fn to_value(&self) -> Value {
        let mut value = self.signing_payload();
        if let (Value::Object(map), Some(signature)) = (&mut value, &self.signature) {
            map.insert("signature".to_string(), Value::string(signature.clone()));
        }
        value
    }

    pub fn id(&self) -> String {
        self.to_value().digest()
    }

    /// Sign with `identity`, whose public half *becomes* the `identity` field.
    ///
    /// Same rule as a signed claim's submitter and a peer record's identity: a
    /// name you sign for cannot be worn by anyone else, and a record whose name
    /// and key disagreed would be a record about somebody else.
    pub fn signed_with(mut self, identity: &crate::crypto::identity::Identity) -> Undertaking {
        self.identity = identity.submitter_id();
        self.signature = Some(identity.sign_value(&self.signing_payload()).to_hex());
        self
    }

    /// Check the signature. Always required — see the field's documentation.
    pub fn verify_signature(&self) -> Result<(), SignatureError> {
        const RECORD: &str = "undertaking";
        if signed_submitter(&self.identity).is_none() {
            return Err(SignatureError::Invalid {
                record: RECORD,
                submitter: self.identity.clone(),
            });
        }
        let Some(signature) = self.signature.as_deref() else {
            return Err(SignatureError::Missing {
                record: RECORD,
                submitter: self.identity.clone(),
            });
        };
        verify_record_signature(
            RECORD,
            &self.identity,
            &self.signing_payload(),
            Some(signature),
        )
    }

    pub fn validate(&self) -> Result<(), RecordError> {
        const RECORD: &str = "undertaking";
        if !is_hex64(&self.identity) {
            return Err(RecordError::InvalidField {
                record: RECORD,
                field: "identity",
                expected: "64 lowercase hex characters of ed25519 public key",
            });
        }
        if !is_digest(&self.root) {
            return Err(RecordError::InvalidField {
                record: RECORD,
                field: "root",
                expected: "sha256: followed by 64 lowercase hex characters",
            });
        }
        // Zero is refused rather than treated as "the empty log". An empty log
        // has no root at all, so a height of zero beside a well-formed root is
        // a record that contradicts itself, and there is nothing in it to
        // sample.
        if self.height == 0 || self.height > MAX_UNDERTAKING_HEIGHT {
            return Err(RecordError::InvalidField {
                record: RECORD,
                field: "height",
                expected: "between 1 and 2^32 - 1 entries",
            });
        }
        // A promise backed by nothing earns nothing, so it is refused rather
        // than admitted at zero weight: an unbonded undertaking in the log is a
        // node that believes it is being sampled and will never be paid, and
        // saying so on admission is kinder than saying it by silence.
        if self.bond == 0 {
            return Err(RecordError::InvalidField {
                record: RECORD,
                field: "bond",
                expected: "at least one unit staked",
            });
        }
        Ok(())
    }

    pub fn from_value(value: &Value) -> Result<Undertaking, RecordError> {
        const RECORD: &str = "undertaking";
        let value = expect_object(value, RECORD)?;
        let record = Undertaking {
            identity: required_string(value, RECORD, "identity")?,
            root: required_string(value, RECORD, "root")?,
            height: required_u64(value, RECORD, "height")?,
            bond: required_u64(value, RECORD, "bond")?,
            created_at: required_string(value, RECORD, "created_at")?,
            signature: optional_string(value, RECORD, "signature")?,
        };
        record.validate()?;
        Ok(record)
    }
}

/// Money put up to pay for availability, for a stated run of epochs.
///
/// The other half of the promise, and the reason the two arrive in one change.
/// `docs/roadmap.md`: *"a record nothing pays against is bookkeeping, and a
/// payment with no record to challenge is unenforceable."* An
/// [`Undertaking`] with no pool behind it is the first; a pool with no
/// undertaking to sample is the second.
///
/// Shaped like an objective on purpose — a funder names a sum and settlement
/// spends it, never more. `per_epoch` times the epoch count is the ceiling, and
/// [`crate::node::Node::audit`] checks the total paid against it in `u128` for
/// the same reason objective pools are checked: a wrapped sum turns an
/// overspent pool into a small number and hides the fault being looked for.
///
/// # What a fixed pot buys, and what it does not
///
/// The pot is split among the epoch's verified answers **in proportion to the
/// bond behind each**, so the cost to a funder is bounded no matter how many
/// nodes appear *and* splitting one identity into forty earns exactly what it
/// earned as one — stake is conserved when it is divided, a head count is not.
/// Split equally, as this first did, ten identities behind one disk answered
/// ten samples from one copy and took ten shares.
///
/// What it still does not buy is proof that the answerer *stored* anything: the
/// answer proves the entry was produced, and a node fetching it from a peer as
/// the epoch opens is not excluded. Nor is the bond slashed yet — silence is
/// recorded and the units are locked, but nothing takes them. Stated here
/// rather than left to be discovered, because a funder reading only the ceiling
/// would conclude something stronger than is true.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvailabilityPool {
    /// Who is paying. A name, not necessarily a key: funding is not a claim
    /// about anything, so it needs no signature to be meaningful.
    pub funder: String,
    /// Units available for each epoch in range.
    pub per_epoch: u64,
    /// First epoch this pool pays for, inclusive.
    pub from_epoch: u64,
    /// Last epoch this pool pays for, inclusive.
    pub to_epoch: u64,
    pub created_at: String,
}

impl AvailabilityPool {
    pub fn to_value(&self) -> Value {
        Value::object([
            ("type", Value::string("availability_pool")),
            ("created_at", Value::string(self.created_at.clone())),
            ("from_epoch", Value::Int(i128::from(self.from_epoch))),
            ("funder", Value::string(self.funder.clone())),
            ("per_epoch", Value::Int(i128::from(self.per_epoch))),
            ("to_epoch", Value::Int(i128::from(self.to_epoch))),
        ])
    }

    pub fn id(&self) -> String {
        self.to_value().digest()
    }

    /// Total this pool can ever pay: `per_epoch × epochs`, in `u128`.
    ///
    /// Widened deliberately. Both factors are `u64`, and their product is not:
    /// computing the ceiling in `u64` would wrap a large pool into a small one
    /// and let the audit certify an overspend as fine.
    pub fn ceiling(&self) -> u128 {
        let epochs = u128::from(self.to_epoch.saturating_sub(self.from_epoch)) + 1;
        u128::from(self.per_epoch) * epochs
    }

    pub fn covers(&self, epoch: u64) -> bool {
        self.from_epoch <= epoch && epoch <= self.to_epoch
    }

    pub fn validate(&self) -> Result<(), RecordError> {
        const RECORD: &str = "availability_pool";
        if self.funder.is_empty() {
            return Err(RecordError::InvalidField {
                record: RECORD,
                field: "funder",
                expected: "a non-empty name",
            });
        }
        // A pool that pays nothing is not a pool, and an inverted range is a
        // record whose ceiling arithmetic would be nonsense. Both refused
        // rather than normalised: a record two implementations might normalise
        // differently is a consensus split.
        if self.per_epoch == 0 {
            return Err(RecordError::InvalidField {
                record: RECORD,
                field: "per_epoch",
                expected: "at least one unit",
            });
        }
        if self.from_epoch > self.to_epoch {
            return Err(RecordError::InvalidField {
                record: RECORD,
                field: "to_epoch",
                expected: "an epoch at or after from_epoch",
            });
        }
        Ok(())
    }

    pub fn from_value(value: &Value) -> Result<AvailabilityPool, RecordError> {
        const RECORD: &str = "availability_pool";
        let value = expect_object(value, RECORD)?;
        let record = AvailabilityPool {
            funder: required_string(value, RECORD, "funder")?,
            per_epoch: required_u64(value, RECORD, "per_epoch")?,
            from_epoch: required_u64(value, RECORD, "from_epoch")?,
            to_epoch: required_u64(value, RECORD, "to_epoch")?,
            created_at: required_string(value, RECORD, "created_at")?,
        };
        record.validate()?;
        Ok(record)
    }
}

/// A unit of money entering the log, and the only way any ever does.
///
/// # Why the supply is a record and not a constant
///
/// Everything this crate weights by money — the availability pool's stake
/// split, an objective's escrow, a bond — is worth exactly what the money is
/// scarce. It was not. [`crate::node::Node::post_objective`] took no deposit,
/// so a funder named a reward and nothing checked it had one: post a bounty for
/// an arbitrary sum against a verifier you chose, answer your own question,
/// stake the proceeds, repeat per key. Four commands, and the log audited
/// clean, because nothing there broke a rule — the rule was missing.
///
/// An issuance is that rule. It says *this identity holds these units*, and
/// once a log declares a supply, every unit in it is traceable to one:
/// [`crate::node::Node::audit`] checks that issued equals held plus escrowed
/// plus locked, in `u128`, and reports the difference rather than rounding it
/// away.
///
/// # Why only in the genesis prefix
///
/// An issuance anywhere else is a mint, so it is admissible only *before* the
/// log's first non-issuance entry. That makes the supply a property of the
/// log's opening bytes: common knowledge in the sense the consensus literature
/// means it, fixed at creation, and checkable by anyone reading forward from
/// the first line. Anything later is an audit fault, not a balance.
///
/// # Why a log with no issuance is still legal
///
/// Declaring a supply is what turns the accounting on. A log with no issuance
/// record has not claimed its units are scarce, and refusing every such log
/// would refuse every log written before this record existed, including the
/// published one. So the rule is conditional on the record, not on a flag: on a
/// log with a declared supply, no unit exists that the supply did not issue; on
/// a log without one, the operator's word is the backing and the audit says so
/// rather than pretending otherwise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issuance {
    /// Who receives the units. A name or a key: a supply is declared by
    /// whoever opened the log, and it is the *position* of the record rather
    /// than a signature that authorises it — a signature would only prove who
    /// wrote it, and in the genesis prefix there is nobody else it could be.
    pub holder: String,
    /// Units issued to `holder`.
    pub units: u64,
    pub created_at: String,
}

impl Issuance {
    pub fn new(holder: impl Into<String>, units: u64, created_at: impl Into<String>) -> Issuance {
        Issuance {
            holder: holder.into(),
            units,
            created_at: created_at.into(),
        }
    }

    pub fn to_value(&self) -> Value {
        Value::object([
            ("type", Value::string("issuance")),
            ("created_at", Value::string(self.created_at.clone())),
            ("holder", Value::string(self.holder.clone())),
            ("units", Value::Int(i128::from(self.units))),
        ])
    }

    pub fn id(&self) -> String {
        self.to_value().digest()
    }

    pub fn validate(&self) -> Result<(), RecordError> {
        const RECORD: &str = "issuance";
        if self.holder.is_empty() {
            return Err(RecordError::InvalidField {
                record: RECORD,
                field: "holder",
                expected: "a non-empty name",
            });
        }
        // Zero is refused rather than admitted as a no-op: it is a record that
        // declares nothing while looking like a declaration, and a supply
        // padded with them reads as larger than it is.
        if self.units == 0 {
            return Err(RecordError::InvalidField {
                record: RECORD,
                field: "units",
                expected: "at least one unit",
            });
        }
        Ok(())
    }

    pub fn from_value(value: &Value) -> Result<Issuance, RecordError> {
        const RECORD: &str = "issuance";
        let value = expect_object(value, RECORD)?;
        let record = Issuance {
            holder: required_string(value, RECORD, "holder")?,
            units: required_u64(value, RECORD, "units")?,
            created_at: required_string(value, RECORD, "created_at")?,
        };
        record.validate()?;
        Ok(record)
    }
}

/// An answer to one availability sample: the path the holder produced.
///
/// # Why this carries a path and not a proof
///
/// [`crate::ledger::Proof`] ships an entry beside its path, because it is meant
/// for a reader who does not have the log. This record goes *into* the log, and
/// the entry being proved is already sitting in it at the sampled index. So the
/// entry is left out and the auditor reads it locally — the redundancy would be
/// a whole record duplicated per node per epoch, forever.
///
/// # What this proves, and what it does not
///
/// The signature is the load-bearing part, and without it the record would be
/// worthless: an auditor holding the log can compute this path themselves, so
/// an unsigned path is evidence of nothing. Signed, it says *K produced the
/// path for the entry K was challenged on*, which K could only do by holding
/// that entry, and which nobody can forge on K's behalf.
///
/// What it does **not** prove is that K stored the log rather than fetching the
/// challenged entry from somebody else the moment the epoch opened. That is the
/// outsourcing attack, and no challenge–response of this shape can rule it out
/// — ruling it out needs a time bound or sequential work, neither of which
/// Stage 0 has. So this catches a node that stored nothing *and* has no source,
/// which is the population the availability payment exists to exclude, and it
/// does not catch a node running a cache. Said here rather than left for
/// somebody to discover, because a check whose strength is overestimated is
/// worse than one that is known to be partial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Availability {
    /// Ed25519 public key, hex. Who is answering — and it must be the identity
    /// that made the promise: you cannot answer somebody else's sample.
    pub identity: String,
    /// The [`Undertaking::id`] being answered.
    pub undertaking: String,
    /// Which epoch's sample. The epoch decides the index, so an answer is
    /// good for exactly one of them and a replay is caught by its own field.
    pub epoch: u64,
    /// The sampled entry itself, in its stored form. See the type docs: without
    /// this the record proves possession of hashes rather than of the log.
    pub entry: Value,
    /// The inclusion path for that entry, bottom up.
    pub path: Vec<String>,
    pub created_at: String,
    /// Ed25519 signature over [`Availability::signing_payload`], hex.
    /// **Required** — see the type docs for why it is the whole record.
    pub signature: Option<String>,
}

/// Longest inclusion path an answer may carry.
///
/// A path has one hash per level that pairs, so a log of `n` entries needs at
/// most `ceil(log2(n))` of them: 32 covers every log up to four billion
/// entries, which is [`MAX_UNDERTAKING_HEIGHT`]. A bound rather than an exact
/// length because the exact length depends on the index — a promoted node
/// contributes nothing at its level — and because the *check* that matters is
/// whether the path reaches the root, which [`crate::canonical::Inclusion`]
/// already makes exact. This only stops a record big enough to be a nuisance.
pub const MAX_AVAILABILITY_PATH: usize = 32;

impl Availability {
    pub fn new(
        identity: impl Into<String>,
        undertaking: impl Into<String>,
        epoch: u64,
        entry: Value,
        path: Vec<String>,
        created_at: impl Into<String>,
    ) -> Availability {
        Availability {
            identity: identity.into(),
            undertaking: undertaking.into(),
            epoch,
            entry,
            path,
            created_at: created_at.into(),
            signature: None,
        }
    }

    pub fn signing_payload(&self) -> Value {
        Value::object([
            ("type", Value::string(RecordKind::Availability.as_str())),
            ("created_at", Value::string(self.created_at.clone())),
            ("entry", self.entry.clone()),
            ("epoch", Value::Int(i128::from(self.epoch))),
            ("identity", Value::string(self.identity.clone())),
            (
                "path",
                Value::Array(self.path.iter().cloned().map(Value::String).collect()),
            ),
            ("undertaking", Value::string(self.undertaking.clone())),
        ])
    }

    pub fn to_value(&self) -> Value {
        let mut value = self.signing_payload();
        if let (Value::Object(map), Some(signature)) = (&mut value, &self.signature) {
            map.insert("signature".to_string(), Value::string(signature.clone()));
        }
        value
    }

    pub fn id(&self) -> String {
        self.to_value().digest()
    }

    pub fn signed_with(mut self, identity: &crate::crypto::identity::Identity) -> Availability {
        self.identity = identity.submitter_id();
        self.signature = Some(identity.sign_value(&self.signing_payload()).to_hex());
        self
    }

    pub fn verify_signature(&self) -> Result<(), SignatureError> {
        const RECORD: &str = "availability";
        if signed_submitter(&self.identity).is_none() {
            return Err(SignatureError::Invalid {
                record: RECORD,
                submitter: self.identity.clone(),
            });
        }
        let Some(signature) = self.signature.as_deref() else {
            return Err(SignatureError::Missing {
                record: RECORD,
                submitter: self.identity.clone(),
            });
        };
        verify_record_signature(
            RECORD,
            &self.identity,
            &self.signing_payload(),
            Some(signature),
        )
    }

    pub fn validate(&self) -> Result<(), RecordError> {
        const RECORD: &str = "availability";
        if !is_hex64(&self.identity) {
            return Err(RecordError::InvalidField {
                record: RECORD,
                field: "identity",
                expected: "64 lowercase hex characters of ed25519 public key",
            });
        }
        if !is_digest(&self.undertaking) {
            return Err(RecordError::InvalidField {
                record: RECORD,
                field: "undertaking",
                expected: "sha256: followed by 64 lowercase hex characters",
            });
        }
        // The entry has to be an object at least; whether it is *the* entry is
        // decided by the rules layer, which recomputes its hash and walks the
        // path. Shape here, meaning there.
        if self.entry.as_object().is_none() {
            return Err(RecordError::InvalidField {
                record: RECORD,
                field: "entry",
                expected: "the sampled log entry as an object",
            });
        }
        // An empty path is legal: a one-entry log's only leaf *is* the root, so
        // the honest answer to it carries no hashes at all. Refusing that would
        // make the first entry of every log unsamplable.
        if self.path.len() > MAX_AVAILABILITY_PATH || !self.path.iter().all(|h| is_digest(h)) {
            return Err(RecordError::InvalidField {
                record: RECORD,
                field: "path",
                expected: "at most 32 sha256: digests",
            });
        }
        Ok(())
    }

    pub fn from_value(value: &Value) -> Result<Availability, RecordError> {
        const RECORD: &str = "availability";
        let value = expect_object(value, RECORD)?;
        let path = match required(value, RECORD, "path")? {
            Value::Array(items) => items
                .iter()
                .map(|item| match item {
                    Value::String(hash) => Ok(hash.clone()),
                    _ => Err(RecordError::InvalidField {
                        record: RECORD,
                        field: "path",
                        expected: "an array of strings",
                    }),
                })
                .collect::<Result<Vec<String>, RecordError>>()?,
            _ => {
                return Err(RecordError::InvalidField {
                    record: RECORD,
                    field: "path",
                    expected: "an array of strings",
                })
            }
        };
        let record = Availability {
            identity: required_string(value, RECORD, "identity")?,
            undertaking: required_string(value, RECORD, "undertaking")?,
            epoch: required_u64(value, RECORD, "epoch")?,
            entry: required(value, RECORD, "entry")?.clone(),
            path,
            created_at: required_string(value, RECORD, "created_at")?,
            signature: optional_string(value, RECORD, "signature")?,
        };
        record.validate()?;
        Ok(record)
    }
}

/// 64 lowercase hex characters, the shape of an ed25519 key or a bare digest.
fn is_hex64(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `sha256:` followed by 64 lowercase hex characters.
fn is_digest(text: &str) -> bool {
    match text.strip_prefix(crate::canonical::DIGEST_PREFIX) {
        Some(rest) => is_hex64(rest),
        None => false,
    }
}

/// An integer field that must fit `u64`.
///
/// Range-checked here rather than at a cast, so a record written by an
/// arbitrary-precision implementation is *refused* rather than silently
/// truncated into a different record.
fn required_u64(
    value: &Value,
    record: &'static str,
    field: &'static str,
) -> Result<u64, RecordError> {
    match required(value, record, field)? {
        Value::Int(n) if *n >= 0 && *n <= i128::from(u64::MAX) => Ok(*n as u64),
        _ => Err(RecordError::InvalidField {
            record,
            field,
            expected: "an integer in [0, 2^64)",
        }),
    }
}

/// A signed, bonded statement about what a verifier said.
///
/// # Why a verdict was not enough
///
/// A `verdict` record says what the checker returned. It does not say **who
/// ran it**, because at Stage 0 a log has one writer and the question did not
/// arise. That is exactly the gap `src/arena` measured: a canary docket names a
/// *claim* whose verdict is wrong and cannot name a *party*, so there is nobody
/// to slash and rubber-stamping pays. The arena reports it as the only OPEN
/// attack in the set, and this record is what closes it.
///
/// # What it commits to
///
/// One identity, one claim, one status, signed. Signing is not decoration: an
/// unsigned attestation is an attestation by nobody, and a penalty with nobody
/// attached is not a penalty. The signature covers the status, so an attestor
/// cannot later claim to have said something else about a claim it attested to.
///
/// # And what stands behind it
///
/// A bond, checked at admission against the attestor's own balance
/// ([`crate::node::VERIFICATION_BOND`]). The bond is what a slash takes, and
/// the reason the whole mechanism is not circular: a canary tells the *issuer*
/// which attestations are wrong for free, and the slash itself is settled by
/// running that one verifier, which anybody can do and anybody can check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attestation {
    /// The claim this is about.
    pub claim_id: String,
    /// Ed25519 public key, hex. Who ran the verifier and is answerable for it.
    pub attestor: String,
    /// What they say it returned: the wire spelling of a
    /// [`crate::verifiers::Status`].
    pub status: String,
    pub created_at: String,
    /// Ed25519 signature over [`Attestation::signing_payload`], hex. Required.
    pub signature: Option<String>,
}

impl Attestation {
    pub fn new(
        claim_id: impl Into<String>,
        attestor: impl Into<String>,
        status: impl Into<String>,
        created_at: impl Into<String>,
    ) -> Attestation {
        Attestation {
            claim_id: claim_id.into(),
            attestor: attestor.into(),
            status: status.into(),
            created_at: created_at.into(),
            signature: None,
        }
    }

    pub fn signing_payload(&self) -> Value {
        Value::object([
            ("type", Value::string("attestation")),
            ("attestor", Value::string(self.attestor.clone())),
            ("claim_id", Value::string(self.claim_id.clone())),
            ("created_at", Value::string(self.created_at.clone())),
            ("status", Value::string(self.status.clone())),
        ])
    }

    pub fn to_value(&self) -> Value {
        let mut value = self.signing_payload();
        if let (Value::Object(map), Some(signature)) = (&mut value, &self.signature) {
            map.insert("signature".to_string(), Value::string(signature.clone()));
        }
        value
    }

    pub fn id(&self) -> String {
        self.to_value().digest()
    }

    pub fn signed_with(mut self, identity: &crate::crypto::identity::Identity) -> Attestation {
        self.attestor = identity.submitter_id();
        self.signature = Some(identity.sign_value(&self.signing_payload()).to_hex());
        self
    }

    pub fn verify_signature(&self) -> Result<(), SignatureError> {
        const RECORD: &str = "attestation";
        if signed_submitter(&self.attestor).is_none() {
            return Err(SignatureError::Invalid {
                record: RECORD,
                submitter: self.attestor.clone(),
            });
        }
        let signature = self.signature.as_deref().ok_or(SignatureError::Missing {
            record: RECORD,
            submitter: self.attestor.clone(),
        })?;
        verify_record_signature(
            RECORD,
            &self.attestor,
            &self.signing_payload(),
            Some(signature),
        )
    }

    pub fn validate(&self) -> Result<(), RecordError> {
        const RECORD: &str = "attestation";
        if self.claim_id.is_empty() {
            return Err(RecordError::InvalidField {
                record: RECORD,
                field: "claim_id",
                expected: "the id of the claim attested to",
            });
        }
        // Only the two *settling* statuses can be attested to under bond.
        //
        // `unavailable` says "my machine could not run this", which is a fact
        // about the attestor rather than the artifact, and it is the answer the
        // whole verifier interface exists to protect. Bonding it would put a
        // price on admitting a broken toolchain, and the cheapest response to
        // that price is to guess instead.
        if self.status != "accept" && self.status != "reject" {
            return Err(RecordError::InvalidField {
                record: RECORD,
                field: "status",
                expected: "accept or reject; a non-settling status is not bondable",
            });
        }
        Ok(())
    }

    pub fn from_value(value: &Value) -> Result<Attestation, RecordError> {
        const RECORD: &str = "attestation";
        let value = expect_object(value, RECORD)?;
        let record = Attestation {
            claim_id: required_string(value, RECORD, "claim_id")?,
            attestor: required_string(value, RECORD, "attestor")?,
            status: required_string(value, RECORD, "status")?,
            created_at: required_string(value, RECORD, "created_at")?,
            signature: optional_string(value, RECORD, "signature")?,
        };
        record.validate()?;
        Ok(record)
    }
}

// ---------------------------------------------------------------------------
// Interactive fraud proofs
// ---------------------------------------------------------------------------

/// A bonded objection to a settled claim's committed trace.
///
/// The record that opens a dispute. It names the claim, commits the challenger
/// to a trace root of their own, and stakes a bond behind the objection.
///
/// **The bond is the whole record.** Without it, opening a dispute is free, and
/// a free dispute is a denial-of-service on every honest submitter: post one
/// against every claim, answer nothing, and every payout is held for the length
/// of the window. The bond makes losing cost something and makes stalling cost
/// the same as losing, since a challenger who stops answering forfeits.
///
/// The challenger's root is committed **here**, before any bisection move, and
/// that ordering is the security property rather than a convenience. A
/// challenger who could choose their trace after seeing the defender's answers
/// would win every dispute by construction: at each round, answer whatever the
/// defender did not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    /// The claim whose trace is disputed.
    pub claim_id: String,
    /// Ed25519 public key, hex. Who objects, and the record's authority.
    pub challenger: String,
    /// The challenger's own committed trace root.
    pub root: String,
    /// How many states both sides claim the trace has. Equal length is a rule:
    /// two parties claiming different lengths have already stated their
    /// disagreement in public and need no search to find it.
    pub states: u64,
    /// Units staked behind the objection, forfeit if it loses.
    pub bond: u64,
    pub created_at: String,
    /// Ed25519 signature over [`Challenge::signing_payload`], hex. Required:
    /// an unsigned objection is an objection by nobody, and there would be
    /// nobody to slash.
    pub signature: Option<String>,
}

impl Challenge {
    pub fn new(
        claim_id: impl Into<String>,
        challenger: impl Into<String>,
        root: impl Into<String>,
        states: u64,
        bond: u64,
        created_at: impl Into<String>,
    ) -> Challenge {
        Challenge {
            claim_id: claim_id.into(),
            challenger: challenger.into(),
            root: root.into(),
            states,
            bond,
            created_at: created_at.into(),
            signature: None,
        }
    }

    pub fn signing_payload(&self) -> Value {
        Value::object([
            ("type", Value::string("challenge")),
            ("bond", Value::Int(i128::from(self.bond))),
            ("challenger", Value::string(self.challenger.clone())),
            ("claim_id", Value::string(self.claim_id.clone())),
            ("created_at", Value::string(self.created_at.clone())),
            ("root", Value::string(self.root.clone())),
            ("states", Value::Int(i128::from(self.states))),
        ])
    }

    pub fn to_value(&self) -> Value {
        let mut value = self.signing_payload();
        if let (Value::Object(map), Some(signature)) = (&mut value, &self.signature) {
            map.insert("signature".to_string(), Value::string(signature.clone()));
        }
        value
    }

    pub fn id(&self) -> String {
        self.to_value().digest()
    }

    pub fn signed_with(mut self, identity: &crate::crypto::identity::Identity) -> Challenge {
        self.challenger = identity.submitter_id();
        self.signature = Some(identity.sign_value(&self.signing_payload()).to_hex());
        self
    }

    pub fn verify_signature(&self) -> Result<(), SignatureError> {
        const RECORD: &str = "challenge";
        if signed_submitter(&self.challenger).is_none() {
            return Err(SignatureError::Invalid {
                record: RECORD,
                submitter: self.challenger.clone(),
            });
        }
        let signature = self.signature.as_deref().ok_or(SignatureError::Missing {
            record: RECORD,
            submitter: self.challenger.clone(),
        })?;
        verify_record_signature(
            RECORD,
            &self.challenger,
            &self.signing_payload(),
            Some(signature),
        )
    }

    pub fn validate(&self) -> Result<(), RecordError> {
        const RECORD: &str = "challenge";
        if self.claim_id.is_empty() {
            return Err(RecordError::InvalidField {
                record: RECORD,
                field: "claim_id",
                expected: "the id of the claim being disputed",
            });
        }
        if !self.root.starts_with("sha256:") {
            return Err(RecordError::InvalidField {
                record: RECORD,
                field: "root",
                expected: "a sha256: Merkle root over the trace",
            });
        }
        // Fewer than two states is not a trace, so there is no step to
        // disagree about; more than the cap is a dispute no log can carry.
        if self.states < 2 || self.states > crate::challenge::MAX_TRACE as u64 {
            return Err(RecordError::InvalidField {
                record: RECORD,
                field: "states",
                expected: "between 2 and 2^24 states",
            });
        }
        // A zero bond is the free objection the record exists to prevent.
        if self.bond == 0 {
            return Err(RecordError::InvalidField {
                record: RECORD,
                field: "bond",
                expected: "a bond of at least one unit",
            });
        }
        Ok(())
    }

    pub fn from_value(value: &Value) -> Result<Challenge, RecordError> {
        const RECORD: &str = "challenge";
        let value = expect_object(value, RECORD)?;
        let challenge = Challenge {
            claim_id: required_string(value, RECORD, "claim_id")?,
            challenger: required_string(value, RECORD, "challenger")?,
            root: required_string(value, RECORD, "root")?,
            states: required_u64(value, RECORD, "states")?,
            bond: required_u64(value, RECORD, "bond")?,
            created_at: required_string(value, RECORD, "created_at")?,
            signature: optional_string(value, RECORD, "signature")?,
        };
        challenge.validate()?;
        Ok(challenge)
    }
}

/// One party's answer to one bisection query, as a record.
///
/// The wire form of [`crate::challenge::Move`]. Carries the state itself rather
/// than only its digest, and the inclusion path proving that state is the one
/// its author committed to before the game started. Both are checked at
/// admission: a move that does not open its author's root is not a move.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BisectionMove {
    /// The [`Challenge::id`] this belongs to.
    pub challenge_id: String,
    /// Ed25519 public key, hex. Which party is answering. Whether that is the
    /// defender or the challenger is derived from the log — the claim names its
    /// submitter and the challenge names its challenger — so a mover cannot
    /// answer for the other side by saying so.
    pub mover: String,
    /// Which state index the game asked about.
    pub index: u64,
    /// The state at that index.
    pub state: Value,
    /// The inclusion path, bottom up, against the mover's own root.
    pub path: Vec<String>,
    pub created_at: String,
    /// Ed25519 signature over [`BisectionMove::signing_payload`], hex.
    pub signature: Option<String>,
}

impl BisectionMove {
    pub fn new(
        challenge_id: impl Into<String>,
        mover: impl Into<String>,
        index: u64,
        state: Value,
        path: Vec<String>,
        created_at: impl Into<String>,
    ) -> BisectionMove {
        BisectionMove {
            challenge_id: challenge_id.into(),
            mover: mover.into(),
            index,
            state,
            path,
            created_at: created_at.into(),
            signature: None,
        }
    }

    pub fn signing_payload(&self) -> Value {
        Value::object([
            ("type", Value::string("bisection")),
            ("challenge_id", Value::string(self.challenge_id.clone())),
            ("created_at", Value::string(self.created_at.clone())),
            ("index", Value::Int(i128::from(self.index))),
            ("mover", Value::string(self.mover.clone())),
            (
                "path",
                Value::Array(self.path.iter().cloned().map(Value::String).collect()),
            ),
            ("state", self.state.clone()),
        ])
    }

    pub fn to_value(&self) -> Value {
        let mut value = self.signing_payload();
        if let (Value::Object(map), Some(signature)) = (&mut value, &self.signature) {
            map.insert("signature".to_string(), Value::string(signature.clone()));
        }
        value
    }

    pub fn id(&self) -> String {
        self.to_value().digest()
    }

    pub fn signed_with(mut self, identity: &crate::crypto::identity::Identity) -> BisectionMove {
        self.mover = identity.submitter_id();
        self.signature = Some(identity.sign_value(&self.signing_payload()).to_hex());
        self
    }

    pub fn verify_signature(&self) -> Result<(), SignatureError> {
        const RECORD: &str = "bisection";
        if signed_submitter(&self.mover).is_none() {
            return Err(SignatureError::Invalid {
                record: RECORD,
                submitter: self.mover.clone(),
            });
        }
        let signature = self.signature.as_deref().ok_or(SignatureError::Missing {
            record: RECORD,
            submitter: self.mover.clone(),
        })?;
        verify_record_signature(
            RECORD,
            &self.mover,
            &self.signing_payload(),
            Some(signature),
        )
    }

    pub fn validate(&self) -> Result<(), RecordError> {
        const RECORD: &str = "bisection";
        if self.challenge_id.is_empty() {
            return Err(RecordError::InvalidField {
                record: RECORD,
                field: "challenge_id",
                expected: "the id of the challenge being played",
            });
        }
        // The same bound the availability answer carries, for the same reason:
        // a path longer than any tree needs is a record big enough to be a
        // nuisance and proves nothing extra.
        if self.path.len() > MAX_AVAILABILITY_PATH {
            return Err(RecordError::InvalidField {
                record: RECORD,
                field: "path",
                expected: "at most 32 sibling hashes",
            });
        }
        if self.state.canonical_bytes().len() > crate::challenge::MAX_STATE_BYTES {
            return Err(RecordError::InvalidField {
                record: RECORD,
                field: "state",
                expected: "a state of at most 64 KiB",
            });
        }
        Ok(())
    }

    pub fn from_value(value: &Value) -> Result<BisectionMove, RecordError> {
        const RECORD: &str = "bisection";
        let value = expect_object(value, RECORD)?;
        let path = match value.get("path") {
            Some(Value::Array(items)) => {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    match item.as_str() {
                        Some(hash) => out.push(hash.to_string()),
                        None => {
                            return Err(RecordError::InvalidField {
                                record: RECORD,
                                field: "path",
                                expected: "a list of hash strings",
                            })
                        }
                    }
                }
                out
            }
            _ => {
                return Err(RecordError::InvalidField {
                    record: RECORD,
                    field: "path",
                    expected: "a list of hash strings",
                })
            }
        };
        let record = BisectionMove {
            challenge_id: required_string(value, RECORD, "challenge_id")?,
            mover: required_string(value, RECORD, "mover")?,
            index: required_u64(value, RECORD, "index")?,
            state: value
                .get("state")
                .cloned()
                .ok_or(RecordError::InvalidField {
                    record: RECORD,
                    field: "state",
                    expected: "the state at that index",
                })?,
            path,
            created_at: required_string(value, RECORD, "created_at")?,
            signature: optional_string(value, RECORD, "signature")?,
        };
        record.validate()?;
        Ok(record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TS: &str = "2026-07-28T00:00:00+00:00";
    // Ids pinned by conformance/vectors.json, section "records".
    const OBJ_PLAIN: &str =
        "sha256:36dc4eb23ddd295b12608a6d84e2b03b48d437ce278105f93143215d260bb711";
    const OBJ_DEADLINE: &str =
        "sha256:963b51817b25a73e371736c38235dc6ef603f81fe765b41010ed1b89001d76f5";
    const OBJ_RATCHET: &str =
        "sha256:7aa80a57f7c916ba0bcff805b4a2fec9ee9c6b4fcccc1e9321d724c2d92922e4";

    fn certificate_verifier() -> Value {
        Value::object([
            ("kind", Value::string("certificate")),
            ("checker", Value::string("c.py")),
            ("entrypoint", Value::string("check")),
            ("checker_sha256", Value::string("ab".repeat(32))),
        ])
    }

    fn objective() -> Objective {
        Objective {
            goal: "GOAL-x".to_string(),
            statement: "find it".to_string(),
            verifier: certificate_verifier(),
            reward: 1000,
            funder: "treasury".to_string(),
            created_at: TS.to_string(),
            deadline: None,
            ratchet: None,
            confidentiality: Confidentiality::Public,
            embargo_epochs: None,
            artifact_schema: None,
            require_signed_submitter: false,
        }
    }

    fn artifact(n: i128) -> Value {
        Value::object([("n", Value::Int(n))])
    }

    // -- conformance vectors ------------------------------------------------

    #[test]
    fn objective_ids_match_the_reference_implementation() {
        assert_eq!(objective().id(), OBJ_PLAIN);

        let with_deadline = Objective {
            deadline: Some("2026-12-31T00:00:00+00:00".to_string()),
            ..objective()
        };
        assert_eq!(with_deadline.id(), OBJ_DEADLINE);

        let ratcheted = Objective {
            statement: "climb".to_string(),
            verifier: Value::object([
                ("kind", Value::string("evaluator")),
                ("threshold", Value::Int(0)),
            ]),
            reward: 1100,
            ratchet: Some(Value::object([
                ("baseline", Value::Int(9)),
                ("target", Value::Int(20)),
                ("reward", Value::Int(1100)),
                ("direction", Value::string("maximize")),
                ("min_improvement", Value::Int(1)),
            ])),
            ..objective()
        };
        assert_eq!(ratcheted.id(), OBJ_RATCHET);
    }

    #[test]
    fn claim_ids_match_the_reference_implementation() {
        let first = Claim::new(OBJ_PLAIN, "alice", artifact(42), "nonce-1", TS, vec![]).unwrap();
        assert_eq!(
            first.id(),
            "sha256:51b216380d88cf32e1e179dc8c52336c26e2aac447045dc4079f3a24bdeb334e"
        );
        assert_eq!(
            first.artifact_id(),
            "sha256:49620d2cbd95777da46e1c3d34793a4926d2f61f6ca2121bac91011e8613de4e"
        );
        assert_eq!(
            first.commitment_hash(),
            "sha256:4a1cf72173356258ac7b068cefa3a29e8e90b0e59c82ceb23207932210e1cf13"
        );

        let second = Claim::new(
            OBJ_PLAIN,
            "bob",
            artifact(43),
            "nonce-2",
            TS,
            vec![first.id()],
        )
        .unwrap();
        assert_eq!(
            second.id(),
            "sha256:b9ec4fb44ea9cda9ec1a5ca32ab41deb02abea633505fbaa41851ba81a28f60c"
        );
        assert_eq!(
            second.artifact_id(),
            "sha256:bf5d31f7fdaa4742e81515a8e60bc980fe9949878fded9aede8fbedcc4e896dd"
        );
        assert_eq!(
            second.commitment_hash(),
            "sha256:ac3e67c18598ba104830eb4ee2c4f21d60d5e2b3b51ad71925d94b7c52691180"
        );
    }

    #[test]
    fn commitment_id_matches_the_reference_implementation() {
        let commitment = Commitment::new(
            OBJ_PLAIN,
            "alice",
            "sha256:4a1cf72173356258ac7b068cefa3a29e8e90b0e59c82ceb23207932210e1cf13",
            TS,
        );
        assert_eq!(
            commitment.id(),
            "sha256:e86a6262807b107542f64d05900e54906dbebdd1a0e48e2e8d812b06bb900c28"
        );
    }

    #[test]
    fn commitment_hash_cases_match_the_reference_implementation() {
        // Each case differs from the first in exactly one input, so these also
        // demonstrate that submitter, nonce and artifact are all bound in.
        assert_eq!(
            commitment_hash(OBJ_PLAIN, "alice", &artifact(42), "n1"),
            "sha256:c4b7d428439e598333b066afb7eeddb2dbdc8f1e1a914ed639885740b1d5ff5e"
        );
        assert_eq!(
            commitment_hash(OBJ_PLAIN, "bob", &artifact(42), "n1"),
            "sha256:26287c0f8f805964d6772500fff3d5600e150977fd3ebb6bec4f8c088f86163d"
        );
        assert_eq!(
            commitment_hash(OBJ_PLAIN, "alice", &artifact(43), "n1"),
            "sha256:b5eef7ee4abaad1c787adf592778a6aec83cb8c5e7d84efe5a692eaeccec2552"
        );
        assert_eq!(
            commitment_hash(OBJ_PLAIN, "alice", &artifact(42), "n2"),
            "sha256:105a49b7816cfe2564c122a1b0e816f9539ee01bde503ec8d5a2b4055669e06e"
        );
        assert_eq!(
            commitment_hash(OBJ_PLAIN, "", &Value::Object(BTreeMap::new()), ""),
            "sha256:a081aaf9fef8ef92875521f0b864f2cb79ec6a19488df81ab5bde777425f9fa7"
        );
    }

    #[test]
    fn separators_stop_submitter_nonce_confusion() {
        // Without the '|' bytes, ("ab", "") and ("a", "b") would collide.
        assert_ne!(
            commitment_hash(OBJ_PLAIN, "ab", &artifact(1), ""),
            commitment_hash(OBJ_PLAIN, "a", &artifact(1), "b")
        );
    }

    // -- identity semantics -------------------------------------------------

    #[test]
    fn editing_the_verifier_forks_the_objective() {
        let a = objective();
        let b = Objective {
            verifier: Value::object([
                ("kind", Value::string("evaluator")),
                ("threshold", Value::Int(11)),
            ]),
            ..objective()
        };
        assert_ne!(a.id(), b.id());
    }

    #[test]
    fn editing_the_ratchet_forks_the_objective() {
        let with_ratchet = Objective {
            ratchet: Some(Value::object([("baseline", Value::Int(9))])),
            ..objective()
        };
        assert_ne!(with_ratchet.id(), objective().id());
    }

    #[test]
    fn unset_optionals_are_omitted_not_nulled() {
        let value = objective().to_value();
        assert!(value.get("deadline").is_none());
        assert!(value.get("ratchet").is_none());
        // The null-bearing spelling is a different record; if to_value ever
        // emitted it, every id in the network would move.
        let mut nulled = match value.clone() {
            Value::Object(map) => map,
            _ => unreachable!(),
        };
        nulled.insert("deadline".to_string(), Value::Null);
        assert_ne!(Value::Object(nulled).digest(), value.digest());
    }

    #[test]
    fn empty_cites_is_present_in_the_canonical_form() {
        let claim = Claim::new(OBJ_PLAIN, "alice", artifact(1), "n", TS, vec![]).unwrap();
        assert_eq!(claim.to_value().get("cites"), Some(&Value::Array(vec![])));
    }

    // -- decoding -----------------------------------------------------------

    #[test]
    fn objective_round_trips() {
        let original = Objective {
            deadline: Some("2026-12-31T00:00:00+00:00".to_string()),
            ratchet: Some(Value::object([("baseline", Value::Int(9))])),
            ..objective()
        };
        let decoded = Objective::from_value(&original.to_value()).unwrap();
        assert_eq!(decoded, original);
        assert_eq!(decoded.id(), original.id());
    }

    // -- artifact shape -----------------------------------------------------

    #[test]
    fn an_objective_without_an_artifact_schema_keeps_the_id_it_had_before_the_field_existed() {
        // Same argument as the confidentiality default, and the same
        // consequence if it ever fails: every objective in every deployed log
        // reissued, every claim against a live bounty orphaned. The
        // conformance vectors are the stronger check -- they were generated
        // before this field existed and still pass byte for byte.
        let plain = objective();
        assert!(plain.artifact_schema.is_none());
        assert!(
            plain.to_value().get("artifact_schema").is_none(),
            "an absent hint must not appear in the canonical form"
        );

        // Absent and explicitly-null decode the same, and neither is the
        // record a *present* hint produces.
        let mut nulled = match plain.to_value() {
            Value::Object(map) => map,
            _ => unreachable!(),
        };
        nulled.insert("artifact_schema".to_string(), Value::Null);
        let decoded = Objective::from_value(&Value::Object(nulled)).expect("decodes");
        assert_eq!(decoded.id(), plain.id());
        assert!(decoded.artifact_schema.is_none());
    }

    #[test]
    fn a_declared_artifact_shape_is_part_of_the_objective() {
        // It is a hint about what passes, so it belongs to the funded question
        // the way the verifier does: a funder cannot swap the documented shape
        // out from under work already submitted, because that is a different
        // objective.
        let plain = objective();
        let hinted = plain
            .clone()
            .with_artifact_schema(Value::object([("type", Value::string("object"))]))
            .expect("valid hint");
        assert_ne!(plain.id(), hinted.id());
        assert_eq!(
            hinted.to_value().get("artifact_schema").unwrap(),
            &Value::object([("type", Value::string("object"))])
        );
        let decoded = Objective::from_value(&hinted.to_value()).expect("round trips");
        assert_eq!(decoded, hinted);
        assert_eq!(decoded.id(), hinted.id());
    }

    #[test]
    fn an_artifact_schema_must_be_an_object_but_is_never_interpreted() {
        // Shape is checked so the field cannot be a bare string that one
        // implementation iterates and the other refuses. What it *says* is
        // never checked: the pinned verifier decides what passes, and a second
        // gate here would be a second answer to that question.
        let refused = objective().with_artifact_schema(Value::string("an object, honest"));
        assert!(refused.is_err(), "a non-object hint must be refused");

        // Nonsense that is shaped correctly is accepted, because validating it
        // is not this layer's business.
        let accepted = objective()
            .with_artifact_schema(Value::object([("wat", Value::Int(-1))]))
            .expect("shape is all that is checked");
        assert!(accepted.artifact_schema.is_some());
    }

    // -- confidentiality ----------------------------------------------------

    #[test]
    fn a_public_objective_keeps_the_id_it_had_before_the_field_existed() {
        // The reason `Public` is omitted from the canonical form. If this ever
        // fails, every objective in every deployed log has been reissued and
        // every claim against a live bounty has been orphaned.
        //
        // `objective_ids_match_the_reference_implementation` is the stronger
        // version of this check, since those digests were computed before the
        // field existed; this states the intent locally.
        let public = objective();
        assert_eq!(public.confidentiality, Confidentiality::Public);
        assert!(
            public.to_value().get("confidentiality").is_none(),
            "the default class must not appear in the canonical form"
        );
    }

    #[test]
    fn an_embargoed_objective_is_a_different_objective() {
        // Confidentiality is part of the funded question, so changing it forks
        // the objective exactly as changing the verifier does. A funder cannot
        // move a live bounty from public to embargoed after work has started.
        let public = objective();
        let embargoed = public
            .clone()
            .with_confidentiality(Confidentiality::Embargoed)
            .unwrap();
        assert_ne!(public.id(), embargoed.id());
        assert_eq!(
            embargoed.to_value().get("confidentiality").unwrap(),
            &Value::string("embargoed")
        );
    }

    #[test]
    fn sealed_is_refused_rather_than_downgraded() {
        // A submitter who asked for "never revealed" and silently got
        // "revealed later" would be misled about the only thing they cared
        // about, so this is an error rather than a fallback.
        let err = objective()
            .with_confidentiality(Confidentiality::Sealed)
            .unwrap_err();
        assert_eq!(err, RecordError::SealedNotImplemented);
        assert!(err.to_string().contains("zero-knowledge"), "{err}");

        // And it cannot be smuggled in through the decoder either.
        let mut body = objective().to_value().as_object().unwrap().clone();
        body.insert("confidentiality".to_string(), Value::string("sealed"));
        assert_eq!(
            Objective::from_value(&Value::Object(body)).unwrap_err(),
            RecordError::SealedNotImplemented
        );
    }

    #[test]
    fn an_unknown_class_is_refused_never_defaulted() {
        // Defaulting an unrecognised class to `public` would publish an
        // artifact whose funder asked for something else.
        let mut body = objective().to_value().as_object().unwrap().clone();
        body.insert("confidentiality".to_string(), Value::string("secret"));
        assert_eq!(
            Objective::from_value(&Value::Object(body)).unwrap_err(),
            RecordError::UnknownConfidentiality {
                value: "secret".to_string()
            }
        );
    }

    #[test]
    fn a_non_string_class_is_refused() {
        let mut body = objective().to_value().as_object().unwrap().clone();
        body.insert("confidentiality".to_string(), Value::Int(1));
        assert!(matches!(
            Objective::from_value(&Value::Object(body)).unwrap_err(),
            RecordError::InvalidField {
                field: "confidentiality",
                ..
            }
        ));
    }

    #[test]
    fn an_absent_or_null_class_decodes_as_public() {
        // Absent is the common case: every record written before this field
        // existed. Null is what a lax writer emits for "unset".
        for body in [None, Some(Value::Null)] {
            let mut raw = objective().to_value().as_object().unwrap().clone();
            if let Some(v) = body {
                raw.insert("confidentiality".to_string(), v);
            }
            let decoded = Objective::from_value(&Value::Object(raw)).unwrap();
            assert_eq!(decoded.confidentiality, Confidentiality::Public);
            assert_eq!(decoded.id(), objective().id());
        }
    }

    #[test]
    fn every_valid_class_round_trips() {
        for class in [Confidentiality::Public, Confidentiality::Embargoed] {
            let original = objective().with_confidentiality(class).unwrap();
            let decoded = Objective::from_value(&original.to_value()).unwrap();
            assert_eq!(decoded, original);
            assert_eq!(decoded.id(), original.id());
            assert_eq!(Confidentiality::parse(class.as_str()).unwrap(), class);
        }
    }

    #[test]
    fn only_public_reveals_at_settlement() {
        assert!(Confidentiality::Public.reveals_at_settlement());
        assert!(!Confidentiality::Embargoed.reveals_at_settlement());
        assert!(!Confidentiality::Sealed.reveals_at_settlement());
    }

    #[test]
    fn claim_round_trips() {
        let original = Claim::new(
            OBJ_PLAIN,
            "bob",
            artifact(43),
            "n",
            TS,
            vec!["sha256:aa".to_string(), "sha256:bb".to_string()],
        )
        .unwrap();
        let decoded = Claim::from_value(&original.to_value()).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn commitment_round_trips() {
        let original = Commitment::new(OBJ_PLAIN, "alice", "sha256:ff", TS);
        assert_eq!(
            Commitment::from_value(&original.to_value()).unwrap(),
            original
        );
    }

    #[test]
    fn an_untagged_objective_decodes() {
        // examples/*/objective.json carry no "type" field.
        let text = r#"{"created_at":"2026-07-28T00:00:00+00:00","funder":"treasury",
            "goal":"G","reward":100000,"statement":"do it",
            "verifier":{"kind":"certificate"}}"#;
        let value = Value::from_json(text).unwrap();
        assert_eq!(Objective::from_value(&value).unwrap().reward, 100_000);
    }

    #[test]
    fn a_null_deadline_decodes_as_absent() {
        let mut body = match objective().to_value() {
            Value::Object(map) => map,
            _ => unreachable!(),
        };
        body.insert("deadline".to_string(), Value::Null);
        let decoded = Objective::from_value(&Value::Object(body)).unwrap();
        assert_eq!(decoded.deadline, None);
        assert_eq!(decoded.id(), OBJ_PLAIN);
    }

    #[test]
    fn missing_and_mistyped_fields_are_named() {
        let mut body = match objective().to_value() {
            Value::Object(map) => map,
            _ => unreachable!(),
        };
        body.remove("funder");
        assert_eq!(
            Objective::from_value(&Value::Object(body.clone())),
            Err(RecordError::MissingField {
                record: "objective",
                field: "funder"
            })
        );
        body.insert("funder".to_string(), Value::Int(7));
        assert_eq!(
            Objective::from_value(&Value::Object(body)),
            Err(RecordError::InvalidField {
                record: "objective",
                field: "funder",
                expected: "a string"
            })
        );
    }

    #[test]
    fn a_non_object_is_not_a_record() {
        assert_eq!(
            Objective::from_value(&Value::Array(vec![])),
            Err(RecordError::NotAnObject {
                record: "objective"
            })
        );
    }

    // -- reward range -------------------------------------------------------

    #[test]
    fn the_largest_representable_reward_round_trips() {
        let big = Objective {
            reward: u64::MAX,
            ..objective()
        };
        let value = big.to_value();
        assert_eq!(value.get("reward"), Some(&Value::Int(i128::from(u64::MAX))));
        assert_eq!(Objective::from_value(&value).unwrap().reward, u64::MAX);
    }

    #[test]
    fn rewards_outside_u64_are_refused_not_truncated() {
        // Python has bignums; this crate does not. Silently wrapping such a
        // record would mean two implementations disagreeing about how much
        // money an objective holds.
        let too_big = i128::from(u64::MAX) + 1;
        let mut body = match objective().to_value() {
            Value::Object(map) => map,
            _ => unreachable!(),
        };
        body.insert("reward".to_string(), Value::Int(too_big));
        assert_eq!(
            Objective::from_value(&Value::Object(body.clone())),
            Err(RecordError::RewardOutOfRange { reward: too_big })
        );

        body.insert("reward".to_string(), Value::Int(-1));
        assert_eq!(
            Objective::from_value(&Value::Object(body)),
            Err(RecordError::RewardOutOfRange { reward: -1 })
        );
    }

    #[test]
    fn a_boolean_is_not_a_reward() {
        let mut body = match objective().to_value() {
            Value::Object(map) => map,
            _ => unreachable!(),
        };
        body.insert("reward".to_string(), Value::Bool(true));
        assert_eq!(
            Objective::from_value(&Value::Object(body)),
            Err(RecordError::InvalidField {
                record: "objective",
                field: "reward",
                expected: "an integer unit count"
            })
        );
    }

    // -- validation ---------------------------------------------------------

    #[test]
    fn an_objective_needs_a_statement() {
        let blank = Objective {
            statement: "   \n".to_string(),
            ..objective()
        };
        assert_eq!(blank.validate(), Err(RecordError::EmptyStatement));
    }

    #[test]
    fn an_objective_needs_a_verifier_with_a_kind() {
        let no_kind = Objective {
            verifier: Value::object([("checker", Value::string("c.py"))]),
            ..objective()
        };
        assert_eq!(no_kind.validate(), Err(RecordError::VerifierWithoutKind));

        let not_an_object = Objective {
            verifier: Value::string("certificate"),
            ..objective()
        };
        assert_eq!(
            not_an_object.validate(),
            Err(RecordError::VerifierWithoutKind)
        );
    }

    #[test]
    fn a_ratchet_must_be_an_object() {
        let bad = Objective {
            ratchet: Some(Value::Int(3)),
            ..objective()
        };
        assert_eq!(
            bad.validate(),
            Err(RecordError::InvalidField {
                record: "objective",
                field: "ratchet",
                expected: "an object"
            })
        );
    }

    #[test]
    fn duplicate_citations_are_refused() {
        let dup = Claim::new(
            OBJ_PLAIN,
            "alice",
            artifact(1),
            "n",
            TS,
            vec!["sha256:aa".to_string(), "sha256:aa".to_string()],
        );
        assert_eq!(
            dup,
            Err(RecordError::DuplicateCitation {
                id: "sha256:aa".to_string()
            })
        );
    }

    #[test]
    fn an_artifact_must_be_an_object() {
        let bad = Claim::new(OBJ_PLAIN, "alice", Value::Int(42), "n", TS, vec![]);
        assert_eq!(
            bad,
            Err(RecordError::InvalidField {
                record: "claim",
                field: "artifact",
                expected: "an object"
            })
        );
    }

    #[test]
    fn cites_must_be_an_array_of_strings() {
        let mut body = match Claim::new(OBJ_PLAIN, "alice", artifact(1), "n", TS, vec![])
            .unwrap()
            .to_value()
        {
            Value::Object(map) => map,
            _ => unreachable!(),
        };
        body.insert("cites".to_string(), Value::Array(vec![Value::Int(1)]));
        assert!(Claim::from_value(&Value::Object(body.clone())).is_err());
        body.insert("cites".to_string(), Value::Null);
        assert!(Claim::from_value(&Value::Object(body.clone())).is_err());
        body.remove("cites");
        assert_eq!(
            Claim::from_value(&Value::Object(body)).unwrap().cites,
            Vec::<String>::new()
        );
    }

    #[test]
    fn errors_display_usefully() {
        assert_eq!(
            RecordError::EmptyStatement.to_string(),
            "objective needs a statement"
        );
        assert!((RecordError::RewardOutOfRange { reward: -1 })
            .to_string()
            .contains("-1"));
    }

    // -- peer records -------------------------------------------------------

    fn peer_identity(byte: u8) -> crate::crypto::identity::Identity {
        crate::crypto::identity::Identity::from_secret_bytes([byte; 32])
    }

    fn peer_record(identity: &crate::crypto::identity::Identity, seq: u64) -> PeerRecord {
        PeerRecord::new(
            identity.submitter_id(),
            "ab".repeat(32),
            "203.0.113.9:9000",
            seq,
            "2026-07-28T00:00:00+00:00",
        )
        .signed_with(identity)
    }

    #[test]
    fn a_peer_record_round_trips_and_its_id_covers_its_signature() {
        // The same property every signed record here has: strip the signature
        // and you have a *different* record, so a signature cannot be removed
        // from something somebody cited.
        let identity = peer_identity(1);
        let record = peer_record(&identity, 1);
        assert!(record.verify_signature().is_ok());

        let decoded = PeerRecord::from_value(&record.to_value()).expect("decodes");
        assert_eq!(decoded, record);
        assert!(decoded.verify_signature().is_ok());

        let mut stripped = record.clone();
        stripped.signature = None;
        assert_ne!(stripped.id(), record.id());
    }

    #[test]
    fn a_peer_record_must_be_signed_and_only_for_itself() {
        // A claim may be posted under a nickname because a nickname claims
        // nothing. A peer record exists to authenticate an address, so an
        // unsigned one authenticates nothing and is refused rather than
        // admitted as a weaker statement.
        let identity = peer_identity(2);
        let mut unsigned = peer_record(&identity, 1);
        unsigned.signature = None;
        assert!(matches!(
            unsigned.verify_signature(),
            Err(SignatureError::Missing { .. })
        ));

        // Signed by one identity, claiming another's name.
        let mallory = peer_identity(3);
        let mut forged = peer_record(&mallory, 1);
        forged.identity = identity.submitter_id();
        assert!(matches!(
            forged.verify_signature(),
            Err(SignatureError::Invalid { .. })
        ));

        // And a nickname is not an identity here at all.
        let mut nickname = peer_record(&identity, 1);
        nickname.identity = String::from("alice");
        assert!(nickname.verify_signature().is_err());
    }

    #[test]
    fn every_signed_field_is_covered_by_the_signature() {
        // The check that makes the record worth anything: an attacker who
        // could change the address without breaking the signature would have
        // the whole prize, since redirecting dials is the only thing this
        // record can be abused for.
        let identity = peer_identity(4);
        let record = peer_record(&identity, 1);
        for tamper in [
            |r: &mut PeerRecord| r.addr = String::from("198.51.100.1:9000"),
            |r: &mut PeerRecord| r.transport = "cd".repeat(32),
            |r: &mut PeerRecord| r.seq = 99,
            |r: &mut PeerRecord| r.created_at = String::from("2030-01-01T00:00:00+00:00"),
        ] {
            let mut tampered = record.clone();
            tamper(&mut tampered);
            assert!(
                tampered.verify_signature().is_err(),
                "a field outside the signature: {tampered:?}"
            );
        }
    }

    #[test]
    fn an_address_is_bounded_and_never_parsed() {
        // Deliberately not `SocketAddr::from_str`. Two implementations
        // disagreeing about whether an IPv6 form is well-formed is a consensus
        // split, so the rule is length and printable ASCII and the network
        // layer parses what it can.
        let identity = peer_identity(5);
        let mut record = peer_record(&identity, 1);

        record.addr = String::new();
        assert!(record.validate().is_err(), "an empty address was admitted");

        record.addr = "a".repeat(MAX_PEER_ADDR + 1);
        assert!(
            record.validate().is_err(),
            "an unbounded address was admitted"
        );

        record.addr = "a".repeat(MAX_PEER_ADDR);
        assert!(record.validate().is_ok());

        // A form this crate cannot dial is still admissible: the consensus
        // layer does not get to decide what a network layer can reach.
        record.addr = String::from("peer.example.onion:9000");
        assert!(record.validate().is_ok());

        for bad in ["with space:1", "quote\":1", "back\\slash:1", "tab\t:1"] {
            record.addr = bad.to_string();
            assert!(record.validate().is_err(), "{bad:?} was admitted");
        }
    }

    #[test]
    fn identity_and_transport_must_both_be_key_shaped() {
        let identity = peer_identity(6);
        let mut record = peer_record(&identity, 1);
        record.transport = "AB".repeat(32);
        assert!(record.validate().is_err(), "uppercase hex was admitted");
        record.transport = String::from("ab");
        assert!(
            record.validate().is_err(),
            "a short transport id was admitted"
        );
        record.transport = "ab".repeat(32);
        assert!(record.validate().is_ok());
    }

    #[test]
    fn a_sequence_outside_u64_is_refused_rather_than_truncated() {
        // The boundary an arbitrary-precision implementation reaches and this
        // one has to agree about. Truncating would make a record that is
        // *admissible elsewhere* decode here as a different record.
        let identity = peer_identity(7);
        let record = peer_record(&identity, 1);
        let Value::Object(mut body) = record.to_value() else {
            panic!("a record is an object");
        };
        for bad in [
            Value::Int(-1),
            Value::Int(i128::from(u64::MAX) + 1),
            Value::string("3"),
        ] {
            body.insert("seq".to_string(), bad.clone());
            assert!(
                PeerRecord::from_value(&Value::Object(body.clone())).is_err(),
                "seq {bad:?} was admitted"
            );
        }
        body.insert("seq".to_string(), Value::Int(i128::from(u64::MAX)));
        assert_eq!(
            PeerRecord::from_value(&Value::Object(body))
                .expect("the top of the range decodes")
                .seq,
            u64::MAX
        );
    }

    /// The signed undertaking the *other* implementation pins as a fixture.
    ///
    /// `reference/rust` cannot sign — deliberately, so it can never agree with
    /// this crate by sharing its bug — which means its audit tests need a
    /// genuinely signed record borrowed from here. A borrowed constant rots
    /// silently: add a field to the record and the reference's copy becomes a
    /// record this crate would no longer write, so the two implementations stop
    /// being compared on the same bytes while both still pass.
    ///
    /// So the bytes live here, where changing the record breaks *this* test
    /// first and names the file to update. If you are reading this because it
    /// failed: paste the printed value into `SIGNED` in
    /// `reference/rust/src/node.rs`.
    #[test]
    fn the_signed_undertaking_the_reference_crate_pins_is_still_what_this_crate_writes() {
        const SIGNED: &str = r#"{"bond":500,"created_at":"2026-08-14T00:00:00+00:00","height":3,"identity":"197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa8b3d368d61","root":"sha256:30ffa4f80f8e0198fd85844b9a63b682f11f1bca7a67532aaaae0f20d17e78ed","signature":"bac8259da5214a3026e01f1e912988a1cb4fd6969085a6ad0cddb6a43af99ee1a6202b4df610dd2e8df8472c34f6a7985d3ee0ed2ea37d1094f1f64ef15d4f06","type":"undertaking"}"#;

        let who = crate::crypto::identity::Identity::from_secret_bytes([42u8; 32]);
        let record = Undertaking::new(
            "",
            crate::canonical::digest_bytes(b"a root no log ever had"),
            3,
            500,
            "2026-08-14T00:00:00+00:00",
        )
        .signed_with(&who);
        record.verify_signature().expect("this crate signs it");
        assert_eq!(
            record.to_value().canonical_string(),
            SIGNED,
            "the undertaking record changed shape; \
             reference/rust/src/node.rs pins the old bytes"
        );
    }
}
