//! The three records: objective, commitment, claim.
//!
//! Every record is content-addressed -- its id *is* the hash of its canonical
//! form -- and two rules follow from that, both of which this crate exists to
//! check independently.
//!
//! **Optional fields are omitted, never nulled.** A field emitted as `null`
//! is a different byte string, hence a different digest, hence a different
//! record. Any field added after launch must therefore be absent when it holds
//! whatever every pre-existing record meant by its absence, or every id ever
//! issued moves and every claim against a live bounty is orphaned.
//!
//! **The verifier is part of the objective's identity.** Editing an evaluator
//! does not rescore work already done against it; it produces a different
//! objective. Mid-bounty rule changes are unrepresentable rather than guarded.

use std::collections::BTreeSet;
use std::fmt;

use crate::canonical::{digest_bytes, short, Value};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordError(pub String);

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for RecordError {}

pub const CONFIDENTIALITY_CLASSES: &[&str] = &["public", "embargoed", "sealed"];
pub const DEFAULT_CONFIDENTIALITY: &str = "public";
/// The format's reward ceiling: `u64::MAX`. Python has bignums and fixed-width
/// implementations do not, so the bound is part of the format rather than of
/// any one language.
pub const MAX_UNITS: i128 = u64::MAX as i128;

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a Value, RecordError> {
    value
        .get(name)
        .ok_or_else(|| RecordError(format!("missing required field {name:?}")))
}

fn text(value: &Value, name: &str) -> Result<String, RecordError> {
    field(value, name)?
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| RecordError(format!("field {name:?} must be a string")))
}

fn optional_text(value: &Value, name: &str) -> Result<Option<String>, RecordError> {
    match value.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text.clone())),
        Some(_) => Err(RecordError(format!("field {name:?} must be a string"))),
    }
}

/// Whether a submitter name is an ed25519 public key.
///
/// `submitter` is a free string, which means a nickname is worth nothing:
/// anyone can type one, and citation flow pays it. A submitter that is 64
/// lowercase hex characters is different -- it *is* a public key, and a record
/// naming one must carry a signature that verifies under it. The name is the
/// key, so no registry is consulted.
///
/// Lowercase only. Accepting mixed case would make `AB…` and `ab…` two names
/// for one key, so one key could hold two reputations and cite itself.
pub fn signed_submitter(submitter: &str) -> Option<&str> {
    let looks_like_key = submitter.len() == 64
        && submitter
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    looks_like_key.then_some(submitter)
}

/// Verify the signature a record carries, if the rules demand one.
pub fn verify_record_signature(
    record: &str,
    submitter: &str,
    payload: &Value,
    signature: Option<&str>,
) -> Result<(), RecordError> {
    let Some(key_hex) = signed_submitter(submitter) else {
        // A nickname claims nothing, so nothing is checked. A signature on one
        // is still refused rather than ignored, so it cannot look like
        // authentication it is not.
        return match signature {
            None => Ok(()),
            Some(_) => Err(RecordError(format!(
                "{record} carries a signature but submitter {submitter:?} is not a public \
                 key, so nothing authenticates it"
            ))),
        };
    };
    let Some(signature) = signature else {
        return Err(RecordError(format!(
            "{record} submitter {} is a public key, so the record must carry a signature \
             from it",
            short(submitter)
        )));
    };
    let bad = || {
        RecordError(format!(
            "{record} signature does not verify under submitter {}",
            short(submitter)
        ))
    };
    let key = crate::sig::public_key(key_hex).ok_or_else(bad)?;
    let signature = crate::sig::signature(signature).ok_or_else(bad)?;
    crate::sig::verify(&key, &payload.canonical_bytes(), &signature)
        .then_some(())
        .ok_or_else(bad)
}

// -- objective --------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Objective {
    pub goal: String,
    pub statement: String,
    pub verifier: Value,
    pub reward: u64,
    pub funder: String,
    pub created_at: String,
    pub deadline: Option<String>,
    pub ratchet: Option<Value>,
    pub confidentiality: String,
    pub artifact_schema: Option<Value>,
    pub require_signed_submitter: bool,
}

impl Objective {
    pub fn to_value(&self) -> Value {
        let mut body = vec![
            ("type", Value::string("objective")),
            ("goal", Value::string(self.goal.clone())),
            ("statement", Value::string(self.statement.clone())),
            ("verifier", self.verifier.clone()),
            ("reward", Value::Int(i128::from(self.reward))),
            ("funder", Value::string(self.funder.clone())),
            ("created_at", Value::string(self.created_at.clone())),
        ];
        if let Some(deadline) = &self.deadline {
            body.push(("deadline", Value::string(deadline.clone())));
        }
        if let Some(ratchet) = &self.ratchet {
            body.push(("ratchet", ratchet.clone()));
        }
        if self.confidentiality != DEFAULT_CONFIDENTIALITY {
            body.push((
                "confidentiality",
                Value::string(self.confidentiality.clone()),
            ));
        }
        if let Some(schema) = &self.artifact_schema {
            body.push(("artifact_schema", schema.clone()));
        }
        if self.require_signed_submitter {
            body.push(("require_signed_submitter", Value::Bool(true)));
        }
        Value::object(body)
    }

    pub fn id(&self) -> String {
        self.to_value().digest()
    }

    pub fn verifier_kind(&self) -> Option<&str> {
        self.verifier.get("kind").and_then(Value::as_str)
    }

    pub fn from_value(value: &Value) -> Result<Objective, RecordError> {
        if value.as_object().is_none() {
            return Err(RecordError("objective must be an object".into()));
        }
        let raw_reward = field(value, "reward")?
            .as_i128()
            .ok_or_else(|| RecordError("reward must be an integer unit count".into()))?;
        if !(0..=MAX_UNITS).contains(&raw_reward) {
            return Err(RecordError(format!(
                "reward {raw_reward} is outside the representable range (0..={MAX_UNITS})"
            )));
        }
        // Absent and null both mean unset; anything else must be the right
        // type. Treating a falsy value as unset is how the two implementations
        // once disagreed about which records were valid.
        let confidentiality = match value.get("confidentiality") {
            None | Some(Value::Null) => DEFAULT_CONFIDENTIALITY.to_string(),
            Some(Value::String(class)) => class.clone(),
            Some(_) => return Err(RecordError("confidentiality must be a string".into())),
        };
        if !CONFIDENTIALITY_CLASSES.contains(&confidentiality.as_str()) {
            return Err(RecordError(format!(
                "unknown confidentiality class {confidentiality:?}"
            )));
        }
        if confidentiality == "sealed" {
            return Err(RecordError(
                "confidentiality \"sealed\" requires zero-knowledge verification, which is \
                 not implemented"
                    .into(),
            ));
        }
        let require_signed_submitter = match value.get("require_signed_submitter") {
            None | Some(Value::Null) => false,
            Some(Value::Bool(flag)) => *flag,
            // Not coerced. "yes" meaning true here and false elsewhere is two
            // implementations disagreeing about which submissions are legal.
            Some(_) => {
                return Err(RecordError(
                    "require_signed_submitter must be a boolean".into(),
                ))
            }
        };
        let objective = Objective {
            goal: text(value, "goal")?,
            statement: text(value, "statement")?,
            verifier: field(value, "verifier")?.clone(),
            reward: raw_reward as u64,
            funder: text(value, "funder")?,
            created_at: text(value, "created_at")?,
            deadline: optional_text(value, "deadline")?,
            ratchet: match value.get("ratchet") {
                None | Some(Value::Null) => None,
                Some(other) => Some(other.clone()),
            },
            confidentiality,
            artifact_schema: match value.get("artifact_schema") {
                None | Some(Value::Null) => None,
                Some(other) => Some(other.clone()),
            },
            require_signed_submitter,
        };
        objective.validate()?;
        Ok(objective)
    }

    pub fn validate(&self) -> Result<(), RecordError> {
        if self.statement.trim().is_empty() {
            return Err(RecordError("objective needs a statement".into()));
        }
        if self.verifier_kind().is_none() {
            return Err(RecordError(
                "objective needs a verifier with a 'kind'".into(),
            ));
        }
        if let Some(ratchet) = &self.ratchet {
            if ratchet.as_object().is_none() {
                return Err(RecordError("ratchet must be an object".into()));
            }
        }
        if let Some(schema) = &self.artifact_schema {
            if schema.as_object().is_none() {
                return Err(RecordError("artifact_schema must be an object".into()));
            }
        }
        Ok(())
    }
}

// -- commitment -------------------------------------------------------------

/// `H(H({objective_id, artifact}) ‖ submitter ‖ nonce)`.
///
/// The submitter is inside the hash so an observer cannot replay somebody
/// else's commitment under their own name; the nonce stops a guessable
/// artifact being brute-forced out of the commitment before it is revealed.
pub fn commitment_hash(
    objective_id: &str,
    submitter: &str,
    artifact: &Value,
    nonce: &str,
) -> String {
    let inner = Value::object([
        ("objective_id", Value::string(objective_id)),
        ("artifact", artifact.clone()),
    ])
    .digest();
    let mut buf = Vec::new();
    buf.extend_from_slice(inner.as_bytes());
    buf.push(b'|');
    buf.extend_from_slice(submitter.as_bytes());
    buf.push(b'|');
    buf.extend_from_slice(nonce.as_bytes());
    digest_bytes(&buf)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commitment {
    pub objective_id: String,
    pub submitter: String,
    pub hash: String,
    pub created_at: String,
    /// The artifact sealed to the epoch's threshold committee, when this is a
    /// sealed submission.
    ///
    /// **Carried opaquely, and that is the right thing for this
    /// implementation to do.** The primary decodes it into a
    /// `crypto::envelope::SealedEnvelope` because it has to open one; this
    /// crate never opens anything, and re-deriving a KEM stack here would be
    /// re-deriving the wrong thing. What must agree between the two is the
    /// *encoding* — the field is inside the signing payload and therefore
    /// inside every sealed commitment's id — and carrying the raw `Value`
    /// through is exactly what makes that checkable: if the primary emitted
    /// bytes this could not round-trip, the audit's re-encode pass says so.
    ///
    /// Omitted when absent, so a commitment written before the field existed
    /// digests to what it always did.
    pub envelope: Option<Value>,
    pub signature: Option<String>,
}

impl Commitment {
    /// The bytes a signature covers: this record without its own signature.
    /// Excluded rather than zeroed -- a signature over the field holding it is
    /// not something anyone can produce.
    pub fn signing_payload(&self) -> Value {
        let mut value = Value::object([
            ("type", Value::string("commitment")),
            ("objective_id", Value::string(self.objective_id.clone())),
            ("submitter", Value::string(self.submitter.clone())),
            ("hash", Value::string(self.hash.clone())),
            ("created_at", Value::string(self.created_at.clone())),
        ]);
        if let (Value::Object(map), Some(envelope)) = (&mut value, &self.envelope) {
            map.insert("envelope".into(), envelope.clone());
        }
        value
    }

    pub fn to_value(&self) -> Value {
        let mut value = self.signing_payload();
        if let (Value::Object(map), Some(signature)) = (&mut value, &self.signature) {
            map.insert("signature".into(), Value::string(signature.clone()));
        }
        value
    }

    pub fn id(&self) -> String {
        self.to_value().digest()
    }

    pub fn verify_signature(&self) -> Result<(), RecordError> {
        verify_record_signature(
            "commitment",
            &self.submitter,
            &self.signing_payload(),
            self.signature.as_deref(),
        )
    }

    pub fn from_value(value: &Value) -> Result<Commitment, RecordError> {
        Ok(Commitment {
            objective_id: text(value, "objective_id")?,
            submitter: text(value, "submitter")?,
            hash: text(value, "hash")?,
            created_at: text(value, "created_at")?,
            envelope: value.get("envelope").cloned(),
            signature: optional_text(value, "signature")?,
        })
    }
}

// -- claim ------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    pub objective_id: String,
    pub submitter: String,
    pub artifact: Value,
    pub nonce: String,
    pub created_at: String,
    pub cites: Vec<String>,
    /// Typed assertions about earlier claims. Carries no money — this crate
    /// re-derives attribution from `cites` alone and never consults this.
    ///
    /// Held as decoded `(kind, target)` pairs rather than raw values so that an
    /// unknown kind fails here, where the primary also fails, instead of
    /// surviving as an opaque blob this crate would happily re-emit.
    pub relations: Vec<ClaimRelation>,
    pub signature: Option<String>,
}

/// The nine relation kinds, spelled as they appear on the wire.
///
/// Kept as a list rather than an enum: this crate's job is to agree with the
/// primary about which spellings exist, and a list is the smallest way to say
/// that. What matters is that the set is closed and that an unknown spelling is
/// an error — a kind one implementation accepted and the other dropped would
/// give the two different claim bytes for the same input.
pub const RELATION_KINDS: [&str; 9] = [
    "refutes",
    "fails_to_replicate",
    "replicates",
    "generalizes",
    "narrows",
    "corrects",
    "supersedes",
    "conflicts_with",
    "retracts",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimRelation {
    pub kind: String,
    pub target: String,
}

impl ClaimRelation {
    pub fn to_value(&self) -> Value {
        Value::object([
            ("kind", Value::string(self.kind.clone())),
            ("target", Value::string(self.target.clone())),
        ])
    }

    pub fn from_value(value: &Value) -> Result<ClaimRelation, RecordError> {
        if value.as_object().is_none() {
            return Err(RecordError("a relation must be an object".into()));
        }
        let kind = text(value, "kind")?;
        if !RELATION_KINDS.contains(&kind.as_str()) {
            return Err(RecordError(format!("unknown relation kind {kind:?}")));
        }
        let target = text(value, "target")?;
        if target.is_empty() {
            return Err(RecordError("a relation target must not be empty".into()));
        }
        // Refused rather than ignored: a key the primary rejects and this crate
        // accepts is a record the two disagree about admitting.
        if let Some(map) = value.as_object() {
            for key in map.keys() {
                if key != "kind" && key != "target" {
                    return Err(RecordError(format!("unknown relation field {key:?}")));
                }
            }
        }
        Ok(ClaimRelation { kind, target })
    }
}

impl Claim {
    /// `cites` is always present, empty list included: it is not optional, and
    /// omitting it when empty would give one claim two ids depending on how it
    /// was built.
    ///
    /// `relations` is the opposite: omitted entirely when empty. It was added
    /// after ids were in circulation, so an empty array would have moved every
    /// one of them.
    pub fn signing_payload(&self) -> Value {
        let mut value = Value::object([
            ("type", Value::string("claim")),
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
                        .map(|c| Value::string(c.clone()))
                        .collect(),
                ),
            ),
        ]);
        if !self.relations.is_empty() {
            if let Value::Object(map) = &mut value {
                map.insert(
                    "relations".into(),
                    Value::Array(self.relations.iter().map(ClaimRelation::to_value).collect()),
                );
            }
        }
        value
    }

    pub fn to_value(&self) -> Value {
        let mut value = self.signing_payload();
        if let (Value::Object(map), Some(signature)) = (&mut value, &self.signature) {
            map.insert("signature".into(), Value::string(signature.clone()));
        }
        value
    }

    pub fn id(&self) -> String {
        self.to_value().digest()
    }

    /// Identity of the artifact alone, scoped by objective. Submitter and
    /// nonce are excluded on purpose: that is what makes a copied artifact
    /// recognisable as the same work whoever reveals it.
    pub fn artifact_id(&self) -> String {
        Value::object([
            ("objective_id", Value::string(self.objective_id.clone())),
            ("artifact", self.artifact.clone()),
        ])
        .digest()
    }

    pub fn commitment_hash(&self) -> String {
        commitment_hash(
            &self.objective_id,
            &self.submitter,
            &self.artifact,
            &self.nonce,
        )
    }

    pub fn verify_signature(&self) -> Result<(), RecordError> {
        verify_record_signature(
            "claim",
            &self.submitter,
            &self.signing_payload(),
            self.signature.as_deref(),
        )
    }

    pub fn validate(&self) -> Result<(), RecordError> {
        if self.artifact.as_object().is_none() {
            return Err(RecordError("claim artifact must be an object".into()));
        }
        // Not tidiness: attribution splits credit across a claim's edges, so
        // the same parent listed twice would draw twice the flow.
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for cited in &self.cites {
            if !seen.insert(cited.as_str()) {
                return Err(RecordError(format!("duplicate citation {cited:?}")));
            }
        }
        // Keyed on the target, not the (kind, target) pair: one claim says one
        // thing about any other claim, so there is never a pair of relations
        // whose combined meaning the two implementations must agree on.
        let mut targets: BTreeSet<&str> = BTreeSet::new();
        for relation in &self.relations {
            if !targets.insert(relation.target.as_str()) {
                return Err(RecordError(format!(
                    "two relations name the target {:?}",
                    relation.target
                )));
            }
        }
        Ok(())
    }

    pub fn from_value(value: &Value) -> Result<Claim, RecordError> {
        let cites = match value.get("cites") {
            None => Vec::new(),
            Some(Value::Array(items)) => {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    out.push(
                        item.as_str()
                            .ok_or_else(|| {
                                RecordError("cites must be an array of claim ids".into())
                            })?
                            .to_string(),
                    );
                }
                out
            }
            Some(_) => return Err(RecordError("cites must be an array of claim ids".into())),
        };
        // Absent is empty; `null` is not. A record spelling "no relations" two
        // ways would have two ids.
        let relations = match value.get("relations") {
            None => Vec::new(),
            Some(Value::Array(items)) => items
                .iter()
                .map(ClaimRelation::from_value)
                .collect::<Result<Vec<_>, _>>()?,
            Some(_) => {
                return Err(RecordError(
                    "relations must be an array of {kind, target} objects".into(),
                ))
            }
        };
        let claim = Claim {
            objective_id: text(value, "objective_id")?,
            submitter: text(value, "submitter")?,
            artifact: field(value, "artifact")?.clone(),
            nonce: text(value, "nonce")?,
            created_at: text(value, "created_at")?,
            cites,
            relations,
            signature: optional_text(value, "signature")?,
        };
        claim.validate()?;
        Ok(claim)
    }
}

// -- committee share ---------------------------------------------------------

/// One committee member opening its share of a sealed submission's content key.
///
/// Re-derived here because the primary treats it as an admission rule, and a
/// rule only one implementation applies is a rule two nodes can disagree about
/// while both audit clean. What this crate checks is everything that does not
/// require opening anything: the encoding, the structure, the signature, the
/// epoch ordering against the commitment, and the committee draw itself.
///
/// What it does **not** check is whether the share is *correct*, and neither
/// does the primary — a Shamir point cannot be verified alone without a
/// verifiable-sharing scheme, and the ones that exist need a group where
/// discrete log is hard, which a post-quantum network has declined to assume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitteeShare {
    pub commitment: String,
    pub seat: u8,
    pub x: u8,
    pub share: String,
    pub created_at: String,
    pub identity: String,
    pub signature: Option<String>,
}

/// Longest share body a committee share may carry, in bytes before hex.
pub const MAX_SHARE_BYTES: usize = 1024;

impl CommitteeShare {
    pub fn signing_payload(&self) -> Value {
        Value::object([
            ("type", Value::string("committee_share")),
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

    /// Always required. An unsigned share is an anonymous assertion that a seat
    /// published, which anyone could write for any member.
    pub fn verify_signature(&self) -> Result<(), RecordError> {
        if signed_submitter(&self.identity).is_none() {
            return Err(RecordError(format!(
                "committee_share identity {:?} is not a public key",
                self.identity
            )));
        }
        verify_record_signature(
            "committee_share",
            &self.identity,
            &self.signing_payload(),
            self.signature.as_deref(),
        )
    }

    pub fn validate(&self) -> Result<(), RecordError> {
        let lower_hex = |text: &str| {
            text.len().is_multiple_of(2)
                && text
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        let id = self.commitment.strip_prefix("sha256:").unwrap_or_default();
        if id.len() != 64 || !lower_hex(id) {
            return Err(RecordError(
                "committee_share commitment must be a record id".into(),
            ));
        }
        if self.identity.len() != 64 || !lower_hex(&self.identity) {
            return Err(RecordError(
                "committee_share identity must be 64 lowercase hex".into(),
            ));
        }
        // `f(0)` is the secret itself, so no honest split ever issues x = 0.
        if self.x == 0 {
            return Err(RecordError(
                "committee_share x must be a non-zero Shamir coordinate".into(),
            ));
        }
        if self.share.is_empty() || !lower_hex(&self.share) {
            return Err(RecordError(
                "committee_share share must be non-empty lowercase hex".into(),
            ));
        }
        if self.share.len() / 2 > MAX_SHARE_BYTES {
            return Err(RecordError("committee_share share is too long".into()));
        }
        Ok(())
    }

    pub fn from_value(value: &Value) -> Result<CommitteeShare, RecordError> {
        let small = |name: &str| -> Result<u8, RecordError> {
            value
                .get(name)
                .and_then(Value::as_i128)
                .and_then(|n| u8::try_from(n).ok())
                .ok_or_else(|| {
                    RecordError(format!(
                        "committee_share {name} must be an integer in 0..=255"
                    ))
                })
        };
        Ok(CommitteeShare {
            commitment: text(value, "commitment")?,
            seat: small("seat")?,
            x: small("x")?,
            share: text(value, "share")?,
            created_at: text(value, "created_at")?,
            identity: text(value, "identity")?,
            signature: optional_text(value, "signature")?,
        })
    }
}

// -- peer -------------------------------------------------------------------

/// A peer's permanent identity, and the transport it currently answers on.
///
/// Two keys, and the binding between them is the record's whole content:
/// **ed25519** signs and is 32 bytes, so it is affordable in a log every node
/// replicates; **McEliece** keys the transport, cannot sign at all, and its
/// public key is 261,120 bytes, which is not. So the ed25519 key is the
/// authority and the McEliece *peer id* -- the `sha256` of that key -- is what
/// it vouches for. The transport key itself is fetched over the wire and
/// checked against the id, which needs no trust because the id is its hash.
///
/// The address is a hint and not permanent, so a peer that moves appends a
/// record with a higher `seq`; the highest wins. Append-only plus a sequence
/// number is last-writer-wins with an audit trail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRecord {
    pub identity: String,
    pub transport: String,
    pub addr: String,
    pub seq: u64,
    pub created_at: String,
    pub signature: Option<String>,
}

/// Longest `addr` a peer record may carry.
///
/// A bound rather than a parse, and deliberately so: `SocketAddr` parsing
/// differs between languages at the edges -- IPv6 bracket forms, leading
/// zeros, zone identifiers -- and two implementations disagreeing about
/// whether a record is admissible is a consensus split.
pub const MAX_PEER_ADDR: usize = 255;

impl PeerRecord {
    pub fn signing_payload(&self) -> Value {
        Value::object([
            ("type", Value::string("peer")),
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

    /// Always required, unlike a claim's. A claim may be posted under a
    /// nickname because a nickname claims nothing; a record whose whole purpose
    /// is to authenticate an address would authenticate nothing without one.
    pub fn verify_signature(&self) -> Result<(), RecordError> {
        if signed_submitter(&self.identity).is_none() {
            return Err(RecordError(format!(
                "peer identity {:?} is not a public key, so nothing authenticates the record",
                self.identity
            )));
        }
        verify_record_signature(
            "peer",
            &self.identity,
            &self.signing_payload(),
            self.signature.as_deref(),
        )
    }

    pub fn validate(&self) -> Result<(), RecordError> {
        let hex64 = |text: &str| {
            text.len() == 64
                && text
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        if !hex64(&self.identity) {
            return Err(RecordError("peer identity must be 64 lowercase hex".into()));
        }
        if !hex64(&self.transport) {
            return Err(RecordError(
                "peer transport must be 64 lowercase hex".into(),
            ));
        }
        if self.addr.is_empty()
            || self.addr.len() > MAX_PEER_ADDR
            || !self
                .addr
                .bytes()
                .all(|b| b.is_ascii_graphic() && b != b'"' && b != b'\\')
        {
            return Err(RecordError(
                "peer addr must be 1 to 255 printable ASCII characters, no quote or backslash"
                    .into(),
            ));
        }
        Ok(())
    }

    pub fn from_value(value: &Value) -> Result<PeerRecord, RecordError> {
        let seq = match field(value, "seq")? {
            // Checked here rather than at a cast: a record from an
            // arbitrary-precision implementation must be refused rather than
            // silently truncated into a *different* record.
            Value::Int(n) if *n >= 0 && *n <= i128::from(u64::MAX) => *n as u64,
            _ => {
                return Err(RecordError(
                    "peer seq must be an integer in [0, 2^64)".into(),
                ))
            }
        };
        let record = PeerRecord {
            identity: text(value, "identity")?,
            transport: text(value, "transport")?,
            addr: text(value, "addr")?,
            seq,
            created_at: text(value, "created_at")?,
            signature: optional_text(value, "signature")?,
        };
        record.validate()?;
        Ok(record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verifier() -> Value {
        Value::object([
            ("kind", Value::string("certificate")),
            ("checker", Value::string("c.py")),
            ("checker_sha256", Value::string("ab".repeat(32))),
            ("entrypoint", Value::string("check")),
        ])
    }

    fn objective() -> Objective {
        Objective {
            goal: "G".into(),
            statement: "s".into(),
            verifier: verifier(),
            reward: 1000,
            funder: "treasury".into(),
            created_at: "2026-07-28T00:00:00+00:00".into(),
            deadline: None,
            ratchet: None,
            confidentiality: DEFAULT_CONFIDENTIALITY.into(),
            artifact_schema: None,
            require_signed_submitter: false,
        }
    }

    #[test]
    fn optional_fields_are_omitted_when_unset() {
        // The rule that lets a field be added without reissuing every id.
        let value = objective().to_value();
        for absent in [
            "deadline",
            "ratchet",
            "confidentiality",
            "artifact_schema",
            "require_signed_submitter",
        ] {
            assert!(value.get(absent).is_none(), "{absent} was emitted");
        }
    }

    #[test]
    fn absent_and_null_and_falsy_are_not_interchangeable() {
        let mut body = objective().to_value();
        let base = Objective::from_value(&body).unwrap().id();

        // Explicit null means unset, and must not move the id.
        if let Value::Object(map) = &mut body {
            map.insert("confidentiality".into(), Value::Null);
        }
        assert_eq!(Objective::from_value(&body).unwrap().id(), base);

        // Falsy values of the wrong type are refused, never defaulted -- the
        // divergence a falsy-means-unset decoder introduces.
        for bad in [Value::string(""), Value::Int(0), Value::Bool(false)] {
            let mut body = objective().to_value();
            if let Value::Object(map) = &mut body {
                map.insert("confidentiality".into(), bad.clone());
            }
            assert!(Objective::from_value(&body).is_err(), "{bad:?} accepted");
        }
    }

    #[test]
    fn the_reward_ceiling_is_the_format_bound_not_a_language_one() {
        for (reward, ok) in [
            (Value::Int(0), true),
            (Value::Int(MAX_UNITS), true),
            (Value::Int(MAX_UNITS + 1), false),
            (Value::Int(-1), false),
            (Value::Bool(true), false),
            (Value::string("1000"), false),
        ] {
            let mut body = objective().to_value();
            if let Value::Object(map) = &mut body {
                map.insert("reward".into(), reward.clone());
            }
            assert_eq!(
                Objective::from_value(&body).is_ok(),
                ok,
                "reward {reward:?}"
            );
        }
    }

    #[test]
    fn require_signed_submitter_is_not_coerced() {
        // "yes" meaning true here and false elsewhere is two implementations
        // disagreeing about which submissions are admissible.
        for bad in [Value::string("yes"), Value::Int(1), Value::Array(vec![])] {
            let mut body = objective().to_value();
            if let Value::Object(map) = &mut body {
                map.insert("require_signed_submitter".into(), bad.clone());
            }
            assert!(Objective::from_value(&body).is_err(), "{bad:?} accepted");
        }
    }

    #[test]
    fn a_key_shaped_submitter_is_recognised_by_shape_alone() {
        assert!(signed_submitter(&"a".repeat(64)).is_some());
        assert!(signed_submitter("alice").is_none());
        // Uppercase is a nickname: two spellings of one key would be two
        // reputations able to cite each other.
        assert!(signed_submitter(&"A".repeat(64)).is_none());
        assert!(signed_submitter(&"a".repeat(63)).is_none());
        assert!(signed_submitter(&"g".repeat(64)).is_none());
    }

    #[test]
    fn cites_must_be_an_array_of_strings() {
        let base = Value::object([
            ("type", Value::string("claim")),
            ("objective_id", Value::string("sha256:x")),
            ("submitter", Value::string("alice")),
            ("artifact", Value::object([("n", Value::Int(1))])),
            ("nonce", Value::string("s3cret")),
            ("created_at", Value::string("2026-07-28T00:00:00+00:00")),
        ]);
        // Absent reads as empty.
        assert!(Claim::from_value(&base).unwrap().cites.is_empty());
        for bad in [
            // A decoder that iterates a string produces phantom edges, each
            // of which would draw citation flow.
            Value::string("abc"),
            Value::Null,
            Value::Int(7),
            Value::Array(vec![Value::Int(1)]),
        ] {
            let mut body = base.clone();
            if let Value::Object(map) = &mut body {
                map.insert("cites".into(), bad.clone());
            }
            assert!(Claim::from_value(&body).is_err(), "{bad:?} accepted");
        }
        // Duplicates draw twice the flow for one input.
        let mut body = base.clone();
        if let Value::Object(map) = &mut body {
            map.insert(
                "cites".into(),
                Value::Array(vec![Value::string("x"), Value::string("x")]),
            );
        }
        assert!(Claim::from_value(&body).is_err());
    }

    #[test]
    fn a_signature_is_covered_by_the_id_but_not_by_itself() {
        let claim = Claim {
            objective_id: "sha256:obj".into(),
            submitter: "alice".into(),
            artifact: Value::object([("n", Value::Int(1))]),
            nonce: "s3cret".into(),
            created_at: "2026-07-28T00:00:00+00:00".into(),
            cites: vec![],
            relations: vec![],
            signature: None,
        };
        let mut signed = claim.clone();
        signed.signature = Some("ab".repeat(64));
        // Different records, so a signature cannot be stripped from a claim
        // somebody already cited...
        assert_ne!(claim.id(), signed.id());
        // ...while the bytes a signature covers are the same either way,
        // which is the only way it could be produced.
        assert_eq!(claim.signing_payload(), signed.signing_payload());
    }
}

// ---------------------------------------------------------------------------
// Availability: a promise, an answer to a sample, and the pot that pays for it
// ---------------------------------------------------------------------------

/// Tallest log an undertaking may name. See the primary implementation: the
/// sample is drawn with a `u32` partition count, so a taller promise could
/// never be sampled and is refused by the format rather than at settlement.
pub const MAX_UNDERTAKING_HEIGHT: u64 = u32::MAX as u64;

/// Longest inclusion path an answer may carry -- `ceil(log2(2^32))`.
pub const MAX_AVAILABILITY_PATH: usize = 32;

fn hex64(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn digest_shaped(text: &str) -> bool {
    matches!(text.strip_prefix("sha256:"), Some(rest) if hex64(rest))
}

fn count(value: &Value, name: &str) -> Result<u64, RecordError> {
    match field(value, name)? {
        Value::Int(n) if *n >= 0 && *n <= MAX_UNITS => Ok(*n as u64),
        _ => Err(RecordError(format!(
            "{name} must be an integer in [0, 2^64)"
        ))),
    }
}

/// A past promise: identity `K` undertook to hold the log at root `R`, height
/// `H`. About the past on purpose -- an append-only log cannot say "no longer
/// true", and a claim about what somebody once promised never needs retracting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Undertaking {
    pub identity: String,
    pub root: String,
    pub height: u64,
    pub created_at: String,
    pub signature: Option<String>,
}

impl Undertaking {
    pub fn signing_payload(&self) -> Value {
        Value::object([
            ("type", Value::string("undertaking")),
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

    /// Always required. A promise nobody signed is a promise by nobody, and
    /// this record exists to be held against one identity in particular.
    pub fn verify_signature(&self) -> Result<(), RecordError> {
        if signed_submitter(&self.identity).is_none() {
            return Err(RecordError(format!(
                "undertaking identity {:?} is not a public key",
                self.identity
            )));
        }
        verify_record_signature(
            "undertaking",
            &self.identity,
            &self.signing_payload(),
            self.signature.as_deref(),
        )
    }

    pub fn validate(&self) -> Result<(), RecordError> {
        if !hex64(&self.identity) {
            return Err(RecordError(
                "undertaking identity must be 64 lowercase hex".into(),
            ));
        }
        if !digest_shaped(&self.root) {
            return Err(RecordError(
                "undertaking root must be sha256: and 64 lowercase hex".into(),
            ));
        }
        // Zero contradicts the root beside it -- an empty log has no root at
        // all -- and there would be nothing in it to sample.
        if self.height == 0 || self.height > MAX_UNDERTAKING_HEIGHT {
            return Err(RecordError(
                "undertaking height must be between 1 and 2^32 - 1".into(),
            ));
        }
        Ok(())
    }

    pub fn from_value(value: &Value) -> Result<Undertaking, RecordError> {
        let record = Undertaking {
            identity: text(value, "identity")?,
            root: text(value, "root")?,
            height: count(value, "height")?,
            created_at: text(value, "created_at")?,
            signature: optional_text(value, "signature")?,
        };
        record.validate()?;
        Ok(record)
    }
}

/// An answer to one availability sample: the sampled entry and its path.
///
/// The entry is carried, and that is the difference between proving storage
/// and proving arithmetic. Without it the verifier recomputes the leaf from its
/// own copy, so an answerer needs only the entry hashes -- every path is
/// derivable from those -- and a node keeping a tenth of a log reproduces the
/// honest answer byte for byte.
///
/// The signature is the other half: anyone holding the log could assemble this
/// record, so an unsigned one is evidence of nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Availability {
    pub identity: String,
    pub undertaking: String,
    pub epoch: u64,
    pub entry: Value,
    pub path: Vec<String>,
    pub created_at: String,
    pub signature: Option<String>,
}

impl Availability {
    pub fn signing_payload(&self) -> Value {
        Value::object([
            ("type", Value::string("availability")),
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

    pub fn verify_signature(&self) -> Result<(), RecordError> {
        if signed_submitter(&self.identity).is_none() {
            return Err(RecordError(format!(
                "availability identity {:?} is not a public key",
                self.identity
            )));
        }
        verify_record_signature(
            "availability",
            &self.identity,
            &self.signing_payload(),
            self.signature.as_deref(),
        )
    }

    pub fn validate(&self) -> Result<(), RecordError> {
        if !hex64(&self.identity) {
            return Err(RecordError(
                "availability identity must be 64 lowercase hex".into(),
            ));
        }
        if !digest_shaped(&self.undertaking) {
            return Err(RecordError(
                "availability undertaking must be sha256: and 64 lowercase hex".into(),
            ));
        }
        if self.entry.as_object().is_none() {
            return Err(RecordError(
                "availability entry must be the sampled log entry".into(),
            ));
        }
        // An empty path is legal: a one-entry log's only leaf is its root, so
        // the honest answer to it carries no hashes.
        if self.path.len() > MAX_AVAILABILITY_PATH
            || !self.path.iter().all(|hash| digest_shaped(hash))
        {
            return Err(RecordError(
                "availability path must be at most 32 sha256: digests".into(),
            ));
        }
        Ok(())
    }

    pub fn from_value(value: &Value) -> Result<Availability, RecordError> {
        let path = match field(value, "path")? {
            Value::Array(items) => items
                .iter()
                .map(|item| {
                    item.as_str()
                        .map(str::to_string)
                        .ok_or_else(|| RecordError("availability path must be strings".into()))
                })
                .collect::<Result<Vec<String>, RecordError>>()?,
            _ => return Err(RecordError("availability path must be an array".into())),
        };
        let record = Availability {
            identity: text(value, "identity")?,
            undertaking: text(value, "undertaking")?,
            epoch: count(value, "epoch")?,
            entry: field(value, "entry")?.clone(),
            path,
            created_at: text(value, "created_at")?,
            signature: optional_text(value, "signature")?,
        };
        record.validate()?;
        Ok(record)
    }
}

/// Money put up to pay for availability over a stated run of epochs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvailabilityPool {
    pub funder: String,
    pub per_epoch: u64,
    pub from_epoch: u64,
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

    /// `per_epoch x epochs`, in `u128`. Both factors are `u64` and their
    /// product is not: a `u64` ceiling would wrap a large pool into a small one
    /// and let an overspend certify as fine.
    pub fn ceiling(&self) -> u128 {
        let epochs = u128::from(self.to_epoch.saturating_sub(self.from_epoch)) + 1;
        u128::from(self.per_epoch) * epochs
    }

    pub fn covers(&self, epoch: u64) -> bool {
        self.from_epoch <= epoch && epoch <= self.to_epoch
    }

    pub fn validate(&self) -> Result<(), RecordError> {
        if self.funder.is_empty() {
            return Err(RecordError("availability pool needs a funder".into()));
        }
        if self.per_epoch == 0 {
            return Err(RecordError("availability pool must pay something".into()));
        }
        if self.from_epoch > self.to_epoch {
            return Err(RecordError(
                "availability pool to_epoch must not precede from_epoch".into(),
            ));
        }
        Ok(())
    }

    pub fn from_value(value: &Value) -> Result<AvailabilityPool, RecordError> {
        let record = AvailabilityPool {
            funder: text(value, "funder")?,
            per_epoch: count(value, "per_epoch")?,
            from_epoch: count(value, "from_epoch")?,
            to_epoch: count(value, "to_epoch")?,
            created_at: text(value, "created_at")?,
        };
        record.validate()?;
        Ok(record)
    }
}
