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
    pub signature: Option<String>,
}

impl Commitment {
    /// The bytes a signature covers: this record without its own signature.
    /// Excluded rather than zeroed -- a signature over the field holding it is
    /// not something anyone can produce.
    pub fn signing_payload(&self) -> Value {
        Value::object([
            ("type", Value::string("commitment")),
            ("objective_id", Value::string(self.objective_id.clone())),
            ("submitter", Value::string(self.submitter.clone())),
            ("hash", Value::string(self.hash.clone())),
            ("created_at", Value::string(self.created_at.clone())),
        ])
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
    pub signature: Option<String>,
}

impl Claim {
    /// `cites` is always present, empty list included: it is not optional, and
    /// omitting it when empty would give one claim two ids depending on how it
    /// was built.
    pub fn signing_payload(&self) -> Value {
        Value::object([
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
        ])
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
        let claim = Claim {
            objective_id: text(value, "objective_id")?,
            submitter: text(value, "submitter")?,
            artifact: field(value, "artifact")?.clone(),
            nonce: text(value, "nonce")?,
            created_at: text(value, "created_at")?,
            cites,
            signature: optional_text(value, "signature")?,
        };
        claim.validate()?;
        Ok(claim)
    }
}
