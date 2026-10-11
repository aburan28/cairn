//! Sponsor-bounded accounting for metered research assignments.
//!
//! This module computes eligibility; it does not move ledger balances. A gateway
//! signature establishes who reported usage, while the sponsor's policy limits
//! the cost the network attributes to the assignment. This is cost evidence,
//! never an instruction to transfer that number to a contributor.

use std::collections::BTreeSet;

use crate::canonical::Value;
use crate::crypto::identity::{verify_value, Identity, Signature, VerifyingKeyBytes};

const MILLION: u128 = 1_000_000;

/// Counts supplied by the gateway from one completed provider response.
/// Thinking tokens are already included in `output`, so adding them again
/// would pay twice for the same generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Usage {
    pub input: u64,
    pub cache_creation: u64,
    pub cache_read: u64,
    pub output: u64,
    pub thinking: Option<u64>,
}

impl Usage {
    fn validate(self) -> Result<(), ExplorationError> {
        if self.thinking.is_some_and(|thinking| thinking > self.output) {
            return Err(ExplorationError::ThinkingExceedsOutput);
        }
        Ok(())
    }

    fn to_value(self) -> Value {
        let mut value = Value::object([
            ("input", Value::Int(i128::from(self.input))),
            (
                "cache_creation",
                Value::Int(i128::from(self.cache_creation)),
            ),
            ("cache_read", Value::Int(i128::from(self.cache_read))),
            ("output", Value::Int(i128::from(self.output))),
        ]);
        if let (Value::Object(fields), Some(thinking)) = (&mut value, self.thinking) {
            fields.insert("thinking".into(), Value::Int(i128::from(thinking)));
        }
        value
    }

    fn from_value(value: &Value) -> Result<Self, ExplorationError> {
        let number = |field| {
            value
                .get(field)
                .and_then(Value::as_u64)
                .ok_or(ExplorationError::MalformedReceipt)
        };
        let usage = Self {
            input: number("input")?,
            cache_creation: number("cache_creation")?,
            cache_read: number("cache_read")?,
            output: number("output")?,
            thinking: match value.get("thinking") {
                None => None,
                Some(value) => Some(value.as_u64().ok_or(ExplorationError::MalformedReceipt)?),
            },
        };
        usage.validate()?;
        if usage.to_value() != *value {
            return Err(ExplorationError::MalformedReceipt);
        }
        Ok(usage)
    }
}

/// Cairn units per million tokens in each billing category. These are fixed by
/// the sponsor before work starts; a provider's mutable price page is not a
/// replayable settlement rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenRates {
    pub input: u64,
    pub cache_creation: u64,
    pub cache_read: u64,
    pub output: u64,
}

impl TokenRates {
    fn to_value(self) -> Value {
        Value::object([
            ("input", Value::Int(i128::from(self.input))),
            (
                "cache_creation",
                Value::Int(i128::from(self.cache_creation)),
            ),
            ("cache_read", Value::Int(i128::from(self.cache_read))),
            ("output", Value::Int(i128::from(self.output))),
        ])
    }

    fn from_value(value: &Value) -> Result<Self, ExplorationError> {
        let number = |field| {
            value
                .get(field)
                .and_then(Value::as_u64)
                .ok_or(ExplorationError::MalformedPolicy)
        };
        let rates = Self {
            input: number("input")?,
            cache_creation: number("cache_creation")?,
            cache_read: number("cache_read")?,
            output: number("output")?,
        };
        if rates.to_value() != *value {
            return Err(ExplorationError::MalformedPolicy);
        }
        Ok(rates)
    }

    fn numerator(self, usage: Usage) -> Result<u128, ExplorationError> {
        [
            (usage.input, self.input),
            (usage.cache_creation, self.cache_creation),
            (usage.cache_read, self.cache_read),
            (usage.output, self.output),
        ]
        .into_iter()
        .try_fold(0u128, |sum, (tokens, rate)| {
            sum.checked_add(u128::from(tokens) * u128::from(rate))
                .ok_or(ExplorationError::ArithmeticOverflow)
        })
    }
}

/// One request observed by a gateway whose key the sponsor preapproved.
/// The request and response digests bind the provider exchange. The separate
/// delivered work package is checked by the objective's pinned verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayReceipt {
    pub assignment_id: String,
    pub request_id: String,
    pub contributor: String,
    pub gateway: String,
    pub provider: String,
    pub model: String,
    pub config_digest: String,
    pub request_digest: String,
    pub response_digest: String,
    pub started_at: u64,
    pub ended_at: u64,
    pub usage: Usage,
    pub signature: Option<String>,
}

impl GatewayReceipt {
    pub fn signing_payload(&self) -> Value {
        Value::object([
            ("type", Value::string("exploration_receipt")),
            ("version", Value::Int(1)),
            ("assignment_id", Value::string(self.assignment_id.clone())),
            ("request_id", Value::string(self.request_id.clone())),
            ("contributor", Value::string(self.contributor.clone())),
            ("gateway", Value::string(self.gateway.clone())),
            ("provider", Value::string(self.provider.clone())),
            ("model", Value::string(self.model.clone())),
            ("config_digest", Value::string(self.config_digest.clone())),
            ("request_digest", Value::string(self.request_digest.clone())),
            (
                "response_digest",
                Value::string(self.response_digest.clone()),
            ),
            ("started_at", Value::Int(i128::from(self.started_at))),
            ("ended_at", Value::Int(i128::from(self.ended_at))),
            ("usage", self.usage.to_value()),
        ])
    }

    pub fn to_value(&self) -> Value {
        let mut value = self.signing_payload();
        if let (Value::Object(fields), Some(signature)) = (&mut value, &self.signature) {
            fields.insert("signature".into(), Value::string(signature.clone()));
        }
        value
    }

    pub fn id(&self) -> String {
        self.to_value().digest()
    }

    pub fn from_value(value: &Value) -> Result<Self, ExplorationError> {
        let string = |field| {
            value
                .get(field)
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or(ExplorationError::MalformedReceipt)
        };
        let number = |field| {
            value
                .get(field)
                .and_then(Value::as_u64)
                .ok_or(ExplorationError::MalformedReceipt)
        };
        if string("type")? != "exploration_receipt" || number("version")? != 1 {
            return Err(ExplorationError::MalformedReceipt);
        }
        let receipt = Self {
            assignment_id: string("assignment_id")?,
            request_id: string("request_id")?,
            contributor: string("contributor")?,
            gateway: string("gateway")?,
            provider: string("provider")?,
            model: string("model")?,
            config_digest: string("config_digest")?,
            request_digest: string("request_digest")?,
            response_digest: string("response_digest")?,
            started_at: number("started_at")?,
            ended_at: number("ended_at")?,
            usage: Usage::from_value(
                value
                    .get("usage")
                    .ok_or(ExplorationError::MalformedReceipt)?,
            )?,
            signature: Some(string("signature")?),
        };
        receipt.validate()?;
        if receipt.to_value() != *value {
            return Err(ExplorationError::MalformedReceipt);
        }
        Ok(receipt)
    }

    pub fn signed_with(mut self, identity: &Identity) -> Self {
        self.gateway = identity.submitter_id();
        self.signature = Some(identity.sign_value(&self.signing_payload()).to_hex());
        self
    }

    pub fn verify_signature(&self) -> Result<(), ExplorationError> {
        let public = VerifyingKeyBytes::from_hex(&self.gateway)
            .map_err(|_| ExplorationError::InvalidGatewayKey)?;
        let signature = Signature::from_hex(
            self.signature
                .as_deref()
                .ok_or(ExplorationError::MissingSignature)?,
        )
        .map_err(|_| ExplorationError::InvalidSignature)?;
        verify_value(public.as_bytes(), &self.signing_payload(), &signature)
            .map_err(|_| ExplorationError::InvalidSignature)
    }

    fn validate(&self) -> Result<(), ExplorationError> {
        self.usage.validate()?;
        if self.started_at > self.ended_at {
            return Err(ExplorationError::InvalidTime);
        }
        if self.assignment_id.is_empty()
            || self.request_id.is_empty()
            || self.contributor.is_empty()
            || self.provider.is_empty()
            || self.model.is_empty()
        {
            return Err(ExplorationError::EmptyIdentifier);
        }
        for digest in [
            &self.config_digest,
            &self.request_digest,
            &self.response_digest,
        ] {
            if !is_digest(digest) {
                return Err(ExplorationError::InvalidDigest);
            }
        }
        self.verify_signature()
    }
}

fn is_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// The sponsor's fixed, single-contributor assignment policy. `ceiling` caps
/// attributed provider cost; it is separate from the objective's work reward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignmentPolicy {
    pub assignment_id: String,
    pub contributor: String,
    pub gateway: String,
    pub provider: String,
    pub model: String,
    pub config_digest: String,
    pub from_unix: u64,
    pub to_unix: u64,
    pub max_input_per_request: u64,
    pub max_output_per_request: u64,
    pub max_requests: u64,
    pub ceiling: u64,
    pub rates: TokenRates,
}

impl AssignmentPolicy {
    pub fn to_value(&self) -> Value {
        Value::object([
            ("type", Value::string("exploration_assignment")),
            ("version", Value::Int(1)),
            ("assignment_id", Value::string(self.assignment_id.clone())),
            ("contributor", Value::string(self.contributor.clone())),
            ("gateway", Value::string(self.gateway.clone())),
            ("provider", Value::string(self.provider.clone())),
            ("model", Value::string(self.model.clone())),
            ("config_digest", Value::string(self.config_digest.clone())),
            ("from_unix", Value::Int(i128::from(self.from_unix))),
            ("to_unix", Value::Int(i128::from(self.to_unix))),
            (
                "max_input_per_request",
                Value::Int(i128::from(self.max_input_per_request)),
            ),
            (
                "max_output_per_request",
                Value::Int(i128::from(self.max_output_per_request)),
            ),
            ("max_requests", Value::Int(i128::from(self.max_requests))),
            ("ceiling", Value::Int(i128::from(self.ceiling))),
            ("rates", self.rates.to_value()),
        ])
    }

    pub fn from_value(value: &Value) -> Result<Self, ExplorationError> {
        let string = |field| {
            value
                .get(field)
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or(ExplorationError::MalformedPolicy)
        };
        let number = |field| {
            value
                .get(field)
                .and_then(Value::as_u64)
                .ok_or(ExplorationError::MalformedPolicy)
        };
        if string("type")? != "exploration_assignment" || number("version")? != 1 {
            return Err(ExplorationError::MalformedPolicy);
        }
        let policy = Self {
            assignment_id: string("assignment_id")?,
            contributor: string("contributor")?,
            gateway: string("gateway")?,
            provider: string("provider")?,
            model: string("model")?,
            config_digest: string("config_digest")?,
            from_unix: number("from_unix")?,
            to_unix: number("to_unix")?,
            max_input_per_request: number("max_input_per_request")?,
            max_output_per_request: number("max_output_per_request")?,
            max_requests: number("max_requests")?,
            ceiling: number("ceiling")?,
            rates: TokenRates::from_value(
                value
                    .get("rates")
                    .ok_or(ExplorationError::MalformedPolicy)?,
            )?,
        };
        policy.validate()?;
        if policy.to_value() != *value {
            return Err(ExplorationError::MalformedPolicy);
        }
        Ok(policy)
    }

    pub fn validate(&self) -> Result<(), ExplorationError> {
        if self.from_unix > self.to_unix
            || self.max_requests == 0
            || self.ceiling == 0
            || self.ceiling > i64::MAX as u64
            || self.assignment_id.is_empty()
            || self.provider.is_empty()
            || self.model.is_empty()
            || !is_digest(&self.config_digest)
            || VerifyingKeyBytes::from_hex(&self.contributor).is_ok_and(|key| !key.is_usable())
            || VerifyingKeyBytes::from_hex(&self.gateway).is_ok_and(|key| !key.is_usable())
        {
            return Err(ExplorationError::InvalidPolicy);
        }
        if VerifyingKeyBytes::from_hex(&self.contributor).is_err()
            || VerifyingKeyBytes::from_hex(&self.gateway).is_err()
        {
            return Err(ExplorationError::InvalidPolicy);
        }
        Ok(())
    }
}

/// Compute a maximum eligible cost from preapproved receipts after the
/// assignment's pinned evidence checker accepts. `already_accounted` must
/// come from the audited record history, not from a worker-controlled cache.
pub fn eligible_cost(
    policy: &AssignmentPolicy,
    receipts: &[GatewayReceipt],
    evidence_accepted: bool,
    already_accounted: &BTreeSet<(String, String)>,
) -> Result<u64, ExplorationError> {
    if !evidence_accepted {
        return Err(ExplorationError::EvidenceNotAccepted);
    }
    policy.validate()?;
    if receipts.len() as u128 > u128::from(policy.max_requests) {
        return Err(ExplorationError::RequestLimit);
    }
    let mut seen = BTreeSet::new();
    let mut numerator = 0u128;
    for receipt in receipts {
        receipt.validate()?;
        if receipt.assignment_id != policy.assignment_id
            || receipt.contributor != policy.contributor
            || receipt.gateway != policy.gateway
            || receipt.provider != policy.provider
            || receipt.model != policy.model
            || receipt.config_digest != policy.config_digest
            || receipt.started_at < policy.from_unix
            || receipt.ended_at > policy.to_unix
        {
            return Err(ExplorationError::OutsideAssignment);
        }
        let total_input = u128::from(receipt.usage.input)
            + u128::from(receipt.usage.cache_creation)
            + u128::from(receipt.usage.cache_read);
        if total_input > u128::from(policy.max_input_per_request) {
            return Err(ExplorationError::InputLimit);
        }
        if receipt.usage.output > policy.max_output_per_request {
            return Err(ExplorationError::OutputLimit);
        }
        let key = (receipt.gateway.clone(), receipt.request_id.clone());
        if !seen.insert(key.clone()) || already_accounted.contains(&key) {
            return Err(ExplorationError::DuplicateRequest);
        }
        numerator = numerator
            .checked_add(policy.rates.numerator(receipt.usage)?)
            .ok_or(ExplorationError::ArithmeticOverflow)?;
    }
    // Divide once across the assignment: splitting a request cannot collect
    // an extra rounded-up unit per receipt.
    let cost = (numerator / MILLION).min(u128::from(policy.ceiling));
    u64::try_from(cost).map_err(|_| ExplorationError::ArithmeticOverflow)
}

/// Decode the receipt bundle in an artifact. The caller must pass the verdict
/// of the objective's pinned evidence checker; this function cannot decide
/// whether a search trace is useful merely by authenticating token usage.
pub fn cost_for_artifact(
    policy: &AssignmentPolicy,
    artifact: &Value,
    evidence_accepted: bool,
    already_accounted: &BTreeSet<(String, String)>,
) -> Result<u64, ExplorationError> {
    artifact
        .get("evidence")
        .ok_or(ExplorationError::MalformedReceipt)?;
    let rows = artifact
        .get("receipts")
        .and_then(Value::as_array)
        .ok_or(ExplorationError::MalformedReceipt)?;
    let receipts = rows
        .iter()
        .map(GatewayReceipt::from_value)
        .collect::<Result<Vec<_>, _>>()?;
    eligible_cost(policy, &receipts, evidence_accepted, already_accounted)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExplorationError {
    MalformedReceipt,
    MalformedPolicy,
    ThinkingExceedsOutput,
    InvalidGatewayKey,
    MissingSignature,
    InvalidSignature,
    InvalidTime,
    EmptyIdentifier,
    InvalidDigest,
    InvalidPolicy,
    EvidenceNotAccepted,
    RequestLimit,
    OutsideAssignment,
    OutputLimit,
    InputLimit,
    DuplicateRequest,
    ArithmeticOverflow,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (Identity, AssignmentPolicy, GatewayReceipt) {
        let gateway = Identity::from_secret_bytes([7; 32]);
        let contributor = Identity::from_secret_bytes([8; 32]);
        let policy = AssignmentPolicy {
            assignment_id: "assignment-1".into(),
            contributor: contributor.submitter_id(),
            gateway: gateway.submitter_id(),
            provider: "anthropic".into(),
            model: "claude-version-pinned".into(),
            config_digest:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            from_unix: 100,
            to_unix: 200,
            max_input_per_request: 2_000_000,
            max_output_per_request: 2_000_000,
            max_requests: 2,
            ceiling: 50,
            rates: TokenRates {
                input: 1,
                cache_creation: 2,
                cache_read: 1,
                output: 10,
            },
        };
        let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let receipt = GatewayReceipt {
            assignment_id: policy.assignment_id.clone(),
            request_id: "request-1".into(),
            contributor: policy.contributor.clone(),
            gateway: String::new(),
            provider: policy.provider.clone(),
            model: policy.model.clone(),
            config_digest: digest.into(),
            request_digest: digest.into(),
            response_digest: digest.into(),
            started_at: 120,
            ended_at: 121,
            usage: Usage {
                input: 1_000_000,
                cache_creation: 0,
                cache_read: 0,
                output: 1_000_000,
                thinking: Some(800_000),
            },
            signature: None,
        }
        .signed_with(&gateway);
        (gateway, policy, receipt)
    }

    #[test]
    fn signature_binds_usage_and_assignment() {
        let (_, policy, receipt) = fixture();
        assert!(receipt.verify_signature().is_ok());
        let mut altered = receipt.clone();
        altered.usage.output += 1;
        assert_eq!(
            altered.verify_signature(),
            Err(ExplorationError::InvalidSignature)
        );
        altered = receipt.clone();
        altered.assignment_id = "another-assignment".into();
        assert_eq!(
            altered.verify_signature(),
            Err(ExplorationError::InvalidSignature)
        );
        assert_eq!(policy.gateway, receipt.gateway);
        assert_eq!(GatewayReceipt::from_value(&receipt.to_value()), Ok(receipt));
        assert_eq!(AssignmentPolicy::from_value(&policy.to_value()), Ok(policy));
    }

    #[test]
    fn cap_duplicate_and_evidence_gate() {
        let (_, mut policy, receipt) = fixture();
        let empty = BTreeSet::new();
        assert_eq!(
            eligible_cost(&policy, std::slice::from_ref(&receipt), true, &empty),
            Ok(11)
        );
        let mut cheaper_model = policy.clone();
        cheaper_model.model = "unapproved-model".into();
        assert_eq!(
            eligible_cost(&cheaper_model, std::slice::from_ref(&receipt), true, &empty),
            Err(ExplorationError::OutsideAssignment)
        );
        assert_eq!(
            eligible_cost(&policy, std::slice::from_ref(&receipt), false, &empty),
            Err(ExplorationError::EvidenceNotAccepted)
        );
        assert_eq!(
            eligible_cost(&policy, &[receipt.clone(), receipt.clone()], true, &empty),
            Err(ExplorationError::DuplicateRequest)
        );
        let mut paid = BTreeSet::new();
        paid.insert((receipt.gateway.clone(), receipt.request_id.clone()));
        assert_eq!(
            eligible_cost(&policy, std::slice::from_ref(&receipt), true, &paid),
            Err(ExplorationError::DuplicateRequest)
        );
        policy.ceiling = 5;
        assert_eq!(eligible_cost(&policy, &[receipt], true, &empty), Ok(5));
    }

    #[test]
    fn thinking_is_not_counted_twice() {
        let (_, policy, mut receipt) = fixture();
        receipt.usage.thinking = Some(1_000_001);
        assert_eq!(
            eligible_cost(&policy, &[receipt], true, &BTreeSet::new()),
            Err(ExplorationError::ThinkingExceedsOutput)
        );
    }
}
