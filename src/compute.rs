//! Capability-aware research-job routing and provider request envelopes.
//!
//! This module is deliberately **not** a verifier and it is not part of ledger
//! settlement. It supplies the metadata and transport building blocks needed to
//! ask an inference-capable worker to produce a candidate artifact. The result
//! still has to pass a pinned cairn verifier before it can affect the log.
//!
//! Four boundaries are explicit here:
//!
//! - a worker advertises capabilities, capacity and model manifests;
//! - a model manifest is content-addressed, so an alias never stands alone;
//! - attestation is a ranked trust signal, not a correctness verdict;
//! - request encryption protects bytes in transit, not the truth of a response.
//!
//! The scheduler uses only integer fields and a stable tie-breaker. Latency and
//! queue values are routing hints supplied by a worker; they are never evidence
//! of work performed and must not be copied into a settled claim as facts.

use std::fmt;

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest as _, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret, StaticSecret};

use crate::canonical::{digest_bytes, Value};
use crate::hex;

const CAPABILITY_TYPE: &str = "worker_capability";
const MANIFEST_TYPE: &str = "model_manifest";
const REQUEST_TYPE: &str = "compute_request";
const VERSION: i128 = 1;
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const DIGEST_HEX_LEN: usize = 64;
// Spelled `proofwork/` and not `cairn/`: this is a wire constant, not a
// brand. It is mixed into a hash or a KDF, so changing it changes the
// values every peer already computed -- the project rename left it alone
// deliberately, exactly as it left the `pwenc1:` on-disk marker alone.
const REQUEST_KDF_DOMAIN: &[u8] = b"proofwork/compute/request-key/v1";

/// Trust signals a worker may advertise. A higher level satisfies a request
/// that asks for a lower level, but none of these levels says that an inference
/// response is correct.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AttestationLevel {
    None,
    SelfSigned,
    Hardware,
    CodeIdentity,
}

impl AttestationLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::SelfSigned => "self_signed",
            Self::Hardware => "hardware",
            Self::CodeIdentity => "code_identity",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "none" => Self::None,
            "self_signed" => Self::SelfSigned,
            "hardware" => Self::Hardware,
            "code_identity" => Self::CodeIdentity,
            _ => return None,
        })
    }
}

/// The exact model material a worker claims to have loaded.
///
/// `alias` is for human/API compatibility. `digest()` is the value a job must
/// bind to. Optional fields are omitted rather than encoded as `null`, matching
/// the repository's identity rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelManifest {
    pub alias: String,
    pub family: String,
    pub build: String,
    pub weights_sha256: String,
    pub tokenizer_sha256: String,
    pub template_sha256: Option<String>,
}

impl ModelManifest {
    pub fn validate(&self) -> Result<(), ComputeError> {
        nonempty("alias", &self.alias)?;
        nonempty("family", &self.family)?;
        nonempty("build", &self.build)?;
        validate_digest("weights_sha256", &self.weights_sha256)?;
        validate_digest("tokenizer_sha256", &self.tokenizer_sha256)?;
        if let Some(value) = &self.template_sha256 {
            validate_digest("template_sha256", value)?;
        }
        Ok(())
    }

    pub fn to_value(&self) -> Value {
        let mut fields = vec![
            ("type", Value::string(MANIFEST_TYPE)),
            ("version", Value::Int(VERSION)),
            ("alias", Value::string(self.alias.clone())),
            ("family", Value::string(self.family.clone())),
            ("build", Value::string(self.build.clone())),
            ("weights_sha256", Value::string(self.weights_sha256.clone())),
            (
                "tokenizer_sha256",
                Value::string(self.tokenizer_sha256.clone()),
            ),
        ];
        if let Some(value) = &self.template_sha256 {
            fields.push(("template_sha256", Value::string(value.clone())));
        }
        Value::object(fields)
    }

    /// Content address of the manifest, not of a mutable alias.
    pub fn digest(&self) -> String {
        digest_bytes(&self.to_value().canonical_bytes())
    }

    pub fn from_value(value: &Value) -> Result<Self, ComputeError> {
        expect_type(value, MANIFEST_TYPE)?;
        let manifest = Self {
            alias: field_string(value, "alias")?,
            family: field_string(value, "family")?,
            build: field_string(value, "build")?,
            weights_sha256: field_string(value, "weights_sha256")?,
            tokenizer_sha256: field_string(value, "tokenizer_sha256")?,
            template_sha256: value
                .get("template_sha256")
                .map(|item| {
                    item.as_str()
                        .map(String::from)
                        .ok_or(ComputeError::InvalidField {
                            field: "template_sha256",
                            expected: "a string",
                        })
                })
                .transpose()?,
        };
        manifest.validate()?;
        Ok(manifest)
    }
}

/// A worker's public routing and provenance advertisement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerCapability {
    pub worker_id: String,
    pub endpoint: String,
    pub backend: String,
    pub models: Vec<ModelManifest>,
    pub memory_mb: u64,
    pub max_concurrency: u32,
    pub active_requests: u32,
    pub queue_depth: u32,
    pub estimated_latency_ms: u64,
    pub attestation: AttestationLevel,
    pub encrypted_requests: bool,
    pub encrypted_responses: bool,
    pub request_public_key: [u8; KEY_LEN],
}

impl WorkerCapability {
    pub fn validate(&self) -> Result<(), ComputeError> {
        nonempty("worker_id", &self.worker_id)?;
        nonempty("endpoint", &self.endpoint)?;
        nonempty("backend", &self.backend)?;
        if self.models.is_empty() {
            return Err(ComputeError::InvalidField {
                field: "models",
                expected: "a non-empty array",
            });
        }
        if self.max_concurrency == 0 {
            return Err(ComputeError::InvalidField {
                field: "max_concurrency",
                expected: "a positive integer",
            });
        }
        if self.active_requests > self.max_concurrency {
            return Err(ComputeError::InvalidField {
                field: "active_requests",
                expected: "no greater than max_concurrency",
            });
        }
        for model in &self.models {
            model.validate()?;
        }
        Ok(())
    }

    pub fn supports_manifest(&self, digest: &str) -> bool {
        self.models.iter().any(|model| model.digest() == digest)
    }

    pub fn available_slots(&self) -> u32 {
        self.max_concurrency.saturating_sub(self.active_requests)
    }

    pub fn to_value(&self) -> Value {
        Value::object([
            ("type", Value::string(CAPABILITY_TYPE)),
            ("version", Value::Int(VERSION)),
            ("worker_id", Value::string(self.worker_id.clone())),
            ("endpoint", Value::string(self.endpoint.clone())),
            ("backend", Value::string(self.backend.clone())),
            (
                "models",
                Value::array(self.models.iter().map(ModelManifest::to_value)),
            ),
            ("memory_mb", Value::Int(i128::from(self.memory_mb))),
            (
                "max_concurrency",
                Value::Int(i128::from(self.max_concurrency)),
            ),
            (
                "active_requests",
                Value::Int(i128::from(self.active_requests)),
            ),
            ("queue_depth", Value::Int(i128::from(self.queue_depth))),
            (
                "estimated_latency_ms",
                Value::Int(i128::from(self.estimated_latency_ms)),
            ),
            ("attestation", Value::string(self.attestation.as_str())),
            ("encrypted_requests", Value::Bool(self.encrypted_requests)),
            ("encrypted_responses", Value::Bool(self.encrypted_responses)),
            (
                "request_public_key",
                Value::string(hex::encode(&self.request_public_key)),
            ),
        ])
    }

    pub fn from_value(value: &Value) -> Result<Self, ComputeError> {
        expect_type(value, CAPABILITY_TYPE)?;
        let models = value
            .get("models")
            .ok_or(ComputeError::MissingField { field: "models" })?
            .as_array()
            .ok_or(ComputeError::InvalidField {
                field: "models",
                expected: "an array",
            })?
            .iter()
            .map(ModelManifest::from_value)
            .collect::<Result<Vec<_>, _>>()?;
        let capability = Self {
            worker_id: field_string(value, "worker_id")?,
            endpoint: field_string(value, "endpoint")?,
            backend: field_string(value, "backend")?,
            models,
            memory_mb: field_u64(value, "memory_mb")?,
            max_concurrency: field_u32(value, "max_concurrency")?,
            active_requests: field_u32(value, "active_requests")?,
            queue_depth: field_u32(value, "queue_depth")?,
            estimated_latency_ms: field_u64(value, "estimated_latency_ms")?,
            attestation: AttestationLevel::parse(&field_string(value, "attestation")?).ok_or(
                ComputeError::InvalidField {
                    field: "attestation",
                    expected: "a known attestation level",
                },
            )?,
            encrypted_requests: field_bool(value, "encrypted_requests")?,
            encrypted_responses: field_bool(value, "encrypted_responses")?,
            request_public_key: field_bytes_compute::<KEY_LEN>(value, "request_public_key")?,
        };
        capability.validate()?;
        Ok(capability)
    }
}

/// Constraints supplied by a job dispatcher. The manifest digest is required:
/// an alias-only request is intentionally not schedulable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestRequirements {
    pub model_manifest_sha256: String,
    pub min_memory_mb: u64,
    pub max_queue_depth: u32,
    pub min_attestation: AttestationLevel,
    pub require_encrypted_requests: bool,
    pub require_encrypted_responses: bool,
}

impl RequestRequirements {
    pub fn validate(&self) -> Result<(), ComputeError> {
        validate_digest("model_manifest_sha256", &self.model_manifest_sha256)
    }
}

/// Deterministic capability-aware scheduler.
///
/// This is a routing helper, not a proof-of-execution mechanism. The selected
/// worker and all its advertised fields must be recorded as provenance if a
/// caller wants to explain why a request was routed there.
#[derive(Debug, Clone, Default)]
pub struct CapabilityScheduler {
    workers: Vec<WorkerCapability>,
}

impl CapabilityScheduler {
    pub fn new(workers: Vec<WorkerCapability>) -> Result<Self, ComputeError> {
        let mut seen = std::collections::BTreeSet::new();
        for worker in &workers {
            worker.validate()?;
            if !seen.insert(worker.worker_id.clone()) {
                return Err(ComputeError::DuplicateWorker {
                    worker_id: worker.worker_id.clone(),
                });
            }
        }
        Ok(Self { workers })
    }

    pub fn workers(&self) -> &[WorkerCapability] {
        &self.workers
    }

    /// Choose the lowest advertised completion cost, with a worker-id tie
    /// break. The cost is `queue + active` first and advertised latency second,
    /// so an honest worker cannot reorder equal-cost candidates by vector order.
    pub fn select(
        &self,
        requirements: &RequestRequirements,
    ) -> Result<&WorkerCapability, ComputeError> {
        requirements.validate()?;
        self.workers
            .iter()
            .filter(|worker| eligible(worker, requirements))
            .min_by_key(|worker| {
                (
                    worker.queue_depth.saturating_add(worker.active_requests),
                    worker.estimated_latency_ms,
                    worker.worker_id.as_str(),
                )
            })
            .ok_or_else(|| ComputeError::NoEligibleWorker {
                manifest: requirements.model_manifest_sha256.clone(),
            })
    }
}

fn eligible(worker: &WorkerCapability, requirements: &RequestRequirements) -> bool {
    worker.supports_manifest(&requirements.model_manifest_sha256)
        && worker.memory_mb >= requirements.min_memory_mb
        && worker.available_slots() > 0
        && worker.queue_depth <= requirements.max_queue_depth
        && worker.attestation >= requirements.min_attestation
        && (!requirements.require_encrypted_requests || worker.encrypted_requests)
        && (!requirements.require_encrypted_responses || worker.encrypted_responses)
}

/// A provider-side private key for opening request envelopes.
pub struct RequestKey {
    secret: StaticSecret,
}

impl fmt::Debug for RequestKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RequestKey(<redacted>)")
    }
}

impl RequestKey {
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self {
            secret: StaticSecret::random_from_rng(&mut *rng),
        }
    }

    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self {
            secret: StaticSecret::from(bytes),
        }
    }

    pub fn public(&self) -> [u8; KEY_LEN] {
        PublicKey::from(&self.secret).to_bytes()
    }
}

/// One request sealed to one provider key.
///
/// The envelope binds the request id, task id and exact model-manifest digest
/// into AEAD associated data. Replaying the ciphertext under another request or
/// model therefore fails authentication. This protects transport confidentiality
/// and binding only; it does not attest that the provider produced a correct
/// answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestEnvelope {
    request_id: String,
    task_id: String,
    model_manifest_sha256: String,
    ephemeral_public: [u8; KEY_LEN],
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
}

impl RequestEnvelope {
    pub fn seal<R: RngCore + CryptoRng>(
        request_id: &str,
        task_id: &str,
        model_manifest_sha256: &str,
        payload: &[u8],
        recipient_public: [u8; KEY_LEN],
        rng: &mut R,
    ) -> Result<Self, RequestEnvelopeError> {
        validate_request_fields(request_id, task_id, model_manifest_sha256)?;
        let ephemeral = EphemeralSecret::random_from_rng(&mut *rng);
        let ephemeral_public = PublicKey::from(&ephemeral).to_bytes();
        let recipient = PublicKey::from(recipient_public);
        let shared = ephemeral.diffie_hellman(&recipient);
        if !shared.was_contributory() {
            return Err(RequestEnvelopeError::NonContributoryExchange);
        }
        let aad = aad_bytes(request_id, task_id, model_manifest_sha256);
        let key = derive_request_key(&shared, &ephemeral_public, &recipient_public, &aad);
        let mut nonce = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce);
        let cipher = cipher_for(&key);
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: payload,
                    aad: &aad,
                },
            )
            .map_err(|_| RequestEnvelopeError::EncryptionFailed)?;
        Ok(Self {
            request_id: request_id.into(),
            task_id: task_id.into(),
            model_manifest_sha256: model_manifest_sha256.into(),
            ephemeral_public,
            nonce,
            ciphertext,
        })
    }

    pub fn open(&self, key: &RequestKey) -> Result<Vec<u8>, RequestEnvelopeError> {
        validate_request_fields(&self.request_id, &self.task_id, &self.model_manifest_sha256)?;
        let ephemeral = PublicKey::from(self.ephemeral_public);
        let shared = key.secret.diffie_hellman(&ephemeral);
        if !shared.was_contributory() {
            return Err(RequestEnvelopeError::NonContributoryExchange);
        }
        let recipient_public = key.public();
        let aad = aad_bytes(&self.request_id, &self.task_id, &self.model_manifest_sha256);
        let request_key =
            derive_request_key(&shared, &self.ephemeral_public, &recipient_public, &aad);
        cipher_for(&request_key)
            .decrypt(
                Nonce::from_slice(&self.nonce),
                Payload {
                    msg: &self.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| RequestEnvelopeError::AuthenticationFailed)
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn task_id(&self) -> &str {
        &self.task_id
    }

    pub fn model_manifest_sha256(&self) -> &str {
        &self.model_manifest_sha256
    }

    pub fn to_value(&self) -> Value {
        Value::object([
            ("type", Value::string(REQUEST_TYPE)),
            ("version", Value::Int(VERSION)),
            ("request_id", Value::string(self.request_id.clone())),
            ("task_id", Value::string(self.task_id.clone())),
            (
                "model_manifest_sha256",
                Value::string(self.model_manifest_sha256.clone()),
            ),
            (
                "ephemeral_public",
                Value::string(hex::encode(&self.ephemeral_public)),
            ),
            ("nonce", Value::string(hex::encode(&self.nonce))),
            ("ciphertext", Value::string(hex::encode(&self.ciphertext))),
        ])
    }

    pub fn from_value(value: &Value) -> Result<Self, RequestEnvelopeError> {
        expect_type_request(value)?;
        let envelope = Self {
            request_id: field_string_request(value, "request_id")?,
            task_id: field_string_request(value, "task_id")?,
            model_manifest_sha256: field_string_request(value, "model_manifest_sha256")?,
            ephemeral_public: field_bytes_request::<KEY_LEN>(value, "ephemeral_public")?,
            nonce: field_bytes_request::<NONCE_LEN>(value, "nonce")?,
            ciphertext: field_vec_request(value, "ciphertext")?,
        };
        validate_request_fields(
            &envelope.request_id,
            &envelope.task_id,
            &envelope.model_manifest_sha256,
        )?;
        Ok(envelope)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComputeError {
    MissingField {
        field: &'static str,
    },
    InvalidField {
        field: &'static str,
        expected: &'static str,
    },
    InvalidDigest {
        field: &'static str,
    },
    InvalidAttestation,
    DuplicateWorker {
        worker_id: String,
    },
    NoEligibleWorker {
        manifest: String,
    },
}

impl fmt::Display for ComputeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingField { field } => write!(f, "missing field {field:?}"),
            Self::InvalidField { field, expected } => {
                write!(f, "field {field:?} must be {expected}")
            }
            Self::InvalidDigest { field } => {
                write!(f, "field {field:?} must be a lowercase sha256 digest")
            }
            Self::InvalidAttestation => f.write_str("invalid attestation level"),
            Self::DuplicateWorker { worker_id } => {
                write!(f, "duplicate worker id {worker_id:?}")
            }
            Self::NoEligibleWorker { manifest } => {
                write!(f, "no eligible worker for model manifest {manifest}")
            }
        }
    }
}

impl std::error::Error for ComputeError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestEnvelopeError {
    InvalidField {
        field: &'static str,
        expected: &'static str,
    },
    MissingField {
        field: &'static str,
    },
    InvalidDigest {
        field: &'static str,
    },
    InvalidHex {
        field: &'static str,
    },
    WrongLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    UnsupportedVersion,
    EmptyIdentifier {
        field: &'static str,
    },
    NonContributoryExchange,
    EncryptionFailed,
    AuthenticationFailed,
    NotAnObject,
}

impl fmt::Display for RequestEnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField { field, expected } => {
                write!(f, "field {field:?} must be {expected}")
            }
            Self::MissingField { field } => write!(f, "missing field {field:?}"),
            Self::InvalidDigest { field } => {
                write!(f, "field {field:?} must be a lowercase sha256 digest")
            }
            Self::InvalidHex { field } => {
                write!(f, "field {field:?} must be lowercase even-length hex")
            }
            Self::WrongLength {
                field,
                expected,
                actual,
            } => write!(f, "field {field:?} must be {expected} bytes, got {actual}"),
            Self::UnsupportedVersion => f.write_str("unsupported compute request version"),
            Self::EmptyIdentifier { field } => write!(f, "field {field:?} must not be empty"),
            Self::NonContributoryExchange => f.write_str("non-contributory X25519 exchange"),
            Self::EncryptionFailed => f.write_str("request encryption failed"),
            Self::AuthenticationFailed => f.write_str("request authentication failed"),
            Self::NotAnObject => f.write_str("request envelope must be an object"),
        }
    }
}

impl std::error::Error for RequestEnvelopeError {}

fn expect_type(value: &Value, expected: &'static str) -> Result<(), ComputeError> {
    if value.get("type").and_then(Value::as_str) != Some(expected) {
        return Err(ComputeError::InvalidField {
            field: "type",
            expected,
        });
    }
    if value.get("version").and_then(Value::as_i128) != Some(VERSION) {
        return Err(ComputeError::InvalidField {
            field: "version",
            expected: "version 1",
        });
    }
    Ok(())
}

fn field_string(value: &Value, field: &'static str) -> Result<String, ComputeError> {
    value
        .get(field)
        .ok_or(ComputeError::MissingField { field })?
        .as_str()
        .map(String::from)
        .ok_or(ComputeError::InvalidField {
            field,
            expected: "a string",
        })
}

fn field_u64(value: &Value, field: &'static str) -> Result<u64, ComputeError> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or(ComputeError::InvalidField {
            field,
            expected: "an unsigned integer",
        })
}

fn field_u32(value: &Value, field: &'static str) -> Result<u32, ComputeError> {
    field_u64(value, field)?
        .try_into()
        .map_err(|_| ComputeError::InvalidField {
            field,
            expected: "a 32-bit unsigned integer",
        })
}

fn field_bool(value: &Value, field: &'static str) -> Result<bool, ComputeError> {
    value
        .get(field)
        .and_then(Value::as_bool)
        .ok_or(ComputeError::InvalidField {
            field,
            expected: "a boolean",
        })
}

fn field_bytes_compute<const N: usize>(
    value: &Value,
    field: &'static str,
) -> Result<[u8; N], ComputeError> {
    let text = field_string(value, field)?;
    if !text.len().is_multiple_of(2)
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ComputeError::InvalidField {
            field,
            expected: "lowercase even-length hex",
        });
    }
    let bytes = (0..text.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&text[index..index + 2], 16).map_err(|_| {
                ComputeError::InvalidField {
                    field,
                    expected: "lowercase even-length hex",
                }
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let actual = bytes.len();
    bytes
        .try_into()
        .map_err(|_: Vec<u8>| ComputeError::InvalidField {
            field,
            expected: if actual == N {
                "a fixed-length byte string"
            } else {
                "32-byte lowercase hex"
            },
        })
}

fn nonempty(field: &'static str, value: &str) -> Result<(), ComputeError> {
    if value.is_empty() {
        return Err(ComputeError::InvalidField {
            field,
            expected: "a non-empty string",
        });
    }
    Ok(())
}

fn validate_digest(field: &'static str, value: &str) -> Result<(), ComputeError> {
    let Some(hex_part) = value.strip_prefix("sha256:") else {
        return Err(ComputeError::InvalidDigest { field });
    };
    if hex_part.len() != DIGEST_HEX_LEN
        || !hex_part
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ComputeError::InvalidDigest { field });
    }
    Ok(())
}

fn expect_type_request(value: &Value) -> Result<(), RequestEnvelopeError> {
    if value.as_object().is_none() {
        return Err(RequestEnvelopeError::NotAnObject);
    }
    if value.get("type").and_then(Value::as_str) != Some(REQUEST_TYPE) {
        return Err(RequestEnvelopeError::InvalidField {
            field: "type",
            expected: "compute_request",
        });
    }
    if value.get("version").and_then(Value::as_i128) != Some(VERSION) {
        return Err(RequestEnvelopeError::UnsupportedVersion);
    }
    Ok(())
}

fn field_string_request(
    value: &Value,
    field: &'static str,
) -> Result<String, RequestEnvelopeError> {
    value
        .get(field)
        .ok_or(RequestEnvelopeError::MissingField { field })?
        .as_str()
        .map(String::from)
        .ok_or(RequestEnvelopeError::InvalidField {
            field,
            expected: "a string",
        })
}

fn field_bytes_request<const N: usize>(
    value: &Value,
    field: &'static str,
) -> Result<[u8; N], RequestEnvelopeError> {
    let text = field_string_request(value, field)?;
    let bytes = decode_hex_request(&text, field)?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| RequestEnvelopeError::WrongLength {
            field,
            expected: N,
            actual: bytes.len(),
        })
}

fn field_vec_request(value: &Value, field: &'static str) -> Result<Vec<u8>, RequestEnvelopeError> {
    decode_hex_request(&field_string_request(value, field)?, field)
}

fn decode_hex_request(text: &str, field: &'static str) -> Result<Vec<u8>, RequestEnvelopeError> {
    if !text.len().is_multiple_of(2)
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(RequestEnvelopeError::InvalidHex { field });
    }
    (0..text.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&text[index..index + 2], 16)
                .map_err(|_| RequestEnvelopeError::InvalidHex { field })
        })
        .collect()
}

fn validate_request_fields(
    request_id: &str,
    task_id: &str,
    manifest: &str,
) -> Result<(), RequestEnvelopeError> {
    if request_id.is_empty() {
        return Err(RequestEnvelopeError::EmptyIdentifier {
            field: "request_id",
        });
    }
    if task_id.is_empty() {
        return Err(RequestEnvelopeError::EmptyIdentifier { field: "task_id" });
    }
    let Some(hex_part) = manifest.strip_prefix("sha256:") else {
        return Err(RequestEnvelopeError::InvalidDigest {
            field: "model_manifest_sha256",
        });
    };
    if hex_part.len() != DIGEST_HEX_LEN
        || !hex_part
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(RequestEnvelopeError::InvalidDigest {
            field: "model_manifest_sha256",
        });
    }
    Ok(())
}

fn aad_bytes(request_id: &str, task_id: &str, manifest: &str) -> Vec<u8> {
    Value::object([
        ("type", Value::string(REQUEST_TYPE)),
        ("version", Value::Int(VERSION)),
        ("request_id", Value::string(request_id)),
        ("task_id", Value::string(task_id)),
        ("model_manifest_sha256", Value::string(manifest)),
    ])
    .canonical_bytes()
}

fn derive_request_key(
    shared: &SharedSecret,
    ephemeral_public: &[u8; KEY_LEN],
    recipient_public: &[u8; KEY_LEN],
    aad: &[u8],
) -> [u8; KEY_LEN] {
    let mut hasher = Sha256::new();
    absorb(&mut hasher, REQUEST_KDF_DOMAIN);
    absorb(&mut hasher, shared.as_bytes());
    absorb(&mut hasher, ephemeral_public);
    absorb(&mut hasher, recipient_public);
    absorb(&mut hasher, aad);
    hasher.finalize().into()
}

fn absorb(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn cipher_for(key: &[u8; KEY_LEN]) -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new(Key::from_slice(key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    fn manifest(alias: &str, build: &str) -> ModelManifest {
        ModelManifest {
            alias: alias.into(),
            family: "test-family".into(),
            build: build.into(),
            weights_sha256:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            tokenizer_sha256:
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            template_sha256: None,
        }
    }

    fn worker(id: &str, model: &ModelManifest, queue: u32, latency: u64) -> WorkerCapability {
        WorkerCapability {
            worker_id: id.into(),
            endpoint: format!("wss://{id}"),
            backend: "mlx".into(),
            models: vec![model.clone()],
            memory_mb: 32_768,
            max_concurrency: 2,
            active_requests: 0,
            queue_depth: queue,
            estimated_latency_ms: latency,
            attestation: AttestationLevel::Hardware,
            encrypted_requests: true,
            encrypted_responses: true,
            request_public_key: [7u8; KEY_LEN],
        }
    }

    #[test]
    fn manifest_digest_is_stable_and_alias_changes_identity() {
        let one = manifest("research-model", "build-a");
        let mut two = one.clone();
        two.alias = "another-alias".into();
        assert!(one.digest().starts_with("sha256:"));
        assert_ne!(one.digest(), two.digest());
        ModelManifest::from_value(&one.to_value()).unwrap();
    }

    #[test]
    fn scheduler_filters_capabilities_and_breaks_ties_by_worker_id() {
        let model = manifest("research-model", "build-a");
        let digest = model.digest();
        let mut first = worker("worker-b", &model, 1, 10);
        let second = worker("worker-a", &model, 1, 10);
        first.attestation = AttestationLevel::SelfSigned;
        let scheduler = CapabilityScheduler::new(vec![first, second]).unwrap();
        let selected = scheduler
            .select(&RequestRequirements {
                model_manifest_sha256: digest,
                min_memory_mb: 16_384,
                max_queue_depth: 4,
                min_attestation: AttestationLevel::Hardware,
                require_encrypted_requests: true,
                require_encrypted_responses: true,
            })
            .unwrap();
        assert_eq!(selected.worker_id, "worker-a");

        let encoded = selected.to_value();
        let decoded = WorkerCapability::from_value(&encoded).unwrap();
        assert_eq!(decoded, selected.clone());
    }

    #[test]
    fn scheduler_refuses_alias_only_and_unavailable_requests() {
        let model = manifest("research-model", "build-a");
        let scheduler = CapabilityScheduler::new(vec![worker("worker-a", &model, 0, 10)]).unwrap();
        let alias_only = RequestRequirements {
            model_manifest_sha256: "research-model".into(),
            min_memory_mb: 1,
            max_queue_depth: 4,
            min_attestation: AttestationLevel::None,
            require_encrypted_requests: false,
            require_encrypted_responses: false,
        };
        assert!(matches!(
            scheduler.select(&alias_only),
            Err(ComputeError::InvalidDigest { .. })
        ));

        let mut no_slots = worker("worker-b", &model, 0, 10);
        no_slots.active_requests = no_slots.max_concurrency;
        let scheduler = CapabilityScheduler::new(vec![no_slots]).unwrap();
        let unavailable = RequestRequirements {
            model_manifest_sha256: model.digest(),
            min_memory_mb: 1,
            max_queue_depth: 4,
            min_attestation: AttestationLevel::None,
            require_encrypted_requests: false,
            require_encrypted_responses: false,
        };
        assert!(matches!(
            scheduler.select(&unavailable),
            Err(ComputeError::NoEligibleWorker { .. })
        ));
    }

    #[test]
    fn request_envelope_round_trips_and_binds_metadata() {
        let mut rng = OsRng;
        let provider = RequestKey::generate(&mut rng);
        let model = manifest("research-model", "build-a").digest();
        let envelope = RequestEnvelope::seal(
            "request-1",
            "objective-1",
            &model,
            b"candidate artifact",
            provider.public(),
            &mut rng,
        )
        .unwrap();
        assert_eq!(envelope.open(&provider).unwrap(), b"candidate artifact");

        let mut moved = envelope.clone();
        moved.task_id = "objective-2".into();
        assert_eq!(
            moved.open(&provider),
            Err(RequestEnvelopeError::AuthenticationFailed)
        );
        let decoded = RequestEnvelope::from_value(&envelope.to_value()).unwrap();
        assert_eq!(decoded.open(&provider).unwrap(), b"candidate artifact");
    }

    #[test]
    fn request_envelope_rejects_wrong_key() {
        let mut rng = OsRng;
        let provider = RequestKey::generate(&mut rng);
        let wrong = RequestKey::generate(&mut rng);
        let model = manifest("research-model", "build-a").digest();
        let envelope = RequestEnvelope::seal(
            "request-1",
            "objective-1",
            &model,
            b"secret",
            provider.public(),
            &mut rng,
        )
        .unwrap();
        assert_eq!(
            envelope.open(&wrong),
            Err(RequestEnvelopeError::AuthenticationFailed)
        );
    }
}
