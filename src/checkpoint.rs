//! Post-quantum signed roots for the append-only knowledge chain.
//!
//! A hash chain proves that a file is internally consistent, but a shorter
//! valid prefix is indistinguishable from the current log without an external
//! anchor. This module signs that anchor with FIPS 204 ML-DSA-65. The signing
//! key is separate from the McEliece transport identity: transport
//! authentication and chain authority have different rotation and custody
//! policies.

use crate::canonical::Value;
use crate::ledger::Ledger;
use ml_dsa::{KeyExport, Keypair, MlDsa65, Seed, Signature, SigningKey, VerifyingKey};
use ml_dsa::{Signer, Verifier};
use rand_core::RngCore;
use std::fmt;

// Spelled `proofwork/` and not `cairn/`: this is a wire constant, not a
// brand. It is mixed into a hash or a KDF, so changing it changes the
// values every peer already computed -- the project rename left it alone
// deliberately, exactly as it left the `pwenc1:` on-disk marker alone.
const DOMAIN: &str = "proofwork/knowledge-checkpoint/v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointError {
    Invalid(String),
    BadSignature,
    WrongSigner,
    Mismatch {
        field: String,
        expected: String,
        actual: String,
    },
    /// The local log does not reach the checkpoint's height.
    ///
    /// Distinct from [`CheckpointError::Mismatch`] on `height` because it is a
    /// different accusation. A *longer* log is the normal case -- the signer
    /// checkpointed at height `h` and the reader has since caught up past it --
    /// so `verify_prefix` compares over the first `h` entries. A *shorter* log
    /// is either a rollback or a sync that has not finished, and either way the
    /// reader has nothing to check the signed root against.
    ShortLog {
        height: u64,
        local: u64,
    },
}

impl fmt::Display for CheckpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CheckpointError::Invalid(detail) => write!(f, "invalid checkpoint: {detail}"),
            CheckpointError::BadSignature => f.write_str("checkpoint signature does not verify"),
            CheckpointError::WrongSigner => {
                f.write_str("checkpoint signer does not match the pinned root key")
            }
            CheckpointError::Mismatch {
                field,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "checkpoint {field} mismatch: expected {expected}, got {actual}"
                )
            }
            CheckpointError::ShortLog { height, local } => write!(
                f,
                "local log has {local} entries but the checkpoint covers {height}; \
                 it cannot confirm a root it does not reach"
            ),
        }
    }
}
impl std::error::Error for CheckpointError {}

/// The authority that signs knowledge-chain checkpoints.
pub struct RootKey(SigningKey<MlDsa65>);

impl RootKey {
    pub fn generate() -> RootKey {
        let mut seed = Seed::default();
        rand_core::OsRng.fill_bytes(seed.as_mut_slice());
        RootKey(SigningKey::from_seed(&seed))
    }

    pub fn from_secret_bytes(bytes: [u8; 32]) -> RootKey {
        let seed = Seed::from(bytes);
        RootKey(SigningKey::from_seed(&seed))
    }

    pub fn to_secret_bytes(&self) -> zeroize::Zeroizing<[u8; 32]> {
        zeroize::Zeroizing::new(self.0.to_seed().into())
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.0.verifying_key().to_bytes().to_vec()
    }

    pub fn sign_ledger(&self, ledger: &Ledger, issued_at: impl Into<String>) -> SignedCheckpoint {
        SignedCheckpoint::sign(&self.0, Checkpoint::from_ledger(ledger, issued_at))
    }
}

impl fmt::Debug for RootKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RootKey")
            .field("public_key_bytes", &self.public_key().len())
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub height: u64,
    pub head: Option<String>,
    pub root: Option<String>,
    pub issued_at: String,
}

impl Checkpoint {
    pub fn from_ledger(ledger: &Ledger, issued_at: impl Into<String>) -> Checkpoint {
        Checkpoint {
            height: ledger.len() as u64,
            head: ledger.head().map(str::to_string),
            root: ledger.root(),
            issued_at: issued_at.into(),
        }
    }

    pub fn to_value(&self) -> Value {
        Value::object([
            ("height", Value::Int(self.height.into())),
            (
                "head",
                self.head.clone().map(Value::String).unwrap_or(Value::Null),
            ),
            (
                "root",
                self.root.clone().map(Value::String).unwrap_or(Value::Null),
            ),
            ("issued_at", Value::String(self.issued_at.clone())),
        ])
    }

    pub fn from_value(value: &Value) -> Result<Checkpoint, CheckpointError> {
        let height = value
            .get("height")
            .and_then(Value::as_i128)
            .and_then(|n| u64::try_from(n).ok())
            .ok_or_else(|| CheckpointError::Invalid("height".into()))?;
        let optional_string = |field: &str| -> Result<Option<String>, CheckpointError> {
            match value.get(field) {
                Some(Value::Null) => Ok(None),
                Some(Value::String(text)) => Ok(Some(text.clone())),
                _ => Err(CheckpointError::Invalid(field.into())),
            }
        };
        let issued_at = value
            .get("issued_at")
            .and_then(Value::as_str)
            .ok_or_else(|| CheckpointError::Invalid("issued_at".into()))?
            .to_string();
        Ok(Checkpoint {
            height,
            head: optional_string("head")?,
            root: optional_string("root")?,
            issued_at,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedCheckpoint {
    pub checkpoint: Checkpoint,
    /// ML-DSA-65 encoded public key (1952 bytes).
    pub public_key: Vec<u8>,
    /// ML-DSA-65 encoded signature (3309 bytes).
    pub signature: Vec<u8>,
}

impl SignedCheckpoint {
    fn signing_value(checkpoint: &Checkpoint) -> Value {
        Value::object([
            ("domain", Value::String(DOMAIN.into())),
            ("checkpoint", checkpoint.to_value()),
        ])
    }

    fn sign(identity: &SigningKey<MlDsa65>, checkpoint: Checkpoint) -> SignedCheckpoint {
        let message = Self::signing_value(&checkpoint).canonical_bytes();
        let signature: Signature<MlDsa65> = identity.sign(&message);
        SignedCheckpoint {
            checkpoint,
            public_key: identity.verifying_key().to_bytes().to_vec(),
            signature: signature.encode().to_vec(),
        }
    }

    pub fn to_value(&self) -> Value {
        Value::object([
            ("checkpoint", self.checkpoint.to_value()),
            ("public_key", Value::string(hex_encode(&self.public_key))),
            ("signature", Value::string(hex_encode(&self.signature))),
        ])
    }

    pub fn from_value(value: &Value) -> Result<SignedCheckpoint, CheckpointError> {
        let checkpoint = Checkpoint::from_value(
            value
                .get("checkpoint")
                .ok_or_else(|| CheckpointError::Invalid("checkpoint".into()))?,
        )?;
        let public_key = hex_decode(
            value
                .get("public_key")
                .and_then(Value::as_str)
                .ok_or_else(|| CheckpointError::Invalid("public_key".into()))?,
        )?;
        let signature = hex_decode(
            value
                .get("signature")
                .and_then(Value::as_str)
                .ok_or_else(|| CheckpointError::Invalid("signature".into()))?,
        )?;
        if public_key.len() != 1952 || signature.len() != 3309 {
            return Err(CheckpointError::Invalid(
                "ML-DSA-65 key or signature length".into(),
            ));
        }
        Ok(SignedCheckpoint {
            checkpoint,
            public_key,
            signature,
        })
    }

    pub fn verify(&self, expected_key: &[u8]) -> Result<(), CheckpointError> {
        if self.public_key != expected_key {
            return Err(CheckpointError::WrongSigner);
        }
        let key_array =
            ml_dsa::EncodedVerifyingKey::<MlDsa65>::try_from(self.public_key.as_slice())
                .map_err(|_| CheckpointError::Invalid("public key encoding".into()))?;
        let key = VerifyingKey::<MlDsa65>::decode(&key_array);
        let signature = Signature::<MlDsa65>::try_from(self.signature.as_slice())
            .map_err(|_| CheckpointError::Invalid("signature encoding".into()))?;
        let message = Self::signing_value(&self.checkpoint).canonical_bytes();
        key.verify(&message, &signature)
            .map_err(|_| CheckpointError::BadSignature)
    }

    pub fn verify_against(
        &self,
        ledger: &Ledger,
        expected_key: &[u8],
    ) -> Result<(), CheckpointError> {
        self.verify(expected_key)?;
        let problems = ledger.verify_chain();
        if !problems.is_empty() {
            return Err(CheckpointError::Invalid(format!(
                "ledger prefix failed chain verification: {}",
                problems.join("; ")
            )));
        }
        let actual = Checkpoint::from_ledger(ledger, self.checkpoint.issued_at.clone());
        for (field, expected, got) in [
            (
                "height",
                self.checkpoint.height.to_string(),
                actual.height.to_string(),
            ),
            (
                "head",
                format!("{:?}", self.checkpoint.head),
                format!("{:?}", actual.head),
            ),
            (
                "root",
                format!("{:?}", self.checkpoint.root),
                format!("{:?}", actual.root),
            ),
        ] {
            if expected != got {
                return Err(CheckpointError::Mismatch {
                    field: field.into(),
                    expected,
                    actual: got,
                });
            }
        }
        Ok(())
    }

    /// Verify against the first `height` entries of a log that may be longer.
    ///
    /// [`SignedCheckpoint::verify_against`] is the equality check: it answers
    /// "is my log exactly what was signed?", which is the wrong question for a
    /// reader who has kept syncing. What a reader needs to know is whether the
    /// signed prefix is *contained* in the log it holds. Because the chain is
    /// hash-linked, agreeing on the head at height `h` means agreeing on every
    /// entry below it, so this is the full-strength check and not a weakened
    /// one -- an operator who rewrote entry 3 cannot reproduce the signed head
    /// at height 400.
    pub fn verify_prefix(
        &self,
        ledger: &Ledger,
        expected_key: &[u8],
    ) -> Result<(), CheckpointError> {
        self.verify(expected_key)?;
        let height = usize::try_from(self.checkpoint.height)
            .map_err(|_| CheckpointError::Invalid("height exceeds this platform".into()))?;
        let prefix = ledger
            .prefix(height)
            .ok_or_else(|| CheckpointError::ShortLog {
                height: self.checkpoint.height,
                local: ledger.len() as u64,
            })?;
        self.verify_against(&prefix, expected_key)
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn hex_decode(text: &str) -> Result<Vec<u8>, CheckpointError> {
    if !text.len().is_multiple_of(2) {
        return Err(CheckpointError::Invalid("odd-length hex".into()));
    }
    (0..text.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&text[i..i + 2], 16)
                .map_err(|_| CheckpointError::Invalid("hex".into()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn ml_dsa_checkpoint_binds_the_exact_ledger_state() {
        let path = PathBuf::from("target/checkpoint-test.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut ledger = Ledger::open(&path).unwrap();
        ledger
            .append("objective", Value::object([("x", Value::Int(1))]), "t0")
            .unwrap();
        let key = RootKey::generate();
        let signed = key.sign_ledger(&ledger, "t1");
        signed.verify_against(&ledger, &key.public_key()).unwrap();
        ledger
            .append("claim", Value::object([("x", Value::Int(2))]), "t2")
            .unwrap();
        assert!(matches!(
            signed.verify_against(&ledger, &key.public_key()),
            Err(CheckpointError::Mismatch { .. })
        ));
        let round_trip = SignedCheckpoint::from_value(&signed.to_value()).unwrap();
        assert_eq!(round_trip, signed);
        let other = RootKey::generate();
        assert_eq!(
            signed.verify(&other.public_key()),
            Err(CheckpointError::WrongSigner)
        );
        let mut forged = signed.clone();
        forged.signature[0] ^= 1;
        assert_eq!(
            forged.verify(&key.public_key()),
            Err(CheckpointError::BadSignature)
        );
    }

    #[test]
    fn checkpoint_verification_recomputes_entry_hashes() {
        let path = PathBuf::from("target/checkpoint-tamper-test.jsonl");
        let _ = std::fs::remove_file(&path);
        let mut ledger = Ledger::open(&path).unwrap();
        ledger
            .append(
                "objective",
                Value::object([("x", Value::Int(1))]),
                "2026-08-18T00:00:00+00:00",
            )
            .unwrap();
        let key = RootKey::generate();
        let signed = key.sign_ledger(&ledger, "2026-08-18T00:01:00+00:00");
        drop(ledger);

        let text = std::fs::read_to_string(&path).unwrap();
        let mut stored: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
        stored["payload"]["x"] = serde_json::json!(9);
        // Deliberately preserve `hash`: this is the exact tampering that used
        // to pass because checkpoints Merkle-hashed the stored string.
        std::fs::write(&path, format!("{}\n", stored)).unwrap();
        let tampered = Ledger::open(&path).unwrap();
        assert!(matches!(
            signed.verify_prefix(&tampered, &key.public_key()),
            Err(CheckpointError::Invalid(_))
        ));
    }
}
