//! Signed resource self-reports.
//!
//! A signature proves who said "71% CPU". It does not prove the machine was
//! that busy. These reports are scheduling hints. They are not records, they
//! are not settled, and nothing in this module has a path into a balance.
//!
//! Capacity that should move reputation is a challenge somebody else attests
//! (Freivalds, proof of space). That attestation is a normal record and is
//! slashable. This type is the cheaper half: the claim, labelled as such.

use crate::canonical::Value;
use crate::crypto::{verify_bytes, Identity, Signature};
use crate::hex;
use crate::obj;

/// What a node says about itself. Every field is a self-report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfReport {
    /// Ed25519 public key, 64 lowercase hex, same shape as a signed submitter.
    pub node: String,
    pub cpu_cores: u32,
    pub ram_mib: u64,
    pub gpu: Option<String>,
    pub vram_mib: u64,
    /// 0..=100. A display number, never an input to payment.
    pub cpu_percent: u8,
    /// Unix seconds after which a scheduler should ignore the report.
    pub expires_at: u64,
    pub signature: String,
}

impl SelfReport {
    /// Bytes the node signs. Canonical, so two encoders agree.
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut fields = vec![
            ("cpu_cores", Value::Int(i128::from(self.cpu_cores))),
            ("cpu_percent", Value::Int(i128::from(self.cpu_percent))),
            ("expires_at", Value::Int(i128::from(self.expires_at))),
            ("node", Value::string(self.node.clone())),
            ("ram_mib", Value::Int(i128::from(self.ram_mib))),
            ("vram_mib", Value::Int(i128::from(self.vram_mib))),
        ];
        if let Some(gpu) = &self.gpu {
            fields.push(("gpu", Value::string(gpu.clone())));
        }
        fields.sort_by(|a, b| a.0.cmp(b.0));
        Value::object(fields).canonical_bytes()
    }

    pub fn sign(mut self, identity: &Identity) -> Self {
        self.node = hex::encode(identity.public().as_bytes());
        let sig = identity.sign_bytes(&self.signing_payload());
        self.signature = hex::encode(sig.as_bytes());
        self
    }

    /// `Ok(true)` when the signature matches `node`. A failed check is a bad
    /// hint, not a rejected artifact.
    pub fn verifies(&self) -> bool {
        if self.cpu_percent > 100 {
            return false;
        }
        let Some(key_bytes) = hex::decode(&self.node) else {
            return false;
        };
        if key_bytes.len() != 32 {
            return false;
        }
        let Some(sig_bytes) = hex::decode(&self.signature) else {
            return false;
        };
        if sig_bytes.len() != 64 {
            return false;
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&sig_bytes);
        let signature = Signature::from_bytes(sig);
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);
        verify_bytes(&key, &self.signing_payload(), &signature).is_ok()
    }

    pub fn to_value(&self) -> Value {
        let mut map = obj![
            "node" => Value::string(self.node.clone()),
            "cpu_cores" => Value::Int(i128::from(self.cpu_cores)),
            "ram_mib" => Value::Int(i128::from(self.ram_mib)),
            "vram_mib" => Value::Int(i128::from(self.vram_mib)),
            "cpu_percent" => Value::Int(i128::from(self.cpu_percent)),
            "expires_at" => Value::Int(i128::from(self.expires_at)),
            "signature" => Value::string(self.signature.clone()),
            "pays" => Value::string("never"),
        ];
        if let Some(gpu) = &self.gpu {
            if let Value::Object(ref mut fields) = map {
                fields.insert("gpu".into(), Value::string(gpu.clone()));
            }
        }
        map
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn a_signed_report_verifies_and_a_tampered_one_does_not() {
        let id = Identity::generate(&mut OsRng);
        let report = SelfReport {
            node: String::new(),
            cpu_cores: 8,
            ram_mib: 32_768,
            gpu: Some("example".into()),
            vram_mib: 24_576,
            cpu_percent: 71,
            expires_at: 1_800_000_000,
            signature: String::new(),
        }
        .sign(&id);
        assert!(report.verifies());
        let mut lied = report.clone();
        lied.cpu_percent = 100;
        assert!(!lied.verifies());
        assert!(report.to_value().get("pays").and_then(Value::as_str) == Some("never"));
    }
}
