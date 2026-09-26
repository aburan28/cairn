//! ML-DSA-65 as a second signature on a record.
//!
//! The ed25519 signature stays the one `submitter` names. This key is carried
//! beside it, omitted when absent, so a record written before the field
//! existed keeps its id. When the field is present both signatures have to
//! verify; a record that carries one and not the other is refused.

use ml_dsa::{KeyExport, Keypair, MlDsa65, Seed, Signature, SigningKey, VerifyingKey};
use ml_dsa::{Signer, Verifier};
use rand_core::{CryptoRng, RngCore};

use crate::hex;

pub struct PqKey(SigningKey<MlDsa65>);

impl PqKey {
    pub fn from_seed(bytes: [u8; 32]) -> PqKey {
        PqKey(SigningKey::from_seed(&Seed::from(bytes)))
    }

    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> PqKey {
        let mut seed = Seed::default();
        rng.fill_bytes(seed.as_mut_slice());
        PqKey(SigningKey::from_seed(&seed))
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.0.verifying_key().to_bytes().to_vec()
    }

    pub fn public_hex(&self) -> String {
        hex::encode(&self.public_key())
    }

    pub fn sign_hex(&self, message: &[u8]) -> String {
        let signature: Signature<MlDsa65> = self.0.sign(message);
        hex::encode(signature.encode().as_slice())
    }
}

/// Verify an ML-DSA-65 signature. `false` for a bad key, a bad signature, or
/// a signature that does not match — callers turn that into a refusal.
pub fn verify(public_hex: &str, message: &[u8], signature_hex: &str) -> bool {
    let Some(public) = hex::decode(public_hex) else {
        return false;
    };
    let Some(signature) = hex::decode(signature_hex) else {
        return false;
    };
    let Ok(public) = <ml_dsa::EncodedVerifyingKey<MlDsa65>>::try_from(public.as_slice()) else {
        return false;
    };
    let key = VerifyingKey::<MlDsa65>::decode(&public);
    let Ok(signature) = Signature::<MlDsa65>::try_from(signature.as_slice()) else {
        return false;
    };
    key.verify(message, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Seed `[7u8; 32]`, message `claim-bytes`. The reference crate verifies
    /// these bytes with `fips204`, not with this `ml-dsa` crate.
    #[test]
    fn a_fixed_seed_signature_matches_the_conformance_vector() {
        let (pk, sig) = vector();
        let key = PqKey::from_seed([7u8; 32]);
        assert_eq!(key.public_hex(), pk);
        assert_eq!(key.sign_hex(b"claim-bytes"), sig);
        assert!(verify(pk, b"claim-bytes", sig));
    }

    fn vector() -> (&'static str, &'static str) {
        let text = include_str!("../../conformance/mldsa65-seed7.txt");
        let mut pk = None;
        let mut sig = None;
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("pk ") {
                pk = Some(rest.trim());
            } else if let Some(rest) = line.strip_prefix("sig ") {
                sig = Some(rest.trim());
            }
        }
        (pk.expect("pk"), sig.expect("sig"))
    }
}
