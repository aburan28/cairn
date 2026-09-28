//! SQIsign level 1, as a third signature on a record.
//!
//! Ed25519 is the signature `submitter` names. ML-DSA-65 may sit beside it.
//! This one may sit beside those. It is omitted when absent, so a record
//! written before the field existed keeps its id, and it is never accepted
//! as the only signature on a claim: the ed25519 check still runs.
//!
//! Level 1 standard signatures only, 65-byte public keys and 148-byte
//! signatures. Compressed, expanded, and compact encodings are refused.
//! Two accepted lengths would be two parses, and two parses are how
//! implementations drift.
//!
//! The implementation is `sqisign-rs`. It is not audited. Signing uses an
//! `f64` approximation inside LLL, so a seed does not pin signature bytes
//! across machines. Verification is the check that admits the record.

use rand_core::{CryptoRng, RngCore};
use sqisign_rs::{Level1, PublicKey, Signature, SigningKey, Verifier};

use crate::hex;

pub struct SqiKey {
    inner: SigningKey,
}

impl SqiKey {
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> SqiKey {
        let (_public, inner) = sqisign_rs::generate(rng);
        SqiKey { inner }
    }

    pub fn public_hex(&self) -> String {
        hex::encode(self.inner.public_key().to_bytes().as_slice())
    }

    pub fn sign_hex<R: RngCore + CryptoRng>(&self, message: &[u8], rng: &mut R) -> Option<String> {
        let signature = self.inner.sign(message, rng).ok()?;
        Some(hex::encode(signature.to_bytes().as_slice()))
    }
}

/// Verify a level-1 standard SQIsign signature. `false` for a bad key, a bad
/// length, or a signature that does not match.
pub fn verify(public_hex: &str, message: &[u8], signature_hex: &str) -> bool {
    let Some(public) = hex::decode(public_hex) else {
        return false;
    };
    let Some(signature) = hex::decode(signature_hex) else {
        return false;
    };
    let Ok(key) = PublicKey::<Level1>::from_bytes(&public) else {
        return false;
    };
    let Ok(signature) = Signature::<Level1>::from_bytes(&signature) else {
        return false;
    };
    key.verify(message, &signature).is_ok()
}

#[cfg(test)]
pub struct TestRng {
    seed: [u8; 32],
    counter: u64,
}

#[cfg(test)]
impl TestRng {
    pub fn new(seed: [u8; 32]) -> Self {
        Self { seed, counter: 0 }
    }
}

#[cfg(test)]
impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        use sha2::{Digest, Sha256};
        let mut offset = 0;
        while offset < dest.len() {
            let mut hasher = Sha256::new();
            hasher.update(b"cairn/sqisign/rng");
            hasher.update(self.seed);
            hasher.update(self.counter.to_le_bytes());
            self.counter += 1;
            let block = hasher.finalize();
            let n = (dest.len() - offset).min(32);
            dest[offset..offset + n].copy_from_slice(&block[..n]);
            offset += n;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

#[cfg(test)]
impl CryptoRng for TestRng {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_level1_signature_verifies_and_a_flipped_byte_does_not() {
        let mut rng = TestRng::new([9u8; 32]);
        let key = SqiKey::generate(&mut rng);
        let sig = key.sign_hex(b"claim-bytes", &mut rng).expect("sign");
        assert_eq!(hex::decode(&key.public_hex()).unwrap().len(), 65);
        assert_eq!(hex::decode(&sig).unwrap().len(), 148);
        assert!(verify(&key.public_hex(), b"claim-bytes", &sig));
        let mut bad = sig.clone();
        let last = bad.pop().unwrap();
        bad.push(if last == 'a' { 'b' } else { 'a' });
        assert!(!verify(&key.public_hex(), b"claim-bytes", &bad));
    }

    /// A signature produced by this crate. The reference verifies the same
    /// bytes. Signing is not re-run here: LLL uses `f64`, so a seed is not a
    /// portable way to reproduce the signature.
    #[test]
    fn the_pinned_level1_signature_verifies() {
        let (pk, sig) = vector();
        assert!(verify(pk, b"claim-bytes", sig));
        let mut bad = sig.to_string();
        let last = bad.pop().unwrap();
        bad.push(if last == 'a' { 'b' } else { 'a' });
        assert!(!verify(pk, b"claim-bytes", &bad));
    }

    fn vector() -> (&'static str, &'static str) {
        let text = include_str!("../../conformance/sqisign-level1.txt");
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
