//! Ed25519 verification, and only verification.
//!
//! The reference reads records; it has no business holding a key, and a
//! signer here would be a second place for a nonce bug to live. Signing stays
//! in the primary implementation.
//!
//! `verify_strict` plus an explicit weak-key refusal, matching the primary.
//! Plain `verify` is not enough: the ed25519 family has several places where
//! honest implementations differ, and each is a place two nodes could reach
//! opposite verdicts on identical bytes.

use ed25519_dalek::{Signature, VerifyingKey};

pub fn public_key(hex: &str) -> Option<VerifyingKey> {
    let bytes: [u8; 32] = decode_hex(hex)?.try_into().ok()?;
    let key = VerifyingKey::from_bytes(&bytes).ok()?;
    // A small-order key verifies signatures that require no secret at all, so
    // accepting one authenticates nothing.
    (!key.is_weak()).then_some(key)
}

pub fn signature(hex: &str) -> Option<Signature> {
    let bytes: [u8; 64] = decode_hex(hex)?.try_into().ok()?;
    Some(Signature::from_bytes(&bytes))
}

pub fn verify(key: &VerifyingKey, message: &[u8], signature: &Signature) -> bool {
    key.verify_strict(message, signature).is_ok()
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}
