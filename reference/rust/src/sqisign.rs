//! SQIsign level-1 verification.
//!
//! This is `sqisign-verify`, the verification half of the crate the primary
//! signs with. It is not a second implementation. No other pure-Rust SQIsign
//! is published, and skipping the field here would admit a claim the primary
//! refuses. Level-1 standard encodings only: 65-byte keys, 148-byte signatures.

use sqisign_verify::{Level1, PublicKey, Signature, Verifier};

use crate::records::RecordError;

pub fn verify_claim(
    key: Option<&str>,
    signature: Option<&str>,
    message: &[u8],
) -> Result<(), RecordError> {
    match (key, signature) {
        (None, None) => Ok(()),
        (Some(key), Some(signature)) => {
            let key_bytes = decode(key)?;
            let sig_bytes = decode(signature)?;
            let public = PublicKey::<Level1>::from_bytes(&key_bytes)
                .map_err(|_| RecordError("sqisign_key is not a level-1 public key".into()))?;
            let sig = Signature::<Level1>::from_bytes(&sig_bytes).map_err(|_| {
                RecordError("sqisign_signature is not a level-1 standard signature".into())
            })?;
            if public.verify(message, &sig).is_ok() {
                Ok(())
            } else {
                Err(RecordError(
                    "sqisign_signature does not verify under sqisign_key".into(),
                ))
            }
        }
        _ => Err(RecordError(
            "a claim carries sqisign_key or sqisign_signature but not both".into(),
        )),
    }
}

fn decode(text: &str) -> Result<Vec<u8>, RecordError> {
    if !text.len().is_multiple_of(2) {
        return Err(RecordError("sqisign field is not lowercase hex".into()));
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_val(bytes[i])?;
        let lo = hex_val(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_val(byte: u8) -> Result<u8, RecordError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(RecordError("sqisign field is not lowercase hex".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_primary_level1_signature_verifies_and_a_flipped_byte_does_not() {
        let text = include_str!("../../../conformance/sqisign-level1.txt");
        let mut pk = None;
        let mut sig = None;
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("pk ") {
                pk = Some(rest.trim());
            } else if let Some(rest) = line.strip_prefix("sig ") {
                sig = Some(rest.trim());
            }
        }
        let pk = pk.expect("pk");
        let sig = sig.expect("sig");
        verify_claim(Some(pk), Some(sig), b"claim-bytes").expect("primary vector");
        verify_claim(None, None, b"claim-bytes").expect("absent");
        assert!(verify_claim(Some(pk), None, b"claim-bytes").is_err());
        let mut bad = sig.to_string();
        let last = bad.pop().unwrap();
        bad.push(if last == 'a' { 'b' } else { 'a' });
        assert!(verify_claim(Some(pk), Some(&bad), b"claim-bytes").is_err());
    }
}
