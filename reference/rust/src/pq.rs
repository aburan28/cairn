//! ML-DSA-65 verification with `fips204`, a different library from the primary
//! crate's `ml-dsa`. The two have to agree on a signature or a dual-signed
//! claim audits clean on one node and fails on the other.

use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Verifier};

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
            let public = ml_dsa_65::PublicKey::try_from_bytes(
                key_bytes
                    .try_into()
                    .map_err(|_| RecordError("pq_key is not an ML-DSA-65 public key".into()))?,
            )
            .map_err(|_| RecordError("pq_key is not an ML-DSA-65 public key".into()))?;
            let sig: [u8; 3309] = sig_bytes
                .try_into()
                .map_err(|_| RecordError("pq_signature is not an ML-DSA-65 signature".into()))?;
            if public.verify(message, &sig, &[]) {
                Ok(())
            } else {
                Err(RecordError(
                    "pq_signature does not verify under pq_key".into(),
                ))
            }
        }
        _ => Err(RecordError(
            "a claim carries pq_key or pq_signature but not both".into(),
        )),
    }
}

fn decode(text: &str) -> Result<Vec<u8>, RecordError> {
    if !text.len().is_multiple_of(2) {
        return Err(RecordError("pq field is not lowercase hex".into()));
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
        _ => Err(RecordError("pq field is not lowercase hex".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The primary crate signed this with `ml-dsa` from seed `[7u8; 32]`.
    /// Verifying it here is the check that the two libraries agree on the
    /// bytes; a round trip inside one crate would not be.
    #[test]
    fn the_primary_fixed_seed_signature_verifies_and_a_flipped_byte_does_not() {
        let (pk, sig) = vector();
        verify_claim(Some(pk), Some(sig), b"claim-bytes").expect("primary vector");
        verify_claim(None, None, b"claim-bytes").expect("absent");
        assert!(verify_claim(Some(pk), None, b"claim-bytes").is_err());
        let mut bad = sig.to_string();
        let last = bad.pop().unwrap();
        bad.push(if last == 'a' { 'b' } else { 'a' });
        assert!(verify_claim(Some(pk), Some(&bad), b"claim-bytes").is_err());
    }

    fn vector() -> (&'static str, &'static str) {
        let text = include_str!("../../../conformance/mldsa65-seed7.txt");
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
