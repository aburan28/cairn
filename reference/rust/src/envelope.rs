//! The shape of a sealed envelope, as the primary decodes it.
//!
//! A commitment's `envelope` decides one rule here -- a sealed claim may carry
//! a `created_at` from an earlier epoch than its reveal -- and the primary
//! grants that only to an envelope its decoder accepts. Before this module the
//! reference stored any value as the envelope and treated it as sealed, so
//! `"envelope": null` relaxed the rule here and not there: two implementations
//! disagreeing about whether a claim was admissible, while both audited clean.
//!
//! Written from the primary's rules rather than shared with it (see the crate
//! docs for why): an object of `type` "sealed_envelope", `version` 2, a
//! `threshold` in `1..=` the share count, a 12-byte `nonce`, hex `ciphertext`,
//! a string `aad`, and `sealed_shares` -- at least one, distinct `index`es,
//! each with a 12-byte `nonce`, hex `ciphertext`, and `kem` legs in suite
//! order, each suite once, each ciphertext its suite's length, McEliece among
//! them. Hex is lowercase. Unknown fields are ignored, as the primary ignores
//! them.

use crate::canonical::Value;

/// KEM suites in the order legs must appear, with their ciphertext lengths.
const SUITES: [(&str, usize); 3] = [
    ("mceliece348864", 96),
    ("ml-kem-768", 1088),
    ("hqc-128", 4433),
];

fn hex(value: &Value, field: &str) -> Result<Vec<u8>, String> {
    let text = value
        .get(field)
        .ok_or_else(|| format!("missing {field}"))?
        .as_str()
        .ok_or_else(|| format!("{field} must be a string"))?;
    if !text.len().is_multiple_of(2) {
        return Err(format!("{field} is not lowercase hex"));
    }
    let nibble = |b: u8| match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    };
    text.as_bytes()
        .chunks(2)
        .map(|pair| Some((nibble(pair[0])? << 4) | nibble(pair[1])?))
        .collect::<Option<Vec<u8>>>()
        .ok_or_else(|| format!("{field} is not lowercase hex"))
}

fn fixed12(value: &Value, field: &str) -> Result<[u8; 12], String> {
    hex(value, field)?
        .try_into()
        .map_err(|_| format!("{field} must be 12 bytes"))
}

fn small(value: &Value, field: &str) -> Result<u8, String> {
    value
        .get(field)
        .ok_or_else(|| format!("missing {field}"))?
        .as_i128()
        .and_then(|n| u8::try_from(n).ok())
        .ok_or_else(|| format!("{field} must be an integer in 0..=255"))
}

/// Is `value` an envelope the primary's decoder accepts? `Err` names the
/// first rule it breaks.
pub fn check(value: &Value) -> Result<(), String> {
    if value.as_object().is_none() {
        return Err("envelope must be an object".into());
    }
    if value.get("type").and_then(Value::as_str) != Some("sealed_envelope") {
        return Err("envelope type must be \"sealed_envelope\"".into());
    }
    if value.get("version").and_then(Value::as_i128) != Some(2) {
        return Err("envelope version must be 2".into());
    }
    let threshold = small(value, "threshold")?;
    fixed12(value, "nonce")?;
    hex(value, "ciphertext")?;
    value
        .get("aad")
        .and_then(Value::as_str)
        .ok_or("envelope aad must be a string")?;
    let shares = value
        .get("sealed_shares")
        .ok_or("missing sealed_shares")?
        .as_array()
        .ok_or("sealed_shares must be an array")?;
    let mut seen: Vec<u8> = Vec::new();
    for share in shares {
        if share.as_object().is_none() {
            return Err("a sealed share must be an object".into());
        }
        let legs = share
            .get("kem")
            .ok_or("missing kem")?
            .as_array()
            .ok_or("kem must be an array")?;
        if legs.is_empty() {
            return Err("a sealed share needs at least one KEM leg".into());
        }
        let mut last: Option<usize> = None;
        for leg in legs {
            if leg.as_object().is_none() {
                return Err("a KEM leg must be an object".into());
            }
            let name = leg
                .get("suite")
                .ok_or("missing suite")?
                .as_str()
                .ok_or("suite must be a string")?;
            let position = SUITES
                .iter()
                .position(|(suite, _)| *suite == name)
                .ok_or_else(|| format!("unknown KEM suite {name:?}"))?;
            if last.is_some_and(|previous| previous >= position) {
                return Err("KEM legs must be in suite order, each suite once".into());
            }
            last = Some(position);
            if hex(leg, "ciphertext")?.len() != SUITES[position].1 {
                return Err(format!("{name} ciphertext has the wrong length"));
            }
        }
        if !legs
            .iter()
            .any(|leg| leg.get("suite").and_then(Value::as_str) == Some(SUITES[0].0))
        {
            return Err("every sealed share needs a mceliece348864 leg".into());
        }
        let index = small(share, "index")?;
        fixed12(share, "nonce")?;
        hex(share, "ciphertext")?;
        if seen.contains(&index) {
            return Err(format!("sealed share index {index} appears twice"));
        }
        seen.push(index);
    }
    if seen.is_empty() {
        return Err("an envelope needs at least one sealed share".into());
    }
    if threshold == 0 || usize::from(threshold) > seen.len() {
        return Err("envelope threshold must be between 1 and the share count".into());
    }
    Ok(())
}

/// The nonce and ciphertext of the share sealed at `index`, from an envelope
/// [`check`] accepts.
pub fn sealed_share(envelope: &Value, index: u8) -> Option<([u8; 12], Vec<u8>)> {
    let share = envelope
        .get("sealed_shares")?
        .as_array()?
        .iter()
        .find(|share| small(share, "index") == Ok(index))?;
    Some((
        fixed12(share, "nonce").ok()?,
        hex(share, "ciphertext").ok()?,
    ))
}

/// Does `share_key` open the share sealed at `index` to exactly `(x, data)`?
/// The reference's half of the check that makes a committee share verifiable
/// on its own; the sealed share carries no associated data of its own, the
/// key derivation having absorbed it.
pub fn share_opens(envelope: &Value, index: u8, share_key: &[u8; 32], x: u8, data: &[u8]) -> bool {
    let Some((nonce, ciphertext)) = sealed_share(envelope, index) else {
        return false;
    };
    match crate::aead::open(share_key, &nonce, b"", &ciphertext) {
        Some(plaintext) => plaintext.split_first() == Some((&x, data)),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leg(suite: &str, length: usize) -> Value {
        Value::object([
            ("suite", Value::string(suite)),
            ("ciphertext", Value::string("00".repeat(length))),
        ])
    }

    fn share(index: i128, legs: Vec<Value>) -> Value {
        Value::object([
            ("index", Value::Int(index)),
            ("kem", Value::Array(legs)),
            ("nonce", Value::string("00".repeat(12))),
            ("ciphertext", Value::string("abcd")),
        ])
    }

    fn envelope(threshold: i128, shares: Vec<Value>) -> Value {
        Value::object([
            ("type", Value::string("sealed_envelope")),
            ("version", Value::Int(2)),
            ("threshold", Value::Int(threshold)),
            ("nonce", Value::string("11".repeat(12))),
            ("ciphertext", Value::string("ff")),
            ("aad", Value::string("sha256:00")),
            ("sealed_shares", Value::Array(shares)),
        ])
    }

    #[test]
    fn an_envelope_is_checked_as_the_primary_decodes_it() {
        let good = || vec![leg("mceliece348864", 96), leg("ml-kem-768", 1088)];
        assert_eq!(check(&envelope(1, vec![share(1, good())])), Ok(()));
        assert!(check(&Value::Null).is_err());
        assert!(check(&Value::object(Vec::<(&str, Value)>::new())).is_err());
        assert!(check(&envelope(0, vec![share(1, good())])).is_err());
        assert!(check(&envelope(2, vec![share(1, good())])).is_err());
        assert!(check(&envelope(1, vec![])).is_err());
        assert!(check(&envelope(1, vec![share(1, good()), share(1, good())])).is_err());
        assert!(check(&envelope(1, vec![share(256, good())])).is_err());
        // Suites: order, uniqueness, length, McEliece mandatory, names known.
        let reordered = vec![leg("ml-kem-768", 1088), leg("mceliece348864", 96)];
        assert!(check(&envelope(1, vec![share(1, reordered)])).is_err());
        let twice = vec![leg("mceliece348864", 96), leg("mceliece348864", 96)];
        assert!(check(&envelope(1, vec![share(1, twice)])).is_err());
        assert!(check(&envelope(
            1,
            vec![share(1, vec![leg("mceliece348864", 95)])]
        ))
        .is_err());
        assert!(check(&envelope(1, vec![share(1, vec![leg("ml-kem-768", 1088)])])).is_err());
        assert!(check(&envelope(1, vec![share(1, vec![leg("x25519", 32)])])).is_err());
        // Uppercase hex is not this format's hex.
        let mut upper = share(1, good());
        if let Value::Object(map) = &mut upper {
            map.insert("ciphertext".into(), Value::string("ABCD"));
        }
        assert!(check(&envelope(1, vec![upper])).is_err());
    }
}
