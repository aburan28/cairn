//! The cross-implementation contract. If these fail, this crate cannot
//! interoperate with any other implementation and nothing else matters.
use proofwork::canonical::{merkle_root, Value};

fn vectors() -> Value {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/conformance/vectors.json"
    ))
    .expect("conformance/vectors.json is missing");
    Value::from_json(&text).expect("vectors.json must itself be canonical-parseable")
}

#[test]
fn canonical_bytes_match_the_reference_implementation() {
    let v = vectors();
    let cases = v.get("canonical").unwrap().as_array().unwrap();
    assert!(cases.len() >= 12, "expected the full vector set");
    for (i, case) in cases.iter().enumerate() {
        let value = case.get("value").unwrap();
        let expected = case.get("canonical_utf8").unwrap().as_str().unwrap();
        let expected_hex = case.get("canonical_hex").unwrap().as_str().unwrap();
        let expected_digest = case.get("digest").unwrap().as_str().unwrap();

        let actual = value.canonical_string();
        assert_eq!(actual, expected, "case {i}: canonical text differs");

        let actual_hex: String = value
            .canonical_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(actual_hex, expected_hex, "case {i}: canonical bytes differ");
        assert_eq!(value.digest(), expected_digest, "case {i}: digest differs");
    }
}

#[test]
fn merkle_roots_match_the_reference_implementation() {
    let v = vectors();
    for (i, case) in v
        .get("merkle")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        let leaves: Vec<String> = case
            .get("leaves")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|l| l.as_str().unwrap().to_string())
            .collect();
        let expected = case.get("root").unwrap();
        match merkle_root(&leaves) {
            None => assert!(expected.is_null(), "case {i}: expected a root"),
            Some(root) => assert_eq!(root, expected.as_str().unwrap(), "case {i}"),
        }
    }
}

#[test]
fn floats_are_refused_at_the_json_boundary() {
    assert!(Value::from_json(r#"{"x": 1.5}"#).is_err());
    assert!(Value::from_json(r#"{"x": [1, {"y": 0.1}]}"#).is_err());
    assert!(Value::from_json(r#"{"x": 1e3}"#).is_err());
    assert!(Value::from_json(r#"{"x": 1}"#).is_ok());
}

#[test]
fn oversized_integers_are_refused_rather_than_becoming_floats() {
    // The failure this prevents: a bignum silently degrading to a float and
    // hashing differently on the other implementation.
    let too_big = "1".repeat(60);
    assert!(Value::from_json(&format!(r#"{{"x": {too_big}}}"#)).is_err());
}
