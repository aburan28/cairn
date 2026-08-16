//! The cross-implementation contract. If these fail, this crate cannot
//! interoperate with any other implementation and nothing else matters.
use cairn::canonical::{merkle_root, Value};

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

/// Regenerate `conformance/signed-records.json`, which the reference
/// implementation reproduces field for field via
/// `cairn-reference signed-records`.
///
/// A signature is part of the record, so it is part of the id. Two
/// implementations that disagreed about how a signed record digests would give
/// every signed claim two ids, and citation would break at the first one --
/// so this pins the canonical bytes, not just the signature.
///
/// `CAIRN_WRITE_VECTORS=1` rewrites the file.
#[test]
fn signed_record_vectors_match_the_committed_file() {
    use cairn::canonical::Value;
    use cairn::crypto::identity::Identity;
    use cairn::records::{Claim, Commitment};

    let alice = Identity::from_secret_bytes([23u8; 32]);
    let ts = "2026-07-28T00:00:00+00:00";
    let claim = Claim::new(
        "sha256:obj",
        "placeholder",
        Value::object([("n", Value::Int(42))]),
        "s3cret",
        ts,
        vec![],
    )
    .expect("valid")
    .signed_with(&alice);
    let commitment =
        Commitment::new("sha256:obj", "placeholder", "sha256:h", ts).signed_with(&alice);

    // Both must verify here before they are offered as vectors at all.
    claim.verify_signature().expect("claim self-verifies");
    commitment
        .verify_signature()
        .expect("commitment self-verifies");

    let produced = Value::object([
        (
            "claim",
            Value::object([
                (
                    "canonical",
                    Value::string(claim.to_value().canonical_string()),
                ),
                ("id", Value::string(claim.id())),
                ("record", claim.to_value()),
            ]),
        ),
        (
            "commitment",
            Value::object([
                (
                    "canonical",
                    Value::string(commitment.to_value().canonical_string()),
                ),
                ("id", Value::string(commitment.id())),
                ("record", commitment.to_value()),
            ]),
        ),
    ])
    .canonical_string();

    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/conformance/signed-records.json"
    );
    if std::env::var("CAIRN_WRITE_VECTORS").is_ok() {
        std::fs::write(path, format!("{produced}\n")).expect("write vectors");
        return;
    }
    let committed =
        std::fs::read_to_string(path).expect("conformance/signed-records.json is missing");
    assert_eq!(
        committed.trim(),
        produced,
        "signed record vectors moved -- signing or canonical encoding changed"
    );
}
