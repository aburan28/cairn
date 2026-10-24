use cairn::canonical::Value;
use cairn::verifiers::sixclass;
use cairn::Status;

#[test]
fn isolated_secp_example_accepts_and_tampering_rejects() {
    let objective = Value::from_json(include_str!(
        "../examples/crypto-goals/sixclass-secp256k1-piecework/objective.json"
    ))
    .unwrap();
    let artifact = Value::from_json(include_str!(
        "../examples/crypto-goals/sixclass-secp256k1-piecework/sample-dp.json"
    ))
    .unwrap();
    let spec = objective.get("verifier").unwrap();
    assert_eq!(sixclass::verify(spec, &artifact).status, Status::Accept);
    let mut changed = artifact.clone();
    if let Value::Object(root) = &mut changed {
        if let Value::Array(dps) = root.get_mut("dps").unwrap() {
            if let Value::Object(dp) = &mut dps[0] {
                dp.insert("a".into(), Value::string("1"));
            }
        }
    }
    assert_eq!(sixclass::verify(spec, &changed).status, Status::Reject);
}
