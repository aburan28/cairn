//! The primary's sealed-submission logs, audited here to the same verdicts.
//!
//! `conformance/sealed/` holds logs the primary wrote: two clean ones, and one
//! per dealer-accountability rule with a single record appended beneath the
//! rules engine. Each must audit clean here when the manifest says clean, and
//! be flagged at the entry it names otherwise. The primary runs the same check
//! over the same files (`the_sealed_fixtures_audit_as_their_manifest_says`),
//! so the two agree on every case or one of these fails.

use std::path::PathBuf;

use cairn_reference::canonical::Value;
use cairn_reference::ledger::Ledger;
use cairn_reference::node::Node;

#[test]
fn the_primarys_sealed_fixtures_audit_as_their_manifest_says() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/sealed");
    let text = std::fs::read_to_string(dir.join("manifest.json")).expect("the manifest");
    let manifest = Value::from_json(&text).expect("the manifest parses");
    let cases = manifest.as_array().expect("an array");
    assert!(cases.len() >= 10, "{} cases", cases.len());
    for case in cases {
        let file = case.get("log").and_then(Value::as_str).expect("log");
        let path = dir.join(file);
        // A missing log opens as an empty one, which audits clean: CI once
        // passed the clean cases that way while the files were gitignored.
        assert!(path.is_file(), "conformance/sealed/{file} is missing");
        let ledger = Ledger::open(path).expect("opens");
        let node = Node::new(ledger, &dir);
        let problems = node.audit(false);
        match case.get("flagged_entry").and_then(Value::as_i128) {
            None => assert!(problems.is_empty(), "{file}: {problems:?}"),
            Some(seq) => assert!(
                problems
                    .iter()
                    .any(|problem| problem.contains(&format!("entry {seq}:"))),
                "{file}: entry {seq} not flagged in {problems:?}"
            ),
        }
    }
}
