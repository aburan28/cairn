//! An assigned research budget cannot be claimed by a copied submitter name,
//! and an imported log cannot bypass the same restriction.

use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use cairn::canonical::Value;
use cairn::contributor_score::{observations_from_node, AssignmentOutcome};
use cairn::crypto::identity::Identity;
use cairn::ledger::Ledger;
use cairn::node::{Node, RuleViolation};
use cairn::records::{commitment_hash, Commitment, Objective};
use cairn::verifiers::VerifierRegistry;

const TS: &str = "2026-07-28T00:00:00+00:00";

#[test]
fn assignment_is_enforced_at_admission_and_audit() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir =
        std::env::temp_dir().join(format!("cairn-exploration-{}-{unique}", std::process::id()));
    fs::create_dir_all(&dir).expect("scratch directory");
    let ledger = Ledger::open(dir.join("log.jsonl")).expect("log");
    let mut node = Node::with_registry(ledger, VerifierRegistry::new(&dir));
    let alice = Identity::from_secret_bytes([23; 32]);
    let bob = Identity::from_secret_bytes([2; 32]);
    let objective = Objective::new(
        "assigned-research",
        "Deliver one metered research assignment",
        Value::object([
            ("kind", Value::string("lean")),
            ("statement", Value::string("theorem assigned : True")),
        ]),
        0,
        "treasury",
        TS,
        Some(TS.to_string()),
        None,
    )
    .expect("objective")
    .assigned_to(alice.submitter_id())
    .expect("assignee is a key");
    // Independently computed with Python's sorted, compact JSON and hashlib.
    assert_eq!(
        objective.id(),
        "sha256:64b34b8780a101a6014e889eae0823bc1f5d5606c358dd2f4051f2d59680dc15"
    );
    assert_ne!(objective.id(), {
        let mut open = objective.clone();
        open.assignee = None;
        assert!(open.to_value().get("assignee").is_none());
        open.id()
    });
    node.post_objective(&objective, TS).expect("post");
    let artifact = Value::object([("n", Value::Int(1))]);
    let bob_commitment = Commitment::new(
        objective.id(),
        bob.submitter_id(),
        commitment_hash(&objective.id(), &bob.submitter_id(), &artifact, "nonce"),
        TS,
    )
    .signed_with(&bob);
    assert!(matches!(
        node.commit(&bob_commitment, TS),
        Err(RuleViolation::WrongAssignee { .. })
    ));
    let alice_commitment = Commitment::new(
        objective.id(),
        alice.submitter_id(),
        commitment_hash(&objective.id(), &alice.submitter_id(), &artifact, "nonce"),
        TS,
    )
    .signed_with(&alice);
    node.commit(&alice_commitment, TS)
        .expect("assignee commits");
    assert!(node.audit(false).is_empty(), "honest log must audit");
    let as_of = cairn::partition::epoch_of(
        cairn::time::parse_rfc3339(TS).expect("timestamp") as u64,
        cairn::partition::EPOCH_SECONDS,
    ) + 1;
    let trusted = std::collections::BTreeSet::from([String::from("treasury")]);
    let rows = observations_from_node(&node, &alice.submitter_id(), &trusted, as_of)
        .expect("derive assignments");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].outcome, AssignmentOutcome::Missed);
    assert!(
        observations_from_node(&node, &alice.submitter_id(), &Default::default(), as_of)
            .expect("untrusted funders are omitted")
            .is_empty()
    );

    // A peer can send bytes this node's admission path would refuse. The
    // auditor must still name the policy violation on the imported record.
    node.ledger_mut()
        .append("commitment", bob_commitment.to_value(), TS)
        .expect("inject imported commitment");
    let problems = node.audit(false);
    assert!(
        problems.iter().any(|problem| problem.contains("assignee")),
        "{problems:?}"
    );
    drop(node);
    fs::remove_dir_all(dir).expect("remove scratch directory");
}
