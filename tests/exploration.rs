//! An assigned research budget cannot be claimed by a copied submitter name,
//! and an imported log cannot bypass the same restriction.

use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use cairn::canonical::Value;
use cairn::contributor_score::{observations_from_node, AssignmentOutcome};
use cairn::crypto::identity::Identity;
use cairn::ledger::Ledger;
use cairn::node::{Node, RuleViolation};
use cairn::records::{commitment_hash, Claim, Commitment, Objective};
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
    let funder = Identity::from_secret_bytes([31; 32]);
    let unsigned_objective = Objective::new(
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
        unsigned_objective.id(),
        "sha256:64b34b8780a101a6014e889eae0823bc1f5d5606c358dd2f4051f2d59680dc15"
    );
    assert_ne!(unsigned_objective.id(), {
        let mut open = unsigned_objective.clone();
        open.assignee = None;
        assert!(open.to_value().get("assignee").is_none());
        open.id()
    });
    let objective = unsigned_objective.clone().funded_by(&funder);
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
    let trusted = std::collections::BTreeSet::from([funder.submitter_id()]);
    let rows = observations_from_node(&node, &alice.submitter_id(), &trusted, as_of)
        .expect("derive assignments");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].outcome, AssignmentOutcome::Missed);
    assert!(
        observations_from_node(&node, &alice.submitter_id(), &Default::default(), as_of)
            .expect("untrusted funders are omitted")
            .is_empty()
    );
    node.post_objective(&unsigned_objective, TS)
        .expect("legacy objective with a funder name");
    let legacy_commitment = Commitment::new(
        unsigned_objective.id(),
        alice.submitter_id(),
        commitment_hash(
            &unsigned_objective.id(),
            &alice.submitter_id(),
            &artifact,
            "legacy-nonce",
        ),
        TS,
    )
    .signed_with(&alice);
    node.commit(&legacy_commitment, TS)
        .expect("signed worker accepts legacy objective");
    let spoofed_funder = std::collections::BTreeSet::from([String::from("treasury")]);
    assert!(
        observations_from_node(&node, &alice.submitter_id(), &spoofed_funder, as_of)
            .expect("unsigned sponsor name is ignored")
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

#[test]
fn accepted_work_scores_only_after_settlement() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "cairn-exploration-settlement-{}-{unique}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("scratch directory");
    let ledger = Ledger::open(dir.join("log.jsonl")).expect("log");
    let mut node = Node::with_registry(ledger, VerifierRegistry::new(env!("CARGO_MANIFEST_DIR")));
    let contributor = Identity::from_secret_bytes([41; 32]);
    let funder = Identity::from_secret_bytes([42; 32]);
    let base = cairn::time::parse_rfc3339(TS).expect("timestamp");
    let epoch_seconds = cairn::partition::EPOCH_SECONDS as i64;
    let reveal_at = cairn::time::format_iso8601_utc(base + epoch_seconds);
    let settle_at = cairn::time::format_iso8601_utc(
        base + (2 + cairn::partition::finality_epochs() as i64) * epoch_seconds,
    );
    let deadline = cairn::time::format_iso8601_utc(base + 8 * epoch_seconds);
    let example = fs::read_to_string("examples/collatz/objective.json").expect("objective");
    let mut objective = Objective::from_value(&Value::from_json(&example).expect("JSON"))
        .expect("example objective");
    objective.deadline = Some(deadline);
    let objective = objective
        .assigned_to(contributor.submitter_id())
        .expect("assignee")
        .funded_by(&funder);
    node.post_objective(&objective, TS).expect("post");
    let artifact =
        Value::from_json(&fs::read_to_string("examples/collatz/artifact.json").expect("artifact"))
            .expect("JSON");
    let nonce = "first";
    let commitment = Commitment::new(
        objective.id(),
        contributor.submitter_id(),
        commitment_hash(
            &objective.id(),
            &contributor.submitter_id(),
            &artifact,
            nonce,
        ),
        TS,
    )
    .signed_with(&contributor);
    node.commit(&commitment, TS).expect("commit");
    let claim = Claim::new(
        objective.id(),
        contributor.submitter_id(),
        artifact,
        nonce,
        &reveal_at,
        vec![],
    )
    .expect("claim")
    .signed_with(&contributor);
    let outcome = node.reveal(&claim, &reveal_at).expect("reveal");
    assert!(outcome.is_pending(), "{outcome:?}");
    let trusted = std::collections::BTreeSet::from([funder.submitter_id()]);
    let reveal_epoch = cairn::partition::epoch_of(
        (base + epoch_seconds) as u64,
        cairn::partition::EPOCH_SECONDS,
    );
    assert!(
        observations_from_node(&node, &contributor.submitter_id(), &trusted, reveal_epoch)
            .expect("pending score")
            .is_empty(),
        "an accepted verdict cannot buy delivery credit before settlement"
    );
    node.settle_at(&settle_at).expect("settle");
    let rows = observations_from_node(
        &node,
        &contributor.submitter_id(),
        &trusted,
        reveal_epoch + cairn::partition::finality_epochs() + 1,
    )
    .expect("settled score");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].outcome, AssignmentOutcome::Verified);
    assert_eq!(rows[0].verified_gain, objective.reward);
    assert_eq!(rows[0].epoch, reveal_epoch);
    assert!(node.audit(false).is_empty(), "finished log must audit");
    drop(node);
    fs::remove_dir_all(dir).expect("remove scratch directory");
}
