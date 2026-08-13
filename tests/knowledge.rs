//! The knowledge layer, end to end through a real node.
//!
//! `src/knowledge.rs` tests the arithmetic against hand-built facts. This file
//! asks the question those cannot: with a live node, a funded objective, a
//! pinned verifier and real commit–reveal, does adding relations change
//! anything it must not?
//!
//! The properties, in the order they are checked:
//!
//! 1. **A relation moves no money.** Two logs identical but for a `refutes`
//!    edge settle the same amounts and produce the same citation flow. This is
//!    the one that matters: if declaring "X is wrong" could shift a payout,
//!    refutation becomes a way to bill X, and a knowledge graph becomes an
//!    attack surface on the ledger.
//! 2. **A relation moves no frontier.** Superseding a claim in prose does not
//!    supersede it in the ratchet, which answers only to the pinned evaluator.
//! 3. **A relation names a claim that exists**, and a reveal that invents one
//!    is refused.
//! 4. **A relation may name a rejected claim.** Refuting something the verifier
//!    threw out is exactly what a useful negative result looks like, and the
//!    admission rule must not get in the way of it.
//! 5. **The signature covers relations**, so nobody can staple a retraction to
//!    somebody else's signed work.
//! 6. **The log round-trips them**, and the standing an auditor computes from a
//!    re-read log is the standing the writer saw.
//!
//! Everything goes through the public API, because that is the surface a third
//! party re-deriving this history actually has.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use proofwork::attribution::{payouts_over, FlowParams};
use proofwork::canonical::Value;
use proofwork::knowledge::{ConfidencePolicy, Standing};
use proofwork::ledger::Ledger;
use proofwork::node::{Node, Outcome, RuleViolation};
use proofwork::partition::{epoch_seconds, finality_epochs};
use proofwork::records::{commitment_hash, Claim, ClaimRelation, Commitment, Objective, Relation};
use proofwork::time::format_iso8601_utc;
use proofwork::verifiers::{Status, VerifierRegistry};

const TS: &str = "2026-07-28T00:00:00+00:00";
const BASE: i64 = 1_785_196_800;

/// Accepts `{"n": 42}` and nothing else, so a "wrong" artifact is genuinely
/// rejected by the pinned checker rather than by anyone's say-so.
const CHECKER: &str = r#"
def check(artifact):
    return artifact.get("n") == 42
"#;

const EVALUATOR: &str = r#"
def score(artifact):
    return artifact.get("score", 0)
"#;

fn epoch() -> i64 {
    epoch_seconds() as i64
}

fn finality() -> i64 {
    finality_epochs() as i64
}

fn stamp(offset: i64) -> String {
    format_iso8601_utc(BASE + offset)
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> TempDir {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "proofwork-knowledge-{label}-{}-{nanos}-{n}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("scratch directory is creatable");
        TempDir { path }
    }

    fn file(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    proofwork::hex::encode(&hasher.finalize())
}

fn write_pinned(dir: &TempDir, name: &str, source: &str) -> String {
    fs::write(dir.file(name), source).expect("pinned source is writable");
    sha256_hex(source.as_bytes())
}

fn node_at(dir: &TempDir) -> Node {
    let ledger = Ledger::open(dir.file("log.jsonl")).expect("a missing file is an empty log");
    Node::with_registry(ledger, VerifierRegistry::new(&dir.path))
}

/// A certificate objective worth 1000 whose checker accepts exactly `{"n": 42}`.
fn certificate_env(label: &str) -> (TempDir, Node, Objective) {
    let dir = TempDir::new(label);
    let sha = write_pinned(&dir, "c.py", CHECKER);
    let mut node = node_at(&dir);
    let objective = Objective::new(
        "G",
        "find n = 42",
        Value::object([
            ("kind", Value::string("certificate")),
            ("checker", Value::string("c.py")),
            ("checker_sha256", Value::string(sha.as_str())),
            ("entrypoint", Value::string("check")),
        ]),
        1000,
        "treasury",
        TS,
        None,
        None,
    )
    .expect("valid objective");
    node.post_objective(&objective, TS).expect("post");
    (dir, node, objective)
}

fn ratchet_env(label: &str) -> (TempDir, Node, Objective) {
    let dir = TempDir::new(label);
    let sha = write_pinned(&dir, "e.py", EVALUATOR);
    let mut node = node_at(&dir);
    let objective = Objective::new(
        "G",
        "maximize the score",
        Value::object([
            ("kind", Value::string("evaluator")),
            ("evaluator", Value::string("e.py")),
            ("evaluator_sha256", Value::string(sha.as_str())),
            ("entrypoint", Value::string("score")),
            ("threshold", Value::Int(0)),
            ("direction", Value::string("maximize")),
        ]),
        1_000_000,
        "treasury",
        TS,
        None,
        Some(Value::object([
            ("baseline", Value::Int(0)),
            ("target", Value::Int(100)),
            ("reward", Value::Int(1_000_000)),
            ("direction", Value::string("maximize")),
        ])),
    )
    .expect("valid objective");
    node.post_objective(&objective, TS).expect("post");
    (dir, node, objective)
}

fn n(value: i128) -> Value {
    Value::object([("n", Value::Int(value))])
}

fn scored(value: i128) -> Value {
    Value::object([("score", Value::Int(value))])
}

/// Commit, reveal (optionally carrying relations), and close the batch.
#[allow(clippy::too_many_arguments)]
fn submit(
    node: &mut Node,
    objective: &Objective,
    submitter: &str,
    artifact: Value,
    nonce: &str,
    cites: Vec<String>,
    relations: Vec<ClaimRelation>,
) -> Result<Outcome, RuleViolation> {
    let step = node.ledger().len() as i64 * (3 + finality()) * epoch();
    let hash = commitment_hash(&objective.id(), submitter, &artifact, nonce);
    let at = stamp(step);
    node.commit(
        &Commitment::new(objective.id(), submitter, hash, at.as_str()),
        &at,
    )
    .expect("commit");

    let claim = Claim::new(objective.id(), submitter, artifact, nonce, TS, cites)
        .expect("valid claim")
        .relating(relations)
        .expect("valid claim");

    let outcome = node.reveal(&claim, &stamp(step + epoch()))?;
    if !outcome.is_pending() {
        return Ok(outcome);
    }
    let settled = node.settle_at(&stamp(step + (2 + finality()) * epoch()))?;
    Ok(settled
        .into_iter()
        .find(|candidate| candidate.claim_id == outcome.claim_id)
        .unwrap_or(outcome))
}

/// Every settled `(claim_id, reward)` in a log, in log order.
fn settlements(node: &Node) -> Vec<(String, u64)> {
    let mut out = Vec::new();
    for claim_id in node.all_claims().keys() {
        if let Some(reward) = node.settlement_for_claim(claim_id) {
            out.push((claim_id.clone(), reward));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// 1. A relation moves no money
// ---------------------------------------------------------------------------

#[test]
fn refuting_a_claim_pays_the_refuter_nothing_extra_and_costs_the_target_nothing() {
    // Two runs of the identical script. The only difference is that in the
    // second, the follow-up claim declares `refutes` on the first.
    //
    // A progressive objective, because a one-shot certificate bounty closes on
    // its first accept and there would be no second submission to compare.
    let run = |label: &str, refute: bool| -> (Vec<(String, u64)>, BTreeMap<String, u64>) {
        let (_dir, mut node, objective) = ratchet_env(label);

        let first = submit(
            &mut node,
            &objective,
            "alice",
            scored(60),
            "n1",
            vec![],
            vec![],
        )
        .expect("alice submits");
        assert_eq!(first.verdict.status, Status::Accept);
        let first_id = first.claim_id.clone();

        let relations = if refute {
            vec![ClaimRelation::new(Relation::Refutes, &first_id)]
        } else {
            vec![]
        };
        // The frontier citation is identical in both runs, so any difference in
        // the payouts is the relation's doing and nothing else.
        submit(
            &mut node,
            &objective,
            "bob",
            scored(80),
            "n2",
            vec![first_id.clone()],
            relations,
        )
        .expect("bob submits");

        let settled = settlements(&node);
        let flow = payouts_over(&settled, &node.all_claims(), &FlowParams::default())
            .expect("citation flow");
        (settled, flow)
    };

    let (plain_settled, plain_flow) = run("money-plain", false);
    let (refuted_settled, refuted_flow) = run("money-refuted", true);

    // The claim ids differ between runs -- a relation is inside the id, which
    // is the point of putting it in the signing payload -- so compare the
    // amounts and the per-submitter totals rather than the ids.
    let amounts = |settled: &[(String, u64)]| -> Vec<u64> {
        let mut v: Vec<u64> = settled.iter().map(|(_, reward)| *reward).collect();
        v.sort_unstable();
        v
    };
    assert_eq!(
        amounts(&plain_settled),
        amounts(&refuted_settled),
        "declaring a refutation changed what settled"
    );
    let total = |flow: &BTreeMap<String, u64>| -> u64 { flow.values().copied().sum() };
    assert_eq!(
        total(&plain_flow),
        total(&refuted_flow),
        "declaring a refutation changed citation flow"
    );
    assert_eq!(
        plain_flow.get("alice").copied().unwrap_or(0),
        refuted_flow.get("alice").copied().unwrap_or(0),
        "being refuted cost alice money"
    );
}

#[test]
fn a_relation_is_not_a_citation_and_creates_no_flow_edge() {
    let (_dir, mut node, objective) = certificate_env("no-flow");
    // Alice's artifact fails the pinned checker, so the bounty stays open and
    // there is something in the log worth speaking about that citations may not
    // point at.
    let first =
        submit(&mut node, &objective, "alice", n(41), "n1", vec![], vec![]).expect("alice submits");
    assert_eq!(first.verdict.status, Status::Reject);
    let first_id = first.claim_id.clone();

    // Bob relates to alice's claim and cites nothing.
    submit(
        &mut node,
        &objective,
        "bob",
        n(42),
        "n2",
        vec![],
        vec![ClaimRelation::new(Relation::Refutes, &first_id)],
    )
    .expect("bob submits");

    let claims = node.all_claims();
    let bob = claims
        .values()
        .find(|claim| claim.submitter == "bob")
        .expect("bob's claim is in the log");
    assert!(
        bob.cites.is_empty(),
        "a relation leaked into the paying edge"
    );
    assert_eq!(bob.relations.len(), 1);
}

// ---------------------------------------------------------------------------
// 2. A relation moves no frontier
// ---------------------------------------------------------------------------

#[test]
fn declaring_supersedes_does_not_move_the_frontier() {
    let (_dir, mut node, objective) = ratchet_env("frontier");
    let leader = submit(
        &mut node,
        &objective,
        "alice",
        scored(60),
        "n1",
        vec![],
        vec![],
    )
    .expect("alice sets the frontier");
    let leader_id = leader.claim_id.clone();

    let before = node
        .frontier_of(&objective.id())
        .expect("a frontier exists");

    // A worse score that *claims* to supersede the leader. The ratchet answers
    // to the pinned evaluator and to nothing anybody writes in a record.
    submit(
        &mut node,
        &objective,
        "mallory",
        scored(10),
        "n2",
        vec![leader_id.clone()],
        vec![ClaimRelation::new(Relation::Supersedes, &leader_id)],
    )
    .expect("mallory submits");

    let after = node
        .frontier_of(&objective.id())
        .expect("a frontier exists");
    assert_eq!(
        before.score, after.score,
        "a declared supersession moved the frontier"
    );

    // And the knowledge view does report it -- the assertion is real, it just
    // has no purchase on the money.
    let state = node
        .knowledge_state(&leader_id, &ConfidencePolicy::default(), 0)
        .expect("the leader is in the log");
    assert_eq!(state.standing, Standing::Superseded);
}

// ---------------------------------------------------------------------------
// 3 & 4. What a relation may name
// ---------------------------------------------------------------------------

#[test]
fn a_relation_naming_a_claim_that_does_not_exist_is_refused() {
    let (_dir, mut node, objective) = certificate_env("invented");
    let invented = format!("sha256:{}", "ab".repeat(32));
    let error = submit(
        &mut node,
        &objective,
        "mallory",
        n(42),
        "n1",
        vec![],
        vec![ClaimRelation::new(Relation::Refutes, &invented)],
    )
    .expect_err("a relation cannot name a claim nobody has seen");
    assert!(
        matches!(&error, RuleViolation::UnknownRelationTarget { claim_id } if claim_id == &invented),
        "{error}"
    );
}

#[test]
fn a_relation_may_name_a_claim_the_verifier_rejected() {
    let (_dir, mut node, objective) = certificate_env("rejected-target");

    // A claim the pinned checker throws out. It is in the log, it settled
    // nothing, and it is not an accepted claim.
    let wrong = submit(&mut node, &objective, "alice", n(41), "n1", vec![], vec![])
        .expect("the reveal is admitted even though it fails");
    assert_eq!(wrong.verdict.status, Status::Reject);
    let wrong_id = wrong.claim_id.clone();

    // Citing it is refused -- citations must point at accepted claims...
    let citing = submit(
        &mut node,
        &objective,
        "bob",
        n(42),
        "n2",
        vec![wrong_id.clone()],
        vec![],
    )
    .expect_err("a rejected claim is not citable");
    assert!(
        matches!(&citing, RuleViolation::UnknownCitation { .. }),
        "{citing}"
    );

    // ...but relating to it is exactly what a negative result is for.
    let good = submit(
        &mut node,
        &objective,
        "bob",
        n(42),
        "n3",
        vec![],
        vec![ClaimRelation::new(Relation::Refutes, &wrong_id)],
    )
    .expect("refuting a rejected claim is admissible");
    assert_eq!(good.verdict.status, Status::Accept);

    // The target was already refuted by the machine, which outranks anything
    // said about it either way.
    let state = node
        .knowledge_state(&wrong_id, &ConfidencePolicy::default(), 0)
        .expect("the rejected claim is in the log");
    assert_eq!(state.standing, Standing::Refuted);
}

// ---------------------------------------------------------------------------
// 5. The signature covers relations
// ---------------------------------------------------------------------------

#[test]
fn a_retraction_cannot_be_stapled_to_somebody_elses_signed_claim() {
    use proofwork::crypto::identity::Identity;
    use rand_core::OsRng;

    let identity = Identity::generate(&mut OsRng);
    let honest = Claim::new("sha256:obj", "placeholder", n(42), "nonce", TS, vec![])
        .expect("valid claim")
        .signed_with(&identity);
    honest
        .verify_signature()
        .expect("the author's own signature verifies");

    // An attacker appends a retraction of somebody else's claim and leaves the
    // signature alone.
    let mut tampered = honest.clone();
    tampered.relations = vec![ClaimRelation::new(
        Relation::Retracts,
        format!("sha256:{}", "cd".repeat(32)),
    )];
    assert!(
        tampered.verify_signature().is_err(),
        "relations are outside the signature -- anyone could withdraw anyone's work"
    );
    assert_ne!(
        honest.id(),
        tampered.id(),
        "a relation must be inside the claim's identity"
    );
}

// ---------------------------------------------------------------------------
// 6. Round-trip
// ---------------------------------------------------------------------------

#[test]
fn relations_survive_the_log_and_an_auditor_computes_the_same_standing() {
    let dir = TempDir::new("roundtrip");
    let sha = write_pinned(&dir, "e.py", EVALUATOR);
    let objective = Objective::new(
        "G",
        "maximize the score",
        Value::object([
            ("kind", Value::string("evaluator")),
            ("evaluator", Value::string("e.py")),
            ("evaluator_sha256", Value::string(sha.as_str())),
            ("entrypoint", Value::string("score")),
            ("threshold", Value::Int(0)),
            ("direction", Value::string("maximize")),
        ]),
        1_000_000,
        "treasury",
        TS,
        None,
        Some(Value::object([
            ("baseline", Value::Int(0)),
            ("target", Value::Int(100)),
            ("reward", Value::Int(1_000_000)),
            ("direction", Value::string("maximize")),
        ])),
    )
    .expect("valid objective");

    let (first_id, written) = {
        let mut node = node_at(&dir);
        node.post_objective(&objective, TS).expect("post");
        let first = submit(
            &mut node,
            &objective,
            "alice",
            scored(60),
            "n1",
            vec![],
            vec![],
        )
        .expect("alice submits");
        let first_id = first.claim_id.clone();
        // A negative score misses the threshold, so bob's own claim is
        // rejected -- and a rejected claim's assertions are not heard.
        let bob = submit(
            &mut node,
            &objective,
            "bob",
            scored(-5),
            "n2",
            vec![first_id.clone()],
            vec![ClaimRelation::new(Relation::FailsToReplicate, &first_id)],
        )
        .expect("bob submits");
        assert_eq!(bob.verdict.status, Status::Reject);
        let written = node
            .knowledge_state(&first_id, &ConfidencePolicy::default(), 0)
            .expect("state");
        (first_id, written)
    };

    // A second node opens the same file with no memory of any of it.
    let reopened = node_at(&dir);
    let claims = reopened.all_claims();
    let bob = claims
        .values()
        .find(|claim| claim.submitter == "bob")
        .expect("bob's claim survived the round trip");
    assert_eq!(bob.relations.len(), 1);
    assert_eq!(bob.relations[0].kind, Relation::FailsToReplicate);
    assert_eq!(bob.relations[0].target, first_id);

    let read_back = reopened
        .knowledge_state(&first_id, &ConfidencePolicy::default(), 0)
        .expect("state");
    assert_eq!(written, read_back);
    // Bob's claim missed the threshold, so his assertion is recorded and not
    // heard. Contesting costs a verified result, and he does not have one.
    assert_eq!(read_back.standing, Standing::Accepted);
    assert_eq!(read_back.disputes, 0);
    assert_eq!(read_back.assertions.len(), 1);
    assert!(!read_back.assertions[0].grounded);
}

#[test]
fn a_contest_from_a_verified_peer_is_heard() {
    // The same shape as above, except the contesting claim passes its own
    // verifier -- which is the price of being heard.
    let (_dir, mut node, objective) = ratchet_env("heard");
    let first = submit(
        &mut node,
        &objective,
        "alice",
        scored(60),
        "n1",
        vec![],
        vec![],
    )
    .expect("alice submits");
    let first_id = first.claim_id.clone();

    // Bob clears the threshold, so his claim is accepted and his assertion
    // counts. He also cites alice, because the frontier rule requires it --
    // which is the case worth pinning: the paying edge and the semantic edge
    // point at the same claim and still do different things.
    let bob = submit(
        &mut node,
        &objective,
        "bob",
        scored(80),
        "n2",
        vec![first_id.clone()],
        vec![ClaimRelation::new(Relation::ConflictsWith, &first_id)],
    )
    .expect("bob submits");
    assert_eq!(bob.verdict.status, Status::Accept);

    let state = node
        .knowledge_state(&first_id, &ConfidencePolicy::default(), 0)
        .expect("state");
    assert_eq!(state.standing, Standing::Contested);
    assert_eq!(state.disputes, 1);
    assert!(state.assertions.iter().all(|a| a.grounded));
    // Verified, contested, and still verified: `was_verified` must survive a
    // dispute or a reader cannot tell "the machine passed it, someone objects"
    // from "the machine failed it".
    assert!(state.standing.was_verified());
}
