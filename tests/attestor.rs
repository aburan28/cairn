//! The validator loop around a `Node`: it attests what *this* node's
//! verifier finds, once per claim, never a verdict that does not settle, and
//! stops when the bond cannot be covered. `scripts/validator-demo.sh` closes
//! the same loop around the binary across real epochs.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use cairn::attestor::Attestor;
use cairn::canonical::Value;
use cairn::crypto::identity::Identity;
use cairn::ledger::Ledger;
use cairn::node::{Node, VERIFICATION_BOND};
use cairn::records::{Claim, Commitment, Issuance, Objective};
use cairn::verifiers::{Status, VerifierRegistry};

const GENESIS: &str = "2026-07-28T00:00:00+00:00";
const COMMIT_AT: &str = "2026-07-28T00:10:00+00:00";
const REVEAL_AT: &str = "2026-07-28T00:30:00+00:00";
const ATTEST_AT: &str = "2026-07-28T00:40:00+00:00";

const CHECKER: &str = r#"
def check(artifact):
    return artifact.get("n", 0) % 2 == 0
"#;

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> TempDir {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "cairn-attestor-{label}-{unique}-{}",
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).expect("temp dir is creatable");
        TempDir { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn have_python() -> bool {
    std::process::Command::new("python3")
        .arg("--version")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

fn sha(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    cairn::hex::encode(&hasher.finalize())
}

fn identity(seed: u8) -> Identity {
    Identity::from_secret_bytes([seed; 32])
}

struct Fixture {
    _dir: TempDir,
    node: Node,
    objective_id: String,
}

/// A funded log with one even-numbers objective. `funded` names identities
/// given units in the opening prefix, so a bond costs something.
fn fixture(label: &str, funded: &[(&Identity, u64)]) -> Fixture {
    let dir = TempDir::new(label);
    fs::write(dir.path.join("c.py"), CHECKER).expect("writable");
    let ledger = Ledger::open(dir.path.join("log.jsonl")).expect("an empty log");
    let mut node = Node::with_registry(ledger, VerifierRegistry::new(&dir.path));
    let treasury = identity(0);
    node.post_issuance(
        &Issuance::new(treasury.submitter_id(), 1_000_000, GENESIS),
        GENESIS,
    )
    .expect("genesis issuance");
    for (who, units) in funded {
        node.post_issuance(&Issuance::new(who.submitter_id(), *units, GENESIS), GENESIS)
            .expect("funded");
    }
    let verifier = Value::object([
        ("kind", Value::string("certificate")),
        ("checker", Value::string("c.py")),
        ("checker_sha256", Value::string(sha(CHECKER))),
        ("entrypoint", Value::string("check")),
    ]);
    let objective = Objective::new(
        "G",
        "attestor fixture: even numbers only",
        verifier,
        1_000,
        treasury.submitter_id(),
        GENESIS,
        None,
        None,
    )
    .expect("valid objective")
    .funded_by(&treasury);
    node.post_objective(&objective, GENESIS).expect("post");
    Fixture {
        _dir: dir,
        objective_id: objective.id(),
        node,
    }
}

fn claim(fixture: &mut Fixture, who: &str, n: i128, nonce: &str) -> String {
    let objective_id = fixture.objective_id.clone();
    let artifact = Value::object([("n", Value::Int(n))]);
    let hash = cairn::records::commitment_hash(&objective_id, who, &artifact, nonce);
    let commitment = Commitment::new(&objective_id, who, hash, COMMIT_AT);
    fixture.node.commit(&commitment, COMMIT_AT).expect("commit");
    let record = Claim::new(&objective_id, who, artifact, nonce, REVEAL_AT, Vec::new())
        .expect("valid claim");
    fixture.node.reveal(&record, REVEAL_AT).expect("reveal");
    record.id()
}

/// A claim against an objective nothing here can run (Lean).
fn unrunnable_claim(fixture: &mut Fixture, who: &str, nonce: &str) -> String {
    let treasury = identity(0);
    let objective = Objective::new(
        "G",
        "attestor fixture: nothing here can run this",
        Value::object([
            ("kind", Value::string("lean")),
            ("project_root", Value::string(".")),
            ("entry", Value::string("Main.lean")),
        ]),
        1_000,
        treasury.submitter_id(),
        GENESIS,
        None,
        None,
    )
    .expect("valid objective")
    .funded_by(&treasury);
    fixture
        .node
        .post_objective(&objective, GENESIS)
        .expect("post");
    let id = objective.id();
    let artifact = Value::object([("theorem", Value::string("trivial"))]);
    let hash = cairn::records::commitment_hash(&id, who, &artifact, nonce);
    fixture
        .node
        .commit(&Commitment::new(&id, who, hash, COMMIT_AT), COMMIT_AT)
        .expect("commit");
    let record = Claim::new(&id, who, artifact, nonce, REVEAL_AT, Vec::new()).expect("valid");
    fixture.node.reveal(&record, REVEAL_AT).expect("reveal");
    record.id()
}

#[test]
fn the_loop_attests_what_it_found_once_per_claim_and_never_what_does_not_settle() {
    if !have_python() {
        eprintln!("skipping: no python3");
        return;
    }
    let validator = identity(5);
    let mut fx = fixture("once", &[(&validator, 1_000_000)]);
    let even = claim(&mut fx, "alice", 8, "a");
    let odd = claim(&mut fx, "bob", 7, "b");
    let lean = unrunnable_claim(&mut fx, "carol", "c");

    let mut attestor = Attestor::new(validator.clone());
    let candidates = attestor.candidates(&fx.node);
    assert_eq!(candidates.len(), 3, "{candidates:?}");

    let (tally, outcomes) = attestor.tick(&mut fx.node, ATTEST_AT);
    assert_eq!(tally.considered, 3, "{tally}");
    assert_eq!(tally.posted, 2, "{tally}: {outcomes:?}");
    assert_eq!(tally.unavailable, 1);
    assert_eq!(tally.disagreements, 0);
    assert!(!tally.stopped_for_bond);

    let by_claim: std::collections::BTreeMap<&str, &cairn::attestor::Outcome> = outcomes
        .iter()
        .map(|outcome| (outcome.claim_id.as_str(), outcome))
        .collect();
    assert_eq!(by_claim[even.as_str()].found, Status::Accept);
    assert_eq!(by_claim[even.as_str()].recorded, Some(Status::Accept));
    assert!(by_claim[even.as_str()].posted());
    assert_eq!(by_claim[odd.as_str()].found, Status::Reject);
    assert!(by_claim[odd.as_str()].posted());
    // Unavailable (no Lean here) or InvalidSpec (a stub project): either
    // way it does not settle, and that is the property the loop keys on.
    assert!(
        !by_claim[lean.as_str()].found.settles(),
        "{:?}",
        by_claim[lean.as_str()]
    );
    assert!(!by_claim[lean.as_str()].posted());

    let posted = fx.node.attestations();
    assert_eq!(posted.len(), 2);
    for attestation in posted.values() {
        assert_eq!(attestation.attestor, validator.submitter_id());
        assert_eq!(attestation.created_at, ATTEST_AT);
    }
    // Nothing left but the unrunnable one, and it waits out its cooldown.
    assert!(attestor.candidates(&fx.node).is_empty());
    let (again, _) = attestor.tick(&mut fx.node, ATTEST_AT);
    assert_eq!(again.considered, 0, "{again}");
    attestor.retry_after_ticks = 1;
    assert_eq!(attestor.candidates(&fx.node), vec![lean.clone()]);
    let (retry, _) = attestor.tick(&mut fx.node, ATTEST_AT);
    assert_eq!(retry.unavailable, 1);
    assert_eq!(
        fx.node.attestations().len(),
        2,
        "unavailable is never attested"
    );

    // The audit agrees with every attestation this node posted, because each
    // was what the pinned verifier said.
    let problems = fx.node.audit(true);
    assert!(problems.is_empty(), "audit found problems: {problems:?}");
}

#[test]
fn the_loop_stops_when_the_bond_cannot_be_covered() {
    if !have_python() {
        eprintln!("skipping: no python3");
        return;
    }
    // Enough for exactly one bond.
    let validator = identity(6);
    let mut fx = fixture("broke", &[(&validator, VERIFICATION_BOND)]);
    claim(&mut fx, "alice", 2, "a");
    claim(&mut fx, "bob", 4, "b");
    claim(&mut fx, "carol", 6, "c");

    let mut attestor = Attestor::new(validator);
    let (tally, outcomes) = attestor.tick(&mut fx.node, ATTEST_AT);
    assert_eq!(tally.posted, 1, "{tally}: {outcomes:?}");
    assert_eq!(tally.refused, 1, "one refusal, then it stops: {tally}");
    assert!(tally.stopped_for_bond, "{tally}");
    assert_eq!(fx.node.attestations().len(), 1);
    let refused = outcomes
        .iter()
        .find(|o| o.refusal.is_some())
        .expect("a refusal");
    assert!(
        refused
            .refusal
            .as_deref()
            .unwrap()
            .contains("not already committed"),
        "{refused:?}"
    );
    // The refused claim is not written off: units may arrive.
    assert_eq!(attestor.candidates(&fx.node).len(), 2);
}

#[test]
fn newest_claims_are_verified_first_and_the_limit_bounds_a_pass() {
    if !have_python() {
        eprintln!("skipping: no python3");
        return;
    }
    let validator = identity(7);
    let mut fx = fixture("limit", &[(&validator, 1_000_000)]);
    let first = claim(&mut fx, "alice", 2, "a");
    let second = claim(&mut fx, "bob", 4, "b");
    let mut attestor = Attestor::new(validator);
    attestor.limit_per_tick = 1;
    // Same created_at, so the tie breaks on id: deterministic, whichever it is.
    let order = attestor.candidates(&fx.node);
    assert_eq!(order.len(), 2);
    let (tally, outcomes) = attestor.tick(&mut fx.node, ATTEST_AT);
    assert_eq!(tally.considered, 1, "{tally}");
    assert_eq!(outcomes[0].claim_id, order[0]);
    let (tally, _) = attestor.tick(&mut fx.node, ATTEST_AT);
    assert_eq!(tally.posted, 1);
    assert_eq!(fx.node.attestations().len(), 2);
    assert!([first, second].iter().all(|id| fx
        .node
        .attestations()
        .values()
        .any(|a| &a.claim_id == id)));
}
