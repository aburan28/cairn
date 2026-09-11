//! End-to-end behaviour of a piecework objective: a coordinator posts a
//! divided problem, peers pick units up from the partition, and every novel
//! accepted unit is paid from the pool until the pool is empty.
//!
//! What these tests defend, in the order the file walks them:
//!
//! 1. **A unit pays once.** The first paid claim that answers a unit takes
//!    the unit price; a second answer to the same unit verifies fine and
//!    mints zero, whether it arrives in a later epoch or in the same batch.
//! 2. **Only a paid claim consumes a unit.** A rejected answer and an answer
//!    that arrived after the pool ran dry leave the unit open. Anything else
//!    would let a griefer close units with wrong answers for free.
//! 3. **The pool is the only limit.** The last unit is paid whatever is
//!    left, then the objective is closed and further units earn nothing --
//!    but commitments are still admitted, because a piecework objective is
//!    open until the pool is empty and not before.
//! 4. **A top-up is the same job.** A second objective with the same
//!    verifier and the same piecework block shares novelty history with the
//!    first: funding a job twice must not pay every unit twice.
//! 5. **The audit re-derives it all.** A unit paid twice is reported, and an
//!    honest log is reported clean.
//! 6. **Shape rules hold at the boundary.** A ratchet and a piecework block
//!    cannot share an objective, a malformed block is refused, and a unit
//!    price larger than the pool is refused before it is posted.
//!
//! Everything goes through the public API, for the same reason `rules.rs`
//! does: this is exactly the surface a peer has when it re-derives the
//! network's history from a copy of the log.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use cairn::canonical::Value;
use cairn::ledger::Ledger;
use cairn::node::{Node, Outcome, RuleViolation};
use cairn::partition::epoch_seconds;
use cairn::records::{commitment_hash, Claim, Commitment, Objective, RecordError};
use cairn::time::format_iso8601_utc;
use cairn::verifiers::{Status, VerifierRegistry};

/// Frozen timestamp: nothing here depends on wall-clock time.
const TS: &str = "2026-07-28T00:00:00+00:00";

/// [`TS`] as seconds since the Unix epoch.
const BASE: i64 = 1_785_196_800;

const NO_LEAN: &str = "cairn-piecework-definitely-no-such-lean-binary";

/// A checker that accepts any artifact whose `n` is a small non-negative
/// integer, whatever else the artifact carries. That is what a unit checker
/// looks like from the network's side: it validates one answer, and knows
/// nothing about which unit the answer belongs to.
const UNIT_CHECKER: &str = r#"
def check(artifact):
    n = artifact.get("n")
    return isinstance(n, int) and 0 <= n < 1000
"#;

const EVALUATOR: &str = r#"
def score(artifact):
    return artifact.get("score", 0)
"#;

fn epoch() -> i64 {
    epoch_seconds() as i64
}

fn finality() -> i64 {
    cairn::partition::finality_epochs() as i64
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
            "cairn-piecework-{label}-{}-{nanos}-{n}",
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
    cairn::hex::encode(&hasher.finalize())
}

fn write_pinned(dir: &TempDir, name: &str, source: &str) -> String {
    fs::write(dir.file(name), source).expect("pinned source is writable");
    sha256_hex(source.as_bytes())
}

fn node_at(dir: &TempDir) -> Node {
    let ledger = Ledger::open(dir.file("log.jsonl")).expect("a missing file is an empty log");
    Node::with_registry(
        ledger,
        VerifierRegistry::new(&dir.path).with_lean_binary(NO_LEAN),
    )
}

fn certificate_verifier(checker: &str, sha: &str) -> Value {
    Value::object([
        ("kind", Value::string("certificate")),
        ("checker", Value::string(checker)),
        ("checker_sha256", Value::string(sha)),
        ("entrypoint", Value::string("check")),
    ])
}

/// A piecework block. `key` of `None` is digest mode: the artifact itself
/// names the unit. `Some("unit")` is key mode: the `unit` field does.
fn piecework_block(unit_price: i128, units: Option<i128>, key: Option<&str>) -> Value {
    let mut fields = vec![("unit_price", Value::Int(unit_price))];
    if let Some(units) = units {
        fields.push(("units", Value::Int(units)));
    }
    if let Some(key) = key {
        fields.push(("key", Value::string(key)));
    }
    Value::object(fields)
}

/// Build (but do not post) a piecework objective over the pinned unit
/// checker. `statement` is what distinguishes a top-up from its original.
fn piecework_objective(sha: &str, statement: &str, reward: u64, block: Value) -> Objective {
    Objective::new(
        "G",
        statement,
        certificate_verifier("c.py", sha),
        reward,
        "treasury",
        TS,
        None,
        None,
    )
    .expect("valid objective")
    .with_piecework(block)
    .expect("valid piecework block")
}

/// A posted piecework objective of `reward` with the given block.
fn piecework_env(label: &str, reward: u64, block: Value) -> (TempDir, Node, Objective) {
    let dir = TempDir::new(label);
    let sha = write_pinned(&dir, "c.py", UNIT_CHECKER);
    let mut node = node_at(&dir);
    let objective = piecework_objective(&sha, "answer the units", reward, block);
    node.post_objective(&objective, TS).expect("post");
    (dir, node, objective)
}

fn n(value: i128) -> Value {
    Value::object([("n", Value::Int(value))])
}

fn unit(unit: i128, value: i128) -> Value {
    Value::object([("unit", Value::Int(unit)), ("n", Value::Int(value))])
}

/// Where the next submission's epoch starts: stepped off the ledger length so
/// successive submissions occupy successive, not-yet-settled epochs.
fn next_step(node: &Node) -> i64 {
    node.ledger().len() as i64 * (3 + finality()) * epoch()
}

fn commit_at(node: &mut Node, objective: &Objective, who: &str, artifact: &Value, ts: &str) {
    let hash = commitment_hash(&objective.id(), who, artifact, who);
    node.commit(&Commitment::new(objective.id(), who, hash, ts), ts)
        .expect("commit");
}

fn reveal_at(
    node: &mut Node,
    objective: &Objective,
    who: &str,
    artifact: Value,
    ts: &str,
) -> Result<Outcome, RuleViolation> {
    let claim = Claim::new(objective.id(), who, artifact, who, ts, vec![])
        .expect("structurally valid claim");
    node.reveal(&claim, ts)
}

/// Commit, reveal, close the batch; return the claim's final outcome. The
/// nonce is the submitter's name, which is fine here: nothing in this file
/// tests nonce secrecy.
fn submit(node: &mut Node, objective: &Objective, who: &str, artifact: Value) -> Outcome {
    let step = next_step(node);
    commit_at(node, objective, who, &artifact, &stamp(step));
    let outcome =
        reveal_at(node, objective, who, artifact, &stamp(step + epoch())).expect("reveal");
    if !outcome.is_pending() {
        return outcome;
    }
    let settled = node
        .settle_at(&stamp(step + (2 + finality()) * epoch()))
        .expect("settle");
    settled
        .into_iter()
        .find(|candidate| candidate.claim_id == outcome.claim_id)
        .unwrap_or(outcome)
}

fn assert_paid(outcome: &Outcome, reward: u64) {
    assert_eq!(outcome.verdict.status, Status::Accept, "{}", outcome.note);
    assert!(
        outcome.settled,
        "expected a paid unit, got: {}",
        outcome.note
    );
    assert_eq!(outcome.reward, reward, "{}", outcome.note);
}

fn assert_unpaid(outcome: &Outcome, needle: &str) {
    assert_eq!(outcome.verdict.status, Status::Accept, "{}", outcome.note);
    assert!(
        !outcome.settled,
        "expected nothing to move, got: {}",
        outcome.note
    );
    assert_eq!(outcome.reward, 0);
    assert!(
        outcome.note.contains(needle),
        "note {:?} does not mention {needle:?}",
        outcome.note
    );
}

fn assert_clean(problems: &[String]) {
    assert!(
        problems.is_empty(),
        "expected an honest log, got {problems:?}"
    );
}

fn assert_reports(problems: &[String], needle: &str) {
    assert!(
        problems.iter().any(|p| p.contains(needle)),
        "no problem mentioned {needle:?}: {problems:?}"
    );
}

// ---------------------------------------------------------------------------
// A unit pays once
// ---------------------------------------------------------------------------

#[test]
fn each_novel_unit_pays_the_unit_price_and_leaves_the_objective_open() {
    let (_dir, mut node, objective) =
        piecework_env("novel", 350, piecework_block(100, Some(1000), None));

    assert_paid(&submit(&mut node, &objective, "alice", n(1)), 100);
    assert!(
        !node.objective_is_closed(&objective),
        "one paid unit is when there is the most left to earn"
    );
    // The commit inside `submit` is the proof that commitments stay admitted
    // after a settlement; a pass/fail objective would have refused it.
    assert_paid(&submit(&mut node, &objective, "bob", n(2)), 100);

    assert_eq!(node.paid_total(&objective.id()), 200);
    assert!(!node.objective_is_closed(&objective));
    assert_clean(&node.audit(true));
}

#[test]
fn a_duplicate_artifact_mints_nothing_in_digest_mode() {
    let (_dir, mut node, objective) =
        piecework_env("dup-digest", 1000, piecework_block(100, None, None));

    assert_paid(&submit(&mut node, &objective, "alice", n(1)), 100);
    let again = submit(&mut node, &objective, "bob", n(1));
    assert_unpaid(&again, "duplicate unit");
    assert_eq!(node.paid_total(&objective.id()), 100);
    assert_clean(&node.audit(true));
}

#[test]
fn key_mode_dedups_on_the_key_field_not_on_the_artifact() {
    let (_dir, mut node, objective) = piecework_env(
        "dup-key",
        1000,
        piecework_block(100, Some(64), Some("unit")),
    );

    assert_paid(&submit(&mut node, &objective, "alice", unit(7, 1)), 100);
    // A different artifact for the same unit is the same unit.
    assert_unpaid(
        &submit(&mut node, &objective, "bob", unit(7, 2)),
        "duplicate unit",
    );
    // A different unit is new work.
    assert_paid(&submit(&mut node, &objective, "carol", unit(8, 2)), 100);
    assert_eq!(node.paid_total(&objective.id()), 200);
    assert_clean(&node.audit(true));
}

#[test]
fn an_artifact_without_the_key_field_names_no_unit() {
    let (_dir, mut node, objective) =
        piecework_env("no-key", 1000, piecework_block(100, Some(64), Some("unit")));

    // The checker accepts it, but it does not say which unit it answers, so
    // there is nothing to pay it for.
    assert_unpaid(
        &submit(&mut node, &objective, "alice", n(1)),
        "names no unit",
    );
    assert_eq!(node.paid_total(&objective.id()), 0);
    assert_clean(&node.audit(true));
}

#[test]
fn two_answers_to_one_unit_in_the_same_batch_pay_once() {
    let (_dir, mut node, objective) = piecework_env(
        "same-batch",
        1000,
        piecework_block(100, Some(64), Some("unit")),
    );

    // Both commit in one epoch, both reveal in the next, one batch settles.
    let step = next_step(&node);
    commit_at(&mut node, &objective, "alice", &unit(3, 1), &stamp(step));
    commit_at(&mut node, &objective, "bob", &unit(3, 2), &stamp(step));
    commit_at(&mut node, &objective, "carol", &unit(4, 1), &stamp(step));
    let reveal = stamp(step + epoch());
    for (who, artifact) in [
        ("alice", unit(3, 1)),
        ("bob", unit(3, 2)),
        ("carol", unit(4, 1)),
    ] {
        let pending = reveal_at(&mut node, &objective, who, artifact, &reveal).expect("reveal");
        assert!(pending.is_pending(), "{}", pending.note);
    }
    let settled = node
        .settle_at(&stamp(step + (2 + finality()) * epoch()))
        .expect("settle");

    let paid: Vec<u64> = settled.iter().map(|o| o.reward).collect();
    assert_eq!(settled.len(), 3);
    assert_eq!(
        paid.iter().sum::<u64>(),
        200,
        "unit 3 is paid to exactly one of its two answers: {paid:?}"
    );
    assert_eq!(
        settled
            .iter()
            .filter(|o| o.note.contains("duplicate unit"))
            .count(),
        1
    );
    assert_eq!(node.paid_total(&objective.id()), 200);
    assert_clean(&node.audit(true));
}

// ---------------------------------------------------------------------------
// Only a paid claim consumes a unit
// ---------------------------------------------------------------------------

#[test]
fn a_rejected_answer_does_not_consume_the_unit() {
    let (_dir, mut node, objective) =
        piecework_env("reject", 1000, piecework_block(100, Some(64), Some("unit")));

    let wrong = submit(&mut node, &objective, "mallory", unit(7, 5000));
    assert_eq!(wrong.verdict.status, Status::Reject);
    assert!(!wrong.settled);

    // The unit is still open for the honest answer.
    assert_paid(&submit(&mut node, &objective, "alice", unit(7, 1)), 100);
    assert_clean(&node.audit(true));
}

// ---------------------------------------------------------------------------
// The pool is the only limit
// ---------------------------------------------------------------------------

#[test]
fn the_last_unit_is_paid_the_remainder_and_then_the_objective_is_closed() {
    let (_dir, mut node, objective) =
        piecework_env("exhaust", 250, piecework_block(100, None, None));

    assert_paid(&submit(&mut node, &objective, "alice", n(1)), 100);
    assert_paid(&submit(&mut node, &objective, "bob", n(2)), 100);
    assert!(!node.objective_is_closed(&objective));

    let last = submit(&mut node, &objective, "carol", n(3));
    assert_paid(&last, 50);
    assert!(last.note.contains("pool exhausted"), "{}", last.note);
    assert!(node.objective_is_closed(&objective));
    assert_eq!(node.paid_total(&objective.id()), 250);

    // Work that lands after the pool is empty verifies and earns nothing --
    // and, because it was not paid, it does not consume its unit either.
    assert_unpaid(
        &submit(&mut node, &objective, "dave", n(4)),
        "pool exhausted",
    );
    assert_eq!(node.paid_total(&objective.id()), 250);
    assert_clean(&node.audit(true));
}

// ---------------------------------------------------------------------------
// A top-up is the same job
// ---------------------------------------------------------------------------

#[test]
fn a_top_up_with_the_same_verifier_and_block_shares_novelty_history() {
    let dir = TempDir::new("top-up");
    let sha = write_pinned(&dir, "c.py", UNIT_CHECKER);
    let mut node = node_at(&dir);
    let block = piecework_block(100, Some(64), Some("unit"));
    let first = piecework_objective(&sha, "round one", 100, block.clone());
    let second = piecework_objective(&sha, "round two", 1000, block);
    assert_ne!(first.id(), second.id());
    node.post_objective(&first, TS).expect("post");
    node.post_objective(&second, TS).expect("post");

    // Unit 7 drains the first objective.
    assert_paid(&submit(&mut node, &first, "alice", unit(7, 1)), 100);
    assert!(node.objective_is_closed(&first));

    // The top-up does not pay unit 7 again, and does pay a fresh unit.
    assert_unpaid(
        &submit(&mut node, &second, "bob", unit(7, 2)),
        "duplicate unit",
    );
    assert_paid(&submit(&mut node, &second, "carol", unit(8, 1)), 100);
    assert_eq!(node.paid_total(&second.id()), 100);
    assert_clean(&node.audit(true));
}

#[test]
fn a_different_block_is_a_different_job() {
    let dir = TempDir::new("other-job");
    let sha = write_pinned(&dir, "c.py", UNIT_CHECKER);
    let mut node = node_at(&dir);
    let first = piecework_objective(
        &sha,
        "job",
        1000,
        piecework_block(100, Some(64), Some("unit")),
    );
    let other = piecework_objective(
        &sha,
        "job",
        1000,
        piecework_block(100, Some(128), Some("unit")),
    );
    node.post_objective(&first, TS).expect("post");
    node.post_objective(&other, TS).expect("post");

    assert_paid(&submit(&mut node, &first, "alice", unit(7, 1)), 100);
    // Same key, but the unit is of a different problem.
    assert_paid(&submit(&mut node, &other, "bob", unit(7, 1)), 100);
    assert_clean(&node.audit(true));
}

// ---------------------------------------------------------------------------
// The audit re-derives it all
// ---------------------------------------------------------------------------

#[test]
fn the_audit_catches_a_unit_paid_twice() {
    let (_dir, mut node, objective) =
        piecework_env("audit-twice", 1000, piecework_block(100, None, None));
    let paid = submit(&mut node, &objective, "alice", n(1));
    assert_paid(&paid, 100);

    node.ledger_mut()
        .append(
            "settlement",
            Value::object([
                ("objective_id", Value::string(objective.id())),
                ("claim_id", Value::string(paid.claim_id)),
                ("submitter", Value::string("alice")),
                ("reward", Value::Int(100)),
            ]),
            TS,
        )
        .expect("a hostile log is still a log");

    assert_reports(&node.audit(false), "paid more than once");
}

#[test]
fn the_audit_catches_a_unit_paid_the_wrong_amount() {
    let (_dir, mut node, objective) =
        piecework_env("audit-amount", 1000, piecework_block(100, None, None));
    let paid = submit(&mut node, &objective, "alice", n(1));
    assert_paid(&paid, 100);

    node.ledger_mut()
        .append(
            "settlement",
            Value::object([
                ("objective_id", Value::string(objective.id())),
                ("claim_id", Value::string(paid.claim_id)),
                ("submitter", Value::string("alice")),
                ("reward", Value::Int(900)),
            ]),
            TS,
        )
        .expect("a hostile log is still a log");

    let problems = node.audit(false);
    assert!(!problems.is_empty(), "an overpaid unit went unreported");
}

// ---------------------------------------------------------------------------
// Shape rules hold at the boundary
// ---------------------------------------------------------------------------

#[test]
fn a_ratchet_and_piecework_cannot_share_an_objective() {
    let err = Objective::new(
        "G",
        "maximize",
        Value::object([
            ("kind", Value::string("evaluator")),
            ("evaluator", Value::string("e.py")),
            (
                "evaluator_sha256",
                Value::string(sha256_hex(EVALUATOR.as_bytes())),
            ),
            ("entrypoint", Value::string("score")),
            ("threshold", Value::Int(0)),
            ("direction", Value::string("maximize")),
        ]),
        1000,
        "treasury",
        TS,
        None,
        Some(Value::object([
            ("baseline", Value::Int(0)),
            ("target", Value::Int(100)),
            ("reward", Value::Int(1000)),
            ("direction", Value::string("maximize")),
        ])),
    )
    .expect("valid ratchet objective")
    .with_piecework(piecework_block(10, None, None))
    .expect_err("one pool has one rule for spending it");
    assert!(matches!(err, RecordError::PieceworkWithRatchet), "{err}");
}

#[test]
fn a_unit_price_above_the_pool_is_refused_at_post() {
    let dir = TempDir::new("price");
    let sha = write_pinned(&dir, "c.py", UNIT_CHECKER);
    let mut node = node_at(&dir);
    let objective = piecework_objective(&sha, "job", 10, piecework_block(1000, None, None));
    let err = node
        .post_objective(&objective, TS)
        .expect_err("not one unit could be paid in full");
    assert!(
        matches!(
            err,
            RuleViolation::PieceworkPriceExceedsPool {
                unit_price: 1000,
                pool: 10
            }
        ),
        "{err}"
    );
    assert!(!node.objectives().contains_key(&objective.id()));
}

#[test]
fn a_malformed_piecework_block_is_refused_at_post() {
    let dir = TempDir::new("malformed");
    let sha = write_pinned(&dir, "c.py", UNIT_CHECKER);
    let mut node = node_at(&dir);
    for (label, block) in [
        ("zero price", piecework_block(0, None, None)),
        ("zero units", piecework_block(10, Some(0), None)),
        ("empty key", piecework_block(10, None, Some(""))),
        ("missing price", Value::object([("units", Value::Int(4))])),
    ] {
        let objective = piecework_objective(&sha, label, 1000, block);
        let err = node
            .post_objective(&objective, TS)
            .expect_err("a block the rules cannot read is refused");
        assert!(
            matches!(err, RuleViolation::MalformedPiecework(_)),
            "{label}: {err}"
        );
    }
}

#[test]
fn a_piecework_objective_survives_the_log_round_trip() {
    let (dir, node, objective) = piecework_env(
        "round-trip",
        1000,
        piecework_block(100, Some(64), Some("unit")),
    );
    drop(node);

    let reopened = node_at(&dir);
    let back = reopened
        .objectives()
        .remove(&objective.id())
        .expect("the posted objective decodes from the log");
    assert_eq!(back.id(), objective.id());
    assert_eq!(back.piecework, objective.piecework);
}

// ---------------------------------------------------------------------------
// Batches: many units in one claim
// ---------------------------------------------------------------------------

/// A checker for a batch of units: an artifact `{"dps": [ {n, w?}, ... ]}`
/// where every element's `n` is a small non-negative integer. `w` is
/// provenance the checker does not care about and the novelty rule, keyed
/// on `["n"]`, must ignore.
const BATCH_CHECKER: &str = r#"
def check(artifact):
    dps = artifact.get("dps")
    if not isinstance(dps, list) or not dps:
        return False, "dps must be a non-empty list"
    for e in dps:
        n = e.get("n") if isinstance(e, dict) else None
        if not isinstance(n, int) or not 0 <= n < 1000:
            return False, "every element needs an n in [0, 1000)"
    return True, "verified %d units" % len(dps)
"#;

fn batch_block(unit_price: i128) -> Value {
    Value::object([
        ("unit_price", Value::Int(unit_price)),
        ("items", Value::string("dps")),
        ("key", Value::Array(vec![Value::string("n")])),
    ])
}

/// `{"dps": [{"n": n, "w": w}, ...]}` from `(n, w)` pairs.
fn batch(elements: &[(i128, i128)]) -> Value {
    Value::object([(
        "dps",
        Value::Array(
            elements
                .iter()
                .map(|(n, w)| Value::object([("n", Value::Int(*n)), ("w", Value::Int(*w))]))
                .collect(),
        ),
    )])
}

fn batch_env(label: &str, reward: u64) -> (TempDir, Node, Objective) {
    let dir = TempDir::new(label);
    let sha = write_pinned(&dir, "c.py", BATCH_CHECKER);
    let mut node = node_at(&dir);
    let objective = piecework_objective(
        &sha,
        "answer the units, in batches",
        reward,
        batch_block(100),
    );
    node.post_objective(&objective, TS).expect("post");
    (dir, node, objective)
}

#[test]
fn a_batch_pays_once_per_novel_element() {
    let (_dir, mut node, objective) = batch_env("batch", 100_000);

    let first = submit(
        &mut node,
        &objective,
        "alice",
        batch(&[(1, 0), (2, 0), (3, 0)]),
    );
    assert_paid(&first, 300);
    assert!(
        first.note.contains("3 novel unit(s) paid"),
        "{}",
        first.note
    );

    // Two of bob's units are alice's, relabelled; one is new.
    let second = submit(
        &mut node,
        &objective,
        "bob",
        batch(&[(2, 9), (4, 9), (3, 9)]),
    );
    assert_paid(&second, 100);
    assert!(second.note.contains("2 duplicate(s)"), "{}", second.note);

    // A batch that is all duplicates verifies and earns nothing.
    assert_unpaid(
        &submit(&mut node, &objective, "eve", batch(&[(1, 5), (4, 5)])),
        "every unit in the batch was already paid",
    );
    // Listing a unit twice in one batch is one unit.
    assert_paid(
        &submit(
            &mut node,
            &objective,
            "carol",
            batch(&[(7, 0), (7, 1), (7, 2)]),
        ),
        100,
    );
    assert_eq!(node.paid_total(&objective.id()), 500);
    assert!(!node.objective_is_closed(&objective));
    assert_clean(&node.audit(true));
}

#[test]
fn a_batch_at_the_end_of_the_pool_takes_the_remainder_and_consumes_all_its_units() {
    let (_dir, mut node, objective) = batch_env("batch-remainder", 250);

    let last = submit(
        &mut node,
        &objective,
        "alice",
        batch(&[(1, 0), (2, 0), (3, 0)]),
    );
    assert_paid(&last, 250);
    assert!(last.note.contains("pool exhausted"), "{}", last.note);
    assert!(node.objective_is_closed(&objective));

    // Every unit of a paid batch is spoken for, including the one the pool
    // could not cover in full: a top-up does not pay it again.
    let dir_sha = {
        let sha = sha256_hex(BATCH_CHECKER.as_bytes());
        sha
    };
    let top_up = piecework_objective(&dir_sha, "round two", 1000, batch_block(100));
    node.post_objective(&top_up, TS).expect("post");
    assert_unpaid(
        &submit(&mut node, &top_up, "bob", batch(&[(3, 1)])),
        "every unit in the batch was already paid",
    );
    assert_paid(
        &submit(&mut node, &top_up, "bob", batch(&[(3, 1), (4, 1)])),
        100,
    );
    assert_clean(&node.audit(true));
}

#[test]
fn two_batches_sharing_a_unit_in_one_epoch_pay_for_it_once() {
    let (_dir, mut node, objective) = batch_env("batch-same-epoch", 100_000);
    let step = next_step(&node);
    let a = batch(&[(1, 0), (2, 0)]);
    let b = batch(&[(2, 1), (3, 1)]);
    commit_at(&mut node, &objective, "alice", &a, &stamp(step));
    commit_at(&mut node, &objective, "bob", &b, &stamp(step));
    let reveal = stamp(step + epoch());
    reveal_at(&mut node, &objective, "alice", a, &reveal).expect("reveal");
    reveal_at(&mut node, &objective, "bob", b, &reveal).expect("reveal");
    let settled = node
        .settle_at(&stamp(step + (2 + finality()) * epoch()))
        .expect("settle");
    let paid: u64 = settled.iter().map(|o| o.reward).sum();
    assert_eq!(
        paid, 300,
        "three distinct units across the two batches: {settled:?}"
    );
    assert_clean(&node.audit(true));
}

#[test]
fn the_audit_catches_a_batch_paid_for_no_novel_unit() {
    let (_dir, mut node, objective) = batch_env("batch-audit", 100_000);
    let paid = submit(&mut node, &objective, "alice", batch(&[(1, 0), (2, 0)]));
    assert_paid(&paid, 200);
    let copy = submit(&mut node, &objective, "eve", batch(&[(1, 3), (2, 3)]));
    assert_unpaid(&copy, "every unit in the batch was already paid");

    node.ledger_mut()
        .append(
            "settlement",
            Value::object([
                ("objective_id", Value::string(objective.id())),
                ("claim_id", Value::string(copy.claim_id)),
                ("submitter", Value::string("eve")),
                ("reward", Value::Int(200)),
            ]),
            TS,
        )
        .expect("a hostile log is still a log");

    assert_reports(&node.audit(false), "batch with no novel unit");
}

#[test]
fn a_batch_objective_publishes_its_block_and_names_no_unit_for_a_bare_artifact() {
    let (_dir, mut node, objective) = batch_env("batch-shape", 100_000);
    // The checker refuses an artifact that is not a batch, so nothing is
    // paid; the rule underneath would have found no unit in it either.
    let bare = submit(&mut node, &objective, "alice", n(1));
    assert_eq!(bare.verdict.status, Status::Reject);
    let piecework = cairn::piecework::Piecework::from_value(objective.piecework.as_ref().unwrap())
        .expect("valid block");
    assert!(piecework.unit_keys(&n(1)).is_empty());
    assert_eq!(
        piecework.unit_keys(&batch(&[(1, 0), (1, 1), (2, 0)])).len(),
        2
    );
    assert_clean(&node.audit(true));
}
