//! Claim assets typed by verification tier.
//!
//! The attack this closes, in one sentence: **run a cheap certificate mill,
//! then spend the proceeds where expensive work is priced.**
//!
//! Every bond in this crate is drawn from a balance — an availability
//! undertaking, a dispute challenge, and now the stake `custody_guard` measures
//! when it sizes a committee against the value it seals. A balance earned in
//! milliseconds of certificate checking was indistinguishable from one earned
//! in minutes of Lean, so standing manufactured on the cheapest tier bought
//! influence on the dearest. Sizing the committee against members' stakes, in
//! the commit before this one, made that attack *more* valuable rather than
//! less.
//!
//! | claim | test |
//! |---|---|
//! | settling mints units of the objective's tier | [`settling_mints_units_of_the_verifiers_own_tier`] |
//! | cheap earnings cannot fund expensive work | [`a_certificate_mill_cannot_fund_lean_work`] |
//! | and they still fund their own tier | [`earnings_fund_their_own_tier_as_before`] |
//! | genesis stays universal, or nothing bootstraps | [`the_reserve_declared_at_genesis_funds_any_tier`] |
//! | one reserve cannot back two tiers at once | [`the_reserve_cannot_be_promised_twice`] |
//! | the audit re-derives it | [`the_audit_names_a_funder_whose_units_were_the_wrong_kind`] |

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use cairn::canonical::Value;
use cairn::crypto::identity::Identity;
use cairn::ledger::Ledger;
use cairn::node::{Node, RuleViolation};
use cairn::records::{Claim, Commitment, Issuance, Objective};
use cairn::tier::Tier;
use cairn::verifiers::VerifierRegistry;

const GENESIS: &str = "2026-07-28T00:00:00+00:00";
const COMMIT_AT: &str = "2026-07-28T00:10:00+00:00";
const REVEAL_AT: &str = "2026-07-28T00:30:00+00:00";
const SETTLE_AT: &str = "2026-07-28T01:30:00+00:00";

/// Accepts anything. The tier is a property of the verifier's *kind*, not of
/// what it checks, so a permissive checker keeps these tests about the money.
const CHECKER: &str = r#"
def check(artifact):
    return True
"#;

/// An evaluator, for an objective in a different tier. Same permissiveness.
const EVALUATOR: &str = r#"
def score(artifact):
    return 100
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
            "proofwork-tiers-{label}-{unique}-{}",
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

fn identity(name: &str) -> Identity {
    let mut hasher = Sha256::new();
    hasher.update(b"cairn/tests/tiers/identity/v1");
    hasher.update(name.as_bytes());
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&hasher.finalize());
    Identity::from_secret_bytes(secret)
}

fn key(name: &str) -> String {
    identity(name).submitter_id()
}

struct Fixture {
    _dir: TempDir,
    node: Node,
}

/// A log whose only money is a universal reserve held by `treasury`.
fn fixture(label: &str, reserve: u64) -> Fixture {
    let dir = TempDir::new(label);
    fs::write(dir.path.join("c.py"), CHECKER).expect("writable");
    fs::write(dir.path.join("e.py"), EVALUATOR).expect("writable");
    let ledger = Ledger::open(dir.path.join("log.jsonl")).expect("an empty log");
    let mut node = Node::with_registry(ledger, VerifierRegistry::new(&dir.path));
    node.post_issuance(&Issuance::new(key("treasury"), reserve, GENESIS), GENESIS)
        .expect("genesis issuance");
    Fixture { _dir: dir, node }
}

/// An objective in a chosen tier. `certificate` and `evaluator` are the two
/// with runnable pinned code in this fixture; `lean` needs no toolchain here
/// because nothing ever submits to it — the test refuses at *post* time.
fn objective(kind: &str, funder: &str, reward: u64, label: &str) -> Objective {
    let signer = identity(funder);
    let verifier = match kind {
        "certificate" => Value::object([
            ("kind", Value::string("certificate")),
            ("checker", Value::string("c.py")),
            ("checker_sha256", Value::string(sha(CHECKER))),
            ("entrypoint", Value::string("check")),
        ]),
        "evaluator" => Value::object([
            ("kind", Value::string("evaluator")),
            ("evaluator", Value::string("e.py")),
            ("evaluator_sha256", Value::string(sha(EVALUATOR))),
            ("entrypoint", Value::string("score")),
            ("threshold", Value::Int(1)),
            ("direction", Value::string("maximize")),
        ]),
        "lean" => Value::object([
            ("kind", Value::string("lean")),
            ("project_root", Value::string(".")),
            ("entry", Value::string("Main.lean")),
        ]),
        other => panic!("no fixture for {other}"),
    };
    Objective::new(
        "G",
        format!("tier fixture: {label}"),
        verifier,
        reward,
        signer.submitter_id(),
        GENESIS,
        None,
        None,
    )
    .expect("valid objective")
    .funded_by(&signer)
}

/// Submit and settle, so the submitter is actually paid.
fn earn(fixture: &mut Fixture, objective: &Objective, who: &str, nonce: &str) {
    let id = objective.id();
    let signer = identity(who);
    let who = signer.submitter_id();
    let artifact = Value::object([("n", Value::Int(1))]);
    let commitment = Commitment::new(
        &id,
        &who,
        cairn::records::commitment_hash(&id, &who, &artifact, nonce),
        COMMIT_AT,
    )
    .signed_with(&signer);
    fixture.node.commit(&commitment, COMMIT_AT).expect("commit");
    let claim = Claim::new(&id, &who, artifact, nonce, REVEAL_AT, Vec::new())
        .expect("valid claim")
        .signed_with(&signer);
    fixture.node.reveal(&claim, REVEAL_AT).expect("reveal");

    let now = {
        let seconds = cairn::time::parse_rfc3339(SETTLE_AT).expect("an instant");
        cairn::partition::epoch_of(seconds as u64, cairn::partition::epoch_seconds())
    };
    let paid = fixture
        .node
        .settle_due(now, SETTLE_AT)
        .expect("settlement runs");
    assert!(!paid.is_empty(), "nothing settled");
}

fn tier(name: &str) -> Tier {
    Tier::parse(name).expect("a known tier")
}

// -- the tests -------------------------------------------------------------

/// Settling mints units of the tier the objective's own verifier names.
#[test]
fn settling_mints_units_of_the_verifiers_own_tier() {
    if !have_python() {
        eprintln!("skipping: no python3");
        return;
    }
    let mut fixture = fixture("mint", 10_000);
    let certificate = objective("certificate", "treasury", 1_000, "cert");
    fixture
        .node
        .post_objective(&certificate, GENESIS)
        .expect("post");
    earn(&mut fixture, &certificate, "alice", "n1");

    let tiered = fixture.node.tiered();
    let alice = tiered.get(&key("alice")).expect("alice was paid");
    assert_eq!(alice.held(tier("certificate")), 1_000);
    assert_eq!(alice.held(Tier::Universal), 0, "work minted reserve");
    assert_eq!(alice.held(tier("lean")), 0);
    // And the untyped total is unchanged, so every existing reader of
    // `balances` still gets the same number.
    assert_eq!(
        fixture
            .node
            .balances()
            .get(&key("alice"))
            .copied()
            .unwrap_or(0),
        1_000
    );
    assert!(fixture.node.audit(true).is_empty());
}

/// The attack, closed. Alice's thousand units are real, and they are the wrong
/// kind.
#[test]
fn a_certificate_mill_cannot_fund_lean_work() {
    if !have_python() {
        eprintln!("skipping: no python3");
        return;
    }
    let mut fixture = fixture("mill", 10_000);
    let certificate = objective("certificate", "treasury", 1_000, "cert");
    fixture
        .node
        .post_objective(&certificate, GENESIS)
        .expect("post");
    earn(&mut fixture, &certificate, "alice", "n1");
    assert_eq!(
        fixture
            .node
            .balances()
            .get(&key("alice"))
            .copied()
            .unwrap_or(0),
        1_000,
        "alice really does hold a thousand units"
    );

    // A Lean bounty for exactly what she holds.
    let lean = objective("lean", "alice", 1_000, "lean");
    let refused = fixture.node.post_objective(&lean, REVEAL_AT);
    let message = match refused {
        Err(RuleViolation::UnfundedInTier {
            tier: wanted,
            spendable,
            ..
        }) => {
            assert_eq!(wanted, tier("lean"));
            assert_eq!(spendable, 0, "certificate units were spendable on Lean");
            format!("{}", refused.unwrap_err())
        }
        other => panic!("a certificate mill funded Lean work: {other:?}"),
    };
    assert!(
        message.contains("do not convert"),
        "the refusal did not say why: {message}"
    );

    // An evaluator bounty is refused for the same reason: this is not a ladder
    // with Lean at the top, it is five separate assets.
    let evaluator = objective("evaluator", "alice", 1_000, "eval");
    assert!(matches!(
        fixture.node.post_objective(&evaluator, REVEAL_AT),
        Err(RuleViolation::UnfundedInTier { .. })
    ));
}

/// The same earnings still fund the same tier, so this is a provenance rule and
/// not a tax.
#[test]
fn earnings_fund_their_own_tier_as_before() {
    if !have_python() {
        eprintln!("skipping: no python3");
        return;
    }
    let mut fixture = fixture("same", 10_000);
    let first = objective("certificate", "treasury", 1_000, "cert-1");
    fixture.node.post_objective(&first, GENESIS).expect("post");
    earn(&mut fixture, &first, "alice", "n1");

    let second = objective("certificate", "alice", 1_000, "cert-2");
    fixture
        .node
        .post_objective(&second, REVEAL_AT)
        .expect("certificate earnings fund certificate work");
    assert_eq!(
        fixture.node.spendable_in(
            &key("alice"),
            tier("certificate"),
            fixture.node.ledger().len(),
        ),
        0,
        "the whole balance should now be committed"
    );
    assert!(fixture.node.audit(true).is_empty());
}

/// Genesis stays universal, or nothing bootstraps: the units to fund the first
/// Lean objective could only come from settling a Lean objective nobody could
/// fund.
#[test]
fn the_reserve_declared_at_genesis_funds_any_tier() {
    let mut fixture = fixture("reserve", 10_000);
    for kind in ["certificate", "evaluator", "lean"] {
        let objective = objective(kind, "treasury", 1_000, kind);
        fixture
            .node
            .post_objective(&objective, GENESIS)
            .unwrap_or_else(|why| panic!("the reserve could not fund {kind}: {why}"));
    }
    let tiered = fixture.node.tiered();
    let treasury = tiered.get(&key("treasury")).expect("the funder");
    assert_eq!(treasury.held(Tier::Universal), 10_000);
    assert_eq!(treasury.spendable_in(Tier::Universal), 7_000);
    // Every tier sees the same remaining reserve, because it is one pool.
    for kind in ["certificate", "evaluator", "lean", "replay"] {
        assert_eq!(treasury.spendable_in(tier(kind)), 7_000, "{kind}");
    }
}

/// One reserve cannot back two tiers at once.
///
/// The case the `tier::Ledger` type exists for. A per-tier column that did not
/// talk to its neighbours would report the same universal units as available in
/// every tier, and a funder could post five bounties against one reserve.
#[test]
fn the_reserve_cannot_be_promised_twice() {
    let mut fixture = fixture("twice", 1_000);
    fixture
        .node
        .post_objective(&objective("certificate", "treasury", 1_000, "a"), GENESIS)
        .expect("the whole reserve funds one bounty");
    let refused = fixture
        .node
        .post_objective(&objective("lean", "treasury", 1, "b"), GENESIS);
    assert!(
        matches!(refused, Err(RuleViolation::UnfundedReward { .. }))
            || matches!(refused, Err(RuleViolation::UnfundedInTier { .. })),
        "the same reserve funded a second tier: {refused:?}"
    );
    assert!(fixture.node.audit(false).is_empty());
}

/// The audit re-derives the rule rather than trusting the writer that applied
/// it.
///
/// The repository's characteristic failure is a rule enforced only at admission,
/// which a log imported from a peer therefore does not have. The injection is
/// what keeps the audit's copy load-bearing: revert `audit_tiers` and this test
/// fails.
#[test]
fn the_audit_names_a_funder_whose_units_were_the_wrong_kind() {
    if !have_python() {
        eprintln!("skipping: no python3");
        return;
    }
    let mut fixture = fixture("audit", 10_000);
    let certificate = objective("certificate", "treasury", 1_000, "cert");
    fixture
        .node
        .post_objective(&certificate, GENESIS)
        .expect("post");
    earn(&mut fixture, &certificate, "alice", "n1");
    assert!(fixture.node.audit(true).is_empty(), "the honest log audits");

    // Alice's Lean bounty, appended straight into the log because
    // `post_objective` refuses it — which is the point.
    let lean = objective("lean", "alice", 1_000, "lean");
    fixture
        .node
        .ledger_mut()
        .append("objective", lean.to_value(), REVEAL_AT)
        .expect("the log accepts an appended record");

    let problems = fixture.node.audit(false);
    assert!(
        problems
            .iter()
            .any(|problem| problem.contains("do not convert")),
        "the audit did not name the tier mismatch: {problems:?}"
    );
    // And the untyped conservation check is silent on it, which is why the
    // typed one had to exist: the total is there, the provenance is not.
    assert!(
        !problems
            .iter()
            .any(|problem| problem.contains("money made by naming it")),
        "the untyped check fired, so this test is not exercising the typed one: \
         {problems:?}"
    );
}
