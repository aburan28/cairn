//! Bonded verification: who ran the checker, and what it costs them to lie.
//!
//! The gap this closes was not found by reading. `src/arena` played a
//! rubber-stamper against the real rules engine and reported the only **OPEN**
//! verdict in the set: a canary docket names a *claim* whose verdict is wrong
//! and could not name a *party*, so there was nobody to slash and stamping paid
//! exactly the verification cost it skipped.
//!
//! An [`Attestation`] is the missing half. It says *this identity ran the
//! checker on this claim and got this*, under signature and under bond, so a
//! docket that already knows the answer has something to take.
//!
//! | claim | test |
//! |---|---|
//! | standing behind a verdict locks a bond | [`standing_behind_a_verdict_locks_a_bond`] |
//! | an attestation by nobody is not bonded, so it is refused | [`an_attestation_nobody_signed_is_refused`] |
//! | one statement per attestor per claim | [`one_attestor_stands_behind_a_claim_once`] |
//! | volume is its own limit | [`a_stamper_can_only_stand_behind_what_it_can_stake`] |
//! | `unavailable` is not bondable | [`admitting_a_broken_toolchain_is_never_bonded`] |
//! | a false attestation pays its bond to the catcher | [`a_false_attestation_pays_its_bond_to_the_catcher`] |
//! | a true one stands, and keeps its bond | [`a_true_attestation_stands`] |
//! | a verifier that cannot run takes nothing | [`a_verifier_that_cannot_run_takes_nothing`] |
//! | a slash needs an attestation to point at | [`a_slash_needs_an_attestation_to_point_at`] |
//! | the bond comes back when the window shuts | [`a_bond_returns_once_the_window_shuts`] |
//! | and a slash after that takes nothing | [`a_slash_after_the_window_takes_nothing`] |
//! | a bond must be affordable when posted | [`a_bond_posted_against_nothing_is_named_even_when_a_later_payout_covers_it`] |
//! | the audit re-derives every slash, cheaply | [`the_audit_names_a_slash_the_verifier_does_not_support`] |
//! | including whether the bond was still there | [`the_audit_names_a_slash_written_after_the_bond_returned`] |
//! | and finds a false attestation only when it reruns | [`a_false_attestation_is_found_by_the_rerunning_audit`] |
//!
//! The last pair is the one that matters most. Re-verifying every attestation
//! on every audit is precisely the cost the bond exists so that nobody pays
//! routinely; what an ordinary audit re-derives is every *taking*, which needs
//! one verifier run per slash and there are as many slashes as there are people
//! caught.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use proofwork::canonical::Value;
use proofwork::crypto::identity::Identity;
use proofwork::ledger::Ledger;
use proofwork::node::{Node, RuleViolation, VERIFICATION_BOND};
use proofwork::records::{Attestation, Claim, Commitment, Issuance, Objective};
use proofwork::verifiers::VerifierRegistry;

const GENESIS: &str = "2026-07-28T00:00:00+00:00";
const COMMIT_AT: &str = "2026-07-28T00:10:00+00:00";
const REVEAL_AT: &str = "2026-07-28T00:30:00+00:00";
const ATTEST_AT: &str = "2026-07-28T00:40:00+00:00";
const SLASH_AT: &str = "2026-07-28T00:50:00+00:00";
const SETTLE_AT: &str = "2026-07-28T01:30:00+00:00";
// Past `ATTEST_AT` plus the six-epoch window, at ten minutes to the epoch.
const LATE_COMMIT: &str = "2026-07-28T02:00:00+00:00";
const LATE_REVEAL: &str = "2026-07-28T02:10:00+00:00";
const LATE_SETTLE: &str = "2026-07-28T03:00:00+00:00";
const AFTER_WINDOW: &str = "2026-07-28T03:10:00+00:00";

/// Even accepts, odd rejects. The verdict has to depend on the artifact, or an
/// attestation could not be wrong about anything.
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
            "proofwork-attest-{label}-{unique}-{}",
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
    proofwork::hex::encode(&hasher.finalize())
}

struct Fixture {
    _dir: TempDir,
    node: Node,
    objective_id: String,
}

/// One objective with a runnable checker, and reserves to bond against.
///
/// Every issuance is at genesis because they have to be: minting after the
/// first entry is refused, so an attestor a test funds halfway through is an
/// attestor the log rejects.
fn fixture(label: &str, funded: &[(&str, u64)]) -> Fixture {
    let dir = TempDir::new(label);
    fs::write(dir.path.join("c.py"), CHECKER).expect("writable");
    let ledger = Ledger::open(dir.path.join("log.jsonl")).expect("an empty log");
    let mut node = Node::with_registry(ledger, VerifierRegistry::new(&dir.path));
    node.post_issuance(&Issuance::new("treasury", 1_000_000, GENESIS), GENESIS)
        .expect("genesis issuance");
    for (who, units) in funded {
        node.post_issuance(&Issuance::new(*who, *units, GENESIS), GENESIS)
            .expect("the attestor is funded");
    }

    let verifier = Value::object([
        ("kind", Value::string("certificate")),
        ("checker", Value::string("c.py")),
        ("checker_sha256", Value::string(sha(CHECKER))),
        ("entrypoint", Value::string("check")),
    ]);
    let objective = Objective::new(
        "G",
        "attestation fixture: even numbers only",
        verifier,
        1_000,
        "treasury",
        GENESIS,
        None,
        None,
    )
    .expect("valid objective");
    node.post_objective(&objective, GENESIS).expect("post");
    let objective_id = objective.id();
    Fixture {
        _dir: dir,
        node,
        objective_id,
    }
}

/// Reveal a claim carrying `n`, and return its id. Even is accepted by the
/// pinned checker and odd is rejected; both land in the log as claims, which is
/// what an attestation needs.
fn claim(fixture: &mut Fixture, who: &str, n: i128, nonce: &str) -> String {
    let objective_id = fixture.objective_id.clone();
    let artifact = Value::object([("n", Value::Int(n))]);
    claim_against(fixture, &objective_id, who, artifact, nonce)
}

fn claim_against(
    fixture: &mut Fixture,
    objective_id: &str,
    who: &str,
    artifact: Value,
    nonce: &str,
) -> String {
    let hash = proofwork::records::commitment_hash(objective_id, who, &artifact, nonce);
    let commitment = Commitment::new(objective_id, who, hash, COMMIT_AT);
    fixture.node.commit(&commitment, COMMIT_AT).expect("commit");
    let record =
        Claim::new(objective_id, who, artifact, nonce, REVEAL_AT, Vec::new()).expect("valid claim");
    fixture.node.reveal(&record, REVEAL_AT).expect("reveal");
    record.id()
}

/// A claim against an objective whose verifier this node has no toolchain for.
///
/// Deleting the checker file would have been the obvious way to make a verifier
/// unavailable, and it does not work — which is worth knowing rather than
/// working around. The blob store keeps pinned bytes it has resolved once, on
/// purpose, so a node that has ever run a checker can re-derive settlement
/// without the bundle. A verifier *kind* with no toolchain here is the honest
/// form of the same condition.
fn unrunnable_claim(fixture: &mut Fixture, who: &str, nonce: &str) -> String {
    let objective = Objective::new(
        "G",
        "attestation fixture: nothing here can run this",
        Value::object([
            ("kind", Value::string("lean")),
            ("project_root", Value::string(".")),
            ("entry", Value::string("Main.lean")),
        ]),
        1_000,
        "treasury",
        GENESIS,
        None,
        None,
    )
    .expect("valid objective");
    fixture
        .node
        .post_objective(&objective, GENESIS)
        .expect("post");
    let id = objective.id();
    claim_against(
        fixture,
        &id,
        who,
        Value::object([("theorem", Value::string("trivial"))]),
        nonce,
    )
}

/// Settle an epoch past the attestation window, so the log's own clock moves.
///
/// It has to be a *settlement* rather than a timestamp, because that is what
/// the rule reads: the highest epoch any `batch` record names. An entry's `ts`
/// is advisory text its author writes, so a window closing on one would be a
/// window its beneficiary could close.
///
/// A fresh objective, because the fixture's has a reward escrowed once and
/// paying it twice is a different bug than this test is looking for.
fn settle_past_the_window(fixture: &mut Fixture) {
    let id = fresh_objective(fixture, "something to settle later", LATE_COMMIT);
    let artifact = Value::object([("n", Value::Int(8))]);
    let hash = proofwork::records::commitment_hash(&id, "later", &artifact, "late");
    fixture
        .node
        .commit(
            &Commitment::new(&id, "later", hash, LATE_COMMIT),
            LATE_COMMIT,
        )
        .expect("commit");
    let record =
        Claim::new(&id, "later", artifact, "late", LATE_REVEAL, Vec::new()).expect("valid claim");
    fixture.node.reveal(&record, LATE_REVEAL).expect("reveal");

    let now = {
        let seconds = proofwork::time::parse_rfc3339(LATE_SETTLE).expect("an instant");
        proofwork::partition::epoch_of(seconds as u64, proofwork::partition::epoch_seconds())
    };
    let paid = fixture
        .node
        .settle_due(now, LATE_SETTLE)
        .expect("settlement runs");
    assert!(
        !paid.is_empty(),
        "nothing settled, so the clock did not move"
    );
}

/// Another objective against the fixture's checker, funded from the reserve.
///
/// One per claim that has to settle: a reward is escrowed once, and paying it
/// twice is a different bug than any of these tests is looking for.
fn fresh_objective(fixture: &mut Fixture, label: &str, ts: &str) -> String {
    let verifier = Value::object([
        ("kind", Value::string("certificate")),
        ("checker", Value::string("c.py")),
        ("checker_sha256", Value::string(sha(CHECKER))),
        ("entrypoint", Value::string("check")),
    ]);
    let objective = Objective::new(
        "G",
        format!("attestation fixture: {label}"),
        verifier,
        1_000,
        "treasury",
        GENESIS,
        None,
        None,
    )
    .expect("valid objective");
    fixture.node.post_objective(&objective, ts).expect("post");
    objective.id()
}

/// A funded, key-shaped attestor.
fn identity(seed: u8) -> Identity {
    Identity::from_secret_bytes([seed; 32])
}

fn attest(
    fixture: &mut Fixture,
    who: &Identity,
    claim_id: &str,
    status: &str,
    ts: &str,
) -> Result<String, RuleViolation> {
    let record = Attestation::new(claim_id, "", status, ts).signed_with(who);
    fixture.node.post_attestation(&record, ts)
}

// -- the bond --------------------------------------------------------------

/// The bond is locked at admission, and it is a *commitment* rather than a
/// payment: the attestor still holds the units, and cannot stake them twice.
#[test]
fn standing_behind_a_verdict_locks_a_bond() {
    if !have_python() {
        eprintln!("skipping: no python3");
        return;
    }
    let stamper = identity(11);
    let key = stamper.submitter_id();
    let mut fixture = fixture("lock", &[(key.as_str(), VERIFICATION_BOND * 3)]);
    let claim_id = claim(&mut fixture, "alice", 2, "n1");

    let before = fixture.node.balances().get(&key).copied().unwrap_or(0);
    assert_eq!(before, u128::from(VERIFICATION_BOND) * 3);
    attest(&mut fixture, &stamper, &claim_id, "accept", ATTEST_AT).expect("a bonded attestation");

    assert_eq!(
        fixture.node.balances().get(&key).copied().unwrap_or(0),
        u128::from(VERIFICATION_BOND) * 2,
        "the bond was not locked"
    );
    // Locked, not spent: the tiered view still shows the units held.
    let tiered = fixture.node.tiered();
    let ledger = tiered.get(&key).expect("the attestor holds units");
    assert_eq!(ledger.total_held(), u128::from(VERIFICATION_BOND) * 3);
    assert_eq!(ledger.total_committed(), u128::from(VERIFICATION_BOND));
    assert!(fixture.node.audit(true).is_empty());
}

/// An attestation by nobody has nobody to slash, which makes it free — and a
/// free attestation is rubber-stamping with a record attached.
#[test]
fn an_attestation_nobody_signed_is_refused() {
    if !have_python() {
        eprintln!("skipping: no python3");
        return;
    }
    let stamper = identity(12);
    let key = stamper.submitter_id();
    let mut fixture = fixture("unsigned", &[(key.as_str(), VERIFICATION_BOND * 2)]);
    let claim_id = claim(&mut fixture, "alice", 2, "n1");

    let unsigned = Attestation::new(&claim_id, &key, "accept", ATTEST_AT);
    assert!(
        matches!(
            fixture.node.post_attestation(&unsigned, ATTEST_AT),
            Err(RuleViolation::UnsignedIdentity(_))
        ),
        "an unsigned attestation was admitted"
    );

    // And one signed by somebody else, under this key's name, is refused for
    // the same reason: the signature is what binds the bond to a person.
    let mut forged =
        Attestation::new(&claim_id, "", "accept", ATTEST_AT).signed_with(&identity(13));
    forged.attestor = key.clone();
    assert!(fixture.node.post_attestation(&forged, ATTEST_AT).is_err());
    assert!(fixture.node.attestations().is_empty());
}

/// One statement per attestor per claim. A second is either a change of mind,
/// which the first signature already forecloses, or a way to bury the first
/// under noise.
#[test]
fn one_attestor_stands_behind_a_claim_once() {
    if !have_python() {
        eprintln!("skipping: no python3");
        return;
    }
    let stamper = identity(14);
    let key = stamper.submitter_id();
    let second = identity(15);
    let other = second.submitter_id();
    let mut fixture = fixture(
        "dup",
        &[
            (key.as_str(), VERIFICATION_BOND * 3),
            (other.as_str(), VERIFICATION_BOND),
        ],
    );
    let claim_id = claim(&mut fixture, "alice", 2, "n1");

    attest(&mut fixture, &stamper, &claim_id, "accept", ATTEST_AT).expect("the first");
    let again = attest(&mut fixture, &stamper, &claim_id, "reject", SLASH_AT);
    assert!(
        matches!(again, Err(RuleViolation::DuplicateAttestation { .. })),
        "the same identity stood behind one claim twice: {again:?}"
    );
    // A *different* identity may of course say the same thing, and stakes its
    // own bond to do so.
    attest(&mut fixture, &second, &claim_id, "accept", ATTEST_AT).expect("a second attestor");
    assert_eq!(fixture.node.attestations().len(), 2);
}

/// The property that makes a stamper's own volume the thing that stops it. The
/// bond is per *attestation*: one bond covering a thousand statements would be
/// the same units staked a thousand times.
#[test]
fn a_stamper_can_only_stand_behind_what_it_can_stake() {
    if !have_python() {
        eprintln!("skipping: no python3");
        return;
    }
    let stamper = identity(16);
    let key = stamper.submitter_id();
    let mut fixture = fixture("volume", &[(key.as_str(), VERIFICATION_BOND * 2)]);
    let first = claim(&mut fixture, "alice", 2, "n1");
    let second = claim(&mut fixture, "bob", 4, "n2");
    let third = claim(&mut fixture, "carol", 6, "n3");

    attest(&mut fixture, &stamper, &first, "accept", ATTEST_AT).expect("one");
    attest(&mut fixture, &stamper, &second, "accept", ATTEST_AT).expect("two");
    let refused = attest(&mut fixture, &stamper, &third, "accept", ATTEST_AT);
    match refused {
        Err(RuleViolation::UnfundedReward {
            reward, spendable, ..
        }) => {
            assert_eq!(reward, u128::from(VERIFICATION_BOND));
            assert_eq!(spendable, 0, "the first two bonds were not held against it");
        }
        other => panic!("a third attestation was free: {other:?}"),
    }
    assert!(fixture.node.audit(true).is_empty());
}

/// `unavailable` says *my machine could not run this*, which is a fact about
/// the attestor rather than the artifact. Bonding it would put a price on
/// admitting a broken toolchain, and the cheapest response to that price is to
/// guess instead — which is the exact behaviour the verifier interface exists
/// to prevent.
#[test]
fn admitting_a_broken_toolchain_is_never_bonded() {
    let record = Attestation::new("claim", "attestor", "unavailable", ATTEST_AT);
    let refused = record.validate();
    assert!(refused.is_err(), "unavailable was bondable");
    let message = format!("{}", refused.unwrap_err());
    assert!(
        message.contains("not bondable"),
        "the refusal did not say why: {message}"
    );
}

// -- the slash -------------------------------------------------------------

/// The whole point, with the money on it.
///
/// The stamper says `accept` about a claim the pinned checker rejects. A
/// catcher — the holder of a canary docket, in the network this is for — points
/// at the attestation, one verifier run settles it, and the bond moves.
#[test]
fn a_false_attestation_pays_its_bond_to_the_catcher() {
    if !have_python() {
        eprintln!("skipping: no python3");
        return;
    }
    let stamper = identity(17);
    let key = stamper.submitter_id();
    let mut fixture = fixture("slash", &[(key.as_str(), VERIFICATION_BOND * 2)]);
    // Odd, so the checker rejects it.
    let claim_id = claim(&mut fixture, "alice", 3, "n1");

    let attestation = attest(&mut fixture, &stamper, &claim_id, "accept", ATTEST_AT)
        .expect("nothing is checked at admission");
    let outcome = fixture
        .node
        .slash_attestation(&attestation, "catcher", SLASH_AT)
        .expect("the verifier disagrees, so the bond moves");
    assert_eq!(
        outcome.get("units").and_then(Value::as_i128),
        Some(i128::from(VERIFICATION_BOND))
    );

    let balances = fixture.node.balances();
    assert_eq!(
        balances.get("catcher").copied().unwrap_or(0),
        u128::from(VERIFICATION_BOND),
        "the catcher was not paid"
    );
    assert_eq!(
        balances.get(&key).copied().unwrap_or(0),
        u128::from(VERIFICATION_BOND),
        "the stamper kept its bond"
    );
    assert_eq!(
        fixture.node.attestation_debits().get(&key).copied(),
        Some(u128::from(VERIFICATION_BOND)),
        "the loss is not visible as a debit"
    );
    // Slashing is idempotent: a second attempt returns the first record rather
    // than taking the bond twice.
    let again = fixture
        .node
        .slash_attestation(&attestation, "catcher", SLASH_AT)
        .expect("idempotent");
    assert_eq!(again, outcome);
    assert_eq!(
        fixture.node.balances().get("catcher").copied().unwrap_or(0),
        u128::from(VERIFICATION_BOND)
    );
    assert!(fixture.node.audit(true).is_empty(), "the honest log audits");
}

/// Nothing to take. An attestation that matches what the verifier returns is
/// left alone, and pointing at it is an error rather than a coin flip.
#[test]
fn a_true_attestation_stands() {
    if !have_python() {
        eprintln!("skipping: no python3");
        return;
    }
    let honest = identity(18);
    let key = honest.submitter_id();
    let mut fixture = fixture("stands", &[(key.as_str(), VERIFICATION_BOND * 2)]);
    let claim_id = claim(&mut fixture, "alice", 2, "n1");
    let attestation = attest(&mut fixture, &honest, &claim_id, "accept", ATTEST_AT).expect("post");

    let refused = fixture
        .node
        .slash_attestation(&attestation, "catcher", SLASH_AT);
    assert!(
        matches!(refused, Err(RuleViolation::AttestationStands { .. })),
        "a true attestation was slashed: {refused:?}"
    );
    assert_eq!(fixture.node.balances().get("catcher").copied(), None);
    assert!(fixture.node.audit(true).is_empty());
}

/// `Unavailable` is never `Reject`, here as everywhere. Taking somebody's bond
/// because a machine broke would make breaking machines profitable — and an
/// attacker who can take a verifier offline could then slash every honest
/// attestor in the log.
#[test]
fn a_verifier_that_cannot_run_takes_nothing() {
    if !have_python() {
        eprintln!("skipping: no python3");
        return;
    }
    let stamper = identity(19);
    let key = stamper.submitter_id();
    let mut fixture = fixture("unavailable", &[(key.as_str(), VERIFICATION_BOND * 2)]);
    let claim_id = unrunnable_claim(&mut fixture, "alice", "n1");
    let attestation = attest(&mut fixture, &stamper, &claim_id, "accept", ATTEST_AT)
        .expect("an attestation about a claim nothing here can check");

    let refused = fixture
        .node
        .slash_attestation(&attestation, "catcher", SLASH_AT);
    assert!(
        matches!(refused, Err(RuleViolation::SlashUnavailable { .. })),
        "a broken toolchain took somebody's bond: {refused:?}"
    );
    assert_eq!(fixture.node.balances().get("catcher").copied(), None);
    assert_eq!(
        fixture.node.balances().get(&key).copied().unwrap_or(0),
        u128::from(VERIFICATION_BOND),
        "the bond should still be locked, not lost"
    );
}

// -- the audit -------------------------------------------------------------

/// The injection this rule stands or falls on.
///
/// A slash is a *taking*, so it is re-derived on the cheap path — every audit,
/// not only `--rerun`. Revert `audit_attestations`' slash loop and this test
/// fails: the forged record below moves fifty thousand units out of an honest
/// attestor's balance and a log imported from a peer would carry it.
#[test]
fn the_audit_names_a_slash_the_verifier_does_not_support() {
    if !have_python() {
        eprintln!("skipping: no python3");
        return;
    }
    let honest = identity(20);
    let key = honest.submitter_id();
    let mut fixture = fixture("forged", &[(key.as_str(), VERIFICATION_BOND * 2)]);
    let claim_id = claim(&mut fixture, "alice", 2, "n1");
    let attestation = attest(&mut fixture, &honest, &claim_id, "accept", ATTEST_AT).expect("post");
    assert!(
        fixture.node.audit(false).is_empty(),
        "the honest log audits"
    );

    // Appended straight into the log, because `slash_attestation` refuses it —
    // which is the point.
    let forged = Value::object([
        ("attestation_id", Value::string(&attestation)),
        ("attestor", Value::string(key.clone())),
        ("catcher", Value::string("thief")),
        ("claim_id", Value::string(&claim_id)),
        ("detail", Value::string("because I said so")),
        ("units", Value::Int(i128::from(VERIFICATION_BOND))),
    ]);
    fixture
        .node
        .ledger_mut()
        .append("verification_slash", forged, SLASH_AT)
        .expect("the log accepts an appended record");
    assert_eq!(
        fixture.node.balances().get("thief").copied().unwrap_or(0),
        u128::from(VERIFICATION_BOND),
        "the forgery did not actually move money, so this test proves nothing"
    );

    let problems = fixture.node.audit(false);
    assert!(
        problems
            .iter()
            .any(|problem| problem.contains("which is what the verifier returns")),
        "the cheap audit did not re-derive the slash: {problems:?}"
    );
}

/// And the other half of the bargain, stated as a test so it cannot quietly
/// change: whether an *unslashed* attestation is true is asked only under
/// `--rerun`.
///
/// This is not a concession to speed. Re-verifying every attestation on every
/// audit is exactly the cost the bond exists so that nobody pays routinely; if
/// the cheap path fired here, the mechanism would have bought nothing.
#[test]
fn a_false_attestation_is_found_by_the_rerunning_audit() {
    if !have_python() {
        eprintln!("skipping: no python3");
        return;
    }
    let stamper = identity(21);
    let key = stamper.submitter_id();
    let mut fixture = fixture("rerun", &[(key.as_str(), VERIFICATION_BOND * 2)]);
    let claim_id = claim(&mut fixture, "alice", 3, "n1");
    attest(&mut fixture, &stamper, &claim_id, "accept", ATTEST_AT).expect("post");

    assert!(
        fixture.node.audit(false).is_empty(),
        "the cheap audit re-verified an attestation nobody disputed"
    );
    let problems = fixture.node.audit(true);
    assert!(
        problems
            .iter()
            .any(|problem| problem.contains("stood behind accept")),
        "the rerunning audit missed a false attestation: {problems:?}"
    );
}

/// A slash names an attestation, and only one that exists.
#[test]
fn a_slash_needs_an_attestation_to_point_at() {
    if !have_python() {
        eprintln!("skipping: no python3");
        return;
    }
    let stamper = identity(22);
    let key = stamper.submitter_id();
    let mut fixture = fixture("missing", &[(key.as_str(), VERIFICATION_BOND)]);
    let refused = fixture
        .node
        .slash_attestation("sha256:not-in-this-log", "catcher", SLASH_AT);
    assert!(
        matches!(refused, Err(RuleViolation::UnknownAttestation { .. })),
        "a slash pointed at nothing: {refused:?}"
    );
}

// -- the window ------------------------------------------------------------

/// The bond comes back, and that is what makes verification a service rather
/// than a capital sink.
///
/// The first draft of this rule locked the bond for good and called the
/// permanence a feature. It is not: an operator holding `S` units could stand
/// behind `S / VERIFICATION_BOND` verdicts in its entire life and then never
/// verify again, which fixes the network's total verification capacity at
/// `supply / bond` forever.
#[test]
fn a_bond_returns_once_the_window_shuts() {
    if !have_python() {
        eprintln!("skipping: no python3");
        return;
    }
    let honest = identity(23);
    let key = honest.submitter_id();
    let mut fixture = fixture("window", &[(key.as_str(), VERIFICATION_BOND)]);
    let first = claim(&mut fixture, "alice", 2, "n1");
    attest(&mut fixture, &honest, &first, "accept", ATTEST_AT).expect("the whole balance staked");
    assert_eq!(
        fixture.node.balances().get(&key).copied().unwrap_or(0),
        0,
        "the bond should be locked while the window is open"
    );

    settle_past_the_window(&mut fixture);
    assert_eq!(
        fixture.node.balances().get(&key).copied().unwrap_or(0),
        u128::from(VERIFICATION_BOND),
        "the bond did not come back"
    );

    // And the same units stake the next statement, which is the property the
    // window exists for: standing behind more claims costs more *at once*, not
    // once and for all.
    // A fresh objective, and a claim revealed after the settlement above: the
    // fixture's own objective has drained its escrow and the epoch it settled
    // in is shut.
    let objective_id = fresh_objective(&mut fixture, "after the window", LATE_SETTLE);
    let artifact = Value::object([("n", Value::Int(6))]);
    let hash = proofwork::records::commitment_hash(&objective_id, "bob", &artifact, "n2");
    fixture
        .node
        .commit(
            &Commitment::new(&objective_id, "bob", hash, LATE_SETTLE),
            LATE_SETTLE,
        )
        .expect("commit");
    let record = Claim::new(
        &objective_id,
        "bob",
        artifact,
        "n2",
        AFTER_WINDOW,
        Vec::new(),
    )
    .expect("valid claim");
    fixture.node.reveal(&record, AFTER_WINDOW).expect("reveal");
    let second = record.id();
    attest(&mut fixture, &honest, &second, "accept", AFTER_WINDOW)
        .expect("the returned bond stakes the next attestation");
    assert!(fixture.node.audit(true).is_empty());
}

/// And a slash after the bond has returned takes nothing.
///
/// Not tidiness: the units are back in the attestor's balance and may already
/// be staked behind something else, so a late taking debits money twice.
#[test]
fn a_slash_after_the_window_takes_nothing() {
    if !have_python() {
        eprintln!("skipping: no python3");
        return;
    }
    let stamper = identity(24);
    let key = stamper.submitter_id();
    let mut fixture = fixture("late-slash", &[(key.as_str(), VERIFICATION_BOND * 2)]);
    let claim_id = claim(&mut fixture, "alice", 3, "n1");
    let attestation = attest(&mut fixture, &stamper, &claim_id, "accept", ATTEST_AT)
        .expect("a false attestation nobody caught in time");

    settle_past_the_window(&mut fixture);
    let refused = fixture
        .node
        .slash_attestation(&attestation, "catcher", LATE_SETTLE);
    match refused {
        Err(RuleViolation::AttestationWindowShut { .. }) => {}
        other => panic!("a returned bond was taken anyway: {other:?}"),
    }
    assert_eq!(fixture.node.balances().get("catcher").copied(), None);
    assert!(fixture.node.audit(false).is_empty());
}

/// The audit re-derives the window too, because a log arrives from peers.
///
/// The injection: revert the window check in `audit_attestations` and this
/// test fails. Without it a peer could hand you a log whose last record takes
/// fifty thousand units out of a balance that had already been credited back.
#[test]
fn the_audit_names_a_slash_written_after_the_bond_returned() {
    if !have_python() {
        eprintln!("skipping: no python3");
        return;
    }
    let stamper = identity(25);
    let key = stamper.submitter_id();
    let mut fixture = fixture("late-forged", &[(key.as_str(), VERIFICATION_BOND * 2)]);
    let claim_id = claim(&mut fixture, "alice", 3, "n1");
    let attestation = attest(&mut fixture, &stamper, &claim_id, "accept", ATTEST_AT).expect("post");
    settle_past_the_window(&mut fixture);

    // Appended straight into the log, because `slash_attestation` refuses it.
    // Everything else about this record is correct -- the attestor, the claim,
    // the bond to the unit -- so only the window check can catch it.
    let late = Value::object([
        ("attestation_id", Value::string(&attestation)),
        ("attestor", Value::string(key.clone())),
        ("catcher", Value::string("latecomer")),
        ("claim_id", Value::string(&claim_id)),
        (
            "detail",
            Value::string("attested accept where the verifier returns reject"),
        ),
        ("units", Value::Int(i128::from(VERIFICATION_BOND))),
    ]);
    fixture
        .node
        .ledger_mut()
        .append("verification_slash", late, LATE_SETTLE)
        .expect("the log accepts an appended record");

    let problems = fixture.node.audit(false);
    assert!(
        problems
            .iter()
            .any(|problem| problem.contains("after its window shut")),
        "the audit did not re-derive the window: {problems:?}"
    );
}

/// **A bond has to be affordable when it is posted, and the audit has to say so.**
///
/// The repository's characteristic bug, and this file shipped it. `audit_attestations`
/// re-derived the signature, the duplicate rule, the claim and every slash --
/// and not whether the attestor could cover the bond at the point it staked it.
/// The undertaking audit has checked exactly this since it was written, with a
/// comment saying why: *a later payout must not retroactively justify a bond
/// that was unfunded at the time.*
///
/// The whole-log conservation sum does not catch it, and the log below is built
/// to show that rather than to assert it. The attestor is broke when the
/// attestation lands and is paid afterwards, so by the last entry `committed`
/// and `held` agree exactly — the forgery balances, and is still a bond nobody
/// could have made.
#[test]
fn a_bond_posted_against_nothing_is_named_even_when_a_later_payout_covers_it() {
    if !have_python() {
        eprintln!("skipping: no python3");
        return;
    }
    let stamper = identity(26);
    let key = stamper.submitter_id();
    // Deliberately unfunded at genesis: everything this identity ever holds it
    // has to earn, and it earns it *after* the attestation.
    let mut fixture = fixture("retroactive", &[]);

    // A bounty big enough to cover the bond, so the log ends balanced.
    let objective = Objective::new(
        "G",
        "attestation fixture: pays more than a bond",
        Value::object([
            ("kind", Value::string("certificate")),
            ("checker", Value::string("c.py")),
            ("checker_sha256", Value::string(sha(CHECKER))),
            ("entrypoint", Value::string("check")),
        ]),
        VERIFICATION_BOND,
        "treasury",
        GENESIS,
        None,
        None,
    )
    .expect("valid objective");
    fixture
        .node
        .post_objective(&objective, GENESIS)
        .expect("post");
    let id = objective.id();

    let artifact = Value::object([("n", Value::Int(2))]);
    let hash = proofwork::records::commitment_hash(&id, &key, &artifact, "n1");
    fixture
        .node
        .commit(
            &Commitment::new(&id, &key, hash, COMMIT_AT).signed_with(&stamper),
            COMMIT_AT,
        )
        .expect("commit");
    let claim = Claim::new(&id, &key, artifact, "n1", REVEAL_AT, Vec::new())
        .expect("valid claim")
        .signed_with(&stamper);
    fixture.node.reveal(&claim, REVEAL_AT).expect("reveal");
    let claim_id = claim.id();

    // Posted here, before the settlement, and appended straight in because
    // `post_attestation` refuses it -- which is the point.
    let record = Attestation::new(&claim_id, "", "accept", REVEAL_AT).signed_with(&stamper);
    assert!(
        matches!(
            fixture.node.post_attestation(&record, REVEAL_AT),
            Err(RuleViolation::UnfundedReward { .. })
        ),
        "admission let an unfunded bond through, so this test is checking the \
         wrong half of the rule"
    );
    fixture
        .node
        .ledger_mut()
        .append("attestation", record.to_value(), REVEAL_AT)
        .expect("the log accepts an appended record");

    // And now the payout that makes the arithmetic work out.
    let now = {
        let seconds = proofwork::time::parse_rfc3339(SETTLE_AT).expect("an instant");
        proofwork::partition::epoch_of(seconds as u64, proofwork::partition::epoch_seconds())
    };
    let paid = fixture
        .node
        .settle_due(now, SETTLE_AT)
        .expect("settlement runs");
    assert!(
        !paid.is_empty(),
        "nothing settled, so nothing covers the bond"
    );

    let problems = fixture.node.audit(false);
    // First: the forgery really does balance, or the conservation sum would be
    // catching it and this test would prove nothing about the new rule.
    assert!(
        !problems
            .iter()
            .any(|problem| problem.contains("money made by naming it")),
        "the whole-log conservation check fired, so the fixture is not \
         exercising the affordability rule: {problems:?}"
    );
    assert!(
        problems.iter().any(|problem| {
            problem.contains("attestation at entry") && problem.contains("against a balance of 0")
        }),
        "the audit did not name a bond that was unfunded when it was posted: \
         {problems:?}"
    );
}
