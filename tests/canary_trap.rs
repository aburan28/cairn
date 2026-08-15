//! The canary trap, end to end: mint, submit, and catch a node that did not look.
//!
//! `src/canary.rs` proves the generator's invariants over `Value`s. This file
//! asks the question those unit tests cannot: does the trap actually close
//! around a **node**, against a real log, through the public commit–reveal API
//! an ordinary contributor uses?
//!
//! Three things get executed here rather than asserted in prose:
//!
//! | claim | test |
//! |---|---|
//! | an honest node walks through the trap untouched | [`an_honest_node_leaves_the_docket_clean`] |
//! | a rubber-stamper is named by the log it wrote | [`a_node_that_accepted_without_looking_is_named`] |
//! | a blind rejecter is named too | [`a_node_that_rejected_without_looking_is_named`] |
//! | a canary in the log is not separable from a real submission | [`the_log_does_not_say_which_claims_were_canaries`] |
//! | checking is orders of magnitude cheaper than re-verifying | [`the_docket_polices_the_log_without_running_a_verifier`] |
//!
//! The last one is the reason the mechanism is affordable at all, and it is the
//! only one that has to be *measured* rather than proved.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use proofwork::canary::{fingerprint, Canary, Docket, Expectation, Generator};
use proofwork::canonical::Value;
use proofwork::ledger::Ledger;
use proofwork::node::Node;
use proofwork::records::{Claim, Commitment, Objective};
use proofwork::verifiers::{Status, VerifierRegistry};

const COMMIT_AT: &str = "2026-07-28T00:00:00+00:00";
const REVEAL_AT: &str = "2026-07-28T00:20:00+00:00";

/// A pinned checker with both sides reachable in one edit.
///
/// Accepting exactly the permutations of 1..8 is deliberate: swapping two
/// entries leaves a permutation (a known-*good* canary), and shifting one entry
/// does not (a known-*bad* one). An objective whose artifact is a single number
/// admits no cheap good canary at all — see `ranked_sites` — and that asymmetry
/// is a fact about objectives, not something to paper over here.
const CHECKER: &str = r#"
def check(artifact):
    picks = artifact.get("picks")
    if not isinstance(picks, list):
        return False
    return sorted(picks) == list(range(1, 9))
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
            "proofwork-canary-{label}-{unique}-{}",
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

/// The honest artifact a real contributor would submit.
fn honest_artifact() -> Value {
    Value::object([(
        "picks",
        Value::array((1..=8).map(Value::Int).collect::<Vec<_>>()),
    )])
}

fn network(label: &str) -> (TempDir, Node, Objective) {
    let dir = TempDir::new(label);
    fs::write(dir.path.join("c.py"), CHECKER).expect("pinned checker is writable");
    let mut hasher = Sha256::new();
    hasher.update(CHECKER.as_bytes());
    let sha = proofwork::hex::encode(&hasher.finalize());

    let ledger = Ledger::open(dir.path.join("log.jsonl")).expect("an empty log");
    let mut node = Node::with_registry(ledger, VerifierRegistry::new(&dir.path));

    let objective = Objective::new(
        "G",
        "exhibit a permutation of 1..8",
        Value::object([
            ("kind", Value::string("certificate")),
            ("checker", Value::string("c.py")),
            ("checker_sha256", Value::string(sha.as_str())),
            ("entrypoint", Value::string("check")),
        ]),
        1000,
        "treasury",
        COMMIT_AT,
        None,
        None,
    )
    .expect("valid objective");
    node.post_objective(&objective, COMMIT_AT).expect("post");
    (dir, node, objective)
}

/// Submit an artifact the ordinary way: commit, then reveal. The node runs the
/// verifier and writes the verdict itself — nothing here tells it the answer.
fn submit(node: &mut Node, objective: &Objective, who: &str, artifact: &Value, nonce: &str) {
    let commitment = Commitment::new(
        objective.id(),
        who,
        proofwork::records::commitment_hash(&objective.id(), who, artifact, nonce),
        COMMIT_AT,
    );
    node.commit(&commitment, COMMIT_AT).expect("commit");
    let claim = Claim::new(
        objective.id(),
        who,
        artifact.clone(),
        nonce,
        REVEAL_AT,
        Vec::new(),
    )
    .expect("valid claim");
    node.reveal(&claim, REVEAL_AT).expect("reveal");
}

/// Mint a mixed docket against the objective's own pinned verifier.
fn canaries(node: &Node, objective: &Objective) -> Vec<Canary> {
    let generator = Generator::new(node.registry(), &objective.verifier);
    let seed = honest_artifact();
    assert_eq!(
        generator.verdict(&seed).status,
        Status::Accept,
        "the seed must be an artifact the network really accepts"
    );
    let (minted, failures) = generator.mint_batch(&seed, 4, 1, 2);
    assert!(failures.is_empty(), "minting failed: {failures:?}");
    assert_eq!(minted.len(), 4);
    let (good, bad) = Docket::from_canaries(&minted).mix();
    assert_eq!((good, bad), (2, 2), "the reference mix is half and half");
    minted
}

/// Forge a verdict record straight into the log, which is what a node that
/// never ran the verifier would have written.
///
/// Going in at the ledger rather than through `reveal` is the only way to get a
/// verdict the verifier disagrees with — `reveal` runs the check itself, which
/// is exactly the honest behaviour under test everywhere else.
fn forge_verdict(node: &mut Node, claim_id: &str, objective_id: &str, status: Status) {
    let record = Value::object([
        ("claim_id", Value::string(claim_id)),
        ("objective_id", Value::string(objective_id)),
        (
            "verdict",
            Value::object([
                ("status", Value::string(status.as_str())),
                ("detail", Value::string("checked, honest, definitely")),
                ("evidence", Value::object(Vec::<(&str, Value)>::new())),
            ]),
        ),
    ]);
    node.ledger_mut()
        .append("verdict", record, REVEAL_AT)
        .expect("the log accepts an appended record");
}

// -- the tests -------------------------------------------------------------

/// A node that actually runs the verifier is accused of nothing.
///
/// The direction that matters most. A trap with false positives is worse than
/// no trap: it costs honest operators money for behaving correctly, and the
/// rational response is to stop operating.
#[test]
fn an_honest_node_leaves_the_docket_clean() {
    if !have_python() {
        eprintln!("skipping: no python3");
        return;
    }
    let (_dir, mut node, objective) = network("honest");
    let minted = canaries(&node, &objective);
    let docket = Docket::from_canaries(&minted);

    submit(&mut node, &objective, "alice", &honest_artifact(), "real-0");
    for (index, canary) in minted.iter().enumerate() {
        submit(
            &mut node,
            &objective,
            &format!("watcher-{index}"),
            &canary.artifact,
            &format!("canary-{index}"),
        );
    }

    let recorded = node.recorded_verdicts();
    assert_eq!(recorded.len(), 5, "one verdict per submission");
    let found = docket.discrepancies(&recorded);
    assert!(found.is_empty(), "honest node accused: {found:?}");

    // And the node's own audit agrees, so the canaries did not corrupt the log
    // they were submitted into.
    let problems = node.audit(true);
    assert!(problems.is_empty(), "audit: {problems:?}");
}

/// A node that wrote `accept` without looking is named by the log it wrote.
#[test]
fn a_node_that_accepted_without_looking_is_named() {
    if !have_python() {
        eprintln!("skipping: no python3");
        return;
    }
    let (_dir, mut node, objective) = network("stamp");
    let minted = canaries(&node, &objective);
    let docket = Docket::from_canaries(&minted);

    let bad = minted
        .iter()
        .find(|c| c.expectation == Expectation::Rejects)
        .expect("a known-bad canary");
    submit(&mut node, &objective, "watcher", &bad.artifact, "canary-0");

    let claim_id = node
        .recorded_verdicts()
        .first()
        .expect("a verdict")
        .claim_id
        .clone();
    // The honest verdict is already in the log and says reject. The liar
    // supersedes it, which is what a rubber-stamping node's log looks like.
    forge_verdict(&mut node, &claim_id, &objective.id(), Status::Accept);

    let found = docket.discrepancies(&node.recorded_verdicts());
    assert_eq!(found.len(), 1, "the stamp was not caught: {found:?}");
    assert_eq!(found[0].expected, Expectation::Rejects);
    assert_eq!(found[0].recorded, Status::Accept);
    assert_eq!(found[0].claim_id, claim_id);
}

/// The other half of the trap. Blind rejection catches every known-bad canary
/// and looks diligent doing it; only a known-good canary tells the difference.
#[test]
fn a_node_that_rejected_without_looking_is_named() {
    if !have_python() {
        eprintln!("skipping: no python3");
        return;
    }
    let (_dir, mut node, objective) = network("blind");
    let minted = canaries(&node, &objective);

    let good = minted
        .iter()
        .find(|c| c.expectation == Expectation::Accepts)
        .expect("a known-good canary");
    let bad = minted
        .iter()
        .find(|c| c.expectation == Expectation::Rejects)
        .expect("a known-bad canary");

    submit(&mut node, &objective, "watcher-g", &good.artifact, "c-g");
    submit(&mut node, &objective, "watcher-b", &bad.artifact, "c-b");
    let verdicts = node.recorded_verdicts();
    let good_claim = verdicts
        .iter()
        .find(|v| v.artifact_id == good.artifact_id())
        .expect("the good canary's claim")
        .claim_id
        .clone();
    forge_verdict(&mut node, &good_claim, &objective.id(), Status::Reject);

    // A docket of only known-bad canaries sees nothing at all: the blind
    // rejecter got that one right, for the wrong reason.
    let bad_only = Docket::from_canaries(std::slice::from_ref(bad));
    assert!(
        bad_only.discrepancies(&node.recorded_verdicts()).is_empty(),
        "a bad-only docket should be blind to blind rejection"
    );

    let full = Docket::from_canaries(&minted);
    let found = full.discrepancies(&node.recorded_verdicts());
    assert_eq!(
        found.len(),
        1,
        "the blind rejecter was not caught: {found:?}"
    );
    assert_eq!(found[0].expected, Expectation::Accepts);
    assert_eq!(found[0].recorded, Status::Reject);
}

/// Deployment-level indistinguishability: reading the finished log, a canary
/// claim is not separable from a real one by anything cheaper than the verifier.
///
/// The unit test in `src/canary.rs` proves the *artifact* is shape- and
/// length-identical to its parent. This one checks the property survives the
/// journey into the log, where a claim carries a submitter, a nonce, and a
/// timestamp alongside the artifact.
/// The first version of this test failed, and it failed on its own fixture:
/// the canary submissions carried nonces spelled `canary-0`, `canary-1`. Every
/// artifact-level property held perfectly and the log still handed over a
/// complete list of which claims were traps, because the *envelope* around the
/// artifact was labelled. That is the whole class of mistake the deployment
/// note in `src/canary.rs` is about, reproduced by accident in twelve lines of
/// test setup, which is a fair estimate of how easy it is to make.
///
/// So the submissions below are interleaved from one pool of same-length names
/// with same-length nonces, and the log is checked to be uniform: identical
/// claim-record lengths, identical artifact fingerprints, no keyword anywhere.
#[test]
fn the_log_does_not_say_which_claims_were_canaries() {
    if !have_python() {
        eprintln!("skipping: no python3");
        return;
    }
    let (_dir, mut node, objective) = network("blind-spot");
    let minted = canaries(&node, &objective);
    let honest = honest_artifact();

    // Real, canary, real, canary, ... from a single naming scheme. Order does
    // not separate them and neither does the name.
    let mut artifacts: Vec<Value> = Vec::new();
    for canary in &minted {
        artifacts.push(honest.clone());
        artifacts.push(canary.artifact.clone());
    }
    for (index, artifact) in artifacts.iter().enumerate() {
        submit(
            &mut node,
            &objective,
            &format!("sub-{index:02}"),
            artifact,
            &format!("nonce-{index:02}"),
        );
    }

    let mark = fingerprint(&honest);
    let mut sizes = std::collections::BTreeSet::new();
    for canary in &minted {
        assert_eq!(
            fingerprint(&canary.artifact),
            mark,
            "a canary's fingerprint differs from a real submission's"
        );
        sizes.insert(canary.artifact.canonical_bytes().len());
    }
    sizes.insert(honest.canonical_bytes().len());
    assert_eq!(
        sizes.len(),
        1,
        "artifact sizes separate the canaries: {sizes:?}"
    );

    // The record around the artifact is uniform too: with same-length
    // submitters and nonces, every claim in this log encodes to the same number
    // of bytes. A canary that arrived in a longer record is a canary you can
    // count.
    let lengths: std::collections::BTreeSet<usize> = node
        .ledger()
        .entries_of_kind("claim")
        .into_iter()
        .map(|entry| entry.payload.canonical_bytes().len())
        .collect();
    assert_eq!(
        lengths.len(),
        1,
        "claim record sizes separate the canaries: {lengths:?}"
    );

    // And nothing in the log names one. A helpful field, a labelled nonce, or a
    // submitter called `canary-bot` undoes every property above at a stroke.
    let log = fs::read_to_string(node.ledger().path()).expect("the log is readable");
    assert!(
        !log.to_lowercase().contains("canary"),
        "the log names its own canaries"
    );

    // Every canary is a *distinct* artifact, so a node cannot recognise one by
    // having seen it before either.
    let mut digests = std::collections::BTreeSet::new();
    digests.insert(honest.digest());
    for canary in &minted {
        assert!(
            digests.insert(canary.artifact_id()),
            "two submissions share an artifact"
        );
    }
}

/// The economic claim, measured: checking a docket costs no verifier runs.
///
/// This is why a canary rate is affordable. The auditor pays full verification
/// cost once, at mint time, and then polices every verdict the network writes
/// for the price of a map lookup. Re-auditing with `rerun` is the alternative
/// and it costs one subprocess per claim, forever.
#[test]
fn the_docket_polices_the_log_without_running_a_verifier() {
    if !have_python() {
        eprintln!("skipping: no python3");
        return;
    }
    let (_dir, mut node, objective) = network("cost");
    let minted = canaries(&node, &objective);
    let docket = Docket::from_canaries(&minted);

    for index in 0..12 {
        submit(
            &mut node,
            &objective,
            &format!("alice-{index}"),
            &honest_artifact(),
            &format!("real-{index}"),
        );
    }
    for (index, canary) in minted.iter().enumerate() {
        submit(
            &mut node,
            &objective,
            &format!("watcher-{index}"),
            &canary.artifact,
            &format!("canary-{index}"),
        );
    }

    let recorded = node.recorded_verdicts();
    assert_eq!(recorded.len(), 16);

    let started = Instant::now();
    let found = docket.discrepancies(&recorded);
    let checking = started.elapsed();
    assert!(found.is_empty());

    let started = Instant::now();
    let problems = node.audit(true);
    let reverifying = started.elapsed();
    assert!(problems.is_empty(), "audit: {problems:?}");

    eprintln!(
        "16 verdicts: docket check {:?}, re-verifying audit {:?}",
        checking, reverifying
    );
    // Three orders of magnitude is a floor, not the measurement: a docket check
    // is a few map lookups and a re-verifying audit spawns a jailed interpreter
    // per claim. The assertion is deliberately loose because the ratio grows
    // with the log while the check stays flat, and a CI machine under load must
    // not make this flaky.
    assert!(
        reverifying > checking * 1_000,
        "re-verification was not dramatically more expensive: \
         {reverifying:?} against {checking:?}"
    );
}
