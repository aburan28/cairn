//! A bonded dispute, end to end, through the rules engine.
//!
//! `src/challenge/tests.rs` proves the game. This file asks what the game
//! cannot: does it survive being written down as records, folded back out of a
//! log by somebody who was not there, and settled with money attached?
//!
//! | claim | test |
//! |---|---|
//! | a liar's claim is refuted and the liar pays | [`a_forged_trace_loses_its_bond_to_the_challenger`] |
//! | a false objection pays the honest submitter | [`a_false_objection_costs_the_challenger_its_bond`] |
//! | a challenger who stops answering forfeits | [`a_challenger_who_stops_answering_forfeits`] |
//! | a bond is locked while the dispute is live | [`a_live_bond_cannot_be_staked_twice`] |
//! | an objection nobody could adjudicate is refused | [`a_challenge_needs_something_it_can_be_settled_against`] |
//! | a party cannot play a state it never committed to | [`a_move_outside_the_committed_root_is_refused`] |
//! | the audit re-derives every one of these rules | [`the_audit_names_a_dispute_that_should_never_have_been_admitted`] |
//!
//! The last one is the load-bearing test in this file, and the reason is the
//! repository's characteristic failure: a rule enforced only at admission and
//! not re-derivable by the audit is a rule a log imported from a peer does not
//! have. Removing an audit check here must break a named test.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use cairn::canonical::Value;
use cairn::challenge::{Side, Trace};
use cairn::crypto::identity::Identity;
use cairn::ledger::Ledger;
use cairn::node::{DisputeState, Node, RuleViolation};
use cairn::records::{BisectionMove, Challenge, Claim, Commitment, Issuance, Objective};
use cairn::verifiers::VerifierRegistry;

const START: i128 = 27;
const STATES: usize = 33;

const COMMIT_AT: &str = "2026-07-28T00:00:00+00:00";
const REVEAL_AT: &str = "2026-07-28T00:20:00+00:00";
const CHALLENGE_AT: &str = "2026-07-28T00:30:00+00:00";
const MOVE_AT: &str = "2026-07-28T00:40:00+00:00";
/// Well past `CHALLENGE_WINDOW_EPOCHS` (6) from `MOVE_AT`, so a forfeit is due.
const LATE_AT: &str = "2026-07-28T02:00:00+00:00";

/// The pinned stepper, and a checker that accepts anything shaped like a
/// submission. The checker is deliberately permissive: this file is about the
/// *dispute*, and a checker that rejected the forged artifact would settle the
/// question before a dispute could start.
const CHECKER: &str = r#"
def check(artifact):
    return isinstance(artifact.get("trace_root"), str)
"#;

const STEPPER: &str = r#"
def step(state):
    n = state.get("n")
    i = state.get("i", 0)
    if isinstance(n, bool) or not isinstance(n, int):
        return {"halted": "n is not an integer", "i": i + 1, "n": 0}
    if n == 1:
        return {"n": 1, "i": i + 1}
    return {"n": n // 2 if n % 2 == 0 else 3 * n + 1, "i": i + 1}
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
            "proofwork-fraud-{label}-{unique}-{}",
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

fn state(n: i128, i: i128) -> Value {
    Value::object([("i", Value::Int(i)), ("n", Value::Int(n))])
}

/// The honest trajectory, computed in-process so a fixture needs no subprocess.
fn honest() -> Vec<Value> {
    let mut out = vec![state(START, 0)];
    let mut current = START;
    for i in 1..STATES {
        current = if current == 1 {
            1
        } else if current % 2 == 0 {
            current / 2
        } else {
            3 * current + 1
        };
        out.push(state(current, i as i128));
    }
    out
}

/// Honest up to `lie_at`, then wrong all the way to the end. The divergence
/// must persist: two traces that rejoin end on the same state, and a dispute
/// over them is refused because the challenger has contradicted nothing.
fn forged(lie_at: usize) -> Vec<Value> {
    let mut out = honest();
    for (index, item) in out.iter_mut().enumerate().skip(lie_at) {
        let n = item.get("n").and_then(Value::as_i128).unwrap_or(0);
        *item = state(n + 1, index as i128);
    }
    out
}

fn artifact(trace: &Trace) -> Value {
    Value::object([
        ("n", Value::Int(START)),
        ("trace_root", Value::string(trace.root())),
        ("trace_states", Value::Int(trace.len() as i128)),
    ])
}

struct Network {
    _dir: TempDir,
    node: Node,
    objective: Objective,
    alice: Identity,
    bob: Identity,
}

/// An objective with a stepper, a declared supply, and two funded identities.
///
/// The supply matters: without an `issuance` record the escrow rules are off,
/// so a bond costs nothing and the mechanism this file tests is not running.
fn network(label: &str) -> Network {
    let dir = TempDir::new(label);
    fs::write(dir.path.join("c.py"), CHECKER).expect("writable");
    fs::write(dir.path.join("s.py"), STEPPER).expect("writable");
    let sha = |text: &str| {
        let mut hasher = Sha256::new();
        hasher.update(text.as_bytes());
        cairn::hex::encode(&hasher.finalize())
    };

    let ledger = Ledger::open(dir.path.join("log.jsonl")).expect("an empty log");
    let mut node = Node::with_registry(ledger, VerifierRegistry::new(&dir.path));

    let alice = Identity::from_secret_bytes([7u8; 32]);
    let bob = Identity::from_secret_bytes([9u8; 32]);
    let treasury = Identity::from_secret_bytes([0u8; 32]);
    // Genesis first: issuance is admissible only in the genesis prefix.
    for (who, units) in [
        (alice.submitter_id(), 5_000_000u64),
        (bob.submitter_id(), 5_000_000),
        (treasury.submitter_id(), 5_000_000),
    ] {
        node.post_issuance(&Issuance::new(who, units, COMMIT_AT), COMMIT_AT)
            .expect("genesis issuance");
    }

    let objective = Objective::new(
        "G",
        "commit to a Collatz trajectory",
        Value::object([
            ("kind", Value::string("certificate")),
            ("checker", Value::string("c.py")),
            ("checker_sha256", Value::string(sha(CHECKER))),
            ("entrypoint", Value::string("check")),
            (
                "stepper",
                Value::object([
                    ("code", Value::string("s.py")),
                    ("code_sha256", Value::string(sha(STEPPER))),
                    ("entrypoint", Value::string("step")),
                ]),
            ),
        ]),
        1000,
        treasury.submitter_id(),
        COMMIT_AT,
        None,
        None,
    )
    .expect("valid objective")
    .funded_by(&treasury);
    node.post_objective(&objective, COMMIT_AT).expect("post");
    Network {
        _dir: dir,
        node,
        objective,
        alice,
        bob,
    }
}

/// Submit through commit–reveal, signed. Returns the claim id.
fn submit(net: &mut Network, who: &Identity, artifact: &Value, nonce: &str) -> String {
    let id = net.objective.id();
    let submitter = who.submitter_id();
    let commitment = Commitment::new(
        &id,
        &submitter,
        cairn::records::commitment_hash(&id, &submitter, artifact, nonce),
        COMMIT_AT,
    )
    .signed_with(who);
    net.node.commit(&commitment, COMMIT_AT).expect("commit");
    let claim = Claim::new(
        &id,
        &submitter,
        artifact.clone(),
        nonce,
        REVEAL_AT,
        Vec::new(),
    )
    .expect("valid claim")
    .signed_with(who);
    net.node.reveal(&claim, REVEAL_AT).expect("reveal");
    claim.id()
}

fn open_challenge(
    net: &mut Network,
    who: &Identity,
    claim_id: &str,
    trace: &Trace,
    bond: u64,
) -> String {
    let challenge = Challenge::new(
        claim_id,
        who.submitter_id(),
        trace.root(),
        trace.len() as u64,
        bond,
        CHALLENGE_AT,
    )
    .signed_with(who);
    net.node
        .post_challenge(&challenge, CHALLENGE_AT)
        .expect("a well-formed objection")
}

fn play(net: &mut Network, who: &Identity, id: &str, trace: &Trace, index: usize, ts: &str) {
    let mv = trace.open(id, index).expect("in range");
    let record = BisectionMove::new(
        id,
        who.submitter_id(),
        index as u64,
        mv.state.clone(),
        mv.path.siblings.clone(),
        ts,
    )
    .signed_with(who);
    net.node
        .post_bisection(&record, ts)
        .unwrap_or_else(|why| panic!("move at {index}: {why}"));
}

/// Run the whole dispute to the point where it can be settled.
///
/// Endpoints first, then every round the log itself asks for — nothing here
/// knows the search order in advance, which is the point: the transcript is the
/// state, and a party reads what it owes out of the log.
fn play_out(net: &mut Network, id: &str, defence: &Trace, objection: &Trace) {
    let (alice, bob) = (net.alice.clone(), net.bob.clone());
    let last = defence.len() - 1;
    for index in [0, last] {
        play(net, &alice, id, defence, index, MOVE_AT);
        play(net, &bob, id, objection, index, MOVE_AT);
    }
    for _ in 0..64 {
        let Some(DisputeState::Live { dispute, .. }) = net.node.dispute(id) else {
            break;
        };
        let cairn::challenge::Next::Open { index, waiting_on } = dispute.next() else {
            break;
        };
        for side in waiting_on {
            match side {
                Side::Defender => play(net, &alice, id, defence, index, MOVE_AT),
                Side::Challenger => play(net, &bob, id, objection, index, MOVE_AT),
            }
        }
    }
}

fn balance(net: &Node, who: &Identity) -> u128 {
    net.balances()
        .get(&who.submitter_id())
        .copied()
        .unwrap_or(0)
}

// -- the tests -------------------------------------------------------------

/// Alice commits to a forged trajectory. Bob objects with the honest one, they
/// bisect, one step decides it, and Alice pays.
#[test]
fn a_forged_trace_loses_its_bond_to_the_challenger() {
    if !have_python() {
        eprintln!("skipping: no python3");
        return;
    }
    let mut net = network("liar");
    let (alice, bob) = (net.alice.clone(), net.bob.clone());
    let lie = Trace::commit(forged(11)).expect("a trace");
    let truth = Trace::commit(honest()).expect("a trace");
    let claim = submit(&mut net, &alice, &artifact(&lie), "n-1");

    let before = balance(&net.node, &net.bob);
    let id = open_challenge(&mut net, &bob, &claim, &truth, 500);
    play_out(&mut net, &id, &lie, &truth);

    let outcome = net
        .node
        .settle_challenge(&id, MOVE_AT)
        .expect("the dispute is adjudicable");
    assert_eq!(
        outcome.get("winning_side").and_then(Value::as_str),
        Some("challenger"),
        "{outcome:?}"
    );
    assert_eq!(
        outcome.get("winner").and_then(Value::as_str),
        Some(net.bob.submitter_id().as_str())
    );
    // Bob's bond is released and he is paid out of Alice's balance.
    let moved = outcome.get("units").and_then(Value::as_i128).unwrap_or(0) as u128;
    assert!(moved > 0, "a won dispute moved nothing");
    assert_eq!(balance(&net.node, &net.bob), before + moved);

    assert!(
        net.node.audit(true).is_empty(),
        "{:?}",
        net.node.audit(true)
    );
}

/// Bob objects to an honest trace and is wrong. His bond goes to Alice.
#[test]
fn a_false_objection_costs_the_challenger_its_bond() {
    if !have_python() {
        eprintln!("skipping: no python3");
        return;
    }
    let mut net = network("false");
    let (alice, bob) = (net.alice.clone(), net.bob.clone());
    let truth = Trace::commit(honest()).expect("a trace");
    let lie = Trace::commit(forged(20)).expect("a trace");
    let claim = submit(&mut net, &alice, &artifact(&truth), "n-1");

    let alice_before = balance(&net.node, &net.alice);
    let bob_before = balance(&net.node, &net.bob);
    let id = open_challenge(&mut net, &bob, &claim, &lie, 500);
    // Bonding is not free: the bond is committed the moment the objection is.
    assert_eq!(balance(&net.node, &net.bob), bob_before - 500);

    play_out(&mut net, &id, &truth, &lie);
    let outcome = net
        .node
        .settle_challenge(&id, MOVE_AT)
        .expect("the dispute is adjudicable");
    assert_eq!(
        outcome.get("winning_side").and_then(Value::as_str),
        Some("defender"),
        "{outcome:?}"
    );
    assert_eq!(outcome.get("units").and_then(Value::as_i128), Some(500));
    assert_eq!(balance(&net.node, &net.alice), alice_before + 500);
    assert_eq!(balance(&net.node, &net.bob), bob_before - 500);
    assert!(
        net.node.audit(true).is_empty(),
        "{:?}",
        net.node.audit(true)
    );
}

/// A liar's dominant strategy against any interactive protocol is to play until
/// the search reaches the step where they lied, and then stop. Silence loses.
#[test]
fn a_challenger_who_stops_answering_forfeits() {
    if !have_python() {
        eprintln!("skipping: no python3");
        return;
    }
    let mut net = network("silent");
    let (alice, bob) = (net.alice.clone(), net.bob.clone());
    let truth = Trace::commit(honest()).expect("a trace");
    let lie = Trace::commit(forged(20)).expect("a trace");
    let claim = submit(&mut net, &alice, &artifact(&truth), "n-1");
    let id = open_challenge(&mut net, &bob, &claim, &lie, 500);

    // Endpoints, then Alice answers the first query and Bob goes quiet.
    let last = truth.len() - 1;
    for index in [0, last] {
        play(&mut net, &alice, &id, &truth, index, MOVE_AT);
        play(&mut net, &bob, &id, &lie, index, MOVE_AT);
    }
    let Some(DisputeState::Live { dispute, .. }) = net.node.dispute(&id) else {
        panic!("expected a live dispute");
    };
    let cairn::challenge::Next::Open { index, .. } = dispute.next() else {
        panic!("expected a query");
    };
    play(&mut net, &alice, &id, &truth, index, MOVE_AT);

    // Inside the window, nobody has forfeited yet.
    assert!(matches!(
        net.node.settle_challenge(&id, MOVE_AT),
        Err(RuleViolation::ChallengeStillOpen { .. })
    ));

    let outcome = net
        .node
        .settle_challenge(&id, LATE_AT)
        .expect("the window has shut on the silent party");
    assert_eq!(
        outcome.get("winning_side").and_then(Value::as_str),
        Some("defender")
    );
    assert!(
        outcome
            .get("detail")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .contains("stopped answering"),
        "{outcome:?}"
    );
    assert!(
        net.node.audit(true).is_empty(),
        "{:?}",
        net.node.audit(true)
    );
}

/// A bond behind a live dispute is spent-but-not-gone. Without that, one
/// balance funds an unlimited number of simultaneous objections.
#[test]
fn a_live_bond_cannot_be_staked_twice() {
    if !have_python() {
        eprintln!("skipping: no python3");
        return;
    }
    let mut net = network("locked");
    let (alice, bob) = (net.alice.clone(), net.bob.clone());
    let truth = Trace::commit(honest()).expect("a trace");
    let lie = Trace::commit(forged(9)).expect("a trace");
    let claim_a = submit(&mut net, &alice, &artifact(&truth), "n-1");
    let claim_b = submit(&mut net, &alice, &artifact(&lie), "n-2");

    let whole = balance(&net.node, &net.bob);
    open_challenge(&mut net, &bob, &claim_a, &lie, whole as u64);
    assert_eq!(balance(&net.node, &net.bob), 0, "the bond was not locked");

    // The second objection is for money that is already at risk.
    let second = Challenge::new(
        &claim_b,
        net.bob.submitter_id(),
        truth.root(),
        truth.len() as u64,
        1,
        CHALLENGE_AT,
    )
    .signed_with(&net.bob);
    assert!(
        matches!(
            net.node.post_challenge(&second, CHALLENGE_AT),
            Err(RuleViolation::UnfundedReward { .. })
        ),
        "a locked bond was spendable again"
    );
}

/// An objection that could never be settled is refused before it locks
/// anything, because a bond held over an unadjudicable dispute is a griefing
/// tool rather than a mechanism.
#[test]
fn a_challenge_needs_something_it_can_be_settled_against() {
    if !have_python() {
        eprintln!("skipping: no python3");
        return;
    }
    let mut net = network("refuse");
    let (alice, bob) = (net.alice.clone(), net.bob.clone());
    let truth = Trace::commit(honest()).expect("a trace");
    let lie = Trace::commit(forged(11)).expect("a trace");
    let claim = submit(&mut net, &alice, &artifact(&truth), "n-1");

    // Agreement is not a dispute.
    let agrees = Challenge::new(
        &claim,
        net.bob.submitter_id(),
        truth.root(),
        truth.len() as u64,
        10,
        CHALLENGE_AT,
    )
    .signed_with(&net.bob);
    assert!(matches!(
        net.node.post_challenge(&agrees, CHALLENGE_AT),
        Err(RuleViolation::ChallengeAgrees { .. })
    ));

    // A different length is a disagreement that is already public.
    let shorter = Challenge::new(
        &claim,
        net.bob.submitter_id(),
        lie.root(),
        (truth.len() - 1) as u64,
        10,
        CHALLENGE_AT,
    )
    .signed_with(&net.bob);
    assert!(matches!(
        net.node.post_challenge(&shorter, CHALLENGE_AT),
        Err(RuleViolation::TraceLengthMismatch { .. })
    ));

    // And an objection that arrives after the window shut.
    let late = Challenge::new(
        &claim,
        net.bob.submitter_id(),
        lie.root(),
        lie.len() as u64,
        10,
        LATE_AT,
    )
    .signed_with(&net.bob);
    assert!(matches!(
        net.node.post_challenge(&late, LATE_AT),
        Err(RuleViolation::ChallengeWindowClosed { .. })
    ));

    // One live objection per challenger per claim.
    let id = open_challenge(&mut net, &bob, &claim, &lie, 10);
    assert!(!id.is_empty());
    let again = Challenge::new(
        &claim,
        net.bob.submitter_id(),
        Trace::commit(forged(12)).expect("a trace").root(),
        truth.len() as u64,
        10,
        CHALLENGE_AT,
    )
    .signed_with(&net.bob);
    assert!(matches!(
        net.node.post_challenge(&again, CHALLENGE_AT),
        Err(RuleViolation::DuplicateChallenge { .. })
    ));
}

/// The single most important check in the game, at the record layer: a party
/// that could answer with a state it never committed to would win every dispute
/// by playing whatever beats the other side this round.
#[test]
fn a_move_outside_the_committed_root_is_refused() {
    if !have_python() {
        eprintln!("skipping: no python3");
        return;
    }
    let mut net = network("forge");
    let (alice, bob) = (net.alice.clone(), net.bob.clone());
    let truth = Trace::commit(honest()).expect("a trace");
    let lie = Trace::commit(forged(11)).expect("a trace");
    let claim = submit(&mut net, &alice, &artifact(&truth), "n-1");
    let id = open_challenge(&mut net, &bob, &claim, &lie, 500);

    // Alice answers with Bob's state: well formed, a real path, wrong tree.
    let borrowed = lie.open(&id, 0).expect("in range");
    let forgery = BisectionMove::new(
        &id,
        net.alice.submitter_id(),
        0,
        borrowed.state.clone(),
        borrowed.path.siblings.clone(),
        MOVE_AT,
    )
    .signed_with(&net.alice);
    assert!(matches!(
        net.node.post_bisection(&forgery, MOVE_AT),
        Err(RuleViolation::MoveNotUnderRoot { .. })
    ));

    // A stranger is not a party at all.
    let stranger = Identity::from_secret_bytes([3u8; 32]);
    let outsider = BisectionMove::new(
        &id,
        stranger.submitter_id(),
        0,
        borrowed.state.clone(),
        borrowed.path.siblings.clone(),
        MOVE_AT,
    )
    .signed_with(&stranger);
    assert!(matches!(
        net.node.post_bisection(&outsider, MOVE_AT),
        Err(RuleViolation::NotAParty { .. })
    ));

    // And a well-formed answer to a question the game did not ask.
    let elsewhere = truth.open(&id, 7).expect("in range");
    let out_of_turn = BisectionMove::new(
        &id,
        net.alice.submitter_id(),
        7,
        elsewhere.state.clone(),
        elsewhere.path.siblings.clone(),
        MOVE_AT,
    )
    .signed_with(&net.alice);
    assert!(matches!(
        net.node.post_bisection(&out_of_turn, MOVE_AT),
        Err(RuleViolation::MoveOutOfTurn { .. })
    ));
}

/// The audit re-derives the dispute rules rather than trusting the writer that
/// applied them.
///
/// A log can arrive from a peer, a queue, or a text editor, so a rule that
/// lives only in `post_challenge` is a rule an imported log does not have. This
/// module has been caught by exactly that twice; the injection here is what
/// keeps the audit's copy load-bearing.
#[test]
fn the_audit_names_a_dispute_that_should_never_have_been_admitted() {
    if !have_python() {
        eprintln!("skipping: no python3");
        return;
    }
    let mut net = network("audit");
    let alice = net.alice.clone();
    let truth = Trace::commit(honest()).expect("a trace");
    let claim = submit(&mut net, &alice, &artifact(&truth), "n-1");
    assert!(net.node.audit(true).is_empty());

    // Append a challenge that agrees with the claim it disputes, going in at
    // the ledger because `post_challenge` refuses it -- which is the point.
    let sneaked = Challenge::new(
        &claim,
        net.bob.submitter_id(),
        truth.root(),
        truth.len() as u64,
        10,
        CHALLENGE_AT,
    )
    .signed_with(&net.bob);
    net.node
        .ledger_mut()
        .append("challenge", sneaked.to_value(), CHALLENGE_AT)
        .expect("the log accepts an appended record");

    let problems = net.node.audit(true);
    assert!(
        problems.iter().any(|p| p.contains("agrees with the claim")),
        "the audit did not name the challenge: {problems:?}"
    );
}

/// A dispute nobody plays resolves against the challenger.
///
/// Found by `src/arena` playing a griefer that opened bonded objections and
/// then did nothing at all. At the very start of a dispute *both* sides owe
/// their opening endpoints, so `overdue` named nobody, no forfeit was ever due,
/// and the challenge stayed open forever with the bond locked and no outcome —
/// a defender who wanted the matter closed could not close it, and a griefer
/// got an indefinite open case for the price of a bond it never actually lost.
///
/// The burden of prosecution is the challenger's: they opened the objection, so
/// if they have made no move at all by the time the window has run, they
/// forfeit whatever the defender has or has not done.
#[test]
fn a_dispute_neither_side_plays_resolves_against_the_challenger() {
    if !have_python() {
        eprintln!("skipping: no python3");
        return;
    }
    let mut net = network("unplayed");
    let (alice, bob) = (net.alice.clone(), net.bob.clone());
    let truth = Trace::commit(honest()).expect("a trace");
    let lie = Trace::commit(forged(11)).expect("a trace");
    let claim = submit(&mut net, &alice, &artifact(&truth), "n-1");
    let id = open_challenge(&mut net, &bob, &claim, &lie, 500);

    // Nobody moves. Not one endpoint, from either side.
    assert!(matches!(
        net.node.settle_challenge(&id, MOVE_AT),
        Err(RuleViolation::ChallengeStillOpen { .. })
    ));

    let outcome = net
        .node
        .settle_challenge(&id, LATE_AT)
        .expect("an unprosecuted dispute closes once its window has run");
    assert_eq!(
        outcome.get("winning_side").and_then(Value::as_str),
        Some("defender"),
        "an objection nobody prosecuted was not decided against its author"
    );
    assert_eq!(outcome.get("units").and_then(Value::as_i128), Some(500));
    assert!(
        net.node.audit(true).is_empty(),
        "{:?}",
        net.node.audit(true)
    );
}
