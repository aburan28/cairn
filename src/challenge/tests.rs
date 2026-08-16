//! The bisection game, executed rather than argued.
//!
//! Two properties carry the whole mechanism, and neither is obvious enough to
//! take on faith:
//!
//! 1. **The search always finds the *first* divergence.** Not any divergence —
//!    the first. Adjudicating a later one would run a step from a state the
//!    parties agreed on but which is already downstream of the lie, and the
//!    liar's own bad state would reproduce correctly from it. `a_liar_loses`
//!    sweeps every position a lie can occupy and confirms the search lands on
//!    it every time.
//! 2. **Neither party can win by lying during the game.** Bisection is
//!    interactive, so a losing party's obvious move is to answer with whatever
//!    state wins the round. Every move is checked against the root its author
//!    committed to before the game began, which is what makes that impossible.

use super::*;
use crate::canonical::Value;
use crate::verifiers::VerifierRegistry;
use std::path::PathBuf;
use std::time::Instant;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn registry() -> VerifierRegistry {
    VerifierRegistry::new(repo_root())
}

fn spec() -> Value {
    let text =
        std::fs::read_to_string(repo_root().join("examples/collatz_bisectable/objective.json"))
            .expect("the bisectable example exists");
    Value::from_json(&text)
        .expect("valid json")
        .get("verifier")
        .expect("a verifier")
        .clone()
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

/// The honest trajectory of `n`, as the stepper would produce it, computed here
/// so the pure tests need no subprocess.
fn honest(n: i128, steps: usize) -> Vec<Value> {
    let mut out = vec![state(n, 0)];
    let mut current = n;
    for i in 0..steps {
        current = if current == 1 {
            1
        } else if current % 2 == 0 {
            current / 2
        } else {
            3 * current + 1
        };
        out.push(state(current, i as i128 + 1));
    }
    out
}

/// A trace identical to `truth` up to `lie_at`, then wrong from there on.
///
/// Wrong *from there on*, not wrong at one index: a liar who diverges and then
/// rejoins the truth is not what the mechanism is up against, and testing
/// against that easier case would flatter it.
fn forged(truth: &[Value], lie_at: usize) -> Vec<Value> {
    forged_by(truth, lie_at, 1)
}

/// The same, with a chosen offset, so two *different* forgeries of one truth
/// can be played against each other.
fn forged_by(truth: &[Value], lie_at: usize, delta: i128) -> Vec<Value> {
    let mut out = truth.to_vec();
    for (offset, item) in out.iter_mut().enumerate().skip(lie_at) {
        let n = item.get("n").and_then(Value::as_i128).unwrap_or(0);
        *item = state(n + delta, offset as i128);
    }
    out
}

/// Play a whole dispute between two traces, without a stepper.
///
/// Returns the dispute once the search has narrowed. This is the pure half of
/// the mechanism and it is the half that has to be exactly right.
fn bisect(defender: &Trace, challenger: &Trace) -> (Dispute, usize) {
    let mut dispute = Dispute::between("d1", defender, challenger).expect("a well-founded dispute");
    let mut rounds = 0;
    loop {
        match dispute.next() {
            Next::Open { index, .. } => {
                rounds += 1;
                let d = defender.open("d1", index).expect("in range");
                let c = challenger.open("d1", index).expect("in range");
                dispute.play(Side::Defender, &d).expect("a legal move");
                dispute.play(Side::Challenger, &c).expect("a legal move");
            }
            Next::Adjudicate { .. } => break,
            Next::Done(_) => break,
        }
        assert!(rounds < 64, "the search did not converge");
    }
    (dispute, rounds)
}

// -- the search itself -----------------------------------------------------

/// The search lands on the *first* divergence, wherever it is.
///
/// The sweep is the test. A bisection that lands on *a* divergence looks
/// correct on any single example — the interesting failures are all at the
/// ends, where a lie in the first step or the last one makes the interval
/// arithmetic degenerate.
#[test]
fn the_search_finds_the_first_divergence_wherever_it_is() {
    let truth = honest(27, 32);
    let defender = Trace::commit(truth.clone()).expect("a trace");
    for lie_at in 1..truth.len() {
        let challenger = Trace::commit(forged(&truth, lie_at)).expect("a trace");
        let (dispute, _) = bisect(&defender, &challenger);
        let (lo, hi) = dispute.interval();
        assert_eq!(
            (lo, hi),
            (lie_at - 1, lie_at),
            "a lie first told at state {lie_at} narrowed to {lo}..{hi}"
        );
        // And the state they agreed on really is the honest one, so the step
        // taken from it is the step that was actually in dispute.
        assert_eq!(dispute.agreed_state(lo), Some(&truth[lo]));
    }
}

/// Never more than `⌈log₂(states - 1)⌉` rounds, and that bound is reached.
///
/// Two assertions, because one of them alone is worthless. The bound is what
/// makes a dispute affordable to carry on an append-only log, so no lie
/// position may exceed it — and a bound nothing attains would be satisfied by
/// a search that always terminated in one round on the wrong answer, so it must
/// also be *tight*. The sweep runs every lie position at every length.
#[test]
fn the_search_costs_a_logarithmic_number_of_rounds() {
    for states in 2..80usize {
        let truth = honest(27, states - 1);
        let defender = Trace::commit(truth.clone()).expect("a trace");
        let bound = Dispute::rounds_needed(states);
        let mut worst = 0;
        for lie_at in 1..states {
            let challenger = Trace::commit(forged(&truth, lie_at)).expect("a trace");
            let (_, rounds) = bisect(&defender, &challenger);
            assert!(
                rounds as u32 <= bound,
                "{states} states, lie at {lie_at}: {rounds} rounds exceeds {bound}"
            );
            worst = worst.max(rounds as u32);
        }
        assert_eq!(worst, bound, "{states} states never reached its own bound");
    }
    // The numbers, so a change to the arithmetic has to edit this line.
    assert_eq!(Dispute::rounds_needed(2), 0);
    assert_eq!(Dispute::rounds_needed(3), 1);
    assert_eq!(Dispute::rounds_needed(9), 3);
    assert_eq!(Dispute::rounds_needed(1025), 10);
}

/// A million-state trace is 20 rounds. This is the mechanism's entire reason
/// for existing, stated as a number.
#[test]
fn a_long_trace_is_still_a_short_dispute() {
    assert_eq!(Dispute::rounds_needed(1_000_001), 20);
    // The cap is 2^24 states, so the longest dispute this module will ever
    // carry is 24 rounds -- 48 records, whoever is lying and wherever.
    assert_eq!(Dispute::rounds_needed(MAX_TRACE), 24);
}

// -- lying during the game -------------------------------------------------

/// A party cannot answer with a state it did not commit to.
///
/// Without this the game is worthless: the losing side simply plays whichever
/// state wins the current round, and the search converges on nothing.
#[test]
fn a_move_that_does_not_open_the_committed_root_is_refused() {
    let truth = honest(27, 16);
    let defender = Trace::commit(truth.clone()).expect("a trace");
    let challenger = Trace::commit(forged(&truth, 5)).expect("a trace");
    let mut dispute =
        Dispute::between("d1", &defender, &challenger).expect("a well-founded dispute");

    let Next::Open { index, .. } = dispute.next() else {
        panic!("expected a query");
    };

    // The defender tries to answer with the challenger's state — which exists,
    // is well-formed, and even carries a valid path, just against the wrong
    // root.
    let borrowed = challenger.open("d1", index).expect("in range");
    assert_eq!(
        dispute.play(Side::Defender, &borrowed),
        Err(DisputeError::NotUnderRoot {
            side: Side::Defender
        })
    );

    // And an invented state with a real path from elsewhere in its own tree.
    let mut forgery = defender.open("d1", index).expect("in range");
    forgery.state = state(999_999, index as i128);
    assert_eq!(
        dispute.play(Side::Defender, &forgery),
        Err(DisputeError::NotUnderRoot {
            side: Side::Defender
        })
    );

    // The honest move is accepted.
    let honest_move = defender.open("d1", index).expect("in range");
    assert_eq!(dispute.play(Side::Defender, &honest_move), Ok(()));
}

/// Answering a question the game did not ask is refused.
///
/// The stall that looks like cooperation: keep publishing well-formed moves at
/// indices nobody asked about, and the window never advances.
#[test]
fn answering_a_different_index_is_refused() {
    let truth = honest(27, 16);
    let defender = Trace::commit(truth.clone()).expect("a trace");
    let challenger = Trace::commit(forged(&truth, 5)).expect("a trace");
    let mut dispute =
        Dispute::between("d1", &defender, &challenger).expect("a well-founded dispute");
    let Next::Open { index, .. } = dispute.next() else {
        panic!("expected a query");
    };
    let elsewhere = defender.open("d1", index + 1).expect("in range");
    assert_eq!(
        dispute.play(Side::Defender, &elsewhere),
        Err(DisputeError::WrongIndex {
            asked: index,
            answered: index + 1
        })
    );
}

/// Answering twice does not move the interval twice.
#[test]
fn a_side_cannot_answer_the_same_round_twice() {
    let truth = honest(27, 16);
    let defender = Trace::commit(truth.clone()).expect("a trace");
    let challenger = Trace::commit(forged(&truth, 5)).expect("a trace");
    let mut dispute =
        Dispute::between("d1", &defender, &challenger).expect("a well-founded dispute");
    let Next::Open { index, .. } = dispute.next() else {
        panic!("expected a query");
    };
    let mv = defender.open("d1", index).expect("in range");
    assert_eq!(dispute.play(Side::Defender, &mv), Ok(()));
    assert_eq!(
        dispute.play(Side::Defender, &mv),
        Err(DisputeError::AlreadyMoved {
            side: Side::Defender,
            index
        })
    );
    assert_eq!(
        dispute.interval(),
        (0, defender.len() - 1),
        "the interval moved on one answer"
    );
}

/// A round is only complete when both sides have answered, and the order does
/// not change the result.
#[test]
fn the_order_of_the_two_answers_does_not_matter() {
    let truth = honest(27, 16);
    let defender = Trace::commit(truth.clone()).expect("a trace");
    let challenger = Trace::commit(forged(&truth, 5)).expect("a trace");
    let play = |first: Side| {
        let mut dispute =
            Dispute::between("d1", &defender, &challenger).expect("a well-founded dispute");
        while let Next::Open { index, .. } = dispute.next() {
            let moves = [
                (
                    Side::Defender,
                    defender.open("d1", index).expect("in range"),
                ),
                (
                    Side::Challenger,
                    challenger.open("d1", index).expect("in range"),
                ),
            ];
            for (side, mv) in moves.iter().filter(|(side, _)| *side == first) {
                dispute.play(*side, mv).expect("legal");
            }
            for (side, mv) in moves.iter().filter(|(side, _)| *side != first) {
                dispute.play(*side, mv).expect("legal");
            }
        }
        dispute.interval()
    };
    assert_eq!(play(Side::Defender), play(Side::Challenger));
    assert_eq!(play(Side::Defender), (4, 5));
}

/// Two identical traces cannot be disputed. Opening one anyway would let a
/// griefer bond-lock an honest submitter over nothing.
#[test]
fn there_is_nothing_to_bisect_when_both_sides_agree() {
    let truth = honest(27, 8);
    let trace = Trace::commit(truth).expect("a trace");
    assert_eq!(
        Dispute::between("d1", &trace, &trace),
        Err(DisputeError::Agreed)
    );
}

#[test]
fn a_trace_with_no_step_is_not_a_trace() {
    assert_eq!(Trace::commit(vec![]), Err(TraceError::TooShort(0)));
    assert_eq!(
        Trace::commit(vec![state(1, 0)]),
        Err(TraceError::TooShort(1))
    );
    assert!(Trace::commit(vec![state(1, 0), state(1, 1)]).is_ok());
}

/// Silence loses, and it has to: a liar's dominant strategy is to answer until
/// the search reaches the step where they lied, and then stop.
#[test]
fn a_side_that_stops_answering_loses() {
    let truth = honest(27, 16);
    let defender = Trace::commit(truth.clone()).expect("a trace");
    let challenger = Trace::commit(forged(&truth, 5)).expect("a trace");
    let mut dispute =
        Dispute::between("d1", &defender, &challenger).expect("a well-founded dispute");
    let Next::Open { index, waiting_on } = dispute.next() else {
        panic!("expected a query");
    };
    assert_eq!(waiting_on, vec![Side::Defender, Side::Challenger]);
    dispute
        .play(Side::Challenger, &challenger.open("d1", index).expect("ok"))
        .expect("legal");
    let Next::Open { waiting_on, .. } = dispute.next() else {
        panic!("expected the same query");
    };
    assert_eq!(waiting_on, vec![Side::Defender], "the debt is attributable");

    let outcome = dispute
        .forfeit(Side::Defender)
        .expect("not yet decided")
        .clone();
    assert_eq!(outcome.winner(), Side::Challenger);
    assert_eq!(
        dispute.forfeit(Side::Challenger),
        Err(DisputeError::Finished)
    );
}

// -- adjudication ----------------------------------------------------------

/// A dispute that has not narrowed cannot be adjudicated, so nobody settles a
/// dispute early by pointing a stepper at the wrong interval.
#[test]
fn adjudicating_before_the_search_ends_is_refused() {
    if !have_python() {
        eprintln!("skipping: no python3");
        return;
    }
    let registry = registry();
    let stepper = Stepper::from_spec(&registry, &spec()).expect("a stepper");
    let truth = honest(27, 16);
    let defender = Trace::commit(truth.clone()).expect("a trace");
    let challenger = Trace::commit(forged(&truth, 5)).expect("a trace");
    let mut dispute =
        Dispute::between("d1", &defender, &challenger).expect("a well-founded dispute");
    assert_eq!(
        dispute.adjudicate(&stepper),
        Err(AdjudicationError::NotNarrowed((0, 16)))
    );
}

/// The whole mechanism, against the real pinned stepper: a liar loses wherever
/// they lie, and one step of execution is what decides it.
#[test]
fn a_liar_loses_wherever_the_lie_is() {
    if !have_python() {
        eprintln!("skipping: no python3");
        return;
    }
    let registry = registry();
    let stepper = Stepper::from_spec(&registry, &spec()).expect("a stepper");
    let truth = Trace::run(&stepper, state(27, 0), 16).expect("the stepper runs");

    for lie_at in 1..truth.len() {
        let states: Vec<Value> = (0..truth.len())
            .map(|i| truth.state_at(i).expect("in range").clone())
            .collect();
        let liar = Trace::commit(forged(&states, lie_at)).expect("a trace");

        // The liar defends; the honest party challenges.
        let (mut dispute, _) = bisect(&liar, &truth);
        let outcome = dispute.adjudicate(&stepper).expect("adjudicable").clone();
        assert_eq!(
            outcome.winner(),
            Side::Challenger,
            "a lie at state {lie_at} was not caught: {outcome}"
        );

        // And symmetrically: an honest defender beats a false challenger.
        let (mut dispute, _) = bisect(&truth, &liar);
        let outcome = dispute.adjudicate(&stepper).expect("adjudicable").clone();
        assert_eq!(
            outcome.winner(),
            Side::Defender,
            "an honest trace lost to a forgery at state {lie_at}: {outcome}"
        );
    }
}

/// The claim the module is built on, measured: settling a dispute costs one
/// step whatever the trace length, while re-running costs the whole trace.
#[test]
fn a_dispute_settles_in_one_step_however_long_the_trace_is() {
    if !have_python() {
        eprintln!("skipping: no python3");
        return;
    }
    let registry = registry();
    let stepper = Stepper::from_spec(&registry, &spec()).expect("a stepper");

    // Built in-process rather than through the stepper: the point of the
    // measurement is the *adjudication*, and spawning 256 subprocesses to set
    // it up would say nothing about that.
    let truth = honest(27, 255);
    let defender = Trace::commit(truth.clone()).expect("a trace");
    let challenger = Trace::commit(forged(&truth, 200)).expect("a trace");

    let started = Instant::now();
    let (mut dispute, rounds) = bisect(&defender, &challenger);
    let searching = started.elapsed();

    let started = Instant::now();
    let outcome = dispute.adjudicate(&stepper).expect("adjudicable").clone();
    let adjudicating = started.elapsed();

    let started = Instant::now();
    let replayed = Trace::run(&stepper, truth[0].clone(), 255).expect("the stepper runs");
    let replaying = started.elapsed();
    assert_eq!(
        replayed.root(),
        defender.root(),
        "the honest trace reproduces"
    );

    assert_eq!(outcome.winner(), Side::Defender);
    eprintln!(
        "256 states: {rounds} rounds of search in {searching:?}, one step of \
         adjudication in {adjudicating:?}, full replay in {replaying:?}"
    );
    assert_eq!(rounds, 8, "256 states should be 8 rounds");
    // 255 steps against 1. The margin is deliberately loose -- a subprocess
    // spawn dominates a single step, so the ratio is well under 255 and the
    // assertion is that the *shape* is right, not that a CI machine hits a
    // number.
    assert!(
        replaying > adjudicating * 20,
        "adjudication was not dramatically cheaper than replay: \
         {adjudicating:?} against {replaying:?}"
    );
}

/// Both traces wrong at the disputed step: the challenger still wins.
///
/// The alternative — awarding it to the defender because the challenger is also
/// wrong — makes a false claim safe as long as nobody can produce a perfectly
/// correct refutation, which is a much harder thing to produce than a correct
/// *objection*.
#[test]
fn when_neither_state_reproduces_the_defence_still_fails() {
    if !have_python() {
        eprintln!("skipping: no python3");
        return;
    }
    let registry = registry();
    let stepper = Stepper::from_spec(&registry, &spec()).expect("a stepper");
    let truth = honest(27, 8);

    // Both wrong from state 5 onward, and differently wrong all the way to the
    // end. The divergence has to persist: two traces that diverge and rejoin
    // end on the same state, and `Dispute::open` refuses that outright, because
    // a challenger who arrives at the same answer by another route has
    // contradicted nothing.
    let defender = Trace::commit(forged_by(&truth, 5, 1_000)).expect("a trace");
    let challenger = Trace::commit(forged_by(&truth, 5, 2_000)).expect("a trace");
    let (mut dispute, _) = bisect(&defender, &challenger);
    assert_eq!(dispute.interval(), (4, 5));
    let outcome = dispute.adjudicate(&stepper).expect("adjudicable").clone();
    assert_eq!(outcome.winner(), Side::Challenger);
    assert!(
        format!("{outcome}").contains("neither"),
        "the reason should say so: {outcome}"
    );
}

// -- the stepper -----------------------------------------------------------

/// An objective without a stepper is simply not bisectable, and says so
/// distinguishably from a broken one.
#[test]
fn an_objective_with_no_stepper_is_not_bisectable() {
    let registry = registry();
    let plain = Value::object([("kind", Value::string("certificate"))]);
    assert!(!Stepper::declared(&plain));
    match Stepper::from_spec(&registry, &plain) {
        Err(StepError::NotBisectable(_)) => {}
        other => panic!("expected NotBisectable, got {other:?}"),
    }
}

#[test]
fn a_stepper_missing_a_field_is_reported_as_not_bisectable() {
    let registry = registry();
    let partial = Value::object([("stepper", Value::object([("code", Value::string("x.py"))]))]);
    assert!(Stepper::declared(&partial));
    match Stepper::from_spec(&registry, &partial) {
        Err(StepError::NotBisectable(why)) => assert!(why.contains("code_sha256"), "{why}"),
        other => panic!("expected NotBisectable, got {other:?}"),
    }
}

/// The pinned stepper describes the same computation the pinned checker does.
///
/// If it does not, every dispute settles the wrong way while every individual
/// piece looks correct — which is the failure mode with no other alarm on it.
#[test]
fn the_stepper_and_the_checker_agree_about_the_same_trajectory() {
    if !have_python() {
        eprintln!("skipping: no python3");
        return;
    }
    let registry = registry();
    let spec = spec();
    let stepper = Stepper::from_spec(&registry, &spec).expect("a stepper");

    // 27 reaches 1 in 111 steps; the checker's own `steps()` is the authority.
    let mut current = state(27, 0);
    let mut reached = None;
    for step in 1..=200 {
        current = stepper.step(&current).expect("the stepper runs");
        if current.get("n").and_then(Value::as_i128) == Some(1) && reached.is_none() {
            reached = Some(step);
        }
    }
    assert_eq!(reached, Some(111), "the stepper's trajectory length moved");

    // And 1 is absorbing, which is what lets a trace be padded to a fixed
    // length so two parties can commit to the same one.
    let after = stepper.step(&state(1, 7)).expect("the stepper runs");
    assert_eq!(after.get("n").and_then(Value::as_i128), Some(1));
}

/// A malformed state steps to a halted state rather than raising.
///
/// A stepper that raises hands the adjudicator `unavailable`, and a dispute
/// that cannot be adjudicated is exactly what a liar wants. So totality is a
/// property of the stepper contract, tested here against the shipped example.
#[test]
fn a_bad_state_halts_rather_than_making_the_dispute_unadjudicable() {
    if !have_python() {
        eprintln!("skipping: no python3");
        return;
    }
    let registry = registry();
    let stepper = Stepper::from_spec(&registry, &spec()).expect("a stepper");
    for bad in [
        Value::object([("i", Value::Int(0)), ("n", Value::string("twelve"))]),
        Value::object([("i", Value::Int(0)), ("n", Value::Int(0))]),
        Value::object([("i", Value::Int(0))]),
    ] {
        let next = stepper
            .step(&bad)
            .unwrap_or_else(|why| panic!("{bad:?}: {why}"));
        assert!(
            next.get("halted").is_some(),
            "{bad:?} did not halt, it stepped to {next:?}"
        );
    }
}

/// A tampered stepper never runs. The hash is checked before the subprocess
/// exists, the same as every other piece of objective-authored code.
#[test]
fn a_stepper_whose_hash_does_not_match_is_never_executed() {
    if !have_python() {
        eprintln!("skipping: no python3");
        return;
    }
    let registry = registry();
    let mut spec = spec();
    if let Value::Object(map) = &mut spec {
        let mut block = map.get("stepper").cloned().expect("a stepper");
        if let Value::Object(inner) = &mut block {
            inner.insert("code_sha256".to_string(), Value::string("00".repeat(32)));
        }
        map.insert("stepper".to_string(), block);
    }
    let stepper = Stepper::from_spec(&registry, &spec).expect("the block parses");
    match stepper.step(&state(27, 0)) {
        Err(StepError::Failed(verdict)) => assert!(!verdict.settles(), "{verdict:?}"),
        other => panic!("a tampered stepper ran: {other:?}"),
    }
}

/// A move carrying a state larger than the cap does not open anything, so an
/// enormous state cannot be used to make a dispute untransmittable.
#[test]
fn an_oversized_state_does_not_open_a_root() {
    let big = Value::object([("pad", Value::string("x".repeat(MAX_STATE_BYTES + 1)))]);
    let trace = Trace::commit(vec![state(1, 0), big]).expect("a trace");
    let mv = trace.open("d1", 1).expect("in range");
    assert!(
        !mv.opens(trace.root()),
        "an oversized state opened its own root"
    );
    // The small one is fine, so the cap is what refused it and not the path.
    let small = trace.open("d1", 0).expect("in range");
    assert!(small.opens(trace.root()));
}

/// The two preconditions `Endpoints` exists to witness, each pinned by the
/// dispute that could not be settled without it.
///
/// Both of these were found by the tests above failing, not by review. The
/// first left `lo` at 0 forever with nobody having opened state 0, so a lie in
/// the very first step produced a dispute nothing could adjudicate. The second
/// let two traces that diverge and rejoin reach a "narrowed" interval whose
/// endpoints both agree — a dispute with no answer, because the challenger had
/// contradicted nothing.
#[test]
fn a_dispute_is_only_well_founded_when_its_endpoints_are() {
    let truth = honest(27, 8);

    // Different starting states: two computations, not one disagreement.
    let mut other_start = truth.clone();
    other_start[0] = state(28, 0);
    assert_eq!(
        Dispute::between(
            "d1",
            &Trace::commit(truth.clone()).expect("a trace"),
            &Trace::commit(other_start).expect("a trace"),
        ),
        Err(DisputeError::DifferentStart)
    );

    // Same final state: diverged and rejoined, so nothing is contradicted.
    let mut rejoins = truth.clone();
    rejoins[4] = state(9_999, 4);
    assert_eq!(
        Dispute::between(
            "d1",
            &Trace::commit(truth.clone()).expect("a trace"),
            &Trace::commit(rejoins).expect("a trace"),
        ),
        Err(DisputeError::SameEnd)
    );

    // Different lengths: already public, no search needed.
    assert_eq!(
        Dispute::between(
            "d1",
            &Trace::commit(truth.clone()).expect("a trace"),
            &Trace::commit(honest(27, 9)).expect("a trace"),
        ),
        Err(DisputeError::LengthMismatch {
            defender: 9,
            challenger: 10
        })
    );

    // A lie in the very first step is adjudicable, which is the case that was
    // broken: `lo` never moves off 0, so state 0 has to have been opened when
    // the dispute was created or there is nothing to step from.
    let defender = Trace::commit(truth.clone()).expect("a trace");
    let challenger = Trace::commit(forged(&truth, 1)).expect("a trace");
    let (dispute, _) = bisect(&defender, &challenger);
    assert_eq!(dispute.interval(), (0, 1));
    assert_eq!(dispute.agreed_state(0), Some(&truth[0]));

    // And a lie in the very last one, the mirror case: `hi` never moves off
    // the end.
    let mut last_only = truth.clone();
    let last = last_only.len() - 1;
    last_only[last] = state(4_242, last as i128);
    let challenger = Trace::commit(last_only).expect("a trace");
    let (dispute, _) = bisect(&defender, &challenger);
    assert_eq!(dispute.interval(), (last - 1, last));
    assert!(dispute.opened_state(last, Side::Challenger).is_some());
}
