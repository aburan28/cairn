//! The adversarial arena, asserted.
//!
//! `proofwork-arena` prints the payoff tables for a human. This file is the
//! machine's copy: the same scenarios, with the verdicts pinned, so a change to
//! a mechanism that quietly re-opens an attack fails a named test rather than
//! changing a number nobody reads.
//!
//! One test is deliberately an assertion that an attack **still pays**. Pinning
//! a known-open hole is worth as much as pinning a closed one — more, because a
//! closed one cannot silently regress into being open without something else
//! failing first, and an open one can silently be believed fixed.

use proofwork::arena::{scenarios, Verdict};

const SEED: u64 = 1;

/// Sybil splitting is *neutral*, which is stronger than unprofitable: an
/// operator wearing eight keys earns no more than the same operator wearing
/// one, because stake is conserved when it is divided and a head count is not.
#[test]
fn splitting_an_identity_earns_no_more_than_keeping_it_whole() {
    if !have_python() {
        eprintln!("skipping: no python3");
        return;
    }
    let trial = scenarios::sybil_split(SEED);
    match trial.verdict() {
        Verdict::Neutral {
            attacker,
            honest,
            without,
        } => {
            assert!(
                attacker <= honest,
                "eight keys earned {attacker} against one key's {honest}"
            );
            // And the counterfactual is not trivially small: a head-counted
            // pool really would have paid the splitter far more, so the run is
            // measuring a defence rather than an absence of opportunity.
            assert!(
                without > honest,
                "a head count paid {without} against {honest}; nothing was at stake"
            );
        }
        other => panic!("sybil splitting: {other}"),
    }
}

/// A node that did not keep the log cannot answer the sample, so it earns
/// nothing — while a node that did keep it earns the whole pool.
#[test]
fn a_node_that_stored_nothing_earns_nothing() {
    if !have_python() {
        eprintln!("skipping: no python3");
        return;
    }
    let trial = scenarios::availability_free_riding(SEED);
    match trial.verdict() {
        Verdict::Neutral {
            attacker, honest, ..
        } => {
            assert_eq!(attacker, 0, "a free-rider was paid");
            assert!(honest > 0, "the honest holder was not paid either");
        }
        other => panic!("availability free-riding: {other}"),
    }
}

/// Certificate earnings do not convert into standing where expensive work is
/// priced.
#[test]
fn a_certificate_mill_converts_nothing() {
    if !have_python() {
        eprintln!("skipping: no python3");
        return;
    }
    let trial = scenarios::cheap_tier_standing(SEED);
    match trial.verdict() {
        Verdict::Closed { with, without } => {
            assert_eq!(with, 0, "typed units were spendable in another tier");
            assert!(without > 0, "the miller earned nothing to convert");
        }
        other => panic!("cheap-tier standing: {other}"),
    }
}

/// An objective with no step function cannot be disputed at all, so a griefer
/// has nothing to open. Stronger than pricing the attack: the mechanism
/// declines to represent it.
#[test]
fn a_plain_objective_cannot_be_griefed() {
    if !have_python() {
        eprintln!("skipping: no python3");
        return;
    }
    match scenarios::unbisectable_objectives(SEED).verdict() {
        Verdict::Refused { attempts } => assert!(attempts > 0),
        other => panic!("griefing a plain objective: {other}"),
    }
}

/// A griefer who opens bonded objections and prosecutes none of them forfeits,
/// and the submitter it tried to stall is *better off* for having been
/// challenged.
///
/// This is the scenario that found the bug it now guards. Before it, a dispute
/// nobody played was never overdue — both sides owed their opening moves, so
/// `overdue` named nobody and the challenge stayed open forever with the bond
/// locked and no outcome. A defender who wanted the matter closed could not
/// close it.
#[test]
fn a_griefer_that_prosecutes_nothing_forfeits() {
    if !have_python() {
        eprintln!("skipping: no python3");
        return;
    }
    let trial = scenarios::griefing_disputes(SEED);
    match trial.verdict() {
        Verdict::Protected {
            victim_with,
            victim_without,
            attacker,
        } => {
            assert!(attacker < 0, "the griefer kept its bonds: {attacker}");
            assert!(
                victim_with > victim_without,
                "the submitter was not made whole: {victim_without} -> {victim_with}"
            );
        }
        other => panic!("griefing disputes: {other}"),
    }
}

/// **A known-open hole, pinned deliberately.**
///
/// A canary docket names a rubber-stamper and takes nothing from it, because
/// nothing is staked on verification. Every document in this repository says
/// so; this is that sentence with a number attached — the stamper ends ahead of
/// an identical honest operator by exactly the verification it did not pay for.
///
/// When a verification bond lands, this test should start failing. That is the
/// point of writing it.
#[test]
fn rubber_stamping_still_pays_because_nothing_is_staked_on_verification() {
    if !have_python() {
        eprintln!("skipping: no python3");
        return;
    }
    let trial = scenarios::rubber_stamping(SEED);
    match trial.verdict() {
        Verdict::StillPays { with, without } => {
            assert!(with > 0 && without > 0);
            let honest = trial.defended.net("honest");
            assert!(
                with > honest,
                "the stamper did not beat the honest operator: {with} against {honest}"
            );
            // The gap is exactly the verification the stamper skipped, which is
            // what makes this a measurement rather than an impression.
            assert_eq!(
                with - honest,
                trial
                    .defended
                    .payoff("honest")
                    .map(|payoff| payoff.spent as i128)
                    .unwrap_or(0),
                "the advantage is not the skipped verification cost"
            );
        }
        other => panic!(
            "rubber-stamping now reports {other}. If a verification bond has \
             landed, this test has done its job and should be rewritten."
        ),
    }
}

/// Every scenario is a deterministic function of its seed, or a run is an
/// anecdote rather than a measurement.
#[test]
fn a_run_is_reproducible_from_its_seed() {
    if !have_python() {
        eprintln!("skipping: no python3");
        return;
    }
    let first = scenarios::cheap_tier_standing(7);
    let again = scenarios::cheap_tier_standing(7);
    assert_eq!(first.swing(), again.swing());
    assert_eq!(first.defended.payoffs, again.defended.payoffs);
}

fn have_python() -> bool {
    std::process::Command::new("python3")
        .arg("--version")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}
