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

/// **The hole this file used to pin as open.**
///
/// The earlier version of this test asserted `StillPays` and carried the note
/// *"when a verification bond lands, this test should start failing — that is
/// the point of writing it."* It did, and this is the rewrite.
///
/// What changed is one record. A canary docket always knew *which* verdicts
/// were wrong for the price of a map lookup; what it could not do was name a
/// party, because a Stage-0 log has one writer and no record said who ran the
/// checker. `records::Attestation` is that record, and the docket is now
/// compared against attestations rather than against the node's own verdicts —
/// so the finding arrives already attached to a key with a bond behind it.
#[test]
fn rubber_stamping_costs_more_than_it_saves() {
    if !have_python() {
        eprintln!("skipping: no python3");
        return;
    }
    let trial = scenarios::rubber_stamping(SEED);
    match trial.verdict() {
        Verdict::Closed { with, without } => {
            assert!(
                without > 0,
                "stamping did not pay undefended either, so this measures nothing: {without}"
            );
            assert!(with < 0, "the stamper kept its bonds: {with}");
            // The two arms run identical histories, so the whole swing between
            // them is the bonds a slash took — and it is a whole number of
            // them, which is what makes this a measurement rather than an
            // impression.
            let stamper = trial.attacker.clone();
            let swing = without - with;
            let bond = i128::from(proofwork::node::VERIFICATION_BOND);
            assert_eq!(
                swing % bond,
                0,
                "the defence cost the stamper {swing}, which is not a whole \
                 number of {bond}-unit bonds"
            );
            // And every one of them was named before it was charged. A slash
            // the docket did not point at would mean the expensive half ran on
            // its own, which is the cost the cheap half exists to avoid.
            let caught = trial
                .defended
                .payoff(&stamper)
                .map(|payoff| payoff.caught.len())
                .unwrap_or(0);
            assert_eq!(
                caught as i128,
                swing / bond,
                "bonds taken and canaries that named them do not match"
            );
        }
        other => panic!("rubber-stamping now reports {other}"),
    }
}

/// The honest operator pays to verify and keeps every unit of it.
///
/// Half of the pair, and the half that would be easy to lose: a defence that
/// punishes stamping by making *everybody* poorer has not distinguished
/// anything. The honest operator stakes exactly the same bonds on exactly the
/// same claims, and ends the run with all of them.
#[test]
fn standing_behind_the_truth_costs_only_the_check() {
    if !have_python() {
        eprintln!("skipping: no python3");
        return;
    }
    let trial = scenarios::rubber_stamping(SEED);
    let honest = trial
        .defended
        .payoff("honest")
        .expect("the benchmark operator");
    assert!(
        honest.closed >= honest.opened,
        "an honest attestor lost a bond: {} -> {}",
        honest.opened,
        honest.closed
    );
    assert!(
        honest.caught.is_empty(),
        "the docket named an honest attestor: {:?}",
        honest.caught
    );
    // And the catcher is paid for the work of catching, or nobody does it.
    let auditor = trial
        .defended
        .payoff("auditor")
        .expect("the policing party");
    assert!(
        auditor.net() > 0,
        "policing did not pay for itself: {}",
        auditor.net()
    );
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
