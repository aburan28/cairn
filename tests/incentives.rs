//! End-to-end tests for the node-incentive harness.
//!
//! The unit tests inside `src/incentive/` check each piece against the algebra
//! it implements. These check the claims the README and the docs make, from
//! outside the crate and through the public API only -- because a design
//! document that says "rubber-stamping stops being an equilibrium" is a claim
//! about the shipped mechanism, and the place to pin it is where a reader can
//! find it.
//!
//! Every test here is a sentence somebody could write in a paper, restated so a
//! machine can refuse it.

use proofwork::incentive::design::{
    committee_window, minimum_audit_rate, minimum_canary_rate, minimum_stake_for_custody,
    participation, Report,
};
use proofwork::incentive::dynamics::tipping_point;
use proofwork::incentive::game::{
    everyone, invasion, sybil_gain, symmetric_stability, Invades, Stability,
};
use proofwork::incentive::mechanism::{
    Attest, Availability, Custody, RewardRule, Serve, Share, SplitIdentities, Verification,
};
use proofwork::incentive::{NodeParams, ParamError, Rat};

fn reference() -> NodeParams {
    NodeParams::reference()
}

fn rate(num: u32, den: u32) -> Rat {
    Rat::rate(num, den).expect("a valid rate")
}

// ---------------------------------------------------------------------------
// The headline claims
// ---------------------------------------------------------------------------

#[test]
fn the_reference_mechanism_holds_at_every_rung() {
    let report = Report::of(&reference()).expect("the reference network validates");
    assert!(report.passes(), "reference report:\n{report}");
    for service in &report.services {
        assert!(
            service.exact,
            "{} used saturated arithmetic",
            service.service
        );
        assert!(
            service.stability.is_some(),
            "{} honest profile is not an equilibrium",
            service.service
        );
        assert!(
            service.defection.is_none(),
            "{} has a profitable defection",
            service.service
        );
        assert!(
            service.rivals.is_empty(),
            "{} has a rival strict equilibrium",
            service.service
        );
    }
}

#[test]
fn rubber_stamping_survives_any_penalty_when_the_trigger_is_conditional() {
    // The claim the whole mechanism is built around, and the one that makes
    // canaries structural rather than a tuning knob. If a node is punished for
    // accepting bad work only when somebody *else* proves it bad, then a
    // population in which nobody checks punishes nobody -- at any stake, at any
    // slash rate, at any bounty.
    for stake in [1_000u64, 1_000_000, 1_000_000_000, 1 << 40] {
        for bounty in [0u64, 1_000_000, 1 << 40] {
            let params = NodeParams {
                canary_rate: Rat::ZERO,
                stake,
                slash_rate: Rat::ONE,
                catch_bounty: bounty,
                ..reference()
            };
            let game = Verification::new(&params).expect("validated");
            let trap = everyone(&game, Attest::Stamp.index());
            let held = symmetric_stability(&game, &trap).expect("valid counts");
            // A bounty above cost/fraud-rate is the one escape, and it is the
            // expensive one: at these parameters it takes 200_000 units of
            // bounty to buy a 200-unit check.
            let bounty_escape =
                Rat::units(bounty) * params.fraud_rate > Rat::units(params.verify_cost);
            if bounty_escape {
                assert_eq!(held, None, "a huge bounty does break the trap");
            } else {
                assert!(
                    held.is_some(),
                    "the trap survived stake {stake} bounty {bounty}"
                );
            }
        }
    }
}

#[test]
fn canaries_are_the_cheap_escape_and_the_harness_prices_both() {
    let params = NodeParams {
        canary_rate: Rat::ZERO,
        canary_leak: Rat::ZERO,
        ..reference()
    };
    let needed = minimum_canary_rate(&params)
        .expect("validated")
        .expect("a rate exists");
    // One canary in fourteen hundred, against a bounty of two hundred thousand
    // units to achieve the same thing. That ratio is the argument.
    assert!(needed < rate(1, 1_000));
    let fixed = NodeParams {
        canary_rate: rate(1, 100),
        ..params.clone()
    };
    let game = Verification::new(&fixed).expect("validated");
    assert_eq!(
        symmetric_stability(&game, &everyone(&game, Attest::Stamp.index())).expect("valid counts"),
        None,
        "the trap is gone"
    );
    assert_eq!(
        symmetric_stability(&game, &everyone(&game, Attest::Verify.index())).expect("valid counts"),
        Some(Stability::Strict)
    );
}

#[test]
fn the_more_honest_the_network_the_weaker_a_bounty_only_scheme_is() {
    // The perverse comparative static: with no canaries the only reason to
    // check is the chance of catching real fraud, so a network where fraud is
    // rare is a network nobody checks -- which is exactly the network where an
    // undetected fraud is worth the most.
    let honest_rate = rate(1, 100_000);
    let crooked_rate = rate(1, 10);
    let needed = |fraud_rate: Rat| {
        let params = NodeParams {
            canary_rate: Rat::ZERO,
            canary_leak: Rat::ZERO,
            fraud_rate,
            ..reference()
        };
        minimum_canary_rate(&params)
            .expect("validated")
            .expect("a rate exists")
    };
    assert!(
        needed(honest_rate) > needed(crooked_rate),
        "an honest network needs more manufactured fraud, not less"
    );
}

#[test]
fn availability_needs_no_canaries_because_the_protocol_holds_the_answer() {
    // The contrast that explains why verification is the hard one. A Merkle
    // challenge is checked against a root the protocol published, so a node
    // that fails one has proved something about itself with nobody's help.
    let params = reference();
    let game = Availability::new(&params).expect("validated");
    assert_eq!(
        symmetric_stability(&game, &everyone(&game, Serve::Store.index())).expect("valid counts"),
        Some(Stability::Strict)
    );
    assert_eq!(
        invasion(
            &game,
            Serve::Store.index(),
            params.nodes,
            Invades::WeaklyBetter
        )
        .expect("valid resident"),
        None
    );
    // And the only thing that can break it is arithmetic, not coordination.
    let threshold = minimum_audit_rate(&params)
        .expect("validated")
        .expect("a rate exists");
    assert!(params.audit_rate > threshold);
}

// ---------------------------------------------------------------------------
// The committee
// ---------------------------------------------------------------------------

#[test]
fn the_committee_threshold_has_a_window_and_both_walls_are_real() {
    let params = reference();
    let window = committee_window(&params).expect("validated");
    assert!(!window.is_empty(), "the reference committee has a window");
    let (low, high) = (window[0], window[window.len() - 1]);
    assert!(low > 1 && high < params.committee, "both walls bind");
    assert!(
        window.contains(&params.threshold),
        "the reference threshold {} is inside {low}..={high}",
        params.threshold
    );

    // Below the window: a cartel of `t` opens the envelope early.
    let too_low = NodeParams {
        threshold: low - 1,
        ..params.clone()
    };
    let game = Custody::new(&too_low).expect("validated");
    let found = invasion(
        &game,
        Share::Publish.index(),
        too_low.committee,
        Invades::StrictlyBetter,
    )
    .expect("valid resident")
    .expect("a low threshold is cheap to reach");
    assert_eq!(found.mutant, Share::OpenEarly.index());

    // Above it: a cartel of `n - t + 1` blocks the opening and censors.
    let too_high = NodeParams {
        threshold: high + 1,
        ..params
    };
    let game = Custody::new(&too_high).expect("validated");
    let found = invasion(
        &game,
        Share::Publish.index(),
        too_high.committee,
        Invades::StrictlyBetter,
    )
    .expect("valid resident")
    .expect("a high threshold is cheap to block");
    assert_eq!(found.mutant, Share::Withhold.index());
}

#[test]
fn the_committee_must_grow_with_the_value_it_seals() {
    // Not a tuning issue: a fixed committee shape that is safe for a small
    // bounty is corruptible for a large one, and no code changes in between.
    let base = reference();
    let mut previous = 0u64;
    for multiple in [1u64, 2, 4, 8] {
        let params = NodeParams {
            sealed_value: base.sealed_value * multiple,
            ..base.clone()
        };
        let needed = minimum_stake_for_custody(&params)
            .expect("validated")
            .expect("some bond works at this size");
        assert!(
            needed > previous,
            "a larger sealed value must demand a larger bond"
        );
        previous = needed;
    }
}

#[test]
fn standing_ready_to_collude_is_free_and_the_harness_says_so() {
    // The property no mechanism here can fix, reported rather than hidden: a
    // committee member below the threshold behaves and is paid exactly like an
    // honest one, so the honest profile is weak and a cartel assembles at zero
    // cost. What the bond buys is that reaching the threshold does not pay.
    let params = reference();
    let game = Custody::new(&params).expect("validated");
    assert_eq!(
        symmetric_stability(&game, &everyone(&game, Share::Publish.index())).expect("valid counts"),
        Some(Stability::Weak)
    );
    let drift = invasion(
        &game,
        Share::Publish.index(),
        params.committee,
        Invades::WeaklyBetter,
    )
    .expect("valid resident")
    .expect("free drift exists");
    assert_eq!(drift.gain, Rat::ZERO);
    assert_eq!(
        invasion(
            &game,
            Share::Publish.index(),
            params.committee,
            Invades::StrictlyBetter
        )
        .expect("valid resident"),
        None,
        "but nobody profits"
    );
}

// ---------------------------------------------------------------------------
// Participation and sybils
// ---------------------------------------------------------------------------

#[test]
fn security_spend_is_proportional_to_settled_value_including_at_zero() {
    // The bootstrap problem, exactly as stated in the module docs. Node rewards
    // are a fee on settlement rather than a mint, which is the right long-run
    // answer and means a network that has settled nothing pays nobody.
    let dead = NodeParams {
        settled_value: 0,
        ..reference()
    };
    let found = participation(&dead).expect("validated");
    assert!(found.net.is_negative());
    assert_eq!(found.supports_nodes, None, "no node count is viable");
    let needed = found
        .break_even_settled_value
        .expect("some settlement level works");
    assert!(needed > 0);

    let alive = NodeParams {
        settled_value: needed,
        ..dead
    };
    assert!(!participation(&alive).expect("validated").net.is_negative());
}

#[test]
fn an_even_per_node_split_pays_for_identities_and_a_stake_split_does_not() {
    let params = reference();
    let per_node = SplitIdentities::verification(&params, RewardRule::PerNode).expect("validated");
    let per_stake =
        SplitIdentities::verification(&params, RewardRule::PerStake).expect("validated");
    assert!(sybil_gain(&per_node, 100).gain.is_positive());
    assert_eq!(sybil_gain(&per_stake, 100).gain, Rat::ZERO);

    // And the report fails the network that chooses the wrong rule.
    let naive = NodeParams {
        reward_rule: RewardRule::PerNode,
        ..params
    };
    assert!(!Report::of(&naive).expect("validated").passes());
}

// ---------------------------------------------------------------------------
// Dynamics
// ---------------------------------------------------------------------------

#[test]
fn the_reference_network_absorbs_a_shock_of_any_size() {
    let params = reference();
    let game = Verification::new(&params).expect("validated");
    assert_eq!(
        tipping_point(
            &game,
            Attest::Verify.index(),
            Attest::Stamp.index(),
            100_000
        )
        .expect("valid actions"),
        None
    );
}

#[test]
fn a_thin_bond_and_no_canaries_makes_the_collapse_gradual() {
    // Two different failures with two different fixes. Without canaries the
    // network is bistable -- fine until everyone moves at once. With a thin bond
    // as well, it erodes one operator at a time, which is far worse and far
    // easier to see coming.
    let bistable = NodeParams {
        canary_rate: Rat::ZERO,
        ..reference()
    };
    let game = Verification::new(&bistable).expect("validated");
    assert_eq!(
        tipping_point(
            &game,
            Attest::Verify.index(),
            Attest::Stamp.index(),
            100_000
        )
        .expect("valid actions"),
        Some(bistable.nodes),
        "only a total defection reaches the trap"
    );

    let slope = NodeParams {
        stake: 1_000,
        ..bistable
    };
    let game = Verification::new(&slope).expect("validated");
    assert_eq!(
        tipping_point(
            &game,
            Attest::Verify.index(),
            Attest::Stamp.index(),
            100_000
        )
        .expect("valid actions"),
        Some(1),
        "one lazy operator is enough"
    );
}

// ---------------------------------------------------------------------------
// The harness refuses rather than guesses
// ---------------------------------------------------------------------------

#[test]
fn a_parameter_set_that_is_not_a_network_is_refused_by_every_entry_point() {
    let broken = NodeParams {
        threshold: 0,
        ..reference()
    };
    assert!(matches!(
        broken.validate(),
        Err(ParamError::BadThreshold { .. })
    ));
    assert!(Verification::new(&broken).is_err());
    assert!(Custody::new(&broken).is_err());
    assert!(Availability::new(&broken).is_err());
    assert!(Report::of(&broken).is_err());
    assert!(participation(&broken).is_err());
    assert!(minimum_canary_rate(&broken).is_err());
}

#[test]
fn a_report_is_reproducible_to_the_last_character() {
    // Exact rationals throughout, so two runs of the same analysis produce the
    // same bytes. Not a given: this is the property a float-based harness
    // cannot offer, and the reason a report can be checked into a repository
    // and diffed when a parameter changes.
    let params = reference();
    let first = Report::of(&params).expect("validated").to_string();
    for _ in 0..5 {
        assert_eq!(Report::of(&params).expect("validated").to_string(), first);
    }
    assert_eq!(
        Report::of(&params).expect("validated"),
        Report::of(&params).expect("validated")
    );
}
