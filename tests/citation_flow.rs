//! Adversarial tests on the payment mechanism.
//!
//! The ratchet's telescoping property is stated as "the pool is identical
//! however the curve is chopped", and `frontier.rs` proves that for the
//! **direct** reward. These tests ask the question that guarantee does not
//! answer: what happens to **citation flow** when an improver chops?
//!
//! The answer, pinned below, is that hop-count decay makes chopping strictly
//! profitable at the upstream contributor's expense — for free, because the
//! improver already holds the result and telescoping protects the direct
//! reward. A participant who declines to slice is leaving money on the table,
//! which makes slicing the dominant strategy rather than an exotic attack.
//!
//! The numbers are asserted exactly. If a change to attribution moves them,
//! that is a change to who gets paid and it should require editing this file.

use std::collections::BTreeMap;

use proofwork::attribution::{payouts_over, FlowParams};
use proofwork::canonical::Value;
use proofwork::records::Claim;

const TS: &str = "2026-07-29T00:00:00+00:00";
const OBJ: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

fn claim(who: &str, n: i128, cites: Vec<String>) -> Claim {
    Claim::new(
        OBJ,
        who,
        Value::object([("n", Value::Int(n))]),
        format!("nonce-{n}"),
        TS,
        cites,
    )
    .expect("valid claim")
}

/// Settle `steps` in order, each claim citing the one before it, and return
/// the citation-flow payouts per submitter.
fn payouts(steps: &[(&str, u64)], params: &FlowParams) -> BTreeMap<String, u64> {
    let mut claims = BTreeMap::new();
    let mut settlements = Vec::new();
    let mut previous: Option<String> = None;
    for (i, (who, reward)) in steps.iter().enumerate() {
        let c = claim(who, i as i128, previous.clone().into_iter().collect());
        let id = c.id();
        claims.insert(id.clone(), c);
        settlements.push((id.clone(), *reward));
        previous = Some(id);
    }
    payouts_over(&settlements, &claims, params).expect("flow succeeds")
}

fn take(p: &BTreeMap<String, u64>, who: &str) -> u64 {
    p.get(who).copied().unwrap_or(0)
}

/// The CLI defaults, and the parameters every number below assumes.
fn default_params() -> FlowParams {
    FlowParams::new(1, 4, 6).expect("delta 1/4, depth 6")
}

/// The README's showcase, unchopped: alice 9->12, bob 12->16, carol 16->20 on
/// a 1,100,000 pool.
fn showcase() -> Vec<(&'static str, u64)> {
    vec![("alice", 300_000), ("bob", 400_000), ("carol", 400_000)]
}

#[test]
fn the_documented_showcase_still_pays_what_the_readme_says() {
    // If this fails, the README is wrong, not the test.
    let p = payouts(&showcase(), &default_params());
    assert_eq!(take(&p, "alice"), 425_000);
    assert_eq!(take(&p, "bob"), 375_000);
    assert_eq!(take(&p, "carol"), 300_000);
    assert!(
        take(&p, "alice") > take(&p, "bob"),
        "the headline claim is that alice ends up ahead of bob"
    );
}

#[test]
fn slicing_an_improvement_transfers_value_from_the_upstream_contributor() {
    // THE FINDING. bob does exactly the same work for exactly the same direct
    // reward -- telescoping guarantees that -- but reveals it as four 1-point
    // steps instead of one 4-point step. He already holds the result, so the
    // chopping costs him nothing.
    let mut sliced: Vec<(&str, u64)> = vec![("alice", 300_000)];
    for _ in 0..4 {
        sliced.push(("bob", 100_000));
    }
    sliced.push(("carol", 400_000));

    let honest = payouts(&showcase(), &default_params());
    let attack = payouts(&sliced, &default_params());

    // Conservation still holds: this is a transfer, not an inflation.
    let honest_total: u64 = honest.values().sum();
    let attack_total: u64 = attack.values().sum();
    assert_eq!(honest_total, 1_100_000);
    assert_eq!(attack_total, 1_100_000);

    // Exact, so a change to attribution has to come here and edit them.
    assert_eq!(take(&attack, "alice"), 333_592);
    assert_eq!(take(&attack, "bob"), 466_408);
    assert_eq!(take(&attack, "carol"), 300_000);

    // bob gains precisely what alice loses, and carol is untouched.
    let gained = take(&attack, "bob") - take(&honest, "bob");
    let lost = take(&honest, "alice") - take(&attack, "alice");
    assert_eq!(gained, lost, "the transfer should be exact");
    assert_eq!(gained, 91_408);
    assert_eq!(take(&attack, "carol"), take(&honest, "carol"));

    // And it inverts the headline: after slicing, bob is ahead of alice.
    assert!(
        take(&attack, "bob") > take(&attack, "alice"),
        "slicing should overturn the README's showcase result"
    );
}

#[test]
fn the_more_finely_an_improver_slices_the_less_the_upstream_gets() {
    // Monotone in the number of steps, so there is no threshold below which
    // slicing is harmless -- every additional cut pays.
    let params = default_params();
    // Measure the *flow* alice receives, not her total: her own 300,000 direct
    // reward is a floor that no amount of slicing can touch, and including it
    // would understate the effect.
    const ALICE_DIRECT: u64 = 300_000;
    let mut previous = u64::MAX;
    let mut inflow = Vec::new();
    for steps in [1u64, 2, 4, 8, 16] {
        let mut curve: Vec<(&str, u64)> = vec![("alice", ALICE_DIRECT)];
        for _ in 0..steps {
            curve.push(("bob", 400_000 / steps));
        }
        let received = take(&payouts(&curve, &params), "alice") - ALICE_DIRECT;
        assert!(
            received < previous,
            "{steps} steps gave alice {received} of flow, not less than {previous}"
        );
        previous = received;
        inflow.push(received);
    }
    // One honest claim pays alice 100,000 of flow; sixteen slices pay 8,329 --
    // a 92% cut for work bob was going to do anyway.
    assert_eq!(inflow[0], 100_000);
    assert_eq!(inflow[4], 8_329);
    assert!(
        inflow[4] * 10 < inflow[0],
        "16 slices should cost alice most of her flow: {inflow:?}"
    );
}

#[test]
fn max_depth_does_not_defend_against_slicing() {
    // A plausible first instinct is that bounding the walk bounds the damage.
    // It does not: the decay is geometric *within* the chain, so a deeper cap
    // changes almost nothing.
    let mut sliced: Vec<(&str, u64)> = vec![("alice", 300_000)];
    for _ in 0..8 {
        sliced.push(("bob", 50_000));
    }

    let shallow = take(
        &payouts(&sliced, &FlowParams::new(1, 4, 6).unwrap()),
        "alice",
    );
    let deep = take(
        &payouts(&sliced, &FlowParams::new(1, 4, 64).unwrap()),
        "alice",
    );
    let difference = shallow.abs_diff(deep);
    assert!(
        difference * 1000 < shallow,
        "raising max_depth from 6 to 64 changed alice's take by {difference}, \
         which would mean depth is a real defence"
    );
}

#[test]
fn a_larger_delta_does_not_remove_the_incentive_either() {
    // Turning up the citation share raises alice's take in absolute terms but
    // leaves slicing strictly profitable, so it is not a fix.
    for (num, den) in [(1u64, 4u64), (1, 2), (3, 4)] {
        let params = FlowParams::new(num, den, 6).unwrap();

        let honest = payouts(&showcase(), &params);
        let mut sliced: Vec<(&str, u64)> = vec![("alice", 300_000)];
        for _ in 0..4 {
            sliced.push(("bob", 100_000));
        }
        sliced.push(("carol", 400_000));
        let attack = payouts(&sliced, &params);

        assert!(
            take(&attack, "bob") > take(&honest, "bob"),
            "delta {num}/{den}: slicing should still pay bob more"
        );
        assert!(
            take(&attack, "alice") < take(&honest, "alice"),
            "delta {num}/{den}: slicing should still cost alice"
        );
    }
}

#[test]
fn slicing_gains_nothing_when_there_is_nobody_upstream() {
    // Confirms the mechanism of the attack: the gain comes entirely from
    // withholding flow that would have gone upstream, not from the ratchet.
    // With no upstream contributor there is nothing to withhold.
    let params = default_params();
    let one = payouts(&[("bob", 400_000)], &params);
    let mut many: Vec<(&str, u64)> = Vec::new();
    for _ in 0..4 {
        many.push(("bob", 100_000));
    }
    let split = payouts(&many, &params);
    assert_eq!(take(&one, "bob"), 400_000);
    assert_eq!(take(&split, "bob"), 400_000);
}

// -- the reward-weighted rule ----------------------------------------------
//
// Implemented and proven here; not yet the default, because switching it
// moves settled money and therefore the conformance vectors. See
// docs/design/citation-flow-dilution.md.

/// Build a chain and settle it, returning weighted payouts.
fn weighted(steps: &[(&str, u64)]) -> BTreeMap<String, u64> {
    let mut claims: BTreeMap<String, Claim> = BTreeMap::new();
    let mut settlements: Vec<(String, u64)> = Vec::new();
    let mut previous: Option<String> = None;
    for (index, (who, reward)) in steps.iter().enumerate() {
        let cites = previous.clone().map(|id| vec![id]).unwrap_or_default();
        let record = claim(who, index as i128, cites);
        let id = record.id();
        claims.insert(id.clone(), record);
        settlements.push((id.clone(), *reward));
        previous = Some(id);
    }
    proofwork::attribution::payouts_weighted(&settlements, &claims, &default_params())
        .expect("no overflow at this size")
}

fn sliced_chain(slices: u64) -> Vec<(&'static str, u64)> {
    let mut steps: Vec<(&str, u64)> = vec![("alice", 300_000)];
    for _ in 0..slices {
        steps.push(("bob", 400_000 / slices));
    }
    steps.push(("carol", 400_000));
    steps
}

#[test]
fn weighted_attribution_conserves_exactly() {
    // The bar every attribution rule has to clear: what is distributed equals
    // what was settled, at every slicing. Attribution that conserves
    // approximately is attribution that mints.
    for slices in [1u64, 2, 3, 4, 7, 16, 64] {
        let steps = sliced_chain(slices);
        let settled: u64 = steps.iter().map(|(_, reward)| reward).sum();
        let paid: u64 = weighted(&steps).values().sum();
        assert_eq!(paid, settled, "{slices} slices did not conserve");
    }
}

#[test]
fn a_downstream_citer_pays_the_same_however_the_middle_was_chopped() {
    // The half of the attack this closes outright. Carol builds on bob; what
    // she sends alice must not depend on how bob chose to package his work.
    //
    // Measured against the *whole* chain rather than carol alone, because
    // alice's total is what she is actually paid.
    let one = take(&weighted(&sliced_chain(1)), "alice");
    for slices in [2u64, 4, 16, 64] {
        let many = take(&weighted(&sliced_chain(slices)), "alice");
        // Under the current rule this gap grows without limit; under this one
        // it converges. The assertion is the bound, not equality, because the
        // slicer's own claims legitimately stand on each other.
        let lost = one.saturating_sub(many);
        assert!(
            lost * 10 < one,
            "{slices} slices cost alice {lost} of {one} -- more than the 10% bound"
        );
    }
}

#[test]
fn the_slicers_gain_converges_instead_of_growing() {
    // The property that distinguishes a bounded premium from an attack. Under
    // the per-hop rule alice tends to her own direct reward and nothing else:
    // her citation flow is driven to zero. Here it settles.
    let alice_at = |slices: u64| take(&weighted(&sliced_chain(slices)), "alice");
    let (coarse, fine, finest) = (alice_at(16), alice_at(64), alice_at(256));

    assert!(
        coarse.abs_diff(finest) * 100 < coarse,
        "alice moved more than 1% between 16 and 256 slices ({coarse} -> {finest}), \
         which is not convergence"
    );
    assert!(fine >= finest, "the sequence should be monotone in slices");
    // And she keeps real flow, not just her direct reward.
    assert!(
        finest > 400_000,
        "alice kept only {finest}; her direct reward alone is 300,000, so her \
         citation flow has been driven to nothing"
    );
}

#[test]
fn weighted_attribution_is_identity_blind() {
    // Four slices by one submitter and four claims by four submitters must
    // produce the same distribution. Nothing may key on *who* submitted:
    // minting an identity is one command, so a rule that did would have a
    // sybil version and be worth nothing.
    let same = weighted(&[
        ("alice", 300_000),
        ("bob", 100_000),
        ("bob", 100_000),
        ("bob", 100_000),
        ("bob", 100_000),
        ("carol", 400_000),
    ]);
    let different = weighted(&[
        ("alice", 300_000),
        ("b1", 100_000),
        ("b2", 100_000),
        ("b3", 100_000),
        ("b4", 100_000),
        ("carol", 400_000),
    ]);
    assert_eq!(take(&same, "alice"), take(&different, "alice"));
    assert_eq!(take(&same, "carol"), take(&different, "carol"));
    let split: u64 = ["b1", "b2", "b3", "b4"]
        .iter()
        .map(|who| take(&different, who))
        .sum();
    assert_eq!(take(&same, "bob"), split);
}

#[test]
fn a_zero_reward_ancestor_cannot_dilute_the_people_who_moved_something() {
    // A claim that settled for nothing moved no ground, so it can take no
    // share -- otherwise a chain of them is a free way to thin everyone else.
    let with_ghosts = weighted(&[
        ("alice", 300_000),
        ("ghost", 0),
        ("ghost", 0),
        ("carol", 400_000),
    ]);
    let without = weighted(&[("alice", 300_000), ("carol", 400_000)]);
    assert_eq!(take(&with_ghosts, "ghost"), 0);
    assert_eq!(take(&with_ghosts, "alice"), take(&without, "alice"));
}

#[test]
fn weighted_attribution_matches_the_design_harness() {
    // The numbers in docs/design/citation-flow-dilution.md come from
    // scripts/citation-flow-harness.py, which computes in exact rationals.
    // If this implementation disagrees with it, one of the two is wrong and
    // the design note is describing something nobody has built.
    let showcase = weighted(&[("alice", 300_000), ("bob", 400_000), ("carol", 400_000)]);
    assert_eq!(take(&showcase, "alice"), 442_857);
    assert_eq!(take(&showcase, "bob"), 357_143);
    assert_eq!(take(&showcase, "carol"), 300_000);

    let four = weighted(&sliced_chain(4));
    assert_eq!(take(&four, "alice"), 414_107);
    assert_eq!(take(&four, "carol"), 300_000);
}
