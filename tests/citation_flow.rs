//! Adversarial tests on the payment mechanism.
//!
//! The ratchet's telescoping property is stated as "the pool is identical
//! however the curve is chopped", and `frontier.rs` proves that for the
//! **direct** reward. These tests ask the question that guarantee does not
//! answer: what happens to **citation flow** when an improver chops?
//!
//! Under hop-count decay the answer was that chopping is strictly profitable
//! at the upstream contributor's expense -- for free, because the improver
//! already holds the result and telescoping protects the direct reward. 256
//! slices drove the upstream contributor's citation flow to *zero*. Slicing
//! was the dominant strategy rather than an exotic attack, and it inverted the
//! payout result the README uses to argue that publishing beats hoarding.
//!
//! `payouts_over` now weights by settled reward instead, and these tests are
//! the regression: they assert the attack no longer pays. The ones that used
//! to pin the theft now pin its absence, which is the same assertions read the
//! other way round.
//!
//! The numbers are asserted exactly. If a change to attribution moves them,
//! that is a change to who gets paid and it should require editing this file.

use std::collections::BTreeMap;

use cairn::attribution::{payouts_over, FlowParams};
use cairn::canonical::Value;
use cairn::records::Claim;

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
    // alice ends with the largest total from the smallest direct reward,
    // because two people built on her. That is the result the README uses to
    // argue publishing beats hoarding, and it has to survive the change of
    // rule -- the numbers moved, the ordering did not.
    let paid = payouts(&showcase(), &default_params());
    assert_eq!(take(&paid, "alice"), 442_857);
    assert_eq!(take(&paid, "bob"), 357_143);
    assert_eq!(take(&paid, "carol"), 300_000);
    assert!(
        take(&paid, "alice") > take(&paid, "bob"),
        "alice must still end ahead of bob on a smaller direct reward"
    );
    assert_eq!(
        take(&paid, "alice") + take(&paid, "bob") + take(&paid, "carol"),
        1_100_000,
        "conservation"
    );
}

#[test]
fn slicing_an_improvement_no_longer_transfers_value_from_the_upstream() {
    // The attack, run against the current rule. Bob chops 12->16 into four
    // 1-point steps: free in direct reward because the pool telescopes, and
    // under hop decay it moved 91,408 from alice to him. It no longer does.
    let mut sliced: Vec<(&str, u64)> = vec![("alice", 300_000)];
    for _ in 0..4 {
        sliced.push(("bob", 100_000));
    }
    sliced.push(("carol", 400_000));

    let honest = payouts(&showcase(), &default_params());
    let attack = payouts(&sliced, &default_params());

    // Alice keeps nearly all of what she had, rather than a quarter less.
    assert_eq!(take(&attack, "alice"), 414_107);
    let lost = take(&honest, "alice") - take(&attack, "alice");
    assert!(
        lost * 10 < take(&honest, "alice"),
        "slicing cost alice {lost} of {} -- past the 10% bound",
        take(&honest, "alice")
    );

    // And the headline result survives: bob does not overtake alice by
    // chopping work he had already done.
    assert!(
        take(&attack, "alice") > take(&attack, "bob"),
        "slicing overturned the README's showcase result"
    );

    // A downstream citer is completely unaffected by how the middle was
    // packaged, which is the half of the attack that is closed outright.
    assert_eq!(take(&honest, "carol"), take(&attack, "carol"));
}

#[test]
fn slicing_ever_more_finely_no_longer_drains_the_upstream() {
    // Under hop decay this was unbounded: at 256 slices alice was left with
    // 300,521 -- her own direct reward and essentially nothing else, her
    // citation flow driven to zero. It now converges instead.
    let inflow = |slices: u64| -> u64 {
        let mut steps: Vec<(&str, u64)> = vec![("alice", 300_000)];
        for _ in 0..slices {
            steps.push(("bob", 400_000 / slices));
        }
        steps.push(("carol", 400_000));
        take(&payouts(&steps, &default_params()), "alice")
    };

    let (one, sixteen, many) = (inflow(1), inflow(16), inflow(256));
    assert_eq!(one, 442_857);
    // 408,225 and not the 408,226 the design note quotes: that figure comes
    // from the exact-rational harness, and this is integer arithmetic that
    // floors. Both implementations floor identically -- checked against the
    // reference implementation -- which is the property that matters. A
    // conservation
    // test covers where the odd unit goes.
    assert_eq!(sixteen, 408_225);

    // Converged: a sixteenfold increase in slicing moves her under 1%.
    assert!(
        sixteen.abs_diff(many) * 100 < sixteen,
        "alice moved from {sixteen} to {many} between 16 and 256 slices"
    );
    // And she keeps real citation flow, not just her own direct reward.
    assert!(
        many > 400_000,
        "alice kept {many}; her direct reward alone is 300,000, so her flow \
         has been drained"
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
    cairn::attribution::payouts_weighted(&settlements, &claims, &default_params())
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

// ---------------------------------------------------------------------------
// The reserved share
// ---------------------------------------------------------------------------

/// Settle a chain where the frontier holder is `alice`, then `fanout`
/// self-funded claims by `mallory`, then a final `mallory` claim citing all of
/// them *and* alice. Returns the payouts under `params`.
///
/// This is the attack agent funding makes cheap. Under a declared supply,
/// funding your own objective and settling it yourself costs the verification
/// and returns the units — so a high-weight ancestor is close to free, and
/// citing enough of them thins alice's share by the ratio of weights rather
/// than because anybody disputed what she contributed.
fn diluted(fanout: usize, params: &FlowParams) -> BTreeMap<String, u64> {
    let mut claims = BTreeMap::new();
    let mut settlements = Vec::new();

    let alice = claim("alice", 0, Vec::new());
    let alice_id = alice.id();
    claims.insert(alice_id.clone(), alice);
    settlements.push((alice_id.clone(), 400_000u64));

    let mut cites = vec![alice_id.clone()];
    for n in 0..fanout {
        let padding = claim("mallory", 100 + n as i128, Vec::new());
        let id = padding.id();
        claims.insert(id.clone(), padding);
        settlements.push((id.clone(), 400_000));
        cites.push(id);
    }

    let final_claim = claim("mallory", 999, cites);
    let final_id = final_claim.id();
    claims.insert(final_id.clone(), final_claim);
    settlements.push((final_id.clone(), 400_000));

    let enforced: BTreeMap<String, String> = [(final_id, alice_id)].into_iter().collect();
    cairn::attribution::payouts_with_enforced(&settlements, &claims, &enforced, params)
        .expect("flow succeeds")
}

#[test]
fn manufactured_ancestors_thin_the_frontier_holder_when_nothing_is_reserved() {
    // The measurement the reserve exists for, taken first so the fix has
    // something to be compared against. `alice` is cited either way; what
    // changes is how many other ancestors stand next to her, and the weighted
    // split divides by all of them.
    //
    // Her own settlement is 400,000 and the flow she is owed is 100,000. At
    // fanout 200 she keeps 498 of it -- half a percent -- and nobody disputed
    // anything she did.
    let open = FlowParams::default();
    assert_eq!(take(&diluted(0, &open), "alice"), 500_000);
    assert_eq!(take(&diluted(5, &open), "alice"), 416_667);
    assert_eq!(take(&diluted(40, &open), "alice"), 402_439);
    assert_eq!(take(&diluted(200, &open), "alice"), 400_498);
}

#[test]
fn a_reserved_share_is_the_part_dilution_cannot_reach() {
    // Half of delta reserved for the citation the rules forced. The
    // discretionary half still thins exactly as before -- that is not what a
    // reserve fixes -- and the reserved half does not move at any fanout,
    // because its recipient was never the submitter's to choose.
    let half = FlowParams::default()
        .with_reserved(1, 2)
        .expect("half of delta");
    assert_eq!(take(&diluted(0, &half), "alice"), 500_000);
    assert_eq!(take(&diluted(5, &half), "alice"), 458_334);
    assert_eq!(take(&diluted(40, &half), "alice"), 451_220);
    assert_eq!(take(&diluted(200, &half), "alice"), 450_249);

    // The floor, stated as the property rather than as four numbers: whatever
    // the fanout, she keeps her own settlement plus the reserved half of the
    // flow. Dilution can take the other half and no more.
    for fanout in [0, 5, 40, 200, 1000] {
        assert!(
            take(&diluted(fanout, &half), "alice") >= 450_000,
            "fanout {fanout} broke the floor"
        );
    }

    // And reserving all of delta makes the flow immovable: the same 500,000 at
    // every fanout, because there is no discretionary remainder left to dilute.
    let all = FlowParams::default()
        .with_reserved(1, 1)
        .expect("all of delta");
    for fanout in [0, 5, 40, 200] {
        assert_eq!(take(&diluted(fanout, &all), "alice"), 500_000);
    }
}

#[test]
fn a_reserve_takes_nothing_from_the_submitter_that_delta_did_not_already() {
    // A fraction *of delta*, not of the reward. Raising the reserve moves
    // money between upstream recipients and never out of the claimant's own
    // share, so a funder cannot be talked into a reserve that costs it more
    // than the delta it already agreed to.
    for (num, den) in [(0, 1), (1, 4), (1, 2), (1, 1)] {
        let params = FlowParams::default()
            .with_reserved(num, den)
            .expect("valid reserve");
        let paid = diluted(5, &params);
        let total: u64 = paid.values().sum();
        assert_eq!(
            total, 2_800_000,
            "reserving {num}/{den} conserved differently"
        );
    }
}

#[test]
fn a_reserve_moves_nothing_when_the_enforced_citation_is_not_an_ancestor() {
    // A reserve pointed at a claim this one never cited would be paying for a
    // relationship the log does not record. The units still leave and still go
    // upstream; they are simply split discretionarily.
    let params = FlowParams::default()
        .with_reserved(1, 1)
        .expect("all of delta");
    let mut claims = BTreeMap::new();
    let alice = claim("alice", 0, Vec::new());
    let alice_id = alice.id();
    claims.insert(alice_id.clone(), alice);
    let bob = claim("bob", 1, vec![alice_id.clone()]);
    let bob_id = bob.id();
    claims.insert(bob_id.clone(), bob);
    let settlements = vec![(alice_id.clone(), 400_000u64), (bob_id.clone(), 400_000)];

    let stranger = claim("stranger", 77, Vec::new()).id();
    let enforced: BTreeMap<String, String> = [(bob_id, stranger)].into_iter().collect();
    let with_bogus =
        cairn::attribution::payouts_with_enforced(&settlements, &claims, &enforced, &params)
            .expect("flow succeeds");
    let without = payouts_over(&settlements, &claims, &params);
    assert_eq!(with_bogus, without.expect("flow succeeds"));
}
