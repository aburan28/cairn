//! Laws, not examples.
//!
//! Ported from the reference implementation's `test_gossip.py`,
//! `test_attribution.py`, `test_partition.py` and `test_ledger.py`. Each test
//! here states a property that has to hold for *every* input, not a single
//! worked case, because every one of them is load-bearing for a guarantee the
//! network makes to a reader who was not there when the work happened:
//!
//! - **Gossip merge is a join.** Commutative, associative, idempotent -- and it
//!   stays that way after pruning. If it did not, two nodes that saw the same
//!   messages in different orders would hold different populations and never
//!   find out.
//! - **Attribution conserves exactly.** Payouts sum to the amount settled. Not
//!   approximately: a rounding rule that leaks or invents a unit is a rounding
//!   rule that mints money.
//! - **Work assignment needs no coordinator.** It is a pure function every node
//!   can evaluate for every other node, and its slices tile the space with no
//!   gaps (unsearched regions) and no overlaps (two nodes provably responsible
//!   for one item).
//! - **The log is tamper-evident.** Editing or deleting an entry is detectable
//!   by anyone holding a copy, with no trusted party involved.
//!
//! Randomised properties use a small deterministic LCG defined below rather
//! than a random-number crate: a property test that cannot be replayed is a
//! property test that cannot be debugged, and the dependency budget for this
//! crate is spent on things that end up in a hash.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use proofwork::attribution::{flow, FlowError, FlowParams};
use proofwork::canonical::Value;
use proofwork::gossip::{ingest, Candidate, GossipError, Population};
use proofwork::ledger::Ledger;
use proofwork::partition::{assign, assignment_for, beacon, epoch_of, PartitionError, SPACE};
use proofwork::records::Claim;

// -- deterministic randomness ----------------------------------------------

/// A 64-bit linear congruential generator (Knuth's MMIX constants).
///
/// Not cryptographic and not trying to be: these tests need many *reproducible*
/// inputs, so the only requirements are that the stream is well spread and that
/// a failure can be replayed by re-running with the same seed. Wrapping
/// arithmetic is the definition of the generator, not an overflow bug.
struct Lcg(u64);

impl Lcg {
    fn new(seed: u64) -> Lcg {
        Lcg(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }

    /// A value in `0..bound`. The high bits are used because an LCG's low bits
    /// have short periods, which would make "random" tags repeat in a pattern.
    fn below(&mut self, bound: u64) -> u64 {
        if bound == 0 {
            return 0;
        }
        (self.next_u64() >> 33) % bound
    }

    fn below_usize(&mut self, bound: usize) -> usize {
        usize::try_from(self.below(bound as u64)).unwrap_or(0)
    }
}

/// Fisher-Yates. Every permutation is reachable, so "order does not matter" is
/// tested against real reorderings rather than rotations.
fn shuffle<T>(items: &mut [T], rng: &mut Lcg) {
    let mut i = items.len();
    while i > 1 {
        i -= 1;
        let j = rng.below_usize(i + 1);
        items.swap(i, j);
    }
}

// ==========================================================================
// Gossip: CRDT laws
// ==========================================================================

fn artifact(tag: &str) -> Value {
    Value::object([("tag", Value::string(tag))])
}

/// The reference implementation's `cand(score, tag)` helper.
fn cand(score: i64, tag: &str) -> Candidate {
    Candidate::new("obj", artifact(tag), score, "n0")
}

fn cand_from(score: i64, tag: &str, origin: &str) -> Candidate {
    Candidate::new("obj", artifact(tag), score, origin)
}

/// The reference implementation's `pop(*candidates, islands, capacity)`.
fn pop(candidates: Vec<Candidate>, islands: u32, capacity: usize) -> Population {
    Population::with_candidates(islands, capacity, candidates)
        .expect("islands and capacity are positive in every fixture here")
}

fn pop4x8(candidates: Vec<Candidate>) -> Population {
    pop(candidates, 4, 8)
}

fn merged(left: &Population, right: &Population) -> Population {
    left.merge(right).expect("island counts match")
}

#[test]
fn merge_is_commutative() {
    let a = pop4x8(vec![cand(1, "a"), cand(2, "b")]);
    let b = pop4x8(vec![cand(3, "c")]);
    assert_eq!(merged(&a, &b), merged(&b, &a));
}

#[test]
fn merge_is_associative() {
    let a = pop4x8(vec![cand(1, "a")]);
    let b = pop4x8(vec![cand(2, "b")]);
    let c = pop4x8(vec![cand(3, "c")]);
    assert_eq!(
        merged(&merged(&a, &b), &c),
        merged(&a, &merged(&b, &c)),
        "a join must not care how the messages were grouped"
    );
}

#[test]
fn merge_is_idempotent() {
    // Gossip redelivers. Receiving the same population twice must be a no-op,
    // or a duplicate delivery would look like new information.
    let a = pop4x8(vec![cand(1, "a"), cand(2, "b")]);
    assert_eq!(merged(&a, &a), a);
}

#[test]
fn pruning_preserves_associativity() {
    // The load-bearing property: bounded retention must not make merge order
    // matter. If it did, two nodes seeing the same messages in different orders
    // would end up with different populations and never notice.
    //
    // Why it holds: if a candidate is not in the top K of `A ∪ B`, then K
    // candidates in `A ∪ B` beat it, and those all survive into `A ∪ B ∪ C`, so
    // it is not in the top K of the larger union either. Dropping it early can
    // therefore never change a later answer.
    let mut rng = Lcg::new(1234);
    for case in 0..200 {
        let mut groups: Vec<Vec<Candidate>> = Vec::with_capacity(3);
        for _ in 0..3 {
            let size = rng.below(12) + 1;
            let mut group = Vec::new();
            for _ in 0..size {
                let score = i64::try_from(rng.below(51)).unwrap_or(0);
                let tag = format!("t{}", rng.below(100));
                group.push(cand(score, &tag));
            }
            groups.push(group);
        }
        let mut iter = groups.into_iter();
        let a = pop(iter.next().expect("three groups"), 2, 3);
        let b = pop(iter.next().expect("three groups"), 2, 3);
        let c = pop(iter.next().expect("three groups"), 2, 3);
        assert_eq!(
            merged(&merged(&a, &b), &c),
            merged(&a, &merged(&b, &c)),
            "case {case}: pruning made merge order observable"
        );
    }
}

#[test]
fn pruning_preserves_the_laws_when_origins_disagree() {
    // Same property, but with the one field that is *not* part of a candidate's
    // identity varying: two peers gossiping byte-identical content under
    // different names. The tie-break keeps the lexicographically smaller origin
    // -- a function of the values, so every node picks the same one, whereas
    // "first one seen" would make the result depend on delivery order.
    let mut rng = Lcg::new(0xC0FFEE);
    let origins = ["alice", "bob", "carol", "mallory"];
    for case in 0..200 {
        let mut groups: Vec<Vec<Candidate>> = Vec::with_capacity(3);
        for _ in 0..3 {
            let size = rng.below(8) + 1;
            let mut group = Vec::new();
            for _ in 0..size {
                let score = i64::try_from(rng.below(20)).unwrap_or(0);
                let tag = format!("t{}", rng.below(12));
                let origin = origins
                    .get(rng.below_usize(origins.len()))
                    .copied()
                    .unwrap_or("n0");
                group.push(cand_from(score, &tag, origin));
            }
            groups.push(group);
        }
        let mut iter = groups.into_iter();
        let a = pop(iter.next().expect("three groups"), 2, 3);
        let b = pop(iter.next().expect("three groups"), 2, 3);
        let c = pop(iter.next().expect("three groups"), 2, 3);

        assert_eq!(
            merged(&a, &b),
            merged(&b, &a),
            "case {case}: not commutative"
        );
        assert_eq!(
            merged(&merged(&a, &b), &c),
            merged(&a, &merged(&b, &c)),
            "case {case}: not associative"
        );
        assert_eq!(merged(&a, &a), a, "case {case}: not idempotent");
    }
}

#[test]
fn gossip_converges_regardless_of_delivery_order() {
    // The end-to-end statement of the three laws: a node that receives the same
    // 40 messages in twelve different orders ends up in the same state twelve
    // times. This is what buys convergence with no rounds, no leader and no
    // voting.
    let mut rng = Lcg::new(99);
    let messages: Vec<Candidate> = (0..40)
        .map(|i| {
            let score = i64::try_from(rng.below(101)).unwrap_or(0);
            cand(score, &format!("t{i}"))
        })
        .collect();

    let mut finals: Vec<Population> = Vec::new();
    for _ in 0..12 {
        let mut delivery = messages.clone();
        shuffle(&mut delivery, &mut rng);
        let mut node = Population::new(4, 5).expect("positive bounds");
        for message in delivery {
            node = merged(&node, &pop(vec![message], 4, 5));
        }
        finals.push(node);
    }
    let first = finals.first().expect("twelve runs");
    for (i, f) in finals.iter().enumerate() {
        assert_eq!(f, first, "delivery order {i} diverged");
    }
}

#[test]
fn ties_break_deterministically() {
    // Twenty candidates at the same score and a capacity that cannot hold them
    // all: the survivors must be chosen by a total order derived from the
    // values themselves. A tie-break on arrival time or sender would silently
    // fork the network.
    let same_score: Vec<Candidate> = (0..20).map(|i| cand(7, &format!("t{i}"))).collect();
    let first = pop(same_score.clone(), 2, 3);
    let mut rng = Lcg::new(0);
    for round in 0..10 {
        let mut shuffled = same_score.clone();
        shuffle(&mut shuffled, &mut rng);
        assert_eq!(
            pop(shuffled, 2, 3),
            first,
            "round {round}: equal scores were broken by something other than content"
        );
    }
}

#[test]
fn identical_artifact_from_two_peers_converges() {
    // Same content, two senders. Only `origin` differs, and origin is not part
    // of identity, so the two collapse to one entry -- the same one on both
    // nodes.
    let left = pop4x8(vec![cand_from(5, "a", "alice")]);
    let right = pop4x8(vec![cand_from(5, "a", "bob")]);
    assert_eq!(merged(&left, &right), merged(&right, &left));
    assert_eq!(merged(&left, &right).len(), 1);
    assert_eq!(
        merged(&left, &right)
            .best()
            .map(|c| c.origin.clone())
            .as_deref(),
        Some("alice"),
        "the tie-break keeps the lexicographically smaller origin"
    );
}

#[test]
fn same_artifact_at_two_scores_converges() {
    // One peer is lying about this artifact's score. Merge must still converge:
    // both entries are representable and every node keeps the same ones.
    //
    // This is why the claimed score is part of a candidate's identity. If it
    // were not, merge would have to pick a winner between two values equal
    // under the key, and any tie-break not derived from the values themselves
    // destroys convergence. Keeping both makes the disagreement *visible*
    // instead of silently absorbed -- which is what lets `ingest` catch it.
    let honest = cand_from(5, "a", "alice");
    let inflated = cand_from(999, "a", "mallory");
    assert_eq!(
        honest.artifact_id(),
        inflated.artifact_id(),
        "the artifact is the same artifact"
    );
    assert_ne!(honest.id(), inflated.id(), "the assertions about it differ");
    assert_eq!(
        honest.island(8),
        inflated.island(8),
        "honest and inflated variants must land in the same island so they \
         compete for one slot instead of occupying two"
    );

    let left = pop4x8(vec![honest]);
    let right = pop4x8(vec![inflated]);
    assert_eq!(merged(&left, &right), merged(&right, &left));
    assert_eq!(merged(&left, &right).len(), 2);
}

#[test]
fn merging_different_island_counts_is_refused() {
    // The same candidate hashes into different islands under different counts,
    // so the union would not be well defined and per-island retention would not
    // be either. Refused loudly rather than silently producing a population
    // neither peer can reproduce.
    let left = pop(vec![cand(1, "x")], 2, 8);
    let right = pop(vec![cand(1, "x")], 4, 8);
    assert_eq!(
        left.merge(&right),
        Err(GossipError::IslandCountMismatch { left: 2, right: 4 })
    );
}

#[test]
fn capacity_is_enforced_per_island_and_the_best_survive() {
    let mut population = Population::new(1, 3).expect("positive bounds");
    for i in 0..20 {
        population.add(cand(i, &format!("t{i}")));
    }
    let scores: Vec<i64> = population.top(3).iter().map(|c| c.score).collect();
    assert_eq!(
        scores,
        vec![19, 18, 17],
        "pruning must keep the top K, not any K"
    );
    assert_eq!(population.len(), 3);
}

#[test]
fn islands_preserve_diversity() {
    // A run of strong candidates must not evict every weaker island: diversity
    // is what the search depends on, so retention is per island, not global.
    let mut population = Population::new(4, 2).expect("positive bounds");
    for i in 0..200 {
        population.add(cand(i, &format!("t{i}")));
    }
    let occupied = (0..4)
        .filter(|i| !population.island_members(*i).is_empty())
        .count();
    assert!(occupied > 1, "one lineage swept every island");
    assert!(
        population.len() <= 8,
        "the global bound is islands * capacity"
    );
}

#[test]
fn digest_detects_equality_cheaply() {
    // Two peers exchange digests; equal digests mean there is nothing to send.
    // The digest must therefore depend on the retained set and nothing else --
    // not on insertion order, not on island layout.
    let a = pop4x8(vec![cand(1, "a"), cand(2, "b")]);
    let b = pop4x8(vec![cand(2, "b"), cand(1, "a")]);
    assert_eq!(a.digest(), b.digest());
    assert_ne!(a.digest(), pop4x8(vec![cand(1, "a")]).digest());
}

#[test]
fn round_trips_through_its_wire_form() {
    let population = pop4x8(vec![cand(1, "a"), cand(9, "b"), cand(4, "c")]);
    let decoded = Population::from_value(&population.to_value()).expect("its own encoding decodes");
    assert_eq!(decoded, population);
}

// -- gossip is untrusted ---------------------------------------------------

/// The reference implementation's `real_score`: the honest local evaluation.
fn real_score(artifact: &Value) -> Option<i64> {
    let tag = artifact.get("tag").and_then(Value::as_str).unwrap_or("");
    i64::try_from(tag.len()).ok()
}

#[test]
fn ingest_accepts_an_honest_candidate() {
    let mut population = Population::new(2, 4).expect("positive bounds");
    assert!(ingest(&mut population, cand(3, "abc"), real_score));
    assert_eq!(population.len(), 1);
}

#[test]
fn ingest_rejects_an_inflated_score() {
    // Without this, a peer asserts score = 10^9 and evicts every genuine
    // candidate from a bounded population -- a cheap denial of service against
    // the search itself. The defence is that checking costs one evaluation,
    // which is the evaluation the node was going to spend on this candidate
    // anyway.
    let mut population = Population::new(2, 4).expect("positive bounds");
    assert!(!ingest(
        &mut population,
        cand(1_000_000_000, "abc"),
        real_score
    ));
    assert_eq!(
        population.len(),
        0,
        "an unverified score must not reach the population"
    );
}

#[test]
fn ingest_rejects_a_candidate_that_crashes_the_scorer() {
    // A crash while scoring a peer's candidate says nothing about the candidate
    // and must not be recorded as a score of its own. The Python reference
    // catches the exception; here the contract is that a scorer signals failure
    // with `None`, because `catch_unwind` does nothing under `panic = "abort"`
    // and a defence that silently stops working is worse than none.
    let mut population = Population::new(2, 4).expect("positive bounds");
    let explode = |_: &Value| -> Option<i64> { None };
    assert!(!ingest(&mut population, cand(1, "a"), explode));
    assert_eq!(population.len(), 0);
}

#[test]
fn ingest_rejects_a_score_the_scorer_cannot_state_as_an_integer() {
    // The reference implementation's `lambda a: 3.0` case. A float score is not
    // merely rejected here, it is unrepresentable: `rescore` returns
    // `Option<i64>`, so a scorer with a non-integer answer has no way to state
    // it and must report failure instead. Failure means reject, never accept.
    let mut population = Population::new(2, 4).expect("positive bounds");
    let unrepresentable = |_: &Value| -> Option<i64> { None };
    assert!(!ingest(&mut population, cand(3, "abc"), unrepresentable));
    assert_eq!(population.len(), 0);
}

#[test]
fn ingest_rejects_a_score_that_is_merely_close() {
    // Reproduction is exact. "Close enough" is a policy two nodes can disagree
    // about, and disagreement about which candidates exist is the failure this
    // whole module is built to avoid.
    let mut population = Population::new(2, 4).expect("positive bounds");
    assert!(!ingest(&mut population, cand(4, "abc"), real_score));
    assert!(!ingest(&mut population, cand(2, "abc"), real_score));
    assert!(ingest(&mut population, cand(3, "abc"), real_score));
    assert_eq!(population.len(), 1);
}

// ==========================================================================
// Attribution: conservation and determinism
// ==========================================================================

fn claim(submitter: &str, cites: Vec<String>) -> Claim {
    Claim::new(
        "obj",
        submitter,
        Value::object([("who", Value::string(submitter))]),
        "n",
        "2026-07-28T00:00:00+00:00",
        cites,
    )
    .expect("fixture claims are well formed")
}

fn index(claims: &[Claim]) -> BTreeMap<String, Claim> {
    claims.iter().map(|c| (c.id(), c.clone())).collect()
}

fn params(num: u64, den: u64, depth: u32) -> FlowParams {
    FlowParams::new(num, den, depth).expect("fixture parameters are valid")
}

/// Summed in `u128` so the assertion itself cannot be the thing that overflows.
fn total(payouts: &BTreeMap<String, u64>) -> u128 {
    payouts.values().map(|v| u128::from(*v)).sum()
}

#[test]
fn claim_with_no_citations_keeps_everything() {
    let solo = claim("alice", vec![]);
    let payouts = flow(
        &solo.id(),
        1000,
        &index(std::slice::from_ref(&solo)),
        &FlowParams::default(),
    );
    assert_eq!(payouts.get("alice").copied(), Some(1000));
    assert_eq!(payouts.len(), 1);
}

#[test]
fn one_hop_split_pays_the_shoulders_stood_on() {
    let base = claim("alice", vec![]);
    let built = claim("bob", vec![base.id()]);
    let claims = index(&[base, built.clone()]);
    let payouts = flow(&built.id(), 1000, &claims, &params(1, 4, 6));
    assert_eq!(payouts.get("bob").copied(), Some(750));
    assert_eq!(payouts.get("alice").copied(), Some(250));
}

#[test]
fn two_hops_decay() {
    let a = claim("alice", vec![]);
    let b = claim("bob", vec![a.id()]);
    let c = claim("carol", vec![b.id()]);
    let claims = index(&[a, b, c.clone()]);
    let payouts = flow(&c.id(), 1000, &claims, &params(1, 4, 6));
    assert_eq!(payouts.get("carol").copied(), Some(750));
    assert_eq!(payouts.get("bob").copied(), Some(188)); // 250 - floor(250/4)
    assert_eq!(payouts.get("alice").copied(), Some(62));
    assert_eq!(total(&payouts), 1000);
}

#[test]
fn conservation_is_exact() {
    // Rounding must never leak or invent a unit, at any amount or any delta.
    // The Rust-only entries in `amounts` are the ones Python could not have:
    // `share * delta_num` overflows u64 long before the *result* stops fitting,
    // because delta <= 1. A wrapped intermediate here would pay somebody a
    // number unrelated to what was funded.
    let amounts: [u64; 12] = [
        1,
        2,
        3,
        7,
        999,
        1000,
        1_000_000,
        1_000_000_007,
        u64::MAX / 3,
        u64::MAX / 2,
        u64::MAX - 1,
        u64::MAX,
    ];
    let deltas: [(u64, u64); 6] = [(0, 1), (1, 3), (1, 4), (1, 2), (2, 3), (1, 1)];

    let a = claim("alice", vec![]);
    let b = claim("bob", vec![]);
    let c = claim("carol", vec![a.id(), b.id()]);
    let d = claim("dave", vec![c.id(), a.id()]);
    let claims = index(&[a, b, c, d.clone()]);

    for amount in amounts {
        for (num, den) in deltas {
            let payouts = flow(&d.id(), amount, &claims, &params(num, den, 8));
            assert_eq!(
                total(&payouts),
                u128::from(amount),
                "amount {amount} with delta {num}/{den} did not conserve"
            );
        }
    }
}

#[test]
fn conservation_holds_down_a_deep_chain_at_the_top_of_the_range() {
    // Depth multiplies the number of divisions, so it multiplies the number of
    // chances to lose a unit. Ten hops at u64::MAX is the worst case this crate
    // can be handed.
    let mut chain = vec![claim("a0", vec![])];
    for i in 1..10 {
        let previous = chain.last().map(Claim::id).unwrap_or_default();
        chain.push(claim(&format!("a{i}"), vec![previous]));
    }
    let claims = index(&chain);
    let last = chain.last().map(Claim::id).unwrap_or_default();
    for (num, den) in [(1u64, 2u64), (2, 3), (1, 7), (1, 1)] {
        let payouts = flow(&last, u64::MAX, &claims, &params(num, den, 9));
        assert_eq!(total(&payouts), u128::from(u64::MAX), "delta {num}/{den}");
    }
}

#[test]
fn uneven_split_is_deterministic() {
    // Three citations, one indivisible remainder: every node must agree who
    // gets the odd unit. Any rule conserves; only a rule reproducible from the
    // record itself keeps two nodes in agreement, so the remainder goes to the
    // earliest citations in sorted claim-id order.
    let a = claim("alice", vec![]);
    let b = claim("bob", vec![]);
    let c = claim("carol", vec![]);
    let d = claim("dave", vec![a.id(), b.id(), c.id()]);
    let claims = index(&[a.clone(), b.clone(), c.clone(), d.clone()]);

    let first = flow(&d.id(), 1001, &claims, &params(1, 2, 4));
    for round in 0..20 {
        assert_eq!(
            flow(&d.id(), 1001, &claims, &params(1, 2, 4)),
            first,
            "round {round}: the split moved"
        );
    }

    // And the odd units land where the rule says: 1001 -> dave keeps 501,
    // 500 splits three ways as 167/167/166, with the extra unit going to the
    // two lexicographically smallest citation ids.
    assert_eq!(first.get("dave").copied(), Some(501));
    let mut by_id: Vec<(String, String)> = [&a, &b, &c]
        .iter()
        .map(|cl| (cl.id(), cl.submitter.clone()))
        .collect();
    by_id.sort();
    let paid: Vec<u64> = by_id
        .iter()
        .map(|(_, who)| first.get(who).copied().unwrap_or(0))
        .collect();
    assert_eq!(
        paid,
        vec![167, 167, 166],
        "the remainder must go to the earliest citations in sorted id order"
    );
    assert_eq!(total(&first), 1001);
}

#[test]
fn diamond_accumulates_both_paths() {
    // The same root cited through two different descendants is paid twice, once
    // per real edge. Attribution prices *declared dependency*, and a diamond
    // declares the dependency twice.
    let root = claim("alice", vec![]);
    let left = claim("bob", vec![root.id()]);
    let right = claim("carol", vec![root.id()]);
    let top = claim("dave", vec![left.id(), right.id()]);
    let claims = index(&[root, left, right, top.clone()]);

    let payouts = flow(&top.id(), 10_000, &claims, &params(1, 2, 6));
    assert_eq!(
        payouts.get("alice").copied(),
        Some(2500),
        "both paths must land"
    );
    assert_eq!(total(&payouts), 10_000);
}

#[test]
fn depth_cap_stops_the_flow() {
    // Without a cap, one settlement walks an unbounded DAG. The remainder stays
    // with the claim that reached the cap rather than evaporating.
    let mut chain = vec![claim("a0", vec![])];
    for i in 1..10 {
        let previous = chain.last().map(Claim::id).unwrap_or_default();
        chain.push(claim(&format!("a{i}"), vec![previous]));
    }
    let claims = index(&chain);
    let last = chain.last().map(Claim::id).unwrap_or_default();

    let payouts = flow(&last, 1_000_000, &claims, &params(1, 2, 2));
    assert!(
        !payouts.contains_key("a6"),
        "value travelled further than max_depth"
    );
    assert_eq!(
        total(&payouts),
        1_000_000,
        "the capped remainder must not be burned"
    );
}

#[test]
fn zero_depth_pays_only_the_settling_claim() {
    let a = claim("alice", vec![]);
    let b = claim("bob", vec![a.id()]);
    let claims = index(&[a, b.clone()]);
    let payouts = flow(&b.id(), 500, &claims, &params(1, 4, 0));
    assert_eq!(payouts.get("bob").copied(), Some(500));
    assert_eq!(payouts.len(), 1);
}

#[test]
fn delta_zero_pays_only_the_settling_claim() {
    let a = claim("alice", vec![]);
    let b = claim("bob", vec![a.id()]);
    let claims = index(&[a, b.clone()]);
    let payouts = flow(&b.id(), 500, &claims, &params(0, 1, 6));
    assert_eq!(payouts.get("bob").copied(), Some(500));
    assert_eq!(payouts.len(), 1, "nobody upstream should even appear");
}

#[test]
fn delta_one_passes_everything_upstream_and_still_conserves() {
    // delta = 1 is the edge the reference implementation deliberately allows:
    // the settling claim keeps zero and still appears in the map with a zero
    // value, because it was credited. Conservation is unaffected.
    let a = claim("alice", vec![]);
    let b = claim("bob", vec![a.id()]);
    let claims = index(&[a, b.clone()]);
    let payouts = flow(&b.id(), 400, &claims, &params(1, 1, 6));
    assert_eq!(payouts.get("bob").copied(), Some(0));
    assert_eq!(payouts.get("alice").copied(), Some(400));
    assert_eq!(total(&payouts), 400);
}

#[test]
fn unresolvable_citation_does_not_burn_value() {
    // A citation nobody can resolve is not evidence of anything, but the units
    // behind it are real. They stay with the claim that cited it rather than
    // disappearing from the accounts.
    let ghost = format!("sha256:{}", "0".repeat(64));
    let orphan = claim("bob", vec![ghost.clone()]);
    let claims = index(std::slice::from_ref(&orphan));
    let payouts = flow(&orphan.id(), 800, &claims, &FlowParams::default());
    assert_eq!(payouts.get("bob").copied(), Some(800));
    assert_eq!(payouts.len(), 1);
    assert_eq!(total(&payouts), 800);
}

#[test]
fn a_mix_of_real_and_ghost_citations_conserves() {
    // The dangerous middle case: one edge resolves and one does not, so the
    // split has to happen over the survivors only. Splitting over all of them
    // and dropping the ghost's portion would silently burn a quarter of the
    // reward.
    let real = claim("alice", vec![]);
    let ghost = format!("sha256:{}", "f".repeat(64));
    let built = claim("bob", vec![real.id(), ghost.clone()]);
    let claims = index(&[real, built.clone()]);
    let payouts = flow(&built.id(), 1000, &claims, &params(1, 4, 6));
    assert_eq!(payouts.get("bob").copied(), Some(750));
    assert_eq!(payouts.get("alice").copied(), Some(250));
    assert_eq!(total(&payouts), 1000);
}

#[test]
fn self_citation_cycle_terminates() {
    // Citations point backwards, so a cycle should be impossible -- but "should"
    // is not a termination argument when the DAG is attacker-supplied. A claim
    // that reaches itself must stop, and must still conserve.
    let a = claim("alice", vec![]);
    let looped = Claim::new(
        "obj",
        "alice",
        Value::object([("x", Value::Int(1))]),
        "n",
        "t",
        vec![a.id()],
    )
    .expect("well formed");

    // Deliberately a log whose keys disagree with the records under them: the
    // id `a.id()` resolves to `looped`, so following the citation returns to the
    // same record under a different key. Keying the cycle check on the map key
    // is what stops this.
    let mut claims: BTreeMap<String, Claim> = BTreeMap::new();
    claims.insert(a.id(), looped.clone());
    claims.insert(looped.id(), looped.clone());

    let payouts = flow(&looped.id(), 100, &claims, &FlowParams::default());
    assert_eq!(total(&payouts), 100);
}

#[test]
fn zero_amount_pays_nobody() {
    // An empty map, not a map of zeros: nothing was settled, so nobody was
    // credited.
    let a = claim("alice", vec![]);
    let payouts = flow(
        &a.id(),
        0,
        &index(std::slice::from_ref(&a)),
        &FlowParams::default(),
    );
    assert!(payouts.is_empty());
}

#[test]
fn settling_an_unknown_claim_pays_nobody() {
    let a = claim("alice", vec![]);
    let payouts = flow(
        "sha256:deadbeef",
        1000,
        &index(&[a]),
        &FlowParams::default(),
    );
    assert!(
        payouts.is_empty(),
        "there is no submitter to pay and inventing one would be worse"
    );
}

#[test]
fn invalid_flow_params_are_rejected() {
    // A delta above one would have a claim send upstream more than it received,
    // which conservation cannot survive. A zero denominator is not "delta = 0",
    // it is a division with no answer -- and in Rust it is also a panic, so it
    // is refused at construction rather than at split time.
    assert_eq!(
        FlowParams::new(3, 2, 4),
        Err(FlowError::DeltaAboveOne { num: 3, den: 2 })
    );
    assert_eq!(FlowParams::new(1, 0, 4), Err(FlowError::ZeroDenominator));
    // The reference implementation's third case, `max_depth = -1`, has no port:
    // `max_depth` is a `u32`, so a negative depth cannot be written down.
    assert!(FlowParams::new(1, 4, 0).is_ok());
    assert!(FlowParams::new(4, 4, 6).is_ok());
}

// ==========================================================================
// Partition: coordinator-free work assignment
// ==========================================================================

fn drawn(node: &str, objective: &str, epoch_beacon: &str, partitions: u32) -> u32 {
    assign(node, objective, epoch_beacon, partitions).expect("partitions are positive")
}

#[test]
fn assignment_is_deterministic() {
    // Every node must be able to recompute every other node's assignment, which
    // is what turns "did you actually search your region?" into a checkable
    // question rather than a matter of trust.
    let b = beacon(7, "anchor");
    assert_eq!(
        drawn("node-a", "obj", &b, 16),
        drawn("node-a", "obj", &b, 16)
    );
}

#[test]
fn different_nodes_get_different_partitions() {
    let b = beacon(7, "anchor");
    let seen: HashSet<u32> = (0..200)
        .map(|i| drawn(&format!("node-{i}"), "obj", &b, 16))
        .collect();
    assert!(
        seen.len() > 8,
        "assignment is not spreading nodes across partitions"
    );
}

#[test]
fn assignment_rotates_between_epochs() {
    // Without rotation a node owns a region forever, so an adversary grinds one
    // identity into a region and then does nothing, starving it indefinitely.
    // Rotation makes squatting cost a fresh grinding effort every epoch.
    let moved = (0..100u64)
        .filter(|e| {
            drawn("node-a", "obj", &beacon(*e, "anchor"), 32)
                != drawn("node-a", "obj", &beacon(e + 1, "anchor"), 32)
        })
        .count();
    assert!(
        moved > 90,
        "only {moved} of 100 epoch boundaries moved the assignment"
    );
}

#[test]
fn assignment_differs_across_objectives() {
    // A node must not be able to hold the same region on every objective at
    // once; the objective id is mixed in for exactly that reason.
    let b = beacon(3, "anchor");
    let seen: HashSet<u32> = (0..100)
        .map(|i| drawn("node-a", &format!("obj-{i}"), &b, 32))
        .collect();
    assert!(seen.len() > 8);
}

#[test]
fn distribution_is_roughly_uniform() {
    // Assignment only has to spread nodes out, not be uniform to the last bit
    // -- but a badly skewed draw would leave regions with nobody in them, which
    // is the same failure as no assignment at all.
    let b = beacon(1, "anchor");
    let partitions = 8u32;
    let mut counts = vec![0usize; partitions as usize];
    for i in 0..8000 {
        let p = drawn(&format!("node-{i}"), "obj", &b, partitions);
        if let Some(slot) = counts.get_mut(p as usize) {
            *slot += 1;
        }
    }
    let expected = 8000 / partitions as usize;
    for count in &counts {
        assert!(
            *count * 100 > expected * 85 && *count * 100 < expected * 115,
            "skewed distribution: {counts:?}"
        );
    }
}

#[test]
fn shares_tile_the_space_without_gaps_or_overlap() {
    // Both halves matter. A gap leaves items nobody is assigned to search; an
    // overlap makes two nodes provably responsible for the same item and breaks
    // the "did you search your region?" check.
    let partitions = 7u32;
    let mut spans: Vec<(u64, u64)> = (0..200)
        .map(|i| {
            assignment_for(&format!("n{i}"), "obj", 1, "anchor", partitions)
                .expect("partitions are positive")
                .share()
        })
        .collect();
    spans.sort();
    spans.dedup();

    assert_eq!(
        spans.len(),
        partitions as usize,
        "not every partition was drawn"
    );
    assert_eq!(
        spans.first().map(|s| s.0),
        Some(0),
        "the space must start at 0"
    );
    assert_eq!(
        spans.last().map(|s| s.1),
        Some(SPACE),
        "the last partition absorbs the truncation remainder and ends at 2^32"
    );
    for pair in spans.windows(2) {
        if let [(_, hi), (lo, _)] = pair {
            assert_eq!(hi, lo, "partitions must tile the space exactly");
        }
    }
}

#[test]
fn covers_partitions_items_exactly_once() {
    // The consequence of tiling, stated over real items: every item has exactly
    // one owner, so responsibility for a region is unambiguous.
    let partitions = 4u32;
    let mut by_partition: BTreeMap<u32, _> = BTreeMap::new();
    for i in 0..400 {
        let a = assignment_for(&format!("n{i}"), "obj", 1, "anchor", partitions)
            .expect("partitions are positive");
        by_partition.insert(a.partition, a);
    }
    assert_eq!(by_partition.len(), partitions as usize);

    for i in 0..300 {
        let item = format!("item-{i}");
        let owners: Vec<u32> = by_partition
            .iter()
            .filter(|(_, a)| a.covers(&item))
            .map(|(p, _)| *p)
            .collect();
        assert_eq!(owners.len(), 1, "{item} owned by {owners:?}");
    }
}

#[test]
fn beacon_changes_with_anchor_and_stays_bare_hex() {
    assert_ne!(beacon(1, "a"), beacon(1, "b"));
    // The beacon is fed to the MAC as key material byte for byte, so its
    // spelling is part of the wire format: prefixing it the way digests are
    // prefixed would move every assignment in the network.
    let value = beacon(1, "a");
    assert_eq!(value.len(), 64);
    assert!(!value.starts_with("sha256:"));
}

#[test]
fn epoch_of_is_monotone() {
    assert_eq!(epoch_of(0, 600), 0);
    assert_eq!(epoch_of(599, 600), 0);
    assert_eq!(epoch_of(600, 600), 1);
}

#[test]
fn partitions_must_be_positive() {
    // Python raises ValueError; in Rust `draw % 0` is a panic, and a panic in
    // assignment is a remote crash triggered by a number any peer can put in a
    // record.
    assert_eq!(
        assign("n", "o", &beacon(1, "a"), 0),
        Err(PartitionError::ZeroPartitions)
    );
    assert_eq!(
        assignment_for("n", "o", 1, "a", 0),
        Err(PartitionError::ZeroPartitions)
    );
}

// ==========================================================================
// Ledger: tamper evidence
// ==========================================================================

/// A scratch directory that removes itself, including when a test panics.
///
/// No `tempfile` crate: the dependency budget for this crate is spent on things
/// whose bytes end up in a hash. Uniqueness comes from the process id, a
/// monotonic clock reading and a counter, so parallel test threads and
/// concurrent `cargo test` runs cannot collide.
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> TempDir {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "proofwork-properties-{label}-{}-{nanos}-{n}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("scratch directory is creatable");
        TempDir { path }
    }

    fn file(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        // Best effort: a failed cleanup must not turn a passing test red, and
        // must not mask the panic that is already unwinding through here.
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn note(i: i128) -> Value {
    Value::object([("i", Value::Int(i))])
}

fn read_lines(path: &Path) -> Vec<String> {
    fs::read_to_string(path)
        .expect("the log is readable")
        .lines()
        .map(str::to_string)
        .collect()
}

#[test]
fn chain_verifies_when_intact() {
    let dir = TempDir::new("intact");
    let path = dir.file("log.jsonl");
    let mut ledger = Ledger::open(&path).expect("a missing file is an empty log");
    for i in 0..5 {
        ledger
            .append("note", note(i), "2026-07-28T00:00:00+00:00")
            .expect("append succeeds");
    }
    assert_eq!(ledger.verify_chain(), Vec::<String>::new());
    assert_eq!(ledger.len(), 5);
}

#[test]
fn entries_link_to_their_predecessor() {
    let dir = TempDir::new("links");
    let mut ledger = Ledger::open(dir.file("log.jsonl")).expect("empty log");
    let first = ledger.append("note", note(0), "t").expect("append").clone();
    let second = ledger.append("note", note(1), "t").expect("append").clone();
    assert_eq!(first.prev, None, "genesis has no predecessor");
    assert_eq!(second.prev.as_deref(), Some(first.hash.as_str()));
    assert_eq!(second.seq, 1);
}

#[test]
fn reload_from_disk_preserves_the_chain() {
    // The whole promise is that a reader with nothing but a copy of the file can
    // re-derive what the operator derived. So a ledger loaded from disk must be
    // indistinguishable from the one that wrote it.
    let dir = TempDir::new("reload");
    let path = dir.file("log.jsonl");
    let head = {
        let mut ledger = Ledger::open(&path).expect("empty log");
        ledger.append("note", note(0), "t").expect("append");
        ledger.append("note", note(1), "t").expect("append");
        ledger.head().map(str::to_string)
    };

    let reloaded = Ledger::open(&path).expect("the log reloads");
    assert_eq!(reloaded.head().map(str::to_string), head);
    assert_eq!(reloaded.verify_chain(), Vec::<String>::new());
    assert_eq!(reloaded.len(), 2);
}

#[test]
fn tampering_with_a_payload_is_detected() {
    // The attack: quietly raise an amount already written to the log. The entry
    // hash covers the payload, so the edit no longer reproduces the stored hash
    // -- and repairing that hash would break every `prev` after it, which is why
    // rewriting one entry means rewriting the whole suffix.
    let dir = TempDir::new("tamper");
    let path = dir.file("log.jsonl");
    {
        let mut ledger = Ledger::open(&path).expect("empty log");
        ledger
            .append("note", Value::object([("amount", Value::Int(1))]), "t")
            .expect("append");
        ledger
            .append("note", Value::object([("amount", Value::Int(2))]), "t")
            .expect("append");
    }

    let mut lines = read_lines(&path);
    let first = lines.first().cloned().expect("two entries were written");
    let value = Value::from_json(&first).expect("the stored line is JSON");
    let mut record = match value {
        Value::Object(map) => map,
        _ => panic!("a stored entry is an object"),
    };
    let mut payload = match record.get("payload") {
        Some(Value::Object(map)) => map.clone(),
        _ => panic!("a stored entry carries an object payload"),
    };
    payload.insert("amount".to_string(), Value::Int(1_000_000));
    record.insert("payload".to_string(), Value::Object(payload));
    // The `hash` field is left exactly as written -- that is the forgery.
    if let Some(slot) = lines.first_mut() {
        *slot = Value::Object(record).canonical_string();
    }
    fs::write(&path, format!("{}\n", lines.join("\n"))).expect("the log is writable");

    let problems = Ledger::open(&path)
        .expect("a doctored log still parses")
        .verify_chain();
    assert!(
        problems.iter().any(|p| p.contains("hash mismatch")),
        "an edited payload went unnoticed: {problems:?}"
    );
}

#[test]
fn deleting_an_entry_breaks_the_chain() {
    // Every surviving entry is perfectly well-formed on its own, which is why
    // `seq` counting from zero and `prev` linking backwards are separate checks:
    // a deletion is invisible to either one alone.
    let dir = TempDir::new("deletion");
    let path = dir.file("log.jsonl");
    {
        let mut ledger = Ledger::open(&path).expect("empty log");
        for i in 0..4 {
            ledger.append("note", note(i), "t").expect("append");
        }
    }

    let mut lines = read_lines(&path);
    assert_eq!(lines.len(), 4);
    lines.remove(1);
    fs::write(&path, format!("{}\n", lines.join("\n"))).expect("the log is writable");

    let problems = Ledger::open(&path)
        .expect("a shortened log still parses")
        .verify_chain();
    assert!(
        !problems.is_empty(),
        "removing an entry must not go unnoticed"
    );
}

#[test]
fn a_malformed_line_is_an_error_not_a_silently_shorter_log() {
    // Skipping an unparseable line would turn corruption into truncation, and a
    // truncated prefix of a valid chain verifies. Refusing to open is the only
    // safe answer.
    let dir = TempDir::new("malformed");
    let path = dir.file("log.jsonl");
    fs::write(&path, "{not json}\n").expect("the log is writable");
    assert!(Ledger::open(&path).is_err());
}

#[test]
fn a_float_payload_cannot_reach_the_log_at_all() {
    // The reference implementation checks for floats on append and raises. Here
    // the check is earlier and stronger: `Value` has no float variant, so a
    // payload built in Rust is canonically serializable by construction and the
    // only way a float can appear is in a line written by some other tool --
    // where it is caught at the parsing boundary instead.
    assert!(Value::from_json(r#"{"score": 0.5}"#).is_err());

    let dir = TempDir::new("float");
    let path = dir.file("log.jsonl");
    fs::write(
        &path,
        "{\"hash\":\"sha256:00\",\"kind\":\"note\",\"payload\":{\"score\":0.5},\
         \"prev\":null,\"seq\":0,\"ts\":\"t\"}\n",
    )
    .expect("the log is writable");
    assert!(
        Ledger::open(&path).is_err(),
        "a float on disk must be refused, not rounded into agreement"
    );
}

#[test]
fn merkle_root_changes_with_every_append() {
    // The root is what a third party pins to prove one settlement is in the log
    // without holding the log. A root that repeated across appends would let two
    // different logs share a commitment.
    let dir = TempDir::new("merkle");
    let mut ledger = Ledger::open(dir.file("log.jsonl")).expect("empty log");
    assert_eq!(ledger.root(), None, "an empty log commits to nothing");

    let mut roots: BTreeSet<String> = BTreeSet::new();
    for i in 0..6 {
        ledger.append("note", note(i), "t").expect("append");
        roots.insert(ledger.root().expect("a non-empty log has a root"));
    }
    assert_eq!(roots.len(), 6, "an append left the commitment unchanged");
}

#[test]
fn head_and_root_move_together_and_survive_a_reload() {
    // Verifying the chain proves the log is internally consistent; it cannot
    // prove nobody truncated the tail, because a prefix of a valid chain is a
    // valid chain. That gap is closed by a reader who remembers yesterday's head
    // and root -- so both must be stable across a reload.
    let dir = TempDir::new("pinning");
    let path = dir.file("log.jsonl");
    let (head, root) = {
        let mut ledger = Ledger::open(&path).expect("empty log");
        for i in 0..3 {
            ledger.append("note", note(i), "t").expect("append");
        }
        (
            ledger.head().map(str::to_string),
            ledger.root().expect("non-empty"),
        )
    };

    let reloaded = Ledger::open(&path).expect("reload");
    assert_eq!(reloaded.head().map(str::to_string), head);
    assert_eq!(reloaded.root().expect("non-empty"), root);

    // Truncating the tail is exactly the case verify_chain cannot see on its
    // own: the shortened log is internally consistent, and only the remembered
    // root catches it.
    let mut lines = read_lines(&path);
    lines.pop();
    fs::write(&path, format!("{}\n", lines.join("\n"))).expect("writable");
    let truncated = Ledger::open(&path).expect("reload");
    assert_eq!(
        truncated.verify_chain(),
        Vec::<String>::new(),
        "a truncated prefix is itself a valid chain"
    );
    assert_ne!(
        truncated.root().expect("non-empty"),
        root,
        "the published root is what catches the rollback"
    );
}
