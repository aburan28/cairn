//! Deterministic simulation of a multi-node network, FoundationDB-style.
//!
//! # What this is
//!
//! A discrete-event simulator over **real nodes**: every `Node` here runs the
//! actual rules engine — real verifiers, real epochs, real settlement — and
//! only the *network and the clock* are simulated. A sync session is a set of
//! records delivered at a virtual instant drawn from a seeded PRNG; replay
//! mirrors `p2p::service::apply_records` exactly, kind by kind, stamped with
//! each record's own `created_at`. Nothing here mocks the thing under test.
//!
//! # Why it exists
//!
//! Every settlement-ordering defect this repository has had was a *timing*
//! bug, and the convergence tests in `tests/p2p_convergence.rs` are
//! synchronous — hand alice's records to bob, all at once, then settle. They
//! state the deterministic half of the invariant and structurally cannot
//! reach the timing half: what happens when a session lands **after** a node
//! has already drained the epoch its records belong to. That case is the one
//! `docs/design/settlement-convergence.md` documents as open, and until this
//! file nothing in the repository could reproduce it, let alone pin a fix.
//!
//! It earned its keep before it was even green: the first run found that
//! `apply_records` replayed claims in **id order**, so a later-epoch reveal
//! replayed first drains an earlier epoch as a side effect and the earlier
//! claim is refused out of the same session. See the sorting comment in
//! `p2p::service::replay_records`.
//!
//! That find also cost a wrong claim, which is worth recording because it is
//! the failure mode this file exists to prevent. The first test written for
//! it used a cold sync and **passed with the fix removed** — a node holding
//! nothing for an epoch never drains it, so cold sync is immune. A mutation
//! test caught that the test pinned nothing. Every assertion here about a fix
//! has since been checked the same way: disable the fix, watch it fail.
//!
//! A failure prints its seed, and the same seed replays the same run — the
//! idiom `scripts/fuzz-differential.sh` established.
//!
//! # What this is not
//!
//! Not a performance model (virtual time is free), not a byzantine simulator
//! (every node runs the honest rules; adversarial *strategies* belong to an
//! agent harness over the incentive layer, a different tool), and not a
//! substitute for TLC (TLC checks all interleavings of a small abstract
//! model; this checks many interleavings of the real code).

use std::path::PathBuf;

use proofwork::canonical::Value;
use proofwork::ledger::Ledger;
use proofwork::node::Node;
use proofwork::records::{commitment_hash, Claim, Commitment, Objective};
use proofwork::time::format_iso8601_utc;

/// The protocol's default epoch length. The sim never overrides
/// `PROOFWORK_EPOCH_SECONDS`; runs simulate the deployed configuration.
const EPOCH: i64 = 600;

// ---------------------------------------------------------------------------
// A tiny, seedable, well-understood PRNG.
//
// SplitMix64: public domain, and *stable forever* -- which is the property
// that matters, because a seed printed by a failure last month must replay
// the same run today. `rand` would trade that for someone else's version
// bumps; `Date::now`-style entropy would trade it for nothing at all.
// ---------------------------------------------------------------------------

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Uniform enough in `[0, bound)` for delays; bias is irrelevant here.
    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound.max(1)
    }
}

// ---------------------------------------------------------------------------
// The simulated network.
// ---------------------------------------------------------------------------

/// One sync session in flight: every exchangeable record the sender held,
/// arriving at one node at one virtual instant. A session rather than a
/// message per record, because that is what the real protocol does --
/// `p2p::sync::reconcile` moves the whole want-set over one connection, and
/// `apply_records` replays it as one batch.
struct Session {
    to: usize,
    at: i64,
    records: Vec<(String, Value)>,
}

/// N real nodes under a simulated clock and a delaying, reordering network.
struct Sim {
    nodes: Vec<Node>,
    /// Virtual now, unix seconds. Every timestamp any node sees derives from
    /// this; nothing in a run reads a real clock.
    now: i64,
    inflight: Vec<Session>,
    rng: Rng,
    seed: u64,
}

/// Scratch ledgers under `target/`, one directory per (test, seed), so a
/// failing run leaves its logs behind for inspection.
///
/// The `tag` is not decoration. Tests in one binary run concurrently, and two
/// tests that swept overlapping seed ranges shared ledger paths and clobbered
/// each other -- passing alone, failing in the full suite. Keying on the seed
/// alone is only unique if every test picks disjoint seeds, which is a rule
/// nothing enforces; keying on the test as well needs no coordination.
fn scratch(tag: &str, seed: u64, node: usize) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("sim-tests")
        .join(format!("{tag}-seed-{seed}"));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let path = dir.join(format!("node-{node}.jsonl"));
    let _ = std::fs::remove_file(&path);
    path
}

impl Sim {
    fn new(tag: &str, seed: u64, nodes: usize) -> Sim {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        Sim {
            nodes: (0..nodes)
                .map(|i| Node::new(Ledger::open(scratch(tag, seed, i)).expect("ledger"), &root))
                .collect(),
            // Fixed origin: runs are comparable across seeds, and it sits far
            // from the epoch's own origin so nothing degenerate is exercised
            // by accident.
            now: 1_900_000_000,
            inflight: Vec::new(),
            rng: Rng(seed),
            seed,
        }
    }

    fn ts(&self) -> String {
        format_iso8601_utc(self.now)
    }

    /// Queue a sync session from `from` to every other node, each with its own
    /// delivery delay in `[0, max_delay)` virtual seconds.
    ///
    /// A delay may cross an epoch boundary. That is not an edge case — it is
    /// the case this simulator exists to reach.
    fn gossip(&mut self, from: usize, max_delay: u64) {
        let records: Vec<(String, Value)> = self.nodes[from]
            .ledger()
            .entries()
            .iter()
            .filter(|e| ["objective", "commitment", "claim"].contains(&e.kind.as_str()))
            .map(|e| (e.kind.clone(), e.payload.clone()))
            .collect();
        for to in 0..self.nodes.len() {
            if to == from {
                continue;
            }
            let at = self.now + self.rng.below(max_delay) as i64;
            self.inflight.push(Session {
                to,
                at,
                records: records.clone(),
            });
        }
    }

    /// Advance virtual time to `to`, delivering every session due on the way,
    /// in arrival order.
    ///
    /// Delivery goes through [`proofwork::p2p::service::replay_records`] — the
    /// daemon's own replay, not a copy of it. The simulator's claim is "this
    /// is what the real code does under this schedule", and a re-implemented
    /// replay would quietly turn that into "what a copy did".
    fn advance(&mut self, to: i64) {
        self.inflight.sort_by_key(|s| s.at);
        let sessions = std::mem::take(&mut self.inflight);
        let (due, later): (Vec<Session>, Vec<Session>) =
            sessions.into_iter().partition(|s| s.at <= to);
        self.inflight = later;
        for session in due {
            proofwork::p2p::service::replay_records(&mut self.nodes[session.to], &session.records);
        }
        self.now = to;
    }

    /// Every node drains what is due at the current virtual instant, as the
    /// daemon's tick does.
    fn settle_all(&mut self) {
        let ts = self.ts();
        for node in &mut self.nodes {
            let _ = node.settle_at(&ts);
        }
    }

    /// The instant just past the next epoch boundary.
    fn next_boundary(&self) -> i64 {
        ((self.now / EPOCH) + 1) * EPOCH + 1
    }

    /// The claims each node paid, in payment order.
    fn orders(&self) -> Vec<Vec<String>> {
        self.nodes
            .iter()
            .map(|node| {
                node.ledger()
                    .entries_of_kind("settlement")
                    .into_iter()
                    .filter_map(|e| {
                        e.payload
                            .get("claim_id")
                            .and_then(Value::as_str)
                            .map(str::to_string)
                    })
                    .collect()
            })
            .collect()
    }

    /// Each node's epoch-chain head.
    fn heads(&self) -> Vec<String> {
        self.nodes
            .iter()
            .map(|node| {
                node.epoch_chain()
                    .last()
                    .map(|l| l.link.clone())
                    .unwrap_or_default()
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Workloads, authored on node 0 through the real rules.
// ---------------------------------------------------------------------------

fn shipped_objective_and_artifact() -> (Objective, Value) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(root.join("examples/collatz/objective.json"))
        .expect("objective json");
    let objective =
        Objective::from_value(&Value::from_json(&text).expect("parse")).expect("decode");
    let artifact_text = std::fs::read_to_string(root.join("examples/collatz/artifact.json"))
        .expect("artifact json");
    (
        objective,
        Value::from_json(&artifact_text).expect("artifact"),
    )
}

/// `claims` commit/reveal pairs against distinct objectives. All commitments
/// land in the current epoch; all reveals land together in the next — one
/// batch, which is the shape the ordering invariant is about.
fn author_one_batch(sim: &mut Sim, claims: usize) {
    let (base, artifact) = shipped_objective_and_artifact();
    let commit_ts = sim.ts();
    let reveal_at = sim.now + EPOCH;
    let reveal_ts = format_iso8601_utc(reveal_at);

    let mut pending = Vec::new();
    for i in 0..claims {
        let objective = Objective::new(
            format!("GOAL-sim-{i}"),
            base.statement.clone(),
            base.verifier.clone(),
            base.reward,
            base.funder.clone(),
            &commit_ts,
            None,
            None,
        )
        .expect("objective");
        let id = sim.nodes[0]
            .post_objective(&objective, &commit_ts)
            .expect("post");
        let submitter = format!("sub-{i}");
        let nonce = format!("n-{i}");
        let hash = commitment_hash(&id, &submitter, &artifact, &nonce);
        sim.nodes[0]
            .commit(
                &Commitment::new(&id, &submitter, hash, &commit_ts),
                &commit_ts,
            )
            .expect("commit");
        pending.push((id, submitter, nonce));
    }
    sim.advance(reveal_at);
    for (id, submitter, nonce) in pending {
        let claim = Claim::new(
            &id,
            &submitter,
            artifact.clone(),
            &nonce,
            &reveal_ts,
            vec![],
        )
        .expect("claim");
        sim.nodes[0].reveal(&claim, &reveal_ts).expect("reveal");
    }
}

/// One commit/reveal pair per epoch, across `epochs` consecutive epochs — the
/// multi-epoch log shape that exposed the `apply_records` id-order bug.
fn author_across_epochs(sim: &mut Sim, epochs: usize) {
    let (base, artifact) = shipped_objective_and_artifact();
    for i in 0..epochs {
        let commit_ts = sim.ts();
        let objective = Objective::new(
            format!("GOAL-epoch-{i}"),
            base.statement.clone(),
            base.verifier.clone(),
            base.reward,
            base.funder.clone(),
            &commit_ts,
            None,
            None,
        )
        .expect("objective");
        let id = sim.nodes[0]
            .post_objective(&objective, &commit_ts)
            .expect("post");
        let submitter = format!("sub-{i}");
        let nonce = format!("n-{i}");
        let hash = commitment_hash(&id, &submitter, &artifact, &nonce);
        sim.nodes[0]
            .commit(
                &Commitment::new(&id, &submitter, hash, &commit_ts),
                &commit_ts,
            )
            .expect("commit");
        let reveal_at = sim.now + EPOCH;
        let reveal_ts = format_iso8601_utc(reveal_at);
        let claim = Claim::new(
            &id,
            &submitter,
            artifact.clone(),
            &nonce,
            &reveal_ts,
            vec![],
        )
        .expect("claim");
        sim.advance(reveal_at);
        sim.nodes[0].reveal(&claim, &reveal_ts).expect("reveal");
    }
}

// ---------------------------------------------------------------------------
// The properties.
// ---------------------------------------------------------------------------

/// **Convergence under benign asynchrony.** Sessions are delayed but land
/// inside the epoch, so every record arrives before the epoch it belongs to
/// drains anywhere. Under those conditions the epoch chain must make every
/// node agree — across many seeds, which is many delivery schedules.
#[test]
fn nodes_converge_when_sessions_land_inside_the_epoch() {
    for seed in 1..=25u64 {
        let mut sim = Sim::new("converge", seed, 3);
        author_one_batch(&mut sim, 4);
        // Delays bounded by the time actually left in the reveal epoch --
        // computed, not assumed. The first version assumed EPOCH/2 of
        // headroom, but the origin is not epoch-aligned, so some sessions
        // landed after the boundary and the test was accidentally exercising
        // the partial-view case it exists to exclude. "Benign" means every
        // session lands before the epoch can drain anywhere, so the bound
        // must be derived from the boundary, not from the epoch length.
        let headroom = (sim.next_boundary() - sim.now - 2).max(1) as u64;
        sim.gossip(0, headroom);
        let boundary = sim.next_boundary();
        sim.advance(boundary);
        sim.settle_all();

        let orders = sim.orders();
        let heads = sim.heads();
        assert_eq!(
            orders[0].len(),
            4,
            "seed {seed}: the authoring node settled {} of 4",
            orders[0].len()
        );
        for n in 1..orders.len() {
            assert_eq!(
                orders[n], orders[0],
                "seed {}: node {n} paid a different order. Replay: Sim::new(converge, {}, 3)",
                sim.seed, sim.seed
            );
            assert_eq!(
                heads[n], heads[0],
                "seed {}: node {n} computed a different chain head. Replay: Sim::new(converge, {}, 3)",
                sim.seed, sim.seed
            );
        }
    }
}

/// **A multi-epoch log syncs whole, whatever order its records arrive in.**
/// The log spans several epochs, and the receiving node gets it as one
/// session — the cold-sync case, a node joining late and pulling history.
///
/// Cold sync specifically: an empty node, the whole history in one session.
/// It passes with or without the `created_at` sort in `replay_records`, and
/// that is not a weakness in the test but a fact about the rules — a node
/// holding nothing for an epoch never drains it (`Node::due_epochs` considers
/// only epochs with accepted claims), so nothing can refuse a later arrival.
/// The sort is pinned by
/// `replay_does_not_lose_a_claim_to_the_order_records_arrive_in` below, which
/// sets up the partial-history precondition this scenario deliberately lacks.
#[test]
fn a_cold_sync_across_epochs_replays_whole_whatever_the_id_order() {
    for seed in 1..=10u64 {
        let mut sim = Sim::new("coldsync", seed, 2);
        author_across_epochs(&mut sim, 4);
        // One session carrying the whole multi-epoch history, delivered
        // promptly; then the boundary passes and both settle.
        sim.gossip(0, 30);
        let boundary = sim.next_boundary();
        sim.advance(boundary);
        sim.settle_all();

        let orders = sim.orders();
        assert_eq!(
            orders[0].len(),
            4,
            "seed {seed}: the author settled {} of 4",
            orders[0].len()
        );
        assert_eq!(
            orders[1], orders[0],
            "seed {seed}: the cold-syncing node lost claims to replay order. \
             Replay: Sim::new(coldsync, {seed}, 2)"
        );
        assert_eq!(
            sim.heads()[1],
            sim.heads()[0],
            "seed {seed}: chain heads differ after a whole-log sync"
        );
    }
}

/// **Replay must not depend on the order records sit in a session.**
///
/// This is the test that actually pins the `created_at` sort in
/// `p2p::service::replay_records`, and writing it corrected a claim I had
/// already made wrongly. A mutation test — disable the sort, run the suite —
/// showed the cold-sync test above passing either way, because a node holding
/// *nothing* for an epoch never drains it: `Node::due_epochs` only considers
/// epochs that have accepted claims, so there is no batch and no drained
/// marker to refuse a later arrival. Cold sync is safe with or without the
/// sort.
///
/// The order *does* matter once the node already holds a claim for the earlier
/// epoch. Then replaying a later-epoch reveal first drains that earlier epoch
/// as a side effect — `Node::reveal` calls `settle_due` before admitting —
/// paying a batch that omits the claim still sitting in the same session, and
/// that claim is then refused with "epoch already settled". Which is a real
/// arrangement: a node that synced partway, then received more history.
///
/// The adverse order is constructed rather than hoped for. In the daemon it
/// comes from `Peer::ids()`, a `BTreeSet` of content hashes — so whether a
/// node kept a claim depended on how a hash happened to sort.
#[test]
fn replay_does_not_lose_a_claim_to_the_order_records_arrive_in() {
    let (base, artifact) = shipped_objective_and_artifact();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut node = Node::new(
        Ledger::open(scratch("replayorder", 0, 0)).expect("ledger"),
        &root,
    );

    // Three objectives: two revealed in epoch E, one in E+2.
    let t0: i64 = 1_900_000_000;
    let early_reveal = format_iso8601_utc(t0 + EPOCH);
    let late_reveal = format_iso8601_utc(t0 + 3 * EPOCH);
    let commit_ts = format_iso8601_utc(t0);

    let mut author = Node::new(
        Ledger::open(scratch("replayorder", 0, 1)).expect("ledger"),
        &root,
    );
    let mut made = Vec::new();
    for (i, reveal_ts) in [&early_reveal, &early_reveal, &late_reveal]
        .into_iter()
        .enumerate()
    {
        let objective = Objective::new(
            format!("GOAL-order-{i}"),
            base.statement.clone(),
            base.verifier.clone(),
            base.reward,
            base.funder.clone(),
            &commit_ts,
            None,
            None,
        )
        .expect("objective");
        let id = author.post_objective(&objective, &commit_ts).expect("post");
        let submitter = format!("sub-{i}");
        let nonce = format!("n-{i}");
        let hash = commitment_hash(&id, &submitter, &artifact, &nonce);
        author
            .commit(
                &Commitment::new(&id, &submitter, hash, &commit_ts),
                &commit_ts,
            )
            .expect("commit");
        let claim = Claim::new(&id, &submitter, artifact.clone(), &nonce, reveal_ts, vec![])
            .expect("claim");
        let outcome = author.reveal(&claim, reveal_ts).expect("reveal");
        // The premise, checked rather than assumed. These claims run the real
        // pinned verifier as a subprocess, and a verifier that could not run
        // returns `unavailable` -- never a rejection, by design. If that
        // happens the claim is not accepted anywhere and the assertion at the
        // end of this test would fire and blame *replay ordering* for a
        // verifier that simply did not get scheduled. That is precisely the
        // false accusation this repository is careful about elsewhere, so the
        // premise gets its own message.
        assert!(
            outcome.verdict.accepted(),
            "claim {i} was not accepted by the author, so this test cannot say \
             anything about replay order. Verdict: {:?}. An `unavailable` here \
             means the pinned verifier could not run (missing toolchain, or a \
             deadline missed under parallel test load) -- not an ordering bug.",
            outcome.verdict
        );
        made.push((i, claim));
    }

    let records: Vec<(String, Value)> = author
        .ledger()
        .entries()
        .iter()
        .filter(|e| ["objective", "commitment", "claim"].contains(&e.kind.as_str()))
        .map(|e| (e.kind.clone(), e.payload.clone()))
        .collect();

    // First session: everything except the *second* epoch-E claim. The node
    // now holds one accepted claim for epoch E, so epoch E is drainable.
    let held_back = made[1].1.id();
    let first: Vec<(String, Value)> = records
        .iter()
        .filter(|(k, p)| !(k == "claim" && p.digest() == made[1].1.to_value().digest()))
        .cloned()
        .collect();
    // Only the objective/commitment/claim for #0 -- and #2's inputs, but not
    // #2's claim yet, so nothing drains epoch E during this session.
    let first: Vec<(String, Value)> = first
        .into_iter()
        .filter(|(k, p)| !(k == "claim" && p.digest() == made[2].1.to_value().digest()))
        .collect();
    proofwork::p2p::service::replay_records(&mut node, &first);

    // Second session, in the adverse order: the epoch-E+2 claim *before* the
    // epoch-E claim that is still missing.
    let second: Vec<(String, Value)> = vec![
        ("claim".to_string(), made[2].1.to_value()),
        ("claim".to_string(), made[1].1.to_value()),
    ];
    proofwork::p2p::service::replay_records(&mut node, &second);

    let accepted = node.accepted_claims();
    assert!(
        accepted.contains_key(&held_back),
        "the epoch-E claim was lost because a later-epoch claim sat before it \
         in the same session: replaying the later reveal drained epoch E \
         first. `replay_records` must sort by created_at."
    );
}

/// **The open defect, reproduced on demand.** A session lands *after* the
/// receiving node drained the epoch its claims belong to. The late claims are
/// refused — correctly, per the current rules — and the chains diverge
/// permanently: the partial-view case
/// `docs/design/settlement-convergence.md` names as unsolved, pinned by a
/// test instead of prose.
///
/// `#[ignore]`d because it documents a defect rather than guards a fix: it
/// asserts the divergence HAPPENS. The day a finality delay or reorg rule
/// lands, this failing is the signal to move the scenario into the
/// convergence suite above.
#[test]
#[ignore = "reproduces the documented partial-view divergence; the finality \
            delay that would fix it is designed, not built -- \
            docs/design/settlement-convergence.md"]
fn a_partial_view_at_drain_time_forks_the_chain() {
    // The fork needs a *partial* view, literally: a node that holds nothing
    // never drains -- no claims means no batch, no batch means the epoch is
    // never marked settled, and late history is accepted whole. (That is why
    // cold sync works, and the first version of this repro converged by
    // accident because of it.) The divergence needs a node that drains with
    // SOME of an epoch's claims while another is still in flight.
    let mut sim = Sim::new("partialview", 11, 2);
    author_one_batch(&mut sim, 4);

    // Which records belong to the claim that will arrive late? Everything
    // touching the objective authored as GOAL-sim-3.
    let straggler_id = sim.nodes[0]
        .objectives()
        .iter()
        .find(|(_, o)| o.goal == "GOAL-sim-3")
        .map(|(id, _)| id.clone())
        .expect("the 4th objective exists");
    let belongs_to_straggler = |payload: &Value| -> bool {
        payload.get("goal").and_then(Value::as_str) == Some("GOAL-sim-3")
            || payload.get("objective_id").and_then(Value::as_str) == Some(&straggler_id)
    };
    let records: Vec<(String, Value)> = sim.nodes[0]
        .ledger()
        .entries()
        .iter()
        .filter(|e| ["objective", "commitment", "claim"].contains(&e.kind.as_str()))
        .map(|e| (e.kind.clone(), e.payload.clone()))
        .collect();

    // Two sync rounds, as a real daemon would see them: the first round ran
    // before the straggler was revealed and lands in time; the second carries
    // it and lands after the boundary.
    let boundary = sim.next_boundary();
    sim.inflight.push(Session {
        to: 1,
        at: sim.now + 30,
        records: records
            .iter()
            .filter(|(_, p)| !belongs_to_straggler(p))
            .cloned()
            .collect(),
    });
    sim.inflight.push(Session {
        to: 1,
        at: boundary + 60,
        records,
    });

    sim.advance(boundary);
    sim.settle_all(); // node 1 drains with 3 of 4 claims...
    sim.advance(boundary + 120); // ...the straggler arrives...
    sim.settle_all(); // ...and cannot join the batch that already paid.

    let orders = sim.orders();
    assert_eq!(orders[0].len(), 4, "the author settled all four");
    assert_eq!(
        orders[1].len(),
        3,
        "node 1 should have settled exactly the three that arrived in time"
    );
    let heads = sim.heads();
    assert_ne!(
        heads[0], heads[1],
        "the partial view CONVERGED: a fix for the partial-view case has \
         landed -- move this scenario into the convergence suite and delete \
         the #[ignore]. See docs/design/settlement-convergence.md."
    );
}

// ---------------------------------------------------------------------------
// Forged batches. Found by adversarially probing the epoch chain rather than
// by the tests that shipped with it.
// ---------------------------------------------------------------------------

/// **An empty batch is forged, moves the chain, and must not audit clean.**
///
/// Every batch is a link, and the chain head is the anchor later batches sort
/// against. A batch settling *no* claims can never come from a drain — a drain
/// runs only for epochs that have accepted claims — but it still advances the
/// head, and it matches its own (empty) claim list trivially, so the audit
/// passed it clean. That is an unlimited re-roll of the order every later
/// epoch is paid in, handed to whoever can append to the log: exactly the
/// lever `AGENTS.md` says beacon ordering exists to remove.
///
/// The forged record is appended through `Ledger` directly, because no rules
/// path produces one — which is the point.
#[test]
fn an_empty_forged_batch_does_not_audit_clean() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let path = scratch("emptybatch", 0, 0);
    let (base, artifact) = shipped_objective_and_artifact();

    let t0: i64 = 1_900_000_000;
    let commit_ts = format_iso8601_utc(t0);
    let reveal_ts = format_iso8601_utc(t0 + EPOCH);
    let settle_ts = format_iso8601_utc(t0 + 2 * EPOCH);

    let mut node = Node::new(Ledger::open(&path).expect("ledger"), &root);
    let objective = Objective::new(
        "GOAL-forge",
        base.statement.clone(),
        base.verifier.clone(),
        base.reward,
        base.funder.clone(),
        &commit_ts,
        None,
        None,
    )
    .expect("objective");
    let id = node.post_objective(&objective, &commit_ts).expect("post");
    let hash = commitment_hash(&id, "alice", &artifact, "n");
    node.commit(&Commitment::new(&id, "alice", hash, &commit_ts), &commit_ts)
        .expect("commit");
    let claim = Claim::new(&id, "alice", artifact, "n", &reveal_ts, vec![]).expect("claim");
    node.reveal(&claim, &reveal_ts).expect("reveal");
    node.settle_at(&settle_ts).expect("settle");
    assert!(
        node.audit(false).is_empty(),
        "the honest log must audit clean before anything is forged"
    );

    let before = node
        .epoch_chain()
        .last()
        .map(|l| l.link.clone())
        .unwrap_or_default();

    // An empty batch for an epoch nobody ever claimed in, anchored honestly to
    // the head as it stands -- so nothing about it is internally inconsistent.
    let forged = Value::object([
        ("epoch", Value::Int(4242)),
        ("anchor", Value::string(before.clone())),
        ("claims", Value::Array(vec![])),
    ]);
    node.ledger_mut()
        .append("batch", forged, &settle_ts)
        .expect("append");

    let after = node
        .epoch_chain()
        .last()
        .map(|l| l.link.clone())
        .unwrap_or_default();
    assert_ne!(
        before, after,
        "fixture is wrong: the forged batch did not move the chain, so this \
         test would pass for the wrong reason"
    );

    let problems = node.audit(false);
    assert!(
        problems.iter().any(|p| p.contains("settles no claims")),
        "an empty forged batch moved the settlement anchor and audited clean. \
         Problems reported: {problems:?}"
    );
}

/// **Every link the chain publishes must be recomputable from what it
/// publishes.** A batch naming an epoch outside `u64` used to fold into a link
/// whose reported `epoch` was `0` while its hash committed to the real value,
/// so anyone recomputing `H({prev, epoch, claims})` from `GET /chain` got a
/// different digest and no way to tell why. Such a batch is now left out of
/// the chain entirely, and the audit reports it separately.
#[test]
fn every_published_link_recomputes_from_its_published_fields() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut node = Node::new(
        Ledger::open(scratch("recompute", 0, 0)).expect("ledger"),
        &root,
    );
    let ts = format_iso8601_utc(1_900_000_000);

    node.ledger_mut()
        .append(
            "batch",
            Value::object([
                ("epoch", Value::Int(-5)),
                ("anchor", Value::string("")),
                (
                    "claims",
                    Value::Array(vec![Value::string("sha256:whatever")]),
                ),
            ]),
            &ts,
        )
        .expect("append");

    for link in node.epoch_chain() {
        let recomputed = Value::object([
            ("prev", Value::string(link.prev.clone())),
            ("epoch", Value::Int(i128::from(link.epoch))),
            (
                "claims",
                Value::Array(link.claims.iter().cloned().map(Value::String).collect()),
            ),
        ])
        .digest();
        assert_eq!(
            recomputed, link.link,
            "the chain published a link nobody can recompute from its own \
             fields: epoch {} claims {:?}",
            link.epoch, link.claims
        );
    }
}
