//! The ecdsa.fail-shaped challenge: does it verify, does it pay, and is the
//! thing it pays for the thing anyone wants done?
//!
//! `examples/ecdsa-fail/` ships two funded objectives -- a toy MVP and a
//! live-scale port with the real challenge's numbers -- and before this file
//! neither had a test. `scripts/check-examples.sh` proved their pins resolve and
//! that `cairn post` accepts them; nothing ran an artifact through them, and
//! nothing settled one. Compare `reversible-adder` (two CI demo scripts) or
//! `faster-algorithms` (an adversarial `selftest.py`): the flagship example was
//! the least covered of the family.
//!
//! Three things are checked here, in order of how much they matter.
//!
//! **The evaluators.** Both, against every shipped artifact and a battery of
//! hostile ones. A `minimize` objective inverts every comparison in the scoring
//! path, and the family it belongs to -- `evaluator` + `minimize` + `ratchet` --
//! is now most of `examples/`, so a defect here is not confined to this
//! directory.
//!
//! **The settlement.** Both objectives driven end to end through the real rules
//! engine: commit, reveal an epoch later, settle after finality, then audited by
//! a reader who trusts none of it.
//!
//! **The strategies.** What a submitter *gains* by hoarding, copying, lying,
//! chopping an improvement into slices, or splitting across identities --
//! measured on a log the rules engine actually settled, counting both the direct
//! reward and the citation flow. That last part is not a duplicate of
//! `tests/citation_flow.rs`: those tests build claims by hand and call
//! `payouts_over` directly, which is the only check the reward-weighted rule
//! has. `docs/design/citation-flow-dilution.md` says so outright -- the
//! conformance vectors pin the per-hop `flow`, and the weighted rule that
//! actually moves money has no independent check. These simulations are that
//! check, on a settled ratchet log rather than a fixture.
//!
//! # The finding this file records
//!
//! The live objective is **dead on arrival**, and the tests below pin it rather
//! than paper over it. Its `min_improvement` of 100,000,000 is larger than the
//! 83,649,332 of span left between the published world best and the target, so
//! the first accepted submission takes 4,955,310 of the 5,000,000 pool and shuts
//! the objective permanently: every later improvement, including one that beats
//! the world record outright, is refused. `Ratchet::is_exhausted` already
//! answers the question and `Stall::ClampedByTarget` already words the refusal
//! kindly -- `GAP.md` item 7 records both -- but the shipped objective still
//! has the shape, and what it pays for is reproducing published work rather
//! than advancing it. See `the_live_objective_strands_its_own_pool` and
//! `docs/threat-model.md`.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use cairn::attribution::{payouts_over, FlowParams};
use cairn::canonical::Value;
use cairn::frontier::{Direction, Ratchet, Stall};
use cairn::ledger::Ledger;
use cairn::node::{Node, Outcome, RuleViolation};
use cairn::partition::{epoch_seconds, finality_epochs};
use cairn::records::{commitment_hash, Claim, Commitment, Objective};
use cairn::time::format_iso8601_utc;
use cairn::verifiers::{Status, VerifierRegistry};

/// Frozen origin, so record ids do not move between runs.
const BASE: i64 = 1_785_196_800;

/// The bundle root the shipped objectives pin their evaluators against.
const REPO_ROOT: &str = env!("CARGO_MANIFEST_DIR");

/// The published world best at the time `objective-live.json` was written:
/// 1,154 qubits x 1,285,658 Toffoli.
const WORLD_BEST: i64 = 1_483_649_332;

fn epoch() -> i64 {
    epoch_seconds() as i64
}

fn finality() -> i64 {
    finality_epochs() as i64
}

fn stamp(offset: i64) -> String {
    format_iso8601_utc(BASE + offset)
}

// ---------------------------------------------------------------------------
// Scaffolding
// ---------------------------------------------------------------------------

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
            "cairn-ecdsa-{label}-{}-{nanos}-{n}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("scratch directory is creatable");
        TempDir { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn example_path(file: &str) -> PathBuf {
    Path::new(REPO_ROOT)
        .join("examples")
        .join("ecdsa-fail")
        .join(file)
}

fn load_value(path: &Path) -> Value {
    let text = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    Value::from_json(&text)
        .unwrap_or_else(|error| panic!("{} is not canonical JSON: {error}", path.display()))
}

/// One of the two shipped objectives, decoded from the file an agent would pull.
/// Never a copy of it: the pin, the threshold and the ratchet all come from disk,
/// so an edit to the example cannot leave these tests asserting the old shape.
fn objective(file: &str) -> Objective {
    Objective::from_value(&load_value(&example_path(file)))
        .unwrap_or_else(|error| panic!("examples/ecdsa-fail/{file} is malformed: {error}"))
}

fn mvp() -> Objective {
    objective("objective.json")
}

fn live() -> Objective {
    objective("objective-live.json")
}

fn ratchet_of(objective: &Objective) -> Ratchet {
    Ratchet::from_value(
        objective
            .ratchet
            .as_ref()
            .expect("both ecdsa-fail objectives are progressive"),
    )
    .expect("the shipped ratchet decodes")
}

/// One of the shipped candidate artifacts.
fn shipped(name: &str) -> Value {
    load_value(&example_path(&format!("artifacts/{name}.json")))
}

fn empty() -> Value {
    Value::Object(BTreeMap::new())
}

/// `{qubits, toffoli}` with no declared `score`, so the evaluator multiplies it
/// out itself.
fn metrics(qubits: i128, toffoli: i128) -> Value {
    Value::object([
        ("qubits", Value::Int(qubits)),
        ("toffoli", Value::Int(toffoli)),
    ])
}

/// An artifact scoring exactly `score`, tagged so two submitters reaching the
/// same number do not produce byte-identical artifacts.
///
/// The tag is a field no evaluator reads, and that is the point: a real
/// submission carries a circuit, and two circuits of equal cost are not the same
/// artifact. Copying is modelled below by copying the bytes, never by coinciding.
fn tagged(score: i64, qubits: i128, tag: &str) -> Value {
    assert!(
        i128::from(score) % qubits == 0,
        "{score} is not a whole multiple of {qubits} qubits"
    );
    Value::object([
        ("qubits", Value::Int(qubits)),
        ("toffoli", Value::Int(i128::from(score) / qubits)),
        ("tag", Value::string(tag.to_string())),
    ])
}

fn registry() -> VerifierRegistry {
    VerifierRegistry::new(REPO_ROOT)
}

/// A node whose bundle root is the repository, because that is where the
/// objectives pin their evaluators.
fn node_at(dir: &TempDir) -> Node {
    let ledger = Ledger::open(dir.path.join("log.jsonl")).expect("a missing file is an empty log");
    Node::new(ledger, REPO_ROOT)
}

/// Drives one funded objective through successive epochs.
///
/// Each `submit` takes a fresh block of epochs: commit, reveal one epoch later,
/// settle once the reveal epoch has closed and finality has passed. `reveal_all`
/// exists for the one question that needs several reveals inside a *single*
/// epoch, which is where beacon ordering becomes visible.
struct Runner {
    node: Node,
    objective: Objective,
    ratchet: Ratchet,
    /// Next unused epoch, as an offset in epochs from [`BASE`].
    next: i64,
}

impl Runner {
    fn new(label: &str, objective: Objective) -> Runner {
        // The scratch dir is only the log's home; the bundle root stays the
        // repository, so `TempDir` is dropped with the runner.
        let dir = TempDir::new(label);
        let mut node = node_at(&dir);
        node.post_objective(&objective, &stamp(0))
            .expect("the shipped objective is postable");
        let ratchet = ratchet_of(&objective);
        // Leak the scratch dir deliberately: the node holds the log open for the
        // life of the runner, and tying the two lifetimes together buys nothing
        // that the OS temp sweeper does not already do.
        std::mem::forget(dir);
        Runner {
            node,
            objective,
            ratchet,
            next: 1,
        }
    }

    fn frontier_score(&self) -> Option<i64> {
        self.node
            .frontier_of(&self.objective.id())
            .map(|held| held.score)
    }

    fn frontier_claim(&self) -> Option<String> {
        self.node
            .frontier_of(&self.objective.id())
            .map(|held| held.claim_id)
    }

    fn frontier_artifact(&self) -> Option<Value> {
        let held = self.node.frontier_of(&self.objective.id())?;
        self.node
            .accepted_claims()
            .get(&held.claim_id)
            .map(|claim| claim.artifact.clone())
    }

    /// The citation the rules require right now: the frontier holder, if there
    /// is one. Every claim on a ratcheted objective must carry it, improvement
    /// or not.
    fn required_cites(&self) -> Vec<String> {
        self.frontier_claim().into_iter().collect()
    }

    /// Commit, reveal, settle. Returns the claim's final outcome.
    fn submit(
        &mut self,
        who: &str,
        artifact: Value,
        nonce: &str,
    ) -> Result<Outcome, RuleViolation> {
        let cites = self.required_cites();
        self.submit_citing(who, artifact, nonce, cites)
    }

    fn submit_citing(
        &mut self,
        who: &str,
        artifact: Value,
        nonce: &str,
        cites: Vec<String>,
    ) -> Result<Outcome, RuleViolation> {
        let outcomes = self.reveal_all(&[(who.to_string(), artifact, nonce.to_string())], cites)?;
        Ok(outcomes
            .into_iter()
            .next()
            .expect("one submission, one outcome"))
    }

    /// Reveal several claims inside one epoch, all citing `cites`, and settle
    /// the batch.
    ///
    /// The batch is what makes beacon ordering observable: the frontier moves
    /// only at settlement, so everything revealed in one epoch cites the same
    /// holder, and the order they are paid in is nobody's choice.
    fn reveal_all(
        &mut self,
        submissions: &[(String, Value, String)],
        cites: Vec<String>,
    ) -> Result<Vec<Outcome>, RuleViolation> {
        let commit_at = self.next;
        let reveal_at = commit_at + 1;
        // Settlement waits for the reveal epoch to close and for finality.
        let settle_at = reveal_at + 1 + finality();
        self.next = settle_at + 1;

        let commit_ts = stamp(commit_at * epoch());
        for (who, artifact, nonce) in submissions {
            let hash = commitment_hash(&self.objective.id(), who, artifact, nonce);
            self.node.commit(
                &Commitment::new(self.objective.id(), who, hash, &commit_ts),
                &commit_ts,
            )?;
        }

        let reveal_ts = stamp(reveal_at * epoch());
        let mut revealed = Vec::new();
        for (who, artifact, nonce) in submissions {
            // The claim carries the reveal instant: a claim stamped elsewhere
            // could be placed in a different settlement epoch by two nodes that
            // agree on its id.
            let claim = Claim::new(
                self.objective.id(),
                who,
                artifact.clone(),
                nonce,
                &reveal_ts,
                cites.clone(),
            )
            .expect("structurally valid claim");
            revealed.push(self.node.reveal(&claim, &reveal_ts)?);
        }

        let settle_ts = stamp(settle_at * epoch());
        let settled = self.node.settle_at(&settle_ts)?;

        // Report each revealed claim's *final* state, so a caller can ask "what
        // did this earn" in one line.
        Ok(revealed
            .into_iter()
            .map(|outcome| {
                settled
                    .iter()
                    .find(|final_state| final_state.claim_id == outcome.claim_id)
                    .cloned()
                    .unwrap_or(outcome)
            })
            .collect())
    }

    /// Let epochs pass without submitting anything.
    fn idle(&mut self, epochs: i64) {
        self.next += epochs;
    }

    fn settlements(&self) -> Vec<(String, u64)> {
        self.node
            .ledger()
            .entries_of_kind("settlement")
            .iter()
            .filter(|entry| {
                entry.payload.get("objective_id").and_then(Value::as_str)
                    == Some(self.objective.id().as_str())
            })
            .map(|entry| {
                (
                    entry
                        .payload
                        .get("claim_id")
                        .and_then(Value::as_str)
                        .expect("a settlement names a claim")
                        .to_string(),
                    entry
                        .payload
                        .get("reward")
                        .and_then(Value::as_u64)
                        .expect("a settlement carries a unit count")
                        .to_owned(),
                )
            })
            .collect()
    }

    /// What each submitter was paid by the ratchet, before citation flow.
    fn direct(&self) -> BTreeMap<String, u64> {
        let claims = self.node.accepted_claims();
        let mut totals: BTreeMap<String, u64> = BTreeMap::new();
        for (claim_id, reward) in self.settlements() {
            let who = claims
                .get(&claim_id)
                .map(|claim| claim.submitter.clone())
                .expect("a settled claim is an accepted claim");
            *totals.entry(who).or_insert(0) += reward;
        }
        totals
    }

    /// What each submitter ends up with once citation flow has run. The number
    /// that decides whether a strategy was worth playing.
    fn total(&self) -> BTreeMap<String, u64> {
        payouts_over(
            &self.settlements(),
            &self.node.accepted_claims(),
            &FlowParams::default(),
        )
        .expect("flow over a settled log")
    }

    fn paid_directly(&self, who: &str) -> u64 {
        self.direct().get(who).copied().unwrap_or(0)
    }

    fn paid(&self, who: &str) -> u64 {
        self.total().get(who).copied().unwrap_or(0)
    }

    fn claims_by(&self, who: &str) -> usize {
        self.node
            .accepted_claims()
            .values()
            .filter(|claim| claim.submitter == who)
            .count()
    }

    /// "Earned nothing" and "never submitted" produce the same payout and mean
    /// opposite things. Every strategy this file measures has to have played.
    fn assert_played(&self, who: &str) {
        assert!(
            self.claims_by(who) > 0,
            "{who} has no accepted claim, so its payout says nothing"
        );
    }

    /// Invariants that hold at the end of any run, however hostile.
    fn assert_sound(&self) {
        let problems = self.node.audit(false);
        assert!(
            problems.is_empty(),
            "an auditor re-deriving this log found: {problems:#?}"
        );

        let settled: u64 = self.direct().values().sum();
        assert!(
            settled <= self.ratchet.reward,
            "the pool paid {settled} of a {} bounty",
            self.ratchet.reward
        );

        // Citation flow redistributes settled money. It never mints or burns.
        let flowed: u64 = self.total().values().sum();
        assert_eq!(
            flowed, settled,
            "citation flow changed the total paid: {flowed} against {settled}"
        );

        // The frontier's own running total is the pool's ledger, and it must
        // agree with the settlements and with the curve.
        if let Some(held) = self.node.frontier_of(&self.objective.id()) {
            assert_eq!(
                held.paid_cumulative, settled,
                "the frontier's cumulative disagrees with the settlements"
            );
            assert_eq!(
                held.paid_cumulative,
                self.ratchet.cumulative(held.score).expect("a live curve"),
                "the pool paid something other than the distance moved"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// The evaluators
// ---------------------------------------------------------------------------

#[test]
fn both_shipped_objectives_decode_and_their_pins_resolve() {
    // A stale `evaluator_sha256` is how an example rots: the file is edited, the
    // hash is not, and every submission comes back InvalidSpec. Cheap to ask.
    for (label, objective) in [("mvp", mvp()), ("live", live())] {
        let verdict = registry().run(&objective.verifier, &empty());
        assert_ne!(
            verdict.status,
            Status::InvalidSpec,
            "{label}: the pin does not resolve: {}",
            verdict.detail
        );
        // Both minimize. The direction is the whole reason this family needed
        // its own tests.
        let ratchet = ratchet_of(&objective);
        assert_eq!(ratchet.direction, Direction::Minimize, "{label}");
        assert!(ratchet.target < ratchet.baseline, "{label}");
    }
}

#[test]
fn every_shipped_artifact_scores_what_its_objective_says() {
    // The demo scripts and the README tell a story about these files. If one
    // stops scoring what is claimed, the story teaches something false.
    let mvp = mvp();
    let live = live();

    // (artifact, MVP verdict, live verdict, score under whichever accepts it)
    let cases: [(&str, Status, Status); 7] = [
        ("baseline", Status::Accept, Status::Reject),
        ("open", Status::Accept, Status::Reject),
        ("mid", Status::Accept, Status::Reject),
        ("best", Status::Accept, Status::Reject),
        // A declared `score` the metrics do not support.
        ("bogus", Status::Reject, Status::Reject),
        // Real numbers: too few qubits for the live bounds under the MVP's
        // ceiling-free rules, and exactly the live baseline under its own.
        ("challenge-start", Status::Reject, Status::Accept),
        ("world-best-aug2026", Status::Reject, Status::Accept),
    ];

    for (name, on_mvp, on_live) in cases {
        let artifact = shipped(name);
        let got_mvp = registry().run(&mvp.verifier, &artifact);
        assert_eq!(
            got_mvp.status, on_mvp,
            "{name} on the MVP objective: {}",
            got_mvp.detail
        );
        let got_live = registry().run(&live.verifier, &artifact);
        assert_eq!(
            got_live.status, on_live,
            "{name} on the live objective: {}",
            got_live.detail
        );
        // Whatever the verdict, a score must come back, or the curve has nothing
        // to read and a rejection becomes indistinguishable from a broken
        // evaluator.
        assert!(
            got_mvp.score().is_some(),
            "{name} scored nothing on the MVP"
        );
        assert!(
            got_live.score().is_some(),
            "{name} scored nothing on the live objective"
        );
    }

    // The two real-world artifacts carry the numbers the live statement quotes.
    assert_eq!(
        registry()
            .run(&live.verifier, &shipped("challenge-start"))
            .score(),
        Some(ratchet_of(&live).baseline),
        "challenge-start should be exactly the live baseline"
    );
    assert_eq!(
        registry()
            .run(&live.verifier, &shipped("world-best-aug2026"))
            .score(),
        Some(WORLD_BEST)
    );
}

#[test]
fn a_declared_product_the_metrics_do_not_support_is_refused_either_way() {
    // The ecdsafail `score.json` shape carries qubits, toffoli *and* their
    // product, so the objective has to check the arithmetic. Understating is
    // the profitable direction on a minimize objective; overstating is still a
    // lie, and a verifier that trusts the field at all is not checking.
    let mvp = mvp();
    let honest = Value::object([
        ("qubits", Value::Int(50)),
        ("toffoli", Value::Int(400)),
        ("score", Value::Int(20_000)),
    ]);
    assert_eq!(registry().run(&mvp.verifier, &honest).score(), Some(20_000));

    for lie in [1_i128, 19_999, 20_001, 999_999_999] {
        let artifact = Value::object([
            ("qubits", Value::Int(50)),
            ("toffoli", Value::Int(400)),
            ("score", Value::Int(lie)),
        ]);
        assert_eq!(
            registry().run(&mvp.verifier, &artifact).status,
            Status::Reject,
            "a declared score of {lie} against 50x400 must not clear"
        );
    }
}

#[test]
fn hostile_metrics_score_the_invalid_sentinel_rather_than_crashing() {
    // Every case here is a bad artifact and none is a broken verifier, so none
    // may come back Unavailable or InvalidSpec. An evaluator that raises on
    // hostile input hands an attacker a way to make an objective unusable by
    // submitting to it.
    let mvp = mvp();
    let live = live();

    let hostile = [
        ("nothing at all", empty()),
        ("only qubits", Value::object([("qubits", Value::Int(50))])),
        ("zero qubits", metrics(0, 400)),
        ("negative qubits", metrics(-50, 400)),
        ("string metrics", {
            Value::object([
                ("qubits", Value::string("50")),
                ("toffoli", Value::string("400")),
            ])
        }),
        // Python's `bool` is an `int` subclass, so `isinstance(True, int)` is
        // true and a check that forgets it scores `True * True == 1`: the best
        // product reachable on a minimize objective, from an artifact carrying
        // no circuit at all.
        ("booleans posing as integers", {
            Value::object([
                ("qubits", Value::Bool(true)),
                ("toffoli", Value::Bool(true)),
            ])
        }),
        (
            "a nested object",
            Value::object([("qubits", metrics(50, 400))]),
        ),
    ];

    for (label, artifact) in hostile {
        for (which, objective) in [("mvp", &mvp), ("live", &live)] {
            let verdict = registry().run(&objective.verifier, &artifact);
            assert_eq!(
                verdict.status,
                Status::Reject,
                "{label} on {which} came back {} ({})",
                verdict.status,
                verdict.detail
            );
            assert!(
                verdict.score().is_some(),
                "{label} on {which} produced no score"
            );
        }
    }
}

#[test]
fn each_evaluator_enforces_its_own_feasibility_bounds() {
    // The two evaluators exist because a toy demo and a real port need
    // different floors. Getting these backwards would let 8-qubit spam win the
    // live bounty, so the bounds are checked against the objective that
    // declares them rather than assumed.
    let mvp = mvp();
    let live = live();

    // MVP: 8 <= qubits <= 8192, toffoli >= qubits.
    assert_eq!(
        registry().run(&mvp.verifier, &metrics(4, 400)).status,
        Status::Reject,
        "under the MVP width floor"
    );
    assert_eq!(
        registry().run(&mvp.verifier, &metrics(8193, 400)).status,
        Status::Reject,
        "over the MVP width ceiling"
    );
    assert_eq!(
        registry().run(&mvp.verifier, &metrics(100, 99)).status,
        Status::Reject,
        "thinner than one Toffoli per qubit"
    );

    // Live: qubits >= 500, toffoli >= 100_000, product >= 500_000_000. The
    // product floor is what stops a physically absurd claim from taking the
    // whole curve in one step.
    assert_eq!(
        registry()
            .run(&live.verifier, &metrics(499, 1_000_000))
            .status,
        Status::Reject,
        "under the live width floor"
    );
    assert_eq!(
        registry()
            .run(&live.verifier, &metrics(1_000, 99_999))
            .status,
        Status::Reject,
        "under the live Toffoli floor"
    );
    assert_eq!(
        registry()
            .run(&live.verifier, &metrics(500, 100_000))
            .status,
        Status::Reject,
        "product 50,000,000 is under the live product floor"
    );
    // And a claim inside every bound is scored, not refused.
    let inside = registry().run(&live.verifier, &metrics(1_154, 1_285_658));
    assert_eq!(inside.status, Status::Accept, "{}", inside.detail);
    assert_eq!(inside.score(), Some(WORLD_BEST));
}

#[test]
fn a_product_too_large_for_the_ledger_is_refused_instead_of_wrapping() {
    // Wrapping would invent a cheap product out of an enormous circuit, which
    // on a minimize objective is the most profitable bug available.
    for (label, objective) in [("mvp", mvp()), ("live", live())] {
        let verdict = registry().run(
            &objective.verifier,
            &metrics(8_192, i128::from(i64::MAX) / 4_096),
        );
        assert_eq!(
            verdict.status,
            Status::Reject,
            "{label}: {}",
            verdict.detail
        );
        assert!(
            verdict.score().unwrap() >= 1_000_000_000_000_000_000,
            "{label}: an overflowing product must score the invalid sentinel"
        );
    }
}

#[test]
fn a_swapped_evaluator_is_an_invalid_spec_and_a_missing_one_is_unavailable() {
    // Two failures that must never be confused with each other, or with a
    // rejection. The pin is the whole trust model: whoever funded the objective
    // agreed to *that* scoring function.
    let objective = mvp();

    // Present at the pinned path, wrong bytes.
    let swapped = TempDir::new("repin");
    let planted = swapped.path.join("examples/ecdsa-fail/evaluators");
    fs::create_dir_all(&planted).expect("scratch tree");
    fs::write(
        planted.join("circuit_cost.py"),
        "def score(a):\n    return 1\n",
    )
    .expect("planting the swap");
    let verdict = VerifierRegistry::new(&swapped.path).run(&objective.verifier, &shipped("best"));
    assert_eq!(
        verdict.status,
        Status::InvalidSpec,
        "a hash mismatch must not be scored: {}",
        verdict.detail
    );
    assert_ne!(
        verdict.score(),
        Some(1),
        "the swapped file must not have run at all"
    );

    // Absent entirely. The node knows nothing about the artifact, and saying
    // `reject` would let an attacker fail every honest submission by making the
    // pinned code unreachable -- the first rule in AGENTS.md.
    let bare = TempDir::new("nocode");
    let verdict = VerifierRegistry::new(&bare.path).run(&objective.verifier, &shipped("best"));
    assert_eq!(
        verdict.status,
        Status::Unavailable,
        "missing pinned code must be Unavailable: {}",
        verdict.detail
    );
    assert!(!verdict.settles(), "an outage must not settle anything");
}

// ---------------------------------------------------------------------------
// Settlement, end to end
// ---------------------------------------------------------------------------

#[test]
fn the_mvp_objective_ratchets_from_baseline_to_best_and_audits_clean() {
    // The demo's narrative through the rules engine rather than the CLI: a lying
    // artifact earns nothing, three real improvements walk the frontier down,
    // each citing the holder it beat, and an auditor re-derives every payment.
    let mut run = Runner::new("mvp-e2e", mvp());
    let ratchet = run.ratchet.clone();

    // The liar first, so everything after it happens on a log that already
    // carries a refused claim.
    let outcome = run
        .submit("mallory", shipped("bogus"), "m1")
        .expect("a rejected claim is still a recorded claim");
    assert_eq!(outcome.verdict.status, Status::Reject);
    assert!(!outcome.settled);
    assert!(run.frontier_score().is_none(), "a lie moved the frontier");

    // The baseline artifact verifies -- it is exactly at the threshold -- and
    // still cannot open the frontier, because zero progress is not an
    // improvement. Worth its own step: "accepted" and "paid" are different
    // answers and this is the cheapest place to see it.
    let outcome = run
        .submit("dana", shipped("baseline"), "d1")
        .expect("submitted");
    assert_eq!(outcome.verdict.status, Status::Accept);
    assert_eq!(outcome.reward, 0, "the baseline is worth no progress");
    assert!(run.frontier_score().is_none());

    let mut expected_total = 0u64;
    let mut previous: Option<i64> = None;
    for (who, file, score) in [
        ("alice", "open", 90_000i64),
        ("bob", "mid", 56_000),
        ("carol", "best", 20_000),
    ] {
        let outcome = run
            .submit(who, shipped(file), file)
            .unwrap_or_else(|error| panic!("{who} could not submit: {error}"));
        assert_eq!(outcome.verdict.status, Status::Accept, "{who}");
        assert_eq!(outcome.verdict.score(), Some(score), "{who}");
        assert_eq!(
            outcome.reward,
            ratchet.payout(previous, score).expect("a live curve"),
            "{who} was paid other than the distance moved"
        );
        assert!(outcome.settled, "{who}: {}", outcome.note);
        expected_total += outcome.reward;
        previous = Some(score);

        let held = run.frontier_score().expect("the frontier moved");
        assert_eq!(held, score, "{who} did not take the frontier");
    }

    // The pool paid the cumulative at 20,000 and not a unit more. The target is
    // 10,000, so it is not empty.
    assert_eq!(
        run.direct().values().sum::<u64>(),
        expected_total,
        "the settlements and the outcomes disagree"
    );
    assert_eq!(expected_total, ratchet.cumulative(20_000).unwrap());
    assert!(
        expected_total < ratchet.reward,
        "the target was not reached, so the pool is not empty"
    );
    run.assert_sound();
}

#[test]
fn reaching_the_mvp_target_exhausts_the_pool_exactly_and_never_over() {
    // The pool bound is what makes a bounty a bounty. Overshooting the target
    // pays for the span and not a unit further, however far past it the artifact
    // goes.
    let mut run = Runner::new("mvp-exhaust", mvp());
    let ratchet = run.ratchet.clone();

    // 10 x 800 = 8,000, past the 10,000 target.
    let outcome = run
        .submit("alice", metrics(10, 800), "a1")
        .expect("submitted");
    assert_eq!(outcome.verdict.status, Status::Accept);
    assert_eq!(
        outcome.reward, ratchet.reward,
        "the target pays the whole pool"
    );
    assert!(
        outcome.note.contains("exhaust"),
        "the outcome should say the pool is spent: {}",
        outcome.note
    );

    // A further improvement earns nothing, because there is nothing left.
    let outcome = run.submit("bob", metrics(8, 500), "b1").expect("submitted");
    assert_eq!(outcome.reward, 0, "the pool was already exhausted");
    assert_eq!(
        run.direct().values().sum::<u64>(),
        ratchet.reward,
        "the pool paid out exactly once over"
    );
    run.assert_sound();
}

#[test]
fn an_improvement_under_min_improvement_earns_nothing_and_is_told_why() {
    // `min_improvement` is 1,000 on the MVP objective. A 999-unit step is a real
    // improvement that pays zero, and the message matters as much as the money:
    // an agent reads it as a reward signal, and "you did not improve" would send
    // somebody holding a genuine advance away to discard it.
    let mut run = Runner::new("mvp-floor", mvp());
    assert_eq!(run.ratchet.min_improvement, 1_000);

    run.submit("alice", metrics(90, 1_000), "a1")
        .expect("alice opens at 90,000");
    assert_eq!(run.frontier_score(), Some(90_000));

    // 9 x 9,889 = 89,001: better by 999, which is under the gate.
    let outcome = run
        .submit("bob", metrics(9, 9_889), "b1")
        .expect("submitted");
    assert_eq!(outcome.verdict.score(), Some(89_001));
    assert_eq!(
        outcome.reward, 0,
        "999 units of progress is under the floor"
    );
    assert_eq!(
        run.frontier_score(),
        Some(90_000),
        "a sub-floor step must not move the frontier"
    );
    assert!(
        matches!(
            run.ratchet.stall(Some(90_000), 89_001),
            Some(Stall::BelowMinImprovement { .. })
        ),
        "the refusal must read as better-but-too-small, not as a regression"
    );

    // One unit further and it clears.
    let outcome = run
        .submit("carol", metrics(10, 8_900), "c1")
        .expect("submitted");
    assert_eq!(outcome.verdict.score(), Some(89_000));
    assert!(
        outcome.reward > 0,
        "exactly 1,000 units of progress must pay"
    );
    assert_eq!(run.frontier_score(), Some(89_000));
    run.assert_sound();
}

#[test]
fn the_frontier_holder_must_be_cited_even_by_a_claim_that_does_not_improve() {
    // Not conditional on improving, and that is the point: citation flow is how
    // the person you built on gets paid, so it cannot be optional for the
    // submissions that happen to fail.
    let mut run = Runner::new("mvp-cite", mvp());
    run.submit("alice", metrics(90, 1_000), "a1")
        .expect("alice opens");

    for (label, artifact, nonce) in [
        ("an improvement", metrics(50, 400), "b1"),
        ("a regression", metrics(95, 1_000), "b2"),
    ] {
        let refused = run.submit_citing("bob", artifact, nonce, Vec::new());
        assert!(
            matches!(refused, Err(RuleViolation::MissingFrontierCitation { .. })),
            "{label} without the frontier citation must be refused: {refused:?}"
        );
    }

    // With the citation it is admitted.
    let outcome = run
        .submit("bob", metrics(50, 400), "b3")
        .expect("bob cites and is admitted");
    assert_eq!(outcome.verdict.status, Status::Accept);
    run.assert_sound();
}

// ---------------------------------------------------------------------------
// The live objective, and what it actually pays for
// ---------------------------------------------------------------------------

#[test]
fn the_live_objective_settles_the_published_world_best() {
    // The live port at real scale: scores near 1.1e10, a 5,000,000 pool, and a
    // span of 9,358,874,395. Nothing here is a small number, which is the point
    // -- every payout multiplies a reward by a progress and divides by a span,
    // and this is the shipped objective where those factors are large enough to
    // matter.
    let mut run = Runner::new("live-e2e", live());
    let ratchet = run.ratchet.clone();

    // The challenge-start artifact is exactly the baseline: it verifies, and it
    // is worth no progress at all.
    let outcome = run
        .submit("start", shipped("challenge-start"), "s1")
        .expect("submitted");
    assert_eq!(outcome.verdict.status, Status::Accept);
    assert_eq!(outcome.verdict.score(), Some(ratchet.baseline));
    assert_eq!(outcome.reward, 0, "the baseline is worth nothing");
    assert!(run.frontier_score().is_none());

    // The published world best opens the frontier.
    let outcome = run
        .submit("edi3on", shipped("world-best-aug2026"), "w1")
        .expect("submitted");
    assert_eq!(outcome.verdict.status, Status::Accept);
    assert_eq!(outcome.verdict.score(), Some(WORLD_BEST));
    assert_eq!(outcome.reward, ratchet.payout(None, WORLD_BEST).unwrap());
    assert_eq!(run.frontier_score(), Some(WORLD_BEST));

    run.assert_sound();
}

#[test]
fn the_live_objective_strands_its_own_pool() {
    // THE FINDING. `GAP.md` item 7 records that a ratchet can strand its pool
    // and that the *diagnostics* were fixed; this pins that the shipped live
    // objective still has the shape, with its own numbers, through the rules
    // engine.
    //
    // The published world best leaves 83,649,332 of span. `min_improvement` is
    // 100,000,000. So the largest gain any further claim can record is smaller
    // than the gate, and no artifact at any score ever settles against this
    // objective again -- including one that beats the world record outright.
    let mut run = Runner::new("live-strand", live());
    let ratchet = run.ratchet.clone();

    let remaining_span = ratchet.span() - ratchet.progress(WORLD_BEST);
    assert_eq!(remaining_span, 83_649_332);
    assert!(
        remaining_span < ratchet.min_improvement,
        "the premise: {remaining_span} of span left against a {} gate",
        ratchet.min_improvement
    );

    let opened = run
        .submit("edi3on", shipped("world-best-aug2026"), "w1")
        .expect("submitted");
    let paid_out = opened.reward;
    let stranded = ratchet.reward - paid_out;
    assert_eq!(paid_out, 4_955_310, "the first accepted submission's take");
    assert_eq!(stranded, 44_690, "and what is left behind forever");
    assert!(
        paid_out * 100 / ratchet.reward >= 99,
        "the bounty paid {paid_out} of {} for reproducing published work",
        ratchet.reward
    );

    // The objective is now shut. `is_exhausted` says so directly.
    assert!(
        ratchet.is_exhausted(WORLD_BEST),
        "the ratchet should know it can never move again"
    );

    // And it is shut against real advances, not just against spam. Each of these
    // beats the published world record; every one earns zero and leaves the
    // frontier where it was. What must never happen is a refusal that reads as
    // "your result is worse" -- that is what would tell a contributor holding a
    // world record to throw it away.
    for (better, gain) in [
        (1_470_000_000i64, "0.9%"),
        (1_450_000_000, "2.3%"),
        (1_420_000_000, "4.3%"),
        // Exactly the target. Still the gate that bites rather than the clamp:
        // no progress is thrown away at the target itself, there simply is not
        // enough span left between the frontier and it.
        (ratchet.target, "the target"),
    ] {
        assert!(better < WORLD_BEST, "{better} is supposed to be better");
        assert!(
            !ratchet.improves(Some(WORLD_BEST), better),
            "a {gain} gain on the world record should be refused by the gate"
        );
        // Still short of the target, so the gate is the one that bites and the
        // shortfall is a real number the submitter could in principle close.
        match ratchet.stall(Some(WORLD_BEST), better) {
            Some(Stall::BelowMinImprovement { gained, .. }) => assert!(
                gained < ratchet.min_improvement,
                "{better} reported a gain of {gained} that clears the gate"
            ),
            other => panic!("a {gain} gain stalled as {other:?}"),
        }
    }

    // Past the target the diagnosis has to change, because no larger improvement
    // would help either: progress stops at the target, so the whole remaining
    // span is all anyone can ever gain however far past it they go, and it is
    // under the gate. That is the difference between "find a bigger improvement"
    // and "this objective cannot be moved again", and conflating them is exactly
    // what `Stall` exists to stop.
    for unreachable in [ratchet.target - 1, 1_170_013_503] {
        match ratchet.stall(Some(WORLD_BEST), unreachable) {
            Some(Stall::ClampedByTarget { gained, .. }) => {
                assert_eq!(gained, remaining_span, "{unreachable}")
            }
            other => panic!("{unreachable} stalled as {other:?}, not clamped-by-target"),
        }
    }

    // Through the engine, not just the arithmetic: a genuine world-record
    // improvement is admitted, verified, and paid nothing.
    let outcome = run
        .submit("frontier-holder", metrics(1_000, 1_450_000), "f1")
        .expect("submitted");
    assert_eq!(
        outcome.verdict.status,
        Status::Accept,
        "{}",
        outcome.verdict.detail
    );
    assert_eq!(
        outcome.verdict.score(),
        Some(1_450_000_000),
        "a 2.3% gain on the world record"
    );
    assert_eq!(
        outcome.reward, 0,
        "a world-record improvement earned {} against a pool holding {stranded}",
        outcome.reward
    );
    assert_eq!(
        run.frontier_score(),
        Some(WORLD_BEST),
        "and the frontier still names the older, worse result"
    );

    // The money is not lost or double-counted, just unreachable: the log is
    // consistent and the audit is clean. That is what makes this a design
    // defect rather than a bug -- nothing is broken, and nobody can be paid.
    assert_eq!(run.direct().values().sum::<u64>(), paid_out);
    run.assert_sound();
}

// ---------------------------------------------------------------------------
// Strategies: what a submitter gains by playing something other than straight
// ---------------------------------------------------------------------------

#[test]
fn publishing_immediately_beats_holding_the_same_result_back() {
    // The most important economic claim the design makes: an agent that
    // publishes as soon as it has something is not punished for it. Two agents
    // can reach 20,000; one submits at the first opportunity, the other waits.
    let mut run = Runner::new("publish-vs-hoard", mvp());

    let prompt = run
        .submit("prompt", tagged(20_000, 10, "prompt"), "p1")
        .expect("submitted");
    assert!(prompt.reward > 0, "the agent that published got nothing");

    run.idle(4);

    // The hoarder submits the same score four epochs later. Deliberately not
    // gated on "would this still improve": an agent does not know it has been
    // beaten until it looks, and suppressing the submission would make "earned
    // nothing" and "never submitted" the same observation.
    let late = run
        .submit("hoarder", tagged(20_000, 20, "hoarder"), "h1")
        .expect("submitted");
    run.assert_played("hoarder");
    assert_eq!(
        late.reward, 0,
        "holding a result back while somebody else publishes it earns nothing"
    );
    assert!(
        run.paid("prompt") > run.paid("hoarder"),
        "hoarding must not pay better: prompt {} against hoarder {}",
        run.paid("prompt"),
        run.paid("hoarder")
    );
    run.assert_sound();
}

#[test]
fn hoarding_costs_nothing_only_when_nobody_else_is_looking() {
    // The honest other half, and the reason the incentive is a *bet* rather than
    // a penalty. Telescoping means a hoarder alone in the world loses nothing by
    // waiting: the curve pays for distance moved, not for when it moved. So the
    // pressure to publish early is "waiting is a bet that nobody else finds it",
    // and the previous test is that bet losing.
    let mut alone = Runner::new("hoard-alone", mvp());
    alone.idle(4);
    let late = alone
        .submit("hoarder", tagged(20_000, 10, "hoarder"), "h1")
        .expect("submitted");

    let mut prompt = Runner::new("publish-alone", mvp());
    let early = prompt
        .submit("prompt", tagged(20_000, 10, "prompt"), "p1")
        .expect("submitted");

    assert_eq!(
        late.reward, early.reward,
        "with no competition the timing of a single improvement changes nothing"
    );
    assert_eq!(late.reward, alone.ratchet.payout(None, 20_000).unwrap());
    alone.assert_sound();
    prompt.assert_sound();
}

#[test]
fn copying_the_frontier_artifact_mints_nothing() {
    // "Copying earns exactly zero" is the promise that makes publishing
    // immediately safe. Copying is also the cheapest strategy available -- no
    // search, no risk -- so if it paid anything it would dominate.
    let mut run = Runner::new("copy", mvp());
    run.submit("carol", shipped("best"), "c1")
        .expect("carol submits");
    let held = run.frontier_artifact().expect("carol holds the frontier");
    let carol_before = run.paid_directly("carol");

    // eve resubmits carol's bytes under her own name, citing the frontier as the
    // rules require.
    let outcome = run.submit("eve", held, "e1").expect("the copy is admitted");
    run.assert_played("eve");
    assert_eq!(
        outcome.verdict.status,
        Status::Accept,
        "the copy verifies; that was never the defence"
    );
    assert_eq!(outcome.reward, 0, "a copy must mint nothing");
    assert_eq!(run.paid_directly("eve"), 0);
    assert_eq!(
        run.paid_directly("carol"),
        carol_before,
        "the copy changed what the original was paid"
    );
    // And nothing reaches her through the citation graph either: flow follows
    // settlements, and she has none.
    assert_eq!(run.paid("eve"), 0, "a copy collected citation flow");
    run.assert_sound();
}

#[test]
fn a_liar_earns_nothing_and_leaves_the_honest_run_untouched() {
    // The verifier is the only thing between a funded objective and an agent
    // that simply asserts a number. A rejected claim must also be inert: it is
    // recorded, and it changes nothing about what anyone else is paid.
    let mut honest = Runner::new("no-liar", mvp());
    honest
        .submit("alice", metrics(40, 1_000), "a1")
        .expect("submitted");

    let mut invaded = Runner::new("with-liar", mvp());
    invaded
        .submit("mallory", shipped("bogus"), "m1")
        .expect("recorded");
    invaded
        .submit("alice", metrics(40, 1_000), "a1")
        .expect("submitted");

    assert_eq!(invaded.paid("mallory"), 0, "a lie was paid");
    assert_eq!(
        invaded.claims_by("mallory"),
        0,
        "a rejected claim must not count as an accepted one"
    );
    assert_eq!(
        invaded.paid("alice"),
        honest.paid("alice"),
        "the liar changed what the honest submitter received"
    );
    invaded.assert_sound();
}

/// Run alice -> bob (-> carol) on the MVP objective, with bob's improvement
/// delivered as `slices` steps, and return the finished log.
///
/// alice opens the frontier and bob walks it down, chopped or not. `downstream`
/// adds carol, who improves on whatever bob left. Three parties is the minimum
/// that separates the two halves of the slicing question: carol is the
/// *downstream* citer whose contribution the weighting was designed to protect,
/// and bob's own steps citing each other are the half it does not.
fn sliced_run(label: &str, slices: usize, downstream: bool) -> Runner {
    let gain = 8_000i64;
    let step = gain / slices as i64;
    assert!(step > 0, "a slice must be a whole number of units");

    let mut run = Runner::new(label, mvp());
    run.submit("alice", tagged(90_000, 10, "alice"), "a1")
        .expect("alice opens at 90,000");
    for i in 0..slices {
        let score = 90_000 - step * (i as i64 + 1);
        run.submit("bob", tagged(score, 20, &format!("b{i}")), &format!("b{i}"))
            .unwrap_or_else(|error| panic!("{label}: slice {i} refused: {error}"));
    }
    assert_eq!(
        run.frontier_score(),
        Some(90_000 - gain),
        "{label}: bob did not finish his improvement"
    );
    if downstream {
        run.submit("carol", tagged(70_000, 10, "carol"), "c1")
            .expect("carol improves on whatever bob left");
    }
    run.assert_sound();
    run
}

/// What a downstream citer's own settlement sends the original contributor.
///
/// Attribution reports totals, not who paid whom, and the weights come from the
/// *whole* settlement set -- so running it over one payer's settlement in
/// isolation zeroes every ancestor's weight and answers a different question.
/// Differencing two runs that agree on everything except whether carol exists
/// isolates her contribution without touching the rule: bob's settlement
/// distributes the same either way, so what changes when carol is added is
/// exactly what carol paid.
fn downstream_contribution(slices: usize, to: &str) -> u64 {
    let with = sliced_run(&format!("with-carol-{slices}"), slices, true);
    let without = sliced_run(&format!("no-carol-{slices}"), slices, false);
    with.paid(to)
        .checked_sub(without.paid(to))
        .expect("adding a downstream citer cannot reduce what an ancestor is paid")
}

#[test]
fn slicing_leaves_the_direct_reward_and_the_downstream_half_exactly_invariant() {
    // The two guarantees the payment mechanism actually makes, measured on a log
    // the rules engine settled rather than on hand-built claims.
    //
    // Telescoping covers the direct reward: the pool is identical however the
    // curve is chopped. Telescoping never covered citation *flow*, and under the
    // old per-hop rule chopping drove the upstream contributor's flow to zero --
    // the dominant strategy rather than an exotic attack. `payouts_over` now
    // weights delta by each ancestor's settled reward, and the half of the attack
    // that closes *exactly* is the downstream one: however bob chops, a later
    // contributor building on him pays alice the same.
    //
    // `tests/citation_flow.rs` pins this through `payouts_over` on fixtures,
    // which `docs/design/citation-flow-dilution.md` notes is the only check the
    // weighted rule has -- the conformance vectors pin the per-hop `flow`, not
    // this. Here it runs where the money moves: real verdicts, real batches, and
    // the frontier citation the rules force on every slice.
    let whole = sliced_run("downstream-whole", 1, true);
    let sliced = sliced_run("downstream-sliced", 8, true);

    assert_eq!(sliced.claims_by("bob"), 8, "every slice landed");
    assert_eq!(whole.claims_by("bob"), 1);
    assert_eq!(sliced.frontier_score(), whole.frontier_score());

    // Telescoping, unit for unit.
    assert_eq!(
        sliced.paid_directly("bob"),
        whole.paid_directly("bob"),
        "chopping changed bob's direct reward"
    );
    assert_eq!(
        sliced.direct().values().sum::<u64>(),
        whole.direct().values().sum::<u64>(),
        "chopping changed the size of the pool paid out"
    );

    // The downstream half, exact: what carol's settlement sends alice does not
    // depend on how bob chopped the middle.
    let from_carol_whole = downstream_contribution(1, "alice");
    let from_carol_sliced = downstream_contribution(8, "alice");
    assert!(
        from_carol_whole > 0,
        "carol should be paying alice something, or this measures nothing"
    );
    assert_eq!(
        from_carol_sliced, from_carol_whole,
        "a downstream citer paid alice {from_carol_sliced} against {from_carol_whole} \
         when bob chopped -- the half the weighting is supposed to close exactly"
    );
}

#[test]
fn the_slicers_own_premium_is_bounded_and_converges() {
    // The half that does *not* close, pinned so it cannot quietly grow.
    //
    // Each of bob's later slices counts his earlier slices as ancestors, so
    // alice's weight is diluted by bob's own reward in the denominator. That is
    // a real residue and the design accepts it, on the grounds that it is
    // bounded: under the old per-hop rule the extraction was unbounded and a
    // determined slicer took *all* of alice's flow, and the qualitative
    // difference between "converges" and "tends to zero" is the whole argument.
    // So the assertions here are about the shape of the sequence, not a single
    // number.
    let mut takes: Vec<(usize, u64)> = Vec::new();
    for slices in [1usize, 2, 4, 8] {
        let run = sliced_run(&format!("premium-{slices}"), slices, true);
        takes.push((slices, run.paid("alice")));
    }

    // Exact, because these are the numbers `docs/threat-model.md` quotes for the
    // size of the residue. A change to attribution that moves them is a change
    // to who gets paid, and it should have to come here and edit them.
    assert_eq!(
        takes,
        vec![(1, 151_851u64), (2, 148_676), (4, 147_253), (8, 146_587)],
        "the premium's measured shape has moved"
    );

    let unchopped = takes[0].1;
    // Monotone: more cuts never pay alice more. (The old rule was monotone too;
    // this is the premise, not the defence.)
    for pair in takes.windows(2) {
        assert!(
            pair[1].1 <= pair[0].1,
            "alice was paid more at {} slices than at {}: {takes:?}",
            pair[1].0,
            pair[0].0
        );
    }

    // Bounded: she keeps essentially all of it. Under the per-hop rule her
    // citation flow went to zero, leaving only her direct reward.
    let direct = sliced_run("premium-direct", 1, true).paid_directly("alice");
    let worst = takes.last().expect("measurements").1;
    assert!(
        worst > direct,
        "alice kept {worst} against a direct reward of {direct}: her citation \
         flow has been driven to zero, which is the failure this rule replaced"
    );
    assert!(
        (unchopped - worst) * 20 < unchopped,
        "slicing took {} of alice's {unchopped} units, over 5%: {takes:?}",
        unchopped - worst
    );

    // Converging: each doubling of the slice count costs alice strictly less
    // than the previous doubling did. An extraction that grew would show up here
    // as a flat or rising marginal cost.
    let marginal: Vec<u64> = takes.windows(2).map(|pair| pair[0].1 - pair[1].1).collect();
    assert!(
        marginal.iter().all(|step| *step > 0),
        "no slice count changed anything, so this measures nothing: {takes:?}"
    );
    for pair in marginal.windows(2) {
        assert!(
            pair[1] < pair[0],
            "the marginal gain from slicing is not shrinking: {marginal:?}"
        );
    }

    // And `min_improvement` caps how finely the curve can be cut at all, which
    // is what bounds the slice count rather than trusting the convergence.
    let run = sliced_run("premium-cap", 8, true);
    let held = run.frontier_score().expect("a frontier");
    assert!(
        run.ratchet.min_improvement == 1_000,
        "this bound is what makes 8 slices of an 8,000-unit gain the finest cut"
    );
    let _ = held;
}

#[test]
fn splitting_a_slicer_across_identities_gains_nothing_either() {
    // Minting a name is one command, so a rule that only resists slicing by
    // *one* submitter resists nothing. Reward weighting is identity-blind --
    // it weights by what each claim settled for, and never asks who submitted
    // it -- so eight slices under eight names must distribute exactly as eight
    // slices under one.
    let step = 1_000i64;

    let mut single = Runner::new("one-name", mvp());
    single
        .submit("alice", tagged(90_000, 10, "alice"), "a1")
        .expect("alice opens");
    for i in 0..8 {
        let score = 90_000 - step * (i as i64 + 1);
        single
            .submit("bob", tagged(score, 20, &format!("b{i}")), &format!("b{i}"))
            .expect("slice lands");
    }

    let mut split = Runner::new("eight-names", mvp());
    split
        .submit("alice", tagged(90_000, 10, "alice"), "a1")
        .expect("alice opens");
    for i in 0..8 {
        let score = 90_000 - step * (i as i64 + 1);
        split
            .submit(
                &format!("bob-{i}"),
                tagged(score, 20, &format!("b{i}")),
                &format!("b{i}"),
            )
            .expect("slice lands");
    }

    assert_eq!(single.frontier_score(), split.frontier_score());
    // The upstream contributor is paid the same either way, which is the claim
    // that "there is no sybil version of this attack" rests on.
    assert_eq!(
        split.paid("alice"),
        single.paid("alice"),
        "eight names took {} units from alice that eight slices did not",
        single.paid("alice").abs_diff(split.paid("alice"))
    );
    let sybil_total: u64 = split
        .total()
        .iter()
        .filter(|(who, _)| who.starts_with("bob"))
        .map(|(_, units)| *units)
        .sum();
    assert_eq!(
        sybil_total,
        single.paid("bob"),
        "the split identities' total differs from the single name's"
    );
    split.assert_sound();
    single.assert_sound();
}

#[test]
fn several_slices_in_one_epoch_are_ordered_by_the_beacon_and_paid_once() {
    // Chopping inside a single epoch is a different move from chopping across
    // epochs, and it is worse for the slicer. The frontier advances only at
    // settlement, so every claim revealed in one epoch cites the same holder;
    // then the batch settles in an order no submitter chooses, and a slice that
    // arrives after a better one has already advanced the frontier earns zero.
    let mut run = Runner::new("one-epoch", mvp());
    run.submit("alice", tagged(90_000, 10, "alice"), "a1")
        .expect("alice opens");
    let cites = run.required_cites();

    let submissions: Vec<(String, Value, String)> = (1..=5)
        .map(|i| {
            let score = 90_000 - i * 1_000;
            (
                "bob".to_string(),
                tagged(score, 20, &format!("b{i}")),
                format!("b{i}"),
            )
        })
        .collect();
    let outcomes = run
        .reveal_all(&submissions, cites)
        .expect("five reveals in one epoch");

    assert_eq!(outcomes.len(), 5);
    assert!(
        outcomes
            .iter()
            .all(|outcome| outcome.verdict.status == Status::Accept),
        "every chop verifies"
    );
    let paid = outcomes.iter().filter(|outcome| outcome.reward > 0).count();
    assert!(
        paid < outcomes.len(),
        "every one of five chops paid, so the beacon handed bob the sorted \
         order -- possible, but then this test measures nothing"
    );
    assert!(paid >= 1, "no chop paid at all");

    // Whatever the beacon chose, the total is the telescoped distance: the waste
    // falls on the slicer and never on the pool.
    assert_eq!(
        run.paid_directly("bob"),
        run.ratchet.payout(Some(90_000), 85_000).unwrap(),
        "the pool paid other than the distance bob moved"
    );
    assert_eq!(run.frontier_score(), Some(85_000));
    run.assert_sound();
}

#[test]
fn a_commitment_binds_the_artifact_and_the_epoch_it_can_open_in() {
    // Two admission rules the whole two-phase design rests on. Without the
    // first, an agent commits early to reserve a settlement slot and decides
    // what to submit after watching what everyone else revealed; without the
    // second, the sequencer -- who sees reveals first -- opens a commitment of
    // its own in the same breath.
    let dir = TempDir::new("commitment");
    let mut node = node_at(&dir);
    let objective = mvp();
    node.post_objective(&objective, &stamp(0)).expect("posted");

    let committed = metrics(90, 1_000);
    let hash = commitment_hash(&objective.id(), "alice", &committed, "a1");
    node.commit(
        &Commitment::new(objective.id(), "alice", hash, stamp(0)),
        &stamp(0),
    )
    .expect("commit lands");

    // Same nonce, same submitter, better artifact.
    let swapped = Claim::new(
        objective.id(),
        "alice",
        metrics(50, 400),
        "a1",
        stamp(epoch()),
        Vec::new(),
    )
    .expect("structurally valid");
    assert!(
        matches!(
            node.reveal(&swapped, &stamp(epoch())),
            Err(RuleViolation::NoMatchingCommitment)
        ),
        "a swapped artifact must not open a commitment"
    );

    // The committed artifact, revealed in the commitment's own epoch.
    let same_epoch = Claim::new(
        objective.id(),
        "alice",
        committed.clone(),
        "a1",
        stamp(0),
        Vec::new(),
    )
    .expect("structurally valid");
    assert!(
        matches!(
            node.reveal(&same_epoch, &stamp(0)),
            Err(RuleViolation::RevealBeforeEpoch { .. })
        ),
        "a same-epoch reveal must be refused"
    );

    // And an epoch later it is admitted, so both refusals were about what they
    // said they were about.
    let honest = Claim::new(
        objective.id(),
        "alice",
        committed,
        "a1",
        stamp(epoch()),
        Vec::new(),
    )
    .expect("structurally valid");
    let outcome = node.reveal(&honest, &stamp(epoch())).expect("admitted");
    assert_eq!(outcome.verdict.status, Status::Accept);
}
