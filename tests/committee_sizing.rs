//! Sizing the committee against what it guards.
//!
//! `docs/node-incentives.md` derives the condition under which opening a sealed
//! submission early does not pay:
//!
//! ```text
//! V  <=  t * d * S'
//! ```
//!
//! and says in bold that **the committee has to grow with the size of the
//! bounties it seals**. A fixed 3-of-5 that is right for a thousand-unit bounty
//! is corruptible for a million-unit one, and nothing about the code changes.
//! Until this file existed, nothing about the code changed.
//!
//! | claim | test |
//! |---|---|
//! | a quiet log still draws exactly five | [`a_log_with_nothing_at_stake_draws_the_floor`] |
//! | value carried into an epoch grows the committee | [`a_committee_grows_with_the_value_it_guards`] |
//! | the size is fixed before the epoch's first record | [`the_size_is_fixed_at_the_epoch_boundary`] |
//! | a cartel is priced at its cheapest members, not its average | [`the_guard_is_the_cheapest_members_not_the_average`] |
//! | a seal the committee cannot guard is refused, at seal time | [`a_bounty_bigger_than_its_committee_is_refused_before_it_is_sealed`] |
//! | the threshold rule reproduces the old constants | [`the_threshold_rule_reproduces_the_constants`] |

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use rand_core::OsRng;
use sha2::{Digest, Sha256};

use cairn::canonical::Value;
use cairn::crypto::envelope::CommitteeKey;
use cairn::crypto::identity::Identity;
use cairn::ledger::Ledger;
use cairn::node::Node;
use cairn::partition::{threshold_for, COMMITTEE_SIZE, COMMITTEE_THRESHOLD};
use cairn::records::{Claim, Commitment, Issuance, Objective, PeerRecord};
use cairn::verifiers::VerifierRegistry;

/// Epoch boundaries. `EPOCH_SECONDS` is 600.
const EPOCH_0: &str = "2026-07-28T00:00:00+00:00";
const EPOCH_1: &str = "2026-07-28T00:10:00+00:00";
const EPOCH_2: &str = "2026-07-28T00:20:00+00:00";

const CHECKER: &str = r#"
def check(artifact):
    return artifact.get("n") == 42
"#;

/// The *absolute* epoch a timestamp falls in.
///
/// Not a small ordinal. Epochs are `unix_seconds / EPOCH_SECONDS`, so the
/// epochs these fixtures live in are around 2.9 million — and passing `1` where
/// the code expects that number silently asks about an epoch in 1970, whose
/// boundary prefix is empty and whose committee therefore has nothing staked
/// behind it. Every failure in the first run of this file was that.
fn epoch_of(ts: &str) -> u64 {
    let seconds = cairn::time::parse_rfc3339(ts).expect("a well-formed instant");
    cairn::partition::epoch_of(seconds as u64, cairn::partition::EPOCH_SECONDS)
}

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
            "proofwork-sizing-{label}-{unique}-{}",
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

/// One peer: a committee key, an identity, and the record tying them together.
struct Member {
    committee: CommitteeKey,
    identity: Identity,
}

impl Member {
    fn new(seed: u8) -> Member {
        Member {
            committee: CommitteeKey::generate(&mut OsRng),
            identity: Identity::from_secret_bytes([seed; 32]),
        }
    }

    fn peer_record(&self, port: u16, ts: &str) -> PeerRecord {
        PeerRecord::new(
            self.identity.submitter_id(),
            cairn::hex::encode(&self.committee.id()),
            format!("127.0.0.1:{port}"),
            1,
            ts,
        )
        .signed_with(&self.identity)
    }
}

struct Fixture {
    _dir: TempDir,
    node: Node,
    objective: Objective,
    members: Vec<Member>,
}

/// A log with `peers` registered peers, each issued `stake` units at genesis,
/// and one objective worth `reward`.
///
/// `stake` is what a member can lose, and it is an ordinary balance rather than
/// a new record: a member's spendable units are already derived, already scarce
/// once a supply is declared, and already what every other bond in this crate
/// is drawn from.
fn fixture(label: &str, peers: u8, stake: u64, reward: u64) -> Fixture {
    let dir = TempDir::new(label);
    fs::write(dir.path.join("c.py"), CHECKER).expect("writable");
    let mut hasher = Sha256::new();
    hasher.update(CHECKER.as_bytes());
    let sha = cairn::hex::encode(&hasher.finalize());

    let ledger = Ledger::open(dir.path.join("log.jsonl")).expect("an empty log");
    let mut node = Node::with_registry(ledger, VerifierRegistry::new(&dir.path));

    let members: Vec<Member> = (1..=peers).map(Member::new).collect();
    // Genesis first: issuance is admissible only in the genesis prefix.
    for member in &members {
        node.post_issuance(
            &Issuance::new(member.identity.submitter_id(), stake, EPOCH_0),
            EPOCH_0,
        )
        .expect("genesis issuance");
    }
    node.post_issuance(&Issuance::new("treasury", 100_000_000, EPOCH_0), EPOCH_0)
        .expect("genesis issuance");

    let objective = Objective::new(
        "G",
        "find n = 42",
        Value::object([
            ("kind", Value::string("certificate")),
            ("checker", Value::string("c.py")),
            ("checker_sha256", Value::string(sha.as_str())),
            ("entrypoint", Value::string("check")),
        ]),
        reward,
        "treasury",
        EPOCH_0,
        None,
        None,
    )
    .expect("valid objective");
    node.post_objective(&objective, EPOCH_0).expect("post");
    for (index, member) in members.iter().enumerate() {
        node.post_peer(&member.peer_record(9000 + index as u16, EPOCH_0), EPOCH_0)
            .expect("peer");
    }
    Fixture {
        _dir: dir,
        node,
        objective,
        members,
    }
}

/// The same log with **no** issuance records, so no supply is declared.
fn fixture_without_supply(label: &str, peers: u8, reward: u64) -> Fixture {
    let dir = TempDir::new(label);
    fs::write(dir.path.join("c.py"), CHECKER).expect("writable");
    let mut hasher = Sha256::new();
    hasher.update(CHECKER.as_bytes());
    let sha = cairn::hex::encode(&hasher.finalize());
    let ledger = Ledger::open(dir.path.join("log.jsonl")).expect("an empty log");
    let mut node = Node::with_registry(ledger, VerifierRegistry::new(&dir.path));
    let members: Vec<Member> = (1..=peers).map(Member::new).collect();
    let objective = Objective::new(
        "G",
        "find n = 42",
        Value::object([
            ("kind", Value::string("certificate")),
            ("checker", Value::string("c.py")),
            ("checker_sha256", Value::string(sha.as_str())),
            ("entrypoint", Value::string("check")),
        ]),
        reward,
        "treasury",
        EPOCH_0,
        None,
        None,
    )
    .expect("valid objective");
    node.post_objective(&objective, EPOCH_0).expect("post");
    for (index, member) in members.iter().enumerate() {
        node.post_peer(&member.peer_record(9200 + index as u16, EPOCH_0), EPOCH_0)
            .expect("peer");
    }
    Fixture {
        _dir: dir,
        node,
        objective,
        members,
    }
}

/// Seal a submission into `ts`'s committee and append it straight to the log.
///
/// A **real** envelope, because `Commitment::from_value` parses the field and a
/// marker object is silently dropped — which made every sizing assertion in the
/// first run of this file read zero exposure and pass the floor.
///
/// Appended rather than committed through the rules, because several of these
/// tests need a log whose exposure the admission rules would have refused to
/// create. That is the point of the admission rule; it is not the point of the
/// sizing rule, and the two have to be testable apart.
fn seal_raw(fixture: &mut Fixture, who: &str, ts: &str) {
    let epoch = epoch_of(ts);
    let seats = fixture
        .node
        .committee_for(epoch, fixture.node.ledger().len())
        .expect("a committee");
    let committee: Vec<cairn::crypto::CommitteeMember> = seats
        .iter()
        .map(|seat| {
            fixture
                .members
                .iter()
                .find(|m| m.identity.submitter_id() == seat.identity)
                .expect("the seat is one of ours")
                .committee
                .member(seat.seat)
        })
        .collect();
    let claim = Claim::new(
        fixture.objective.id(),
        who,
        Value::object([("n", Value::Int(42))]),
        who,
        ts,
        Vec::new(),
    )
    .expect("a valid claim");
    let submission = cairn::sealed::SealedSubmission::seal_claim(
        &claim,
        epoch,
        ts,
        &committee,
        threshold_for(seats.len() as u8),
        &mut OsRng,
    )
    .expect("seals");
    let commitment = Commitment::new(
        fixture.objective.id(),
        who,
        submission.commitment.clone(),
        ts,
    )
    .sealed_with(submission.envelope.clone());
    fixture
        .node
        .ledger_mut()
        .append("commitment", commitment.to_value(), ts)
        .expect("the log accepts an appended record");
}

/// Seal a real submission through the ordinary path, so the check under test is
/// the *value* one rather than the shape one.
fn seal_real(fixture: &mut Fixture, ts: &str) -> Result<String, cairn::node::RuleViolation> {
    let epoch = {
        let seconds = cairn::time::parse_rfc3339(ts).expect("a well-formed instant");
        cairn::partition::epoch_of(seconds as u64, cairn::partition::EPOCH_SECONDS)
    };
    let seats = fixture
        .node
        .committee_for(epoch, fixture.node.ledger().len())
        .expect("a committee");
    let committee: Vec<cairn::crypto::CommitteeMember> = seats
        .iter()
        .map(|seat| {
            let member = fixture
                .members
                .iter()
                .find(|m| m.identity.submitter_id() == seat.identity)
                .expect("the seat is one of ours");
            member.committee.member(seat.seat)
        })
        .collect();
    let claim = Claim::new(
        fixture.objective.id(),
        "alice",
        Value::object([("n", Value::Int(42))]),
        "n",
        ts,
        Vec::new(),
    )
    .expect("a valid claim");
    let submission = cairn::sealed::SealedSubmission::seal_claim(
        &claim,
        epoch,
        ts,
        &committee,
        threshold_for(seats.len() as u8),
        &mut OsRng,
    )
    .expect("seals");
    let commitment = Commitment::new(
        fixture.objective.id(),
        "alice",
        submission.commitment.clone(),
        ts,
    )
    .sealed_with(submission.envelope.clone());
    fixture.node.commit(&commitment, ts)
}

// -- the tests -------------------------------------------------------------

/// The floor, and the reason every test written before this feature still
/// passes: with nothing sealed there is nothing to guard, so the size is the
/// constant it always was.
#[test]
fn a_log_with_nothing_at_stake_draws_the_floor() {
    let fixture = fixture("floor", COMMITTEE_SIZE + 4, 1_000, 1_000);
    for ts in [EPOCH_0, EPOCH_1, EPOCH_2] {
        let epoch = epoch_of(ts);
        assert_eq!(
            fixture
                .node
                .committee_size_at(epoch, fixture.node.ledger().len()),
            COMMITTEE_SIZE,
            "epoch {epoch} grew a committee with nothing to guard"
        );
    }
}

/// Value carried into an epoch grows the committee that guards it.
///
/// The measurement the whole feature exists for. Each member holds 1,000 and
/// the detection rate is a half, so a committee of `n` with threshold
/// `n/2 + 1` puts `(n/2 + 1) * 1000 / 2` at risk:
///
/// ```text
///   seats     5     6     7     8     9    10    11    12
///   t         3     4     4     5     5     6     6     7
///   guarded 1500  2000  2000  2500  2500  3000  3000  3500
/// ```
///
/// Note what the table says and the prose above it did not: with a strict
/// majority, an **odd** committee guards exactly what the even one below it
/// does — seven seats and six both need four colluders. So the rule always
/// lands on an even size when it grows, and a network paying for a seventh seat
/// is buying liveness, not collusion resistance. The first version of this test
/// asserted 5/7/9/13 from arithmetic done in prose; the numbers below are the
/// ones the mechanism produces.
#[test]
fn a_committee_grows_with_the_value_it_guards() {
    for (reward, want) in [(1_000u64, 5u8), (1_600, 6), (2_200, 8), (3_400, 12)] {
        let mut fixture = fixture("grow", 20, 1_000, reward);
        seal_raw(&mut fixture, "alice", EPOCH_1);
        let positions = fixture.node.ledger().len();
        // Sealed in epoch 1, so epoch 2's committee is the one carrying it.
        let size = fixture.node.committee_size_at(epoch_of(EPOCH_2), positions);
        assert_eq!(
            size, want,
            "a bounty of {reward} against 1000-unit stakes drew {size} seats"
        );
        // And the committee really does cover it at that size.
        let guarded = fixture
            .node
            .custody_guard(epoch_of(EPOCH_2), size, positions);
        assert!(
            guarded >= u128::from(reward),
            "{size} seats guard {guarded} against a bounty of {reward}"
        );
        // One seat smaller and it does not, so the answer is the *smallest*
        // committee that works rather than a comfortable one.
        if size > COMMITTEE_SIZE {
            let smaller = fixture
                .node
                .custody_guard(epoch_of(EPOCH_2), size - 1, positions);
            assert!(
                smaller < u128::from(reward),
                "{} seats already guarded {smaller}; the rule overshot",
                size - 1
            );
        }
    }
}

/// The size is a function of the epoch's *boundary* prefix, so it is fixed
/// before the epoch's first record exists.
///
/// The consistency requirement the whole design turns on. A submitter seals at
/// commit time and the committee opens an epoch later; if the shape moved in
/// between, the envelope would no longer match the seats and the submission
/// would be unopenable — by nobody's fault, and at the expense of the one party
/// who sealed precisely because they might not be able to come back.
#[test]
fn the_size_is_fixed_at_the_epoch_boundary() {
    let mut fixture = fixture("stable", 20, 1_000, 2_200);
    seal_raw(&mut fixture, "alice", EPOCH_1);
    let before = fixture
        .node
        .committee_size_at(epoch_of(EPOCH_2), fixture.node.ledger().len());
    assert_eq!(before, 8);

    // More records land *inside* epoch 2, including another sealed submission
    // that raises the epoch's own exposure. The size for epoch 2 does not move.
    seal_raw(&mut fixture, "bob", EPOCH_2);
    seal_raw(&mut fixture, "carol", EPOCH_2);
    assert_eq!(
        fixture
            .node
            .committee_size_at(epoch_of(EPOCH_2), fixture.node.ledger().len()),
        before,
        "the committee changed shape while its epoch was running"
    );
}

/// A cartel forms out of the cheapest members, so the guard is the sum of the
/// `t` smallest stakes and not `t` times an average.
///
/// The difference is not cosmetic. With one very rich member and four poor
/// ones, an average-based rule reports a committee that is safe and a
/// cheapest-members rule reports one that is not — and the cartel that actually
/// forms is the cheap one, because the rich member is the expensive way to buy
/// a seat.
#[test]
fn the_guard_is_the_cheapest_members_not_the_average() {
    let dir = TempDir::new("cheapest");
    let ledger = Ledger::open(dir.path.join("log.jsonl")).expect("an empty log");
    let mut node = Node::with_registry(ledger, VerifierRegistry::new(&dir.path));
    let members: Vec<Member> = (1..=COMMITTEE_SIZE).map(Member::new).collect();

    // One member holds a fortune and the rest hold almost nothing.
    for (index, member) in members.iter().enumerate() {
        let units = if index == 0 { 1_000_000 } else { 10 };
        node.post_issuance(
            &Issuance::new(member.identity.submitter_id(), units, EPOCH_0),
            EPOCH_0,
        )
        .expect("genesis issuance");
    }
    for (index, member) in members.iter().enumerate() {
        node.post_peer(&member.peer_record(9100 + index as u16, EPOCH_0), EPOCH_0)
            .expect("peer");
    }

    let positions = node.ledger().len();
    let guarded = node.custody_guard(epoch_of(EPOCH_1), COMMITTEE_SIZE, positions);
    // Threshold is 3. The three cheapest hold 10 each, so 30 at risk, halved by
    // the detection rate: 15. The average would have said 200,006.
    assert_eq!(guarded, 15, "the fortune was counted as if it were shared");
}

/// A submitter is told **before** sealing that the committee cannot guard the
/// value, not an epoch later when they may be gone.
///
/// The direction that matters. Letting the seal through would hand the
/// submitter a receipt for protection the arithmetic says they did not get, and
/// the whole reason to seal is that you may not be able to come back and check.
#[test]
fn a_bounty_bigger_than_its_committee_is_refused_before_it_is_sealed() {
    let mut poor = fixture("refuse", COMMITTEE_SIZE, 10, 1_000_000);
    let message = match seal_real(&mut poor, EPOCH_1) {
        Err(why) => format!("{why}"),
        Ok(_) => panic!("a million-unit bounty sealed behind 10-unit stakes was admitted"),
    };
    assert!(
        message.contains("better off opening it early"),
        "the refusal did not say why: {message}"
    );

    // The same bounty is fine once the members have something to lose, so the
    // rule is about the arithmetic rather than about sealed submissions.
    let mut rich = fixture("afford", COMMITTEE_SIZE, 10_000_000, 1_000_000);
    seal_real(&mut rich, EPOCH_1).expect("a committee with real stake accepts the seal");
    assert!(
        rich.node.audit(false).is_empty(),
        "{:?}",
        rich.node.audit(false)
    );

    // And a log that has never declared a supply is not held to it: it has not
    // claimed its units are scarce, so it has not claimed this protection
    // either. Checked because the alternative -- refusing every sealed
    // submission on a Stage-0 log -- is correct arithmetic and wrong behaviour.
    let mut stage0 = fixture_without_supply("stage0", COMMITTEE_SIZE, 1_000_000);
    seal_real(&mut stage0, EPOCH_1).expect("a log with no declared supply seals as before");
}

/// The threshold is derived from the size now, so the derivation has to
/// reproduce the constants it replaced or every log written before it becomes
/// unreadable.
#[test]
fn the_threshold_rule_reproduces_the_constants() {
    assert_eq!(threshold_for(COMMITTEE_SIZE), COMMITTEE_THRESHOLD);
    // A strict majority at every size, which is what makes an early-opening
    // cartel and a withholding cartel both need more than half the seats.
    for size in 1..=64u8 {
        let threshold = threshold_for(size);
        assert!(
            u32::from(threshold) * 2 > u32::from(size),
            "{threshold} of {size} is not a majority"
        );
        assert!(threshold <= size, "{threshold} of {size} is unreachable");
    }
}
