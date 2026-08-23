//! The key reveal, as a consensus rule rather than as a promise.
//!
//! `docs/censorship.md` §2 says a threshold committee opens a sealed submission
//! at the epoch boundary, without the submitter. Until the `committee_share`
//! record existed, none of the three nouns in that sentence were anchored to
//! anything a reader could check: the *committee* was whoever the submitter
//! sealed to, the *epoch boundary* was whatever a member's local clock said,
//! and the *opening* happened off-log. Every one of those is now derived from
//! records, and this file is where that claim is executed rather than asserted.
//!
//! | property | test |
//! |---|---|
//! | the committee is a pure function of the log, computable by anyone | [`the_committee_is_drawn_from_the_log_and_anyone_recomputes_it`] |
//! | a submission opens with the submitter permanently gone | [`a_censored_submitter_is_paid_by_the_committee_alone`] |
//! | a member cannot publish early | [`a_share_published_in_the_commitment_epoch_is_refused`] |
//! | a member cannot publish for someone else's seat | [`only_the_drawn_identity_can_publish_its_seat`] |
//! | a non-member cannot publish at all | [`a_peer_outside_the_committee_has_no_seat_to_publish`] |
//! | one lying member cannot stall a reveal | [`a_member_who_publishes_garbage_does_not_stop_the_reveal`] |
//! | below threshold, nothing opens | [`below_threshold_the_submission_stays_sealed`] |
//! | the threshold is the network's, not the submitter's | [`a_submitter_cannot_choose_a_weaker_committee`] |
//! | the audit re-derives every share rule | [`the_audit_reports_a_share_that_should_never_have_been_admitted`] |
//!
//! Everything goes through the public API, because that is the surface an
//! auditor has when they re-derive the network's history from a copy of the log.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use rand_core::OsRng;
use sha2::{Digest, Sha256};

use cairn::canonical::Value;
use cairn::crypto::envelope::CommitteeKey;
use cairn::crypto::identity::Identity;
use cairn::crypto::CommitteeMember;
use cairn::ledger::Ledger;
use cairn::node::{CommitteeSeat, Node, RuleViolation};
use cairn::partition::{COMMITTEE_SIZE, COMMITTEE_THRESHOLD};
use cairn::records::{Claim, Commitment, CommitteeShare, Objective, PeerRecord};
use cairn::sealed::SealedSubmission;
use cairn::verifiers::{Status, VerifierRegistry};

/// A Lean binary guaranteed absent, so no verdict here depends on a toolchain.
const NO_LEAN: &str = "cairn-committee-definitely-no-such-lean-binary";

/// Epoch boundaries. `EPOCH_SECONDS` is 600, so these are three whole epochs
/// apart and every "strictly later" rule below is unambiguous.
const COMMIT_AT: &str = "2026-07-28T00:00:00+00:00";
const REVEAL_AT: &str = "2026-07-28T00:20:00+00:00";
const LATER_AT: &str = "2026-07-28T00:40:00+00:00";

const CHECKER: &str = r#"
def check(artifact):
    return artifact.get("n") == 42
"#;

// -- fixtures --------------------------------------------------------------

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
            "cairn-committee-{label}-{unique}-{}",
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).expect("temp dir is creatable");
        TempDir { path }
    }

    fn file(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// One node on the network: a McEliece committee key, an ed25519 identity, and
/// the peer record tying them together.
///
/// The pairing is the whole reason a committee can be drawn from peer records
/// at all — the draw ranks on the transport id, the share is signed by the
/// ed25519 key, and the peer record is what says the two belong to one party.
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

    fn transport(&self) -> String {
        cairn::hex::encode(&self.committee.id())
    }

    fn peer_record(&self, port: u16) -> PeerRecord {
        PeerRecord::new(
            self.identity.submitter_id(),
            self.transport(),
            format!("127.0.0.1:{port}"),
            1,
            COMMIT_AT,
        )
        .signed_with(&self.identity)
    }
}

/// A funded objective, a node, and `COMMITTEE_SIZE + 1` registered peers.
///
/// One more peer than the committee needs, so that "drawn" and "registered" are
/// different sets and a test can tell a real draw from a rule that quietly
/// admits every peer.
fn network(label: &str) -> (TempDir, Node, Objective, Vec<Member>) {
    network_with(label, None)
}

/// The same network, with the objective embargoed for `epochs`.
fn embargoed_network(label: &str, epochs: u64) -> (TempDir, Node, Objective, Vec<Member>) {
    network_with(label, Some(epochs))
}

fn network_with(label: &str, embargo: Option<u64>) -> (TempDir, Node, Objective, Vec<Member>) {
    let dir = TempDir::new(label);
    fs::write(dir.file("c.py"), CHECKER).expect("pinned checker is writable");
    let mut hasher = Sha256::new();
    hasher.update(CHECKER.as_bytes());
    let sha = cairn::hex::encode(&hasher.finalize());

    let ledger = Ledger::open(dir.file("log.jsonl")).expect("a missing file is an empty log");
    let mut node = Node::with_registry(
        ledger,
        VerifierRegistry::new(&dir.path).with_lean_binary(NO_LEAN),
    );

    let objective = Objective::new(
        "G",
        "find n = 42",
        Value::object([
            ("kind", Value::string("certificate")),
            ("checker", Value::string("c.py")),
            ("checker_sha256", Value::string(sha.as_str())),
            ("entrypoint", Value::string("check")),
        ]),
        1000,
        "treasury",
        COMMIT_AT,
        None,
        None,
    )
    .expect("valid objective");
    let objective = match embargo {
        None => objective,
        Some(epochs) => objective.with_embargo(epochs).expect("embargoed"),
    };
    node.post_objective(&objective, COMMIT_AT).expect("post");

    let members: Vec<Member> = (1..=COMMITTEE_SIZE + 1).map(Member::new).collect();
    for (i, member) in members.iter().enumerate() {
        node.post_peer(&member.peer_record(9000 + i as u16), COMMIT_AT)
            .expect("peer registers");
    }
    (dir, node, objective, members)
}

/// Find the `Member` holding a drawn seat. The draw is over transport ids, so
/// this is the lookup a real member performs on itself.
fn holder<'a>(members: &'a [Member], seat: &CommitteeSeat) -> &'a Member {
    members
        .iter()
        .find(|m| m.transport() == seat.transport)
        .expect("every seat is held by a registered peer")
}

/// Seal a signed claim to the drawn committee and commit it.
///
/// This is the submitter's *entire* participation. Nothing after this line is
/// theirs to do, which is the property the whole file exists to demonstrate.
fn commit_sealed(
    node: &mut Node,
    objective: &Objective,
    members: &[Member],
    submitter: &Identity,
    artifact: Value,
    threshold: u8,
) -> String {
    let seats = node
        .committee_for(epoch_of(COMMIT_AT), node.ledger().len())
        .expect("enough peers are registered");

    // The submitter resolves each seat's McEliece key. On a live network this
    // is a fetch by transport id over `p2p::dht`'s `GetKey`; here the keys are
    // to hand, and the *lookup* is by the same id either way.
    let committee: Vec<CommitteeMember> = seats
        .iter()
        .map(|seat| holder(members, seat).committee.member(seat.seat))
        .collect();

    let claim = Claim::new(
        objective.id(),
        submitter.submitter_id(),
        artifact,
        "nonce-1",
        COMMIT_AT,
        Vec::new(),
    )
    .expect("valid claim")
    .signed_with(submitter);

    let submission = SealedSubmission::seal_claim(
        &claim,
        epoch_of(COMMIT_AT),
        COMMIT_AT,
        &committee,
        threshold,
        &mut OsRng,
    )
    .expect("seals");

    let commitment = Commitment::new(
        objective.id(),
        submitter.submitter_id(),
        submission.commitment.clone(),
        COMMIT_AT,
    )
    .sealed_with(submission.envelope.clone())
    .signed_with(submitter);

    node.commit(&commitment, COMMIT_AT).expect("commit")
}

fn epoch_of(ts: &str) -> u64 {
    let seconds = cairn::time::parse_rfc3339(ts).expect("a well-formed instant");
    cairn::partition::epoch_of(seconds as u64, cairn::partition::EPOCH_SECONDS)
}

/// One member's share of a commitment, signed and ready to post.
fn share_for(
    node: &Node,
    members: &[Member],
    commitment_id: &str,
    seat: &CommitteeSeat,
    ts: &str,
) -> CommitteeShare {
    let member = holder(members, seat);
    let commitment = node
        .commitment_of(commitment_id)
        .expect("the commitment is in the log");
    let envelope = commitment.envelope.as_ref().expect("a sealed commitment");
    let share = member
        .committee
        .open_share(envelope, seat.seat)
        .expect("a member opens its own sealed share");
    CommitteeShare::new(
        commitment_id,
        seat.seat,
        share.index,
        cairn::hex::encode(&share.data),
        ts,
    )
    .signed_with(&member.identity)
}

fn n(value: i128) -> Value {
    Value::object([("n", Value::Int(value))])
}

// -- the draw --------------------------------------------------------------

/// The committee is a pure function of public inputs, so nobody issues an
/// invitation and nobody can decline to send one — the same property
/// `docs/coordination.md` gets for work assignment.
#[test]
fn the_committee_is_drawn_from_the_log_and_anyone_recomputes_it() {
    let (_dir, node, _objective, members) = network("draw");
    let at = node.ledger().len();
    let epoch = epoch_of(COMMIT_AT);

    let once = node.committee_for(epoch, at).expect("draws");
    let twice = node.committee_for(epoch, at).expect("draws again");
    assert_eq!(once, twice, "the draw is a function, not a sample");

    assert_eq!(once.len(), usize::from(COMMITTEE_SIZE));
    let seats: Vec<u8> = once.iter().map(|s| s.seat).collect();
    assert_eq!(seats, (1..=COMMITTEE_SIZE).collect::<Vec<u8>>());

    // Drawn is a strict subset of registered: there are `COMMITTEE_SIZE + 1`
    // peers. Without this the test would pass on a rule that admitted everyone.
    assert_eq!(members.len(), usize::from(COMMITTEE_SIZE) + 1);
    assert!(
        members
            .iter()
            .any(|m| once.iter().all(|s| s.transport != m.transport())),
        "some registered peer must have been left out, or nothing was drawn"
    );

    // A different epoch draws a different committee, which is what stops a
    // fixed set being worth bribing (`docs/censorship.md` §2 on rotation).
    let elsewhere = node.committee_for(epoch + 7, at).expect("draws");
    assert_ne!(
        once.iter().map(|s| &s.transport).collect::<Vec<_>>(),
        elsewhere.iter().map(|s| &s.transport).collect::<Vec<_>>(),
        "the committee must rotate with the epoch"
    );
}

// -- the property the whole design exists for ------------------------------

/// **The submitter commits and is never heard from again.**
///
/// `docs/censorship.md` §1: an adversary who can neither forge nor steal your
/// work takes it by stopping your second action. Here there is no second
/// action — three committee members publish shares, a *bystander* opens the
/// submission, and the claim that lands carries the submitter's own signature.
#[test]
fn a_censored_submitter_is_paid_by_the_committee_alone() {
    let (_dir, mut node, objective, members) = network("censored");
    let submitter = Identity::from_secret_bytes([200u8; 32]);

    let commitment_id = commit_sealed(
        &mut node,
        &objective,
        &members,
        &submitter,
        n(42),
        COMMITTEE_THRESHOLD,
    );

    // --- the submitter is now gone. Nothing below uses `submitter`. ---

    let seats = node
        .committee_of_commitment(&commitment_id)
        .expect("the committee is derivable from the log");

    // Exactly `t` members publish. The other two are offline, which is what
    // `n - t` exists to absorb.
    for seat in seats.iter().take(usize::from(COMMITTEE_THRESHOLD)) {
        let share = share_for(&node, &members, &commitment_id, seat, REVEAL_AT);
        node.post_committee_share(&share, REVEAL_AT)
            .expect("a drawn member publishes its share");
    }

    let pending = node.pending_sealed_reveals(epoch_of(REVEAL_AT));
    assert_eq!(pending.len(), 1);
    assert!(pending[0].openable(), "t shares must be enough");

    // Anyone at all. This call holds no key of the submitter's and takes no
    // input from them.
    let outcome = node
        .open_sealed(&commitment_id, REVEAL_AT)
        .expect("the committee's shares open it");
    assert_eq!(outcome.verdict.status, Status::Accept);

    // And the claim that landed is the submitter's own, signature included --
    // which is what makes it indistinguishable from one they posted themselves.
    let claim = node
        .accepted_claims()
        .into_values()
        .find(|c| c.artifact == n(42))
        .expect("the opened claim is in the log");
    assert_eq!(claim.submitter, submitter.submitter_id());
    claim
        .verify_signature()
        .expect("the submitter's signature survived the envelope");

    // Settlement is deferred to the epoch boundary as always; drain it and the
    // censored submitter is paid.
    node.settle_at(LATER_AT).expect("batch runs");
    assert_eq!(
        node.settlement_for_claim(&claim.id()),
        Some(1000),
        "the submitter collects without ever having revealed"
    );

    assert!(
        node.audit(false).is_empty(),
        "a committee reveal must audit clean: {:?}",
        node.audit(false)
    );
}

// -- the time rule ---------------------------------------------------------

/// A committee that could publish inside the commitment's own epoch would hand
/// the sequencer every artifact while it was still worth front-running.
///
/// The check is a comparison of two timestamps that are both in the log, so a
/// member with a fast clock writes a record every node refuses rather than one
/// every node accepts on their word. **This is the "time is consensus" claim.**
#[test]
fn a_share_published_in_the_commitment_epoch_is_refused() {
    let (_dir, mut node, objective, members) = network("early");
    let submitter = Identity::from_secret_bytes([201u8; 32]);
    let commitment_id = commit_sealed(
        &mut node,
        &objective,
        &members,
        &submitter,
        n(42),
        COMMITTEE_THRESHOLD,
    );
    let seats = node
        .committee_of_commitment(&commitment_id)
        .expect("committee");

    // Same epoch as the commitment: refused.
    let early = share_for(&node, &members, &commitment_id, &seats[0], COMMIT_AT);
    let error = node
        .post_committee_share(&early, COMMIT_AT)
        .expect_err("a share may not open an epoch that is still running");
    assert!(
        matches!(error, RuleViolation::ShareBeforeEpoch { .. }),
        "got {error:?}"
    );

    // The identical share, one epoch later: admitted. Nothing about the record
    // changed except the epoch it names, which is the point.
    let in_time = share_for(&node, &members, &commitment_id, &seats[0], REVEAL_AT);
    node.post_committee_share(&in_time, REVEAL_AT)
        .expect("the same member, an epoch later");
}

// -- who may publish -------------------------------------------------------

/// A Shamir share is not individually checkable, so anyone able to publish for
/// any seat could stall every reveal by filling seats with noise. The draw says
/// which identity holds a seat; the signature says which identity wrote the
/// record; they must agree.
#[test]
fn only_the_drawn_identity_can_publish_its_seat() {
    let (_dir, mut node, objective, members) = network("impostor");
    let submitter = Identity::from_secret_bytes([202u8; 32]);
    let commitment_id = commit_sealed(
        &mut node,
        &objective,
        &members,
        &submitter,
        n(42),
        COMMITTEE_THRESHOLD,
    );
    let seats = node
        .committee_of_commitment(&commitment_id)
        .expect("committee");

    // Seat 1's real share, re-signed by seat 2's holder.
    let real = share_for(&node, &members, &commitment_id, &seats[0], REVEAL_AT);
    let thief = holder(&members, &seats[1]);
    let stolen = CommitteeShare::new(
        &real.commitment,
        real.seat,
        real.x,
        real.share.clone(),
        REVEAL_AT,
    )
    .signed_with(&thief.identity);

    let error = node
        .post_committee_share(&stolen, REVEAL_AT)
        .expect_err("a seat is answered by its holder");
    assert!(
        matches!(error, RuleViolation::SeatImpostor { .. }),
        "got {error:?}"
    );

    // And a seat that was never drawn does not exist to be answered.
    let phantom = CommitteeShare::new(
        &real.commitment,
        COMMITTEE_SIZE + 9,
        real.x,
        real.share.clone(),
        REVEAL_AT,
    )
    .signed_with(&thief.identity);
    let error = node
        .post_committee_share(&phantom, REVEAL_AT)
        .expect_err("no such seat");
    assert!(
        matches!(error, RuleViolation::UnknownSeat { .. }),
        "got {error:?}"
    );

    // A second share for a seat that already published is refused too: one
    // seat, one share, or a member could search for a subset that opens.
    let first = share_for(&node, &members, &commitment_id, &seats[0], REVEAL_AT);
    node.post_committee_share(&first, REVEAL_AT).expect("first");
    let again = CommitteeShare::new(&real.commitment, real.seat, real.x, "00", REVEAL_AT)
        .signed_with(&holder(&members, &seats[0]).identity);
    let error = node
        .post_committee_share(&again, REVEAL_AT)
        .expect_err("one seat, one share");
    assert!(
        matches!(error, RuleViolation::SeatAlreadyPublished { .. }),
        "got {error:?}"
    );
}

/// The registered peer the draw left out holds no seat, so it has nothing to
/// publish — which is what makes the committee a *subset* rather than a label.
#[test]
fn a_peer_outside_the_committee_has_no_seat_to_publish() {
    let (_dir, mut node, objective, members) = network("outsider");
    let submitter = Identity::from_secret_bytes([203u8; 32]);
    let commitment_id = commit_sealed(
        &mut node,
        &objective,
        &members,
        &submitter,
        n(42),
        COMMITTEE_THRESHOLD,
    );
    let seats = node
        .committee_of_commitment(&commitment_id)
        .expect("committee");

    let outsider = members
        .iter()
        .find(|m| seats.iter().all(|s| s.transport != m.transport()))
        .expect("one peer was left out of the draw");

    // It can write a record naming any seat; every one of them is refused,
    // because the draw put another identity there.
    for seat in &seats {
        let record = CommitteeShare::new(&commitment_id, seat.seat, 1, "abcd", REVEAL_AT)
            .signed_with(&outsider.identity);
        let error = node
            .post_committee_share(&record, REVEAL_AT)
            .expect_err("an outsider holds no seat");
        assert!(
            matches!(error, RuleViolation::SeatImpostor { .. }),
            "seat {} gave {error:?}",
            seat.seat
        );
    }
}

// -- liveness under a dishonest member -------------------------------------

/// A member who publishes a share that is not theirs cannot stall the reveal.
///
/// Shamir cannot say *which* share was wrong — the AEAD tag reports only that
/// the set was — and verifiable secret sharing, which would attribute it, needs
/// a group where discrete log is hard and is therefore unavailable to a
/// post-quantum scheme. So the answer is a bounded subset search: with four
/// shares published and one of them a lie, some three of them still open it.
#[test]
fn a_member_who_publishes_garbage_does_not_stop_the_reveal() {
    let (_dir, mut node, objective, members) = network("liar");
    let submitter = Identity::from_secret_bytes([204u8; 32]);
    let commitment_id = commit_sealed(
        &mut node,
        &objective,
        &members,
        &submitter,
        n(42),
        COMMITTEE_THRESHOLD,
    );
    let seats = node
        .committee_of_commitment(&commitment_id)
        .expect("committee");

    // Seat 1 lies: a well-formed share of the right length that is not its own.
    let real = share_for(&node, &members, &commitment_id, &seats[0], REVEAL_AT);
    let mut bytes = cairn::hex::encode(&[0xa5u8; 32]);
    bytes.truncate(real.share.len());
    let lie = CommitteeShare::new(&commitment_id, seats[0].seat, real.x, bytes, REVEAL_AT)
        .signed_with(&holder(&members, &seats[0]).identity);
    node.post_committee_share(&lie, REVEAL_AT)
        .expect("nothing about a single share is checkable, so it is admitted");

    // Three honest members publish.
    for seat in seats.iter().skip(1).take(usize::from(COMMITTEE_THRESHOLD)) {
        let share = share_for(&node, &members, &commitment_id, seat, REVEAL_AT);
        node.post_committee_share(&share, REVEAL_AT)
            .expect("honest member publishes");
    }

    let outcome = node
        .open_sealed(&commitment_id, REVEAL_AT)
        .expect("some honest subset opens it");
    assert_eq!(outcome.verdict.status, Status::Accept);
}

/// With only the liar and two honest members, no subset of three opens it, and
/// the failure says so rather than naming a culprit it cannot identify.
#[test]
fn a_share_set_with_no_working_subset_fails_without_accusing_anyone() {
    let (_dir, mut node, objective, members) = network("no-subset");
    let submitter = Identity::from_secret_bytes([205u8; 32]);
    let commitment_id = commit_sealed(
        &mut node,
        &objective,
        &members,
        &submitter,
        n(42),
        COMMITTEE_THRESHOLD,
    );
    let seats = node
        .committee_of_commitment(&commitment_id)
        .expect("committee");

    let real = share_for(&node, &members, &commitment_id, &seats[0], REVEAL_AT);
    let mut bytes = cairn::hex::encode(&[0x5au8; 32]);
    bytes.truncate(real.share.len());
    let lie = CommitteeShare::new(&commitment_id, seats[0].seat, real.x, bytes, REVEAL_AT)
        .signed_with(&holder(&members, &seats[0]).identity);
    node.post_committee_share(&lie, REVEAL_AT)
        .expect("admitted");
    for seat in seats.iter().skip(1).take(2) {
        let share = share_for(&node, &members, &commitment_id, seat, REVEAL_AT);
        node.post_committee_share(&share, REVEAL_AT)
            .expect("honest");
    }

    let error = node
        .open_sealed(&commitment_id, REVEAL_AT)
        .expect_err("two honest shares are one short");
    assert!(
        matches!(error, RuleViolation::SealedOpenFailed { tried: 3, .. }),
        "got {error:?}"
    );
}

/// Below the threshold the content key is information-theoretically hidden, so
/// there is nothing to try and the failure is "not yet" rather than "never".
#[test]
fn below_threshold_the_submission_stays_sealed() {
    let (_dir, mut node, objective, members) = network("below");
    let submitter = Identity::from_secret_bytes([206u8; 32]);
    let commitment_id = commit_sealed(
        &mut node,
        &objective,
        &members,
        &submitter,
        n(42),
        COMMITTEE_THRESHOLD,
    );
    let seats = node
        .committee_of_commitment(&commitment_id)
        .expect("committee");

    for seat in seats.iter().take(usize::from(COMMITTEE_THRESHOLD) - 1) {
        let share = share_for(&node, &members, &commitment_id, seat, REVEAL_AT);
        node.post_committee_share(&share, REVEAL_AT).expect("share");
    }

    let error = node
        .open_sealed(&commitment_id, REVEAL_AT)
        .expect_err("t-1 shares open nothing");
    assert!(
        matches!(
            error,
            RuleViolation::NotEnoughShares {
                have: 2,
                need: 3,
                ..
            }
        ),
        "got {error:?}"
    );

    let pending = node.pending_sealed_reveals(epoch_of(REVEAL_AT));
    assert!(!pending[0].openable());
    assert_eq!(pending[0].published, vec![seats[0].seat, seats[1].seat]);
}

// -- the parameters are the network's --------------------------------------

/// `threshold` travels inside the envelope, where the submitter writes it. A
/// submission sealed at one-of-five is one every drawn member can open alone
/// the moment the epoch turns, which is front-running restored through a field
/// the front-runner never had to touch.
#[test]
fn a_submitter_cannot_choose_a_weaker_committee() {
    let (_dir, mut node, objective, members) = network("weak");
    let submitter = Identity::from_secret_bytes([207u8; 32]);

    let seats = node
        .committee_for(epoch_of(COMMIT_AT), node.ledger().len())
        .expect("committee");
    let committee: Vec<CommitteeMember> = seats
        .iter()
        .map(|seat| holder(&members, seat).committee.member(seat.seat))
        .collect();

    let claim = Claim::new(
        objective.id(),
        submitter.submitter_id(),
        n(42),
        "nonce-weak",
        COMMIT_AT,
        Vec::new(),
    )
    .expect("valid")
    .signed_with(&submitter);

    let submission = SealedSubmission::seal_claim(
        &claim,
        epoch_of(COMMIT_AT),
        COMMIT_AT,
        &committee,
        1, // one-of-five: any single member reads it early
        &mut OsRng,
    )
    .expect("seals");

    let commitment = Commitment::new(
        objective.id(),
        submitter.submitter_id(),
        submission.commitment.clone(),
        COMMIT_AT,
    )
    .sealed_with(submission.envelope.clone())
    .signed_with(&submitter);

    let error = node
        .commit(&commitment, COMMIT_AT)
        .expect_err("the network's threshold is not the submitter's to lower");
    assert!(
        matches!(
            error,
            RuleViolation::WrongCommitteeShape { threshold: 1, .. }
        ),
        "got {error:?}"
    );
}

// -- the reader-side counterpart -------------------------------------------

/// An admission rule with no reader-side counterpart binds only the people who
/// use this tool to write, and a log can be assembled by concatenation. So a
/// share that `post_committee_share` would have refused must show up in the
/// audit when it reaches the log another way.
#[test]
fn the_audit_reports_a_share_that_should_never_have_been_admitted() {
    let (dir, mut node, objective, members) = network("audit");
    let submitter = Identity::from_secret_bytes([208u8; 32]);
    let commitment_id = commit_sealed(
        &mut node,
        &objective,
        &members,
        &submitter,
        n(42),
        COMMITTEE_THRESHOLD,
    );
    let seats = node
        .committee_of_commitment(&commitment_id)
        .expect("committee");
    assert!(node.audit(false).is_empty(), "clean before the tampering");

    // Append the record the way concatenating two logs would: straight into the
    // file, with none of `post_committee_share`'s checks having run. The seat
    // belongs to someone else.
    let real = share_for(&node, &members, &commitment_id, &seats[0], REVEAL_AT);
    let forged = CommitteeShare::new(
        &commitment_id,
        seats[0].seat,
        real.x,
        real.share.clone(),
        REVEAL_AT,
    )
    .signed_with(&holder(&members, &seats[1]).identity);
    node.ledger_mut()
        .append("committee_share", forged.to_value(), REVEAL_AT)
        .expect("the ledger itself enforces no rules; that is this module's job");

    let problems = node.audit(false);
    assert!(
        problems
            .iter()
            .any(|p| p.contains("committee_share") && p.contains("belongs to another identity")),
        "the audit must name it: {problems:?}"
    );

    // And a reader reaches the same answer as an appender: the bad record is
    // not counted toward the threshold either.
    assert!(
        node.committee_shares_for(&commitment_id).is_empty(),
        "a share that does not check is not a share"
    );
    drop(dir);
}

// -- the embargo -----------------------------------------------------------

/// An embargo is the time rule with a longer arm, and this is what makes the
/// class more than a label.
///
/// `Confidentiality::Embargoed` said *when* an artifact becomes public and
/// nothing consulted it: a committee that felt like opening early could, and
/// the funder who chose the class for a dual-use result would find out
/// afterwards. A committee share is what opens a sealed artifact, so the wait
/// is enforceable in exactly one place — here — and it is two integers an
/// auditor re-reads out of the log rather than a policy anyone is trusted to
/// apply.
#[test]
fn an_embargoed_artifact_stays_shut_until_its_epochs_have_passed() {
    // Three epochs. The share that would have been in time on a public
    // objective is now early, and the identical record three epochs later is
    // admitted.
    let (_dir, mut node, objective, members) = embargoed_network("embargo", 3);
    assert_eq!(objective.embargo(), 3);

    let submitter = Identity::from_secret_bytes([211u8; 32]);
    let commitment_id = commit_sealed(
        &mut node,
        &objective,
        &members,
        &submitter,
        n(42),
        COMMITTEE_THRESHOLD,
    );
    let seats = node
        .committee_of_commitment(&commitment_id)
        .expect("committee");

    // One epoch on: in time for a public objective, early for this one.
    let early = share_for(&node, &members, &commitment_id, &seats[0], REVEAL_AT);
    let error = node
        .post_committee_share(&early, REVEAL_AT)
        .expect_err("the embargo has not lifted");
    assert!(
        matches!(error, RuleViolation::ShareBeforeEpoch { .. }),
        "got {error:?}"
    );

    // Four epochs on -- past the commitment's epoch plus three -- and the same
    // member's share is admitted. Nothing about the record changed except the
    // epoch it names.
    const AFTER_EMBARGO: &str = "2026-07-28T01:20:00+00:00";
    assert!(
        epoch_of(AFTER_EMBARGO) > epoch_of(COMMIT_AT) + 3,
        "the fixture must actually clear the embargo"
    );
    let in_time = share_for(&node, &members, &commitment_id, &seats[0], AFTER_EMBARGO);
    node.post_committee_share(&in_time, AFTER_EMBARGO)
        .expect("the same member, past the embargo");
    assert!(
        node.audit(false).is_empty(),
        "an embargoed reveal must audit clean: {:?}",
        node.audit(false)
    );
}

/// The length is inside the objective's id, so it cannot be shortened after
/// work has started.
///
/// That is the whole reason it is a field on the objective rather than a
/// setting on the node: an embargo a funder could edit is a promise made to
/// the submitter and then taken back, and a submitter deciding whether to
/// disclose through this network is deciding on the strength of that promise.
#[test]
fn shortening_an_embargo_makes_a_different_objective() {
    let three = objective_embargoed_for(3);
    let one = objective_embargoed_for(1);
    assert_ne!(three.id(), one.id());

    // And a length on an objective that is not embargoed is refused rather
    // than ignored: a funder who thinks they asked for delay and did not is
    // the failure they cannot see.
    let public = cairn::records::Objective::new(
        "G",
        "public",
        Value::object([("kind", Value::string("certificate"))]),
        1,
        "treasury",
        COMMIT_AT,
        None,
        None,
    )
    .expect("valid");
    assert!(public.with_embargo_epochs(3).is_err());

    // An embargo of zero epochs is `public` wearing a longer name.
    let zero = cairn::records::Objective::new(
        "G",
        "zero",
        Value::object([("kind", Value::string("certificate"))]),
        1,
        "treasury",
        COMMIT_AT,
        None,
        None,
    )
    .expect("valid");
    assert!(zero.with_embargo(0).is_err());
}

fn objective_embargoed_for(epochs: u64) -> cairn::records::Objective {
    cairn::records::Objective::new(
        "G",
        "dual use",
        Value::object([("kind", Value::string("certificate"))]),
        1,
        "treasury",
        COMMIT_AT,
        None,
        None,
    )
    .expect("valid")
    .with_embargo(epochs)
    .expect("embargoed")
}
