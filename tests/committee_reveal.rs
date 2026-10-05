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

use std::collections::BTreeMap;

use cairn::canonical::Value;
use cairn::crypto::envelope::{CommitteeKey, DealerSecret};
use cairn::crypto::identity::Identity;
use cairn::crypto::CommitteeMember;
use cairn::ledger::Ledger;
use cairn::node::{CommitteeSeat, Node, RuleViolation};
use cairn::partition::{COMMITTEE_SIZE, COMMITTEE_THRESHOLD};
use cairn::records::{
    Claim, Commitment, CommitteeShare, Objective, PeerRecord, ShareAnswer, ShareComplaint,
};
use cairn::sealed::SealedSubmission;
use cairn::verifiers::{Status, VerifierRegistry};

/// A Lean binary guaranteed absent, so no verdict here depends on a toolchain.
const NO_LEAN: &str = "cairn-committee-definitely-no-such-lean-binary";

/// Epoch boundaries. `EPOCH_SECONDS` is 600, so these are three whole epochs
/// apart and every "strictly later" rule below is unambiguous.
const COMMIT_AT: &str = "2026-07-28T00:00:00+00:00";
/// The epoch after the commitment's: still inside the complaint window.
const NEXT_AT: &str = "2026-07-28T00:10:00+00:00";
const REVEAL_AT: &str = "2026-07-28T00:20:00+00:00";
/// The first epoch past the answer window.
const ANSWERS_CLOSED_AT: &str = "2026-07-28T00:30:00+00:00";
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
            // McEliece alone, as `commit --sealed` seals to: the bundle a seat
            // publishes in the field. The three-suite combiner has its own
            // tests in `crypto`.
            committee: CommitteeKey::generate_over(
                &[cairn::crypto::kem::Suite::McEliece],
                &mut OsRng,
            ),
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
    commit_sealed_with(
        node,
        objective,
        members,
        submitter,
        artifact,
        threshold,
        |envelope| envelope,
    )
}

/// [`commit_sealed`], with the envelope's encoded form rewritten before the
/// commitment carries it: what a dishonest submitter controls.
fn commit_sealed_with(
    node: &mut Node,
    objective: &Objective,
    members: &[Member],
    submitter: &Identity,
    artifact: Value,
    threshold: u8,
    rewrite: impl FnOnce(Value) -> Value,
) -> String {
    let (commitment, _dealer, _claim) = seal_commitment(
        node, objective, members, submitter, artifact, threshold, rewrite,
    );
    node.commit(&commitment, COMMIT_AT).expect("commit")
}

/// [`commit_sealed_with`], keeping what the dealer needs to answer a
/// complaint.
fn commit_sealed_dealing(
    node: &mut Node,
    objective: &Objective,
    members: &[Member],
    submitter: &Identity,
    rewrite: impl FnOnce(Value) -> Value,
) -> (String, DealerSecret, Claim) {
    let (commitment, dealer, claim) = seal_commitment(
        node,
        objective,
        members,
        submitter,
        n(42),
        COMMITTEE_THRESHOLD,
        rewrite,
    );
    (
        node.commit(&commitment, COMMIT_AT).expect("commit"),
        dealer,
        claim,
    )
}

/// The commitment a submitter would post, with the dealer's secret and the
/// signed claim it seals -- not yet committed.
fn seal_commitment(
    node: &Node,
    objective: &Objective,
    members: &[Member],
    submitter: &Identity,
    artifact: Value,
    threshold: u8,
    rewrite: impl FnOnce(Value) -> Value,
) -> (Commitment, DealerSecret, Claim) {
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

    let (submission, dealer) = SealedSubmission::seal_claim_dealing(
        &claim,
        epoch_of(COMMIT_AT),
        COMMIT_AT,
        &committee,
        threshold,
        &mut OsRng,
    )
    .expect("seals");

    let envelope = cairn::crypto::envelope::SealedEnvelope::from_value(&rewrite(
        submission.envelope.to_value(),
    ))
    .expect("the rewritten envelope still has its shape");
    let commitment = Commitment::new(
        objective.id(),
        submitter.submitter_id(),
        submission.commitment.clone(),
        COMMIT_AT,
    )
    .sealed_with(envelope)
    .signed_with(submitter);
    (commitment, dealer, claim)
}

/// Flip a byte of the sealed share addressed to `seat`: the dealer sealing
/// that seat something that is not its share.
fn garble_seat(envelope: Value, seat: u8) -> Value {
    let mut map = envelope.as_object().expect("an object").clone();
    let shares = map
        .get("sealed_shares")
        .and_then(Value::as_array)
        .expect("sealed shares")
        .iter()
        .map(|share| {
            if share.get("index").and_then(Value::as_i128) != Some(i128::from(seat)) {
                return share.clone();
            }
            let mut fields = share.as_object().expect("an object").clone();
            let text = fields
                .get("ciphertext")
                .and_then(Value::as_str)
                .expect("ciphertext")
                .to_string();
            let flipped = if text.starts_with('0') { "1" } else { "0" };
            fields.insert(
                "ciphertext".into(),
                Value::string(format!("{flipped}{}", &text[1..])),
            );
            Value::Object(fields)
        })
        .collect();
    map.insert("sealed_shares".into(), Value::Array(shares));
    Value::Object(map)
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
    let (share, key) = member
        .committee
        .open_share_keyed(envelope, seat.seat)
        .expect("a member opens its own sealed share");
    // With its key, as `post_owed_committee_shares` publishes it, so the share
    // is checkable by anyone.
    CommitteeShare::new(
        commitment_id,
        seat.seat,
        share.index,
        cairn::hex::encode(&share.data),
        ts,
    )
    .with_share_key(&key)
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

    // The draw varies with the epoch, which is what stops a fixed set being
    // worth bribing (`docs/censorship.md` §2 on rotation).  Two pseudorandom
    // draws may legitimately select the same ordered 5-of-6 committee, so a
    // single chosen epoch is a probabilistic assertion.  A committee that is
    // actually fixed cannot survive this bounded sweep.
    let first: Vec<_> = once.iter().map(|seat| &seat.transport).collect();
    let rotates = (1..=64).any(|offset| {
        let elsewhere = node.committee_for(epoch + offset, at).expect("draws");
        elsewhere
            .iter()
            .map(|seat| &seat.transport)
            .collect::<Vec<_>>()
            != first
    });
    assert!(rotates, "the committee stayed fixed across 64 epochs");
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

/// A committee member cannot sign a share for one epoch and have a sequencer
/// admit it in another. Otherwise the signed bytes and the log disagree about
/// when an embargo lifted, and replaying peers can reach opposite verdicts.
#[test]
fn a_committee_share_cannot_be_backdated_across_an_epoch() {
    let (_dir, mut node, objective, members) = network("backdated-share");
    let submitter = Identity::from_secret_bytes([212u8; 32]);
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
    let share = share_for(&node, &members, &commitment_id, &seats[0], REVEAL_AT);

    let error = node.post_committee_share(&share, LATER_AT);
    assert!(
        matches!(
            error,
            Err(RuleViolation::RecordEpochMismatch {
                record: "committee_share",
                ..
            })
        ),
        "got {error:?}"
    );
    node.ledger_mut()
        .append("committee_share", share.to_value(), LATER_AT)
        .expect("inject a peer-imported share");
    let problems = node.audit(false);
    assert!(
        problems
            .iter()
            .any(|problem| problem.contains("committee_share declares epoch")),
        "the audit missed a backdated committee share: {problems:?}"
    );
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
    let again = CommitteeShare::new(&real.commitment, real.seat, real.x, real.share, LATER_AT)
        .signed_with(&holder(&members, &seats[0]).identity);
    let error = node
        .post_committee_share(&again, LATER_AT)
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

/// A member who publishes a share that is not theirs is refused at the door.
///
/// The envelope commits to the sharing (`crate::crypto::vss`), so a share is
/// checkable on its own: one that is not on the committed polynomials is not
/// a share, whoever signed it, and it never reaches the reveal to stall it.
#[test]
fn a_member_who_publishes_garbage_is_refused_at_the_door() {
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
    let lie = CommitteeShare::new(
        &commitment_id,
        seats[0].seat,
        real.x,
        cairn::hex::encode(&[0x05u8; 64]),
        REVEAL_AT,
    )
    .signed_with(&holder(&members, &seats[0]).identity);
    let refused = node.post_committee_share(&lie, REVEAL_AT);
    assert!(
        matches!(refused, Err(RuleViolation::ShareFailsCommitments { .. })),
        "{refused:?}"
    );
    // Its real share, published at another seat's abscissa, is refused too.
    let shifted = CommitteeShare::new(
        &commitment_id,
        seats[0].seat,
        real.x + 1,
        real.share.clone(),
        REVEAL_AT,
    )
    .signed_with(&holder(&members, &seats[0]).identity);
    assert!(matches!(
        node.post_committee_share(&shifted, REVEAL_AT),
        Err(RuleViolation::ShareAbscissaNotSeat { .. })
    ));

    // Three honest members publish, and the reveal does not notice the liar.
    for seat in seats.iter().skip(1).take(usize::from(COMMITTEE_THRESHOLD)) {
        let share = share_for(&node, &members, &commitment_id, seat, REVEAL_AT);
        node.post_committee_share(&share, REVEAL_AT)
            .expect("honest member publishes");
    }
    let outcome = node.open_sealed(&commitment_id, REVEAL_AT).expect("opens");
    assert_eq!(outcome.verdict.status, Status::Accept);
    assert!(node.audit(false).is_empty(), "{:?}", node.audit(false));
}

/// A share that carries its key is checked against the sealed share it claims
/// to be, as well as against the commitments, so a liar who also publishes a
/// key -- its own real one, or any other -- is refused at the door.
#[test]
fn a_share_whose_key_does_not_open_its_sealed_share_is_refused() {
    let (_dir, mut node, objective, members) = network("keyed-liar");
    let submitter = Identity::from_secret_bytes([207u8; 32]);
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
    let liar = &holder(&members, &seats[0]).identity;
    let key = real
        .share_key_bytes()
        .expect("the honest record carries a key");

    // The member's real key, with a share that is not the one it opens.
    let mut wrong = real.share.clone();
    wrong.replace_range(0..2, if &wrong[0..2] == "00" { "01" } else { "00" });
    let forged = CommitteeShare::new(&commitment_id, seats[0].seat, real.x, wrong, REVEAL_AT)
        .with_share_key(&key)
        .signed_with(liar);
    let refused = node.post_committee_share(&forged, REVEAL_AT);
    assert!(
        matches!(refused, Err(RuleViolation::ShareKeyDoesNotOpen { .. })),
        "{refused:?}"
    );
    // The right share under a key that is not its key.
    let mut other = key;
    other[0] ^= 1;
    let rekeyed = CommitteeShare::new(
        &commitment_id,
        seats[0].seat,
        real.x,
        real.share.clone(),
        REVEAL_AT,
    )
    .with_share_key(&other)
    .signed_with(liar);
    assert!(matches!(
        node.post_committee_share(&rekeyed, REVEAL_AT),
        Err(RuleViolation::ShareKeyDoesNotOpen { .. })
    ));
    // The right share and key under a relabelled x-coordinate.
    let relabelled = CommitteeShare::new(
        &commitment_id,
        seats[0].seat,
        real.x.wrapping_add(1).max(1),
        real.share.clone(),
        REVEAL_AT,
    )
    .with_share_key(&key)
    .signed_with(liar);
    assert!(matches!(
        node.post_committee_share(&relabelled, REVEAL_AT),
        Err(RuleViolation::ShareKeyDoesNotOpen { .. })
    ));

    // Without a key, garbage is no longer admitted: the commitments check it.
    let unkeyed = CommitteeShare::new(
        &commitment_id,
        seats[0].seat,
        real.x,
        cairn::hex::encode(&[0x05u8; 64]),
        REVEAL_AT,
    )
    .signed_with(liar);
    assert!(matches!(
        node.post_committee_share(&unkeyed, REVEAL_AT),
        Err(RuleViolation::ShareFailsCommitments { .. })
    ));
    for seat in seats.iter().skip(1).take(usize::from(COMMITTEE_THRESHOLD)) {
        let share = share_for(&node, &members, &commitment_id, seat, REVEAL_AT);
        node.post_committee_share(&share, REVEAL_AT)
            .expect("a verified share is admitted");
    }
    let outcome = node
        .open_sealed(&commitment_id, REVEAL_AT)
        .expect("the verified shares open it");
    assert_eq!(outcome.verdict.status, Status::Accept);
    assert!(node.audit(false).is_empty(), "{:?}", node.audit(false));
}

/// With the liar refused and only two honest members published, the reveal
/// is one share short, and says so: there is no subset to search, because
/// every share on the log checks.
#[test]
fn two_checked_shares_of_three_are_reported_as_exactly_that() {
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
    for seat in seats.iter().skip(1).take(2) {
        let share = share_for(&node, &members, &commitment_id, seat, REVEAL_AT);
        node.post_committee_share(&share, REVEAL_AT)
            .expect("honest");
    }
    let error = node
        .open_sealed(&commitment_id, REVEAL_AT)
        .expect_err("two honest shares are one short");
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
}

// -- dealer accountability -------------------------------------------------

/// A seat whose share does not open complains, the dealer answers with that
/// seat's share in the clear, anyone checks it against the envelope, and the
/// reveal goes ahead with it counted -- in the epoch after the commitment,
/// because every seat is then accounted for.
#[test]
fn a_complaint_answered_with_the_seats_share_restores_the_seat() {
    let (_dir, mut node, objective, members) = network("answered");
    let submitter = Identity::from_secret_bytes([210u8; 32]);
    let (commitment_id, dealer, _claim) =
        commit_sealed_dealing(&mut node, &objective, &members, &submitter, |envelope| {
            garble_seat(envelope, 1)
        });
    let seats = node
        .committee_of_commitment(&commitment_id)
        .expect("committee");
    let commit_epoch = epoch_of(COMMIT_AT);

    // The seat's own duty finds the garbage and complains; no other seat does.
    for seat in &seats {
        let member = holder(&members, seat);
        let posted =
            node.post_owed_complaints(&member.committee, &member.identity, commit_epoch, COMMIT_AT);
        if seat.seat == 1 {
            assert_eq!(posted.len(), 1, "{posted:?}");
            assert!(posted[0].1.is_ok(), "{posted:?}");
        } else {
            assert!(
                posted.is_empty(),
                "seat {} complained: {posted:?}",
                seat.seat
            );
        }
    }

    // Every other seat publishes in the next epoch; the reveal waits on the
    // dealer.
    for seat in seats.iter().skip(1) {
        let share = share_for(&node, &members, &commitment_id, seat, NEXT_AT);
        node.post_committee_share(&share, NEXT_AT)
            .expect("publishes");
    }
    let waiting = node
        .open_sealed(&commitment_id, NEXT_AT)
        .expect_err("a complaint is unanswered");
    assert!(
        matches!(waiting, RuleViolation::AwaitingDealerAnswer { ref seats, .. } if seats == &vec![1]),
        "{waiting:?}"
    );

    // The dealer answers from its seed, and the seat counts.
    let dealt = BTreeMap::from([(commitment_id.clone(), dealer)]);
    let answers = node.post_owed_answers(&dealt, epoch_of(NEXT_AT), NEXT_AT);
    assert_eq!(answers.len(), 1, "{answers:?}");
    assert!(answers[0].1.is_ok(), "{answers:?}");
    assert!(
        node.post_owed_answers(&dealt, epoch_of(NEXT_AT), NEXT_AT)
            .is_empty(),
        "answered once"
    );
    let outcome = node
        .open_sealed(&commitment_id, NEXT_AT)
        .expect("every seat is accounted for");
    assert_eq!(outcome.verdict.status, Status::Accept);
    assert!(node.audit(false).is_empty(), "{:?}", node.audit(false));
}

/// A dealer who leaves a complaint unanswered past the window is disqualified:
/// neither the committee nor the submitter can ever reveal the submission, and
/// an answer that does not check, or comes late, changes nothing.
#[test]
fn a_dealer_who_does_not_answer_is_disqualified_for_good() {
    let (_dir, mut node, objective, members) = network("disqualified");
    let submitter = Identity::from_secret_bytes([211u8; 32]);
    let (commitment_id, dealer, claim) =
        commit_sealed_dealing(&mut node, &objective, &members, &submitter, |envelope| {
            garble_seat(envelope, 1)
        });
    let seats = node
        .committee_of_commitment(&commitment_id)
        .expect("committee");
    let first = holder(&members, &seats[0]);
    let complaint = ShareComplaint::new(&commitment_id, 1, COMMIT_AT).signed_with(&first.identity);
    node.post_share_complaint(&complaint, COMMIT_AT)
        .expect("the seat complains");

    // An answer that is not the seat's share is refused; so is one for a seat
    // nobody complained about, even though it is a real share.
    let bogus = ShareAnswer::new(&commitment_id, 1, &[0x07u8; 64], NEXT_AT);
    assert!(matches!(
        node.post_share_answer(&bogus, NEXT_AT),
        Err(RuleViolation::ShareFailsCommitments { .. })
    ));
    let unasked = dealer.share(2).expect("seat 2");
    let unasked = ShareAnswer::new(&commitment_id, 2, &unasked.data, NEXT_AT);
    assert!(matches!(
        node.post_share_answer(&unasked, NEXT_AT),
        Err(RuleViolation::AnswerWithoutComplaint { .. })
    ));

    for seat in seats.iter().skip(1) {
        let share = share_for(&node, &members, &commitment_id, seat, NEXT_AT);
        node.post_committee_share(&share, NEXT_AT)
            .expect("publishes");
    }
    // Inside the answer window: pending.
    assert!(matches!(
        node.open_sealed(&commitment_id, REVEAL_AT),
        Err(RuleViolation::AwaitingDealerAnswer { .. })
    ));
    // Past it: final, on the committee's path and on the submitter's.
    let refused = node
        .open_sealed(&commitment_id, ANSWERS_CLOSED_AT)
        .expect_err("disqualified");
    assert!(
        matches!(refused, RuleViolation::DealerDisqualified { ref seats, .. } if seats == &vec![1]),
        "{refused:?}"
    );
    assert!(matches!(
        node.reveal(&claim, ANSWERS_CLOSED_AT),
        Err(RuleViolation::DealerDisqualified { .. })
    ));
    // The real answer, too late, is refused.
    let late = dealer.share(1).expect("seat 1");
    let late = ShareAnswer::new(&commitment_id, 1, &late.data, ANSWERS_CLOSED_AT);
    assert!(matches!(
        node.post_share_answer(&late, ANSWERS_CLOSED_AT),
        Err(RuleViolation::OutsideDealingWindow { .. })
    ));
    assert!(node.audit(false).is_empty(), "{:?}", node.audit(false));
}

/// The reveal gate is a reader's rule too: a claim written past an unanswered
/// complaint -- by a tool that skipped the rule, or by hand -- is reported by
/// the audit, because it pays a dealer who kept the choice of whether to open.
#[test]
fn the_audit_reports_a_claim_revealed_past_an_unanswered_complaint() {
    let (dir, mut node, objective, members) = network("gate-audit");
    let submitter = Identity::from_secret_bytes([215u8; 32]);
    let (commitment_id, _dealer, claim) =
        commit_sealed_dealing(&mut node, &objective, &members, &submitter, |envelope| {
            garble_seat(envelope, 1)
        });
    let seats = node
        .committee_of_commitment(&commitment_id)
        .expect("committee");
    let complaint = ShareComplaint::new(&commitment_id, 1, COMMIT_AT)
        .signed_with(&holder(&members, &seats[0]).identity);
    node.post_share_complaint(&complaint, COMMIT_AT)
        .expect("the seat complains");
    assert!(node.audit(false).is_empty(), "{:?}", node.audit(false));
    drop(node);

    // Appended beneath the rules engine, as a log assembled elsewhere might be.
    let mut ledger = Ledger::open(dir.file("log.jsonl")).expect("reopen");
    ledger
        .append("claim", claim.to_value(), ANSWERS_CLOSED_AT)
        .expect("raw append");
    let node = Node::with_registry(
        ledger,
        VerifierRegistry::new(&dir.path).with_lean_binary(NO_LEAN),
    );
    let problems = node.audit(false);
    assert!(
        problems.iter().any(
            |problem| problem.starts_with("claim at entry") && problem.contains("disqualified")
        ),
        "{problems:?}"
    );
}

/// Only a seat's holder complains for it, inside its window, once, and only
/// while its share is not already on the log. A false complaint costs an
/// honest dealer one answer.
#[test]
fn only_a_seat_complains_for_itself_inside_its_window() {
    let (_dir, mut node, objective, members) = network("complaints");
    let submitter = Identity::from_secret_bytes([212u8; 32]);
    let (commitment_id, dealer, _claim) =
        commit_sealed_dealing(&mut node, &objective, &members, &submitter, |envelope| {
            envelope
        });
    let seats = node
        .committee_of_commitment(&commitment_id)
        .expect("committee");
    let first = holder(&members, &seats[0]);
    let second = holder(&members, &seats[1]);

    let impostor = ShareComplaint::new(&commitment_id, 1, COMMIT_AT).signed_with(&second.identity);
    assert!(matches!(
        node.post_share_complaint(&impostor, COMMIT_AT),
        Err(RuleViolation::SeatImpostor { .. })
    ));
    let unsigned = ShareComplaint::new(&commitment_id, 1, COMMIT_AT);
    assert!(node.post_share_complaint(&unsigned, COMMIT_AT).is_err());
    let late = ShareComplaint::new(&commitment_id, 1, REVEAL_AT).signed_with(&first.identity);
    assert!(matches!(
        node.post_share_complaint(&late, REVEAL_AT),
        Err(RuleViolation::OutsideDealingWindow { .. })
    ));

    // Seat 1 publishes its share; it has nothing left to complain about.
    let share = share_for(&node, &members, &commitment_id, &seats[0], NEXT_AT);
    node.post_committee_share(&share, NEXT_AT)
        .expect("publishes");
    let moot = ShareComplaint::new(&commitment_id, 1, NEXT_AT).signed_with(&first.identity);
    assert!(matches!(
        node.post_share_complaint(&moot, NEXT_AT),
        Err(RuleViolation::SeatAlreadyAccounted { .. })
    ));

    // Seat 2 complains falsely; once is admitted, twice is not.
    let false_complaint =
        ShareComplaint::new(&commitment_id, 2, COMMIT_AT).signed_with(&second.identity);
    node.post_share_complaint(&false_complaint, COMMIT_AT)
        .expect("admitted: a complaint is not checkable");
    let again = ShareComplaint::new(&commitment_id, 2, NEXT_AT).signed_with(&second.identity);
    assert!(matches!(
        node.post_share_complaint(&again, NEXT_AT),
        Err(RuleViolation::DuplicateDealingRecord { .. })
    ));
    // The honest dealer answers it; a second answer is refused.
    let dealt = BTreeMap::from([(commitment_id.clone(), dealer)]);
    let answers = node.post_owed_answers(&dealt, epoch_of(NEXT_AT), NEXT_AT);
    assert!(
        answers.iter().all(|(_, result)| result.is_ok()),
        "{answers:?}"
    );
    let share = dealt[&commitment_id].share(2).expect("seat 2");
    let twice = ShareAnswer::new(&commitment_id, 2, &share.data, REVEAL_AT);
    assert!(matches!(
        node.post_share_answer(&twice, REVEAL_AT),
        Err(RuleViolation::DuplicateDealingRecord { .. })
    ));
    assert!(node.audit(false).is_empty(), "{:?}", node.audit(false));
}

/// Inside the complaint window a reveal waits until every seat is accounted
/// for, because a seat that has said nothing might still complain. After it,
/// `t` shares are enough.
#[test]
fn a_reveal_waits_for_every_seat_or_for_the_complaint_window() {
    let (_dir, mut node, objective, members) = network("window");
    let submitter = Identity::from_secret_bytes([213u8; 32]);
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
    for seat in seats.iter().take(usize::from(COMMITTEE_THRESHOLD)) {
        let share = share_for(&node, &members, &commitment_id, seat, NEXT_AT);
        node.post_committee_share(&share, NEXT_AT)
            .expect("publishes");
    }
    assert!(matches!(
        node.open_sealed(&commitment_id, NEXT_AT),
        Err(RuleViolation::AwaitingComplaints { .. })
    ));
    let outcome = node
        .open_sealed(&commitment_id, REVEAL_AT)
        .expect("the window has closed");
    assert_eq!(outcome.verdict.status, Status::Accept);
}

/// A sealed commitment must commit to its sharing: an envelope that does not
/// (version 2, plain Shamir) is refused, because nothing in it would let a
/// share be checked or the dealer be held to one.
#[test]
fn a_sealed_commitment_must_commit_to_its_sharing() {
    let (_dir, mut node, objective, members) = network("unverifiable");
    let submitter = Identity::from_secret_bytes([214u8; 32]);
    let (commitment, _dealer, _claim) = seal_commitment(
        &node,
        &objective,
        &members,
        &submitter,
        n(42),
        COMMITTEE_THRESHOLD,
        |envelope| {
            let mut map = envelope.as_object().expect("object").clone();
            map.remove("commitments");
            map.insert("version".into(), Value::Int(2));
            Value::Object(map)
        },
    );
    let refused = node.commit(&commitment, COMMIT_AT);
    assert!(
        matches!(
            refused,
            Err(RuleViolation::UnverifiableEnvelope { version: 2 })
        ),
        "{refused:?}"
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

// -- the running node ------------------------------------------------------

/// What a daemon does each tick, done by hand: every member serves its own
/// seats with `post_owed_committee_shares`, and a bystander opens with
/// `open_due_sealed`. No test-side share construction, so this pins the code a
/// running node runs rather than the records it would write.
#[test]
fn members_serve_their_own_seats_and_anyone_opens() {
    let (_dir, mut node, objective, members) = network("duty");
    let submitter = Identity::from_secret_bytes([201u8; 32]);
    let commitment_id = commit_sealed(
        &mut node,
        &objective,
        &members,
        &submitter,
        n(42),
        COMMITTEE_THRESHOLD,
    );

    // Inside the commitment's own epoch nothing is owed yet.
    for member in &members {
        assert!(node
            .post_owed_committee_shares(
                &member.committee,
                &member.identity,
                epoch_of(COMMIT_AT),
                COMMIT_AT
            )
            .is_empty());
    }

    let mut posted = 0;
    for member in &members {
        for (commitment, result) in node.post_owed_committee_shares(
            &member.committee,
            &member.identity,
            epoch_of(REVEAL_AT),
            REVEAL_AT,
        ) {
            assert_eq!(commitment, commitment_id);
            result.expect("a drawn member's own share is admitted");
            posted += 1;
        }
    }
    assert_eq!(
        posted,
        usize::from(COMMITTEE_SIZE),
        "every seat served, no more"
    );

    // A second pass owes nothing: each seat publishes once.
    for member in &members {
        assert!(node
            .post_owed_committee_shares(
                &member.committee,
                &member.identity,
                epoch_of(REVEAL_AT),
                REVEAL_AT
            )
            .is_empty());
    }

    let opened = node.open_due_sealed(epoch_of(REVEAL_AT), REVEAL_AT, |_, _| false);
    assert_eq!(opened.len(), 1);
    opened[0].2.as_ref().expect("the shares open it");
    assert!(node
        .accepted_claims()
        .into_values()
        .any(|claim| claim.artifact == n(42) && claim.submitter == submitter.submitter_id()));
    assert!(
        node.open_due_sealed(epoch_of(REVEAL_AT), REVEAL_AT, |_, _| false)
            .is_empty(),
        "an opened submission is no longer pending"
    );
}

/// A submitter can seal something to a seat that is not its share. `commit`
/// checks the envelope's shape, not what it sealed, so it is admitted; the seat
/// then has nothing honest to publish. It must say so rather than fall silent,
/// because silence reads exactly like withholding -- and the others still open
/// the submission.
#[test]
fn a_seat_sealed_a_share_it_cannot_open_says_so() {
    let (_dir, mut node, objective, members) = network("framed");
    let submitter = Identity::from_secret_bytes([202u8; 32]);
    let seats = node
        .committee_for(epoch_of(COMMIT_AT), node.ledger().len())
        .expect("enough peers are registered");
    let framed = seats[0].clone();
    let commitment_id = commit_sealed_with(
        &mut node,
        &objective,
        &members,
        &submitter,
        n(43),
        COMMITTEE_THRESHOLD,
        |envelope| {
            let shares: Vec<Value> = envelope
                .get("sealed_shares")
                .and_then(Value::as_array)
                .expect("sealed_shares")
                .iter()
                .map(|share| {
                    if share.get("index").and_then(Value::as_i128) != Some(i128::from(framed.seat))
                    {
                        return share.clone();
                    }
                    let text = share
                        .get("ciphertext")
                        .and_then(Value::as_str)
                        .expect("ciphertext");
                    let mut bytes = cairn::hex::decode(text).expect("hex");
                    bytes[0] ^= 1;
                    let mut map = share.as_object().cloned().expect("an object");
                    map.insert(
                        "ciphertext".to_string(),
                        Value::string(cairn::hex::encode(&bytes)),
                    );
                    Value::Object(map)
                })
                .collect();
            let mut map = envelope.as_object().cloned().expect("an object");
            map.insert("sealed_shares".to_string(), Value::array(shares));
            Value::Object(map)
        },
    );

    let owner = holder(&members, &framed);
    let said = node.post_owed_committee_shares(
        &owner.committee,
        &owner.identity,
        epoch_of(REVEAL_AT),
        REVEAL_AT,
    );
    assert_eq!(said.len(), 1, "{said:?}");
    assert_eq!(said[0].0, commitment_id);
    assert!(
        matches!(
            &said[0].1,
            Err(RuleViolation::ShareWillNotOpen { seat, .. }) if *seat == framed.seat
        ),
        "{said:?}"
    );

    for seat in &seats[1..] {
        let member = holder(&members, seat);
        for (_, result) in node.post_owed_committee_shares(
            &member.committee,
            &member.identity,
            epoch_of(REVEAL_AT),
            REVEAL_AT,
        ) {
            result.expect("an honest seat's share is admitted");
        }
    }
    let opened = node.open_due_sealed(epoch_of(REVEAL_AT), REVEAL_AT, |_, _| false);
    assert_eq!(opened.len(), 1);
    opened[0].2.as_ref().expect("the honest seats open it");
}

/// Shares written on one node open the submission on another. The reason
/// `committee_share` is an exchangeable kind: a share that never left the node
/// that wrote it could only ever be combined there.
#[test]
fn shares_replayed_from_a_peer_open_the_submission_there() {
    let (_dir, mut writer, objective, members) = network("share-writer");
    let submitter = Identity::from_secret_bytes([202u8; 32]);
    let commitment_id = commit_sealed(
        &mut writer,
        &objective,
        &members,
        &submitter,
        n(42),
        COMMITTEE_THRESHOLD,
    );
    for member in &members {
        for (_, result) in writer.post_owed_committee_shares(
            &member.committee,
            &member.identity,
            epoch_of(REVEAL_AT),
            REVEAL_AT,
        ) {
            result.expect("admitted");
        }
    }

    // A second node with the same history up to the commitment: the same
    // objective and peer records, written at the same instants.
    let dir = TempDir::new("share-reader");
    fs::write(dir.file("c.py"), CHECKER).expect("pinned checker is writable");
    let mut reader = Node::with_registry(
        Ledger::open(dir.file("log.jsonl")).expect("empty log"),
        VerifierRegistry::new(&dir.path).with_lean_binary(NO_LEAN),
    );
    reader.post_objective(&objective, COMMIT_AT).expect("post");
    for (i, member) in members.iter().enumerate() {
        reader
            .post_peer(&member.peer_record(9000 + i as u16), COMMIT_AT)
            .expect("peer registers");
    }

    let records: Vec<(String, Value)> = writer
        .ledger()
        .entries()
        .iter()
        .filter(|entry| cairn::p2p::sync::EXCHANGEABLE.contains(&entry.kind.as_str()))
        .filter(|entry| entry.kind != "objective")
        .map(|entry| (entry.kind.clone(), entry.payload.clone()))
        .collect();
    cairn::p2p::service::replay_records(&mut reader, &records);

    assert_eq!(
        reader.committee_shares_for(&commitment_id).len(),
        usize::from(COMMITTEE_SIZE),
        "the shares did not replay"
    );
    let opened = reader.open_due_sealed(epoch_of(REVEAL_AT), REVEAL_AT, |_, _| false);
    assert_eq!(opened.len(), 1);
    opened[0].2.as_ref().expect("replayed shares open it");
}

// -- cross-implementation fixtures -----------------------------------------

/// What `conformance/sealed/` holds: logs written by this implementation that
/// the reference must audit to the same verdicts. A clean log must audit clean
/// in both; a log with one record appended beneath the rules must be flagged
/// at that entry by both.
fn sealed_fixtures() -> Vec<(&'static str, Option<u64>, PathBuf, TempDir)> {
    let mut out = Vec::new();
    let raw = |dir: &TempDir, kind: &str, payload: Value, ts: &str| -> u64 {
        let mut ledger = Ledger::open(dir.file("log.jsonl")).expect("reopen");
        let seq = ledger.len() as u64;
        ledger.append(kind, payload, ts).expect("raw append");
        seq
    };

    // An answered complaint, revealed in the next epoch: clean.
    {
        let (dir, mut node, objective, members) = network("fixture-answered");
        let submitter = Identity::from_secret_bytes([220u8; 32]);
        let (id, dealer, _) =
            commit_sealed_dealing(&mut node, &objective, &members, &submitter, |e| {
                garble_seat(e, 1)
            });
        let seats = node.committee_of_commitment(&id).expect("committee");
        let first = holder(&members, &seats[0]);
        node.post_owed_complaints(
            &first.committee,
            &first.identity,
            epoch_of(COMMIT_AT),
            COMMIT_AT,
        );
        for seat in seats.iter().skip(1) {
            let share = share_for(&node, &members, &id, seat, NEXT_AT);
            node.post_committee_share(&share, NEXT_AT)
                .expect("publishes");
        }
        let dealt = BTreeMap::from([(id.clone(), dealer)]);
        node.post_owed_answers(&dealt, epoch_of(NEXT_AT), NEXT_AT);
        node.open_sealed(&id, NEXT_AT).expect("opens");
        assert!(node.audit(false).is_empty(), "{:?}", node.audit(false));
        drop(node);
        out.push(("answered", None, dir.file("log.jsonl"), dir));
    }
    // Every seat published in the next epoch, revealed then: clean.
    {
        let (dir, mut node, objective, members) = network("fixture-prompt");
        let submitter = Identity::from_secret_bytes([221u8; 32]);
        let id = commit_sealed(
            &mut node,
            &objective,
            &members,
            &submitter,
            n(42),
            COMMITTEE_THRESHOLD,
        );
        let seats = node.committee_of_commitment(&id).expect("committee");
        for seat in &seats {
            let share = share_for(&node, &members, &id, seat, NEXT_AT);
            node.post_committee_share(&share, NEXT_AT)
                .expect("publishes");
        }
        node.open_sealed(&id, NEXT_AT).expect("opens");
        drop(node);
        out.push(("prompt", None, dir.file("log.jsonl"), dir));
    }
    // A claim revealed past an unanswered complaint.
    {
        let (dir, mut node, objective, members) = network("fixture-disqualified");
        let submitter = Identity::from_secret_bytes([222u8; 32]);
        let (id, _, claim) =
            commit_sealed_dealing(&mut node, &objective, &members, &submitter, |e| {
                garble_seat(e, 1)
            });
        let seats = node.committee_of_commitment(&id).expect("committee");
        let complaint = ShareComplaint::new(&id, 1, COMMIT_AT)
            .signed_with(&holder(&members, &seats[0]).identity);
        node.post_share_complaint(&complaint, COMMIT_AT)
            .expect("complains");
        drop(node);
        let at = raw(&dir, "claim", claim.to_value(), ANSWERS_CLOSED_AT);
        out.push(("disqualified", Some(at), dir.file("log.jsonl"), dir));
    }
    // A claim revealed inside the complaint window with seats unaccounted.
    {
        let (dir, mut node, objective, members) = network("fixture-early");
        let submitter = Identity::from_secret_bytes([223u8; 32]);
        let (id, _, claim) =
            commit_sealed_dealing(&mut node, &objective, &members, &submitter, |e| e);
        let seats = node.committee_of_commitment(&id).expect("committee");
        for seat in seats.iter().take(usize::from(COMMITTEE_THRESHOLD)) {
            let share = share_for(&node, &members, &id, seat, NEXT_AT);
            node.post_committee_share(&share, NEXT_AT)
                .expect("publishes");
        }
        drop(node);
        let at = raw(&dir, "claim", claim.to_value(), NEXT_AT);
        out.push(("early", Some(at), dir.file("log.jsonl"), dir));
    }
    // An answer that is not the seat's share.
    {
        let (dir, mut node, objective, members) = network("fixture-bad-answer");
        let submitter = Identity::from_secret_bytes([224u8; 32]);
        let (id, _, _) = commit_sealed_dealing(&mut node, &objective, &members, &submitter, |e| e);
        let seats = node.committee_of_commitment(&id).expect("committee");
        let complaint = ShareComplaint::new(&id, 2, COMMIT_AT)
            .signed_with(&holder(&members, &seats[1]).identity);
        node.post_share_complaint(&complaint, COMMIT_AT)
            .expect("complains");
        drop(node);
        let answer = ShareAnswer::new(&id, 2, &[0x07u8; 64], NEXT_AT);
        let at = raw(&dir, "share_answer", answer.to_value(), NEXT_AT);
        out.push(("bad-answer", Some(at), dir.file("log.jsonl"), dir));
    }
    // An answer nobody asked for.
    {
        let (dir, node, objective, members) = network("fixture-unasked");
        let submitter = Identity::from_secret_bytes([225u8; 32]);
        let mut node = node;
        let (id, dealer, _) =
            commit_sealed_dealing(&mut node, &objective, &members, &submitter, |e| e);
        drop(node);
        let share = dealer.share(3).expect("seat 3");
        let answer = ShareAnswer::new(&id, 3, &share.data, NEXT_AT);
        let at = raw(&dir, "share_answer", answer.to_value(), NEXT_AT);
        out.push(("unasked-answer", Some(at), dir.file("log.jsonl"), dir));
    }
    // A complaint for a seat its signer does not hold, and one too late.
    for (label, seat_holder, ts) in [
        ("impostor-complaint", 1usize, COMMIT_AT),
        ("late-complaint", 0, REVEAL_AT),
    ] {
        let (dir, mut node, objective, members) = network(&format!("fixture-{label}"));
        let submitter = Identity::from_secret_bytes([226u8; 32]);
        let (id, _, _) = commit_sealed_dealing(&mut node, &objective, &members, &submitter, |e| e);
        let seats = node.committee_of_commitment(&id).expect("committee");
        drop(node);
        let complaint = ShareComplaint::new(&id, 1, ts)
            .signed_with(&holder(&members, &seats[seat_holder]).identity);
        let at = raw(&dir, "share_complaint", complaint.to_value(), ts);
        out.push((label, Some(at), dir.file("log.jsonl"), dir));
    }
    // A committee share that does not check, signed by the seat's holder.
    {
        let (dir, mut node, objective, members) = network("fixture-garbage-share");
        let submitter = Identity::from_secret_bytes([227u8; 32]);
        let id = commit_sealed(
            &mut node,
            &objective,
            &members,
            &submitter,
            n(42),
            COMMITTEE_THRESHOLD,
        );
        let seats = node.committee_of_commitment(&id).expect("committee");
        drop(node);
        let share = CommitteeShare::new(
            &id,
            seats[0].seat,
            seats[0].seat,
            cairn::hex::encode(&[0x05u8; 64]),
            REVEAL_AT,
        )
        .signed_with(&holder(&members, &seats[0]).identity);
        let at = raw(&dir, "committee_share", share.to_value(), REVEAL_AT);
        out.push(("garbage-share", Some(at), dir.file("log.jsonl"), dir));
    }
    // A sealed commitment whose envelope commits to nothing.
    {
        let (dir, node, objective, members) = network("fixture-unverifiable");
        let submitter = Identity::from_secret_bytes([228u8; 32]);
        let (commitment, _, _) = seal_commitment(
            &node,
            &objective,
            &members,
            &submitter,
            n(42),
            COMMITTEE_THRESHOLD,
            |envelope| {
                let mut map = envelope.as_object().expect("object").clone();
                map.remove("commitments");
                map.insert("version".into(), Value::Int(2));
                Value::Object(map)
            },
        );
        drop(node);
        let at = raw(&dir, "commitment", commitment.to_value(), COMMIT_AT);
        out.push(("unverifiable", Some(at), dir.file("log.jsonl"), dir));
    }
    out
}

/// Where the fixtures live.
fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("conformance/sealed")
}

/// Rewrites `conformance/sealed/` when `CAIRN_WRITE_SEALED_FIXTURES` is set.
/// Otherwise does nothing: the fixtures are committed, and regenerating them
/// draws fresh keys and so new bytes.
#[test]
fn write_the_sealed_fixtures_when_asked() {
    if std::env::var_os("CAIRN_WRITE_SEALED_FIXTURES").is_none() {
        return;
    }
    let dir = fixture_dir();
    fs::create_dir_all(&dir).expect("fixture dir");
    let mut manifest = Vec::new();
    for (name, flagged, log, _keep) in sealed_fixtures() {
        let file = format!("{name}.jsonl");
        fs::copy(&log, dir.join(&file)).expect("copy fixture");
        manifest.push(Value::object([
            ("log", Value::string(file)),
            (
                "flagged_entry",
                flagged.map_or(Value::Null, |seq| Value::Int(i128::from(seq))),
            ),
        ]));
    }
    fs::write(
        dir.join("manifest.json"),
        Value::Array(manifest).canonical_string(),
    )
    .expect("manifest");
}

/// This implementation's verdict on every committed fixture: clean where the
/// manifest says clean, flagged at the named entry otherwise. The reference
/// runs the same check over the same files.
#[test]
fn the_sealed_fixtures_audit_as_their_manifest_says() {
    let dir = fixture_dir();
    let Ok(text) = fs::read_to_string(dir.join("manifest.json")) else {
        panic!("conformance/sealed/manifest.json is missing; write it with CAIRN_WRITE_SEALED_FIXTURES=1");
    };
    let manifest = Value::from_json(&text).expect("manifest parses");
    let cases = manifest.as_array().expect("an array");
    assert!(cases.len() >= 10, "{} cases", cases.len());
    for case in cases {
        let file = case.get("log").and_then(Value::as_str).expect("log");
        let path = dir.join(file);
        // A missing log opens as an empty one, which audits clean: CI once
        // passed the clean cases that way while the files were gitignored.
        assert!(path.is_file(), "conformance/sealed/{file} is missing");
        let ledger = Ledger::open(path).expect("opens");
        let node = Node::with_registry(
            ledger,
            VerifierRegistry::new(&dir).with_lean_binary(NO_LEAN),
        );
        let problems = node.audit(false);
        match case.get("flagged_entry").and_then(Value::as_i128) {
            None => assert!(problems.is_empty(), "{file}: {problems:?}"),
            Some(seq) => assert!(
                problems
                    .iter()
                    .any(|problem| problem.contains(&format!("entry {seq}:"))),
                "{file}: entry {seq} not flagged in {problems:?}"
            ),
        }
    }
}
