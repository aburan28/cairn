//! The threat model of `docs/censorship.md` §8, executed.
//!
//! Every test here is one adversary from that table, written as a scenario
//! rather than as a unit test, because the property being demonstrated is a
//! claim about *people* — a censor, a sequencer, a competitor, a committee, a
//! state — and not about a function's return value. The unit tests in
//! `src/crypto/*` and `src/sealed.rs` already cover the primitives; what is
//! checked here is that the assembled mechanism delivers the guarantee the
//! design promises:
//!
//! | adversary | goal | test |
//! |---|---|---|
//! | attacker | stop a submitter from revealing | [`submitter_is_censored_after_commit_and_still_gets_paid`] |
//! | `t-1` colluding committee members | early decryption | [`committee_below_threshold_cannot_read_early`] |
//! | sequencer | drop the submissions it dislikes | [`sequencer_cannot_tell_two_sealed_submissions_apart`] |
//! | thief | move somebody else's ciphertext under their own name | [`envelope_replayed_into_another_submission_fails`] |
//! | submitter | seal something other than what they committed to | [`submitter_who_seals_something_other_than_what_they_committed_is_caught`] |
//! | state | identify who worked on a topic | [`pseudonyms_do_not_link_across_objectives`] |
//! | — | (the compatibility obligation) | [`sealing_does_not_change_the_commitment`] |
//! | — | (the guarantee sealing must not weaken) | [`opened_artifact_is_publicly_verifiable`] |
//!
//! Two of these tests deliberately assert a *limit* rather than a defence:
//! `t` colluding members really can read early (§8: "mitigated, not
//! prevented"), and envelope sizes really do leak payload sizes (§4). Tests
//! that only asserted the good news would misrepresent what was built.
//!
//! Everything below goes through the public API only — this is the view a node
//! operator, a committee member, or an auditor has.

use rand_core::{CryptoRng, RngCore};

use proofwork::canonical::Value;
use proofwork::crypto::{
    CommitteeKey, CommitteeMember, EnvelopeError, MasterSeed, SealedEnvelope, Share,
};
use proofwork::records::{Claim, Commitment};
use proofwork::sealed::{open, SealedError, SealedSubmission};
use proofwork::{commitment_hash, obj};

// -- scenario fixtures -----------------------------------------------------

const OBJECTIVE_A: &str = "sha256:36dc4eb23ddd295b12608a6d84e2b03b48d437ce278105f93143215d260bb711";
const OBJECTIVE_B: &str = "sha256:0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";
const CREATED_AT: &str = "2026-07-28T00:00:00+00:00";
const EPOCH: u64 = 12;

/// Distinctive plaintext markers. Uppercase and hyphenated on purpose: the
/// sealed wire form is lowercase hex plus a handful of known field names, so
/// any of these strings appearing anywhere in it is a real leak and not a
/// coincidence of the encoding.
const MARKER_ALPHA: &str = "PLAINTEXT-MARKER-ALPHA";
const MARKER_BETA: &str = "PLAINTEXT-MARKER-BETAX";

/// Deterministic splitmix64, so a failure here reproduces exactly.
///
/// It claims `CryptoRng`, which is a lie — the same lie `shamir::split`'s docs
/// warn about. That is acceptable in a test, where the point is reproducibility,
/// and nowhere else: with a predictable RNG the Shamir coefficients are
/// recoverable and one share reconstructs the content key. No assertion below
/// depends on the *values* this produces, only on the mechanism's behaviour.
struct TestRng(u64);

impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let word = self.next_u64().to_le_bytes();
            for (slot, byte) in chunk.iter_mut().zip(word.iter()) {
                *slot = *byte;
            }
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl CryptoRng for TestRng {}

/// The epoch's threshold committee: `n` members, each holding one X25519 key.
///
/// Modelled as separate keys rather than one object with a master view, because
/// the security argument is precisely that no single party holds enough. Each
/// member below acts with nothing but their own key and the public envelope.
struct Committee {
    keys: Vec<CommitteeKey>,
    members: Vec<CommitteeMember>,
}

impl Committee {
    fn new(size: u8, rng: &mut TestRng) -> Committee {
        let mut keys = Vec::new();
        let mut members = Vec::new();
        for index in 1..=size {
            let key = CommitteeKey::generate(rng);
            members.push(key.member(index));
            keys.push(key);
        }
        Committee { keys, members }
    }

    fn members(&self) -> &[CommitteeMember] {
        &self.members
    }

    /// The epoch boundary: the named members each publish their share.
    ///
    /// A member who does not appear in `indices` is absent — offline, refusing,
    /// or under the same pressure as the submitter. That is the case the
    /// threshold exists to absorb (§2: "`n - t` must be large enough to
    /// tolerate absentees").
    fn publish(&self, envelope: &SealedEnvelope, indices: &[u8]) -> Vec<Share> {
        indices
            .iter()
            .map(|&index| {
                let key = self
                    .keys
                    .get(usize::from(index).saturating_sub(1))
                    .expect("test committee has this member");
                key.open_share(envelope, index)
                    .expect("a member can always open the share addressed to them")
            })
            .collect()
    }
}

fn artifact_with(marker: &str) -> Value {
    obj! {
        "answer" => Value::string(marker),
        "steps" => Value::Int(7),
    }
}

/// Whether `needle` occurs anywhere in `haystack`. Used to search ciphertext
/// bytes directly, in addition to searching the canonical wire text.
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Everything a passive observer of the log can read about a submission.
fn public_view(submission: &SealedSubmission) -> String {
    submission.to_value().canonical_string()
}

/// Assert that no part of the sealed record — wire text or raw ciphertext —
/// carries the plaintext.
fn assert_sealed_against(submission: &SealedSubmission, marker: &str) {
    let wire = public_view(submission);
    assert!(
        !wire.contains(marker),
        "the sealed wire form leaked {marker:?}: {wire}"
    );
    assert!(
        !contains_bytes(submission.envelope.ciphertext(), marker.as_bytes()),
        "the payload ciphertext leaked {marker:?}"
    );
    for share in submission.envelope.sealed_shares() {
        assert!(
            !contains_bytes(share.ciphertext(), marker.as_bytes()),
            "a sealed share leaked {marker:?}"
        );
    }
}

// -- 1. the headline -------------------------------------------------------

/// **The whole point of the mechanism** (`docs/censorship.md` §1 → §2).
///
/// Plain commit–reveal requires the submitter to act twice. An adversary who
/// can neither forge nor steal the work takes it anyway by stopping the second
/// action: a targeted DoS, a network block, a detention, a seized laptop, or a
/// sequencer that drops the reveal until the deadline passes. The commitment
/// sits on the log proving they had the answer first, and they cannot collect.
///
/// So this test does the cruellest thing available to it: it makes the
/// submitter cease to exist immediately after commit, in a way the compiler
/// enforces, and then requires the payout-shaped record to be produced anyway.
#[test]
fn submitter_is_censored_after_commit_and_still_gets_paid() {
    let mut rng = TestRng(0xC0FFEE);
    let committee = Committee::new(5, &mut rng);
    let artifact = artifact_with(MARKER_ALPHA);
    let nonce = "nonce-alpha-01";

    // The submitter exists only inside this block. Everything that leaves it is
    // public log data: a record and a pseudonym id that is already printed on
    // that record.
    let (submission, submitter_id) = {
        let seed = MasterSeed::generate(&mut rng);
        let identity = seed.pseudonym(OBJECTIVE_A);
        let submitter_id = identity.submitter_id();
        let submission = SealedSubmission::seal(
            OBJECTIVE_A,
            &submitter_id,
            &artifact,
            nonce,
            EPOCH,
            CREATED_AT,
            committee.members(),
            3,
            &mut rng,
        )
        .expect("sealing is the submitter's one and only action");
        (submission, submitter_id)
    };
    // ---------------------------------------------------------------------
    // THE SUBMITTER IS GONE. Their `Identity` and `MasterSeed` were dropped at
    // the closing brace above, and their key material zeroized with them.
    // Nothing below this line calls anything on their behalf, and nothing below
    // this line *could*: the values no longer exist and the borrow checker will
    // reject any attempt to add such a call later. Detained, firewalled,
    // laptop seized — from here on it makes no difference which.
    // ---------------------------------------------------------------------

    // Two of the five members are unreachable as well; the censor got to them,
    // or they simply never showed up. Any `t` suffice and order is irrelevant.
    let shares = committee.publish(&submission.envelope, &[2, 4, 5]);
    let opened = open(&submission, &shares).expect("the committee opens it without the submitter");

    assert_eq!(opened.artifact, artifact, "the artifact came back exactly");
    assert_eq!(opened.nonce, nonce, "and so did the nonce that binds it");

    // The check a node performs before moving value: recompute the commitment
    // from what came out of the envelope and compare it to what is on the log.
    // It matches, so this is provably the work committed to at commit time, by
    // this pseudonym, for this objective.
    assert_eq!(
        commitment_hash(OBJECTIVE_A, &submitter_id, &opened.artifact, &opened.nonce),
        submission.commitment,
        "the opened submission reproduces the commitment on the log"
    );

    // And the settlement-shaped record exists, built by a third party from
    // public data alone. The submitter is still gone; they are still paid.
    let claim = Claim::new(
        OBJECTIVE_A,
        submitter_id.clone(),
        opened.artifact.clone(),
        opened.nonce.clone(),
        CREATED_AT,
        Vec::new(),
    )
    .expect("the opened artifact is a well-formed claim");
    assert_eq!(claim.commitment_hash(), submission.commitment);
    assert_eq!(
        claim.submitter, submitter_id,
        "the payout is addressed to the pseudonym that committed, not to whoever opened it"
    );
}

// -- 2. the committee itself -----------------------------------------------

/// `t-1` colluding members learn nothing; `t` of them can read early.
///
/// Both halves matter. The first is the confidentiality guarantee. The second
/// is §8's honest row — "`t` colluding committee members: mitigated, not
/// prevented" — and asserting it here keeps the test suite from implying a
/// protection the design explicitly does not claim. Rotation, diversity and a
/// high threshold raise the cost of that collusion; nothing makes it
/// impossible.
#[test]
fn committee_below_threshold_cannot_read_early() {
    let mut rng = TestRng(0x51DE);
    let committee = Committee::new(6, &mut rng);
    let artifact = artifact_with(MARKER_ALPHA);

    let submission = SealedSubmission::seal(
        OBJECTIVE_A,
        "alice",
        &artifact,
        "nonce-alpha-01",
        EPOCH,
        CREATED_AT,
        committee.members(),
        4, // 4-of-6
        &mut rng,
    )
    .expect("seal succeeds");

    // Three members conspire before the epoch boundary and pool everything they
    // have. Each of them can decrypt the share addressed to them — that much is
    // by design — so they hold three genuine, uncorrupted shares of the content
    // key, plus the entire public record.
    let conspiracy = committee.publish(&submission.envelope, &[1, 3, 6]);
    assert_eq!(conspiracy.len(), 3, "one short of the threshold");

    // Shamir cannot report "too few shares": any three points define some
    // polynomial, and that is the information-theoretic security property
    // rather than a defect. So the sub-threshold set reconstructs a perfectly
    // well-formed *wrong* key, and the AEAD tag is what turns that into a
    // refusal. It is load bearing, not decorative.
    match open(&submission, &conspiracy) {
        Err(SealedError::Envelope(EnvelopeError::Authentication { .. })) => {}
        other => panic!("t-1 colluding members must learn nothing, got {other:?}"),
    }

    // Not even a byte of the plaintext escapes: the failure is total, not
    // partial, and the public record they also hold is opaque.
    assert!(
        submission.envelope.open_with_shares(&conspiracy).is_err(),
        "the raw envelope must not yield a plaintext to a sub-threshold set either"
    );
    assert_sealed_against(&submission, MARKER_ALPHA);

    // Every three-member subset, not just the one above.
    for trio in [[1u8, 2, 3], [2, 4, 6], [3, 5, 6], [1, 5, 6]] {
        let shares = committee.publish(&submission.envelope, &trio);
        assert!(
            open(&submission, &shares).is_err(),
            "subset {trio:?} is below threshold and must not open"
        );
    }

    // The threshold is exactly where it says it is — a boundary, checked from
    // both sides. THIS is §8's unresolved row: four colluding members read the
    // artifact before the epoch boundary and could front-run it. The defence is
    // economic (rotation, diversity, a high `t`), not cryptographic.
    let quorum = committee.publish(&submission.envelope, &[1, 3, 6, 4]);
    assert_eq!(
        open(&submission, &quorum)
            .expect("t colluding members CAN read early")
            .artifact,
        artifact,
        "the design does not claim to stop t colluding members, and this test says so"
    );
}

// -- 3. the sequencer ------------------------------------------------------

/// A sequencer cannot see what it is dropping, so it cannot drop selectively.
///
/// This is §2's third dividend and, per §8, most of the win: forcing an
/// attacker from targeted censorship to indiscriminate censorship, because
/// indiscriminate censorship is detectable by everyone at once. It also kills
/// in-flight front-running — nobody, sequencer included, sees an artifact while
/// they could still act on it.
///
/// The test takes the sequencer's position: it holds both records in full and
/// must find something in them that distinguishes "the submission I want to
/// suppress" from "the submission I am happy to include".
#[test]
fn sequencer_cannot_tell_two_sealed_submissions_apart() {
    let mut rng = TestRng(0x5E9);
    let committee = Committee::new(5, &mut rng);

    // Same objective, same epoch, two different submitters, two different
    // artifacts. Payload sizes are matched deliberately; see the size caveat at
    // the end of this test for what happens when they are not.
    let alpha = SealedSubmission::seal(
        OBJECTIVE_A,
        "alice",
        &artifact_with(MARKER_ALPHA),
        "nonce-alpha-01",
        EPOCH,
        CREATED_AT,
        committee.members(),
        3,
        &mut rng,
    )
    .expect("seal succeeds");
    let beta = SealedSubmission::seal(
        OBJECTIVE_A,
        "bob",
        &artifact_with(MARKER_BETA),
        "nonce-beta-002",
        EPOCH,
        CREATED_AT,
        committee.members(),
        3,
        &mut rng,
    )
    .expect("seal succeeds");

    // Nothing of either plaintext is anywhere in either record.
    assert_sealed_against(&alpha, MARKER_ALPHA);
    assert_sealed_against(&beta, MARKER_BETA);
    let alpha_wire = public_view(&alpha);
    let beta_wire = public_view(&beta);
    assert!(!alpha_wire.contains(MARKER_BETA) && !beta_wire.contains(MARKER_ALPHA));

    // The ciphertexts differ, so neither is a copy of the other...
    assert_ne!(alpha.envelope.ciphertext(), beta.envelope.ciphertext());
    assert_ne!(alpha.id(), beta.id());
    assert_ne!(alpha.commitment, beta.commitment);

    // ...and yet the records are structurally identical: same fields, same
    // objective, same epoch, same threshold, same committee size. Every public
    // field a sequencer could filter on is either shared by both or an
    // unpredictable hash.
    let alpha_value = alpha.to_value();
    let beta_value = beta.to_value();
    let alpha_keys: Vec<&String> = alpha_value
        .as_object()
        .expect("a submission encodes to an object")
        .keys()
        .collect();
    let beta_keys: Vec<&String> = beta_value
        .as_object()
        .expect("a submission encodes to an object")
        .keys()
        .collect();
    assert_eq!(alpha_keys, beta_keys, "the shapes are indistinguishable");
    assert_eq!(alpha.objective_id, beta.objective_id);
    assert_eq!(alpha.epoch, beta.epoch);
    assert_eq!(
        alpha.envelope.threshold(),
        beta.envelope.threshold(),
        "committee parameters are public and identical"
    );
    assert_eq!(
        alpha.envelope.sealed_shares().len(),
        beta.envelope.sealed_shares().len()
    );

    // Two seals of the *same* artifact are also unlinkable: the content key and
    // both nonces are fresh per envelope, so a sequencer cannot even detect a
    // duplicate submission, let alone read one.
    let same_again = SealedSubmission::seal(
        OBJECTIVE_A,
        "alice",
        &artifact_with(MARKER_ALPHA),
        "nonce-alpha-02",
        EPOCH,
        CREATED_AT,
        committee.members(),
        3,
        &mut rng,
    )
    .expect("seal succeeds");
    assert_ne!(
        alpha.envelope.ciphertext(),
        same_again.envelope.ciphertext(),
        "one artifact sealed twice must not produce one ciphertext"
    );
    assert_ne!(alpha.commitment, same_again.commitment);

    // The honest limit (§4). Equal ciphertext lengths above are a consequence
    // of equal payload sizes, not of padding — this library does not pad, and
    // a bigger artifact produces a visibly bigger envelope. Size, count and
    // timing survive encryption; only fixed-size buckets and cover traffic
    // address that, and cover traffic is the mitigation nobody wants to pay
    // for.
    assert_eq!(
        alpha.envelope.ciphertext().len(),
        beta.envelope.ciphertext().len(),
        "equal-size payloads happen to give equal-size envelopes"
    );
    let bulky = SealedSubmission::seal(
        OBJECTIVE_A,
        "carol",
        &obj! { "answer" => Value::string("x".repeat(4096)) },
        "nonce-carol-01",
        EPOCH,
        CREATED_AT,
        committee.members(),
        3,
        &mut rng,
    )
    .expect("seal succeeds");
    assert!(
        bulky.envelope.ciphertext().len() > alpha.envelope.ciphertext().len(),
        "size leaks, as documented in §4; this test states the limit rather than hiding it"
    );
}

// -- 4. the thief ----------------------------------------------------------

/// An envelope is welded to the submission it was sealed for.
///
/// The attack: let someone else do the work, then serve their ciphertext under
/// your own commitment, or your own name, or a different objective, and collect
/// when the committee opens it. The AEAD alone does not stop the first variant
/// — associated data travels *with* the envelope, so a wholesale move still
/// authenticates against its own `aad` — which is why the submission layer
/// compares that `aad` to the commitment instead of trusting the tag.
#[test]
fn envelope_replayed_into_another_submission_fails() {
    let mut rng = TestRng(0x7417F);
    let committee = Committee::new(5, &mut rng);

    let victim = SealedSubmission::seal(
        OBJECTIVE_A,
        "alice",
        &artifact_with(MARKER_ALPHA),
        "nonce-alpha-01",
        EPOCH,
        CREATED_AT,
        committee.members(),
        3,
        &mut rng,
    )
    .expect("seal succeeds");
    let thiefs_own = SealedSubmission::seal(
        OBJECTIVE_A,
        "mallory",
        &artifact_with(MARKER_BETA),
        "nonce-beta-002",
        EPOCH,
        CREATED_AT,
        committee.members(),
        3,
        &mut rng,
    )
    .expect("seal succeeds");

    let shares = committee.publish(&victim.envelope, &[1, 2, 3]);

    // Variant 1: keep your own commitment, serve the victim's ciphertext. The
    // envelope is bound to a commitment that is not this submission's, and the
    // mismatch is caught before any cryptography runs.
    let swapped = SealedSubmission {
        envelope: victim.envelope.clone(),
        ..thiefs_own.clone()
    };
    match open(&swapped, &shares) {
        Err(SealedError::EnvelopeNotBound { .. }) => {}
        other => panic!("a transplanted envelope must not open, got {other:?}"),
    }
    // And it never even reaches a node's memory: decoding refuses it too, so
    // the check is not something a caller can forget to perform.
    match SealedSubmission::from_value(&swapped.to_value()) {
        Err(SealedError::EnvelopeNotBound { .. }) => {}
        other => panic!("the wire boundary must refuse an unbound envelope, got {other:?}"),
    }

    // Variant 2: the thorough theft — copy the victim's commitment *and* their
    // envelope, change only the name on the record. `aad` now matches the
    // commitment, so the binding check passes and the payload decrypts; the
    // commitment is then recomputed over the thief's `submitter` and cannot
    // match. Identity and commitment are the same fact.
    let renamed = SealedSubmission {
        submitter: "mallory".to_string(),
        ..victim.clone()
    };
    match open(&renamed, &shares) {
        Err(SealedError::CommitmentMismatch { .. }) => {}
        other => panic!("a stolen submission must not open under a new name, got {other:?}"),
    }

    // Variant 3: replay the whole thing under a different objective, to collect
    // a second bounty for one piece of work. `objective_id` is inside the
    // commitment, so the same single comparison catches it.
    let relabelled = SealedSubmission {
        objective_id: OBJECTIVE_B.to_string(),
        ..victim.clone()
    };
    match open(&relabelled, &shares) {
        Err(SealedError::CommitmentMismatch { .. }) => {}
        other => panic!("a replayed objective must not open, got {other:?}"),
    }

    // The victim's own submission is untouched by any of this.
    assert_eq!(
        open(&victim, &shares)
            .expect("the genuine submission still opens")
            .artifact,
        artifact_with(MARKER_ALPHA)
    );
}

// -- 5. the lying submitter ------------------------------------------------

/// "The commitment binds the plaintext", from §8's `forge a sealed artifact`
/// row, tested as an actual forgery attempt.
///
/// This is the reason sealing is safe without trusting the submitter, and §2
/// notes that it is free: the commitment was already a hash of the plaintext,
/// so catching a mis-sealed submission costs one SHA-256 at the epoch boundary.
/// Nothing detects the lie earlier — nobody can read the envelope — and nothing
/// needs to.
#[test]
fn submitter_who_seals_something_other_than_what_they_committed_is_caught() {
    let mut rng = TestRng(0x11A5);
    let committee = Committee::new(5, &mut rng);

    let committed_artifact = artifact_with(MARKER_ALPHA); // artifact A: announced
    let sealed_artifact = artifact_with(MARKER_BETA); // artifact B: actually sealed
    let nonce = "nonce-alpha-01";

    // The commitment is over A, and it is a perfectly ordinary commitment: an
    // observer cannot tell it apart from an honest one, because a hash of A
    // looks exactly like a hash of B.
    let commitment = commitment_hash(OBJECTIVE_A, "mallory", &committed_artifact, nonce);

    // ...but the envelope holds B. The payload layout is the documented
    // `{artifact, nonce}` object in canonical form, and the commitment is the
    // associated data, so this forgery is internally consistent: every AEAD tag
    // in it verifies and every share opens.
    let payload = obj! {
        "artifact" => sealed_artifact.clone(),
        "nonce" => Value::string(nonce),
    }
    .canonical_bytes();
    let envelope = SealedEnvelope::seal(&payload, &commitment, committee.members(), 3, &mut rng)
        .expect("a lie seals just as well as the truth");
    let forgery = SealedSubmission {
        objective_id: OBJECTIVE_A.to_string(),
        submitter: "mallory".to_string(),
        commitment,
        envelope,
        epoch: EPOCH,
        created_at: CREATED_AT.to_string(),
    };

    // It passes every structural check a node can make while it is still
    // sealed. This is the point: the log accepts it, and the fraud is invisible
    // until the epoch boundary.
    let decoded = SealedSubmission::from_value(&forgery.to_value())
        .expect("a mis-sealed submission is structurally valid; only opening reveals it");

    let shares = committee.publish(&decoded.envelope, &[1, 2, 3]);
    match open(&decoded, &shares) {
        Err(SealedError::CommitmentMismatch { committed, sealed }) => {
            assert_eq!(
                committed, forgery.commitment,
                "the log's commitment is reported unchanged"
            );
            assert_eq!(
                sealed,
                commitment_hash(OBJECTIVE_A, "mallory", &sealed_artifact, nonce),
                "and it is compared against the commitment the sealed artifact actually implies"
            );
            assert_ne!(committed, sealed);
            // §2: the submission is invalid and the bond is slashable. Note
            // that the failure names the submission, not the committee — the
            // committee did its job perfectly.
        }
        other => {
            panic!("sealing something other than the committed artifact must be caught: {other:?}")
        }
    }

    // The same attack through the nonce instead of the artifact, since the
    // commitment binds both.
    let commitment = commitment_hash(OBJECTIVE_A, "mallory", &committed_artifact, nonce);
    let payload = obj! {
        "artifact" => committed_artifact.clone(),
        "nonce" => Value::string("a-different-nonce"),
    }
    .canonical_bytes();
    let envelope = SealedEnvelope::seal(&payload, &commitment, committee.members(), 3, &mut rng)
        .expect("seal succeeds");
    let nonce_forgery = SealedSubmission {
        objective_id: OBJECTIVE_A.to_string(),
        submitter: "mallory".to_string(),
        commitment,
        envelope,
        epoch: EPOCH,
        created_at: CREATED_AT.to_string(),
    };
    let shares = committee.publish(&nonce_forgery.envelope, &[3, 4, 5]);
    assert!(matches!(
        open(&nonce_forgery, &shares),
        Err(SealedError::CommitmentMismatch { .. })
    ));
}

// -- 6. the state ----------------------------------------------------------

/// Per-objective pseudonyms: §3, layer 1 — the cheap layer that defeats routine
/// analysis.
///
/// An observer asking "who is working on X" gets a fresh key per objective and
/// no way to join the two. The test also pins the two things this does *not*
/// buy, because §3 is explicit that a design claiming both anonymity and
/// mechanical attribution is lying: repeat submissions to one objective share a
/// pseudonym by construction, and the citation graph between pseudonyms is
/// public because it *is* the attribution mechanism.
#[test]
fn pseudonyms_do_not_link_across_objectives() {
    let mut rng = TestRng(0x57A7E);
    let committee = Committee::new(4, &mut rng);

    let seed_bytes = [0x5au8; 32];
    let seed = MasterSeed::from_bytes(seed_bytes);

    let on_a = seed.pseudonym(OBJECTIVE_A).submitter_id();
    let on_b = seed.pseudonym(OBJECTIVE_B).submitter_id();

    // One person, two objectives, two unrelated names.
    assert_ne!(
        on_a, on_b,
        "the same researcher must not carry one name across objectives"
    );

    // Reproducible for its own objective, from the seed alone. This is what
    // makes the scheme usable rather than merely private: a key that was never
    // stored can always be recomputed, so a submitter who backs up one seed can
    // still answer for work they did under a pseudonym they have forgotten.
    assert_eq!(
        seed.pseudonym(OBJECTIVE_A).submitter_id(),
        on_a,
        "a pseudonym is stable for its objective within a session"
    );
    let after_restart = MasterSeed::from_bytes(seed_bytes);
    assert_eq!(
        after_restart.pseudonym(OBJECTIVE_A).submitter_id(),
        on_a,
        "and across a restore from backup"
    );
    assert_eq!(after_restart.pseudonym(OBJECTIVE_B).submitter_id(), on_b);

    // A different seed under the same objective is a different person.
    assert_ne!(
        MasterSeed::from_bytes([0x5bu8; 32])
            .pseudonym(OBJECTIVE_A)
            .submitter_id(),
        on_a
    );

    // On the log, the two submissions share nothing an observer can join on:
    // neither record mentions the other's pseudonym, and neither carries any
    // artifact content.
    let submission_a = SealedSubmission::seal(
        OBJECTIVE_A,
        &on_a,
        &artifact_with(MARKER_ALPHA),
        "nonce-alpha-01",
        EPOCH,
        CREATED_AT,
        committee.members(),
        3,
        &mut rng,
    )
    .expect("seal succeeds");
    let submission_b = SealedSubmission::seal(
        OBJECTIVE_B,
        &on_b,
        &artifact_with(MARKER_BETA),
        "nonce-beta-002",
        EPOCH,
        CREATED_AT,
        committee.members(),
        3,
        &mut rng,
    )
    .expect("seal succeeds");

    let wire_a = public_view(&submission_a);
    let wire_b = public_view(&submission_b);
    assert!(wire_a.contains(&on_a) && !wire_a.contains(&on_b));
    assert!(wire_b.contains(&on_b) && !wire_b.contains(&on_a));
    assert_ne!(submission_a.submitter, submission_b.submitter);
    assert_sealed_against(&submission_a, MARKER_ALPHA);
    assert_sealed_against(&submission_b, MARKER_BETA);

    // The honest half (§3). Two submissions to the *same* objective from the
    // same seed are trivially linked to each other — derivation is
    // deterministic, and that is the price of a pseudonym that can be paid.
    // What is withheld is the link to this seed's activity anywhere else.
    let second_on_a = SealedSubmission::seal(
        OBJECTIVE_A,
        &seed.pseudonym(OBJECTIVE_A).submitter_id(),
        &artifact_with(MARKER_BETA),
        "nonce-alpha-02",
        EPOCH,
        CREATED_AT,
        committee.members(),
        3,
        &mut rng,
    )
    .expect("seal succeeds");
    assert_eq!(
        second_on_a.submitter, submission_a.submitter,
        "repeat submissions to one objective are linkable to each other, by design"
    );
}

// -- 7. the compatibility obligation ---------------------------------------

/// A sealed submission and a plain commitment produce the *same* commitment
/// hash, so the two paths cannot diverge.
///
/// If they diverged, the network would have two notions of a valid submission
/// and nodes would settle different things depending on which flow a submitter
/// happened to use. Sealing adds a ciphertext beside the commitment; it changes
/// nothing about what is committed to. That is what lets a node treat both
/// uniformly, and it is why §2 can call the binding property free.
#[test]
fn sealing_does_not_change_the_commitment() {
    let mut rng = TestRng(0x5A11E);
    let committee = Committee::new(3, &mut rng);
    let artifact = artifact_with(MARKER_ALPHA);
    let nonce = "nonce-alpha-01";

    // The plain flow: commit to a hash now, reveal the artifact yourself later.
    let plain_hash = commitment_hash(OBJECTIVE_A, "alice", &artifact, nonce);
    let plain = Commitment::new(OBJECTIVE_A, "alice", plain_hash.clone(), CREATED_AT);

    // The sealed flow: commit and seal in one action, and never act again.
    let sealed = SealedSubmission::seal(
        OBJECTIVE_A,
        "alice",
        &artifact,
        nonce,
        EPOCH,
        CREATED_AT,
        committee.members(),
        2,
        &mut rng,
    )
    .expect("seal succeeds");

    assert_eq!(
        sealed.commitment, plain_hash,
        "one artifact, one commitment, whichever path the submitter took"
    );

    // A node holding only the commitment record cannot tell which flow produced
    // it, byte for byte — so the record layer needs no sealed-specific case.
    let from_sealed = Commitment::new(
        sealed.objective_id.clone(),
        sealed.submitter.clone(),
        sealed.commitment.clone(),
        sealed.created_at.clone(),
    );
    assert_eq!(
        from_sealed.to_value().canonical_bytes(),
        plain.to_value().canonical_bytes()
    );
    assert_eq!(from_sealed.to_value().digest(), plain.to_value().digest());

    // And the reveals converge too: the claim a committee reveal produces is
    // the same claim the submitter would have revealed by hand.
    let shares = committee.publish(&sealed.envelope, &[1, 2]);
    let opened = open(&sealed, &shares).expect("opens");
    let committee_reveal = Claim::new(
        OBJECTIVE_A,
        "alice",
        opened.artifact,
        opened.nonce,
        CREATED_AT,
        Vec::new(),
    )
    .expect("valid claim");
    let self_reveal = Claim::new(
        OBJECTIVE_A,
        "alice",
        artifact.clone(),
        nonce,
        CREATED_AT,
        Vec::new(),
    )
    .expect("valid claim");
    assert_eq!(
        committee_reveal, self_reveal,
        "the two reveals are one record"
    );
    assert_eq!(committee_reveal.commitment_hash(), plain_hash);
    assert_eq!(committee_reveal.id(), self_reveal.id());
}

// -- 8. the guarantee sealing must not weaken ------------------------------

/// Sealing moves **when** an artifact becomes public. It never moves
/// **whether**.
///
/// proofwork's entire guarantee is that anyone can independently re-derive
/// every settled result, which requires settled artifacts to be public
/// (`docs/censorship.md`, "The tension, stated plainly"). An opened artifact is
/// therefore an ordinary [`Value`] with no residue of the mechanism that
/// carried it: same bytes, same digest, same re-parse, ready to hand to a
/// verifier. A `sealed`-class objective, whose artifact is never revealed, is a
/// different thing entirely and needs zero-knowledge verification (§6); this is
/// not that.
#[test]
fn opened_artifact_is_publicly_verifiable() {
    let mut rng = TestRng(0x0FE7);
    let committee = Committee::new(5, &mut rng);
    let artifact = artifact_with(MARKER_ALPHA);

    let submission = SealedSubmission::seal(
        OBJECTIVE_A,
        "alice",
        &artifact,
        "nonce-alpha-01",
        EPOCH,
        CREATED_AT,
        committee.members(),
        3,
        &mut rng,
    )
    .expect("seal succeeds");

    // Before the boundary: opaque.
    assert_sealed_against(&submission, MARKER_ALPHA);

    let shares = committee.publish(&submission.envelope, &[5, 1, 4]);
    let opened = open(&submission, &shares).expect("opens at the epoch boundary");

    // After the boundary: an ordinary canonical value, byte-identical to what
    // was sealed. No wrapper, no residual encoding, nothing a verifier has to
    // know about sealing in order to run.
    assert_eq!(opened.artifact, artifact);
    assert_eq!(
        opened.artifact.canonical_bytes(),
        artifact.canonical_bytes(),
        "the artifact round-trips through canonical bytes unchanged"
    );
    assert_eq!(opened.artifact.digest(), artifact.digest());

    // It survives the wire as text, which is what "anyone can re-derive this"
    // means in practice: publish the canonical string, and a stranger's parser
    // recovers exactly the value the commitment binds.
    let text = opened.artifact.canonical_string();
    let reparsed = Value::from_json(&text).expect("canonical output is valid JSON");
    assert_eq!(reparsed, artifact);
    assert_eq!(reparsed.canonical_string(), text);
    assert!(
        text.contains(MARKER_ALPHA),
        "the artifact is public now — that is the whole point of a reveal"
    );

    // And it is readable as an artifact, not as an opaque blob: a verifier
    // reads named fields off it exactly as it would in the plain flow.
    assert_eq!(
        reparsed
            .get("answer")
            .and_then(|v| v.as_str())
            .expect("the verifier reads a named field"),
        MARKER_ALPHA
    );
    assert_eq!(reparsed.get("steps").and_then(|v| v.as_i64()), Some(7));

    // The audit trail closes: the published artifact reproduces the commitment
    // that was on the log before anyone could read it, so priority and content
    // are both provable after the fact by a third party with no special access.
    let claim = Claim::new(
        OBJECTIVE_A,
        "alice",
        reparsed,
        opened.nonce,
        CREATED_AT,
        Vec::new(),
    )
    .expect("valid claim");
    assert_eq!(claim.commitment_hash(), submission.commitment);
    assert_eq!(
        claim.artifact_id(),
        Claim::new(
            OBJECTIVE_A,
            "someone-else",
            artifact,
            "a-different-nonce",
            CREATED_AT,
            Vec::new(),
        )
        .expect("valid claim")
        .artifact_id(),
        "the artifact is recognisable as the same work no matter who republishes it"
    );
}
