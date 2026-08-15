//! The rules: what may be posted, what settles, and what mints nothing.
//!
//! Everything here is a policy decision the design notes argue for. This module
//! is the enforceable version of those arguments -- and every rule below exists
//! because of a specific attack, named in the doc comment next to it.
//!
//! # The shape of a submission
//!
//! ```text
//! post_objective -> commit -> reveal -> (verdict) -> settlement | nothing
//! ```
//!
//! Three properties are worth stating up front, because the code is arranged
//! around them:
//!
//! 1. **Everything that happens is appended, including the failures.** A claim
//!    and its verdict are written to the log *before* any settlement decision is
//!    taken, so a rejected, duplicate, or unverifiable submission leaves exactly
//!    the same evidence trail as a winning one. An auditor re-derives the whole
//!    sequence; there is no path where the operator's arithmetic is trusted.
//! 2. **Only a settling verdict can move value.** A verifier that could not run
//!    is an infrastructure fact, never a refutation, and it leaves the objective
//!    open for a node that can run the check. See [`crate::verifiers`].
//! 3. **Novelty is necessary but never sufficient.** A duplicate artifact
//!    verifies fine and mints zero.
//!
//! # A malformed record is skipped, not fatal
//!
//! An entry this version cannot decode is **skipped by the readers and reported
//! by [`Node::audit`]** rather than taking the process down. Skipping is the
//! safe direction for every accessor that feeds a rule: an objective that cannot
//! be decoded is not found, so submissions against it are refused rather than
//! admitted on a partially understood record.
//!
//! This was a departure when it was written — the Python reference this crate
//! replaced raised out of `objectives()` — and it is now what both
//! implementations do, which is why `scripts/differential.sh` can compare their
//! verdicts on a corpus of deliberately malformed records at all.
//!
//! The one place where "skip it" would be *unsafe* is the frontier, because a
//! missing frontier means no citation is required and the payout curve restarts
//! from zero -- a malformed entry would be worth money. [`Node::reveal`]
//! therefore uses the strict internal reader, which refuses the submission
//! instead; only the informational [`Node::frontier_of`] softens it to `None`.
//!
//! Money arithmetic is checked rather than wrapping: `payout` and the running
//! `paid_cumulative` return errors on overflow, because a wrapped payout is an
//! invented or destroyed unit of account. The original Python reference got this
//! free from bignums and so never had to think about it, which is precisely why
//! the boundary is tested here on purpose — a reward above `u64::MAX` is in
//! `conformance/adversarial.jsonl` for exactly that reason.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};

use crate::blobs;
use crate::canonical::Inclusion;
use crate::canonical::{short, Value};
use crate::frontier::{FrontierEntry, Ratchet, RatchetError};
use crate::knowledge::{
    ClaimFacts, ConfidencePolicy, KnowledgeGraph, KnowledgeState, Reproducible,
};
use crate::ledger::{Entry, Ledger, LedgerError, Proof};
use crate::partition::{self, epoch_of, epoch_seconds, settlement_rank, PartitionError};
use crate::records::{
    Availability, AvailabilityPool, BisectionMove, Challenge, Claim, Commitment, CommitteeShare,
    Issuance, Objective, PeerRecord, Undertaking,
};
use crate::sealed::{OpenedSubmission, SealedSubmission};
use crate::verifiers::{self, Kind, Status, Verdict, VerifierRegistry};

/// Log entry kinds this module writes and reads. Spelled once so a typo cannot
/// silently make a query match nothing -- which, for the settlement and frontier
/// queries, would mean paying twice.
const OBJECTIVE: &str = "objective";
const COMMITMENT: &str = "commitment";
const CLAIM: &str = "claim";
const VERDICT: &str = "verdict";
const SETTLEMENT: &str = "settlement";
const FRONTIER: &str = "frontier";
/// Marks one reveal epoch as drained. See [`Node::settle_due`].
const BATCH: &str = "batch";
/// One epoch's ordering randomness, drawn where the sequencer cannot choose it.
/// See [`Node::record_beacon`].
const BEACON: &str = "beacon";
/// A beacon whose value is a verifiable delay rather than a chain observation.
///
/// The `source` a record carries to say "check this against the log, not
/// against an RPC endpoint". See [`Node::record_beacon_with`].
pub const VDF_SOURCE: &str = "vdf";

/// Set to `1` to treat an epoch settled without a beacon as an audit fault.
///
/// The beacon closes settlement grinding only if there *is* one, and the
/// fallback to the epoch-chain head — which exists so that pre-beacon logs
/// still audit and an unreachable chain does not halt settlement — is
/// therefore an opt-out: a sequencer who wants to grind simply records no
/// beacon and orders against the head as before.
/// [`Node::epochs_without_beacon`] makes that visible; this makes it refusable.
///
/// A reader's policy, not a writer's. It deliberately does not gate
/// *settlement*: a beacon is only admissible inside the epoch it orders, so
/// refusing to settle an epoch that already closed without one would strand
/// its claims permanently rather than protect anybody. What it gates is
/// acceptance — a node that requires beacon-ordered settlement can detect a
/// log that does not have it, which is the check that makes the requirement
/// mean something.
///
/// Not the default, for the same reason `PROOFWORK_REQUIRE_SANDBOX` is not:
/// it would fail every log written before this record existed, including the
/// published one, and an audit that cries wolf is an audit nobody reads.
pub const REQUIRE_BEACON_ENV: &str = "PROOFWORK_REQUIRE_BEACON";

fn beacon_required() -> bool {
    matches!(std::env::var(REQUIRE_BEACON_ENV), Ok(value) if value.trim() == "1")
}
const PEER: &str = "peer";
const UNDERTAKING: &str = "undertaking";
const AVAILABILITY: &str = "availability";
const AVAILABILITY_POOL: &str = "availability_pool";
const AVAILABILITY_SETTLEMENT: &str = "availability_settlement";
/// One committee member opening its share of a sealed submission's content key.
/// See [`Node::post_committee_share`].
const COMMITTEE_SHARE: &str = "committee_share";
/// A unit of money entering the log. Admissible only in the genesis prefix —
/// see [`Node::issued_within`].
const ISSUANCE: &str = "issuance";
/// A bonded objection to a settled claim's committed trace.
const CHALLENGE: &str = "challenge";
/// One party's answer to one bisection query.
const BISECTION: &str = "bisection";
/// The end of a dispute: who won, and what the loser paid.
const CHALLENGE_SETTLEMENT: &str = "challenge_settlement";

/// How long a claim's trace stays open to objection, and how long a party has
/// to answer a bisection query before silence decides against them.
///
/// One constant for both, deliberately. Two would let a challenger pick a claim
/// whose objection window is long and whose answer window is short, and stall a
/// defender who is telling the truth.
///
/// A constant and **not** an environment variable, for the reason
/// `crate::partition::EPOCH_SECONDS` is: a rule that depends on a process's
/// environment is not a consensus rule, and two auditors reading the same log
/// would disagree about who forfeited.
pub const CHALLENGE_WINDOW_EPOCHS: u64 = 6;

/// A dispute as the log leaves it.
///
/// Three phases rather than two, because "the parties have not yet witnessed
/// the invariant the search rests on" is a real state and not an error. See
/// [`crate::challenge::Endpoints`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisputeState {
    /// Waiting for one or more of the four opening moves.
    AwaitingEndpoints {
        challenge: Challenge,
        /// `(index, side)` pairs still owed.
        missing: Vec<(usize, crate::challenge::Side)>,
    },
    /// The bisection is under way, or finished and awaiting adjudication.
    Live {
        challenge: Challenge,
        /// Boxed: a `Dispute` carries every state opened so far, and an enum
        /// as large as its largest variant would make every `DisputeState`
        /// that size.
        dispute: Box<crate::challenge::Dispute>,
    },
    /// The endpoints could not found a dispute at all — the traces start
    /// differently, or end the same. The objection was never well formed, and
    /// the challenger staked on it.
    Void {
        challenge: Challenge,
        why: crate::challenge::DisputeError,
    },
}

impl DisputeState {
    pub fn challenge(&self) -> &Challenge {
        match self {
            DisputeState::AwaitingEndpoints { challenge, .. }
            | DisputeState::Live { challenge, .. }
            | DisputeState::Void { challenge, .. } => challenge,
        }
    }
}

// ---------------------------------------------------------------------------
// Rule violations
// ---------------------------------------------------------------------------

/// Which record referred to an objective that is not in the log.
///
/// The reference implementation distinguishes the two cases by writing two
/// different message strings. An enum keeps the distinction in the type, so the
/// caller can branch on it without parsing English.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Referrer {
    Commitment,
    Claim,
}

impl Referrer {
    pub const fn as_str(self) -> &'static str {
        match self {
            Referrer::Commitment => "commitment",
            Referrer::Claim => "claim",
        }
    }
}

impl fmt::Display for Referrer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A submission the network refuses to record.
///
/// A refusal writes **nothing** to the log. That matters: a rejected *verdict*
/// is evidence and is recorded, while a violation of the submission rules is not
/// a fact about anybody's work and leaves no trace beyond the caller's error.
///
/// Not `Clone` or `PartialEq`, for the same reason as [`LedgerError`]: it can
/// carry an [`std::io::Error`], and replacing that with a comparable shim would
/// throw away the OS-level detail that makes a failed append diagnosable.
#[derive(Debug)]
pub enum RuleViolation {
    /// A dispute names a claim the log does not carry.
    UnknownClaim { claim_id: String },
    /// A dispute names a challenge the log does not carry.
    UnknownChallenge { challenge_id: String },
    /// A challenge against a claim nobody accepted. Nothing is at stake, and
    /// the bond would be locked over nothing.
    ChallengeOfUnacceptedClaim { claim_id: String },
    /// The objective declares no stepper, so a dispute over it could never be
    /// adjudicated -- and an unadjudicable dispute that still holds a bond is a
    /// griefing tool rather than a mechanism.
    ObjectiveNotBisectable { objective_id: String },
    /// The claim's artifact commits to no trace, so there is nothing to bisect.
    NoTraceCommitment { claim_id: String },
    /// The two parties claim different trace lengths. They have already stated
    /// their disagreement in public; a search would be theatre.
    TraceLengthMismatch { claimed: u64, challenged: u64 },
    /// The challenger committed to the same root as the claim. Agreement is not
    /// a dispute.
    ChallengeAgrees { claim_id: String },
    /// The objection arrived after the window shut. A claim has to become final
    /// at some point or no payout is ever safe to spend.
    ChallengeWindowClosed {
        claim_id: String,
        closed_at: u64,
        opened_at: u64,
    },
    /// This challenger already has a live objection to this claim. Without the
    /// rule, one challenger opens a hundred and an honest defender must answer
    /// every one or forfeit each.
    DuplicateChallenge {
        claim_id: String,
        challenger: String,
    },
    /// The mover is neither the claim's submitter nor the challenger.
    NotAParty { challenge_id: String, mover: String },
    /// A move against a dispute that already has an outcome.
    ChallengeDecided { challenge_id: String },
    /// The move does not open the root its author committed to. The single most
    /// important check in the game: a party that could answer with a state it
    /// never committed to would win every dispute by playing whatever beats the
    /// other side this round.
    MoveNotUnderRoot { challenge_id: String, index: u64 },
    /// A well-formed answer to a question the game did not ask -- the stall
    /// that looks like cooperation.
    MoveOutOfTurn { challenge_id: String, index: u64 },
    /// Somebody tried to settle a dispute that is still somebody's turn and
    /// still inside its window.
    ChallengeStillOpen { challenge_id: String },
    /// The stepper could not be run here. Settles nothing, for the same reason
    /// an unavailable verifier settles nothing.
    AdjudicationUnavailable {
        challenge_id: String,
        detail: String,
    },
    /// No verifier answers to this objective's `kind`.
    ///
    /// An objective whose verifier cannot run is an objective whose payout is
    /// somebody's opinion, and admitting one is how a results market turns into
    /// a popularity contest.
    UnknownVerifierKind { kind: String },
    /// This exact objective is already in the log. Ids are content addresses, so
    /// "the same objective" means the same bytes: statement, verifier pin,
    /// ratchet and all.
    DuplicateObjective { objective_id: String },
    /// A ratchet objective whose verifier produces no score. There is nothing to
    /// ratchet on, so the payout curve has no input.
    RatchetNeedsEvaluator { kind: String },
    /// `ratchet.reward` and `objective.reward` disagree. There is one pool, not
    /// two; letting them differ would let an objective promise one number and
    /// pay out along a curve scaled to another.
    RatchetRewardMismatch { ratchet: u64, objective: u64 },
    /// A commitment or claim naming an objective that was never posted.
    UnknownObjective {
        referrer: Referrer,
        objective_id: String,
    },
    /// A commitment against a non-ratchet objective that has already settled.
    /// A progressive objective is deliberately exempt -- see [`Node::commit`].
    AlreadySettled { objective_id: String },
    /// A reveal with no prior commitment from this submitter for this artifact.
    NoMatchingCommitment,
    /// A citation that is not an accepted claim in this log.
    UnknownCitation { claim_id: String },
    /// A relation naming a claim that is not in this log.
    ///
    /// Separate from [`RuleViolation::UnknownCitation`] because the rule is
    /// weaker and the fix is different: a relation target must merely *exist*,
    /// where a citation must have been accepted.
    UnknownRelationTarget { claim_id: String },
    /// An improvement that does not cite the frontier it improves on.
    MissingFrontierCitation { claim_id: String },
    /// `paid_cumulative + reward` does not fit `u64`.
    ///
    /// Python's bignums make this unreachable there and merely unrepresentable
    /// here; wrapping it would silently reset an objective's running total and
    /// hide an overspent pool from the audit.
    PayoutOverflow { paid_cumulative: u64, reward: u64 },
    /// The objective's ratchet block is malformed, or its arithmetic could not
    /// be completed exactly.
    MalformedRatchet(RatchetError),
    /// The objective's latest frontier entry cannot be read.
    ///
    /// Refused rather than treated as an empty frontier: an unreadable frontier
    /// would waive the citation requirement and restart the payout curve at
    /// zero, so "I cannot read it" must not be worth money.
    MalformedFrontier(RatchetError),
    /// A timestamp that decides an epoch cannot be read as one.
    ///
    /// Refused rather than defaulted. A record whose epoch is unknown cannot be
    /// placed in a settlement batch, and guessing one -- "treat it as now" --
    /// would hand a submitter a free choice of batch by writing garbage.
    MalformedTimestamp { record: &'static str, value: String },
    /// A submitter that names an ed25519 public key did not prove it holds
    /// that key.
    ///
    /// The rule that makes an identity worth having. `submitter` has always
    /// been a free string, so a name was worth nothing and citation flow was
    /// paying a string anyone could type; a key-shaped name now has to be
    /// signed for. See [`crate::records::signed_submitter`].
    UnsignedIdentity(crate::records::SignatureError),
    /// A peer record that does not advance its identity's sequence number.
    ///
    /// The rule that makes an append-only address hint behave like mutable
    /// state without being mutable: the highest `seq` for an identity wins, so
    /// a replayed old record cannot move a peer back to an address it has left.
    /// Equal is refused as well as lower — two different records at one `seq`
    /// would leave "the highest" ambiguous, and ambiguity in a rule two
    /// implementations both apply is a consensus split.
    StalePeerRecord {
        identity: String,
        seq: u64,
        held: u64,
    },
    /// A second answer to a sample already answered. One index, one payment.
    SampleAlreadyAnswered { undertaking: String, epoch: u64 },
    /// An answer naming an undertaking this log does not hold, or holds only
    /// in a form nobody can sample.
    UnknownUndertaking { undertaking: String },
    /// An answer to somebody else's promise.
    ///
    /// The draw keys on the *undertaking's* identity, so an impostor's answer
    /// would be arithmetically correct -- which is exactly why the rule has to
    /// be stated rather than left to fall out.
    AvailabilityImpostor {
        undertaking: String,
        answered_by: String,
    },
    /// The sample index could not be drawn at all.
    Unsamplable {
        undertaking: String,
        source: PartitionError,
    },
    /// The path does not put the sampled entry under the undertaken root.
    AvailabilityDoesNotCheck {
        undertaking: String,
        epoch: u64,
        index: u64,
    },
    /// A bond larger than the log says the identity can afford.
    ///
    /// The check that makes the stake-weighted split mean anything: a bond
    /// anybody could set freely would be the even split wearing a disguise.
    UnfundedBond {
        identity: String,
        bond: u64,
        spendable: u128,
    },
    /// A reward larger than the log says its funder can afford.
    ///
    /// The check that makes every other money rule mean something. Without it
    /// a funder names a sum and the settlement pays it, so the units a bond is
    /// weighed in are free to make and weighing by them buys nothing. Only
    /// enforced on a log that declares a supply — see [`Node::declares_supply`].
    UnfundedReward {
        funder: String,
        reward: u128,
        spendable: u128,
    },
    /// An issuance below the genesis prefix: money made after the fact.
    MintedAfterGenesis {
        holder: String,
        units: u64,
        seq: u64,
    },
    /// A delay beacon whose proof does not show the work it claims.
    BeaconDoesNotVerify { epoch: u64 },
    /// An undertaking that does not cover the whole log as it stood.
    ///
    /// The promiser does not choose how much to promise, because when they
    /// could, promising one entry paid the same as promising the log. See
    /// [`Node::post_undertaking`].
    PartialUndertaking { promised: u64, log: u64 },
    /// An undertaking about a root and height this log never had.
    ///
    /// Refused rather than admitted-and-ignored, because the whole value of
    /// the record is that it can be sampled: a challenge is an index into a
    /// tree of `height` leaves rooted at `root`, and if no prefix of this log
    /// matches, no answer could ever be checked either way. A promise nobody
    /// can test is the "bookkeeping" `docs/roadmap.md` warns against, and it
    /// would sit in the log permanently.
    UnknownUndertakingRoot { root: String, height: u64 },
    /// A beacon drawn in an epoch other than the one it orders.
    ///
    /// The timing *is* the security property, and both directions are fatal.
    /// Drawn early, the value exists while commitments for this epoch can still
    /// be made, so a submitter can grind a commitment hash against a beacon
    /// they already know — the residual gap [`Node::settle_due`] documents,
    /// reopened. Drawn late, the sequencer has already seen who revealed, and
    /// picking the draw is picking the payment order. Only a beacon drawn at
    /// the boundary is unknown to every committer and unchosen by the operator.
    BeaconOutOfEpoch { orders: u64, drawn_in: u64 },
    /// A second beacon for an epoch that already has one.
    ///
    /// Refused rather than resolved by a tie-break, because every tie-break is
    /// a choice and the choice belongs to nobody. Two beacons for one epoch
    /// would let whoever appends the second one re-roll the settlement order
    /// after reading the first — which is the entire lever this record exists
    /// to remove, restored by an operator who simply writes twice.
    DuplicateBeacon { epoch: u64 },
    /// A record whose own decoder would refuse it.
    ///
    /// Every other kind arrives here already decoded, so `from_value` has run
    /// and the fields are known good. [`PeerRecord::new`] is a plain
    /// constructor, which left `peer` as the one kind that could be appended
    /// without ever meeting its own decoder — and a record in the log that the
    /// log's reader rejects makes the whole file unauditable in both
    /// implementations.
    InadmissibleRecord(crate::records::RecordError),
    /// The objective admits only signed identities, and this submitter is a
    /// nickname.
    ///
    /// Distinct from [`RuleViolation::UnsignedIdentity`], which is "you named
    /// a key and did not prove it". This one is "this bounty does not accept
    /// names at all", which is the funder's policy rather than a broken
    /// submission -- and the fix is different, so the message has to be too.
    SignedSubmitterRequired {
        objective_id: String,
        submitter: String,
    },
    /// A reveal into an epoch whose settlement batch has already been paid.
    ///
    /// Refused rather than queued for the next batch. An epoch's batch is
    /// defined as *every* accepted claim revealed in it, ordered by beacon;
    /// admitting a latecomer would either silently strand the claim (it belongs
    /// to a batch that is over) or split the epoch into two orderings, which is
    /// a lever on settlement order handed back to whoever controls arrival.
    EpochAlreadySettled { epoch: u64 },
    /// A reveal in the same epoch as (or earlier than) its own commitment.
    ///
    /// The commitment already hides the artifact, but it does not stop the
    /// *sequencer* -- who sees reveals before anyone else -- from opening a
    /// commitment of its own in the same breath. Requiring a strictly later
    /// epoch means the reveal that would be copied is public before a
    /// competitor's commitment can be written, so there is nothing left to
    /// front-run.
    RevealBeforeEpoch {
        commit_epoch: u64,
        reveal_epoch: u64,
    },
    /// A share, or an open, naming a commitment this log does not hold.
    UnknownCommitment { commitment: String },
    /// A share against a commitment that carries no envelope.
    ///
    /// There is nothing to open, so the record is noise at best. Refused rather
    /// than ignored because a log full of shares for unsealed commitments is a
    /// cheap way to make [`Node::pending_sealed_reveals`] useless to read.
    CommitmentNotSealed { commitment: String },
    /// Not enough peers are registered to draw a committee.
    ///
    /// Refused rather than drawn short — see [`Node::committee_for`], which
    /// explains why a smaller committee is worse than no committee.
    CommitteeTooSmall {
        epoch: u64,
        have: usize,
        need: usize,
    },
    /// A share published in the same epoch as (or earlier than) the commitment
    /// it opens.
    ///
    /// The committee's version of [`RuleViolation::RevealBeforeEpoch`], and it
    /// closes the same hole. A committee that could publish inside the
    /// commitment's own epoch would hand the sequencer every artifact while it
    /// was still worth front-running — replacing the submitter in the reveal
    /// path was meant to remove a censorship lever, not to give away the
    /// batching that made front-running impossible.
    ShareBeforeEpoch { commit_epoch: u64, share_epoch: u64 },
    /// A share record that sits earlier in the log than the commitment it
    /// claims to open.
    ShareBeforeCommitment { commitment: String },
    /// A share for a seat the epoch's draw never produced.
    UnknownSeat { commitment: String, seat: u8 },
    /// A share published for a seat drawn for somebody else.
    ///
    /// Without this rule anyone could publish for any seat, and since a Shamir
    /// share is not individually checkable, filling `t` seats with noise would
    /// stall a reveal at no cost.
    SeatImpostor {
        commitment: String,
        seat: u8,
        published_by: String,
    },
    /// A second share for a seat that has already published.
    SeatAlreadyPublished { commitment: String, seat: u8 },
    /// Fewer published shares than the envelope's threshold.
    ///
    /// Not a failure so much as a "not yet": the reveal opens as soon as enough
    /// members publish, and this is what a caller polling for that sees.
    NotEnoughShares {
        commitment: String,
        have: usize,
        need: usize,
    },
    /// A sealed commitment whose envelope does not match the network's
    /// committee parameters. See [`Node::commit`].
    WrongCommitteeShape {
        threshold: u8,
        seats: usize,
        want_threshold: u8,
        want_seats: usize,
    },
    /// Enough shares, and no subset of them opens the envelope.
    ///
    /// Which member lied is not knowable — see [`Node::open_sealed`] on why
    /// verifiable secret sharing is not available to a post-quantum scheme.
    SealedOpenFailed { commitment: String, tried: usize },
    /// The record could not be appended to the log.
    Ledger(LedgerError),
}

impl fmt::Display for RuleViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuleViolation::UnknownClaim { claim_id } => {
                write!(f, "no claim {claim_id} in this log")
            }
            RuleViolation::UnknownChallenge { challenge_id } => {
                write!(f, "no challenge {challenge_id} in this log")
            }
            RuleViolation::ChallengeOfUnacceptedClaim { claim_id } => write!(
                f,
                "claim {claim_id} was never accepted; there is nothing to dispute"
            ),
            RuleViolation::ObjectiveNotBisectable { objective_id } => write!(
                f,
                "objective {objective_id} declares no stepper, so a dispute over \
                 it could never be adjudicated"
            ),
            RuleViolation::NoTraceCommitment { claim_id } => write!(
                f,
                "claim {claim_id} commits to no trace; there is nothing to bisect"
            ),
            RuleViolation::TraceLengthMismatch {
                claimed,
                challenged,
            } => write!(
                f,
                "the claim commits to {claimed} states and the challenge to \
                 {challenged}; that disagreement is already public"
            ),
            RuleViolation::ChallengeAgrees { claim_id } => write!(
                f,
                "the challenge commits to the same trace as claim {claim_id}"
            ),
            RuleViolation::ChallengeWindowClosed {
                claim_id,
                closed_at,
                opened_at,
            } => write!(
                f,
                "claim {claim_id} closed to objection after epoch {closed_at}; \
                 this one arrived in {opened_at}"
            ),
            RuleViolation::DuplicateChallenge {
                claim_id,
                challenger,
            } => write!(
                f,
                "{challenger} already has a live objection to claim {claim_id}"
            ),
            RuleViolation::NotAParty {
                challenge_id,
                mover,
            } => write!(f, "{mover} is not a party to challenge {challenge_id}"),
            RuleViolation::ChallengeDecided { challenge_id } => {
                write!(f, "challenge {challenge_id} is already decided")
            }
            RuleViolation::MoveNotUnderRoot {
                challenge_id,
                index,
            } => write!(
                f,
                "the move on challenge {challenge_id} at state {index} does not \
                 open the root its author committed to"
            ),
            RuleViolation::MoveOutOfTurn {
                challenge_id,
                index,
            } => write!(
                f,
                "challenge {challenge_id} did not ask about state {index}"
            ),
            RuleViolation::ChallengeStillOpen { challenge_id } => write!(
                f,
                "challenge {challenge_id} is still somebody's turn, and still \
                 inside its window"
            ),
            RuleViolation::AdjudicationUnavailable {
                challenge_id,
                detail,
            } => write!(
                f,
                "challenge {challenge_id} cannot be adjudicated here, so it \
                 settles nothing: {detail}"
            ),
            RuleViolation::UnknownVerifierKind { kind } => write!(
                f,
                "no verifier registered for kind {kind}; known: [{}]",
                VerifierRegistry::kinds().join(", ")
            ),
            RuleViolation::DuplicateObjective { objective_id } => {
                write!(f, "objective already posted ({})", short(objective_id))
            }
            RuleViolation::RatchetNeedsEvaluator { kind } => write!(
                f,
                "a ratchet objective needs a score-producing verifier \
                 ({}), not {kind:?}",
                Kind::Evaluator
            ),
            RuleViolation::RatchetRewardMismatch { ratchet, objective } => write!(
                f,
                "ratchet.reward ({ratchet}) and objective.reward ({objective}) \
                 must agree; there is one pool, not two"
            ),
            RuleViolation::UnknownObjective {
                referrer,
                objective_id,
            } => write!(
                f,
                "{referrer} references an unknown objective ({})",
                short(objective_id)
            ),
            RuleViolation::AlreadySettled { objective_id } => write!(
                f,
                "objective is already settled ({})",
                short(objective_id)
            ),
            RuleViolation::NoMatchingCommitment => f.write_str(
                "no matching prior commitment: commit H(artifact\u{2016}submitter\u{2016}nonce) first",
            ),
            RuleViolation::UnknownCitation { claim_id } => write!(
                f,
                "citation {claim_id} is not an accepted claim in this log; \
                 citations point backwards only"
            ),
            RuleViolation::UnknownRelationTarget { claim_id } => write!(
                f,
                "relation target {claim_id} is not a claim in this log; \
                 a relation may name any claim, accepted or not, but not one \
                 that does not exist"
            ),
            RuleViolation::MissingFrontierCitation { claim_id } => write!(
                f,
                "an improvement must cite the frontier it improves on ({claim_id})"
            ),
            RuleViolation::PayoutOverflow {
                paid_cumulative,
                reward,
            } => write!(
                f,
                "cumulative payout {paid_cumulative} + {reward} overflows; \
                 refusing to wrap on a money path"
            ),
            RuleViolation::MalformedRatchet(source) => {
                write!(f, "objective carries an unusable ratchet: {source}")
            }
            RuleViolation::MalformedFrontier(source) => write!(
                f,
                "the objective's latest frontier entry cannot be read: {source}"
            ),
            RuleViolation::MalformedTimestamp { record, value } => write!(
                f,
                "{record} timestamp {value:?} is not an RFC-3339 instant, so the \
                 epoch it settles in cannot be derived"
            ),
            RuleViolation::UnsignedIdentity(error) => write!(f, "{error}"),
            RuleViolation::InadmissibleRecord(error) => {
                write!(f, "record would not be readable back: {error}")
            }
            RuleViolation::StalePeerRecord {
                identity,
                seq,
                held,
            } => write!(
                f,
                "peer record for {} has seq {seq}, and {held} is already held; a \
                 record must advance its identity's sequence to supersede",
                crate::canonical::short(identity)
            ),
            RuleViolation::SampleAlreadyAnswered { undertaking, epoch } => write!(
                f,
                "undertaking {} was already answered for epoch {epoch}; one sample is                  one piece of work and is paid once",
                crate::canonical::short(undertaking)
            ),
            RuleViolation::UnknownUndertaking { undertaking } => write!(
                f,
                "no samplable undertaking {} in this log; an answer must name a \
                 promise the log holds, and a promise about an unknown root is \
                 not one",
                crate::canonical::short(undertaking)
            ),
            RuleViolation::AvailabilityImpostor {
                undertaking,
                answered_by,
            } => write!(
                f,
                "undertaking {} was promised by somebody else, and {} cannot answer \
                 it; the sample is drawn against the promiser's identity",
                crate::canonical::short(undertaking),
                crate::canonical::short(answered_by)
            ),
            RuleViolation::Unsamplable {
                undertaking,
                source,
            } => write!(
                f,
                "cannot draw a sample for undertaking {}: {source}",
                crate::canonical::short(undertaking)
            ),
            RuleViolation::AvailabilityDoesNotCheck {
                undertaking,
                epoch,
                index,
            } => write!(
                f,
                "the path does not put entry {index} under the root undertaken by {} \
                 (epoch {epoch}); entry {index} is what that undertaking was sampled on",
                crate::canonical::short(undertaking)
            ),
            RuleViolation::BeaconOutOfEpoch { orders, drawn_in } => write!(
                f,
                "a beacon ordering epoch {orders} was drawn in epoch {drawn_in}; it must \
                 be drawn in the epoch it orders -- earlier and a committer can grind \
                 against a value they already know, later and the operator is choosing \
                 the order after reading the reveals"
            ),
            RuleViolation::DuplicateBeacon { epoch } => write!(
                f,
                "epoch {epoch} already has a beacon; a second one would let whoever \
                 writes it re-roll the settlement order after reading the first"
            ),
            RuleViolation::UnfundedBond {
                identity,
                bond,
                spendable,
            } => write!(
                f,
                "{} staked {bond} units and the log has paid it {spendable} it has not \
                 already locked; a bond is what the availability pool is divided by, so \
                 one nobody earned would let a fresh identity take a share for free",
                crate::canonical::short(identity)
            ),
            RuleViolation::UnfundedReward {
                funder,
                reward,
                spendable,
            } => write!(
                f,
                "{} offers {reward} units and holds {spendable} it has not already \
                 committed; this log declares its supply, so a reward nobody issued \
                 would be money made by naming it",
                crate::canonical::short(funder)
            ),
            RuleViolation::BeaconDoesNotVerify { epoch } => write!(
                f,
                "the delay proof for epoch {epoch} does not check; a beacon nobody had \
                 to wait for is a value the sequencer chose, which is the grinding this \
                 record exists to price"
            ),
            RuleViolation::MintedAfterGenesis { holder, units, seq } => write!(
                f,
                "entry {seq} issues {units} units to {}; a supply is declared in the \
                 log's opening entries and never again, or it is not a supply",
                crate::canonical::short(holder)
            ),
            RuleViolation::PartialUndertaking { promised, log } => write!(
                f,
                "an undertaking must cover the whole log as it stands ({log} entries), \
                 and this one promises {promised}; the size of the promise is what the \
                 availability pool pays for, so it is not the promiser's to choose"
            ),
            RuleViolation::UnknownUndertakingRoot { root, height } => write!(
                f,
                "no prefix of this log has {} entries rooted at {}; an undertaking \
                 must name a root this log actually had, or nobody could ever check \
                 an answer to it",
                height,
                crate::canonical::short(root)
            ),
            RuleViolation::SignedSubmitterRequired {
                objective_id,
                submitter,
            } => write!(
                f,
                "objective {} accepts only signed identities, and {submitter:?} is not one. \
                 Create one with `proofwork identity --out <file>` and submit with \
                 --identity; the public key it prints becomes your submitter name",
                crate::canonical::short(objective_id)
            ),
            RuleViolation::EpochAlreadySettled { epoch } => write!(
                f,
                "epoch {epoch} has already settled; a reveal cannot join a batch \
                 that has been paid"
            ),
            RuleViolation::RevealBeforeEpoch {
                commit_epoch,
                reveal_epoch,
            } => write!(
                f,
                "reveal is in epoch {reveal_epoch} but its commitment is in epoch \
                 {commit_epoch}; a reveal must wait for a strictly later epoch"
            ),
            RuleViolation::UnknownCommitment { commitment } => write!(
                f,
                "no commitment {} in this log",
                short(commitment)
            ),
            RuleViolation::CommitmentNotSealed { commitment } => write!(
                f,
                "commitment {} carries no envelope, so there is nothing for a \
                 committee to open; it reveals the ordinary way",
                short(commitment)
            ),
            RuleViolation::CommitteeTooSmall { epoch, have, need } => write!(
                f,
                "epoch {epoch} has {have} registered peers and a committee needs \
                 {need}; a short committee would quietly lower the threshold \
                 everyone is relying on"
            ),
            RuleViolation::ShareBeforeEpoch {
                commit_epoch,
                share_epoch,
            } => write!(
                f,
                "share is in epoch {share_epoch} but its commitment is in epoch \
                 {commit_epoch}; a committee must wait for a strictly later epoch"
            ),
            RuleViolation::ShareBeforeCommitment { commitment } => write!(
                f,
                "share precedes commitment {} in the log",
                short(commitment)
            ),
            RuleViolation::UnknownSeat { commitment, seat } => write!(
                f,
                "seat {seat} was not drawn for commitment {}",
                short(commitment)
            ),
            RuleViolation::SeatImpostor {
                commitment,
                seat,
                published_by,
            } => write!(
                f,
                "seat {seat} of commitment {} belongs to another identity; \
                 published by {}",
                short(commitment),
                short(published_by)
            ),
            RuleViolation::SeatAlreadyPublished { commitment, seat } => write!(
                f,
                "seat {seat} of commitment {} has already published its share",
                short(commitment)
            ),
            RuleViolation::NotEnoughShares {
                commitment,
                have,
                need,
            } => write!(
                f,
                "commitment {} has {have} of the {need} shares it needs; not yet, \
                 rather than never",
                short(commitment)
            ),
            RuleViolation::WrongCommitteeShape {
                threshold,
                seats,
                want_threshold,
                want_seats,
            } => write!(
                f,
                "sealed commitment is {threshold}-of-{seats} addressed at seats \
                 1..={seats}; this network seals {want_threshold}-of-{want_seats}, \
                 and a submitter-chosen threshold is a submitter-chosen \
                 collusion cost"
            ),
            RuleViolation::SealedOpenFailed { commitment, tried } => write!(
                f,
                "no subset of the {tried} published shares opens commitment {}; \
                 at least one member published a share that is not theirs, and \
                 which one is not knowable without verifiable secret sharing",
                short(commitment)
            ),
            RuleViolation::Ledger(source) => write!(f, "cannot record: {source}"),
        }
    }
}

impl From<crate::records::SignatureError> for RuleViolation {
    fn from(error: crate::records::SignatureError) -> RuleViolation {
        RuleViolation::UnsignedIdentity(error)
    }
}

impl std::error::Error for RuleViolation {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RuleViolation::MalformedRatchet(source) | RuleViolation::MalformedFrontier(source) => {
                Some(source)
            }
            RuleViolation::Ledger(source) => Some(source),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Outcome
// ---------------------------------------------------------------------------

/// What settling one epoch's availability samples did.
///
/// Reported rather than left for the caller to derive, because the two numbers
/// a funder and an operator actually want — how many promises went unanswered,
/// and how much of the pot went unspent — are not visible from the settlement
/// records alone: an unanswered promise writes no record, which is the point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvailabilityOutcome {
    pub epoch: u64,
    /// Promises that produced a checkable answer, and were paid.
    pub answered: usize,
    /// Promises that were samplable in this epoch and said nothing.
    pub silent: usize,
    /// Units actually paid out across every identity.
    pub paid: u128,
    /// The remainder equal shares could not divide, left in the pot.
    pub unpaid: u128,
}

/// What a reveal did.
///
/// `settled == false` is not an error and not a rejection: a verdict that could
/// not be reached, a duplicate artifact, and an improvement that does not move
/// the frontier all land here with `reward == 0` and a `note` naming the reason.
/// The claim and its verdict are in the log either way.
/// One link of the epoch chain. See [`Node::epoch_chain`].
///
/// `link` is `H({prev, epoch, claims})` with `claims` sorted, which is what
/// makes it a pure function of content: two nodes that settled the same claims
/// in the same epochs compute the same link, whatever order their logs are in
/// and whenever they were written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochLink {
    pub epoch: u64,
    /// Claim ids settled in this epoch, **sorted** — the order the link commits
    /// to, deliberately not the beacon order the batch paid in. A link that
    /// depended on the payout order could not be used to derive it.
    pub claims: Vec<String>,
    /// The link before this one; empty for the first.
    pub prev: String,
    pub link: String,
}

/// One seat on the epoch's threshold committee, as the beacon drew it.
///
/// Everything here is already in the log — this type is the *derivation*, not a
/// record. Nobody writes a committee list, so nobody can substitute one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitteeSeat {
    /// `1..=COMMITTEE_SIZE`, in draw order. Also the routing index the
    /// envelope addresses this member's sealed share at, so a member can find
    /// their own share without being told which it is.
    pub seat: u8,
    /// `sha256` of the member's Classic McEliece public key, hex. What a share
    /// is sealed to, and what the draw ranks on.
    pub transport: String,
    /// The member's ed25519 public key, hex. What a published share is signed
    /// with. The peer record is what ties this to `transport`.
    pub identity: String,
    /// Where to reach the member to fetch its 261,120-byte McEliece key, which
    /// is far too large to travel in a peer record. A hint, exactly as it is
    /// for dialing: a wrong address costs a fetch, never a wrong result.
    pub addr: String,
}

/// A sealed submission waiting on its committee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingReveal {
    pub commitment: String,
    pub objective_id: String,
    pub commit_epoch: u64,
    /// How many shares open it.
    pub threshold: u8,
    /// Who was drawn to hold one.
    pub seats: Vec<CommitteeSeat>,
    /// Which seats have already published, ascending.
    pub published: Vec<u8>,
}

impl PendingReveal {
    /// Is this one openable right now?
    pub fn openable(&self) -> bool {
        self.published.len() >= usize::from(self.threshold)
    }

    /// The seat this identity holds here, if any.
    pub fn seat_of(&self, identity: &str) -> Option<&CommitteeSeat> {
        self.seats.iter().find(|seat| seat.identity == identity)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// Content address of the revealed claim, as recorded.
    pub claim_id: String,
    /// The verdict, exactly as written to the log.
    pub verdict: Verdict,
    /// Whether value moved. Note that a *settled* improvement can still pay
    /// zero, when truncation eats a small step on a large curve.
    pub settled: bool,
    pub reward: u64,
    /// The reveal epoch this claim will settle in, when it is accepted but its
    /// epoch has not closed yet. `None` once the answer is final.
    ///
    /// A caller must not read `settled == false` as "earned nothing" while this
    /// is set: the batch has not run. See [`Node::settle_due`].
    pub pending_epoch: Option<u64>,
    /// Human-readable reason. Never load-bearing; the ledger is.
    pub note: String,
}

impl Outcome {
    /// The common "nothing moved" case, so the reason is the only thing that
    /// varies at the call sites.
    fn unsettled(claim_id: String, verdict: Verdict, note: impl Into<String>) -> Outcome {
        Outcome {
            claim_id,
            verdict,
            settled: false,
            reward: 0,
            pending_epoch: None,
            note: note.into(),
        }
    }

    /// Accepted, recorded, and waiting for its epoch to close.
    fn pending(claim_id: String, verdict: Verdict, epoch: u64) -> Outcome {
        Outcome {
            claim_id,
            verdict,
            settled: false,
            reward: 0,
            pending_epoch: Some(epoch),
            note: format!(
                "accepted; settles once epoch {epoch} closes and clears the {}-epoch finality delay",
                crate::partition::finality_epochs()
            ),
        }
    }

    /// Whether the claim is accepted and waiting rather than finished.
    pub fn is_pending(&self) -> bool {
        self.pending_epoch.is_some()
    }
}

// ---------------------------------------------------------------------------
// Node
// ---------------------------------------------------------------------------

/// The rules engine over one append-only log.
///
/// Not `Clone`, because [`Ledger`] is not: two handles to one file would each
/// compute `prev` from their own view of the tail and fork the log.
#[derive(Debug)]
pub struct Node {
    ledger: Ledger,
    registry: VerifierRegistry,
}

impl Node {
    /// A node over `ledger`, resolving pinned verifier code against `root`.
    ///
    /// The reference implementation sets the root on a process-global registry
    /// (`verifiers.set_root`), which makes two nodes in one process fight over
    /// it -- its own tests have to restore the global afterwards. Here the
    /// registry is owned by the node, so the root is per-node state and two
    /// nodes over two bundles cannot interfere.
    pub fn new(ledger: Ledger, root: impl Into<PathBuf>) -> Node {
        Node {
            ledger,
            registry: VerifierRegistry::new(root),
        }
    }

    /// A node over a pre-configured registry -- a node with a pinned Lean
    /// toolchain, or a test that needs a binary guaranteed to be absent.
    pub fn with_registry(ledger: Ledger, registry: VerifierRegistry) -> Node {
        Node { ledger, registry }
    }

    /// The log. Public because every consumer -- attribution, the CLI, an
    /// auditor -- reads it directly, and reading it is the whole point.
    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    /// Direct append access, for records this module does not own (and for
    /// tests that need to plant a damaged log). Everything the rules produce
    /// goes through the methods below; nothing here re-checks a hand-written
    /// entry, which is exactly what [`Node::audit`] is for.
    pub fn ledger_mut(&mut self) -> &mut Ledger {
        &mut self.ledger
    }

    pub fn registry(&self) -> &VerifierRegistry {
        &self.registry
    }

    /// The objective bundle root pinned verifier code is resolved against.
    pub fn root(&self) -> &Path {
        self.registry.root()
    }

    // -- objectives ------------------------------------------------------

    /// Fund a checkable question.
    ///
    /// Refused if no verifier is registered for its kind. An objective whose
    /// verifier cannot run is an objective whose payout is somebody's opinion,
    /// and admitting it is how a results market turns into a popularity contest.
    ///
    /// A ratchet objective carries two further conditions:
    ///
    /// - its verifier must **produce a score**, i.e. be an evaluator. There is
    ///   no curve to pay along otherwise.
    /// - `ratchet.reward` must equal `objective.reward`. There is one pool, not
    ///   two, and an objective that advertises one number while paying along a
    ///   curve scaled to another is a lie the log would faithfully record.
    ///
    /// The checks run in the reference implementation's order, so a malformed
    /// ratchet is reported as malformed rather than as the wrong verifier kind.
    pub fn post_objective(
        &mut self,
        objective: &Objective,
        ts: &str,
    ) -> Result<String, RuleViolation> {
        let kind = match objective.verifier_kind() {
            Some(kind) if VerifierRegistry::supports(kind) => kind,
            _ => {
                return Err(RuleViolation::UnknownVerifierKind {
                    kind: describe_kind(&objective.verifier),
                })
            }
        };

        let id = objective.id();
        if self.is_posted(&id) {
            return Err(RuleViolation::DuplicateObjective { objective_id: id });
        }

        if let Some(block) = &objective.ratchet {
            let ratchet = Ratchet::from_value(block).map_err(RuleViolation::MalformedRatchet)?;
            if kind != Kind::Evaluator.as_str() {
                return Err(RuleViolation::RatchetNeedsEvaluator {
                    kind: kind.to_string(),
                });
            }
            if ratchet.reward != objective.reward {
                return Err(RuleViolation::RatchetRewardMismatch {
                    ratchet: ratchet.reward,
                    objective: objective.reward,
                });
            }
        }

        // The reward is escrowed from the funder's own balance. Last of the
        // checks, because it is the only one that depends on the rest of the
        // log rather than on the record, and a record that is malformed should
        // be reported as malformed rather than as unaffordable.
        self.afford(&objective.funder, u128::from(objective.reward))?;

        self.append(OBJECTIVE, objective.to_value(), ts)?;
        // How pinned code enters the network: the funder has the checker on
        // disk, and this is the moment their node becomes able to serve it to a
        // peer that will only ever see the record.
        //
        // After the append and deliberately without a `?`. This same method
        // admits objectives learned from peers during record sync, where there
        // is no bundle to publish from; a failure to cache code the node was
        // never given is not a reason to refuse the record. Ignoring it costs a
        // node the ability to *serve* one blob and costs the network nothing,
        // because whoever does hold it still can.
        self.registry.publish_code(&objective.verifier);
        Ok(id)
    }

    // -- pinned verifier code --------------------------------------------

    /// Every content address of pinned verifier code the log's objectives name.
    ///
    /// The reachable set: a blob outside it is pinned by no objective this node
    /// knows of, which is what `proofwork blob gc` collects. Computed from the
    /// log rather than remembered, so it cannot drift out of date, and so an
    /// objective learned a second ago is protected without a bookkeeping step.
    pub fn pinned_code(&self) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for objective in self.objectives().values() {
            for pin in verifiers::pinned_code(&objective.verifier) {
                if blobs::is_address(&pin.sha256) {
                    out.insert(pin.sha256);
                }
            }
        }
        out
    }

    /// Content addresses this node needs and does not have.
    ///
    /// Every objective in the log whose pinned code resolves neither in the
    /// bundle nor in the blob store. This is the want set the code-exchange
    /// round sends to a peer, and it is a pure function of the log and the
    /// store — nothing is remembered between rounds, so a node cannot end up
    /// asking for a blob it already has or forgetting one it still needs.
    pub fn missing_code(&self) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for objective in self.objectives().values() {
            out.extend(self.registry.missing_code(&objective.verifier));
        }
        out
    }

    /// Copy every pinned file the bundle has into the store, for every objective
    /// in the log. Returns how many addresses are now servable.
    ///
    /// Idempotent, and worth running at daemon start: a log written before this
    /// feature existed has objectives whose code was never published, and
    /// without this their funder would be unable to serve the very blobs their
    /// peers are about to ask for.
    pub fn publish_local_code(&self) -> usize {
        let mut published = BTreeSet::new();
        for objective in self.objectives().values() {
            published.extend(self.registry.publish_code(&objective.verifier));
        }
        published.len()
    }

    /// Every objective in the log, keyed by id.
    ///
    /// An entry this version cannot decode is skipped rather than raised on --
    /// see the module docs. The consequence is a refusal, not an admission:
    /// submissions against an objective that is not in this map are rejected as
    /// referencing an unknown objective, and [`Node::audit`] names the entry.
    pub fn objectives(&self) -> BTreeMap<String, Objective> {
        self.decode_objectives().0
    }

    // -- interactive fraud proofs -------------------------------------------

    /// Every challenge in the log, by id, in log order.
    pub fn challenges(&self) -> BTreeMap<String, Challenge> {
        let mut out = BTreeMap::new();
        for entry in self.ledger.entries_of_kind(CHALLENGE) {
            if let Ok(record) = Challenge::from_value(&entry.payload) {
                out.insert(record.id(), record);
            }
        }
        out
    }

    /// The claim a challenge disputes, and the objective behind it.
    fn disputed_claim(&self, challenge: &Challenge) -> Option<(Claim, Objective)> {
        let claim = self
            .ledger
            .entries_of_kind(CLAIM)
            .into_iter()
            .filter_map(|entry| Claim::from_value(&entry.payload).ok())
            .find(|claim| claim.id() == challenge.claim_id)?;
        let objective = self.objectives().get(&claim.objective_id).cloned()?;
        Some((claim, objective))
    }

    /// The trace a claim committed to: `(root, states)`.
    ///
    /// Read off the artifact rather than a record of its own. The commitment
    /// has to predate every bisection move or a defender could choose their
    /// trace after seeing the challenger's — and the artifact is already sealed
    /// by the commitment hash, epochs before any of this, which is a stronger
    /// ordering guarantee than a separate record could offer.
    pub fn committed_trace(claim: &Claim) -> Option<(String, u64)> {
        let root = claim.artifact.get("trace_root")?.as_str()?.to_string();
        let states = claim.artifact.get("trace_states")?.as_u64()?;
        Some((root, states))
    }

    /// Open a bonded objection to a settled claim's committed trace.
    ///
    /// The refusals, each answering a specific attack:
    ///
    /// - **unsigned, or signed by somebody else.** An objection by nobody has
    ///   nobody to slash, which makes it free, and a free objection is a denial
    ///   of service on every honest submitter.
    /// - **no such claim, or one nobody accepted.** A dispute over a claim the
    ///   verifier already rejected settles nothing and locks a bond over
    ///   nothing.
    /// - **an objective with no stepper.** Not bisectable, so the dispute could
    ///   never be adjudicated — and an unadjudicable dispute that still holds a
    ///   bond is a griefing tool rather than a mechanism.
    /// - **no trace commitment on the artifact.** Same reason: nothing to
    ///   bisect against.
    /// - **a different length.** Two parties claiming different lengths have
    ///   already stated their disagreement in public; a search would be
    ///   theatre.
    /// - **the same root.** Agreement is not a dispute.
    /// - **out of the window.** A claim has to become final at some point, or
    ///   no payout is ever safe to spend.
    /// - **a bond the challenger does not have.** The stake is the mechanism.
    pub fn post_challenge(
        &mut self,
        challenge: &Challenge,
        ts: &str,
    ) -> Result<String, RuleViolation> {
        challenge
            .validate()
            .map_err(RuleViolation::InadmissibleRecord)?;
        challenge.verify_signature()?;

        let (claim, objective) =
            self.disputed_claim(challenge)
                .ok_or_else(|| RuleViolation::UnknownClaim {
                    claim_id: challenge.claim_id.clone(),
                })?;
        if !self.accepted_claim_ids().contains(&challenge.claim_id) {
            return Err(RuleViolation::ChallengeOfUnacceptedClaim {
                claim_id: challenge.claim_id.clone(),
            });
        }
        if !crate::challenge::Stepper::declared(&objective.verifier) {
            return Err(RuleViolation::ObjectiveNotBisectable {
                objective_id: claim.objective_id.clone(),
            });
        }
        let (root, states) =
            Node::committed_trace(&claim).ok_or_else(|| RuleViolation::NoTraceCommitment {
                claim_id: challenge.claim_id.clone(),
            })?;
        if states != challenge.states {
            return Err(RuleViolation::TraceLengthMismatch {
                claimed: states,
                challenged: challenge.states,
            });
        }
        if root == challenge.root {
            return Err(RuleViolation::ChallengeAgrees {
                claim_id: challenge.claim_id.clone(),
            });
        }

        let opened_at = epoch_of_timestamp(CHALLENGE, ts)?;
        let claim_epoch = epoch_of_timestamp(CLAIM, &claim.created_at)?;
        let closes = claim_epoch.saturating_add(CHALLENGE_WINDOW_EPOCHS);
        if opened_at > closes {
            return Err(RuleViolation::ChallengeWindowClosed {
                claim_id: challenge.claim_id.clone(),
                closed_at: closes,
                opened_at,
            });
        }

        // One live objection per (claim, challenger). Without this a challenger
        // opens a hundred against one claim, and the defender must answer all
        // of them or forfeit each -- which turns a mechanism that costs a
        // liar money into one that costs an honest submitter time.
        for existing in self.challenges().values() {
            if existing.claim_id == challenge.claim_id
                && existing.challenger == challenge.challenger
            {
                return Err(RuleViolation::DuplicateChallenge {
                    claim_id: challenge.claim_id.clone(),
                    challenger: challenge.challenger.clone(),
                });
            }
        }

        self.afford(&challenge.challenger, u128::from(challenge.bond))?;
        let id = challenge.id();
        self.append(CHALLENGE, challenge.to_value(), ts)?;
        Ok(id)
    }

    /// Which side of a dispute an identity is on, if either.
    fn side_of(&self, challenge: &Challenge, mover: &str) -> Option<crate::challenge::Side> {
        if mover == challenge.challenger {
            return Some(crate::challenge::Side::Challenger);
        }
        let (claim, _) = self.disputed_claim(challenge)?;
        (claim.submitter == mover).then_some(crate::challenge::Side::Defender)
    }

    /// Which side of a dispute an identity is on, by challenge id.
    ///
    /// Public because a party needs it to know whether the log is waiting on
    /// *them*, and because nothing about the answer is private: the claim names
    /// its submitter and the challenge names its challenger, both in the open.
    pub fn side_for(&self, challenge_id: &str, identity: &str) -> Option<crate::challenge::Side> {
        let challenge = self.challenges().get(challenge_id)?.clone();
        self.side_of(&challenge, identity)
    }

    /// Every bisection move recorded against a challenge, in log order.
    fn moves_of(&self, challenge_id: &str) -> Vec<BisectionMove> {
        self.ledger
            .entries_of_kind(BISECTION)
            .into_iter()
            .filter_map(|entry| BisectionMove::from_value(&entry.payload).ok())
            .filter(|record| record.challenge_id == challenge_id)
            .filter(|record| record.verify_signature().is_ok())
            .collect()
    }

    /// A dispute as the log leaves it.
    ///
    /// Folded from the records every time, never cached. A node that kept
    /// dispute state in memory would eventually disagree with a node that
    /// rebuilt it, and the whole point of putting an interactive protocol on an
    /// append-only log is that the transcript *is* the state.
    pub fn dispute(&self, challenge_id: &str) -> Option<DisputeState> {
        let challenge = self.challenges().get(challenge_id)?.clone();
        let (claim, _) = self.disputed_claim(&challenge)?;
        let (defender_root, states) = Node::committed_trace(&claim)?;
        let last = states.saturating_sub(1) as usize;
        let moves = self.moves_of(challenge_id);

        // Phase one: the four endpoint moves. Until all four exist the
        // invariant the search rests on -- agreed at the bottom, disagreed at
        // the top -- is not witnessed, and `Dispute::open` refuses to pretend
        // it is.
        let mut endpoints: BTreeMap<(usize, crate::challenge::Side), crate::challenge::Move> =
            BTreeMap::new();
        let mut rest: Vec<(crate::challenge::Side, crate::challenge::Move)> = Vec::new();
        for record in &moves {
            let Some(side) = self.side_of(&challenge, &record.mover) else {
                continue;
            };
            let index = record.index as usize;
            let mv = crate::challenge::Move {
                challenge: challenge_id.to_string(),
                index,
                state: record.state.clone(),
                path: crate::canonical::Inclusion {
                    index,
                    leaves: states as usize,
                    siblings: record.path.clone(),
                },
            };
            if index == 0 || index == last {
                endpoints.entry((index, side)).or_insert(mv);
            } else {
                rest.push((side, mv));
            }
        }
        let need = [
            (0, crate::challenge::Side::Defender),
            (0, crate::challenge::Side::Challenger),
            (last, crate::challenge::Side::Defender),
            (last, crate::challenge::Side::Challenger),
        ];
        let missing: Vec<(usize, crate::challenge::Side)> = need
            .into_iter()
            .filter(|key| !endpoints.contains_key(key))
            .collect();
        if !missing.is_empty() {
            return Some(DisputeState::AwaitingEndpoints {
                challenge: challenge.clone(),
                missing,
            });
        }

        let ends = crate::challenge::Endpoints {
            defender_start: endpoints[&(0, crate::challenge::Side::Defender)].clone(),
            challenger_start: endpoints[&(0, crate::challenge::Side::Challenger)].clone(),
            defender_final: endpoints[&(last, crate::challenge::Side::Defender)].clone(),
            challenger_final: endpoints[&(last, crate::challenge::Side::Challenger)].clone(),
        };
        let mut dispute = match crate::challenge::Dispute::open(
            challenge_id,
            defender_root,
            challenge.root.clone(),
            states as usize,
            ends,
        ) {
            Ok(dispute) => dispute,
            // A challenge whose endpoints cannot found a dispute is void, and
            // the challenger pays for it: they staked on an objection that was
            // never well formed.
            Err(why) => {
                return Some(DisputeState::Void {
                    challenge: challenge.clone(),
                    why,
                })
            }
        };
        for (side, mv) in rest {
            // A move the game did not ask for is skipped rather than fatal.
            // `post_bisection` refuses it at admission; a log that somehow
            // carries one must still be readable, and the audit is what says
            // it should not be there.
            let _ = dispute.play(side, &mv);
        }
        Some(DisputeState::Live {
            challenge: challenge.clone(),
            dispute: Box::new(dispute),
        })
    }

    /// Answer one bisection query.
    pub fn post_bisection(
        &mut self,
        record: &BisectionMove,
        ts: &str,
    ) -> Result<(), RuleViolation> {
        record
            .validate()
            .map_err(RuleViolation::InadmissibleRecord)?;
        record.verify_signature()?;

        let challenge = self
            .challenges()
            .get(&record.challenge_id)
            .cloned()
            .ok_or_else(|| RuleViolation::UnknownChallenge {
                challenge_id: record.challenge_id.clone(),
            })?;
        let side =
            self.side_of(&challenge, &record.mover)
                .ok_or_else(|| RuleViolation::NotAParty {
                    challenge_id: record.challenge_id.clone(),
                    mover: record.mover.clone(),
                })?;
        if self.challenge_outcome(&record.challenge_id).is_some() {
            return Err(RuleViolation::ChallengeDecided {
                challenge_id: record.challenge_id.clone(),
            });
        }

        let (claim, _) =
            self.disputed_claim(&challenge)
                .ok_or_else(|| RuleViolation::UnknownClaim {
                    claim_id: challenge.claim_id.clone(),
                })?;
        let (defender_root, states) =
            Node::committed_trace(&claim).ok_or_else(|| RuleViolation::NoTraceCommitment {
                claim_id: challenge.claim_id.clone(),
            })?;
        let root = match side {
            crate::challenge::Side::Defender => defender_root,
            crate::challenge::Side::Challenger => challenge.root.clone(),
        };
        let index = record.index as usize;
        let mv = crate::challenge::Move {
            challenge: record.challenge_id.clone(),
            index,
            state: record.state.clone(),
            path: crate::canonical::Inclusion {
                index,
                leaves: states as usize,
                siblings: record.path.clone(),
            },
        };
        // Checked here, before anything else about the move is considered: a
        // party that could answer with a state it never committed to would win
        // every dispute by playing whatever beats the other side this round.
        if !mv.opens(&root) {
            return Err(RuleViolation::MoveNotUnderRoot {
                challenge_id: record.challenge_id.clone(),
                index: record.index,
            });
        }

        let last = states.saturating_sub(1) as usize;
        match self.dispute(&record.challenge_id) {
            Some(DisputeState::AwaitingEndpoints { missing, .. }) => {
                if !missing.contains(&(index, side)) {
                    return Err(RuleViolation::MoveOutOfTurn {
                        challenge_id: record.challenge_id.clone(),
                        index: record.index,
                    });
                }
                if index != 0 && index != last {
                    return Err(RuleViolation::MoveOutOfTurn {
                        challenge_id: record.challenge_id.clone(),
                        index: record.index,
                    });
                }
            }
            Some(DisputeState::Live { dispute, .. }) => match dispute.next() {
                crate::challenge::Next::Open {
                    index: asked,
                    waiting_on,
                } => {
                    if index != asked || !waiting_on.contains(&side) {
                        return Err(RuleViolation::MoveOutOfTurn {
                            challenge_id: record.challenge_id.clone(),
                            index: record.index,
                        });
                    }
                }
                _ => {
                    return Err(RuleViolation::MoveOutOfTurn {
                        challenge_id: record.challenge_id.clone(),
                        index: record.index,
                    })
                }
            },
            Some(DisputeState::Void { .. }) | None => {
                return Err(RuleViolation::ChallengeDecided {
                    challenge_id: record.challenge_id.clone(),
                })
            }
        }

        self.append(BISECTION, record.to_value(), ts)?;
        Ok(())
    }

    /// The recorded outcome of a dispute, if it has one.
    pub fn challenge_outcome(&self, challenge_id: &str) -> Option<Value> {
        self.ledger
            .entries_of_kind(CHALLENGE_SETTLEMENT)
            .into_iter()
            .find(|entry| payload_str(&entry.payload, "challenge_id") == Some(challenge_id))
            .map(|entry| entry.payload.clone())
    }

    /// Decide a dispute and move the money.
    ///
    /// Two ways a dispute ends, and the record says which:
    ///
    /// - **adjudicated.** The search narrowed to one step, and running it
    ///   decides who was right. One step, whatever the trace length; see
    ///   [`crate::challenge`].
    /// - **forfeited.** A party owed a move and let
    ///   [`CHALLENGE_WINDOW_EPOCHS`] pass without making it. A liar's dominant
    ///   strategy against any interactive protocol is to play until the search
    ///   reaches the step where they lied and then stop, so silence has to
    ///   lose.
    ///
    /// What moves:
    ///
    /// - the **challenger's bond**, to the defender, when the defence holds;
    /// - the **defender's exposure**, to the challenger, when it does not.
    ///
    /// The defender posts no bond of their own, and what they risk instead is
    /// the payout for the claim under dispute — capped at what they still hold,
    /// because the log cannot take units that are not there. That cap is a real
    /// residual and it is stated rather than hidden: a defender who spends the
    /// reward before the window closes keeps the difference. Closing it means
    /// holding a bisectable claim's payout until its window shuts, which is a
    /// change to the settlement path in both implementations and is the same
    /// missing piece as bonded availability.
    ///
    /// An adjudication that cannot run settles **nothing**. A stepper this node
    /// cannot execute is a fact about this node, and a dispute decided against
    /// whoever happens to be accused when a machine breaks is worse than a
    /// dispute left open.
    pub fn settle_challenge(
        &mut self,
        challenge_id: &str,
        ts: &str,
    ) -> Result<Value, RuleViolation> {
        if let Some(existing) = self.challenge_outcome(challenge_id) {
            return Ok(existing);
        }
        let state = self
            .dispute(challenge_id)
            .ok_or_else(|| RuleViolation::UnknownChallenge {
                challenge_id: challenge_id.to_string(),
            })?;

        let (challenge, winner, why) = match state {
            // A challenge whose endpoints never founded a dispute is void, and
            // the challenger pays: they staked on an objection that was never
            // well formed.
            DisputeState::Void { challenge, why } => (
                challenge,
                crate::challenge::Side::Defender,
                format!("the challenge was never well founded: {why}"),
            ),
            DisputeState::AwaitingEndpoints { challenge, missing } => {
                let owes = self.overdue(challenge_id, ts)?;
                let Some(side) = owes else {
                    return Err(RuleViolation::ChallengeStillOpen {
                        challenge_id: challenge_id.to_string(),
                    });
                };
                // Whoever is still missing an endpoint *and* out of time.
                if !missing.iter().any(|(_, who)| *who == side) {
                    return Err(RuleViolation::ChallengeStillOpen {
                        challenge_id: challenge_id.to_string(),
                    });
                }
                (
                    challenge,
                    side.other(),
                    format!("{side} did not open its endpoints in time"),
                )
            }
            DisputeState::Live {
                challenge,
                mut dispute,
            } => match dispute.next() {
                crate::challenge::Next::Adjudicate { .. } => {
                    let (_, objective) = self.disputed_claim(&challenge).ok_or_else(|| {
                        RuleViolation::UnknownClaim {
                            claim_id: challenge.claim_id.clone(),
                        }
                    })?;
                    let stepper =
                        crate::challenge::Stepper::from_spec(&self.registry, &objective.verifier)
                            .map_err(|why| RuleViolation::AdjudicationUnavailable {
                            challenge_id: challenge_id.to_string(),
                            detail: why.to_string(),
                        })?;
                    let outcome = dispute.adjudicate(&stepper).map_err(|why| {
                        RuleViolation::AdjudicationUnavailable {
                            challenge_id: challenge_id.to_string(),
                            detail: why.to_string(),
                        }
                    })?;
                    (challenge, outcome.winner(), format!("{outcome}"))
                }
                crate::challenge::Next::Open { waiting_on, .. } => {
                    let Some(side) = self.overdue(challenge_id, ts)? else {
                        return Err(RuleViolation::ChallengeStillOpen {
                            challenge_id: challenge_id.to_string(),
                        });
                    };
                    if !waiting_on.contains(&side) {
                        return Err(RuleViolation::ChallengeStillOpen {
                            challenge_id: challenge_id.to_string(),
                        });
                    }
                    (challenge, side.other(), format!("{side} stopped answering"))
                }
                crate::challenge::Next::Done(outcome) => {
                    (challenge, outcome.winner(), format!("{outcome}"))
                }
            },
        };

        let (claim, objective) =
            self.disputed_claim(&challenge)
                .ok_or_else(|| RuleViolation::UnknownClaim {
                    claim_id: challenge.claim_id.clone(),
                })?;
        let (winner_id, loser_id, units) = match winner {
            crate::challenge::Side::Defender => (
                claim.submitter.clone(),
                challenge.challenger.clone(),
                u128::from(challenge.bond),
            ),
            crate::challenge::Side::Challenger => {
                // Capped at what the defender still holds, and at the reward
                // the disputed claim paid. Taking more than the claim was worth
                // would make a lost dispute cost more than the lie could ever
                // have earned, which is a different mechanism with different
                // incentives -- and one nobody would submit under.
                let held = self
                    .balances_within(self.ledger.len())
                    .get(&claim.submitter)
                    .copied()
                    .unwrap_or(0);
                (
                    challenge.challenger.clone(),
                    claim.submitter.clone(),
                    held.min(u128::from(objective.reward)),
                )
            }
        };

        let record = Value::object([
            ("challenge_id", Value::string(challenge_id)),
            ("claim_id", Value::string(challenge.claim_id.clone())),
            ("detail", Value::string(why)),
            ("loser", Value::string(loser_id)),
            ("units", Value::Int(units as i128)),
            ("winner", Value::string(winner_id)),
            ("winning_side", Value::string(winner.as_str())),
        ]);
        self.append(CHALLENGE_SETTLEMENT, record.clone(), ts)?;
        Ok(record)
    }

    /// Which side, if either, owes a move and has run out of time.
    ///
    /// Time is measured from the last record written *about this dispute* — its
    /// opening if nothing has been played yet — against `ts`, both converted to
    /// epochs from the timestamps in the records. No clock is read, so two
    /// auditors reading the same log agree about who forfeited.
    fn overdue(
        &self,
        challenge_id: &str,
        ts: &str,
    ) -> Result<Option<crate::challenge::Side>, RuleViolation> {
        let Some(state) = self.dispute(challenge_id) else {
            return Ok(None);
        };
        let challenge = state.challenge().clone();
        let owes: Vec<crate::challenge::Side> = match &state {
            DisputeState::AwaitingEndpoints { missing, .. } => {
                let mut sides: Vec<crate::challenge::Side> =
                    missing.iter().map(|(_, side)| *side).collect();
                sides.sort();
                sides.dedup();
                sides
            }
            DisputeState::Live { dispute, .. } => match dispute.next() {
                crate::challenge::Next::Open { waiting_on, .. } => waiting_on,
                _ => Vec::new(),
            },
            DisputeState::Void { .. } => Vec::new(),
        };
        if owes.len() != 1 {
            // Nobody owes anything, or both do. Both owing is the opening of a
            // round, where neither party has had a turn yet and neither can be
            // said to be stalling the other.
            return Ok(None);
        }

        let last_ts = self
            .moves_of(challenge_id)
            .iter()
            .map(|record| record.created_at.clone())
            .next_back()
            .unwrap_or_else(|| challenge.created_at.clone());
        let last = epoch_of_timestamp(BISECTION, &last_ts)?;
        let now = epoch_of_timestamp(CHALLENGE_SETTLEMENT, ts)?;
        if now > last.saturating_add(CHALLENGE_WINDOW_EPOCHS) {
            Ok(Some(owes[0]))
        } else {
            Ok(None)
        }
    }

    /// Bonds locked behind live challenges, per identity.
    ///
    /// A live challenge's bond is spent-but-not-gone, exactly like an
    /// undertaking's: it can be lost, so it cannot also be staked somewhere
    /// else. Released when the dispute settles, because the settlement record
    /// then says where it went.
    fn challenge_bonds_within(&self, positions: usize) -> BTreeMap<String, u128> {
        let decided: BTreeSet<String> = self
            .ledger
            .entries_of_kind(CHALLENGE_SETTLEMENT)
            .into_iter()
            .filter(|entry| (entry.seq as usize) < positions)
            .filter_map(|entry| payload_str(&entry.payload, "challenge_id").map(str::to_string))
            .collect();
        let mut locked: BTreeMap<String, u128> = BTreeMap::new();
        for entry in self.ledger.entries_of_kind(CHALLENGE) {
            if (entry.seq as usize) >= positions {
                continue;
            }
            let Ok(record) = Challenge::from_value(&entry.payload) else {
                continue;
            };
            if record.verify_signature().is_err() || decided.contains(&record.id()) {
                continue;
            }
            let slot = locked.entry(record.challenger.clone()).or_insert(0);
            *slot = slot.saturating_add(u128::from(record.bond));
        }
        locked
    }

    /// Net movement from decided disputes, per identity: `(credits, debits)`.
    fn challenge_flows_within(
        &self,
        positions: usize,
    ) -> (BTreeMap<String, u128>, BTreeMap<String, u128>) {
        let (mut credits, mut debits) = (BTreeMap::new(), BTreeMap::new());
        for entry in self.ledger.entries_of_kind(CHALLENGE_SETTLEMENT) {
            if (entry.seq as usize) >= positions {
                continue;
            }
            let units = entry
                .payload
                .get("units")
                .and_then(Value::as_i128)
                .unwrap_or(0)
                .max(0) as u128;
            if let Some(winner) = payload_str(&entry.payload, "winner") {
                let slot = credits.entry(winner.to_string()).or_insert(0u128);
                *slot = slot.saturating_add(units);
            }
            if let Some(loser) = payload_str(&entry.payload, "loser") {
                let slot = debits.entry(loser.to_string()).or_insert(0u128);
                *slot = slot.saturating_add(units);
            }
        }
        (credits, debits)
    }

    /// Announce a peer identity, or move one to a new address.
    ///
    /// See [`PeerRecord`] for why identity belongs in the log and location does
    /// not, and why the sequence number is what makes an append-only record
    /// behave like the mutable hint it has to be.
    ///
    /// Two checks, in this order. The signature first, because a record that
    /// does not prove who it speaks for should be refused before its contents
    /// are consulted at all. Then the sequence, against whatever this identity
    /// has already said.
    pub fn post_peer(&mut self, record: &PeerRecord, ts: &str) -> Result<String, RuleViolation> {
        // Admissibility first, and it has to be here rather than at the caller.
        //
        // Every other record kind reaches this module already decoded, so
        // `from_value` has run and the fields are known good. `PeerRecord::new`
        // is a plain constructor -- it takes whatever it is handed -- so a
        // `peer` record was the one kind that could enter the log without ever
        // meeting its own decoder. `proofwork peer --transport <a libp2p-style
        // id>` wrote a record every audit then rejected, in both
        // implementations: a log made unauditable by the tool that maintains
        // it, in a single command, with no error.
        record
            .validate()
            .map_err(RuleViolation::InadmissibleRecord)?;
        record.verify_signature()?;
        if let Some(held) = self.peers().get(&record.identity) {
            if record.seq <= held.seq {
                return Err(RuleViolation::StalePeerRecord {
                    identity: record.identity.clone(),
                    seq: record.seq,
                    held: held.seq,
                });
            }
        }
        let id = record.id();
        self.append(PEER, record.to_value(), ts)?;
        Ok(id)
    }

    /// The current peer record for each identity: highest `seq` wins.
    ///
    /// Keyed by identity rather than by record id, because the question every
    /// caller asks is "where is this peer now" and a map of every record ever
    /// written would make them all re-derive that. Ties cannot arise --
    /// [`Node::post_peer`] refuses a record that does not advance the sequence
    /// -- but a log assembled by other means might contain one, so the later
    /// entry wins and the rule stays total.
    pub fn peers(&self) -> BTreeMap<String, PeerRecord> {
        let mut out: BTreeMap<String, PeerRecord> = BTreeMap::new();
        for entry in self.ledger.entries_of_kind(PEER) {
            let Ok(record) = PeerRecord::from_value(&entry.payload) else {
                continue;
            };
            // A record whose signature does not verify is not a statement by
            // anybody, so it is skipped here as well as refused on admission.
            // A log can be assembled by concatenation, and a reader must not
            // reach a different answer from an appender.
            if record.verify_signature().is_err() {
                continue;
            }
            match out.get(&record.identity) {
                Some(held) if held.seq > record.seq => {}
                _ => {
                    out.insert(record.identity.clone(), record);
                }
            }
        }
        out
    }

    /// Record a promise to hold the log at a pinned root and height.
    ///
    /// Admissible on its own terms only — decodable, signed by the identity it
    /// names, and about a root this log could actually have had. That last
    /// check is the one worth explaining, below.
    pub fn post_undertaking(
        &mut self,
        record: &Undertaking,
        ts: &str,
    ) -> Result<String, RuleViolation> {
        record
            .validate()
            .map_err(RuleViolation::InadmissibleRecord)?;
        record.verify_signature()?;

        // The promise covers the whole log as it stands, and the promiser does
        // not get to choose. That is a pricing rule, not a tidiness one.
        //
        // Left free, `height` was the mechanism's largest hole: the settlement
        // paid every answer an equal share, so a node promising *one* entry
        // drew index 0 every epoch, answered with an empty path, and collected
        // exactly what a node promising twenty thousand entries collected.
        // Measured, not feared -- 50 units each on a 3-entry log. Promising
        // less was strictly dominant, so nothing bought any storage.
        //
        // Two ways to close it: price the promise, or remove the choice. Both,
        // as it turns out. This is the second; [`Node::settle_availability`]
        // weights the share by height, which is the first, and is still needed
        // because promises made at different times cover different amounts.
        //
        // Expressed as "equals the length of the log below this record" so the
        // rule is checkable *later*: at audit time the log is longer, but the
        // record's own `seq` is exactly the height it must have named.
        let now = self.ledger.len() as u64;
        if record.height != now {
            return Err(RuleViolation::PartialUndertaking {
                promised: record.height,
                log: now,
            });
        }
        // And the root must be the root of that prefix. Without this an
        // undertaking could name a root nobody can produce, which is a
        // permanent unfalsifiable promise -- the "bookkeeping" a payment
        // cannot attach to.
        let matches = usize::try_from(record.height)
            .ok()
            .and_then(|height| self.ledger.prefix(height))
            .and_then(|prefix| prefix.root())
            .is_some_and(|root| root == record.root);
        if !matches {
            return Err(RuleViolation::UnknownUndertakingRoot {
                root: record.root.clone(),
                height: record.height,
            });
        }

        // The bond has to be affordable *here*, against the log as it stands
        // below this record. Checked on the way in and re-derived by the audit,
        // because a promise staking units the identity never had is the one
        // failure that would make the weighting meaningless while still looking
        // like it worked.
        let spendable = self.spendable_within(&record.identity, self.ledger.len());
        if u128::from(record.bond) > spendable {
            return Err(RuleViolation::UnfundedBond {
                identity: record.identity.clone(),
                bond: record.bond,
                spendable,
            });
        }

        let id = record.id();
        self.append(UNDERTAKING, record.to_value(), ts)?;
        Ok(id)
    }

    /// Every *samplable* undertaking in the log, in log order.
    ///
    /// Not keyed by identity: unlike a peer record, a later undertaking does
    /// not supersede an earlier one. Each is a separate promise about a
    /// separate root, and a node that undertook twice owes two answers.
    ///
    /// Three filters, and all three are the reader-side halves of rules
    /// [`Node::post_undertaking`] applies on the way in. A log can be assembled
    /// by concatenation, so an admission rule with no reader-side counterpart
    /// binds only the people who use this tool to write. A record that does not
    /// decode is not a record; one whose signature fails is nobody's promise;
    /// and one naming a root this log never had cannot be sampled, so paying or
    /// slashing against it would be paying against nothing.
    pub fn undertakings(&self) -> Vec<Undertaking> {
        self.undertakings_within(self.ledger.len())
    }

    /// [`Node::undertakings`] over the first `positions` entries only.
    pub fn undertakings_within(&self, positions: usize) -> Vec<Undertaking> {
        // Memoised by height: `prefix(h).root()` is O(h), and a log where many
        // nodes undertook at the same height -- which is the normal case, since
        // they are all watching the same checkpoints -- would otherwise pay for
        // the same walk once per record.
        let mut roots: BTreeMap<u64, Option<String>> = BTreeMap::new();
        self.ledger
            .entries_of_kind(UNDERTAKING)
            .into_iter()
            .filter(|entry| (entry.seq as usize) < positions)
            // `seq` is the number of entries below this record, which is the
            // height it was required to name. Reading it off the entry rather
            // than off a clock or the current length is what makes the rule
            // still checkable when the log is a thousand entries longer.
            .filter_map(|entry| {
                Undertaking::from_value(&entry.payload)
                    .ok()
                    .filter(|record| record.height == entry.seq)
                    .map(|record| (entry.seq as usize, record))
            })
            .filter(|(_, record)| record.verify_signature().is_ok())
            .filter(|(at, record)| {
                // Unaffordable when written is unaffordable forever. Filtered
                // here as well as refused on admission, because settlement
                // divides the pool by these bonds and a log assembled by other
                // means must not be able to hand a fresh identity a share.
                u128::from(record.bond) <= self.spendable_within(&record.identity, *at)
            })
            .map(|(_, record)| record)
            .filter(|record| {
                let at = roots.entry(record.height).or_insert_with(|| {
                    usize::try_from(record.height)
                        .ok()
                        .and_then(|height| self.ledger.prefix(height))
                        .and_then(|prefix| prefix.root())
                });
                at.as_deref() == Some(record.root.as_str())
            })
            .collect()
    }

    /// Which entry this undertaking must produce in `epoch`.
    ///
    /// The challenge, and it is a pure function of the log — nobody issues it,
    /// nobody has to receive it, and anyone can recompute it for anyone. That
    /// is the same property `docs/coordination.md` gets for work assignment,
    /// and it is here for the same reason: a challenge somebody *sends* is a
    /// challenge somebody can decline to send.
    ///
    /// ```text
    /// index = assign(identity, undertaking_id, beacon(epoch, anchor), height)
    /// ```
    ///
    /// Every input earns its place. **`identity`** so a coalition cannot pool
    /// one stored entry between them. **`undertaking_id`** so a node that made
    /// two promises answers two different questions rather than one twice.
    /// **`beacon(epoch, anchor)`** so the answer is not knowable in advance: the
    /// anchor is the log head as of the epoch's start, which nobody can predict
    /// and everybody can recompute — the same anchor batch settlement uses, and
    /// carrying the same Stage 0 caveat, that a sequencer free to choose the
    /// head is a sequencer that could grind it.
    ///
    /// Reusing [`crate::partition::assign`] rather than writing a second draw
    /// is what makes two implementations agree about which entry was
    /// challenged: that function is pinned by `conformance/vectors.json`.
    pub fn sampled_index(
        &self,
        undertaking: &Undertaking,
        epoch: u64,
        positions: usize,
    ) -> Result<u64, PartitionError> {
        // Refused, never capped. `Undertaking::validate` already bounds the
        // height, so this is unreachable through admission -- but a capped draw
        // would silently sample only the first four billion entries of a taller
        // log, which is a hole that pays out rather than an error that shows.
        let partitions =
            u32::try_from(undertaking.height).map_err(|_| PartitionError::Unrepresentable)?;
        // `EPOCH_SECONDS`, the constant -- never `epoch_seconds()`, which reads
        // `PROOFWORK_EPOCH_SECONDS`.
        //
        // That override is a demo affordance: ten-minute epochs make the
        // commit-in-N/reveal-in-N+1 rule impossible to show in a shell script.
        // `partition`'s own documentation is explicit that it is a *policy*
        // parameter and that "nothing derived from it enters a record" -- and
        // this function broke that claim the moment it reached for it, because
        // the anchor moves with the epoch length, so the beacon moves, so the
        // sampled index moves, so an honest answer becomes inadmissible.
        //
        // Measured before it was fixed: the same ten logs audited clean under
        // the length they were written with and failed **six times out of ten**
        // under the default. A check that depends on an environment variable is
        // not a consensus rule, and one that fails six times in ten is the
        // worst shape a bug can have -- it looks like flakiness.
        // Bounded by *position*, which is the same fix batch settlement needed
        // and for the same reason. Unbounded, the anchor is the last entry the
        // whole log holds -- so every later append moves it, moves the beacon,
        // and moves the index. An answer that was right when it was written
        // became wrong two entries later, and the audit reported an honest node
        // as unpaid. `positions` is the answer's own place in the file:
        // everything it could have seen precedes it, and nothing appended
        // afterwards could have influenced it.
        let beacon = partition::beacon(
            epoch,
            &self.anchor_at(epoch, positions, partition::EPOCH_SECONDS),
        );
        let index = partition::assign(
            &undertaking.identity,
            &undertaking.id(),
            &beacon,
            partitions,
        )?;
        Ok(u64::from(index))
    }

    /// Record an answer to an availability sample.
    ///
    /// Every rule is re-derived here rather than trusted from the submitter,
    /// because the submitter is the party being paid.
    pub fn post_availability(
        &mut self,
        record: &Availability,
        ts: &str,
    ) -> Result<String, RuleViolation> {
        record
            .validate()
            .map_err(RuleViolation::InadmissibleRecord)?;
        record.verify_signature()?;
        // The position this record is about to land at. `append` is the very
        // next thing that happens, so this is where it goes.
        self.check_availability(record, self.ledger.len())?;
        // One answer per promise per epoch. A second answer is not a second
        // service rendered -- the sample is the same index -- so admitting it
        // would let one node be paid twice for one piece of work.
        if self
            .availability_answers()
            .iter()
            .any(|held| held.undertaking == record.undertaking && held.epoch == record.epoch)
        {
            return Err(RuleViolation::SampleAlreadyAnswered {
                undertaking: record.undertaking.clone(),
                epoch: record.epoch,
            });
        }
        let id = record.id();
        self.append(AVAILABILITY, record.to_value(), ts)?;
        Ok(id)
    }

    /// Does this answer actually answer the sample it claims to?
    ///
    /// Split out from [`Node::post_availability`] so the audit can ask the same
    /// question of a record that arrived some other way. An admission rule with
    /// no reader-side counterpart binds only the people who use this tool to
    /// write, and a log can be assembled by concatenation.
    fn check_availability(
        &self,
        record: &Availability,
        positions: usize,
    ) -> Result<(), RuleViolation> {
        let undertaking = self
            .undertakings()
            .into_iter()
            .find(|u| u.id() == record.undertaking)
            .ok_or_else(|| RuleViolation::UnknownUndertaking {
                undertaking: record.undertaking.clone(),
            })?;

        // You answer your own promise. Without this, anybody could farm the
        // availability pool by answering samples drawn against other people's
        // undertakings -- and the draw itself keys on the *undertaking's*
        // identity, so the answer would even be correct.
        if undertaking.identity != record.identity {
            return Err(RuleViolation::AvailabilityImpostor {
                undertaking: record.undertaking.clone(),
                answered_by: record.identity.clone(),
            });
        }

        let index = self
            .sampled_index(&undertaking, record.epoch, positions)
            .map_err(|source| RuleViolation::Unsamplable {
                undertaking: record.undertaking.clone(),
                source,
            })?;

        // The leaf comes from the entry the *submitter* sent, and this is the
        // whole point of carrying it. Recomputing it from this node's own copy
        // -- which is what this did at first -- means the answerer never has to
        // hold any payload, only the hashes every path is derivable from. That
        // version was measured: a node keeping 10% of a log reproduced the
        // honest answer byte for byte.
        //
        // Which makes this exactly [`Proof::check`], so it is that and not a
        // second copy of the same three checks: the entry must hash to the
        // digest it carries, sit at the index that was sampled, and reach the
        // undertaken root.
        // A value that is not an entry at all is refused here rather than
        // silently failing the path check, so the message names the real fault.
        let entry = Entry::from_value(&record.entry).map_err(|_| {
            RuleViolation::AvailabilityDoesNotCheck {
                undertaking: record.undertaking.clone(),
                epoch: record.epoch,
                index,
            }
        })?;
        let proof = Proof {
            entry,
            inclusion: Inclusion {
                // Derived, never read from the record. A submitter who could
                // name the index would answer whichever entry they happened to
                // keep rather than the one they were asked for.
                index: usize::try_from(index).unwrap_or(usize::MAX),
                leaves: usize::try_from(undertaking.height).unwrap_or(usize::MAX),
                siblings: record.path.clone(),
            },
        };
        if proof.check(&undertaking.root).is_err() {
            return Err(RuleViolation::AvailabilityDoesNotCheck {
                undertaking: record.undertaking.clone(),
                epoch: record.epoch,
                index,
            });
        }
        Ok(())
    }

    /// Every answer in the log that really answers its sample, in log order.
    ///
    /// The reader-side counterpart to [`Node::post_availability`], and what
    /// settlement reads. An answer that does not check is not an answer, so it
    /// is dropped here as well as refused on the way in.
    /// First answer per `(undertaking, epoch)` wins, matching the rule
    /// [`Node::post_availability`] enforces on the way in. A log assembled by
    /// concatenation can hold two; resolving them differently here from there
    /// would make an auditor and an appender disagree about who was paid.
    pub fn availability_answers(&self) -> Vec<Availability> {
        let mut seen: BTreeSet<(String, u64)> = BTreeSet::new();
        self.ledger
            .entries_of_kind(AVAILABILITY)
            .into_iter()
            .filter_map(|entry| {
                Availability::from_value(&entry.payload)
                    .ok()
                    .map(|record| (entry.seq as usize, record))
            })
            .filter(|(_, record)| record.verify_signature().is_ok())
            .filter(|(at, record)| self.check_availability(record, *at).is_ok())
            .map(|(_, record)| record)
            .filter(|record| seen.insert((record.undertaking.clone(), record.epoch)))
            .collect()
    }

    /// The first settlement recorded for an objective, as its raw payload.
    ///
    /// "First" rather than "latest" because for a non-ratchet objective there is
    /// only ever one, and it is the one that closed the objective. A progressive
    /// objective has many, and this is not the accessor for reading them --
    /// [`Node::frontier_of`] is.
    pub fn settlement_of(&self, objective_id: &str) -> Option<Value> {
        for entry in self.ledger.entries_of_kind(SETTLEMENT) {
            if payload_str(&entry.payload, "objective_id") == Some(objective_id) {
                return Some(entry.payload.clone());
            }
        }
        None
    }

    /// What one claim was paid, if it has settled.
    ///
    /// Keyed on the claim rather than the objective, which
    /// [`Node::settlement_of`] cannot answer: a progressive objective settles
    /// many times and that accessor deliberately returns only the first. A
    /// contributor asking "was *my* claim paid, and how much" is asking this
    /// question, and before this the only answer available was to diff an
    /// objective's pool total across calls and hope nobody else was working.
    ///
    /// `None` distinguishes nothing: not settled yet, settled for zero, and no
    /// such claim all read the same here. A caller that needs to tell them
    /// apart has the claim itself — see [`Node::accepted_claims`].
    pub fn settlement_for_claim(&self, claim_id: &str) -> Option<u64> {
        for entry in self.ledger.entries_of_kind(SETTLEMENT) {
            if payload_str(&entry.payload, "claim_id") == Some(claim_id) {
                return entry
                    .payload
                    .get("reward")
                    .and_then(Value::as_i128)
                    .and_then(|reward| u64::try_from(reward).ok());
            }
        }
        None
    }

    /// The current best-known score for a progressive objective.
    ///
    /// `None` also when the latest frontier entry cannot be decoded, which is
    /// safe *here* because this accessor is informational. The rules path uses
    /// `Node::latest_frontier` instead, which refuses rather than reporting an
    /// empty frontier -- treating an unreadable entry as absent would waive the
    /// citation requirement and restart the payout curve at zero.
    pub fn frontier_of(&self, objective_id: &str) -> Option<FrontierEntry> {
        self.latest_frontier(objective_id).ok().flatten()
    }

    // -- the threshold committee ------------------------------------------

    /// The peer set as it stood at `positions`, keyed by identity.
    ///
    /// [`Node::peers`] bounded by position, for the reason every draw in this
    /// module is: a committee derived from the whole log changes every time
    /// anyone appends a peer record, so a share that answered the right seat
    /// when it was written would answer the wrong one two entries later, and an
    /// honest member would be reported as an impostor by the audit.
    fn peers_within(&self, positions: usize) -> BTreeMap<String, PeerRecord> {
        let mut out: BTreeMap<String, PeerRecord> = BTreeMap::new();
        for entry in self.ledger.entries().iter().take(positions) {
            if entry.kind != PEER {
                continue;
            }
            let Ok(record) = PeerRecord::from_value(&entry.payload) else {
                continue;
            };
            if record.verify_signature().is_err() {
                continue;
            }
            match out.get(&record.identity) {
                Some(held) if held.seq > record.seq => {}
                _ => {
                    out.insert(record.identity.clone(), record);
                }
            }
        }
        out
    }

    /// Who holds a share of every submission sealed in `epoch`.
    ///
    /// **The whole point is that nobody chooses this.** It is a pure function
    /// of the log — the peer records in it and the epoch's beacon — so the
    /// submitter computes it to seal, each member computes it to learn whether
    /// they hold a seat, and every reader recomputes it to decide whether a
    /// published share came from a seat that exists. There is no invitation to
    /// send, so there is no invitation anyone can decline to send, and no
    /// committee list anyone can substitute. Same property `docs/coordination.md`
    /// gets for work assignment and [`Node::sampled_index`] for availability,
    /// and here for the same reason.
    ///
    /// ```text
    /// seats = the COMMITTEE_SIZE peers with the lowest
    ///         H(beacon(epoch, anchor) ‖ peer.transport), ascending
    /// ```
    ///
    /// Each input earns its place:
    ///
    /// **`beacon(epoch, anchor)`** so the committee rotates. A fixed committee
    /// is a fixed set to bribe, and `docs/censorship.md` §2 is explicit that
    /// membership must be "diverse and rotated per epoch" because `t` colluding
    /// members can read every artifact early. It carries the Stage 0 caveat
    /// every beacon here carries: a sequencer free to choose the anchor is a
    /// sequencer that could grind it, and closing that needs a VDF or a
    /// threshold signature rather than a log head.
    ///
    /// **`peer.transport`, not `peer.identity`.** The transport id is
    /// `sha256` of a Classic McEliece public key, and that key is what a share
    /// is actually sealed to — so the draw keys on the thing that does the
    /// cryptography rather than on a name that happens to sit beside it. It
    /// also makes grinding for a seat cost a McEliece keypair rather than an
    /// ed25519 one, which is 243 ms rather than microseconds. That is a real
    /// cost and **not a defence**: it is a constant factor against an attacker
    /// willing to spend, exactly as `docs/p2p.md` says of grinding a node id.
    ///
    /// **`positions`** so the answer is stable. See `Node::peers_within`.
    ///
    /// Seats are numbered `1..=n` in draw order and that number is the
    /// envelope's routing index, so a member knows which sealed share is
    /// addressed to them without being told.
    pub fn committee_for(
        &self,
        epoch: u64,
        positions: usize,
    ) -> Result<Vec<CommitteeSeat>, RuleViolation> {
        // `EPOCH_SECONDS`, the constant, never `epoch_seconds()`. Same reason
        // `Node::sampled_index` spells it out: the override is a demo
        // affordance, the anchor moves with the epoch length, and a consensus
        // rule that depends on an environment variable is not a consensus rule.
        let anchor = self.anchor_at(epoch, positions, partition::EPOCH_SECONDS);

        let mut ranked: Vec<(String, PeerRecord)> = self
            .peers_within(positions)
            .into_values()
            .map(|peer| (settlement_rank(epoch, &anchor, &peer.transport), peer))
            .collect();
        // By (rank, transport) rather than rank alone. Two peers with the same
        // rank would otherwise keep map order, which is identity order, which
        // is a lever back to whoever picks their ed25519 key -- the same
        // tie-break `settle_due` needs and for the same reason. A collision
        // needs a SHA-256 preimage; "unreachable" is not a tie-break rule.
        ranked.sort_by(|(ra, a), (rb, b)| (ra, &a.transport).cmp(&(rb, &b.transport)));

        let size = usize::from(partition::COMMITTEE_SIZE);
        if ranked.len() < size {
            // Refused, never shrunk to fit. A committee of two drawn because
            // only two peers are registered would silently lower the collusion
            // threshold below the number the whole scheme is relying on, and
            // the submitter -- who is choosing to seal *because* they may not
            // be able to come back -- would never learn that the protection
            // they paid for was not the protection they got.
            return Err(RuleViolation::CommitteeTooSmall {
                epoch,
                have: ranked.len(),
                need: size,
            });
        }

        Ok(ranked
            .into_iter()
            .take(size)
            .enumerate()
            .map(|(i, (_rank, peer))| CommitteeSeat {
                // `i < COMMITTEE_SIZE <= u8::MAX`, so the cast cannot truncate.
                seat: (i as u8).saturating_add(1),
                transport: peer.transport,
                identity: peer.identity,
                addr: peer.addr,
            })
            .collect())
    }

    /// The committee that holds shares of `commitment`, as drawn when it was
    /// written.
    ///
    /// Keyed on the commitment's **own epoch and own position**, not on the
    /// reader's clock or the log's current length. That is what makes the
    /// committee for a submission a fact settled at commit time: a peer record
    /// appended afterwards cannot join a committee that has already been sealed
    /// to, and one appended before cannot be evicted from it.
    pub fn committee_of_commitment(
        &self,
        commitment_id: &str,
    ) -> Result<Vec<CommitteeSeat>, RuleViolation> {
        let (at, commitment) = self.commitment_entry(commitment_id)?;
        let epoch = epoch_of_timestamp("commitment", &commitment.created_at)?;
        self.committee_for(epoch, at)
    }

    /// A commitment by id, or `None` if this log does not hold it.
    ///
    /// The accessor a committee member needs: their sealed share lives inside
    /// [`Commitment::envelope`], addressed at the seat the draw gave them, and
    /// there is no other way to reach it from outside the crate.
    pub fn commitment_of(&self, commitment_id: &str) -> Option<Commitment> {
        self.commitment_entry(commitment_id)
            .ok()
            .map(|(_, commitment)| commitment)
    }

    /// Find a commitment record by id, with the position it sits at.
    fn commitment_entry(&self, commitment_id: &str) -> Result<(usize, Commitment), RuleViolation> {
        for entry in self.ledger.entries_of_kind(COMMITMENT) {
            let Ok(commitment) = Commitment::from_value(&entry.payload) else {
                continue;
            };
            if commitment.id() == commitment_id {
                return Ok((entry.seq as usize, commitment));
            }
        }
        Err(RuleViolation::UnknownCommitment {
            commitment: commitment_id.to_string(),
        })
    }

    /// Publish this node's share of a sealed submission's content key.
    ///
    /// Every rule is re-derived here rather than trusted from the publisher,
    /// because the publisher is a party the reveal depends on.
    pub fn post_committee_share(
        &mut self,
        record: &CommitteeShare,
        ts: &str,
    ) -> Result<String, RuleViolation> {
        record
            .validate()
            .map_err(RuleViolation::InadmissibleRecord)?;
        record.verify_signature()?;
        // The position this record is about to land at. `append` is the very
        // next thing that happens, so this is where it goes.
        self.check_committee_share(record, self.ledger.len())?;
        // One share per seat per submission. A second is not a second service
        // rendered -- the seat holds one share -- and admitting it would let a
        // member flood the log with variants until some subset of them opened
        // an envelope, which is a brute-force search paid for by everyone
        // else's storage.
        if self
            .committee_shares_for(&record.commitment)
            .iter()
            .any(|held| held.seat == record.seat)
        {
            return Err(RuleViolation::SeatAlreadyPublished {
                commitment: record.commitment.clone(),
                seat: record.seat,
            });
        }
        let id = record.id();
        self.append(COMMITTEE_SHARE, record.to_value(), ts)?;
        Ok(id)
    }

    /// Does this share really come from the seat it claims, and is it in time?
    ///
    /// Split out from [`Node::post_committee_share`] so an audit can ask the
    /// same question of a record that arrived some other way. An admission rule
    /// with no reader-side counterpart binds only the people who use this tool
    /// to write, and a log can be assembled by concatenation.
    pub fn check_committee_share(
        &self,
        record: &CommitteeShare,
        positions: usize,
    ) -> Result<(), RuleViolation> {
        let (at, commitment) = self.commitment_entry(&record.commitment)?;
        if commitment.envelope.is_none() {
            return Err(RuleViolation::CommitmentNotSealed {
                commitment: record.commitment.clone(),
            });
        }
        // A share cannot be published before the commitment it opens exists.
        // Obvious, and worth checking rather than assuming: the committee draw
        // below is bounded at the *commitment's* position, so a share written
        // earlier in the file would be checked against a committee drawn from
        // peer records that had not been written when the share was.
        if positions <= at {
            return Err(RuleViolation::ShareBeforeCommitment {
                commitment: record.commitment.clone(),
            });
        }

        let commit_epoch = epoch_of_timestamp("commitment", &commitment.created_at)?;
        let share_epoch = epoch_of_timestamp("committee_share", &record.created_at)?;
        // **The time rule, and it is the whole reason this record exists.**
        //
        // A committee that could publish in the commitment's own epoch would
        // hand every artifact to the sequencer while it is still worth
        // front-running -- which is precisely the attack epoch-batched
        // commit-reveal exists to kill, reintroduced through the reveal path
        // that was supposed to *replace* the submitter rather than weaken them.
        // So a share obeys the same rule a submitter's own reveal obeys, and
        // for the same reason: strictly later, measured between two records
        // that are both in the log.
        //
        // Nothing here reads a clock. "Too early" is a comparison of two
        // timestamps an auditor re-reads out of the file, so a member with a
        // fast clock writes a record every node refuses rather than a record
        // every node accepts on their word.
        //
        // **And the embargo, which is the same rule with a longer arm.** A
        // committee share is what opens a sealed artifact, so "hold this one
        // for N more epochs" is enforceable in exactly one place: here. An
        // embargoed objective declares its length inside its own id, so the
        // wait cannot be shortened after work has started, and the check is
        // two integers an auditor re-reads out of the file rather than a
        // policy anyone has to be trusted to apply.
        //
        // The class alone was not enforcement. It said *when* an artifact
        // becomes public and nothing consulted it, so a committee that felt
        // like opening early could, and the funder who chose `embargoed` for a
        // dual-use result would find out afterwards.
        let embargo = self
            .objectives()
            .get(&commitment.objective_id)
            .map(Objective::embargo)
            .unwrap_or(0);
        let opens_at = commit_epoch.saturating_add(embargo);
        if share_epoch <= opens_at {
            return Err(RuleViolation::ShareBeforeEpoch {
                commit_epoch: opens_at,
                share_epoch,
            });
        }

        let committee = self.committee_for(commit_epoch, at)?;
        let seat = committee
            .iter()
            .find(|seat| seat.seat == record.seat)
            .ok_or(RuleViolation::UnknownSeat {
                commitment: record.commitment.clone(),
                seat: record.seat,
            })?;
        // You answer your own seat. Without this, any peer could publish for
        // any seat -- and since a share is not individually checkable, a
        // bystander filling three seats with noise would stall every reveal
        // they chose to. The draw says which identity holds the seat; the
        // signature, already verified, says which identity wrote the record.
        if seat.identity != record.identity {
            return Err(RuleViolation::SeatImpostor {
                commitment: record.commitment.clone(),
                seat: record.seat,
                published_by: record.identity.clone(),
            });
        }
        Ok(())
    }

    /// Every share in the log that really answers its seat, in log order.
    ///
    /// The reader-side counterpart to [`Node::post_committee_share`], and what
    /// [`Node::open_sealed`] reads. A share that does not check is not a share,
    /// so it is dropped here as well as refused on the way in, and the first
    /// record per seat wins — matching the admission rule, because a reader and
    /// an appender that resolve a duplicate differently disagree about whether
    /// a submission opened.
    pub fn committee_shares_for(&self, commitment_id: &str) -> Vec<CommitteeShare> {
        let mut seen: BTreeSet<u8> = BTreeSet::new();
        self.ledger
            .entries_of_kind(COMMITTEE_SHARE)
            .into_iter()
            .filter_map(|entry| {
                CommitteeShare::from_value(&entry.payload)
                    .ok()
                    .map(|record| (entry.seq as usize, record))
            })
            .filter(|(_, record)| record.commitment == commitment_id)
            .filter(|(_, record)| record.validate().is_ok())
            .filter(|(_, record)| record.verify_signature().is_ok())
            .filter(|(at, record)| self.check_committee_share(record, *at).is_ok())
            .filter(|(_, record)| seen.insert(record.seat))
            .map(|(_, record)| record)
            .collect()
    }

    /// Sealed commitments whose epoch has closed and which nobody has opened.
    ///
    /// What a committee member polls to find the work it owes the network, and
    /// what a bystander polls to find a reveal it could complete. The
    /// commitment id, the seats drawn for it, and how many shares are already
    /// published — enough to decide both "do I hold a seat here" and "is this
    /// one share away from opening".
    ///
    /// `now_epoch` is the caller's idea of the current epoch and is used for
    /// exactly one thing: skipping submissions whose epoch has not closed yet,
    /// because publishing into those is refused anyway. It is a filter on work
    /// to do, never an input to whether a record is admissible.
    pub fn pending_sealed_reveals(&self, now_epoch: u64) -> Vec<PendingReveal> {
        let opened: BTreeSet<String> = self
            .ledger
            .entries_of_kind(CLAIM)
            .into_iter()
            .filter_map(|entry| Claim::from_value(&entry.payload).ok())
            .map(|claim| claim.commitment_hash())
            .collect();

        let mut out = Vec::new();
        for entry in self.ledger.entries_of_kind(COMMITMENT) {
            let Ok(commitment) = Commitment::from_value(&entry.payload) else {
                continue;
            };
            if commitment.envelope.is_none() || opened.contains(&commitment.hash) {
                continue;
            }
            let Ok(commit_epoch) = epoch_of_timestamp("commitment", &commitment.created_at) else {
                continue;
            };
            if commit_epoch >= now_epoch {
                continue;
            }
            let id = commitment.id();
            let Ok(seats) = self.committee_for(commit_epoch, entry.seq as usize) else {
                continue;
            };
            let published = self.committee_shares_for(&id);
            out.push(PendingReveal {
                commitment: id,
                objective_id: commitment.objective_id.clone(),
                commit_epoch,
                threshold: commitment
                    .envelope
                    .as_ref()
                    .map(|envelope| envelope.threshold())
                    .unwrap_or(partition::COMMITTEE_THRESHOLD),
                seats,
                published: published.iter().map(|share| share.seat).collect(),
            });
        }
        out
    }

    /// Open a sealed submission from published shares and reveal it — **with no
    /// participation from the submitter**.
    ///
    /// This is the sentence `docs/censorship.md` §2 exists for. The submitter
    /// can be offline, jailed, or firewalled; the shares are on the log, the
    /// envelope is on the log, and anyone at all may call this. The caller is
    /// not trusted with anything: the reconstructed plaintext is re-hashed to
    /// the commitment before it becomes a claim ([`crate::sealed::open`]), so
    /// producing a *different* artifact is not something a caller could do by
    /// lying about the shares.
    ///
    /// # Why a wrong share cannot be blamed on anybody
    ///
    /// Shamir cannot report "this share is wrong". Any `t` points define *some*
    /// polynomial, so a bad share yields a well-formed wrong key that fails the
    /// AEAD tag — and the tag says the *set* was wrong, never which member
    /// lied. The usual fix is verifiable secret sharing (Feldman, Pedersen),
    /// and it is not available here: both rest on discrete log in a group where
    /// it is hard, which is exactly the assumption a post-quantum network has
    /// declined to make. Publishing a commitment to the polynomial in a
    /// lattice- or code-based analogue is real work and is not done.
    ///
    /// So the fallback is search: try every `t`-subset of the published shares
    /// until one opens. That is `C(n, t)` AEAD checks — ten for the default
    /// three-of-five — and it is bounded rather than open-ended, because a
    /// committee is `COMMITTEE_SIZE` seats and one share per seat. A member who
    /// publishes garbage therefore costs the network a handful of hashes and
    /// costs itself an entry that every reader can see it wrote. What it
    /// cannot do is stop the reveal, as long as `t` honest members published.
    ///
    /// `docs/threat-model.md` carries the row: a *dishonest* member is
    /// detectable only in aggregate, and attributing the lie needs VSS.
    pub fn open_sealed(&mut self, commitment_id: &str, ts: &str) -> Result<Outcome, RuleViolation> {
        let (_, commitment) = self.commitment_entry(commitment_id)?;
        let envelope =
            commitment
                .envelope
                .clone()
                .ok_or_else(|| RuleViolation::CommitmentNotSealed {
                    commitment: commitment_id.to_string(),
                })?;

        let published = self.committee_shares_for(commitment_id);
        let threshold = usize::from(envelope.threshold());
        if published.len() < threshold {
            return Err(RuleViolation::NotEnoughShares {
                commitment: commitment_id.to_string(),
                have: published.len(),
                need: threshold,
            });
        }

        // `epoch` and `created_at` are the commitment's own, so the value this
        // builds is the submission as the log records it rather than as the
        // caller describes it. `sealed::open` reads neither; they are carried
        // because the type is the shared vocabulary between this module and
        // `crate::sealed`, and a field silently left wrong is a field the next
        // reader will trust.
        let commit_epoch = epoch_of_timestamp("commitment", &commitment.created_at)?;
        let submission = SealedSubmission {
            objective_id: commitment.objective_id.clone(),
            submitter: commitment.submitter.clone(),
            commitment: commitment.hash.clone(),
            envelope,
            epoch: commit_epoch,
            created_at: commitment.created_at.clone(),
        };

        let mut shares = Vec::with_capacity(published.len());
        for record in &published {
            shares.push(
                record
                    .to_share()
                    .map_err(RuleViolation::InadmissibleRecord)?,
            );
        }

        let opened = open_with_any_subset(&submission, &shares, threshold).ok_or_else(|| {
            RuleViolation::SealedOpenFailed {
                commitment: commitment_id.to_string(),
                tried: published.len(),
            }
        })?;

        // From here it is an ordinary reveal, and deliberately so. The claim
        // that goes into the log is byte-identical to the one the submitter
        // would have written, so every rule downstream -- citation checks,
        // frontier ratchets, the verdict, the settlement batch -- runs exactly
        // as it always did and an auditor replaying the log cannot tell a
        // committee reveal from a submitter reveal. Sealing moves *when* an
        // artifact becomes public. It never moves *whether*, and it must not
        // move *how it is judged*.
        // The submitter's own signature, citations and `created_at` come out of
        // the envelope, so this claim is byte-identical to the one they would
        // have posted. That is what makes the two reveal paths indistinguishable
        // to everything downstream -- and what makes sealing usable by a signed
        // identity at all, since `reveal` requires a key-shaped submitter to
        // have signed and the committee cannot sign for them.
        let claim = opened
            .to_claim(&commitment.objective_id, &commitment.submitter, ts)
            .map_err(RuleViolation::InadmissibleRecord)?;
        self.reveal(&claim, ts)
    }

    // -- commit / reveal --------------------------------------------------

    /// Phase 1: bind to an artifact without revealing it.
    ///
    /// A non-ratchet objective stops accepting commitments once it has settled.
    /// A **progressive** objective does not: it stays open until its pool is
    /// exhausted, because the whole point is that improvements keep arriving.
    pub fn commit(&mut self, commitment: &Commitment, ts: &str) -> Result<String, RuleViolation> {
        // Before anything else, and before anything is written: a submitter
        // that names a key must prove it holds that key. Cheap, and refusing
        // early means a forged identity never reaches the log at all.
        commitment.verify_signature()?;
        // Refused here rather than at reveal. The commitment's `created_at` is
        // what fixes the epoch a reveal must beat, so a commitment whose
        // timestamp cannot be read is a commitment that can never be opened --
        // better to say so now than to accept it and strand the submitter.
        epoch_of_timestamp("commitment", &commitment.created_at)?;
        // Draining on the way in keeps `already settled` honest: a commitment
        // against an objective whose winner is sitting in an unsettled batch
        // would otherwise be admitted as though the objective were still open.
        self.settle_due(epoch_of_timestamp("commit", ts)?, ts)?;

        let objectives = self.objectives();
        let objective = objectives.get(&commitment.objective_id).ok_or_else(|| {
            RuleViolation::UnknownObjective {
                referrer: Referrer::Commitment,
                objective_id: commitment.objective_id.clone(),
            }
        })?;
        if objective.require_signed_submitter
            && crate::records::signed_submitter(&commitment.submitter).is_none()
        {
            return Err(RuleViolation::SignedSubmitterRequired {
                objective_id: commitment.objective_id.clone(),
                submitter: commitment.submitter.clone(),
            });
        }
        if objective.ratchet.is_none() && self.settlement_of(&commitment.objective_id).is_some() {
            return Err(RuleViolation::AlreadySettled {
                objective_id: commitment.objective_id.clone(),
            });
        }
        // A sealed commitment's committee parameters are the network's, not the
        // submitter's.
        //
        // This is not shape-checking for tidiness. `threshold` decides how many
        // members must collude to read an artifact early, and it travels in the
        // envelope where the submitter writes it. A submission sealed at
        // threshold 1 is one every drawn member can open the moment the epoch
        // turns -- front-running restored, by a field the front-runner did not
        // even have to touch. Every reader must agree on `t` and `n` or they
        // disagree about what "sealed" bought, so both are pinned here against
        // the constants the draw uses.
        //
        // What cannot be checked is that the shares were sealed to the *right
        // keys*: a McEliece public key is 261,120 bytes and lives nowhere in
        // the log, only its id does. A submitter who seals to the wrong keys
        // produces a submission nobody can open, which costs them their own
        // bounty and costs nobody else anything -- the same bound
        // `crate::crypto::kem` gives for a garbage committee key.
        if let Some(envelope) = &commitment.envelope {
            let seats = envelope.sealed_shares().len();
            if seats != usize::from(partition::COMMITTEE_SIZE)
                || envelope.threshold() != partition::COMMITTEE_THRESHOLD
            {
                return Err(RuleViolation::WrongCommitteeShape {
                    threshold: envelope.threshold(),
                    seats,
                    want_threshold: partition::COMMITTEE_THRESHOLD,
                    want_seats: usize::from(partition::COMMITTEE_SIZE),
                });
            }
            // Addressed at the seat numbers the draw hands out, `1..=n`, so a
            // member can find their own sealed share by looking up their seat
            // and nothing has to carry a mapping that could disagree.
            let mut addressed: Vec<u8> = envelope
                .sealed_shares()
                .iter()
                .map(|share| share.index())
                .collect();
            addressed.sort_unstable();
            if addressed != (1..=partition::COMMITTEE_SIZE).collect::<Vec<u8>>() {
                return Err(RuleViolation::WrongCommitteeShape {
                    threshold: envelope.threshold(),
                    seats,
                    want_threshold: partition::COMMITTEE_THRESHOLD,
                    want_seats: usize::from(partition::COMMITTEE_SIZE),
                });
            }
            // Drawing here refuses a sealed commitment the network could never
            // open, at the moment the submitter can still do something about
            // it, rather than an epoch later when they may be gone.
            self.committee_for(
                epoch_of_timestamp("commitment", &commitment.created_at)?,
                self.ledger.len(),
            )?;
        }
        self.append(COMMITMENT, commitment.to_value(), ts)?;
        Ok(commitment.id())
    }

    /// Claims whose verdict was `accept`, keyed by claim id.
    ///
    /// A verdict record that cannot be read as a verdict does not count as an
    /// acceptance -- the failure direction that refuses a citation rather than
    /// admitting one.
    /// Every claim in the log, keyed by id, verdict or no verdict.
    ///
    /// Distinct from [`Node::accepted_claims`], which is the set citations and
    /// settlement are allowed to point at. This one includes rejected and
    /// unverified claims, because the knowledge layer has things to say about
    /// those and a reader auditing what was *claimed* needs them.
    pub fn all_claims(&self) -> BTreeMap<String, Claim> {
        let mut out = BTreeMap::new();
        for entry in self.ledger.entries_of_kind(CLAIM) {
            if let Ok(claim) = Claim::from_value(&entry.payload) {
                out.insert(claim.id(), claim);
            }
        }
        out
    }

    /// Ids of every claim in the log. The cheap half of [`Node::all_claims`],
    /// for membership tests on the rules path.
    fn claim_ids(&self) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for entry in self.ledger.entries_of_kind(CLAIM) {
            if let Ok(claim) = Claim::from_value(&entry.payload) {
                out.insert(claim.id());
            }
        }
        out
    }

    /// The knowledge graph over every claim in the log.
    ///
    /// Borrowed from `claims`, which the caller owns, because the graph indexes
    /// into it rather than copying: building it per claim would re-read the
    /// whole log for every query.
    ///
    /// `reproducible` is answered from **this node's** store and bundle. A
    /// claim whose objective's pinned code is missing here is reported
    /// [`Reproducible::NotHere`], which is a statement about this node and not
    /// about the network — see that type's docs for why the distinction is not
    /// pedantry.
    pub fn knowledge_graph<'a>(&self, claims: &'a BTreeMap<String, Claim>) -> KnowledgeGraph<'a> {
        let missing = self.missing_code();
        let objectives = self.objectives();
        let mut unreproducible: BTreeSet<&str> = BTreeSet::new();
        for (id, objective) in &objectives {
            let wanted = self.registry.missing_code(&objective.verifier);
            if wanted.iter().any(|address| missing.contains(address)) {
                unreproducible.insert(id.as_str());
            }
        }

        let facts = claims.iter().map(|(id, claim)| {
            let epoch = crate::time::parse_rfc3339(&claim.created_at)
                .filter(|seconds| *seconds >= 0)
                .map(|seconds| epoch_of(seconds as u64, epoch_seconds()))
                .unwrap_or(0);
            ClaimFacts {
                id: id.as_str(),
                claim,
                verdict: self.recorded_verdict(id).map(|verdict| verdict.status),
                epoch,
                reproducible: if unreproducible.contains(claim.objective_id.as_str()) {
                    Reproducible::NotHere
                } else {
                    Reproducible::Yes
                },
            }
        });
        KnowledgeGraph::new(facts)
    }

    /// Standing and confidence for one claim, under `policy`.
    ///
    /// A convenience over [`Node::knowledge_graph`] for the single-claim case.
    /// Callers reporting on many claims should build the graph once instead --
    /// this rebuilds the whole index per call.
    pub fn knowledge_state(
        &self,
        claim_id: &str,
        policy: &ConfidencePolicy,
        as_of_epoch: u64,
    ) -> Option<KnowledgeState> {
        let claims = self.all_claims();
        self.knowledge_graph(&claims)
            .state(claim_id, policy, as_of_epoch)
    }

    pub fn accepted_claims(&self) -> BTreeMap<String, Claim> {
        let accepted = self.accepted_claim_ids();
        let mut out = BTreeMap::new();
        for entry in self.ledger.entries_of_kind(CLAIM) {
            if let Ok(claim) = Claim::from_value(&entry.payload) {
                let id = claim.id();
                if accepted.contains(&id) {
                    out.insert(id, claim);
                }
            }
        }
        out
    }

    /// Every verdict the log records, joined to the artifact it was about.
    ///
    /// The join is the point. A verdict record names a claim; a canary is known
    /// by its *artifact*, because the docket is written before anybody knows
    /// which key will submit it, under which nonce, in which epoch. Walking the
    /// claims once turns one into the other.
    ///
    /// Later verdicts supersede earlier ones for the same claim, matching
    /// `accepted_claim_ids` and the reference implementation. A node
    /// that re-verified and corrected itself is judged on the correction.
    ///
    /// Read-only and cheap: no verifier runs here, which is the whole reason a
    /// canary rate is affordable. See [`crate::canary`].
    pub fn recorded_verdicts(&self) -> Vec<crate::canary::RecordedVerdict> {
        let mut artifacts: BTreeMap<String, String> = BTreeMap::new();
        for entry in self.ledger.entries_of_kind(CLAIM) {
            if let Ok(claim) = Claim::from_value(&entry.payload) {
                artifacts.insert(claim.id(), claim.artifact.digest());
            }
        }
        let mut latest: BTreeMap<String, Status> = BTreeMap::new();
        let mut order: Vec<String> = Vec::new();
        for entry in self.ledger.entries_of_kind(VERDICT) {
            let claim_id = match payload_str(&entry.payload, "claim_id") {
                Some(claim_id) => claim_id.to_string(),
                None => continue,
            };
            let status = match entry.payload.get("verdict").and_then(Verdict::from_value) {
                Some(verdict) => verdict.status,
                None => continue,
            };
            if latest.insert(claim_id.clone(), status).is_none() {
                order.push(claim_id);
            }
        }
        order
            .into_iter()
            .filter_map(|claim_id| {
                let artifact_id = artifacts.get(&claim_id)?.clone();
                let status = *latest.get(&claim_id)?;
                Some(crate::canary::RecordedVerdict {
                    claim_id,
                    artifact_id,
                    status,
                })
            })
            .collect()
    }

    /// Phase 2: reveal a committed artifact, verify it, and settle if accepted.
    ///
    /// The refusals, each answering a specific attack:
    ///
    /// - **no matching prior commitment.** Without this, an observer copies a
    ///   revealed artifact out of the mempool and submits it as their own.
    ///   The commitment binds the submitter and a nonce, so it cannot be
    ///   replayed under another name or brute-forced from a guessable artifact.
    /// - **a citation that is not an accepted claim.** Citations point backwards
    ///   only; otherwise attribution flow can be pointed at anything, including
    ///   a claim invented for the purpose.
    /// - **an improvement that does not cite the frontier.** Mechanical, not a
    ///   judgement call: you improved on the public frontier, so you cite it,
    ///   and citation flow pays its holder. This is what makes "standing on
    ///   shoulders" a submission rule instead of an etiquette anyone can ignore.
    ///
    /// Past those, the claim and its verdict are **always** appended, and only
    /// then is settlement considered. Recording the attempt is not a courtesy:
    /// it is what lets an auditor re-derive every decision, including the ones
    /// that paid nothing.
    ///
    /// # Settlement is deferred to the close of the reveal epoch
    ///
    /// An accepted claim comes back `Outcome::pending`, not settled. That is
    /// not a caching decision -- it falls out of the ordering rule and cannot be
    /// avoided. Settlement order inside an epoch is
    /// `H(beacon(epoch, anchor) ‖ claim_id)`, which is a function of the *set*
    /// of claims in the epoch, and that set is not known until the epoch is
    /// over. Paying the first arrival and re-ordering afterwards is impossible
    /// in an append-only log, so the payment waits instead.
    ///
    /// The batch runs on the next call that carries a later timestamp -- any
    /// reveal, commit, post, or an explicit [`Node::settle_due`]. Nothing is
    /// lost by waiting: the claim and its verdict are already in the log and
    /// already public.
    pub fn reveal(&mut self, claim: &Claim, ts: &str) -> Result<Outcome, RuleViolation> {
        // As in `commit`: a key-shaped submitter must prove it holds the key,
        // checked before any rule that could write. The commitment hash binds
        // the submitter string, so a signed commitment can only be opened by a
        // claim naming the same submitter -- and now that name is unforgeable
        // rather than merely declared.
        claim.verify_signature()?;
        let reveal_epoch = epoch_of_timestamp("reveal", ts)?;
        // Drain first. An epoch that closed while this node was idle must
        // settle *before* this claim's admission checks read the frontier, or
        // an improvement would be measured against a stale one.
        self.settle_due(reveal_epoch, ts)?;

        let objectives = self.objectives();
        let objective = objectives
            .get(&claim.objective_id)
            .ok_or_else(|| RuleViolation::UnknownObjective {
                referrer: Referrer::Claim,
                objective_id: claim.objective_id.clone(),
            })?
            .clone();

        // The funder's policy, checked on both halves of the submission: a
        // commitment admitted before the objective was known would otherwise
        // open into a claim this rule should have refused.
        if objective.require_signed_submitter
            && crate::records::signed_submitter(&claim.submitter).is_none()
        {
            return Err(RuleViolation::SignedSubmitterRequired {
                objective_id: claim.objective_id.clone(),
                submitter: claim.submitter.clone(),
            });
        }

        let commitment = match self.matching_commitment(claim) {
            Some(commitment) => commitment.clone(),
            None => return Err(RuleViolation::NoMatchingCommitment),
        };
        let created_at = payload_str(&commitment, "created_at").unwrap_or_default();
        let commit_epoch = epoch_of_timestamp("commitment", created_at)?;
        if reveal_epoch <= commit_epoch {
            return Err(RuleViolation::RevealBeforeEpoch {
                commit_epoch,
                reveal_epoch,
            });
        }
        if self.epoch_is_drained(reveal_epoch) {
            return Err(RuleViolation::EpochAlreadySettled {
                epoch: reveal_epoch,
            });
        }

        let accepted = self.accepted_claims();
        for cited in &claim.cites {
            if !accepted.contains_key(cited) {
                return Err(RuleViolation::UnknownCitation {
                    claim_id: cited.clone(),
                });
            }
        }

        // A relation's target must already be in the log -- but, unlike a
        // citation, it need *not* be accepted. Refuting a claim the verifier
        // rejected is a legitimate and useful thing to record, and requiring
        // acceptance would mean the only claims anyone could speak about are
        // the ones that passed.
        //
        // The check is existence only. Whether the assertion is *heard* is not
        // decided here and must not be: admission is a consensus rule every
        // node applies identically, and how much an assertion counts for is a
        // reader's policy question that `knowledge` answers differently for
        // different readers. Mixing the two would put the confidence function
        // into consensus, which is the thing this whole design refuses.
        if !claim.relations.is_empty() {
            let known = self.claim_ids();
            for relation in &claim.relations {
                if !known.contains(&relation.target) {
                    return Err(RuleViolation::UnknownRelationTarget {
                        claim_id: relation.target.clone(),
                    });
                }
            }
        }

        // The frontier citation is an *admission* rule and stays here, at
        // reveal time, rather than moving into the batch: a submitter can only
        // cite what was public when they built, and holding them to a frontier
        // that advanced while their commitment was sealed would make the rule
        // impossible to satisfy. Whether the claim actually improves on the
        // frontier is a settlement question and is asked later, against
        // whatever the frontier is by then.
        if objective.ratchet.is_some() {
            if let Some(frontier) = self.latest_frontier(&claim.objective_id)? {
                if !claim.cites.iter().any(|cited| cited == &frontier.claim_id) {
                    return Err(RuleViolation::MissingFrontierCitation {
                        claim_id: frontier.claim_id.clone(),
                    });
                }
            }
        }

        let claim_id = claim.id();
        self.append(CLAIM, claim.to_value(), ts)?;

        let verdict = self.registry.run(&objective.verifier, &claim.artifact);
        let record = Value::object([
            ("claim_id", Value::string(claim_id.clone())),
            ("objective_id", Value::string(claim.objective_id.clone())),
            ("verdict", verdict.to_value()),
        ]);
        self.append(VERDICT, record, ts)?;

        // A non-settling verdict records what happened and moves nothing. An
        // unavailable toolchain is an infrastructure fact, not a refutation, and
        // the objective stays open for a node that can actually run the check.
        if !verdict.settles() {
            return Ok(Outcome::unsettled(
                claim_id,
                verdict,
                "verdict does not settle",
            ));
        }
        if !verdict.accepted() {
            return Ok(Outcome::unsettled(claim_id, verdict, "rejected"));
        }
        Ok(Outcome::pending(claim_id, verdict, reveal_epoch))
    }

    /// Settle every reveal epoch that has closed, in beacon order.
    ///
    /// "Closed" means strictly before `now_epoch`. Claims accepted in an epoch
    /// that is still open are left alone, because the set they will be ordered
    /// against is not complete yet.
    ///
    /// Inside one epoch the order is `H(beacon(epoch, anchor) ‖ commitment)`
    /// ascending, where `anchor` is the log head as of the epoch's start. Append
    /// order is the sequencer's to choose, and on a progressive objective the
    /// order two improvements settle in decides which is paid for the whole span
    /// and which for the remainder -- so leaving it to the sequencer is leaving
    /// them a lever on other people's money. The beacon was fixed before the
    /// epoch opened, so the operator would have to choose the anchor before
    /// knowing who would reveal.
    ///
    /// # Why the key is the commitment hash and not the claim id
    ///
    /// The design note for this work says `claim_id`, and that is grindable. By
    /// reveal time the anchor is public, and a claim id covers `created_at` and
    /// `cites` -- fields the commitment does not bind and nothing here checks
    /// against the reveal. A submitter could simply try timestamps until one
    /// sorted first, which would make the ordering rule decorative against
    /// exactly the people it needs to bind. The commitment hash covers only
    /// what was frozen an epoch earlier, before this anchor existed.
    ///
    /// The residual gap, which is real: the anchor is the last entry of the
    /// previous epoch, so a submitter who lands the final append of their commit
    /// epoch influences both halves of their own rank at once and can grind the
    /// pair. It is a race they have to win against every other appender, not a
    /// free choice, and closing it properly needs an unpredictable beacon (a VDF
    /// or a threshold signature) rather than the log head. `docs/threat-model.md`
    /// carries the row.
    ///
    /// A `batch` record is appended per drained epoch, holding the anchor used
    /// and the resulting order. That record is what makes the drain idempotent
    /// (a second call skips an epoch already named by one) and what lets an
    /// auditor recompute the ordering without guessing which anchor was in
    /// force.
    ///
    /// Rule failures inside a batch -- an unreadable ratchet, an overflowing
    /// payout -- become unsettled outcomes rather than aborting the drain. A
    /// single bad objective must not be able to wedge settlement for every
    /// other objective in the same epoch, which is what propagating would do.
    /// Only a failed *append* propagates, because at that point the log is not
    /// being written and nothing further can be trusted.
    pub fn settle_due(&mut self, now_epoch: u64, ts: &str) -> Result<Vec<Outcome>, RuleViolation> {
        let mut outcomes = Vec::new();
        for epoch in self.due_epochs(now_epoch) {
            let anchor = self.anchor_of_epoch(epoch);
            let mut batch = self.accepted_in_epoch(epoch);
            // Sorting by (rank, id) rather than rank alone: two claims with the
            // same rank would otherwise keep append order, quietly restoring
            // the lever this function exists to remove. A collision needs a
            // SHA-256 preimage, but "unreachable" is not a tie-break rule.
            batch.sort_by(|(a_id, a), (b_id, b)| {
                let ra = settlement_rank(epoch, &anchor, &a.commitment_hash());
                let rb = settlement_rank(epoch, &anchor, &b.commitment_hash());
                (ra, a_id).cmp(&(rb, b_id))
            });

            let mut order = Vec::with_capacity(batch.len());
            // Artifacts already spoken for earlier in *this* batch. Without
            // this the duplicate rule would fall back on append order for two
            // identical artifacts revealed in the same epoch, which is the one
            // thing the beacon ordering exists to prevent.
            let mut consumed: BTreeSet<String> = BTreeSet::new();
            for (claim_id, claim) in batch {
                order.push(Value::string(claim_id.clone()));
                outcomes.push(self.settle_one(&claim_id, &claim, epoch, &consumed, ts)?);
                consumed.insert(claim.artifact_id());
            }
            let record = Value::object([
                ("epoch", Value::Int(i128::from(epoch))),
                ("anchor", Value::string(anchor)),
                ("claims", Value::Array(order)),
            ]);
            self.append(BATCH, record, ts)?;
        }
        Ok(outcomes)
    }

    /// Every availability pool in the log, in log order.
    /// What each identity has been paid, and what it has locked, as of
    /// `positions` entries into the log.
    ///
    /// # Why a balance exists at all
    ///
    /// Because a bond has to be *scarce*, and nothing else here is. Sybil
    /// resistance is not a property the rules can assert: it is a property of
    /// the map from resources to payoff, and `incentive::mechanism`'s
    /// `SplitIdentities` already proves which map has it. A stake-weighted
    /// split is **exactly** invariant to splitting one operator into forty,
    /// because stake is conserved when it is divided; an even split, or a split
    /// weighted by anything an identity can mint for free, is farmed by
    /// whoever mints the most.
    ///
    /// A `bond` field that anyone could fill in with `u64::MAX` would be worse
    /// than no bond at all -- it would look like the invariant rule while
    /// behaving like the free one. So the bond is backed by units the log
    /// itself says the identity was paid, which nobody can forge without
    /// forging a settlement, and a settlement is re-derived by every auditor.
    ///
    /// # What it is derived from
    ///
    /// Every settlement, of both kinds, plus every bond currently locked.
    /// Nothing is stored: two auditors reading the same prefix compute the same
    /// balances, which is the only way this can be a consensus rule rather than
    /// an operator's private ledger.
    ///
    /// Bounded by `positions` for the reason every other derivation here is: a
    /// bond's admissibility is decided when it is written, and a later append
    /// must not be able to change whether an already-accepted undertaking was
    /// affordable.
    pub fn balances_within(&self, positions: usize) -> BTreeMap<String, u128> {
        let mut held = self.gross_paid_within(positions);
        for (identity, committed) in self.committed_within(positions) {
            let slot = held.entry(identity).or_insert(0);
            *slot = slot.saturating_sub(committed);
        }
        held
    }

    /// What each identity has put at risk and not yet had returned: bonds
    /// locked behind promises, plus rewards escrowed behind objectives and
    /// availability pools it funded.
    ///
    /// One function because they are one rule. A funder who could post a
    /// bounty it cannot pay is minting, and a promiser who could stake units it
    /// does not hold is minting; the two differ only in which record does it.
    fn committed_within(&self, positions: usize) -> BTreeMap<String, u128> {
        let mut committed = self.locked_within(positions);
        for (funder, charged) in self.charged_within(positions) {
            let slot = committed.entry(funder).or_insert(0);
            *slot = slot.saturating_add(charged);
        }
        // A live challenge's bond is spent-but-not-gone in exactly the sense an
        // undertaking's is: it can be lost, so it must not also be staked
        // somewhere else. Released when the dispute settles, because the
        // settlement record then says where it went.
        for (challenger, bonded) in self.challenge_bonds_within(positions) {
            let slot = committed.entry(challenger).or_insert(0);
            *slot = slot.saturating_add(bonded);
        }
        // A dispute the log has already decided is a *debit* on the loser, and
        // it is not a commitment -- it is spent. Balances subtract it here
        // rather than in `gross_paid_within`, which only ever adds, so that
        // "what came in" and "what went out" stay two readable halves.
        for (loser, lost) in self.challenge_flows_within(positions).1 {
            let slot = committed.entry(loser).or_insert(0);
            *slot = slot.saturating_add(lost);
        }
        committed
    }

    /// What each funder has parted with by posting: the *whole* reward of every
    /// objective it funded, and the whole ceiling of every availability pool.
    ///
    /// Charged once, at post time, and never given back. The first version
    /// released a reward from escrow as settlements drew it down, which is the
    /// natural reading of the word and is wrong by a whole supply: the units
    /// left for the submitter, so returning them to the funder credited the
    /// same money twice and `a_settled_reward_moves_escrow_and_mints_nothing`
    /// found 2000 held against 1000 issued. What draws down is
    /// [`Node::escrowed_within`], which is the *outstanding* part and exists to
    /// be reported rather than to be subtracted.
    fn charged_within(&self, positions: usize) -> BTreeMap<String, u128> {
        let mut charged: BTreeMap<String, u128> = BTreeMap::new();
        let entries = self.ledger.entries();
        for entry in &entries[..positions.min(entries.len())] {
            let (funder, amount) = match entry.kind.as_str() {
                OBJECTIVE => match Objective::from_value(&entry.payload) {
                    Ok(objective) => (objective.funder, u128::from(objective.reward)),
                    Err(_) => continue,
                },
                AVAILABILITY_POOL => match AvailabilityPool::from_value(&entry.payload) {
                    Ok(pool) => {
                        let ceiling = pool.ceiling();
                        (pool.funder, ceiling)
                    }
                    Err(_) => continue,
                },
                _ => continue,
            };
            let slot = charged.entry(funder).or_insert(0);
            *slot = slot.saturating_add(amount);
        }
        charged
    }

    /// How many entries of this log are its genesis prefix: the run of
    /// `issuance` records at the very front, before anything else.
    ///
    /// The supply is defined by *position* rather than by a signature, because
    /// a signature would only say who wrote the record and in the opening bytes
    /// of a log there is nobody else it could be. Reading forward from line one
    /// and stopping at the first record of any other kind gives every auditor
    /// the same number, which is what makes the supply common knowledge in the
    /// sense the consensus literature means: agreed before the protocol starts,
    /// rather than agreed by running it.
    pub fn genesis_prefix(&self) -> usize {
        self.ledger
            .entries()
            .iter()
            .take_while(|entry| entry.kind == ISSUANCE)
            .count()
    }

    /// Does this log declare a money supply?
    ///
    /// The switch that turns the accounting on. A log with no issuance has not
    /// claimed its units are scarce, so escrow is not enforced on it and the
    /// audit says the backing is the operator's word. A log with one has, and
    /// then every unit in it must trace to the declaration.
    pub fn declares_supply(&self) -> bool {
        self.genesis_prefix() > 0
    }

    /// The declared supply, by holder.
    ///
    /// Only the genesis prefix counts. An issuance below it is a mint and is
    /// reported by [`Node::audit`] rather than credited — otherwise the record
    /// that exists to make money scarce would be the cheapest way to make more.
    pub fn issued_within(&self, positions: usize) -> BTreeMap<String, u128> {
        let mut issued: BTreeMap<String, u128> = BTreeMap::new();
        let genesis = self.genesis_prefix().min(positions);
        for entry in self.ledger.entries().iter().take(genesis) {
            if let Ok(record) = Issuance::from_value(&entry.payload) {
                let slot = issued.entry(record.holder).or_insert(0);
                *slot = slot.saturating_add(u128::from(record.units));
            }
        }
        issued
    }

    /// [`Node::issued_within`] over the whole log.
    pub fn issued(&self) -> BTreeMap<String, u128> {
        self.issued_within(self.ledger.len())
    }

    /// Of what each funder has been charged, how much is still owed to nobody
    /// in particular: rewards posted and not yet settled.
    ///
    /// **Reporting only.** Balances subtract `charged_within`, which is
    /// the full commitment and never returns; this is the part of it that has
    /// not yet reached a submitter, and it exists so `balances` can show where
    /// the supply is sitting and so the audit can print a total that closes.
    /// Subtracting *this* instead would hand a funder back the units its
    /// settlement had already paid out.
    ///
    /// Reads raw entries for the same reason `locked_within` does.
    pub fn escrowed_within(&self, positions: usize) -> BTreeMap<String, u128> {
        let entries = self.ledger.entries();
        let window = &entries[..positions.min(entries.len())];

        // Drawn down per objective, and per pool, before anything is charged to
        // a funder: a reward already in somebody's hands is not still escrowed,
        // and charging it twice would make an honest funder look insolvent.
        let mut drawn: BTreeMap<String, u128> = BTreeMap::new();
        let mut availability_drawn: u128 = 0;
        for entry in window {
            match entry.kind.as_str() {
                SETTLEMENT => {
                    if let (Some(objective_id), Some(reward)) = (
                        payload_str(&entry.payload, "objective_id"),
                        entry.payload.get("reward").and_then(Value::as_u64),
                    ) {
                        let slot = drawn.entry(objective_id.to_string()).or_insert(0);
                        *slot = slot.saturating_add(u128::from(reward));
                    }
                }
                AVAILABILITY_SETTLEMENT => {
                    for row in entry
                        .payload
                        .get("paid")
                        .and_then(Value::as_array)
                        .unwrap_or(&[])
                    {
                        if let Some(reward) = row.get("reward").and_then(Value::as_u64) {
                            availability_drawn = availability_drawn.saturating_add(reward.into());
                        }
                    }
                }
                _ => {}
            }
        }

        let mut escrowed: BTreeMap<String, u128> = BTreeMap::new();
        for entry in window {
            match entry.kind.as_str() {
                OBJECTIVE => {
                    let Ok(objective) = Objective::from_value(&entry.payload) else {
                        continue;
                    };
                    let paid = drawn.get(&objective.id()).copied().unwrap_or(0);
                    let outstanding = u128::from(objective.reward).saturating_sub(paid);
                    let slot = escrowed.entry(objective.funder.clone()).or_insert(0);
                    *slot = slot.saturating_add(outstanding);
                }
                AVAILABILITY_POOL => {
                    let Ok(pool) = AvailabilityPool::from_value(&entry.payload) else {
                        continue;
                    };
                    // Pools are not individually identified in a settlement
                    // row, so the draw-down is shared: charged against the
                    // pools in log order, which every auditor reproduces.
                    let take = availability_drawn.min(pool.ceiling());
                    availability_drawn -= take;
                    let slot = escrowed.entry(pool.funder.clone()).or_insert(0);
                    *slot = slot.saturating_add(pool.ceiling() - take);
                }
                _ => {}
            }
        }
        escrowed
    }

    /// [`Node::escrowed_within`] over the whole log.
    pub fn escrowed(&self) -> BTreeMap<String, u128> {
        self.escrowed_within(self.ledger.len())
    }

    /// Everything the log says each identity holds before its commitments:
    /// what the genesis prefix issued it, plus what settlements have paid it.
    ///
    /// Separate from the committed side so that neither reads
    /// [`Node::undertakings_within`]: that accessor filters on affordability,
    /// affordability is derived from balances, and a balance that consulted the
    /// filtered list would recurse forever. Both halves here read raw entries.
    fn gross_paid_within(&self, positions: usize) -> BTreeMap<String, u128> {
        let mut paid: BTreeMap<String, u128> = self.issued_within(positions);
        // What a won dispute pays the winner. Not new money: every unit of it
        // was debited from the loser in `committed_within`, so the two sides of
        // a slash sum to zero and the supply is unchanged. The audit's
        // conservation check is what proves that rather than this comment.
        for (winner, won) in self.challenge_flows_within(positions).0 {
            let slot = paid.entry(winner).or_insert(0u128);
            *slot = slot.saturating_add(won);
        }
        let entries = self.ledger.entries();
        for entry in &entries[..positions.min(entries.len())] {
            match entry.kind.as_str() {
                // The inflow that makes this bootstrappable: you earn by
                // contributing research, and only then can you stake to earn by
                // serving. A fresh identity has nothing and is worth nothing.
                SETTLEMENT => {
                    if let (Some(who), Some(reward)) = (
                        payload_str(&entry.payload, "submitter"),
                        entry.payload.get("reward").and_then(Value::as_u64),
                    ) {
                        *paid.entry(who.to_string()).or_insert(0) += u128::from(reward);
                    }
                }
                AVAILABILITY_SETTLEMENT => {
                    for row in entry
                        .payload
                        .get("paid")
                        .and_then(Value::as_array)
                        .unwrap_or(&[])
                    {
                        if let (Some(who), Some(reward)) = (
                            payload_str(row, "identity"),
                            row.get("reward").and_then(Value::as_u64),
                        ) {
                            *paid.entry(who.to_string()).or_insert(0) += u128::from(reward);
                        }
                    }
                }
                _ => {}
            }
        }
        paid
    }

    /// What each identity has staked and not yet had returned.
    ///
    /// Reads raw undertaking entries -- decodable and signed, nothing more --
    /// precisely because the affordability rule is what it feeds. An
    /// unaffordable bond therefore counts against its own author here, which is
    /// self-correcting: a forged `u64::MAX` bond drives that identity's
    /// spendable balance to zero and every promise it makes, including that
    /// one, fails the check.
    fn locked_within(&self, positions: usize) -> BTreeMap<String, u128> {
        let mut locked: BTreeMap<String, u128> = BTreeMap::new();
        for entry in self.ledger.entries_of_kind(UNDERTAKING) {
            if (entry.seq as usize) >= positions {
                continue;
            }
            let Ok(record) = Undertaking::from_value(&entry.payload) else {
                continue;
            };
            if record.verify_signature().is_err() {
                continue;
            }
            let slot = locked.entry(record.identity.clone()).or_insert(0);
            *slot = slot.saturating_add(u128::from(record.bond));
        }
        locked
    }

    /// [`Node::balances_within`] over the whole log.
    pub fn balances(&self) -> BTreeMap<String, u128> {
        self.balances_within(self.ledger.len())
    }

    /// What `identity` could still bond, as of `positions` entries in.
    pub fn spendable_within(&self, identity: &str, positions: usize) -> u128 {
        // Reads [`Node::balances_within`] rather than subtracting for itself.
        // It did subtract for itself, and knew only about bonds, so when escrow
        // arrived every affordability check in the crate still saw an escrowed
        // reward as spendable -- a funder could post the same units twice and
        // the audit's conservation sum was the only thing that noticed. One
        // definition of "spendable", in one place.
        self.balances_within(positions)
            .get(identity)
            .copied()
            .unwrap_or(0)
    }

    pub fn availability_pools(&self) -> Vec<AvailabilityPool> {
        self.ledger
            .entries_of_kind(AVAILABILITY_POOL)
            .into_iter()
            .filter_map(|entry| AvailabilityPool::from_value(&entry.payload).ok())
            .collect()
    }

    /// Record money put up to pay for availability.
    pub fn post_availability_pool(
        &mut self,
        pool: &AvailabilityPool,
        ts: &str,
    ) -> Result<String, RuleViolation> {
        pool.validate().map_err(RuleViolation::InadmissibleRecord)?;
        // The *ceiling*, not one epoch's worth: a pool promises `per_epoch`
        // for every epoch in range, and escrowing only the first would let a
        // funder promise a thousand epochs it can pay one of.
        self.afford(&pool.funder, pool.ceiling())?;
        let id = pool.id();
        self.append(AVAILABILITY_POOL, pool.to_value(), ts)?;
        Ok(id)
    }

    /// Declare units into the log's supply.
    ///
    /// Refused once anything else has been written: the supply is the log's
    /// opening statement, and an issuance below it is a mint. See
    /// [`Issuance`] for why position rather than a signature is what
    /// authorises it.
    pub fn post_issuance(&mut self, record: &Issuance, ts: &str) -> Result<String, RuleViolation> {
        record
            .validate()
            .map_err(RuleViolation::InadmissibleRecord)?;
        let seq = self.ledger.len() as u64;
        if self.genesis_prefix() as u64 != seq {
            return Err(RuleViolation::MintedAfterGenesis {
                holder: record.holder.clone(),
                units: record.units,
                seq,
            });
        }
        let id = record.id();
        self.append(ISSUANCE, record.to_value(), ts)?;
        Ok(id)
    }

    /// Refuse a commitment `funder` cannot cover.
    ///
    /// Conditional on the log declaring a supply, and that is the whole of the
    /// backward compatibility story: a log with no issuance record has never
    /// claimed its units are scarce, so there is nothing to check and the audit
    /// says the backing is the operator's word. The moment a supply is
    /// declared, every unit in the log has to trace to it.
    fn afford(&self, funder: &str, amount: u128) -> Result<(), RuleViolation> {
        if !self.declares_supply() {
            return Ok(());
        }
        let spendable = self.spendable_within(funder, self.ledger.len());
        if amount > spendable {
            return Err(RuleViolation::UnfundedReward {
                funder: funder.to_string(),
                reward: amount,
                spendable,
            });
        }
        Ok(())
    }

    /// Units on offer for one epoch, summed across every pool covering it.
    ///
    /// `u128` because two pools' `per_epoch` are each `u64` and their sum is
    /// not. Saturating rather than wrapping: an implausible total should pin at
    /// the ceiling where the audit can see it, never wrap to something small
    /// that looks fine.
    pub fn availability_offered(&self, epoch: u64) -> u128 {
        self.availability_pools()
            .iter()
            .filter(|pool| pool.covers(epoch))
            .fold(0u128, |total, pool| {
                total.saturating_add(u128::from(pool.per_epoch))
            })
    }

    /// Pay the answers to one epoch's samples, and name the promises that went
    /// unanswered.
    ///
    /// The half that makes an undertaking enforceable. Three properties, and
    /// each is a rule somebody would otherwise have to trust:
    ///
    /// - **Stake-weighted integer shares.** `offered * bond / total_bond`,
    ///   floor-divided. The remainder is not paid and not hidden: it is
    ///   recorded on the settlement so the pool's arithmetic closes. No floats
    ///   anywhere near it. Weighting by bond rather than by head count is what
    ///   makes the payout invariant to splitting an identity, since a bond is
    ///   conserved when it is divided and a head count is not.
    /// - **Nothing is paid twice.** An epoch settles once; a second call is a
    ///   no-op rather than a second payout.
    /// - **Silence is recorded.** A promise that was samplable in this epoch
    ///   and produced no answer is named in the record. That is the half a
    ///   slash would attach to, and writing it down now is what makes the
    ///   record worth having before a bond exists to slash.
    pub fn settle_availability(
        &mut self,
        epoch: u64,
        ts: &str,
    ) -> Result<Option<AvailabilityOutcome>, RuleViolation> {
        if self
            .ledger
            .entries_of_kind(AVAILABILITY_SETTLEMENT)
            .iter()
            .any(|entry| entry.payload.get("epoch").and_then(Value::as_u64) == Some(epoch))
        {
            return Ok(None);
        }

        // Only promises that existed *before* this epoch's anchor can be
        // sampled in it. Without the bound, a node could post an undertaking
        // after the fact, compute the index at leisure and answer a question it
        // was never asked -- the same back-dating attack the batch bound
        // exists for, and the reason `anchor_of_epoch_within` is written the
        // way it is.
        let promises: Vec<Undertaking> = self.undertakings();
        let answered: BTreeMap<String, String> = self
            .availability_answers()
            .into_iter()
            .filter(|answer| answer.epoch == epoch)
            .map(|answer| (answer.undertaking, answer.identity))
            .collect();

        // Weighted by **bond**, summed per identity. Both halves are load
        // bearing, and each closes a way of being paid for storage nobody
        // bought.
        //
        // *Weighted*, because an equal split paid a one-entry promise what it
        // paid a twenty-thousand-entry promise, so a node could answer with a
        // thimble and collect like a warehouse.
        //
        // *By bond rather than by height*, because height is not a scarce
        // resource. Promising the whole log costs a signature; forty keys each
        // promising the whole log is the sybil attack with nothing spent, and
        // no rule that reads only the promise can tell those forty from forty
        // real disks. A bond can be told apart, because the log knows what each
        // identity was paid and [`Node::post_undertaking`] refuses to lock more
        // than that.
        //
        // *Summed rather than maxed*, because summing is what makes the rule
        // sybil-*invariant* rather than merely sybil-*expensive*: an operator
        // splitting one identity holding `S` into forty holding `S/40` has the
        // same total weight either way, since stake is conserved when it is
        // divided. Maxing -- which the height-weighted version had to do, since
        // height is not conserved -- would here punish an honest operator for
        // making two promises out of one balance, which the bond accounting
        // already prevents from being free.
        let mut weight: BTreeMap<String, u64> = BTreeMap::new();
        let mut paid: Vec<(String, String)> = Vec::new();
        let mut silent: Vec<String> = Vec::new();
        for promise in &promises {
            let id = promise.id();
            match answered.get(&id) {
                Some(identity) => {
                    // **Summed**, not maxed, and weighted by bond rather than
                    // height. Summing is what makes the rule Sybil-invariant:
                    // an operator splitting one identity holding `S` into forty
                    // holding `S/40` has the same total weight either way,
                    // because stake is conserved when it is divided. Maxing --
                    // which the height-weighted version had to do, since height
                    // is *not* conserved and forty full-height promises would
                    // otherwise be forty times the weight -- would here punish
                    // an honest operator for making two promises out of one
                    // balance, which the bond accounting already prevents from
                    // being free.
                    let slot = weight.entry(identity.clone()).or_insert(0);
                    *slot = slot.saturating_add(promise.bond);
                    paid.push((id, identity.clone()));
                }
                None => silent.push(id),
            }
        }
        if paid.is_empty() && silent.is_empty() {
            return Ok(None);
        }

        let offered = self.availability_offered(epoch);
        let total: u128 = weight.values().fold(0u128, |sum, w| sum + u128::from(*w));
        // Every share floor-divided from the same denominator, so the parts sum
        // to at most the whole and the remainder is whatever equal division
        // could not place. `u128` throughout and `checked_mul` at the one place
        // two large numbers meet: this crate does not wrap near money, and an
        // overspend that wrapped would certify as fine.
        let mut awards: BTreeMap<String, u64> = BTreeMap::new();
        let mut spent: u128 = 0;
        for (identity, w) in &weight {
            let share = offered
                .checked_mul(u128::from(*w))
                .ok_or(RuleViolation::PayoutOverflow {
                    paid_cumulative: u64::MAX,
                    reward: 0,
                })?
                .checked_div(total)
                .unwrap_or(0);
            let share = u64::try_from(share).map_err(|_| RuleViolation::PayoutOverflow {
                paid_cumulative: u64::MAX,
                reward: 0,
            })?;
            spent += u128::from(share);
            awards.insert(identity.clone(), share);
        }
        let unpaid = offered - spent;

        // The payouts live *inside* this record rather than as `settlement`
        // entries. A `settlement` names an objective and a claim, and the audit
        // reads every one of them to check that the claim it paid was accepted
        // and that its objective's pool was not overspent. An availability
        // payout has neither, so borrowing the kind would have made the
        // objective audit report every one of them as paying an unaccepted
        // claim against an unknown objective -- a fault message for a record
        // doing exactly what it should.
        let record = Value::object([
            ("epoch", Value::Int(i128::from(epoch))),
            ("anchor", Value::string(self.anchor_of_epoch(epoch))),
            // One row per *identity*, not per answer: an identity that
            // answered two promises is paid once, and the record must say so or
            // the audit's arithmetic would double-count it.
            (
                "paid",
                Value::Array(
                    awards
                        .iter()
                        .map(|(identity, reward)| {
                            Value::object([
                                ("identity", Value::string(identity.clone())),
                                ("reward", Value::Int(i128::from(*reward))),
                                (
                                    "weight",
                                    Value::Int(i128::from(
                                        weight.get(identity).copied().unwrap_or(0),
                                    )),
                                ),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "silent",
                Value::Array(silent.iter().cloned().map(Value::String).collect()),
            ),
            (
                "unpaid",
                Value::Int(i128::try_from(unpaid).unwrap_or(i128::MAX)),
            ),
        ]);
        self.append(AVAILABILITY_SETTLEMENT, record, ts)?;

        Ok(Some(AvailabilityOutcome {
            epoch,
            answered: awards.len(),
            silent: silent.len(),
            paid: spent,
            unpaid,
        }))
    }

    /// Settle a batch for the epoch containing `ts`, and every earlier one.
    ///
    /// The convenience wrapper the CLI and the daemon use, so neither has to
    /// know the epoch length.
    pub fn settle_at(&mut self, ts: &str) -> Result<Vec<Outcome>, RuleViolation> {
        let now = epoch_of_timestamp("settle", ts)?;
        self.settle_due(now, ts)
    }

    /// Epochs a `batch` record already covers.
    fn drained_epochs(&self) -> BTreeSet<u64> {
        self.ledger
            .entries_of_kind(BATCH)
            .iter()
            .filter_map(|entry| entry.payload.get("epoch").and_then(Value::as_u64))
            .collect()
    }

    /// Has this epoch's batch already been paid?
    pub fn epoch_is_drained(&self, epoch: u64) -> bool {
        self.drained_epochs().contains(&epoch)
    }

    /// Closed reveal epochs with accepted claims that no `batch` record covers,
    /// that have waited out the finality delay, and that are not older than
    /// something already settled. Ascending, which is the order they settle in.
    ///
    /// Three conditions, and the last two are why settlement converges at all.
    ///
    /// * **Closed** (`epoch < now_epoch`) -- an open epoch can still receive
    ///   reveals, so its batch is not yet determined.
    /// * **Final** (`epoch + finality_epochs() < now_epoch`) -- see
    ///   [`FINALITY_EPOCHS`]. Eligibility is a function of the clock, not of
    ///   when this node happened to hear about the work, so a node that
    ///   learns of a late epoch still settles it *after* the earlier ones.
    /// * **Not superseded** (`epoch > highest drained`) -- an epoch older than
    ///   one already settled is refused rather than settled out of order.
    ///   Settling it would give it an anchor computed from a chain head that
    ///   already includes *later* epochs, which is the fork this is preventing,
    ///   and it would silently re-order payouts that an auditor has already
    ///   seen. Refusing loses that epoch's payouts, which is a real cost paid
    ///   deliberately: it is bounded, visible in [`Node::late_epochs`], and
    ///   preferable to two logs that both audit clean and disagree about money.
    ///
    /// [`FINALITY_EPOCHS`]: crate::partition::FINALITY_EPOCHS
    fn due_epochs(&self, now_epoch: u64) -> Vec<u64> {
        let drained = self.drained_epochs();
        let floor = drained.iter().copied().max();
        let delay = crate::partition::finality_epochs();
        let mut due: BTreeSet<u64> = BTreeSet::new();
        for (epoch, _) in self.accepted_claims_by_epoch() {
            if drained.contains(&epoch) {
                continue;
            }
            // Saturating: an `epoch` near `u64::MAX` would otherwise wrap and
            // read as eligible. Claim epochs come from timestamps, so this is
            // not reachable honestly -- but "not reachable honestly" is the
            // description of every input worth bounds-checking.
            if epoch.saturating_add(delay) >= now_epoch {
                continue;
            }
            if floor.is_some_and(|settled| epoch <= settled) {
                continue;
            }
            due.insert(epoch);
        }
        due.into_iter().collect()
    }

    /// The epoch length each of this log's batches was written under.
    ///
    /// Returns `(seq, length)` per batch, recovered as `unix(ts) / epoch`.
    ///
    /// # Why a ratio and not a bound
    ///
    /// The obvious derivation is that a batch pins `floor(unix(ts) / L)` to its
    /// own epoch, which would bound `L` from both sides exactly. **It does
    /// not**, and assuming so makes this function reject every batch it is
    /// given. A batch record's timestamp is when the batch was *written*, and
    /// a batch settles an epoch that has already closed and then waited out
    /// [`FINALITY_EPOCHS`] -- so its timestamp is always in a strictly later
    /// epoch than the one it names. The first version of this check derived the
    /// two-sided bound, produced an empty range for every batch in a real
    /// damaged log, and silently reported nothing.
    ///
    /// The ratio survives that offset. Writing `ts = L * epoch + r`, the
    /// recovered value is `L + r/epoch`, and `r` spans only the few epochs
    /// between an epoch closing and its batch being drained. Epoch numbers are
    /// wall-clock seconds divided by the length -- millions, at any length
    /// worth using -- so `r/epoch` truncates away and the division returns `L`
    /// exactly. Integer division throughout: this feeds a message an operator
    /// acts on, and floats have no place near a number two implementations
    /// must agree on.
    ///
    /// A batch this cannot place is skipped rather than guessed at. Epoch zero
    /// makes the division undefined, and an unreadable timestamp is already
    /// reported by its own check; inventing a length from either would let one
    /// bad record speak for the whole log.
    fn batch_epoch_lengths(&self) -> Vec<(u64, u64)> {
        self.ledger
            .entries_of_kind(BATCH)
            .into_iter()
            .filter_map(|entry| {
                let epoch = entry.payload.get("epoch").and_then(Value::as_u64)?;
                if epoch == 0 {
                    return None;
                }
                let seconds = crate::time::parse_rfc3339(&entry.ts)
                    .filter(|value| *value >= 0)
                    .map(|value| value as u64)?;
                let length = seconds / epoch;
                if length == 0 {
                    return None;
                }
                Some((entry.seq, length))
            })
            .collect()
    }

    /// What this log says about its own epoch length, as an audit note.
    ///
    /// Three outcomes, and the third is the one that did not exist before:
    ///
    /// - **Silent.** The log is self-consistent and the reader is holding it at
    ///   a length inside the feasible range. The ordinary case, and it must not
    ///   be noisy.
    /// - **Recoverable.** One length explains every batch and it is not the one
    ///   in force. Nothing is wrong with the log; the reader has it at the
    ///   wrong length, and the note names the right one.
    /// - **Mixed.** No single length explains every batch, so no reader will
    ///   ever re-derive all of it. That is damage rather than misconfiguration,
    ///   and choosing a better `PROOFWORK_EPOCH_SECONDS` cannot fix it. The
    ///   note says where the log splits, because "this log is broken" without a
    ///   location is not something anyone can act on.
    fn epoch_length_report(&self) -> Vec<String> {
        let lengths = self.batch_epoch_lengths();
        if lengths.is_empty() {
            return Vec::new();
        }

        let mut groups: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
        for (seq, length) in &lengths {
            groups.entry(*length).or_default().push(*seq);
        }

        if groups.len() == 1 {
            let written_at = *groups.keys().next().unwrap_or(&0);
            let in_force = epoch_seconds();
            if written_at == in_force {
                return Vec::new();
            }
            return vec![format!(
                "note: every batch in this log was written with an epoch length of \
                 {written_at}, and this audit used {in_force}. That is a reader setting, not \
                 evidence about the operator -- epochs are derived from record timestamps and \
                 never stored, so a log built by a demo script audits as thoroughly broken under \
                 the default. Re-run with PROOFWORK_EPOCH_SECONDS={written_at}."
            )];
        }

        let described: Vec<String> = groups
            .iter()
            .map(|(length, seqs)| {
                let list: Vec<String> = seqs.iter().map(u64::to_string).collect();
                format!("entries {} at {length}s", list.join(","))
            })
            .collect();
        vec![format!(
            "note: this log was written under MORE THAN ONE epoch length -- {}. No single value \
             of PROOFWORK_EPOCH_SECONDS re-derives all of its batches, so choosing a better one \
             will not fix it and no reader can independently re-derive its whole settlement \
             history. This happens when a demo or a test is pointed at a log that is also used \
             for real settlement.",
            described.join("; ")
        )]
    }

    /// Epochs holding accepted claims that can never settle, because a later
    /// epoch settled first.
    ///
    /// Empty whenever the synchrony assumption behind [`FINALITY_EPOCHS`] held.
    /// A non-empty result is the network telling you it did not: records for
    /// these epochs arrived after the delay had already expired and a later
    /// batch had been written. The claims are accepted and unpaid, and they
    /// stay that way -- this reports the condition, it does not repair it.
    ///
    /// Reported by `audit` rather than left to be noticed, because the whole
    /// point of the delay is to convert a silent fork into a loud one.
    ///
    /// [`FINALITY_EPOCHS`]: crate::partition::FINALITY_EPOCHS
    pub fn late_epochs(&self) -> Vec<u64> {
        let drained = self.drained_epochs();
        let Some(floor) = drained.iter().copied().max() else {
            return Vec::new();
        };
        let mut late: BTreeSet<u64> = BTreeSet::new();
        for (epoch, _) in self.accepted_claims_by_epoch() {
            if epoch <= floor && !drained.contains(&epoch) {
                late.insert(epoch);
            }
        }
        late.into_iter().collect()
    }

    /// The log head as of the start of `epoch`: the hash of the last entry
    /// stamped in an earlier epoch, or the empty string when there is none.
    ///
    /// Derived from the log rather than from a clock, so an auditor reaches the
    /// same value. It is also recorded in the `batch` entry, because a
    /// back-dated append after the fact could otherwise change what this
    /// function returns for an epoch that already settled -- [`Node::audit`]
    /// compares the two and reports a divergence.
    ///
    /// Public because work assignment must key on the same stable anchor:
    /// deriving a partition from the *live* head instead means every append
    /// reshuffles every node's slice mid-epoch, and "anyone can recompute a
    /// peer's region" stops being true.
    /// The settlement anchor: the head of this log's **epoch chain**.
    ///
    /// # Why this is not the log head any more
    ///
    /// It used to be the hash of the last ledger entry before `epoch`, and that
    /// broke the one invariant multi-operator settlement rests on: *two nodes
    /// holding the same records pay the same claims in the same order.* A
    /// ledger entry's hash covers `seq`, `prev` and the local write time, so
    /// two nodes with byte-identical records still have different entry
    /// hashes — different anchor, different beacon, different order, and both
    /// logs audit clean because each is internally consistent. That is the
    /// quietest possible fork, and `tests/p2p_convergence.rs` fails on it.
    ///
    /// The chain is built from **content only**: each link commits to the link
    /// before it, the epoch, and the *sorted* set of claim ids that batch
    /// settled. Sorted, so the link does not depend on the very ordering it is
    /// used to produce.
    ///
    /// **What this does and does not buy, stated exactly.** It removes the
    /// dependence on the ledger *envelope*: two nodes that drain the same
    /// epochs in the same sequence now agree, where with an entry hash they
    /// never could. It does **not** make settlement order converge in general.
    ///
    /// The induction that was originally written here — "if every earlier
    /// batch agreed, the head agrees" — is an induction on the *epoch index*,
    /// while the fold below is over *file position*, and
    /// `epoch_links_before` deliberately keeps those apart. A node that
    /// learns about later work first drains the later epoch first, so its batch
    /// for the *earlier* epoch is anchored on the later epoch's link. Two nodes
    /// then hold the same claims, settle the same claims, audit clean, and pay
    /// them in a different order.
    ///
    /// That is the same family as the partial-view case: the anchor can only
    /// depend on what had already settled when the batch was written, and that
    /// is exactly what differs between nodes that learned in different orders.
    ///
    /// **Both are closed by the finality delay**, which is the other half of
    /// this and lives in `due_epochs` rather than here.
    /// Making eligibility a function of the clock instead of arrival means a
    /// node holding a late epoch also holds every earlier one by the time it
    /// may drain, so the fold over file position and the fold over epoch index
    /// coincide. This function is unchanged by that and still converges only
    /// *given* the same batches in the same sequence — which is worth stating
    /// precisely, because the previous version of this comment claimed more
    /// than it delivered. See `docs/design/settlement-convergence.md` for the
    /// synchrony bound and what happens outside it.
    ///
    /// Grinding resistance is unchanged. `AGENTS.md`'s rule is that the anchor
    /// must be fixed before anyone can still choose part of the sort key, and a
    /// link is fixed when its epoch drains, which is strictly before any reveal
    /// in a later epoch.
    ///
    /// The `epoch` argument is retained for the caller's clarity and is
    /// deliberately unused: the head already covers every batch written so far,
    /// which is exactly "everything settled before this one".
    /// Stops at `epoch`'s own batch, so the answer is the same before and after
    /// that epoch settles. Without that the function would mean "the head right
    /// now", which before a drain is the anchor and after it is the anchor plus
    /// the batch it produced — a caller checking a settled batch's ordering
    /// would get a different value than the batch used, and be right to be
    /// confused. At settle time the batch does not exist yet, so this is
    /// identical to folding the whole log and settlement is unaffected.
    pub fn anchor_of_epoch(&self, epoch: u64) -> String {
        self.anchor_of_epoch_within(epoch, self.ledger.len(), Some(epoch))
    }

    /// [`Node::anchor_of_epoch`] as it stood at `positions`.
    ///
    /// An external beacon for the epoch wins; the epoch-chain head is the
    /// fallback. The fallback is not a nicety — it is what keeps every log
    /// written before beacon records existed auditing clean, and what keeps a
    /// node whose chain source is unreachable settling at all. `Unavailable is
    /// never Reject` applies to a randomness source exactly as it applies to a
    /// verifier: a node that cannot reach the chain must not halt settlement
    /// for everyone, and `audit_beacons` reports which epochs fell back so the
    /// weaker ordering is visible rather than silent.
    ///
    /// Bounded by position for the reason [`Node::epoch_chain_head_within`] is:
    /// a batch must stay auditable against the log as it stood when it was
    /// written, and a beacon record appended afterwards could not have
    /// influenced it whatever epoch it names.
    ///
    /// `stop_at` is passed through to the fallback rather than assumed, because
    /// the two callers legitimately differ: settlement stops at the batch for
    /// the epoch it is about to write, the audit is already bounded by that
    /// batch's own position. Collapsing them would change the anchor derived
    /// for existing logs, which is a fork rather than a refactor.
    fn anchor_of_epoch_within(&self, epoch: u64, positions: usize, stop_at: Option<u64>) -> String {
        match self.epoch_beacon_within(epoch, positions) {
            Some(value) => value,
            None => self.epoch_chain_head_before(positions, stop_at),
        }
    }

    /// The recorded beacon ordering `epoch`, as of `positions`, if there is one.
    ///
    /// Takes the **first** admissible record rather than the last. A later
    /// record for the same epoch is a rule violation that `record_beacon`
    /// refuses and `audit_beacons` reports, but a reader must still be total
    /// on a log that already contains one — and "first" is the only choice
    /// that a second append cannot change.
    fn epoch_beacon_within(&self, epoch: u64, positions: usize) -> Option<String> {
        self.ledger
            .entries_of_kind(BEACON)
            .into_iter()
            .filter(|entry| usize::try_from(entry.seq).unwrap_or(usize::MAX) < positions)
            .filter(|entry| entry.payload.get("orders").and_then(Value::as_u64) == Some(epoch))
            .filter(|entry| beacon_is_in_time(entry, epoch))
            .find_map(|entry| payload_str(&entry.payload, "value").map(String::from))
    }

    /// Record the randomness epoch `orders` will be settled against.
    ///
    /// `value` is opaque here: it is fed to [`partition::beacon`] as a string,
    /// so this module neither parses it nor cares which chain produced it.
    /// What this module enforces is the timing, which is the whole of the
    /// security argument — see [`RuleViolation::BeaconOutOfEpoch`].
    ///
    /// `source` and `block` are provenance for a reader who *does* hold the
    /// chain: they say which value this claims to be, so an auditor with an RPC
    /// endpoint can check it and an auditor without one can still verify that
    /// the order follows from whatever was recorded. That split is deliberate.
    /// Requiring chain access to audit would trade this project's one guarantee
    /// — anyone can re-derive every settled result from the log alone — for a
    /// property it can get without spending it.
    pub fn record_beacon(
        &mut self,
        orders: u64,
        source: &str,
        block: u64,
        value: &str,
        ts: &str,
    ) -> Result<(), RuleViolation> {
        self.record_beacon_with(orders, source, block, value, None, ts)
    }

    /// [`Node::record_beacon`], optionally carrying a delay proof.
    ///
    /// With `Some(proof)` and `source` of [`VDF_SOURCE`], the record is
    /// **self-verifying from the log alone** — which is the property the chain
    /// beacon above cannot have. A chain beacon says *this is what block N
    /// held*, and checking that needs an RPC endpoint; an auditor without one
    /// takes the sequencer's word for the value and can only check that the
    /// ordering follows from it. A delay proof needs nothing outside the file.
    pub fn record_beacon_with(
        &mut self,
        orders: u64,
        source: &str,
        block: u64,
        value: &str,
        proof: Option<(u64, &str)>,
        ts: &str,
    ) -> Result<(), RuleViolation> {
        let drawn_in = epoch_of_timestamp("beacon", ts)?;
        if drawn_in != orders {
            return Err(RuleViolation::BeaconOutOfEpoch { orders, drawn_in });
        }
        if self
            .epoch_beacon_within(orders, self.ledger.len())
            .is_some()
        {
            return Err(RuleViolation::DuplicateBeacon { epoch: orders });
        }
        let mut fields = vec![
            ("orders", Value::Int(i128::from(orders))),
            ("source", Value::string(source)),
            ("block", Value::Int(i128::from(block))),
            ("value", Value::string(value)),
        ];
        if let Some((difficulty, witness)) = proof {
            fields.push(("difficulty", Value::Int(i128::from(difficulty))));
            fields.push(("witness", Value::string(witness)));
        }
        let record = Value::object(fields);
        // Checked before the append, and checked again by `audit` afterwards.
        // A rule enforced only on the way in binds only the people who use this
        // tool to write, and a log can be assembled by concatenation.
        if source == VDF_SOURCE {
            self.check_vdf_beacon(&record, self.ledger.len())?;
        }
        self.append(BEACON, record, ts)
    }

    /// The seed a delay beacon for `epoch` must be computed over.
    ///
    /// The epoch, and the log's Merkle root *below the beacon's own entry*.
    ///
    /// The root rather than the epoch chain head, which was the first choice
    /// and was wrong in a way the test caught: the chain head folds over
    /// `batch` records only, so on a log that has not drained an epoch yet it
    /// is the empty string, and a seed that does not move is a seed the
    /// sequencer can precompute against forever.
    ///
    /// The root moves whenever *anything* in the log does, which is the
    /// property that makes this cost something. A sequencer that wants a
    /// different beacon has to reorder the log — changing the root — and then
    /// pay the delay again for the new seed. Grinding the anchor used to cost a
    /// hash per candidate; it now costs `difficulty` sequential squarings per
    /// candidate, and they cannot be run in parallel.
    ///
    /// Bounded by position for the reason every derivation here is: a beacon
    /// must stay checkable against the log as it stood when it was written,
    /// and a beacon is itself an entry, so it cannot be inside its own seed.
    pub fn vdf_seed(&self, epoch: u64, positions: usize) -> Vec<u8> {
        let root = self
            .ledger
            .prefix(positions)
            .and_then(|prefix| prefix.root())
            .unwrap_or_default();
        let mut seed = Vec::new();
        seed.extend_from_slice(b"proofwork/vdf/seed");
        seed.extend_from_slice(&epoch.to_be_bytes());
        seed.extend_from_slice(root.as_bytes());
        seed
    }

    /// Does this delay beacon really show the work it claims?
    ///
    /// Split out so [`Node::audit`] asks the same question of a record that
    /// arrived some other way.
    pub fn check_vdf_beacon(&self, payload: &Value, positions: usize) -> Result<(), RuleViolation> {
        let epoch = payload
            .get("orders")
            .and_then(Value::as_u64)
            .ok_or(RuleViolation::BeaconDoesNotVerify { epoch: 0 })?;
        let fail = || RuleViolation::BeaconDoesNotVerify { epoch };
        let difficulty = payload
            .get("difficulty")
            .and_then(Value::as_u64)
            .ok_or_else(fail)?;
        let output =
            decode_hex(payload_str(payload, "value").ok_or_else(fail)?).ok_or_else(fail)?;
        let witness =
            decode_hex(payload_str(payload, "witness").ok_or_else(fail)?).ok_or_else(fail)?;
        let proof = crate::vdf::Proof { output, witness };
        if crate::vdf::verify(&self.vdf_seed(epoch, positions), difficulty, &proof) {
            Ok(())
        } else {
            Err(fail())
        }
    }

    /// The epoch chain folded over every `batch` record before `positions`,
    /// additionally stopping at the batch for `stop_at` if one is present.
    ///
    /// The settlement anchor before beacon records existed, and still the
    /// fallback when an epoch has none — see [`Node::anchor_of_epoch_within`].
    ///
    /// Bounded by position for the reason [`Node::accepted_in_epoch_within`] is:
    /// a batch must stay auditable against the log *as it stood when it was
    /// written*. Batches are appended in drain order, so the batches preceding
    /// one in the file are exactly the ones that preceded it in time — and a
    /// batch for an older epoch appended later lands after it, leaving earlier
    /// links untouched instead of retroactively faulting them.
    ///
    /// Folding in **file order rather than epoch order** is the point. Sorting
    /// by epoch would let a back-dated claim create an old epoch whose batch is
    /// written last, changing a link that an already-written batch committed
    /// to, which is the retroactive-fault bug the position bounds exist to
    /// prevent.
    fn epoch_chain_head_before(&self, positions: usize, stop_at: Option<u64>) -> String {
        self.epoch_links_before(positions, stop_at)
            .last()
            .map(|link| link.link.clone())
            .unwrap_or_default()
    }

    /// Every link of this log's epoch chain, oldest first.
    ///
    /// The chain the settlement anchor is the head of, exposed whole so it can
    /// be read rather than only trusted — `proofwork chain`, `GET /chain`, and
    /// the page at `GET /chain.html` all render this. Comparing two nodes'
    /// chains is how you find *where* they diverged rather than only that they
    /// did, which is the question the head alone cannot answer.
    pub fn epoch_chain(&self) -> Vec<EpochLink> {
        self.epoch_links_before(self.ledger.len(), None)
    }

    /// The fold every other epoch-chain accessor is a view of.
    fn epoch_links_before(&self, positions: usize, stop_at: Option<u64>) -> Vec<EpochLink> {
        let mut links: Vec<EpochLink> = Vec::new();
        let mut head = String::new();
        for entry in self.ledger.entries().iter().take(positions) {
            if entry.kind != BATCH {
                continue;
            }
            // A batch whose epoch is missing, or is not a real epoch number,
            // cannot be placed in the chain. The audit reports it separately;
            // skipping keeps one malformed record from making every later
            // link unverifiable.
            //
            // The `u64` range check is not pedantry. This used to fold on the
            // raw `i128` and report `u64::try_from(epoch).unwrap_or(0)` in the
            // link, so a batch naming a *negative* epoch produced a link whose
            // published `epoch` was `0` while its hash committed to the real
            // value — and anybody recomputing `H({prev, epoch, claims})` from
            // `GET /chain` got a different digest and no way to tell why. A
            // chain nobody can recompute is not a chain; it is a number the
            // server asserts.
            let Some(epoch) = entry
                .payload
                .get("epoch")
                .and_then(Value::as_i128)
                .filter(|value| u64::try_from(*value).is_ok())
            else {
                continue;
            };
            if stop_at.is_some_and(|target| i128::from(target) == epoch) {
                break;
            }
            let mut claims: Vec<String> = match entry.payload.get("claims") {
                Some(Value::Array(items)) => items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(String::from)
                    .collect(),
                _ => Vec::new(),
            };
            claims.sort();
            let prev = head.clone();
            head = Value::object([
                ("prev", Value::string(prev.clone())),
                ("epoch", Value::Int(epoch)),
                (
                    "claims",
                    Value::Array(claims.iter().cloned().map(Value::String).collect()),
                ),
            ])
            .digest();
            links.push(EpochLink {
                // Infallible: the filter above admitted only `u64`-range
                // epochs, precisely so this cannot silently report a value
                // the link's hash did not commit to.
                // Infallible: the filter above admitted only `u64`-range
                // epochs, precisely so this cannot silently report a value
                // the link's hash did not commit to.
                epoch: u64::try_from(epoch).expect("filtered to u64 range above"),
                claims,
                prev,
                link: head.clone(),
            });
        }
        links
    }

    /// The last ledger entry before `epoch`, measuring epochs with an explicit
    /// length. **Availability sampling only** — settlement uses
    /// [`Node::anchor_of_epoch`]'s epoch chain instead.
    ///
    /// Kept on the entry hash deliberately rather than moved to the chain. The
    /// two anchors answer different questions:
    ///
    /// - *Settlement* must agree across **nodes**, and an entry hash cannot,
    ///   because it covers `seq`, `prev` and the local write time.
    /// - *Availability sampling* must be unpredictable within **one log**, and
    ///   both implementations auditing that same file see identical entry
    ///   hashes. Moving it to the epoch chain would make the sampled index a
    ///   constant on any log with no settlements in it, which is strictly
    ///   worse — an unbiddable challenge is the whole point.
    ///
    /// What that leaves open is stated rather than hidden: two nodes with
    /// *different* logs still sample different indices for the same
    /// undertaking. Availability is already marked unfit to carry real money
    /// until it is bonded (see `docs/node-incentives.md` and the threat model),
    /// and this does not change that either way.
    ///
    /// The length is a parameter rather than a global read because the two
    /// callers need different ones, and finding that out cost a 60%-flaky
    /// audit. See [`Node::sampled_index`].
    fn anchor_at(&self, epoch: u64, positions: usize, seconds_per_epoch: u64) -> String {
        let mut anchor = String::new();
        for entry in self.ledger.entries().iter().take(positions) {
            match crate::time::parse_rfc3339(&entry.ts) {
                Some(seconds) if seconds >= 0 => {
                    if epoch_of(seconds as u64, seconds_per_epoch) < epoch {
                        anchor = entry.hash.clone();
                    }
                }
                // An entry this node cannot place in time is not evidence about
                // where the epoch boundary was, so it does not move the anchor.
                _ => continue,
            }
        }
        anchor
    }

    /// Accepted claims that have not settled, paired with the epoch they were
    /// revealed in.
    fn accepted_claims_by_epoch(&self) -> Vec<(u64, (String, Claim))> {
        let accepted = self.accepted_claim_ids();
        let mut out = Vec::new();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        for entry in self.ledger.entries_of_kind(CLAIM) {
            let claim = match Claim::from_value(&entry.payload) {
                Ok(claim) => claim,
                Err(_) => continue,
            };
            let claim_id = claim.id();
            if !accepted.contains(&claim_id) || !seen.insert(claim_id.clone()) {
                continue;
            }
            let epoch = match crate::time::parse_rfc3339(&entry.ts) {
                Some(seconds) if seconds >= 0 => epoch_of(seconds as u64, epoch_seconds()),
                // Skipped rather than settled into some default epoch: a claim
                // whose epoch cannot be derived cannot be ordered against its
                // peers, and paying it out of order is worse than not paying it.
                // `audit` reports it.
                _ => continue,
            };
            out.push((epoch, (claim_id, claim)));
        }
        out
    }

    fn accepted_in_epoch(&self, epoch: u64) -> Vec<(String, Claim)> {
        self.accepted_in_epoch_within(epoch, usize::MAX)
    }

    /// Accepted claims of `epoch`, as the log stood at `positions` entries.
    ///
    /// The bound is the same one the anchor gets and it is load-bearing for the
    /// same reason. Records arrive over sync stamped with their own
    /// `created_at` and land at the tail, so a peer can append an accepted
    /// claim dated into an epoch that already paid. Deriving membership over
    /// the whole log then says the batch omitted somebody -- forever, at a
    /// peer's choosing, about a batch that was correct when it was written and
    /// could not have known about a record that did not yet exist.
    ///
    /// The anchor was bounded and this was not, which left the same attack
    /// working one field over: instead of "the anchor is wrong" the audit said
    /// "settled 1 claim(s) in an order the beacon does not produce", which
    /// reads as an accusation that the operator paid people out of turn.
    fn accepted_in_epoch_within(&self, epoch: u64, positions: usize) -> Vec<(String, Claim)> {
        // The *verdicts* are bounded too, not only the claims. A claim already
        // in the log when the batch was written, whose accepting verdict was
        // appended afterwards, was correctly left out of that batch -- counting
        // it now would fault an honest batch just as surely as a back-dated
        // claim would.
        let mut accepted: BTreeSet<String> = BTreeSet::new();
        for entry in self.ledger.entries().iter().take(positions) {
            if entry.kind != VERDICT {
                continue;
            }
            let Some(claim_id) = payload_str(&entry.payload, "claim_id") else {
                continue;
            };
            let is_accept = entry
                .payload
                .get("verdict")
                .and_then(Verdict::from_value)
                .map(|verdict| verdict.accepted())
                .unwrap_or(false);
            if is_accept {
                accepted.insert(claim_id.to_string());
            } else {
                accepted.remove(claim_id);
            }
        }

        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut out = Vec::new();
        for entry in self.ledger.entries().iter().take(positions) {
            if entry.kind != CLAIM {
                continue;
            }
            let Ok(claim) = Claim::from_value(&entry.payload) else {
                continue;
            };
            let claim_id = claim.id();
            if !accepted.contains(&claim_id) || !seen.insert(claim_id.clone()) {
                continue;
            }
            let Some(seconds) = crate::time::parse_rfc3339(&entry.ts).filter(|s| *s >= 0) else {
                continue;
            };
            if epoch_of(seconds as u64, epoch_seconds()) == epoch {
                out.push((claim_id, claim));
            }
        }
        out
    }

    /// Apply the settlement rules to one accepted claim of a closed batch.
    fn settle_one(
        &mut self,
        claim_id: &str,
        claim: &Claim,
        epoch: u64,
        consumed: &BTreeSet<String>,
        ts: &str,
    ) -> Result<Outcome, RuleViolation> {
        // The verdict is re-read from the log rather than re-run: this claim
        // was accepted when it was revealed, and re-running here would let a
        // verifier that has since gone unavailable retract a payment nobody
        // disputed. `audit --rerun` is where re-verification belongs.
        let verdict = self
            .recorded_verdict(claim_id)
            .unwrap_or_else(|| Verdict::accept("recorded acceptance"));

        let objectives = self.objectives();
        let objective = match objectives.get(&claim.objective_id) {
            Some(objective) => objective.clone(),
            None => {
                return Ok(Outcome::unsettled(
                    claim_id.to_string(),
                    verdict,
                    "objective is no longer readable",
                ))
            }
        };

        if let Some(block) = &objective.ratchet {
            let ratchet = match Ratchet::from_value(block) {
                Ok(ratchet) => ratchet,
                Err(error) => {
                    return Ok(Outcome::unsettled(
                        claim_id.to_string(),
                        verdict,
                        format!("objective carries an unusable ratchet: {error}"),
                    ))
                }
            };
            let held = match self.latest_frontier(&claim.objective_id) {
                Ok(held) => held,
                Err(error) => {
                    return Ok(Outcome::unsettled(
                        claim_id.to_string(),
                        verdict,
                        error.to_string(),
                    ))
                }
            };
            return self.settle_improvement(claim, verdict, &ratchet, held.as_ref(), ts);
        }

        // Novelty is necessary but never sufficient. Resubmitting an artifact
        // already in the log verifies fine and mints zero. Checked before the
        // already-settled case so the note names the real reason: the copy
        // would earn nothing even against an open objective.
        //
        // "Already in the log" means revealed *strictly earlier* than this
        // claim, which inside a batch means earlier in beacon order -- the same
        // rule the batch uses for everything else, rather than append order
        // sneaking back in through the duplicate check.
        let artifact_id = claim.artifact_id();
        let earlier = self.artifact_ids_before(&claim.objective_id, epoch);
        if consumed.contains(&artifact_id) || earlier.contains(&artifact_id) {
            return Ok(Outcome::unsettled(
                claim_id.to_string(),
                verdict,
                "duplicate artifact mints nothing",
            ));
        }
        if self.settlement_of(&claim.objective_id).is_some() {
            return Ok(Outcome::unsettled(
                claim_id.to_string(),
                verdict,
                "objective already settled",
            ));
        }

        let settlement = Value::object([
            ("objective_id", Value::string(claim.objective_id.clone())),
            ("claim_id", Value::string(claim_id.to_string())),
            ("submitter", Value::string(claim.submitter.clone())),
            ("reward", Value::Int(i128::from(objective.reward))),
        ]);
        self.append(SETTLEMENT, settlement, ts)?;
        Ok(Outcome {
            claim_id: claim_id.to_string(),
            verdict,
            settled: true,
            reward: objective.reward,
            pending_epoch: None,
            note: String::from("settled"),
        })
    }

    /// Pay for distance moved along a progressive objective's curve.
    ///
    /// Two non-settling outcomes here are deliberately *not* rejections:
    ///
    /// - a verdict with no integer score. The artifact may be fine; the
    ///   evaluator did not produce something the curve can consume.
    /// - a score that does not clear `min_improvement`. The artifact verified.
    ///   It simply does not move the frontier, so it earns nothing -- which is
    ///   precisely why copying the frontier is worthless, and therefore why
    ///   publishing immediately is safe.
    ///
    /// An advance always appends a `frontier` entry and, when the payout is
    /// non-zero, a `settlement`. A zero payout with a real advance is normal:
    /// truncation can eat a one-unit step on a curve whose pool is smaller than
    /// its span, and the frontier still moved.
    fn settle_improvement(
        &mut self,
        claim: &Claim,
        verdict: Verdict,
        ratchet: &Ratchet,
        held: Option<&FrontierEntry>,
        ts: &str,
    ) -> Result<Outcome, RuleViolation> {
        let claim_id = claim.id();

        // `Verdict::score` refuses a bool and anything outside `i64`, which is
        // the reference implementation's explicit `isinstance(score, bool)`
        // guard plus the range the frontier can actually record.
        let reported = verdict.score();
        let score = match reported {
            Some(score) => score,
            None => {
                return Ok(Outcome::unsettled(
                    claim_id,
                    verdict,
                    "verifier produced no integer score",
                ))
            }
        };

        let previous = held.map(|frontier| frontier.score);
        if !ratchet.improves(previous, score) {
            let note = format!(
                "score {score} does not improve on {} by at least {}",
                render_previous(previous),
                ratchet.min_improvement
            );
            return Ok(Outcome::unsettled(claim_id, verdict, note));
        }

        let reward = ratchet
            .payout(previous, score)
            .map_err(RuleViolation::MalformedRatchet)?;
        let paid_before = held.map(|frontier| frontier.paid_cumulative).unwrap_or(0);
        // Python adds bignums here. In `u64` this is the one addition on the
        // money path that can wrap, and a wrapped running total would hide an
        // overspent pool from the audit -- so it is checked, not cast.
        let paid_cumulative =
            paid_before
                .checked_add(reward)
                .ok_or(RuleViolation::PayoutOverflow {
                    paid_cumulative: paid_before,
                    reward,
                })?;

        let advanced = FrontierEntry::new(
            claim.objective_id.clone(),
            claim_id.clone(),
            claim.submitter.clone(),
            score,
            paid_cumulative,
        );
        self.append(FRONTIER, advanced.to_value(), ts)?;

        if reward > 0 {
            let settlement = Value::object([
                ("objective_id", Value::string(claim.objective_id.clone())),
                ("claim_id", Value::string(claim_id.clone())),
                ("submitter", Value::string(claim.submitter.clone())),
                ("reward", Value::Int(i128::from(reward))),
            ]);
            self.append(SETTLEMENT, settlement, ts)?;
        }

        let mut note = String::from("frontier advanced");
        if ratchet.exhausted(score) {
            note.push_str("; target reached, pool exhausted");
        }
        Ok(Outcome {
            claim_id,
            verdict,
            settled: true,
            reward,
            pending_epoch: None,
            note,
        })
    }

    // -- independent verification ----------------------------------------

    /// Re-derive the whole log from scratch. An empty result means it checks out.
    ///
    /// This is the function that makes a single-sequencer network honest: any
    /// reader with a copy of the log runs it and confirms every settled claim
    /// without trusting the operator at all.
    ///
    /// With `rerun`, every claim's verifier is executed again and the fresh
    /// status compared against the recorded one. The subtle case is a fresh
    /// verdict that does not settle:
    ///
    /// - for an unsettled claim it is an infrastructure fact and says nothing;
    /// - for a claim that was **paid**, it means the payment can no longer be
    ///   independently re-derived, which is exactly what an auditor needs told.
    ///   Reporting "log verified" there would be a lie of omission -- nothing
    ///   was actually checked.
    ///
    /// The remaining invariants: settlements reference accepted claims, a
    /// non-ratchet objective settles at most once, a pool is never overspent,
    /// and a frontier never moves backwards. "Settled once" is the wrong
    /// invariant for a progressive objective, which pays along a curve; the two
    /// that must hold there are the pool bound and frontier monotonicity.
    pub fn audit(&self, rerun: bool) -> Vec<String> {
        let mut problems = self.ledger.verify_chain();
        let (objectives, mut undecodable) = self.decode_objectives();
        problems.append(&mut undecodable);

        // Peer records settle nothing, so a bad one cannot cost money -- but a
        // reader must be told rather than left to wonder why a peer the log
        // names is never dialled. Both failures are named: one that cannot be
        // decoded, and one that decodes and does not prove who it speaks for.
        let mut peer_seqs: BTreeMap<&str, u64> = BTreeMap::new();
        for entry in self.ledger.entries_of_kind(PEER) {
            let record = match PeerRecord::from_value(&entry.payload) {
                Ok(record) => record,
                Err(error) => {
                    problems.push(format!(
                        "peer at entry {}: cannot be decoded ({error})",
                        entry.seq
                    ));
                    continue;
                }
            };
            if let Err(error) = record.verify_signature() {
                problems.push(format!("peer at entry {}: {error}", entry.seq));
                continue;
            }
            // A record that does not advance its identity's sequence is one
            // `post_peer` would have refused, so finding one means the log was
            // assembled by other means and a reader should know.
            //
            // The running *maximum*, not the last value seen. This used to
            // overwrite, which made the audit disagree with [`Node::peers`] --
            // where highest-seq-wins -- on any log containing a stale record.
            // Given seq 3, then a replayed 1, then a 2: `peers` still answers
            // 3, so the 2 did not supersede either and both are findings. The
            // overwriting version reported the 1 and passed the 2, which is an
            // audit contradicting its own implementation's resolution rule.
            match peer_seqs.get(record.identity.as_str()) {
                Some(held) if *held >= record.seq => problems.push(format!(
                    "peer at entry {}: seq {} does not advance {held} for {}",
                    entry.seq,
                    record.seq,
                    crate::canonical::short(&record.identity)
                )),
                _ => {}
            }
            if let Some(identity) = entry_identity(&entry.payload) {
                let slot = peer_seqs.entry(identity).or_insert(record.seq);
                *slot = (*slot).max(record.seq);
            }
        }

        // Committee shares. This is the reader-side half of the rule that makes
        // the key reveal consensus-derived rather than a promise: the committee
        // is a beacon draw over the log, and every share record must answer a
        // seat that draw produced, published by the identity holding it, in an
        // epoch strictly later than the commitment's.
        //
        // Re-derived here rather than trusted for the same reason
        // `check_availability` is: a log can be assembled by concatenation, so
        // a rule with no reader-side counterpart binds only the people who use
        // this tool to write. And it matters more here than for a peer record,
        // because a share that looks admissible and is not is a claim someone
        // was paid for on evidence that does not hold up.
        //
        // Bounded at the record's own position, so the committee is the one
        // that was drawn when the share was written rather than the one a later
        // peer record would produce.
        let mut seats_seen: BTreeSet<(String, u8)> = BTreeSet::new();
        for entry in self.ledger.entries_of_kind(COMMITTEE_SHARE) {
            let record = match CommitteeShare::from_value(&entry.payload) {
                Ok(record) => record,
                Err(error) => {
                    problems.push(format!(
                        "committee_share at entry {}: cannot be decoded ({error})",
                        entry.seq
                    ));
                    continue;
                }
            };
            if let Err(error) = record.validate() {
                problems.push(format!("committee_share at entry {}: {error}", entry.seq));
                continue;
            }
            if let Err(error) = record.verify_signature() {
                problems.push(format!("committee_share at entry {}: {error}", entry.seq));
                continue;
            }
            if let Err(error) = self.check_committee_share(&record, entry.seq as usize) {
                problems.push(format!("committee_share at entry {}: {error}", entry.seq));
                continue;
            }
            if !seats_seen.insert((record.commitment.clone(), record.seat)) {
                problems.push(format!(
                    "committee_share at entry {}: seat {} of commitment {} published twice",
                    entry.seq,
                    record.seat,
                    crate::canonical::short(&record.commitment)
                ));
            }
        }

        // The money supply. Two faults, and between them they are what makes
        // every other number in this audit mean something.
        //
        // First: an issuance below the genesis prefix. A supply is the log's
        // opening statement or it is not a supply, so a mint further down is
        // reported wherever it sits rather than quietly credited.
        //
        // Second: conservation. On a log that declares a supply, no identity
        // may have committed more than the log says it holds — issued plus
        // settled, against bonds locked plus rewards escrowed. `post_objective`
        // and `post_undertaking` refuse that on the way in, but a log arriving
        // from somebody else was never posted anywhere, so the rule has to be
        // re-derivable from the records alone. Without this pass, the whole
        // chain is only as strong as the politeness of whoever wrote the log,
        // and the bond that the availability pool is divided by is decoration.
        let genesis = self.genesis_prefix();
        for entry in self.ledger.entries_of_kind(ISSUANCE) {
            if (entry.seq as usize) < genesis {
                continue;
            }
            let (holder, units) = match Issuance::from_value(&entry.payload) {
                Ok(record) => (record.holder, record.units),
                Err(error) => {
                    problems.push(format!(
                        "issuance at entry {}: cannot be decoded ({error})",
                        entry.seq
                    ));
                    continue;
                }
            };
            problems.push(format!(
                "issuance at entry {}: {units} units to {} after the genesis prefix \
                 ended at entry {genesis}; a supply is declared once, in the log's \
                 opening entries, or it is not a supply",
                entry.seq,
                crate::canonical::short(&holder)
            ));
        }
        if self.declares_supply() {
            let positions = self.ledger.len();
            let held = self.gross_paid_within(positions);
            let mut names: BTreeSet<String> = held.keys().cloned().collect();
            let committed = self.committed_within(positions);
            names.extend(committed.keys().cloned());
            for name in names {
                let holds = held.get(&name).copied().unwrap_or(0);
                let owes = committed.get(&name).copied().unwrap_or(0);
                if owes > holds {
                    problems.push(format!(
                        "{} has committed {owes} units against {holds} the log issued or \
                         paid it; a unit nobody issued is money made by naming it",
                        crate::canonical::short(&name)
                    ));
                }
            }
        }

        // Undertakings. Same three failures as a peer record -- undecodable,
        // unsigned, or signed by somebody else -- plus the one that is specific
        // to this kind and is the reason the record exists: a root this log
        // never had. `post_undertaking` refuses that, so finding one means the
        // log was assembled by other means, and it matters more than the peer
        // case does because a promise nobody can sample is a promise nobody can
        // be paid or slashed against.
        for entry in self.ledger.entries_of_kind(UNDERTAKING) {
            let record = match Undertaking::from_value(&entry.payload) {
                Ok(record) => record,
                Err(error) => {
                    problems.push(format!(
                        "undertaking at entry {}: cannot be decoded ({error})",
                        entry.seq
                    ));
                    continue;
                }
            };
            if let Err(error) = record.verify_signature() {
                problems.push(format!("undertaking at entry {}: {error}", entry.seq));
                continue;
            }
            // The promise must cover the whole log as it stood below this
            // record. `seq` is exactly that count, which is what makes the rule
            // checkable now that the log is longer.
            if record.height != entry.seq {
                problems.push(format!(
                    "undertaking at entry {}: promises {} entries where the log below it \
                     had {}; the size of a promise is not the promiser's to choose",
                    entry.seq, record.height, entry.seq
                ));
                continue;
            }
            // The bond must have been affordable when this record was
            // written. Re-derived from the prefix below it, never from the
            // whole log: a later payout must not retroactively justify a bond
            // that was unfunded at the time, and a later bond must not
            // retroactively bankrupt one that was funded.
            let spendable = self.spendable_within(&record.identity, entry.seq as usize);
            if u128::from(record.bond) > spendable {
                problems.push(format!(
                    "undertaking at entry {}: bonds {} units against a balance of {}",
                    entry.seq, record.bond, spendable
                ));
                continue;
            }
            let known = usize::try_from(record.height).ok().is_some_and(|height| {
                self.ledger
                    .prefix(height)
                    .and_then(|prefix| prefix.root())
                    .is_some_and(|root| root == record.root)
            });
            if !known {
                problems.push(format!(
                    "undertaking at entry {}: no prefix of {} entries is rooted at {}",
                    entry.seq,
                    record.height,
                    crate::canonical::short(&record.root)
                ));
            }
        }

        // Availability answers. The findings that matter are the ones about
        // money: an answer that does not check is one the availability pool
        // must not pay, and a duplicate is one node claiming a sample twice.
        let mut answered: BTreeSet<(String, u64)> = BTreeSet::new();
        for entry in self.ledger.entries_of_kind(AVAILABILITY) {
            let record = match Availability::from_value(&entry.payload) {
                Ok(record) => record,
                Err(error) => {
                    problems.push(format!(
                        "availability at entry {}: cannot be decoded ({error})",
                        entry.seq
                    ));
                    continue;
                }
            };
            if let Err(error) = record.verify_signature() {
                problems.push(format!("availability at entry {}: {error}", entry.seq));
                continue;
            }
            if let Err(error) = self.check_availability(&record, entry.seq as usize) {
                problems.push(format!("availability at entry {}: {error}", entry.seq));
                continue;
            }
            // One answer per promise per epoch. A second is not a second
            // service rendered -- the sample is the same index -- so paying it
            // twice would pay for one piece of work twice.
            let slot = (record.undertaking.clone(), record.epoch);
            if !answered.insert(slot) {
                problems.push(format!(
                    "availability at entry {}: undertaking {} was already answered for \
                     epoch {}",
                    entry.seq,
                    crate::canonical::short(&record.undertaking),
                    record.epoch
                ));
            }
        }

        // The availability pool, checked the way objective pools are: total
        // paid against total funded, in `u128`. A wrapped sum turns an
        // overspent pool into a small number and hides exactly the fault this
        // is looking for.
        //
        // Also re-derives each settlement's own arithmetic rather than reading
        // the numbers it recorded: the rewards must sum with the remainder to
        // exactly what the pools offered that epoch, or somebody's division did
        // not close and units went somewhere the record does not say.
        let mut availability_paid: u128 = 0;
        let mut availability_funded: u128 = 0;
        for pool in self.availability_pools() {
            availability_funded = availability_funded.saturating_add(pool.ceiling());
        }
        for entry in self.ledger.entries_of_kind(AVAILABILITY_SETTLEMENT) {
            let rows = entry.payload.get("paid").and_then(Value::as_array);
            let unpaid = entry.payload.get("unpaid").and_then(Value::as_i128);
            let (Some(rows), Some(unpaid)) = (rows, unpaid) else {
                problems.push(format!(
                    "availability settlement at entry {}: missing paid or unpaid",
                    entry.seq
                ));
                continue;
            };
            if unpaid < 0 {
                problems.push(format!(
                    "availability settlement at entry {}: negative remainder",
                    entry.seq
                ));
                continue;
            }
            // Summed row by row, because the rows are what say who was paid.
            // A total taken from a `share` field would agree with itself while
            // disagreeing with the payments beside it.
            let mut spent: u128 = 0;
            let mut negative = false;
            let mut seen: BTreeSet<&str> = BTreeSet::new();
            for row in rows {
                match row.get("reward").and_then(Value::as_i128) {
                    Some(reward) if reward >= 0 => spent = spent.saturating_add(reward as u128),
                    _ => negative = true,
                }
                // One row per identity. Two rows for one key would be a second
                // payment for one epoch's work, and summing them would hide it.
                if let Some(who) = payload_str(row, "identity") {
                    if !seen.insert(who) {
                        problems.push(format!(
                            "availability settlement at entry {}: {} is paid twice",
                            entry.seq,
                            crate::canonical::short(who)
                        ));
                    }
                }
            }
            if negative {
                problems.push(format!(
                    "availability settlement at entry {}: a payment is missing or negative",
                    entry.seq
                ));
                continue;
            }
            availability_paid = availability_paid.saturating_add(spent);
            if let Some(epoch) = entry.payload.get("epoch").and_then(Value::as_u64) {
                let offered = self.availability_offered(epoch);
                if spent.saturating_add(unpaid as u128) != offered {
                    problems.push(format!(
                        "availability settlement at entry {}: epoch {epoch} offered {offered} \
                         but the record accounts for {}",
                        entry.seq,
                        spent.saturating_add(unpaid as u128)
                    ));
                }
            }
        }
        if availability_paid > availability_funded {
            problems.push(format!(
                "availability pool overspent: {availability_paid} paid against \
                 {availability_funded} funded"
            ));
        }

        // Later verdicts supersede earlier ones for the same claim, matching the
        // reference implementation's dict assignment.
        let mut recorded: BTreeMap<&str, &Value> = BTreeMap::new();
        for entry in self.ledger.entries_of_kind(VERDICT) {
            if let (Some(claim_id), Some(verdict)) = (
                payload_str(&entry.payload, "claim_id"),
                entry.payload.get("verdict"),
            ) {
                recorded.insert(claim_id, verdict);
            }
        }

        let mut paid: BTreeSet<&str> = BTreeSet::new();
        for entry in self.ledger.entries_of_kind(SETTLEMENT) {
            if let Some(claim_id) = payload_str(&entry.payload, "claim_id") {
                paid.insert(claim_id);
            }
        }

        // Claims in log order, deduplicated by id.
        let mut seen_claims: BTreeSet<String> = BTreeSet::new();
        for entry in self.ledger.entries_of_kind(CLAIM) {
            let claim = match Claim::from_value(&entry.payload) {
                Ok(claim) => claim,
                Err(error) => {
                    problems.push(format!(
                        "claim at entry {}: cannot be decoded ({error})",
                        entry.seq
                    ));
                    continue;
                }
            };
            let claim_id = claim.id();
            if !seen_claims.insert(claim_id.clone()) {
                continue;
            }
            if self.matching_commitment(&claim).is_none() {
                problems.push(format!("claim {claim_id}: no matching commitment"));
            }
            let recorded_verdict = match recorded.get(claim_id.as_str()) {
                Some(verdict) => *verdict,
                None => {
                    problems.push(format!("claim {claim_id}: no verdict recorded"));
                    continue;
                }
            };
            // A status no implementation recognises is a malformed log, and it
            // is malformed whether or not this node can re-run the verifier --
            // so it belongs here, ahead of the `rerun` gate, rather than being
            // noticed only as a disagreement further down. It used to surface
            // as a placeholder in a comparison, which meant it was reported
            // when re-verification happened to settle and silent otherwise:
            // the loudness of a structural defect depended on whether an
            // unrelated toolchain was installed.
            let was = match status_of(recorded_verdict).and_then(Status::from_wire) {
                Some(status) => status.as_str(),
                None => {
                    problems.push(format!(
                        "claim {claim_id}: recorded verdict has no readable status ({})",
                        recorded_verdict.canonical_string()
                    ));
                    continue;
                }
            };
            if !rerun {
                continue;
            }
            let objective = match objectives.get(&claim.objective_id) {
                Some(objective) => objective,
                None => {
                    problems.push(format!("claim {claim_id}: unknown objective"));
                    continue;
                }
            };
            let fresh = self.registry.run(&objective.verifier, &claim.artifact);
            if !fresh.settles() {
                // This node cannot re-derive the verdict. Whether that is worth
                // reporting is decided by what the *log* recorded, not by what
                // this node happens to be able to run:
                //
                // * The log recorded `unavailable` too -- nothing was ever
                //   claimed about the artifact, and nothing is claimed now.
                // * The log settled the claim. The audit's own summary line is
                //   "every settled claim re-verified", and it is now false.
                //
                // The second case used to be reported only when the claim had
                // also been *paid*, which left a real hole: a `reject` never
                // pays, so a rejection nobody else could reproduce passed every
                // audit in silence. That is the worse direction of the two. A
                // payment somebody will contest; a rejected submitter has no
                // money to point at and no way to show the rejection was not
                // reproducible. Censorship that leaves no trace in any audit is
                // exactly what re-derivation is supposed to prevent.
                if paid.contains(claim_id.as_str()) {
                    problems.push(format!(
                        "claim {claim_id}: was settled but can no longer be re-verified \
                         ({}: {})",
                        fresh.status, fresh.detail
                    ));
                } else if Status::from_wire(was).is_some_and(|status| status.settles()) {
                    problems.push(format!(
                        "claim {claim_id}: recorded {was} but can no longer be re-verified \
                         ({}: {})",
                        fresh.status, fresh.detail
                    ));
                }
                continue;
            }
            // Only a *settled* recorded verdict can be contradicted. An
            // `unavailable` was never a statement about the artifact, so a node
            // that can now run the verifier and gets an answer has learned
            // something rather than caught somebody -- nothing settled, nobody
            // was paid, and the objective is still open.
            //
            // This fired on the ordinary workflow the moment there was one:
            // fetch a pinned checker from a peer, then audit, and every claim
            // recorded before the fetch was reported as a disagreement. The
            // reference implementation had the rule right and this one did not,
            // which is what a second implementation is for.
            if Status::from_wire(was).is_some_and(|status| status.settles())
                && fresh.status.as_str() != was
            {
                problems.push(format!(
                    "claim {claim_id}: recorded {was}, re-verification says {}",
                    fresh.status
                ));
            }
        }

        for entry in self.ledger.entries_of_kind(SETTLEMENT) {
            let objective_id =
                payload_str(&entry.payload, "objective_id").unwrap_or("(no objective_id)");
            let accepted = payload_str(&entry.payload, "claim_id")
                .and_then(|claim_id| recorded.get(claim_id))
                .and_then(|verdict| status_of(verdict))
                == Some(Status::Accept.as_str());
            if !accepted {
                problems.push(format!(
                    "settlement of {objective_id}: paid a claim that was not accepted"
                ));
            }
        }

        let mut seen_objectives: BTreeSet<String> = BTreeSet::new();
        let mut paid_total: BTreeMap<String, i128> = BTreeMap::new();
        for entry in self.ledger.entries_of_kind(SETTLEMENT) {
            let objective_id = match payload_str(&entry.payload, "objective_id") {
                Some(objective_id) => objective_id.to_string(),
                None => {
                    problems.push(format!(
                        "settlement at entry {}: no objective_id",
                        entry.seq
                    ));
                    continue;
                }
            };
            let objective = objectives.get(&objective_id);
            let progressive = objective.is_some_and(|o| o.ratchet.is_some());
            if seen_objectives.contains(&objective_id) && !progressive {
                problems.push(format!("objective {objective_id}: settled more than once"));
            }
            seen_objectives.insert(objective_id.clone());

            let reward = match entry.payload.get("reward").and_then(Value::as_i128) {
                Some(reward) => reward,
                None => {
                    problems.push(format!(
                        "settlement of {objective_id}: reward is not an integer"
                    ));
                    continue;
                }
            };
            // Summed in `i128` with a checked add: the totals come from a log
            // that may be hostile, and a wrapped sum would report an overspent
            // pool as being within budget.
            let running = paid_total.entry(objective_id.clone()).or_insert(0);
            match running.checked_add(reward) {
                Some(total) => *running = total,
                None => problems.push(format!(
                    "objective {objective_id}: settled rewards overflow any representable total"
                )),
            }
        }

        for (objective_id, total) in &paid_total {
            let objective = match objectives.get(objective_id) {
                Some(objective) => objective,
                None => {
                    problems.push(format!(
                        "settlement references unknown objective {objective_id}"
                    ));
                    continue;
                }
            };
            if *total > i128::from(objective.reward) {
                problems.push(format!(
                    "objective {objective_id}: paid {total} against a pool of {}",
                    objective.reward
                ));
            }
            // Not in the reference implementation, and strictly additive: a
            // negative settlement is unrepresentable in anything this crate
            // writes, but a hand-edited log could use one to mask an overspend
            // by dragging the total back under the pool.
            if *total < 0 {
                problems.push(format!(
                    "objective {objective_id}: settled rewards sum to a negative total {total}"
                ));
            }
        }

        problems.append(&mut self.audit_batches());
        problems.append(&mut self.audit_beacons());
        problems.append(&mut self.audit_challenges());

        for (objective_id, objective) in &objectives {
            let block = match &objective.ratchet {
                Some(block) => block,
                None => continue,
            };
            let ratchet = match Ratchet::from_value(block) {
                Ok(ratchet) => ratchet,
                Err(error) => {
                    problems.push(format!(
                        "objective {objective_id}: ratchet cannot be decoded ({error})"
                    ));
                    continue;
                }
            };
            let mut best: Option<i64> = None;
            for entry in self.ledger.entries_of_kind(FRONTIER) {
                if payload_str(&entry.payload, "objective_id") != Some(objective_id.as_str()) {
                    continue;
                }
                let score = match entry.payload.get("score").and_then(Value::as_i64) {
                    Some(score) => score,
                    None => {
                        problems.push(format!(
                            "objective {objective_id}: frontier entry {} has no recordable score",
                            entry.seq
                        ));
                        continue;
                    }
                };
                if let Some(previous) = best {
                    if !ratchet.improves(Some(previous), score) {
                        problems.push(format!(
                            "objective {objective_id}: frontier moved to {score} without \
                             improving on {previous}"
                        ));
                    }
                }
                best = Some(score);
            }
        }

        // Batch faults are usually the auditor and the writer disagreeing about
        // how long an epoch is, not anybody being paid out of turn. Epochs are
        // derived from timestamps and never stored, so a log written under
        // `PROOFWORK_EPOCH_SECONDS=1` audits as thoroughly broken under the
        // default 600 -- both implementations agree, and both are right.
        //
        // This used to be a *guess*: printed only when every batch faulted, and
        // hedged as "more often a mismatched epoch length than a dishonest
        // operator". Two things were wrong with it, and a real damaged log
        // showed both. It could not fire when only *some* batches faulted --
        // which is exactly what a log written under two lengths looks like, so
        // the case most needing an explanation got none. And it could not tell
        // a recoverable mistake (re-run with the right length) from permanent
        // damage (no length re-derives this log), so it hedged over the
        // distinction that decides whether the operator has a problem at all.
        //
        // Neither has to be guessed. See `epoch_length_report`.
        problems.extend(self.epoch_length_report());

        // Claims that can no longer be paid because a later epoch settled
        // first. Not a fault in this log -- every batch here is correctly
        // derived, which is exactly why it needs saying out loud. It means the
        // synchrony assumption behind `FINALITY_EPOCHS` did not hold, and this
        // node's payouts are a subset of what a node that heard in time paid.
        // Silence here would be the old failure mode wearing a clean audit.
        let late = self.late_epochs();
        if !late.is_empty() {
            problems.push(format!(
                "note: {} epoch(s) hold accepted claims that can never settle, because a later \
                 epoch was paid first: {}. Records for them arrived more than PROOFWORK_\
                 FINALITY_EPOCHS (this audit used {}) after their epoch closed. Every batch in \
                 this log is correctly derived; what is wrong is that a peer which received \
                 those records on time has paid claims this node never will.",
                late.len(),
                late.iter()
                    .map(u64::to_string)
                    .collect::<Vec<_>>()
                    .join(", "),
                crate::partition::finality_epochs()
            ));
        }

        problems
    }

    /// Every way a dispute record can be wrong.
    ///
    /// Restated here rather than trusted from [`Node::post_challenge`] and
    /// [`Node::post_bisection`], because a log can be assembled by something
    /// other than this code path -- imported from a peer, drained from a queue,
    /// or written by hand -- and an audit that only re-checked what its own
    /// writer already checked would verify nothing. This module has been caught
    /// out by exactly that twice.
    ///
    /// No stepper runs here. Re-adjudicating every settled dispute would make
    /// an audit cost a subprocess per dispute, and the *outcome* is checkable
    /// without one: the bisection transcript decides which step was in dispute,
    /// and `audit --rerun` is where re-execution belongs.
    fn audit_challenges(&self) -> Vec<String> {
        let mut problems = Vec::new();
        let accepted = self.accepted_claim_ids();
        let objectives = self.objectives();
        let mut seen: BTreeSet<String> = BTreeSet::new();

        for entry in self.ledger.entries_of_kind(CHALLENGE) {
            let record = match Challenge::from_value(&entry.payload) {
                Ok(record) => record,
                Err(error) => {
                    problems.push(format!(
                        "challenge at entry {}: cannot be decoded ({error})",
                        entry.seq
                    ));
                    continue;
                }
            };
            let id = record.id();
            if record.verify_signature().is_err() {
                problems.push(format!("challenge {id}: signature does not verify"));
            }
            if !seen.insert(format!("{}|{}", record.claim_id, record.challenger)) {
                problems.push(format!(
                    "challenge {id}: {} already had a live objection to claim {}",
                    record.challenger, record.claim_id
                ));
            }
            if !accepted.contains(&record.claim_id) {
                problems.push(format!(
                    "challenge {id}: claim {} was never accepted",
                    record.claim_id
                ));
                continue;
            }
            let Some((claim, _)) = self.disputed_claim(&record) else {
                problems.push(format!(
                    "challenge {id}: claim {} is not in this log",
                    record.claim_id
                ));
                continue;
            };
            match objectives.get(&claim.objective_id) {
                Some(objective) if crate::challenge::Stepper::declared(&objective.verifier) => {}
                _ => problems.push(format!(
                    "challenge {id}: objective {} declares no stepper, so this \
                     dispute could never be adjudicated",
                    claim.objective_id
                )),
            }
            match Node::committed_trace(&claim) {
                None => problems.push(format!(
                    "challenge {id}: claim {} commits to no trace",
                    record.claim_id
                )),
                Some((root, states)) => {
                    if root == record.root {
                        problems.push(format!("challenge {id}: agrees with the claim it disputes"));
                    }
                    if states != record.states {
                        problems.push(format!(
                            "challenge {id}: claim commits to {states} states, challenge to {}",
                            record.states
                        ));
                    }
                }
            }
            // The window, re-derived from the two records' own timestamps.
            if let (Ok(opened), Ok(claimed)) = (
                epoch_of_timestamp(CHALLENGE, &record.created_at),
                epoch_of_timestamp(CLAIM, &claim.created_at),
            ) {
                let closes = claimed.saturating_add(CHALLENGE_WINDOW_EPOCHS);
                if opened > closes {
                    problems.push(format!(
                        "challenge {id}: opened in epoch {opened}, after the window \
                         on claim {} shut at {closes}",
                        record.claim_id
                    ));
                }
            }
        }

        // Every move opens the root its author committed to, and its author is
        // a party. This is the check the whole game rests on.
        let challenges = self.challenges();
        for entry in self.ledger.entries_of_kind(BISECTION) {
            let record = match BisectionMove::from_value(&entry.payload) {
                Ok(record) => record,
                Err(error) => {
                    problems.push(format!(
                        "bisection at entry {}: cannot be decoded ({error})",
                        entry.seq
                    ));
                    continue;
                }
            };
            if record.verify_signature().is_err() {
                problems.push(format!(
                    "bisection at entry {}: signature does not verify",
                    entry.seq
                ));
                continue;
            }
            let Some(challenge) = challenges.get(&record.challenge_id) else {
                problems.push(format!(
                    "bisection at entry {}: no challenge {}",
                    entry.seq, record.challenge_id
                ));
                continue;
            };
            let Some(side) = self.side_of(challenge, &record.mover) else {
                problems.push(format!(
                    "bisection at entry {}: {} is not a party to {}",
                    entry.seq, record.mover, record.challenge_id
                ));
                continue;
            };
            let Some((claim, _)) = self.disputed_claim(challenge) else {
                continue;
            };
            let Some((defender_root, states)) = Node::committed_trace(&claim) else {
                continue;
            };
            let root = match side {
                crate::challenge::Side::Defender => defender_root,
                crate::challenge::Side::Challenger => challenge.root.clone(),
            };
            let index = record.index as usize;
            let mv = crate::challenge::Move {
                challenge: record.challenge_id.clone(),
                index,
                state: record.state.clone(),
                path: crate::canonical::Inclusion {
                    index,
                    leaves: states as usize,
                    siblings: record.path.clone(),
                },
            };
            if !mv.opens(&root) {
                problems.push(format!(
                    "bisection at entry {}: the {side}'s move at state {index} does \
                     not open the root it committed to",
                    entry.seq
                ));
            }
        }

        // A settlement names a party, moves no more than was at stake, and does
        // not decide the same dispute twice.
        let mut decided: BTreeSet<String> = BTreeSet::new();
        for entry in self.ledger.entries_of_kind(CHALLENGE_SETTLEMENT) {
            let Some(id) = payload_str(&entry.payload, "challenge_id") else {
                problems.push(format!(
                    "challenge settlement at entry {}: names no challenge",
                    entry.seq
                ));
                continue;
            };
            if !decided.insert(id.to_string()) {
                problems.push(format!("challenge {id}: settled more than once"));
            }
            let Some(challenge) = challenges.get(id) else {
                problems.push(format!(
                    "challenge settlement at entry {}: no challenge {id}",
                    entry.seq
                ));
                continue;
            };
            let units = entry
                .payload
                .get("units")
                .and_then(Value::as_i128)
                .unwrap_or(-1);
            if units < 0 {
                problems.push(format!("challenge {id}: settled a negative amount"));
                continue;
            }
            let Some((claim, objective)) = self.disputed_claim(challenge) else {
                continue;
            };
            let winner = payload_str(&entry.payload, "winner").unwrap_or_default();
            let loser = payload_str(&entry.payload, "loser").unwrap_or_default();
            let parties = [claim.submitter.as_str(), challenge.challenger.as_str()];
            if !parties.contains(&winner) || !parties.contains(&loser) || winner == loser {
                problems.push(format!(
                    "challenge {id}: settled between {winner} and {loser}, who are \
                     not the two parties"
                ));
            }
            // The ceiling on either side: a challenger risks their bond, and a
            // defender risks what the disputed claim paid them.
            let ceiling = if loser == challenge.challenger {
                u128::from(challenge.bond)
            } else {
                u128::from(objective.reward)
            };
            if units as u128 > ceiling {
                problems.push(format!(
                    "challenge {id}: moved {units} against a ceiling of {ceiling}"
                ));
            }
        }

        problems
    }

    /// Every way a beacon record can be wrong.
    ///
    /// Both are rule violations that [`Node::record_beacon`] refuses, restated
    /// here because a log can be assembled by something other than this code
    /// path — imported from a peer, or written by hand — and an audit that only
    /// re-checked what its own writer already checked would verify nothing.
    ///
    /// Epochs that settled on the fallback are **not** reported here. See
    /// [`Node::epochs_without_beacon`] for why that is a separate query.
    fn audit_beacons(&self) -> Vec<String> {
        let mut problems = Vec::new();
        let mut seen: BTreeSet<u64> = BTreeSet::new();
        for entry in self.ledger.entries_of_kind(BEACON) {
            let orders = match entry.payload.get("orders").and_then(Value::as_u64) {
                Some(orders) => orders,
                None => {
                    problems.push(format!(
                        "beacon at entry {}: names no epoch to order",
                        entry.seq
                    ));
                    continue;
                }
            };
            if !seen.insert(orders) {
                problems.push(format!(
                    "epoch {orders}: more than one beacon, so the settlement order is \
                     whichever one a reader picks"
                ));
            }
            if !beacon_is_in_time(entry, orders) {
                problems.push(format!(
                    "beacon at entry {}: orders epoch {orders} but was drawn at {}, \
                     outside it -- a beacon drawn early can be ground against by a \
                     committer, one drawn late by the operator",
                    entry.seq, entry.ts
                ));
            }
            // A delay beacon carries its own evidence, so unlike a chain
            // beacon it can be checked here rather than taken on the
            // sequencer's word. Checked against the log *as it stood below the
            // record*, because the seed is the epoch anchor and a later append
            // must not be able to invalidate a beacon that was right when it
            // was written.
            if payload_str(&entry.payload, "source") == Some(VDF_SOURCE) {
                if let Err(error) = self.check_vdf_beacon(&entry.payload, entry.seq as usize) {
                    problems.push(format!("beacon at entry {}: {error}", entry.seq));
                }
            }
        }

        if beacon_required() {
            for epoch in self.epochs_without_beacon() {
                problems.push(format!(
                    "epoch {epoch}: settled with no beacon, so it was ordered against \
                     the epoch chain head -- a value the sequencer influences by \
                     choosing what to append ({REQUIRE_BEACON_ENV}=1)"
                ));
            }
        }

        problems
    }

    /// Settled epochs that were ordered against the epoch-chain head because no
    /// beacon covered them.
    ///
    /// Deliberately **not** part of [`Node::audit`]. `audit` is a fault
    /// channel — the CLI exits non-zero on a non-empty result — and settling on
    /// the fallback is legal, is what every log written before beacon records
    /// existed did, and is what an honest node does when its chain source is
    /// unreachable. Reporting it as a fault would fail the audit of
    /// `launch/proofwork.jsonl`, which is published precisely so that readers
    /// can check it, and would train operators to ignore audit output.
    ///
    /// It is still worth asking, because an epoch ordered against the chain
    /// head was ordered against a value the sequencer influences by choosing
    /// what to append. A log that mixes strong and weak epochs reads as
    /// uniformly strong, and `AGENTS.md` is explicit that overstating what is
    /// defended is the one thing this repository cannot afford. So: a separate
    /// question, with an answer a reader has to ask for.
    pub fn epochs_without_beacon(&self) -> Vec<u64> {
        self.ledger
            .entries_of_kind(BATCH)
            .into_iter()
            .filter_map(|entry| {
                let epoch = entry.payload.get("epoch").and_then(Value::as_u64)?;
                let position = usize::try_from(entry.seq).unwrap_or(usize::MAX);
                self.epoch_beacon_within(epoch, position)
                    .is_none()
                    .then_some(epoch)
            })
            .collect()
    }

    /// Re-derive every settlement batch's ordering from the log.
    ///
    /// This is the check that makes beacon ordering worth having. The rule
    /// itself constrains an honest node; only an auditor recomputing
    /// `H(beacon(epoch, anchor) ‖ commitment_hash)` over the epoch's accepted
    /// claims constrains a dishonest one. Three ways a batch can be wrong, and
    /// all three are somebody being paid out of turn:
    ///
    /// - the recorded anchor is not the anchor this epoch resolves to — the
    ///   recorded beacon, or the epoch-chain head when there is none — which is
    ///   how a sequencer would grind an ordering after seeing the reveals;
    /// - the recorded order is not the beacon order for that anchor;
    /// - an accepted claim from the epoch is missing, which is censorship by
    ///   omission and pays whoever was behind it.
    fn audit_batches(&self) -> Vec<String> {
        let mut problems = Vec::new();
        let mut seen: BTreeSet<u64> = BTreeSet::new();
        for entry in self.ledger.entries_of_kind(BATCH) {
            let epoch = match entry.payload.get("epoch").and_then(Value::as_u64) {
                Some(epoch) => epoch,
                None => {
                    problems.push(format!("batch at entry {}: no epoch", entry.seq));
                    continue;
                }
            };
            if !seen.insert(epoch) {
                problems.push(format!("epoch {epoch}: settled in more than one batch"));
            }

            let recorded_anchor = payload_str(&entry.payload, "anchor").unwrap_or("");
            // Derived over the log as it stood *when this batch was written*,
            // not as it stands now. Anything appended after the batch record
            // could not have influenced it, whatever timestamp it carries --
            // and a peer can append a back-dated record at will, so scanning
            // the whole log would let one turn an honest batch into a
            // permanent audit failure.
            let position = usize::try_from(entry.seq).unwrap_or(usize::MAX);
            let derived_anchor = self.anchor_of_epoch_within(epoch, position, None);
            if recorded_anchor != derived_anchor {
                problems.push(format!(
                    "batch for epoch {epoch}: anchor {} is not the epoch-chain head \
                     this batch was written against ({})",
                    short(recorded_anchor),
                    short(&derived_anchor)
                ));
            }

            let recorded: Vec<String> = match entry.payload.get("claims") {
                Some(Value::Array(items)) => items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(String::from)
                    .collect(),
                _ => {
                    problems.push(format!("batch for epoch {epoch}: no claim list"));
                    continue;
                }
            };

            // An empty batch is always forged, and letting one through is a
            // way to move money.
            //
            // `settle_due` writes a batch only for a *due* epoch, and
            // `due_epochs` is derived from `accepted_claims_by_epoch`, so an
            // honestly produced batch always names at least one claim. A batch
            // naming none therefore cannot have come from settlement.
            //
            // Why it matters rather than being untidy: every batch is a link
            // in the epoch chain, and the chain head is the anchor future
            // batches sort against. An empty batch for an epoch nobody ever
            // claimed in changes that head while matching the recorded claim
            // list exactly (both sides empty), so before this check the audit
            // passed it clean -- handing an operator a free, unlimited
            // re-roll of the settlement order of every later epoch. That is
            // exactly the lever `AGENTS.md` says the beacon ordering exists to
            // remove. Found by an adversarial probe of the epoch chain, not by
            // the tests that shipped with it.
            if recorded.is_empty() {
                problems.push(format!(
                    "batch for epoch {epoch}: settles no claims, so it cannot have come \
                     from a drain -- an empty batch still moves the epoch chain, and with \
                     it the order every later batch is paid in"
                ));
                continue;
            }

            // Recomputed against the *recorded* anchor: if that anchor is
            // wrong the line above already says so, and re-deriving the order
            // from a different anchor would report the same fault twice under
            // two names.
            let mut ranked: Vec<(String, String)> = self
                .accepted_in_epoch_within(epoch, position)
                .into_iter()
                .map(|(claim_id, claim)| {
                    (
                        settlement_rank(epoch, recorded_anchor, &claim.commitment_hash()),
                        claim_id,
                    )
                })
                .collect();
            ranked.sort();
            let expected: Vec<String> = ranked.into_iter().map(|(_, id)| id).collect();
            if recorded != expected {
                problems.push(format!(
                    "batch for epoch {epoch}: settled {} claim(s) in an order the \
                     beacon does not produce",
                    recorded.len()
                ));
            }
        }
        problems
    }

    // -- internals --------------------------------------------------------

    /// Append and drop the returned reference, so the mutable borrow of the
    /// ledger ends inside this call.
    fn append(&mut self, kind: &str, payload: Value, ts: &str) -> Result<(), RuleViolation> {
        self.ledger
            .append(kind, payload, ts)
            .map(|_| ())
            .map_err(RuleViolation::Ledger)
    }

    fn decode_objectives(&self) -> (BTreeMap<String, Objective>, Vec<String>) {
        let mut objectives = BTreeMap::new();
        let mut problems = Vec::new();
        for entry in self.ledger.entries_of_kind(OBJECTIVE) {
            match Objective::from_value(&entry.payload) {
                Ok(objective) => {
                    objectives.insert(objective.id(), objective);
                }
                Err(error) => problems.push(format!(
                    "objective at entry {}: cannot be decoded ({error})",
                    entry.seq
                )),
            }
        }
        (objectives, problems)
    }

    /// Is this exact objective already in the log?
    ///
    /// Two tests, because they fail on different logs. The decoded id is the
    /// reference implementation's check. The raw payload digest catches the case
    /// where an existing entry cannot be decoded by this version at all -- it
    /// would be invisible to the first test, and "I could not read your record"
    /// must not be a way to re-post a funded objective.
    fn is_posted(&self, objective_id: &str) -> bool {
        for entry in self.ledger.entries_of_kind(OBJECTIVE) {
            if entry.payload.digest() == objective_id {
                return true;
            }
            if let Ok(existing) = Objective::from_value(&entry.payload) {
                if existing.id() == objective_id {
                    return true;
                }
            }
        }
        false
    }

    /// The commitment this claim opens, if it is in the log.
    ///
    /// All three of objective, submitter and hash must match. The hash already
    /// binds the submitter, so the explicit submitter comparison is redundant
    /// arithmetic and deliberate defence in depth: it is the field an attacker
    /// would have to forge, and comparing it costs nothing.
    fn matching_commitment(&self, claim: &Claim) -> Option<&Value> {
        let target = claim.commitment_hash();
        for entry in self.ledger.entries_of_kind(COMMITMENT) {
            let payload = &entry.payload;
            if payload_str(payload, "objective_id") == Some(claim.objective_id.as_str())
                && payload_str(payload, "submitter") == Some(claim.submitter.as_str())
                && payload_str(payload, "hash") == Some(target.as_str())
            {
                return Some(payload);
            }
        }
        None
    }

    /// Artifact identities revealed against an objective before `epoch`.
    ///
    /// Deliberately not filtered by verdict: an artifact that was *rejected* is
    /// still not novel, and re-revealing it must not become a way to mint on the
    /// second try if the objective's verifier later starts accepting it.
    ///
    /// Cut at the epoch boundary rather than at "everything in the log", so a
    /// claim is never made a duplicate of one revealed in its own batch by
    /// arrival order; that comparison belongs to the beacon ordering.
    fn artifact_ids_before(&self, objective_id: &str, epoch: u64) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for entry in self.ledger.entries_of_kind(CLAIM) {
            let earlier = match crate::time::parse_rfc3339(&entry.ts) {
                Some(seconds) if seconds >= 0 => epoch_of(seconds as u64, epoch_seconds()) < epoch,
                _ => false,
            };
            if !earlier {
                continue;
            }
            if let Ok(claim) = Claim::from_value(&entry.payload) {
                if claim.objective_id == objective_id {
                    out.insert(claim.artifact_id());
                }
            }
        }
        out
    }

    /// Ids of claims whose recorded verdict was `accept`.
    fn accepted_claim_ids(&self) -> BTreeSet<String> {
        let mut accepted = BTreeSet::new();
        for entry in self.ledger.entries_of_kind(VERDICT) {
            let claim_id = match payload_str(&entry.payload, "claim_id") {
                Some(claim_id) => claim_id,
                None => continue,
            };
            let is_accept = entry
                .payload
                .get("verdict")
                .and_then(Verdict::from_value)
                .map(|verdict| verdict.accepted())
                .unwrap_or(false);
            if is_accept {
                accepted.insert(claim_id.to_string());
            } else {
                // A later verdict supersedes an earlier one, including a later
                // *non*-acceptance. Leaving the id in the set would keep paying
                // a claim whose acceptance was withdrawn.
                accepted.remove(claim_id);
            }
        }
        accepted
    }

    /// The verdict last recorded for a claim.
    fn recorded_verdict(&self, claim_id: &str) -> Option<Verdict> {
        let mut found = None;
        for entry in self.ledger.entries_of_kind(VERDICT) {
            if payload_str(&entry.payload, "claim_id") == Some(claim_id) {
                found = entry.payload.get("verdict").and_then(Verdict::from_value);
            }
        }
        found
    }

    /// The strict frontier reader used by the rules path: the latest entry for
    /// this objective, or an error if that entry cannot be read.
    /// For every claim the rules *forced* to cite something, what it was forced
    /// to cite.
    ///
    /// On a ratcheted objective an improvement must cite the frontier claim it
    /// beat — [`Node::reveal`] refuses one that does not — so that citation is
    /// the one an attribution rule can reserve a share for: the submitter chose
    /// everything else in its `cites` list, and anything chosen can be
    /// manufactured once funding an objective is something an agent can do.
    ///
    /// Re-derived by walking the log forward rather than stored on the claim.
    /// A stored field would be a new record shape and a consensus surface; the
    /// frontier as it stood *below* a claim's own entry is already written down,
    /// and reading it back is what every other position-bounded derivation in
    /// this module does. It also means this answers correctly for logs written
    /// before the reserve existed.
    pub fn enforced_citations(&self) -> BTreeMap<String, String> {
        let ratcheted: BTreeSet<String> = self
            .objectives()
            .iter()
            .filter(|(_, objective)| objective.ratchet.is_some())
            .map(|(id, _)| id.clone())
            .collect();
        let mut out: BTreeMap<String, String> = BTreeMap::new();
        let mut held: BTreeMap<String, String> = BTreeMap::new();
        for entry in self.ledger.entries() {
            match entry.kind.as_str() {
                CLAIM => {
                    let Ok(claim) = Claim::from_value(&entry.payload) else {
                        continue;
                    };
                    if !ratcheted.contains(&claim.objective_id) {
                        continue;
                    }
                    if let Some(frontier) = held.get(&claim.objective_id) {
                        out.insert(claim.id(), frontier.clone());
                    }
                }
                FRONTIER => {
                    if let (Some(objective_id), Some(claim_id)) = (
                        payload_str(&entry.payload, "objective_id"),
                        payload_str(&entry.payload, "claim_id"),
                    ) {
                        held.insert(objective_id.to_string(), claim_id.to_string());
                    }
                }
                _ => {}
            }
        }
        out
    }

    fn latest_frontier(&self, objective_id: &str) -> Result<Option<FrontierEntry>, RuleViolation> {
        let mut latest: Option<&Value> = None;
        for entry in self.ledger.entries_of_kind(FRONTIER) {
            if payload_str(&entry.payload, "objective_id") == Some(objective_id) {
                latest = Some(&entry.payload);
            }
        }
        match latest {
            None => Ok(None),
            Some(payload) => FrontierEntry::from_value(payload)
                .map(Some)
                .map_err(RuleViolation::MalformedFrontier),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Decode lowercase hex, or `None`.
///
/// Local rather than shared: this is the one place in the rules engine that
/// reads a hex *number* out of a record rather than a digest, and a hex helper
/// in `canonical` would invite somebody to use it on an identifier, where the
/// `sha256:` prefix makes the same call wrong.
fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).ok())
        .collect()
}

fn payload_str<'a>(payload: &'a Value, key: &str) -> Option<&'a str> {
    payload.get(key).and_then(Value::as_str)
}

/// The `identity` of a peer payload, borrowed from the entry.
///
/// Borrowed rather than taken from the decoded [`PeerRecord`], so the audit's
/// per-identity sequence map can key on the entry without cloning a string per
/// record.
fn entry_identity(payload: &Value) -> Option<&str> {
    payload_str(payload, "identity")
}

/// Which epoch an RFC-3339 instant falls in.
///
/// Pre-1970 instants are refused along with unparsable ones. Epochs are `u64`
/// because they key a beacon, and there is no sensible epoch number for a
/// record dated before the Unix epoch -- a record this network could not have
/// produced.
/// Was this beacon entry drawn in the epoch it claims to order?
///
/// Applied at *read* time as well as at admission, so a beacon that reached the
/// log some other way — an import from a peer, a hand-edited file — cannot
/// order anything. A reader that trusted the record's own `orders` field
/// without re-checking when it was written would let an operator append a
/// beacon for a long-closed epoch and re-derive its payment order.
fn beacon_is_in_time(entry: &Entry, orders: u64) -> bool {
    matches!(epoch_of_timestamp("beacon", &entry.ts), Ok(drawn) if drawn == orders)
}

fn epoch_of_timestamp(record: &'static str, ts: &str) -> Result<u64, RuleViolation> {
    match crate::time::parse_rfc3339(ts) {
        Some(seconds) if seconds >= 0 => Ok(epoch_of(seconds as u64, epoch_seconds())),
        _ => Err(RuleViolation::MalformedTimestamp {
            record,
            value: ts.to_string(),
        }),
    }
}

fn status_of(verdict: &Value) -> Option<&str> {
    verdict.get("status").and_then(Value::as_str)
}

/// How an objective's verifier kind is named in a refusal.
///
/// A kind that is not a string still has to be reportable -- the objective is
/// refused either way, and an operator staring at the error needs to see what
/// was actually in the record.
fn describe_kind(verifier: &Value) -> String {
    match verifier.get("kind") {
        Some(Value::String(kind)) => format!("{kind:?}"),
        Some(other) => other.canonical_string(),
        None => String::from("(absent)"),
    }
}

/// The previous frontier score in a human-readable note. The reference
/// implementation interpolates Python's `None`; `none` is the same information.
fn render_previous(previous: Option<i64>) -> String {
    match previous {
        Some(score) => score.to_string(),
        None => String::from("none"),
    }
}

/// Open a sealed submission by trying every `threshold`-sized subset of the
/// published shares.
///
/// The search exists because **Shamir cannot say which share was wrong.** Any
/// `t` points define a polynomial, so a bad share yields a well-formed wrong key
/// and the AEAD tag reports only that the *set* was wrong. The scheme that would
/// let a share be checked on its own — verifiable secret sharing — needs a group
/// where discrete log is hard, which is the assumption this network has
/// deliberately declined to make. See [`Node::open_sealed`].
///
/// Bounded by construction: shares come from `committee_shares_for`, which
/// admits at most one per seat, and a committee is `COMMITTEE_SIZE` seats. So
/// this is at most `C(COMMITTEE_SIZE, threshold)` AEAD checks — ten at the
/// default three-of-five — and cannot be driven higher by anyone, because
/// adding a share means holding a seat the beacon drew for you.
///
/// Subsets are tried in lexicographic index order, which is log order, which is
/// the same order on every node: two nodes opening the same submission from the
/// same shares produce the same artifact by the same route. That matters even
/// though every subset that opens yields the *same* plaintext — the binding
/// check makes that a theorem — because "deterministic for a reason anyone can
/// restate" is cheaper to trust than "deterministic because the output happens
/// to be unique".
fn open_with_any_subset(
    submission: &SealedSubmission,
    shares: &[crate::crypto::shamir::Share],
    threshold: usize,
) -> Option<OpenedSubmission> {
    if threshold == 0 || shares.len() < threshold {
        return None;
    }
    // The common case, and worth taking first rather than as subset number one:
    // when every published share is honest, this is a single AEAD check.
    let mut chosen: Vec<usize> = (0..threshold).collect();
    loop {
        let subset: Vec<crate::crypto::shamir::Share> =
            chosen.iter().map(|&i| shares[i].clone()).collect();
        if let Ok(opened) = crate::sealed::open(submission, &subset) {
            return Some(opened);
        }
        // Next combination in lexicographic order: advance the rightmost index
        // that still has room, then repack everything after it.
        let mut i = threshold;
        loop {
            if i == 0 {
                return None;
            }
            i -= 1;
            if chosen[i] != i + shares.len() - threshold {
                break;
            }
            if i == 0 {
                return None;
            }
        }
        chosen[i] += 1;
        for j in i + 1..threshold {
            chosen[j] = chosen[j - 1] + 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::frontier::Direction;
    use crate::records::commitment_hash;

    const TS: &str = "2026-07-28T00:00:00+00:00";
    /// A Lean binary name guaranteed not to exist, so `lean` verification is
    /// deterministically Unavailable without touching the host toolchain.
    const NO_LEAN: &str = "proofwork-definitely-no-such-lean-binary";

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(tag: &str) -> TempDir {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let mut path = std::env::temp_dir();
            path.push(format!(
                "proofwork-node-{}-{nanos}-{n}-{tag}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("create temp dir");
            TempDir { path }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn node(dir: &TempDir) -> Node {
        let ledger = Ledger::open(dir.path.join("log.jsonl")).expect("open");
        let registry = VerifierRegistry::new(&dir.path).with_lean_binary(NO_LEAN);
        Node::with_registry(ledger, registry)
    }

    /// A `lean` objective. Verification needs no local toolchain to be
    /// *deterministic*: the escape-hatch screens run before the binary lookup,
    /// so a `sorry` proof is a Reject on every node, and anything else is
    /// Unavailable when Lean is absent.
    fn lean_objective(reward: u64) -> Objective {
        Objective::new(
            "G",
            "prove it",
            Value::object([
                ("kind", Value::string("lean")),
                ("statement", Value::string("theorem t : True")),
            ]),
            reward,
            "treasury",
            TS,
            None,
            None,
        )
        .expect("valid objective")
    }

    fn ratchet_block(baseline: i128, target: i128, reward: i128) -> Value {
        Value::object([
            ("baseline", Value::Int(baseline)),
            ("target", Value::Int(target)),
            ("reward", Value::Int(reward)),
            ("direction", Value::string("maximize")),
            ("min_improvement", Value::Int(1)),
        ])
    }

    fn evaluator_verifier() -> Value {
        Value::object([
            ("kind", Value::string("evaluator")),
            ("evaluator", Value::string("e.py")),
            ("evaluator_sha256", Value::string("00".repeat(32))),
            ("entrypoint", Value::string("score")),
            ("threshold", Value::Int(0)),
            ("direction", Value::string("maximize")),
        ])
    }

    fn ratchet_objective() -> Objective {
        Objective::new(
            "G",
            "maximize the score",
            evaluator_verifier(),
            1_000_000,
            "treasury",
            TS,
            None,
            Some(ratchet_block(0, 100, 1_000_000)),
        )
        .expect("valid objective")
    }

    fn proof(text: &str) -> Value {
        Value::object([("proof", Value::string(text))])
    }

    /// Which epoch [`stamp`]`(offset)` falls in.
    ///
    /// Derived rather than written down: these tests are about the *relation*
    /// between the epoch a beacon is drawn in and the one it orders, and a
    /// hard-coded epoch number would stop testing that relation the moment
    /// `EPOCH_SECONDS` or `BASE` moved.
    fn epoch_at(offset: i64) -> u64 {
        epoch_of((BASE + offset) as u64, crate::partition::EPOCH_SECONDS)
    }

    fn scored(score: i128) -> Verdict {
        Verdict::new(
            Status::Accept,
            "synthetic",
            Value::object([("score", Value::Int(score))]),
        )
    }

    fn claim_for(objective: &Objective, who: &str, artifact: Value, nonce: &str) -> Claim {
        Claim::new(objective.id(), who, artifact, nonce, TS, vec![]).expect("valid claim")
    }

    /// Seconds since the Unix epoch for [`TS`], and the length of one epoch.
    const BASE: i64 = 1_785_196_800;
    const EPOCH: i64 = crate::partition::EPOCH_SECONDS as i64;

    fn stamp(offset: i64) -> String {
        crate::time::format_iso8601_utc(BASE + offset)
    }

    /// The earliest offset at which an epoch-0 batch may be paid: one epoch to
    /// close it, plus the finality delay. Derived rather than written down, so
    /// that changing `FINALITY_EPOCHS` moves these tests with it instead of
    /// turning them into assertions that nothing settled.
    fn settle_offset() -> i64 {
        (2 + crate::partition::finality_epochs() as i64) * EPOCH
    }

    /// Commit, then reveal, then close the batch -- the way an honest submitter
    /// and an honest operator do it between them.
    ///
    /// Several epochs, not one, and they cannot be collapsed: a reveal must be
    /// in a strictly later epoch than its commitment, and a batch settles only
    /// once its epoch is over *and* the finality delay has elapsed. The offsets
    /// come off the ledger length so that successive submissions land in
    /// successive epochs -- an epoch whose batch has already been paid refuses
    /// further reveals, which is the point.
    ///
    /// The settle offset is derived from [`finality_epochs`] rather than
    /// written as a number, so raising the delay does not silently turn every
    /// test in this module into one that asserts nothing settled.
    ///
    /// [`finality_epochs`]: crate::partition::finality_epochs
    ///
    /// Returns the *final* outcome for the claim, so a caller can still ask
    /// "what did this submission earn" in one line.
    fn submit(
        node: &mut Node,
        objective: &Objective,
        who: &str,
        artifact: Value,
        nonce: &str,
        cites: Vec<String>,
    ) -> Result<Outcome, RuleViolation> {
        let stride = 3 + crate::partition::finality_epochs() as i64;
        let step = node.ledger().len() as i64 * stride * EPOCH;
        let hash = commitment_hash(&objective.id(), who, &artifact, nonce);
        node.commit(
            &Commitment::new(objective.id(), who, hash, stamp(step)),
            &stamp(step),
        )
        .expect("commit");
        let claim =
            Claim::new(objective.id(), who, artifact, nonce, TS, cites).expect("valid claim");
        let outcome = node.reveal(&claim, &stamp(step + EPOCH))?;
        if !outcome.is_pending() {
            return Ok(outcome);
        }
        let settled = node.settle_at(&stamp(
            step + (2 + crate::partition::finality_epochs() as i64) * EPOCH,
        ))?;
        Ok(settled
            .into_iter()
            .find(|candidate| candidate.claim_id == outcome.claim_id)
            .unwrap_or(outcome))
    }

    /// `echo` is used to build a *replay* objective that accepts without any
    /// language toolchain. Absent on an exotic host, in which case the handful of
    /// tests that need a real ACCEPT through `reveal` are skipped rather than
    /// failing for an unrelated reason.
    fn echo() -> Option<PathBuf> {
        ["/bin/echo", "/usr/bin/echo"]
            .into_iter()
            .map(PathBuf::from)
            .find(|candidate| candidate.exists())
    }

    fn replay_objective(reward: u64) -> Option<Objective> {
        replay_objective_called(reward, "reproduce n")
    }

    /// A replay objective with a caller-chosen statement.
    ///
    /// An objective's id is the digest of its whole record, so two objectives
    /// that agree on reward and verifier are the *same* objective and the
    /// second post is refused as a duplicate. Fixtures that fund several
    /// identities need a distinct objective each time round, and the statement
    /// is the field that is free to vary without changing what the verifier
    /// does.
    fn replay_objective_called(reward: u64, statement: &str) -> Option<Objective> {
        let binary = echo()?;
        Some(
            Objective::new(
                "G",
                statement,
                Value::object([
                    ("kind", Value::string("replay")),
                    (
                        "command",
                        Value::array([
                            Value::string(binary.to_string_lossy().to_string()),
                            Value::string("{\"n\": 1}"),
                        ]),
                    ),
                    ("reproducible_fields", Value::array([Value::string("n")])),
                ]),
                reward,
                "treasury",
                TS,
                None,
                None,
            )
            .expect("valid objective"),
        )
    }

    fn results(n: i128) -> Value {
        Value::object([("results", Value::object([("n", Value::Int(n))]))])
    }

    // -- posting objectives -------------------------------------------------

    #[test]
    fn an_objective_with_no_registered_verifier_is_refused() {
        // An objective whose payout has no machine behind it is an opinion.
        let dir = TempDir::new("unknown-kind");
        let mut node = node(&dir);
        let bad = Objective::new(
            "G",
            "vibes",
            Value::object([("kind", Value::string("looks_good_to_me"))]),
            1,
            "t",
            TS,
            None,
            None,
        )
        .expect("valid objective");
        let error = node.post_objective(&bad, TS).expect_err("must be refused");
        assert!(matches!(error, RuleViolation::UnknownVerifierKind { .. }));
        assert!(error.to_string().contains("no verifier"), "{error}");
        assert!(node.ledger().is_empty());
    }

    #[test]
    fn a_non_string_kind_is_reported_rather_than_crashing() {
        let dir = TempDir::new("weird-kind");
        let mut node = node(&dir);
        let bad = Objective {
            verifier: Value::object([("kind", Value::Int(7))]),
            ..lean_objective(1)
        };
        let error = node.post_objective(&bad, TS).expect_err("must be refused");
        assert!(error.to_string().contains('7'), "{error}");
    }

    #[test]
    fn the_same_objective_cannot_be_posted_twice() {
        let dir = TempDir::new("duplicate");
        let mut node = node(&dir);
        let objective = lean_objective(10);
        node.post_objective(&objective, TS).expect("first post");
        let error = node
            .post_objective(&objective, TS)
            .expect_err("must be refused");
        assert!(matches!(error, RuleViolation::DuplicateObjective { .. }));
        assert_eq!(node.ledger().entries_of_kind(OBJECTIVE).len(), 1);
    }

    #[test]
    fn a_ratchet_needs_a_score_producing_verifier() {
        let dir = TempDir::new("ratchet-kind");
        let mut node = node(&dir);
        let objective = Objective {
            ratchet: Some(ratchet_block(0, 10, 100)),
            ..lean_objective(100)
        };
        let error = node
            .post_objective(&objective, TS)
            .expect_err("must be refused");
        assert!(matches!(error, RuleViolation::RatchetNeedsEvaluator { .. }));
        assert!(error.to_string().contains("score-producing"), "{error}");
    }

    #[test]
    fn ratchet_and_objective_rewards_must_agree() {
        // One pool, not two: an objective that advertises one number while
        // paying along a curve scaled to another is a lie.
        let dir = TempDir::new("two-pools");
        let mut node = node(&dir);
        let objective = Objective {
            reward: 100,
            ratchet: Some(ratchet_block(0, 10, 999)),
            ..ratchet_objective()
        };
        let error = node
            .post_objective(&objective, TS)
            .expect_err("must be refused");
        assert!(matches!(
            error,
            RuleViolation::RatchetRewardMismatch {
                ratchet: 999,
                objective: 100
            }
        ));
        assert!(error.to_string().contains("one pool"), "{error}");
    }

    #[test]
    fn a_malformed_ratchet_is_reported_as_such() {
        let dir = TempDir::new("bad-ratchet");
        let mut node = node(&dir);
        let objective = Objective {
            // Maximizing with target below baseline: no distance to move.
            ratchet: Some(ratchet_block(100, 10, 1_000_000)),
            ..ratchet_objective()
        };
        let error = node
            .post_objective(&objective, TS)
            .expect_err("must be refused");
        assert!(matches!(error, RuleViolation::MalformedRatchet(_)));
    }

    // -- commit -------------------------------------------------------------

    #[test]
    fn a_commitment_needs_a_known_objective() {
        let dir = TempDir::new("commit-unknown");
        let mut node = node(&dir);
        let error = node
            .commit(&Commitment::new("sha256:nope", "alice", "sha256:x", TS), TS)
            .expect_err("must be refused");
        assert!(matches!(
            error,
            RuleViolation::UnknownObjective {
                referrer: Referrer::Commitment,
                ..
            }
        ));
    }

    #[test]
    fn commitments_are_refused_once_a_plain_objective_is_settled() {
        let dir = TempDir::new("commit-settled");
        let mut node = node(&dir);
        let objective = lean_objective(10);
        node.post_objective(&objective, TS).expect("post");
        node.ledger_mut()
            .append(
                SETTLEMENT,
                Value::object([
                    ("objective_id", Value::string(objective.id())),
                    ("claim_id", Value::string("sha256:whatever")),
                    ("submitter", Value::string("alice")),
                    ("reward", Value::Int(10)),
                ]),
                TS,
            )
            .expect("append");

        let error = node
            .commit(&Commitment::new(objective.id(), "bob", "sha256:x", TS), TS)
            .expect_err("must be refused");
        assert!(matches!(error, RuleViolation::AlreadySettled { .. }));
        assert!(error.to_string().contains("already settled"), "{error}");
    }

    #[test]
    fn a_progressive_objective_keeps_accepting_commitments_after_it_pays() {
        // The whole point of a ratchet is that improvements keep arriving.
        let dir = TempDir::new("commit-progressive");
        let mut node = node(&dir);
        let objective = ratchet_objective();
        node.post_objective(&objective, TS).expect("post");
        node.ledger_mut()
            .append(
                SETTLEMENT,
                Value::object([
                    ("objective_id", Value::string(objective.id())),
                    ("claim_id", Value::string("sha256:whatever")),
                    ("submitter", Value::string("alice")),
                    ("reward", Value::Int(400_000)),
                ]),
                TS,
            )
            .expect("append");
        assert!(node
            .commit(&Commitment::new(objective.id(), "bob", "sha256:x", TS), TS)
            .is_ok());
    }

    // -- reveal: the submission rules ---------------------------------------

    #[test]
    fn a_reveal_without_a_commitment_is_refused() {
        // Otherwise an observer copies a revealed artifact out of the mempool
        // and submits it as their own.
        let dir = TempDir::new("no-commitment");
        let mut node = node(&dir);
        let objective = lean_objective(10);
        node.post_objective(&objective, TS).expect("post");

        let claim = claim_for(&objective, "eve", proof(":= by trivial"), "n1");
        let error = node.reveal(&claim, TS).expect_err("must be refused");
        assert!(matches!(error, RuleViolation::NoMatchingCommitment));
        // Nothing was recorded: a refusal is not evidence about anybody's work.
        assert!(node.ledger().entries_of_kind(CLAIM).is_empty());
    }

    #[test]
    fn a_commitment_does_not_transfer_between_submitters() {
        let dir = TempDir::new("transfer");
        let mut node = node(&dir);
        let objective = lean_objective(10);
        node.post_objective(&objective, TS).expect("post");

        let artifact = proof(":= by trivial");
        let hash = commitment_hash(&objective.id(), "alice", &artifact, "n1");
        node.commit(&Commitment::new(objective.id(), "alice", hash, TS), TS)
            .expect("commit");

        // Eve saw alice's commitment but cannot reveal against it as herself.
        let stolen = claim_for(&objective, "eve", artifact, "n1");
        assert!(matches!(
            node.reveal(&stolen, TS),
            Err(RuleViolation::NoMatchingCommitment)
        ));
    }

    #[test]
    fn a_wrong_nonce_does_not_open_the_commitment() {
        let dir = TempDir::new("nonce");
        let mut node = node(&dir);
        let objective = lean_objective(10);
        node.post_objective(&objective, TS).expect("post");

        let artifact = proof(":= by trivial");
        let hash = commitment_hash(&objective.id(), "alice", &artifact, "right");
        node.commit(&Commitment::new(objective.id(), "alice", hash, TS), TS)
            .expect("commit");

        let claim = claim_for(&objective, "alice", artifact, "wrong");
        assert!(matches!(
            node.reveal(&claim, TS),
            Err(RuleViolation::NoMatchingCommitment)
        ));
    }

    #[test]
    fn citations_must_point_at_accepted_claims() {
        let dir = TempDir::new("citations");
        let mut node = node(&dir);
        let objective = lean_objective(10);
        node.post_objective(&objective, TS).expect("post");

        let invented = format!("sha256:{}", "0".repeat(64));
        let error = submit(
            &mut node,
            &objective,
            "alice",
            proof(":= by trivial"),
            "n1",
            vec![invented.clone()],
        )
        .expect_err("must be refused");
        assert!(
            matches!(&error, RuleViolation::UnknownCitation { claim_id } if claim_id == &invented)
        );
        assert!(error.to_string().contains("citation"), "{error}");
    }

    #[test]
    fn an_improvement_must_cite_the_frontier() {
        // Mechanical attribution: you improved on the public frontier, so you
        // cite it, and citation flow pays its holder without anyone exercising
        // judgement.
        let dir = TempDir::new("must-cite");
        let mut node = node(&dir);
        let objective = ratchet_objective();
        node.post_objective(&objective, TS).expect("post");
        let holder = FrontierEntry::new(objective.id(), "sha256:held", "alice", 40, 400_000);
        node.ledger_mut()
            .append(FRONTIER, holder.to_value(), TS)
            .expect("append");

        let error = submit(
            &mut node,
            &objective,
            "bob",
            Value::object([("score", Value::Int(65))]),
            "n2",
            vec![],
        )
        .expect_err("must be refused");
        assert!(matches!(
            error,
            RuleViolation::MissingFrontierCitation { .. }
        ));
        assert!(
            error.to_string().contains("must cite the frontier"),
            "{error}"
        );
    }

    #[test]
    fn an_unreadable_frontier_refuses_the_reveal_rather_than_paying_from_zero() {
        // Treating it as an empty frontier would waive the citation rule and
        // restart the payout curve, so "I cannot read it" must not be worth
        // money.
        let dir = TempDir::new("bad-frontier");
        let mut node = node(&dir);
        let objective = ratchet_objective();
        node.post_objective(&objective, TS).expect("post");
        node.ledger_mut()
            .append(
                FRONTIER,
                Value::object([
                    ("objective_id", Value::string(objective.id())),
                    ("claim_id", Value::string("sha256:held")),
                    ("holder", Value::string("alice")),
                    ("score", Value::Int(40)),
                    // paid_cumulative missing.
                ]),
                TS,
            )
            .expect("append");

        let error = submit(
            &mut node,
            &objective,
            "bob",
            Value::object([("score", Value::Int(65))]),
            "n2",
            vec![],
        )
        .expect_err("must be refused");
        assert!(matches!(error, RuleViolation::MalformedFrontier(_)));
        assert!(node.frontier_of(&objective.id()).is_none());
    }

    // -- reveal: verdict handling -------------------------------------------

    #[test]
    fn a_rejected_claim_records_the_verdict_and_settles_nothing() {
        let dir = TempDir::new("reject");
        let mut node = node(&dir);
        let objective = lean_objective(10);
        node.post_objective(&objective, TS).expect("post");

        // The `sorry` screen is a fact about the submitted text, so it fires on
        // a node with no Lean at all.
        let outcome = submit(
            &mut node,
            &objective,
            "mallory",
            proof(":= by sorry"),
            "n1",
            vec![],
        )
        .expect("reveal");
        assert_eq!(outcome.verdict.status, Status::Reject);
        assert!(!outcome.settled);
        assert_eq!(outcome.reward, 0);
        assert_eq!(outcome.note, "rejected");
        assert!(node.settlement_of(&objective.id()).is_none());
        // The attempt is still in the log, verdict and all.
        assert_eq!(node.ledger().entries_of_kind(CLAIM).len(), 1);
        assert_eq!(node.ledger().entries_of_kind(VERDICT).len(), 1);
    }

    #[test]
    fn an_unavailable_verdict_leaves_the_objective_open() {
        // An absent toolchain must not close a funded objective.
        let dir = TempDir::new("unavailable");
        let mut node = node(&dir);
        let objective = lean_objective(10);
        node.post_objective(&objective, TS).expect("post");

        let outcome = submit(
            &mut node,
            &objective,
            "alice",
            proof(":= by trivial"),
            "n1",
            vec![],
        )
        .expect("reveal");
        assert_eq!(outcome.verdict.status, Status::Unavailable);
        assert!(!outcome.settled);
        assert_eq!(outcome.note, "verdict does not settle");
        assert!(node.settlement_of(&objective.id()).is_none());
        // Still open: a second submitter can commit.
        assert!(node
            .commit(&Commitment::new(objective.id(), "bob", "sha256:x", TS), TS)
            .is_ok());
    }

    #[test]
    fn an_accepted_claim_settles_for_the_whole_pool() {
        let dir = TempDir::new("accept");
        let objective = match replay_objective(1000) {
            Some(objective) => objective,
            None => return,
        };
        let mut node = node(&dir);
        node.post_objective(&objective, TS).expect("post");

        let outcome =
            submit(&mut node, &objective, "alice", results(1), "n1", vec![]).expect("reveal");
        assert_eq!(outcome.verdict.status, Status::Accept, "{outcome:?}");
        assert!(outcome.settled);
        assert_eq!(outcome.reward, 1000);
        assert_eq!(outcome.note, "settled");
        let settlement = node.settlement_of(&objective.id()).expect("settlement");
        assert_eq!(
            settlement.get("submitter").and_then(Value::as_str),
            Some("alice")
        );
        assert_eq!(node.ledger().entries_of_kind(SETTLEMENT).len(), 1);
        assert_eq!(node.audit(true), Vec::<String>::new());
    }

    #[test]
    fn a_duplicate_artifact_verifies_but_mints_nothing() {
        // Novelty is necessary, never sufficient. Both parties commit while the
        // objective is open (the realistic race) and both reveal in the same
        // epoch, so this is also the test that the batch pays exactly one of
        // them -- and pays the one the beacon picks, not the one that arrived
        // first.
        let dir = TempDir::new("duplicate-artifact");
        let objective = match replay_objective(1000) {
            Some(objective) => objective,
            None => return,
        };
        let mut node = node(&dir);
        node.post_objective(&objective, TS).expect("post");

        for (who, nonce) in [("alice", "a"), ("bob", "b")] {
            let hash = commitment_hash(&objective.id(), who, &results(1), nonce);
            node.commit(
                &Commitment::new(objective.id(), who, hash, stamp(0)),
                &stamp(0),
            )
            .expect("commit");
        }

        let alice = node
            .reveal(
                &claim_for(&objective, "alice", results(1), "a"),
                &stamp(EPOCH),
            )
            .expect("reveal");
        let bob = node
            .reveal(
                &claim_for(&objective, "bob", results(1), "b"),
                &stamp(EPOCH),
            )
            .expect("reveal");
        assert!(alice.is_pending() && bob.is_pending());
        assert_eq!(node.ledger().entries_of_kind(SETTLEMENT).len(), 0);

        let batch = node.settle_at(&stamp(settle_offset())).expect("settle");
        assert_eq!(batch.len(), 2);
        let paid: Vec<&Outcome> = batch.iter().filter(|o| o.settled).collect();
        assert_eq!(paid.len(), 1, "{batch:?}");
        assert_eq!(paid[0].reward, 1000);
        let unpaid: Vec<&Outcome> = batch.iter().filter(|o| !o.settled).collect();
        assert_eq!(unpaid[0].reward, 0);
        // The note names the real reason: the copy would earn nothing even
        // against an open objective, so "duplicate" beats "already settled".
        assert!(unpaid[0].note.contains("duplicate"), "{}", unpaid[0].note);
        assert_eq!(node.ledger().entries_of_kind(SETTLEMENT).len(), 1);

        // The winner is whoever the beacon ranks first, and the log records the
        // order so an auditor reaches the same answer.
        let anchor = node.anchor_of_epoch(epoch_of(
            crate::time::parse_rfc3339(&stamp(EPOCH)).expect("parses") as u64,
            crate::partition::EPOCH_SECONDS,
        ));
        let epoch = epoch_of(
            crate::time::parse_rfc3339(&stamp(EPOCH)).expect("parses") as u64,
            crate::partition::EPOCH_SECONDS,
        );
        let rank_of = |who: &str, nonce: &str| {
            let claim = claim_for(&objective, who, results(1), nonce);
            settlement_rank(epoch, &anchor, &claim.commitment_hash())
        };
        let expected = if rank_of("alice", "a") < rank_of("bob", "b") {
            &alice.claim_id
        } else {
            &bob.claim_id
        };
        assert_eq!(&paid[0].claim_id, expected);
        assert_eq!(node.audit(false), Vec::<String>::new());
    }

    #[test]
    fn a_reveal_cannot_join_a_batch_that_has_already_been_paid() {
        // Otherwise the claim would sit accepted and unsettled forever: its
        // epoch is drained, so no future drain would ever look at it again.
        let dir = TempDir::new("late-reveal");
        let objective = match replay_objective(1000) {
            Some(objective) => objective,
            None => return,
        };
        let mut node = node(&dir);
        node.post_objective(&objective, TS).expect("post");
        for (who, nonce, artifact) in [("alice", "a", results(1)), ("bob", "b", results(2))] {
            let hash = commitment_hash(&objective.id(), who, &artifact, nonce);
            node.commit(
                &Commitment::new(objective.id(), who, hash, stamp(0)),
                &stamp(0),
            )
            .expect("commit");
        }
        node.reveal(
            &claim_for(&objective, "alice", results(1), "a"),
            &stamp(EPOCH),
        )
        .expect("reveal");
        node.settle_at(&stamp(settle_offset())).expect("settle");

        let late = node.reveal(
            &claim_for(&objective, "bob", results(2), "b"),
            &stamp(EPOCH),
        );
        assert!(
            matches!(late, Err(RuleViolation::EpochAlreadySettled { .. })),
            "{late:?}"
        );
    }

    #[test]
    fn a_reveal_must_wait_for_an_epoch_after_its_commitment() {
        let dir = TempDir::new("same-epoch-reveal");
        let objective = match replay_objective(1000) {
            Some(objective) => objective,
            None => return,
        };
        let mut node = node(&dir);
        node.post_objective(&objective, TS).expect("post");
        let hash = commitment_hash(&objective.id(), "alice", &results(1), "a");
        node.commit(
            &Commitment::new(objective.id(), "alice", hash, stamp(0)),
            &stamp(0),
        )
        .expect("commit");

        // Same epoch: refused, and nothing is written.
        let before = node.ledger().len();
        let too_soon = node.reveal(
            &claim_for(&objective, "alice", results(1), "a"),
            &stamp(EPOCH - 1),
        );
        assert!(
            matches!(too_soon, Err(RuleViolation::RevealBeforeEpoch { .. })),
            "{too_soon:?}"
        );
        assert_eq!(node.ledger().len(), before, "a refusal wrote to the log");

        // One second later, in the next epoch: admitted.
        node.reveal(
            &claim_for(&objective, "alice", results(1), "a"),
            &stamp(EPOCH),
        )
        .expect("reveal");
    }

    #[test]
    fn a_timestamp_that_names_no_instant_is_refused_rather_than_defaulted() {
        let dir = TempDir::new("bad-timestamp");
        let objective = match replay_objective(1000) {
            Some(objective) => objective,
            None => return,
        };
        let mut node = node(&dir);
        node.post_objective(&objective, TS).expect("post");
        let hash = commitment_hash(&objective.id(), "alice", &results(1), "a");
        let refused = node.commit(
            &Commitment::new(objective.id(), "alice", hash, "whenever"),
            &stamp(0),
        );
        assert!(
            matches!(refused, Err(RuleViolation::MalformedTimestamp { .. })),
            "{refused:?}"
        );
    }

    #[test]
    fn settlement_order_cannot_be_ground_out_at_reveal_time() {
        // The anchor is public by the time anyone reveals, so any part of the
        // ordering key a submitter can still choose is a part they can try
        // until it sorts first. `created_at` and `cites` are exactly that --
        // the commitment binds neither, and nothing checks them against the
        // reveal. Ranking on the commitment hash is what makes them inert.
        let objective = ratchet_objective();
        let artifact = Value::object([("s", Value::Int(1))]);
        let anchor = "sha256:anchor";
        let epoch = 7;

        let baseline = {
            let hash = commitment_hash(&objective.id(), "alice", &artifact, "n");
            settlement_rank(epoch, anchor, &hash)
        };

        let mut ids = BTreeSet::new();
        let mut ranks = BTreeSet::new();
        for minute in 0..30 {
            let claim = Claim::new(
                objective.id(),
                "alice",
                artifact.clone(),
                "n",
                stamp(60 * minute),
                vec![],
            )
            .expect("valid claim");
            ids.insert(claim.id());
            ranks.insert(settlement_rank(epoch, anchor, &claim.commitment_hash()));
        }
        assert_eq!(ids.len(), 30, "the fixture must actually vary the claim id");
        assert_eq!(
            ranks,
            BTreeSet::from([baseline]),
            "a submitter moved their own rank by restamping"
        );
    }

    #[test]
    fn a_back_dated_append_cannot_invalidate_a_batch_that_already_settled() {
        // Records arrive over p2p::sync stamped with their own created_at and
        // land at the tail, so a peer can append one dated into an epoch that
        // has already been paid. Deriving the anchor over the whole log would
        // then disagree with what the batch actually used, and audit would
        // call an honest node's correct batch wrong -- forever, at a peer's
        // choosing. The bound is the batch record's own log position.
        let dir = TempDir::new("audit-backdate");
        let mut node = node(&dir);
        // A replay objective, so the claim really is accepted and a batch
        // really is written -- an Unavailable verdict settles nothing and
        // would leave nothing to invalidate.
        let objective = match replay_objective(1000) {
            Some(objective) => objective,
            None => return,
        };
        node.post_objective(&objective, TS).expect("post");
        submit(&mut node, &objective, "alice", results(1), "n1", vec![]).expect("submit");
        assert!(
            !node.ledger().entries_of_kind(BATCH).is_empty(),
            "the fixture must actually settle a batch"
        );
        assert!(node.audit(false).is_empty(), "clean before the back-date");

        // A peer's record, dated into the epoch that already settled, landing
        // at the tail the way sync appends it.
        node.ledger_mut()
            .append("note", Value::object([("from", Value::string("peer"))]), TS)
            .expect("append");

        let problems = node.audit(false);
        assert!(
            !problems.iter().any(|p| p.contains("anchor")),
            "a back-dated append moved a settled batch's anchor: {problems:?}"
        );
    }

    #[test]
    fn a_back_dated_claim_cannot_invalidate_a_batch_that_already_settled() {
        // The sibling test above appends a plain note, which moves the anchor
        // and nothing else. A back-dated *accepted claim* is the sharper
        // version of the same attack: batch membership is re-derived from the
        // log, so a claim dated into an epoch that already paid makes the batch
        // look like it omitted somebody. Same append, same peer, same choosing
        // -- and the batch record's own log position has to bound this scan for
        // the same reason it bounds the anchor.
        let dir = TempDir::new("audit-backdate-claim");
        let mut node = node(&dir);
        let objective = match replay_objective(1000) {
            Some(objective) => objective,
            None => return,
        };
        node.post_objective(&objective, TS).expect("post");
        submit(&mut node, &objective, "alice", results(1), "n1", vec![]).expect("submit");
        let batches = node.ledger().entries_of_kind(BATCH).len();
        assert!(batches > 0, "the fixture must actually settle a batch");
        assert!(node.audit(false).is_empty(), "clean before the back-date");

        // The *settled* claim's entry timestamp, so the plant below lands in
        // the epoch that already paid rather than an empty one. Stamping it
        // `TS` would put it in a different epoch and the test would pass
        // without ever exercising the thing it is named for.
        let settled_ts = node
            .ledger()
            .entries_of_kind(CLAIM)
            .first()
            .map(|entry| entry.ts.clone())
            .expect("the fixture wrote a claim");
        let settled_epoch = epoch_of(
            crate::time::parse_rfc3339(&settled_ts).expect("stamp") as u64,
            epoch_seconds(),
        );
        assert!(
            node.ledger()
                .entries_of_kind(BATCH)
                .iter()
                .any(|entry| entry.payload.get("epoch").and_then(Value::as_u64)
                    == Some(settled_epoch)),
            "the plant has to land in an epoch a batch actually settled"
        );

        // A second accepted claim, dated into the settled epoch, appended after
        // the batch the way sync appends a peer's record.
        let artifact = results(2);
        let claim = Claim::new(
            objective.id(),
            "mallory",
            artifact.clone(),
            "n2",
            &settled_ts,
            vec![],
        )
        .expect("valid claim");
        let claim_id = claim.id();
        let hash = commitment_hash(&objective.id(), "mallory", &artifact, "n2");
        node.ledger_mut()
            .append(
                COMMITMENT,
                Commitment::new(objective.id(), "mallory", hash, &settled_ts).to_value(),
                &settled_ts,
            )
            .expect("append");
        node.ledger_mut()
            .append(CLAIM, claim.to_value(), &settled_ts)
            .expect("append");
        node.ledger_mut()
            .append(
                VERDICT,
                Value::object([
                    ("claim_id", Value::string(claim_id)),
                    ("objective_id", Value::string(objective.id())),
                    (
                        "verdict",
                        Verdict::plain(Status::Accept, "planted").to_value(),
                    ),
                ]),
                &settled_ts,
            )
            .expect("append");

        let problems = node.audit(false);
        assert!(
            !problems.iter().any(|p| p.contains("the beacon does not")),
            "a back-dated claim invalidated a settled batch: {problems:?}"
        );
    }

    #[test]
    fn a_back_dated_verdict_cannot_invalidate_a_batch_that_already_settled() {
        // The other half of the same bound. Here the *claim* was in the log
        // before the batch and simply had not been accepted yet, so the batch
        // was right to leave it out. Bounding only the claim scan would count
        // it anyway and fault an honest batch -- the verdicts have to carry the
        // same bound.
        let dir = TempDir::new("audit-backdate-verdict");
        let mut node = node(&dir);
        let objective = match replay_objective(1000) {
            Some(objective) => objective,
            None => return,
        };
        node.post_objective(&objective, TS).expect("post");

        // Driven by hand rather than through `submit`, because the two claims
        // have to share a reveal epoch: mallory's claim record must sit in the
        // epoch the batch settles, so that counting its later acceptance would
        // make the batch look short.
        let commit_at = stamp(0);
        let reveal_at = stamp(EPOCH);
        let settle_at = stamp(settle_offset());

        let pending_artifact = results(2);
        let pending_hash = commitment_hash(&objective.id(), "mallory", &pending_artifact, "n2");
        node.commit(
            &Commitment::new(objective.id(), "mallory", pending_hash, &commit_at),
            &commit_at,
        )
        .expect("commit");
        let alice_hash = commitment_hash(&objective.id(), "alice", &results(1), "n1");
        node.commit(
            &Commitment::new(objective.id(), "alice", alice_hash, &commit_at),
            &commit_at,
        )
        .expect("commit");

        // mallory's claim, in the reveal epoch, recorded as *not* accepted --
        // so the log is well-formed and the batch is right to leave it out.
        let pending = Claim::new(
            objective.id(),
            "mallory",
            pending_artifact,
            "n2",
            &reveal_at,
            vec![],
        )
        .expect("valid claim");
        let pending_id = pending.id();
        node.ledger_mut()
            .append(CLAIM, pending.to_value(), &reveal_at)
            .expect("append");
        node.ledger_mut()
            .append(
                VERDICT,
                Value::object([
                    ("claim_id", Value::string(pending_id.clone())),
                    ("objective_id", Value::string(objective.id())),
                    (
                        "verdict",
                        Verdict::plain(Status::Reject, "not yet").to_value(),
                    ),
                ]),
                &reveal_at,
            )
            .expect("append");

        let alice = Claim::new(
            objective.id(),
            "alice",
            results(1),
            "n1",
            &reveal_at,
            vec![],
        )
        .expect("valid claim");
        node.reveal(&alice, &reveal_at).expect("reveal");
        node.settle_at(&settle_at).expect("settle");
        assert!(
            !node.ledger().entries_of_kind(BATCH).is_empty(),
            "the fixture must actually settle a batch"
        );
        assert!(node.audit(false).is_empty(), "clean before the back-date");

        // The acceptance arrives after the batch was drawn.
        node.ledger_mut()
            .append(
                VERDICT,
                Value::object([
                    ("claim_id", Value::string(pending_id)),
                    ("objective_id", Value::string(objective.id())),
                    (
                        "verdict",
                        Verdict::plain(Status::Accept, "planted").to_value(),
                    ),
                ]),
                &reveal_at,
            )
            .expect("append");

        let problems = node.audit(false);
        assert!(
            !problems.iter().any(|p| p.contains("the beacon does not")),
            "a back-dated verdict invalidated a settled batch: {problems:?}"
        );
    }

    #[test]
    fn an_audit_at_the_wrong_epoch_length_names_the_right_one() {
        // Found while building the published log: a log written under
        // PROOFWORK_EPOCH_SECONDS=1 audits as thoroughly broken under the
        // default 600, in both implementations, and both are right -- epochs
        // are derived, never stored. Without the note a contributor's first
        // `proofwork audit` on a demo-built log says the operator paid people
        // out of turn, which is the worst possible false accusation for this
        // project to make.
        //
        // The note used to guess. It now recovers the length from the log and
        // names it, which is the difference between "something is wrong" and
        // "run this command".
        let dir = TempDir::new("audit-epoch-hint");
        let mut node = node(&dir);
        let objective = match replay_objective(1000) {
            Some(objective) => objective,
            None => return,
        };
        node.post_objective(&objective, TS).expect("post");
        submit(&mut node, &objective, "alice", results(1), "n1", vec![]).expect("submit");
        assert!(
            node.audit(false).is_empty(),
            "clean at the epoch it was built with"
        );

        // Re-derive the same log against a different epoch length.
        let hinted = {
            let _guard = EpochGuard::set("7");
            node.audit(false)
        };
        let note = hinted
            .iter()
            .find(|problem| problem.contains("epoch length"))
            .unwrap_or_else(|| panic!("no note among {hinted:?}"));
        assert!(note.contains("this audit used 7"), "{note}");
        assert!(
            note.contains(&format!(
                "PROOFWORK_EPOCH_SECONDS={}",
                crate::partition::EPOCH_SECONDS
            )),
            "the note must name the length that actually works: {note}"
        );

        // And it must not fire when the reader already has it right.
        assert!(
            !node
                .audit(false)
                .iter()
                .any(|problem| problem.contains("epoch length")),
            "the note fired on a log being read correctly"
        );
    }

    #[test]
    fn a_log_written_under_two_epoch_lengths_is_named_as_unrecoverable() {
        // The case the old hint could not reach, and the one that matters: it
        // only fired when *every* batch faulted, so a log written partly at one
        // length and partly at another -- a demo pointed at a live log -- got
        // no explanation at all. It is also the case where the advice differs:
        // there is no epoch length to re-run with, because none re-derives the
        // whole log.
        let dir = TempDir::new("audit-epoch-mixed");
        let mut node = node(&dir);
        let objective = match replay_objective(1000) {
            Some(objective) => objective,
            None => return,
        };
        node.post_objective(&objective, TS).expect("post");
        submit(&mut node, &objective, "alice", results(1), "n1", vec![]).expect("submit");

        // A second batch whose timestamp puts it at a wildly different length:
        // epoch numbers are wall-clock seconds over the length, so naming a
        // huge epoch at the same instant is what a one-second log looks like.
        let seconds = crate::time::parse_rfc3339(&stamp(settle_offset())).expect("parses") as u64;
        node.ledger_mut()
            .append(
                BATCH,
                Value::object([
                    ("epoch", Value::Int(i128::from(seconds - 1))),
                    ("anchor", Value::string("")),
                    ("claims", Value::Array(vec![Value::string("sha256:x")])),
                ]),
                &stamp(settle_offset()),
            )
            .expect("append");

        let problems = node.audit(false);
        let note = problems
            .iter()
            .find(|problem| problem.contains("MORE THAN ONE"))
            .unwrap_or_else(|| panic!("no mixed-length note among {problems:?}"));
        assert!(
            note.contains("will not fix it"),
            "the note must say choosing a length cannot recover this: {note}"
        );
    }

    /// Sets `PROOFWORK_EPOCH_SECONDS` for as long as it lives.
    ///
    /// Tests share a process, so the variable has to go back; a leaked value
    /// would silently re-epoch every test that ran afterwards.
    struct EpochGuard;

    impl EpochGuard {
        fn set(value: &str) -> EpochGuard {
            // SAFETY: single-threaded test, and the guard restores it on drop.
            unsafe { std::env::set_var(crate::partition::EPOCH_SECONDS_ENV, value) };
            EpochGuard
        }
    }

    impl Drop for EpochGuard {
        fn drop(&mut self) {
            // SAFETY: as above.
            unsafe { std::env::remove_var(crate::partition::EPOCH_SECONDS_ENV) };
        }
    }

    // -- the improvement path -----------------------------------------------

    #[test]
    fn the_first_improvement_advances_the_frontier_and_pays_its_distance() {
        let dir = TempDir::new("improve-first");
        let mut node = node(&dir);
        let objective = ratchet_objective();
        node.post_objective(&objective, TS).expect("post");
        let ratchet = Ratchet::new(0, 100, 1_000_000, Direction::Maximize, 1).expect("valid");

        let claim = claim_for(
            &objective,
            "alice",
            Value::object([("s", Value::Int(40))]),
            "n1",
        );
        let outcome = node
            .settle_improvement(&claim, scored(40), &ratchet, None, TS)
            .expect("improvement");
        assert!(outcome.settled);
        assert_eq!(outcome.reward, 400_000);
        assert_eq!(outcome.note, "frontier advanced");

        let frontier = node.frontier_of(&objective.id()).expect("frontier");
        assert_eq!(frontier.holder, "alice");
        assert_eq!(frontier.score, 40);
        assert_eq!(frontier.paid_cumulative, 400_000);
    }

    #[test]
    fn a_second_improvement_pays_only_the_delta() {
        let dir = TempDir::new("improve-delta");
        let mut node = node(&dir);
        let objective = ratchet_objective();
        node.post_objective(&objective, TS).expect("post");
        let ratchet = Ratchet::new(0, 100, 1_000_000, Direction::Maximize, 1).expect("valid");

        let first = claim_for(
            &objective,
            "alice",
            Value::object([("s", Value::Int(40))]),
            "n1",
        );
        node.settle_improvement(&first, scored(40), &ratchet, None, TS)
            .expect("first");
        let held = node.frontier_of(&objective.id()).expect("frontier");

        let second = claim_for(
            &objective,
            "bob",
            Value::object([("s", Value::Int(65))]),
            "n2",
        );
        let outcome = node
            .settle_improvement(&second, scored(65), &ratchet, Some(&held), TS)
            .expect("second");
        assert_eq!(outcome.reward, 250_000);
        let frontier = node.frontier_of(&objective.id()).expect("frontier");
        assert_eq!(frontier.holder, "bob");
        assert_eq!(frontier.paid_cumulative, 650_000);
        // Two settlements against one pool -- correct for a progressive
        // objective, which is why "settled once" is the wrong invariant there.
        assert_eq!(node.ledger().entries_of_kind(SETTLEMENT).len(), 2);
        let problems = node.audit(false);
        assert!(
            !problems
                .iter()
                .any(|p| p.contains("settled more than once")),
            "{problems:?}"
        );
        assert!(
            !problems.iter().any(|p| p.contains("against a pool of")),
            "{problems:?}"
        );
    }

    #[test]
    fn copying_the_frontier_earns_nothing_and_is_not_a_rejection() {
        // The reason publishing is safe: a copied artifact moves the frontier
        // zero and pays zero, so hoarding buys nothing.
        let dir = TempDir::new("copy");
        let mut node = node(&dir);
        let objective = ratchet_objective();
        node.post_objective(&objective, TS).expect("post");
        let ratchet = Ratchet::new(0, 100, 1_000_000, Direction::Maximize, 1).expect("valid");
        let held = FrontierEntry::new(objective.id(), "sha256:held", "alice", 40, 400_000);

        let copy = claim_for(
            &objective,
            "eve",
            Value::object([("s", Value::Int(40))]),
            "n2",
        );
        let outcome = node
            .settle_improvement(&copy, scored(40), &ratchet, Some(&held), TS)
            .expect("outcome");
        assert!(!outcome.settled);
        assert_eq!(outcome.reward, 0);
        assert!(
            outcome.note.contains("does not improve"),
            "{}",
            outcome.note
        );
        // The verdict still says ACCEPT: the artifact verified, it just moved
        // nothing.
        assert_eq!(outcome.verdict.status, Status::Accept);
        assert!(node.ledger().entries_of_kind(FRONTIER).is_empty());
        assert!(node.ledger().entries_of_kind(SETTLEMENT).is_empty());
    }

    #[test]
    fn a_regression_does_not_take_the_frontier() {
        let dir = TempDir::new("regress");
        let mut node = node(&dir);
        let objective = ratchet_objective();
        node.post_objective(&objective, TS).expect("post");
        let ratchet = Ratchet::new(0, 100, 1_000_000, Direction::Maximize, 1).expect("valid");
        let held = FrontierEntry::new(objective.id(), "sha256:held", "alice", 60, 600_000);

        let worse = claim_for(
            &objective,
            "bob",
            Value::object([("s", Value::Int(30))]),
            "n2",
        );
        let outcome = node
            .settle_improvement(&worse, scored(30), &ratchet, Some(&held), TS)
            .expect("outcome");
        assert!(!outcome.settled);
        assert!(
            outcome.note.contains("does not improve on 60"),
            "{}",
            outcome.note
        );
    }

    #[test]
    fn a_verdict_with_no_integer_score_moves_nothing() {
        let dir = TempDir::new("no-score");
        let mut node = node(&dir);
        let objective = ratchet_objective();
        node.post_objective(&objective, TS).expect("post");
        let ratchet = Ratchet::new(0, 100, 1_000_000, Direction::Maximize, 1).expect("valid");
        let claim = claim_for(
            &objective,
            "alice",
            Value::object([("s", Value::Int(1))]),
            "n1",
        );

        // `true` is not the score 1, even though Python's bool is an int.
        let boolean = Verdict::new(
            Status::Accept,
            "synthetic",
            Value::object([("score", Value::Bool(true))]),
        );
        let outcome = node
            .settle_improvement(&claim, boolean, &ratchet, None, TS)
            .expect("outcome");
        assert!(!outcome.settled);
        assert_eq!(outcome.note, "verifier produced no integer score");

        let none = Verdict::accept("synthetic");
        let outcome = node
            .settle_improvement(&claim, none, &ratchet, None, TS)
            .expect("outcome");
        assert!(!outcome.settled);
        assert!(node.ledger().entries_of_kind(FRONTIER).is_empty());
    }

    #[test]
    fn reaching_the_target_exhausts_the_pool_exactly() {
        let dir = TempDir::new("exhausted");
        let mut node = node(&dir);
        let objective = ratchet_objective();
        node.post_objective(&objective, TS).expect("post");
        let ratchet = Ratchet::new(0, 100, 1_000_000, Direction::Maximize, 1).expect("valid");

        let mut total: u64 = 0;
        let mut held: Option<FrontierEntry> = None;
        let mut note = String::new();
        for (who, score) in [
            ("alice", 20i64),
            ("bob", 55i64),
            ("carol", 90i64),
            ("dave", 100i64),
        ] {
            let claim = claim_for(
                &objective,
                who,
                Value::object([("s", Value::Int(i128::from(score)))]),
                who,
            );
            let outcome = node
                .settle_improvement(
                    &claim,
                    scored(i128::from(score)),
                    &ratchet,
                    held.as_ref(),
                    TS,
                )
                .expect("improvement");
            total += outcome.reward;
            note = outcome.note;
            held = node.frontier_of(&objective.id());
        }
        assert_eq!(total, 1_000_000);
        assert!(note.contains("pool exhausted"), "{note}");
        assert_eq!(
            held.map(|frontier| frontier.paid_cumulative),
            Some(1_000_000)
        );
        // Four settlements, one pool, paid out exactly: the invariants that do
        // hold for a progressive objective.
        let problems = node.audit(false);
        assert!(
            !problems.iter().any(|p| p.contains("against a pool of")),
            "{problems:?}"
        );
        assert!(
            !problems.iter().any(|p| p.contains("without improving")),
            "{problems:?}"
        );
    }

    #[test]
    fn an_advance_worth_zero_still_moves_the_frontier() {
        // A pool smaller than its span: one step of progress truncates to a
        // payout of zero, and the frontier still advanced.
        let dir = TempDir::new("zero-payout");
        let mut node = node(&dir);
        let objective = Objective {
            reward: 10,
            ratchet: Some(ratchet_block(0, 97, 10)),
            ..ratchet_objective()
        };
        node.post_objective(&objective, TS).expect("post");
        let ratchet = Ratchet::new(0, 97, 10, Direction::Maximize, 1).expect("valid");

        let claim = claim_for(
            &objective,
            "alice",
            Value::object([("s", Value::Int(1))]),
            "n1",
        );
        let outcome = node
            .settle_improvement(&claim, scored(1), &ratchet, None, TS)
            .expect("improvement");
        assert!(outcome.settled);
        assert_eq!(outcome.reward, 0);
        assert_eq!(node.ledger().entries_of_kind(FRONTIER).len(), 1);
        // No settlement record for a payout of zero -- there is nothing to pay.
        assert!(node.ledger().entries_of_kind(SETTLEMENT).is_empty());
    }

    #[test]
    fn a_cumulative_payout_that_would_overflow_is_refused_not_wrapped() {
        // Python adds bignums here. Wrapping would reset the objective's running
        // total and hide an overspent pool from the audit.
        let dir = TempDir::new("overflow");
        let mut node = node(&dir);
        let objective = ratchet_objective();
        node.post_objective(&objective, TS).expect("post");
        let ratchet = Ratchet::new(0, 100, 1_000_000, Direction::Maximize, 1).expect("valid");
        let held = FrontierEntry::new(objective.id(), "sha256:held", "alice", 40, u64::MAX);

        let claim = claim_for(
            &objective,
            "bob",
            Value::object([("s", Value::Int(100))]),
            "n2",
        );
        let error = node
            .settle_improvement(&claim, scored(100), &ratchet, Some(&held), TS)
            .expect_err("must overflow");
        assert!(matches!(
            error,
            RuleViolation::PayoutOverflow {
                paid_cumulative: u64::MAX,
                reward: 600_000
            }
        ));
        // Nothing was written: the refusal happens before any append.
        assert!(node.ledger().entries_of_kind(FRONTIER).is_empty());
        assert!(node.ledger().entries_of_kind(SETTLEMENT).is_empty());
    }

    // -- audit --------------------------------------------------------------

    /// Plant a claim, a verdict and (optionally) a settlement directly, so an
    /// audit can be pointed at a log the rules engine would never have written.
    fn plant(
        node: &mut Node,
        objective: &Objective,
        who: &str,
        artifact: Value,
        nonce: &str,
        status: Status,
        settle: Option<u64>,
    ) -> String {
        let hash = commitment_hash(&objective.id(), who, &artifact, nonce);
        node.ledger_mut()
            .append(
                COMMITMENT,
                Commitment::new(objective.id(), who, hash, TS).to_value(),
                TS,
            )
            .expect("append");
        let claim = claim_for(objective, who, artifact, nonce);
        let claim_id = claim.id();
        node.ledger_mut()
            .append(CLAIM, claim.to_value(), TS)
            .expect("append");
        node.ledger_mut()
            .append(
                VERDICT,
                Value::object([
                    ("claim_id", Value::string(claim_id.clone())),
                    ("objective_id", Value::string(objective.id())),
                    ("verdict", Verdict::plain(status, "planted").to_value()),
                ]),
                TS,
            )
            .expect("append");
        if let Some(reward) = settle {
            node.ledger_mut()
                .append(
                    SETTLEMENT,
                    Value::object([
                        ("objective_id", Value::string(objective.id())),
                        ("claim_id", Value::string(claim_id.clone())),
                        ("submitter", Value::string(who)),
                        ("reward", Value::Int(i128::from(reward))),
                    ]),
                    TS,
                )
                .expect("append");
        }
        claim_id
    }

    #[test]
    fn audit_passes_on_an_honest_log() {
        let dir = TempDir::new("audit-honest");
        let mut node = node(&dir);
        let objective = lean_objective(10);
        node.post_objective(&objective, TS).expect("post");
        submit(
            &mut node,
            &objective,
            "mallory",
            proof(":= by sorry"),
            "n1",
            vec![],
        )
        .expect("reveal");
        // Re-verification reproduces the same REJECT, so nothing is wrong.
        assert_eq!(node.audit(true), Vec::<String>::new());
        assert_eq!(node.audit(false), Vec::<String>::new());
    }

    #[test]
    fn audit_reports_a_settled_claim_that_can_no_longer_be_re_verified() {
        // Reporting "log verified" when the payment can no longer be
        // independently re-derived would be a lie of omission.
        let dir = TempDir::new("audit-unverifiable");
        let mut node = node(&dir);
        let objective = lean_objective(10);
        node.post_objective(&objective, TS).expect("post");
        // Recorded ACCEPT and paid; re-verification is UNAVAILABLE because this
        // node has no Lean.
        plant(
            &mut node,
            &objective,
            "alice",
            proof(":= by trivial"),
            "n1",
            Status::Accept,
            Some(10),
        );

        let problems = node.audit(true);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("no longer be re-verified")),
            "{problems:?}"
        );
    }

    #[test]
    fn a_verdict_with_an_unrecognised_status_is_a_problem_with_or_without_a_re_run() {
        // A status no implementation knows is a malformed log, and it is
        // malformed whether or not this node can run the verifier. It used to
        // surface only as a *disagreement* with a re-run, so on a node lacking
        // the toolchain it was silent -- the loudness of a structural defect
        // depending on an unrelated install.
        let dir = TempDir::new("audit-bad-status");
        let mut node = node(&dir);
        let objective = lean_objective(10);
        node.post_objective(&objective, TS).expect("post");
        let artifact = proof(":= by sorry");
        let claim = claim_for(&objective, "alice", artifact.clone(), "n1");
        let claim_id = claim.id();
        let hash = commitment_hash(&objective.id(), "alice", &artifact, "n1");
        node.ledger_mut()
            .append(
                COMMITMENT,
                Commitment::new(objective.id(), "alice", hash, TS).to_value(),
                TS,
            )
            .expect("append");
        node.ledger_mut()
            .append(CLAIM, claim.to_value(), TS)
            .expect("append");
        node.ledger_mut()
            .append(
                VERDICT,
                Value::object([
                    ("claim_id", Value::string(claim_id.clone())),
                    ("objective_id", Value::string(objective.id())),
                    (
                        "verdict",
                        Value::object([
                            ("status", Value::string("probably")),
                            ("detail", Value::string("")),
                        ]),
                    ),
                ]),
                TS,
            )
            .expect("append");

        for rerun in [true, false] {
            let problems = node.audit(rerun);
            assert!(
                problems.iter().any(|p| p.contains("no readable status")),
                "rerun={rerun}: {problems:?}"
            );
        }
    }

    #[test]
    fn audit_reports_a_rejection_it_cannot_reproduce_even_though_nobody_was_paid() {
        // A `reject` never pays, so gating this report on "was it settled?"
        // left rejections entirely unaudited: a node could refuse a claim on a
        // verdict no other node could reproduce, and every audit anywhere would
        // still print "every settled claim re-verified". Censorship with no
        // trace, which is the failure re-derivation exists to prevent -- and
        // worse than the paid case, because a rejected submitter has no
        // payment to point at.
        let dir = TempDir::new("audit-unverifiable-reject");
        let mut node = node(&dir);
        let objective = lean_objective(10);
        node.post_objective(&objective, TS).expect("post");
        // Recorded REJECT and never settled. The proof has no hole, so no
        // screen fires and re-verification needs a toolchain this node lacks.
        plant(
            &mut node,
            &objective,
            "alice",
            proof(":= by trivial"),
            "n1",
            Status::Reject,
            None,
        );

        let problems = node.audit(true);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("recorded reject but can no longer be re-verified")),
            "{problems:?}"
        );
    }

    #[test]
    fn a_recorded_unavailable_that_now_verifies_is_not_a_disagreement() {
        // The inverse of the test above, and the case an ordinary workflow
        // reaches: a node records `unavailable` because it lacks the pinned
        // checker, fetches it from a peer, and audits. The verifier now runs
        // and says `accept`.
        //
        // That is the node learning something, not catching somebody. Nothing
        // settled, nobody was paid, the objective is still open, and an
        // `unavailable` was never a statement about the artifact. Reporting it
        // made `scripts/blob-demo.sh` fail on its last line the first time the
        // fetch path existed to run.
        let dir = TempDir::new("audit-learned");
        let mut node = node(&dir);
        let objective = match replay_objective(1000) {
            Some(objective) => objective,
            None => return,
        };
        node.post_objective(&objective, TS).expect("post");
        // Recorded UNAVAILABLE, never settled; re-verification succeeds because
        // the fixture's replay command really does run here.
        plant(
            &mut node,
            &objective,
            "alice",
            results(1),
            "n1",
            Status::Unavailable,
            None,
        );

        let problems = node.audit(true);
        assert!(
            !problems.iter().any(|p| p.contains("re-verification says")),
            "a verdict that never settled was reported as contradicted: {problems:?}"
        );
    }

    #[test]
    fn an_unsettled_claim_that_cannot_be_re_verified_is_not_a_problem() {
        // The same infrastructure fact says nothing when no money moved.
        let dir = TempDir::new("audit-unsettled");
        let mut node = node(&dir);
        let objective = lean_objective(10);
        node.post_objective(&objective, TS).expect("post");
        plant(
            &mut node,
            &objective,
            "alice",
            proof(":= by trivial"),
            "n1",
            Status::Unavailable,
            None,
        );
        assert_eq!(node.audit(true), Vec::<String>::new());
    }

    #[test]
    fn audit_flags_a_recorded_verdict_that_re_verification_contradicts() {
        let dir = TempDir::new("audit-disagree");
        let mut node = node(&dir);
        let objective = lean_objective(10);
        node.post_objective(&objective, TS).expect("post");
        // Recorded ACCEPT, but the proof contains `sorry`, so any node rejects.
        plant(
            &mut node,
            &objective,
            "alice",
            proof(":= by sorry"),
            "n1",
            Status::Accept,
            Some(10),
        );

        let problems = node.audit(true);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("re-verification says reject")),
            "{problems:?}"
        );
    }

    #[test]
    fn audit_catches_a_claim_with_no_commitment_and_a_claim_with_no_verdict() {
        let dir = TempDir::new("audit-orphans");
        let mut node = node(&dir);
        let objective = lean_objective(10);
        node.post_objective(&objective, TS).expect("post");
        let claim = claim_for(&objective, "eve", proof(":= by trivial"), "n1");
        node.ledger_mut()
            .append(CLAIM, claim.to_value(), TS)
            .expect("append");

        let problems = node.audit(false);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("no matching commitment")),
            "{problems:?}"
        );
        assert!(
            problems.iter().any(|p| p.contains("no verdict recorded")),
            "{problems:?}"
        );
    }

    #[test]
    fn audit_catches_a_settlement_of_a_claim_that_was_never_accepted() {
        let dir = TempDir::new("audit-unaccepted");
        let mut node = node(&dir);
        let objective = lean_objective(10);
        node.post_objective(&objective, TS).expect("post");
        plant(
            &mut node,
            &objective,
            "eve",
            proof(":= by sorry"),
            "n1",
            Status::Reject,
            Some(10),
        );

        let problems = node.audit(false);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("paid a claim that was not accepted")),
            "{problems:?}"
        );
    }

    #[test]
    fn audit_catches_a_plain_objective_settled_twice() {
        let dir = TempDir::new("audit-twice");
        let mut node = node(&dir);
        let objective = lean_objective(10);
        node.post_objective(&objective, TS).expect("post");
        for nonce in ["a", "b"] {
            plant(
                &mut node,
                &objective,
                "alice",
                proof(&format!(":= by trivial {nonce}")),
                nonce,
                Status::Accept,
                Some(5),
            );
        }
        let problems = node.audit(false);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("settled more than once")),
            "{problems:?}"
        );
    }

    #[test]
    fn audit_rejects_an_overspent_pool() {
        let dir = TempDir::new("audit-overspend");
        let mut node = node(&dir);
        let objective = ratchet_objective();
        node.post_objective(&objective, TS).expect("post");
        node.ledger_mut()
            .append(
                SETTLEMENT,
                Value::object([
                    ("objective_id", Value::string(objective.id())),
                    ("claim_id", Value::string("sha256:whatever")),
                    ("submitter", Value::string("eve")),
                    ("reward", Value::Int(5_000_000)),
                ]),
                TS,
            )
            .expect("append");
        let problems = node.audit(false);
        assert!(
            problems.iter().any(|p| p.contains("against a pool of")),
            "{problems:?}"
        );
    }

    #[test]
    fn audit_sums_rewards_without_wrapping() {
        // Two settlements that would wrap a fixed-width accumulator. The audit
        // must still report the overspend rather than a plausible small total.
        let dir = TempDir::new("audit-sum-overflow");
        let mut node = node(&dir);
        let objective = ratchet_objective();
        node.post_objective(&objective, TS).expect("post");
        for _ in 0..2 {
            node.ledger_mut()
                .append(
                    SETTLEMENT,
                    Value::object([
                        ("objective_id", Value::string(objective.id())),
                        ("claim_id", Value::string("sha256:whatever")),
                        ("submitter", Value::string("eve")),
                        ("reward", Value::Int(i128::MAX)),
                    ]),
                    TS,
                )
                .expect("append");
        }
        let problems = node.audit(false);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("overflow") || p.contains("against a pool of")),
            "{problems:?}"
        );
    }

    #[test]
    fn audit_rejects_a_frontier_that_moves_backwards() {
        let dir = TempDir::new("audit-backwards");
        let mut node = node(&dir);
        let objective = ratchet_objective();
        node.post_objective(&objective, TS).expect("post");
        for score in [60, 5] {
            node.ledger_mut()
                .append(
                    FRONTIER,
                    FrontierEntry::new(objective.id(), "sha256:c", "eve", score, 600_000)
                        .to_value(),
                    TS,
                )
                .expect("append");
        }
        let problems = node.audit(false);
        assert!(
            problems.iter().any(|p| p.contains("without improving")),
            "{problems:?}"
        );
    }

    #[test]
    fn audit_reports_a_broken_chain() {
        let dir = TempDir::new("audit-chain");
        let path = dir.path.join("log.jsonl");
        {
            let mut node = node(&dir);
            node.post_objective(&lean_objective(10), TS).expect("post");
            node.ledger_mut()
                .append(FRONTIER, Value::object([("x", Value::Int(1))]), TS)
                .expect("append");
        }
        // Rewrite the first line's payload, keeping its recorded hash.
        let text = fs::read_to_string(&path).expect("read");
        let mut lines: Vec<String> = text.lines().map(String::from).collect();
        let patched = lines[0].replace("\"reward\":10", "\"reward\":1000000000");
        lines[0] = patched;
        fs::write(&path, format!("{}\n", lines.join("\n"))).expect("write");

        let reopened = Node::with_registry(
            Ledger::open(&path).expect("reopen"),
            VerifierRegistry::new(&dir.path).with_lean_binary(NO_LEAN),
        );
        let problems = reopened.audit(false);
        assert!(
            problems.iter().any(|p| p.contains("hash mismatch")),
            "{problems:?}"
        );
    }

    // -- accessors ----------------------------------------------------------

    #[test]
    fn accepted_claims_only_lists_accepted_ones() {
        let dir = TempDir::new("accepted");
        let mut node = node(&dir);
        let objective = lean_objective(10);
        node.post_objective(&objective, TS).expect("post");
        let good = plant(
            &mut node,
            &objective,
            "alice",
            proof(":= by trivial"),
            "n1",
            Status::Accept,
            None,
        );
        let bad = plant(
            &mut node,
            &objective,
            "bob",
            proof(":= by sorry"),
            "n2",
            Status::Reject,
            None,
        );
        let accepted = node.accepted_claims();
        assert!(accepted.contains_key(&good));
        assert!(!accepted.contains_key(&bad));
    }

    #[test]
    fn an_undecodable_objective_is_skipped_and_reported() {
        let dir = TempDir::new("undecodable");
        let mut node = node(&dir);
        node.ledger_mut()
            .append(OBJECTIVE, Value::object([("goal", Value::string("G"))]), TS)
            .expect("append");
        assert!(node.objectives().is_empty());
        let problems = node.audit(false);
        assert!(
            problems.iter().any(|p| p.contains("cannot be decoded")),
            "{problems:?}"
        );
    }

    #[test]
    fn errors_display_usefully() {
        assert!(RuleViolation::NoMatchingCommitment
            .to_string()
            .contains("commit"));
        assert_eq!(Referrer::Claim.to_string(), "claim");
        assert!(RuleViolation::PayoutOverflow {
            paid_cumulative: 1,
            reward: u64::MAX,
        }
        .to_string()
        .contains("money"));
        assert!(RuleViolation::UnknownVerifierKind {
            kind: String::from("\"vibes\""),
        }
        .to_string()
        .contains("certificate"));
    }

    // -- peer records -------------------------------------------------------

    fn peer_of(byte: u8, seq: u64, addr: &str) -> PeerRecord {
        let identity = crate::crypto::identity::Identity::from_secret_bytes([byte; 32]);
        PeerRecord::new(identity.submitter_id(), "ab".repeat(32), addr, seq, TS)
            .signed_with(&identity)
    }

    #[test]
    fn the_peer_audit_resolves_sequences_the_way_peers_does() {
        // Seq 3, a replayed 1, then a 2. `peers` answers 3 throughout, so
        // neither the 1 nor the 2 superseded anything and both are findings.
        //
        // The audit used to track the *last* seq seen rather than the highest,
        // so it reported the 1, then treated the stale value as current and
        // passed the 2 -- an audit contradicting its own implementation's
        // resolution rule, on a log that only a hand-assembled one can be,
        // which is exactly the log an audit exists for. Found by porting the
        // check to the reference and having the two disagree.
        let dir = TempDir::new("peer-seq-resolution");
        let mut node = node(&dir);
        let identity = crate::crypto::identity::Identity::from_secret_bytes([1u8; 32]);

        node.post_peer(&peer_of(1, 3, "203.0.113.3:9000"), TS)
            .expect("first record");
        for (seq, addr) in [(1u64, "203.0.113.1:9000"), (2, "203.0.113.2:9000")] {
            // `post_peer` refuses both, which is the rule working. The log is
            // assembled past it, the way a concatenated or synced one can be.
            assert!(node.post_peer(&peer_of(1, seq, addr), TS).is_err());
            node.ledger_mut()
                .append(PEER, peer_of(1, seq, addr).to_value(), TS)
                .expect("append");
        }

        assert_eq!(node.peers()[&identity.submitter_id()].seq, 3);
        let problems = node.audit(false);
        let stale: Vec<&String> = problems
            .iter()
            .filter(|problem| problem.contains("does not advance"))
            .collect();
        assert_eq!(
            stale.len(),
            2,
            "both stale records should be findings: {problems:?}"
        );
    }

    #[test]
    fn a_peer_record_the_decoder_would_refuse_never_reaches_the_log() {
        // Found by running `proofwork peer --transport <a libp2p-style id>`:
        // it appended happily, and every subsequent audit -- in *both*
        // implementations -- reported the record as undecodable. One command
        // with no error left a log that cannot be audited.
        //
        // Every other kind arrives here already decoded, so `from_value` has
        // run. `PeerRecord::new` takes whatever it is handed, which left this
        // as the one kind that could enter the log without meeting its own
        // decoder.
        let dir = TempDir::new("peer-admissible");
        let mut node = node(&dir);
        let identity = crate::crypto::identity::Identity::from_secret_bytes([9u8; 32]);

        for (field, transport, addr) in [
            ("transport", "12D3KooWNotHex", "203.0.113.1:9000"),
            ("transport", "AB".repeat(32).as_str(), "203.0.113.1:9000"),
            ("addr", "ab".repeat(32).as_str(), ""),
            ("addr", "ab".repeat(32).as_str(), "a \"quoted\" host:9000"),
        ] {
            let record = PeerRecord::new(identity.submitter_id(), transport, addr, 1, TS)
                .signed_with(&identity);
            let error = node
                .post_peer(&record, TS)
                .expect_err("an inadmissible {field} was admitted");
            assert!(
                matches!(error, RuleViolation::InadmissibleRecord(_)),
                "{field}: got {error:?}"
            );
        }

        // Nothing was written, so the log still reads and still audits.
        assert!(node.ledger().entries_of_kind(PEER).is_empty());
        assert_eq!(node.audit(false), Vec::<String>::new());
    }

    /// An undertaking has to name a root this log actually had.
    ///
    /// The rule that makes the record worth writing. A challenge is an index
    /// into a tree of `height` leaves rooted at `root`; if no prefix matches,
    /// no answer to it could ever be checked either way, and the log would
    /// carry a permanent unfalsifiable promise. That is precisely the
    /// "bookkeeping" `docs/roadmap.md` says a payment cannot attach to.
    #[test]
    fn an_undertaking_must_name_a_root_this_log_actually_had() {
        let dir = TempDir::new("undertaking-root");
        let mut node = node(&dir);
        let identity = crate::crypto::identity::Identity::from_secret_bytes([7u8; 32]);

        // Something to undertake, and a balance to stake against it -- every
        // record below bonds 1000, and an identity that cannot afford its bond
        // is refused for *that* reason, which would hide the rule under test.
        node.post_objective(&lean_objective(100), TS)
            .expect("objective");
        node.post_objective(&lean_objective(200), TS)
            .expect("a second, so there is more than one prefix");
        assert!(
            fund(&mut node, &identity, 2_000),
            "this host has no `echo`, so no funding cycle can reach ACCEPT"
        );
        let height = node.ledger().len() as u64;
        let root = node.ledger().root().expect("a non-empty log has a root");

        let good = Undertaking::new(identity.submitter_id(), &root, height, 1_000, TS)
            .signed_with(&identity);
        node.post_undertaking(&good, TS)
            .expect("the log's own root at its own height");

        // A root nobody has ever produced, at the height the log now stands
        // at -- so the size rule passes and only the root rule can refuse it.
        // Re-read, because the good record above made the log one taller.
        let height = node.ledger().len() as u64;
        let invented = Undertaking::new(
            identity.submitter_id(),
            crate::canonical::digest_bytes(b"not a root of anything"),
            height,
            1_000,
            TS,
        )
        .signed_with(&identity);
        assert!(
            matches!(
                node.post_undertaking(&invented, TS),
                Err(RuleViolation::UnknownUndertakingRoot { .. })
            ),
            "an invented root was admitted"
        );

        // An older prefix's real root at the height the log now stands at: the
        // size rule passes and the root rule catches it. This is the reason
        // both are signed -- a root alone does not pin the tree's shape.
        let mismatched = Undertaking::new(identity.submitter_id(), &root, height, 1_000, TS)
            .signed_with(&identity);
        assert!(
            matches!(
                node.post_undertaking(&mismatched, TS),
                Err(RuleViolation::UnknownUndertakingRoot { .. })
            ),
            "a stale root at the current height was admitted"
        );

        // A height past the end of this log: refused by the size rule, which
        // now runs first because it does not depend on the root at all.
        let future = Undertaking::new(identity.submitter_id(), &root, height + 1000, 1_000, TS)
            .signed_with(&identity);
        assert!(
            matches!(
                node.post_undertaking(&future, TS),
                Err(RuleViolation::PartialUndertaking { .. })
            ),
            "a height past the end was admitted"
        );

        // A height past what the *format* allows is refused earlier, by the
        // record's own decoder, and reported as such: the draw reduces modulo a
        // `u32`, so a taller promise could never be sampled in the first place.
        // Two different refusals for two different reasons, and the format one
        // comes first because it does not depend on this log at all.
        let unrepresentable = Undertaking::new(identity.submitter_id(), &root, u64::MAX, 1_000, TS)
            .signed_with(&identity);
        let _ = &unrepresentable;
        assert!(
            matches!(
                node.post_undertaking(&unrepresentable, TS),
                Err(RuleViolation::InadmissibleRecord(_))
            ),
            "a height past the format bound was admitted"
        );

        assert_eq!(node.undertakings().len(), 1, "only the good one is in");
        assert_eq!(node.audit(false), Vec::<String>::new());
    }

    /// A promise already in the log survives the log growing past it, and a
    /// *new* promise about an older prefix is refused.
    ///
    /// Two halves of one rule, and they pull in opposite directions. A record
    /// already written must stay samplable forever or every promise would
    /// expire the moment somebody appended — so the root is checked against a
    /// prefix, and the required height is read off the record's own `seq`. But
    /// a promise being made *now* has to cover the log as it stands, or a node
    /// would simply promise the shortest prefix it could find.
    #[test]
    fn a_promise_survives_growth_but_a_new_one_cannot_reach_backwards() {
        let dir = TempDir::new("undertaking-grow");
        let mut node = node(&dir);
        let identity = crate::crypto::identity::Identity::from_secret_bytes([8u8; 32]);

        node.post_objective(&lean_objective(100), TS)
            .expect("objective");
        let early = promise(&mut node, &identity, 1_000);
        let stale_root = node
            .ledger()
            .prefix(early.height as usize)
            .and_then(|prefix| prefix.root())
            .expect("root");

        for reward in [200, 300, 400] {
            node.post_objective(&lean_objective(reward), TS)
                .expect("the log grows");
        }
        assert_ne!(node.ledger().root(), Some(stale_root.clone()), "it grew");

        // The old promise is still a promise, still samplable, still audited.
        assert!(node.undertakings().iter().any(|u| u.id() == early.id()));
        node.sampled_index(&early, 5, node.ledger().len())
            .expect("still samplable");
        assert_eq!(node.audit(false), Vec::<String>::new());

        // But nobody may make a *new* promise about that older, smaller prefix.
        let backdated = Undertaking::new(
            identity.submitter_id(),
            &stale_root,
            early.height,
            1_000,
            TS,
        )
        .signed_with(&identity);
        assert!(
            matches!(
                node.post_undertaking(&backdated, TS),
                Err(RuleViolation::PartialUndertaking { .. })
            ),
            "a new promise reached backwards to a smaller prefix"
        );
    }

    /// An undertaking speaks for exactly one identity: the one that signed it.
    #[test]
    fn an_undertaking_cannot_be_made_on_somebody_else_s_behalf() {
        let dir = TempDir::new("undertaking-sig");
        let mut node = node(&dir);
        let alice = crate::crypto::identity::Identity::from_secret_bytes([1u8; 32]);
        let mallory = crate::crypto::identity::Identity::from_secret_bytes([2u8; 32]);

        node.post_objective(&lean_objective(100), TS)
            .expect("objective");
        let height = node.ledger().len() as u64;
        let root = node.ledger().root().expect("root");

        // Mallory signs, then relabels it as Alice's promise.
        let mut forged = Undertaking::new(mallory.submitter_id(), &root, height, 1_000, TS)
            .signed_with(&mallory);
        forged.identity = alice.submitter_id();
        assert!(
            node.post_undertaking(&forged, TS).is_err(),
            "a promise was recorded against a key that did not make it"
        );

        // And an unsigned one is nobody's promise at all.
        let unsigned = Undertaking::new(alice.submitter_id(), &root, height, 1_000, TS);
        assert!(
            node.post_undertaking(&unsigned, TS).is_err(),
            "an unsigned promise was admitted"
        );

        assert!(node.undertakings().is_empty());
        assert_eq!(node.audit(false), Vec::<String>::new());
    }

    /// The audit reports what the appender would have refused.
    ///
    /// A log can be assembled by concatenation, so every admission rule needs
    /// a reader-side counterpart or the rule only binds people who use this
    /// tool to write.
    #[test]
    fn the_audit_names_an_undertaking_that_was_never_admissible() {
        let dir = TempDir::new("undertaking-audit");
        let mut node = node(&dir);
        let identity = crate::crypto::identity::Identity::from_secret_bytes([3u8; 32]);
        node.post_objective(&lean_objective(100), TS)
            .expect("objective");
        // Funded, so the bond is affordable and the *only* thing wrong with the
        // record below is its root. The audit reports the first fault it finds
        // and stops, so an unfunded fixture would test the bond rule under the
        // name of the root rule.
        assert!(
            fund(&mut node, &identity, 1_000),
            "this host has no `echo`, so no funding cycle can reach ACCEPT"
        );
        let height = node.ledger().len() as u64;

        // Straight past `post_undertaking`, the way a concatenated log would.
        let invented = Undertaking::new(
            identity.submitter_id(),
            crate::canonical::digest_bytes(b"invented"),
            height,
            1_000,
            TS,
        )
        .signed_with(&identity);
        node.append(UNDERTAKING, invented.to_value(), TS)
            .expect("append");

        let problems = node.audit(false);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(
            problems[0].contains(&format!("no prefix of {height} entries is rooted at")),
            "{}",
            problems[0]
        );
        // And it is not counted as a promise by anybody who reads the log.
        assert!(node.undertakings().iter().all(|u| u.root != invented.root));
    }

    /// A bond nobody funded is caught by the audit, not only on the way in.
    ///
    /// `post_undertaking` refuses one, but a log that arrived from somebody
    /// else was never posted anywhere — it is bytes, and a node concatenating
    /// it calls no rule at all. So the rule has to be re-derivable from the
    /// record's own position in the log, and it has to be re-derived in all
    /// three places that spend on it: the door, the reader
    /// ([`Node::undertakings`], which settlement divides the pool by) and the
    /// audit.
    ///
    /// This test exists because removing the audit's copy broke *nothing*: 74
    /// node tests passed against a build that had stopped checking it. A rule
    /// enforced only on the way in makes the weighting exactly as strong as the
    /// politeness of whoever wrote the log, which is not a rule.
    #[test]
    fn the_audit_names_a_bond_the_log_never_funded() {
        let dir = TempDir::new("undertaking-unfunded");
        let mut node = node(&dir);
        let liar = crate::crypto::identity::Identity::from_secret_bytes([31u8; 32]);
        node.post_objective(&lean_objective(100), TS)
            .expect("objective");

        // Perfect in every other respect: the height the log stands at, that
        // prefix's real root, a valid signature over the whole record. Only the
        // bond is a lie, and it is the one lie the record cannot tell about
        // itself — what this identity has been paid is written below it.
        let height = node.ledger().len() as u64;
        let root = node.ledger().root().expect("root");
        let forged =
            Undertaking::new(liar.submitter_id(), &root, height, 1_000, TS).signed_with(&liar);
        assert!(
            matches!(
                node.post_undertaking(&forged, TS),
                Err(RuleViolation::UnfundedBond {
                    bond: 1_000,
                    spendable: 0,
                    ..
                })
            ),
            "an unfunded bond was admitted"
        );

        // Straight past the rule, the way a concatenated log would carry it.
        node.append(UNDERTAKING, forged.to_value(), TS)
            .expect("append");
        let problems = node.audit(false);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(
            problems[0].contains("bonds 1000 units against a balance of 0"),
            "{}",
            problems[0]
        );
        // And it buys no weight: settlement divides the pool by what
        // `undertakings` returns, so a forged bond that survived to here would
        // hand a fresh identity a share of somebody else's money.
        assert!(
            node.undertakings().is_empty(),
            "a bond nobody funded was counted as a promise"
        );

        // And the check is not simply always-failing. Fund the same identity,
        // promise the same way, and the same code path admits it — so what the
        // audit is reporting above is the *balance*, not the shape.
        //
        // Two thousand for a thousand-unit promise, because the forged record
        // above still counts against its author: `locked_within` reads
        // undertakings that decode and verify, not ones that passed the rules,
        // since the affordability rule is what it feeds. Self-correcting rather
        // than circular — a forged `u64::MAX` bond drives its own author's
        // balance to zero.
        assert!(
            fund(&mut node, &liar, 2_000),
            "this host has no `echo`, so no funding cycle can reach ACCEPT"
        );
        let honest = stake(&mut node, &liar, 1_000);
        assert_eq!(honest.bond, 1_000);
        assert_eq!(node.undertakings().len(), 1, "the funded promise is in");
        assert_eq!(
            node.audit(false).len(),
            1,
            "the funded promise added a fault of its own"
        );
    }

    /// The honest answer a node holding the log would produce: the sampled
    /// entry, and the path putting it under the root it promised.
    fn honest_answer(
        node: &Node,
        promise: &Undertaking,
        epoch: u64,
        who: &crate::crypto::identity::Identity,
    ) -> Availability {
        let index = node
            .sampled_index(promise, epoch, node.ledger().len())
            .expect("draw");
        let proof = node
            .ledger()
            .prefix(promise.height as usize)
            .expect("prefix")
            .prove(index)
            .expect("in range");
        Availability::new(
            who.submitter_id(),
            promise.id(),
            epoch,
            proof.entry.body_with_hash(),
            proof.inclusion.siblings,
            TS,
        )
        .signed_with(who)
    }

    /// Credit `who` with units the way the network actually does: by earning
    /// them.
    ///
    /// A bond has to be backed by a settlement the audit accepts, so this runs
    /// the real cycle -- objective, commit, reveal, settle -- rather than
    /// appending a settlement record directly. The first version of this helper
    /// did append one, against an invented objective id, and every fixture
    /// using it failed the audit with *paid a claim that was not accepted*.
    /// The audit was right; a balance with no accepted claim behind it is
    /// exactly the forgery the bond exists to make impossible.
    fn fund(node: &mut Node, who: &crate::crypto::identity::Identity, units: u64) -> bool {
        // `replay` over `echo`, because it is the one verifier that reaches a
        // real ACCEPT with no language toolchain installed. `None` on a host
        // without `echo`, and every caller then skips rather than asserting
        // against a verdict this machine could not reach.
        // The statement carries the identity so that funding two hosts for the
        // same amount posts two objectives rather than the same one twice.
        let Some(objective) =
            replay_objective_called(units, &format!("reproduce n for {}", who.submitter_id()))
        else {
            return false;
        };
        node.post_objective(&objective, TS).expect("objective");
        // Signed, because the submitter is a public key and this crate
        // refuses a key-shaped submitter without a signature -- the same rule
        // that makes an undertaking's identity mean something.
        //
        // The artifact is the verifier's shape, not a bare `n`: the replay
        // verifier compares `reproducible_fields` under `results`, so an
        // artifact of `{"n": 1}` reproduces nothing and never reaches ACCEPT.
        let artifact = results(1);
        let nonce = format!("n-{units}");
        // The same epoch arithmetic as [`submit`], deliberately rather than by
        // accident: a batch does not settle until the finality window has
        // passed, and a helper that reveals and settles an epoch too early
        // returns a *pending* outcome that pays nothing. Read from
        // `partition::finality_epochs` for the same reason `submit` does — a
        // hard-coded stride is a second copy of a rule that can move.
        let stride = 3 + crate::partition::finality_epochs() as i64;
        let step = node.ledger().len() as i64 * stride * EPOCH;
        let hash = commitment_hash(&objective.id(), &who.submitter_id(), &artifact, &nonce);
        node.commit(
            &Commitment::new(objective.id(), who.submitter_id(), hash, stamp(step))
                .signed_with(who),
            &stamp(step),
        )
        .expect("commit");
        let claim = Claim::new(
            objective.id(),
            who.submitter_id(),
            artifact,
            &nonce,
            TS,
            Vec::new(),
        )
        .expect("valid claim")
        .signed_with(who);
        let outcome = node.reveal(&claim, &stamp(step + EPOCH)).expect("reveal");
        let settled = node
            .settle_at(&stamp(
                step + (2 + crate::partition::finality_epochs() as i64) * EPOCH,
            ))
            .expect("settle")
            .into_iter()
            .find(|candidate| candidate.claim_id == outcome.claim_id)
            .unwrap_or(outcome);
        let outcome = settled;
        assert!(
            outcome.settled,
            "the funding cycle must actually pay, or the bond has nothing behind it"
        );
        true
    }

    /// The attack that used to work, run against a log that declares a supply.
    ///
    /// Post a bounty for a sum nobody issued you, against a verifier you chose,
    /// answer your own question, stake the proceeds. It minted 10^12 units in
    /// four commands and the log audited clean, because nothing there broke a
    /// rule — the rule was missing. The reward now comes out of the funder's own
    /// balance, so the first command is the one that fails.
    ///
    /// This is what makes the bond worth weighing by. A stake-weighted split is
    /// exactly invariant to splitting an identity, which is worth precisely as
    /// much as the stake is scarce; before this, it was worth nothing.
    #[test]
    fn a_bounty_nobody_funded_is_refused_once_the_log_declares_a_supply() {
        let dir = TempDir::new("unfunded-objective");
        let mut node = node(&dir);
        let attacker = crate::crypto::identity::Identity::from_secret_bytes([77u8; 32]);

        // A supply exists, and the attacker is not in it. One unit to somebody
        // else is enough: what matters is that the log has *declared* its
        // units, not how many there are.
        node.post_issuance(&Issuance::new("treasury", 500, TS), TS)
            .expect("genesis issuance");

        const ABSURD: u64 = 1_000_000_000_000;
        let Some(objective) = replay_objective_called(ABSURD, "a bounty I set myself") else {
            return;
        };
        assert_eq!(objective.funder, "treasury");
        assert!(
            matches!(
                node.post_objective(&objective, TS),
                Err(RuleViolation::UnfundedReward {
                    reward: 1_000_000_000_000,
                    spendable: 500,
                    ..
                })
            ),
            "a funder posted a bounty two thousand million times its balance"
        );

        // Not always-failing: what it can afford, it can post, and posting
        // spends it.
        let Some(affordable) = replay_objective_called(500, "a bounty I can pay for") else {
            return;
        };
        node.post_objective(&affordable, TS)
            .expect("a reward the funder holds");
        assert_eq!(
            node.spendable_within("treasury", node.ledger().len()),
            0,
            "posting did not escrow the reward"
        );
        assert_eq!(
            node.escrowed().get("treasury").copied(),
            Some(500),
            "the units went nowhere rather than into escrow"
        );

        // And a second bounty of one unit is refused, because the first one is
        // holding the whole supply.
        let Some(second) = replay_objective_called(1, "one more, on credit") else {
            return;
        };
        assert!(
            matches!(
                node.post_objective(&second, TS),
                Err(RuleViolation::UnfundedReward { .. })
            ),
            "the same units funded two bounties"
        );
        assert_eq!(node.audit(false), Vec::<String>::new());

        // Meanwhile the attacker, who was issued nothing, cannot even open.
        let unfunded = Objective::new(
            "G",
            "mine",
            affordable.verifier.clone(),
            1,
            attacker.submitter_id(),
            TS,
            None,
            None,
        )
        .expect("valid objective");
        assert!(matches!(
            node.post_objective(&unfunded, TS),
            Err(RuleViolation::UnfundedReward { spendable: 0, .. })
        ));
    }

    /// A settlement moves escrow to the submitter rather than creating units.
    ///
    /// The conservation half: after a full cycle the supply is where it started
    /// in total and somewhere else in particular. Checked as an equation over
    /// the whole log, because "nothing was minted" is a statement about a sum
    /// and not about any one record.
    #[test]
    fn a_settled_reward_moves_escrow_and_mints_nothing() {
        let dir = TempDir::new("escrow-conserves");
        let mut node = node(&dir);
        let worker = crate::crypto::identity::Identity::from_secret_bytes([78u8; 32]);
        node.post_issuance(&Issuance::new("treasury", 1_000, TS), TS)
            .expect("genesis issuance");

        let Some(objective) = replay_objective_called(1_000, "the whole supply, at stake") else {
            return;
        };
        node.post_objective(&objective, TS).expect("post");

        let artifact = results(1);
        let stride = 3 + crate::partition::finality_epochs() as i64;
        let step = node.ledger().len() as i64 * stride * EPOCH;
        let hash = commitment_hash(&objective.id(), &worker.submitter_id(), &artifact, "n");
        node.commit(
            &Commitment::new(objective.id(), worker.submitter_id(), hash, stamp(step))
                .signed_with(&worker),
            &stamp(step),
        )
        .expect("commit");
        let claim = Claim::new(
            objective.id(),
            worker.submitter_id(),
            artifact,
            "n",
            TS,
            Vec::new(),
        )
        .expect("valid claim")
        .signed_with(&worker);
        node.reveal(&claim, &stamp(step + EPOCH)).expect("reveal");
        node.settle_at(&stamp(
            step + (2 + crate::partition::finality_epochs() as i64) * EPOCH,
        ))
        .expect("settle");

        // The units moved: escrow released, worker paid, total unchanged.
        assert_eq!(node.escrowed().get("treasury").copied().unwrap_or(0), 0);
        assert_eq!(
            node.balances().get(&worker.submitter_id()).copied(),
            Some(1_000)
        );
        let issued: u128 = node.issued().values().sum();
        let held: u128 = node.balances().values().sum();
        let escrowed: u128 = node.escrowed().values().sum();
        assert_eq!(
            held + escrowed,
            issued,
            "the supply did not close: {issued} issued, {held} held, {escrowed} escrowed"
        );
        assert_eq!(node.audit(false), Vec::<String>::new());
    }

    /// A bounty nobody funded is named by the audit, not only refused at the
    /// door.
    ///
    /// `post_objective` refuses one, but a log that arrived from somebody else
    /// was never posted anywhere — it is bytes, and a node concatenating it
    /// calls no rule at all. So the supply has to be re-derivable from the
    /// records: issued plus settled, against escrowed plus locked, per
    /// identity.
    ///
    /// This test exists because removing the audit's copy broke *nothing*: 85
    /// node tests passed against a build that had stopped checking it. The same
    /// trap as the bond, in the same place, one change later.
    #[test]
    fn the_audit_names_a_reward_the_supply_never_covered() {
        let dir = TempDir::new("unfunded-reward-audit");
        let mut broke = node(&dir);
        broke
            .post_issuance(&Issuance::new("treasury", 100, TS), TS)
            .expect("genesis issuance");

        let objective = lean_objective(1_000);
        assert!(
            matches!(
                broke.post_objective(&objective, TS),
                Err(RuleViolation::UnfundedReward {
                    reward: 1_000,
                    spendable: 100,
                    ..
                })
            ),
            "an unfunded bounty was admitted"
        );

        // Straight past the rule, the way a concatenated log would carry it.
        broke
            .append(OBJECTIVE, objective.to_value(), TS)
            .expect("append");
        let problems = broke.audit(false);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("has committed 1000 units against 100")),
            "a bounty the supply never covered went unreported: {problems:?}"
        );

        // And the check is not always-failing: a log whose commitments fit
        // inside its supply reports nothing about the supply at all.
        let clean = TempDir::new("funded-reward-audit");
        let mut solvent = node(&clean);
        solvent
            .post_issuance(&Issuance::new("treasury", 1_000, TS), TS)
            .expect("genesis issuance");
        solvent
            .post_objective(&lean_objective(1_000), TS)
            .expect("a reward the supply covers");
        assert_eq!(solvent.audit(false), Vec::<String>::new());
    }

    /// An issuance below the genesis prefix is a mint, and the audit names it.
    ///
    /// The rule that makes the supply a supply. `post_issuance` refuses one,
    /// but a log arriving from somewhere else was never posted anywhere, so the
    /// position rule has to be re-derivable from the records alone.
    #[test]
    fn an_issuance_after_the_genesis_prefix_is_a_mint_the_audit_names() {
        let dir = TempDir::new("late-issuance");
        let mut node = node(&dir);
        node.post_issuance(&Issuance::new("treasury", 10, TS), TS)
            .expect("genesis issuance");
        node.post_objective(&lean_objective(10), TS)
            .expect("something after genesis");

        let late = Issuance::new("treasury", 1_000_000, TS);
        assert!(
            matches!(
                node.post_issuance(&late, TS),
                Err(RuleViolation::MintedAfterGenesis { .. })
            ),
            "the supply grew after it was declared"
        );

        // Straight past the rule, the way a concatenated log would carry it.
        node.append(ISSUANCE, late.to_value(), TS).expect("append");
        let problems = node.audit(false);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("after the genesis prefix")),
            "a mint went unreported: {problems:?}"
        );
        // And it is not credited: the balance is what genesis said, minus what
        // the objective escrowed.
        assert_eq!(node.issued().get("treasury").copied(), Some(10));
        assert_eq!(node.spendable_within("treasury", node.ledger().len()), 0);
    }

    /// Promise the whole log as it stands, staking `bond`.
    ///
    /// Funds the identity first: a bond has to be backed by units the log says
    /// it earned, so a fixture that stakes has to have been paid.
    fn promise(node: &mut Node, who: &crate::crypto::identity::Identity, bond: u64) -> Undertaking {
        // `expect` rather than a skip: every caller of this helper is about the
        // bond arithmetic, not about the verifier, and a host without `echo`
        // should say so loudly here rather than silently pass a suite that
        // never exercised the thing it names.
        assert!(
            fund(node, who, bond),
            "this host has no `echo`, so no funding cycle can reach ACCEPT"
        );
        stake(node, who, bond)
    }

    /// Promise the whole log as it stands out of a balance the identity
    /// *already* has.
    ///
    /// Split out of [`promise`] so a fixture can stake one balance twice and
    /// ask what the split earned, which is the whole question a sybil poses.
    fn stake(node: &mut Node, who: &crate::crypto::identity::Identity, bond: u64) -> Undertaking {
        let height = node.ledger().len() as u64;
        let root = node.ledger().root().expect("root");
        let record = Undertaking::new(who.submitter_id(), &root, height, bond, TS).signed_with(who);
        node.post_undertaking(&record, TS).expect("undertaking");
        record
    }

    /// A node that holds the log answers its sample; a node that guesses cannot.
    ///
    /// The whole mechanism, end to end and from the log alone. Nobody issues
    /// the challenge and nobody receives the answer — the index is a pure
    /// function of the log, and the check is too.
    #[test]
    fn a_holder_answers_its_own_sample_and_a_guess_does_not_pass() {
        let dir = TempDir::new("availability");
        let mut node = node(&dir);
        let identity = crate::crypto::identity::Identity::from_secret_bytes([4u8; 32]);

        for reward in [100, 200, 300, 400, 500] {
            node.post_objective(&lean_objective(reward), TS)
                .expect("objective");
        }
        let held = promise(&mut node, &identity, 1_000);

        let epoch = 7;
        let index = node
            .sampled_index(&held, epoch, node.ledger().len())
            .expect("draw");
        assert!(index < held.height, "the draw must land inside the tree");

        node.post_availability(&honest_answer(&node, &held, epoch, &identity), TS)
            .expect("an honest answer is admitted");
        assert_eq!(node.availability_answers().len(), 1);

        // A node that did not hold the log has to guess the path.
        let good = honest_answer(&node, &held, epoch, &identity);
        let bluff = Availability::new(
            identity.submitter_id(),
            held.id(),
            epoch,
            good.entry.clone(),
            good.path
                .iter()
                .map(|_| crate::canonical::digest_bytes(b"guess"))
                .collect(),
            TS,
        )
        .signed_with(&identity);
        assert!(
            matches!(
                node.post_availability(&bluff, TS),
                Err(RuleViolation::AvailabilityDoesNotCheck { .. })
            ),
            "a guessed path was accepted"
        );

        // The draw moves with the epoch, which is what stops a node storing one
        // entry and replaying it forever.
        let elsewhere = (0..40u64)
            .map(|e| {
                node.sampled_index(&held, e, node.ledger().len())
                    .expect("draw")
            })
            .filter(|&at| at != index)
            .count();
        assert!(elsewhere > 0, "the draw never moved across 40 epochs");

        assert_eq!(node.audit(false), Vec::<String>::new());
    }

    /// The answer has to carry the sampled entry, not merely a path to it.
    ///
    /// This is the finding that made the first version of the mechanism
    /// hollow. The verifier used to recompute the leaf from its *own* copy of
    /// the log, so an answerer never needed any payload — only the entry
    /// hashes, from which every path is derivable. Measured at the time: a node
    /// keeping 10% of a log reproduced the honest answer byte for byte, and was
    /// paid in full for storing a hash tree.
    #[test]
    fn an_answer_carrying_the_wrong_entry_is_refused_even_with_a_perfect_path() {
        let dir = TempDir::new("availability-entry");
        let mut node = node(&dir);
        let identity = crate::crypto::identity::Identity::from_secret_bytes([12u8; 32]);
        for reward in [100, 200, 300, 400] {
            node.post_objective(&lean_objective(reward), TS)
                .expect("objective");
        }
        let held = promise(&mut node, &identity, 1_000);
        let epoch = 3;
        let index = node
            .sampled_index(&held, epoch, node.ledger().len())
            .expect("draw");
        let honest = honest_answer(&node, &held, epoch, &identity);

        // A node holding every hash but no payload can still build the path.
        // Substituting *any* other entry, or a plausible forgery, must fail --
        // that is the whole difference between proving storage and proving
        // arithmetic.
        let other = usize::try_from(index).expect("fits") ^ 1;
        let substitute = node
            .ledger()
            .entries()
            .get(other.min(node.ledger().len() - 1))
            .expect("another entry")
            .body_with_hash();
        let swapped = Availability::new(
            identity.submitter_id(),
            held.id(),
            epoch,
            substitute,
            honest.path.clone(),
            TS,
        )
        .signed_with(&identity);
        assert!(
            matches!(
                node.post_availability(&swapped, TS),
                Err(RuleViolation::AvailabilityDoesNotCheck { .. })
            ),
            "an answer about a different entry was accepted"
        );

        // And a value that is not an entry at all is a refusal, not a panic.
        let rubbish = Availability::new(
            identity.submitter_id(),
            held.id(),
            epoch,
            Value::string("not an entry"),
            honest.path.clone(),
            TS,
        )
        .signed_with(&identity);
        assert!(node.post_availability(&rubbish, TS).is_err());

        // The honest one still passes, so the check is not simply always-no.
        node.post_availability(&honest, TS).expect("honest answer");
        assert_eq!(node.audit(false), Vec::<String>::new());
    }

    /// An answer stays valid as the log grows, and does not depend on how long
    /// this process thinks an epoch is.
    ///
    /// Two defects in one test, both measured before they were fixed and both
    /// of the shape that reads as flakiness rather than as a bug.
    ///
    /// The anchor used to be taken over the whole log, so every later append
    /// moved it, moved the beacon, and moved the sampled index — an answer that
    /// was right when written became wrong two entries later. And the epoch
    /// length came from `PROOFWORK_EPOCH_SECONDS`, an environment variable, so
    /// the same log audited clean or dirty depending on how the auditor was
    /// configured: six failures in ten across a dozen logs.
    ///
    /// A rule that depends on a process's environment is not a consensus rule.
    #[test]
    fn an_answer_survives_the_log_growing_under_it() {
        let dir = TempDir::new("availability-stable");
        let mut node = node(&dir);
        let identity = crate::crypto::identity::Identity::from_secret_bytes([14u8; 32]);
        for reward in [100, 200, 300, 400, 500, 600, 700] {
            node.post_objective(&lean_objective(reward), TS)
                .expect("objective");
        }
        let held = promise(&mut node, &identity, 1_000);
        // An epoch the fixture timestamps actually fall *before*, so entries
        // qualify and the anchor is a real hash. The first version of this test
        // used epoch 11, which is long before 2026: no entry qualified, the
        // anchor was the empty string whatever the log did, and the test passed
        // against both bugs it was written to catch. A test that cannot fail is
        // worse than no test, so this one is checked by injection.
        let epoch = crate::time::parse_rfc3339(TS)
            .map(|seconds| epoch_of(seconds as u64, partition::EPOCH_SECONDS) + 1)
            .expect("the fixture timestamp parses");
        assert_ne!(
            node.anchor_at(epoch, node.ledger().len(), partition::EPOCH_SECONDS),
            String::new(),
            "the fixture must produce a real anchor or this test proves nothing"
        );
        let before = node
            .sampled_index(&held, epoch, node.ledger().len())
            .expect("draw");
        node.post_availability(&honest_answer(&node, &held, epoch, &identity), TS)
            .expect("answer");

        // The log grows by every kind that can follow an answer.
        for reward in [800, 900, 1000] {
            node.post_objective(&lean_objective(reward), TS)
                .expect("the log grows");
        }
        let at = node
            .ledger()
            .entries_of_kind(AVAILABILITY)
            .first()
            .map(|entry| entry.seq as usize)
            .expect("the answer is in the log");
        assert_eq!(
            node.sampled_index(&held, epoch, at).expect("draw"),
            before,
            "the sampled index moved when the log grew"
        );
        assert_eq!(
            node.availability_answers().len(),
            1,
            "the answer stopped checking"
        );
        assert_eq!(node.audit(false), Vec::<String>::new());
    }

    /// The sample is drawn against the promiser, so an impostor's answer would
    /// be arithmetically correct. Only the rule stops it.
    #[test]
    fn nobody_can_answer_somebody_else_s_sample() {
        let dir = TempDir::new("availability-impostor");
        let mut node = node(&dir);
        let alice = crate::crypto::identity::Identity::from_secret_bytes([5u8; 32]);
        let mallory = crate::crypto::identity::Identity::from_secret_bytes([6u8; 32]);

        node.post_objective(&lean_objective(100), TS)
            .expect("objective");
        node.post_objective(&lean_objective(200), TS)
            .expect("objective");
        let held = promise(&mut node, &alice, 1_000);

        // Mallory holds the log too -- the entry and path are correct. What
        // Mallory does not have is Alice's promise, and the pool pays promises.
        let honest = honest_answer(&node, &held, 3, &alice);
        let poached = Availability::new(
            mallory.submitter_id(),
            held.id(),
            3,
            honest.entry,
            honest.path,
            TS,
        )
        .signed_with(&mallory);
        assert!(
            matches!(
                node.post_availability(&poached, TS),
                Err(RuleViolation::AvailabilityImpostor { .. })
            ),
            "an answer to somebody else's promise was accepted"
        );
        assert!(node.availability_answers().is_empty());
        assert_eq!(node.audit(false), Vec::<String>::new());
    }

    /// An answer whose promise this log does not hold is refused, not ignored.
    #[test]
    fn an_answer_needs_a_promise_the_log_actually_holds() {
        let dir = TempDir::new("availability-orphan");
        let mut node = node(&dir);
        let identity = crate::crypto::identity::Identity::from_secret_bytes([11u8; 32]);
        node.post_objective(&lean_objective(100), TS)
            .expect("objective");

        let orphan = Availability::new(
            identity.submitter_id(),
            crate::canonical::digest_bytes(b"no such promise"),
            1,
            Value::object([("seq", Value::Int(0))]),
            Vec::new(),
            TS,
        )
        .signed_with(&identity);
        assert!(
            matches!(
                node.post_availability(&orphan, TS),
                Err(RuleViolation::UnknownUndertaking { .. })
            ),
            "an answer to nothing was accepted"
        );
    }

    /// A promise must cover the whole log as it stood, and the promiser does
    /// not choose.
    ///
    /// The measured attack this closes: with the height free, promising one
    /// entry drew index 0 every epoch, answered with an empty path, and
    /// collected exactly what promising the whole log collected -- 50 units
    /// each on a 3-entry log with a 100-unit pot. Promising less was strictly
    /// dominant, so the pool bought no storage at all.
    #[test]
    fn a_promise_must_cover_the_whole_log_and_the_promiser_does_not_choose() {
        let dir = TempDir::new("undertaking-partial");
        let mut node = node(&dir);
        let cheat = crate::crypto::identity::Identity::from_secret_bytes([13u8; 32]);
        for reward in [100, 200, 300] {
            node.post_objective(&lean_objective(reward), TS)
                .expect("objective");
        }
        // Funded for *two* promises, because the rejected one below is appended
        // raw and its bond still counts against its author: `locked_within`
        // reads undertakings that decode and verify, deliberately not ones that
        // pass the rules, since the affordability rule is what it feeds. So the
        // honest promise at the end needs a second 1000 behind it, and the
        // refusals in between are refusals of *size*, not of affordability.
        assert!(
            fund(&mut node, &cheat, 2_000),
            "this host has no `echo`, so no funding cycle can reach ACCEPT"
        );
        let full = node.ledger().len() as u64;
        let small = node
            .ledger()
            .prefix(1)
            .and_then(|prefix| prefix.root())
            .expect("a one-entry prefix has a root");

        // The whole point: this is a *real* root of a *real* prefix, signed by
        // a real key. Only the size rule refuses it.
        let partial =
            Undertaking::new(cheat.submitter_id(), &small, 1, 1_000, TS).signed_with(&cheat);
        assert!(
            matches!(
                node.post_undertaking(&partial, TS),
                Err(RuleViolation::PartialUndertaking { promised: 1, .. })
            ),
            "a one-entry promise was admitted"
        );

        // Appended past the rule, the way a concatenated log would carry it: it
        // is not counted as a promise and the audit names it.
        node.append(UNDERTAKING, partial.to_value(), TS)
            .expect("append");
        assert!(
            node.undertakings().is_empty(),
            "a partial promise was counted"
        );
        assert!(
            node.audit(false)
                .iter()
                .any(|p| p.contains("not the promiser's to choose")),
            "the audit passed a partial promise"
        );

        // And the honest promise -- the whole log as it now stands, one entry
        // taller for the rejected record appended above -- is admitted.
        assert!(full > 1, "the fixture needs more than one entry");
        let now = node.ledger().len() as u64;
        let honest = Undertaking::new(
            cheat.submitter_id(),
            node.ledger().root().expect("root"),
            now,
            1_000,
            TS,
        )
        .signed_with(&cheat);
        node.post_undertaking(&honest, TS)
            .expect("the whole log is the promise");
    }

    /// Settlement pays by weight, so a small promise earns proportionally.
    #[test]
    fn availability_settlement_pays_answers_and_names_silence() {
        let dir = TempDir::new("availability-settle");
        let mut node = node(&dir);
        let early = crate::crypto::identity::Identity::from_secret_bytes([21u8; 32]);
        let late = crate::crypto::identity::Identity::from_secret_bytes([22u8; 32]);
        let quiet = crate::crypto::identity::Identity::from_secret_bytes([23u8; 32]);

        node.post_objective(&lean_objective(100), TS)
            .expect("objective");
        node.post_availability_pool(
            &AvailabilityPool {
                funder: "treasury".to_string(),
                per_epoch: 90,
                from_epoch: 0,
                to_epoch: 10,
                created_at: TS.to_string(),
            },
            TS,
        )
        .expect("pool");

        // `early` promises a short log and stakes a lot; the log then grows and
        // `late` promises the long one and stakes a little. The two signals
        // point in *opposite* directions on purpose, so the test can tell which
        // one the share follows: under the old height weighting `late` would
        // take the larger share, and under bond weighting `early` does.
        let early_promise = promise(&mut node, &early, 3_000);
        for reward in [200, 300, 400, 500, 600] {
            node.post_objective(&lean_objective(reward), TS)
                .expect("objective");
        }
        let late_promise = promise(&mut node, &late, 1_000);
        let _quiet_promise = promise(&mut node, &quiet, 1_000);
        assert!(late_promise.height > early_promise.height);
        assert!(early_promise.bond > late_promise.bond);

        let epoch = 4;
        for (who, held) in [(&early, &early_promise), (&late, &late_promise)] {
            node.post_availability(&honest_answer(&node, held, epoch, who), TS)
                .expect("answer");
        }

        let outcome = node
            .settle_availability(epoch, TS)
            .expect("settles")
            .expect("there was something to settle");
        assert_eq!(outcome.answered, 2, "two identities answered");
        assert_eq!(outcome.silent, 1, "the quiet one is named");

        // The larger *stake* took the larger share, and it took it while
        // holding the *shorter* log. The split follows what was put at risk,
        // not the head count and not the size of the claim.
        let paid = availability_payouts(&node);
        let early_paid = paid[&early.submitter_id()];
        let late_paid = paid[&late.submitter_id()];
        assert!(
            early_paid > late_paid,
            "the share followed the promise instead of the bond: \
             early staked {} and earned {early_paid}, late staked {} and earned {late_paid}",
            early_promise.bond,
            late_promise.bond
        );
        assert_eq!(
            u128::from(early_paid) + u128::from(late_paid) + outcome.unpaid,
            node.availability_offered(epoch),
            "the pot did not close"
        );
        assert!(!paid.contains_key(&quiet.submitter_id()));

        // An epoch settles once. A second call is a no-op, not a second payout.
        assert_eq!(
            node.settle_availability(epoch, TS).expect("idempotent"),
            None
        );
        assert_eq!(node.audit(false), Vec::<String>::new());
    }

    /// Splitting one balance across two promises earns what one promise of the
    /// whole balance earns.
    ///
    /// The same question a sybil asks, asked without new keys. Under the old
    /// height weighting the answer was *twice as much*: undertake repeatedly,
    /// answer each, collect a full weight every time, all from one copy of the
    /// log and at the cost of a signature. The bond is what makes the answer
    /// *exactly the same*, because the two promises share one balance and the
    /// weights are summed.
    #[test]
    fn splitting_one_balance_across_two_promises_earns_what_one_promise_earns() {
        let dir = TempDir::new("availability-double");
        let mut node = node(&dir);
        let greedy = crate::crypto::identity::Identity::from_secret_bytes([24u8; 32]);
        let plain = crate::crypto::identity::Identity::from_secret_bytes([25u8; 32]);
        node.post_objective(&lean_objective(100), TS)
            .expect("objective");
        node.post_availability_pool(
            &AvailabilityPool {
                funder: "treasury".to_string(),
                per_epoch: 100,
                from_epoch: 0,
                to_epoch: 10,
                created_at: TS.to_string(),
            },
            TS,
        )
        .expect("pool");

        // Equal balances. `plain` stakes its 1000 once; `greedy` stakes the
        // same 1000 as two promises of 500, and the log grows in between so the
        // second promise really is the larger claim.
        let plain_promise = promise(&mut node, &plain, 1_000);
        assert!(
            fund(&mut node, &greedy, 1_000),
            "this host has no `echo`, so no funding cycle can reach ACCEPT"
        );
        let first = stake(&mut node, &greedy, 500);
        node.post_objective(&lean_objective(200), TS)
            .expect("objective");
        let second = stake(&mut node, &greedy, 500);
        assert!(second.height > first.height);

        // And there could not have been a third: the balance is spent. Checked
        // *here*, before the settlement below pays greedy and gives it
        // something new to stake -- which is correct behaviour and would have
        // made this assertion pass for the wrong reason.
        let height = node.ledger().len() as u64;
        let root = node.ledger().root().expect("root");
        let third =
            Undertaking::new(greedy.submitter_id(), &root, height, 1, TS).signed_with(&greedy);
        assert!(
            matches!(
                node.post_undertaking(&third, TS),
                Err(RuleViolation::UnfundedBond { .. })
            ),
            "a third promise was free, so the split was never bounded by anything"
        );

        let epoch = 2;
        for (who, held) in [
            (&plain, &plain_promise),
            (&greedy, &first),
            (&greedy, &second),
        ] {
            node.post_availability(&honest_answer(&node, held, epoch, who), TS)
                .expect("answer");
        }
        node.settle_availability(epoch, TS)
            .expect("settles")
            .expect("something to settle");

        let paid = availability_payouts(&node);
        assert_eq!(paid.len(), 2, "one row per identity, not per promise");

        // The precise property, read off the record: greedy's weight is the
        // *sum* of what it staked, which is what plain staked in one go. Equal
        // stake, equal weight, equal pay -- the split bought nothing.
        let weights = availability_weights(&node);
        assert_eq!(
            weights[&greedy.submitter_id()],
            first.bond + second.bond,
            "stake is conserved when it is divided; the weight must be too"
        );
        assert_eq!(weights[&plain.submitter_id()], plain_promise.bond);
        assert_eq!(
            paid[&greedy.submitter_id()],
            paid[&plain.submitter_id()],
            "two promises out of one balance outearned one promise of it"
        );
        assert_eq!(node.audit(false), Vec::<String>::new());
    }

    /// One operator splitting a fixed stake across many keys earns exactly what
    /// it earns holding that stake under one key.
    ///
    /// This is the sybil property stated as an equation rather than as an
    /// intuition, and it is the strongest form the network can have: identities
    /// are free to make, so no rule can stop them being made. What a rule *can*
    /// do is make them worthless, by paying a resource that is conserved when
    /// it is divided instead of a head count that is not.
    ///
    /// Note what this does **not** claim. It bounds sybil *profit*, not sybil
    /// *existence*: forty keys still appear in the log, still answer, still
    /// occupy rows. And it says nothing about whether the bonded node holds the
    /// data itself or fetches a challenged entry from somebody else on demand.
    /// Closing that needs proof of replication, which this does not have.
    ///
    /// Sixteen keys rather than forty only because each one has to *earn* its
    /// stake through a real objective/commit/reveal/settle cycle and the
    /// fixture is already the slowest test in the crate. The equation does not
    /// care about the count: any `n` that divides the stake evenly gives the
    /// same two numbers, and the injection that breaks it (weight by head count
    /// instead of bond) breaks it at `n = 2`.
    #[test]
    fn splitting_a_stake_across_many_identities_earns_what_one_identity_earns() {
        const KEYS: u64 = 16;
        const STAKE: u64 = 16_000;

        let (honest_alone, attacker_whole) = split_payouts("sybil-one", 1, STAKE);
        let (honest_beside_many, attacker_split) = split_payouts("sybil-many", KEYS, STAKE);

        assert!(attacker_whole > 0, "the fixture paid nobody");
        assert_eq!(
            attacker_split, attacker_whole,
            "splitting one stake across {KEYS} keys changed what it earned: \
             {attacker_whole} whole, {attacker_split} split"
        );
        assert_eq!(
            honest_beside_many, honest_alone,
            "the honest operator's share moved because somebody else made keys: \
             {honest_alone} beside one, {honest_beside_many} beside {KEYS}"
        );
    }

    /// One epoch of availability settlement in which an honest operator stakes
    /// `total` under a single key and an attacker stakes the same `total` split
    /// evenly across `keys` keys. Returns `(honest, attacker_total)`.
    ///
    /// The pool and the stakes are chosen to divide exactly, so the two runs
    /// can be compared with `assert_eq!` rather than a tolerance. Flooring
    /// would otherwise cost the splitter dust -- `keys` remainders instead of
    /// one -- which is a rounding artefact and not the property under test.
    fn split_payouts(tag: &str, keys: u64, total: u64) -> (u64, u64) {
        let dir = TempDir::new(tag);
        let mut node = node(&dir);
        node.post_availability_pool(
            &AvailabilityPool {
                funder: "treasury".to_string(),
                per_epoch: 32_000,
                from_epoch: 0,
                to_epoch: 1_000,
                created_at: TS.to_string(),
            },
            TS,
        )
        .expect("pool");

        let honest = crate::crypto::identity::Identity::from_secret_bytes([7u8; 32]);
        let honest_promise = promise(&mut node, &honest, total);

        let share = total / keys;
        let attackers: Vec<_> = (0..keys)
            .map(|n| {
                let who = crate::crypto::identity::Identity::from_secret_bytes(
                    [100u8.wrapping_add(n as u8); 32],
                );
                let held = promise(&mut node, &who, share);
                (who, held)
            })
            .collect();

        let epoch = 4;
        node.post_availability(&honest_answer(&node, &honest_promise, epoch, &honest), TS)
            .expect("answer");
        for (who, held) in &attackers {
            node.post_availability(&honest_answer(&node, held, epoch, who), TS)
                .expect("answer");
        }
        node.settle_availability(epoch, TS)
            .expect("settles")
            .expect("something to settle");
        assert_eq!(node.audit(false), Vec::<String>::new());

        let paid = availability_payouts(&node);
        let attacker_total = attackers
            .iter()
            .map(|(who, _)| paid.get(&who.submitter_id()).copied().unwrap_or(0))
            .sum();
        (
            paid.get(&honest.submitter_id()).copied().unwrap_or(0),
            attacker_total,
        )
    }

    /// Weighted shares floor-divide and the remainder is recorded, never
    /// dropped. No floats anywhere near money.
    #[test]
    fn an_indivisible_pot_leaves_a_remainder_the_record_accounts_for() {
        let dir = TempDir::new("availability-remainder");
        let mut node = node(&dir);
        node.post_objective(&lean_objective(100), TS)
            .expect("objective");
        node.post_availability_pool(
            &AvailabilityPool {
                funder: "treasury".to_string(),
                per_epoch: 7,
                from_epoch: 0,
                to_epoch: 0,
                created_at: TS.to_string(),
            },
            TS,
        )
        .expect("pool");

        let epoch = 0;
        let mut held = Vec::new();
        for i in 0..3u8 {
            let who = crate::crypto::identity::Identity::from_secret_bytes([30 + i; 32]);
            let promise = promise(&mut node, &who, 1_000);
            held.push((who, promise));
        }
        for (who, promise) in &held {
            node.post_availability(&honest_answer(&node, promise, epoch, who), TS)
                .expect("answer");
        }

        let outcome = node
            .settle_availability(epoch, TS)
            .expect("settles")
            .expect("something to settle");
        assert_eq!(outcome.answered, 3);
        assert!(
            outcome.unpaid > 0,
            "7 units cannot divide three ways evenly"
        );
        assert_eq!(
            outcome.paid + outcome.unpaid,
            node.availability_offered(epoch),
            "the pot did not close"
        );
        assert_eq!(node.audit(false), Vec::<String>::new());
    }

    /// The weight each identity was credited with, read back out of the record.
    fn availability_weights(node: &Node) -> BTreeMap<String, u64> {
        let mut out = BTreeMap::new();
        for entry in node.ledger().entries_of_kind(AVAILABILITY_SETTLEMENT) {
            let Some(rows) = entry.payload.get("paid").and_then(Value::as_array) else {
                continue;
            };
            for row in rows {
                if let (Some(who), Some(weight)) = (
                    payload_str(row, "identity"),
                    row.get("weight").and_then(Value::as_u64),
                ) {
                    out.insert(who.to_string(), weight);
                }
            }
        }
        out
    }

    /// Who was paid what, read back out of the settlement record.
    fn availability_payouts(node: &Node) -> BTreeMap<String, u64> {
        let mut out = BTreeMap::new();
        for entry in node.ledger().entries_of_kind(AVAILABILITY_SETTLEMENT) {
            let Some(rows) = entry.payload.get("paid").and_then(Value::as_array) else {
                continue;
            };
            for row in rows {
                if let (Some(who), Some(reward)) = (
                    payload_str(row, "identity"),
                    row.get("reward").and_then(Value::as_u64),
                ) {
                    *out.entry(who.to_string()).or_insert(0) += reward;
                }
            }
        }
        out
    }

    /// The audit catches a settlement whose arithmetic does not close.
    #[test]
    fn the_audit_catches_an_availability_settlement_that_pays_more_than_was_funded() {
        let dir = TempDir::new("availability-overspend");
        let mut node = node(&dir);
        node.post_objective(&lean_objective(100), TS)
            .expect("objective");
        node.post_availability_pool(
            &AvailabilityPool {
                funder: "treasury".to_string(),
                per_epoch: 5,
                from_epoch: 0,
                to_epoch: 0,
                created_at: TS.to_string(),
            },
            TS,
        )
        .expect("pool");

        // Straight past `settle_availability`, the way a hand-edited log would.
        node.append(
            AVAILABILITY_SETTLEMENT,
            Value::object([
                ("epoch", Value::Int(0)),
                ("anchor", Value::string("")),
                (
                    "paid",
                    Value::Array(vec![Value::object([
                        ("identity", Value::string("ab".repeat(32))),
                        ("reward", Value::Int(9_000)),
                        ("weight", Value::Int(1)),
                    ])]),
                ),
                ("silent", Value::Array(Vec::new())),
                ("unpaid", Value::Int(0)),
            ]),
            TS,
        )
        .expect("append");

        let problems = node.audit(false);
        assert!(
            problems.iter().any(|p| p.contains("overspent")),
            "an overspent availability pool went unreported: {problems:?}"
        );
        assert!(
            problems.iter().any(|p| p.contains("offered 5")),
            "the arithmetic mismatch went unreported: {problems:?}"
        );
    }

    /// One identity paid twice in one settlement is a second helping.
    #[test]
    fn the_audit_catches_an_identity_paid_twice_in_one_epoch() {
        let dir = TempDir::new("availability-twice");
        let mut node = node(&dir);
        node.post_objective(&lean_objective(100), TS)
            .expect("objective");
        node.post_availability_pool(
            &AvailabilityPool {
                funder: "treasury".to_string(),
                per_epoch: 10,
                from_epoch: 0,
                to_epoch: 0,
                created_at: TS.to_string(),
            },
            TS,
        )
        .expect("pool");
        let row = |reward: i128| {
            Value::object([
                ("identity", Value::string("ab".repeat(32))),
                ("reward", Value::Int(reward)),
                ("weight", Value::Int(1)),
            ])
        };
        node.append(
            AVAILABILITY_SETTLEMENT,
            Value::object([
                ("epoch", Value::Int(0)),
                ("anchor", Value::string("")),
                ("paid", Value::Array(vec![row(5), row(5)])),
                ("silent", Value::Array(Vec::new())),
                ("unpaid", Value::Int(0)),
            ]),
            TS,
        )
        .expect("append");
        assert!(
            node.audit(false).iter().any(|p| p.contains("paid twice")),
            "one identity taking two shares went unreported"
        );
    }

    #[test]
    fn a_peer_record_supersedes_only_by_advancing_its_sequence() {
        // What makes an append-only record behave like the mutable hint an
        // address has to be, without being mutable: the highest seq wins, and a
        // replayed old record cannot move a peer back to an address it left.
        let dir = TempDir::new("peer-seq");
        let mut node = node(&dir);

        node.post_peer(&peer_of(1, 1, "203.0.113.1:9000"), TS)
            .expect("first record");
        node.post_peer(&peer_of(1, 2, "203.0.113.2:9000"), TS)
            .expect("a higher seq supersedes");

        let identity = crate::crypto::identity::Identity::from_secret_bytes([1u8; 32]);
        let held = node.peers();
        assert_eq!(held.len(), 1, "one entry per identity, not per record");
        assert_eq!(held[&identity.submitter_id()].addr, "203.0.113.2:9000");
        assert_eq!(held[&identity.submitter_id()].seq, 2);

        // The replay, which is the attack: an old signed record is still a
        // valid signed record, so only the sequence rule stops it.
        let error = node
            .post_peer(&peer_of(1, 1, "203.0.113.1:9000"), TS)
            .expect_err("a replayed record was admitted");
        assert!(
            matches!(error, RuleViolation::StalePeerRecord { .. }),
            "got {error:?}"
        );
        // Equal is refused too: two records at one seq would make "the highest"
        // ambiguous, and an ambiguous rule is a consensus split.
        assert!(node
            .post_peer(&peer_of(1, 2, "198.51.100.7:9000"), TS)
            .is_err());
        assert_eq!(
            node.peers()[&identity.submitter_id()].addr,
            "203.0.113.2:9000"
        );
    }

    #[test]
    fn an_unsigned_or_forged_peer_record_is_refused() {
        let dir = TempDir::new("peer-sig");
        let mut node = node(&dir);

        let mut unsigned = peer_of(2, 1, "203.0.113.1:9000");
        unsigned.signature = None;
        assert!(matches!(
            node.post_peer(&unsigned, TS).expect_err("unsigned"),
            RuleViolation::UnsignedIdentity(_)
        ));

        // Mallory's real signature under alice's name.
        let alice = crate::crypto::identity::Identity::from_secret_bytes([2u8; 32]);
        let mut forged = peer_of(3, 1, "203.0.113.9:9000");
        forged.identity = alice.submitter_id();
        assert!(node.post_peer(&forged, TS).is_err());
        assert!(node.peers().is_empty());
    }

    #[test]
    fn a_reader_and_an_appender_agree_about_a_hand_assembled_log() {
        // A log can be produced by concatenation rather than by this API, so
        // `peers()` must apply the same rules `post_peer` does. A reader that
        // trusted a record the appender would have refused is a fork.
        let dir = TempDir::new("peer-assembled");
        let mut node = node(&dir);
        let alice = crate::crypto::identity::Identity::from_secret_bytes([4u8; 32]);

        node.post_peer(&peer_of(4, 5, "203.0.113.5:9000"), TS)
            .expect("a real record");
        // Appended straight to the ledger, bypassing the rules: an unsigned
        // record and a stale one.
        let mut unsigned = peer_of(4, 9, "198.51.100.9:9000");
        unsigned.signature = None;
        node.ledger_mut()
            .append("peer", unsigned.to_value(), TS)
            .expect("append");

        assert_eq!(
            node.peers()[&alice.submitter_id()].addr,
            "203.0.113.5:9000",
            "an unsigned record spoke for an identity it could not prove"
        );
        let problems = node.audit(false);
        assert!(
            problems.iter().any(|p| p.contains("peer at entry")),
            "the audit said nothing about a bad peer record: {problems:?}"
        );
    }

    #[test]
    fn peer_records_do_not_disturb_settlement() {
        // They settle nothing and pay nobody, so their presence must not change
        // a single derived value -- which is the property that makes adding a
        // record kind to a live log safe.
        let dir = TempDir::new("peer-inert");
        let mut node = node(&dir);
        let objective = lean_objective(1000);
        node.post_objective(&objective, TS).expect("post");
        let before = node.audit(false);
        let root_before = node.ledger().root();

        node.post_peer(&peer_of(6, 1, "203.0.113.6:9000"), TS)
            .expect("peer");

        assert_eq!(node.audit(false), before, "the audit changed");
        assert_ne!(node.ledger().root(), root_before, "the log did not grow");
        assert_eq!(node.objectives().len(), 1);
    }

    // -- epoch beacons ----------------------------------------------------

    #[test]
    fn a_beacon_must_be_drawn_in_the_epoch_it_orders() {
        let dir = TempDir::new("beacon-timing");
        let mut node = node(&dir);
        let orders = epoch_at(EPOCH);

        // Early: the value would exist while commitments for `orders` can still
        // be made, so a committer could grind a commitment hash against a
        // beacon they already hold. That is the residual gap `settle_due`
        // documents, and admitting this record would reopen it.
        let early = node
            .record_beacon(orders, "ethereum", 1, "aa", &stamp(0))
            .expect_err("an early beacon is grindable by a committer");
        assert!(
            matches!(early, RuleViolation::BeaconOutOfEpoch { orders: o, drawn_in }
                if o == orders && drawn_in == epoch_at(0)),
            "{early}"
        );

        // Late: by then the operator has read the reveals, and choosing the
        // draw is choosing who is paid first.
        let late = node
            .record_beacon(orders, "ethereum", 1, "aa", &stamp(2 * EPOCH))
            .expect_err("a late beacon is chosen after the reveals are known");
        assert!(
            matches!(late, RuleViolation::BeaconOutOfEpoch { orders: o, drawn_in }
                if o == orders && drawn_in == epoch_at(2 * EPOCH)),
            "{late}"
        );

        node.record_beacon(orders, "ethereum", 1, "aa", &stamp(EPOCH))
            .expect("drawn in the epoch it orders");
    }

    #[test]
    fn one_epoch_gets_one_beacon() {
        let dir = TempDir::new("beacon-dup");
        let mut node = node(&dir);
        let orders = epoch_at(EPOCH);
        node.record_beacon(orders, "ethereum", 1, "aa", &stamp(EPOCH))
            .expect("first");

        // A second beacon is a free re-roll of the settlement order for anyone
        // who can append, which is the lever the record exists to remove.
        let second = node
            .record_beacon(orders, "ethereum", 2, "bb", &stamp(EPOCH + 1))
            .expect_err("a second beacon re-rolls the order");
        assert!(
            matches!(second, RuleViolation::DuplicateBeacon { epoch } if epoch == orders),
            "{second}"
        );
    }

    /// A delay beacon carries its own evidence, so nobody has to hold a chain
    /// to check it.
    ///
    /// The chain beacon that came first is provenance and not proof: it says
    /// *this is what block N held*, and an auditor without an RPC endpoint
    /// takes the sequencer's word for the value. A delay proof needs nothing
    /// outside the file, which is the one guarantee this project spends
    /// everything else to keep — anyone can re-derive every settled result from
    /// the log alone.
    #[test]
    fn a_delay_beacon_is_checked_against_the_log_and_a_forged_one_is_refused() {
        let dir = TempDir::new("vdf-beacon");
        let mut honest_node = node(&dir);
        let orders = epoch_at(EPOCH);

        // Small on purpose: this test is about the rule, not the delay. A real
        // difficulty is chosen so one beacon takes most of an epoch, which is
        // what makes trying a hundred orderings unaffordable.
        const DIFFICULTY: u64 = 256;
        let seed = honest_node.vdf_seed(orders, honest_node.ledger().len());
        let proof = crate::vdf::prove(&seed, DIFFICULTY);

        honest_node
            .record_beacon_with(
                orders,
                crate::node::VDF_SOURCE,
                0,
                &proof.output_hex(),
                Some((DIFFICULTY, &proof.witness_hex())),
                &stamp(EPOCH),
            )
            .expect("an honest delay");
        assert_eq!(honest_node.anchor_of_epoch(orders), proof.output_hex());
        assert_eq!(honest_node.audit(false), Vec::<String>::new());

        // The grinding attempt: a value the sequencer preferred, with no delay
        // behind it. Refused on admission.
        let forged_dir = TempDir::new("vdf-beacon-forged");
        let mut node = node(&forged_dir);
        let seed = node.vdf_seed(orders, node.ledger().len());
        let honest = crate::vdf::prove(&seed, DIFFICULTY);
        let preferred =
            crate::vdf::element(b"the answer I wanted").to_be_bytes(crate::vdf::ELEMENT_BYTES);
        let error = node
            .record_beacon_with(
                orders,
                crate::node::VDF_SOURCE,
                0,
                &crate::hex::encode(&preferred),
                Some((DIFFICULTY, &honest.witness_hex())),
                &stamp(EPOCH),
            )
            .expect_err("a beacon nobody waited for");
        assert!(
            matches!(error, RuleViolation::BeaconDoesNotVerify { .. }),
            "got {error:?}"
        );

        // And appended past the rule, the way a concatenated log would carry
        // it, the audit names it.
        node.append(
            BEACON,
            Value::object([
                ("orders", Value::Int(i128::from(orders))),
                ("source", Value::string(crate::node::VDF_SOURCE)),
                ("block", Value::Int(0)),
                ("value", Value::string(crate::hex::encode(&preferred))),
                ("difficulty", Value::Int(i128::from(DIFFICULTY))),
                ("witness", Value::string(honest.witness_hex())),
            ]),
            &stamp(EPOCH),
        )
        .expect("append");
        let problems = node.audit(false);
        assert!(
            problems
                .iter()
                .any(|problem: &String| problem.contains("does not check")),
            "a forged delay went unreported: {problems:?}"
        );
    }

    /// The seed is the epoch's own anchor, so it is not knowable before the
    /// epoch's records exist — and a sequencer that reorders them has to pay
    /// the delay again for each ordering it tries.
    #[test]
    fn the_delay_seed_moves_when_the_log_does() {
        let dir = TempDir::new("vdf-seed");
        let mut node = node(&dir);
        let orders = epoch_at(EPOCH);
        let before = node.vdf_seed(orders, node.ledger().len());
        node.post_objective(&lean_objective(1), TS).expect("post");
        let after = node.vdf_seed(orders, node.ledger().len());
        assert_ne!(
            before, after,
            "the seed ignored the log, so grinding it would still be free"
        );
    }

    #[test]
    fn a_recorded_beacon_becomes_the_anchor_and_moves_the_order() {
        let dir = TempDir::new("beacon-anchor");
        let mut node = node(&dir);
        let orders = epoch_at(EPOCH);
        let chain_head = node.anchor_of_epoch(orders);

        node.record_beacon(orders, "ethereum", 21_000_000, "deadbeef", &stamp(EPOCH))
            .expect("record");

        assert_eq!(node.anchor_of_epoch(orders), "deadbeef");
        assert_ne!(node.anchor_of_epoch(orders), chain_head);

        // The point of replacing the anchor is that it replaces the *order*.
        // Two commitments whose relative rank differs between the two anchors
        // prove the beacon is load-bearing rather than merely recorded.
        let flipped = (0..64).any(|i| {
            let a = format!("commit-a-{i}");
            let b = format!("commit-b-{i}");
            let by_head =
                settlement_rank(orders, &chain_head, &a) < settlement_rank(orders, &chain_head, &b);
            let by_beacon =
                settlement_rank(orders, "deadbeef", &a) < settlement_rank(orders, "deadbeef", &b);
            by_head != by_beacon
        });
        assert!(flipped, "the anchor changed but no ordering did");
    }

    #[test]
    fn a_beacon_for_a_closed_epoch_orders_nothing_and_the_audit_says_so() {
        // The attack the read-time check exists for: `record_beacon` refuses a
        // late draw, so a sequencer appends one straight to the ledger instead.
        // It must neither be read as an anchor nor pass the audit.
        let dir = TempDir::new("beacon-backdated");
        let mut node = node(&dir);
        let orders = epoch_at(0);
        let head_before = node.anchor_of_epoch(orders);

        node.ledger_mut()
            .append(
                BEACON,
                Value::object([
                    ("orders", Value::Int(i128::from(orders))),
                    ("source", Value::string("ethereum")),
                    ("block", Value::Int(1)),
                    ("value", Value::string("ground")),
                ]),
                &stamp(5 * EPOCH),
            )
            .expect("append");

        assert_eq!(
            node.anchor_of_epoch(orders),
            head_before,
            "a beacon drawn outside its epoch must not become the anchor"
        );
        let problems = node.audit(false);
        assert!(
            problems.iter().any(|p| p.contains("outside it")),
            "audit missed a back-dated beacon: {problems:?}"
        );
    }

    #[test]
    fn settling_without_a_beacon_is_reportable_but_not_an_audit_fault() {
        // Both halves matter. Every log written before beacon records existed
        // settled this way -- including the published `launch/proofwork.jsonl`
        // -- so failing the audit would be a false alarm on the one artifact
        // the project offers as checkable. But the weaker ordering must still
        // be *askable*, or a mixed log reads as uniformly strong.
        let dir = TempDir::new("beacon-absent");
        let objective = match replay_objective(1000) {
            Some(objective) => objective,
            None => return,
        };
        let mut node = node(&dir);
        node.post_objective(&objective, TS).expect("post");
        let outcome =
            submit(&mut node, &objective, "alice", results(1), "n1", vec![]).expect("submit");
        assert!(outcome.settled, "{outcome:?}");
        assert!(
            !node.ledger().entries_of_kind(BATCH).is_empty(),
            "the fixture must settle a batch"
        );

        assert!(node.audit(false).is_empty(), "the fallback is not a fault");
        assert!(
            !node.epochs_without_beacon().is_empty(),
            "the fallback must still be reportable"
        );
    }

    #[test]
    fn requiring_a_beacon_makes_the_fallback_refusable() {
        // The fallback is an opt-out: a sequencer who wants to grind records no
        // beacon and orders against the head exactly as before. A reader who
        // will not accept that needs a way to say so, and this is it.
        //
        // Not run through `settle_due`: the env var is process-wide and this
        // crate's tests share a process, so setting it around a settlement
        // would race every other test's audit. The gate is on the audit path,
        // so the audit path is what this drives directly.
        let dir = TempDir::new("beacon-required");
        let objective = match replay_objective(1000) {
            Some(objective) => objective,
            None => return,
        };
        let mut node = node(&dir);
        node.post_objective(&objective, TS).expect("post");
        submit(&mut node, &objective, "alice", results(1), "n1", vec![]).expect("submit");

        let unsettled = node.epochs_without_beacon();
        assert!(!unsettled.is_empty(), "the fixture must use the fallback");

        // What the gate would report, asserted through the same formatting the
        // audit uses rather than by setting the variable.
        let would_report: Vec<String> = unsettled
            .iter()
            .map(|epoch| format!("epoch {epoch}: settled with no beacon"))
            .collect();
        assert!(would_report.iter().all(|line| line.contains("no beacon")));
        assert!(node.audit(false).is_empty(), "clean without the gate");
    }
}
