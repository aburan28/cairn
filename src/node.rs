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
//! # Differences from the Python reference
//!
//! The reference implementation raises on a malformed record: `objectives()`
//! calls `Objective.from_dict` and lets the exception out. Here the accessors
//! return plain collections, so an entry this version cannot decode is **skipped
//! by the readers and reported by [`Node::audit`]** rather than taking the
//! process down. Skipping is the safe direction for every accessor that feeds a
//! rule: an objective that cannot be decoded is not found, so submissions
//! against it are refused rather than admitted on a partially understood record.
//!
//! The one place where "skip it" would be *unsafe* is the frontier, because a
//! missing frontier means no citation is required and the payout curve restarts
//! from zero -- a malformed entry would be worth money. [`Node::reveal`]
//! therefore uses the strict internal reader, which refuses the submission
//! instead; only the informational [`Node::frontier_of`] softens it to `None`.
//!
//! Money arithmetic that Python does in bignums is checked here: `payout` and
//! the running `paid_cumulative` return errors on overflow rather than wrapping,
//! because a wrapped payout is an invented or destroyed unit of account.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};

use crate::blobs;
use crate::canonical::{short, Value};
use crate::frontier::{FrontierEntry, Ratchet, RatchetError};
use crate::ledger::{Ledger, LedgerError};
use crate::partition::{epoch_of, epoch_seconds, settlement_rank};
use crate::records::{Claim, Commitment, Objective};
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
    /// The record could not be appended to the log.
    Ledger(LedgerError),
}

impl fmt::Display for RuleViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
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
            RuleViolation::Ledger(source) => write!(f, "cannot record: {source}"),
        }
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

/// What a reveal did.
///
/// `settled == false` is not an error and not a rejection: a verdict that could
/// not be reached, a duplicate artifact, and an improvement that does not move
/// the frontier all land here with `reward == 0` and a `note` naming the reason.
/// The claim and its verdict are in the log either way.
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
            note: format!("accepted; settles when epoch {epoch} closes"),
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

    /// The current best-known score for a progressive objective.
    ///
    /// `None` also when the latest frontier entry cannot be decoded, which is
    /// safe *here* because this accessor is informational. The rules path uses
    /// [`Node::latest_frontier`] instead, which refuses rather than reporting an
    /// empty frontier -- treating an unreadable entry as absent would waive the
    /// citation requirement and restart the payout curve at zero.
    pub fn frontier_of(&self, objective_id: &str) -> Option<FrontierEntry> {
        self.latest_frontier(objective_id).ok().flatten()
    }

    // -- commit / reveal --------------------------------------------------

    /// Phase 1: bind to an artifact without revealing it.
    ///
    /// A non-ratchet objective stops accepting commitments once it has settled.
    /// A **progressive** objective does not: it stays open until its pool is
    /// exhausted, because the whole point is that improvements keep arriving.
    pub fn commit(&mut self, commitment: &Commitment, ts: &str) -> Result<String, RuleViolation> {
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
        if objective.ratchet.is_none() && self.settlement_of(&commitment.objective_id).is_some() {
            return Err(RuleViolation::AlreadySettled {
                objective_id: commitment.objective_id.clone(),
            });
        }
        self.append(COMMITMENT, commitment.to_value(), ts)?;
        Ok(commitment.id())
    }

    /// Claims whose verdict was `accept`, keyed by claim id.
    ///
    /// A verdict record that cannot be read as a verdict does not count as an
    /// acceptance -- the failure direction that refuses a citation rather than
    /// admitting one.
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
    /// An accepted claim comes back [`Outcome::pending`], not settled. That is
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

    /// Closed reveal epochs with accepted claims that no `batch` record covers.
    fn due_epochs(&self, now_epoch: u64) -> Vec<u64> {
        let drained = self.drained_epochs();
        let mut due: BTreeSet<u64> = BTreeSet::new();
        for (epoch, _) in self.accepted_claims_by_epoch() {
            if epoch < now_epoch && !drained.contains(&epoch) {
                due.insert(epoch);
            }
        }
        due.into_iter().collect()
    }

    /// The log head as of the start of `epoch`: the hash of the last entry
    /// stamped in an earlier epoch, or the empty string when there is none.
    ///
    /// Derived from the log rather than from a clock, so an auditor reaches the
    /// same value. It is also recorded in the `batch` entry, because a
    /// back-dated append after the fact could otherwise change what this
    /// function returns for an epoch that already settled -- [`Node::audit`]
    /// compares the two and reports a divergence.
    fn anchor_of_epoch(&self, epoch: u64) -> String {
        let mut anchor = String::new();
        for entry in self.ledger.entries() {
            match crate::time::parse_rfc3339(&entry.ts) {
                Some(seconds) if seconds >= 0 => {
                    if epoch_of(seconds as u64, epoch_seconds()) < epoch {
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
        self.accepted_claims_by_epoch()
            .into_iter()
            .filter(|(candidate, _)| *candidate == epoch)
            .map(|(_, pair)| pair)
            .collect()
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
                if paid.contains(claim_id.as_str()) {
                    problems.push(format!(
                        "claim {claim_id}: was settled but can no longer be re-verified \
                         ({}: {})",
                        fresh.status, fresh.detail
                    ));
                }
                continue;
            }
            let was = status_of(recorded_verdict).unwrap_or("(unreadable)");
            if fresh.status.as_str() != was {
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

        problems
    }

    /// Re-derive every settlement batch's ordering from the log.
    ///
    /// This is the check that makes beacon ordering worth having. The rule
    /// itself constrains an honest node; only an auditor recomputing
    /// `H(beacon(epoch, anchor) ‖ commitment_hash)` over the epoch's accepted
    /// claims constrains a dishonest one. Three ways a batch can be wrong, and
    /// all three are somebody being paid out of turn:
    ///
    /// - the recorded anchor is not the log head at the epoch's start, which is
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
            let derived_anchor = self.anchor_of_epoch(epoch);
            if recorded_anchor != derived_anchor {
                problems.push(format!(
                    "batch for epoch {epoch}: anchor {} is not the log head at the \
                     epoch's start ({})",
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

            // Recomputed against the *recorded* anchor: if that anchor is
            // wrong the line above already says so, and re-deriving the order
            // from a different anchor would report the same fault twice under
            // two names.
            let mut ranked: Vec<(String, String)> = self
                .accepted_in_epoch(epoch)
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

fn payload_str<'a>(payload: &'a Value, key: &str) -> Option<&'a str> {
    payload.get(key).and_then(Value::as_str)
}

/// Which epoch an RFC-3339 instant falls in.
///
/// Pre-1970 instants are refused along with unparsable ones. Epochs are `u64`
/// because they key a beacon, and there is no sensible epoch number for a
/// record dated before the Unix epoch -- a record this network could not have
/// produced.
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

    /// Commit, then reveal, then close the batch -- the way an honest submitter
    /// and an honest operator do it between them.
    ///
    /// Three epochs, not one, and they cannot be collapsed: a reveal must be in
    /// a strictly later epoch than its commitment, and a batch settles only
    /// once its epoch is over. The offsets come off the ledger length so that
    /// successive submissions land in successive epochs -- an epoch whose batch
    /// has already been paid refuses further reveals, which is the point.
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
        let step = node.ledger().len() as i64 * 4 * EPOCH;
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
        let settled = node.settle_at(&stamp(step + 2 * EPOCH))?;
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
        let binary = echo()?;
        Some(
            Objective::new(
                "G",
                "reproduce n",
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

        let batch = node.settle_at(&stamp(2 * EPOCH)).expect("settle");
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
        node.settle_at(&stamp(2 * EPOCH)).expect("settle");

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
}
