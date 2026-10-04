//! The validator loop: re-verify what this node holds, and stand behind
//! what it finds.
//!
//! `docs/bonded-verification.md` built the record and the bond and then
//! stopped: "nothing requires an attestation", and the only way to post one
//! was `cairn attest stand`, by hand, one claim at a time. So a node that
//! declared itself a verifier (`CAIRN_ROLES=verifier`) had a role and no
//! duty. This module is the duty: every tick, take the claims this identity
//! has not stood behind, run each one's pinned verifier *here*, and post an
//! attestation saying what this node found -- under this identity's
//! signature and bond, so a wrong one has somebody to slash.
//!
//! # What it attests, and what it will not
//!
//! It attests what the verifier returned **on this node**, never what the
//! log already says. The log's recorded verdict is the admitting node's;
//! this is a second machine's. Where the two disagree the loop says so out
//! loud and still posts what it found, because an attestation that copied
//! the record would be the rubber-stamper the canary docket exists to catch.
//!
//! It never attests a verdict that does not settle. `Unavailable` and
//! `InvalidSpec` blame this node or the objective, not the artifact, and
//! [`crate::records::Attestation::validate`] refuses them anyway. A claim
//! whose verifier could not run here is set aside and tried again later --
//! a toolchain may be installed, a blob may arrive -- and is counted as
//! `unavailable` in the tick's outcome, which is a fact about the host.
//!
//! # Why it lives in the daemon's tick and not in a route
//!
//! An attestation is a record, and a record is appended by whoever holds
//! the log's write lock, which is the daemon. `POST /submit` takes
//! objectives, commitments and claims and nothing else, and the p2p layer
//! does not exchange attestations at all, so a validator cannot be a
//! stranger posting over HTTP: it is a node, with the log, holding the
//! lock. `cairn attest serve` is the same loop for a validator that runs no
//! daemon -- a log that arrives by `cairn lab`, by bundle, or by a sync the
//! operator runs between passes -- and takes the lock for exactly one pass.
//!
//! # Bounds
//!
//! At most [`Attestor::limit_per_tick`] verifiers run per tick, newest
//! claims first, so a node that joins a long log does not spend an hour in
//! one lock hold. A bond is staked per attestation, so on a log that
//! declares a supply the loop stops the moment the identity cannot cover
//! one more and says so; it does not grind through refusals.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::canonical::Value;
use crate::crypto::identity::Identity;
use crate::node::{Node, RuleViolation};
use crate::records::Attestation;
use crate::verifiers::Status;

/// Verifier runs per tick, by default. Eight is a few seconds of pinned
/// Python under the lock; a Lean proof is slower and an operator with many
/// of them lowers this.
pub const DEFAULT_LIMIT_PER_TICK: usize = 8;

/// Ticks before a claim whose verifier was unavailable here is tried again.
/// The daemon ticks every five seconds, so this is ten minutes.
pub const DEFAULT_RETRY_AFTER_TICKS: u64 = 120;

/// `CAIRN_ATTEST_IDENTITY`: the signing identity the daemon attests under.
/// Set, the daemon runs the loop; unset, it does not.
pub const IDENTITY_ENV: &str = "CAIRN_ATTEST_IDENTITY";
/// `CAIRN_ATTEST_LIMIT`: verifier runs per tick.
pub const LIMIT_ENV: &str = "CAIRN_ATTEST_LIMIT";

/// What happened to one claim in one tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub claim_id: String,
    /// What this node's verifier returned.
    pub found: Status,
    /// What the log had recorded, if a verdict was recorded.
    pub recorded: Option<Status>,
    /// The attestation posted, when one was.
    pub attestation_id: Option<String>,
    /// Why none was posted, when none was.
    pub refusal: Option<String>,
    pub detail: String,
}

impl Outcome {
    /// Posted, and contradicting the admitting node's verdict.
    pub fn disagrees(&self) -> bool {
        matches!(self.recorded, Some(recorded) if recorded.settles() && recorded != self.found)
    }

    pub fn posted(&self) -> bool {
        self.attestation_id.is_some()
    }

    pub fn to_value(&self) -> Value {
        let opt = |value: &Option<String>| match value {
            Some(s) => Value::string(s.clone()),
            None => Value::Null,
        };
        Value::object([
            ("claim_id", Value::string(self.claim_id.clone())),
            ("found", Value::string(self.found.as_str())),
            (
                "recorded",
                match self.recorded {
                    Some(status) => Value::string(status.as_str()),
                    None => Value::Null,
                },
            ),
            ("attestation_id", opt(&self.attestation_id)),
            ("refusal", opt(&self.refusal)),
            ("disagrees", Value::Bool(self.disagrees())),
            ("detail", Value::string(self.detail.clone())),
        ])
    }
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let claim = crate::canonical::short(&self.claim_id);
        match (&self.attestation_id, &self.refusal) {
            (Some(id), _) if self.disagrees() => write!(
                f,
                "claim {claim}: attested {} as {} -- the log recorded {}; a disagreement a \
                 docket should look at ({})",
                crate::canonical::short(id),
                self.found.as_str(),
                self.recorded.map(|s| s.as_str()).unwrap_or("nothing"),
                self.detail
            ),
            (Some(id), _) => write!(
                f,
                "claim {claim}: attested {} as {}",
                crate::canonical::short(id),
                self.found.as_str()
            ),
            (None, Some(why)) => write!(
                f,
                "claim {claim}: verifier found {}, not attested: {why}",
                self.found.as_str()
            ),
            (None, None) => write!(
                f,
                "claim {claim}: {} ({})",
                self.found.as_str(),
                self.detail
            ),
        }
    }
}

/// One tick's tally, for a log line.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tally {
    pub considered: usize,
    pub posted: usize,
    pub unavailable: usize,
    pub refused: usize,
    pub disagreements: usize,
    /// The identity could not cover another bond; the tick stopped early.
    pub stopped_for_bond: bool,
}

impl fmt::Display for Tally {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} considered, {} attested, {} unavailable here, {} refused, {} disagreement(s)",
            self.considered, self.posted, self.unavailable, self.refused, self.disagreements
        )?;
        if self.stopped_for_bond {
            write!(f, "; stopped: cannot cover another bond")?;
        }
        Ok(())
    }
}

/// The loop's state across ticks.
pub struct Attestor {
    identity: Identity,
    pub limit_per_tick: usize,
    pub retry_after_ticks: u64,
    /// Claims whose verifier did not settle here, with the tick it was tried.
    unavailable_at: BTreeMap<String, u64>,
    /// Claims refused by a rule other than affordability. A duplicate or an
    /// unknown claim will not become admissible by waiting.
    refused: BTreeSet<String>,
    ticks: u64,
}

impl Attestor {
    pub fn new(identity: Identity) -> Attestor {
        Attestor {
            identity,
            limit_per_tick: DEFAULT_LIMIT_PER_TICK,
            retry_after_ticks: DEFAULT_RETRY_AFTER_TICKS,
            unavailable_at: BTreeMap::new(),
            refused: BTreeSet::new(),
            ticks: 0,
        }
    }

    /// The hex public key attestations are posted under.
    pub fn attestor_id(&self) -> String {
        self.identity.submitter_id()
    }

    /// Claims this identity has not stood behind, newest first, minus the
    /// ones set aside. Every claim in the log is eligible, with or without
    /// a recorded verdict: a claim the admitting node could not check is
    /// exactly one a validator with the toolchain should.
    pub fn candidates(&self, node: &Node) -> Vec<String> {
        let mine: BTreeSet<String> = node
            .attestations()
            .values()
            .filter(|attestation| attestation.attestor == self.attestor_id())
            .map(|attestation| attestation.claim_id.clone())
            .collect();
        let mut claims: Vec<(String, String)> = node
            .all_claims()
            .into_iter()
            .filter(|(id, _)| !mine.contains(id) && !self.refused.contains(id))
            .filter(|(id, _)| match self.unavailable_at.get(id) {
                Some(tried) => self.ticks.saturating_sub(*tried) >= self.retry_after_ticks,
                None => true,
            })
            .map(|(id, claim)| (claim.created_at, id))
            .collect();
        // Newest first; ties by id so two nodes order the same log the same way.
        claims.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
        claims.into_iter().map(|(_, id)| id).collect()
    }

    /// One pass: run up to `limit_per_tick` verifiers and post what settles.
    /// `ts` is the timestamp every attestation is created at and admitted
    /// at, which the admission rule requires to fall in one epoch.
    pub fn tick(&mut self, node: &mut Node, ts: &str) -> (Tally, Vec<Outcome>) {
        self.ticks = self.ticks.wrapping_add(1);
        let mut tally = Tally::default();
        let mut outcomes = Vec::new();
        let candidates = self.candidates(node);
        if candidates.is_empty() {
            return (tally, outcomes);
        }
        let claims = node.all_claims();
        let objectives = node.objectives();
        let recorded: BTreeMap<String, Status> = node
            .recorded_verdicts()
            .into_iter()
            .map(|verdict| (verdict.claim_id, verdict.status))
            .collect();
        for claim_id in candidates.into_iter().take(self.limit_per_tick) {
            let Some(claim) = claims.get(&claim_id) else {
                continue;
            };
            let Some(objective) = objectives.get(&claim.objective_id) else {
                // A claim whose objective is missing is one the log could
                // not have admitted; nothing to stand behind.
                self.refused.insert(claim_id);
                continue;
            };
            tally.considered += 1;
            let verdict = node.registry().run(&objective.verifier, &claim.artifact);
            let recorded_status = recorded.get(&claim_id).copied();
            if !verdict.status.settles() {
                tally.unavailable += 1;
                self.unavailable_at.insert(claim_id.clone(), self.ticks);
                outcomes.push(Outcome {
                    claim_id,
                    found: verdict.status,
                    recorded: recorded_status,
                    attestation_id: None,
                    refusal: None,
                    detail: verdict.detail,
                });
                continue;
            }
            let record = Attestation::new(
                claim_id.clone(),
                self.attestor_id(),
                verdict.status.as_str(),
                ts,
            )
            .signed_with(&self.identity);
            match node.post_attestation(&record, ts) {
                Ok(id) => {
                    tally.posted += 1;
                    let outcome = Outcome {
                        claim_id,
                        found: verdict.status,
                        recorded: recorded_status,
                        attestation_id: Some(id),
                        refusal: None,
                        detail: verdict.detail,
                    };
                    if outcome.disagrees() {
                        tally.disagreements += 1;
                    }
                    outcomes.push(outcome);
                }
                Err(violation) => {
                    tally.refused += 1;
                    let bond = is_bond_refusal(&violation);
                    if !bond {
                        self.refused.insert(claim_id.clone());
                    }
                    outcomes.push(Outcome {
                        claim_id,
                        found: verdict.status,
                        recorded: recorded_status,
                        attestation_id: None,
                        refusal: Some(violation.to_string()),
                        detail: verdict.detail,
                    });
                    if bond {
                        // Every later one costs the same bond; grinding on
                        // would be `refused` lines until the balance moves.
                        tally.stopped_for_bond = true;
                        break;
                    }
                }
            }
        }
        (tally, outcomes)
    }
}

/// Whether a refusal is about the bond rather than the record: the identity
/// cannot cover another stake. Every later attestation this pass would be
/// refused the same way, so the pass stops; the claim stays a candidate.
fn is_bond_refusal(violation: &RuleViolation) -> bool {
    matches!(
        violation,
        RuleViolation::UnfundedReward { .. } | RuleViolation::UnfundedInTier { .. }
    )
}
