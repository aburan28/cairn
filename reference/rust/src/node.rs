//! The rules: what may be posted, what settles, and what mints nothing.
//!
//! Ported from the protocol's behaviour, not from the primary implementation's
//! source. Where the two disagree, one of them is wrong and the disagreement
//! is the finding -- that is the entire reason this crate exists.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::canonical::{short, Value};
use crate::frontier::Ratchet;
use crate::ledger::Ledger;
use crate::partition::{epoch_of, epoch_seconds, settlement_rank};
use crate::records::{signed_submitter, Claim, Commitment, Objective, PeerRecord};
use crate::time::{timestamp, unix_seconds};
use crate::verifiers::{self, Status, Verdict};

pub const OBJECTIVE: &str = "objective";
pub const COMMITMENT: &str = "commitment";
pub const CLAIM: &str = "claim";
pub const VERDICT: &str = "verdict";
pub const SETTLEMENT: &str = "settlement";
pub const FRONTIER: &str = "frontier";
pub const BATCH: &str = "batch";
pub const PEER: &str = "peer";

#[derive(Debug, Clone)]
pub struct Outcome {
    pub claim_id: String,
    pub verdict: Verdict,
    pub settled: bool,
    pub reward: u64,
    pub note: String,
    pub pending_epoch: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct FrontierEntry {
    pub objective_id: String,
    pub claim_id: String,
    pub holder: String,
    pub score: i64,
    pub paid_cumulative: u64,
}

impl FrontierEntry {
    fn to_value(&self) -> Value {
        Value::object([
            ("objective_id", Value::string(self.objective_id.clone())),
            ("claim_id", Value::string(self.claim_id.clone())),
            ("holder", Value::string(self.holder.clone())),
            ("score", Value::Int(i128::from(self.score))),
            (
                "paid_cumulative",
                Value::Int(i128::from(self.paid_cumulative)),
            ),
        ])
    }

    fn from_value(value: &Value) -> Option<FrontierEntry> {
        Some(FrontierEntry {
            objective_id: value.get("objective_id")?.as_str()?.to_string(),
            claim_id: value.get("claim_id")?.as_str()?.to_string(),
            holder: value.get("holder")?.as_str()?.to_string(),
            score: value.get("score")?.as_i64()?,
            paid_cumulative: value.get("paid_cumulative")?.as_u64()?,
        })
    }
}

pub struct Node {
    pub ledger: Ledger,
    root: PathBuf,
}

impl Node {
    pub fn new(ledger: Ledger, root: impl Into<PathBuf>) -> Node {
        Node {
            ledger,
            root: root.into(),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn epoch_of_ts(&self, record: &str, ts: &str) -> Result<u64, String> {
        unix_seconds(ts)
            .map(|seconds| epoch_of(seconds, epoch_seconds()))
            // Refused, never defaulted: a record whose epoch is unknown cannot
            // be placed in a batch, and "treat it as now" would hand a
            // submitter a free choice of batch by writing garbage.
            .ok_or_else(|| {
                format!("{record} timestamp {ts:?} is not an RFC-3339 instant, so the epoch it settles in cannot be derived")
            })
    }

    // -- reads -----------------------------------------------------------

    pub fn objectives(&self) -> BTreeMap<String, Objective> {
        let mut out = BTreeMap::new();
        for entry in self.ledger.entries_of_kind(OBJECTIVE) {
            if let Ok(objective) = Objective::from_value(&entry.payload) {
                out.insert(objective.id(), objective);
            }
        }
        out
    }

    pub fn settlement_of(&self, objective_id: &str) -> Option<&Value> {
        self.ledger
            .entries_of_kind(SETTLEMENT)
            .into_iter()
            .find(|entry| {
                entry.payload.get("objective_id").and_then(Value::as_str) == Some(objective_id)
            })
            .map(|entry| &entry.payload)
    }

    pub fn frontier_of(&self, objective_id: &str) -> Option<FrontierEntry> {
        // The *last* frontier entry wins: the log records every advance, and
        // the current holder is whoever moved it most recently.
        self.ledger
            .entries_of_kind(FRONTIER)
            .into_iter()
            .rfind(|entry| {
                entry.payload.get("objective_id").and_then(Value::as_str) == Some(objective_id)
            })
            .and_then(|entry| FrontierEntry::from_value(&entry.payload))
    }

    /// Claims whose recorded verdict is `accept`.
    pub fn accepted_claims(&self) -> BTreeMap<String, Claim> {
        let accepted: BTreeSet<String> = self
            .ledger
            .entries_of_kind(VERDICT)
            .into_iter()
            .filter(|entry| {
                entry
                    .payload
                    .get("verdict")
                    .and_then(|v| v.get("status"))
                    .and_then(Value::as_str)
                    == Some("accept")
            })
            .filter_map(|entry| {
                entry
                    .payload
                    .get("claim_id")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .collect();
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

    fn drained_epochs(&self) -> BTreeSet<u64> {
        self.ledger
            .entries_of_kind(BATCH)
            .into_iter()
            .filter_map(|entry| entry.payload.get("epoch").and_then(Value::as_u64))
            .collect()
    }

    /// The log head as of the epoch's *start*.
    ///
    /// Derived from the log rather than a clock, so an auditor reaches the
    /// same value. `positions` bounds the scan to the log as it stood at a
    /// given length, which is what stops a later back-dated append changing
    /// the anchor of a batch that already settled.
    fn anchor_of_epoch(&self, epoch: u64, positions: Option<usize>) -> String {
        let mut anchor = String::new();
        let entries = self.ledger.entries();
        let entries = match positions {
            Some(limit) => &entries[..limit.min(entries.len())],
            None => entries,
        };
        for entry in entries {
            // An entry this node cannot place in time is not evidence about
            // where the boundary was, so it does not move the anchor.
            if let Some(seconds) = unix_seconds(&entry.ts) {
                if epoch_of(seconds, epoch_seconds()) < epoch {
                    anchor = entry.hash.clone();
                }
            }
        }
        anchor
    }

    fn accepted_claims_by_epoch(&self) -> Vec<(u64, Claim)> {
        self.accepted_claims_by_epoch_within(None)
    }

    /// The same, as the log stood at `positions` entries.
    ///
    /// `None` means the whole log, which is what settling wants -- it is
    /// deciding what to pay *now*. Auditing a batch wants the bound, because a
    /// record appended after the batch could not have influenced it whatever
    /// timestamp it carries.
    fn accepted_claims_by_epoch_within(&self, positions: Option<usize>) -> Vec<(u64, Claim)> {
        let entries = self.ledger.entries();
        let entries = match positions {
            Some(limit) => &entries[..limit.min(entries.len())],
            None => entries,
        };

        // The verdicts carry the bound too, not only the claims. A claim
        // already in the log when a batch was written, whose accepting verdict
        // arrived afterwards, was correctly left out of that batch -- counting
        // it now faults an honest batch exactly as a back-dated claim would.
        let mut accepted: BTreeSet<String> = BTreeSet::new();
        for entry in entries.iter().filter(|entry| entry.kind == VERDICT) {
            let Some(claim_id) = entry.payload.get("claim_id").and_then(Value::as_str) else {
                continue;
            };
            let is_accept = entry
                .payload
                .get("verdict")
                .and_then(|v| v.get("status"))
                .and_then(Value::as_str)
                == Some("accept");
            if is_accept {
                accepted.insert(claim_id.to_string());
            } else {
                // A later verdict supersedes an earlier one, a withdrawal of
                // acceptance included.
                accepted.remove(claim_id);
            }
        }

        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut out = Vec::new();
        for entry in entries.iter().filter(|entry| entry.kind == CLAIM) {
            let Ok(claim) = Claim::from_value(&entry.payload) else {
                continue;
            };
            let id = claim.id();
            if !accepted.contains(&id) || !seen.insert(id) {
                continue;
            }
            let Some(seconds) = unix_seconds(&entry.ts) else {
                continue;
            };
            out.push((epoch_of(seconds, epoch_seconds()), claim));
        }
        out
    }

    fn artifact_ids_before(&self, objective_id: &str, epoch: u64) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for entry in self.ledger.entries_of_kind(CLAIM) {
            let Some(seconds) = unix_seconds(&entry.ts) else {
                continue;
            };
            if epoch_of(seconds, epoch_seconds()) >= epoch {
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

    fn matching_commitment(&self, claim: &Claim) -> Option<Value> {
        let target = claim.commitment_hash();
        self.ledger
            .entries_of_kind(COMMITMENT)
            .into_iter()
            .find(|entry| {
                let payload = &entry.payload;
                payload.get("objective_id").and_then(Value::as_str) == Some(&claim.objective_id)
                    && payload.get("submitter").and_then(Value::as_str) == Some(&claim.submitter)
                    && payload.get("hash").and_then(Value::as_str) == Some(target.as_str())
            })
            .map(|entry| entry.payload.clone())
    }

    fn recorded_verdict(&self, claim_id: &str) -> Option<Verdict> {
        self.ledger
            .entries_of_kind(VERDICT)
            .into_iter()
            .rfind(|entry| entry.payload.get("claim_id").and_then(Value::as_str) == Some(claim_id))
            .and_then(|entry| entry.payload.get("verdict").and_then(Verdict::from_value))
    }

    // -- writes ----------------------------------------------------------

    pub fn post_objective(&mut self, objective: &Objective, ts: &str) -> Result<String, String> {
        let kind = objective
            .verifier_kind()
            .ok_or("objective needs a verifier with a 'kind'")?;
        // Asked of the verifier module rather than answered from a list kept
        // here. The list kept here went stale -- it still named two kinds after
        // three more were implemented, so this crate refused to post
        // objectives it could verify perfectly well, and every interop round
        // for those kinds could only run in one direction.
        if !verifiers::implements(kind) {
            return Err(format!(
                "this reference implements {}; kind {kind:?} is not one",
                verifiers::KINDS.join(", ")
            ));
        }
        let id = objective.id();
        if self.objectives().contains_key(&id) {
            return Err("objective already posted".into());
        }
        if let Some(block) = &objective.ratchet {
            let ratchet = Ratchet::from_value(block)?;
            if kind != "evaluator" {
                return Err("a ratchet objective needs a score-producing verifier".into());
            }
            if ratchet.reward != objective.reward {
                return Err("ratchet reward and objective reward disagree".into());
            }
        }
        self.ledger.append(OBJECTIVE, objective.to_value(), ts)?;
        Ok(id)
    }

    pub fn commit(&mut self, commitment: &Commitment, ts: &str) -> Result<String, String> {
        commitment.verify_signature().map_err(|e| e.to_string())?;
        self.epoch_of_ts("commitment", &commitment.created_at)?;
        let now = self.epoch_of_ts("commit", ts)?;
        self.settle_due(now, ts)?;

        let objectives = self.objectives();
        let objective = objectives
            .get(&commitment.objective_id)
            .ok_or("commitment references an unknown objective")?;
        if objective.require_signed_submitter && signed_submitter(&commitment.submitter).is_none() {
            return Err(format!(
                "objective {} accepts only signed identities, and {:?} is not one",
                short(&commitment.objective_id),
                commitment.submitter
            ));
        }
        // A progressive objective stays open after a settlement; a pass/fail
        // one does not.
        if objective.ratchet.is_none() && self.settlement_of(&commitment.objective_id).is_some() {
            return Err("objective already settled".into());
        }
        let entry = self.ledger.append(COMMITMENT, commitment.to_value(), ts)?;
        Ok(entry.hash)
    }

    pub fn reveal(&mut self, claim: &Claim, ts: &str) -> Result<Outcome, String> {
        claim.verify_signature().map_err(|e| e.to_string())?;
        let reveal_epoch = self.epoch_of_ts("reveal", ts)?;
        // Drain first: an epoch that closed while this node was idle must
        // settle before this claim's checks read the frontier, or an
        // improvement would be measured against a stale one.
        self.settle_due(reveal_epoch, ts)?;

        let objectives = self.objectives();
        let objective = objectives
            .get(&claim.objective_id)
            .ok_or("claim references an unknown objective")?
            .clone();

        if objective.require_signed_submitter && signed_submitter(&claim.submitter).is_none() {
            return Err(format!(
                "objective {} accepts only signed identities, and {:?} is not one",
                short(&claim.objective_id),
                claim.submitter
            ));
        }
        let commitment = self
            .matching_commitment(claim)
            .ok_or("no matching prior commitment: commit H(artifact‖submitter‖nonce) first")?;
        let created_at = commitment
            .get("created_at")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let commit_epoch = self.epoch_of_ts("commitment", created_at)?;
        // Strictly later, so the reveal that would be copied is public before
        // a competitor's commitment can be written.
        if reveal_epoch <= commit_epoch {
            return Err(format!(
                "reveal is in epoch {reveal_epoch} but its commitment is in epoch \
                 {commit_epoch}; a reveal must wait for a strictly later epoch"
            ));
        }
        if self.drained_epochs().contains(&reveal_epoch) {
            return Err(format!(
                "epoch {reveal_epoch} has already settled; a reveal cannot join a batch \
                 that has been paid"
            ));
        }
        let accepted = self.accepted_claims();
        for cited in &claim.cites {
            if !accepted.contains_key(cited) {
                return Err(format!(
                    "citation {cited} is not an accepted claim in this log; citations point \
                     backwards only"
                ));
            }
        }
        // Once a frontier exists on a ratcheted objective, *every* claim must
        // cite the holder -- not only improvements.
        if objective.ratchet.is_some() {
            if let Some(held) = self.frontier_of(&claim.objective_id) {
                if !claim.cites.contains(&held.claim_id) {
                    return Err(format!(
                        "an improvement must cite the frontier it improves on ({})",
                        held.claim_id
                    ));
                }
            }
        }

        let claim_id = claim.id();
        self.ledger.append(CLAIM, claim.to_value(), ts)?;
        let verdict = verifiers::run(&self.root, &objective.verifier, &claim.artifact);
        self.ledger.append(
            VERDICT,
            Value::object([
                ("claim_id", Value::string(claim_id.clone())),
                ("objective_id", Value::string(claim.objective_id.clone())),
                ("verdict", verdict.to_value()),
            ]),
            ts,
        )?;

        let note = if !verdict.status.settles() {
            "verdict does not settle"
        } else if !verdict.accepted() {
            "rejected"
        } else {
            return Ok(Outcome {
                claim_id,
                verdict,
                settled: false,
                reward: 0,
                note: format!("accepted; settles when epoch {reveal_epoch} closes"),
                pending_epoch: Some(reveal_epoch),
            });
        };
        Ok(Outcome {
            claim_id,
            verdict,
            settled: false,
            reward: 0,
            note: note.to_string(),
            pending_epoch: None,
        })
    }

    /// Settle every reveal epoch that has closed, in beacon order.
    pub fn settle_due(&mut self, now_epoch: u64, ts: &str) -> Result<Vec<Outcome>, String> {
        let drained = self.drained_epochs();
        let pending = self.accepted_claims_by_epoch();
        let due: BTreeSet<u64> = pending
            .iter()
            .map(|(epoch, _)| *epoch)
            .filter(|epoch| *epoch < now_epoch && !drained.contains(epoch))
            .collect();

        let mut outcomes = Vec::new();
        for epoch in due {
            let anchor = self.anchor_of_epoch(epoch, None);
            let mut batch: Vec<Claim> = pending
                .iter()
                .filter(|(candidate, _)| *candidate == epoch)
                .map(|(_, claim)| claim.clone())
                .collect();
            // Keyed on the *commitment* hash, not the claim id: by reveal time
            // the anchor is public, and a claim id covers `created_at` and
            // `cites`, which a submitter could re-roll until one sorted first.
            // Ties break on the id so append order never leaks back in.
            batch.sort_by_key(|claim| {
                (
                    settlement_rank(epoch, &anchor, &claim.commitment_hash()),
                    claim.id(),
                )
            });
            let mut consumed: BTreeSet<String> = BTreeSet::new();
            let mut order = Vec::with_capacity(batch.len());
            for claim in batch {
                order.push(Value::string(claim.id()));
                outcomes.push(self.settle_one(&claim, epoch, &consumed, ts)?);
                consumed.insert(claim.artifact_id());
            }
            self.ledger.append(
                BATCH,
                Value::object([
                    ("epoch", Value::Int(i128::from(epoch))),
                    ("anchor", Value::string(anchor)),
                    ("claims", Value::Array(order)),
                ]),
                ts,
            )?;
        }
        Ok(outcomes)
    }

    pub fn settle_at(&mut self, ts: &str) -> Result<Vec<Outcome>, String> {
        let now = self.epoch_of_ts("settle", ts)?;
        self.settle_due(now, ts)
    }

    fn settle_one(
        &mut self,
        claim: &Claim,
        epoch: u64,
        consumed: &BTreeSet<String>,
        ts: &str,
    ) -> Result<Outcome, String> {
        let claim_id = claim.id();
        let verdict = self.recorded_verdict(&claim_id).unwrap_or_else(|| {
            Verdict::new(
                Status::Accept,
                "recorded acceptance",
                Value::object(Vec::<(String, Value)>::new()),
            )
        });
        let objectives = self.objectives();
        let Some(objective) = objectives.get(&claim.objective_id).cloned() else {
            return Ok(unsettled(
                claim_id,
                verdict,
                "objective is no longer readable",
            ));
        };

        if let Some(block) = &objective.ratchet {
            // A single bad objective must not wedge settlement for every other
            // objective in the same epoch, so this is an unsettled outcome
            // rather than an error.
            let Ok(ratchet) = Ratchet::from_value(block) else {
                return Ok(unsettled(
                    claim_id,
                    verdict,
                    "objective carries an unusable ratchet",
                ));
            };
            let held = self.frontier_of(&claim.objective_id);
            return self.settle_improvement(claim, verdict, &ratchet, held, ts);
        }

        let artifact_id = claim.artifact_id();
        if consumed.contains(&artifact_id)
            || self
                .artifact_ids_before(&claim.objective_id, epoch)
                .contains(&artifact_id)
        {
            return Ok(unsettled(
                claim_id,
                verdict,
                "duplicate artifact mints nothing",
            ));
        }
        if self.settlement_of(&claim.objective_id).is_some() {
            return Ok(unsettled(claim_id, verdict, "objective already settled"));
        }
        self.ledger.append(
            SETTLEMENT,
            Value::object([
                ("objective_id", Value::string(claim.objective_id.clone())),
                ("claim_id", Value::string(claim_id.clone())),
                ("submitter", Value::string(claim.submitter.clone())),
                ("reward", Value::Int(i128::from(objective.reward))),
            ]),
            ts,
        )?;
        Ok(Outcome {
            claim_id,
            verdict,
            settled: true,
            reward: objective.reward,
            note: "settled".into(),
            pending_epoch: None,
        })
    }

    fn settle_improvement(
        &mut self,
        claim: &Claim,
        verdict: Verdict,
        ratchet: &Ratchet,
        held: Option<FrontierEntry>,
        ts: &str,
    ) -> Result<Outcome, String> {
        let claim_id = claim.id();
        let Some(score) = verdict.score() else {
            return Ok(unsettled(
                claim_id,
                verdict,
                "verifier produced no integer score",
            ));
        };
        let previous = held.as_ref().map(|held| held.score);
        if !ratchet.improves(previous, score) {
            return Ok(unsettled(
                claim_id,
                verdict,
                &format!(
                    "score {score} does not improve on {previous:?} by at least {}",
                    ratchet.min_improvement
                ),
            ));
        }
        let reward = ratchet.payout(previous, score);
        let paid_cumulative = held.as_ref().map_or(0, |held| held.paid_cumulative) + reward;
        self.ledger.append(
            FRONTIER,
            FrontierEntry {
                objective_id: claim.objective_id.clone(),
                claim_id: claim_id.clone(),
                holder: claim.submitter.clone(),
                score,
                paid_cumulative,
            }
            .to_value(),
            ts,
        )?;
        if reward > 0 {
            self.ledger.append(
                SETTLEMENT,
                Value::object([
                    ("objective_id", Value::string(claim.objective_id.clone())),
                    ("claim_id", Value::string(claim_id.clone())),
                    ("submitter", Value::string(claim.submitter.clone())),
                    ("reward", Value::Int(i128::from(reward))),
                ]),
                ts,
            )?;
        }
        Ok(Outcome {
            claim_id,
            verdict,
            settled: reward > 0,
            reward,
            note: if reward > 0 {
                "frontier advanced".into()
            } else {
                "verified but paid nothing".into()
            },
            pending_epoch: None,
        })
    }

    // -- audit -----------------------------------------------------------

    /// Re-derive everything the log claims, from the artifacts themselves.
    pub fn audit(&self, rerun: bool) -> Vec<String> {
        let mut problems = self.ledger.verify_chain();
        let objectives = self.objectives();

        // Every record must decode and re-encode to its own bytes, and carry a
        // valid signature when its submitter names a key.
        for entry in self.ledger.entries() {
            let re_encoded = match entry.kind.as_str() {
                OBJECTIVE => Objective::from_value(&entry.payload)
                    .map(|r| r.to_value())
                    .map_err(|e| e.to_string()),
                COMMITMENT => Commitment::from_value(&entry.payload)
                    .and_then(|r| {
                        r.verify_signature()?;
                        Ok(r.to_value())
                    })
                    .map_err(|e| e.to_string()),
                CLAIM => Claim::from_value(&entry.payload)
                    .and_then(|r| {
                        r.verify_signature()?;
                        Ok(r.to_value())
                    })
                    .map_err(|e| e.to_string()),
                // A peer record settles nothing, so a bad one cannot cost
                // money -- but a reader must be told rather than left to
                // wonder why a peer the log names is never dialled.
                PEER => PeerRecord::from_value(&entry.payload)
                    .and_then(|r| {
                        r.verify_signature()?;
                        Ok(r.to_value())
                    })
                    .map_err(|e| e.to_string()),
                _ => continue,
            };
            match re_encoded {
                Ok(value) if value == entry.payload => {}
                Ok(_) => problems.push(format!(
                    "entry {}: {} does not re-encode to its own bytes",
                    entry.seq, entry.kind
                )),
                Err(error) => problems.push(format!("entry {}: {error}", entry.seq)),
            }
        }

        // Every verdict record must be readable. This is structural, not a
        // re-run: a verdict naming no claim, or carrying a status no
        // implementation recognises, is a malformed log whether or not this
        // node can run the verifier. It used to be skipped in silence by the
        // re-run loop below, which meant a log could carry a verdict that
        // settles nothing anywhere and still audit clean.
        for entry in self.ledger.entries_of_kind(VERDICT) {
            let Some(claim_id) = entry.payload.get("claim_id").and_then(Value::as_str) else {
                problems.push(format!("entry {}: verdict has no claim_id", entry.seq));
                continue;
            };
            if entry
                .payload
                .get("verdict")
                .and_then(Verdict::from_value)
                .is_none()
            {
                problems.push(format!(
                    "entry {}: verdict for {} has no readable status",
                    entry.seq,
                    short(claim_id)
                ));
            }
        }

        // Every settlement must name a claim whose recorded verdict accepted.
        let accepted = self.accepted_claims();
        for entry in self.ledger.entries_of_kind(SETTLEMENT) {
            let Some(claim_id) = entry.payload.get("claim_id").and_then(Value::as_str) else {
                problems.push(format!("entry {}: settlement has no claim_id", entry.seq));
                continue;
            };
            if !accepted.contains_key(claim_id) {
                problems.push(format!(
                    "entry {}: settlement pays {} which has no accepting verdict",
                    entry.seq,
                    short(claim_id)
                ));
            }
        }

        // Every claim opens a commitment, and every claim has a verdict.
        //
        // The first is the commit-reveal scheme itself: a claim with no
        // matching commitment was never bound to an epoch, so its submitter
        // could have read everyone else's reveal before writing it. That is the
        // one thing the scheme exists to prevent, and the independent auditor
        // did not check it -- it looked only from verdicts and settlements
        // *back* to claims, which cannot see a claim nothing points at.
        let mut seen_claims: BTreeSet<String> = BTreeSet::new();
        let with_verdict: BTreeSet<String> = self
            .ledger
            .entries_of_kind(VERDICT)
            .into_iter()
            .filter_map(|entry| {
                entry
                    .payload
                    .get("claim_id")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .collect();
        for entry in self.ledger.entries_of_kind(CLAIM) {
            let Ok(claim) = Claim::from_value(&entry.payload) else {
                // Reported above by the re-encode pass.
                continue;
            };
            let claim_id = claim.id();
            if !seen_claims.insert(claim_id.clone()) {
                continue;
            }
            if self.matching_commitment(&claim).is_none() {
                problems.push(format!(
                    "claim {}: no matching commitment",
                    short(&claim_id)
                ));
            }
            if !with_verdict.contains(&claim_id) {
                problems.push(format!("claim {}: no verdict recorded", short(&claim_id)));
            }
        }

        // No objective pays out more than it funded, and a plain one pays once.
        //
        // The most consequential invariant in the file, and this crate did not
        // check it at all. Everything above is about whether a *record* is
        // well-formed; this is about whether the money adds up, and an
        // independent auditor that re-derives every id and every root while
        // taking the arithmetic on faith is checking the easy half. An operator
        // could have overspent a pool by any amount and the reference would
        // have said "log verified".
        //
        // `i128` throughout, and a total that cannot be represented is a
        // problem rather than a wrap: a wrapped sum resets an overspent pool to
        // something small and hides exactly the fault being looked for.
        let mut settled_once: BTreeSet<String> = BTreeSet::new();
        let mut paid: BTreeMap<String, i128> = BTreeMap::new();
        for entry in self.ledger.entries_of_kind(SETTLEMENT) {
            let Some(objective_id) = entry.payload.get("objective_id").and_then(Value::as_str)
            else {
                problems.push(format!(
                    "entry {}: settlement has no objective_id",
                    entry.seq
                ));
                continue;
            };
            let objective = objectives.get(objective_id);
            // A ratcheted objective pays each improvement, so more than one
            // settlement is the design rather than a fault. Every other kind
            // closes when it pays.
            let progressive = objective.is_some_and(|o| o.ratchet.is_some());
            if !settled_once.insert(objective_id.to_string()) && !progressive {
                problems.push(format!(
                    "objective {}: settled more than once",
                    short(objective_id)
                ));
            }
            let reward = match entry.payload.get("reward") {
                Some(Value::Int(reward)) => *reward,
                // Absent is not zero and a string is not a number. A settlement
                // whose amount cannot be read is not one whose amount is
                // harmless.
                _ => {
                    problems.push(format!(
                        "entry {}: settlement of {} has no integer reward",
                        entry.seq,
                        short(objective_id)
                    ));
                    continue;
                }
            };
            let running = paid.entry(objective_id.to_string()).or_insert(0);
            match running.checked_add(reward) {
                Some(total) => *running = total,
                None => problems.push(format!(
                    "objective {}: settled rewards overflow any representable total",
                    short(objective_id)
                )),
            }
        }
        for (objective_id, total) in &paid {
            let Some(objective) = objectives.get(objective_id) else {
                problems.push(format!(
                    "settlement references unknown objective {}",
                    short(objective_id)
                ));
                continue;
            };
            if *total < 0 {
                problems.push(format!(
                    "objective {}: settled rewards sum to a negative total {total}",
                    short(objective_id)
                ));
            } else if *total > i128::from(objective.reward) {
                problems.push(format!(
                    "objective {}: paid {total} against a pool of {}",
                    short(objective_id),
                    objective.reward
                ));
            }
        }

        // Every batch must name the anchor the log actually had at its epoch's
        // start, and the order the beacon produces.
        let mut batches = 0usize;
        let mut faulted: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
        for entry in self.ledger.entries_of_kind(BATCH) {
            let Some(epoch) = entry.payload.get("epoch").and_then(Value::as_u64) else {
                continue;
            };
            batches += 1;
            let recorded_anchor = entry
                .payload
                .get("anchor")
                .and_then(Value::as_str)
                .unwrap_or_default();
            // Bounded to the log as it stood when the batch was written, so a
            // later back-dated append cannot turn an honest batch into a
            // permanent audit failure.
            let expected = self.anchor_of_epoch(epoch, Some(entry.seq as usize));
            if expected != recorded_anchor {
                faulted.insert(epoch);
                problems.push(format!(
                    "entry {}: batch anchor is {}, expected {}",
                    entry.seq,
                    short(recorded_anchor),
                    short(&expected)
                ));
            }
            let listed: Vec<String> = entry
                .payload
                .get("claims")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            // Membership is derived from the log, not read back out of the
            // batch. Re-sorting the list the batch itself supplied is a check
            // that a batch which *omitted* a claim always passes -- and which
            // claims are in an epoch's batch is precisely what decides who gets
            // paid that epoch, so it is the last thing an independent
            // implementation should take on faith from the record it is
            // auditing.
            //
            // Bounded to the log as it stood when the batch was written, for
            // the same reason the anchor is: a peer can append a claim dated
            // into an epoch that already paid, and an unbounded scan would call
            // an honest batch wrong forever.
            let mut expected_order: Vec<String> = self
                .accepted_claims_by_epoch_within(Some(entry.seq as usize))
                .into_iter()
                .filter(|(candidate, _)| *candidate == epoch)
                .map(|(_, claim)| claim.id())
                .collect();
            expected_order.sort_by_key(|id| {
                let commitment_hash = accepted
                    .get(id)
                    .map(|claim| claim.commitment_hash())
                    .unwrap_or_default();
                (
                    settlement_rank(epoch, recorded_anchor, &commitment_hash),
                    id.clone(),
                )
            });
            if expected_order != listed {
                faulted.insert(epoch);
                problems.push(format!(
                    "entry {}: batch for epoch {epoch} settled {} claim(s) in an order the \
                     beacon does not produce",
                    entry.seq,
                    listed.len()
                ));
            }
        }

        // Every batch faulting at once usually means the auditor and the writer
        // disagree about how long an epoch is, not that anybody was paid out of
        // turn. Epochs are derived from timestamps and never stored, so a log
        // written under `PROOFWORK_EPOCH_SECONDS=1` audits as thoroughly broken
        // under the default 600 -- both implementations agree, and both are
        // right.
        //
        // The primary prints this note; this crate did not, which is the wrong
        // way round. A reader auditing with the *independent* implementation is
        // exactly the reader with no reason to trust a reassuring explanation
        // from the primary, and they were the one left staring at a wall of
        // anchor mismatches that reads like proof the project's central claim
        // is false.
        if batches > 0 && faulted.len() == batches {
            problems.push(format!(
                "note: every batch in this log looks wrong, which is more often a mismatched \
                 epoch length than a dishonest operator. Epochs are derived from record \
                 timestamps and never stored, so a log written with a different \
                 PROOFWORK_EPOCH_SECONDS (this audit used {}) cannot be re-derived without it.",
                crate::partition::epoch_seconds()
            ));
        }

        if rerun {
            // Which claims actually got paid. A claim that settled and can no
            // longer be re-verified is a different thing from one that never
            // settled, and the difference is the whole point of the exercise:
            // money moved on the strength of a verdict this node cannot now
            // reproduce.
            let paid: std::collections::BTreeSet<String> = self
                .ledger
                .entries_of_kind(SETTLEMENT)
                .into_iter()
                .filter_map(|entry| {
                    entry
                        .payload
                        .get("claim_id")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                })
                .collect();

            // The claim the whole design makes: re-run the pinned verifier and
            // check the log's own verdict still holds.
            for entry in self.ledger.entries_of_kind(VERDICT) {
                let Some(claim_id) = entry.payload.get("claim_id").and_then(Value::as_str) else {
                    continue;
                };
                let Some(recorded) = entry.payload.get("verdict").and_then(Verdict::from_value)
                else {
                    continue;
                };
                // Only settled verdicts are re-checked: an `unavailable` was
                // never a statement about the artifact.
                if !recorded.status.settles() {
                    continue;
                }
                let Some(claim) = accepted.get(claim_id).cloned().or_else(|| {
                    self.ledger
                        .entries_of_kind(CLAIM)
                        .into_iter()
                        .filter_map(|e| Claim::from_value(&e.payload).ok())
                        .find(|c| c.id() == claim_id)
                }) else {
                    continue;
                };
                let Some(objective) = objectives.get(&claim.objective_id) else {
                    continue;
                };
                let fresh = verifiers::run(&self.root, &objective.verifier, &claim.artifact);
                // A verifier this node cannot run says nothing *about the
                // artifact* -- `Unavailable` is never `Reject`. But it says
                // something about **this audit**, and staying silent was a
                // divergence from the primary that hid a real gap: an entire
                // verifier kind this crate did not implement produced
                // `Unavailable` for every claim, every one was skipped, and the
                // run still reported "every settled claim re-verified". Correct
                // behaviours composing into a false statement.
                //
                // So: skipped is fine for a verdict the log did not settle
                // either, and a problem for one it did. The summary line says
                // "every settled claim re-verified"; if that cannot be done,
                // the line is false and the audit has to say so.
                //
                // Gating this on *payment* was the first version and it left a
                // hole one rung down: a `reject` never pays, so a rejection no
                // other node could reproduce passed every audit in silence.
                // That is the worse direction. A payment somebody will
                // eventually contest; a rejected submitter has no money to
                // point at and no way to show the rejection was not
                // reproducible.
                if !fresh.status.settles() {
                    if paid.contains(claim_id) {
                        problems.push(format!(
                            "claim {}: was settled but can no longer be re-verified ({}: {})",
                            short(claim_id),
                            fresh.status.as_str(),
                            fresh.detail
                        ));
                    } else {
                        problems.push(format!(
                            "claim {}: recorded {} but can no longer be re-verified ({}: {})",
                            short(claim_id),
                            recorded.status.as_str(),
                            fresh.status.as_str(),
                            fresh.detail
                        ));
                    }
                    continue;
                }
                if fresh.status != recorded.status {
                    problems.push(format!(
                        "claim {}: recorded {} but re-runs as {}",
                        short(claim_id),
                        recorded.status.as_str(),
                        fresh.status.as_str()
                    ));
                }
            }
        }
        problems
    }
}

fn unsettled(claim_id: String, verdict: Verdict, note: &str) -> Outcome {
    Outcome {
        claim_id,
        verdict,
        settled: false,
        reward: 0,
        note: note.to_string(),
        pending_epoch: None,
    }
}

/// Now, for callers that do not want to import the time module.
pub fn now() -> String {
    timestamp()
}
