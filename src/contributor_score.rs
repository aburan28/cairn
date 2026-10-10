//! Reader-side summaries of completed research assignments.
//!
//! These numbers describe observed work. They are not a verdict, a balance, or
//! consensus state; readers choose the window and routing threshold. In
//! particular, eligible token spend never improves the success rate by itself.

use std::collections::BTreeSet;

use crate::exploration::{cost_for_artifact, AssignmentPolicy};
use crate::node::Node;
use crate::partition::{epoch_of, EPOCH_SECONDS};
use crate::records::{Claim, Objective};
use crate::verifiers::{Status, Verdict};

const PARTS_PER_MILLION: u128 = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssignmentOutcome {
    /// The assignment's pinned evidence checker accepted its deliverable.
    Verified,
    /// The checker ran and rejected the deliverable.
    Rejected,
    /// A preaccepted assignment reached its deadline without a deliverable.
    Missed,
    /// A checker or provider could not run; this is not a wrong answer.
    Unavailable,
}

/// A single preaccepted assignment reconstructed from the log. The caller is
/// responsible for deriving these rows from authenticated entries rather than
/// from worker self-reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignmentObservation {
    pub assignment_id: String,
    pub family: String,
    pub verifier_tier: String,
    pub epoch: u64,
    pub outcome: AssignmentOutcome,
    pub eligible_spend: u64,
    pub verified_gain: u64,
}

/// Reader policy. The window and threshold are displayed with the score, so a
/// client does not disguise its own preference as a network-wide reputation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScorePolicy {
    pub window_epochs: u64,
    pub min_decidable: u64,
    pub min_smoothed_rate_ppm: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContributorScore {
    pub verified: u64,
    pub rejected: u64,
    pub missed: u64,
    pub unavailable: u64,
    pub eligible_spend: u128,
    pub verified_gain: u128,
    /// Laplace-smoothed descriptive success fraction, in parts per million.
    /// Not a confidence interval or a prediction on unseen assignments.
    pub smoothed_rate_ppm: u32,
    pub routing_eligible: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScoreError {
    InvalidPolicy,
    DuplicateAssignment,
    InvalidObservation,
    ArithmeticOverflow,
}

/// Summarize one task family and verifier tier. Keeping those strata separate
/// prevents easy certificate work from buying standing on expensive objectives.
pub fn summarize(
    observations: &[AssignmentObservation],
    family: &str,
    verifier_tier: &str,
    as_of_epoch: u64,
    policy: ScorePolicy,
) -> Result<ContributorScore, ScoreError> {
    if policy.window_epochs == 0 || policy.min_smoothed_rate_ppm > 1_000_000 {
        return Err(ScoreError::InvalidPolicy);
    }
    let first_epoch = as_of_epoch.saturating_sub(policy.window_epochs - 1);
    let mut seen = BTreeSet::new();
    let mut score = ContributorScore {
        verified: 0,
        rejected: 0,
        missed: 0,
        unavailable: 0,
        eligible_spend: 0,
        verified_gain: 0,
        smoothed_rate_ppm: 0,
        routing_eligible: false,
    };
    for observation in observations {
        if observation.assignment_id.is_empty()
            || observation.family.is_empty()
            || observation.verifier_tier.is_empty()
            || (observation.outcome != AssignmentOutcome::Verified
                && observation.verified_gain != 0)
        {
            return Err(ScoreError::InvalidObservation);
        }
        if observation.family != family
            || observation.verifier_tier != verifier_tier
            || observation.epoch < first_epoch
            || observation.epoch > as_of_epoch
        {
            continue;
        }
        if !seen.insert(&observation.assignment_id) {
            return Err(ScoreError::DuplicateAssignment);
        }
        let count = match observation.outcome {
            AssignmentOutcome::Verified => &mut score.verified,
            AssignmentOutcome::Rejected => &mut score.rejected,
            AssignmentOutcome::Missed => &mut score.missed,
            AssignmentOutcome::Unavailable => &mut score.unavailable,
        };
        *count = count.checked_add(1).ok_or(ScoreError::ArithmeticOverflow)?;
        score.eligible_spend = score
            .eligible_spend
            .checked_add(u128::from(observation.eligible_spend))
            .ok_or(ScoreError::ArithmeticOverflow)?;
        score.verified_gain = score
            .verified_gain
            .checked_add(u128::from(observation.verified_gain))
            .ok_or(ScoreError::ArithmeticOverflow)?;
    }
    let decidable = score
        .verified
        .checked_add(score.rejected)
        .and_then(|n| n.checked_add(score.missed))
        .ok_or(ScoreError::ArithmeticOverflow)?;
    // One prior success and one prior failure prevent a single easy completion
    // from appearing to establish perfect reliability. These are display and
    // routing numbers only; the raw counts remain available to every reader.
    let numerator = u128::from(score.verified)
        .checked_add(1)
        .and_then(|n| n.checked_mul(PARTS_PER_MILLION))
        .ok_or(ScoreError::ArithmeticOverflow)?;
    let denominator = u128::from(decidable)
        .checked_add(2)
        .ok_or(ScoreError::ArithmeticOverflow)?;
    score.smoothed_rate_ppm =
        u32::try_from(numerator / denominator).map_err(|_| ScoreError::ArithmeticOverflow)?;
    score.routing_eligible = decidable >= policy.min_decidable
        && score.smoothed_rate_ppm >= policy.min_smoothed_rate_ppm;
    Ok(score)
}

/// Derive observations from one audited log. `trusted_funders` is a reader
/// choice: counting self-funded or untrusted assignments would let an identity
/// manufacture a record of easy work and then advertise it as reputation.
/// This accessor does not run the audit, so callers must audit the log first.
pub fn observations_from_node(
    node: &Node,
    assignee: &str,
    trusted_funders: &BTreeSet<String>,
    as_of_epoch: u64,
) -> Result<Vec<AssignmentObservation>, ScoreError> {
    let entries = node.ledger().entries();
    let mut verdicts = std::collections::BTreeMap::new();
    let mut settled = std::collections::BTreeMap::new();
    let entry_epoch = |ts: &str| {
        crate::time::parse_rfc3339(ts)
            .and_then(|seconds| u64::try_from(seconds).ok())
            .map(|seconds| epoch_of(seconds, EPOCH_SECONDS))
            .ok_or(ScoreError::InvalidObservation)
    };
    for entry in entries {
        if entry_epoch(&entry.ts)? > as_of_epoch {
            continue;
        }
        match entry.kind.as_str() {
            "verdict" => {
                let (Some(claim_id), Some(verdict)) = (
                    entry
                        .payload
                        .get("claim_id")
                        .and_then(crate::canonical::Value::as_str),
                    entry.payload.get("verdict").and_then(Verdict::from_value),
                ) else {
                    continue;
                };
                verdicts.insert(claim_id.to_string(), verdict.status);
            }
            "settlement" => {
                let (Some(claim_id), Some(reward)) = (
                    entry
                        .payload
                        .get("claim_id")
                        .and_then(crate::canonical::Value::as_str),
                    entry
                        .payload
                        .get("reward")
                        .and_then(crate::canonical::Value::as_u64),
                ) else {
                    continue;
                };
                settled.insert(claim_id.to_string(), reward);
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    for entry in entries.iter().filter(|entry| entry.kind == "objective") {
        if entry_epoch(&entry.ts)? > as_of_epoch {
            continue;
        }
        let objective =
            Objective::from_value(&entry.payload).map_err(|_| ScoreError::InvalidObservation)?;
        if objective.assignee.as_deref() != Some(assignee)
            || !trusted_funders.contains(&objective.funder)
        {
            continue;
        }
        let policy = objective
            .verifier
            .get("exploration_assignment")
            .map(AssignmentPolicy::from_value)
            .transpose()
            .map_err(|_| ScoreError::InvalidObservation)?;
        if policy
            .as_ref()
            .is_some_and(|policy| policy.contributor != assignee)
        {
            return Err(ScoreError::InvalidObservation);
        }
        let objective_id = objective.id();
        // An objective names its assignee unilaterally. A signed commitment is
        // the worker's observable acceptance; without it, a funder could post
        // unwanted jobs against another person's public key and damage them.
        let accepted_assignment = entries.iter().any(|entry| {
            if entry.kind != "commitment"
                || entry_epoch(&entry.ts)
                    .ok()
                    .is_none_or(|epoch| epoch > as_of_epoch)
            {
                return false;
            }
            crate::records::Commitment::from_value(&entry.payload).is_ok_and(|commitment| {
                commitment.objective_id == objective_id
                    && commitment.submitter == assignee
                    && commitment.verify_signature().is_ok()
            })
        });
        if !accepted_assignment {
            continue;
        }
        let mut accepted = false;
        let mut rejected = false;
        let mut unavailable = false;
        let mut eligible_spend = 0u64;
        let mut verified_gain = 0u64;
        let mut last_claim_epoch = None;
        for claim_entry in entries.iter().filter(|entry| entry.kind == "claim") {
            let Ok(claim) = Claim::from_value(&claim_entry.payload) else {
                continue;
            };
            if claim.objective_id != objective_id || claim.submitter != assignee {
                continue;
            }
            let claim_epoch = entry_epoch(&claim_entry.ts)?;
            if claim_epoch > as_of_epoch {
                continue;
            }
            last_claim_epoch =
                Some(last_claim_epoch.map_or(claim_epoch, |old: u64| old.max(claim_epoch)));
            match verdicts.get(&claim.id()) {
                Some(Status::Accept) => {
                    accepted = true;
                    verified_gain = verified_gain
                        .checked_add(settled.get(&claim.id()).copied().unwrap_or(0))
                        .ok_or(ScoreError::ArithmeticOverflow)?;
                    if let Some(policy) = &policy {
                        let spend =
                            cost_for_artifact(policy, &claim.artifact, true, &BTreeSet::new())
                                .map_err(|_| ScoreError::InvalidObservation)?;
                        eligible_spend = eligible_spend.max(spend);
                    }
                }
                Some(Status::Reject) => rejected = true,
                Some(Status::Unavailable | Status::InvalidSpec) => unavailable = true,
                None => {}
            }
        }
        let deadline_epoch = objective.deadline.as_deref().map(entry_epoch).transpose()?;
        let (outcome, epoch) = if accepted {
            (
                AssignmentOutcome::Verified,
                last_claim_epoch.unwrap_or(as_of_epoch),
            )
        } else if rejected {
            (
                AssignmentOutcome::Rejected,
                last_claim_epoch.unwrap_or(as_of_epoch),
            )
        } else if unavailable {
            (
                AssignmentOutcome::Unavailable,
                last_claim_epoch.unwrap_or(as_of_epoch),
            )
        } else if let Some(deadline_epoch) = deadline_epoch.filter(|epoch| *epoch < as_of_epoch) {
            (AssignmentOutcome::Missed, deadline_epoch)
        } else {
            continue;
        };
        let verifier_tier = Node::tier_of(&objective).as_str().to_string();
        out.push(AssignmentObservation {
            assignment_id: objective_id,
            family: objective.goal,
            verifier_tier,
            epoch,
            outcome,
            eligible_spend,
            verified_gain,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: &str, outcome: AssignmentOutcome, spend: u64) -> AssignmentObservation {
        AssignmentObservation {
            assignment_id: id.into(),
            family: "ecdlp".into(),
            verifier_tier: "certificate".into(),
            epoch: 10,
            outcome,
            eligible_spend: spend,
            verified_gain: u64::from(outcome == AssignmentOutcome::Verified),
        }
    }

    #[test]
    fn spend_cannot_improve_reliability_and_unavailable_is_separate() {
        let policy = ScorePolicy {
            window_epochs: 5,
            min_decidable: 2,
            min_smoothed_rate_ppm: 500_000,
        };
        let rows = [
            row("a", AssignmentOutcome::Verified, 5),
            row("b", AssignmentOutcome::Missed, u64::MAX),
            row("c", AssignmentOutcome::Unavailable, 0),
        ];
        let score = summarize(&rows, "ecdlp", "certificate", 10, policy).unwrap();
        assert_eq!((score.verified, score.missed, score.unavailable), (1, 1, 1));
        assert_eq!(score.smoothed_rate_ppm, 500_000);
        assert!(score.routing_eligible);
        assert_eq!(score.eligible_spend, u128::from(u64::MAX) + 5);
    }

    #[test]
    fn duplicate_assignment_cannot_pad_the_score() {
        let policy = ScorePolicy {
            window_epochs: 5,
            min_decidable: 1,
            min_smoothed_rate_ppm: 0,
        };
        let rows = [
            row("a", AssignmentOutcome::Verified, 5),
            row("a", AssignmentOutcome::Verified, 5),
        ];
        assert_eq!(
            summarize(&rows, "ecdlp", "certificate", 10, policy),
            Err(ScoreError::DuplicateAssignment)
        );
    }
}
