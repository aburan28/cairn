//! Causal conflict detection for multi-operator frontiers.
//!
//! Clocks and cite graphs answer "are these two claims concurrent?" They do
//! **not** answer "who gets paid first." Settlement order stays
//! `H(beacon(epoch, anchor) ‖ commitment_hash)`. Feeding a Lamport timestamp
//! into that key would hand every submitter a free lottery: they choose the
//! clock, so they choose the rank.
//!
//! What this module does is the part clocks are actually good for. Two claims
//! on one objective that neither cites the other are concurrent. A sequencer
//! that silently prefers one is detectable because both are still in the log
//! and this view is derived, not stored.

use std::collections::{BTreeMap, BTreeSet};

/// One claim, reduced to the fields concurrency cares about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CausalClaim {
    pub id: String,
    pub objective_id: String,
    pub cites: Vec<String>,
}

/// Two claims that are concurrent on the same objective.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Conflict {
    pub objective_id: String,
    pub left: String,
    pub right: String,
}

/// Concurrent pairs: same objective, neither id appears in the other's cites.
///
/// A claim that cites the other happened-after it, so it is not a conflict.
/// Pairs are ordered so `(a, b)` and `(b, a)` collapse.
pub fn conflicts(claims: &[CausalClaim]) -> Vec<Conflict> {
    let mut by_objective: BTreeMap<&str, Vec<&CausalClaim>> = BTreeMap::new();
    for claim in claims {
        by_objective
            .entry(claim.objective_id.as_str())
            .or_default()
            .push(claim);
    }

    let mut out = Vec::new();
    for (objective_id, group) in by_objective {
        for (i, left) in group.iter().enumerate() {
            let left_cites: BTreeSet<&str> = left.cites.iter().map(String::as_str).collect();
            for right in group.iter().skip(i + 1) {
                if left_cites.contains(right.id.as_str()) {
                    continue;
                }
                if right.cites.iter().any(|id| id == &left.id) {
                    continue;
                }
                let (a, b) = if left.id <= right.id {
                    (left.id.clone(), right.id.clone())
                } else {
                    (right.id.clone(), left.id.clone())
                };
                out.push(Conflict {
                    objective_id: objective_id.to_string(),
                    left: a,
                    right: b,
                });
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim(id: &str, objective: &str, cites: &[&str]) -> CausalClaim {
        CausalClaim {
            id: id.into(),
            objective_id: objective.into(),
            cites: cites.iter().map(|c| (*c).to_string()).collect(),
        }
    }

    #[test]
    fn a_citation_is_not_a_conflict() {
        let claims = vec![claim("a", "obj", &[]), claim("b", "obj", &["a"])];
        assert!(conflicts(&claims).is_empty());
    }

    #[test]
    fn two_claims_that_cite_neither_are_concurrent() {
        let claims = vec![claim("b", "obj", &["a"]), claim("c", "obj", &["a"])];
        assert_eq!(
            conflicts(&claims),
            vec![Conflict {
                objective_id: "obj".into(),
                left: "b".into(),
                right: "c".into(),
            }]
        );
    }

    #[test]
    fn different_objectives_do_not_conflict() {
        let claims = vec![claim("a", "one", &[]), claim("b", "two", &[])];
        assert!(conflicts(&claims).is_empty());
    }
}
