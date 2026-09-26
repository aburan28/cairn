//! The same activation rule as the primary crate, written out again so a
//! pledge that funds on one implementation and refunds on the other cannot
//! hide. The canonical bytes are pinned to the same string.
//!
//! Remainder units go to sponsors in name order, ties broken by input order.
//! That order is the consensus: a different tie-break would pay a different
//! sponsor for the same log.

use crate::canonical::Value;

#[derive(Clone)]
pub struct Proposal {
    pub id: String,
    pub target: u64,
    pub deadline: u64,
}

#[derive(Clone)]
pub struct Pledge {
    pub proposal: String,
    pub sponsor: String,
    pub units: u64,
}

pub enum Activation {
    Funded { from: Vec<(String, u64)> },
    Refund { to: Vec<(String, u64)> },
}

pub fn proposal_json(proposal: &Proposal) -> String {
    let value = Value::object([
        ("deadline", Value::Int(i128::from(proposal.deadline))),
        ("id", Value::string(proposal.id.clone())),
        ("target", Value::Int(i128::from(proposal.target))),
        ("type", Value::string("proposal")),
    ]);
    String::from_utf8(value.canonical_bytes()).expect("utf8")
}

pub fn pledge_json(pledge: &Pledge) -> String {
    let value = Value::object([
        ("proposal", Value::string(pledge.proposal.clone())),
        ("sponsor", Value::string(pledge.sponsor.clone())),
        ("type", Value::string("pledge")),
        ("units", Value::Int(i128::from(pledge.units))),
    ]);
    String::from_utf8(value.canonical_bytes()).expect("utf8")
}

pub fn activate(proposal: &Proposal, pledges: &[Pledge], now: u64) -> Activation {
    let mut indexed: Vec<(usize, &Pledge)> = pledges
        .iter()
        .enumerate()
        .filter(|(_, pledge)| pledge.proposal == proposal.id)
        .collect();
    indexed.sort_by(|a, b| a.1.sponsor.cmp(&b.1.sponsor).then(a.0.cmp(&b.0)));
    let sum: u128 = indexed
        .iter()
        .map(|(_, pledge)| u128::from(pledge.units))
        .sum();
    let full: Vec<(String, u64)> = indexed
        .iter()
        .map(|(_, pledge)| (pledge.sponsor.clone(), pledge.units))
        .collect();
    if now > proposal.deadline || sum < u128::from(proposal.target) {
        return Activation::Refund { to: full };
    }
    if sum == 0 {
        return Activation::Funded { from: full };
    }
    let target = u128::from(proposal.target);
    let mut pays: Vec<u64> = indexed
        .iter()
        .map(|(_, pledge)| {
            u64::try_from((target * u128::from(pledge.units)) / sum).unwrap_or(u64::MAX)
        })
        .collect();
    let paid: u128 = pays.iter().map(|pay| u128::from(*pay)).sum();
    let mut remainder = target - paid;
    let mut index = 0;
    while remainder > 0 {
        pays[index] = pays[index].saturating_add(1);
        remainder -= 1;
        index += 1;
        if index == pays.len() {
            index = 0;
        }
    }
    Activation::Funded {
        from: indexed
            .iter()
            .zip(pays)
            .map(|((_, pledge), pay)| (pledge.sponsor.clone(), pay))
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proposal() -> Proposal {
        Proposal {
            id: "idea-1".into(),
            target: 30,
            deadline: 100,
        }
    }

    #[test]
    fn the_encoding_matches_the_primary_and_the_rule_refunds_a_shortfall() {
        assert_eq!(
            proposal_json(&proposal()),
            r#"{"deadline":100,"id":"idea-1","target":30,"type":"proposal"}"#
        );
        assert_eq!(
            pledge_json(&Pledge {
                proposal: "idea-1".into(),
                sponsor: "a".into(),
                units: 10,
            }),
            r#"{"proposal":"idea-1","sponsor":"a","type":"pledge","units":10}"#
        );
        let full = vec![
            Pledge {
                proposal: "idea-1".into(),
                sponsor: "a".into(),
                units: 10,
            },
            Pledge {
                proposal: "idea-1".into(),
                sponsor: "b".into(),
                units: 10,
            },
            Pledge {
                proposal: "idea-1".into(),
                sponsor: "c".into(),
                units: 10,
            },
        ];
        assert!(matches!(
            activate(&proposal(), &full, 100),
            Activation::Funded { .. }
        ));
        assert!(matches!(
            activate(&proposal(), &full[..2], 101),
            Activation::Refund { .. }
        ));
    }

    #[test]
    fn an_oversubscription_pays_the_same_sponsors_as_the_primary() {
        let pledges = vec![
            Pledge {
                proposal: "idea-1".into(),
                sponsor: "c".into(),
                units: 20,
            },
            Pledge {
                proposal: "idea-1".into(),
                sponsor: "a".into(),
                units: 10,
            },
            Pledge {
                proposal: "idea-1".into(),
                sponsor: "b".into(),
                units: 10,
            },
        ];
        match activate(&proposal(), &pledges, 100) {
            Activation::Funded { from } => assert_eq!(
                from,
                vec![("a".into(), 8), ("b".into(), 7), ("c".into(), 15)]
            ),
            Activation::Refund { .. } => panic!("refunded"),
        }
    }
}
