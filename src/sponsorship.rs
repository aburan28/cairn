//! Assurance-contract sponsorship.
//!
//! A proposal names a target and a deadline. Pledges name units against it.
//! Activation is derived: at or before the deadline, if the sum meets the
//! target, each sponsor pays a pro-rata share of the target and keeps the
//! rest; otherwise every pledge returns in full. Nothing here writes a
//! balance — a debit that skips `spendable_within` is a bug this repository
//! has already shipped. The audit in both implementations re-derives the
//! same [`Activation`] from the same records.

use crate::canonical::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    pub id: String,
    pub target: u64,
    /// Unix seconds. Compared as an integer, never as a clock reading at audit
    /// time: the deadline is a field of the record.
    pub deadline: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pledge {
    pub proposal: String,
    pub sponsor: String,
    pub units: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Activation {
    /// Pledges covered the target in time. `from` is who pays how much.
    Funded { from: Vec<(String, u64)> },
    /// The deadline passed short. Every pledge returns in full.
    Refund { to: Vec<(String, u64)> },
}

pub fn proposal_value(proposal: &Proposal) -> Value {
    Value::object([
        ("deadline", Value::Int(i128::from(proposal.deadline))),
        ("id", Value::string(proposal.id.clone())),
        ("target", Value::Int(i128::from(proposal.target))),
        ("type", Value::string("proposal")),
    ])
}

pub fn pledge_value(pledge: &Pledge) -> Value {
    Value::object([
        ("proposal", Value::string(pledge.proposal.clone())),
        ("sponsor", Value::string(pledge.sponsor.clone())),
        ("type", Value::string("pledge")),
        ("units", Value::Int(i128::from(pledge.units))),
    ])
}

/// `now` is the timestamp the log is being read at, supplied by the caller
/// from a record, not from the wall clock.
///
/// When the sum meets the target at or before the deadline, each sponsor pays
/// `floor(target * units / sum)` and the remainder — which is strictly less
/// than the number of pledges — is handed out one unit at a time in sponsor
/// name order, ties broken by the order the pledges were given. Both
/// implementations use that order so a unit cannot land on a different
/// sponsor depending on who audits. The excess of a pledge over what it pays
/// is not taken. A shortfall, or a deadline already past, returns every unit.
///
/// This does not write a balance. Debiting a sponsor is a ledger rule, and a
/// debit that does not consult `spendable_within` is the bug this repository
/// has shipped before. Callers that move units have to do that check themselves.
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
            u64::try_from((target * u128::from(pledge.units)) / sum)
                .expect("a pro-rata share is at most the pledge")
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
    fn three_sponsors_fund_it_and_a_late_shortfall_returns_every_unit() {
        let pledges = vec![
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
            activate(&proposal(), &pledges, 100),
            Activation::Funded { .. }
        ));
        assert!(matches!(
            activate(&proposal(), &pledges[..2], 101),
            Activation::Refund { .. }
        ));
    }

    #[test]
    fn an_oversubscription_pays_the_target_and_names_the_same_sponsors() {
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
            Activation::Funded { from } => {
                assert_eq!(
                    from,
                    vec![("a".into(), 8), ("b".into(), 7), ("c".into(), 15),]
                );
                let paid: u64 = from.iter().map(|(_, units)| *units).sum();
                assert_eq!(paid, 30);
            }
            Activation::Refund { .. } => panic!("an oversubscribed proposal refunded"),
        }
    }

    #[test]
    fn a_pledge_encodes_canonically() {
        let bytes = pledge_value(&Pledge {
            proposal: "idea-1".into(),
            sponsor: "a".into(),
            units: 10,
        })
        .canonical_bytes();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            r#"{"proposal":"idea-1","sponsor":"a","type":"pledge","units":10}"#
        );
    }

    #[test]
    fn the_encoding_is_canonical() {
        let bytes = proposal_value(&proposal()).canonical_bytes();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            r#"{"deadline":100,"id":"idea-1","target":30,"type":"proposal"}"#
        );
    }
}
