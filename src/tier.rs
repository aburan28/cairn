//! What a unit was earned for, carried with the unit.
//!
//! # The problem
//!
//! Five verifier kinds sit orders of magnitude apart in what they cost to
//! check. A `certificate` recomputes an NP witness in milliseconds. A `lean`
//! proof runs a kernel for seconds to minutes. A `replay` re-runs an entire
//! computation. `incentive::design::decomposition_floor` prices the gap: at
//! full redundancy across a hundred nodes an objective must settle for more
//! than **800,000** to cover the verification it asks for, and the cheap tiers
//! clear that floor with room to spare while the expensive ones do not.
//!
//! Until this module existed, all five minted the *same unit*. Two consequences,
//! and the second is the serious one:
//!
//! 1. **Gresham's law.** If a millisecond of certificate checking mints what a
//!    minute of Lean checking mints, a rational contributor never runs Lean.
//! 2. **Stake with no provenance.** Every bond in this crate — an availability
//!    undertaking, a dispute challenge, and now the stake
//!    [`crate::node::Node::custody_guard`] measures when it sizes a committee —
//!    is drawn from a balance. A balance earned by a cheap certificate mill is
//!    indistinguishable from one earned by expensive work, so an attacker
//!    manufactures standing on the tier that costs least and spends it where it
//!    counts most. Sizing a committee against members' stakes, which the commit
//!    before this one did, makes that attack *more* valuable rather than less.
//!
//! # What is typed, and what is not
//!
//! **Claim assets** — units minted by settling a claim — carry the tier of the
//! objective's verifier and cannot be spent in another tier. That is the whole
//! rule.
//!
//! **Genesis issuance is [`Tier::Universal`]** and spends anywhere. Not an
//! exemption: a network whose founding supply were typed could never fund its
//! first Lean objective, because the units to fund it could only come from
//! settling a Lean objective that nobody could fund. The reserve a log declares
//! at genesis is deliberately fungible; what work *pays out* is not.
//!
//! # Spending order
//!
//! A commitment in tier `T` draws from `T`'s units first and falls back to
//! universal ones. Typed-first rather than universal-first, and the difference
//! is not bookkeeping: universal units are the only ones that can cover any
//! tier, so spending them while typed units sit idle destroys optionality the
//! holder had. See [`crate::node::Node::spendable_in`].
//!
//! # What this does not do
//!
//! It defines no exchange rate and no ordering. A conversion between tiers,
//! however priced, is a route by which the cheapest tier sets the value of
//! every other one — which is the thing being prevented. Two tiers are simply
//! different assets that happen to share a ledger.

use std::fmt;

use crate::verifiers::Kind;

/// What a unit was earned for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Tier {
    /// Declared at genesis, spendable in any tier. The network's reserve.
    ///
    /// Ordered first so a `BTreeMap` keyed on `Tier` lists it before the earned
    /// tiers, which is the order a reader wants: what was granted, then what was
    /// worked for.
    Universal,
    /// Minted by settling a claim against a verifier of this kind.
    Earned(Kind),
}

impl Tier {
    /// The wire spelling. Consensus-relevant: it is what a balance is keyed on
    /// and what an audit compares.
    pub fn as_str(&self) -> &'static str {
        match self {
            Tier::Universal => "universal",
            Tier::Earned(kind) => kind.as_str(),
        }
    }

    pub fn parse(text: &str) -> Option<Tier> {
        match text {
            "universal" => Some(Tier::Universal),
            other => Kind::parse(other).map(Tier::Earned),
        }
    }

    /// The tier an objective with this verifier kind settles in.
    pub fn of_kind(kind: Kind) -> Tier {
        Tier::Earned(kind)
    }

    /// Whether a unit of this tier can be spent on a commitment in `wanted`.
    ///
    /// Universal spends anywhere; everything else spends only in itself. There
    /// is deliberately no third case: an ordering would imply a conversion, and
    /// a conversion is how the cheapest tier ends up pricing the dearest.
    pub fn covers(&self, wanted: Tier) -> bool {
        *self == Tier::Universal || *self == wanted
    }

    /// Every tier, universal first. Used by the audit to walk balances.
    pub fn all() -> Vec<Tier> {
        let mut out = vec![Tier::Universal];
        out.extend(Kind::ALL.iter().copied().map(Tier::Earned));
        out
    }
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What one identity holds, and what it has promised, per tier.
///
/// The arithmetic that makes typed units spendable at all. Commitments in a
/// tier are covered by that tier's holdings first and by universal units after,
/// so the question "can this identity afford one more unit in tier `T`" is not
/// answerable from `T`'s column alone — a commitment made in some *other* tier
/// may already have drawn on the universal pool they were both relying on.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ledger {
    held: std::collections::BTreeMap<Tier, u128>,
    committed: std::collections::BTreeMap<Tier, u128>,
}

impl Ledger {
    pub fn new() -> Ledger {
        Ledger::default()
    }

    pub fn credit(&mut self, tier: Tier, units: u128) {
        let slot = self.held.entry(tier).or_insert(0);
        *slot = slot.saturating_add(units);
    }

    pub fn commit(&mut self, tier: Tier, units: u128) {
        let slot = self.committed.entry(tier).or_insert(0);
        *slot = slot.saturating_add(units);
    }

    pub fn held(&self, tier: Tier) -> u128 {
        self.held.get(&tier).copied().unwrap_or(0)
    }

    pub fn committed(&self, tier: Tier) -> u128 {
        self.committed.get(&tier).copied().unwrap_or(0)
    }

    /// Everything held, across every tier. What `proofwork balances` printed
    /// before tiers existed, and what a total still means.
    pub fn total_held(&self) -> u128 {
        self.held
            .values()
            .fold(0u128, |sum, units| sum.saturating_add(*units))
    }

    pub fn total_committed(&self) -> u128 {
        self.committed
            .values()
            .fold(0u128, |sum, units| sum.saturating_add(*units))
    }

    /// How much of tier `T`'s commitment its own holdings cannot cover.
    ///
    /// The part that has to come out of the universal pool.
    fn deficit(&self, tier: Tier) -> u128 {
        if tier == Tier::Universal {
            return 0;
        }
        self.committed(tier).saturating_sub(self.held(tier))
    }

    /// Universal units already spoken for by *other* tiers' shortfalls, plus
    /// anything committed directly in universal.
    fn universal_drawn(&self) -> u128 {
        // Over the *union* of the two maps, deduplicated. A tier can appear in
        // both, and adding its deficit twice would report an identity as
        // insolvent for money it never promised.
        let mut seen: std::collections::BTreeSet<Tier> = std::collections::BTreeSet::new();
        let mut total = self.committed(Tier::Universal);
        for tier in self.held.keys().chain(self.committed.keys()) {
            if *tier == Tier::Universal || !seen.insert(*tier) {
                continue;
            }
            total = total.saturating_add(self.deficit(*tier));
        }
        total
    }

    /// What is still spendable in `tier`.
    ///
    /// `tier`'s own uncommitted units, plus whatever of the universal pool no
    /// other tier's shortfall has already claimed.
    pub fn spendable_in(&self, tier: Tier) -> u128 {
        let universal_left = self
            .held(Tier::Universal)
            .saturating_sub(self.universal_drawn());
        if tier == Tier::Universal {
            return universal_left;
        }
        let own = self.held(tier).saturating_sub(self.committed(tier));
        own.saturating_add(universal_left)
    }

    /// Is this identity solvent — are its promises covered by its holdings?
    ///
    /// The per-identity half of the conservation statement the audit makes.
    /// False means some unit has been promised twice, or promised and never
    /// held, which is money made by naming it with an extra step.
    pub fn solvent(&self) -> bool {
        self.universal_drawn() <= self.held(Tier::Universal)
    }

    /// Tiers this identity has any holding or promise in, universal first.
    pub fn tiers(&self) -> Vec<Tier> {
        let mut seen: std::collections::BTreeSet<Tier> = std::collections::BTreeSet::new();
        for tier in self.held.keys().chain(self.committed.keys()) {
            seen.insert(*tier);
        }
        seen.into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tier_round_trips_through_its_wire_spelling() {
        for tier in Tier::all() {
            assert_eq!(Tier::parse(tier.as_str()), Some(tier), "{tier}");
        }
        assert_eq!(Tier::parse("gold"), None);
        // Universal sorts first, so `balances` lists the reserve before the
        // tiers that were worked for.
        assert_eq!(Tier::all().first(), Some(&Tier::Universal));
    }

    #[test]
    fn universal_covers_everything_and_nothing_else_does() {
        for tier in Tier::all() {
            assert!(
                Tier::Universal.covers(tier),
                "universal did not cover {tier}"
            );
            assert!(tier.covers(tier));
            for other in Tier::all() {
                if other == tier || tier == Tier::Universal {
                    continue;
                }
                assert!(
                    !tier.covers(other),
                    "{tier} covered {other}; there is no exchange rate here"
                );
            }
        }
    }

    fn kind(name: &str) -> Tier {
        Tier::parse(name).expect("a known kind")
    }

    #[test]
    fn typed_units_are_spendable_only_in_their_own_tier() {
        let mut ledger = Ledger::new();
        ledger.credit(kind("certificate"), 1_000);
        assert_eq!(ledger.spendable_in(kind("certificate")), 1_000);
        assert_eq!(
            ledger.spendable_in(kind("lean")),
            0,
            "certificate earnings funded Lean work"
        );
        assert_eq!(ledger.total_held(), 1_000);
    }

    #[test]
    fn universal_units_fill_the_gap_in_any_tier() {
        let mut ledger = Ledger::new();
        ledger.credit(Tier::Universal, 500);
        ledger.credit(kind("certificate"), 100);
        assert_eq!(ledger.spendable_in(kind("certificate")), 600);
        assert_eq!(ledger.spendable_in(kind("lean")), 500);
        assert_eq!(ledger.spendable_in(Tier::Universal), 500);
    }

    /// The case the whole `Ledger` type exists for: universal units are shared,
    /// so spending them in one tier has to reduce what is spendable in another.
    /// A per-tier column that did not talk to its neighbours would report the
    /// same reserve as available twice.
    #[test]
    fn a_universal_unit_cannot_be_promised_to_two_tiers() {
        let mut ledger = Ledger::new();
        ledger.credit(Tier::Universal, 100);
        assert_eq!(ledger.spendable_in(kind("lean")), 100);
        assert_eq!(ledger.spendable_in(kind("replay")), 100);

        // Promise the whole reserve to Lean. Replay's column must move too.
        ledger.commit(kind("lean"), 100);
        assert_eq!(ledger.spendable_in(kind("lean")), 0);
        assert_eq!(
            ledger.spendable_in(kind("replay")),
            0,
            "the same reserve was offered to two tiers"
        );
        assert!(ledger.solvent());

        // One more unit anywhere and it is not.
        ledger.commit(kind("replay"), 1);
        assert!(!ledger.solvent(), "an overdraft went unreported");
    }

    #[test]
    fn typed_holdings_are_spent_before_the_reserve() {
        let mut ledger = Ledger::new();
        ledger.credit(Tier::Universal, 100);
        ledger.credit(kind("certificate"), 100);
        // A hundred of certificate work, covered entirely by certificate units.
        ledger.commit(kind("certificate"), 100);
        assert_eq!(ledger.spendable_in(kind("certificate")), 100);
        assert_eq!(
            ledger.spendable_in(kind("lean")),
            100,
            "the reserve was spent on work the typed units already covered"
        );
        assert!(ledger.solvent());
    }

    #[test]
    fn a_promise_with_nothing_behind_it_is_insolvent() {
        let mut ledger = Ledger::new();
        ledger.commit(kind("lean"), 1);
        assert!(!ledger.solvent());
        assert_eq!(ledger.spendable_in(kind("lean")), 0);
    }
}
