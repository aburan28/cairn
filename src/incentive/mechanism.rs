//! proofwork's node game, written down.
//!
//! Three sub-games, one per service, each in the representation that suits it.
//! All payoffs are **marginal**: the cost of running a node at all
//! ([`NodeParams::fixed_cost`]) is sunk with respect to every choice here and
//! appears only in the participation constraint. Conflating the two is the
//! standard way a mechanism comes out looking incentive-compatible because it is
//! expensive, and it hides the fact that the two constraints are fixed by
//! different knobs -- which is the most useful thing this module has to say:
//!
//! > **The size of the reward pool decides how many nodes there are. It has no
//! > effect whatever on whether they do the work.**
//!
//! The pool share cancels out of every honest-versus-lazy comparison below,
//! because a rubber-stamping node collects it too. Only the slash, the catch
//! bounty and the canary rate move that comparison. Paying operators more is
//! therefore an answer to "nobody is running nodes" and never an answer to
//! "nobody is checking anything", and a design that reaches for it in the second
//! case is buying nothing.

use super::exact::Rat;
use super::game::{Sybil, Symmetric};
use super::{NodeParams, ParamError};

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// What an operator does with an artifact it has been sampled to check.
///
/// Four actions, not two. The two-action version -- check or do not check --
/// hides the attack that matters: there are *two* ways to attest without
/// looking, and they need different defences.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Attest {
    /// Re-run the pinned verifier and report what it said.
    Verify,
    /// Accept without running anything. The cheap lie, and the dangerous one:
    /// nobody is harmed *visibly*, so nobody is motivated to catch it.
    Stamp,
    /// Reject without running anything. The other cheap lie, and the harmless
    /// one -- it takes money from a submitter, and the submitter will dispute
    /// it. See [`Verification::payoff`].
    Reject,
    /// Run a node, but attest to nothing.
    Abstain,
}

impl Attest {
    pub const ALL: [Attest; 4] = [
        Attest::Verify,
        Attest::Stamp,
        Attest::Reject,
        Attest::Abstain,
    ];

    pub fn index(self) -> usize {
        match self {
            Attest::Verify => 0,
            Attest::Stamp => 1,
            Attest::Reject => 2,
            Attest::Abstain => 3,
        }
    }

    pub fn from_index(index: usize) -> Option<Attest> {
        Attest::ALL.get(index).copied()
    }

    pub fn name(self) -> &'static str {
        match self {
            Attest::Verify => "verify",
            Attest::Stamp => "rubber-stamp",
            Attest::Reject => "reject-blind",
            Attest::Abstain => "abstain",
        }
    }
}

/// The verifier's dilemma, as `n` interchangeable operators.
///
/// # The payoffs, and where each term comes from
///
/// Write `k` for the number of nodes attesting at all, `v` for the number
/// actually verifying, `q` for the effective canary rate, `g` for the fraction
/// of canaries that are valid, `p` for the genuine fraud rate, `R` for the
/// verification pool, `S'` for the slashable stake and `beta` for the catch
/// bounty.
///
/// ```text
/// verify   R/k - cost + (q(1-g) + p) * beta/v
/// stamp    R/k        - S' * (q(1-g) + p * [v > 0])
/// reject   R/k        - S' * (q*g + (1 - q - p))
/// abstain  0
/// ```
///
/// Four things in that table are load-bearing.
///
/// **`R/k` appears identically in three rows.** A rubber-stamper is paid the
/// same as a verifier, because the mechanism cannot tell them apart -- that is
/// the whole problem, stated in algebra. So it cancels, and the pool size is
/// irrelevant to the honest-versus-lazy comparison.
///
/// **`p * [v > 0]` is the indicator that ruins everything.** A stamper is
/// punished for accepting a genuinely invalid artifact only if somebody else
/// proves it invalid, which requires somebody else to have verified. At `v = 0`
/// the term vanishes, so universal rubber-stamping is a Nash equilibrium *at any
/// slash rate*. This is not a parameter to tune, it is a fixed point to escape;
/// `everybody_stamping_is_an_equilibrium_at_any_slash` proves it holds for
/// slashes up to the entire modelling range.
///
/// **`q(1-g)` has no such indicator.** A canary's verdict is known to the
/// protocol in advance, so slashing on one is unconditional and survives `v = 0`.
/// That single difference is what moves the equilibrium, and it is why
/// [`super::design::minimum_canary_rate`] exists.
///
/// **The `reject` row needs no canary at all** beyond the valid ones. A blind
/// rejection denies a submitter their bounty, and the submitter -- unlike every
/// other party in this game -- is strictly motivated to re-run the verifier and
/// dispute it. So the `(1 - q - p)` term, wrongful rejections of real valid
/// work, is punished at essentially rate one. False rejections police
/// themselves; false acceptances do not. Every mechanism here is downstream of
/// that asymmetry.
///
/// # What the model leaves out
///
/// Every node is sampled onto the same artifact, so "somebody else verified"
/// means `v > 0` exactly. Under real sampling, a stamper is caught only if a
/// verifier drew the same item, which *weakens* the conditional term further and
/// makes the canary argument stronger, not weaker. Modelling full redundancy is
/// therefore the conservative choice.
pub struct Verification<'a> {
    params: &'a NodeParams,
}

impl<'a> Verification<'a> {
    pub fn new(params: &'a NodeParams) -> Result<Verification<'a>, ParamError> {
        params.validate()?;
        Ok(Verification { params })
    }

    pub fn params(&self) -> &NodeParams {
        self.params
    }

    /// Rate at which a rubber-stamper meets an artifact the protocol *knows* is
    /// invalid: the effective canary rate times the invalid share of canaries.
    ///
    /// The whole deterrent against [`Attest::Stamp`], in one number.
    pub fn stamp_deterrent(&self) -> Rat {
        self.params.effective_canary_rate() * (Rat::ONE - self.params.canary_valid_share)
    }

    /// Rate at which a blind rejecter meets an artifact the protocol knows is
    /// valid.
    pub fn reject_deterrent(&self) -> Rat {
        self.params.effective_canary_rate() * self.params.canary_valid_share
    }

    /// Payoff to a node that verifies, given how many others do.
    ///
    /// Split out because [`super::design`] solves against it directly, and a
    /// solver that reconstructs the payoff from counts would be a second copy of
    /// this algebra that could drift from the first.
    pub fn verify_payoff(&self, attesters: u32, verifiers: u32) -> Rat {
        let bounty_rate = self.stamp_deterrent() + self.params.fraud_rate;
        self.pool_share(attesters) - Rat::units(self.params.verify_cost)
            + bounty_rate
                * Rat::units(self.params.catch_bounty)
                    .share(verifiers)
                    .unwrap_or(Rat::ZERO)
    }

    /// Payoff to a node that accepts without checking.
    ///
    /// `others_verifying` is deliberately the count *excluding* this node: the
    /// conditional slash depends on somebody else having looked, and passing the
    /// total here is the off-by-one that would silently make the mechanism look
    /// sound.
    pub fn stamp_payoff(&self, attesters: u32, others_verifying: u32) -> Rat {
        let caught = self.stamp_deterrent()
            + if others_verifying > 0 {
                self.params.fraud_rate
            } else {
                Rat::ZERO
            };
        self.pool_share(attesters) - self.params.slash() * caught
    }

    /// Payoff to a node that rejects without checking.
    pub fn reject_payoff(&self, attesters: u32) -> Rat {
        let genuine_valid = Rat::ONE - self.params.effective_canary_rate() - self.params.fraud_rate;
        let caught = self.reject_deterrent() + genuine_valid;
        self.pool_share(attesters) - self.params.slash() * caught
    }

    fn pool_share(&self, attesters: u32) -> Rat {
        self.params
            .verify_pool()
            .share(attesters)
            .unwrap_or(Rat::ZERO)
    }
}

impl Symmetric for Verification<'_> {
    fn actions(&self) -> usize {
        Attest::ALL.len()
    }

    fn population(&self) -> u32 {
        self.params.nodes
    }

    fn payoff(&self, own: usize, others: &[u32]) -> Rat {
        let own = match Attest::from_index(own) {
            Some(action) => action,
            // Unreachable through the solvers, which only pass indices they got
            // from `actions()`. Abstention is the payoff-zero answer, which is
            // the one that cannot mislead a report.
            None => return Rat::ZERO,
        };
        let others_verifying = others.get(Attest::Verify.index()).copied().unwrap_or(0);
        let others_attesting = others_verifying
            + others.get(Attest::Stamp.index()).copied().unwrap_or(0)
            + others.get(Attest::Reject.index()).copied().unwrap_or(0);
        let attesting = others_attesting + if own == Attest::Abstain { 0 } else { 1 };
        match own {
            Attest::Verify => self.verify_payoff(attesting, others_verifying + 1),
            Attest::Stamp => self.stamp_payoff(attesting, others_verifying),
            Attest::Reject => self.reject_payoff(attesting),
            Attest::Abstain => Rat::ZERO,
        }
    }

    fn action_name(&self, action: usize) -> String {
        Attest::from_index(action)
            .map(|a| a.name().to_string())
            .unwrap_or_else(|| format!("a{action}"))
    }
}

// ---------------------------------------------------------------------------
// Availability
// ---------------------------------------------------------------------------

/// Whether an operator actually keeps the log it is paid to keep.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Serve {
    /// Store the log and answer challenges against it.
    Store,
    /// Collect the pool share and hope nobody asks.
    Freeload,
}

impl Serve {
    pub const ALL: [Serve; 2] = [Serve::Store, Serve::Freeload];

    pub fn index(self) -> usize {
        match self {
            Serve::Store => 0,
            Serve::Freeload => 1,
        }
    }

    pub fn from_index(index: usize) -> Option<Serve> {
        Serve::ALL.get(index).copied()
    }

    pub fn name(self) -> &'static str {
        match self {
            Serve::Store => "store",
            Serve::Freeload => "freeload",
        }
    }
}

/// Storage, which is the easy one -- and worth reading for *why* it is easy.
///
/// ```text
/// store     R/n - storage_cost
/// freeload  (1-a) * R/n - a * S'
/// ```
///
/// A challenge asks for a Merkle path from a random leaf to a root the protocol
/// already published ([`crate::canonical::merkle_root`]). The protocol knows the
/// right answer, so a node that cannot produce the path has proved something
/// about itself, unconditionally and without anyone else's cooperation. No
/// canaries are needed here for the same reason they *are* needed for
/// verification: **the ground truth already exists.**
///
/// The failure mode is not incentive-compatibility, it is arithmetic: the
/// challenge rate `a` has to clear `storage_cost / (R/n + S')`. A node cheap to
/// challenge and expensive to audit is a node that stops storing.
pub struct Availability<'a> {
    params: &'a NodeParams,
}

impl<'a> Availability<'a> {
    pub fn new(params: &'a NodeParams) -> Result<Availability<'a>, ParamError> {
        params.validate()?;
        Ok(Availability { params })
    }

    pub fn store_payoff(&self, claimants: u32) -> Rat {
        self.pool_share(claimants) - Rat::units(self.params.storage_cost)
    }

    pub fn freeload_payoff(&self, claimants: u32) -> Rat {
        let audit = self.params.audit_rate;
        (Rat::ONE - audit) * self.pool_share(claimants) - audit * self.params.slash()
    }

    fn pool_share(&self, claimants: u32) -> Rat {
        self.params
            .availability_pool()
            .share(claimants)
            .unwrap_or(Rat::ZERO)
    }
}

impl Symmetric for Availability<'_> {
    fn actions(&self) -> usize {
        Serve::ALL.len()
    }

    fn population(&self) -> u32 {
        self.params.nodes
    }

    fn payoff(&self, own: usize, others: &[u32]) -> Rat {
        // Everyone claims a share, honestly or not, so the denominator is the
        // whole population however the counts fall.
        let claimants = others.iter().copied().sum::<u32>() + 1;
        match Serve::from_index(own) {
            Some(Serve::Store) => self.store_payoff(claimants),
            Some(Serve::Freeload) => self.freeload_payoff(claimants),
            None => Rat::ZERO,
        }
    }

    fn action_name(&self, action: usize) -> String {
        Serve::from_index(action)
            .map(|a| a.name().to_string())
            .unwrap_or_else(|| format!("a{action}"))
    }
}

// ---------------------------------------------------------------------------
// Custody
// ---------------------------------------------------------------------------

/// What a committee member does with the Shamir share it holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Share {
    /// Publish at epoch end, as designed.
    Publish,
    /// Never publish. If enough members do this the submission never opens, the
    /// submitter is never paid, and a rival wins the bounty: censorship,
    /// executed by the committee that exists to prevent it.
    Withhold,
    /// Pool shares with other members before epoch end and reconstruct early.
    /// Reaching the threshold opens the envelope while the artifact is still
    /// worth front-running.
    OpenEarly,
}

impl Share {
    pub const ALL: [Share; 3] = [Share::Publish, Share::Withhold, Share::OpenEarly];

    pub fn index(self) -> usize {
        match self {
            Share::Publish => 0,
            Share::Withhold => 1,
            Share::OpenEarly => 2,
        }
    }

    pub fn from_index(index: usize) -> Option<Share> {
        Share::ALL.get(index).copied()
    }

    pub fn name(self) -> &'static str {
        match self {
            Share::Publish => "publish",
            Share::Withhold => "withhold",
            Share::OpenEarly => "open-early",
        }
    }
}

/// The `t`-of-`n` committee from [`crate::sealed`], and the vice it sits in.
///
/// ```text
/// publish     [opened] * r - publish_cost
/// withhold    -S' + [not opened] * V/withholders
/// open-early  [opened] * r - publish_cost + [cartel >= t] * (V/cartel - d * S')
/// ```
///
/// Two attacks live in one game and they pull the threshold in opposite
/// directions:
///
/// - **Open early.** Any `t` members can reconstruct the key before the epoch
///   ends and front-run the submission. It takes `t` colluders, so raising `t`
///   makes it harder.
/// - **Withhold.** Any `n - t + 1` members can make reconstruction impossible,
///   denying the submitter the bounty their rival then collects. It takes
///   `n - t + 1` colluders, so raising `t` makes it *easier*.
///
/// There is therefore a window of thresholds where neither attack pays, and for
/// a committee that is too small relative to the value it guards, the window is
/// empty. [`super::design::committee_window`] computes it, and the closed form
/// it must agree with is derived there.
///
/// The third asymmetry, and the reason liveness is the cheap half of this: a
/// share that never appears **names its holder**, because the shares were
/// committed in advance. Withholding is attributable and slashable on the spot.
/// Opening early is invisible -- the cartel learns a secret, and nothing about
/// the log changes -- so it can only be punished at some detection rate `d < 1`,
/// which is why the stake condition carries a `d` and the withholding one does
/// not.
pub struct Custody<'a> {
    params: &'a NodeParams,
}

impl<'a> Custody<'a> {
    pub fn new(params: &'a NodeParams) -> Result<Custody<'a>, ParamError> {
        params.validate()?;
        Ok(Custody { params })
    }

    /// Fee paid to one member for publishing its share on time.
    pub fn publication_fee(&self) -> Rat {
        self.params
            .custody_pool()
            .share(self.params.committee)
            .unwrap_or(Rat::ZERO)
    }

    /// Payoff to a member that publishes, given whether the envelope opened.
    pub fn publish_payoff(&self, opened: bool) -> Rat {
        let earned = if opened {
            self.publication_fee()
        } else {
            Rat::ZERO
        };
        earned - Rat::units(self.params.publish_cost)
    }

    /// Payoff to a member that withholds its share.
    pub fn withhold_payoff(&self, opened: bool, withholders: u32) -> Rat {
        let stolen = if opened {
            Rat::ZERO
        } else {
            Rat::units(self.params.sealed_value)
                .share(withholders)
                .unwrap_or(Rat::ZERO)
        };
        stolen - self.params.slash()
    }

    /// Payoff to a member of an early-opening cartel of size `cartel`.
    pub fn open_early_payoff(&self, opened: bool, cartel: u32) -> Rat {
        let gain = if cartel >= self.params.threshold {
            Rat::units(self.params.sealed_value)
                .share(cartel)
                .unwrap_or(Rat::ZERO)
                - self.params.detection_rate * self.params.slash()
        } else {
            // Below the threshold a cartel member behaves exactly like an
            // honest one and learns nothing. Joining is *free*, which is the
            // uncomfortable part: a cartel can assemble by drift and only
            // becomes profitable, discontinuously, at the threshold.
            Rat::ZERO
        };
        self.publish_payoff(opened) + gain
    }
}

impl Symmetric for Custody<'_> {
    fn actions(&self) -> usize {
        Share::ALL.len()
    }

    fn population(&self) -> u32 {
        self.params.committee
    }

    fn payoff(&self, own: usize, others: &[u32]) -> Rat {
        let own = match Share::from_index(own) {
            Some(action) => action,
            None => return Rat::ZERO,
        };
        let others_publishing = others.get(Share::Publish.index()).copied().unwrap_or(0);
        let others_withholding = others.get(Share::Withhold.index()).copied().unwrap_or(0);
        let others_early = others.get(Share::OpenEarly.index()).copied().unwrap_or(0);
        // An early-opening member still publishes at epoch end: it has already
        // extracted its value and has no reason to forfeit stake as well.
        let publishing =
            others_publishing + others_early + if own == Share::Withhold { 0 } else { 1 };
        let opened = publishing >= self.params.threshold;
        match own {
            Share::Publish => self.publish_payoff(opened),
            Share::Withhold => self.withhold_payoff(opened, others_withholding + 1),
            Share::OpenEarly => self.open_early_payoff(opened, others_early + 1),
        }
    }

    fn action_name(&self, action: usize) -> String {
        Share::from_index(action)
            .map(|a| a.name().to_string())
            .unwrap_or_else(|| format!("a{action}"))
    }
}

// ---------------------------------------------------------------------------
// Sybil
// ---------------------------------------------------------------------------

/// How a service pool is divided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RewardRule {
    /// Evenly, one share per node.
    PerNode,
    /// In proportion to stake.
    PerStake,
}

impl RewardRule {
    pub fn name(self) -> &'static str {
        match self {
            RewardRule::PerNode => "even per-node split",
            RewardRule::PerStake => "stake-weighted split",
        }
    }
}

/// One operator, fixed real resources, choosing how many identities to wear.
///
/// Sybil resistance is not a property of a strategy profile, so it does not
/// belong in the games above: it is a property of the map from resources to
/// payoff. The operator's stake and its verification budget are held constant
/// and only the identity count varies, which is exactly the choice a real
/// operator faces and exactly the one an even split gets wrong.
pub struct SplitIdentities<'a> {
    params: &'a NodeParams,
    rule: RewardRule,
    pool: Rat,
}

impl<'a> SplitIdentities<'a> {
    /// Against the verification pool, under `rule` -- which may deliberately
    /// differ from [`NodeParams::reward_rule`], so a report can price the rule
    /// it did *not* choose.
    pub fn verification(
        params: &'a NodeParams,
        rule: RewardRule,
    ) -> Result<SplitIdentities<'a>, ParamError> {
        params.validate()?;
        Ok(SplitIdentities {
            params,
            rule,
            pool: params.verify_pool(),
        })
    }
}

impl Sybil for SplitIdentities<'_> {
    fn payoff_with(&self, identities: u32) -> Rat {
        let identities = identities.max(1);
        // The rest of the network is unchanged; this operator replaces its one
        // identity with `identities` of them, each holding `stake/identities`.
        let others = self.params.nodes.saturating_sub(1);
        let earned = match self.rule {
            RewardRule::PerNode => {
                let total = others.saturating_add(identities);
                self.pool.share(total).unwrap_or(Rat::ZERO) * Rat::int(i64::from(identities))
            }
            // Stake is conserved by splitting, so a stake-weighted share is
            // exactly invariant. That invariance is the whole property.
            RewardRule::PerStake => {
                let mine = Rat::units(self.params.stake);
                let network = mine * Rat::int(i64::from(self.params.nodes.max(1)));
                self.pool * mine / network
            }
        };
        // Each identity is sampled separately, so each one pays to check.
        earned - Rat::units(self.params.verify_cost) * Rat::int(i64::from(identities))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::incentive::game::{
        everyone, invasion, sybil_gain, symmetric_equilibria, symmetric_stability, Invades,
        Stability,
    };
    use crate::incentive::MAX_UNITS;

    fn reference() -> NodeParams {
        NodeParams::reference()
    }

    fn counts(game: &dyn Symmetric, pairs: &[(usize, u32)]) -> Vec<u32> {
        let mut counts = vec![0u32; game.actions()];
        for (action, count) in pairs {
            counts[*action] = *count;
        }
        counts
    }

    // -- verification -------------------------------------------------------

    #[test]
    fn the_pool_share_cancels_out_of_the_honest_versus_lazy_comparison() {
        // The claim in the module docs, made mechanical: multiply the pool by
        // forty and the gap between verifying and stamping does not move.
        let small = reference();
        let large = NodeParams {
            settled_value: small.settled_value * 40,
            ..small.clone()
        };
        let gap = |params: &NodeParams| {
            let game = Verification::new(params).expect("validated");
            game.verify_payoff(params.nodes, params.nodes)
                - game.stamp_payoff(params.nodes, params.nodes - 1)
        };
        assert_eq!(gap(&small), gap(&large));
        assert!(
            large.verify_pool() > small.verify_pool(),
            "the pools really do differ"
        );
    }

    #[test]
    fn everybody_stamping_is_an_equilibrium_at_any_slash_when_there_are_no_canaries() {
        // The structural result. Remove canaries and the punishment for
        // rubber-stamping is conditional on somebody else looking; if nobody
        // looks, nobody is punished, and no amount of stake changes that.
        for stake in [1_000u64, 1_000_000, 1_000_000_000, MAX_UNITS] {
            let params = NodeParams {
                canary_rate: Rat::ZERO,
                stake,
                slash_rate: Rat::ONE,
                ..reference()
            };
            let game = Verification::new(&params).expect("validated");
            let all_stamp = everyone(&game, Attest::Stamp.index());
            assert_eq!(
                symmetric_stability(&game, &all_stamp).expect("valid counts"),
                Some(Stability::Strict),
                "universal rubber-stamping survives a slash of {stake}"
            );
        }
    }

    #[test]
    fn canaries_are_what_break_the_rubber_stamp_equilibrium() {
        // Same network, same slash, canaries switched on: the equilibrium goes.
        let params = NodeParams {
            canary_rate: Rat::rate(1, 100).expect("a valid rate"),
            canary_leak: Rat::ZERO,
            ..reference()
        };
        let game = Verification::new(&params).expect("validated");
        let all_stamp = everyone(&game, Attest::Stamp.index());
        assert_eq!(
            symmetric_stability(&game, &all_stamp).expect("valid counts"),
            None
        );
        let all_verify = everyone(&game, Attest::Verify.index());
        assert_eq!(
            symmetric_stability(&game, &all_verify).expect("valid counts"),
            Some(Stability::Strict)
        );
    }

    #[test]
    fn the_reference_network_verifies_and_repels_every_size_of_defection() {
        let params = reference();
        let game = Verification::new(&params).expect("validated");
        let all_verify = everyone(&game, Attest::Verify.index());
        assert_eq!(
            symmetric_stability(&game, &all_verify).expect("valid counts"),
            Some(Stability::Strict)
        );
        assert_eq!(
            invasion(
                &game,
                Attest::Verify.index(),
                params.nodes,
                Invades::WeaklyBetter
            )
            .expect("valid resident"),
            None,
            "no coalition of any size gains by defecting together"
        );
    }

    #[test]
    fn blind_rejection_is_dominated_because_the_submitter_disputes_it() {
        // No canary is needed to punish this one: the party who loses money is
        // motivated to re-run the verifier, which nobody is for an acceptance.
        let params = reference();
        let game = Verification::new(&params).expect("validated");
        for attesters in [1u32, 2, 50, params.nodes] {
            assert!(
                game.reject_payoff(attesters) < game.verify_payoff(attesters, attesters),
                "blind rejection beat verification at {attesters} attesters"
            );
            assert!(
                game.reject_payoff(attesters) < game.stamp_payoff(attesters, attesters - 1),
                "blind rejection beat rubber-stamping at {attesters} attesters"
            );
        }
    }

    #[test]
    fn a_fully_leaky_canary_leaves_the_bad_equilibrium_standing() {
        // The engineering assumption stated as a payoff: canaries a node can
        // recognise are worth precisely nothing.
        let params = NodeParams {
            canary_leak: Rat::ONE,
            ..reference()
        };
        let game = Verification::new(&params).expect("validated");
        assert_eq!(game.stamp_deterrent(), Rat::ZERO);
        assert_eq!(
            symmetric_stability(&game, &everyone(&game, Attest::Stamp.index()))
                .expect("valid counts"),
            Some(Stability::Strict)
        );
    }

    #[test]
    fn a_more_honest_network_is_a_less_verified_one_without_canaries() {
        // The perverse comparative static, and the reason bounty-only schemes
        // fail exactly where they look least necessary: with no canaries the
        // only reason to check is the chance of catching real fraud, so the
        // rarer fraud is, the weaker the incentive to look for it.
        let honest = NodeParams {
            canary_rate: Rat::ZERO,
            fraud_rate: Rat::rate(1, 100_000).expect("a valid rate"),
            ..reference()
        };
        let crooked = NodeParams {
            canary_rate: Rat::ZERO,
            fraud_rate: Rat::rate(1, 10).expect("a valid rate"),
            ..reference()
        };
        let incentive = |params: &NodeParams| {
            let game = Verification::new(params).expect("validated");
            // What a lone verifier gains over stamping when nobody else checks.
            game.verify_payoff(params.nodes, 1) - game.stamp_payoff(params.nodes, 0)
        };
        assert!(incentive(&honest) < incentive(&crooked));
        assert!(
            incentive(&honest).is_negative(),
            "in an honest network nobody bothers to check"
        );
    }

    #[test]
    fn abstention_beats_attesting_when_the_pool_cannot_cover_the_cost() {
        let params = NodeParams {
            settled_value: 0,
            ..reference()
        };
        let game = Verification::new(&params).expect("validated");
        let equilibria = symmetric_equilibria(&game).expect("small enough");
        assert!(
            equilibria
                .iter()
                .all(|(counts, _)| counts[Attest::Verify.index()] < params.nodes),
            "an unfunded network does not verify"
        );
    }

    // -- availability -------------------------------------------------------

    #[test]
    fn storing_is_strictly_dominant_when_the_audit_rate_clears_the_cost() {
        let params = reference();
        let game = Availability::new(&params).expect("validated");
        let all_store = everyone(&game, Serve::Store.index());
        assert_eq!(
            symmetric_stability(&game, &all_store).expect("valid counts"),
            Some(Stability::Strict)
        );
        // And unlike verification, it needs no canary and no coordination:
        // the payoff does not depend on what anyone else does.
        assert_eq!(
            invasion(
                &game,
                Serve::Store.index(),
                params.nodes,
                Invades::WeaklyBetter
            )
            .expect("valid resident"),
            None
        );
    }

    #[test]
    fn nobody_stores_when_challenges_are_too_rare() {
        let params = NodeParams {
            audit_rate: Rat::ZERO,
            ..reference()
        };
        let game = Availability::new(&params).expect("validated");
        assert_eq!(
            symmetric_stability(&game, &everyone(&game, Serve::Freeload.index()))
                .expect("valid counts"),
            Some(Stability::Strict)
        );
        assert_eq!(
            symmetric_stability(&game, &everyone(&game, Serve::Store.index()))
                .expect("valid counts"),
            None
        );
    }

    // -- custody ------------------------------------------------------------

    #[test]
    fn the_custody_equilibrium_is_weak_and_cannot_be_made_strict() {
        // Not a slack parameter -- a fact about threshold cryptography. A
        // committee member that has agreed to open early but whose cartel has
        // not reached `t` does exactly what an honest member does and is paid
        // exactly what an honest member is paid. There is no observable to
        // punish, so the honest profile is a *weak* equilibrium at every
        // parameter set, and no amount of stake changes it.
        //
        // What the stake buys is the next rung: no group that reaches the
        // threshold profits, which is what `defection` checks.
        let params = reference();
        let game = Custody::new(&params).expect("validated");
        assert_eq!(
            symmetric_stability(&game, &everyone(&game, Share::Publish.index()))
                .expect("valid counts"),
            Some(Stability::Weak)
        );
        assert_eq!(
            invasion(
                &game,
                Share::Publish.index(),
                params.committee,
                Invades::StrictlyBetter
            )
            .expect("valid resident"),
            None,
            "the reference bond makes both committee attacks unprofitable"
        );
        // Raising the bond tenfold does not promote the equilibrium to strict.
        let fortified = NodeParams {
            stake: params.stake * 10,
            ..params
        };
        let game = Custody::new(&fortified).expect("validated");
        assert_eq!(
            symmetric_stability(&game, &everyone(&game, Share::Publish.index()))
                .expect("valid counts"),
            Some(Stability::Weak)
        );
    }

    #[test]
    fn a_cartel_of_exactly_the_threshold_is_what_opens_early() {
        // Stake deliberately too small to deter it, so the solver has something
        // to find: V = 2_000_000 against t*d*S' = 11 * 1/2 * 10_000 = 55_000.
        let params = NodeParams {
            stake: 100_000,
            ..reference()
        };
        let game = Custody::new(&params).expect("validated");
        let found = invasion(
            &game,
            Share::Publish.index(),
            params.committee,
            Invades::StrictlyBetter,
        )
        .expect("valid resident")
        .expect("an under-staked committee is corruptible");
        assert_eq!(found.mutant, Share::OpenEarly.index());
        assert_eq!(
            found.mutants, params.threshold,
            "the cartel is exactly threshold-sized: no smaller one gains, and a larger one splits the same loot further"
        );
    }

    #[test]
    fn joining_a_sub_threshold_cartel_is_free_which_is_the_uncomfortable_part() {
        // Below `t`, an early-opening member is indistinguishable from an
        // honest one and earns exactly the same. There is no penalty for
        // standing ready to collude, so the cartel can assemble at zero cost
        // and only becomes profitable, discontinuously, at the threshold.
        let params = NodeParams {
            stake: 100_000,
            ..reference()
        };
        let game = Custody::new(&params).expect("validated");
        let drift = invasion(
            &game,
            Share::Publish.index(),
            params.threshold - 1,
            Invades::WeaklyBetter,
        )
        .expect("valid resident")
        .expect("drift into a cartel is free");
        assert_eq!(drift.mutants, 1);
        assert_eq!(drift.gain, Rat::ZERO);
    }

    #[test]
    fn enough_stake_makes_early_opening_unprofitable_at_every_cartel_size() {
        // t * d * S' > V: 11 * 1/2 * (40_000_000 / 10) = 22_000_000 > 2_000_000.
        let params = NodeParams {
            stake: 40_000_000,
            ..reference()
        };
        let game = Custody::new(&params).expect("validated");
        assert_eq!(
            invasion(
                &game,
                Share::Publish.index(),
                params.committee,
                Invades::StrictlyBetter
            )
            .expect("valid resident"),
            None
        );
    }

    #[test]
    fn withholding_censors_the_submission_when_enough_members_do_it() {
        let params = NodeParams {
            stake: 10_000,
            ..reference()
        };
        let game = Custody::new(&params).expect("validated");
        // n - t + 1 = 21 - 11 + 1 = 11 withholders make reconstruction
        // impossible, and the bounty their rival collects is worth more than
        // the stake they forfeit.
        let blocking = params.committee - params.threshold + 1;
        let others = counts(
            &game,
            &[
                (Share::Publish.index(), params.committee - blocking),
                (Share::Withhold.index(), blocking - 1),
            ],
        );
        assert!(game.payoff(Share::Withhold.index(), &others).is_positive());
        let one_fewer = counts(
            &game,
            &[
                (Share::Publish.index(), params.committee - blocking + 1),
                (Share::Withhold.index(), blocking - 2),
            ],
        );
        assert!(
            game.payoff(Share::Withhold.index(), &one_fewer)
                .is_negative(),
            "a cartel one short of blocking just loses its stake"
        );
    }

    #[test]
    fn raising_the_threshold_trades_one_attack_for_the_other() {
        // The vice, demonstrated: at every stake there is a threshold at which
        // early opening stops paying and a (lower) one above which withholding
        // starts.
        let params = NodeParams {
            stake: 300_000,
            ..reference()
        };
        let corruptible = |threshold: u32| {
            let params = NodeParams {
                threshold,
                ..params.clone()
            };
            let game = Custody::new(&params).expect("validated");
            invasion(
                &game,
                Share::Publish.index(),
                params.committee,
                Invades::StrictlyBetter,
            )
            .expect("valid resident")
            .map(|found| found.mutant)
        };
        assert_eq!(
            corruptible(4),
            Some(Share::OpenEarly.index()),
            "a low threshold is cheap to reach"
        );
        assert_eq!(
            corruptible(20),
            Some(Share::Withhold.index()),
            "a high threshold is cheap to block"
        );
    }

    // -- sybil --------------------------------------------------------------

    #[test]
    fn an_even_pool_split_pays_for_identities_rather_than_for_work() {
        let params = reference();
        let model = SplitIdentities::verification(&params, RewardRule::PerNode).expect("validated");
        let result = sybil_gain(&model, 50);
        assert!(result.best > 1, "splitting pays");
        assert!(result.gain.is_positive());
    }

    #[test]
    fn a_stake_weighted_split_is_exactly_sybil_neutral() {
        let params = reference();
        let model =
            SplitIdentities::verification(&params, RewardRule::PerStake).expect("validated");
        let result = sybil_gain(&model, 50);
        assert_eq!(result.best, 1);
        assert_eq!(result.gain, Rat::ZERO);
        // Neutral on the revenue side and strictly worse on the cost side: each
        // identity is sampled and each sample must be checked.
        assert!(model.payoff_with(2) < model.payoff_with(1));
    }
}
