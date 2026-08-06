//! The inverse question: what has to be true for honesty to be the equilibrium.
//!
//! Checking a parameter set is the easy direction and the less useful one. A
//! designer does not have a canary rate and want to know if it works; they have
//! a verification cost they cannot change, a fraud rate they cannot control, and
//! a budget, and they want the smallest canary rate, bond and committee that
//! close the gap. Every function here answers that direction.
//!
//! Two techniques, chosen per constraint:
//!
//! - **Closed form** where the payoff algebra inverts cleanly, as it does for
//!   the canary and audit rates. Exact rationals mean the answer is the true
//!   infimum rather than a bracket around it.
//! - **Bisection on a monotone predicate** where it does not, as for stake and
//!   committee thresholds. The predicate is the *solver* running against the
//!   real payoff functions, so the answer cannot drift from the mechanism the
//!   way a re-derived formula can.
//!
//! Where both are available they are cross-checked against each other --
//! `the_closed_form_agrees_with_the_solver` is the test, and it is the reason to
//! trust either.
//!
//! # A note on strictness
//!
//! Every threshold below is an **infimum of a strict inequality**. At exactly
//! the reported canary rate the honest profile is a *weak* equilibrium: nobody
//! gains by rubber-stamping, and nobody loses either. Design above the number,
//! not at it. `at_the_threshold_the_equilibrium_is_only_weak` pins that
//! behaviour, because it is the kind of off-by-an-epsilon that a float-based
//! harness could not even express.

use std::fmt;

use super::dynamics::tipping_point;
use super::exact::Rat;
use super::game::{
    everyone, invasion, sybil_gain, symmetric_equilibria, Counts, GameError, Invades, Invasion,
    Stability, Symmetric,
};
use super::mechanism::{
    Attest, Availability, Custody, RewardRule, Serve, Share, SplitIdentities, Verification,
};
use super::{NodeParams, ParamError, MAX_UNITS};

/// Steps a population is given to settle before a report gives up on it.
const SETTLE_STEPS: usize = 100_000;

/// Rival equilibria a report will name before it stops listing them.
const MAX_RIVALS: usize = 8;

/// Anything that stops a report being produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DesignError {
    Params(ParamError),
    Game(GameError),
}

impl fmt::Display for DesignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DesignError::Params(error) => write!(f, "{error}"),
            DesignError::Game(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for DesignError {}

impl From<ParamError> for DesignError {
    fn from(error: ParamError) -> DesignError {
        DesignError::Params(error)
    }
}

impl From<GameError> for DesignError {
    fn from(error: GameError) -> DesignError {
        DesignError::Game(error)
    }
}

// ---------------------------------------------------------------------------
// Closed-form thresholds
// ---------------------------------------------------------------------------

/// Smallest canary rate at which verification is the equilibrium.
///
/// Two constraints have to hold at once, and conflating them is how a mechanism
/// ships with a bad equilibrium nobody looked for.
///
/// **The honest profile must be stable.** Everyone verifies; one operator
/// considers stopping. It saves the verification cost `c` and gives up its share
/// of the catch bounty, against a slash `S'` that now fires on canaries *and* on
/// genuine fraud, since the others are still checking:
///
/// ```text
/// (D + p) * (beta/n + S')  >  c
/// ```
///
/// **The lazy profile must not be.** Nobody verifies; one operator considers
/// starting. It pays `c`, collects the *whole* catch bounty because it is the
/// only one who could, and the comparison it is measured against no longer
/// includes the conditional slash -- with nobody checking, accepting genuine
/// fraud is free:
///
/// ```text
/// D * (beta + S')  >  c - p * beta
/// ```
///
/// `D` is the rate at which a rubber-stamper meets an artifact the protocol
/// knows to be invalid: `canary_rate * (1 - leak) * (1 - valid_share)`. The
/// function returns the smallest `canary_rate` satisfying both, or `None` if no
/// rate does -- which happens when leak-free invalid canaries are impossible
/// (`leak = 1` or `valid_share = 1`), or when the answer exceeds one.
///
/// Note what the second constraint says about the alternative: a catch bounty
/// above `c/p` breaks the lazy equilibrium with **no canaries at all**. That is
/// a real design, and it is usually unaffordable -- at a fraud rate of one in a
/// thousand it means paying a thousand times the cost of a check, on the rare
/// occasions there is anything to catch. Canaries are cheaper because the
/// protocol manufactures the occasions.
pub fn minimum_canary_rate(params: &NodeParams) -> Result<Option<Rat>, DesignError> {
    params.validate()?;
    let bounty = Rat::units(params.catch_bounty);
    let slash = params.slash();
    let cost = Rat::units(params.verify_cost);
    let fraud = params.fraud_rate;

    // Stability of the honest profile.
    let shared_bounty = bounty.share(params.nodes).unwrap_or(Rat::ZERO);
    let honest_denominator = shared_bounty + slash;
    let honest_need = if honest_denominator.is_zero() {
        // No bounty and no stake: nothing distinguishes verifying from not, at
        // any canary rate.
        return Ok(None);
    } else {
        cost / honest_denominator - fraud
    };

    // Instability of the lazy profile.
    let lazy_denominator = bounty + slash;
    let lazy_need = if lazy_denominator.is_zero() {
        return Ok(None);
    } else {
        (cost - fraud * bounty) / lazy_denominator
    };

    let deterrent = honest_need.max(lazy_need).max(Rat::ZERO);
    let conversion = (Rat::ONE - params.canary_leak) * (Rat::ONE - params.canary_valid_share);
    if conversion.is_zero() {
        // Every canary is either recognisable or valid, so no canary rate
        // produces an unconditional punishment for accepting.
        return Ok(if deterrent.is_zero() {
            Some(Rat::ZERO)
        } else {
            None
        });
    }
    let needed = deterrent / conversion;
    Ok(if needed > Rat::ONE {
        None
    } else {
        Some(needed)
    })
}

/// Smallest availability challenge rate at which storing beats freeloading.
///
/// ```text
/// a  >  storage_cost / (R_a/n + S')
/// ```
///
/// No canary term and no coordination term, because a Merkle challenge against a
/// published root is ground truth the protocol already holds. This is what the
/// verification constraint would look like if verification were checkable, and
/// the contrast is the argument for why it is not.
pub fn minimum_audit_rate(params: &NodeParams) -> Result<Option<Rat>, DesignError> {
    params.validate()?;
    let denominator = params
        .availability_pool()
        .share(params.nodes)
        .unwrap_or(Rat::ZERO)
        + params.slash();
    if denominator.is_zero() {
        return Ok(None);
    }
    let needed = Rat::units(params.storage_cost) / denominator;
    Ok(if needed > Rat::ONE {
        None
    } else {
        Some(needed)
    })
}

// ---------------------------------------------------------------------------
// Bisection against the solver
// ---------------------------------------------------------------------------

/// Smallest `value` in `[0, MAX_UNITS]` for which `safe` holds, assuming `safe`
/// is monotone: once true it stays true.
///
/// Deliberately generic and deliberately exact -- integers, no tolerance, no
/// convergence criterion. A bisection with a tolerance parameter would put a
/// float back into the middle of an analysis built to avoid one.
fn least_safe<F>(mut safe: F) -> Result<Option<u64>, DesignError>
where
    F: FnMut(u64) -> Result<bool, DesignError>,
{
    if !safe(MAX_UNITS)? {
        return Ok(None);
    }
    let (mut low, mut high) = (0u64, MAX_UNITS);
    while low < high {
        let middle = low + (high - low) / 2;
        if safe(middle)? {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    Ok(Some(low))
}

/// Largest `value` in `[floor, MAX_UNITS]` for which `ok` holds, assuming `ok`
/// is monotone the other way: once false it stays false.
fn most_ok<F>(floor: u64, mut ok: F) -> Result<Option<u64>, DesignError>
where
    F: FnMut(u64) -> Result<bool, DesignError>,
{
    if !ok(floor)? {
        return Ok(None);
    }
    let (mut low, mut high) = (floor, MAX_UNITS);
    while low < high {
        let middle = low + (high - low).div_ceil(2);
        if ok(middle)? {
            low = middle;
        } else {
            high = middle - 1;
        }
    }
    Ok(Some(low))
}

/// Is the committee safe from both of its attacks at these parameters?
///
/// "Safe" means no group of any size strictly gains by deviating together from
/// universal on-time publication -- checked by running the solver against the
/// real payoff functions, not by re-deriving the condition.
pub fn custody_is_safe(params: &NodeParams) -> Result<bool, DesignError> {
    let game = Custody::new(params)?;
    let found = invasion(
        &game,
        Share::Publish.index(),
        params.committee,
        Invades::StrictlyBetter,
    )?;
    Ok(found.is_none())
}

/// Smallest bond at which neither committee attack pays.
///
/// Monotone in stake: both penalties are `slash_rate * stake`, and raising it
/// can only make deviation worse. `None` means no bond within the modelling
/// bound is enough, which for a fixed threshold means the committee is the wrong
/// shape rather than under-collateralised -- see [`committee_window`].
pub fn minimum_stake_for_custody(params: &NodeParams) -> Result<Option<u64>, DesignError> {
    params.validate()?;
    least_safe(|stake| {
        custody_is_safe(&NodeParams {
            stake,
            ..params.clone()
        })
    })
}

/// Thresholds at which the committee is safe from both attacks.
///
/// The vice: raising `t` makes an early-opening cartel need more members, and
/// makes a withholding cartel need fewer. So safety is an interval in the
/// middle, if it is anything, and for a committee too small relative to the
/// value it guards the interval is empty. The closed form the sweep must agree
/// with:
///
/// ```text
/// early opening does not pay    when  V  <=  t * d * S'
/// withholding does not pay      when  V  <=  (n - t + 1) * (S' + r - g)
/// ```
///
/// so a committee is workable at all only when `n + 1` exceeds
/// `V/(d*S') + V/(S' + r - g)` -- an inequality with `n` on one side and the
/// guarded value on the other. **The committee has to grow with the size of the
/// bounties it seals.** A fixed 21-of-41 that is fine for a thousand-unit bounty
/// is corruptible for a million-unit one, and nothing about the code changes.
pub fn committee_window(params: &NodeParams) -> Result<Vec<u32>, DesignError> {
    params.validate()?;
    let mut safe = Vec::new();
    for threshold in 1..=params.committee {
        let candidate = NodeParams {
            threshold,
            ..params.clone()
        };
        if custody_is_safe(&candidate)? {
            safe.push(threshold);
        }
    }
    Ok(safe)
}

/// Smallest committee for which some threshold is safe, holding everything else.
pub fn minimum_committee(params: &NodeParams) -> Result<Option<u32>, DesignError> {
    params.validate()?;
    for committee in 1..=params.nodes {
        let candidate = NodeParams {
            committee,
            threshold: 1.max(committee / 2),
            ..params.clone()
        };
        if !committee_window(&candidate)?.is_empty() {
            return Ok(Some(committee));
        }
    }
    Ok(None)
}

// ---------------------------------------------------------------------------
// Participation
// ---------------------------------------------------------------------------

/// Whether running a node pays for itself, and at what scale it stops.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Participation {
    /// Marginal revenue per node per epoch across all three services, at the
    /// honest profile.
    pub revenue: Rat,
    /// Fixed cost per node per epoch, including the cost of capital on the bond.
    pub cost: Rat,
    /// Revenue minus cost. Negative means the network has no operators, and
    /// every equilibrium computed above is a statement about an empty set.
    pub net: Rat,
    /// The largest node count this fee pool supports. Revenue per node falls as
    /// `1/n`, so there is a hard ceiling and it is set by settled value, not by
    /// any security parameter.
    pub supports_nodes: Option<u64>,
    /// Settled value per epoch at which the current node count breaks even.
    /// The bootstrap number: below it, operators are subsidising the network.
    pub break_even_settled_value: Option<u64>,
}

/// Marginal revenue per node per epoch at the fully honest profile.
///
/// Custody revenue is scaled by `committee/nodes`, the chance of being on the
/// committee in a given epoch: a node is not paid for custody it was not asked
/// to perform.
pub fn honest_revenue(params: &NodeParams) -> Result<Rat, DesignError> {
    let verification = Verification::new(params)?;
    let availability = Availability::new(params)?;
    let custody = Custody::new(params)?;
    let seat = Rat::int(i64::from(params.committee))
        .share(params.nodes)
        .unwrap_or(Rat::ZERO);
    Ok(verification.verify_payoff(params.nodes, params.nodes)
        + availability.store_payoff(params.nodes)
        + seat * custody.publish_payoff(true))
}

/// Does an honest operator clear its costs?
pub fn participation(params: &NodeParams) -> Result<Participation, DesignError> {
    params.validate()?;
    let revenue = honest_revenue(params)?;
    let cost = params.fixed_cost();
    let profitable = |candidate: &NodeParams| -> Result<bool, DesignError> {
        if candidate.validate().is_err() {
            return Ok(false);
        }
        Ok(honest_revenue(candidate)? >= candidate.fixed_cost())
    };
    let supports_nodes = most_ok(u64::from(params.committee), |nodes| {
        let nodes = u32::try_from(nodes).unwrap_or(u32::MAX);
        profitable(&NodeParams {
            nodes,
            ..params.clone()
        })
    })?;
    let break_even_settled_value = least_safe(|settled_value| {
        profitable(&NodeParams {
            settled_value,
            ..params.clone()
        })
    })?;
    Ok(Participation {
        revenue,
        cost,
        net: revenue - cost,
        supports_nodes,
        break_even_settled_value,
    })
}

// ---------------------------------------------------------------------------
// The report
// ---------------------------------------------------------------------------

/// One service's verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceFinding {
    pub service: &'static str,
    /// The action the mechanism is trying to produce.
    pub honest: String,
    /// How firmly the honest profile holds, or `None` if it does not.
    pub stability: Option<Stability>,
    /// How many pure symmetric equilibria exist in total.
    pub equilibria: usize,
    /// Equilibria that are genuine rival resting places: **strict**, and with
    /// somebody playing something other than the honest action.
    ///
    /// The distinction earns its place in the custody game, where every profile
    /// containing a sub-threshold cartel is an equilibrium -- because a member
    /// standing ready to collude behaves and is paid exactly like an honest one.
    /// Those tie with honesty rather than competing with it, and counting them
    /// as failures would report a mechanism as broken for a property no
    /// mechanism can have. A *strict* rival is different: it pays better and
    /// nobody leaves it.
    ///
    /// Capped at `MAX_RIVALS` entries; the count in `equilibria` is exact.
    pub rivals: Vec<Counts>,
    /// The smallest group that strictly gains by defecting together.
    pub defection: Option<Invasion>,
    /// The smallest group that gains *or ties* -- free assembly, which strict
    /// analysis misses.
    pub drift: Option<Invasion>,
    /// Defectors needed before the population stops recovering.
    pub tipping: Option<u32>,
    /// The parameter that has to change, and to what, if anything does.
    pub binding: Option<String>,
    /// False if any payoff examined reached the arithmetic bound.
    ///
    /// The backstop for the claim in [`super::MAX_UNITS`]. Saturation destroys
    /// the ordering every predicate above depends on, so a finding computed from
    /// a saturated payoff is not a weaker finding, it is not a finding -- and it
    /// must not be reported as one. Bounded parameters make this true in
    /// practice; carrying the answer makes it checkable.
    pub exact: bool,
}

impl ServiceFinding {
    pub fn passes(&self) -> bool {
        self.exact && self.stability.is_some() && self.defection.is_none() && self.rivals.is_empty()
    }
}

/// Everything the harness can say about a parameter set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub params: NodeParams,
    pub participation: Participation,
    pub services: Vec<ServiceFinding>,
    /// Identity count an operator would choose under each reward rule, and what
    /// splitting buys. Only the rule in [`NodeParams::reward_rule`] counts
    /// towards the verdict; the other is shown so the cost of choosing it is
    /// visible rather than argued about.
    pub sybil: Vec<(RewardRule, u32, Rat)>,
    /// Thresholds at which the committee resists both of its attacks.
    pub committee_window: Vec<u32>,
}

impl Report {
    /// Analyse a parameter set from every angle the harness has.
    pub fn of(params: &NodeParams) -> Result<Report, DesignError> {
        params.validate()?;
        let verification = Verification::new(params)?;
        let availability = Availability::new(params)?;
        let custody = Custody::new(params)?;

        let canary = minimum_canary_rate(params)?;
        let audit = minimum_audit_rate(params)?;
        let stake = minimum_stake_for_custody(params)?;

        let services = vec![
            finding(
                "verification",
                &verification,
                Attest::Verify.index(),
                Attest::Stamp.index(),
                match canary {
                    Some(rate) if rate > params.canary_rate => Some(format!(
                        "canary_rate must exceed {rate} (currently {})",
                        params.canary_rate
                    )),
                    Some(_) => None,
                    None => Some(
                        "no canary rate suffices: raise the slash or the catch bounty".to_string(),
                    ),
                },
            )?,
            finding(
                "availability",
                &availability,
                Serve::Store.index(),
                Serve::Freeload.index(),
                match audit {
                    Some(rate) if rate > params.audit_rate => Some(format!(
                        "audit_rate must exceed {rate} (currently {})",
                        params.audit_rate
                    )),
                    Some(_) => None,
                    None => Some("no audit rate suffices: raise the slash".to_string()),
                },
            )?,
            finding(
                "custody",
                &custody,
                Share::Publish.index(),
                Share::OpenEarly.index(),
                match stake {
                    Some(units) if units > params.stake => Some(format!(
                        "stake must reach {units} (currently {})",
                        params.stake
                    )),
                    Some(_) => None,
                    None => Some(
                        "no bond suffices at this threshold: change the committee shape"
                            .to_string(),
                    ),
                },
            )?,
        ];

        let mut sybil = Vec::new();
        for rule in [RewardRule::PerNode, RewardRule::PerStake] {
            let model = SplitIdentities::verification(params, rule)?;
            let result = sybil_gain(&model, params.nodes.max(2));
            sybil.push((rule, result.best, result.gain));
        }

        Ok(Report {
            params: params.clone(),
            participation: participation(params)?,
            services,
            sybil,
            committee_window: committee_window(params)?,
        })
    }

    /// True if every service passes, the configured reward rule is sybil-proof,
    /// and operators are paid enough to exist.
    pub fn passes(&self) -> bool {
        let sybil_proof = self
            .sybil
            .iter()
            .filter(|(rule, _, _)| *rule == self.params.reward_rule)
            .all(|(_, _, gain)| !gain.is_positive());
        !self.participation.net.is_negative()
            && sybil_proof
            && self.services.iter().all(ServiceFinding::passes)
    }
}

fn finding<S: Symmetric + ?Sized>(
    service: &'static str,
    game: &S,
    honest: usize,
    defector: usize,
    binding: Option<String>,
) -> Result<ServiceFinding, DesignError> {
    let profile = everyone(game, honest);
    let equilibria = symmetric_equilibria(game)?;
    let rivals: Vec<Counts> = equilibria
        .iter()
        .filter(|(counts, stability)| {
            *stability == Stability::Strict && counts.as_slice() != profile.as_slice()
        })
        .map(|(counts, _)| counts.clone())
        .take(MAX_RIVALS)
        .collect();
    // Every action, judged against a population that is otherwise honest: the
    // comparison every predicate below is built out of.
    let mut probe = profile.clone();
    probe[honest] = probe[honest].saturating_sub(1);
    let exact = (0..game.actions()).all(|action| !game.payoff(action, &probe).is_extreme());
    Ok(ServiceFinding {
        service,
        exact,
        honest: game.action_name(honest),
        stability: super::game::symmetric_stability(game, &profile)?,
        equilibria: equilibria.len(),
        rivals,
        defection: invasion(game, honest, game.population(), Invades::StrictlyBetter)?,
        drift: invasion(game, honest, game.population(), Invades::WeaklyBetter)?,
        tipping: tipping_point(game, honest, defector, SETTLE_STEPS)?,
        binding,
    })
}

/// One aligned report line: label, value, verdict.
///
/// Hand-rolled rather than tabulated because the verdict column is what a reader
/// scans for, and it has to stay in the same place whether the value beside it
/// is "none" or "weak Nash (somebody is indifferent)".
fn row(f: &mut fmt::Formatter<'_>, label: &str, value: String, verdict: &str) -> fmt::Result {
    if verdict.is_empty() {
        writeln!(f, "  {label:<26}{value:>16}")
    } else {
        writeln!(f, "  {label:<26}{value:>16}  {verdict}")
    }
}

/// "1 node" / "4 nodes", because a report that says "1 nodes" reads as a bug.
fn nodes(count: u32) -> String {
    plural(count, "node", "nodes")
}

fn plural(count: u32, one: &str, many: &str) -> String {
    if count == 1 {
        format!("1 {one}")
    } else {
        format!("{count} {many}")
    }
}

/// `ok` / `FAIL`, so a scanned report shows its problems.
fn mark(passed: bool) -> &'static str {
    if passed {
        "ok"
    } else {
        "FAIL"
    }
}

fn describe(stability: Option<Stability>) -> &'static str {
    match stability {
        Some(Stability::Strict) => "strict Nash",
        Some(Stability::Weak) => "weak Nash",
        None => "none",
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let params = &self.params;
        writeln!(
            f,
            "{} nodes, {} settled per epoch, fee {}, stake {}",
            params.nodes, params.settled_value, params.fee, params.stake
        )?;
        writeln!(f)?;

        let participation = &self.participation;
        writeln!(f, "participation")?;
        row(
            f,
            "revenue per node",
            participation.revenue.to_decimal(2),
            "",
        )?;
        row(
            f,
            "fixed cost per node",
            participation.cost.to_decimal(2),
            "",
        )?;
        row(
            f,
            "net",
            participation.net.to_decimal(2),
            mark(!participation.net.is_negative()),
        )?;
        match participation.supports_nodes {
            Some(count) => row(
                f,
                "fee pool supports",
                nodes(u32::try_from(count).unwrap_or(u32::MAX)),
                "",
            )?,
            None => row(f, "fee pool supports", "no nodes".to_string(), "FAIL")?,
        }
        match participation.break_even_settled_value {
            Some(value) => row(f, "break-even settlement", format!("{value} / epoch"), "")?,
            None => row(
                f,
                "break-even settlement",
                "unreachable".to_string(),
                "FAIL",
            )?,
        }

        for service in &self.services {
            writeln!(f)?;
            writeln!(
                f,
                "{} -- honest action: {}",
                service.service, service.honest
            )?;
            row(
                f,
                "honest profile",
                describe(service.stability).to_string(),
                mark(service.stability.is_some()),
            )?;
            row(f, "pure equilibria", service.equilibria.to_string(), "")?;
            row(
                f,
                "rival (strict) equilibria",
                service.rivals.len().to_string(),
                mark(service.rivals.is_empty()),
            )?;
            match &service.defection {
                Some(found) => row(f, "smallest defection", nodes(found.mutants), "FAIL")?,
                None => row(f, "smallest defection", "none".to_string(), "ok")?,
            }
            match &service.drift {
                Some(found) if found.gain.is_zero() => {
                    row(f, "free (zero-gain) drift", nodes(found.mutants), "note")?
                }
                _ => row(f, "free (zero-gain) drift", "none".to_string(), "ok")?,
            }
            match service.tipping {
                Some(size) => row(f, "tipping point", nodes(size), "FAIL")?,
                None => row(f, "tipping point", "recovers".to_string(), "ok")?,
            }
            if !service.exact {
                row(f, "arithmetic", "saturated".to_string(), "FAIL")?;
            }
            if let Some(binding) = &service.binding {
                writeln!(f, "  {:<26}{binding}", "binding constraint")?;
            }
        }

        writeln!(f)?;
        writeln!(f, "sybil resistance -- identities one operator would run")?;
        for (rule, best, gain) in &self.sybil {
            let (label, verdict) = if *rule == self.params.reward_rule {
                (
                    format!("{} (in use)", rule.name()),
                    mark(!gain.is_positive()),
                )
            } else {
                (
                    format!("{} (rejected)", rule.name()),
                    // Not a failure -- the rule is not in use. It is here to
                    // show what choosing it would have cost.
                    if gain.is_positive() {
                        "why not"
                    } else {
                        "note"
                    },
                )
            };
            row(f, &label, plural(*best, "identity", "identities"), verdict)?;
        }

        writeln!(f)?;
        match (self.committee_window.first(), self.committee_window.last()) {
            (Some(low), Some(high)) => writeln!(
                f,
                "committee: thresholds {low}..={high} of {} resist both attacks",
                self.params.committee
            )?,
            _ => writeln!(
                f,
                "committee: no threshold of {} resists both attacks",
                self.params.committee
            )?,
        }
        writeln!(f)?;
        writeln!(f, "verdict: {}", if self.passes() { "ok" } else { "FAIL" })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::incentive::game::symmetric_stability;

    fn reference() -> NodeParams {
        NodeParams::reference()
    }

    /// Grid the nudge helpers work on. Any rate they return has a denominator
    /// dividing this, so it survives [`NodeParams::validate`] -- a threshold
    /// plus an arbitrary epsilon usually does not, because adding two rationals
    /// multiplies their denominators.
    const GRID: i128 = 100_000;

    /// The largest grid point strictly below `rate`.
    fn just_below(rate: Rat) -> Rat {
        let scaled = rate * Rat::new(GRID, 1).expect("nonzero denominator");
        let floor = scaled.floor();
        let step = if scaled == Rat::new(floor, 1).expect("nonzero denominator") {
            floor - 1
        } else {
            floor
        };
        Rat::new(step, GRID).expect("nonzero denominator")
    }

    /// The smallest grid point strictly above `rate`.
    fn just_above(rate: Rat) -> Rat {
        let scaled = rate * Rat::new(GRID, 1).expect("nonzero denominator");
        Rat::new(scaled.floor() + 1, GRID).expect("nonzero denominator")
    }

    /// Is the honest profile an equilibrium, and how firmly?
    fn honest_holds(params: &NodeParams) -> Option<Stability> {
        let game = Verification::new(params).expect("validated");
        symmetric_stability(&game, &everyone(&game, Attest::Verify.index())).expect("valid counts")
    }

    /// Is the rubber-stamp trap still standing?
    fn trap_holds(params: &NodeParams) -> Option<Stability> {
        let game = Verification::new(params).expect("validated");
        symmetric_stability(&game, &everyone(&game, Attest::Stamp.index())).expect("valid counts")
    }

    fn with_canary(params: &NodeParams, canary_rate: Rat) -> NodeParams {
        NodeParams {
            canary_rate,
            ..params.clone()
        }
    }

    #[test]
    fn the_closed_form_agrees_with_the_solver() {
        // The point of having both. The formula is derived by hand and could be
        // wrong; the solver runs the real payoff functions and is slow. They
        // must agree at the boundary, or one of them is lying.
        //
        // What the threshold means is precise: *above* it both constraints hold
        // -- the honest profile is a strict equilibrium and the rubber-stamp
        // trap is not an equilibrium at all -- and below it at least one fails.
        // Checking only the first is the mistake the second constraint exists to
        // catch.
        let base = NodeParams {
            canary_leak: Rat::ZERO,
            ..reference()
        };
        let threshold = minimum_canary_rate(&base)
            .expect("validated")
            .expect("a rate exists");

        let above = with_canary(&base, just_above(threshold));
        assert_eq!(honest_holds(&above), Some(Stability::Strict));
        assert_eq!(
            trap_holds(&above),
            None,
            "the trap must be gone, not merely worse"
        );

        let below = with_canary(&base, just_below(threshold));
        let both_hold =
            honest_holds(&below) == Some(Stability::Strict) && trap_holds(&below).is_none();
        assert!(!both_hold, "below the threshold something must fail");
    }

    #[test]
    fn at_the_threshold_the_trap_is_still_standing() {
        // Exactly at the infimum the binding comparison is an equality: nobody
        // gains by switching and nobody loses, so the rubber-stamp profile is
        // still an equilibrium -- a *weak* one. Design above the number, not at
        // it. A float harness could not distinguish this case from either
        // neighbour, which is the whole reason for exact rationals.
        let base = NodeParams {
            canary_leak: Rat::ZERO,
            ..reference()
        };
        let threshold = minimum_canary_rate(&base)
            .expect("validated")
            .expect("a rate exists");
        assert_eq!(
            trap_holds(&with_canary(&base, threshold)),
            Some(Stability::Weak)
        );
    }

    #[test]
    fn which_constraint_binds_depends_on_the_bond() {
        // Two regimes, and a designer needs to know which one they are in.
        //
        // With a large bond the conditional slash already deters a lone
        // rubber-stamper, so the honest profile is safe even with no canaries at
        // all -- and canaries are needed only to destroy the trap. With a small
        // bond the honest profile itself is at risk and the first constraint
        // binds. `minimum_canary_rate` takes the worse of the two, which is why
        // it is one function and not two.
        let generous = NodeParams {
            canary_rate: Rat::ZERO,
            canary_leak: Rat::ZERO,
            ..reference()
        };
        assert_eq!(
            honest_holds(&generous),
            Some(Stability::Strict),
            "a big bond keeps honest nodes honest without canaries"
        );
        assert_eq!(
            trap_holds(&generous),
            Some(Stability::Strict),
            "and does nothing whatever about the trap"
        );

        let thin = NodeParams {
            stake: 1_000,
            ..generous
        };
        assert_eq!(
            honest_holds(&thin),
            None,
            "with a thin bond the honest profile goes first"
        );
    }

    #[test]
    fn a_leaky_canary_raises_the_rate_needed_in_exact_proportion() {
        let clean = NodeParams {
            canary_leak: Rat::ZERO,
            ..reference()
        };
        let leaky = NodeParams {
            canary_leak: Rat::rate(1, 2).expect("a valid rate"),
            ..clean.clone()
        };
        let clean_rate = minimum_canary_rate(&clean)
            .expect("validated")
            .expect("exists");
        let leaky_rate = minimum_canary_rate(&leaky)
            .expect("validated")
            .expect("exists");
        assert_eq!(leaky_rate, clean_rate * Rat::int(2));
        // And a fully leaky canary set cannot be rescued at any rate.
        let useless = NodeParams {
            canary_leak: Rat::ONE,
            ..clean
        };
        assert_eq!(minimum_canary_rate(&useless).expect("validated"), None);
    }

    #[test]
    fn a_big_enough_catch_bounty_replaces_canaries_entirely() {
        // The alternative the algebra admits: if catching real fraud pays more
        // than checking costs, the lazy equilibrium dies without canaries. The
        // bounty required is c/p, which is why nobody does this.
        let params = NodeParams {
            catch_bounty: 200_000_000,
            ..reference()
        };
        assert_eq!(
            minimum_canary_rate(&params).expect("validated"),
            Some(Rat::ZERO)
        );
        let unfunded = NodeParams {
            canary_rate: Rat::ZERO,
            ..params
        };
        let game = Verification::new(&unfunded).expect("validated");
        assert_eq!(
            symmetric_stability(&game, &everyone(&game, Attest::Stamp.index()))
                .expect("valid counts"),
            None
        );
    }

    #[test]
    fn the_audit_threshold_is_where_storing_starts_to_pay() {
        let params = reference();
        let threshold = minimum_audit_rate(&params)
            .expect("validated")
            .expect("a rate exists");
        let with = |audit_rate: Rat| {
            let params = NodeParams {
                audit_rate,
                ..params.clone()
            };
            let game = Availability::new(&params).expect("validated");
            symmetric_stability(&game, &everyone(&game, Serve::Store.index()))
                .expect("valid counts")
        };
        assert_eq!(with(just_above(threshold)), Some(Stability::Strict));
        assert_eq!(with(just_below(threshold)), None);
        assert!(
            params.audit_rate > threshold,
            "the reference network clears its own bar"
        );
    }

    #[test]
    fn the_committee_window_matches_its_closed_form() {
        // early opening safe: V <= t * d * S'
        // withholding safe:   V <= (n - t + 1) * (S' + r - g)
        let params = NodeParams {
            stake: 3_000_000,
            ..reference()
        };
        let custody = Custody::new(&params).expect("validated");
        let value = Rat::units(params.sealed_value);
        let slash = params.slash();
        let margin = slash + custody.publication_fee() - Rat::units(params.publish_cost);
        let expected: Vec<u32> = (1..=params.committee)
            .filter(|threshold| {
                let early =
                    value <= Rat::int(i64::from(*threshold)) * params.detection_rate * slash;
                let blocking = params.committee - threshold + 1;
                let withhold = value <= Rat::int(i64::from(blocking)) * margin;
                early && withhold
            })
            .collect();
        assert_eq!(committee_window(&params).expect("validated"), expected);
        assert!(!expected.is_empty(), "the fixture should have a window");
    }

    #[test]
    fn a_committee_too_small_for_the_value_it_guards_has_no_safe_threshold() {
        let params = NodeParams {
            committee: 5,
            threshold: 3,
            sealed_value: 4_000_000,
            ..reference()
        };
        assert_eq!(
            committee_window(&params).expect("validated"),
            Vec::<u32>::new()
        );
        // The fix is not more stake at this threshold, it is a bigger committee.
        let bigger = minimum_committee(&params).expect("validated");
        assert!(
            bigger.is_some_and(|size| size > params.committee),
            "a larger committee is what closes the window"
        );
    }

    #[test]
    fn minimum_stake_is_the_smallest_bond_the_solver_accepts() {
        let params = NodeParams {
            stake: 1,
            ..reference()
        };
        let needed = minimum_stake_for_custody(&params)
            .expect("validated")
            .expect("some bond works");
        assert!(custody_is_safe(&NodeParams {
            stake: needed,
            ..params.clone()
        })
        .expect("validated"));
        assert!(!custody_is_safe(&NodeParams {
            stake: needed - 1,
            ..params
        })
        .expect("validated"));
    }

    #[test]
    fn participation_finds_the_ceiling_the_fee_pool_puts_on_node_count() {
        let params = reference();
        let found = participation(&params).expect("validated");
        assert!(found.net.is_positive(), "the reference network pays");
        let ceiling = found.supports_nodes.expect("some node count works");
        assert!(ceiling >= u64::from(params.nodes));
        // One node past the ceiling and the last operator is losing money.
        let crowded = NodeParams {
            nodes: u32::try_from(ceiling + 1).expect("fits"),
            ..params
        };
        assert!(participation(&crowded)
            .expect("validated")
            .net
            .is_negative());
    }

    #[test]
    fn an_unfunded_network_has_no_operators_and_the_report_says_so() {
        // The bootstrap problem, stated rather than assumed away: with nothing
        // settling, the fee pool is zero and every equilibrium above is a
        // statement about an empty set.
        let params = NodeParams {
            settled_value: 0,
            ..reference()
        };
        let found = participation(&params).expect("validated");
        assert!(found.net.is_negative());
        assert_eq!(found.supports_nodes, None);
        assert!(found
            .break_even_settled_value
            .is_some_and(|value| value > 0));
        assert!(!Report::of(&params).expect("validated").passes());
    }

    #[test]
    fn the_reference_network_passes_every_check() {
        let report = Report::of(&reference()).expect("validated");
        assert!(report.passes(), "reference report:\n{report}");
        // And the printed form mentions each service, so the CLI cannot silently
        // drop one.
        let printed = report.to_string();
        for service in ["participation", "verification", "availability", "custody"] {
            assert!(printed.contains(service), "report omitted {service}");
        }
        assert!(printed.contains("verdict: ok"));
    }

    #[test]
    fn the_report_fails_loudly_when_canaries_are_switched_off() {
        let params = NodeParams {
            canary_rate: Rat::ZERO,
            ..reference()
        };
        let report = Report::of(&params).expect("validated");
        assert!(!report.passes());
        let printed = report.to_string();
        assert!(printed.contains("FAIL"));
        assert!(printed.contains("canary_rate must exceed"));
    }

    #[test]
    fn bisection_brackets_a_monotone_predicate_exactly() {
        assert_eq!(
            least_safe(|value| Ok(value >= 12345)).expect("total"),
            Some(12345)
        );
        assert_eq!(least_safe(|_| Ok(false)).expect("total"), None);
        assert_eq!(least_safe(|_| Ok(true)).expect("total"), Some(0));
        assert_eq!(
            most_ok(0, |value| Ok(value <= 999)).expect("total"),
            Some(999)
        );
        assert_eq!(most_ok(5, |value| Ok(value < 5)).expect("total"), None);
    }
}
