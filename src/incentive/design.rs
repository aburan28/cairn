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

/// Smallest blind share at which an operator that never runs the checker loses
/// to one that always does.
///
/// The [`minimum_canary_rate`] of [`Attest::Echo`], and it has the same two
/// constraints for the same reason. Write `b` for the share of paid claims whose
/// verdict is sealed while they are attested, `A = beta/n + S'`, `e` for the
/// admitter's error on fraud, and `F`, `F0` for the best blind move on a sealed
/// claim -- stamp, reject or abstain -- with others checking and with nobody
/// checking.
///
/// **The honest profile must be stable.** Everyone verifies; one operator
/// considers echoing instead. On a shown claim it saves `c` and risks only the
/// admitter's mistakes; on a sealed one it is reduced to `F`:
///
/// ```text
/// (1-b) * (c - p*e*A)  <  b * (V - F)        V = R/n - c + (D + p)*beta/n
/// ```
///
/// **The echo trap must not be.** Everyone echoes; one considers verifying. On
/// a shown claim it pays `c` and earns only what overturning the admitter pays,
/// `p*e*beta`; on a sealed one it is the only checker in a room of stampers:
///
/// ```text
/// (1-b) * (c - p*e*beta)  <  b * (R/n - c + (D + p)*beta - F0)
/// ```
///
/// Both are linear in `b`, so each gives `b > gain / (gain + loss)` and the
/// answer is the larger. Read off the second what a canary cannot do: the left
/// side has no `D` and no `S'` in it. The canary rate and the bond appear only
/// on the sealed side, so they matter only in proportion to how much of the
/// sample is sealed.
///
/// `Some(0)` when echoing does not pay even on a fully shown sample (`c` below
/// what catching the admitter is worth). `None` when no share below one works,
/// which means the four-action game itself is failing on sealed claims -- a
/// verifier does not beat a stamper there either, and that is
/// [`minimum_canary_rate`]'s problem rather than this one's.
///
/// # What it does not buy
///
/// This is the share that stops the operator that never checks anything. It
/// does **not** buy a check of the `1 - b` claims whose verdict is shown: an
/// operator that conditions on what it can see verifies the sealed claims and
/// echoes the rest, and gains [`Verification::selective_echo_gain`] at every
/// share below one. A network that wants a shown claim independently checked
/// cannot get it by paying for attestations on it. The answer is to pay only
/// for the sealed ones, which is `b = 1`, and is what the reference does.
pub fn minimum_blind_sample(params: &NodeParams) -> Result<Option<Rat>, DesignError> {
    params.validate()?;
    let nodes = params.nodes;
    let cost = Rat::units(params.verify_cost);
    let slash = params.slash();
    let bounty = Rat::units(params.catch_bounty);
    let fraud = params.fraud_rate;
    let error = params.admitter_error_rate;
    let effective = params.effective_canary_rate();
    let deterrent = effective * (Rat::ONE - params.canary_valid_share);
    let pool = params.verify_pool().share(nodes).unwrap_or(Rat::ZERO);
    let shared_bounty = bounty.share(nodes).unwrap_or(Rat::ZERO);

    // Re-derived from the algebra rather than read off `Verification`, so the
    // solver test below compares two derivations instead of one with itself.
    let reject =
        pool - slash * (effective * params.canary_valid_share + (Rat::ONE - effective - fraud));
    let blind_move = |stamp: Rat| stamp.max(reject).max(Rat::ZERO);

    // Stability of the honest profile against one echoer.
    let honest_gain = cost - fraud * error * (shared_bounty + slash);
    let verify = pool - cost + (deterrent + fraud) * shared_bounty;
    let honest_loss = verify - blind_move(pool - slash * (deterrent + fraud));

    // Instability of the echo trap against one verifier.
    let trap_gain = cost - fraud * error * bounty;
    let trap_loss =
        pool - cost + (deterrent + fraud) * bounty - blind_move(pool - slash * deterrent);

    let need = |gain: Rat, loss: Rat| -> Option<Rat> {
        if !gain.is_positive() {
            // Echoing a shown claim already loses: no share needs to be sealed.
            Some(Rat::ZERO)
        } else if !loss.is_positive() {
            None
        } else {
            Some(gain / (gain + loss))
        }
    };
    Ok(
        match (need(honest_gain, honest_loss), need(trap_gain, trap_loss)) {
            (Some(honest), Some(trap)) => Some(honest.max(trap)),
            _ => None,
        },
    )
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

/// Smallest reward a settlement can carry without the network subsidising it.
///
/// ```text
/// V_min  =  redundancy × verify_cost / (fee × verify_split)
/// ```
///
/// # What it is for
///
/// Node rewards are a fee on settlement, so every settled artifact pays for the
/// verification it consumed out of a fraction of its own reward. A settlement
/// too small to cover that fraction is paid for by everything else that
/// settles. That is not a rule anyone can enforce — a small bounty is legal and
/// should be — but it is a number a funder is entitled to know **before** it
/// funds, which is the difference between a subsidy and a surprise.
///
/// It matters most for *decomposition*. An agent breaking a bounty into
/// sub-objectives is asking the network for one verification per piece, and the
/// pieces get smaller as the decomposition gets finer: a hundred thousand-unit
/// tasks can easily cost more to check than the parent bounty pays. So
/// sub-objectives should be **few and large**, and this is the arithmetic that
/// says how large.
///
/// # Why redundancy is a parameter and not `params.nodes`
///
/// The harness models full redundancy — every node checks every artifact —
/// deliberately, as the conservative case. Under sampling only `k` nodes check,
/// and the difference between those two numbers is the entire argument for
/// sampled verification. Passing it in means a caller can ask either question,
/// and `docs/agent-market.md` quotes both.
///
/// `None` when the fee reaching verifiers is zero: with no revenue per
/// settlement there is no reward large enough, which is a real answer rather
/// than a division to guard against.
pub fn decomposition_floor(
    params: &NodeParams,
    redundancy: u32,
) -> Result<Option<Rat>, DesignError> {
    params.validate()?;
    let reaching_verifiers = params.fee * params.verify_split;
    if reaching_verifiers.is_zero() {
        return Ok(None);
    }
    let cost = Rat::units(params.verify_cost) * Rat::int(i64::from(redundancy.max(1)));
    Ok(Some(cost / reaching_verifiers))
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

/// Whether attestors copy the admitter instead of checking.
///
/// Its own finding rather than a fifth action in the verification
/// [`ServiceFinding`], for a reason of arithmetic: enumerating five actions at a
/// hundred nodes is `C(104, 4)` = 4.6 million profiles, past the solver's
/// budget. Every check here is instead run against the one profile it
/// threatens -- the honest one for the lone echoer, the echo trap for the lone
/// verifier -- through the same [`Verification`] payoffs the solver uses, which
/// is cheap and exact. What it does not do is find a rival equilibrium that
/// *mixes* echoers with the other four actions; the verification finding covers
/// the profiles in which nobody echoes, and this one the two that matter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchoFinding {
    /// Share of paid claims whose verdict is sealed while they are attested.
    pub blind_sample: Rat,
    /// What one operator that never checks gains over verifying, in an
    /// otherwise honest network. `None` when nothing is shown, so there is
    /// nothing to copy and the action does not exist.
    pub gain: Option<Rat>,
    /// What one operator that checks only the sealed claims and copies the rest
    /// gains over verifying everything. Positive at every share below one
    /// whenever a copy is cheaper than a check; `None` when nothing is shown.
    pub selective_gain: Option<Rat>,
    /// How firmly universal echo holds, if it is an action at all.
    pub trap: Option<Stability>,
    /// What a lone echoer gains with *every* verdict shown -- the protocol as
    /// built, where the admitter's verdict is in the log before anybody attests.
    /// Printed whatever the configured share, so a report run at the reference
    /// cannot hide what the reference had to assume.
    pub shown_gain: Rat,
    /// Universal echo with every verdict shown.
    pub shown_trap: Option<Stability>,
    /// [`minimum_blind_sample`] at these parameters.
    pub minimum: Option<Rat>,
    /// False if any payoff examined reached the arithmetic bound.
    pub exact: bool,
}

impl EchoFinding {
    /// Analyse echo at `params`, and at `params` with every verdict shown.
    pub fn of(params: &NodeParams) -> Result<EchoFinding, DesignError> {
        params.validate()?;
        let shown_params = NodeParams {
            blind_sample: Rat::ZERO,
            ..params.clone()
        };
        let here = lone_echo(params)?;
        let shown = lone_echo(&shown_params)?.unwrap_or((Rat::ZERO, None, true));
        let selective = Verification::new(params)?.selective_echo_gain();
        let (gain, trap, exact) = match here {
            Some((gain, trap, exact)) => (Some(gain), trap, exact),
            None => (None, None, true),
        };
        Ok(EchoFinding {
            blind_sample: params.blind_sample,
            gain,
            selective_gain: gain.map(|_| selective),
            trap,
            shown_gain: shown.0,
            shown_trap: shown.1,
            minimum: minimum_blind_sample(params)?,
            exact: exact && shown.2 && !selective.is_extreme(),
        })
    }

    /// Nobody gains by copying, by either policy, and universal copying is not
    /// a resting place. Trivially true when there is nothing to copy.
    pub fn closed(&self) -> bool {
        let loses = |gain: Option<Rat>| gain.is_none_or(|gain| gain.is_negative());
        self.exact && loses(self.gain) && loses(self.selective_gain) && self.trap.is_none()
    }
}

/// The lone echoer's gain over verifying in the honest profile, how firmly the
/// echo trap holds, and whether neither saturated. `None` when echo is not an
/// action at these parameters.
fn lone_echo(params: &NodeParams) -> Result<Option<(Rat, Option<Stability>, bool)>, DesignError> {
    let game = Verification::new(params)?;
    if !game.echo_available() {
        return Ok(None);
    }
    let verify = Attest::Verify.index();
    let echo = Attest::Echo.index();
    let mut others = everyone(&game, verify);
    others[verify] = others[verify].saturating_sub(1);
    let echoing = game.payoff(echo, &others);
    let verifying = game.payoff(verify, &others);
    let trap = super::game::symmetric_stability(&game, &everyone(&game, echo))?;
    let exact = !echoing.is_extreme() && !verifying.is_extreme();
    Ok(Some((echoing - verifying, trap, exact)))
}

/// Everything the harness can say about a parameter set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub params: NodeParams,
    pub participation: Participation,
    pub services: Vec<ServiceFinding>,
    /// The fifth way to attest, which the verification finding's enumeration
    /// cannot afford to include. Counts towards [`Report::passes`].
    pub echo: EchoFinding,
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
        // The four-action game, whatever the blind share: echo is judged
        // separately in `EchoFinding`, because enumerating it is out of budget.
        let verification = Verification::blind(params)?;
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
            echo: EchoFinding::of(params)?,
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
            && self.echo.closed()
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

/// A gain per attested claim, signed, so a reader sees which way it points.
fn per_claim(gain: Rat) -> String {
    let sign = if gain.is_negative() { "" } else { "+" };
    format!("{sign}{}/claim", gain.to_decimal(2))
}

/// The echo lines of the verification section.
///
/// The counterfactual -- every verdict shown, which is the protocol as built --
/// is printed whatever the configured share and marked `note` rather than
/// `FAIL`, the way the sybil section prints the reward rule it rejected: it is
/// not the mechanism being judged, and it is the thing the mechanism had to
/// assume away.
fn write_echo(f: &mut fmt::Formatter<'_>, echo: &EchoFinding) -> fmt::Result {
    row(
        f,
        "blind share of paid claims",
        echo.blind_sample.to_string(),
        mark(echo.closed()),
    )?;
    match (echo.gain, echo.selective_gain) {
        (Some(gain), Some(selective)) => {
            row(
                f,
                "echo, never checking",
                per_claim(gain),
                mark(gain.is_negative()),
            )?;
            row(
                f,
                "echo where verdicts show",
                per_claim(selective),
                mark(selective.is_negative()),
            )?;
            row(
                f,
                "echo trap",
                describe(echo.trap).to_string(),
                mark(echo.trap.is_none()),
            )?;
        }
        _ => row(f, "echo the admitter", "nothing to copy".to_string(), "ok")?,
    }
    let note = |closed: bool| if closed { "ok" } else { "note" };
    row(
        f,
        "echo, all verdicts shown",
        per_claim(echo.shown_gain),
        note(echo.shown_gain.is_negative()),
    )?;
    row(
        f,
        "echo trap, all shown",
        describe(echo.shown_trap).to_string(),
        note(echo.shown_trap.is_none()),
    )?;
    match echo.minimum {
        Some(share) => writeln!(
            f,
            "  {:<26}{share} stops a node that never checks; below 1, shown claims are copied",
            "blind share needed"
        )?,
        None => writeln!(
            f,
            "  {:<26}none: a verifier loses on sealed claims too",
            "blind share needed"
        )?,
    }
    if !echo.exact {
        row(f, "arithmetic", "saturated".to_string(), "FAIL")?;
    }
    Ok(())
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
            if service.service == "verification" {
                write_echo(f, &self.echo)?;
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

    // -- echo -----------------------------------------------------------------

    /// The echo rates' grid: [`MAX_ECHO_RATE_DEN`](super::super::MAX_ECHO_RATE_DEN).
    const ECHO_GRID: i128 = 1_000;

    fn on_echo_grid(rate: Rat, step: i128) -> Rat {
        let scaled = rate * Rat::new(ECHO_GRID, 1).expect("nonzero denominator");
        let floor = scaled.floor();
        let exact = scaled == Rat::new(floor, 1).expect("nonzero denominator");
        let point = match (step, exact) {
            (1, _) => floor + 1,
            (_, true) => floor - 1,
            (_, false) => floor,
        };
        Rat::new(point, ECHO_GRID).expect("nonzero denominator")
    }

    /// A report row as [`row`] lays it out, so a test can ask for a whole line
    /// without counting spaces.
    fn printed_row(label: &str, value: &str, verdict: &str) -> String {
        format!("  {label:<26}{value:>16}  {verdict}\n")
    }

    fn with_blind(params: &NodeParams, blind_sample: Rat) -> NodeParams {
        NodeParams {
            blind_sample,
            ..params.clone()
        }
    }

    /// Is the honest profile strict in the five-action game?
    fn honest_against_echo(params: &NodeParams) -> Option<Stability> {
        let game = Verification::new(params).expect("validated");
        symmetric_stability(&game, &everyone(&game, Attest::Verify.index())).expect("valid counts")
    }

    /// Is the echo trap standing?
    fn echo_trap(params: &NodeParams) -> Option<Stability> {
        let game = Verification::new(params).expect("validated");
        symmetric_stability(&game, &everyone(&game, Attest::Echo.index())).expect("valid counts")
    }

    #[test]
    fn the_blind_share_closed_form_agrees_with_the_solver() {
        // As for canaries: the formula is derived by hand, the solver runs the
        // real payoffs, and they must agree at the boundary. Above it the honest
        // profile is strict in the five-action game *and* the echo trap is gone;
        // below it something fails. At the reference canary rate.
        let base = reference();
        let threshold = minimum_blind_sample(&base)
            .expect("validated")
            .expect("a share exists");

        // The number, re-derived in the open. At the reference stamping is the
        // better blind move on a sealed claim (2,500 of pool against 2,300 of
        // expected slash with others checking, 1,900 with nobody), so the pool
        // cancels out of both constraints:
        //   honest  c / ((D + p) * (beta/n + S'))          = 200 / 2302.875
        //   trap    c / ((D + p) * beta + D * S')           = 200 / 2187.5
        let verification = Verification::new(&base).expect("validated");
        let deterrent = verification.stamp_deterrent();
        let cost = Rat::units(base.verify_cost);
        let bounty = Rat::units(base.catch_bounty);
        let honest = cost
            / ((deterrent + base.fraud_rate)
                * (bounty.share(base.nodes).expect("nodes") + base.slash()));
        let trap = cost / ((deterrent + base.fraud_rate) * bounty + deterrent * base.slash());
        assert_eq!(honest, Rat::new(1_600, 18_423).expect("valid rational"));
        assert_eq!(trap, Rat::new(16, 175).expect("valid rational"));
        assert_eq!(
            threshold,
            honest.max(trap),
            "the trap binds, as for canaries"
        );

        let above = with_blind(&base, on_echo_grid(threshold, 1));
        assert_eq!(honest_against_echo(&above), Some(Stability::Strict));
        assert_eq!(
            echo_trap(&above),
            None,
            "the trap must be gone, not merely worse"
        );

        let below = with_blind(&base, on_echo_grid(threshold, -1));
        let both =
            honest_against_echo(&below) == Some(Stability::Strict) && echo_trap(&below).is_none();
        assert!(!both, "below the threshold something must fail");

        // And the pool cancels out of it, as long as stamping stays the better
        // blind move -- which a bigger pool only makes more true.
        let rich = NodeParams {
            settled_value: base.settled_value * 40,
            ..base.clone()
        };
        assert_eq!(
            minimum_blind_sample(&rich).expect("validated"),
            Some(threshold)
        );
    }

    #[test]
    fn at_the_blind_threshold_the_echo_trap_is_still_standing() {
        // The infimum of a strict inequality, so exactly at it a lone verifier
        // among copiers neither gains nor loses. 16/175 is on the echo grid, so
        // this is a share the protocol could actually be set to.
        let base = reference();
        let threshold = minimum_blind_sample(&base)
            .expect("validated")
            .expect("a share exists");
        assert_eq!(
            echo_trap(&with_blind(&base, threshold)),
            Some(Stability::Weak)
        );
    }

    #[test]
    fn a_sloppy_admitter_needs_no_sealing_to_stay_honest_but_the_trap_still_does() {
        // A careless enough admitter makes a copy wrong often enough that, with
        // others checking, copying loses -- but a lone verifier among copiers is
        // only paid for overturning it, `p * beta`, which never covers `c` here.
        // So the honest profile needs no sealing and the trap still does.
        let sloppy = NodeParams {
            admitter_error_rate: Rat::ONE,
            ..reference()
        };
        let threshold = minimum_blind_sample(&sloppy)
            .expect("validated")
            .expect("a share exists");
        assert!(threshold.is_positive(), "the trap still needs sealing");
        assert_eq!(
            honest_against_echo(&with_blind(&sloppy, Rat::ZERO)),
            Some(Stability::Strict)
        );
        // With no canaries and no stake there is nothing on the sealed side to
        // lose, and no share works.
        let toothless = NodeParams {
            canary_rate: Rat::ZERO,
            stake: 0,
            ..reference()
        };
        assert_eq!(minimum_blind_sample(&toothless).expect("validated"), None);
    }

    #[test]
    fn the_reference_report_prints_what_echo_would_take_with_verdicts_shown() {
        let report = Report::of(&reference()).expect("validated");
        assert!(report.echo.closed(), "nothing to copy at the reference");
        assert_eq!(report.echo.gain, None);
        assert_eq!(report.echo.shown_gain, Rat::units(200));
        assert_eq!(report.echo.shown_trap, Some(Stability::Strict));
        assert_eq!(
            report.echo.minimum,
            Some(Rat::new(16, 175).expect("valid rational"))
        );
        let printed = report.to_string();
        for line in [
            printed_row("echo the admitter", "nothing to copy", "ok"),
            printed_row("echo, all verdicts shown", "+200.00/claim", "note"),
            printed_row("echo trap, all shown", "strict Nash", "note"),
            "16/175 stops a node that never checks".to_string(),
        ] {
            assert!(
                printed.contains(line.as_str()),
                "report omitted {line:?}:\n{printed}"
            );
        }
    }

    #[test]
    fn the_report_fails_on_any_readable_paid_claim() {
        // Shown verdicts: the copier wins outright. Half sealed: the operator
        // that never checks now loses, and the report says so -- but one that
        // checks the sealed half and copies the rest still wins, so the verdict
        // is still FAIL. Only a share of one passes.
        let shown = Report::of(&with_blind(&reference(), Rat::ZERO)).expect("validated");
        assert!(!shown.passes());
        assert_eq!(shown.echo.gain, Some(Rat::units(200)));
        assert!(shown
            .to_string()
            .contains(&printed_row("echo trap", "strict Nash", "FAIL")));

        let half = Rat::rate(1, 2).expect("a valid rate");
        let report = Report::of(&with_blind(&reference(), half)).expect("validated");
        assert!(report.echo.gain.is_some_and(|gain| gain.is_negative()));
        assert_eq!(report.echo.trap, None);
        assert_eq!(report.echo.selective_gain, Some(Rat::units(100)));
        assert!(!report.passes());
        let printed = report.to_string();
        assert!(printed.contains(&printed_row(
            "echo where verdicts show",
            "+100.00/claim",
            "FAIL"
        )));
        // The four-action finding is untouched by any of it.
        assert_eq!(
            report.services[0],
            Report::of(&reference()).expect("validated").services[0]
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

    // -- the decomposition floor -------------------------------------------

    #[test]
    fn the_decomposition_floor_matches_the_number_the_design_note_quotes() {
        // docs/agent-market.md: "full redundancy, 100 nodes  100 x 200 x 40 =
        // 800,000 per settled artifact". A fee of 1/20 split half to verifiers
        // is a fortieth of settled value reaching them, so a verification
        // costing 200 per node needs 8,000 of settlement per node checking.
        //
        // If this number moves, either the parameters moved or the arithmetic
        // did, and the note is describing something nobody has built.
        let params = reference();
        let full = decomposition_floor(&params, params.nodes)
            .expect("validated")
            .expect("a floor exists");
        assert_eq!(full, Rat::units(800_000));

        let sampled = decomposition_floor(&params, 3)
            .expect("validated")
            .expect("a floor exists");
        assert_eq!(sampled, Rat::units(24_000));
    }

    #[test]
    fn the_floor_is_linear_in_redundancy_and_zero_fee_has_none() {
        // Linear, because each checker is paid for separately -- which is the
        // whole reason sampling is the argument it is.
        let params = reference();
        let one = decomposition_floor(&params, 1)
            .expect("validated")
            .expect("floor");
        let ten = decomposition_floor(&params, 10)
            .expect("validated")
            .expect("floor");
        assert_eq!(ten, one * Rat::int(10));

        // A redundancy of zero is read as one: nobody checking is not a
        // network with a free floor, it is a network with no verification, and
        // reporting an answer of zero would be a lie shaped like a bargain.
        assert_eq!(
            decomposition_floor(&params, 0)
                .expect("validated")
                .expect("floor"),
            one
        );

        // No fee reaching verifiers means no reward is large enough. `None` is
        // the honest answer; a division would have panicked or produced an
        // infinity nobody could act on.
        let mut free = reference();
        free.fee = Rat::ZERO;
        assert_eq!(decomposition_floor(&free, 100).expect("validated"), None);
    }
}
