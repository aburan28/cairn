//! Recursive citation flow: paying the shoulders that were stood on.
//!
//! Ordinary science has never solved attribution -- authorship order is a social
//! negotiation, and the person who wrote the load-bearing lemma three papers
//! back gets a citation and nothing else. A hash-linked claim DAG makes a
//! mechanical answer possible: every claim names what it built on, so value can
//! flow backwards along real edges rather than remembered ones.
//!
//! The rule: a settled claim keeps a fraction `1 - delta` of its reward and
//! sends `delta` upstream, split among the claims it cites, recursively, to a
//! bounded depth. Beyond that depth the remainder stays with the claim that got
//! there.
//!
//! # Two properties this module guarantees
//!
//! - **Conservation.** Payouts sum to exactly the amount distributed. Not
//!   approximately -- exactly. All arithmetic is integer; `delta` is a rational
//!   `num/den`, never a float, so every node computes the same split and
//!   rounding never leaks or invents a unit.
//! - **Determinism.** The odd unit from an uneven split goes to citations in
//!   sorted claim-id order, so two nodes always agree who got it. Rust's `str`
//!   ordering is byte-wise and the reference implementation's is by code point;
//!   UTF-8 makes those the same order, so the two agree without either
//!   special-casing the other.
//!
//! This does not price contribution correctly. Nothing does. It prices
//! *declared dependency*, which is checkable, rather than *importance*, which
//! is not.
//!
//! # Why the walk is a work stack rather than recursion
//!
//! The reference implementation recurses. Citations point backwards only, so a
//! cycle should be impossible and the depth should be small -- but "should" is
//! not a memory-safety argument when the claim DAG is attacker-supplied. Here
//! the traversal is an explicit stack, so a pathological DAG costs heap rather
//! than blowing the native stack, and every frame carries the path that reached
//! it so a node is never revisited while it is still an ancestor of itself.
//! `max_depth` bounds the walk as well; the path check is the belt to its
//! braces.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::records::Claim;

/// Default fraction sent upstream: one quarter.
const DEFAULT_DELTA_NUM: u64 = 1;
const DEFAULT_DELTA_DEN: u64 = 4;
/// Default number of citation hops value travels before it stops.
const DEFAULT_MAX_DEPTH: u32 = 6;

/// Everything that can go wrong in this module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowError {
    /// `delta_den` is zero. A zero denominator is not "delta = 0", it is a
    /// division that has no answer, so it is refused at construction rather
    /// than papered over at split time.
    ZeroDenominator,
    /// `delta_num / delta_den` is greater than one -- a claim cannot send
    /// upstream more than it received.
    DeltaAboveOne { num: u64, den: u64 },
    /// A running payout total exceeded `u64::MAX`.
    ///
    /// Python's integers are unbounded, so the reference implementation has no
    /// equivalent failure. Here the ledger's unit of account is `u64`: totalling
    /// many settlements can genuinely exceed it, and silently wrapping would
    /// mint money. Reported, never wrapped.
    PayoutOverflow { who: String },
}

impl fmt::Display for FlowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FlowError::ZeroDenominator => write!(f, "delta_den must be positive"),
            FlowError::DeltaAboveOne { num, den } => {
                write!(f, "delta must lie in [0, 1], got {num}/{den}")
            }
            FlowError::PayoutOverflow { who } => {
                write!(
                    f,
                    "payout total for {who:?} exceeds the u64 unit of account"
                )
            }
        }
    }
}

impl std::error::Error for FlowError {}

/// How far value travels, and how much of it goes.
///
/// The fields are private and the constructor validates, so a `FlowParams`
/// value that exists is a `FlowParams` that is meaningful: `delta` lies in
/// `[0, 1]` and the denominator is non-zero. That is what lets [`flow`] divide
/// by `delta_den` without a runtime guard, and it is why this type is `Copy`
/// but not constructible field-by-field.
///
/// `max_depth` is `u32` rather than a signed integer: the reference
/// implementation validates `max_depth >= 0` at runtime, and here that check is
/// unnecessary because a negative depth cannot be written down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowParams {
    /// Fraction sent upstream, as an exact rational. Never a float: two nodes
    /// that round differently disagree about who was paid.
    delta_num: u64,
    delta_den: u64,
    /// How many citation hops value travels before it stops.
    max_depth: u32,
    /// What fraction *of delta* is reserved for the citation the protocol
    /// forced, before the rest is split among everything the submitter chose
    /// to cite.
    ///
    /// # Why any of delta is reserved
    ///
    /// The discretionary split weights ancestors by settled reward, which is
    /// slicing-invariant and identity-blind and is the right rule while citable
    /// claims are *scarce*. Agent funding makes them cheap: fund your own
    /// objective, settle it yourself, and the units come back to you having
    /// bought a high-weight ancestor. Cite five of those and the frontier
    /// holder's share falls by the ratio of weights, not because anybody
    /// disputed its contribution.
    ///
    /// A reserved share is the part of that the submitter cannot dilute,
    /// because the recipient is not its choice: on a ratchet an improvement
    /// *must* cite the frontier claim it beat, and this fraction goes there
    /// whatever else is cited. It bounds the loss rather than closing the
    /// attack -- manufacturing ancestors still dilutes the discretionary
    /// remainder -- and `docs/agent-market.md` asks for the smallest reserved
    /// share that makes dilution unprofitable at a given fanout, which is a
    /// question for the harness rather than a constant to guess.
    reserved_num: u64,
    reserved_den: u64,
}

impl FlowParams {
    /// Validated constructor. `delta` must lie in `[0, 1]`.
    ///
    /// Reserves nothing. [`FlowParams::with_reserved`] is the way to ask for a
    /// reserved share, so a caller that has not thought about it gets the
    /// behaviour that existed before the field did.
    pub fn new(delta_num: u64, delta_den: u64, max_depth: u32) -> Result<FlowParams, FlowError> {
        if delta_den == 0 {
            return Err(FlowError::ZeroDenominator);
        }
        if delta_num > delta_den {
            return Err(FlowError::DeltaAboveOne {
                num: delta_num,
                den: delta_den,
            });
        }
        Ok(FlowParams {
            delta_num,
            delta_den,
            max_depth,
            reserved_num: 0,
            reserved_den: 1,
        })
    }

    /// The same parameters, reserving `reserved_num / reserved_den` **of
    /// delta** for the protocol-enforced citation.
    ///
    /// A fraction of delta rather than of the reward, so raising the reserve
    /// never takes anything from the submitter: delta is what leaves, and this
    /// only decides how it is divided. A caller that reserves the whole of
    /// delta has said "citation flow pays the frontier and nobody else", which
    /// is a coherent policy and is why one is permitted.
    pub fn with_reserved(
        self,
        reserved_num: u64,
        reserved_den: u64,
    ) -> Result<FlowParams, FlowError> {
        if reserved_den == 0 {
            return Err(FlowError::ZeroDenominator);
        }
        if reserved_num > reserved_den {
            return Err(FlowError::DeltaAboveOne {
                num: reserved_num,
                den: reserved_den,
            });
        }
        Ok(FlowParams {
            reserved_num,
            reserved_den,
            ..self
        })
    }

    pub fn delta_num(&self) -> u64 {
        self.delta_num
    }

    /// Always non-zero.
    pub fn delta_den(&self) -> u64 {
        self.delta_den
    }

    pub fn max_depth(&self) -> u32 {
        self.max_depth
    }

    pub fn reserved_num(&self) -> u64 {
        self.reserved_num
    }

    /// Always non-zero.
    pub fn reserved_den(&self) -> u64 {
        self.reserved_den
    }

    /// Of `upstream` units leaving a claim, how many are reserved.
    ///
    /// `u128` in the middle for the same reason every other product here is:
    /// both factors are `u64` and their product is not, and a wrapped reserve
    /// would silently pay the frontier holder a rounding error.
    fn reserved_of(&self, upstream: u64) -> u64 {
        let numerator = u128::from(upstream) * u128::from(self.reserved_num);
        u64::try_from(numerator / u128::from(self.reserved_den)).unwrap_or(u64::MAX)
    }
}

impl Default for FlowParams {
    /// One quarter, six hops, nothing reserved -- the reference
    /// implementation's defaults.
    ///
    /// Reserving nothing by default is deliberate: a reserve moves settled
    /// money, so it is a policy the caller states rather than one that arrives
    /// with a version bump. `docs/agent-market.md` asks the harness for the
    /// smallest reserve that makes dilution unprofitable; until that has an
    /// answer, guessing one here would be a constant nobody could defend.
    fn default() -> FlowParams {
        FlowParams {
            delta_num: DEFAULT_DELTA_NUM,
            delta_den: DEFAULT_DELTA_DEN,
            max_depth: DEFAULT_MAX_DEPTH,
            reserved_num: 0,
            reserved_den: 1,
        }
    }
}

/// One node of the traversal, and the path that reached it.
///
/// `id` is the *map key* the claim was found under, not `claim.id()`. Those are
/// normally the same, but the cycle defence has to key on what a citation
/// actually resolves to: a log whose keys disagree with the records under them
/// is exactly the case where recursion would not terminate.
struct Frame<'a> {
    id: &'a str,
    claim: &'a Claim,
    share: u64,
    depth: u32,
    /// Strict ancestors of this frame, in traversal order. Bounded by
    /// `max_depth` and by the number of distinct claims, so cloning it per
    /// child is cheap and a linear membership scan is the fastest thing
    /// available at this size.
    path: Vec<&'a str>,
}

/// Split `amount` across submitters, following citations from `claim_id`.
///
/// Returns `{submitter: units}` whose values sum to exactly `amount`.
///
/// Two behaviours are load-bearing for cross-implementation agreement and are
/// pinned by `conformance/vectors.json`:
///
/// - A submitter that keeps **zero** units still appears in the map with a zero
///   value (this happens when `delta == 1`: the claim passes everything on).
///   The reference implementation accumulates into a `defaultdict`, so the key
///   exists once it has been touched, and the vectors record it.
/// - An amount of zero pays nobody -- an empty map, not a map of zeros.
///
/// If `claim_id` is not in `claims` the result is empty. That mirrors the
/// reference implementation: there is no submitter to pay and inventing one
/// would be worse than returning nothing. Callers settle against claims that
/// are in the log by construction, so this is a programming error, not a
/// routine case.
pub fn flow(
    claim_id: &str,
    amount: u64,
    claims: &BTreeMap<String, Claim>,
    params: &FlowParams,
) -> BTreeMap<String, u64> {
    let mut payouts: BTreeMap<String, u64> = BTreeMap::new();
    if amount == 0 {
        return payouts;
    }
    let (root_id, root) = match claims.get_key_value(claim_id) {
        Some(pair) => pair,
        None => return payouts,
    };

    let mut stack: Vec<Frame<'_>> = vec![Frame {
        id: root_id.as_str(),
        claim: root,
        share: amount,
        depth: 0,
        path: Vec::new(),
    }];

    // Pop order does not affect the result: each frame's contribution is
    // independent and addition commutes. Determinism comes from the sort inside
    // `resolvable_cites`, not from the traversal order.
    while let Some(frame) = stack.pop() {
        let cites = resolvable_cites(frame.claim, claims, &frame.path);

        // Out of depth, or nothing left to pay upstream: this claim keeps the
        // lot. Note that an unresolvable citation is not a leaf's problem --
        // it was already filtered out, so a claim citing only ghosts behaves
        // exactly like a claim citing nobody.
        if frame.depth >= params.max_depth || cites.is_empty() {
            credit(&mut payouts, &frame.claim.submitter, frame.share);
            continue;
        }

        let upstream = upstream_of(frame.share, params);
        credit(
            &mut payouts,
            &frame.claim.submitter,
            frame.share.saturating_sub(upstream),
        );
        if upstream == 0 {
            continue;
        }

        // `cites` is non-empty here and a slice length always fits in u64, so
        // the divisor is structurally non-zero -- `max(1)` states that in code
        // rather than in a comment a later edit could falsify.
        let fanout = u64::try_from(cites.len()).unwrap_or(u64::MAX).max(1);
        let base = upstream / fanout;
        let remainder = upstream % fanout;

        for (position, cited) in cites.iter().enumerate() {
            // The odd units go to the earliest citations in sorted id order.
            // Any rule would conserve; only a rule every node can reproduce
            // from the record itself keeps them in agreement.
            let position = u64::try_from(position).unwrap_or(u64::MAX);
            let portion = if position < remainder {
                base.saturating_add(1)
            } else {
                base
            };
            if portion == 0 {
                continue;
            }
            if let Some((child_id, child)) = claims.get_key_value(*cited) {
                let mut path = frame.path.clone();
                path.push(frame.id);
                stack.push(Frame {
                    id: child_id.as_str(),
                    claim: child,
                    share: portion,
                    depth: frame.depth.saturating_add(1),
                    path,
                });
            }
        }
    }

    // Conservation backstop. Every path above is meant to be exact -- portions
    // sum to `upstream`, and `upstream + kept == share` -- but a unit that goes
    // missing must land somewhere rather than being quietly burned, so any
    // shortfall is handed to the claim that was settled. This costs one pass
    // and removes conservation's dependence on the citation filter staying
    // correct forever.
    let distributed = payouts
        .values()
        .try_fold(0u64, |acc, v| acc.checked_add(*v));
    if let Some(distributed) = distributed {
        // `None` means more was distributed than exists, which cannot happen;
        // `Some(0)` means the split was exact, which is the normal case.
        if let Some(shortfall) = amount.checked_sub(distributed) {
            if shortfall > 0 {
                credit(&mut payouts, &root.submitter, shortfall);
            }
        }
    }
    payouts
}
/// Total payouts across a set of settlements.
///
/// Uses [`payouts_weighted`]: δ split among all transitive ancestors weighted
/// by each one's settled reward. The per-hop rule this replaced let a
/// submitter chop one improvement into many steps and drive an upstream
/// contributor's citation flow to *zero* -- free in direct reward because the
/// pool telescopes, and strictly profitable in flow, so slicing was the
/// dominant strategy rather than an exotic attack. See
/// `docs/design/citation-flow-dilution.md`.
///
/// [`flow`] still implements the per-hop rule and is kept for a caller that
/// has one claim and no settlement context. It is **not** the money path: it
/// cannot be, because the weights come from what each ancestor settled for.
pub fn payouts_over(
    settlements: &[(String, u64)],
    claims: &BTreeMap<String, Claim>,
    params: &FlowParams,
) -> Result<BTreeMap<String, u64>, FlowError> {
    payouts_weighted(settlements, claims, params)
}

/// [`payouts_over`], told which citation the protocol forced on each claim.
///
/// `enforced` maps a settled claim's id to the ancestor it was *required* to
/// cite -- on a ratchet, the frontier claim it beat. That recipient is not the
/// submitter's choice, which is the entire reason a share can be reserved for
/// it: everything else in the citation list is chosen, and anything chosen can
/// be manufactured once funding an objective is something an agent can do.
///
/// A claim absent from `enforced` reserves nothing and splits the whole of
/// delta discretionarily, which is what every claim did before this existed.
pub fn payouts_with_enforced(
    settlements: &[(String, u64)],
    claims: &BTreeMap<String, Claim>,
    enforced: &BTreeMap<String, String>,
    params: &FlowParams,
) -> Result<BTreeMap<String, u64>, FlowError> {
    payouts_inner(settlements, claims, enforced, params)
}

/// Reward-weighted attribution: `delta` split among **all transitive
/// ancestors**, weighted by each ancestor's own settled reward.
///
/// The rule that replaced per-hop decay, and the money path since. See
/// `docs/design/citation-flow-dilution.md`.
///
/// # Why weight by settled reward
///
/// On a ratchet a claim's settled reward *is* the progress it moved, and
/// telescoping guarantees the slices of one improvement sum to the reward of
/// the single claim they replaced. So the weights are slicing-invariant by
/// construction, and no new input is needed -- the settlements the caller
/// already passes carry the measure.
///
/// # What this fixes
///
/// Per-hop decay lets a submitter chop one improvement into many steps and
/// drive an upstream contributor's citation flow to *zero* -- free in direct
/// reward because the pool telescopes, and strictly profitable in flow. Under
/// this rule a downstream citer pays the upstream contributor exactly the same
/// however the middle was chopped, and the slicer's own premium converges
/// instead of growing.
///
/// The rule is identity-blind: four slices by one submitter and four claims by
/// four submitters produce identical numbers. That matters because minting an
/// identity is one command, so anything keyed on *who* submitted would have a
/// sybil version.
pub fn payouts_weighted(
    settlements: &[(String, u64)],
    claims: &BTreeMap<String, Claim>,
    params: &FlowParams,
) -> Result<BTreeMap<String, u64>, FlowError> {
    payouts_inner(settlements, claims, &BTreeMap::new(), params)
}

fn payouts_inner(
    settlements: &[(String, u64)],
    claims: &BTreeMap<String, Claim>,
    enforced: &BTreeMap<String, String>,
    params: &FlowParams,
) -> Result<BTreeMap<String, u64>, FlowError> {
    let weights: BTreeMap<&str, u64> = settlements
        .iter()
        .map(|(id, reward)| (id.as_str(), *reward))
        .collect();
    let mut totals: BTreeMap<String, u64> = BTreeMap::new();

    for (claim_id, reward) in settlements {
        if *reward == 0 {
            continue;
        }
        let Some(claim) = claims.get(claim_id) else {
            continue;
        };

        // Ancestors carrying a non-zero weight. One that settled for nothing
        // cannot take a share -- it moved no ground to be paid for -- and
        // including it would let a chain of zero-reward claims dilute the
        // people who did move something.
        let ancestors = ancestors_of(claim_id, claims);
        let weighted: Vec<(&str, u64)> = ancestors
            .iter()
            .filter_map(|id| weights.get(id).filter(|w| **w > 0).map(|w| (*id, *w)))
            .collect();
        let total_weight: u128 = weighted.iter().map(|(_, w)| u128::from(*w)).sum();

        if weighted.is_empty() || total_weight == 0 {
            add(&mut totals, &claim.submitter, *reward)?;
            continue;
        }

        let upstream = upstream_of(*reward, params);
        add(
            &mut totals,
            &claim.submitter,
            reward.saturating_sub(upstream),
        )?;
        if upstream == 0 {
            continue;
        }

        // The reserved share, off the top and before any weighting. Its
        // recipient is the citation the *protocol* forced -- on a ratchet, the
        // frontier claim this one beat -- so it is the one share a submitter
        // cannot dilute by manufacturing ancestors, because it did not choose
        // who receives it.
        //
        // Paid only if that ancestor actually carries weight and is actually
        // an ancestor. A reserve pointed at a claim this one never cited would
        // be paying for a relationship the log does not record, and silently
        // dropping it back into the discretionary pool is the conservative
        // reading: the units still leave, and they still go upstream.
        let mut upstream = upstream;
        if let Some(target) = enforced.get(claim_id) {
            if weighted.iter().any(|(id, _)| id == target) {
                let reserved = params.reserved_of(upstream).min(upstream);
                if reserved > 0 {
                    if let Some(ancestor) = claims.get(target.as_str()) {
                        add(&mut totals, &ancestor.submitter, reserved)?;
                        upstream -= reserved;
                    }
                }
            }
        }
        if upstream == 0 {
            continue;
        }

        // Largest-remainder, resolved by sorted id. Any rule conserves; only
        // one every node reproduces from the record keeps them in agreement,
        // and `ancestors_of` returns sorted ids for exactly that reason.
        let mut allocated: u64 = 0;
        let mut shares: Vec<(&str, u64, u128)> = Vec::with_capacity(weighted.len());
        for (id, weight) in &weighted {
            let numerator = u128::from(upstream) * u128::from(*weight);
            let floor = numerator / total_weight;
            let remainder = numerator % total_weight;
            let floor = u64::try_from(floor).unwrap_or(u64::MAX);
            allocated = allocated.saturating_add(floor);
            shares.push((id, floor, remainder));
        }
        // Hand the odd units to the largest remainders first, ties by id.
        let mut order: Vec<usize> = (0..shares.len()).collect();
        order.sort_by(|a, b| {
            shares[*b]
                .2
                .cmp(&shares[*a].2)
                .then_with(|| shares[*a].0.cmp(shares[*b].0))
        });
        let mut leftover = upstream.saturating_sub(allocated);
        for index in order {
            if leftover == 0 {
                break;
            }
            shares[index].1 = shares[index].1.saturating_add(1);
            leftover -= 1;
        }

        for (id, share, _) in shares {
            if share == 0 {
                continue;
            }
            let submitter = match claims.get(id) {
                Some(ancestor) => ancestor.submitter.clone(),
                None => continue,
            };
            add(&mut totals, &submitter, share)?;
        }
    }
    Ok(totals)
}

/// Every transitive ancestor of `claim_id`, sorted, excluding itself.
///
/// **Deliberately not bounded by `max_depth`.** That bound belongs to the
/// per-hop rule, where it caps how far decay compounds. Applying it here would
/// make entitlement depend on hop distance again -- and worse than the decay
/// it replaced, because a cliff is sharper than a slope: a submitter could
/// push an upstream contributor past the horizon by slicing and cut them to
/// *zero* rather than merely thinning them. A test pins this
/// (`the_slicers_gain_converges_instead_of_growing`); it caught exactly this
/// bug when the bound was applied.
///
/// The traversal is therefore over the whole ancestor closure, which is
/// bounded by the log and costs `O(edges)` -- the same order as the audit that
/// re-derives the log in the first place.
///
/// Cycle-safe by the visited set rather than by a path check: with a flat
/// split there is no path, and an ancestor reached twice is still one
/// ancestor.
fn ancestors_of<'a>(claim_id: &str, claims: &'a BTreeMap<String, Claim>) -> Vec<&'a str> {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut frontier: Vec<&str> = match claims.get(claim_id) {
        Some(claim) => claim
            .cites
            .iter()
            .filter_map(|id| claims.get_key_value(id).map(|(k, _)| k.as_str()))
            .collect(),
        None => return Vec::new(),
    };
    while !frontier.is_empty() {
        let mut next: Vec<&str> = Vec::new();
        for id in frontier {
            if id == claim_id || !seen.insert(id) {
                continue;
            }
            if let Some(claim) = claims.get(id) {
                for cited in &claim.cites {
                    if let Some((key, _)) = claims.get_key_value(cited) {
                        if !seen.contains(key.as_str()) {
                            next.push(key.as_str());
                        }
                    }
                }
            }
        }
        frontier = next;
    }
    seen.into_iter().collect()
}

/// Add to a running total, refusing to wrap.
fn add(totals: &mut BTreeMap<String, u64>, who: &str, units: u64) -> Result<(), FlowError> {
    let total = totals.entry(who.to_string()).or_insert(0);
    match total.checked_add(units) {
        Some(sum) => {
            *total = sum;
            Ok(())
        }
        None => Err(FlowError::PayoutOverflow {
            who: who.to_string(),
        }),
    }
}

/// Citations worth following: present in `claims`, not already an ancestor on
/// this path, sorted by id.
///
/// Both filters matter. Dropping unresolvable ids here rather than at the
/// recursive call is what makes an unknown citation cost the *citing* claim
/// nothing -- its share is never split off in the first place, so there is
/// nothing to burn. Dropping ancestors is the cycle defence.
fn resolvable_cites<'a>(
    claim: &'a Claim,
    claims: &'a BTreeMap<String, Claim>,
    path: &[&'a str],
) -> Vec<&'a str> {
    let mut cites: Vec<&'a str> = claim
        .cites
        .iter()
        .map(String::as_str)
        .filter(|cited| claims.contains_key(*cited) && !path.contains(cited))
        .collect();
    cites.sort_unstable();
    cites
}

/// `floor(share * delta_num / delta_den)`, computed without overflowing.
///
/// This is the multiplication the Python port never had to think about:
/// `share * delta_num` exceeds `u64` for realistic rewards and denominators
/// even though the *result* always fits, since `delta <= 1`. The intermediate
/// is therefore `u128`, and the result is clamped to `share` so the caller's
/// `share - upstream` cannot underflow no matter what.
fn upstream_of(share: u64, params: &FlowParams) -> u64 {
    let scaled = u128::from(share).checked_mul(u128::from(params.delta_num));
    let upstream = match scaled.and_then(|s| s.checked_div(u128::from(params.delta_den))) {
        Some(value) => value,
        // Unreachable: the u128 product of two u64s cannot overflow, and
        // `FlowParams` refuses a zero denominator. Keeping the whole share
        // local is the failure mode that conserves value.
        None => return 0,
    };
    u64::try_from(upstream).unwrap_or(share).min(share)
}

/// Add `units` to a submitter's total, creating the entry if needed.
///
/// Crediting zero still creates the entry, deliberately: the reference
/// implementation's `defaultdict` does the same, and the conformance vectors
/// contain zero-valued payouts that a "skip if zero" shortcut would fail.
///
/// The addition saturates rather than wrapping. Within one [`flow`] it can
/// never reach that point -- the total credited is exactly `amount`, so no
/// single submitter can exceed it -- but if that invariant were ever broken,
/// capping a payout is a bug and minting one is a catastrophe.
fn credit(payouts: &mut BTreeMap<String, u64>, who: &str, units: u64) {
    let total = payouts.entry(who.to_string()).or_insert(0);
    *total = total.saturating_add(units);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::Value;

    const TS: &str = "2026-07-28T00:00:00+00:00";

    fn claim_of(who: &str, cites: &[String]) -> Claim {
        let artifact = crate::obj!("who" => Value::string(who));
        Claim::new("obj", who, artifact, "n", TS, cites.to_vec())
            .expect("test claim is well formed")
    }

    fn index(claims: &[Claim]) -> BTreeMap<String, Claim> {
        claims.iter().map(|c| (c.id(), c.clone())).collect()
    }

    fn expect(pairs: &[(&str, u64)]) -> BTreeMap<String, u64> {
        pairs
            .iter()
            .map(|(who, units)| ((*who).to_string(), *units))
            .collect()
    }

    fn params(num: u64, den: u64, depth: u32) -> FlowParams {
        FlowParams::new(num, den, depth).expect("test params are valid")
    }

    /// The DAG the conformance vectors are generated over: carol cites alice
    /// and bob, dave cites carol and alice.
    fn diamond() -> (Vec<Claim>, BTreeMap<String, Claim>) {
        let a = claim_of("alice", &[]);
        let b = claim_of("bob", &[]);
        let c = claim_of("carol", &[a.id(), b.id()]);
        let d = claim_of("dave", &[c.id(), a.id()]);
        let claims = index(&[a.clone(), b.clone(), c.clone(), d.clone()]);
        (vec![a, b, c, d], claims)
    }

    fn total(payouts: &BTreeMap<String, u64>) -> u128 {
        payouts.values().map(|v| u128::from(*v)).sum()
    }

    #[test]
    fn claim_with_no_citations_keeps_everything() {
        let solo = claim_of("alice", &[]);
        let claims = index(std::slice::from_ref(&solo));
        assert_eq!(
            flow(&solo.id(), 1000, &claims, &FlowParams::default()),
            expect(&[("alice", 1000)])
        );
    }

    #[test]
    fn one_hop_split() {
        let base = claim_of("alice", &[]);
        let built = claim_of("bob", &[base.id()]);
        let claims = index(&[base, built.clone()]);
        assert_eq!(
            flow(&built.id(), 1000, &claims, &params(1, 4, 6)),
            expect(&[("bob", 750), ("alice", 250)])
        );
    }

    #[test]
    fn two_hops_decay() {
        let a = claim_of("alice", &[]);
        let b = claim_of("bob", &[a.id()]);
        let c = claim_of("carol", &[b.id()]);
        let claims = index(&[a, b, c.clone()]);
        // 250 goes upstream from carol; bob keeps 250 - floor(250/4) = 188.
        assert_eq!(
            flow(&c.id(), 1000, &claims, &params(1, 4, 6)),
            expect(&[("carol", 750), ("bob", 188), ("alice", 62)])
        );
    }

    #[test]
    fn conservation_is_exact_for_every_amount_and_delta() {
        // Rounding must never leak or invent a unit, at any amount or delta.
        let (records, claims) = diamond();
        let dave = records.last().expect("diamond has four claims").id();
        for amount in [1u64, 2, 3, 7, 999, 1000, 1_000_000, 1_000_000_007, u64::MAX] {
            for (num, den) in [(0u64, 1u64), (1, 3), (1, 4), (1, 2), (2, 3), (1, 1)] {
                let payouts = flow(&dave, amount, &claims, &params(num, den, 8));
                assert_eq!(
                    total(&payouts),
                    u128::from(amount),
                    "amount {amount} delta {num}/{den} did not conserve"
                );
            }
        }
    }

    #[test]
    fn conformance_diamond_matches_the_reference_implementation() {
        // Spot checks lifted from conformance/vectors.json.
        let (records, claims) = diamond();
        let dave = records.last().expect("diamond has four claims");
        assert_eq!(
            flow(&dave.id(), 1000, &claims, &params(1, 4, 6)),
            expect(&[("dave", 750), ("alice", 140), ("carol", 94), ("bob", 16)])
        );
        assert_eq!(
            flow(&dave.id(), 3, &claims, &params(1, 2, 8)),
            expect(&[("dave", 2), ("alice", 1)])
        );
        assert_eq!(
            flow(&dave.id(), 1_000_000_007, &claims, &params(2, 3, 8)),
            expect(&[
                ("dave", 333_333_336),
                ("alice", 444_444_447),
                ("carol", 111_111_112),
                ("bob", 111_111_112),
            ])
        );
        assert_eq!(
            flow(&dave.id(), 1000, &claims, &params(1, 4, 0)),
            expect(&[("dave", 1000)])
        );
    }

    #[test]
    fn a_submitter_that_keeps_nothing_still_appears_with_zero() {
        // delta == 1 passes the whole share on. The vectors record the zero
        // entries, so dropping them would break cross-implementation equality.
        let (records, claims) = diamond();
        let dave = records.last().expect("diamond has four claims");
        assert_eq!(
            flow(&dave.id(), 1000, &claims, &params(1, 1, 2)),
            expect(&[("dave", 0), ("alice", 750), ("carol", 0), ("bob", 250)])
        );
    }

    #[test]
    fn share_times_delta_num_does_not_overflow_u64() {
        // u64::MAX * 2 overflows u64; the u128 intermediate is the whole point.
        let (records, claims) = diamond();
        let dave = records.last().expect("diamond has four claims");
        let payouts = flow(&dave.id(), u64::MAX, &claims, &params(2, 3, 8));
        assert_eq!(
            payouts,
            expect(&[
                ("dave", 6_148_914_691_236_517_205),
                ("alice", 8_198_552_921_648_689_606),
                ("carol", 2_049_638_230_412_172_402),
                ("bob", 2_049_638_230_412_172_402),
            ])
        );
        assert_eq!(total(&payouts), u128::from(u64::MAX));
    }

    #[test]
    fn uneven_split_is_deterministic_and_sorted() {
        // Three citations, 500 to divide: the two lowest ids get the odd units.
        let a = claim_of("alice", &[]);
        let b = claim_of("bob", &[]);
        let c = claim_of("carol", &[]);
        let d = claim_of("dave", &[a.id(), b.id(), c.id()]);
        let claims = index(&[a.clone(), b.clone(), c.clone(), d.clone()]);
        let first = flow(&d.id(), 1001, &claims, &params(1, 2, 4));
        assert_eq!(
            first,
            expect(&[("dave", 501), ("carol", 167), ("bob", 167), ("alice", 166)])
        );
        // Sorted-id order, not construction order: carol and bob hold the two
        // lowest ids in this fixture.
        let mut ids = [a.id(), b.id(), c.id()];
        ids.sort();
        assert_eq!(ids[0], c.id());
        assert_eq!(ids[2], a.id());
        for _ in 0..20 {
            assert_eq!(flow(&d.id(), 1001, &claims, &params(1, 2, 4)), first);
        }
    }

    #[test]
    fn depth_cap_stops_the_flow() {
        let mut chain = vec![claim_of("a0", &[])];
        for i in 1..10 {
            let previous = chain.last().expect("chain is never empty").id();
            chain.push(claim_of(&format!("a{i}"), &[previous]));
        }
        let claims = index(&chain);
        let top = chain.last().expect("chain is never empty").id();
        let payouts = flow(&top, 1_000_000, &claims, &params(1, 2, 2));
        assert_eq!(
            payouts,
            expect(&[("a9", 500_000), ("a8", 250_000), ("a7", 250_000)])
        );
        assert!(
            !payouts.contains_key("a6"),
            "value travelled further than max_depth"
        );
    }

    #[test]
    fn delta_zero_pays_only_the_settling_claim() {
        let a = claim_of("alice", &[]);
        let b = claim_of("bob", &[a.id()]);
        let claims = index(&[a, b.clone()]);
        assert_eq!(
            flow(&b.id(), 500, &claims, &params(0, 1, 6)),
            expect(&[("bob", 500)])
        );
    }

    #[test]
    fn unresolvable_citation_does_not_burn_value() {
        let ghost = format!("sha256:{}", "0".repeat(64));
        let orphan = claim_of("bob", &[ghost]);
        let claims = index(std::slice::from_ref(&orphan));
        let payouts = flow(&orphan.id(), 800, &claims, &FlowParams::default());
        assert_eq!(payouts, expect(&[("bob", 800)]));
    }

    #[test]
    fn self_citation_cycle_terminates() {
        // A log whose key does not match the record under it: following
        // alice's id lands back on the looping claim. Value must stop.
        let a = claim_of("alice", &[]);
        let artifact = crate::obj!("x" => Value::Int(1));
        let looped = Claim::new("obj", "alice", artifact, "n", "t", vec![a.id()])
            .expect("looped claim is well formed");
        let mut claims = BTreeMap::new();
        claims.insert(a.id(), looped.clone());
        claims.insert(looped.id(), looped.clone());
        let payouts = flow(&looped.id(), 100, &claims, &FlowParams::default());
        assert_eq!(total(&payouts), 100);
        assert_eq!(payouts, expect(&[("alice", 100)]));
    }

    #[test]
    fn mutual_citation_cycle_terminates() {
        let x = claim_of("alice", &[]);
        let y = claim_of("bob", &[x.id()]);
        let mut claims = BTreeMap::new();
        claims.insert(x.id(), y.clone());
        claims.insert(y.id(), y.clone());
        let payouts = flow(&y.id(), 1000, &claims, &params(1, 2, 10));
        assert_eq!(payouts, expect(&[("bob", 1000)]));
    }

    #[test]
    fn a_deep_chain_does_not_exhaust_the_stack() {
        // delta == 1 with a 50-long chain: every unit walks the whole way up.
        // The explicit work stack is what keeps this a heap cost.
        let mut chain = vec![claim_of("a0", &[])];
        for i in 1..50 {
            let previous = chain.last().expect("chain is never empty").id();
            chain.push(claim_of(&format!("a{i}"), &[previous]));
        }
        let claims = index(&chain);
        let top = chain.last().expect("chain is never empty").id();
        let payouts = flow(&top, 1, &claims, &params(1, 1, 100));
        assert_eq!(total(&payouts), 1);
        assert_eq!(payouts.get("a0"), Some(&1));
        assert_eq!(
            payouts.len(),
            50,
            "every hop is recorded, most of them zero"
        );
    }

    #[test]
    fn zero_amount_pays_nobody() {
        let a = claim_of("alice", &[]);
        let claims = index(std::slice::from_ref(&a));
        assert!(flow(&a.id(), 0, &claims, &FlowParams::default()).is_empty());
    }

    #[test]
    fn unknown_settling_claim_pays_nobody() {
        let (_, claims) = diamond();
        let unknown = format!("sha256:{}", "1".repeat(64));
        assert!(flow(&unknown, 500, &claims, &FlowParams::default()).is_empty());
    }

    #[test]
    fn invalid_params_are_rejected() {
        assert_eq!(
            FlowParams::new(3, 2, 4),
            Err(FlowError::DeltaAboveOne { num: 3, den: 2 })
        );
        assert_eq!(FlowParams::new(1, 0, 4), Err(FlowError::ZeroDenominator));
        // Zero depth is legal -- it means "pay only the settling claim".
        assert!(FlowParams::new(1, 4, 0).is_ok());
        assert_eq!(FlowParams::default(), params(1, 4, 6));
    }

    #[test]
    fn payouts_over_totals_every_settlement() {
        let (records, claims) = diamond();
        let bob = records.get(1).expect("diamond has four claims");
        let carol = records.get(2).expect("diamond has four claims");
        let dave = records.get(3).expect("diamond has four claims");
        let settlements = vec![(dave.id(), 1000u64), (bob.id(), 40), (carol.id(), 100)];
        let totals = payouts_over(&settlements, &claims, &params(1, 4, 6))
            .expect("no overflow at this size");
        // Alice is absent from `settlements`, so she has no *measured*
        // contribution and takes no weight -- see
        // `an_unsettled_ancestor_takes_no_share` for why that is the rule and
        // when it matters. Dave's delta therefore splits between bob and
        // carol in the ratio of what they settled for, 40:100.
        assert_eq!(
            totals,
            expect(&[("dave", 750), ("carol", 254), ("bob", 136)])
        );
        assert_eq!(
            total(&totals),
            1140,
            "conservation holds across settlements"
        );
    }

    #[test]
    fn an_unsettled_ancestor_takes_no_share() {
        // The weights are settled rewards, because on a ratchet that is the
        // progress a claim moved. An ancestor with nothing settled has no
        // measured contribution, so it takes nothing and its share goes to
        // the ancestors that do -- rather than being burned, which would
        // break conservation, or guessed at, which would invent a number the
        // log does not contain.
        //
        // This is a statement about *timing*, not entitlement: `ledger_payouts`
        // draws settlements from the whole log, so a claim that has settled at
        // all is weighted. A claim whose epoch has not closed yet is simply
        // not paid yet, and neither is its upstream flow.
        let (records, claims) = diamond();
        let dave = records.get(3).expect("diamond has four claims");
        let bob = records.get(1).expect("diamond has four claims");

        let without_alice = payouts_over(
            &[(dave.id(), 1000u64), (bob.id(), 100)],
            &claims,
            &params(1, 4, 6),
        )
        .expect("no overflow");
        assert_eq!(without_alice.get("alice"), None);
        assert_eq!(total(&without_alice), 1100, "still conserves exactly");

        // Once alice settles, she is weighted like anyone else.
        let alice = records.first().expect("diamond has four claims");
        let with_alice = payouts_over(
            &[(dave.id(), 1000u64), (bob.id(), 100), (alice.id(), 500)],
            &claims,
            &params(1, 4, 6),
        )
        .expect("no overflow");
        assert!(
            with_alice.get("alice").copied().unwrap_or(0) > 500,
            "alice should receive her own settlement plus upstream flow"
        );
        assert_eq!(total(&with_alice), 1600, "still conserves exactly");
    }

    #[test]
    fn payouts_over_reports_overflow_rather_than_wrapping() {
        let solo = claim_of("alice", &[]);
        let claims = index(std::slice::from_ref(&solo));
        let settlements = vec![(solo.id(), u64::MAX), (solo.id(), 1)];
        assert_eq!(
            payouts_over(&settlements, &claims, &FlowParams::default()),
            Err(FlowError::PayoutOverflow {
                who: "alice".to_string()
            })
        );
    }

    #[test]
    fn upstream_of_uses_a_wide_intermediate() {
        // The bug this guards: u64::MAX * 2 wraps, and 2/3 of u64::MAX is not
        // a small number.
        let p = params(2, 3, 6);
        assert_eq!(upstream_of(u64::MAX, &p), 12_297_829_382_473_034_410);
        assert_eq!(upstream_of(u64::MAX, &params(1, 1, 6)), u64::MAX);
        assert_eq!(upstream_of(u64::MAX, &params(0, 1, 6)), 0);
        assert_eq!(upstream_of(3, &params(1, 2, 6)), 1, "floor, never round");
        assert_eq!(upstream_of(0, &p), 0);
    }

    #[test]
    fn credit_creates_a_zero_entry() {
        let mut payouts = BTreeMap::new();
        credit(&mut payouts, "alice", 0);
        assert_eq!(payouts.get("alice"), Some(&0));
        credit(&mut payouts, "alice", 5);
        assert_eq!(payouts.get("alice"), Some(&5));
        credit(&mut payouts, "alice", u64::MAX);
        assert_eq!(
            payouts.get("alice"),
            Some(&u64::MAX),
            "saturates rather than wrapping"
        );
    }
}
