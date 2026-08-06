//! Citation flow: splitting a settled amount across the people it was built on.
//!
//! # Why this exists here at all
//!
//! `conformance/vectors.json` has carried an `attribution` section since it was
//! frozen, and nothing checked it. Every other section — canonical encoding,
//! Merkle roots, record ids, work assignment, the ratchet — is reproduced by
//! this crate and would fail loudly on a disagreement. The one that decides
//! **who gets paid what** had no independent implementation to disagree with.
//!
//! That is the worst place for the gap to be. A canonical-encoding divergence
//! is loud: two nodes compute different ids and nothing settles. A payout
//! divergence is silent, and both nodes carry on believing they paid the right
//! person a different amount.
//!
//! # Written from the rule, not from the code
//!
//! Transcribing the primary would make this a second copy rather than a second
//! opinion, so what follows is written from the behaviour the vectors describe:
//!
//! * A claim keeps `1 - δ` of its share and sends `δ` upstream, split evenly
//!   among the citations that resolve.
//! * The split recurses to `max_depth` hops. At the limit, or with nothing left
//!   to cite, the claim keeps everything it was given.
//! * `δ` is an exact rational. Never a float — two nodes that round differently
//!   disagree about who was paid, which is the whole reason the format has no
//!   float at all.
//! * Integer division floors, and the odd units go to the earliest citations in
//!   **sorted id order**. Any rule conserves; only one every node reproduces
//!   from the record keeps them in agreement.
//! * A submitter that keeps zero still appears, with zero. That happens
//!   whenever `δ = 1` — the claim passes everything on — and it is observable,
//!   so it is part of the format rather than an accident of how one program
//!   accumulates.
//! * An amount of zero pays nobody: an empty map, not a map of zeros.
//!
//! # Two rules that look like details and are not
//!
//! **A citation already on the path is not followed.** Claims cite by content
//! address, so a cycle needs a hash collision — but a *diamond* does not, and
//! nothing stops a claim being reachable twice by different routes. Following a
//! back-edge would pay the same claim twice for one settlement and, with a
//! cycle, would not terminate.
//!
//! **An unresolvable citation is dropped before the split, not after.** A claim
//! citing one present and one absent id splits `δ` one way, not two with half
//! burned. A node that had fetched fewer records would otherwise compute a
//! different payout for the same settlement, which is a divergence caused by
//! *sync state* rather than by the log.

use std::collections::BTreeMap;

use crate::records::Claim;

/// How much flows upstream, and how far.
#[derive(Debug, Clone, Copy)]
pub struct FlowParams {
    pub delta_num: u64,
    pub delta_den: u64,
    pub max_depth: u32,
}

/// The share of `amount` that goes upstream.
///
/// `u128` intermediate: `amount * delta_num` overflows `u64` for any large
/// settlement, and a wrapped payout invents money.
fn upstream_of(amount: u64, params: &FlowParams) -> u64 {
    if params.delta_den == 0 {
        return 0;
    }
    let scaled = u128::from(amount) * u128::from(params.delta_num);
    let upstream = scaled / u128::from(params.delta_den);
    u64::try_from(upstream).unwrap_or(amount).min(amount)
}

fn credit(payouts: &mut BTreeMap<String, u64>, who: &str, units: u64) {
    let entry = payouts.entry(who.to_string()).or_insert(0);
    *entry = entry.saturating_add(units);
}

/// Split `amount` across submitters by following citations from `claim_id`.
///
/// Recursive rather than the primary's explicit stack, deliberately: a second
/// implementation that shares a control-flow shape shares its blind spots, and
/// the depth is bounded by `max_depth` so the recursion is too.
pub fn flow(
    claim_id: &str,
    amount: u64,
    claims: &BTreeMap<String, Claim>,
    params: &FlowParams,
) -> BTreeMap<String, u64> {
    let mut payouts = BTreeMap::new();
    if amount == 0 {
        return payouts;
    }
    if !claims.contains_key(claim_id) {
        return payouts;
    }
    let mut path: Vec<String> = Vec::new();
    distribute(claim_id, amount, 0, &mut path, claims, params, &mut payouts);

    // Conservation backstop. Every branch above is meant to be exact; a unit
    // that goes missing has to land somewhere rather than being burned, and the
    // claim that was settled is where it lands.
    let distributed: u64 = payouts.values().fold(0u64, |a, v| a.saturating_add(*v));
    if let Some(shortfall) = amount.checked_sub(distributed) {
        if shortfall > 0 {
            if let Some(root) = claims.get(claim_id) {
                credit(&mut payouts, &root.submitter, shortfall);
            }
        }
    }
    payouts
}

#[allow(clippy::too_many_arguments)]
fn distribute(
    claim_id: &str,
    share: u64,
    depth: u32,
    path: &mut Vec<String>,
    claims: &BTreeMap<String, Claim>,
    params: &FlowParams,
    payouts: &mut BTreeMap<String, u64>,
) {
    let Some(claim) = claims.get(claim_id) else {
        return;
    };

    // Resolvable, not already on the path, sorted. Sorting here rather than at
    // the call site is what makes the odd-unit rule reproducible.
    let mut cites: Vec<&str> = claim
        .cites
        .iter()
        .map(String::as_str)
        .filter(|cited| claims.contains_key(*cited))
        .filter(|cited| !path.iter().any(|seen| seen == *cited))
        .collect();
    cites.sort_unstable();
    cites.dedup();

    if depth >= params.max_depth || cites.is_empty() {
        credit(payouts, &claim.submitter, share);
        return;
    }

    let upstream = upstream_of(share, params);
    credit(payouts, &claim.submitter, share.saturating_sub(upstream));
    if upstream == 0 {
        return;
    }

    let fanout = u64::try_from(cites.len()).unwrap_or(u64::MAX).max(1);
    let base = upstream / fanout;
    let remainder = upstream % fanout;

    path.push(claim_id.to_string());
    for (position, cited) in cites.iter().enumerate() {
        let position = u64::try_from(position).unwrap_or(u64::MAX);
        // The odd units to the earliest citations in sorted id order.
        let portion = if position < remainder { base + 1 } else { base };
        if portion == 0 {
            continue;
        }
        distribute(
            cited,
            portion,
            depth.saturating_add(1),
            path,
            claims,
            params,
            payouts,
        );
    }
    path.pop();
}
