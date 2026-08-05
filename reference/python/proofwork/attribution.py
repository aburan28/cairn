"""Recursive citation flow: paying the shoulders that were stood on.

Ordinary science has never solved attribution -- authorship order is a social
negotiation, and the person who wrote the load-bearing lemma three papers back
gets a citation and nothing else. A hash-linked claim DAG makes a mechanical
answer possible: every claim names what it built on, so value can flow backwards
along real edges rather than remembered ones.

The rule: a settled claim keeps a fraction (1 - delta) of its reward and sends
delta upstream, split among the claims it cites, recursively, to a bounded
depth. Beyond that depth the remainder stays with the claim that got there.

Two properties the implementation guarantees, both tested:

- **Conservation.** Payouts sum to exactly the amount distributed. Not
  approximately -- exactly. All arithmetic is integer; delta is a rational
  ``num/den``, never a float, so every node computes the same split and rounding
  never leaks or invents a unit.
- **Determinism.** Remainders from an uneven split go to citations in sorted
  claim-id order, so two nodes always agree who got the odd unit.

This does not price contribution correctly. Nothing does. It prices *declared
dependency*, which is checkable, rather than *importance*, which is not.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Mapping

from .records import Claim


@dataclass(frozen=True)
class FlowParams:
    #: Fraction sent upstream, as an exact rational. 1/4 by default.
    delta_num: int = 1
    delta_den: int = 4
    #: How many citation hops value travels before it stops.
    max_depth: int = 6

    def __post_init__(self) -> None:
        if self.delta_den <= 0:
            raise ValueError("delta_den must be positive")
        if not 0 <= self.delta_num <= self.delta_den:
            raise ValueError("delta must lie in [0, 1]")
        if self.max_depth < 0:
            raise ValueError("max_depth must be non-negative")


def flow(
    claim_id: str,
    amount: int,
    claims: Mapping[str, Claim],
    params: FlowParams | None = None,
) -> dict[str, int]:
    """Split ``amount`` across submitters, following citations from ``claim_id``.

    Returns ``{submitter: units}``. The sum is exactly ``amount``.
    """
    params = params or FlowParams()
    payouts: dict[str, int] = defaultdict(int)
    if amount <= 0:
        return {}

    def walk(node_id: str, share: int, depth: int, path: frozenset[str]) -> None:
        claim = claims.get(node_id)
        if claim is None or share <= 0:
            # A citation we cannot resolve keeps its share with nobody; give it
            # back to the claim that cited it rather than silently burning it.
            return
        cites = sorted(c for c in claim.cites if c in claims and c not in path)
        if depth >= params.max_depth or not cites:
            payouts[claim.submitter] += share
            return

        upstream = share * params.delta_num // params.delta_den
        payouts[claim.submitter] += share - upstream
        if upstream == 0:
            return

        base, remainder = divmod(upstream, len(cites))
        for i, cited in enumerate(cites):
            portion = base + (1 if i < remainder else 0)
            if portion:
                walk(cited, portion, depth + 1, path | {node_id})

    # Unresolvable-citation shares must not vanish: run the walk, then hand any
    # shortfall to the settling claim. Conservation is not negotiable.
    walk(claim_id, amount, 0, frozenset())
    distributed = sum(payouts.values())
    if distributed < amount:
        root = claims.get(claim_id)
        if root is not None:
            payouts[root.submitter] += amount - distributed
    return dict(payouts)


def ancestors_of(claim_id: str, claims: dict[str, Claim]) -> list[str]:
    """Every transitive ancestor of ``claim_id``, sorted, excluding itself.

    **Deliberately not bounded by ``max_depth``.** That bound belongs to the
    per-hop rule, where it caps how far decay compounds. Applying it here would
    make entitlement depend on hop distance again -- and worse than the decay
    it replaced, because a cliff is sharper than a slope: a submitter could
    push an upstream contributor past the horizon by slicing and cut them to
    *zero* rather than merely thinning them.

    Cycle-safe by the visited set rather than by a path check: with a flat
    split there is no path, and an ancestor reached twice is still one
    ancestor.
    """
    root = claims.get(claim_id)
    if root is None:
        return []
    seen: set[str] = set()
    frontier = [c for c in root.cites if c in claims]
    while frontier:
        nxt: list[str] = []
        for node_id in frontier:
            if node_id == claim_id or node_id in seen:
                continue
            seen.add(node_id)
            claim = claims.get(node_id)
            if claim is None:
                continue
            nxt.extend(c for c in claim.cites if c in claims and c not in seen)
        frontier = nxt
    return sorted(seen)


def payouts_weighted(
    settlements: list[tuple[str, int]],
    claims: dict[str, Claim],
    params: FlowParams | None = None,
) -> dict[str, int]:
    """``delta`` split among all transitive ancestors, weighted by settled reward.

    The replacement for per-hop decay. Per-hop decay lets a submitter chop one
    improvement into many steps and drive an upstream contributor's citation
    flow to *zero* -- free in direct reward because the pool telescopes, and
    strictly profitable in flow. Here a downstream citer pays the upstream
    contributor the same however the middle was chopped, and the slicer's own
    premium converges instead of growing.

    Weighted by settled reward because on a ratchet that *is* the progress a
    claim moved, and telescoping guarantees the slices of one improvement sum
    to the reward of the single claim they replaced -- so the weights are
    slicing-invariant by construction, with no new input needed.

    Identity-blind: four slices by one submitter and four claims by four
    submitters produce identical numbers. Anything keyed on *who* submitted
    would have a sybil version, and minting an identity is one command.
    """
    params = params or FlowParams()
    weights = dict(settlements)
    totals: dict[str, int] = defaultdict(int)

    for claim_id, reward in settlements:
        if reward == 0:
            continue
        claim = claims.get(claim_id)
        if claim is None:
            continue

        # An ancestor that settled for nothing moved no ground to be paid for,
        # and including it would let a chain of them thin everyone who did.
        weighted = [
            (a, weights[a])
            for a in ancestors_of(claim_id, claims)
            if weights.get(a, 0) > 0
        ]
        total_weight = sum(w for _, w in weighted)
        if not weighted or total_weight == 0:
            totals[claim.submitter] += reward
            continue

        upstream = reward * params.delta_num // params.delta_den
        totals[claim.submitter] += reward - upstream
        if upstream == 0:
            continue

        # Largest-remainder, ties by sorted id. Any rule conserves; only one
        # every node reproduces from the record keeps them in agreement.
        shares = []
        for ancestor_id, weight in weighted:
            numerator = upstream * weight
            shares.append([ancestor_id, numerator // total_weight, numerator % total_weight])
        leftover = upstream - sum(share for _, share, _ in shares)
        for entry in sorted(shares, key=lambda e: (-e[2], e[0]))[:leftover]:
            entry[1] += 1

        for ancestor_id, share, _ in shares:
            if share == 0:
                continue
            ancestor = claims.get(ancestor_id)
            if ancestor is not None:
                totals[ancestor.submitter] += share
    return dict(totals)


def ledger_payouts(node, params: FlowParams | None = None) -> dict[str, int]:
    """Total payouts across every settlement recorded in a node's log."""
    claims = {
        Claim.from_dict(e.payload).id: Claim.from_dict(e.payload)
        for e in node.ledger.entries("claim")
    }
    settlements = [
        (entry.payload["claim_id"], entry.payload["reward"])
        for entry in node.ledger.entries("settlement")
    ]
    return payouts_weighted(settlements, claims, params)
