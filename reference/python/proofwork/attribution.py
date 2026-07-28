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


def ledger_payouts(node, params: FlowParams | None = None) -> dict[str, int]:
    """Total payouts across every settlement recorded in a node's log."""
    claims = {
        Claim.from_dict(e.payload).id: Claim.from_dict(e.payload)
        for e in node.ledger.entries("claim")
    }
    totals: dict[str, int] = defaultdict(int)
    for entry in node.ledger.entries("settlement"):
        payload = entry.payload
        for who, units in flow(payload["claim_id"], payload["reward"], claims, params).items():
            totals[who] += units
    return dict(totals)
