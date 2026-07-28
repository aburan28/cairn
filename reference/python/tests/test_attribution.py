"""Citation flow. Conservation is exact, not approximate."""
import pytest

from proofwork.attribution import FlowParams, flow
from proofwork.records import Claim


def claim(submitter: str, cites=(), nonce="n") -> Claim:
    return Claim(
        objective_id="obj",
        submitter=submitter,
        artifact={"who": submitter},
        nonce=nonce,
        created_at="2026-07-28T00:00:00+00:00",
        cites=tuple(cites),
    )


def index(*claims: Claim) -> dict[str, Claim]:
    return {c.id: c for c in claims}


def test_claim_with_no_citations_keeps_everything():
    solo = claim("alice")
    assert flow(solo.id, 1000, index(solo)) == {"alice": 1000}


def test_one_hop_split():
    base = claim("alice")
    built = claim("bob", cites=[base.id])
    payouts = flow(built.id, 1000, index(base, built), FlowParams(1, 4, 6))
    assert payouts == {"bob": 750, "alice": 250}


def test_two_hops_decay():
    a = claim("alice")
    b = claim("bob", cites=[a.id])
    c = claim("carol", cites=[b.id])
    payouts = flow(c.id, 1000, index(a, b, c), FlowParams(1, 4, 6))
    assert payouts["carol"] == 750
    assert payouts["bob"] == 188  # 250 - floor(250/4)
    assert payouts["alice"] == 62
    assert sum(payouts.values()) == 1000


@pytest.mark.parametrize("amount", [1, 2, 3, 7, 999, 1000, 10**6, 10**9 + 7])
@pytest.mark.parametrize("delta", [(0, 1), (1, 3), (1, 4), (1, 2), (2, 3), (1, 1)])
def test_conservation_is_exact(amount, delta):
    # Rounding must never leak or invent a unit, at any amount or any delta.
    a = claim("alice")
    b = claim("bob")
    c = claim("carol", cites=[a.id, b.id])
    d = claim("dave", cites=[c.id, a.id])
    claims = index(a, b, c, d)
    payouts = flow(d.id, amount, claims, FlowParams(delta[0], delta[1], 8))
    assert sum(payouts.values()) == amount


def test_uneven_split_is_deterministic():
    # Three citations, one indivisible remainder: every node must agree who
    # gets the odd unit.
    a, b, c = claim("alice"), claim("bob"), claim("carol")
    d = claim("dave", cites=[a.id, b.id, c.id])
    claims = index(a, b, c, d)
    first = flow(d.id, 1001, claims, FlowParams(1, 2, 4))
    for _ in range(20):
        assert flow(d.id, 1001, claims, FlowParams(1, 2, 4)) == first


def test_diamond_accumulates_both_paths():
    root = claim("alice")
    left = claim("bob", cites=[root.id])
    right = claim("carol", cites=[root.id])
    top = claim("dave", cites=[left.id, right.id])
    payouts = flow(top.id, 10_000, index(root, left, right, top), FlowParams(1, 2, 6))
    assert payouts["alice"] > 0
    assert sum(payouts.values()) == 10_000


def test_depth_cap_stops_the_flow():
    chain = [claim("a0")]
    for i in range(1, 10):
        chain.append(claim(f"a{i}", cites=[chain[-1].id]))
    claims = index(*chain)
    payouts = flow(chain[-1].id, 10**6, claims, FlowParams(1, 2, 2))
    assert "a6" not in payouts, "value travelled further than max_depth"
    assert sum(payouts.values()) == 10**6


def test_delta_zero_pays_only_the_settling_claim():
    a = claim("alice")
    b = claim("bob", cites=[a.id])
    assert flow(b.id, 500, index(a, b), FlowParams(0, 1, 6)) == {"bob": 500}


def test_unresolvable_citation_does_not_burn_value():
    orphan = claim("bob", cites=["sha256:" + "0" * 64])
    payouts = flow(orphan.id, 800, index(orphan))
    assert sum(payouts.values()) == 800
    assert payouts == {"bob": 800}


def test_self_citation_cycle_terminates():
    a = claim("alice")
    looped = Claim(
        objective_id="obj",
        submitter="alice",
        artifact={"x": 1},
        nonce="n",
        created_at="t",
        cites=(a.id,),
    )
    claims = {a.id: looped, looped.id: looped}
    assert sum(flow(looped.id, 100, claims).values()) == 100


def test_zero_amount_pays_nobody():
    a = claim("alice")
    assert flow(a.id, 0, index(a)) == {}


def test_invalid_params_are_rejected():
    with pytest.raises(ValueError):
        FlowParams(3, 2, 4)
    with pytest.raises(ValueError):
        FlowParams(1, 0, 4)
    with pytest.raises(ValueError):
        FlowParams(1, 4, -1)
