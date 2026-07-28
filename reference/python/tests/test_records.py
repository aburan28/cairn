"""Record validation, including the bounds that make records portable."""
import pytest

from proofwork.canonical import MAX_UNITS
from proofwork.frontier import Ratchet, RatchetError
from proofwork.records import Objective, RecordError

TS = "2026-07-28T00:00:00+00:00"
VERIFIER = {"kind": "certificate", "checker": "c.py", "checker_sha256": "0" * 64,
            "entrypoint": "check"}


def objective(reward):
    return Objective(goal="G", statement="s", verifier=VERIFIER, reward=reward,
                     funder="t", created_at=TS)


def test_max_units_is_the_64_bit_ceiling():
    assert MAX_UNITS == 2**64 - 1


def test_reward_at_the_ceiling_is_allowed():
    assert objective(MAX_UNITS).reward == MAX_UNITS


def test_reward_above_the_ceiling_is_refused():
    # Python has bignums and other implementations do not. Without this bound,
    # "what is a valid record" depends on which implementation you ask, and a
    # reward of 2**70 written here produces a log a 64-bit implementation cannot
    # audit. That is an interop break, so the format declares the bound and
    # every implementation enforces it.
    with pytest.raises(RecordError, match="exceeds the format maximum"):
        objective(2**64)
    with pytest.raises(RecordError):
        objective(2**70)


def test_negative_reward_is_refused():
    with pytest.raises(RecordError):
        objective(-1)


def test_bool_is_not_an_integer_reward():
    with pytest.raises(RecordError):
        objective(True)


def test_ratchet_reward_obeys_the_same_ceiling():
    with pytest.raises(RatchetError, match="exceeds the format maximum"):
        Ratchet(baseline=0, target=10, reward=2**64)


def test_widest_representable_span_is_allowed():
    # i64::MIN to i64::MAX spans exactly u64::MAX, which a fixed-width
    # implementation holds exactly. The boundary is legal, not an overflow.
    r = Ratchet(baseline=-(2**63), target=2**63 - 1, reward=1000)
    assert r.span == 2**64 - 1


def test_scores_outside_the_signed_64_bit_range_are_refused():
    # Python integers are unbounded; a Rust score is i64. Without this bound a
    # baseline of 2**100 is writable here and unreadable everywhere else.
    with pytest.raises(RatchetError, match="signed 64-bit score range"):
        Ratchet(baseline=0, target=2**100, reward=1000)
    with pytest.raises(RatchetError, match="signed 64-bit score range"):
        Ratchet(baseline=-(2**100), target=0, reward=1000, direction="minimize")
