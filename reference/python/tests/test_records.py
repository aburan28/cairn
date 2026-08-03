"""Record validation: confidentiality classes and the bounds that make records portable."""
import pytest

from proofwork.canonical import MAX_UNITS
from proofwork.frontier import Ratchet, RatchetError
from proofwork.records import (
    Claim,
    CONFIDENTIALITY_CLASSES,
    DEFAULT_CONFIDENTIALITY,
    Objective,
    RecordError,
)

TS = "2026-07-28T00:00:00+00:00"
VERIFIER = {
    "kind": "certificate",
    "checker": "c.py",
    "checker_sha256": "ab" * 32,
    "entrypoint": "check",
}


def objective(**overrides):
    base = dict(
        goal="GOAL-x",
        statement="find it",
        verifier=VERIFIER,
        reward=1000,
        funder="treasury",
        created_at=TS,
    )
    base.update(overrides)
    return Objective(**base)


# ---------------------------------------------------------------------------
# Confidentiality classes
# ---------------------------------------------------------------------------


def test_public_is_the_default_and_is_omitted_from_the_canonical_form():
    # The reason the default is omitted. If this ever fails, every objective in
    # every deployed log has been reissued and every claim against a live
    # bounty has been orphaned.
    obj = objective()
    assert obj.confidentiality == DEFAULT_CONFIDENTIALITY == "public"
    assert "confidentiality" not in obj.to_dict()


def test_an_embargoed_objective_is_a_different_objective():
    # Confidentiality is part of the funded question, so changing it forks the
    # objective exactly as changing the verifier does. A funder cannot move a
    # live bounty from public to embargoed after work has started.
    public = objective()
    embargoed = objective(confidentiality="embargoed")
    assert public.id != embargoed.id
    assert embargoed.to_dict()["confidentiality"] == "embargoed"


def test_sealed_is_refused_rather_than_downgraded():
    # A funder who asked for "never revealed" and silently got "revealed later"
    # would be misled about the only thing they cared about.
    with pytest.raises(RecordError, match="zero-knowledge"):
        objective(confidentiality="sealed")

    # And it cannot be smuggled in through the decoder either.
    body = objective().to_dict()
    body["confidentiality"] = "sealed"
    with pytest.raises(RecordError, match="zero-knowledge"):
        Objective.from_dict(body)


def test_an_unknown_class_is_refused_never_defaulted():
    # Defaulting an unrecognised class to "public" would publish an artifact
    # whose funder asked for something else.
    with pytest.raises(RecordError, match="unknown confidentiality class"):
        objective(confidentiality="secret")

    body = objective().to_dict()
    body["confidentiality"] = "secret"
    with pytest.raises(RecordError, match="unknown confidentiality class"):
        Objective.from_dict(body)


@pytest.mark.parametrize("value", [None, "public"])
def test_absent_or_null_decodes_as_public_with_an_unchanged_id(value):
    # Absent is the common case: every record written before this field
    # existed. Null is what a lax writer emits for "unset".
    body = objective().to_dict()
    if value is not None:
        body["confidentiality"] = value
    decoded = Objective.from_dict(body)
    assert decoded.confidentiality == "public"
    assert decoded.id == objective().id


@pytest.mark.parametrize("value", ["", 0, False, [], {}])
def test_falsy_confidentiality_is_refused_not_defaulted(value):
    # Regression: `data.get("confidentiality") or DEFAULT` treated every falsy
    # value as unset, so a record the Rust decoder refuses -- `""` is an
    # unknown class there, `0` the wrong type -- decoded here as a public
    # objective. Same bytes, two verdicts on validity, is a consensus split.
    body = objective().to_dict()
    body["confidentiality"] = value
    with pytest.raises(RecordError):
        Objective.from_dict(body)


@pytest.mark.parametrize("value", ["abc", None, 7, {"a": 1}, ["ok", 3]])
def test_cites_must_be_an_array_of_strings(value):
    # Regression: `tuple(data.get("cites", ()))` iterated whatever it was
    # handed, so `"cites": "abc"` decoded as three one-letter citations the
    # Rust side refuses -- phantom edges that would have carried citation flow.
    body = Claim(
        objective_id="sha256:" + "a" * 64,
        submitter="alice",
        artifact={"n": 1},
        nonce="s3cret",
        created_at=TS,
    ).to_dict()
    body["cites"] = value
    with pytest.raises(RecordError, match="array of claim ids"):
        Claim.from_dict(body)


def test_absent_cites_decodes_as_empty():
    body = Claim(
        objective_id="sha256:" + "a" * 64,
        submitter="alice",
        artifact={"n": 1},
        nonce="s3cret",
        created_at=TS,
    ).to_dict()
    del body["cites"]
    assert Claim.from_dict(body).cites == ()


@pytest.mark.parametrize("cls", ["public", "embargoed"])
def test_every_usable_class_round_trips(cls):
    original = objective(confidentiality=cls)
    decoded = Objective.from_dict(original.to_dict())
    assert decoded == original
    assert decoded.id == original.id


def test_the_declared_classes_are_the_documented_ones():
    assert CONFIDENTIALITY_CLASSES == ("public", "embargoed", "sealed")


# ---------------------------------------------------------------------------
# Reward bounds
# ---------------------------------------------------------------------------


def test_max_units_is_the_64_bit_ceiling():
    assert MAX_UNITS == 2**64 - 1


def test_reward_at_the_ceiling_is_allowed():
    assert objective(reward=MAX_UNITS).reward == MAX_UNITS


def test_reward_above_the_ceiling_is_refused():
    # Python has bignums and other implementations do not. Without this bound,
    # "what is a valid record" depends on which implementation you ask, and a
    # reward of 2**70 written here produces a log a 64-bit implementation cannot
    # audit. That is an interop break, so the format declares the bound and
    # every implementation enforces it.
    with pytest.raises(RecordError, match="exceeds the format maximum"):
        objective(reward=2**64)
    with pytest.raises(RecordError):
        objective(reward=2**70)


def test_negative_reward_is_refused():
    with pytest.raises(RecordError):
        objective(reward=-1)


def test_bool_is_not_an_integer_reward():
    with pytest.raises(RecordError):
        objective(reward=True)


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
