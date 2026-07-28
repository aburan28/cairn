"""Confidentiality classes on Objective.

The Rust equivalents live in ``src/records.rs``; the two must agree, because a
disagreement about an objective's canonical form is a disagreement about its id
and therefore about which bounty was funded.
"""
import pytest

from proofwork.records import (
    CONFIDENTIALITY_CLASSES,
    DEFAULT_CONFIDENTIALITY,
    Objective,
    RecordError,
)

TS = "2026-07-28T00:00:00+00:00"


def objective(**overrides):
    base = dict(
        goal="GOAL-x",
        statement="find it",
        verifier={
            "kind": "certificate",
            "checker": "c.py",
            "checker_sha256": "ab" * 32,
            "entrypoint": "check",
        },
        reward=1000,
        funder="treasury",
        created_at=TS,
    )
    base.update(overrides)
    return Objective(**base)


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


@pytest.mark.parametrize("cls", ["public", "embargoed"])
def test_every_usable_class_round_trips(cls):
    original = objective(confidentiality=cls)
    decoded = Objective.from_dict(original.to_dict())
    assert decoded == original
    assert decoded.id == original.id


def test_the_declared_classes_are_the_documented_ones():
    assert CONFIDENTIALITY_CLASSES == ("public", "embargoed", "sealed")
