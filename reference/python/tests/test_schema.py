"""The published schemas are a gate, not documentation."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from proofwork import schema
from proofwork.schema import SchemaError, validate_claim, validate_objective

REPO = Path(__file__).resolve().parents[3]

OBJECTIVE = {
    "type": "objective",
    "goal": "G",
    "statement": "find a witness",
    "verifier": {"kind": "certificate", "checker": "c.py", "checker_sha256": "00"},
    "reward": 10,
    "funder": "treasury",
    "created_at": "2026-07-28T00:00:00+00:00",
}

CLAIM = {
    "type": "claim",
    "objective_id": "sha256:" + "0" * 64,
    "submitter": "alice",
    "artifact": {"witness": 3},
    "nonce": "n",
    "created_at": "2026-07-28T00:00:00+00:00",
    "cites": [],
}


def with_(base: dict, **changes) -> dict:
    body = dict(base)
    body.update(changes)
    return body


def test_a_well_formed_objective_passes():
    validate_objective(OBJECTIVE)


def test_a_well_formed_claim_passes():
    validate_claim(CLAIM)


def test_extra_fields_are_refused():
    with pytest.raises(SchemaError, match="surprise"):
        validate_objective(with_(OBJECTIVE, surprise=1))


def test_unknown_verifier_kind_is_refused_at_the_gate():
    with pytest.raises(SchemaError, match="haruspicy"):
        validate_objective(with_(OBJECTIVE, verifier={"kind": "haruspicy"}))


def test_every_registered_kind_is_in_the_published_enum():
    # The schema enum and the registry are two lists of the same thing; adding
    # a kind to one and not the other makes ``post`` refuse an objective the
    # node would happily verify.
    from proofwork.verifiers import kinds

    registered = kinds()
    assert registered
    for kind in registered:
        validate_objective(with_(OBJECTIVE, verifier={"kind": kind}))


def test_a_boolean_reward_is_not_one_unit_of_money():
    with pytest.raises(SchemaError):
        validate_objective(with_(OBJECTIVE, reward=True))


def test_a_negative_reward_is_refused():
    with pytest.raises(SchemaError, match=">= 0"):
        validate_objective(with_(OBJECTIVE, reward=-1))


def test_a_null_deadline_skips_the_date_time_check():
    validate_objective(with_(OBJECTIVE, deadline=None))
    with pytest.raises(SchemaError):
        validate_objective(with_(OBJECTIVE, deadline="soon"))


def test_confidentiality_accepts_null_and_the_three_names():
    for value in (None, "public", "embargoed", "sealed"):
        validate_objective(with_(OBJECTIVE, confidentiality=value))
    with pytest.raises(SchemaError):
        validate_objective(with_(OBJECTIVE, confidentiality="secret"))


@pytest.mark.parametrize("bad", ["", "sha256:zz", "sha512:" + "0" * 64, "0" * 64])
def test_an_objective_id_must_be_a_sha256_digest(bad):
    with pytest.raises(SchemaError):
        validate_claim(with_(CLAIM, objective_id=bad))


def test_duplicate_citations_are_refused():
    one = "sha256:" + "1" * 64
    with pytest.raises(SchemaError, match="duplicate"):
        validate_claim(with_(CLAIM, cites=[one, one]))


def test_every_shipped_example_objective_passes_the_gate():
    # An example that the gate refuses is a broken tutorial: the first thing a
    # newcomer runs is ``proofwork post examples/.../objective.json``.
    found = sorted((REPO / "examples").glob("*/objective.json"))
    assert found, "no example objectives found"
    for path in found:
        with open(path, encoding="utf-8") as handle:
            validate_objective(json.load(handle))


def test_the_shipped_schemas_use_no_unimplemented_keyword():
    # ``_check`` reports an unusable schema for a keyword it does not know, but
    # only along the path an instance happens to take. Walk the documents so a
    # keyword added to a branch no test exercises still trips here rather than
    # silently doing nothing in production.
    def walk(node, spath):
        if not isinstance(node, dict):
            return
        for key in node:
            assert (
                key in schema.ANNOTATIONS or key in schema.SUPPORTED
            ), f"{spath}: keyword {key!r} is in the schema but not implemented"
        for name, child in (node.get("properties") or {}).items():
            walk(child, f"{spath}/properties/{name}")
        if "items" in node:
            walk(node["items"], f"{spath}/items")

    walk(schema.objective_schema(), "#")
    walk(schema.claim_schema(), "#")
