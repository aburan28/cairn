"""Submitter identity: a name that is a key cannot be worn by anyone else.

``submitter`` has always been a free string, so a name was worth nothing --
anyone could submit as ``alice``, and citation flow pays that name. The rule
under test closes that without a registry or a migration: a submitter that is
64 lowercase hex characters *is* an ed25519 public key, and a record carrying
one must be signed by it.

These tests mirror the Rust suite case for case. Both implementations decide
which records are admissible, so a rule enforced in one and not the other is a
consensus split rather than a missing feature.
"""
import json
import pathlib

import pytest

from proofwork.canonical import canonical_bytes, digest
from proofwork.records import (
    Claim,
    Commitment,
    RecordError,
    SignatureError,
    signed_submitter,
    verify_record_signature,
)

REPO = pathlib.Path(__file__).resolve().parents[3]
SIGNED_RECORDS = REPO / "conformance" / "signed-records.json"
TS = "2026-07-28T00:00:00+00:00"


def _vectors():
    assert SIGNED_RECORDS.exists(), f"{SIGNED_RECORDS} is missing"
    return json.loads(SIGNED_RECORDS.read_text())


def test_a_key_shaped_name_is_recognised_without_a_lookup():
    # The name *is* the key, which is why no registry is consulted.
    assert signed_submitter("a" * 64) == "a" * 64
    assert signed_submitter("0123456789abcdef" * 4) is not None
    # Nicknames are untouched -- Stage 0 keeps working.
    assert signed_submitter("alice") is None
    assert signed_submitter("") is None
    assert signed_submitter("a" * 63) is None
    assert signed_submitter("a" * 65) is None
    # Uppercase is refused: AB.. and ab.. must not be two names for one key,
    # or one key could hold two reputations and cite itself.
    assert signed_submitter("A" * 64) is None
    # Hex-length but not hex.
    assert signed_submitter("g" * 64) is None


def test_a_nickname_needs_no_signature_but_may_not_carry_one():
    # Unchanged permissiveness for nicknames...
    verify_record_signature("claim", "alice", {"a": 1}, None)
    # ...but a signature on a nickname is refused rather than ignored, so it
    # cannot look like authentication it is not.
    with pytest.raises(SignatureError):
        verify_record_signature("claim", "alice", {"a": 1}, "00" * 64)


def test_a_key_shaped_name_without_a_signature_is_refused():
    with pytest.raises(SignatureError, match="must carry a signature"):
        verify_record_signature("claim", "a" * 64, {"a": 1}, None)


def test_the_signed_claim_vector_verifies_and_reproduces_its_id():
    # The cross-implementation assertion: Rust produced this record, and this
    # implementation must agree on its bytes, its id, and its validity.
    vector = _vectors()["claim"]
    claim = Claim.from_dict(vector["record"])
    assert canonical_bytes(claim.to_dict()).decode() == vector["canonical"]
    assert digest(claim.to_dict()) == vector["id"]
    claim.verify_signature()


def test_the_signed_commitment_vector_verifies_and_reproduces_its_id():
    vector = _vectors()["commitment"]
    record = vector["record"]
    commitment = Commitment(
        objective_id=record["objective_id"],
        submitter=record["submitter"],
        hash=record["hash"],
        created_at=record["created_at"],
        signature=record["signature"],
    )
    assert canonical_bytes(commitment.to_dict()).decode() == vector["canonical"]
    assert digest(commitment.to_dict()) == vector["id"]
    commitment.verify_signature()


def test_tampering_with_a_signed_record_breaks_it():
    # Every field the signature covers. If any of these still verified, the
    # signature would not be binding the record.
    vector = _vectors()["claim"]
    for field, replacement in [
        ("artifact", {"n": 43}),
        ("nonce", "different"),
        ("objective_id", "sha256:other"),
        ("created_at", "2026-07-29T00:00:00+00:00"),
        ("cites", ["sha256:" + "a" * 64]),
    ]:
        claim = Claim.from_dict({**vector["record"], field: replacement})
        with pytest.raises(SignatureError):
            claim.verify_signature()


def test_a_signature_cannot_be_moved_to_another_submitter():
    # Wearing someone else's name with their signature attached.
    vector = _vectors()["claim"]
    stolen = {**vector["record"], "submitter": "b" * 64}
    with pytest.raises(SignatureError):
        Claim.from_dict(stolen).verify_signature()


def test_stripping_a_signature_changes_the_record_id():
    # This is what stops a signature being removed from a claim other people
    # already cited: the id covers it, so the stripped record is a different
    # record that nobody cited.
    vector = _vectors()["claim"]
    signed = Claim.from_dict(vector["record"])
    unsigned = Claim.from_dict({k: v for k, v in vector["record"].items() if k != "signature"})
    assert digest(signed.to_dict()) != digest(unsigned.to_dict())
    # And the payload the signature covers is identical either way, which is
    # the only way the signature could have been produced.
    assert signed.signing_payload() == unsigned.signing_payload()


def test_an_unsigned_record_digests_exactly_as_it_always_did():
    # The compatibility guarantee. Adding the field must not have moved any
    # id, or every claim posted against a live bounty would be orphaned.
    claim = Claim(
        objective_id="sha256:obj",
        submitter="alice",
        artifact={"n": 1},
        nonce="s3cret",
        created_at=TS,
    )
    assert "signature" not in claim.to_dict()
    assert claim.to_dict() == claim.signing_payload()


def test_a_malformed_signature_is_refused_rather_than_raising_something_else():
    # These arrive from records other people wrote.
    for bad in ["", "zz", "00", "not-hex" * 8]:
        with pytest.raises(RecordError):
            verify_record_signature("claim", "a" * 64, {"a": 1}, bad)


def test_requiring_signed_submitters_is_off_by_default_and_omitted():
    # Adding the field must not have moved any id, so the default has to be
    # what every pre-existing objective already meant.
    from proofwork.records import Objective

    plain = Objective(
        goal="G",
        statement="s",
        verifier={"kind": "certificate", "checker": "c.py",
                  "checker_sha256": "ab" * 32, "entrypoint": "check"},
        reward=1000,
        funder="treasury",
        created_at=TS,
    )
    assert plain.require_signed_submitter is False
    assert "require_signed_submitter" not in plain.to_dict()

    strict = Objective(**{**plain.__dict__, "require_signed_submitter": True})
    # Admission rules are part of what was funded, so this is a different
    # objective -- exactly as changing the verifier is.
    assert strict.id != plain.id
    assert strict.to_dict()["require_signed_submitter"] is True
    assert Objective.from_dict(strict.to_dict()).require_signed_submitter is True


@pytest.mark.parametrize("value", ["yes", 1, 0, "true", []])
def test_a_non_boolean_policy_flag_is_refused_not_coerced(value):
    # Coercion is what a split looks like: "yes" meaning True here and False
    # in the Rust decoder is two implementations disagreeing about which
    # submissions are admissible.
    from proofwork.records import Objective

    body = Objective(
        goal="G",
        statement="s",
        verifier={"kind": "certificate", "checker": "c.py",
                  "checker_sha256": "ab" * 32, "entrypoint": "check"},
        reward=1000,
        funder="treasury",
        created_at=TS,
    ).to_dict()
    body["require_signed_submitter"] = value
    with pytest.raises(RecordError, match="boolean"):
        Objective.from_dict(body)
