"""Epoch-batched commit-reveal: who may reveal when, and in what order they settle.

The rules under test here exist to take a lever away from whoever sequences the
log. Nothing in this file is about whether an artifact is correct; it is all
about whether a correct artifact can be paid to the wrong person.
"""
import hashlib
import os
from datetime import datetime, timezone

import pytest

from proofwork import verifiers
from proofwork.ledger import Ledger
from proofwork.node import BATCH, Node, RuleViolation, unix_seconds
from proofwork.partition import EPOCH_SECONDS, epoch_of, epoch_seconds, settlement_rank
from proofwork.records import Claim, Commitment, Objective, commitment_hash

CHECKER = '''
def check(artifact):
    return artifact.get("n", 0) > 0
'''

TS = "2026-07-28T00:00:00+00:00"
BASE = 1_785_196_800
EPOCH = 600


def stamp(offset: int) -> str:
    return datetime.fromtimestamp(BASE + offset, timezone.utc).isoformat(timespec="seconds")


@pytest.fixture
def env(tmp_path):
    (tmp_path / "c.py").write_text(CHECKER)
    node = Node(Ledger(str(tmp_path / "log.jsonl")), root=str(tmp_path))
    objective = Objective(
        goal="G",
        statement="find a positive n",
        verifier={
            "kind": "certificate",
            "checker": "c.py",
            "checker_sha256": hashlib.sha256(CHECKER.encode()).hexdigest(),
            "entrypoint": "check",
        },
        reward=1000,
        funder="treasury",
        created_at=TS,
    )
    node.post_objective(objective, ts=TS)
    yield node, objective
    verifiers.set_root(".")


def commit(node, objective, who, artifact, nonce, at):
    digest = commitment_hash(objective.id, who, artifact, nonce)
    node.commit(Commitment(objective.id, who, digest, at), ts=at)


def test_a_reveal_must_wait_for_an_epoch_after_its_commitment(env):
    # The commitment hides the artifact but does not stop the sequencer, who
    # sees reveals first, from opening a commitment of its own in the same
    # breath. Same-epoch reveal is the whole attack.
    node, objective = env
    artifact = {"n": 1}
    commit(node, objective, "alice", artifact, "a", stamp(0))
    with pytest.raises(RuleViolation, match="strictly later epoch"):
        node.reveal(Claim(objective.id, "alice", artifact, "a", TS), ts=stamp(EPOCH - 1))
    # One second later is a different epoch, and that is enough.
    outcome = node.reveal(Claim(objective.id, "alice", artifact, "a", TS), ts=stamp(EPOCH))
    assert outcome.is_pending


def test_an_accepted_reveal_does_not_pay_until_its_epoch_closes(env):
    node, objective = env
    artifact = {"n": 7}
    commit(node, objective, "alice", artifact, "a", stamp(0))
    outcome = node.reveal(Claim(objective.id, "alice", artifact, "a", TS), ts=stamp(EPOCH))
    assert outcome.is_pending and not outcome.settled and outcome.reward == 0
    assert node.settlement_of(objective.id) is None

    # Settling inside the same epoch is a no-op: the set of claims it would be
    # ordered against is not complete yet.
    assert node.settle_at(stamp(EPOCH + 1)) == []
    assert node.settlement_of(objective.id) is None

    paid = node.settle_at(stamp(2 * EPOCH))
    assert len(paid) == 1 and paid[0].settled and paid[0].reward == 1000
    assert node.settlement_of(objective.id)["submitter"] == "alice"


def test_draining_twice_pays_once(env):
    node, objective = env
    artifact = {"n": 7}
    commit(node, objective, "alice", artifact, "a", stamp(0))
    node.reveal(Claim(objective.id, "alice", artifact, "a", TS), ts=stamp(EPOCH))
    assert len(node.settle_at(stamp(2 * EPOCH))) == 1
    assert node.settle_at(stamp(3 * EPOCH)) == []
    assert len(node.ledger.entries("settlement")) == 1
    assert len(node.ledger.entries(BATCH)) == 1


def test_a_reveal_cannot_join_a_batch_that_has_already_been_paid(env):
    # Otherwise the ordering rule is decorative: a late reveal into a settled
    # epoch would be paid in arrival order after everyone else was ranked.
    node, objective = env
    first, second = {"n": 1}, {"n": 2}
    commit(node, objective, "alice", first, "a", stamp(0))
    commit(node, objective, "bob", second, "b", stamp(0))
    node.reveal(Claim(objective.id, "alice", first, "a", TS), ts=stamp(EPOCH))
    node.settle_at(stamp(2 * EPOCH))

    with pytest.raises(RuleViolation, match="has already settled"):
        node.reveal(Claim(objective.id, "bob", second, "b", TS), ts=stamp(EPOCH))


def test_a_timestamp_that_names_no_instant_is_refused_rather_than_defaulted(env):
    # Guessing an epoch means guessing which reveals were legal. A record whose
    # time cannot be read is refused; it is not quietly assigned to epoch zero.
    node, objective = env
    artifact = {"n": 1}
    digest = commitment_hash(objective.id, "alice", artifact, "a")
    with pytest.raises(RuleViolation, match="RFC-3339"):
        node.commit(Commitment(objective.id, "alice", digest, "yesterday"), ts=stamp(0))
    # A naive timestamp parses as a date but names no instant on the timeline.
    with pytest.raises(RuleViolation, match="RFC-3339"):
        node.commit(
            Commitment(objective.id, "alice", digest, "2026-07-28T00:00:00"), ts=stamp(0)
        )


def test_same_epoch_reveals_settle_in_beacon_order_not_arrival_order(env):
    # Two distinct artifacts against a single-payout objective: exactly one is
    # paid, and which one must not be a function of who the sequencer wrote
    # first. The check is that append order and beacon order disagree at least
    # sometimes -- and that the payout follows the beacon when they do.
    node, objective = env
    revealed = []
    for who, nonce, n in (("alice", "a", 1), ("bob", "b", 2)):
        artifact = {"n": n}
        commit(node, objective, who, artifact, nonce, stamp(0))
        revealed.append(
            (
                commitment_hash(objective.id, who, artifact, nonce),
                node.reveal(Claim(objective.id, who, artifact, nonce, TS), ts=stamp(EPOCH)),
            )
        )

    epoch = epoch_of(BASE + EPOCH, EPOCH)
    anchor = node._anchor_of_epoch(epoch)
    expected = [
        outcome.claim_id
        for _, outcome in sorted(
            revealed, key=lambda row: settlement_rank(epoch, anchor, row[0])
        )
    ]

    batch = node.settle_at(stamp(2 * EPOCH))
    assert [o.claim_id for o in batch] == expected
    assert [o.settled for o in batch] == [True, False]
    assert node.ledger.entries(BATCH)[0].payload["claims"] == expected
    assert node.audit(rerun=True) == []


def test_settlement_order_cannot_be_ground_out_at_reveal_time(env):
    # The anchor is public by the time anyone reveals, so any part of the
    # ordering key a submitter can still choose is a part they can try until it
    # sorts first. `created_at` and `cites` are exactly that -- the commitment
    # binds neither, and nothing checks them against the reveal. Ranking on the
    # commitment hash is what makes those two fields inert.
    node, objective = env
    artifact = {"n": 3}
    commit(node, objective, "alice", artifact, "a", stamp(0))
    epoch = epoch_of(BASE + EPOCH, EPOCH)
    anchor = node._anchor_of_epoch(epoch)

    key = commitment_hash(objective.id, "alice", artifact, "a")
    baseline = settlement_rank(epoch, anchor, key)
    ranks = set()
    ids = set()
    for minute in range(30):
        claim = Claim(objective.id, "alice", artifact, "a", stamp(60 * minute))
        ids.add(claim.id)
        ranks.add(settlement_rank(epoch, anchor, claim.commitment_hash()))
    assert len(ids) == 30, "the fixture must actually vary the claim id"
    assert ranks == {baseline}, "a submitter moved their own rank by restamping"


def test_audit_catches_a_batch_settled_in_the_wrong_order(env):
    # The rule constrains an honest node; only the audit constrains a dishonest
    # one. A hand-written batch that reverses the beacon order must be caught.
    node, objective = env
    for who, nonce, n in (("alice", "a", 1), ("bob", "b", 2)):
        artifact = {"n": n}
        commit(node, objective, who, artifact, nonce, stamp(0))
        node.reveal(Claim(objective.id, who, artifact, nonce, TS), ts=stamp(EPOCH))
    node.settle_at(stamp(2 * EPOCH))
    assert node.audit(rerun=False) == []

    recorded = node.ledger.entries(BATCH)[0].payload
    recorded["claims"] = list(reversed(recorded["claims"]))
    problems = node.audit(rerun=False)
    assert any("the beacon does not produce" in p for p in problems), problems


def test_audit_catches_a_batch_that_names_the_wrong_anchor(env):
    # A ground-out anchor is how a sequencer would pick the winner after seeing
    # the reveals, so the recorded value is re-derived rather than trusted.
    node, objective = env
    artifact = {"n": 1}
    commit(node, objective, "alice", artifact, "a", stamp(0))
    node.reveal(Claim(objective.id, "alice", artifact, "a", TS), ts=stamp(EPOCH))
    node.settle_at(stamp(2 * EPOCH))

    node.ledger.entries(BATCH)[0].payload["anchor"] = "0" * 64
    problems = node.audit(rerun=False)
    assert any("not the log head" in p for p in problems), problems


def test_the_epoch_length_override_changes_no_canonical_bytes(env, monkeypatch):
    # The override exists so a shell demo can finish. It is a policy dial, not a
    # format one: nothing derived from it enters a record, so a log written with
    # it and a log written without it are byte-identical.
    node, objective = env
    monkeypatch.setenv("PROOFWORK_EPOCH_SECONDS", "1")
    assert epoch_seconds() == 1
    artifact = {"n": 1}
    commit(node, objective, "alice", artifact, "a", stamp(0))
    outcome = node.reveal(Claim(objective.id, "alice", artifact, "a", TS), ts=stamp(1))
    assert outcome.is_pending
    assert node.settle_at(stamp(2))[0].settled

    claim = node.ledger.entries("claim")[0].payload
    assert "epoch" not in claim and "seconds" not in claim


def test_a_malformed_override_falls_back_rather_than_stopping_time(monkeypatch):
    # An epoch length of zero would divide by zero; a negative one would run
    # time backwards. Neither is worth a crash in a rules engine.
    for bad in ("", "0", "-5", "ten", "600.5"):
        monkeypatch.setenv("PROOFWORK_EPOCH_SECONDS", bad)
        assert epoch_seconds() == EPOCH_SECONDS, bad
    monkeypatch.delenv("PROOFWORK_EPOCH_SECONDS")
    assert epoch_seconds() == EPOCH_SECONDS


@pytest.mark.parametrize(
    "text,expected",
    [
        ("1970-01-01T00:00:00+00:00", 0),
        ("2026-07-28T00:00:00+00:00", BASE),
        ("2026-07-28T00:00:00Z", BASE),
        # An offset names the same instant as its UTC equivalent, and epochs are
        # instants -- a node in another timezone must not land in another epoch.
        ("2026-07-28T02:00:00+02:00", BASE),
        ("2026-07-27T21:00:00-03:00", BASE),
    ],
)
def test_offsets_resolve_to_the_same_instant(text, expected):
    assert unix_seconds(text) == expected


@pytest.mark.parametrize(
    "text", ["", "yesterday", "2026-07-28", "2026-07-28T00:00:00", "2026-13-01T00:00:00Z"]
)
def test_a_timestamp_that_names_no_instant_does_not_parse(text):
    assert unix_seconds(text) is None


def test_rust_and_python_agree_on_the_epoch_of_a_timestamp():
    # Both implementations derive epochs from the same instants, so a
    # disagreement here is a disagreement about which reveals were legal.
    # Values pinned by hand rather than computed, so a change in either
    # implementation's arithmetic shows up as a test failure and not as silent
    # agreement on a shared bug.
    assert epoch_of(unix_seconds("2026-07-28T00:00:00Z"), EPOCH_SECONDS) == 2_975_328
    assert epoch_of(unix_seconds("2026-07-28T00:09:59Z"), EPOCH_SECONDS) == 2_975_328
    assert epoch_of(unix_seconds("2026-07-28T00:10:00Z"), EPOCH_SECONDS) == 2_975_329


def test_the_override_is_off_by_default():
    assert os.environ.get("PROOFWORK_EPOCH_SECONDS") is None
    assert epoch_seconds() == EPOCH_SECONDS == 600
