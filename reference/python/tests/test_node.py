"""End-to-end rules: commit-reveal, novelty, settlement, and the audit."""
import hashlib
from datetime import datetime, timezone

import pytest

from proofwork import verifiers
from proofwork.ledger import Ledger
from proofwork.node import Node, RuleViolation
from proofwork.partition import epoch_of, settlement_rank
from proofwork.records import Claim, Commitment, Objective, commitment_hash
from proofwork.verifiers import Status

CHECKER = '''
def check(artifact):
    return artifact.get("n") == 42
'''

TS = "2026-07-28T00:00:00+00:00"
#: Seconds since the Unix epoch for :data:`TS`, and the length of one epoch.
BASE = 1_785_196_800
EPOCH = 600


def stamp(offset: int) -> str:
    return datetime.fromtimestamp(BASE + offset, timezone.utc).isoformat(timespec="seconds")


@pytest.fixture
def env(tmp_path):
    (tmp_path / "c.py").write_text(CHECKER)
    sha = hashlib.sha256(CHECKER.encode()).hexdigest()
    node = Node(Ledger(str(tmp_path / "log.jsonl")), root=str(tmp_path))
    objective = Objective(
        goal="G",
        statement="find n = 42",
        verifier={
            "kind": "certificate",
            "checker": "c.py",
            "checker_sha256": sha,
            "entrypoint": "check",
        },
        reward=1000,
        funder="treasury",
        created_at=TS,
    )
    node.post_objective(objective, ts=TS)
    yield node, objective
    verifiers.set_root(".")


def submit(node, objective, submitter, artifact, nonce="n1", cites=(), commit=True):
    """Commit, then reveal, then close the batch.

    Three epochs, not one, and they cannot be collapsed: a reveal must be in a
    strictly later epoch than its commitment, and a batch settles only once its
    epoch is over. The offsets come off the ledger length so successive
    submissions land in successive epochs -- an epoch whose batch has already
    been paid refuses further reveals, which is the point.

    Returns the *final* outcome, so a caller can still ask "what did this
    submission earn" in one line.
    """
    step = len(node.ledger) * 4 * EPOCH
    if commit:
        digest = commitment_hash(objective.id, submitter, artifact, nonce)
        node.commit(Commitment(objective.id, submitter, digest, stamp(step)), ts=stamp(step))
    claim = Claim(objective.id, submitter, artifact, nonce, TS, tuple(cites))
    outcome = node.reveal(claim, ts=stamp(step + EPOCH))
    if not outcome.is_pending:
        return outcome
    settled = node.settle_at(stamp(step + 2 * EPOCH))
    for candidate in settled:
        if candidate.claim_id == outcome.claim_id:
            return candidate
    return outcome


def test_accepted_claim_settles(env):
    node, objective = env
    outcome = submit(node, objective, "alice", {"n": 42})
    assert outcome.verdict.status is Status.ACCEPT
    assert outcome.settled and outcome.reward == 1000
    assert node.settlement_of(objective.id)["submitter"] == "alice"


def test_rejected_claim_does_not_settle(env):
    node, objective = env
    outcome = submit(node, objective, "mallory", {"n": 41})
    assert outcome.verdict.status is Status.REJECT
    assert not outcome.settled and outcome.reward == 0
    assert node.settlement_of(objective.id) is None


def test_reveal_without_a_commitment_is_refused(env):
    # Otherwise an observer copies a revealed artifact and submits it as theirs.
    node, objective = env
    with pytest.raises(RuleViolation, match="commitment"):
        submit(node, objective, "eve", {"n": 42}, commit=False)


def test_commitment_does_not_transfer_between_submitters(env):
    node, objective = env
    artifact = {"n": 42}
    digest = commitment_hash(objective.id, "alice", artifact, "n1")
    node.commit(Commitment(objective.id, "alice", digest, stamp(0)), ts=stamp(0))
    # Eve saw alice's commitment but cannot reveal against it under her name.
    with pytest.raises(RuleViolation):
        node.reveal(Claim(objective.id, "eve", artifact, "n1", TS), ts=stamp(EPOCH))


def test_wrong_nonce_does_not_match_the_commitment(env):
    node, objective = env
    artifact = {"n": 42}
    digest = commitment_hash(objective.id, "alice", artifact, "right")
    node.commit(Commitment(objective.id, "alice", digest, stamp(0)), ts=stamp(0))
    with pytest.raises(RuleViolation):
        node.reveal(Claim(objective.id, "alice", artifact, "wrong", TS), ts=stamp(EPOCH))


def test_duplicate_artifact_verifies_but_mints_nothing(env):
    # Novelty is necessary, never sufficient. Both parties commit while the
    # objective is open (the realistic race) and both reveal in the same epoch,
    # so this is also the test that the batch pays exactly one of them -- and
    # pays the one the beacon picks, not the one that arrived first.
    node, objective = env
    artifact = {"n": 42}
    for who, nonce in (("alice", "a"), ("bob", "b")):
        digest = commitment_hash(objective.id, who, artifact, nonce)
        node.commit(Commitment(objective.id, who, digest, stamp(0)), ts=stamp(0))

    alice = node.reveal(Claim(objective.id, "alice", artifact, "a", TS), ts=stamp(EPOCH))
    bob = node.reveal(Claim(objective.id, "bob", artifact, "b", TS), ts=stamp(EPOCH))
    assert alice.is_pending and bob.is_pending
    assert node.ledger.entries("settlement") == []

    batch = node.settle_at(stamp(2 * EPOCH))
    assert len(batch) == 2
    paid = [o for o in batch if o.settled]
    unpaid = [o for o in batch if not o.settled]
    assert len(paid) == 1 and paid[0].reward == 1000
    assert unpaid[0].verdict.status is Status.ACCEPT
    assert unpaid[0].reward == 0
    # The note names the real reason: the copy would earn nothing even against
    # an open objective, so "duplicate" beats "already settled".
    assert "duplicate" in unpaid[0].note
    assert len(node.ledger.entries("settlement")) == 1

    # The winner is whoever the beacon ranks first, and the log records the
    # order so an auditor reaches the same answer.
    epoch = epoch_of(BASE + EPOCH, EPOCH)
    anchor = node._anchor_of_epoch(epoch)
    # Ranked on the commitment hash, which was fixed an epoch before the anchor
    # existed -- not on the claim id, which a submitter can still grind at
    # reveal time by choosing a different `created_at`.
    ranked = min(
        (("alice", "a", alice.claim_id), ("bob", "b", bob.claim_id)),
        key=lambda row: settlement_rank(
            epoch, anchor, commitment_hash(objective.id, row[0], artifact, row[1])
        ),
    )
    assert paid[0].claim_id == ranked[2]
    assert node.audit(rerun=True) == []


def test_commitments_are_refused_once_an_objective_is_settled(env):
    node, objective = env
    submit(node, objective, "alice", {"n": 42}, nonce="a")
    digest = commitment_hash(objective.id, "bob", {"n": 42}, "b")
    later = stamp(len(node.ledger) * 4 * EPOCH)
    with pytest.raises(RuleViolation, match="already settled"):
        node.commit(Commitment(objective.id, "bob", digest, later), ts=later)


def test_objective_settles_only_once(env):
    node, objective = env
    submit(node, objective, "alice", {"n": 42}, nonce="a")
    settlements = [
        e for e in node.ledger.entries("settlement") if e.payload["objective_id"] == objective.id
    ]
    assert len(settlements) == 1


def test_objective_with_no_registered_verifier_is_refused(tmp_path):
    node = Node(Ledger(str(tmp_path / "log.jsonl")), root=str(tmp_path))
    bad = Objective(
        goal="G",
        statement="vibes",
        verifier={"kind": "looks_good_to_me"},
        reward=1,
        funder="t",
        created_at=TS,
    )
    with pytest.raises(RuleViolation, match="no verifier"):
        node.post_objective(bad, ts=TS)


def test_unavailable_verdict_leaves_the_objective_open(tmp_path):
    # An absent toolchain must not close a funded objective.
    node = Node(Ledger(str(tmp_path / "log.jsonl")), root=str(tmp_path))
    objective = Objective(
        goal="G",
        statement="prove it",
        verifier={"kind": "lean", "statement": "theorem t : True"},
        reward=10,
        funder="t",
        created_at=TS,
    )
    node.post_objective(objective, ts=TS)
    import shutil

    original = shutil.which
    shutil.which = lambda _: None
    try:
        outcome = submit(node, objective, "alice", {"proof": ":= by trivial"})
    finally:
        shutil.which = original
    assert outcome.verdict.status is Status.UNAVAILABLE
    assert not outcome.settled
    assert node.settlement_of(objective.id) is None


def test_citations_must_point_at_accepted_claims(env):
    node, objective = env
    with pytest.raises(RuleViolation, match="citation"):
        submit(node, objective, "alice", {"n": 42}, cites=["sha256:" + "0" * 64])


def test_audit_passes_on_an_honest_log(env):
    node, objective = env
    submit(node, objective, "alice", {"n": 42})
    assert node.audit(rerun=True) == []


def test_audit_catches_a_settled_claim_that_no_longer_re_verifies(env, tmp_path):
    node, objective = env
    submit(node, objective, "alice", {"n": 42})
    # Someone swaps the checker after the fact, so its pinned hash no longer
    # matches and the ACCEPT cannot be re-derived. Reporting "log verified" here
    # would be a lie of omission -- nothing was actually checked.
    (tmp_path / "c.py").write_text(CHECKER.replace("42", "43"))
    problems = node.audit(rerun=True)
    assert any("no longer be re-verified" in p for p in problems), problems


def test_a_posted_objective_cannot_be_edited(env):
    # Content addressing makes tampering with a funded objective self-defeating
    # rather than merely detectable: the edited record hashes differently, so it
    # is a *different* objective and the claims against the original no longer
    # resolve. There is no "change the rules mid-bounty" operation to guard.
    node, _ = env
    node.ledger.entries("objective")[0].payload["reward"] = 10**9
    problems = node.audit(rerun=False)
    assert any("hash mismatch" in p for p in problems), problems


IMPURE_CHECKER = '''
import os

def check(artifact):
    # Reads state the objective does not pin -- the hazard this test exists for.
    with open(os.path.join(os.path.dirname(__file__), "threshold.txt")) as handle:
        return artifact.get("n") == int(handle.read().strip())
'''


def test_audit_flags_a_settled_claim_that_now_fails_verification(tmp_path):
    # A verifier whose behaviour depends on unpinned external state passes today
    # and fails tomorrow at the same hash. Pinning source is necessary and not
    # sufficient: a verifier must also be pure. The audit is what surfaces it.
    import hashlib

    (tmp_path / "c.py").write_text(IMPURE_CHECKER)
    (tmp_path / "threshold.txt").write_text("42")
    node = Node(Ledger(str(tmp_path / "log.jsonl")), root=str(tmp_path))
    objective = Objective(
        goal="G",
        statement="find the number",
        verifier={
            "kind": "certificate",
            "checker": "c.py",
            "checker_sha256": hashlib.sha256(IMPURE_CHECKER.encode()).hexdigest(),
            "entrypoint": "check",
        },
        reward=1000,
        funder="treasury",
        created_at=TS,
    )
    node.post_objective(objective, ts=TS)
    assert submit(node, objective, "alice", {"n": 42}).settled
    assert node.audit(rerun=True) == []

    (tmp_path / "threshold.txt").write_text("43")
    problems = node.audit(rerun=True)
    assert any("re-verification says reject" in p for p in problems), problems


def test_objective_identity_includes_its_verifier():
    # Editing an evaluator forks the objective rather than silently rescoring
    # work already done against it.
    base = dict(goal="G", statement="s", reward=1, funder="t", created_at=TS)
    a = Objective(verifier={"kind": "evaluator", "threshold": 10}, **base)
    b = Objective(verifier={"kind": "evaluator", "threshold": 11}, **base)
    assert a.id != b.id
