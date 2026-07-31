"""Progressive bounties: the mechanism that makes publishing safe."""
import hashlib
from datetime import datetime, timezone

import pytest

from proofwork import verifiers
from proofwork.frontier import Ratchet, RatchetError
from proofwork.ledger import Ledger
from proofwork.node import Node, RuleViolation
from proofwork.records import Claim, Commitment, Objective, commitment_hash

TS = "2026-07-28T00:00:00+00:00"
#: Seconds since the Unix epoch for :data:`TS`, and the length of one epoch.
BASE = 1_785_196_800
EPOCH = 600


def stamp(offset: int) -> str:
    return datetime.fromtimestamp(BASE + offset, timezone.utc).isoformat(timespec="seconds")


EVALUATOR = '''
def score(artifact):
    return artifact.get("score", 0)
'''


# -- the arithmetic --------------------------------------------------------


def test_payouts_telescope_to_the_pool():
    r = Ratchet(baseline=0, target=100, reward=1_000_000)
    total = 0
    previous = None
    for score in (5, 17, 40, 41, 88, 100):
        total += r.payout(previous, score)
        previous = score
    assert total == 1_000_000


@pytest.mark.parametrize("reward", [1, 7, 999, 10**6, 10**9 + 7])
@pytest.mark.parametrize("steps", [[50, 100], [1, 2, 3, 99, 100], list(range(1, 101))])
def test_pool_is_never_overspent_however_the_curve_is_chopped(reward, steps):
    # Someone submitting 100 one-point improvements must not extract more than
    # someone submitting a single 100-point improvement.
    r = Ratchet(baseline=0, target=100, reward=reward)
    total, previous = 0, None
    for score in steps:
        total += r.payout(previous, score)
        previous = score
    assert total == reward


def test_overshooting_the_target_pays_no_more():
    r = Ratchet(baseline=0, target=10, reward=1000)
    assert r.payout(None, 10) == 1000
    assert r.payout(None, 10_000) == 1000
    assert r.payout(10, 10_000) == 0


def test_no_payout_below_baseline():
    r = Ratchet(baseline=50, target=100, reward=1000)
    assert r.payout(None, 10) == 0
    assert r.payout(None, 50) == 0
    assert r.payout(None, 75) == 500


def test_regression_pays_nothing():
    r = Ratchet(baseline=0, target=100, reward=1000)
    assert r.payout(80, 20) == 0
    assert not r.improves(80, 20)


def test_minimize_direction():
    r = Ratchet(baseline=100, target=0, reward=1000, direction="minimize")
    assert r.payout(None, 50) == 500
    assert r.payout(50, 25) == 250
    assert not r.improves(50, 75)


def test_min_improvement_blocks_epsilon_farming():
    r = Ratchet(baseline=0, target=1000, reward=1000, min_improvement=10)
    assert not r.improves(100, 105)
    assert r.improves(100, 110)


def test_invalid_ratchets_are_refused():
    with pytest.raises(RatchetError):
        Ratchet(baseline=100, target=10, reward=1)  # target below baseline when maximizing
    with pytest.raises(RatchetError):
        Ratchet(baseline=0, target=10, reward=-1)
    with pytest.raises(RatchetError):
        Ratchet(baseline=0, target=10, reward=1, direction="sideways")
    with pytest.raises(RatchetError):
        Ratchet(baseline=0, target=10, reward=1, min_improvement=0)


# -- the node integration --------------------------------------------------


@pytest.fixture
def env(tmp_path):
    (tmp_path / "e.py").write_text(EVALUATOR)
    sha = hashlib.sha256(EVALUATOR.encode()).hexdigest()
    node = Node(Ledger(str(tmp_path / "log.jsonl")), root=str(tmp_path))
    objective = Objective(
        goal="G",
        statement="maximize the score",
        verifier={
            "kind": "evaluator",
            "evaluator": "e.py",
            "evaluator_sha256": sha,
            "entrypoint": "score",
            "threshold": 0,
            "direction": "maximize",
        },
        reward=1_000_000,
        funder="treasury",
        created_at=TS,
        ratchet={"baseline": 0, "target": 100, "reward": 1_000_000, "direction": "maximize"},
    )
    node.post_objective(objective, ts=TS)
    yield node, objective
    verifiers.set_root(".")


def improve(node, objective, who, score, nonce, cites=()):
    """Commit, reveal a strictly later epoch, then close the batch.

    Three epochs because the rules need three: a reveal must beat its
    commitment's epoch, and a batch pays only once its epoch is over. Stepping
    off the ledger length keeps successive improvements in successive epochs,
    which also means each one sees the previous frontier -- exactly the
    sequencing a chain of improvements has in practice.
    """
    artifact = {"score": score}
    step = len(node.ledger) * 4 * EPOCH
    digest = commitment_hash(objective.id, who, artifact, nonce)
    node.commit(Commitment(objective.id, who, digest, stamp(step)), ts=stamp(step))
    claim = Claim(objective.id, who, artifact, nonce, TS, tuple(cites))
    outcome = node.reveal(claim, ts=stamp(step + EPOCH))
    if not outcome.is_pending:
        return outcome
    settled = node.settle_at(stamp(step + 2 * EPOCH))
    for candidate in settled:
        if candidate.claim_id == outcome.claim_id:
            return candidate
    return outcome


def test_first_improvement_advances_the_frontier(env):
    node, objective = env
    outcome = improve(node, objective, "alice", 40, "n1")
    assert outcome.settled and outcome.reward == 400_000
    assert node.frontier_of(objective.id).holder == "alice"


def test_second_improvement_pays_only_the_delta(env):
    node, objective = env
    first = improve(node, objective, "alice", 40, "n1")
    second = improve(node, objective, "bob", 65, "n2", cites=[first.claim_id])
    assert second.reward == 250_000
    assert node.frontier_of(objective.id).holder == "bob"


def test_an_improvement_must_cite_the_frontier(env):
    # Mechanical attribution: you improved on the public frontier, so you cite
    # it, and citation flow pays its holder without anyone exercising judgement.
    node, objective = env
    improve(node, objective, "alice", 40, "n1")
    with pytest.raises(RuleViolation, match="must cite the frontier"):
        improve(node, objective, "bob", 65, "n2")


def test_copying_the_frontier_earns_nothing(env):
    # The reason publishing is safe: a copied artifact moves the frontier zero
    # and pays zero, so hoarding buys nothing.
    node, objective = env
    first = improve(node, objective, "alice", 40, "n1")
    outcome = improve(node, objective, "eve", 40, "n2", cites=[first.claim_id])
    assert not outcome.settled and outcome.reward == 0
    assert "does not improve" in outcome.note
    assert node.frontier_of(objective.id).holder == "alice"


def test_a_worse_result_does_not_take_the_frontier(env):
    node, objective = env
    first = improve(node, objective, "alice", 60, "n1")
    outcome = improve(node, objective, "bob", 30, "n2", cites=[first.claim_id])
    assert not outcome.settled
    assert node.frontier_of(objective.id).score == 60


def test_the_pool_is_exactly_exhausted_at_the_target(env):
    node, objective = env
    previous = None
    total = 0
    for who, score in (("alice", 20), ("bob", 55), ("carol", 90), ("dave", 100)):
        outcome = improve(
            node, objective, who, score, f"n-{who}", cites=[previous] if previous else ()
        )
        total += outcome.reward
        previous = outcome.claim_id
    assert total == 1_000_000
    assert "pool exhausted" in outcome.note
    assert node.audit(rerun=True) == []


def test_audit_rejects_an_overspent_pool(env):
    node, objective = env
    improve(node, objective, "alice", 100, "n1")
    node.ledger.append(
        "settlement",
        {
            "objective_id": objective.id,
            "claim_id": node.frontier_of(objective.id).claim_id,
            "submitter": "eve",
            "reward": 5_000_000,
        },
        TS,
    )
    assert any("against a pool of" in p for p in node.audit(rerun=False))


def test_audit_rejects_a_frontier_that_moves_backwards(env):
    node, objective = env
    first = improve(node, objective, "alice", 60, "n1")
    node.ledger.append(
        "frontier",
        {
            "objective_id": objective.id,
            "claim_id": first.claim_id,
            "holder": "eve",
            "score": 5,
            "paid_cumulative": 600_000,
        },
        TS,
    )
    assert any("without improving" in p for p in node.audit(rerun=False))


def test_progressive_objective_accepts_many_settlements(env):
    node, objective = env
    first = improve(node, objective, "alice", 30, "n1")
    improve(node, objective, "bob", 70, "n2", cites=[first.claim_id])
    settlements = [
        e for e in node.ledger.entries("settlement") if e.payload["objective_id"] == objective.id
    ]
    assert len(settlements) == 2
    assert node.audit(rerun=True) == []


def test_ratchet_needs_a_score_producing_verifier(tmp_path):
    node = Node(Ledger(str(tmp_path / "log.jsonl")), root=str(tmp_path))
    objective = Objective(
        goal="G",
        statement="prove it",
        verifier={"kind": "lean", "statement": "theorem t : True"},
        reward=100,
        funder="t",
        created_at=TS,
        ratchet={"baseline": 0, "target": 10, "reward": 100},
    )
    with pytest.raises(RuleViolation, match="score-producing"):
        node.post_objective(objective, ts=TS)


def test_ratchet_and_objective_rewards_must_agree(tmp_path):
    (tmp_path / "e.py").write_text(EVALUATOR)
    sha = hashlib.sha256(EVALUATOR.encode()).hexdigest()
    node = Node(Ledger(str(tmp_path / "log.jsonl")), root=str(tmp_path))
    objective = Objective(
        goal="G",
        statement="s",
        verifier={
            "kind": "evaluator",
            "evaluator": "e.py",
            "evaluator_sha256": sha,
            "entrypoint": "score",
            "threshold": 0,
        },
        reward=100,
        funder="t",
        created_at=TS,
        ratchet={"baseline": 0, "target": 10, "reward": 999},
    )
    with pytest.raises(RuleViolation, match="one pool"):
        node.post_objective(objective, ts=TS)
