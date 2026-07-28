"""The shipped examples must actually verify. A broken example is a broken claim."""
import json
import os

import pytest

from proofwork import verifiers
from proofwork.records import Objective
from proofwork.verifiers import Status

# repo root: tests/ -> python/ -> reference/ -> <root>
ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)


def load(name):
    with open(os.path.join(ROOT, "examples", name, "objective.json"), encoding="utf-8") as f:
        objective = Objective.from_dict(json.load(f))
    path = os.path.join(ROOT, "examples", name, "artifact.json")
    artifact = None
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            artifact = json.load(f)
    return objective, artifact


@pytest.fixture(autouse=True)
def _root():
    verifiers.set_root(ROOT)
    yield
    verifiers.set_root(".")


@pytest.mark.parametrize("name", ["collatz", "capset"])
def test_shipped_artifact_verifies(name):
    objective, artifact = load(name)
    verdict = verifiers.run(objective.verifier, artifact)
    assert verdict.status is Status.ACCEPT, verdict.detail


@pytest.mark.parametrize(
    "name,bogus",
    [("collatz", {"n": 27}), ("capset", {"points": [[0, 0, 0, 0], [1, 1, 1, 1], [2, 2, 2, 2]]})],
)
def test_bogus_artifact_is_rejected(name, bogus):
    # The capset case is the important one: three collinear points are not a
    # cap set, and the evaluator must score it zero rather than crash.
    objective, _ = load(name)
    assert verifiers.run(objective.verifier, bogus).status is Status.REJECT


@pytest.mark.parametrize("name", ["collatz", "capset", "lean"])
def test_objective_pins_resolve(name):
    objective, _ = load(name)
    verdict = verifiers.run(objective.verifier, {})
    # Whatever the artifact does, the *spec* itself must be well formed: a
    # stale pinned hash would surface as INVALID_SPEC.
    assert verdict.status is not Status.INVALID_SPEC, verdict.detail
