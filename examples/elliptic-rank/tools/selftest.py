#!/usr/bin/env python3
"""Adversarial checks for the rank-31 objective's exact certificate."""

from copy import deepcopy
import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHECKER_PATH = ROOT / "checkers" / "rank_31.py"
RECORD_PATH = ROOT / "artifacts" / "rank-30-record.json"


def _load_checker():
    spec = importlib.util.spec_from_file_location("rank_31", CHECKER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load rank_31 checker")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _assert_reject(checker, artifact, fragment):
    accepted, detail = checker.check(artifact)
    assert not accepted, f"unexpectedly accepted: {detail}"
    assert fragment in detail, f"expected {fragment!r} in {detail!r}"


def main():
    checker = _load_checker()
    record = json.loads(RECORD_PATH.read_text())

    point_count, rank, _, _, no_two_torsion_prime = checker._analyze(record)
    assert point_count == 30
    assert rank == 30
    assert no_two_torsion_prime is not None
    evaluated = checker._evaluate(record)
    assert evaluated[5] == checker.BASELINE_C4
    assert evaluated[6] == checker.BASELINE_C6
    assert evaluated[7] == checker.BASELINE_DISCRIMINANT
    assert checker.score(record) == 30
    assert checker.score_new_j(record) == 0
    assert checker.score_lower_height(record) == 0

    # This is a genuine positive-path test, not a mock: temporarily move the
    # threshold back to the public record and require the exact same checker to
    # accept all 30 points as independent.  Restoring 31 then proves the record
    # is a baseline, not a solution that can drain the new objective.
    checker.TARGET_RANK = 30
    accepted, detail = checker.check(record)
    assert accepted, detail
    checker.TARGET_RANK = 31
    _assert_reject(checker, record, "exactly 31")

    # y^2 = x^3 - 2 with P=(3,5) gives a tiny, independently certifiable
    # positive fixture for every evaluator policy.  It is not a rank-30
    # solution: the temporary rank-one use checks policy direction without
    # fabricating a research result.
    small = {"curve": ["0", "0", "0", "0", "-2"], "points": [["3", "5"]]}
    assert checker.score(small) == 1
    assert checker.score_new_j(small) == 1
    assert checker.score_lower_height(small) == 1

    duplicate = deepcopy(record)
    duplicate["points"].append(deepcopy(record["points"][0]))
    _assert_reject(checker, duplicate, "matrix has rank 30")
    assert checker.score(duplicate) == 0

    inverse = deepcopy(record)
    x_text, y_text = inverse["points"][0]
    # On y^2 + a1*x*y + a3*y = ..., -(x,y) is
    # (x, -y-a1*x-a3).  This is distinct JSON but the same rank-one direction.
    inverse_y = -int(y_text) - int(inverse["curve"][0]) * int(x_text) - int(
        inverse["curve"][2]
    )
    inverse["points"].append([x_text, str(inverse_y)])
    _assert_reject(checker, inverse, "matrix has rank 30")

    off_curve = deepcopy(record)
    off_curve["points"][0][1] = str(int(off_curve["points"][0][1]) + 1)
    _assert_reject(checker, off_curve, "does not lie")

    singular = {"curve": ["0", "0", "0", "0", "0"], "points": [["0", "0"]]}
    _assert_reject(checker, singular, "singular")

    # y^2 = x^3 - x has three rational 2-torsion points.  Its cubic has a root
    # modulo every good prime, so the simplifying no-2-torsion proof must fail.
    has_two_torsion = {
        "curve": ["0", "0", "0", "-1", "0"],
        "points": [["0", "0"]],
    }
    _assert_reject(checker, has_two_torsion, "absence of rational 2-torsion")

    noncanonical = deepcopy(record)
    noncanonical["points"][0][0] += "/1"
    _assert_reject(checker, noncanonical, "canonical")

    print(
        "ELLIPTIC-RANK SELFTEST OK: rank and record-policy entrypoints verified; "
        "threshold, dependence, curve membership, torsion, and encoding attacks rejected"
    )


if __name__ == "__main__":
    main()
