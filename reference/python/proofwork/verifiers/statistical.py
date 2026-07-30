"""Statistical verification: a pinned, seeded test statistic clears a threshold.

The whole point is *pre-registration*. The statistic and the rejection threshold
are fields of the objective, so they sit inside the objective's digest: choosing
the criterion after seeing the data means posting a different objective, with a
different id, that funded nothing and that nobody has cited. That is the only
defence this network has against the oldest fraud in empirical work, and it
costs nothing to enforce because identity already covers the verifier block.

Spec::

    {"kind": "statistical",
     "statistic": {"path": "statistics/paired_permutation.py", "sha256": "<hex>"},
     "entrypoint": "statistic",
     "threshold": 10000,
     "direction": "minimize",
     "seed": 0}

``statistic(artifact: dict, seed: int) -> int``. Two rules beyond the
evaluator's:

* **The seed comes from the objective.** Resampling, permutation, and bootstrap
  statistics are all randomised. A statistic whose randomness the submitter
  chooses is one the submitter can grind until it clears; a statistic whose
  randomness is unpinned makes two honest nodes disagree, which is worse.
  ``seed`` defaults to 0 so the deterministic case stays terse and the field
  stays omitted-on-default in the objective's digest.
* **Integers only**, as for the evaluator: IEEE-754 does not reproduce bitwise
  across hosts, so a p-value arrives scaled (parts per million, say) and the
  objective statement says so.

Stage 0 admits only statistics cheap enough to re-run locally; a resampling test
that needs a compute committee is Stage 2.
"""
from __future__ import annotations

from typing import Any

from .base import PinMismatch, Status, Verdict, register

DIRECTIONS = ("maximize", "minimize")


class StatisticalVerifier:
    kind = "statistical"

    def __init__(self, root: str = "."):
        self.root = root

    def verify(self, spec: dict[str, Any], artifact: dict[str, Any]) -> Verdict:
        from .base import load_pinned

        statistic = spec.get("statistic")
        if not isinstance(statistic, dict):
            return Verdict(
                Status.INVALID_SPEC,
                "statistical spec needs a 'statistic' object with 'path' and 'sha256'",
            )
        for key in ("path", "sha256"):
            if not isinstance(statistic.get(key), str):
                return Verdict(Status.INVALID_SPEC, f"missing spec field 'statistic.{key}'")
        if not isinstance(spec.get("entrypoint"), str):
            return Verdict(Status.INVALID_SPEC, "missing spec field 'entrypoint'")

        threshold = spec.get("threshold")
        if isinstance(threshold, bool) or not isinstance(threshold, int):
            return Verdict(
                Status.INVALID_SPEC,
                "threshold must be an integer (scale fractional scores)",
            )
        direction = spec.get("direction", "maximize")
        if direction not in DIRECTIONS:
            return Verdict(Status.INVALID_SPEC, f"direction must be one of {DIRECTIONS}")

        # Absent and an explicit 0 must mean the same thing, or the two
        # spellings would be two objectives with two ids.
        seed = spec.get("seed", 0)
        if seed is None:
            seed = 0
        if isinstance(seed, bool) or not isinstance(seed, int):
            return Verdict(
                Status.INVALID_SPEC,
                "seed must be an integer; a seed two nodes could read differently "
                "is not a seed",
            )

        try:
            statistic_fn = load_pinned(
                self.root,
                statistic["path"],
                statistic["sha256"],
                spec["entrypoint"],
            )
        except PinMismatch as exc:
            return Verdict(Status.INVALID_SPEC, str(exc))
        except (OSError, AttributeError) as exc:
            return Verdict(Status.UNAVAILABLE, f"cannot load statistic: {exc}")

        score = statistic_fn(artifact, seed)
        if isinstance(score, bool) or not isinstance(score, int):
            return Verdict(
                Status.INVALID_SPEC,
                f"statistic returned {type(score).__name__}; scores must be int "
                "so every node agrees on the comparison",
            )

        met = score >= threshold if direction == "maximize" else score <= threshold
        return Verdict(
            Status.ACCEPT if met else Status.REJECT,
            f"score {score} vs threshold {threshold} ({direction})",
            {
                "score": score,
                "threshold": threshold,
                "direction": direction,
                "statistic_sha256": statistic["sha256"],
                # Recorded so an auditor re-running this does not have to guess
                # which seed produced the number.
                "seed": seed,
            },
        )


register(StatisticalVerifier())
