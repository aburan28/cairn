"""Evaluator verification: score a candidate against a pinned fitness function.

The FunSearch / AlphaEvolve shape. Verification cost is exactly one evaluation
-- the same evaluation the network was going to run anyway -- so verification is
free rather than merely cheap.

Spec::

    {"kind": "evaluator",
     "evaluator": "evaluators/cap_set.py",
     "evaluator_sha256": "<hex>",
     "entrypoint": "score",
     "threshold": 512,
     "direction": "maximize"}

``score(artifact: dict) -> int``. **Integers only.** A float score does not
reproduce bitwise across heterogeneous hardware, so two honest nodes could
disagree about whether the threshold was met. Scale your score and document the
scale in the objective statement.

The evaluator's hash is part of the objective's identity, so editing it forks
the objective instead of silently rescoring the work already done against it.
"""
from __future__ import annotations

from typing import Any

from .base import PinMismatch, Status, Verdict, register

DIRECTIONS = ("maximize", "minimize")


class EvaluatorVerifier:
    kind = "evaluator"

    def __init__(self, root: str = "."):
        self.root = root

    def verify(self, spec: dict[str, Any], artifact: dict[str, Any]) -> Verdict:
        from .base import load_pinned

        for key in ("evaluator", "evaluator_sha256", "entrypoint"):
            if not isinstance(spec.get(key), str):
                return Verdict(Status.INVALID_SPEC, f"missing spec field {key!r}")
        threshold = spec.get("threshold")
        if isinstance(threshold, bool) or not isinstance(threshold, int):
            return Verdict(
                Status.INVALID_SPEC,
                "threshold must be an integer (scale fractional scores)",
            )
        direction = spec.get("direction", "maximize")
        if direction not in DIRECTIONS:
            return Verdict(Status.INVALID_SPEC, f"direction must be one of {DIRECTIONS}")

        try:
            score_fn = load_pinned(
                self.root,
                spec["evaluator"],
                spec["evaluator_sha256"],
                spec["entrypoint"],
            )
        except PinMismatch as exc:
            return Verdict(Status.INVALID_SPEC, str(exc))
        except (OSError, AttributeError) as exc:
            return Verdict(Status.UNAVAILABLE, f"cannot load evaluator: {exc}")

        score = score_fn(artifact)
        if isinstance(score, bool) or not isinstance(score, int):
            return Verdict(
                Status.INVALID_SPEC,
                f"evaluator returned {type(score).__name__}; scores must be int "
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
                "evaluator_sha256": spec["evaluator_sha256"],
            },
        )


register(EvaluatorVerifier())
