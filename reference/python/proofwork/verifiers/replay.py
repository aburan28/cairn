"""Replay verification: re-run a pinned computation and compare declared fields.

For deterministic simulation and search whose output is not self-certifying.
Costs a full re-run, so it is the expensive end of what this network should be
doing -- but it is honest, and it needs no hardware attestation.

Spec::

    {"kind": "replay",
     "command": ["python3", "search.py", "--seed", "7"],
     "cwd": "examples/search",
     "reproducible_fields": ["relations_found", "solving_degree"],
     "timeout_seconds": 600}

The command must print a single JSON object to stdout. The artifact's claimed
values for every ``reproducible_fields`` entry must match the re-run exactly.

**Time-like fields cannot be reproducible.** Wall-clock, CPU seconds, and
memory-high-water are properties of the machine that ran the job, not of the
computation, so two honest nodes disagree about them by construction. Declaring
one as reproducible is a malformed objective, not a failed run -- a cost claim
denominated in seconds is a claim about somebody's hardware and cannot be
settled by re-execution.
"""
from __future__ import annotations

import json
import subprocess
from typing import Any

from .base import Status, Verdict, register

#: Substrings that make a field machine-dependent. Denied in specs.
TIME_LIKE = (
    "time", "seconds", "duration", "elapsed", "latency", "throughput",
    "memory", "rss", "flops", "timestamp", "date",
)


def _machine_dependent(field: str) -> bool:
    low = field.lower()
    return any(token in low for token in TIME_LIKE)


class ReplayVerifier:
    kind = "replay"

    def __init__(self, root: str = "."):
        self.root = root

    def verify(self, spec: dict[str, Any], artifact: dict[str, Any]) -> Verdict:
        command = spec.get("command")
        if not isinstance(command, list) or not all(isinstance(c, str) for c in command):
            return Verdict(Status.INVALID_SPEC, "command must be a list of strings")
        fields = spec.get("reproducible_fields")
        if not isinstance(fields, list) or not fields:
            return Verdict(Status.INVALID_SPEC, "reproducible_fields must be non-empty")

        bad = [f for f in fields if not isinstance(f, str) or _machine_dependent(f)]
        if bad:
            return Verdict(
                Status.INVALID_SPEC,
                f"machine-dependent fields cannot be reproducible: {bad}. "
                "Timings and memory measure the host, not the computation.",
            )

        timeout = spec.get("timeout_seconds", 600)
        if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout <= 0:
            return Verdict(Status.INVALID_SPEC, "timeout_seconds must be a positive int")

        import os

        cwd = os.path.normpath(os.path.join(self.root, spec.get("cwd", ".")))
        try:
            proc = subprocess.run(
                command, capture_output=True, text=True, timeout=timeout, cwd=cwd
            )
        except subprocess.TimeoutExpired:
            return Verdict(
                Status.UNAVAILABLE,
                f"replay exceeded {timeout}s; a timeout is not a refutation",
            )
        except OSError as exc:
            return Verdict(Status.UNAVAILABLE, f"cannot run replay command: {exc}")

        if proc.returncode != 0:
            return Verdict(
                Status.UNAVAILABLE,
                f"replay command exited {proc.returncode}; infrastructure failure "
                "is not evidence about the artifact",
                {"stderr_tail": proc.stderr[-2000:]},
            )
        try:
            observed = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            return Verdict(Status.UNAVAILABLE, f"replay output is not JSON: {exc}")
        if not isinstance(observed, dict):
            return Verdict(Status.UNAVAILABLE, "replay output is not a JSON object")

        claimed = artifact.get("results")
        if not isinstance(claimed, dict):
            return Verdict(Status.REJECT, "artifact has no 'results' object")

        mismatches = {}
        for field in fields:
            if field not in observed:
                return Verdict(
                    Status.UNAVAILABLE,
                    f"replay output is missing declared field {field!r}",
                )
            if claimed.get(field) != observed[field]:
                mismatches[field] = {"claimed": claimed.get(field), "observed": observed[field]}

        if mismatches:
            return Verdict(Status.REJECT, "replay disagrees with the claim", {"mismatches": mismatches})
        return Verdict(
            Status.ACCEPT,
            f"replay reproduced {len(fields)} declared field(s)",
            {"reproduced": {f: observed[f] for f in fields}},
        )


register(ReplayVerifier())
