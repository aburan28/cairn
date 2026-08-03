"""Lean verification: the proof-assistant kernel is the arbiter.

The one class of general research output where "prove things as currency" is
literally rather than metaphorically true. A submitted proof is checked in
seconds by a kernel anyone can run, and the trust assumption is kernel soundness
and nothing else -- no hardware vendor, no stake, no committee.

Spec::

    {"kind": "lean",
     "preamble": "import Mathlib\\n",
     "statement": "theorem foo (n : Nat) : n + 0 = n",
     "timeout_seconds": 120}

Artifact: ``{"proof": ":= by simp"}``. The submitted proof text is appended to
the pinned statement, so a submitter cannot prove a *different*, easier theorem
and collect -- the statement half comes from the objective, not from them.

Three escape hatches are rejected before Lean ever runs, because each produces a
file the kernel accepts while proving nothing (or proving it by a route outside
the kernel):

- ``sorry`` / ``admit`` -- an explicit hole. Compiles, proves nothing.
- ``native_decide`` -- discharges goals via compiled evaluation, trusting the
  compiler and runtime rather than the kernel. A known soundness escape hatch;
  allowed only if the objective opts in with ``allow_native_decide``.
- ``axiom`` / ``@[implemented_by]`` -- new trusted assumptions smuggled in
  alongside the proof.

This is the "verifier gaming" attack in its most concrete form: the artifact
satisfies the checker while missing the goal. Every verifier needs its own
version of this list, and writing it is the real work of authoring an objective.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from typing import Any

from .base import Status, Verdict, register

#: (pattern, human explanation). Matched against the submitted proof only.
FORBIDDEN: tuple[tuple[str, str], ...] = (
    (r"\bsorry\b", "contains `sorry`: an explicit hole, proves nothing"),
    (r"\badmit\b", "contains `admit`: an explicit hole, proves nothing"),
    (r"\baxiom\b", "declares an axiom: adds a trusted assumption"),
    (r"@\[implemented_by", "replaces an implementation outside the kernel"),
)

NATIVE_DECIDE = (r"\bnative_decide\b", "uses `native_decide`: trusts the compiler, not the kernel")


class LeanVerifier:
    kind = "lean"

    def __init__(self, lean_binary: str = "lean", root: str = "."):
        self.lean_binary = lean_binary
        # Picked up by ``verifiers.set_root``, like the code-loading verifiers:
        # ``project_root`` resolves against the bundle root, never the host.
        self.root = root

    def _available(self) -> str | None:
        return shutil.which(self.lean_binary)

    def verify(self, spec: dict[str, Any], artifact: dict[str, Any]) -> Verdict:
        statement = spec.get("statement")
        if not isinstance(statement, str) or not statement.strip():
            return Verdict(Status.INVALID_SPEC, "lean spec needs a 'statement'")
        proof = artifact.get("proof")
        if not isinstance(proof, str) or not proof.strip():
            return Verdict(Status.REJECT, "artifact has no 'proof' text")

        checks = list(FORBIDDEN)
        if not spec.get("allow_native_decide", False):
            checks.append(NATIVE_DECIDE)
        for pattern, why in checks:
            if re.search(pattern, proof):
                return Verdict(Status.REJECT, why, {"pattern": pattern})

        # ``project_root`` comes from the objective record -- attacker-authored
        # like every other spec field -- and the Rust implementation binds it
        # into the verifier jail *writable* (a Lake build writes ``.olean``
        # files). Unconfined, "/" turns that jail into a pass-through, so it
        # resolves against the bundle root and must stay inside it, and both
        # implementations refuse the same objectives in the same place --
        # before the toolchain lookup, because a malformed spec is malformed
        # whether or not this node has Lean. A non-string value falls back to
        # the scratch directory, matching the Rust decoder.
        project_root = spec.get("project_root")
        run_cwd = None
        if isinstance(project_root, str) and project_root:
            root_abs = os.path.abspath(self.root)
            resolved = os.path.abspath(os.path.join(root_abs, project_root))
            if resolved != root_abs and not resolved.startswith(root_abs + os.sep):
                return Verdict(
                    Status.INVALID_SPEC,
                    f"project_root escapes the objective root: {project_root}",
                )
            run_cwd = resolved

        binary = self._available()
        if binary is None:
            # No toolchain is an infrastructure fact about this node. It says
            # nothing about the proof, and must never settle the objective.
            return Verdict(
                Status.UNAVAILABLE,
                f"{self.lean_binary!r} not on PATH; install a Lean toolchain to verify",
            )

        source = f"{spec.get('preamble', '')}\n{statement} {proof}\n"
        timeout = spec.get("timeout_seconds", 120)
        if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout <= 0:
            return Verdict(Status.INVALID_SPEC, "timeout_seconds must be a positive int")

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "Claim.lean")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(source)
            try:
                proc = subprocess.run(
                    [binary, path],
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    cwd=run_cwd or tmp,
                )
            except subprocess.TimeoutExpired:
                # A timeout is not a refutation. The proof may be fine and slow.
                return Verdict(
                    Status.UNAVAILABLE,
                    f"lean exceeded {timeout}s; timeout is not a refutation",
                )
            except OSError as exc:
                return Verdict(Status.UNAVAILABLE, f"cannot run lean: {exc}")

        output = (proc.stdout + proc.stderr).strip()
        evidence = {
            "returncode": proc.returncode,
            "output_tail": output[-2000:],
            "lean_binary": binary,
        }
        if proc.returncode != 0:
            return Verdict(Status.REJECT, "lean rejected the proof", evidence)
        # Lean warns rather than errors on a declaration that uses sorryAx.
        if "declaration uses 'sorry'" in output:
            return Verdict(Status.REJECT, "proof depends on sorryAx", evidence)
        return Verdict(Status.ACCEPT, "kernel accepted the proof", evidence)


register(LeanVerifier())
