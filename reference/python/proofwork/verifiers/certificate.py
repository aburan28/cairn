"""Certificate verification: re-check an NP witness by recomputation.

The cheapest and soundest shape the network supports. A claimed counterexample,
witness, construction, collision, or assignment is checked in milliseconds by
code that knows nothing about how it was found.

Spec::

    {"kind": "certificate",
     "checker": "checkers/collatz.py",
     "checker_sha256": "<hex>",
     "entrypoint": "check"}

The checker is ``check(artifact: dict) -> bool | (bool, str)``.
"""
from __future__ import annotations

from typing import Any

from .base import PinMismatch, Status, Verdict, register


class CertificateVerifier:
    kind = "certificate"

    def __init__(self, root: str = "."):
        self.root = root

    def verify(self, spec: dict[str, Any], artifact: dict[str, Any]) -> Verdict:
        from .base import load_pinned

        required = ("checker", "checker_sha256", "entrypoint")
        missing = [k for k in required if not isinstance(spec.get(k), str)]
        if missing:
            return Verdict(Status.INVALID_SPEC, f"missing spec fields: {missing}")

        try:
            check = load_pinned(
                self.root, spec["checker"], spec["checker_sha256"], spec["entrypoint"]
            )
        except PinMismatch as exc:
            # A tampered checker is a broken objective, not a bad artifact.
            return Verdict(Status.INVALID_SPEC, str(exc))
        except (OSError, AttributeError) as exc:
            return Verdict(Status.UNAVAILABLE, f"cannot load checker: {exc}")

        result = check(artifact)
        detail = ""
        if isinstance(result, tuple):
            ok, detail = result[0], str(result[1])
        else:
            ok = result
        if not isinstance(ok, bool):
            return Verdict(
                Status.INVALID_SPEC,
                f"checker returned {type(ok).__name__}, expected bool",
            )
        return Verdict(
            Status.ACCEPT if ok else Status.REJECT,
            detail or ("certificate verified" if ok else "certificate does not check out"),
            {"checker_sha256": spec["checker_sha256"]},
        )


register(CertificateVerifier())
