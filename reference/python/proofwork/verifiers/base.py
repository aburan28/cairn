"""The verifier interface -- the load-bearing abstraction of the network.

An objective is not admissible until its verifier is written, pinned by hash,
and runnable by any contributor before they start work. A task whose payout is
somebody's opinion gets gamed the week the network has value.

The single most important rule in this module:

    A verifier that cannot run returns UNAVAILABLE. Never ACCEPT, never REJECT.

An unavailable toolchain, a missing file, or a crashed evaluator is an
infrastructure fact, not a fact about the artifact. Collapsing it into REJECT
turns "my Lean install is broken" into "your proof is wrong" -- and on a network
with money attached, into an attack: take verifiers offline and every honest
submission fails.
"""
from __future__ import annotations

import enum
import hashlib
import os
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol


class Status(str, enum.Enum):
    ACCEPT = "accept"
    REJECT = "reject"
    #: The verifier could not reach a verdict. Settles nothing, refutes nothing.
    UNAVAILABLE = "unavailable"
    #: The objective's verifier spec is itself malformed or tampered with.
    INVALID_SPEC = "invalid_spec"

    @property
    def settles(self) -> bool:
        """Only a real verdict may move value or close an objective."""
        return self in (Status.ACCEPT, Status.REJECT)


@dataclass(frozen=True)
class Verdict:
    status: Status
    detail: str = ""
    #: Anything a third party needs to re-derive this verdict.
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "detail": self.detail,
            "evidence": self.evidence,
        }

    @property
    def accepted(self) -> bool:
        return self.status is Status.ACCEPT


class Verifier(Protocol):
    kind: str

    def verify(self, spec: dict[str, Any], artifact: dict[str, Any]) -> Verdict: ...


_REGISTRY: dict[str, Verifier] = {}


def register(verifier: Verifier) -> Verifier:
    _REGISTRY[verifier.kind] = verifier
    return verifier


def get(kind: str) -> Verifier | None:
    return _REGISTRY.get(kind)


def kinds() -> list[str]:
    return sorted(_REGISTRY)


def run(spec: dict[str, Any], artifact: dict[str, Any]) -> Verdict:
    """Dispatch to the verifier named by ``spec['kind']``."""
    kind = spec.get("kind")
    if not isinstance(kind, str):
        return Verdict(Status.INVALID_SPEC, "verifier spec has no 'kind'")
    verifier = get(kind)
    if verifier is None:
        return Verdict(
            Status.UNAVAILABLE,
            f"no verifier registered for kind {kind!r}; known: {kinds()}",
        )
    try:
        return verifier.verify(spec, artifact)
    except Exception as exc:  # a crashed verifier is unavailable, not a rejection
        return Verdict(
            Status.UNAVAILABLE,
            f"verifier {kind!r} raised {type(exc).__name__}: {exc}",
        )


# --------------------------------------------------------------------------
# Pinned code loading
# --------------------------------------------------------------------------
#
# Checkers and evaluators are ordinary source files pinned by SHA-256. The hash
# is part of the objective's identity, so editing an evaluator does not silently
# rescore an objective -- it forks it into a different objective.


def load_pinned(root: str, path: str, expected_sha256: str, entrypoint: str) -> Callable:
    """Load ``entrypoint`` from a source file whose hash must match.

    Raises FileNotFoundError / PinMismatch / AttributeError, all of which the
    caller converts into a non-settling verdict.
    """
    # Resolve both sides to absolute paths before comparing: a relative root
    # like "." never prefixes a normalized relative join, so a naive check
    # rejects every legitimate objective.
    root_abs = os.path.abspath(root)
    full = os.path.abspath(os.path.join(root_abs, path))
    if full != root_abs and not full.startswith(root_abs + os.sep):
        raise PinMismatch(f"pinned path escapes the objective root: {path}")
    with open(full, "rb") as handle:
        source = handle.read()
    actual = hashlib.sha256(source).hexdigest()
    if actual != expected_sha256:
        raise PinMismatch(
            f"pinned code {path} has sha256 {actual}, objective declares {expected_sha256}"
        )
    namespace: dict[str, Any] = {"__name__": f"pinned_{actual[:12]}", "__file__": full}
    exec(compile(source, full, "exec"), namespace)  # noqa: S102 -- see SANDBOXING
    func = namespace.get(entrypoint)
    if not callable(func):
        raise AttributeError(f"{path} has no callable {entrypoint!r}")
    return func


class PinMismatch(Exception):
    """Pinned verifier code does not match the hash the objective declares."""


SANDBOXING = """
This reference implementation executes pinned verifier code in-process. That is
adequate for a single-operator Stage 0 deployment where the operator authors or
reviews every objective, and it is NOT adequate for a permissionless network: a
malicious objective author would be running arbitrary code on every contributor
that touches the objective. Before opening objective authorship, verifier
execution must move into a sandbox (container, gVisor/Firecracker, or WASM) with
no network and a wall-clock cap. Tracked as a launch blocker, not a nice-to-have.
"""
