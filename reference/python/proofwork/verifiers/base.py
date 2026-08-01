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

from .. import blobs


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
#
# Two sources, in this order:
#
#   1. the bundle file the objective names, relative to the root;
#   2. the content-addressed blob store under that root (``proofwork.blobs``).
#
# The bundle is first so an operator who edits a checker in place is told their
# edit no longer matches the pin, rather than having a cached blob silently stand
# in for the file they are looking at. The store is second because a node that
# received the objective over the network has no bundle at all, and the blob it
# holds is byte-identical by construction: its filename is the pin.


def pinned_code(spec: dict[str, Any]) -> list[tuple[str, str, str]]:
    """Every pinned code file a verifier spec names: ``(role, path, sha256)``.

    Extracted here rather than at each call site because the field names differ
    per kind and three copies of that knowledge would drift. Everything that has
    to answer "which blobs does this objective need" -- publishing, garbage
    collection, the Rust node's want set -- goes through this.

    ``replay`` and ``lean`` produce nothing, and that is a real limitation rather
    than an oversight: a ``replay`` spec names a command and a ``lean`` spec needs
    a proof-assistant toolchain. Neither is a blob, so neither is made portable by
    content-addressing the code. See ``docs/verification.md``.
    """
    kind = spec.get("kind")
    if kind == "certificate":
        fields = ("checker", "checker", "checker_sha256")
    elif kind == "evaluator":
        fields = ("evaluator", "evaluator", "evaluator_sha256")
    elif kind == "statistical":
        statistic = spec.get("statistic")
        if not isinstance(statistic, dict):
            return []
        path, sha = statistic.get("path"), statistic.get("sha256")
        if isinstance(path, str) and isinstance(sha, str):
            return [("statistic", path, sha)]
        return []
    else:
        return []
    role, path_key, sha_key = fields
    path, sha = spec.get(path_key), spec.get(sha_key)
    if isinstance(path, str) and isinstance(sha, str):
        return [(role, path, sha)]
    return []


def resolve_pinned(root: str, path: str, expected_sha256: str) -> str:
    """The file to load for a pin, from the bundle or from the blob store.

    Split out from :func:`load_pinned` so that "which blobs am I missing" can be
    answered by the *same* resolution the verifier will use. Two implementations
    of that question would eventually disagree, and the failure would be a node
    that fetches nothing while reporting UNAVAILABLE forever.

    Raises :class:`PinMismatch` for a broken objective and ``OSError`` for code
    this node simply does not have -- the split the caller turns into
    INVALID_SPEC and UNAVAILABLE respectively.
    """
    # Resolve both sides to absolute paths before comparing: a relative root
    # like "." never prefixes a normalized relative join, so a naive check
    # rejects every legitimate objective.
    root_abs = os.path.abspath(root)
    full = os.path.abspath(os.path.join(root_abs, path))
    # Checked before the store is consulted, and that order is deliberate: a pin
    # whose path leaves the bundle is a malformed objective, and content
    # addressing must not rescue it. Otherwise an objective could name
    # ``../../.ssh/id_rsa`` with a matching hash, be refused today, and start
    # resolving tomorrow because some node happened to hold that blob.
    if full != root_abs and not full.startswith(root_abs + os.sep):
        raise PinMismatch(f"pinned path escapes the objective root: {path}")

    try:
        with open(full, "rb") as handle:
            source = handle.read()
    except OSError as bundle_error:
        store = blobs.BlobStore.under(root_abs)
        try:
            store.read(expected_sha256)
            return store.path_of(expected_sha256)
        except blobs.BlobError as store_error:
            raise FileNotFoundError(f"{bundle_error}; {store_error}") from None
    else:
        # Mismatch is raised here, before the store is consulted: a cached blob
        # must not silently stand in for an edited bundle file (see module
        # comment above). The store is only for peers that have no bundle file.
        actual = hashlib.sha256(source).hexdigest()
        if actual != expected_sha256:
            raise PinMismatch(
                f"pinned code {path} has sha256 {actual}, "
                f"objective declares {expected_sha256}"
            )
        return full


def missing_code(root: str, spec: dict[str, Any]) -> list[str]:
    """The content addresses of pinned code this node cannot obtain.

    Empty for a spec whose code resolves, for a kind with no pinned code, and for
    a pin whose path escapes the root -- the last because such an objective is
    broken and fetching its blob would not make it runnable.
    """
    out = []
    for _role, path, sha in pinned_code(spec):
        if not blobs.is_address(sha):
            continue
        try:
            resolve_pinned(root, path, sha)
        except PinMismatch:
            continue
        except OSError:
            out.append(sha)
    return out


def publish_code(root: str, spec: dict[str, Any]) -> list[str]:
    """Copy every pinned file this bundle has into the blob store.

    Best effort by construction, and it must stay that way: this runs when an
    objective is admitted, and an objective may be admitted by a node that has
    never seen the bundle. Refusing the record because code could not be cached
    would stop a log from importing objectives.
    """
    store = blobs.BlobStore.under(root)
    published = []
    root_abs = os.path.abspath(root)
    for _role, path, sha in pinned_code(spec):
        if not blobs.is_address(sha):
            continue
        if store.holds(sha):
            published.append(sha)
            continue
        full = os.path.abspath(os.path.join(root_abs, path))
        if full != root_abs and not full.startswith(root_abs + os.sep):
            continue
        try:
            if store.publish_file(full, sha):
                published.append(sha)
        except blobs.BlobError:
            continue
    return published


def load_pinned(root: str, path: str, expected_sha256: str, entrypoint: str) -> Callable:
    """Load ``entrypoint`` from a source file whose hash must match.

    Raises FileNotFoundError / PinMismatch / AttributeError, all of which the
    caller converts into a non-settling verdict.
    """
    full = resolve_pinned(root, path, expected_sha256)
    with open(full, "rb") as handle:
        source = handle.read()
    actual = hashlib.sha256(source).hexdigest()
    # Re-checked after resolution rather than trusted from it. Both sources
    # verified the bytes, but the file could have changed in between and this is
    # the last moment before ``exec``; a check here costs one hash and removes
    # any argument about whether the window matters.
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
This reference implementation executes pinned verifier code IN-PROCESS, with no
jail, no network restriction, and no wall-clock cap. A malicious objective
author gets the interpreter running this module: its memory, its keys, its
filesystem, its network.

This is a deliberate and stated parity gap with the Rust implementation, which
spawns the same code inside an OS jail (bubblewrap on Linux, seatbelt on macOS)
and documents exactly what that does and does not bound. The gap is not closed
here because closing it would mean reimplementing that jail in a second
language, and the value of this package is that it is small enough to read
end to end and check the *encoding and settlement rules* against -- not that it
is a hardened node.

So: run this package only on objectives you wrote or have read. To verify
objectives from strangers, use the Rust node. Tracked as a launch blocker for
this package, not a nice-to-have.
"""
