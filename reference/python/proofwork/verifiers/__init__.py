"""Verifier registry. Importing this package registers the built-in verifiers."""
from __future__ import annotations

from .base import (  # noqa: F401
    SANDBOXING,
    PinMismatch,
    Status,
    Verdict,
    Verifier,
    get,
    kinds,
    load_pinned,
    missing_code,
    pinned_code,
    publish_code,
    register,
    resolve_pinned,
    run,
)
from . import certificate, evaluator, lean, replay, statistical  # noqa: F401,E402

__all__ = [
    "SANDBOXING",
    "PinMismatch",
    "Status",
    "Verdict",
    "Verifier",
    "get",
    "kinds",
    "load_pinned",
    "missing_code",
    "pinned_code",
    "publish_code",
    "register",
    "resolve_pinned",
    "run",
    "set_root",
]


def set_root(root: str) -> None:
    """Point the code-loading verifiers at an objective bundle root.

    ``lean`` is here because ``project_root`` resolves against -- and is
    contained inside -- the bundle root, the same rule pinned code paths obey.
    """
    for kind in ("certificate", "evaluator", "lean", "replay", "statistical"):
        verifier = get(kind)
        if verifier is not None:
            verifier.root = root  # type: ignore[attr-defined]
