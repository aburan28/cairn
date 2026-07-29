"""Canonical serialization and content addressing.

Consensus-critical. Two nodes that disagree about the bytes of an object
disagree about its identity, and therefore about which objective was funded and
which artifact was accepted. Everything here is deliberately boring and
deliberately strict.

Rules:

- Object keys sorted, no insignificant whitespace, UTF-8, no NaN/Infinity.
- **Floats are rejected outright.** IEEE-754 doubles do not round-trip
  identically through every JSON implementation, and floating-point results do
  not reproduce bitwise across heterogeneous hardware -- which is the entire
  reason verifiable-compute projects build bitwise-deterministic primitives.
  A quantity that needs a fractional part is carried as a scaled integer (or a
  decimal string), so the same claim hashes the same everywhere.
- Only str, int, bool, None, list, dict[str, ...] survive encoding.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

DIGEST_PREFIX = "sha256:"

#: Largest value any unit-of-account field may carry.
#:
#: Python has bignums and other implementations do not, so "what is a valid
#: record" would otherwise depend on which implementation you asked -- and a
#: reward of 2**70 produced here is a log a 64-bit implementation cannot audit.
#: That is an interop break, not a difference of opinion: it silently splits the
#: network into readers who accept a record and readers who cannot. The *format*
#: therefore declares the bound and every implementation enforces it.
MAX_UNITS = 2**64 - 1

#: Range any score-like field may occupy. Same reasoning as MAX_UNITS: scores
#: are signed 64-bit in a fixed-width implementation, so a score outside this
#: range is a record only a bignum language can read.
MIN_SCORE = -(2**63)
MAX_SCORE = 2**63 - 1


class CanonicalizationError(ValueError):
    """An object cannot be canonically serialized."""


def _check(value: Any, path: str = "$") -> None:
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return
    if isinstance(value, int):
        return
    if isinstance(value, float):
        raise CanonicalizationError(
            f"{path}: float values are not canonically serializable; carry a "
            "scaled integer or a decimal string instead"
        )
    if isinstance(value, list):
        for i, item in enumerate(value):
            _check(item, f"{path}[{i}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError(
                    f"{path}: object keys must be strings, got {type(key).__name__}"
                )
            _check(item, f"{path}.{key}")
        return
    raise CanonicalizationError(f"{path}: unsupported type {type(value).__name__}")


def canonical_bytes(value: Any) -> bytes:
    """Return the one canonical byte encoding of ``value``."""
    _check(value)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def digest(value: Any) -> str:
    """Content address of ``value``, as ``sha256:<hex>``."""
    return DIGEST_PREFIX + hashlib.sha256(canonical_bytes(value)).hexdigest()


def digest_bytes(data: bytes) -> str:
    return DIGEST_PREFIX + hashlib.sha256(data).hexdigest()


def short(identifier: str) -> str:
    """Display form: ``sha256:ab12cd34``. Never use for equality."""
    if identifier.startswith(DIGEST_PREFIX):
        return DIGEST_PREFIX + identifier[len(DIGEST_PREFIX) :][:8]
    return identifier[:8]


def merkle_root(leaves: list[str]) -> str | None:
    """Binary Merkle root over pre-hashed leaves.

    An odd node is promoted rather than duplicated: duplicating the last leaf
    lets two different leaf sets produce one root (CVE-2012-2459 in Bitcoin).
    """
    if not leaves:
        return None
    level = list(leaves)
    while len(level) > 1:
        nxt: list[str] = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(digest_bytes((level[i] + level[i + 1]).encode("utf-8")))
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0]
