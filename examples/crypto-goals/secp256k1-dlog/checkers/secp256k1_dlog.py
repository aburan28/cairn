"""Certificate checker for a full-order secp256k1 discrete logarithm.

The target point is derived by deterministic try-and-increment from a fixed
public seed. It is never constructed as a known multiple of the generator, so
the verifier publisher does not receive the answer while creating the
instance. The curve parameters follow SEC 2, section 2.7.1.
"""

from __future__ import annotations

import hashlib


FIELD_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
CURVE_A = 0
CURVE_B = 7
ORDER_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GENERATOR = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
SEED = b"cairn/crypto-goals/secp256k1/full-dlog/v1"


def _on_curve(point: tuple[int, int] | None, p: int, a: int, b: int) -> bool:
    if point is None:
        return False
    x, y = point
    return 0 <= x < p and 0 <= y < p and (y * y - x * x * x - a * x - b) % p == 0


def _add(
    left: tuple[int, int] | None,
    right: tuple[int, int] | None,
    p: int,
    a: int,
) -> tuple[int, int] | None:
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if left == right:
        if y1 == 0:
            return None
        slope = (3 * x1 * x1 + a) * pow(2 * y1, -1, p) % p
    else:
        slope = (y2 - y1) * pow((x2 - x1) % p, -1, p) % p
    x3 = (slope * slope - x1 - x2) % p
    y3 = (slope * (x1 - x3) - y1) % p
    return x3, y3


def _mul(
    scalar: int,
    point: tuple[int, int] | None,
    p: int,
    a: int,
) -> tuple[int, int] | None:
    result = None
    addend = point
    while scalar:
        if scalar & 1:
            result = _add(result, addend, p, a)
        addend = _add(addend, addend, p, a)
        scalar >>= 1
    return result


def _derive_target() -> tuple[int, int] | None:
    """Hash to a secp256k1 point without knowing its discrete logarithm."""
    for counter in range(1 << 32):
        digest = hashlib.sha256(SEED + b"/" + counter.to_bytes(4, "big")).digest()
        x = int.from_bytes(digest, "big") % FIELD_P
        rhs = (pow(x, 3, FIELD_P) + CURVE_B) % FIELD_P
        if rhs == 0 or pow(rhs, (FIELD_P - 1) // 2, FIELD_P) != 1:
            continue
        y = pow(rhs, (FIELD_P + 1) // 4, FIELD_P)
        if y * y % FIELD_P != rhs:
            continue
        return x, min(y, FIELD_P - y)
    return None


def _check_log(
    scalar: int,
    target: tuple[int, int] | None,
    p: int,
    a: int,
    b: int,
    order: int,
    generator: tuple[int, int],
) -> tuple[bool, str]:
    if not 1 <= scalar < order:
        return False, "k must lie in [1, n)"
    if not _on_curve(generator, p, a, b) or not _on_curve(target, p, a, b):
        return False, "generator or target is not a finite point on the curve"
    if _mul(order, generator, p, a) is not None:
        return False, "generator does not satisfy [n]G = infinity"
    if _mul(order, target, p, a) is not None:
        return False, "target does not satisfy [n]Q = infinity"
    if _mul(scalar, generator, p, a) != target:
        return False, "[k]G is not the target Q"
    return True, "verified: [k]G = Q"


def check(artifact: dict) -> tuple[bool, str]:
    if not isinstance(artifact, dict) or set(artifact) != {"k"}:
        return False, "artifact must be an object containing exactly k"
    value = artifact["k"]
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in "0123456789abcdef" for char in value)
    ):
        return False, "k must be exactly 64 lowercase hexadecimal characters"
    scalar = int(value, 16)
    if not 1 <= scalar < ORDER_N:
        return False, "k must lie in [1, n)"
    target = _derive_target()
    if target is None:
        return False, "deterministic target derivation failed"
    return _check_log(scalar, target, FIELD_P, CURVE_A, CURVE_B, ORDER_N, GENERATOR)
