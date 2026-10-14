"""Certificate checker for Certicom's random-curve ECC2-131 challenge.

The challenge is the fixed logarithm Q = [k]P on
    y^2 + xy = x^3 + a*x^2 + b over GF(2^131),
with field polynomial x^131 + x^13 + x^2 + x + 1. This checker implements
the field and curve operations directly and has no external dependencies.
"""

from __future__ import annotations

FIELD_DEGREE = 131
FIELD_POLY = (1 << 131) | 0x2007
ORDER_N = int("0400000000000000026ABB991FE311FE83", 16)

CURVE_A = int("07EBCB7EECC296A1C4A1A14F2C9E44352E", 16)
CURVE_B = int("00610B0A57C73649AD0093BDD622A61D81", 16)
GENERATOR = (
    int("00439CBC8DC73AA981030D5BC57B331663", 16),
    int("014904C07D4F25A16C2DE036D60B762BD4", 16),
)
TARGET = (
    int("0602339C5DB0E9C694AC8908528C51C440", 16),
    int("04F7B99169FA1A0F2737813742B1588CB8", 16),
)


def _reduce(value: int) -> int:
    while value.bit_length() > FIELD_DEGREE:
        value ^= FIELD_POLY << (value.bit_length() - FIELD_DEGREE - 1)
    return value


def _mul(a: int, b: int) -> int:
    product = 0
    while b:
        bit = b & -b
        product ^= a << (bit.bit_length() - 1)
        b ^= bit
    return _reduce(product)


def _inv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError("zero has no inverse")
    u, v = a, FIELD_POLY
    g1, g2 = 1, 0
    while u != 1:
        shift = u.bit_length() - v.bit_length()
        if shift < 0:
            u, v = v, u
            g1, g2 = g2, g1
            shift = -shift
        u ^= v << shift
        g1 ^= g2 << shift
    return _reduce(g1)


def _add(P: tuple[int, int] | None, Q: tuple[int, int] | None):
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2:
        if y1 != y2 or x1 == 0:
            return None
        lam = x1 ^ _mul(y1, _inv(x1))
        x3 = _mul(lam, lam) ^ lam ^ CURVE_A
        y3 = _mul(x1, x1) ^ _mul(lam ^ 1, x3)
        return (x3, y3)
    lam = _mul(y1 ^ y2, _inv(x1 ^ x2))
    x3 = _mul(lam, lam) ^ lam ^ x1 ^ x2 ^ CURVE_A
    y3 = _mul(lam, x1 ^ x3) ^ x3 ^ y1
    return (x3, y3)


def _mul_point(k: int, P: tuple[int, int] | None):
    result = None
    addend = P
    while k:
        if k & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        k >>= 1
    return result


def _on_curve(P: tuple[int, int]) -> bool:
    x, y = P
    lhs = _mul(y, y) ^ _mul(x, y)
    rhs = _mul(_mul(x, x), x) ^ _mul(CURVE_A, _mul(x, x)) ^ CURVE_B
    return lhs == rhs


def _check_scalar(k: int, target=TARGET) -> tuple[bool, str]:
    if not 1 <= k < ORDER_N:
        return False, "k must lie in [1, n)"
    if _mul_point(k, GENERATOR) != target:
        return False, "k*P does not equal the challenge point Q"
    return True, "verified: k*P = Q for the Certicom ECC2-131 challenge"


def check(artifact: dict) -> tuple[bool, str]:
    if not isinstance(artifact, dict) or set(artifact) != {"k"}:
        return False, "artifact must contain exactly the field k"
    encoded = artifact.get("k")
    if not isinstance(encoded, str) or len(encoded) != 64:
        return False, "artifact.k must be 64 lowercase hexadecimal characters"
    if any(c not in "0123456789abcdef" for c in encoded):
        return False, "artifact.k must be 64 lowercase hexadecimal characters"
    return _check_scalar(int(encoded, 16))
