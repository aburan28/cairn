"""Ed25519 *verification*, in the standard library alone.

This module exists because of a constraint that is worth stating plainly: the
reference implementation has no dependencies, and it must reach the same
verdict as the Rust implementation on every record. If Rust could verify a
signature Python could not, the two would disagree about which claims are
valid, and "anyone can independently re-derive every settled result" would be
false the moment anybody signed anything.

Signing is deliberately absent. A reference implementation that reads records
needs to check signatures; it has no business holding a key, and a hand-rolled
signer is a much sharper edge than a hand-rolled verifier (a repeated or
biased nonce leaks the key, while a verifier bug is caught by any test vector).
Use the Rust CLI to sign.

Matching ``verify_strict``
--------------------------
The Rust side calls ``ed25519_dalek::VerifyingKey::verify_strict`` and
additionally rejects weak keys. Plain "verify" is not enough to agree with it,
because the ed25519 family has several well-known places where honest
implementations differ, and each of those is a place where two nodes could
reach opposite verdicts on identical bytes. This module therefore reproduces
the strict rules exactly:

* **Canonical encodings.** A point whose ``y`` coordinate is >= p is refused
  rather than reduced. Reduction would let two distinct 32-byte strings name
  one key, so a signature would verify under a public key nobody published.
* **Small-order rejection**, for both the public key ``A`` and the commitment
  ``R``. A small-order key verifies signatures that require no secret at all,
  which is an authentication bypass wearing a valid-signature costume.
* **Canonical scalar.** ``S`` must be below the group order ``L``. Otherwise
  ``S`` and ``S + L`` are two encodings of one signature, and a "verified"
  record could be re-encoded into a different record id.
* **The strict equation** ``[S]B = R + [h]A``, computed without the cofactor
  multiplication that the batch-friendly form allows.

RFC 8032 §7.1 vectors and the RFC 8032 §5.1.7 malleability cases are pinned in
the test suite, together with signatures produced by the Rust implementation.
"""
from __future__ import annotations

import hashlib

# Curve25519 field and group constants (RFC 8032 §5.1).
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
# sqrt(-1), used to recover x from y during point decompression.
SQRT_M1 = pow(2, (P - 1) // 4, P)

KEY_LEN = 32
SIG_LEN = 64

# Base point B.
_BY = (4 * pow(5, P - 2, P)) % P
_BX_SQ_NUM = (_BY * _BY - 1) % P
_BX_SQ_DEN = (D * _BY * _BY + 1) % P


def _recover_x(y: int, sign: int) -> int | None:
    """The x matching this y on the curve, or None if there is none.

    Returning None rather than raising matters: a public key that is not a
    point is an invalid *record*, not a broken verifier, and the caller turns
    it into a refusal.
    """
    if y >= P:
        # Non-canonical: reducing would let two encodings name one point.
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    if x2 == 0:
        # x = 0 is only on the curve for one sign; the other is no point.
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None
    if x % 2 != sign:
        x = P - x
    return x


# Points are held in extended homogeneous coordinates (X, Y, Z, T) with
# x = X/Z, y = Y/Z and x*y = T/Z -- the representation that makes addition
# complete, so no input needs a special case and no branch can leak.
_IDENTITY = (0, 1, 1, 0)


def _point_add(p, q):
    px, py, pz, pt = p
    qx, qy, qz, qt = q
    a = (py - px) * (qy - qx) % P
    b = (py + px) * (qy + qx) % P
    c = 2 * pt * qt * D % P
    d = 2 * pz * qz % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _point_mul(scalar: int, point):
    result = _IDENTITY
    while scalar > 0:
        if scalar & 1:
            result = _point_add(result, point)
        point = _point_add(point, point)
        scalar >>= 1
    return result


def _point_equal(p, q) -> bool:
    px, py, pz, _ = p
    qx, qy, qz, _ = q
    # Cross-multiplied so the comparison is projective: (X:Y:Z) and (2X:2Y:2Z)
    # are the same point and must compare equal.
    return (px * qz - qx * pz) % P == 0 and (py * qz - qy * pz) % P == 0


def _decompress(data: bytes):
    """A 32-byte encoded point, or None if the bytes are not one."""
    if len(data) != KEY_LEN:
        return None
    value = int.from_bytes(data, "little")
    sign = value >> 255
    y = value & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % P)


def _is_small_order(point) -> bool:
    """Does [8]P land on the identity?

    True for the eight points of order dividing 8. A signature under such a
    key can be produced by anyone, so accepting one authenticates nothing.
    """
    doubled = _point_add(point, point)
    quadrupled = _point_add(doubled, doubled)
    return _point_equal(_point_add(quadrupled, quadrupled), _IDENTITY)


_BASE = None


def _base_point():
    global _BASE
    if _BASE is None:
        x = _recover_x(_BY, 0)
        # The base point is a fixed constant of the curve; if this fails the
        # module's own arithmetic is wrong, and every verdict below is too.
        assert x is not None, "curve constants are inconsistent"
        _BASE = (x, _BY, 1, x * _BY % P)
    return _BASE


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Does `signature` verify over `message` under `public_key`?

    Returns False for every kind of failure -- malformed key, malformed
    signature, wrong signature -- because the distinction is not one a caller
    can act on differently and collapsing it removes a branch that could
    otherwise leak which part was wrong.
    """
    if len(public_key) != KEY_LEN or len(signature) != SIG_LEN:
        return False

    a_point = _decompress(public_key)
    if a_point is None or _is_small_order(a_point):
        return False

    r_point = _decompress(signature[:32])
    if r_point is None or _is_small_order(r_point):
        return False

    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        # Non-canonical scalar: S and S+L would be two encodings of one
        # signature, and therefore two records with different ids.
        return False

    h = int.from_bytes(
        hashlib.sha512(signature[:32] + public_key + message).digest(), "little"
    ) % L

    # [S]B == R + [h]A, strict: no cofactor multiplication on either side.
    left = _point_mul(s, _base_point())
    right = _point_add(r_point, _point_mul(h, a_point))
    return _point_equal(left, right)


def is_usable_public_key(public_key: bytes) -> bool:
    """Whether these bytes are a key that can meaningfully verify anything.

    Mirrors the Rust `VerifyingKeyBytes::is_usable`: a well-formed point that
    is not small-order.
    """
    if len(public_key) != KEY_LEN:
        return False
    point = _decompress(public_key)
    return point is not None and not _is_small_order(point)
