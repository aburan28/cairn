"""Certificate checker: a discrete logarithm on a small prime-order curve.

The canonical shape this network is built for. Finding `k` such that `k*G = Q`
takes about `sqrt(n)` group operations; *checking* a claimed `k` is one scalar
multiplication. Nothing about how the submitter found it is verifiable, and
nothing about it needs to be.

The instance is baked into this file and this file is pinned by hash inside the
objective's id, so the instance IS part of the objective's identity: nobody can
retarget a funded bounty at an easier point, and an edit forks the objective
instead of rescoring work already done against it.

# Why this is not secp256k1 any more

It used to be, with `k` confined to `[2^39, 2^40)` so the search was feasible.
That bound was the whole problem. A confined scalar is a *chosen* scalar, so
whoever built the instance knew the answer and could collect their own bounty --
the **self-dealing** row in `docs/threat-model.md`.

It cannot be patched on a 256-bit curve, and the arithmetic says why. Derive `Q`
honestly, by hashing to a point, and `k` is uniform in `[1, n)` with `n ~ 2^256`,
which is 2^128 work and unsolvable. Keep it solvable by bounding `k` and you are
back to somebody having picked it. **Solvability has to come from a small group,
not a small scalar** -- so the curve changed instead.

# Nothing here was chosen

Every number below is a SHA-256 output of the public seed string recorded in
`SEED`, and `examples/certicom-ecdlp/tools/nums.py verify` re-derives all of
them. There is no step at which anyone selected a scalar, so the answer is as
unknown to whoever posted this as to anyone reading it.

`n` is prime, so the group is cyclic, every point lies in `<G>`, and the hashed
`Q` is guaranteed to have a logarithm -- the instance cannot be quietly
unsolvable. `n` was found by baby-step giant-step over the Hasse interval and
then required to be prime, so the order is known rather than assumed.

This is the introductory rung, at about 2^22 group operations -- seconds. The
graded ladder and the open Certicom frontier are in
`examples/certicom-ecdlp/`.
"""

SEED = "cairn ecdlp intro v1 45"

CURVE_P = 35184372088763
CURVE_A = 17410361175639
CURVE_B = 17766383712479
ORDER_N = 35184362222279
GEN_X = 21472226374721
GEN_Y = 34743114722854
TARGET_X = 34723134103378
TARGET_Y = 21757300104678


def _add(P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    (x1, y1), (x2, y2) = P, Q
    if x1 == x2 and (y1 + y2) % CURVE_P == 0:
        return None
    if P == Q:
        lam = (3 * x1 * x1 + CURVE_A) * pow(2 * y1, -1, CURVE_P) % CURVE_P
    else:
        lam = (y2 - y1) * pow((x2 - x1) % CURVE_P, -1, CURVE_P) % CURVE_P
    x3 = (lam * lam - x1 - x2) % CURVE_P
    return (x3, (lam * (x1 - x3) - y1) % CURVE_P)


def _mul(k, P):
    R, A = None, P
    while k:
        if k & 1:
            R = _add(R, A)
        A = _add(A, A)
        k >>= 1
    return R


def check(artifact: dict) -> tuple[bool, str]:
    # `k` travels as 64 lowercase hex characters, in one spelling, matching the
    # rest of the ECDLP family in `examples/certicom-ecdlp/`. Their 131-bit
    # instance does not fit a canonical integer, so the whole family uses a
    # string rather than having two artifact shapes for one kind of problem.
    if not isinstance(artifact, dict):
        return False, "artifact must be an object"
    k = artifact.get("k")
    if not isinstance(k, str):
        return False, "artifact.k must be a 64-character lowercase hex string"
    if len(k) != 64 or any(c not in "0123456789abcdef" for c in k):
        return False, "artifact.k must be a 64-character lowercase hex string"
    k = int(k, 16)
    # The logarithm is only unique modulo n, so without this bound `k + n` is a
    # second settling answer to one problem, with a different artifact digest.
    if not 1 <= k < ORDER_N:
        return False, f"k must lie in [1, n); got a {k.bit_length()}-bit value"
    got = _mul(k, (GEN_X, GEN_Y))
    if got is None:
        return False, "k*G is the point at infinity"
    if got != (TARGET_X, TARGET_Y):
        return False, "k*G does not equal the target point Q"
    return True, f"verified: k*G = Q for the {k.bit_length()}-bit k supplied"
