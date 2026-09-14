"""Certificate checker: the discrete logarithm on a binary Koblitz curve.

The answer to cairn ecc2k-23 orbit rho. Finding `k` with `[k]P = Q` takes about
`sqrt(pi * n / (4 * m))` group operations once the `<-1> x <sigma>` speed-up
is taken; *checking* a claimed `k` is one scalar multiplication. Nothing about
how the submitter found it is verifiable, and nothing about it needs to be.

The companion objective `objective-ecc2k-23-orbit-batch.json` pays for the search itself, orbit
by orbit, and is the one that will actually settle claims. This one pays for
the answer, once. The two are linked only by naming the same job document: a
contributor whose new orbit matches one already in the log holds both halves
of a collision and computes `k` with `tools/orbit_dp.py collide`.

# What is checked, exactly

`k` is required to lie in `[1, n)` and to satisfy `[k]P = Q`. The range
matters: the logarithm is only unique modulo `n`, so without it `k + n` would
be an equally correct answer under a different artifact digest, and one
problem would have unboundedly many settling answers. `k` is HEX_LEN
lowercase hex characters, zero-padded, so one value has one spelling.

# What this does NOT decide

Anything about the method. A `k` found by this network's own rho, by a
structural weakness in the curve, or by having been told it, verifies
identically.
"""


def _reduce(a):
    while a > MASK:
        hi = a >> M
        a &= MASK
        for t in TAPS:
            a ^= hi << t
    return a


def _mul(a, b):
    table = [0] * 16
    table[1] = a
    table[2] = a << 1
    table[4] = a << 2
    table[8] = a << 3
    for i in (3, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15):
        low = i & -i
        table[i] = table[low] ^ table[i ^ low]
    r = 0
    shift = 0
    while b:
        r ^= table[b & 15] << shift
        b >>= 4
        shift += 4
    return _reduce(r)


def _inv(a):
    """Itoh-Tsujii; `a` is never zero on the paths that reach here."""
    n = M - 1
    x, k = a, 1
    for bit in bin(n)[3:]:
        y = x
        for _ in range(k):
            y = _mul(y, y)
        x = _mul(y, x)
        k *= 2
        if bit == "1":
            x = _mul(_mul(x, x), a)
            k += 1
    return _mul(x, x)


def _dbl(P):
    if P is None or P[0] == 0:
        return None
    x, y = P
    lam = x ^ _mul(y, _inv(x))
    x3 = _mul(lam, lam) ^ lam ^ CURVE_A
    return (x3, _mul(x, x) ^ _mul(lam ^ 1, x3))


def _add(P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2:
        return _dbl(P) if y1 == y2 else None
    d = x1 ^ x2
    lam = _mul(y1 ^ y2, _inv(d))
    x3 = _mul(lam, lam) ^ lam ^ d ^ CURVE_A
    return (x3, _mul(lam, x1 ^ x3) ^ x3 ^ y1)


def _scalar(k, P):
    r, base = None, P
    while k:
        if k & 1:
            r = _add(r, base)
        base = _dbl(base)
        k >>= 1
    return r


def check(artifact: dict) -> tuple[bool, str]:
    if not isinstance(artifact, dict):
        return False, "artifact must be an object"
    if set(artifact) != {"k"}:
        return False, "artifact must carry exactly the key k"
    value = artifact["k"]
    if not isinstance(value, str) or len(value) != HEX_LEN:
        return False, f"k must be exactly {HEX_LEN} lowercase hex characters"
    if any(c not in "0123456789abcdef" for c in value):
        return False, "k must be lowercase hex"
    k = int(value, 16)
    if not 1 <= k < ORDER_N:
        return False, "k must lie in [1, n)"
    if _scalar(k, (GEN_X, GEN_Y)) != (TARGET_X, TARGET_Y):
        return False, "[k]P is not Q"
    return True, "verified: [k]P = Q"


# -- the pinned instance -------------------------------------------------------
M = 23
POLY = 8388641
CURVE_A = 0
CURVE_B = 1
ORDER_N = 2095853
GEN_X = 7502454
GEN_Y = 6195881
TARGET_X = 4907764
TARGET_Y = 112483
HEX_LEN = 6
JOB = "examples/certicom-ecdlp/jobs/ecc2k-23.json"
JOB_SHA256 = "72c83d28e6bd8c3c31b9e1b01d4225c1a6c3a15147c37b8bc4ae5b4fd5826ced"
JOB_ID = "c22d2033b98a00dbf6635349d70278294c654a6f717c54389c217cde448099f6"

MASK = (1 << M) - 1
TAPS = [i for i in range(M) if (POLY >> i) & 1]
