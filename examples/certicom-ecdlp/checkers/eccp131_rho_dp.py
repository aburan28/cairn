"""Certificate checker: one distinguished point of a shared Pollard rho walk.

The unit of work in a *piecework* objective (docs/design/rho-piecework.md).
The answer objective for this instance -- objective-certicom-eccp131.json -- pays once, for
`k`; this one pays many times, for the search that finds it. A record
`(x, y, a, b)` with `a*P + b*Q = (x, y)` and the low DP_BITS bits of `x` zero
costs about 2^DP_BITS group operations to produce by the cheapest known
method and two scalar multiplications to check, so it is proof of work that
is also the work: every accepted point is one more entry in the shared table
that any other contributor's trail can collide with. Whoever's point lands on
one already in the log computes `k` (`tools/rho_dp.py collide`) and claims the
answer objective.

# What is checked, exactly

The artifact is exactly the four keys `x`, `y`, `a`, `b`, each a lowercase hex
string with no prefix and no leading zero, and:

- `(x, y)` is on the pinned curve;
- the low DP_BITS bits of `x` are zero (the point is distinguished);
- `2*y <= p` (the canonical representative, so one point has one spelling
  whichever walk reached it, and a negated copy is not a second artifact);
- `a` and `b` lie in `[0, n)`, so the coefficient pair is unique;
- `a*P + b*Q == (x, y)`.

Nothing else may travel in the artifact. A walker index or a step count would
let a copier re-mint a public point by relabelling it, because cairn's
piecework rule keys novelty on the artifact digest. Two contributors who reach
the same point along different trails hold *different* coefficients, so both
artifacts are novel -- and their pair is the collision that solves the
instance.

# What this does NOT decide

Which walk produced the point. A point from a private walk verifies the same
and is paid the same; it costs its producer the same 2^DP_BITS steps and
contributes only its endpoint to the shared search. The walk everyone is
asked to run is the job document named below, pinned here by hash so that
the job is part of this objective's identity: `tools/rho_dp.py` and
`crypto cryptanalysis rho-collab work` both run it.
"""


def _inv(x, p):
    return pow(x, -1, p)


def _add(P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    (x1, y1), (x2, y2) = P, Q
    if x1 == x2 and (y1 + y2) % CURVE_P == 0:
        return None
    if P == Q:
        lam = (3 * x1 * x1 + CURVE_A) * _inv(2 * y1, CURVE_P) % CURVE_P
    else:
        lam = (y2 - y1) * _inv((x2 - x1) % CURVE_P, CURVE_P) % CURVE_P
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


def _hex_field(artifact, key):
    value = artifact.get(key)
    if not isinstance(value, str) or not value:
        return None
    if any(c not in "0123456789abcdef" for c in value):
        return None
    if len(value) > 1 and value[0] == "0":
        return None
    return int(value, 16)


def check(artifact: dict) -> tuple[bool, str]:
    if not isinstance(artifact, dict):
        return False, "artifact must be an object"
    if set(artifact) != {"x", "y", "a", "b"}:
        return False, "artifact must carry exactly the keys x, y, a, b and nothing else"
    values = {key: _hex_field(artifact, key) for key in ("x", "y", "a", "b")}
    for key, value in values.items():
        if value is None:
            return False, f"artifact.{key} must be lowercase hex with no prefix and no leading zero"
    x, y, a, b = values["x"], values["y"], values["a"], values["b"]
    if not (x < CURVE_P and y < CURVE_P):
        return False, "x and y must be field elements"
    if (y * y - (x * x * x + CURVE_A * x + CURVE_B)) % CURVE_P != 0:
        return False, "(x, y) is not on the curve"
    if x & ((1 << DP_BITS) - 1):
        return False, f"x is not distinguished: its low {DP_BITS} bits are not all zero"
    if 2 * y > CURVE_P:
        return False, "y is not canonical: the artifact must carry the representative with 2y <= p"
    if not (a < ORDER_N and b < ORDER_N):
        return False, "a and b must lie in [0, n)"
    if _mul(a, (GEN_X, GEN_Y)) is None and _mul(b, (TARGET_X, TARGET_Y)) is None:
        return False, "a*P + b*Q is the point at infinity"
    got = _add(_mul(a, (GEN_X, GEN_Y)), _mul(b, (TARGET_X, TARGET_Y)))
    if got != (x, y):
        return False, "a*P + b*Q does not equal the claimed point"
    return True, f"verified: a distinguished point of the ECCp-131 walk (about 2^{DP_BITS} steps of work)"


# -- the pinned instance and walk ----------------------------------------------
#
# The curve, P, Q and n are exactly those of checkers/certicom_eccp131.py -- the
# answer objective this search feeds. DP_BITS is the walk's distinguished-point
# density: a point is distinguished when the low DP_BITS bits of x are zero, so
# a trail runs about 2^DP_BITS steps between points.
#
# The shared walk is the job document below. Its hash is pinned here so the
# walk is inside this objective's id: change the job, and this is a different
# objective. `tools/rho_dp.py job-id --job <JOB>` prints JOB_ID, which the
# `crypto` implementation agrees with.
CURVE_P = 1550031797834347859248576414813139942411
CURVE_A = 1399267573763578815877905235971153316710
CURVE_B = 1009296542191532464076260367525816293976
ORDER_N = 1550031797834347859219047037805205710577
GEN_X = 1317953763239595888465524145589872695690
GEN_Y = 434829348619031278460656303481105428081
TARGET_X = 1247392211317907151303247721489640699240
TARGET_Y = 207534858442090452193999571026315995117
DP_BITS = 44
JOB = "examples/certicom-ecdlp/jobs/eccp131-rho.json"
JOB_SHA256 = "ac0b8b332a9ef507e0705139cc673bff479fe1e389ad0d3bb5c646749171f5d9"
JOB_ID = "6f4881b59a78bfd929a7bf87bd2d4ce3210066862e62418b8333c39ec855cf7c"
