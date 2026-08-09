"""Certificate checker: an elliptic-curve discrete logarithm.

The canonical shape this network exists for. Finding `k` with `k*G = Q` takes
about `sqrt(n)` group operations; *checking* a claimed `k` is one scalar
multiplication. Nothing about how the submitter found it is verifiable, and
nothing about it needs to be.

The instance is baked into this file and this file is pinned by hash inside the
objective's id, so **the instance is part of the objective's identity**: nobody
can retarget a funded bounty at an easier point, and an edit forks the objective
rather than rescoring work already done against it.

# What is checked, exactly

`k` is required to lie in `[1, n)` and to satisfy `k*G = Q`. The range matters:
the discrete logarithm is only unique modulo `n`, so without it a submitter
could offer `k + n` and be equally correct while claiming a different artifact,
and one problem would have unboundedly many settling answers.

# What this does NOT decide

Anything about the method. A `k` found by Pollard rho, by a structural weakness
in the curve, or by having been told it, verifies identically -- which is the
property that makes an unreliable contributor safe to accept, and the reason
this network buys artifacts rather than effort.
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


def check(artifact: dict) -> tuple[bool, str]:
    # A field element does not fit a canonical integer at these sizes -- ORDER_N
    # is 131 bits for the Certicom instances, past i128 -- so `k` travels as a
    # string, in exactly one spelling. 64 lowercase hex characters, zero-padded,
    # uniformly across this family so the frontier instance and the ladder do
    # not need two artifact shapes.
    if not isinstance(artifact, dict):
        return False, "artifact must be an object"
    k = artifact.get("k")
    if not isinstance(k, str):
        return False, "artifact.k must be a 64-character lowercase hex string"
    if len(k) != 64 or any(c not in "0123456789abcdef" for c in k):
        return False, "artifact.k must be a 64-character lowercase hex string"
    k = int(k, 16)
    if not 1 <= k < ORDER_N:
        return False, f"k must lie in [1, n); got a {k.bit_length()}-bit value"
    got = _mul(k, (GEN_X, GEN_Y))
    if got is None:
        return False, "k*G is the point at infinity"
    if got != (TARGET_X, TARGET_Y):
        return False, "k*G does not equal the target point Q"
    return True, f"verified: k*G = Q for the {k.bit_length()}-bit k supplied"


# -- the pinned instance -----------------------------------------------------
#
# Certicom's ECCp-131, verbatim, from the archived challenge page
# (web.archive.org/web/20161124190427/https://www.certicom.com/index.php/curves-list).
#
# Authenticated by arithmetic rather than by its source, which is the only
# defence available for a page whose original host is gone: p prime, the curve
# non-singular, P and Q both on it, n prime, and n*P = n*Q = O. A single
# corrupted hex digit fails "on the curve" with probability ~1 - 2^-131.
# tools/validate_certicom.py re-runs all of it.
#
# The generator is Certicom's P and the target is their Q; this file calls them
# GEN and TARGET to match the rest of the family.
#
# OPEN since 1997. Pollard rho needs about 2^65.3 group operations -- roughly
# 2,048x the ECCp-109 effort, which took 549 days across ~10,000 machines.
CURVE_P = 1550031797834347859248576414813139942411
CURVE_A = 1399267573763578815877905235971153316710
CURVE_B = 1009296542191532464076260367525816293976
ORDER_N = 1550031797834347859219047037805205710577
GEN_X = 1317953763239595888465524145589872695690
GEN_Y = 434829348619031278460656303481105428081
TARGET_X = 1247392211317907151303247721489640699240
TARGET_Y = 207534858442090452193999571026315995117
