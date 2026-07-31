"""Certificate checker: First-Blood ECDLP instance, 128-bit.

Recover k with k*G == Q on the curve below. Finding k is believed to cost
~sqrt(n) group operations; checking a claimed k is one scalar multiplication.
How it was found is irrelevant and unverifiable, which is the point.

k is UNKNOWN to whoever posted this -- discarded at instance generation. That is
what makes this a real bounty rather than a self-dealt one: the funder cannot
already hold the answer.

The instance is baked into this file, and this file is pinned by hash inside the
objective's id, so the instance IS part of the objective's identity. Nobody can
retarget a funded bounty at an easier point.

Self-contained on purpose. The verifier pins the sha256 of THIS FILE ONLY -- an
imported helper module would not be covered by that hash, so shared curve
arithmetic would be an unpinned hole. Duplication is the price of pinning.

Source: ecdlp-cost-challenge, first_blood/instance_public_128.json (seed 1).
"""

P = 295177254943362223916299992651383358767
A = 14161427341314993120236695357718212503
B = 112079458708500844035282496481810762805
N = 295177254943362223930881168223821270637
GX = 22277941299458159307984049048665514193
GY = 166743309875712818705719654057341916148
QX = 113291150549108454151939787625775981945
QY = 65249396265307419762166255945466900257
BITS = 128


def _on_curve(x, y):
    return (y * y - x * x * x - A * x - B) % P == 0


def _add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    (x1, y1), (x2, y2) = p, q
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p == q:
        lam = (3 * x1 * x1 + A) * pow(2 * y1, P - 2, P) % P
    else:
        lam = (y2 - y1) * pow((x2 - x1) % P, P - 2, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


def _mul(k, point):
    result, addend = None, point
    while k:
        if k & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        k >>= 1
    return result


def check(artifact: dict) -> tuple[bool, str]:
    k = artifact.get("k")
    if isinstance(k, bool) or not isinstance(k, int):
        return False, "artifact.k must be an integer"
    # k is a group element exponent: any representative in [1, n) is a valid
    # discrete log, and there is exactly one.
    if not 1 <= k < N:
        return False, f"k must lie in [1, n) with n = {N}"
    # Guard the constants themselves. If either point were off-curve the
    # objective would be unsatisfiable, and a submitter should not spend
    # compute discovering that.
    if not _on_curve(GX, GY) or not _on_curve(QX, QY):
        return False, "instance constants are not on the curve"
    got = _mul(k, (GX, GY))
    if got is None:
        return False, "k*G is the point at infinity"
    if got != (QX, QY):
        return False, "k*G does not equal Q"
    return True, f"verified: k*G == Q on the {BITS}-bit instance"
