"""Certificate checker: a discrete logarithm on secp256k1.

The canonical shape this network is built for. Finding k such that k*G = P is
believed to take ~sqrt(n) group operations; *checking* a claimed k is one
scalar multiplication, about five milliseconds here. Nothing about how the
submitter found it is verifiable, and nothing about it needs to be.

The target point is baked into this file, and this file is pinned by hash inside
the objective's id. So the instance IS part of the objective's identity: nobody
can retarget a funded bounty at an easier point, and an edit forks the objective
instead of rescoring work already done against it.

Instance: secp256k1, with k drawn uniformly from [2^39, 2^40). The bound is
stated in the objective and is what makes this searchable at all -- it is not a
weakness in the curve, and it is checked here so a submitter cannot satisfy the
objective with some other representative of the logarithm.
"""

# secp256k1
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

# The target. P_TARGET = k*G for the k this objective is asking for.
TARGET_X = 31507860178967156289734765118213508342860546274352776588422724636527951356918
TARGET_Y = 89226042985490024420312584068128455649955992162493091208423132478145195358694

LOW = 2**39
HIGH = 2**40


def _add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    (x1, y1), (x2, y2) = p, q
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p == q:
        lam = (3 * x1 * x1) * pow(2 * y1, P - 2, P) % P
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
    if not LOW <= k < HIGH:
        return False, f"k must lie in [2^39, 2^40); got a {k.bit_length()}-bit value"
    got = _mul(k, (GX, GY))
    if got is None:
        return False, "k*G is the point at infinity"
    if got != (TARGET_X, TARGET_Y):
        return False, "k*G does not equal the target point"
    return True, f"verified: k*G = P for the {k.bit_length()}-bit k supplied"
