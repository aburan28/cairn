"""Pure-Python checker for a deterministic BLS12-381 G1 discrete-log target."""
import hashlib

P = int("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 16)
R = int("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)
H1 = int("396c8c005555e1568c00aaab0000aaab", 16)
G = (
    int("17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb", 16),
    int("08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1", 16),
)
SEED = b"cairn/bls12-381/g1-dlog/v1"


def add(left, right):
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if left == right:
        slope = 3 * x1 * x1 * pow(2 * y1, -1, P) % P
    else:
        slope = (y2 - y1) * pow((x2 - x1) % P, -1, P) % P
    x3 = (slope * slope - x1 - x2) % P
    return x3, (slope * (x1 - x3) - y1) % P


def multiply(scalar, point):
    result = None
    while scalar:
        if scalar & 1:
            result = add(result, point)
        point = add(point, point)
        scalar >>= 1
    return result


def target():
    """Hash-to-point by first-valid x, then clear the full G1 cofactor."""
    width = (P.bit_length() + 7) // 8
    for counter in range(1 << 32):
        digest = hashlib.shake_256(SEED + counter.to_bytes(4, "big")).digest(width + 32)
        x = int.from_bytes(digest, "big") % P
        rhs = (x * x * x + 4) % P
        y = pow(rhs, (P + 1) // 4, P)
        if y * y % P != rhs:
            continue
        if (y & 1) != (digest[-1] & 1):
            y = P - y
        point = multiply(H1, (x, y))
        if point is not None and multiply(R, point) is None:
            return point, counter
    raise RuntimeError("deterministic target search exhausted")


def check(artifact):
    if not isinstance(artifact, dict) or set(artifact) != {"k"}:
        return False
    value = artifact["k"]
    if not isinstance(value, str) or len(value) != 64:
        return False
    if any(char not in "0123456789abcdef" for char in value):
        return False
    scalar = int(value, 16)
    if not 1 <= scalar < R:
        return False
    return multiply(scalar, G) == target()[0]
