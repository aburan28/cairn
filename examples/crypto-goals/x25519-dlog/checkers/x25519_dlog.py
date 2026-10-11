"""Pure-Python checker for a sign-canonical Curve25519 subgroup DLP."""
import hashlib

P = 2**255 - 19
A = 486662
ELL = 2**252 + 27742317777372353535851937790883648493
A24 = 121665
G = (9, 14781619447589544791020593568409986887264606134616475288964881837755586237401)
SEED = b"cairn/x25519/prime-subgroup-dlog/v1"


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
        slope = (3 * x1 * x1 + 2 * A * x1 + 1) * pow(2 * y1, -1, P) % P
    else:
        slope = (y2 - y1) * pow((x2 - x1) % P, -1, P) % P
    x3 = (slope * slope - A - x1 - x2) % P
    y3 = (slope * (x1 - x3) - y1) % P
    return x3, y3


def multiply(scalar, point):
    result = None
    while scalar:
        if scalar & 1:
            result = add(result, point)
        point = add(point, point)
        scalar >>= 1
    return result


def square_root(value):
    """Square root modulo P; P = 5 (mod 8)."""
    value %= P
    root = pow(value, (P + 3) // 8, P)
    if root * root % P != value:
        root = root * pow(2, (P - 1) // 4, P) % P
    return root if root * root % P == value else None


def x_multiply(scalar, u):
    """RFC 7748 Montgomery ladder for an unclamped nonnegative scalar."""
    if scalar == 0:
        return None
    x1 = u % P
    x2, z2 = 1, 0
    x3, z3 = x1, 1
    swap = 0
    for bit in range(scalar.bit_length() - 1, -1, -1):
        current = (scalar >> bit) & 1
        swap ^= current
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = current
        a = (x2 + z2) % P
        aa = a * a % P
        b = (x2 - z2) % P
        bb = b * b % P
        e = (aa - bb) % P
        c = (x3 + z3) % P
        d = (x3 - z3) % P
        da = d * a % P
        cb = c * b % P
        x3 = (da + cb) ** 2 % P
        z3 = x1 * (da - cb) ** 2 % P
        x2 = aa * bb % P
        z2 = e * (aa + A24 * e) % P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return None if z2 == 0 else x2 * pow(z2, -1, P) % P


def target():
    """Derive a curve point from SHAKE256 and clear Curve25519's cofactor 8."""
    width = 32
    for counter in range(1 << 32):
        digest = hashlib.shake_256(SEED + counter.to_bytes(4, "big")).digest(width + 32)
        x = int.from_bytes(digest[:width], "big") % P
        rhs = (x * x * x + A * x * x + x) % P
        y = square_root(rhs)
        if y is None:
            continue
        if (y & 1) != (digest[-1] & 1):
            y = P - y
        subgroup_point = multiply(8, (x, y))
        if subgroup_point is None:
            continue
        qx = subgroup_point[0]
        if x_multiply(ELL, qx) is None:
            return qx, counter
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
    if not 1 <= scalar <= (ELL - 1) // 2:
        return False
    return x_multiply(scalar, 9) == target()[0]
