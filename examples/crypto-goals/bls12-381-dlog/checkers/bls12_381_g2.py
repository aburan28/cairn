"""Pure-Python checker for a deterministic BLS12-381 G2 DLP target."""
import hashlib

P = int("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 16)
R = int("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)
H2 = int("5d543a95414e7f1091d50792876a202cd91de4547085abaa68a205b2e5a7ddfa628f1cb4d9e82ef21537e293a6691ae1616ec6e786f0c70cf1c38e31c7238e5", 16)
# Fp2 uses the polynomial basis 1, u with u^2 = -1.
B = (4, 4)
G = (
    (int("024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8", 16),
     int("13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e", 16)),
    (int("0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801", 16),
     int("0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be", 16)),
)
SEED = b"cairn/bls12-381/g2-dlog/v1"
ZERO = (0, 0)
ONE = (1, 0)


def fadd(x, y):
    return ((x[0] + y[0]) % P, (x[1] + y[1]) % P)


def fneg(x):
    return (-x[0] % P, -x[1] % P)


def fsub(x, y):
    return fadd(x, fneg(y))


def fmul(x, y):
    return ((x[0] * y[0] - x[1] * y[1]) % P,
            (x[0] * y[1] + x[1] * y[0]) % P)


def finv(x):
    norm = (x[0] * x[0] + x[1] * x[1]) % P
    inv_norm = pow(norm, -1, P)
    return (x[0] * inv_norm % P, -x[1] * inv_norm % P)


def fp_sqrt(value):
    value %= P
    root = pow(value, (P + 1) // 4, P)
    return root if root * root % P == value else None


def fsqrt(z):
    """Return an Fp2 square root or None; P is 3 mod 4."""
    a, b = z
    if b == 0:
        root = fp_sqrt(a)
        if root is not None:
            return (root, 0)
        root = fp_sqrt(-a)
        return None if root is None else (0, root)
    norm_root = fp_sqrt((a * a + b * b) % P)
    if norm_root is None:
        return None
    inv_two = (P + 1) // 2
    for norm in (norm_root, -norm_root % P):
        real_sq = ((a + norm) * inv_two) % P
        real = fp_sqrt(real_sq)
        if real is None or real == 0:
            continue
        imag = b * pow(2 * real, -1, P) % P
        candidate = (real, imag)
        if fmul(candidate, candidate) == z:
            return candidate
    return None


def add(left, right):
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and fadd(y1, y2) == ZERO:
        return None
    if left == right:
        slope = fmul((3, 0), fmul(x1, x1))
        slope = fmul(slope, finv(fmul((2, 0), y1)))
    else:
        slope = fmul(fsub(y2, y1), finv(fsub(x2, x1)))
    x3 = fsub(fsub(fmul(slope, slope), x1), x2)
    y3 = fsub(fmul(slope, fsub(x1, x3)), y1)
    return x3, y3


def multiply(scalar, point):
    result = None
    while scalar:
        if scalar & 1:
            result = add(result, point)
        point = add(point, point)
        scalar >>= 1
    return result


def target():
    """Hash Fp2 x-coordinates, then clear the full G2 twist cofactor."""
    width = (P.bit_length() + 7) // 8
    for counter in range(1 << 32):
        digest = hashlib.shake_256(SEED + counter.to_bytes(4, "big")).digest(2 * width + 32)
        x = (int.from_bytes(digest[:width], "big") % P,
             int.from_bytes(digest[width:2 * width], "big") % P)
        rhs = fadd(fmul(fmul(x, x), x), B)
        y = fsqrt(rhs)
        if y is None:
            continue
        if (y[0] & 1) != (digest[-1] & 1):
            y = fneg(y)
        point = multiply(H2, (x, y))
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
