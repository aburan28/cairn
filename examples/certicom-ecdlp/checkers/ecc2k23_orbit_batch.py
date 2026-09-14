"""Certificate checker: a batch of distinguished orbits of a Koblitz rho walk.

The unit of work in a *piecework* objective over a binary Koblitz curve --
cairn ecc2k-23 orbit rho -- where a point cannot carry its own coefficients.
`objective-ecc2k-23.json` pays once, for `k`; this one pays for the search that
finds it, a batch at a time. See `docs/design/orbit-piecework.md`.

# What a unit is

Not a point: an **orbit**. `sigma: (x, y) -> (x^2, y^2)` and negation
`(x, y) -> (x, x + y)` generate a group of order `2m` acting on the curve,
the iteration function is defined on its orbits, and two trails that reach
the same orbit have collided. So the unit a claim answers is the orbit, named
by the least cyclic rotation of `x`'s normal-basis coordinates -- and the
objective's piecework block keys novelty on exactly that field. Submitting
another spelling of a paid orbit mints nothing, which is what stops `2m`
relabellings of one point being paid `2m` times.

# What is checked, exactly

The artifact is exactly `{"dps": [...]}` with 1 to MAX_BATCH elements, each
carrying exactly `x`, `seed` and `j`:

- `x` is the orbit: lowercase hex, no leading zero, M normal-basis
  coordinates of the abscissa. Its Hamming weight -- which is invariant under
  both generators, and is therefore a property of the orbit and not of a
  representative -- must be at most DP_MAX_WEIGHT, and it must already be the
  least of its M rotations;
- `seed` is the 64-bit walk seed, which fixes the start point
  `R_0 = Q + sum_i c_i sigma^i(P) = [alpha_0]P + Q`;
- `j` is the **witness**: J_COUNT counters saying how many steps of the trail
  took each branch. One step is `R -> R + sigma^j(R) = [1 + s^j]R`, and
  multiplication in the endomorphism ring commutes, so the whole trail is
  `[mu]R_0` for `mu = prod_j (1 + s^j)^(j[j - J_BASE])` whatever order the
  steps came in. The checker recomputes `mu`, forms `[mu*alpha_0]P + [mu]Q`
  with one double scalar multiplication, and requires it to land on the
  claimed orbit.

A batch with one bad element is refused whole, naming the element: the
submitter verified every point locally before shipping it, so a bad one is
their mistake, and refusing the batch keeps this a yes/no certificate.

# What this does NOT decide

Whether the counters are the ones *this* walk's `j` rule produces. A
contributor who applies `sigma^3` at every step regardless of the weight
produces witnesses that verify here and trails that merge with nobody -- the
same cost to them, no search progress for the network. Deciding that costs
the trail again, so it is sampled by an auditor (`tools/orbit_dp.py audit`)
and backed by a bond, not decided here. What the witness *does* buy is that
forgery is no longer free: without it, a low-weight canonical bit string is
something anyone can type, and the cheapest attack on this objective would
cost nothing at all.
"""


# -- GF(2^M), polynomial basis -------------------------------------------------


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


def _sqr(a):
    r = 0
    shift = 0
    while a:
        r |= SPREAD[a & 255] << shift
        a >>= 8
        shift += 16
    return _reduce(r)


def _inv(a):
    n = M - 1
    x, k = a, 1
    for bit in bin(n)[3:]:
        y = x
        for _ in range(k):
            y = _sqr(y)
        x = _mul(y, x)
        k *= 2
        if bit == "1":
            x = _mul(_sqr(x), a)
            k += 1
    return _sqr(x)


# -- the normal basis the weight and the orbit are read in ---------------------


def _to_nb(x):
    v = 0
    for i, row in enumerate(NB_ROWS):
        if bin(x & row).count("1") & 1:
            v |= 1 << i
    return v


def _least_rotation(c):
    best = c
    for _ in range(M - 1):
        c = ((c << 1) | (c >> (M - 1))) & MASK
        if c < best:
            best = c
    return best


# -- the curve, in Lopez-Dahab projective coordinates --------------------------
#
# A batch is up to MAX_BATCH double scalar multiplications and an affine one
# pays a field inversion per group operation, which is the most expensive
# thing here. Projective coordinates pay one inversion for the whole scalar
# multiplication instead.


def _ld_double(T):
    X1, Y1, Z1 = T
    if Z1 == 0 or X1 == 0:
        return (1, 0, 0)
    X1sq = _mul(X1, X1)
    Z1sq = _mul(Z1, Z1)
    Z3 = _mul(X1sq, Z1sq)
    bZ4 = _mul(CURVE_B, _mul(Z1sq, Z1sq))
    X3 = _mul(X1sq, X1sq) ^ bZ4
    t = _mul(Y1, Y1) ^ bZ4 ^ _mul(CURVE_A, Z3)
    return (X3, _mul(bZ4, Z3) ^ _mul(X3, t), Z3)


def _ld_add(T, P):
    X1, Y1, Z1 = T
    if Z1 == 0:
        return (P[0], P[1], 1)
    x2, y2 = P
    Z1sq = _mul(Z1, Z1)
    A = _mul(y2, Z1sq) ^ Y1
    B = _mul(x2, Z1) ^ X1
    if B == 0:
        return _ld_double(T) if A == 0 else (1, 0, 0)
    C = _mul(Z1, B)
    D = _mul(_mul(B, B), C ^ _mul(CURVE_A, Z1sq))
    Z3 = _mul(C, C)
    E = _mul(A, C)
    X3 = _mul(A, A) ^ D ^ E
    Y3 = _mul(E, X3 ^ _mul(x2, Z3)) ^ _mul(Z3, X3 ^ _mul(y2, Z3))
    return (X3, Y3, Z3)


def _combine(c, d):
    """`[c]P + [d]Q` as an affine point, or `None` for the identity."""
    table = (None, (GEN_X, GEN_Y), (TARGET_X, TARGET_Y), SUM_PQ)
    T = (1, 0, 0)
    for i in range(max(c.bit_length(), d.bit_length()) - 1, -1, -1):
        T = _ld_double(T)
        idx = ((c >> i) & 1) | (((d >> i) & 1) << 1)
        if idx:
            T = _ld_add(T, table[idx])
    X, Y, Z = T
    if Z == 0:
        return None
    zi = _inv(Z)
    return (_mul(X, zi), _mul(Y, _mul(zi, zi)))


# -- the witness ---------------------------------------------------------------


def _splitmix64(seed, index):
    z = (seed + 0x9E3779B97F4A7C15 * (index + 1)) & 0xFFFFFFFFFFFFFFFF
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF
    return z ^ (z >> 31)


def _relation(seed, counts):
    """`(c, d)` with `[c]P + [d]Q` the endpoint the witness names."""
    words = [_splitmix64(seed, i) for i in range((START_TERMS + 63) // 64)]
    alpha = 0
    for i in range(START_TERMS):
        if (words[i >> 6] >> (i & 63)) & 1:
            alpha = (alpha + SPOW[i % M]) % ORDER_N
    mu = 1
    for t, count in enumerate(counts):
        if count:
            mu = mu * pow(FACTOR[t], count, ORDER_N) % ORDER_N
    return mu * alpha % ORDER_N, mu


# -- what a claim must satisfy -------------------------------------------------


def _hex_field(element, key):
    value = element.get(key)
    if not isinstance(value, str) or not value:
        return None
    if any(c not in "0123456789abcdef" for c in value):
        return None
    if len(value) > 1 and value[0] == "0":
        return None
    return int(value, 16)


def _check_point(element):
    """One element. Cheap decidable-from-`x` checks first, arithmetic last."""
    if not isinstance(element, dict):
        return "must be an object"
    if set(element) != {"x", "seed", "j"}:
        return "must carry exactly the keys x, seed, j"
    x = _hex_field(element, "x")
    seed = _hex_field(element, "seed")
    if x is None:
        return "x must be lowercase hex with no prefix and no leading zero"
    if seed is None:
        return "seed must be lowercase hex with no prefix and no leading zero"
    if x >> M:
        return "x must be %d normal-basis coordinates" % M
    if seed > 0xFFFFFFFFFFFFFFFF:
        return "seed must fit 64 bits"
    weight = bin(x).count("1")
    if weight > DP_MAX_WEIGHT:
        return "x is not distinguished: weight %d exceeds %d" % (weight, DP_MAX_WEIGHT)
    if x != _least_rotation(x):
        return "x is not the canonical member of its orbit: a rotation of it is smaller"
    counts = element["j"]
    if not isinstance(counts, list) or len(counts) != J_COUNT:
        return "j must be a list of %d step counts" % J_COUNT
    for count in counts:
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            return "every element of j must be a non-negative integer"
    steps = sum(counts)
    if steps > MAX_STEPS:
        return "j sums to %d steps, past the cap of %d" % (steps, MAX_STEPS)
    c, d = _relation(seed, counts)
    endpoint = _combine(c, d)
    if endpoint is None:
        return "the witness reaches the identity, which is on no orbit"
    if _least_rotation(_to_nb(endpoint[0])) != x:
        return "the witness does not reach this orbit"
    return None


def check(artifact: dict) -> tuple[bool, str]:
    if not isinstance(artifact, dict):
        return False, "artifact must be an object"
    if set(artifact) != {"dps"}:
        return False, "artifact must carry exactly the key dps"
    dps = artifact["dps"]
    if not isinstance(dps, list):
        return False, "dps must be a list"
    if not 1 <= len(dps) <= MAX_BATCH:
        return False, f"dps must carry between 1 and {MAX_BATCH} points; got {len(dps)}"
    seen = set()
    for index, element in enumerate(dps):
        why = _check_point(element)
        if why is not None:
            return False, f"dps[{index}]: {why}"
        if element["x"] in seen:
            return False, f"dps[{index}] repeats an orbit already in the batch"
        seen.add(element["x"])
    return True, f"verified: {len(dps)} distinguished orbits of the cairn ecc2k-23 orbit rho walk (about 2^2 steps each)"


# -- the pinned instance and walk ----------------------------------------------
#
# The job document is the contract; these constants are it, and the checker's
# bytes are inside the objective's id, so the walk everyone is asked to run
# cannot be changed without forking the objective.
M = 23
POLY = 8388641
CURVE_A = 0
CURVE_B = 1
ORDER_N = 2095853
GEN_X = 7502454
GEN_Y = 6195881
TARGET_X = 4907764
TARGET_Y = 112483
FROBENIUS_S = 93194
NB_GENERATOR = 7664795
J_BASE = 3
J_COUNT = 8
START_TERMS = 128
DP_MAX_WEIGHT = 8
DP_BITS = 2
MAX_BATCH = 16
MAX_STEPS = 128
JOB = "examples/certicom-ecdlp/jobs/ecc2k-23.json"
JOB_SHA256 = "72c83d28e6bd8c3c31b9e1b01d4225c1a6c3a15147c37b8bc4ae5b4fd5826ced"
JOB_ID = "c22d2033b98a00dbf6635349d70278294c654a6f717c54389c217cde448099f6"

# -- tables derived from those constants ---------------------------------------
#
# Derived, never pinned: a table copied into this file is a table that can be
# wrong about the constants above it and say nothing. Deriving costs one
# GF(2) matrix inversion at import.
MASK = (1 << M) - 1
TAPS = [i for i in range(M) if (POLY >> i) & 1]
SPREAD = [0] * 256
for _v in range(256):
    _s = 0
    for _i in range(8):
        if (_v >> _i) & 1:
            _s |= 1 << (2 * _i)
    SPREAD[_v] = _s
SPOW = [1] * M
for _i in range(1, M):
    SPOW[_i] = SPOW[_i - 1] * FROBENIUS_S % ORDER_N
FACTOR = [(1 + pow(FROBENIUS_S, J_BASE + _t, ORDER_N)) % ORDER_N for _t in range(J_COUNT)]


def _nb_rows():
    """Rows of the inverse of the matrix whose columns are gamma^(2^i)."""
    cols, cur = [], NB_GENERATOR
    for _ in range(M):
        cols.append(cur)
        cur = _sqr(cur)
    left = [0] * M
    right = [0] * M
    for i in range(M):
        r = 0
        for j in range(M):
            if (cols[j] >> i) & 1:
                r |= 1 << j
        left[i], right[i] = r, 1 << i
    row = 0
    for col in range(M):
        pivot = -1
        for r in range(row, M):
            if (left[r] >> col) & 1:
                pivot = r
                break
        if pivot < 0:
            raise ValueError("NB_GENERATOR is not a normal element")
        left[row], left[pivot] = left[pivot], left[row]
        right[row], right[pivot] = right[pivot], right[row]
        for r in range(M):
            if r != row and ((left[r] >> col) & 1):
                left[r] ^= left[row]
                right[r] ^= right[row]
        row += 1
    out = [0] * M
    for r in range(M):
        out[(left[r] & -left[r]).bit_length() - 1] = right[r]
    return out


NB_ROWS = _nb_rows()


def _sum_pq():
    x1, y1 = GEN_X, GEN_Y
    x2, y2 = TARGET_X, TARGET_Y
    d = x1 ^ x2
    lam = _mul(y1 ^ y2, _inv(d))
    x3 = _mul(lam, lam) ^ lam ^ d ^ CURVE_A
    return (x3, _mul(lam, x1 ^ x3) ^ x3 ^ y1)


SUM_PQ = _sum_pq()
