#!/usr/bin/env python3
"""Walk one unit of a Koblitz-curve orbit rho job and emit distinguished points.

    python3 examples/certicom-ecdlp/tools/orbit_dp.py job-id   --job JOB
    python3 examples/certicom-ecdlp/tools/orbit_dp.py describe --job JOB
    python3 examples/certicom-ecdlp/tools/orbit_dp.py walk     --job JOB --unit U [--count N] [--out FILE]
    python3 examples/certicom-ecdlp/tools/orbit_dp.py verify   --job JOB ARTIFACT...
    python3 examples/certicom-ecdlp/tools/orbit_dp.py collide  --job JOB ARTIFACT ARTIFACT
    python3 examples/certicom-ecdlp/tools/orbit_dp.py audit    --job JOB --log LOG [--rate N] [--docket FILE]
    python3 examples/certicom-ecdlp/tools/orbit_dp.py mint     --m M --dp-weight W --name NAME [--secret K]
    python3 examples/certicom-ecdlp/tools/orbit_dp.py selftest

The contributor's side of a *version 2* search job: Pollard rho on a binary
Koblitz curve, walking the orbits of `<-1> x <sigma>` rather than points.
`rho_dp.py` is the version 1 tool, for prime-field r-adding jobs where a
point carries its own coefficients; this one exists because ECC2K-130 cannot
be run that way, and `docs/design/orbit-piecework.md` is why.

# The walk

Everything is pinned by the job document, whose SHA-256 over canonical
`tag=value` lines is the job id the checker carries:

- the field is `GF(2^m) = F_2[z]/(poly)`, the curve `y^2 + xy = x^3 + b`;
- weight and orbits are read in the **normal basis** `gamma^(2^i)` generated
  by the job's `nb_generator`. Frobenius is a cyclic rotation of those
  coordinates, so the Hamming weight `HW(x)` is invariant under `sigma`, and
  negation leaves `x` alone -- which is what makes the iteration
  well defined on orbits of size `2m`;
- one step is `R <- R + sigma^j(R)` with `j = j_base + ((HW(x_R) / 2) mod
  j_count)`, the ECC2K-130 iteration of Bailey et al.;
- a point is **distinguished** when `HW(x_R) <= max_weight`, tested before
  each step, so a start point that is already distinguished reports at step
  zero;
- walk `u` starts at `R_0 = Q + sum_i c_i sigma^i(P)` over the 128 bits of
  `splitmix64(seed)`, which is `[alpha_0]P + Q` for a scalar the walker can
  compute without touching the curve.

# The witness, and why a point alone is not enough

The client that actually runs this walk stores no coefficients: the state is
the point, and a corpus record is `(seed, canonical x)`. That record is not
checkable in less than the work that produced it, and a *canonical x* on its
own is free to invent -- pick any low-weight bit string and rotate it to its
least rotation. Paying for one would pay for nothing.

The step is linear: `R + sigma^j(R) = [1 + s^j]R`, where `s` is the
Frobenius eigenvalue on the order-`n` subgroup. Multiplication in the
endomorphism ring commutes, so the whole trail collapses to

    R_end = [mu] R_0,   mu = prod_j (1 + s^j)^(n_j)

and the exponents `n_j` are just how many steps took each of the `j_count`
branches -- eight counters, in any order. So a walker that carries eight
counters ships a record anyone verifies with one double scalar
multiplication: `mu * alpha_0 * P + mu * Q` must land on the claimed orbit.
That is the `j-counts` witness, and it is what an artifact carries.

What the witness does *not* prove is that the counters came from this walk's
own `j` rule rather than some other sequence of `sigma^j` additions. That
costs a re-walk, which is what `audit` samples.
"""
import argparse
import hashlib
import json
import os
import sys

# -- GF(2^m) -------------------------------------------------------------------


class Field:
    """`F_2[z] / (poly)`, elements as Python ints over the polynomial basis.

    Three speeds matter here and none of them is the obvious loop over the
    bits of the multiplier. Verification is a double scalar multiplication
    per point and a batch carries up to 64 of them, so a checker that spends
    20 microseconds a multiply spends half a minute on one claim. The comb
    below is four times faster for sixteen precomputed multiples, and
    squaring -- which a Frobenius-heavy curve does far more often than it
    multiplies -- is a table lookup per byte.
    """

    def __init__(self, m, poly):
        if poly >> m != 1:
            raise ValueError(f"reduction polynomial must have degree {m}")
        self.m = m
        self.poly = poly
        self.mask = (1 << m) - 1
        # poly = z^m + tail; folding the high part costs one shift per set bit
        # of the tail, so keep the tail's exponents rather than rediscovering
        # them on every reduction.
        self.taps = [i for i in range(m) if (poly >> i) & 1]
        self.spread = [0] * 256
        for v in range(256):
            s = 0
            for i in range(8):
                if (v >> i) & 1:
                    s |= 1 << (2 * i)
            self.spread[v] = s

    def reduce(self, a):
        while a > self.mask:
            hi = a >> self.m
            a &= self.mask
            for t in self.taps:
                a ^= hi << t
        return a

    def mul(self, a, b):
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
        return self.reduce(r)

    def sqr(self, a):
        r = 0
        shift = 0
        spread = self.spread
        while a:
            r |= spread[a & 255] << shift
            a >>= 8
            shift += 16
        return self.reduce(r)

    def frob(self, a, j=1):
        for _ in range(j % self.m):
            a = self.sqr(a)
        return a

    def inv(self, a):
        """Itoh-Tsujii: `a^(2^m - 2)`, which is `m - 1` squarings and about
        `log2(m)` multiplications rather than `m` of each."""
        if a == 0:
            raise ZeroDivisionError("no inverse of zero")
        n = self.m - 1
        x, k = a, 1
        for bit in bin(n)[3:]:
            x = self.mul(self.frob(x, k), x)
            k *= 2
            if bit == "1":
                x = self.mul(self.sqr(x), a)
                k += 1
        return self.sqr(x)

    def trace(self, a):
        t, acc = a, a
        for _ in range(self.m - 1):
            t = self.sqr(t)
            acc ^= t
        return acc & 1


def poly_mod(a, b):
    db = b.bit_length() - 1
    while a and a.bit_length() - 1 >= db:
        a ^= b << (a.bit_length() - 1 - db)
    return a


def poly_gcd(a, b):
    while b:
        a, b = b, poly_mod(a, b)
    return a


def is_irreducible(poly, m):
    """`x^(2^m) = x` and `gcd(x^(2^(m/q)) - x, f) = 1` for every prime `q | m`."""
    field = Field(m, poly)

    def iterate(a, k):
        for _ in range(k):
            a = field.sqr(a)
        return a

    if iterate(2, m) != 2:
        return False
    primes, n, q = set(), m, 2
    while q * q <= n:
        while n % q == 0:
            primes.add(q)
            n //= q
        q += 1
    if n > 1:
        primes.add(n)
    return all(poly_gcd(poly, iterate(2, m // q) ^ 2) == 1 for q in primes)


def is_prime(n):
    if n < 2:
        return False
    small = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for p in small:
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in small:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


# -- the normal basis the weight and the orbits are read in --------------------


class NormalBasis:
    """Coordinates against `gamma, gamma^2, gamma^4, ..., gamma^(2^(m-1))`.

    Two facts do all the work in this file. Squaring permutes the basis
    cyclically, so `sigma` is a rotation of the coordinate string and the
    Hamming weight is `sigma`-invariant; and negation on `y^2 + xy = x^3 + b`
    is `(x, y) -> (x, x + y)`, which does not touch `x` at all. So both the
    distinguished-point test and the orbit's name are functions of one
    rotation class of one bit string.
    """

    def __init__(self, field, gamma):
        self.field = field
        self.gamma = gamma
        m = field.m
        conj, cur = [], gamma
        for _ in range(m):
            conj.append(cur)
            cur = field.sqr(cur)
        self.conj = conj
        rows = _invert_gf2(conj, m)
        if rows is None:
            raise ValueError("nb_generator is not a normal element: its conjugates are dependent")
        self.rows = rows

    def to_nb(self, x):
        v = 0
        for i, row in enumerate(self.rows):
            if bin(x & row).count("1") & 1:
                v |= 1 << i
        return v

    def from_nb(self, c):
        x = 0
        for i in range(self.field.m):
            if (c >> i) & 1:
                x ^= self.conj[i]
        return x

    def weight(self, x):
        return bin(self.to_nb(x)).count("1")

    def canonical(self, x):
        return least_rotation(self.to_nb(x), self.field.m)


def least_rotation(c, m):
    """The smallest cyclic rotation of an `m`-bit string.

    Unique whenever the string is not rotation-symmetric. For prime `m` the
    only symmetric strings are all-zeros and all-ones, which are the field
    elements `0` and `1`; neither is the abscissa of a point of odd order, so
    on the subgroup this search picks exactly one representative.
    """
    mask = (1 << m) - 1
    best = c
    for _ in range(m - 1):
        c = ((c << 1) | (c >> (m - 1))) & mask
        if c < best:
            best = c
    return best


def _invert_gf2(cols, m):
    """Rows of the inverse of the `m x m` GF(2) matrix whose columns are `cols`."""
    left, right = [0] * m, [0] * m
    for i in range(m):
        r = 0
        for j in range(m):
            if (cols[j] >> i) & 1:
                r |= 1 << j
        left[i], right[i] = r, 1 << i
    row = 0
    for col in range(m):
        pivot = -1
        for r in range(row, m):
            if (left[r] >> col) & 1:
                pivot = r
                break
        if pivot < 0:
            return None
        left[row], left[pivot] = left[pivot], left[row]
        right[row], right[pivot] = right[pivot], right[row]
        for r in range(m):
            if r != row and ((left[r] >> col) & 1):
                left[r] ^= left[row]
                right[r] ^= right[row]
        row += 1
    out = [0] * m
    for r in range(m):
        col = (left[r] & -left[r]).bit_length() - 1
        out[col] = right[r]
    return out


def normal_generator(field):
    """A deterministic normal element, and how it was found.

    Prefers `zeta + zeta^-1` for `zeta` of order `2m + 1` -- the type-II
    optimal normal basis, which is the representation a bitsliced client
    computes the weight in natively, so pinning it costs a real implementation
    nothing. Falls back to the least normal element when that root does not
    live in this field (`ord_{2m+1}(2) = 2m` rather than `m`), which changes
    nothing about the protocol: any normal basis makes `sigma` a rotation.
    """
    m = field.m
    n = 2 * m + 1
    if is_prime(n) and ((1 << m) - 1) % n == 0:
        exponent = ((1 << m) - 1) // n
        base = 2
        while base < 1 << min(m, 20):
            zeta = _pow(field, base, exponent)
            if zeta != 1:
                gamma = zeta ^ _pow(field, zeta, n - 1)
                if _invert_gf2([field.frob(gamma, i) for i in range(m)], m) is not None:
                    return gamma, "type-II"
            base += 1
    for gamma in range(2, 1 << m):
        if _invert_gf2([field.frob(gamma, i) for i in range(m)], m) is not None:
            return gamma, "least-normal"
    raise ValueError(f"no normal element found for m={m}")


def _pow(field, a, e):
    r, base = 1, a
    while e:
        if e & 1:
            r = field.mul(r, base)
        base = field.mul(base, base)
        e >>= 1
    return r


# -- the curve -----------------------------------------------------------------


class Curve:
    """`y^2 + xy = x^3 + a x^2 + b` over `GF(2^m)`, affine, `None` for infinity."""

    def __init__(self, field, a, b):
        self.f = field
        self.a = a
        self.b = b

    def on_curve(self, P):
        if P is None:
            return True
        x, y = P
        f = self.f
        if not (0 <= x <= f.mask and 0 <= y <= f.mask):
            return False
        lhs = f.mul(y, y) ^ f.mul(x, y)
        rhs = f.mul(f.mul(x, x), x) ^ f.mul(self.a, f.mul(x, x)) ^ self.b
        return lhs == rhs

    def neg(self, P):
        return None if P is None else (P[0], P[0] ^ P[1])

    def dbl(self, P):
        if P is None or P[0] == 0:
            return None
        f = self.f
        x, y = P
        lam = x ^ f.mul(y, f.inv(x))
        x3 = f.mul(lam, lam) ^ lam ^ self.a
        return (x3, f.mul(x, x) ^ f.mul(lam ^ 1, x3))

    def add(self, P, Q):
        if P is None:
            return Q
        if Q is None:
            return P
        f = self.f
        x1, y1 = P
        x2, y2 = Q
        if x1 == x2:
            return self.dbl(P) if y1 == y2 else None
        d = x1 ^ x2
        lam = f.mul(y1 ^ y2, f.inv(d))
        x3 = f.mul(lam, lam) ^ lam ^ d ^ self.a
        return (x3, f.mul(lam, x1 ^ x3) ^ x3 ^ y1)

    def add_raw(self, P, Q):
        """The client's branch-free chord formula, degenerate cases included.

        The start point is built with 128 unconditional additions on a device
        that cannot represent infinity and does not branch. On a real curve
        two summands share an abscissa with probability about `2^-m` and this
        never fires; on a toy field it does, and the walk must agree with the
        client rather than with the group law. `start` reports it instead.
        """
        f = self.f
        x1, y1 = P
        x2, y2 = Q
        d = x1 ^ x2
        lam = f.mul(y1 ^ y2, f.inv(d))
        x3 = f.mul(lam, lam) ^ lam ^ d ^ self.a
        return (x3, f.mul(lam, x1 ^ x3) ^ x3 ^ y1)

    def mul(self, P, k):
        r, base = None, P
        while k > 0:
            if k & 1:
                r = self.add(r, base)
            base = self.dbl(base)
            k >>= 1
        return r

    def frob(self, P, j=1):
        return None if P is None else (self.f.frob(P[0], j), self.f.frob(P[1], j))

    def half_trace(self, c):
        f = self.f
        acc = t = c
        for _ in range((f.m - 1) // 2):
            t = f.sqr(f.sqr(t))
            acc ^= t
        return acc

    def point_from_x(self, x):
        """`(x, y)` on the curve, or `None` when `x` is not an abscissa."""
        if x == 0:
            return None
        f = self.f
        c = x ^ f.mul(self.a, 1) ^ f.mul(self.b, f.inv(f.mul(x, x)))
        if f.trace(c):
            return None
        return (x, f.mul(x, self.half_trace(c)))

    # ---- Lopez-Dahab projective: the verification path ----------------------
    #
    # Verifying one point is `[c]P + [d]Q` for 130-bit scalars. Affine costs an
    # inversion per group operation and an inversion is the most expensive
    # thing in the field; projective coordinates trade it for a handful of
    # multiplications and pay one inversion for the whole scalar
    # multiplication. On a 64-point batch that is the difference between
    # half a second and half a minute.

    def _ld_double(self, T):
        X1, Y1, Z1 = T
        if Z1 == 0 or X1 == 0:
            return (1, 0, 0)
        f = self.f
        X1sq = f.mul(X1, X1)
        Z1sq = f.mul(Z1, Z1)
        Z3 = f.mul(X1sq, Z1sq)
        bZ4 = f.mul(self.b, f.mul(Z1sq, Z1sq))
        X3 = f.mul(X1sq, X1sq) ^ bZ4
        t = f.mul(Y1, Y1) ^ bZ4 ^ f.mul(self.a, Z3)
        Y3 = f.mul(bZ4, Z3) ^ f.mul(X3, t)
        return (X3, Y3, Z3)

    def _ld_add_affine(self, T, P):
        if P is None:
            return T
        X1, Y1, Z1 = T
        if Z1 == 0:
            return (P[0], P[1], 1)
        f = self.f
        x2, y2 = P
        Z1sq = f.mul(Z1, Z1)
        A = f.mul(y2, Z1sq) ^ Y1
        B = f.mul(x2, Z1) ^ X1
        if B == 0:
            return self._ld_double(T) if A == 0 else (1, 0, 0)
        C = f.mul(Z1, B)
        D = f.mul(f.mul(B, B), C ^ f.mul(self.a, Z1sq))
        Z3 = f.mul(C, C)
        E = f.mul(A, C)
        X3 = f.mul(A, A) ^ D ^ E
        F = X3 ^ f.mul(x2, Z3)
        G = X3 ^ f.mul(y2, Z3)
        Y3 = f.mul(E, F) ^ f.mul(Z3, G)
        return (X3, Y3, Z3)

    def _ld_affine(self, T):
        X, Y, Z = T
        if Z == 0:
            return None
        f = self.f
        zi = f.inv(Z)
        return (f.mul(X, zi), f.mul(Y, f.mul(zi, zi)))

    def shamir(self, P, c, Q, d):
        """`[c]P + [d]Q` by interleaved double-and-add over a four-entry table."""
        table = (None, P, Q, self.add(P, Q))
        T = (1, 0, 0)
        for i in range(max(c.bit_length(), d.bit_length()) - 1, -1, -1):
            T = self._ld_double(T)
            idx = ((c >> i) & 1) | (((d >> i) & 1) << 1)
            if idx:
                T = self._ld_add_affine(T, table[idx])
        return self._ld_affine(T)


# -- the job document ----------------------------------------------------------

FAMILY = "koblitz-frobenius-rho"
WITNESS_KINDS = ("j-counts",)
JOB_TAGS = (
    "version", "name", "family", "m", "poly", "a", "b", "gx", "gy", "qx", "qy",
    "n", "cofactor", "s", "nb", "j_base", "j_count", "start_terms", "trail_bits",
    "dp_max_weight", "witness", "max_batch", "unit_size", "units", "max_steps", "seed",
)
MASK64 = (1 << 64) - 1


def parse_hex(s):
    t = s.strip()
    if t[:2].lower() == "0x":
        t = t[2:]
    if not t:
        raise ValueError("empty hex value")
    return int(t, 16)


def to_hex(v):
    """Lowercase, no prefix, no leading zeros -- one value, one spelling."""
    return format(v, "x")


def load_job(path):
    with open(path) as handle:
        return json.load(handle)


def job_id(job):
    """SHA-256 over canonical `tag=value` lines, values lowercased.

    The same discipline as the version 1 jobs: two peers holding
    byte-different files -- different key order, different whitespace -- must
    still agree on the id, because the id is what the checker pins and
    therefore what the objective's own id covers.
    """
    values = {
        "version": str(job["version"]),
        "name": job["name"],
        "family": job["family"],
        "m": str(job["m"]),
        "poly": job["poly"],
        "a": job["a"],
        "b": job["b"],
        "gx": job["generator"]["x"],
        "gy": job["generator"]["y"],
        "qx": job["target"]["x"],
        "qy": job["target"]["y"],
        "n": job["order"],
        "cofactor": str(job["cofactor"]),
        "s": job["frobenius_eigenvalue"],
        "nb": job["nb_generator"],
        "j_base": str(job["j_base"]),
        "j_count": str(job["j_count"]),
        "start_terms": str(job["start_terms"]),
        "trail_bits": str(job["trail_bits"]),
        "dp_max_weight": str(job["dp_max_weight"]),
        "witness": job["witness"],
        "max_batch": str(job["max_batch"]),
        "unit_size": str(job["unit_size"]),
        "units": str(job["units"]),
        "max_steps": str(job["max_steps_per_walker"]),
        "seed": str(job["seed"]),
    }
    body = b"".join(f"{tag}={values[tag].lower()}\n".encode() for tag in JOB_TAGS)
    return hashlib.sha256(body).hexdigest()


def splitmix64(seed, index):
    z = (seed + 0x9E3779B97F4A7C15 * (index + 1)) & MASK64
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK64
    return z ^ (z >> 31)


class Job:
    """A validated job document with everything the walk and the check need.

    Construction revalidates the instance rather than trusting the file: `P`
    and `Q` on the curve and of order `n`, `s` an actual eigenvalue of
    Frobenius on `<P>` and a root of `s^2 + s + 2`, and `nb_generator` an
    actual normal element. A job whose constants are wrong produces a walk
    nobody else runs and a witness nobody can check, and it would do it
    silently.
    """

    def __init__(self, job):
        if job.get("version") != 2:
            raise ValueError(f"job version {job.get('version')!r} is not 2")
        if job.get("family") != FAMILY:
            raise ValueError(f"job family {job.get('family')!r} is not {FAMILY!r}")
        if job.get("witness") not in WITNESS_KINDS:
            raise ValueError(f"witness {job.get('witness')!r} is not one of {WITNESS_KINDS}")
        self.job = job
        self.m = int(job["m"])
        self.field = Field(self.m, parse_hex(job["poly"]))
        self.curve = Curve(self.field, parse_hex(job["a"]), parse_hex(job["b"]))
        self.basis = NormalBasis(self.field, parse_hex(job["nb_generator"]))
        self.n = parse_hex(job["order"])
        self.cofactor = int(job["cofactor"])
        self.P = (parse_hex(job["generator"]["x"]), parse_hex(job["generator"]["y"]))
        self.Q = (parse_hex(job["target"]["x"]), parse_hex(job["target"]["y"]))
        self.s = parse_hex(job["frobenius_eigenvalue"])
        self.j_base = int(job["j_base"])
        self.j_count = int(job["j_count"])
        self.start_terms = int(job["start_terms"])
        self.trail_bits = int(job["trail_bits"])
        self.dp_max_weight = int(job["dp_max_weight"])
        self.max_batch = int(job["max_batch"])
        self.unit_size = int(job["unit_size"])
        self.units = int(job["units"])
        self.seed_tweak = int(job["seed"])
        cap = int(job["max_steps_per_walker"])
        self.step_cap = cap if cap else 32 << max(0, self.dp_expected_bits())
        if not self.curve.on_curve(self.P):
            raise ValueError("generator is not on the curve")
        if not self.curve.on_curve(self.Q):
            raise ValueError("target is not on the curve")
        if self.curve.mul(self.P, self.n) is not None:
            raise ValueError("n*P is not the identity: order is wrong")
        if self.curve.mul(self.Q, self.n) is not None:
            raise ValueError("n*Q is not the identity: target is outside <P>")
        if (self.s * self.s + self.s + 2) % self.n != 0:
            raise ValueError("frobenius_eigenvalue does not satisfy s^2 + s + 2 = 0 mod n")
        if self.curve.frob(self.P, 1) != self.curve.mul(self.P, self.s):
            raise ValueError("frobenius_eigenvalue does not act as sigma on <P>")
        if self.units < 1 or self.units > 1 << (64 - self.trail_bits):
            raise ValueError("units does not fit the seed layout")
        self.id = job_id(job)
        self.spow = [1] * self.m
        for i in range(1, self.m):
            self.spow[i] = self.spow[i - 1] * self.s % self.n
        # (1 + s^j) for each branch: the factor one step contributes to the
        # trail's multiplier, and the only reason a witness is eight numbers
        # rather than the whole step sequence.
        self.factor = [(1 + pow(self.s, self.j_base + t, self.n)) % self.n
                       for t in range(self.j_count)]

    def dp_expected_bits(self):
        """`log2` of the expected steps to a distinguished point, rounded down."""
        total, m = 0, self.m
        # Points of odd order on this curve have trace-zero abscissae, so the
        # weight is even and only even weights are reachable.
        for w in range(0, self.dp_max_weight + 1, 2):
            total += _binom(m, w)
        if total == 0:
            return 0
        return max(0, (1 << (m - 1)) // total).bit_length() - 1

    # ---- seeds and units ----------------------------------------------------

    def seed_of(self, unit, trail=0):
        if not 0 <= unit < self.units:
            raise ValueError(f"unit {unit} is outside [0, {self.units})")
        if not 0 <= trail < (1 << self.trail_bits):
            raise ValueError(f"trail {trail} does not fit {self.trail_bits} bits")
        return ((unit << self.trail_bits) | trail) & MASK64

    def unit_of(self, seed):
        return seed >> self.trail_bits

    # ---- the relation a witness reconstructs --------------------------------

    def alpha0(self, seed):
        """`R_0 = [alpha_0]P + Q`, read off the seed without touching the curve."""
        words = [splitmix64((seed ^ self.seed_tweak) & MASK64, i) for i in range((self.start_terms + 63) // 64)]
        alpha = 0
        for i in range(self.start_terms):
            if (words[i >> 6] >> (i & 63)) & 1:
                alpha = (alpha + self.spow[i % self.m]) % self.n
        return alpha

    def start(self, seed):
        """The start point, built the way a branch-free client builds it."""
        words = [splitmix64((seed ^ self.seed_tweak) & MASK64, i) for i in range((self.start_terms + 63) // 64)]
        R, degenerate = self.Q, False
        for i in range(self.start_terms):
            if (words[i >> 6] >> (i & 63)) & 1:
                S = self.curve.frob(self.P, i % self.m)
                if R[0] == S[0]:
                    degenerate = True
                R = self.curve.add_raw(R, S)
        return R, degenerate

    def multiplier(self, counts):
        mu = 1
        for t, count in enumerate(counts):
            if count:
                mu = mu * pow(self.factor[t], count, self.n) % self.n
        return mu

    def relation(self, seed, counts):
        """`(c, d)` with `[c]P + [d]Q` the trail's endpoint, from the witness."""
        mu = self.multiplier(counts)
        return mu * self.alpha0(seed) % self.n, mu

    # ---- the walk -----------------------------------------------------------

    def is_distinguished(self, x):
        return self.basis.weight(x) <= self.dp_max_weight

    def walk(self, seed):
        """Walk to a distinguished point.

        Returns `(canonical x, counts, steps)`, or `None` when the step cap is
        reached first. A capped trail earns nothing: the client reports it so
        it can reseed the lane, but a point that is not distinguished is not
        a unit, and paying for one would pay for an unfinished trail.
        """
        R, degenerate = self.start(seed)
        if degenerate:
            return None
        counts = [0] * self.j_count
        steps = 0
        while True:
            weight = self.basis.weight(R[0])
            if weight <= self.dp_max_weight:
                return least_rotation(self.basis.to_nb(R[0]), self.m), counts, steps
            if steps >= self.step_cap:
                return None
            branch = (weight >> 1) % self.j_count
            R = self.curve.add(R, self.curve.frob(R, self.j_base + branch))
            if R is None:
                return None
            counts[branch] += 1
            steps += 1

    def element(self, canonical_x, seed, counts):
        return {"x": to_hex(canonical_x), "seed": to_hex(seed), "j": list(counts)}


def _binom(n, k):
    r = 1
    for i in range(k):
        r = r * (n - i) // (i + 1)
    return r


# -- what the checker checks ---------------------------------------------------


def hex_field(element, key):
    value = element.get(key)
    if not isinstance(value, str) or not value:
        return None
    if any(c not in "0123456789abcdef" for c in value):
        return None
    if len(value) > 1 and value[0] == "0":
        return None
    return int(value, 16)


def verify_element(job, element):
    """One batch element against the job. `None` when it is good.

    The order is deliberate: everything decidable from `x` alone comes first,
    because those checks are bit operations and the last one is a double
    scalar multiplication. A malformed batch is refused before anyone pays
    for the arithmetic.
    """
    if not isinstance(element, dict):
        return "must be an object"
    if set(element) != {"x", "seed", "j"}:
        return "must carry exactly the keys x, seed, j"
    x = hex_field(element, "x")
    seed = hex_field(element, "seed")
    if x is None:
        return "x must be lowercase hex with no prefix and no leading zero"
    if seed is None:
        return "seed must be lowercase hex with no prefix and no leading zero"
    if x >> job.m:
        return f"x must be {job.m} normal-basis coordinates"
    if seed > MASK64:
        return "seed must fit 64 bits"
    weight = bin(x).count("1")
    if weight > job.dp_max_weight:
        return f"x is not distinguished: weight {weight} exceeds {job.dp_max_weight}"
    if x != least_rotation(x, job.m):
        return "x is not the canonical representative of its orbit: a rotation of it is smaller"
    counts = element["j"]
    if not isinstance(counts, list) or len(counts) != job.j_count:
        return f"j must be a list of {job.j_count} step counts"
    for count in counts:
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            return "every element of j must be a non-negative integer"
    steps = sum(counts)
    if steps > job.step_cap:
        return f"j sums to {steps} steps, past the cap of {job.step_cap}"
    c, d = job.relation(seed, counts)
    endpoint = job.curve.shamir(job.P, c, job.Q, d)
    if endpoint is None:
        return "the witness reaches the identity, which is on no orbit"
    if least_rotation(job.basis.to_nb(endpoint[0]), job.m) != x:
        return "the witness does not reach this orbit"
    return None


def verify_batch(job, artifact):
    if not isinstance(artifact, dict):
        return False, "artifact must be an object"
    if set(artifact) != {"dps"}:
        return False, "artifact must carry exactly the key dps"
    dps = artifact["dps"]
    if not isinstance(dps, list):
        return False, "dps must be a list"
    if not 1 <= len(dps) <= job.max_batch:
        return False, f"dps must carry between 1 and {job.max_batch} points; got {len(dps)}"
    seen = set()
    for index, element in enumerate(dps):
        why = verify_element(job, element)
        if why is not None:
            return False, f"dps[{index}]: {why}"
        if element["x"] in seen:
            return False, f"dps[{index}] repeats an orbit already in the batch"
        seen.add(element["x"])
    return True, f"verified: {len(dps)} distinguished orbits of the {job.job['name']} walk"


def solve_collision(job, left, right):
    """`k` with `[k]P = Q` from two witnesses for one orbit, or `None`.

    Two trails that reach the same orbit reach endpoints that differ by a
    Frobenius power and possibly a sign -- that is what the orbit *is* -- so
    `S_A = [eps s^e] S_B` for some `e`, and the two relations become one
    linear equation in `k`.
    """
    cA, dA = job.relation(hex_field(left, "seed"), left["j"])
    cB, dB = job.relation(hex_field(right, "seed"), right["j"])
    SA = job.curve.shamir(job.P, cA, job.Q, dA)
    SB = job.curve.shamir(job.P, cB, job.Q, dB)
    if SA is None or SB is None:
        return None
    for e in range(job.m):
        T = job.curve.frob(SB, e)
        for sign in (1, -1):
            U = T if sign == 1 else job.curve.neg(T)
            if U != SA:
                continue
            w = job.spow[e] if sign == 1 else (-job.spow[e]) % job.n
            num = (cA - w * cB) % job.n
            den = (w * dB - dA) % job.n
            if den == 0:
                return None
            return num * pow(den, -1, job.n) % job.n
    return None


def audit_element(job, element, max_steps=None):
    """Re-walk one element from its seed. `None` when it is where the walk leads.

    This is the half of verification the witness cannot do. The witness proves
    the endpoint is `[mu]R_0` for the `mu` the counters name; it does not prove
    those counters are the ones this walk's own `j` rule produces. A private
    iteration rule yields witnesses that check out and trails that merge with
    nobody, so the search would be paying for points that can never collide.
    Catching that costs the trail again, which is why an auditor samples.
    """
    seed = hex_field(element, "seed")
    if seed is None:
        return "seed is not canonical hex"
    if max_steps is not None and sum(element["j"]) > max_steps:
        return None
    walked = job.walk(seed)
    if walked is None:
        return "the seed is a dead trail: it reaches no distinguished point"
    canonical_x, counts, _steps = walked
    if to_hex(canonical_x) != element["x"]:
        return "the seed leads to a different orbit: not a trail of the shared walk"
    if list(counts) != list(element["j"]):
        return f"the trail takes {counts} branch steps, not {element['j']}"
    return None


# -- minting a job -------------------------------------------------------------


def curve_order_koblitz(m, a):
    """`#E(GF(2^m))` for `y^2 + xy = x^3 + a x^2 + 1` by the Frobenius recursion."""
    mu = 1 if a else -1
    v0, v1 = 2, mu
    for _ in range(m - 1):
        v0, v1 = v1, mu * v1 - 2 * v0
    return (1 << m) + 1 - v1


def lowest_weight_irreducible(m):
    for k in range(1, m):
        poly = (1 << m) | (1 << k) | 1
        if is_irreducible(poly, m):
            return poly
    for k3 in range(3, m):
        for k2 in range(2, k3):
            for k1 in range(1, k2):
                poly = (1 << m) | (1 << k3) | (1 << k2) | (1 << k1) | 1
                if is_irreducible(poly, m):
                    return poly
    raise ValueError(f"no irreducible polynomial of degree {m} found")


def sqrt_mod(a, p):
    a %= p
    if a == 0:
        return 0
    if pow(a, (p - 1) // 2, p) != 1:
        return None
    q, s = p - 1, 0
    while q % 2 == 0:
        q //= 2
        s += 1
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1
    mm, c, t, r = s, pow(z, q, p), pow(a, q, p), pow(a, (q + 1) // 2, p)
    while t != 1:
        i, tt = 0, t
        while tt != 1:
            tt = tt * tt % p
            i += 1
        b = pow(c, 1 << (mm - i - 1), p)
        mm, c, t, r = i, b * b % p, t * b * b % p, r * b % p
    return r


def frobenius_eigenvalue(curve, P, n):
    """`s` with `sigma(R) = [s]R` on `<P>`: a root of `s^2 + s + 2` mod `n`."""
    root = sqrt_mod(-7 % n, n)
    if root is None:
        raise ValueError("-7 is not a square mod n: this is not a Koblitz subgroup")
    half = pow(2, -1, n)
    for candidate in (((-1 + root) * half) % n, ((-1 - root) * half) % n):
        if curve.mul(P, candidate) == curve.frob(P, 1):
            return candidate
    raise ValueError("neither root of s^2 + s + 2 acts as Frobenius")


def mint(m, dp_weight, name, secret=None, max_batch=64, unit_bits=16, trail_bits=16):
    """A complete, self-verifying job document for a toy instance.

    Every constant is derived, none chosen: the lowest-weight irreducible
    polynomial, the first abscissa that yields a point of order `n`, and a
    secret from the name when none is given. A toy job exists to exercise the
    protocol end to end, and one whose parameters came from a random draw
    nobody recorded cannot be regenerated to check that it did.
    """
    poly = lowest_weight_irreducible(m)
    field = Field(m, poly)
    order = curve_order_koblitz(m, 0)
    if order % 4:
        raise ValueError(f"#E(GF(2^{m})) is not divisible by the cofactor 4")
    n = order // 4
    if not is_prime(n):
        raise ValueError(f"#E(GF(2^{m}))/4 is not prime; pick another m")
    curve = Curve(field, 0, 1)
    P = None
    for x in range(1, 1 << m):
        candidate = curve.point_from_x(x)
        if candidate is None:
            continue
        candidate = curve.mul(candidate, 4)
        if candidate is None or curve.mul(candidate, n) is not None:
            continue
        P = candidate
        break
    if P is None:
        raise ValueError("no generator found")
    if secret is None:
        digest = hashlib.sha256(("cairn orbit job|" + name).encode()).digest()
        secret = int.from_bytes(digest, "big") % (n - 1) + 1
    Q = curve.mul(P, secret)
    gamma, _how = normal_generator(field)
    s = frobenius_eigenvalue(curve, P, n)
    job = {
        "version": 2,
        "name": name,
        "family": FAMILY,
        "m": m,
        "poly": to_hex(poly),
        "a": "0",
        "b": "1",
        "generator": {"x": to_hex(P[0]), "y": to_hex(P[1])},
        "target": {"x": to_hex(Q[0]), "y": to_hex(Q[1])},
        "order": to_hex(n),
        "cofactor": 4,
        "frobenius_eigenvalue": to_hex(s),
        "nb_generator": to_hex(gamma),
        "j_base": 3,
        "j_count": 8,
        "start_terms": 128,
        "trail_bits": trail_bits,
        "dp_max_weight": dp_weight,
        "witness": "j-counts",
        "max_batch": max_batch,
        "unit_size": 256,
        "units": 1 << unit_bits,
        "max_steps_per_walker": 0,
        "seed": 0,
    }
    return job, secret


# -- the published schema, enforced --------------------------------------------

SCHEMA_ANNOTATIONS = ("$schema", "$id", "title", "description", "$comment", "default", "examples")
SCHEMA_KEYWORDS = ("type", "const", "enum", "required", "properties", "additionalProperties",
                   "minLength", "minimum", "maximum", "pattern", "oneOf", "$ref", "$defs")


def validate_schema(schema, value, root=None, spath="#", path="$"):
    """`spec/search-job.schema.json` against a job document.

    A subset validator, and an unrecognised keyword is an error rather than a
    no-op -- the same discipline as `src/schema.rs`, for the same reason.
    Silently ignoring a keyword somebody adds to the schema turns a tightened
    contract into an unenforced comment, and this schema's whole job is to be
    the thing two implementations of one walk agree against.
    """
    import re

    if root is None:
        root = schema
    for key in schema:
        if key not in SCHEMA_ANNOTATIONS and key not in SCHEMA_KEYWORDS:
            raise ValueError(f"{spath}: keyword {key!r} is not implemented by this validator")
    if "$ref" in schema:
        ref = schema["$ref"]
        if not ref.startswith("#/"):
            raise ValueError(f"{spath}: only local $ref is supported, got {ref!r}")
        target = root
        for part in ref[2:].split("/"):
            target = target[part]
        return validate_schema(target, value, root, ref, path)
    if "oneOf" in schema:
        reasons = []
        for index, branch in enumerate(schema["oneOf"]):
            try:
                validate_schema(branch, value, root, f"{spath}/oneOf/{index}", path)
                break
            except ValueError as exc:
                reasons.append(str(exc))
        else:
            raise ValueError(f"{path}: matches no branch of oneOf ({'; '.join(reasons)})")
    if "const" in schema and value != schema["const"]:
        raise ValueError(f"{path}: must equal {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        raise ValueError(f"{path}: must be one of {schema['enum']!r}")
    kinds = schema.get("type")
    if kinds is not None:
        kinds = [kinds] if isinstance(kinds, str) else kinds
        if not any(_json_type_ok(kind, value) for kind in kinds):
            raise ValueError(f"{path}: must be {'/'.join(kinds)}")
    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            raise ValueError(f"{path}: shorter than {schema['minLength']}")
        if "pattern" in schema and not re.search(schema["pattern"], value):
            raise ValueError(f"{path}: does not match {schema['pattern']}")
    if isinstance(value, int) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            raise ValueError(f"{path}: below minimum {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            raise ValueError(f"{path}: above maximum {schema['maximum']}")
    if isinstance(value, dict):
        for name in schema.get("required", []):
            if name not in value:
                raise ValueError(f"{path}: missing required property {name!r}")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            for name in value:
                if name not in properties:
                    raise ValueError(f"{path}: unexpected property {name!r}")
        for name, sub in properties.items():
            if name in value:
                validate_schema(sub, value[name], root, f"{spath}/properties/{name}", f"{path}.{name}")


def _json_type_ok(kind, value):
    if kind == "object":
        return isinstance(value, dict)
    if kind == "array":
        return isinstance(value, list)
    if kind == "string":
        return isinstance(value, str)
    if kind == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if kind == "boolean":
        return isinstance(value, bool)
    if kind == "null":
        return value is None
    raise ValueError(f"unsupported type {kind!r}")


def schema_path():
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.normpath(os.path.join(here, "..", "..", "..", "spec", "search-job.schema.json"))


# -- CLI -----------------------------------------------------------------------


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value):
    return "sha256:" + hashlib.sha256(_canonical(value).encode()).hexdigest()


def _read_log(source):
    if source.startswith("http://") or source.startswith("https://"):
        import urllib.request

        with urllib.request.urlopen(source, timeout=60) as response:
            return response.read().decode()
    with open(source) as handle:
        return handle.read()


def _load(args):
    return Job(load_job(args.job))


def cmd_job_id(args):
    print(_load(args).id)
    return 0


def cmd_describe(args):
    job = _load(args)
    expected = job.dp_expected_bits()
    print(f"job          {job.id}")
    print(f"name         {job.job['name']}")
    print(f"field        GF(2^{job.m}), poly 0x{job.job['poly']}")
    print(f"curve        y^2 + xy = x^3 + {job.job['b']}   #E = {job.cofactor} * n")
    print(f"n            {job.n}  ({job.n.bit_length()} bits)")
    print(f"orbit        <-1> x <sigma>, size {2 * job.m}")
    print(f"distinguished  HW_nb(x) <= {job.dp_max_weight}, about 2^{expected} steps per point")
    print(f"witness      {job.job['witness']}, {job.j_count} counters, cap {job.step_cap} steps")
    print(f"units        {job.units} seed slots of {1 << job.trail_bits} trails, batches of up to {job.max_batch}")
    return 0


def cmd_walk(args):
    job = _load(args)
    out, trail, unit = [], 0, args.unit
    while len(out) < args.count:
        if trail >= 1 << job.trail_bits:
            break
        walked = job.walk(job.seed_of(unit, trail))
        if walked is not None:
            canonical_x, counts, steps = walked
            out.append(job.element(canonical_x, job.seed_of(unit, trail), counts))
            print(f"unit {unit} trail {trail}: {steps} steps -> orbit {to_hex(canonical_x)}", file=sys.stderr)
        trail += 1
    if not out:
        print("no distinguished point: every trail hit the step cap", file=sys.stderr)
        return 1
    artifact = {"dps": out}
    text = json.dumps(artifact, indent=2, sort_keys=True) + "\n"
    if args.out:
        with open(args.out, "w") as handle:
            handle.write(text)
        print(f"wrote {args.out} ({len(out)} point(s))", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


def cmd_verify(args):
    job = _load(args)
    bad = 0
    for path in args.artifacts:
        with open(path) as handle:
            artifact = json.load(handle)
        ok, why = verify_batch(job, artifact)
        print(f"{'ok  ' if ok else 'FAIL'} {path}: {why}")
        bad += 0 if ok else 1
    return 1 if bad else 0


def cmd_collide(args):
    job = _load(args)
    batches = []
    for path in args.artifacts:
        with open(path) as handle:
            artifact = json.load(handle)
        ok, why = verify_batch(job, artifact)
        if not ok:
            print(f"{path}: {why}", file=sys.stderr)
            return 1
        batches.append(artifact["dps"])
    by_orbit = {}
    for dps in batches:
        for element in dps:
            for other in by_orbit.get(element["x"], []):
                if other["seed"] == element["seed"]:
                    # The same trail submitted twice is not a collision: it is
                    # one relation, and the equation it gives is 0 = 0.
                    continue
                k = solve_collision(job, other, element)
                if k is None:
                    continue
                if job.curve.mul(job.P, k) != job.Q:
                    print("collision did not solve: is n the order of P?", file=sys.stderr)
                    return 1
                print(json.dumps({"k": to_hex(k)}, indent=2))
                return 0
            by_orbit.setdefault(element["x"], []).append(element)
    print("no collision: no orbit is reached by two different trails", file=sys.stderr)
    return 1


def cmd_audit(args):
    job = _load(args)
    lines = _read_log(args.log).splitlines()
    claims, paid = {}, set()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        payload = entry.get("payload") or {}
        if entry.get("kind") == "claim":
            if args.objective and payload.get("objective_id") != args.objective:
                continue
            artifact = payload.get("artifact")
            if isinstance(artifact, dict) and isinstance(artifact.get("dps"), list) and artifact["dps"]:
                record = dict(payload)
                record["type"] = "claim"
                claims[_digest(record)] = payload
        elif entry.get("kind") == "settlement":
            paid.add(payload.get("claim_id"))
    rate = max(1, args.rate)
    sampled = checked = skipped = 0
    mismatches = []
    for claim_id, payload in claims.items():
        if claim_id not in paid:
            continue
        pick = hashlib.sha256((args.seed + "|" + claim_id).encode()).digest()
        if int.from_bytes(pick[:8], "big") % rate != 0:
            continue
        sampled += 1
        dps = payload["artifact"]["dps"]
        if args.elements == "all":
            indices = list(range(len(dps)))
        else:
            indices = [int.from_bytes(pick[8:16], "big") % len(dps)]
        submitter = payload.get("submitter", "?")
        for index in indices:
            element = dps[index]
            why = verify_element(job, element)
            if why is not None:
                print(f"FAIL  {claim_id[:23]}… {submitter}: dps[{index}]: {why}")
                mismatches.append({
                    "artifact": _digest(payload["artifact"]),
                    "expect": "reject",
                    "detail": f"claim {claim_id}: dps[{index}]: {why}",
                })
                continue
            steps = sum(element["j"])
            if args.max_steps and steps > args.max_steps:
                skipped += 1
                print(f"skip  {claim_id[:23]}… {submitter}: dps[{index}]: witness ok, "
                      f"{steps} steps is past --max-steps {args.max_steps}; not re-walked")
                continue
            checked += 1
            why = audit_element(job, element)
            if why is None:
                print(f"ok    {claim_id[:23]}… {submitter}: dps[{index}] re-walked, {steps} steps")
            else:
                print(f"FAIL  {claim_id[:23]}… {submitter}: dps[{index}]: {why}")
                mismatches.append({
                    "artifact": _digest(payload["artifact"]),
                    "expect": "reject",
                    "detail": f"claim {claim_id}: dps[{index}]: {why}",
                })
    print(f"{len(claims)} batch claim(s), {len([c for c in claims if c in paid])} paid, "
          f"{sampled} sampled at 1/{rate}, {checked} re-walked, {skipped} too long to re-walk here, "
          f"{len(mismatches)} mismatch(es)")
    if args.docket:
        with open(args.docket, "w") as handle:
            json.dump({"entries": mismatches}, handle, indent=2)
            handle.write("\n")
        print(f"docket written to {args.docket} ({len(mismatches)} entries)")
    return 1 if mismatches else 0


def cmd_mint(args):
    job, secret = mint(args.m, args.dp_weight, args.name, args.secret,
                       max_batch=args.max_batch, unit_bits=args.unit_bits)
    context = Job(job)
    text = json.dumps(job, indent=2, sort_keys=True) + "\n"
    if args.out:
        with open(args.out, "w") as handle:
            handle.write(text)
        print(f"wrote {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    print(f"job id {context.id}", file=sys.stderr)
    if args.answer:
        with open(args.answer, "w") as handle:
            json.dump({"job": context.id, "k": to_hex(secret)}, handle, indent=2)
            handle.write("\n")
        print(f"answer written to {args.answer}", file=sys.stderr)
    return 0


def cmd_validate(args):
    """Every shipped job document against the published schema."""
    with open(schema_path()) as handle:
        schema = json.load(handle)
    here = os.path.dirname(os.path.abspath(__file__))
    paths = args.jobs or sorted(
        os.path.join(here, "..", "jobs", name)
        for name in os.listdir(os.path.join(here, "..", "jobs"))
        if name.endswith(".json")
    )
    bad = 0
    for path in paths:
        with open(path) as handle:
            document = json.load(handle)
        try:
            validate_schema(schema, document)
            print(f"ok   {os.path.relpath(path)}: version {document.get('version')}")
        except ValueError as exc:
            print(f"FAIL {os.path.relpath(path)}: {exc}")
            bad += 1
    return 1 if bad else 0


def cmd_selftest(args):
    """Everything the protocol claims, on an instance small enough to finish.

    Each assertion below is a rule the design note states and the checker
    relies on. A selftest that only walked and verified would pass for a
    protocol whose orbit key was wrong, whose weight was not Frobenius
    invariant, or whose forgeries were free.
    """
    failures = []

    def check(label, ok, detail=""):
        print(f"{'ok  ' if ok else 'FAIL'} {label}{': ' + detail if detail and not ok else ''}")
        if not ok:
            failures.append(label)

    here = os.path.dirname(os.path.abspath(__file__))
    with open(schema_path()) as handle:
        schema = json.load(handle)
    jobs_dir = os.path.join(here, "..", "jobs")
    for name in sorted(os.listdir(jobs_dir)):
        if not name.endswith(".json"):
            continue
        with open(os.path.join(jobs_dir, name)) as handle:
            document = json.load(handle)
        try:
            validate_schema(schema, document)
            check(f"{name} satisfies spec/search-job.schema.json (version {document['version']})", True)
        except ValueError as exc:
            check(f"{name} satisfies spec/search-job.schema.json", False, str(exc))
    for path, sample_size in ((os.path.join(here, "..", "jobs", "ecc2k-23.json"), 200),
                              (os.path.join(here, "..", "jobs", "ecc2k130.json"), 12)):
        name = os.path.basename(path)
        try:
            job = Job(load_job(path))
        except Exception as exc:  # noqa: BLE001 -- the point is to report it
            check(f"{name} validates", False, str(exc))
            continue
        check(f"{name} validates (P, Q of order n; s^2+s+2=0; sigma(P)=[s]P; nb normal)", True)
        check(f"{name} job id matches the file", job.id == job_id(job.job))
        # Sampled across the subgroup, not read off P. Each of these is a
        # premise the payment rule rests on, and a premise that happens to
        # hold at one point is not a premise.
        sample = [job.P]
        scalar = 1
        for _ in range(sample_size - 1):
            scalar = scalar * 6364136223846793005 % job.n or 1
            sample.append(job.curve.mul(job.P, scalar))
        invariant = all(len({job.basis.weight(job.field.frob(R[0], j)) for j in range(job.m)}) == 1
                        for R in sample)
        check(f"{name} weight is invariant under sigma ({len(sample)} points)", invariant)
        check(f"{name} weight is invariant under negation",
              all(job.basis.weight(job.curve.neg(R)[0]) == job.basis.weight(R[0]) for R in sample))
        check(f"{name} abscissae of <P> have trace zero, so the weight is even",
              all(job.field.trace(R[0]) == 0 and job.basis.weight(R[0]) % 2 == 0 for R in sample))
        check(f"{name} the sigma-orbit of an abscissa has full size m",
              all(len({job.field.frob(R[0], j) for j in range(job.m)}) == job.m for R in sample))
        check(f"{name} every orbit member canonicalises to one representative",
              all(len({least_rotation(job.basis.to_nb(job.field.frob(R[0], j)), job.m)
                       for j in range(job.m)}) == 1 for R in sample))
        check(f"{name} the all-ones normal-basis string is the field element 1, "
              f"so only 0 and 1 are rotation-symmetric",
              job.basis.from_nb((1 << job.m) - 1) == 1)
        # The projective verification path must agree with the affine group law.
        c, d = 12345 % job.n, 67890 % job.n
        affine = job.curve.add(job.curve.mul(job.P, c), job.curve.mul(job.Q, d))
        check(f"{name} projective [c]P+[d]Q agrees with affine", job.curve.shamir(job.P, c, job.Q, d) == affine)

    job = Job(load_job(os.path.join(here, "..", "jobs", "ecc2k-23.json")))
    answer = json.load(open(os.path.join(here, "..", "instances", "ecc2k-23.json")))
    k = parse_hex(answer["k"])
    check("toy answer is the discrete logarithm", job.curve.mul(job.P, k) == job.Q)

    # Walk until two trails meet, verifying every point on the way.
    table, solved, walked = {}, None, 0
    for unit in range(job.units):
        result = job.walk(job.seed_of(unit))
        if result is None:
            continue
        walked += 1
        canonical_x, counts, _steps = result
        element = job.element(canonical_x, job.seed_of(unit), counts)
        why = verify_element(job, element)
        if why is not None:
            check(f"witness verifies for unit {unit}", False, why)
            break
        if element["x"] in table and table[element["x"]]["seed"] != element["seed"]:
            solved = solve_collision(job, table[element["x"]], element)
            if solved is not None:
                break
        table.setdefault(element["x"], element)
    check(f"every witness verified ({walked} trails, {len(table)} distinct orbits)", walked > 0)
    check("a collision recovers the discrete logarithm", solved == k,
          f"got {solved}, wanted {k}")

    # A batch round-trips through exactly what the checker accepts.
    batch = {"dps": list(table.values())[:job.max_batch]}
    ok, why = verify_batch(job, batch)
    check(f"a batch of {len(batch['dps'])} verifies", ok, why)
    dup = {"dps": [batch["dps"][0], dict(batch["dps"][0])]}
    ok, _ = verify_batch(job, dup)
    check("a batch that lists one orbit twice is refused", not ok)

    # Forgery: the cheapest thing an attacker can make without doing the work
    # is a low-weight canonical bit string. The witness is what refuses it.
    victim = dict(batch["dps"][0])
    fake = least_rotation((1 << job.dp_max_weight) - 1, job.m)
    victim["x"] = to_hex(fake)
    check("an invented orbit with a real witness is refused", verify_element(job, victim) is not None)
    victim = dict(batch["dps"][0])
    victim["j"] = [c + 1 for c in victim["j"]]
    check("a witness with altered counters is refused", verify_element(job, victim) is not None)
    victim = dict(batch["dps"][0])
    victim["seed"] = to_hex(parse_hex(victim["seed"]) ^ 1)
    check("a witness re-labelled with another seed is refused", verify_element(job, victim) is not None)
    rotated = dict(batch["dps"][0])
    x = parse_hex(rotated["x"])
    rot = ((x << 1) | (x >> (job.m - 1))) & ((1 << job.m) - 1)
    if rot != x:
        rotated["x"] = to_hex(rot)
        check("a non-canonical rotation of a real orbit is refused",
              verify_element(job, rotated) is not None)

    # An honest walk that used a different j rule: the witness still checks out.
    # This is the gap the audit exists for, and the selftest pins it so nobody
    # reads the witness as proving more than it does.
    seed = job.seed_of(0)
    R, degenerate = job.start(seed)
    private = None
    if not degenerate:
        counts = [0] * job.j_count
        for _ in range(job.step_cap):
            if job.basis.weight(R[0]) <= job.dp_max_weight:
                private = job.element(least_rotation(job.basis.to_nb(R[0]), job.m), seed, counts)
                break
            R = job.curve.add(R, job.curve.frob(R, job.j_base))
            if R is None:
                break
            counts[0] += 1
    if private is not None:
        check("a private iteration rule still passes the witness (the audit's job)",
              verify_element(job, private) is None)
        check("and the audit catches it", audit_element(job, private) is not None)

    print()
    print(f"{len(failures)} failure(s)")
    return 1 if failures else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)

    def with_job(p):
        p.add_argument("--job", required=True, help="path to the job document")
        return p

    with_job(sub.add_parser("job-id")).set_defaults(fn=cmd_job_id)
    with_job(sub.add_parser("describe")).set_defaults(fn=cmd_describe)

    p = with_job(sub.add_parser("walk"))
    p.add_argument("--unit", type=int, required=True, help="unit index from work_assignment")
    p.add_argument("--count", type=int, default=1, help="points to collect before stopping")
    p.add_argument("--out", help="write the batch artifact here instead of stdout")
    p.set_defaults(fn=cmd_walk)

    p = with_job(sub.add_parser("verify"))
    p.add_argument("artifacts", nargs="+")
    p.set_defaults(fn=cmd_verify)

    p = with_job(sub.add_parser("collide"))
    p.add_argument("artifacts", nargs="+")
    p.set_defaults(fn=cmd_collide)

    p = with_job(sub.add_parser("audit"))
    p.add_argument("--log", required=True, help="a cairn log file, or a node's GET /log URL")
    p.add_argument("--objective", help="restrict to one objective id")
    p.add_argument("--rate", type=int, default=16, help="sample one paid claim in N")
    p.add_argument("--elements", choices=("one", "all"), default="one")
    p.add_argument("--max-steps", type=int, default=0,
                   help="skip the re-walk past this many steps (0: no bound)")
    p.add_argument("--seed", default="cairn-audit", help="sampling domain separator")
    p.add_argument("--docket", help="write mismatches where `cairn attest slash --docket` reads them")
    p.set_defaults(fn=cmd_audit)

    p = sub.add_parser("mint")
    p.add_argument("--m", type=int, required=True)
    p.add_argument("--dp-weight", type=int, required=True)
    p.add_argument("--name", required=True)
    p.add_argument("--secret", type=int, default=None)
    p.add_argument("--max-batch", type=int, default=64)
    p.add_argument("--unit-bits", type=int, default=16)
    p.add_argument("--out")
    p.add_argument("--answer", help="write the instance's known k here")
    p.set_defaults(fn=cmd_mint)

    p = sub.add_parser("validate")
    p.add_argument("jobs", nargs="*", help="job documents; default: every file in jobs/")
    p.set_defaults(fn=cmd_validate)

    sub.add_parser("selftest").set_defaults(fn=cmd_selftest)

    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
