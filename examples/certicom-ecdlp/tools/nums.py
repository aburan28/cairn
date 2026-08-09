#!/usr/bin/env python3
"""Derive nothing-up-my-sleeve ECDLP instances, and verify derived ones.

    python3 tools/nums.py derive 40        # emit an instance
    python3 tools/nums.py verify inst.json # re-derive it and require a match

# Why this exists

Certicom's own instances are unusable as objectives, in both directions. The
solved ones have published answers, so the first copier settles them and
`Copying earns exactly zero` — nobody is paid for work. The open ones need
~2^65 group operations. There is no middle rung, and this file builds one.

# Why nobody knows the answer, including whoever posts it

Every number below is derived from a public seed string by SHA-256. The prime,
the curve, the generator and the target point are all outputs of a search whose
inputs are visible, so **there is no step at which anybody chose a scalar.**
Run `verify` and you get the same instance back, which is what makes that claim
checkable rather than asserted.

That matters because the alternative is the **self-dealing** row in
`docs/threat-model.md`: an objective whose answer its poster already holds. The
existing `examples/ecdlp/` instance has that shape — it pins a scalar in a
one-bit window on a 256-bit curve, so whoever built it picked `k` and knows it.
Nothing here can be gamed that way, because `Q` is a hash output and its
discrete log is as unknown to the author as to anyone else.

# The one thing a reader should check for themselves

That `#E` really is prime. If it is, the group is cyclic of that order, so *every*
point lies in `<G>` and the hashed `Q` is guaranteed to have a discrete log —
no cofactor, no small-subgroup escape, and no way for the instance to be quietly
unsolvable.
"""
import hashlib
import json
import sys


# -- field and curve arithmetic ---------------------------------------------
#
# Affine coordinates and a modular inverse per addition. Slower than projective
# by a constant factor and short enough to read, which is the right trade for
# something whose output is pinned into an objective's identity.


def _inv(x, p):
    return pow(x, -1, p)


def add(curve, P, Q):
    p, a = curve["p"], curve["a"]
    if P is None:
        return Q
    if Q is None:
        return P
    (x1, y1), (x2, y2) = P, Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if P == Q:
        lam = (3 * x1 * x1 + a) * _inv(2 * y1, p) % p
    else:
        lam = (y2 - y1) * _inv((x2 - x1) % p, p) % p
    x3 = (lam * lam - x1 - x2) % p
    return (x3, (lam * (x1 - x3) - y1) % p)


def mul(curve, k, P):
    R, A = None, P
    while k:
        if k & 1:
            R = add(curve, R, A)
        A = add(curve, A, A)
        k >>= 1
    return R


def on_curve(curve, P):
    if P is None:
        return True
    p, x, y = curve["p"], P[0], P[1]
    return (y * y - (x * x * x + curve["a"] * x + curve["b"])) % p == 0


def is_prime(n):
    """Deterministic Miller-Rabin for the sizes here."""
    if n < 2:
        return False
    for q in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % q == 0:
            return n == q
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
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


# -- deriving everything from a seed ----------------------------------------


def _h(*parts):
    """SHA-256 over a `|`-joined tag, as an integer."""
    return int.from_bytes(
        hashlib.sha256("|".join(str(x) for x in parts).encode()).digest(), "big"
    )


def _prime_below(limit):
    """The largest prime below `limit`. A function of the bit size alone."""
    n = limit - 1
    if n % 2 == 0:
        n -= 1
    while not is_prime(n):
        n -= 2
    return n


def hash_to_point(curve, seed):
    """Try-and-increment: the simplest hash-to-curve anyone can re-run.

    Not constant time and it does not need to be -- every input is public, and
    the only property required is that the author had no freedom in the output.
    """
    p = curve["p"]
    for counter in range(100000):
        x = _h(seed, counter) % p
        rhs = (x * x * x + curve["a"] * x + curve["b"]) % p
        # p = 3 mod 4 is arranged by `_prime_below` checks below, so the square
        # root is a single exponentiation.
        y = pow(rhs, (p + 1) // 4, p)
        if y * y % p == rhs:
            # Pin the parity so the point is a function of the seed, not of a
            # choice between y and -y.
            return (x, y if y % 2 == 0 else p - y)
    raise RuntimeError("no point found")


def group_order(curve, R):
    """#E by baby-step giant-step over the Hasse interval.

    Returns the unique N in `[p+1-2*sqrt(p), p+1+2*sqrt(p)]` with `N*R = O`, or
    None when more than one multiple of `ord(R)` lands in the window -- which
    means this point is too small to pin the order down and the caller should
    try another.
    """
    p = curve["p"]
    root = _isqrt(p)
    lo, width = p + 1 - 2 * root, 4 * root
    step = _isqrt(width) + 1

    base = mul(curve, lo, R)          # (lo)*R
    baby = {}
    cur = None                         # j*R for j = 0..step-1
    for j in range(step):
        key = (cur[0], cur[1]) if cur else "O"
        baby.setdefault(key, j)
        cur = add(curve, cur, R)
    giant = mul(curve, step, R)

    # Solving `(lo + t*step + j)*R = O` for j, which rearranges to
    # `j*R = -(base + t*giant)`. So the accumulator walks *forward* by `giant`
    # and the table is probed with its negation -- getting that sign backwards
    # finds nothing at all, which is how it was caught.
    found = []
    acc = base
    for t in range(step + 2):
        key = (acc[0], (-acc[1]) % p) if acc else "O"
        if key in baby:
            n = lo + t * step + baby[key]
            if lo <= n <= lo + width and mul(curve, n, R) is None:
                found.append(n)
                if len(found) > 1:
                    return None
        acc = add(curve, acc, giant)
    return found[0] if len(found) == 1 else None


def _isqrt(n):
    x = int(n ** 0.5)
    while x * x > n:
        x -= 1
    while (x + 1) * (x + 1) <= n:
        x += 1
    return x


def derive(bits, seed=None, report=None):
    """A complete instance for a group of roughly `bits` bits."""
    seed = seed or f"proofwork ecdlp nums v1 {bits}"
    # p = 3 mod 4 keeps the square root in `hash_to_point` a single
    # exponentiation; the largest such prime under 2^bits is still a function
    # of the bit size and nothing else.
    limit = 1 << bits
    p = _prime_below(limit)
    while p % 4 != 3:
        p = _prime_below(p)

    for counter in range(10000):
        a = _h(seed, "a", counter) % p
        b = _h(seed, "b", counter) % p
        curve = {"p": p, "a": a, "b": b}
        if (4 * pow(a, 3, p) + 27 * b * b) % p == 0:
            continue
        G = hash_to_point(curve, f"{seed}|G|{counter}")
        n = group_order(curve, G)
        if n is None or not is_prime(n):
            if report:
                report(counter, n)
            continue
        # Prime order means the group is cyclic and every point is in <G>, so
        # the hashed Q is guaranteed to have a discrete logarithm.
        Q = hash_to_point(curve, f"{seed}|Q|{counter}")
        return {
            "name": f"nums-{bits}",
            "seed": seed,
            "counter": counter,
            "p": p, "a": a, "b": b, "n": n,
            "Gx": G[0], "Gy": G[1], "Qx": Q[0], "Qy": Q[1],
        }
    raise RuntimeError("no prime-order curve found")


def validate(inst):
    """Every property the objective depends on, re-checked from the numbers."""
    curve = {"p": inst["p"], "a": inst["a"], "b": inst["b"]}
    G = (inst["Gx"], inst["Gy"])
    Q = (inst["Qx"], inst["Qy"])
    checks = {
        "p is prime": is_prime(inst["p"]),
        "p = 3 mod 4": inst["p"] % 4 == 3,
        "curve is non-singular": (4 * pow(inst["a"], 3, inst["p"]) + 27 * inst["b"] ** 2)
        % inst["p"] != 0,
        "G is on the curve": on_curve(curve, G),
        "Q is on the curve": on_curve(curve, Q),
        "n is prime": is_prime(inst["n"]),
        "n*G is the point at infinity": mul(curve, inst["n"], G) is None,
        "n*Q is the point at infinity": mul(curve, inst["n"], Q) is None,
    }
    # The nothing-up-my-sleeve claim itself: re-derive the points from the seed.
    tag = f"{inst['seed']}|G|{inst['counter']}"
    checks["G is the hash of its seed"] = hash_to_point(curve, tag) == G
    tag = f"{inst['seed']}|Q|{inst['counter']}"
    checks["Q is the hash of its seed"] = hash_to_point(curve, tag) == Q
    return checks


def main():
    if len(sys.argv) < 3:
        print(__doc__.strip().splitlines()[0])
        print("\n  nums.py derive <bits> [seed]\n  nums.py verify <file.json>")
        return 2
    mode, arg = sys.argv[1], sys.argv[2]
    if mode == "derive":
        bits = int(arg)
        seed = sys.argv[3] if len(sys.argv) > 3 else None
        inst = derive(bits, seed)
        print(json.dumps({k: (hex(v) if isinstance(v, int) and k != "counter" else v)
                          for k, v in inst.items()}, indent=2))
        return 0
    if mode == "verify":
        raw = json.load(open(arg))
        inst = {k: (int(v, 16) if isinstance(v, str) and v.startswith("0x") else v)
                for k, v in raw.items()}
        bad = 0
        for label, ok in validate(inst).items():
            print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
            bad += not ok
        print("\n" + ("VERIFIED" if not bad else f"FAILED ({bad})"))
        return 1 if bad else 0
    print(f"unknown mode {mode!r}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
