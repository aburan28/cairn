#!/usr/bin/env python3
"""Regenerate the First-Blood ECDLP checkers with public-coin instances.

# What this fixes

The instances used to be `Q = k*G` for a random `k` the operator generated and
said they discarded. `examples/first-blood/README.md` disclosed the obvious
problem: that claim is unverifiable, so the anti-self-dealing property was
trust in the poster rather than a fact anyone could check. A funder who kept
`k` could collect their own bounty, and nothing in the repository would notice.
`docs/launch-review.md` names the fix -- "a public-coin instance derivation" --
and this is it.

# The construction

`Q` is **hashed to the curve** from a fixed public seed instead of being
multiplied into existence:

    x = sha256(SEED || bits || counter) mod p,   counter = 0, 1, 2, ...
    until x^3 + ax + b is a quadratic residue
    y = sqrt(x^3 + ax + b)                       (p = 3 mod 4, so this is a power)

`Q` is therefore never constructed as a multiple of `G`, and **nobody knows
`log_G(Q)` -- recovering it is exactly the ECDLP the bounty pays for.** This is
the standard nothing-up-my-sleeve technique, the same one used to derive the
second generator `H` for Pedersen commitments on secp256k1.

Grinding the seed buys an attacker nothing, which is the part worth being
explicit about. To gain from trying many seeds you would have to *recognise* a
`Q` whose logarithm you know -- and recognising one means solving the instance.
So a fixed, published seed is as good as an unpredictable one here, and it has
the advantage of being re-derivable by anyone forever.

# What this does NOT prove

The curve itself -- `p`, `a`, `b`, `G` -- is still the poster's choice, and a
maliciously chosen curve can be weak in ways this does not address (smooth
group order for Pohlig-Hellman, low embedding degree for MOV). What is checked
here is that `N` is prime and that `G` and `Q` both have order `N`, which rules
out the smooth-order family. Deriving the curve from the seed too is the
stronger construction and is not done. See the README.

Usage:
    derive-first-blood.py            # rewrite the checkers and objectives
    derive-first-blood.py --check    # verify the checked-in files match (CI)
"""

import hashlib
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
CHECKERS = ROOT / "examples/first-blood/checkers"
OBJECTIVES = ROOT / "examples/first-blood"
SIZES = (80, 88, 96, 112, 128)

# Published, fixed, and re-derivable by anyone. See the module docstring for
# why this does not need to be unpredictable.
SEED = b"proofwork/first-blood/ecdlp/public-coin/v1"


def curve_of(bits):
    """Read the curve out of the existing checker.

    The curve is carried forward unchanged -- only `Q` is replaced. Reusing it
    keeps the difficulty of each bounty exactly what it was.
    """
    src = (CHECKERS / f"instance_{bits}.py").read_text()
    names = ("P", "A", "B", "N", "GX", "GY")
    out = {}
    for name in names:
        match = re.search(rf"^{name} = (\d+)$", src, re.M)
        if not match:
            raise SystemExit(f"instance_{bits}.py: no constant {name}")
        out[name] = int(match.group(1))
    return out


def add(p, q, P, A):
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


def mul(k, point, P, A):
    result, addend = None, point
    while k:
        if k & 1:
            result = add(result, addend, P, A)
        addend = add(addend, addend, P, A)
        k >>= 1
    return result


def derive_q(bits, c):
    """Try-and-increment hash-to-curve. Returns (x, y, counter)."""
    P, A, B = c["P"], c["A"], c["B"]
    if P % 4 != 3:
        raise SystemExit(f"{bits}: p % 4 != 3, the sqrt shortcut does not apply")
    for counter in range(100_000):
        digest = hashlib.sha256(
            SEED + b"/" + str(bits).encode() + b"/" + str(counter).encode()
        ).digest()
        x = int.from_bytes(digest, "big") % P
        rhs = (x * x * x + A * x + B) % P
        if pow(rhs, (P - 1) // 2, P) != 1:
            continue
        y = pow(rhs, (P + 1) // 4, P)
        if (y * y - rhs) % P != 0:
            continue
        # Canonical root, so the derivation has exactly one answer.
        return x, min(y, P - y), counter
    raise SystemExit(f"{bits}: no point found")


def audit(bits, c, qx, qy):
    """Refuse to emit an instance that is not sound."""
    P, A, N = c["P"], c["A"], c["N"]
    g = (c["GX"], c["GY"])
    if pow(2, N - 1, N) != 1:
        raise SystemExit(f"{bits}: N is not prime, so Pohlig-Hellman may apply")
    if (qy * qy - qx**3 - A * qx - c["B"]) % P != 0:
        raise SystemExit(f"{bits}: derived Q is not on the curve")
    if mul(N, g, P, A) is not None:
        raise SystemExit(f"{bits}: G does not have order N")
    # Order N and not the identity, in a group of prime order N: Q = k*G has
    # exactly one solution with k in [1, N). The bounty is provably solvable.
    if mul(N, (qx, qy), P, A) is not None:
        raise SystemExit(f"{bits}: derived Q does not have order N")


TEMPLATE = '''"""Certificate checker: First-Blood ECDLP instance, {bits}-bit.

Recover k with k*G == Q on the curve below. Finding k is believed to cost
~sqrt(n) group operations; checking a claimed k is one scalar multiplication.
How it was found is irrelevant and unverifiable, which is the point.

**Nobody knows k, and that is checkable rather than promised.** Q is not a
multiple of G that somebody computed and discarded -- it is *hashed to the
curve* from the public seed below:

    x = sha256(SEED || bits || counter) mod p,  counter = 0, 1, 2, ...
    until x^3 + ax + b is a square; y = its canonical root

Q is therefore never built as k*G, so recovering log_G(Q) IS the ECDLP this
bounty pays for -- the funder has no more idea what k is than you do. Re-derive
it yourself: `_derive_q()` below runs at every check, and this file is pinned by
hash inside the objective's id.

Grinding the seed gains an attacker nothing. Profiting from a different seed
would mean recognising a Q whose logarithm you already know, and recognising one
means solving the instance.

What this does NOT prove: the curve (p, a, b, G) is still the poster's choice.
`check` verifies that N is prime-ish, and that G and Q both have order N, which
rules out a smooth-order curve; it does not rule out every weak-curve family.
Deriving the curve from the seed too is the stronger construction and is not
done here. See examples/first-blood/README.md.

The instance is derived, not baked in, and this file is pinned by hash inside
the objective's id, so the instance IS part of the objective's identity. Nobody
can retarget a funded bounty at an easier point.

Self-contained on purpose. The verifier pins the sha256 of THIS FILE ONLY -- an
imported helper module would not be covered by that hash, so shared curve
arithmetic would be an unpinned hole. Duplication is the price of pinning.

Generated by scripts/derive-first-blood.py. Do not edit by hand.
"""

import hashlib

P = {P}
A = {A}
B = {B}
N = {N}
GX = {GX}
GY = {GY}
BITS = {bits}
SEED = {seed!r}


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


def _derive_q():
    """Hash-to-curve, try-and-increment. The whole provenance of the instance.

    Deterministic: same seed, same Q, forever, for anyone who runs it.
    """
    for counter in range(100000):
        digest = hashlib.sha256(
            SEED + b"/" + str(BITS).encode() + b"/" + str(counter).encode()
        ).digest()
        x = int.from_bytes(digest, "big") % P
        rhs = (x * x * x + A * x + B) % P
        if pow(rhs, (P - 1) // 2, P) != 1:
            continue
        y = pow(rhs, (P + 1) // 4, P)
        if (y * y - rhs) % P != 0:
            continue
        return x, min(y, P - y)
    return None


def check(artifact: dict) -> tuple[bool, str]:
    k = artifact.get("k")
    if isinstance(k, bool) or not isinstance(k, int):
        return False, "artifact.k must be an integer"
    # k is a group element exponent: any representative in [1, n) is a valid
    # discrete log, and there is exactly one.
    if not 1 <= k < N:
        return False, f"k must lie in [1, n) with n = {{N}}"
    q = _derive_q()
    if q is None:
        return False, "instance derivation failed"
    # Guard the constants themselves. If either point were off-curve, or either
    # had an order smaller than N, the objective would be unsatisfiable or
    # cheap -- and a submitter should not spend compute discovering that.
    if not _on_curve(GX, GY) or not _on_curve(*q):
        return False, "instance constants are not on the curve"
    if _mul(N, (GX, GY)) is not None or _mul(N, q) is not None:
        return False, "instance points do not have order N"
    got = _mul(k, (GX, GY))
    if got is None:
        return False, "k*G is the point at infinity"
    if got != q:
        return False, "k*G does not equal Q"
    return True, f"verified: k*G == Q on the {{BITS}}-bit public-coin instance"
'''


def render(bits):
    c = curve_of(bits)
    qx, qy, counter = derive_q(bits, c)
    audit(bits, c, qx, qy)
    body = TEMPLATE.format(bits=bits, seed=SEED, **c)
    return body, qx, qy, counter


def main():
    checking = "--check" in sys.argv[1:]
    drift = []
    for bits in SIZES:
        body, qx, qy, counter = render(bits)
        checker = CHECKERS / f"instance_{bits}.py"
        objective = OBJECTIVES / f"objective_{bits}.json"

        if checking:
            if checker.read_text() != body:
                drift.append(f"{checker.relative_to(ROOT)} differs from its derivation")
        else:
            checker.write_text(body)

        digest = hashlib.sha256(body.encode()).hexdigest()
        record = json.loads(objective.read_text())
        if checking:
            if record["verifier"]["checker_sha256"] != digest:
                drift.append(f"{objective.relative_to(ROOT)} pins a stale checker hash")
        else:
            record["verifier"]["checker_sha256"] = digest
            objective.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")

        print(f"  {bits:>3}-bit  counter={counter:<3} Q=({qx}, {qy})")
        print(f"           sha256={digest}")

    if drift:
        for line in drift:
            print(f"DRIFT: {line}", file=sys.stderr)
        raise SystemExit(1)
    print("  --check: checked-in files match the derivation" if checking else "  written")


if __name__ == "__main__":
    main()
