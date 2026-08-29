#!/usr/bin/env python3
"""Disturbance vectors in the frame the correction map actually reads.

    python3 dv_shift.py space <steps> <out>      basis of usable vectors
    python3 dv_shift.py delta <steps> <80 words> message difference + path

The subtlety this file exists for.  The message difference at step t is built
from disturbances at steps t-5 .. t, so for the difference to satisfy SHA-1's
expansion from step 16 on, the disturbance vector must satisfy *its* recurrence
from five steps earlier.  Indexing the vector from step -5 makes that automatic;
indexing it from step 0 makes it false at steps 16..20 only, which is the kind
of boundary error that shows up as a search which simply never finds anything.

So `dv[i]` here is the disturbance at step `i - 5`.
"""
import sys

MASK = 0xFFFFFFFF
def rotl(x, n): return ((x << n) | (x >> (32 - n))) & MASK

SHIFT = 5


def expand(seed, upto):
    dv = list(seed)
    for i in range(16, upto):
        dv.append(rotl(dv[i-3] ^ dv[i-8] ^ dv[i-14] ^ dv[i-16], 1))
    return dv


def delta_and_path(dv, steps):
    """message difference for steps 0..15, and the expected difference in `a`"""
    dw, path = [], []
    for t in range(80):
        i = t + SHIFT
        v = dv[i] if i < len(dv) else 0
        for lag, rot in ((1, 5), (2, 0), (3, 30), (4, 30), (5, 30)):
            j = i - lag
            if 0 <= j < len(dv):
                v ^= rotl(dv[j], rot)
        dw.append(v)
        path.append(dv[i] if i < len(dv) else 0)
    return dw, path


mode = sys.argv[1]
STEPS = int(sys.argv[2])
# disturbances must stop early enough for every local collision to close
ZERO_FROM = STEPS

if mode == "space":
    OUT = sys.argv[3]
    cols = []
    for i in range(512):
        seed = [0]*16
        seed[i // 32] = 1 << (i % 32)
        dv = expand(seed, STEPS + SHIFT)
        # Two conditions, both structural.  The tail: every local collision has
        # to close inside the step count.  The head: a disturbance at a step
        # before 0 presumes a state difference at the IV, and both messages
        # start from the same IV, so those slots must be empty or the path
        # describes a pair that cannot exist.
        con = 0
        for j, k in enumerate(list(range(ZERO_FROM, STEPS + SHIFT)) + list(range(SHIFT))):
            con |= dv[k] << (32*j)
        cols.append(con)

    nrows = 32 * SHIFT * 2
    rows = []
    for r in range(nrows):
        row = 0
        for i in range(512):
            if (cols[i] >> r) & 1:
                row |= 1 << i
        rows.append(row)

    pivots, rank = [], 0
    for col in range(512):
        piv = next((r for r in range(rank, len(rows)) if (rows[r] >> col) & 1), None)
        if piv is None:
            continue
        rows[rank], rows[piv] = rows[piv], rows[rank]
        for r in range(len(rows)):
            if r != rank and (rows[r] >> col) & 1:
                rows[r] ^= rows[rank]
        pivots.append(col); rank += 1

    pivset = set(pivots)
    free = [c for c in range(512) if c not in pivset]
    sys.stderr.write(f"steps {STEPS}: rank {rank}, solution space {len(free)}\n")
    out = []
    for f in free:
        sel = 1 << f
        for r, p in enumerate(pivots):
            if (rows[r] >> f) & 1:
                sel |= 1 << p
        seed = [0]*16
        for i in range(512):
            if (sel >> i) & 1:
                seed[i // 32] ^= 1 << (i % 32)
        dv = expand(seed, STEPS + SHIFT)
        assert not any(dv[ZERO_FROM:]), "a local collision would not close"
        assert not any(dv[:SHIFT]), "the path presumes a difference at the IV"
        out.append(dv + [0] * (80 - len(dv)))
    with open(OUT, "w") as fh:
        fh.write(f"{len(out)} 80\n")
        for dv in out:
            fh.write(" ".join(f"{w:08x}" for w in dv) + "\n")

elif mode == "delta":
    dv = [int(x, 16) for x in sys.argv[3:83]]
    dw, path = delta_and_path(dv, STEPS)
    # verify: the difference must be an expansion of its own first 16 words
    exp = list(dw[:16])
    for t in range(16, STEPS):
        exp.append(rotl(exp[t-3] ^ exp[t-8] ^ exp[t-14] ^ exp[t-16], 1))
    bad = [t for t in range(16, STEPS) if exp[t] != dw[t]]
    if bad:
        sys.stderr.write(f"difference violates the expansion at steps {bad[:6]}\n")
        sys.exit(1)
    late = sum(bin(dv[i]).count("1") for i in range(21, STEPS))
    total = sum(bin(x).count("1") for x in dv[:STEPS])
    sys.stderr.write(f"steps {STEPS}: {total} disturbances, {late} of them past step 16; "
                     f"difference consistent with the expansion\n")
    print(" ".join(f"{x:08x}" for x in path))      # expected difference in a
    print(" ".join(f"{x:08x}" for x in dw[:16]))   # message difference
else:
    sys.stderr.write("mode must be 'space' or 'delta'\n")
    sys.exit(2)
