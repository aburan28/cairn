#!/usr/bin/env python3
"""Emit a basis for the SHA-1 disturbance vectors that can carry an attack.

A disturbance vector is a codeword of the message expansion, so the 512 bits
at steps 0..15 determine all 80 words.  The usable ones are those whose local
collisions all close inside the 80 steps -- no disturbance in steps 75..79 --
which is 160 linear conditions.  What is left is the null space, and searching
inside it means every candidate the searcher touches is already a valid
codeword with a closing tail; validity is structural rather than tested.
"""
import sys

MASK = 0xFFFFFFFF
def rotl1(x): return ((x << 1) | (x >> 31)) & MASK

def expand(words):
    dv = list(words)
    for t in range(16, 80):
        dv.append(rotl1(dv[t-3] ^ dv[t-8] ^ dv[t-14] ^ dv[t-16]))
    return dv

# column i of the constraint matrix: what seed bit i puts into steps 75..79
cols = []
for i in range(512):
    seed = [0]*16
    seed[i // 32] = 1 << (i % 32)
    dv = expand(seed)
    tail = 0
    for j, t in enumerate(range(75, 80)):
        tail |= dv[t] << (32*j)
    cols.append(tail)

# rows over the 512 columns, then RREF over GF(2)
rows = []
for r in range(160):
    row = 0
    for i in range(512):
        if (cols[i] >> r) & 1:
            row |= 1 << i
    rows.append(row)

pivots = []
rank = 0
for col in range(512):
    piv = None
    for r in range(rank, len(rows)):
        if (rows[r] >> col) & 1:
            piv = r
            break
    if piv is None:
        continue
    rows[rank], rows[piv] = rows[piv], rows[rank]
    for r in range(len(rows)):
        if r != rank and (rows[r] >> col) & 1:
            rows[r] ^= rows[rank]
    pivots.append(col)
    rank += 1

free = [c for c in range(512) if c not in set(pivots)]
sys.stderr.write(f"constraint rank {rank}, null space dimension {len(free)}\n")

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
    dv = expand(seed)
    assert not any(dv[t] for t in range(75, 80)), "basis vector violates the tail condition"
    out.append(dv)

with open(sys.argv[1] if len(sys.argv) > 1 else "dv_basis.txt", "w") as fh:
    fh.write(f"{len(out)} 80\n")
    for dv in out:
        fh.write(" ".join(f"{w:08x}" for w in dv) + "\n")
sys.stderr.write(f"wrote {len(out)} basis codewords\n")
