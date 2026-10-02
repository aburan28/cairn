"""Batcher's odd-even merge sort on 8 wires: 19 comparators, depth 6."""

import json


def merge(lo, n, r, out):
    step = r * 2
    if step < n:
        merge(lo, n, step, out)
        merge(lo + r, n, step, out)
        for i in range(lo + r, lo + n - r, step):
            out.append([i, i + r])
    else:
        out.append([lo, lo + r])


def sort(lo, n, out):
    if n > 1:
        half = n // 2
        sort(lo, half, out)
        sort(lo + half, half, out)
        merge(lo, n, 1, out)


network = []
sort(0, 8, network)
print(json.dumps(network))
