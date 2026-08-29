#!/usr/bin/env python3
"""Solve the truncated MD5 rung, and write the artifact it settles with.

    solve_truncated.py            # search, verify against the pinned checker, write
    solve_truncated.py --check    # re-verify the committed artifact only

# Why this exists

`objective-collide-md5-48.json` asks for two messages behind the pinned prefix
whose MD5 digests agree on their leading 48 bits. That is generic birthday
work -- about 2^24 compressions -- and there is no cryptanalysis in it at all.

It is worth having anyway, and the reason is about the *checker* rather than
about MD5. Every other objective in this directory is open, so running their
checkers only ever demonstrates rejection, and a checker shown only to reject
is indistinguishable from one that rejects everything. This produces a real
pair that a real checker accepts, from the same generated template as the other
five, which is the only evidence available that the template accepts anything.

That the answer is published here is what makes this instance a demonstration
rather than a bounty: copying it settles and mints nothing.

# The search

Pollard rho over f(x) = MD5(PREFIX || x)[:6], on 48-bit states, with Floyd
cycle detection and an entry-point walk to recover the colliding pair. Memory
is constant, which matters more than it looks: the table-based birthday attack
at this size wants 2^24 entries, and a Python dict of them is several
gigabytes for a result rho reaches in a minute with none.

The start value is derived rather than random, so this run is reproducible and
the artifact in `../artifacts/` can be re-derived by anyone who doubts it.
"""

import hashlib
import importlib.util
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
ARTIFACT = ROOT / "artifacts" / "md5-48.json"
SEED = "cairn hash-differential v1 md5-48 rho"
TRUNC = 6


def checker():
    path = ROOT / "checkers" / "collide_md5_48.py"
    spec = importlib.util.spec_from_file_location("collide_md5_48", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def solve(prefix):
    def f(x):
        return hashlib.md5(prefix + x).digest()[:TRUNC]

    start = hashlib.sha256(SEED.encode()).digest()[:TRUNC]
    # Floyd: the tortoise and the hare meet somewhere inside the cycle.
    slow, fast = f(start), f(f(start))
    steps = 0
    while slow != fast:
        slow, fast = f(slow), f(f(fast))
        steps += 1
    # Re-walk from the start in lockstep. The step before they first agree is a
    # pair of distinct points with the same image -- the collision. If the start
    # was already inside the cycle there is no such step, and the caller retries.
    slow = start
    prev_slow = prev_fast = None
    while slow != fast:
        prev_slow, prev_fast = slow, fast
        slow, fast = f(slow), f(fast)
        steps += 1
    if prev_slow is None or prev_slow == prev_fast:
        raise SystemExit("start value landed inside the cycle; pick another SEED")
    assert f(prev_slow) == f(prev_fast)
    return prev_slow, prev_fast, steps


def verify(module, artifact, note):
    ok, detail = module.check(artifact)
    print("  %-9s %s -- %s" % (note, "ACCEPT" if ok else "REJECT", detail))
    return ok


def main():
    module = checker()
    if "--check" in sys.argv[1:]:
        artifact = json.loads(ARTIFACT.read_text())
        return 0 if verify(module, artifact, "committed") else 1

    left, right, steps = solve(module.PREFIX)
    print("rho found a 48-bit collision after %d evaluations" % steps)
    artifact = {
        "m": (module.PREFIX + left).hex(),
        "m_prime": (module.PREFIX + right).hex(),
    }
    if not verify(module, artifact, "found"):
        return 1
    ARTIFACT.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n")
    print("wrote %s" % ARTIFACT.relative_to(ROOT.parent.parent))
    return 0


if __name__ == "__main__":
    sys.exit(main())
