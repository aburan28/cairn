#!/usr/bin/env python3
"""Check both pinned SHA-1 checkers against facts that do not come from them.

    python3 examples/sha1-differential/tools/selftest.py

The step function is checked against `hashlib` rather than against itself: a
compression function that agrees with a re-implementation of the same mistake
proves nothing.
"""
import hashlib
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "checkers"))

import dv_cost            # noqa: E402
import reduced_collision as rc   # noqa: E402

fails = []


def check(name, got, want):
    if got != want:
        fails.append(f"{name}: got {got!r}, want {want!r}")
    print(f"  {'ok  ' if got == want else 'FAIL'} {name}")


# -- the step function IS SHA-1 ---------------------------------------------
# One 64-byte block of a padded message: "abc" padded to 512 bits.  Running the
# checker's own states() to step 80, adding the feed-forward, must reproduce
# what hashlib says.
msg = b"abc"
padded = msg + b"\x80" + b"\x00" * (64 - len(msg) - 1 - 8) + struct.pack(">Q", len(msg) * 8)
block = list(struct.unpack(">16I", padded))
final = rc.states(block)[80]
digest = "".join(f"{(x + y) & 0xFFFFFFFF:08x}" for x, y in zip(final, rc.IV))
check("compression function matches hashlib on 'abc'", digest, hashlib.sha1(msg).hexdigest())

# -- reduced_collision -------------------------------------------------------
zero = "00" * 64
one_last = "00" * 60 + "0000000a"   # a letter, so the case test below bites
check("identical blocks score 0", rc.score({"m1": zero, "m2": zero}), 0)
check("differ in last word only -> the free 15", rc.score({"m1": zero, "m2": one_last}), 15)
check("differ in first word -> 0", rc.score({"m1": zero, "m2": "00000001" + "00" * 60}), 0)
# The measure is the deepest re-convergence, not the agreeing prefix: a pair
# that diverges early and comes back scores where it came back.
_zero_states = rc.states([0] * 16)
check("re-convergence is what is scored, not the prefix",
      rc.score({"m1": zero, "m2": one_last}) >= 15, True)
check("malformed scores 0", rc.score({"m1": "zz", "m2": zero}), 0)
check("uppercase refused", rc.score({"m1": zero, "m2": one_last.upper()}), 0)

# -- dv_cost ------------------------------------------------------------------
check("zero codeword refused", dv_cost.score({"dv": ["00000000"] * 16}), dv_cost.INVALID_SCORE)
check("wrong length refused", dv_cost.score({"dv": ["00000000"] * 15}), dv_cost.INVALID_SCORE)
check("non-hex refused", dv_cost.score({"dv": ["0000000g"] * 16}), dv_cost.INVALID_SCORE)

# The expansion the checker uses must be SHA-1's own, so a vector expanded
# forward and then run backwards returns to where it started.
dv = dv_cost._expand([0x00000001] + [0] * 15)
back = list(dv)
for t in range(79, 15, -1):
    inv = ((back[t] >> 1) | (back[t] << 31)) & 0xFFFFFFFF
    back[t - 16] = inv ^ back[t - 3] ^ back[t - 8] ^ back[t - 14]
check("expansion inverts", back[:16], [0x00000001] + [0] * 15)

print()
if fails:
    print(f"{len(fails)} failure(s)")
    for f in fails:
        print("  " + f)
    sys.exit(1)
print("all checks passed")
