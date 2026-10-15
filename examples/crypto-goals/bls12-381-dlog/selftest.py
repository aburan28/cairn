"""Independent sanity checks and positive/negative controls for BLS12-381 G1."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent / "checkers"))
import bls12_381_g1 as d

assert d.P % 4 == 3
assert (d.G[1] * d.G[1] - d.G[0] ** 3 - 4) % d.P == 0
assert d.multiply(d.R, d.G) is None
q, counter = d.target()
assert counter == 0
assert q is not None
assert (q[1] * q[1] - q[0] ** 3 - 4) % d.P == 0
assert d.multiply(d.R, q) is None

width = 64
scalar = 0x123456789ABCDEF
artifact = {"k": f"{scalar:0{width}x}"}
original_target = d.target
d.target = lambda: (d.multiply(scalar, d.G), 0)
assert d.check(artifact)
d.target = original_target
assert not d.check(artifact)
assert not d.check({"k": f"{scalar + 1:0{width}x}"})
assert not d.check({"k": f"{d.R:064x}"})
assert not d.check({"k": artifact["k"].upper()})
assert not d.check({"k": artifact["k"], "extra": 1})
print(f"BLS12-381 G1: point counter {counter}, curve, subgroup, positive and negative controls pass")
