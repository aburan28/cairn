"""Independent sanity checks and controls for BLS12-381 G2."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent / "checkers"))
import bls12_381_g2 as d

assert d.P % 4 == 3
assert d.fmul(d.G[1], d.G[1]) == d.fadd(d.fmul(d.fmul(d.G[0], d.G[0]), d.G[0]), d.B)
assert d.multiply(d.R, d.G) is None
# Check that extension-field square roots are exact on non-real values.
sample = (123456789, 987654321)
square = d.fmul(sample, sample)
root = d.fsqrt(square)
assert root is not None and d.fmul(root, root) == square
q, counter = d.target()
assert counter == 0
assert q is not None
assert d.fmul(q[1], q[1]) == d.fadd(d.fmul(d.fmul(q[0], q[0]), q[0]), d.B)
assert d.multiply(d.R, q) is None

scalar = 0x123456789ABCDEF
artifact = {"k": f"{scalar:064x}"}
original_target = d.target
d.target = lambda: (d.multiply(scalar, d.G), 0)
assert d.check(artifact)
d.target = original_target
assert not d.check(artifact)
assert not d.check({"k": f"{scalar + 1:064x}"})
assert not d.check({"k": f"{d.R:064x}"})
assert not d.check({"k": artifact["k"].upper()})
assert not d.check({"k": artifact["k"], "extra": 1})
print(f"BLS12-381 G2: point counter {counter}, Fp2 arithmetic, curve, subgroup, and answer controls pass")
