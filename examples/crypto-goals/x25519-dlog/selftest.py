"""Published parameter checks plus controlled X25519 answer tests."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent / "checkers"))
import x25519_dlog as d

assert (d.G[1] ** 2 - d.G[0] ** 3 - d.A * d.G[0] ** 2 - d.G[0]) % d.P == 0
assert d.multiply(d.ELL, d.G) is None
assert d.x_multiply(d.ELL, 9) is None
for scalar in (1, 2, 3, 8, 19, 123456789):
    assert d.x_multiply(scalar, 9) == d.multiply(scalar, d.G)[0]
    assert d.x_multiply(d.ELL - scalar, 9) == d.x_multiply(scalar, 9)
q, counter = d.target()
assert counter == 0
assert d.x_multiply(d.ELL, q) is None
rhs = (q**3 + d.A * q**2 + q) % d.P
assert d.square_root(rhs) is not None

scalar = 0x123456789ABCDEF
artifact = {"k": f"{scalar:064x}"}
original_target = d.target
d.target = lambda: (d.x_multiply(scalar, 9), 0)
assert d.check(artifact)
d.target = original_target
assert not d.check(artifact)
assert not d.check({"k": f"{scalar + 1:064x}"})
assert not d.check({"k": f"{d.ELL:064x}"})
assert not d.check({"k": artifact["k"].upper()})
assert not d.check({"k": artifact["k"], "extra": 1})
print(f"X25519 DLP: target counter {counter}, generator order, ladder agreement, sign canonicalization, and answer controls pass")
