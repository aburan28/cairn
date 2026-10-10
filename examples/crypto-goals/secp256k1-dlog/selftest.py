"""Positive and adversarial checks for the secp256k1 DLP verifier."""

from __future__ import annotations

import importlib.util
from pathlib import Path


CHECKER = Path(__file__).parent / "checkers" / "secp256k1_dlog.py"
SPEC = importlib.util.spec_from_file_location("secp256k1_dlog", CHECKER)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def main() -> None:
    # SEC 1's small example curve y^2 = x^3 + 2x + 2 over F_17 has order 19;
    # (5, 1) is a generator. This exercises an actual positive certificate.
    p, a, b, n, g = 17, 2, 2, 19, (5, 1)
    assert MODULE._mul(n, g, p, a) is None
    assert MODULE._check_log(1, g, p, a, b, n, g)[0]
    assert MODULE._check_log(2, g, p, a, b, n, g)[0] is False
    assert MODULE._check_log(0, g, p, a, b, n, g)[0] is False
    assert MODULE._check_log(1, None, p, a, b, n, g)[0] is False

    target = MODULE._derive_target()
    assert target is not None
    assert MODULE._on_curve(MODULE.GENERATOR, MODULE.FIELD_P, MODULE.CURVE_A, MODULE.CURVE_B)
    assert MODULE._on_curve(target, MODULE.FIELD_P, MODULE.CURVE_A, MODULE.CURVE_B)
    assert MODULE._mul(MODULE.ORDER_N, MODULE.GENERATOR, MODULE.FIELD_P, MODULE.CURVE_A) is None
    assert MODULE._mul(MODULE.ORDER_N, target, MODULE.FIELD_P, MODULE.CURVE_A) is None
    assert MODULE.check({"k": "0" * 64})[0] is False
    assert MODULE.check({"k": "A" * 64})[0] is False
    assert MODULE.check({"k": "0" * 63 + "1", "extra": 1})[0] is False
    print("secp256k1 dlog checker selftest: ok")


if __name__ == "__main__":
    main()
