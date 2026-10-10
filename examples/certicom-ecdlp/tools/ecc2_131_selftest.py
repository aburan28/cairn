#!/usr/bin/env python3
"""Reproduce exact validation controls for the ECC2-131 answer checker."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "checkers"))
import certicom_ecc2_131 as ecc  # noqa: E402


def run() -> None:
    assert ecc._on_curve(ecc.GENERATOR)
    assert ecc._on_curve(ecc.TARGET)
    assert ecc._mul_point(ecc.ORDER_N, ecc.GENERATOR) is None
    assert ecc._mul_point(ecc.ORDER_N, ecc.TARGET) is None

    # Exercise the acceptance path against a target generated from a known
    # scalar, while leaving the pinned challenge point untouched.
    known_k = 0x123456789ABCDEF0123456789ABCDEF
    known_target = ecc._mul_point(known_k, ecc.GENERATOR)
    assert ecc._check_scalar(known_k, known_target)[0]
    assert not ecc._check_scalar(known_k + 1, known_target)[0]

    assert not ecc.check({"k": f"{known_k:064x}"})[0]
    for artifact in (
        None,
        {},
        {"k": "0" * 64},
        {"k": "g" * 64},
        {"k": "1"},
        {"k": "1" * 64, "extra": "field"},
    ):
        assert not ecc.check(artifact)[0], artifact

    print("ECC2-131 SELFTEST OK: point, subgroup, positive control, and malformed answers")


if __name__ == "__main__":
    run()
