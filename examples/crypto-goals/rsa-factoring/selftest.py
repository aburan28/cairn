"""Fast positive and adversarial tests for the RSA challenge checker helpers."""

from __future__ import annotations

import importlib.util
from pathlib import Path


CHECKER = Path(__file__).parent / "checkers" / "rsa_challenge.py"
SPEC = importlib.util.spec_from_file_location("rsa_challenge", CHECKER)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def main() -> None:
    # The known small semiprime exercises the same exact split rule without
    # pretending that it is a factorization of any RSA challenge modulus.
    assert MODULE._check_factor({"factor": "101"}, 101 * 113)[0]
    assert MODULE._check_factor({"factor": "113"}, 101 * 113)[0]
    assert not MODULE._check_factor({"factor": "1"}, 101 * 113)[0]
    assert not MODULE._check_factor({"factor": "101"}, 101 * 113 + 1)[0]
    assert not MODULE._check_factor({"factor": "0101"}, 101 * 113)[0]
    assert not MODULE._check_factor({"factor": 101}, 101 * 113)[0]
    assert not MODULE._check_factor({"factor": "11413"}, 101 * 113)[0]
    assert not MODULE._check_factor({"factor": "9" * 5000}, 101 * 113)[0]
    assert MODULE.RSA_1024.bit_length() == 1024
    assert MODULE.RSA_1536.bit_length() == 1536
    assert MODULE.RSA_2048.bit_length() == 2048
    print("rsa challenge checker selftest: ok")


if __name__ == "__main__":
    main()
