#!/usr/bin/env python3
"""Re-check Certicom's prime-field parameters against the curve arithmetic.

    python3 examples/certicom-ecdlp/tools/validate_certicom.py

The parameters in `instances/certicom-eccp.json` were transcribed from a 2016
Internet Archive snapshot of `certicom.com/index.php/curves-list`, because the
original host is gone. That is a weak provenance and it does not need to be a
strong one:

    p prime · curve non-singular · P on the curve · Q on the curve
    n prime · n*P = O · n*Q = O

A single corrupted hex digit fails "on the curve" with probability about
`1 - 2^-p_bits`. Passing all seven is not evidence that these are *some* valid
curve -- a forger would have to produce a curve of prime order with two points
on it whose order matches the advertised bit size, which is the same work as
constructing a challenge. **The source stops mattering once the arithmetic
agrees**, which is the same reason `swarm::piece` can accept a manifest from a
stranger.

Exits non-zero if anything fails.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import nums  # noqa: E402


def main():
    path = os.path.join(os.path.dirname(HERE), "instances", "certicom-eccp.json")
    raw = json.load(open(path))
    order = sorted(raw, key=lambda s: int(s.split("-")[1]))

    print(f"{'instance':<11}{'p':>5}{'n':>5}  p prm  nonsng  P on E  Q on E  n prm  nP=O  nQ=O")
    bad = 0
    for name in order:
        d = {k: int(v, 16) for k, v in raw[name].items()}
        curve = {"p": d["p"], "a": d["a"], "b": d["b"]}
        P, Q = (d["Px"], d["Py"]), (d["Qx"], d["Qy"])
        checks = [
            nums.is_prime(d["p"]),
            (4 * pow(d["a"], 3, d["p"]) + 27 * d["b"] ** 2) % d["p"] != 0,
            nums.on_curve(curve, P),
            nums.on_curve(curve, Q),
            nums.is_prime(d["n"]),
            nums.mul(curve, d["n"], P) is None,
            nums.mul(curve, d["n"], Q) is None,
        ]
        bad += sum(not c for c in checks)
        print(f"{name:<11}{d['p'].bit_length():>5}{d['n'].bit_length():>5}  "
              + "   ".join("yes " if c else "NO  " for c in checks))

    # The cofactor is 1 on every one of these, so the group order is n and the
    # curve is cyclic -- no small subgroup for a submission to hide in.
    cofactors = {name: int(raw[name]["h"], 16) for name in order}
    print(f"\ncofactors all 1: {set(cofactors.values()) == {1}}")

    print("\n" + ("VALIDATED" if not bad else f"FAILED: {bad} check(s)"))
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
