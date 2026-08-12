#!/usr/bin/env python3
"""Exercise every pinned checker in this directory.

    python3 examples/certicom-ecdlp/tools/selftest.py

None of the three pinned instances is solved, so running their checkers can
only ever demonstrate *rejection* -- and a verifier shown only to reject is
indistinguishable from one that rejects everything.

So acceptance is proven against two instances derived exactly the same way and
then **actually solved**: `testvector-40.json` by baby-step giant-step in about
three seconds, and `testvector-50.json` by Pollard rho in 37,672,363 steps and
221 seconds -- within 10% of the 2^25.3 the theory predicts, which is itself
evidence the group order is what the instance claims.

Neither is an objective. Once an answer is published, posting the instance would
settle instantly for the first copier and mint nothing, so each retired to a test
vector the moment it was solved. The live 50-bit objective uses a fresh v2 seed
whose logarithm nobody has computed.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "checkers"))
sys.path.insert(0, HERE)

import nums  # noqa: E402

# The two solved test vectors. Anyone can redo either: `tools/nums.py verify`
# confirms the instance, then BSGS or rho against the same G and Q.
NUMS40_K = 1015864291073
NUMS50_K = 588682124876062


def load(name):
    raw = json.load(open(os.path.join(ROOT, "instances", name)))
    return {k: (int(v, 16) if isinstance(v, str) and v.startswith("0x") else v)
            for k, v in raw.items()}


def hexk(k):
    return f"{k:064x}"


def main():
    failures = []

    def require(cond, label):
        print(f"  {'ok  ' if cond else 'FAIL'}  {label}")
        if not cond:
            failures.append(label)

    # -- acceptance, against a genuinely solved instance --------------------
    print("acceptance, on solved instances")
    for label, fname, k in (("nums-40 (BSGS)", "testvector-40.json", NUMS40_K),
                            ("nums-50 (rho)", "testvector-50.json", NUMS50_K)):
        i = load(fname)
        cc = {"p": i["p"], "a": i["a"], "b": i["b"]}
        require(nums.mul(cc, k, (i["Gx"], i["Gy"])) == (i["Qx"], i["Qy"]),
                f"{label}: the published k satisfies k*G = Q")
    inst = load("testvector-40.json")
    curve = {"p": inst["p"], "a": inst["a"], "b": inst["b"]}
    G, Q = (inst["Gx"], inst["Gy"]), (inst["Qx"], inst["Qy"])
    # The checker for it, built from the same template the objectives use.
    import importlib.util
    spec = importlib.util.spec_from_loader("nums40chk", loader=None)
    mod = importlib.util.module_from_spec(spec)
    tpl = open(os.path.join(ROOT, "checkers", "nums_50.py")).read()
    tpl = tpl.split("# -- the pinned instance")[0]
    exec(tpl + f"""
CURVE_P = {inst['p']}
CURVE_A = {inst['a']}
CURVE_B = {inst['b']}
ORDER_N = {inst['n']}
GEN_X = {G[0]}
GEN_Y = {G[1]}
TARGET_X = {Q[0]}
TARGET_Y = {Q[1]}
""", mod.__dict__)

    ok, why = mod.check({"k": hexk(NUMS40_K)})
    require(ok, f"the checker accepts it -- {why}")
    require(not mod.check({"k": hexk(NUMS40_K + 1)})[0], "and rejects k+1")
    require(not mod.check({"k": hexk(NUMS40_K + inst["n"])})[0],
            "and rejects k+n, which is the same logarithm out of range")

    print("\nmalformed artifacts, each scored rather than raised")
    for label, bad in [
        ("not an object", []),
        ("k absent", {}),
        ("k as an integer", {"k": NUMS40_K}),
        ("k too short", {"k": "01"}),
        ("uppercase hex", {"k": hexk(NUMS40_K).upper()}),
        ("non-hex", {"k": "z" * 64}),
        ("k = 0", {"k": hexk(0)}),
    ]:
        try:
            require(not mod.check(bad)[0], label)
        except Exception as exc:  # noqa: BLE001
            require(False, f"{label} -- raised {type(exc).__name__}: {exc}")

    # -- every pinned instance is well formed -------------------------------
    print("\nthe pinned instances")
    for name, module in [("nums-50", "nums_50"), ("nums-60", "nums_60"),
                         ("ECCp-131", "certicom_eccp131")]:
        chk = __import__(module)
        c = {"p": chk.CURVE_P, "a": chk.CURVE_A, "b": chk.CURVE_B}
        Gp, Qp = (chk.GEN_X, chk.GEN_Y), (chk.TARGET_X, chk.TARGET_Y)
        good = (
            nums.is_prime(chk.CURVE_P)
            and (4 * pow(chk.CURVE_A, 3, chk.CURVE_P) + 27 * chk.CURVE_B ** 2) % chk.CURVE_P != 0
            and nums.on_curve(c, Gp) and nums.on_curve(c, Qp)
            and nums.is_prime(chk.ORDER_N)
            and nums.mul(c, chk.ORDER_N, Gp) is None
            and nums.mul(c, chk.ORDER_N, Qp) is None
        )
        require(good, f"{name}: p prime, non-singular, G and Q on curve, n prime, nG = nQ = O "
                      f"({chk.ORDER_N.bit_length()}-bit group)")
        require(not chk.check({"k": hexk(1)})[0], f"{name}: refuses k = 1")

    # -- the nothing-up-my-sleeve claim, re-derived -------------------------
    print("\nnothing-up-my-sleeve: the ladder re-derives from its seeds")
    for name in ("testvector-40", "testvector-50", "nums-50", "nums-60"):
        checks = nums.validate(load(name + ".json"))
        require(all(checks.values()), f"{name}: {sum(checks.values())}/{len(checks)} properties")

    print()
    if failures:
        print(f"FAILED: {len(failures)}")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("SELFTEST OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
