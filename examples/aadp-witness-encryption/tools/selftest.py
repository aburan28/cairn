#!/usr/bin/env python3
"""Exercise the pinned checker against a *solved* AADP instance.

    python3 examples/aadp-witness-encryption/tools/selftest.py

Nobody has broken the pinned m=8 instance, so running the checker against it
can only ever demonstrate rejection -- and a verifier shown only to reject is
indistinguishable from one that rejects everything. That is the failure mode
this file exists to rule out.

So it builds a *small* instance from the same published construction, keeps the
secrets, and requires the checker to accept them and to recover the message.
Then it perturbs each of `L`, `R` and `xi` in turn and requires refusal, and
feeds malformed artifacts and requires them to be *scored* rather than raised
(`docs/verification.md` rule 3: an invalid submission is a bad artifact, an
exception is a broken verifier).

What this does NOT establish, stated plainly because the distinction is the
whole risk in this objective: the generator below and the checker transcribe
the same published construction, so agreement between them proves the
verification logic and the byte layout, and does *not* prove either matches
alloc-init's sage. See the README's "residual risk".

Not pinned by the objective and not run by the checker -- a development tool,
like anything in `scripts/`.
"""
import base64
import copy
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "checkers"))

import full_recovery as fr  # noqa: E402

P = fr.P


def build(m, seed, msg):
    """A complete AADP instance, with the secrets kept."""
    rng = random.Random(seed)
    n, k = m - 1, 2 * m + 1

    # A quadratic non-residue target, so no witness exists -- the same choice
    # the real challenge generator makes, and the reason a solver cannot
    # shortcut the problem by simply finding a witness.
    while True:
        target = rng.randrange(1, P)
        if pow(target, (P - 1) // 2, P) == P - 1:
            break

    A, B, C, D = fr.build_circuit(m, target)
    L = [[[rng.randrange(P) for _ in range(4)] for _ in range(k)] for _ in range(m)]
    R = [[[rng.randrange(P) for _ in range(k)] for _ in range(4)] for _ in range(m)]
    xi = [[rng.randrange(P) for _ in range(n + 1)] for _ in range(m)]

    M = fr._recompute(m, A, B, C, D, L, R, xi)
    M_hat = [[row[:] for row in Mj] for Mj in M]
    M_hat[0][k - 1][k - 1] = (M_hat[0][k - 1][k - 1] + msg) % P
    return target, M_hat, L, R, xi


def artifact_of(L, R, xi):
    hx = lambda v: f"{v:064x}"  # noqa: E731
    return {
        "L": [[[hx(v) for v in row] for row in Li] for Li in L],
        "R": [[[hx(v) for v in row] for row in Ri] for Ri in R],
        "xi": [[hx(v) for v in row] for row in xi],
    }


def serialise(target, M_hat):
    out = bytearray(target.to_bytes(32, "big"))
    for Mj in M_hat:
        for row in Mj:
            for v in row:
                out += v.to_bytes(32, "big")
    return bytes(out)


def main():
    failures = []

    def require(condition, label):
        print(f"  {'ok  ' if condition else 'FAIL'}  {label}")
        if not condition:
            failures.append(label)

    m, msg = 5, 0xC0FFEE
    target, M_hat, L, R, xi = build(m, seed=1, msg=msg)
    good = artifact_of(L, R, xi)

    print(f"a solved instance (m={m}, k={2 * m + 1}, msg={msg:#x})")
    ok, why = fr.verify_against(m, target, M_hat, good)
    require(ok, f"a genuine solution is accepted -- {why[:60]}")
    require(f"{msg:064x}" in why, "and the message is recovered from the corner entry")

    raw = serialise(target, M_hat)
    t2, m2 = fr.parse_instance(raw, m)
    require(t2 == target and m2 == M_hat, f"the byte layout round-trips ({len(raw)} bytes)")

    print("\nperturbations, each of which must be refused")
    k = 2 * m + 1
    for label, mutate in [
        ("a replaced L[0]", lambda a: a["L"].__setitem__(0, [[f"{1:064x}"] * 4 for _ in range(k)])),
        ("one wrong R entry", lambda a: a["R"][1][0].__setitem__(0, f"{0:064x}")),
        ("one wrong xi entry", lambda a: a["xi"][2].__setitem__(1, f"{7:064x}")),
    ]:
        bad = copy.deepcopy(good)
        mutate(bad)
        ok, _ = fr.verify_against(m, target, M_hat, bad)
        require(not ok, label)

    print("\nmalformed artifacts, each of which must be scored and never raised")
    for label, bad in [
        ("not an object", []),
        ("L absent", {"R": [], "xi": []}),
        ("wrong gate count", {"L": [], "R": [], "xi": []}),
        ("non-hex digits", {**good, "xi": [["z" * 64] * m for _ in range(m)]}),
        ("uppercase hex", {**good, "xi": [["A" * 64] * m for _ in range(m)]}),
        ("not a field element", {**good, "xi": [[f"{P:064x}"] * m for _ in range(m)]}),
        ("an integer, not a string", {**good, "xi": [[1] * m for _ in range(m)]}),
        ("a short row", {**good, "xi": [[f"{1:064x}"] for _ in range(m)]}),
    ]:
        try:
            ok, _ = fr.verify_against(m, target, M_hat, bad)
            require(not ok, label)
        except Exception as exc:  # noqa: BLE001
            require(False, f"{label} -- raised {type(exc).__name__}: {exc}")

    print("\nthe pinned instance")
    embedded = base64.b64decode(fr.INSTANCE_B64)
    require(len(embedded) == 74016, f"is {len(embedded)} bytes, the published size")
    pinned_target, pinned = fr.parse_instance(embedded, fr.M_GATES)
    require(len(pinned) == fr.M_GATES, f"holds {len(pinned)} public matrices")
    require(
        pow(pinned_target, (P - 1) // 2, P) == P - 1,
        "has a quadratic non-residue target, so no witness exists",
    )
    require(
        all(v < P for Mj in pinned for row in Mj for v in row),
        "has every entry inside the field",
    )
    ok, why = fr.check({"L": [], "R": [], "xi": []})
    require(not ok, f"refuses a malformed submission -- {why[:50]}")

    print()
    if failures:
        print(f"FAILED: {len(failures)}")
        for label in failures:
            print(f"  - {label}")
        return 1
    print("SELFTEST OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
