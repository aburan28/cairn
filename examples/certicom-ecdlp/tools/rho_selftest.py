#!/usr/bin/env python3
"""Exercise the rho distinguished-point checkers and the walk they pin.

    python3 examples/certicom-ecdlp/tools/rho_selftest.py

Three things have to agree for a piecework rho objective to be honest, and
none of them is checked by `scripts/check-examples.sh`, which only follows
the pins inside the verifier block:

1. **The checker pins the job it names.** Each `*_rho_dp.py` and
   `*_rho_batch.py` carries the
   SHA-256 of its job document, so the walk is inside the objective's id.
   A job edited after the fact would leave the checker verifying points of a
   walk nobody runs.
2. **The checker and the job describe one curve.** The curve, P, Q, n and
   DP_BITS baked into the checker must be the job's, or a point of the walk
   would fail the checker and the bounty would be unsatisfiable.
3. **The checker accepts a real point and nothing else.** Acceptance is shown
   against a point actually walked with `rho_dp.py` (about 2^16 steps for
   nums-50, a fraction of a second); rejection against the point with one
   coefficient changed, an extra key, a non-canonical y, and a point that is
   on the curve but not distinguished. ECCp-131 is exercised for rejection
   only: a point of its walk costs 2^44 steps, which is the point.

The batch checkers are exercised the same way: a walked batch is accepted,
and a relabelled repeat, a tampered element, a missing provenance field, an
empty or oversized batch and an impossible step count are each refused.
The audit is exercised against the walked elements: each re-walks to itself,
a wrong walker index or step count is caught, and a point of a *private*
walk -- valid, canonical, verifiable, and not where any walker of the job
leads -- is caught too.

The collision arithmetic is proven on a 14-bit instance with a planted
secret: twenty-odd walkers collide, and `collide` recovers the secret.
"""
import json
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
REPO = os.path.dirname(os.path.dirname(ROOT))
sys.path.insert(0, os.path.join(ROOT, "checkers"))
sys.path.insert(0, HERE)

import rho_dp  # noqa: E402

# A 14-bit prime-order curve with a *planted* secret, k = 0x1a2b, from
# `crypto cryptanalysis rho-collab init --curve demo-small --secret 1a2b`.
# Fine here because nothing is paid for it: it exists to show that two walks
# meeting at one point yield k, on an instance whose k is known to compare to.
TINY_JOB = json.loads('''{"version": 1, "name": "selftest", "p": "2717", "a": "3", "b": "6", "generator": {"x": "0", "y": "7b5"}, "target": {"x": "1ab3", "y": "390"}, "order": "2737", "dp_bits": 3, "num_branches": 8, "negation_map": false, "unit_size": 4, "max_steps_per_walker": 0, "seed": 0}''')
TINY_K = 0x1A2B


def sha256_file(path):
    import hashlib

    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def main():
    failures = []

    def require(cond, label):
        print(f"  {'ok  ' if cond else 'FAIL'}  {label}")
        if not cond:
            failures.append(label)

    contexts = {}
    for name in ("nums_50_rho_dp", "eccp131_rho_dp"):
        checker = __import__(name)
        print(f"{name}: the pinned job")
        job_path = os.path.join(REPO, checker.JOB)
        require(os.path.exists(job_path), f"{checker.JOB} exists")
        require(sha256_file(job_path) == checker.JOB_SHA256, "job document hashes to JOB_SHA256")
        job = rho_dp.load_job(job_path)
        require(rho_dp.job_id(job) == checker.JOB_ID, "job id matches JOB_ID")
        ctx = rho_dp.Context(job)
        contexts[name] = (checker, ctx)
        require(
            (ctx.p, ctx.a, ctx.b, ctx.n) == (checker.CURVE_P, checker.CURVE_A, checker.CURVE_B, checker.ORDER_N),
            "curve and order match the job",
        )
        require(ctx.g == (checker.GEN_X, checker.GEN_Y) and ctx.q == (checker.TARGET_X, checker.TARGET_Y),
                "P and Q match the job")
        require(ctx.dp_bits == checker.DP_BITS, "DP_BITS matches the job")

        print(f"{name}: rejection")
        rng = random.Random(name)
        a, b = rng.randrange(1, ctx.n), rng.randrange(1, ctx.n)
        point = ctx.combine(a, b)
        # A random point is on the curve and, with overwhelming probability,
        # not distinguished -- the checker must say which.
        x, y = point
        if 2 * y > ctx.p:
            y, a, b = (-y) % ctx.p, (-a) % ctx.n, (-b) % ctx.n
        art = {"x": format(x, "x"), "y": format(y, "x"), "a": format(a, "x"), "b": format(b, "x")}
        ok, why = checker.check(art)
        require(not ok and "distinguished" in why, f"an undistinguished point is refused for that reason: {why}")
        ok, why = checker.check({"k": "00"})
        require(not ok, f"the answer objective's artifact shape is refused: {why}")
        ok, why = checker.check("not an object")
        require(not ok, f"a non-object is refused: {why}")

    print("nums_50_rho_dp: acceptance, on a point actually walked")
    checker, ctx = contexts["nums_50_rho_dp"]
    rec = ctx.run_walker(0)
    require(rec is not None, "walker 0 reaches a distinguished point")
    steps, x, y, a, b = rec
    art = ctx.artifact(x, y, a, b)
    ok, why = checker.check(art)
    require(ok, f"the pinned checker accepts it after {steps} steps: {why}")
    require(ctx.verify(art)[0], "rho_dp.verify agrees with the checker")
    tampered = dict(art, a=format((int(art["a"], 16) + 1) % ctx.n, "x"))
    require(not checker.check(tampered)[0], "one coefficient changed is refused")
    relabelled = dict(art, walker=0)
    require(not checker.check(relabelled)[0], "an extra key (relabelling) is refused")
    negated = dict(art, y=format((-int(art["y"], 16)) % ctx.p, "x"),
                   a=format((-int(art["a"], 16)) % ctx.n, "x"), b=format((-int(art["b"], 16)) % ctx.n, "x"))
    ok, why = checker.check(negated)
    require(not ok and "canonical" in why, f"the negated copy is refused as non-canonical: {why}")
    padded = dict(art, x="0" + art["x"])
    require(not checker.check(padded)[0], "a leading zero (second spelling of one point) is refused")
    uppercase = dict(art, x=art["x"].upper())
    require(not checker.check(uppercase)[0], "uppercase hex is refused")

    print("nums_50_rho_batch: a walked batch, and what a batch may not do")
    batch_checker = __import__("nums_50_rho_batch")
    require(batch_checker.JOB_SHA256 == checker.JOB_SHA256 and batch_checker.JOB_ID == checker.JOB_ID,
            "the batch checker pins the same job as the single-point checker")
    require((batch_checker.CURVE_P, batch_checker.ORDER_N, batch_checker.DP_BITS)
            == (checker.CURVE_P, checker.ORDER_N, checker.DP_BITS), "and the same curve and DP_BITS")
    elements = []
    for i in range(3):
        rec = ctx.run_walker(i)
        if rec is not None:
            steps, x, y, a, b = rec
            elements.append(ctx.batch_element(i, steps, x, y, a, b))
    require(len(elements) == 3, "walkers 0..2 each reach a distinguished point")
    walked = {"dps": elements}
    ok, why = batch_checker.check(walked)
    require(ok, f"the batch checker accepts the walked batch: {why}")
    require(ctx.verify_batch(walked)[0], "rho_dp.verify_batch agrees with the checker")
    relabelled = json.loads(json.dumps(walked))
    relabelled["dps"].append(dict(elements[0], walker=77, steps=5))
    ok, why = batch_checker.check(relabelled)
    require(not ok and "repeats" in why, f"a point listed twice under another label is refused: {why}")
    tampered = json.loads(json.dumps(walked))
    tampered["dps"][1]["b"] = format((int(elements[1]["b"], 16) + 1) % ctx.n, "x")
    ok, why = batch_checker.check(tampered)
    require(not ok and why.startswith("dps[1]"), f"one bad element refuses the batch, by index: {why}")
    stripped = {"dps": [{k: elements[0][k] for k in ("x", "y", "a", "b")}]}
    require(not batch_checker.check(stripped)[0], "an element without provenance is refused")
    require(not batch_checker.check({"dps": []})[0], "an empty batch is refused")
    require(not batch_checker.check({"dps": [elements[0]] * 1 + [dict(elements[0], walker=1)] })[0],
            "the same point twice, even relabelled, is refused")
    too_many = {"dps": [dict(elements[0], walker=i) for i in range(batch_checker.MAX_BATCH + 1)]}
    require(not batch_checker.check(too_many)[0], f"more than MAX_BATCH ({batch_checker.MAX_BATCH}) is refused")
    require(not batch_checker.check({"dps": [dict(elements[0], steps=batch_checker.MAX_STEPS + 1)]})[0],
            "steps past the walk's cap are refused")

    print("audit: re-walking provenance")
    require(ctx.audit_element(elements[0]) is None, "a walked element re-walks to itself")
    lie = dict(elements[0], walker=elements[1]["walker"])
    why = ctx.audit_element(lie)
    require(why is not None and "different point" in why, f"a point labelled with another walker is caught: {why}")
    lie = dict(elements[0], steps=elements[0]["steps"] + 1)
    why = ctx.audit_element(lie)
    require(why is not None and "steps" in why, f"a wrong step count is caught: {why}")
    # A private-walk point: valid, canonical, verifiable -- and not where any
    # walker of the shared job leads.
    rng = random.Random("private walk")
    private = None
    for _ in range(20000):
        a, b = rng.randrange(1, ctx.n), rng.randrange(1, ctx.n)
        x, y = ctx.combine(a, b)
        if ctx.is_dp((x, y)):
            private = ctx.batch_element(elements[2]["walker"], 1, x, y, a, b)
            break
    if private is None:
        print("  skip  no distinguished point found by sampling (probability 2^-16 per try)")
    else:
        require(batch_checker.check({"dps": [private]})[0], "a private-walk point passes the checker")
        require(ctx.audit_element(private) is not None, "and the audit catches it")

    print("collision on a 14-bit planted instance")
    tiny = rho_dp.Context(TINY_JOB)
    seen = {}
    solved = None
    for i in range(1000):
        rec = tiny.run_walker(i)
        if rec is None:
            continue
        art = tiny.artifact(*rec[1:])
        key = (art["x"], art["y"])
        if key in seen and seen[key]["a"] != art["a"]:
            solved = (i, tiny.solve_collision(seen[key], art))
            break
        seen[key] = art
    require(solved is not None, "two walkers reach one point with different coefficients")
    if solved is not None:
        walker, k = solved
        require(k == TINY_K, f"collide recovers the planted k after {walker + 1} walkers (k = {k:#x})")

    print()
    if failures:
        print(f"{len(failures)} check(s) failed:")
        for label in failures:
            print(f"  - {label}")
        return 1
    print("all rho checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
