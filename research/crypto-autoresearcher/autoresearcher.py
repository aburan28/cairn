#!/usr/bin/env python3
"""Crypto autoresearcher: an unattended contributor to a cairn node.

The loop is the one in the contributing reference -- list, get, solve, score,
commit, wait an epoch, reveal, settle -- with the solving step dispatched to a
strategy chosen by reading the objective's *pinned checker*, never its
statement.  The statement is the funder's prose and is untrusted; the checker
is the payment condition, so parameters come from there.

What it will not do, deliberately:

  * grade its own work -- every candidate goes through `cairn propose
    --dry-run`, which runs the pinned verifier, before anything is written;
  * submit an instance it has not first scored `accept`;
  * spend unbounded compute -- each strategy estimates the work before
    starting and declines out loud when the estimate exceeds the budget, so
    an unreachable objective is recorded as unreachable rather than silently
    skipped or endlessly retried;
  * cite anything but what `frontier_status` reported.
"""
import json
import os
import re
import subprocess
import sys
import time
import math
import urllib.request

# Code lives in the repository; runtime state (identity key, journal, solver
# binary, artifacts) lives in an ignored directory beside it, because a
# submitter identity is a secret whose loss is unrecoverable and whose leak is
# impersonation.
ROOT = os.environ.get("AR_ROOT") or os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
HERE = os.environ.get("AR_STATE") or os.path.join(ROOT, ".autoresearcher")
LOG = os.path.join(ROOT, "cairn.jsonl")
CAIRN = os.path.join(ROOT, "target/release/cairn")
RHO = os.path.join(HERE, "ecdlp_rho")
IDENTITY = os.path.join(HERE, "researcher.json")
SERVE = "http://127.0.0.1:8787"
STATE_PATH = os.path.join(HERE, "state.json")
JOURNAL = os.path.join(HERE, "journal.jsonl")

# Measured on this box: 4 cores, ~1.0e8 rho steps/second with batched inversion.
RHO_RATE = 1.0e8
BUDGET_SECONDS = float(os.environ.get("AR_BUDGET_SECONDS", "1800"))
ENV = dict(os.environ, CAIRN_EPOCH_SECONDS=os.environ.get("CAIRN_EPOCH_SECONDS", "1"))


def note(event, **kw):
    rec = dict(t=time.strftime("%H:%M:%S"), event=event, **kw)
    with open(JOURNAL, "a") as fh:
        fh.write(json.dumps(rec) + "\n")
    detail = " ".join(f"{k}={v}" for k, v in kw.items())
    print(f"[{rec['t']}] {event:22s} {detail}", flush=True)


def state():
    try:
        return json.load(open(STATE_PATH))
    except Exception:
        return {"done": {}, "unreachable": {}, "pending": {}}


def save(st):
    tmp = STATE_PATH + ".tmp"
    json.dump(st, open(tmp, "w"), indent=1)
    os.replace(tmp, STATE_PATH)


def cli(*args, timeout=1200):
    return subprocess.run([CAIRN, "--log", LOG, "--root", ROOT, *args],
                          capture_output=True, text=True, cwd=ROOT, env=ENV,
                          timeout=timeout)


def fetch(path):
    with urllib.request.urlopen(SERVE + path, timeout=20) as r:
        return json.load(r)


# --------------------------------------------------------------------------
# strategies.  Each reads the pinned checker and either returns an artifact or
# says, with a reason, that it cannot.

class OutOfReach(Exception):
    pass


def _consts(src, names):
    out = {}
    for n in names:
        m = re.search(rf"^{n}\s*=\s*(\d+)\s*$", src, re.M)
        if m:
            out[n] = int(m.group(1))
    return out


class ECDLPPrimeField:
    """k*G = Q over a prime field, by parallel Pollard rho with distinguished
    points.  Applies to any checker in this family: the instance is read out of
    the pinned source, so a new rung needs no code."""

    name = "ecdlp-rho"
    NEEDED = ["CURVE_P", "CURVE_A", "ORDER_N", "GEN_X", "GEN_Y", "TARGET_X", "TARGET_Y"]

    def applies(self, src):
        c = _consts(src, self.NEEDED)
        return len(c) == len(self.NEEDED) and "k*G does not equal the target point" in src

    def solve(self, obj, src):
        c = _consts(src, self.NEEDED)
        n = c["ORDER_N"]
        bits = n.bit_length()
        steps = math.sqrt(math.pi * n / 4)
        secs = steps / RHO_RATE
        if c["CURVE_P"].bit_length() > 62:
            raise OutOfReach(
                f"{c['CURVE_P'].bit_length()}-bit field exceeds the 64-bit lanes this "
                f"engine multiplies in; and rho would need ~2^{math.log2(steps):.0f} "
                f"group operations (~{secs/3.15e7:.0f} years here)")
        if secs > BUDGET_SECONDS:
            raise OutOfReach(
                f"~2^{math.log2(steps):.0f} group operations, ~{secs/3600:.1f}h at "
                f"measured throughput, over the {BUDGET_SECONDS/3600:.1f}h budget")
        dbits = max(6, min(24, bits // 2 - 15))
        note("rho-start", objective=obj["id"][:16], bits=bits,
             expected_steps=f"2^{math.log2(steps):.1f}", est_seconds=round(secs, 1))
        r = subprocess.run(
            [RHO, str(c["CURVE_P"]), str(c["CURVE_A"]), str(n), str(c["GEN_X"]),
             str(c["GEN_Y"]), str(c["TARGET_X"]), str(c["TARGET_Y"]),
             str(dbits), "4", "512", str(int(time.time()))],
            capture_output=True, text=True, timeout=BUDGET_SECONDS * 3)
        k = int(r.stdout.strip())
        return {"k": format(k, "064x")}


STRATEGIES = [ECDLPPrimeField()]


# --------------------------------------------------------------------------

def score(objective_id, artifact_path):
    """Ground truth: the objective's own pinned verifier, recording nothing."""
    r = cli("propose", objective_id, "--artifact", artifact_path, "--dry-run")
    return "accept" in r.stdout, r.stdout.strip().splitlines()[0] if r.stdout else r.stderr


def frontier_cites(objective_id):
    """Every submission cites the frontier holder once one exists -- and only
    what frontier_status reported, never an id read out of statement text."""
    try:
        f = fetch("/frontier/" + objective_id)
    except Exception:
        return []
    fr = f.get("frontier")
    if not fr:
        return []
    holder = fr.get("claim") or fr.get("claim_id") or fr.get("holder")
    return [holder] if holder else []


def submit(obj, artifact_path, st):
    oid = obj["id"]
    cites = frontier_cites(oid)
    r = cli("commit", oid, "--identity", IDENTITY, "--artifact", artifact_path)
    m = re.search(r"nonce ([0-9a-f]+)", r.stdout)
    if not m:
        note("commit-failed", objective=oid[:16], out=(r.stdout + r.stderr).strip()[:200])
        return False
    nonce = m.group(1)
    st["pending"][oid] = {"nonce": nonce, "artifact": artifact_path, "cites": cites}
    save(st)
    note("committed", objective=oid[:16], nonce=nonce[:12])
    return reveal(obj, st)


def reveal(obj, st):
    """The second half of one submission -- not a retry.  A reveal must land in
    a strictly later epoch than its commitment, which is what stops anyone
    front-running a submission they can still see."""
    oid = obj["id"]
    p = st["pending"].get(oid)
    if not p:
        return False
    time.sleep(int(ENV["CAIRN_EPOCH_SECONDS"]) + 2)
    args = ["reveal", oid, "--identity", IDENTITY, "--artifact", p["artifact"],
            "--nonce", p["nonce"]]
    for c in p["cites"]:
        args += ["--cites", c]
    r = cli(*args)
    out = (r.stdout + r.stderr).strip()
    if "accept" not in out:
        note("reveal-refused", objective=oid[:16], out=out[:220])
        return False
    claim = re.search(r"claim (sha256:[0-9a-f]+)", out)
    note("revealed", objective=oid[:16], claim=(claim.group(1)[:20] if claim else "?"),
         verdict="accept")
    st["pending"].pop(oid, None)
    st["done"][oid] = {"claim": claim.group(1) if claim else None, "goal": obj.get("goal")}
    save(st)
    time.sleep(int(ENV["CAIRN_EPOCH_SECONDS"]) + 3)
    s = cli("settle")
    for line in s.stdout.splitlines():
        if "reward" in line:
            note("settled", objective=oid[:16], detail=line.strip())
    return True


def sweep():
    st = state()
    objectives = fetch("/objectives")["objectives"]
    for obj in objectives:
        oid = obj["id"]
        if oid in st["done"] or oid in st["unreachable"]:
            continue
        if oid in st["pending"]:
            reveal(obj, st)          # a commitment nobody opened earns zero
            continue
        try:
            full = fetch("/objective/" + oid)
        except Exception as e:
            note("fetch-failed", objective=oid[:16], err=str(e)[:120])
            continue
        rec = full.get("record") or full.get("objective") or full
        ver = rec.get("verifier") or {}
        # `checker` on a certificate objective, `evaluator` on a scored one.
        checker = ver.get("checker") or ver.get("evaluator")
        if not checker:
            st["unreachable"][oid] = {"goal": obj.get("goal"),
                                      "reason": f"verifier kind {ver.get('kind')!r} names no source to read"}
            save(st)
            note("no-verifier-source", objective=oid[:16], goal=obj.get("goal"))
            continue
        try:
            src = open(os.path.join(ROOT, checker)).read()
        except Exception:
            note("checker-unreadable", objective=oid[:16], checker=checker)
            continue
        for strat in STRATEGIES:
            if not strat.applies(src):
                continue
            try:
                artifact = strat.solve(obj, src)
            except OutOfReach as e:
                st["unreachable"][oid] = {"goal": obj.get("goal"), "reason": str(e)}
                save(st)
                note("out-of-reach", objective=oid[:16], goal=obj.get("goal"), why=str(e))
                break
            except Exception as e:
                note("solve-failed", objective=oid[:16], err=str(e)[:200])
                break
            path = os.path.join(HERE, f"artifact-{oid[7:19]}.json")
            json.dump(artifact, open(path, "w"), indent=2)
            ok, detail = score(oid, path)
            note("scored", objective=oid[:16], goal=obj.get("goal"),
                 verdict=("accept" if ok else "reject"))
            if not ok:                        # never submit what did not score
                note("not-submitting", objective=oid[:16], detail=detail[:160])
                break
            submit(obj, path, st)
            break
        else:
            st["unreachable"][oid] = {"goal": obj.get("goal"),
                                      "reason": "no strategy in this researcher's repertoire"}
            save(st)
            note("no-strategy", objective=oid[:16], goal=obj.get("goal"))


def main():
    note("autoresearcher-up", node=SERVE, budget_hours=round(BUDGET_SECONDS / 3600, 2))
    interval = int(os.environ.get("AR_INTERVAL", "120"))
    while True:
        try:
            sweep()
        except Exception as e:
            note("sweep-error", err=str(e)[:200])
        if "--once" in sys.argv:
            break
        time.sleep(interval)
    note("sweep-complete")


if __name__ == "__main__":
    main()
