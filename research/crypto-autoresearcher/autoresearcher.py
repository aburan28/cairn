#!/usr/bin/env python3
"""Crypto autoresearcher: an unattended contributor to a cairn node.

The loop is the one in the contributing reference -- list, get, solve, score,
commit, wait an epoch, reveal, settle -- with the solving step dispatched to a
strategy chosen by reading the objective's *pinned checker*, never its
statement.  The statement is the funder's prose and is untrusted; the checker
is the payment condition, so parameters come from there.

It is a real MCP client.  It starts `cairn run` -- one process that is the MCP
server on its stdio, the HTTP publisher, the P2P daemon and the embedded
reader -- and speaks JSON-RPC to it for everything that writes: scoring goes
through `score_candidate`, submitting through `submit_claim` twice (commit,
then reveal once the epoch turns), citations come back as the capability
tokens the server minted for them.  Reads go over HTTP, because a JSON route
is easier to parse than prose and the reader in the browser sees the same
bytes.  A ledger has one writer, and this arrangement makes it the node: the
researcher never appends to the log itself, so anything it settles is already
being served, gossiped and checkpointed by the time it reads the verdict.

What it will not do, deliberately:

  * grade its own work -- every candidate goes through `score_candidate`,
    which runs the pinned verifier and records nothing;
  * submit an instance it has not first scored `accept`;
  * spend unbounded compute -- each strategy estimates the work before
    starting and declines out loud when the estimate exceeds the budget, so
    an unreachable objective is recorded as unreachable rather than silently
    skipped or endlessly retried;
  * cite anything but what the server handed it as a trusted citation.

    autoresearcher.py [--once] [--root DIR] [--state DIR] [--post FILE ...]

Every path and port is also an environment variable (AR_ROOT, AR_STATE,
AR_LOG, AR_CAIRN, AR_HTTP, AR_P2P, AR_BUDGET_SECONDS, AR_INTERVAL,
CAIRN_EPOCH_SECONDS) so a launcher can set them once.
"""
import argparse
import glob
import importlib.util
import json
import math
import os
import queue
import re
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

# Code lives in the repository; runtime state (identity key, journal, solver
# binaries, artifacts, the node's own log and keys) lives in an ignored
# directory beside it, because a submitter identity is a secret whose loss is
# unrecoverable and whose leak is impersonation.
HERE_SRC = os.path.dirname(os.path.abspath(__file__))
ROOT = os.environ.get("AR_ROOT") or os.path.dirname(os.path.dirname(HERE_SRC))
STATE = os.environ.get("AR_STATE") or os.path.join(ROOT, ".autoresearcher")
LOG = os.environ.get("AR_LOG") or os.path.join(STATE, "cairn.jsonl")
# Not 8080/9000: those are what an operator's own `cairn run` binds, and the
# researcher's node is a second node on the same machine.
HTTP = os.environ.get("AR_HTTP", "127.0.0.1:8090")
P2P = os.environ.get("AR_P2P", "127.0.0.1:9010")
BUDGET_SECONDS = float(os.environ.get("AR_BUDGET_SECONDS", "1800"))
INTERVAL = int(os.environ.get("AR_INTERVAL", "120"))
EPOCH_SECONDS = int(os.environ.get("CAIRN_EPOCH_SECONDS", "5"))
FINALITY_EPOCHS = int(os.environ.get("CAIRN_FINALITY_EPOCHS", "1"))
THREADS = os.cpu_count() or 4

IDENTITY = os.path.join(STATE, "researcher.json")
STATE_PATH = os.path.join(STATE, "state.json")
STATUS_PATH = os.path.join(STATE, "status.json")
JOURNAL = os.path.join(STATE, "journal.jsonl")
NODE_LOG = os.path.join(STATE, "node.log")

# Measured on this box (14 cores): ~6e7 rho steps per second in total with
# batched inversion, ~1.5e7 MD5 compressions per second on one core.
RHO_RATE = 4.5e6 * THREADS
MD5_RATE = 1.5e7


def cairn_binary():
    for candidate in (os.environ.get("AR_CAIRN"),
                      os.path.join(ROOT, "bin", "cairn"),
                      os.path.join(ROOT, "target", "release", "cairn")):
        if candidate and os.access(candidate, os.X_OK):
            return candidate
    sys.exit("no cairn binary: run `make build` (or set AR_CAIRN)")


def solver(name):
    """A compiled engine beside the state, built from the source beside this
    file the first time it is needed or whenever the source is newer."""
    src = os.path.join(HERE_SRC, name + ".c")
    out = os.path.join(STATE, name)
    if not os.path.exists(out) or os.path.getmtime(out) < os.path.getmtime(src):
        note("compiling", engine=name)
        subprocess.run(["cc", "-O3", "-march=native", "-pthread", "-o", out, src],
                       check=True)
    return out


# --------------------------------------------------------------------------
# journal, state, status, progress

PROGRESS_PATH = os.path.join(STATE, "progress.json")


def run_engine(argv, objective, engine, timeout):
    """Run a solver, mirroring its stderr into progress.json as it goes so a
    dashboard can show the walk instead of a spinner.  Returns (stdout,
    last stderr line); raises on a non-zero exit."""
    started = time.time()
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    last = ""

    def publish(done=False):
        doc = {"objective": objective, "engine": engine, "started": started,
               "elapsed": round(time.time() - started, 1), "line": last.strip(), "done": done}
        tmp = PROGRESS_PATH + ".tmp"
        json.dump(doc, open(tmp, "w"))
        os.replace(tmp, PROGRESS_PATH)

    publish()
    # The rho engine redraws one line with \r; split on either terminator.
    buf = ""
    tick = time.time()
    while True:
        ch = proc.stderr.read(1)
        if not ch:
            break
        if ch in "\r\n":
            if buf.strip():
                last = buf
            buf = ""
            if time.time() - tick > 0.5:
                publish()
                tick = time.time()
        else:
            buf += ch
        if time.time() - started > timeout:
            proc.kill()
            raise TimeoutError(f"{engine} exceeded {timeout:.0f}s")
    out = proc.stdout.read()
    proc.wait()
    if buf.strip():
        last = buf
    publish(done=True)
    if proc.returncode != 0:
        raise RuntimeError(f"{engine} failed: {last.strip()[-200:]}")
    return out, last.strip()

def note(event, **kw):
    rec = dict(t=time.strftime("%Y-%m-%dT%H:%M:%S"), event=event, **kw)
    os.makedirs(STATE, exist_ok=True)
    with open(JOURNAL, "a") as fh:
        fh.write(json.dumps(rec) + "\n")
    detail = " ".join(f"{k}={v}" for k, v in kw.items())
    print(f"[{rec['t'][11:]}] {event:22s} {detail}", flush=True)


def state():
    try:
        return json.load(open(STATE_PATH))
    except Exception:
        return {"done": {}, "unreachable": {}, "pending": {}}


def save(st):
    tmp = STATE_PATH + ".tmp"
    json.dump(st, open(tmp, "w"), indent=1)
    os.replace(tmp, STATE_PATH)


LAST_OBJECTIVES = []


def publish_status(node, st, objectives, phase, submitter):
    """One JSON file with everything a dashboard needs, rewritten on every
    change: the launcher reads this rather than parsing the journal.  With
    `objectives` None the last list is reused, so a stop does not erase the
    table it is reporting the end of."""
    global LAST_OBJECTIVES
    if objectives is None:
        objectives = LAST_OBJECTIVES
    LAST_OBJECTIVES = objectives
    rows = []
    for obj in objectives:
        oid = obj["id"]
        row = {"id": oid, "goal": obj.get("goal"), "reward": obj.get("reward"),
               "verifier": obj.get("verifier_kind"), "status": "open"}
        if oid in st["done"]:
            row.update(status="solved", **st["done"][oid])
        elif oid in st["unreachable"]:
            row.update(status="unreachable", **st["unreachable"][oid])
        elif oid in st["pending"]:
            row.update(status="committed", **st["pending"][oid])
        rows.append(row)
    doc = {"updated": time.strftime("%Y-%m-%dT%H:%M:%S"), "phase": phase,
           "http": f"http://{HTTP}", "submitter": submitter, "log": LOG,
           "epoch_seconds": EPOCH_SECONDS, "pid": os.getpid(),
           "node_pid": node.proc.pid if node and node.proc else None,
           "balance": st.get("balance"), "objectives": rows}
    tmp = STATUS_PATH + ".tmp"
    json.dump(doc, open(tmp, "w"), indent=1)
    os.replace(tmp, STATUS_PATH)


# --------------------------------------------------------------------------
# the node: `cairn run`, MCP on its stdio, HTTP for reads

class Node:
    def __init__(self, cairn):
        self.cairn = cairn
        self.proc = None
        self.next_id = 1
        self.inbox = queue.Queue()
        self.citations = {}

    def start(self):
        os.makedirs(STATE, exist_ok=True)
        env = dict(os.environ, CAIRN_EPOCH_SECONDS=str(EPOCH_SECONDS),
                   CAIRN_FINALITY_EPOCHS=str(FINALITY_EPOCHS))
        argv = [self.cairn, "--log", LOG, "--root", ROOT, "run",
                "--identity", os.path.join(STATE, "node.identity.json"),
                "--root-key", os.path.join(STATE, "root.key"),
                "--checkpoint", os.path.join(STATE, "checkpoint.json"),
                "--listen", P2P, "--serve", HTTP,
                "--queue", os.path.join(STATE, "queue"),
                "--mcp-identity", IDENTITY]
        self.stderr = open(NODE_LOG, "ab")
        self.proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=self.stderr, cwd=ROOT, env=env)
        threading.Thread(target=self._reader, daemon=True).start()
        init = self.rpc("initialize", {"protocolVersion": "2025-06-18",
                                       "clientInfo": {"name": "crypto-autoresearcher"}})
        self.notify("notifications/initialized")
        deadline = time.time() + 60
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"cairn run exited at startup ({self.proc.returncode}); see {NODE_LOG}")
            try:
                with urllib.request.urlopen(f"http://{HTTP}/health", timeout=2) as r:
                    if r.status == 200:
                        break
            except Exception:
                pass
            time.sleep(0.25)
        else:
            raise RuntimeError(f"the node never answered on http://{HTTP}; see {NODE_LOG}")
        return init

    def _reader(self):
        for line in self.proc.stdout:
            try:
                self.inbox.put(json.loads(line))
            except json.JSONDecodeError:
                self.inbox.put({"_garbage": line.decode("utf-8", "replace")})
        # EOF: the node is gone. Wake whoever is waiting rather than letting
        # them sit out a timeout meant for a slow verifier.
        self.inbox.put({"_eof": True})

    def _send(self, msg):
        self.proc.stdin.write((json.dumps(msg) + "\n").encode())
        self.proc.stdin.flush()

    def notify(self, method, params=None):
        self._send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def rpc(self, method, params, timeout=1800):
        rid = self.next_id
        self.next_id += 1
        self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
        deadline = time.time() + timeout
        while True:
            try:
                msg = self.inbox.get(timeout=max(0.1, deadline - time.time()))
            except queue.Empty:
                raise TimeoutError(f"no answer to {method} in {timeout}s")
            if "_garbage" in msg:
                raise RuntimeError("the node wrote something on stdout that is not JSON-RPC: "
                                   + msg["_garbage"][:200])
            if "_eof" in msg:
                self.proc.wait(timeout=5)
                why = open(NODE_LOG, "rb").read()[-400:].decode("utf-8", "replace").strip()
                raise RuntimeError(f"the node exited (status {self.proc.returncode}) during {method}: {why}")
            if msg.get("id") == rid:
                if "error" in msg:
                    raise RuntimeError(f"{method}: {msg['error']}")
                return msg["result"]

    def call(self, tool, **arguments):
        """One MCP tool call.  Returns (text, is_error); every trusted citation
        the server has minted so far is remembered from structuredContent,
        which is the only place a claim id may legitimately come from."""
        result = self.rpc("tools/call", {"name": tool, "arguments": arguments})
        for c in (result.get("structuredContent") or {}).get("citations", []):
            self.citations[c["claim_id"]] = c["capability"]
        text = "".join(b.get("text", "") for b in result.get("content", []))
        return text, bool(result.get("isError"))

    def get(self, path):
        with urllib.request.urlopen(f"http://{HTTP}{path}", timeout=20) as r:
            return json.load(r)

    def stop(self):
        if not self.proc:
            return
        try:
            self.proc.stdin.close()      # the node stops when its MCP stdin closes
            self.proc.wait(timeout=15)
        except Exception:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except Exception:
                self.proc.kill()
        self.stderr.close()
        self.proc = None


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


def _load_checker(path):
    """Import the pinned checker as a module.  It is the payment condition,
    so running its own derivation (`_derive_q`) is reading the instance,
    not trusting the statement."""
    spec = importlib.util.spec_from_file_location("pinned_checker", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _duration(secs):
    """Wall-clock at measured throughput, in the unit that reads honestly:
    '0 years' for a fortnight of compute is the wrong sentence."""
    if secs < 3600:
        return f"{secs / 60:.0f} minutes"
    if secs < 86400 * 3:
        return f"{secs / 3600:.1f} hours"
    if secs < 3.15e7:
        return f"{secs / 86400:.0f} days"
    return f"{secs / 3.15e7:,.0f} years"


class ECDLPPrimeField:
    """k*G = Q over a prime field, by parallel Pollard rho with distinguished
    points.  Applies to both spellings of the instance in examples/: the
    `CURVE_P ... TARGET_Y` family, and the first-blood family whose Q is
    derived from a public seed by the checker itself."""

    name = "ecdlp-rho"
    A_NAMES = ["CURVE_P", "CURVE_A", "ORDER_N", "GEN_X", "GEN_Y", "TARGET_X", "TARGET_Y"]
    B_NAMES = ["P", "A", "B", "N", "GX", "GY"]

    def _instance(self, src, path):
        a = _consts(src, self.A_NAMES)
        if len(a) == len(self.A_NAMES):
            return dict(p=a["CURVE_P"], a=a["CURVE_A"], n=a["ORDER_N"],
                        gx=a["GEN_X"], gy=a["GEN_Y"],
                        target=lambda: (a["TARGET_X"], a["TARGET_Y"]), hex_k=True)
        b = _consts(src, self.B_NAMES)
        if len(b) == len(self.B_NAMES) and "_derive_q" in src:
            return dict(p=b["P"], a=b["A"], n=b["N"], gx=b["GX"], gy=b["GY"],
                        target=lambda: _load_checker(path)._derive_q(), hex_k=False)
        return None

    def applies(self, src, path):
        return self._instance(src, path) is not None and "k*G does not equal" in src

    def solve(self, obj, src, path):
        inst = self._instance(src, path)
        n = inst["n"]
        bits = n.bit_length()
        steps = math.sqrt(math.pi * n / 4)
        secs = steps / RHO_RATE
        if inst["p"].bit_length() > 62:
            raise OutOfReach(
                f"{inst['p'].bit_length()}-bit field exceeds the 64-bit lanes this "
                f"engine multiplies in; rho would need ~2^{math.log2(steps):.0f} "
                f"group operations (~{_duration(secs)} here)")
        if secs > BUDGET_SECONDS:
            raise OutOfReach(
                f"~2^{math.log2(steps):.0f} group operations, ~{secs / 3600:.1f}h at "
                f"measured throughput, over the {BUDGET_SECONDS / 3600:.1f}h budget")
        qx, qy = inst["target"]()
        dbits = max(6, min(24, bits // 2 - 15))
        note("rho-start", objective=obj["id"][:16], bits=bits,
             expected_steps=f"2^{math.log2(steps):.1f}", est_seconds=round(secs, 1),
             threads=THREADS)
        t0 = time.time()
        out, last = run_engine(
            [solver("ecdlp_rho"), str(inst["p"]), str(inst["a"]), str(n), str(inst["gx"]),
             str(inst["gy"]), str(qx), str(qy), str(dbits), str(THREADS), "512",
             str(int(time.time()))],
            obj["id"], "ecdlp_rho", BUDGET_SECONDS * 3)
        if not out.strip():
            raise RuntimeError("rho engine printed no answer: " + last[-200:])
        k = int(out.strip())
        note("rho-solved", objective=obj["id"][:16], seconds=round(time.time() - t0, 1),
             detail=last[:80])
        return {"k": format(k, "064x") if inst["hex_k"] else k}


class HashCollision:
    """A conforming pair behind the pinned prefix, for the MD4-family checkers
    in examples/hash-differential.  What it can actually do is the generic
    birthday search, which is in range only for a truncated digest: the full
    128- and 160-bit instances need a differential-path attack this
    repertoire does not yet carry, and it says so rather than trying."""

    name = "hash-birthday"

    def _instance(self, src):
        m = re.search(r'^PREFIX\s*=\s*bytes\.fromhex\(\s*((?:"[0-9a-f]+"\s*)+)\)', src, re.M)
        c = _consts(src, ["STEPS", "DIGEST_BYTES"])
        if not m or len(c) != 2:
            return None
        prefix = "".join(re.findall(r'"([0-9a-f]+)"', m.group(1)))
        # The function is named in the checker's first line ("a conforming
        # pair for SHA-1 reduced to 64 steps"); the body mentions the others
        # in prose, so a search over all of it names the wrong one.
        head = src.split("\n", 1)[0]
        m2 = re.search(r"for (MD4|MD5|SHA-0|SHA-1)", head)
        func = m2.group(1).replace("-", "").lower() if m2 else "?"
        return dict(prefix=prefix, steps=c["STEPS"], digest_bytes=c["DIGEST_BYTES"], func=func)

    def applies(self, src, path):
        return self._instance(src) is not None and "m_prime" in src

    def solve(self, obj, src, path):
        inst = self._instance(src)
        bits = 8 * inst["digest_bytes"]
        birthday = 2.0 ** (bits / 2)
        if inst["digest_bytes"] > 7:
            raise OutOfReach(
                f"a full {bits}-bit collision on {inst['func'].upper().replace('SHA', 'SHA-')} needs a "
                f"differential-path attack, which this repertoire does not carry; "
                f"the generic birthday bound is 2^{bits // 2} compressions "
                f"(~{_duration(birthday / MD5_RATE)} here)")
        if inst["func"] != "md5":
            raise OutOfReach(f"the truncated-digest engine speaks MD5 only, not {inst['func']}")
        secs = 3 * birthday / MD5_RATE
        if secs > BUDGET_SECONDS:
            raise OutOfReach(f"~2^{bits // 2} compressions, ~{secs / 3600:.1f}h, over budget")
        note("birthday-start", objective=obj["id"][:16], bits=bits, steps=inst["steps"],
             expected=f"2^{bits // 2}", est_seconds=round(secs, 1))
        t0 = time.time()
        out, last = run_engine([solver("md5_birthday"), inst["prefix"], str(inst["steps"]),
                                str(inst["digest_bytes"]), str(int(time.time()))],
                               obj["id"], "md5_birthday", BUDGET_SECONDS * 3)
        lines = out.split()
        if len(lines) != 2:
            raise RuntimeError("birthday engine printed no pair: " + last[-200:])
        note("birthday-solved", objective=obj["id"][:16], seconds=round(time.time() - t0, 1),
             detail=last[:80])
        return {"m": lines[0], "m_prime": lines[1]}


STRATEGIES = [ECDLPPrimeField(), HashCollision()]


# --------------------------------------------------------------------------
# the contributor loop, over MCP

def score(node, oid, artifact):
    """Ground truth: the objective's own pinned verifier, recording nothing."""
    text, err = node.call("score_candidate", objective_id=oid, artifact=artifact)
    first = text.strip().splitlines()[0] if text.strip() else ""
    status = first.split(":", 1)[0].strip() if ":" in first else ("error" if err else "?")
    return status, first


def frontier_citation(node, oid):
    """Every submission cites the frontier holder once one exists -- and only
    with the capability the server minted for it.  `frontier_status` both
    reports the holder and offers the token; the HTTP route confirms the id."""
    text, _ = node.call("frontier_status", objective_id=oid)
    holder = None
    try:
        fr = node.get("/frontier/" + oid).get("frontier")
        holder = fr and fr.get("claim_id")
    except Exception:
        pass
    if not holder:
        m = re.search(r'"claim_id":"(sha256:[0-9a-f]+)"', text)
        holder = m.group(1) if m else None
    if holder and holder in node.citations:
        return [{"claim_id": holder, "capability": node.citations[holder]}]
    return []


def submit(node, obj, artifact, st, submitter, strategy=None, seconds=None):
    """commit, wait for the epoch to turn, reveal: two calls to submit_claim
    with the same artifact.  A commitment nobody opens is never paid."""
    oid = obj["id"]
    cites = frontier_citation(node, oid)
    text, err = node.call("submit_claim", objective_id=oid, submitter=submitter,
                          artifact=artifact, cites=cites)
    if err:
        note("commit-refused", objective=oid[:16], why=text.strip()[:220])
        return False
    m = re.search(r"[Cc]ommitted in epoch (\d+)", text)
    if not m:
        note("commit-unexpected", objective=oid[:16], out=text.strip()[:220])
        return False
    st["pending"][oid] = {"artifact": artifact, "cites": cites, "epoch": int(m.group(1)),
                          "goal": obj.get("goal"), "strategy": strategy, "seconds": seconds}
    save(st)
    note("committed", objective=oid[:16], epoch=int(m.group(1)))
    return reveal(node, obj, st, submitter)


def reveal(node, obj, st, submitter):
    """The second half of one submission -- not a retry.  A reveal must land in
    a strictly later epoch than its commitment, which is what stops anyone
    front-running a submission they can still see."""
    oid = obj["id"]
    p = st["pending"].get(oid)
    if not p:
        return False
    deadline = time.time() + 6 * EPOCH_SECONDS + 30
    while time.time() < deadline:
        time.sleep(EPOCH_SECONDS + 1)
        text, err = node.call("submit_claim", objective_id=oid, submitter=submitter,
                              artifact=p["artifact"], cites=p["cites"])
        if "Already committed" in text:
            continue
        if err:
            note("reveal-refused", objective=oid[:16], why=text.strip()[:220])
            if "can no longer be opened" in text or "no longer" in text:
                st["pending"].pop(oid, None)
                save(st)
            return False
        claim = re.search(r"^claim (sha256:[0-9a-f]+)", text, re.M)
        verdict = re.search(r"^verdict: (\w+)", text, re.M)
        if not claim:
            note("reveal-unexpected", objective=oid[:16], out=text.strip()[:220])
            return False
        st["pending"].pop(oid, None)
        st["done"][oid] = {"claim": claim.group(1), "goal": obj.get("goal"),
                           "verdict": verdict.group(1) if verdict else "?",
                           "reward": 0, "settled": False, "settled_at": None,
                           "artifact": p.get("artifact"), "strategy": p.get("strategy"),
                           "seconds": p.get("seconds")}
        save(st)
        note("revealed", objective=oid[:16], claim=claim.group(1)[:20],
             verdict=st["done"][oid]["verdict"])
        return True
    note("reveal-timeout", objective=oid[:16])
    return False


def settle(node, st, submitter):
    """Settlement is deferred to the close of the reveal epoch plus the
    finality delay, and any later call applies it.  Ask about each unsettled
    claim until the answer changes or the wait is clearly over."""
    open_claims = {oid: d for oid, d in st["done"].items()
                   if d.get("claim") and not d.get("settled")}
    if not open_claims:
        return
    time.sleep((FINALITY_EPOCHS + 1) * EPOCH_SECONDS + 2)
    for oid, d in open_claims.items():
        for _ in range(4):
            text, err = node.call("get_claim", claim_id=d["claim"])
            m = re.search(r"^settled: yes, reward (\d+)", text, re.M)
            if m:
                d.update(settled=True, reward=int(m.group(1)),
                         settled_at=time.strftime("%Y-%m-%dT%H:%M:%S"))
                note("settled", objective=oid[:16], reward=int(m.group(1)))
                break
            time.sleep(EPOCH_SECONDS + 1)
        else:
            note("settle-pending", objective=oid[:16])
    st["balance"] = balance(node, submitter)
    save(st)


def balance(node, submitter):
    """What the identity holds, from the CLI's read-only view of the node's
    own log.  Reads take no lock, so this is safe while the node runs."""
    env = dict(os.environ, CAIRN_EPOCH_SECONDS=str(EPOCH_SECONDS),
               CAIRN_FINALITY_EPOCHS=str(FINALITY_EPOCHS))
    r = subprocess.run([node.cairn, "--log", LOG, "--root", ROOT, "balances"],
                       capture_output=True, text=True, cwd=ROOT, env=env, timeout=120)
    # `balances` prints names truncated to eight characters, so match the
    # prefix; a second identity sharing eight hex digits is not a concern
    # for a table this size.
    m = re.search(rf"^\s*{re.escape(submitter[:8])}\S*\s+spendable\s+(\d+)", r.stdout, re.M)
    return int(m.group(1)) if m else None


def objectives_of(node):
    return node.get("/objectives")["objectives"]


def sweep(node, st, submitter):
    objectives = objectives_of(node)
    publish_status(node, st, objectives, "sweeping", submitter)
    for obj in objectives:
        oid = obj["id"]
        if oid in st["done"] or oid in st["unreachable"]:
            continue
        if oid in st["pending"]:
            reveal(node, obj, st, submitter)      # a commitment nobody opened earns zero
            continue
        try:
            full = node.get("/objective/" + oid)
        except Exception as e:
            note("fetch-failed", objective=oid[:16], err=str(e)[:120])
            continue
        rec = full.get("record") or full
        ver = rec.get("verifier") or {}
        # `checker` on a certificate objective, `evaluator` on a scored one.
        checker = ver.get("checker") or ver.get("evaluator")
        if not checker:
            st["unreachable"][oid] = {"goal": obj.get("goal"),
                                      "reason": f"verifier kind {ver.get('kind')!r} names no source to read"}
            save(st)
            note("no-verifier-source", objective=oid[:16], goal=obj.get("goal"))
            continue
        path = os.path.join(ROOT, checker)
        try:
            src = open(path).read()
        except Exception:
            note("checker-unreadable", objective=oid[:16], checker=checker)
            continue
        publish_status(node, st, objectives, f"working {obj.get('goal')}", submitter)
        for strat in STRATEGIES:
            if not strat.applies(src, path):
                continue
            t_solve = time.time()
            try:
                artifact = strat.solve(obj, src, path)
            except OutOfReach as e:
                st["unreachable"][oid] = {"goal": obj.get("goal"), "reason": str(e),
                                          "strategy": strat.name}
                save(st)
                note("out-of-reach", objective=oid[:16], goal=obj.get("goal"), why=str(e))
                break
            except Exception as e:
                note("solve-failed", objective=oid[:16], err=str(e)[:200])
                break
            artifact_path = os.path.join(STATE, f"artifact-{oid[7:19]}.json")
            json.dump(artifact, open(artifact_path, "w"), indent=2)
            status, detail = score(node, oid, artifact)
            note("scored", objective=oid[:16], goal=obj.get("goal"), verdict=status)
            if status != "accept":                # never submit what did not score
                note("not-submitting", objective=oid[:16], detail=detail[:160])
                break
            submit(node, obj, artifact, st, submitter, strategy=strat.name,
                   seconds=round(time.time() - t_solve, 1))
            publish_status(node, st, objectives, "sweeping", submitter)
            break
        else:
            st["unreachable"][oid] = {"goal": obj.get("goal"),
                                      "reason": "no strategy in this researcher's repertoire"}
            save(st)
            note("no-strategy", objective=oid[:16], goal=obj.get("goal"))
    settle(node, st, submitter)
    st["balance"] = balance(node, submitter)
    save(st)
    publish_status(node, st, objectives_of(node), "idle", submitter)


# --------------------------------------------------------------------------

def ensure_identity(cairn):
    if os.path.exists(IDENTITY):
        return json.load(open(IDENTITY))["public"]
    os.makedirs(STATE, exist_ok=True)
    subprocess.run([cairn, "identity", "--out", IDENTITY], check=True, capture_output=True)
    pub = json.load(open(IDENTITY))["public"]
    note("identity-created", submitter=pub[:16], file=IDENTITY)
    return pub


def post(cairn, files):
    """Post objectives before the node starts: a ledger has one writer, and
    once `cairn run` holds the lock the CLI cannot append.  Re-posting an
    objective already in the log is a no-op, so this is safe on every start."""
    env = dict(os.environ, CAIRN_EPOCH_SECONDS=str(EPOCH_SECONDS))
    for f in files:
        r = subprocess.run([cairn, "--log", LOG, "--root", ROOT, "post", f],
                           capture_output=True, text=True, cwd=ROOT, env=env)
        out = (r.stdout + r.stderr).strip()
        # An objective already in the log is refused by id, which is the
        # right answer and not a failure: its pin is in the log and its
        # bounty is live. Say so once, quietly, and move on.
        m = re.search(r"already posted \((sha256:[0-9a-f]+)\)", out)
        if m:
            note("already-posted", file=os.path.relpath(f, ROOT), id=m.group(1)[:20])
        elif r.returncode != 0:
            note("post-failed", file=os.path.relpath(f, ROOT), why=out[:160])
        else:
            first = out.splitlines()[0]
            note("posted", file=os.path.relpath(f, ROOT), id=first.split()[-1][:20])


def expand(patterns):
    files = []
    for p in patterns:
        if os.path.isfile(p) and not p.endswith(".json"):
            files += [ln.strip() for ln in open(p) if ln.strip() and not ln.startswith("#")]
        else:
            files += glob.glob(p, recursive=True) or [p]
    return [f if os.path.isabs(f) else os.path.join(ROOT, f) for f in files]


def port_free(addr):
    host, port = addr.rsplit(":", 1)
    s = socket.socket()
    s.settimeout(0.2)
    try:
        return s.connect_ex((host, int(port))) != 0
    finally:
        s.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--once", action="store_true", help="one sweep, then stop the node and exit")
    ap.add_argument("--post", nargs="*", default=[],
                    help="objective files, globs, or a list file to post before the node starts")
    ap.add_argument("--interval", type=int, default=INTERVAL)
    args = ap.parse_args()

    cairn = cairn_binary()
    os.makedirs(STATE, exist_ok=True)
    submitter = ensure_identity(cairn)
    note("autoresearcher-up", root=ROOT, state=STATE, http=HTTP, epoch_seconds=EPOCH_SECONDS,
         budget_hours=round(BUDGET_SECONDS / 3600, 2), threads=THREADS, submitter=submitter[:16])
    if not port_free(HTTP):
        sys.exit(f"something is already listening on {HTTP}; stop it or set AR_HTTP")
    if args.post:
        post(cairn, expand(args.post))

    node = Node(cairn)
    stopping = threading.Event()

    def on_signal(signum, _frame):
        note("signal", signal=signal.Signals(signum).name)
        stopping.set()

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)

    st = state()
    try:
        init = node.start()
        note("node-up", server=init.get("serverInfo", {}).get("name"),
             http=f"http://{HTTP}", ui=f"http://{HTTP}/ui/", pid=node.proc.pid)
        while not stopping.is_set():
            try:
                sweep(node, st, submitter)
            except Exception as e:
                note("sweep-error", err=str(e)[:200])
                if node.proc.poll() is not None:
                    raise RuntimeError(f"the node exited ({node.proc.returncode}); see {NODE_LOG}")
            if args.once:
                break
            publish_status(node, st, objectives_of(node), f"idle, next sweep in {args.interval}s", submitter)
            stopping.wait(args.interval)
    finally:
        try:
            publish_status(None, st, None, "stopped", submitter)
        except Exception:
            pass
        node.stop()
        note("sweep-complete", solved=len(st["done"]), unreachable=len(st["unreachable"]),
             pending=len(st["pending"]), balance=st.get("balance"))


if __name__ == "__main__":
    main()
