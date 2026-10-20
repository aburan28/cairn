#!/usr/bin/env python3
"""Challenge-to-payment acceptance using real private nodes and isolated ledgers.

No live-node option: all writers, keys and evidence belong to a newly created
run directory. A native AI draft can be supplied to exercise its exact checker.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request


def require(condition, detail):
    if not condition:
        raise RuntimeError(detail)


def text(result):
    return "\n".join(item.get("text", "") for item in result.get("content", []))


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def http(url, payload=None, headers=None):
    data = None if payload is None else json.dumps(payload).encode()
    request = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json", **(headers or {})})
    try:
        response = urllib.request.urlopen(request, timeout=40)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        raw = response.read()
        value = json.loads(raw) if raw and response.headers.get("Content-Type", "").split(";")[0] == "application/json" else raw.decode()
        return response.status, value, dict(response.headers)


def wait_for(check, description, seconds=90):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = check()
        if result:
            return result
        time.sleep(.25)
    raise RuntimeError("Timed out: " + description)


class Node:
    def __init__(self, binary, root, environment):
        self.binary, self.root, self.env = binary, root, environment
        self.base = "http://127.0.0.1:" + str(port())
        self.mcp = "http://127.0.0.1:" + str(port()) + "/mcp"
        self.listen = "127.0.0.1:" + str(port())
        self.process, self.session, self.sequence = None, None, 0
        self.output = (root / "node.log").open("a")

    def start(self):
        self.process = subprocess.Popen([
            str(self.binary), "--data-dir", str(self.root / "data"), "--root", str(self.root),
            "run", "--no-mcp", "--listen", self.listen, "--serve", self.base.removeprefix("http://"),
            "--mcp-http", self.mcp.removeprefix("http://").removesuffix("/mcp"), "--mcp-max-spend", "160",
        ], env=self.env, cwd=self.root, stdout=self.output, stderr=self.output)
        def ready():
            require(self.process.poll() is None, "Node exited; see node.log")
            try:
                return http(self.base + "/health")[1] == "ok\n"
            except OSError:
                return False
        wait_for(ready, "node startup", 40)
        self.session = None
        self.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "cairn-wargame", "version": "1"}})

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=12)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)

    def rpc(self, method, params):
        self.sequence += 1
        headers = {"Mcp-Session-Id": self.session} if self.session else {}
        code, answer, reply_headers = http(self.mcp, {"jsonrpc": "2.0", "id": self.sequence, "method": method, "params": params}, headers)
        require(code == 200 and "result" in answer, f"MCP {method}: {code} {answer}")
        if method == "initialize":
            self.session = next(v for k, v in reply_headers.items() if k.lower() == "mcp-session-id")
        return answer["result"]

    def call(self, name, **arguments):
        return self.rpc("tools/call", {"name": name, "arguments": arguments})

    def records(self):
        code, raw, _ = http(self.base + "/log")
        require(code == 200, "Could not export ledger")
        return [json.loads(line) for line in raw.splitlines() if line]


def fixture(root):
    checker = root / "checker.py"
    checker.write_text("def check(a):\n    ok = isinstance(a, dict) and set(a) == {'unit', 'square'} and type(a['unit']) is int and type(a['square']) is int\n    return (ok and 0 <= a['unit'] < 16 and a['square'] == a['unit'] ** 2), 'recomputed square'\n")
    return {"goal": "GOAL-cairn-acceptance/squares", "statement": "For each unit n in [0,16), return integer unit=n and square=n*n. One completed unit pays 10.", "funder": "acceptance-fixture", "reward": 160,
            "created_at": "2026-10-19T00:00:00+00:00", "piecework": {"unit_price": 10, "units": 16, "key": "unit"},
            "verifier": {"kind": "certificate", "checker": "checker.py", "checker_sha256": hashlib.sha256(checker.read_bytes()).hexdigest(), "entrypoint": "check"}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True, help="New evidence directory; must not exist")
    parser.add_argument("--generated-manifest", type=Path, help="Native acceptance manifest for the 16-unit square task")
    args = parser.parse_args()
    root = args.out.resolve()
    root.mkdir(parents=True, exist_ok=False)
    binary, reference = args.binary.resolve(), args.reference.resolve()
    env = {k: v for k, v in os.environ.items() if not k.startswith("CAIRN_")}
    env.update(PATH="/usr/bin:/bin:/usr/sbin:/sbin", TMPDIR=str(root), CAIRN_KEY=str(root / "absent-key"), CAIRN_NETWORK="private", CAIRN_SEEDS="off", CAIRN_BEACON_PORT="off", CAIRN_PORTMAP="off", CAIRN_PORTMAP_HTTP="off", CAIRN_EPOCH_SECONDS="12", CAIRN_REQUIRE_SANDBOX="1", CAIRN_PYTHON="/usr/bin/python3", CAIRN_SANDBOX_CPUS="1", CAIRN_SANDBOX_MEMORY_MB="512")
    report = {"binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(), "scenarios": [], "status": "running"}
    node = Node(binary, root, env)
    workers = []
    def passed(name, **evidence):
        report["scenarios"].append({"scenario": name, "status": "passed", **evidence})
        (root / "report.json").write_text(json.dumps(report, indent=2))
        print("PASS " + name, flush=True)
    try:
        if args.generated_manifest:
            manifest = json.loads(args.generated_manifest.read_text())
            source = Path(manifest["objective"])
            objective = json.loads(source.read_text())
            relative = Path(objective["verifier"]["checker"])
            require(not relative.is_absolute() and ".." not in relative.parts, "Unsafe fixture checker path")
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(args.generated_manifest.resolve().parent / relative, destination)
            report["provider"] = {k: manifest[k] for k in ("provider", "model", "requests")}
        else:
            objective = fixture(root)
        piecework = objective["piecework"]
        # Over nonnegative integers, either n or n*n uniquely names a square.
        require(objective["reward"] == 160 and piecework["unit_price"] == 10 and piecework["units"] == 16
                and piecework.get("key") in ("unit", "square") and "items" not in piecework,
                "This acceptance runner requires the documented square task and budget")
        (root / "objective.json").write_text(json.dumps(objective, indent=2))
        node.start()
        network = http(node.base + "/network")[1]
        require(network["node"]["peers_policy"]["policy"] == "allowlist" and network["peers"]["reached"] == 0, "Fixture is not private")
        passed("fresh private node serves real MCP and HTTP", base=node.base)
        oversized = dict(objective, reward=161)
        refused = node.call("post_objective", objective=oversized)
        require(refused.get("isError") and not node.records(), "Spend ceiling allowed or recorded an over-budget challenge")
        created = node.call("post_objective", objective=objective)
        require(not created.get("isError"), text(created))
        oid = re.search(r"sha256:[a-f0-9]{64}", text(created)).group()
        report["objective_id"] = oid
        if args.generated_manifest:
            require(oid == manifest["id"], "Publication changed the native-checked objective id")
        require(any(r["kind"] == "objective" for r in node.records()), "Posted objective absent from ledger")
        require(oid in text(node.call("list_objectives")), "Submitted objective not discoverable")
        require(node.call("post_objective", objective=dict(objective, goal="GOAL-over-budget", reward=1)).get("isError"), "Ceiling was not cumulative")
        passed("MCP challenge submission and cumulative funding ceiling", objective_id=oid)
        count = len(node.records())
        candidates = [(dict(unit=n, square=n*n), True) for n in range(16)]
        candidates += [(a, False) for a in [{}, {"unit": -1, "square": 1}, {"unit": 16, "square": 256}, {"unit": True, "square": 1}, {"unit": 3, "square": 10}, {"unit": "3", "square": 9}]]
        for artifact, accept in candidates:
            scored = node.call("score_candidate", objective_id=oid, artifact=artifact)
            verdict = text(scored).lower()
            require(not scored.get("isError") and ("accept" if accept else "reject") in verdict and "unavailable" not in verdict, f"Wrong score for {artifact}: {scored}")
        require(len(node.records()) == count, "Scoring mutated the ledger")
        passed("all 16 valid units and six invalid artifacts checked without ledger writes")
        missing = dict(objective, goal="GOAL-cairn-acceptance/unavailable", reward=0,
                       verifier={"kind": "certificate", "checker": "missing.py", "checker_sha256": "0" * 64, "entrypoint": "check"})
        missing.pop("piecework")
        unavailable = node.call("post_objective", objective=missing)
        require(not unavailable.get("isError"), text(unavailable))
        missing_id = re.search(r"sha256:[a-f0-9]{64}", text(unavailable)).group()
        unavailable = node.call("score_candidate", objective_id=missing_id, artifact={"unit": 3, "square": 9})
        require(text(unavailable).startswith("unavailable:"), f"Missing verifier misclassified: {unavailable}")
        passed("missing pinned verifier reports unavailable without rejecting the artifact")
        code, answer, _ = http(node.mcp, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}, {"Origin": "https://unrelated.invalid"})
        require(code == 403, f"Cross-origin MCP request: {code} {answer}")
        code, answer, _ = http(node.base + "/submit?kind=objective", objective, {"Content-Type": "text/plain"})
        require(code == 415, f"Simple browser write was not refused: {code} {answer}")
        invalid = dict(objective, goal="GOAL-cairn-acceptance/refused", verifier={"kind": "unrecognized-acceptance-verifier"})
        code, receipt, _ = http(node.base + "/submit?kind=objective", invalid)
        require(code == 202, f"Expected queue receipt: {code} {receipt}")
        def refused_receipt():
            result = http(node.base + "/submissions/" + receipt["queued"])[1]
            return result if result.get("status") == "refused" else None
        final = wait_for(refused_receipt, "invalid verifier refusal receipt")
        passed("invalid queued objective reports refusal; browser and cross-origin MCP writes refused", receipt=final)
        committed = node.call("submit_claim", objective_id=oid, submitter="restart-participant", artifact={"unit": 7, "square": 49})
        require(committed.get("_meta", {}).get("cairn/reason") == "committed", f"Commit failed: {committed}")
        again = node.call("submit_claim", objective_id=oid, submitter="restart-participant", artifact={"unit": 7, "square": 49})
        require(again.get("_meta", {}).get("cairn/reason") == "already_committed", f"Duplicate commit failed: {again}")
        node.stop()
        node.start()
        require(oid in text(node.call("pending_reveals", submitter="restart-participant")), "Restart lost the pending commitment")
        def reveal():
            result = node.call("submit_claim", objective_id=oid, submitter="restart-participant", artifact={"unit": 7, "square": 49})
            reason = result.get("_meta", {}).get("cairn/reason")
            require(reason in ("already_committed", "revealed"), f"Unexpected reveal: {result}")
            return result if reason == "revealed" else None
        revealed = wait_for(reveal, "reveal after process restart", 40)
        require(revealed["_meta"]["cairn/verdict"] == "accept", f"Checker rejected valid recovered commitment: {revealed}")
        passed("duplicate commit is idempotent and restart preserves pending reveal")
        solver = root / "solver.py"
        solver.write_text("import json,sys,time\na=json.loads(sys.stdin.readline())\nassert 'epoch' in a and a['units']['first'] == 0 and a['units']['end'] == 16\ntime.sleep(2)\nfor n in range(16): print(json.dumps({'unit':n,'square':n*n}),flush=True)\nprint(json.dumps({'unit':0,'square':1}),flush=True)\n")
        worker_dir = root / "participant"
        worker_dir.mkdir()
        identity = worker_dir / "identity.json"
        created_identity = subprocess.run([str(binary), "identity", "--out", str(identity)], env=env, text=True, capture_output=True, timeout=15)
        require(created_identity.returncode == 0, "Could not create participant identity: " + created_identity.stderr)
        public_identity = json.loads(identity.read_text())["public"]
        report["participant_public_key"] = public_identity
        with (root / "participant.log").open("w") as output:
            worker = subprocess.Popen([str(binary), "work", "--node", node.base, "--objective", oid, "--worker", "fresh-participant", "--identity", str(identity), "--device", "isolated participant process", "--partitions", "1", "--rounds", "1", "--heartbeat", "1", "--margin", "2", "--", "/usr/bin/python3", str(solver)], cwd=worker_dir, env=env, stdout=output, stderr=output)
            workers.append(worker)
            wait_for(lambda: any(w["worker"] == "fresh-participant" for w in http(node.base + "/progress/" + oid)[1]["reported"]["workers"]), "participant roster", 45)
            worker.wait(timeout=150)
            require(worker.returncode == 0, "Participant failed; see participant.log")
        def paid():
            # This is also the normal agent's settlement trigger after revealing.
            node.call("frontier_status", objective_id=oid)
            records = node.records()
            payouts = [r["payload"] for r in records if r["kind"] == "settlement"]
            total = sum(p["reward"] for p in payouts)
            require(total <= 160, "Budget overspent")
            return payouts if total == 160 else None
        payouts = wait_for(paid, "all 16 units settle", 80)
        require(len(payouts) == 16 and all(p["reward"] == 10 for p in payouts), f"Wrong piecework accounting: {payouts}")
        require(sum(p["reward"] for p in payouts if p.get("submitter") == public_identity) == 150, "Payments did not name the participant signing key")
        records = node.records()
        verdicts = [r["payload"] for r in records if r["kind"] == "verdict"]
        require(any(v["verdict"]["status"] == "reject" for v in verdicts), "Wrong submission did not receive a rejection")
        passed("fresh participant joins, finishes, and is paid; duplicate and wrong answers earn nothing", paid=160, paid_units=len(payouts))
        node.stop()
        ledger = root / "data/log/cairn.jsonl"
        for name, tool in [("primary", binary), ("reference", reference)]:
            result = subprocess.run([str(tool), "--log", str(ledger), "--root", str(root), "audit"], env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
            (root / (name + "-audit.log")).write_text(result.stdout)
            require(result.returncode == 0 and "log verified" in result.stdout, f"{name} audit failed: {result.stdout}")
        passed("primary and independent reference re-run verifiers and agree on the ledger")
        report["ledger_sha256"] = hashlib.sha256(ledger.read_bytes()).hexdigest()
        report["status"] = "passed"
    except Exception as error:
        report["status"], report["error"] = "failed", str(error)
        raise
    finally:
        for worker in workers:
            if worker.poll() is None:
                worker.terminate()
                try:
                    worker.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    worker.kill()
                    worker.wait()
        node.stop()
        node.output.close()
        (root / "report.json").write_text(json.dumps(report, indent=2))
        print("Evidence: " + str(root), flush=True)


if __name__ == "__main__":
    main()
