"""Two HTTP MCP sessions, one signed DP operating period, one audited ledger."""

import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from types import SimpleNamespace
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
CAIRN = Path(os.environ.get("CAIRN_BIN", ROOT / "target/debug/cairn")).resolve()
REFERENCE = Path(os.environ.get("REF_BIN", ROOT / "reference/rust/target/debug/cairn-reference")).resolve()
spec = importlib.util.spec_from_file_location(
    "ingest_service", ROOT / "examples/ecc2k-ingest-service/service.py")
service = importlib.util.module_from_spec(spec)
spec.loader.exec_module(service)


def command(*args, env=None):
    return subprocess.run(args, check=True, text=True, capture_output=True, env=env).stdout


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def request(port, payload, session=None):
    body = json.dumps(payload, separators=(",", ":")).encode()
    headers = {"Accept": "application/json, text/event-stream",
               "Content-Type": "application/json"}
    if session:
        headers["Mcp-Session-Id"] = session
        headers["MCP-Protocol-Version"] = "2025-06-18"
    req = Request(f"http://127.0.0.1:{port}/mcp", body, headers=headers)
    try:
        with urlopen(req, timeout=180) as response:
            return response.status, response.headers, json.load(response)
    except HTTPError as error:
        return error.code, error.headers, None


def rpc(port, session, method, params=None):
    status, _, payload = request(port,
                                 {"jsonrpc": "2.0", "id": 1,
                                  "method": method, "params": params or {}}, session)
    assert status == 200 and "error" not in payload, (status, payload)
    return payload["result"]


def tool(port, session, name, args):
    result = rpc(port, session, "tools/call",
                 {"name": name, "arguments": args})
    assert not result.get("isError"), (name, result)
    return result["content"][0]["text"]


def prepare_fixture(root, operator):
    key = Ed25519PrivateKey.generate()
    auditor = root / "auditor.pem"
    auditor.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    period = int(time.time()) // 3600 - 1
    for name, boundary, dps in (("before", period, 100),
                                ("after", period + 1, 101)):
        stamp = datetime.fromtimestamp(boundary * 3600, timezone.utc)
        timestamp = stamp.strftime("%Y-%m-%dT%H:%M:%SZ")
        value = {"campaign_id": "ecc2k-130", "generated_at": timestamp,
                 "published_at": timestamp, "dps": dps,
                 "ingest": {"outstanding_objects": 0, "unrecognised_objects": 0}}
        (root / f"{name}.json").write_text(json.dumps(value, sort_keys=True) + "\n")
    (root / "objects.json").write_text(json.dumps([
        {"key": "dp/fixture.bin", "sha256": "ab" * 32,
         "bytes": 64, "records": 2}]))
    (root / "progress.json").write_text(json.dumps([
        {"key": "dp/fixture.bin", "records": 2, "duplicates": 1}]))
    service.objective(SimpleNamespace(
        service="ecc2k130-dp-ingest-v1", input_bucket="example-private-dp",
        period_seconds=3600, unit_price=17, periods=2, funder="treasury",
        goal="GOAL-certicom-ecc2k130", created_at="2026-10-10T00:00:00Z",
        auditor_public_key=service.auditor_public_key(auditor), out_dir=root))
    service.prepare(SimpleNamespace(
        service="ecc2k130-dp-ingest-v1", input_bucket="example-private-dp",
        period=period, operator=operator, nonce="ab" * 32, polls=3,
        objects=root / "objects.json", progress=root / "progress.json",
        before=root / "before.json", after=root / "after.json",
        out=root / "body.json"))
    service.sign(SimpleNamespace(body=root / "body.json", auditor_key=auditor,
                                 out=root / "receipt.json"))
    return json.loads((root / "receipt.json").read_text())


def main():
    if not CAIRN.is_file() or not REFERENCE.is_file():
        raise SystemExit("build `cargo build --features ui` and the reference binary first")
    with tempfile.TemporaryDirectory(prefix="cairn-remote-ingest-") as temporary:
        root = Path(temporary)
        env = os.environ.copy()
        env.update(CAIRN_KEY=str(root / "absent.key"), CAIRN_EPOCH_SECONDS="1",
                   CAIRN_FINALITY_EPOCHS="1")
        identity = root / "operator.json"
        command(str(CAIRN), "identity", "--out", str(identity), env=env)
        operator = json.loads(identity.read_text())["public"]
        receipt = prepare_fixture(root, operator)
        log = root / "log.jsonl"
        common = [str(CAIRN), "--log", str(log), "--root", str(root)]
        posted = command(*common, "post", str(root / "objective.json"), env=env)
        objective_id = posted.splitlines()[0].split()[1]
        remote = free_port()
        with open(root / "node.log", "w") as output:
            node = subprocess.Popen(
                [*common, "mcp", "--http", f"127.0.0.1:{remote}",
                 "--identity", str(identity)],
                env=env, stdin=subprocess.DEVNULL, stdout=output, stderr=output)
            try:
                for _ in range(100):
                    if node.poll() is not None:
                        raise AssertionError((root / "node.log").read_text())
                    try:
                        with socket.create_connection(("127.0.0.1", remote), timeout=0.2):
                            break
                    except OSError:
                        time.sleep(0.1)
                else:
                    raise AssertionError("remote MCP listener did not start")
                sessions = []
                for _ in range(2):
                    status, headers, result = request(remote, {
                        "jsonrpc": "2.0", "id": 1, "method": "initialize",
                        "params": {"protocolVersion": "2025-06-18"}})
                    assert status == 200 and result["result"]["protocolVersion"] == "2025-06-18"
                    sessions.append(headers["Mcp-Session-Id"])
                for session in sessions:
                    assert objective_id in tool(remote, session, "list_objectives", {})
                scored = tool(remote, sessions[0], "score_candidate",
                              {"objective_id": objective_id, "artifact": receipt})
                assert "accept" in scored.lower(), scored
                submitted = tool(remote, sessions[0], "submit_claim",
                                 {"objective_id": objective_id, "artifact": receipt})
                assert "Committed" in submitted, submitted
                time.sleep(1.2)
                revealed = tool(remote, sessions[0], "submit_claim",
                                {"objective_id": objective_id, "artifact": receipt})
                assert "accept" in revealed.lower(), revealed
                time.sleep(2.2)
                frontier = tool(remote, sessions[1], "frontier_status",
                                {"objective_id": objective_id})
                assert "(17 paid so far)" in frontier, frontier
                stdio_input = "\n".join(json.dumps(message) for message in (
                    {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                     "params": {"protocolVersion": "2025-06-18"}},
                    {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                )) + "\n"
                adapter_env = env | {"CAIRN_MCP_USER": "local-smoke",
                                     "CAIRN_MCP_PASSWORD": "local-smoke-password"}
                adapter = subprocess.run(
                    [sys.executable, str(ROOT / "scripts/cairn-remote-stdio.py"),
                     f"http://127.0.0.1:{remote}/mcp", "--allow-loopback-http"],
                    input=stdio_input, capture_output=True, text=True,
                    timeout=30, env=adapter_env, check=True)
                frames = [json.loads(line) for line in adapter.stdout.splitlines()]
                assert len(frames) == 2 and frames[1]["result"]["tools"], adapter.stdout
            finally:
                node.terminate()
                try:
                    node.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    node.kill()
                    node.wait()
        audit = command(str(REFERENCE), "--log", str(log), "--root", str(root),
                        "audit", "--rerun", env=env)
        assert "log verified" in audit, audit
        print("two remote sessions, signed period payment, and reference replay: OK")


if __name__ == "__main__":
    main()
