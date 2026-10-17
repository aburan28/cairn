"""Exercise the public CLI, MCP and persistent encrypted collaboration workflow.

No Git command, external service, container daemon or optional sandbox required.
The runner/replay seam is checked via its immutable capture function in tests.
"""
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time

BINARY = str(Path(os.environ.get("RUST_BIN", "target/release/cairn")).resolve())


def run(*args, stdin=None):
    result = subprocess.run([BINARY, *map(str, args)], input=stdin, text=True,
                            capture_output=True, timeout=30)
    assert result.returncode == 0, (args, result.stdout, result.stderr)
    return result.stdout


with tempfile.TemporaryDirectory(prefix="cairn-live-demo-") as directory:
    root = Path(directory)
    key = root / "author.json"
    run("lab", "identity", "--out", key)
    policy = root / "policy.json"
    policy.write_text(json.dumps({"write_once": ["checkpoints/**"]}))
    a, b = root / "a", root / "b"

    def lab(where, *args):
        return run("lab", "--lab", where, *args)

    def collab(where, *args):
        return json.loads(lab(where, "collab", *args))

    lab(a, "init", "--name", "live-demo", "--identity", key, "--policy", policy)
    workspace = collab(a, "create", "shared", "--request", "create", "--identity", key)["workspace"]
    space = json.loads(lab(a, "status", "--json"))["space"]
    lab(b, "clone", "--space", space, "--dir", a)
    base = root / "base.json"
    base.write_text(json.dumps(collab(a, "read", workspace)))
    edits = root / "edits.json"
    edits.write_text(json.dumps([{"path": "main.py", "start": 0, "delete": 0, "insert": "print('hello collaboration')\n"}]))
    collab(a, "edit", workspace, "--base", base, "--edits", edits,
           "--request", "source", "--identity", key)

    # Pin both transport identities; the server explicitly authorizes the client.
    server_key, client_key = root / "server-peer.json", root / "client-peer.json"
    server_id = lab(b, "peer-id", "--peer-identity", server_key).strip()
    client_id = lab(a, "peer-id", "--peer-identity", client_key).strip()
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    endpoint = f"127.0.0.1:{port}"
    server_log = root / "server.log"
    server = None
    try:
        with server_log.open("w") as log:
            server = subprocess.Popen([BINARY, "lab", "--lab", str(b), "serve", "--listen", endpoint,
                                       "--peer-identity", str(server_key), "--allow", client_id],
                                      stdout=subprocess.DEVNULL, stderr=log)
            deadline = time.monotonic() + 10
            while "serving" not in server_log.read_text():
                assert server.poll() is None, server_log.read_text()
                assert time.monotonic() < deadline, "listener did not become ready"
                time.sleep(0.02)
            output = lab(a, "sync", "--peer", f"{server_id}@{endpoint}", "--peer-identity", client_key,
                         "--watch", "--interval-ms", "50", "--rounds", "3")
            assert "1 sent" in output, output
            assert collab(b, "read", workspace)["contents"]["main.py"].startswith("print(")
        assert server_log.read_text().count("session with") == 1, "watcher must reuse its authenticated connection"
    finally:
        if server is not None:
            server.terminate()
            server.wait(timeout=10)

    # Start disconnected, then restore the same pinned server. Reconnection
    # must retain local work, rather than requiring an operator restart.
    offline_base = root / "offline-base.json"
    offline_base.write_text(json.dumps(collab(a, "read", workspace)))
    edits.write_text(json.dumps([{"path": "offline.txt", "start": 0, "delete": 0,
                                  "insert": "work completed during the partition"}]))
    collab(a, "edit", workspace, "--base", offline_base, "--edits", edits,
           "--request", "offline-work", "--identity", key)
    reconnect_log = root / "reconnect.log"
    watcher = None
    try:
        with reconnect_log.open("w") as output:
            watcher = subprocess.Popen([BINARY, "lab", "--lab", str(a), "sync", "--peer",
                f"{server_id}@{endpoint}", "--peer-identity", str(client_key), "--watch",
                "--interval-ms", "50", "--rounds", "16"], stdout=output, stderr=output)
            deadline = time.monotonic() + 10
            while "disconnected" not in reconnect_log.read_text():
                assert watcher.poll() is None, reconnect_log.read_text()
                assert time.monotonic() < deadline, "watcher did not report disconnection"
                time.sleep(0.02)
            with server_log.open("a") as log:
                server = subprocess.Popen([BINARY, "lab", "--lab", str(b), "serve", "--listen", endpoint,
                    "--peer-identity", str(server_key), "--allow", client_id],
                    stdout=subprocess.DEVNULL, stderr=log)
                watcher.wait(timeout=20)
                assert watcher.returncode == 0, reconnect_log.read_text()
                assert "reconnected" in reconnect_log.read_text(), reconnect_log.read_text()
                assert collab(b, "read", workspace)["contents"]["offline.txt"] == "work completed during the partition"
    finally:
        if watcher is not None and watcher.poll() is None:
            watcher.terminate()
            watcher.wait(timeout=10)
        if server is not None and server.poll() is None:
            server.terminate()
            server.wait(timeout=10)

    pinned = root / "pinned.json"
    pinned.write_text(json.dumps(collab(a, "read", workspace)))
    checkpoint = collab(a, "checkpoint", workspace, "--base", pinned, "--identity", key)
    assert checkpoint["inputs"][0]["target"] == "/src/main.py"
    checkout = root / "checkout"
    collab(a, "checkout", workspace, checkout, "--base", pinned)
    assert (checkout / "main.py").read_text() == "print('hello collaboration')\n"

    # Actual JSON-RPC framing and schemas, rather than calling the Rust helper.
    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
            "name": "collab_read", "arguments": {"workspace": workspace}}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
            "name": "collab_edit", "arguments": {"workspace": workspace,
                "heads": json.loads(pinned.read_text())["heads"], "request": "mcp-edit",
                "edits": [{"path": "notes.md", "start": 0, "delete": 0, "insert": "from an agent"}]}}},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {
            "name": "collab_feed", "arguments": {"workspace": workspace, "limit": 2}}},
    ]
    frames = run("lab", "--lab", a, "mcp", "--identity", key,
                 stdin="\n".join(map(json.dumps, messages)) + "\n").splitlines()
    responses = list(map(json.loads, frames))
    schemas = responses[0]["result"]["tools"]
    tools = {tool["name"]: tool for tool in schemas}
    assert tools["collab_edit"]["annotations"]["readOnlyHint"] is False
    assert tools["collab_read"]["annotations"]["readOnlyHint"] is True
    for response in responses[1:]:
        assert response["result"]["isError"] is False, response
    assert collab(a, "read", workspace)["contents"]["notes.md"] == "from an agent"
    events = collab(a, "feed", workspace, "--limit", "256")["changes"]
    for event in events:
        encoded = json.dumps(event["change"], sort_keys=True, ensure_ascii=False,
                             separators=(",", ":")).encode("utf-8")
        assert event["id"] == "sha256:" + hashlib.sha256(encoded).hexdigest(), event
    assert not (root / ".git").exists()
    print("collaboration: CLI + MCP + persistent encrypted sync + checkpoint + safe checkout passed")
