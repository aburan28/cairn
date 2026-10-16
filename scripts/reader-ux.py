#!/usr/bin/env python3
"""Exercise the embedded reader against a disposable node; never an operator log."""
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request
import uuid


def main():
    repo = Path(__file__).resolve().parent.parent
    binary = Path(os.environ.get("RUST_BIN", repo / "target/debug/cairn")).resolve()
    if not binary.is_file():
        raise SystemExit("Build the embedded reader first: npm --prefix ui run build; cargo build --locked --features ui")
    with tempfile.TemporaryDirectory(prefix="cairn-reader-ux-") as directory:
        root = Path(directory)
        fixture_id = str(uuid.uuid4())
        env = dict(os.environ, CAIRN_KEY=str(root / "absent-key"), CAIRN_SEEDS="off",
                   CAIRN_BEACON_PORT="off", CAIRN_LAB_HTTP=str(root / "lab"),
                   CAIRN_LAB_IDENTITY=str(root / "identity.json"))
        # A live reader fixture has a real ledger. Only the copied example
        # records change, and only this temporary tree receives CLI writes.
        shutil.copytree(repo / "examples/collatz", root / "examples/collatz")
        (root / "log.jsonl").write_text("")

        def run(*args):
            return subprocess.check_output([str(binary), "--log", str(root / "log.jsonl"),
                                            "--root", str(root), *map(str, args)], env=env, text=True)

        def digest(output):
            return re.search(r"sha256:[a-f0-9]{64}", output).group(0)

        for name, source in [("certificate", "examples/collatz/objective.json"),
                             ("piecework", "examples/certicom-ecdlp/objective-ecc2k-23-orbit-batch.json")]:
            record = json.loads((repo / source).read_text())
            record.update(goal=f"GOAL-ux-{fixture_id}-{name}", funder="reader-ux-fixture")
            record.pop("funding_signature", None)
            record.pop("deadline", None)
            file = root / f"{name}.json"
            file.write_text(json.dumps(record))
            objective = digest(run("post", file))
            if name == "certificate":
                certificate_id = objective

        def lab(*args, location="lab"):
            return run("lab", "--lab", root / location, *args)

        run("lab", "identity", "--out", root / "identity.json")
        space = digest(lab("init", "--name", "Reader regression workspace", "--identity", root / "identity.json"))
        lab("put", "inputs/artifact.json", "--file", root / "examples/collatz/artifact.json", "--identity", root / "identity.json")
        (root / "image").mkdir()
        lab("env", "import", "fixture", "--dir", root / "image", "--identity", root / "identity.json")
        lab("exec", "--env", "fixture", "--input", "inputs:/in", "--sandbox", "none", "--identity", root / "identity.json", "--",
            "/bin/sh", "-c", 'cp "$CAIRN_LAB_MOUNT_IN/artifact.json" "$CAIRN_LAB_OUT/artifact.json"')
        lab("doc", "set", "coordination", "objective_id", json.dumps(certificate_id), "--identity", root / "identity.json")
        lab("clone", "--space", space, "--dir", root / "lab", location="other")
        lab("put", "inputs/artifact.json", "--text", '{"n":27}', "--identity", root / "identity.json")
        lab("put", "inputs/artifact.json", "--text", '{"n":1}', "--identity", root / "identity.json", location="other")
        lab("sync", "--dir", root / "other")
        (root / "fixture.json").write_text(json.dumps({"id": fixture_id, "binary": str(binary), "space": space}))

        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        address = f"http://127.0.0.1:{port}"
        with (root / "server.log").open("w+") as output:
            server = subprocess.Popen([str(binary), "--log", str(root / "log.jsonl"), "--root", str(root),
                                       "serve", "--listen", f"127.0.0.1:{port}", "--queue", str(root / "queue")],
                                      env=env, stdout=output, stderr=output)
            try:
                for _ in range(100):
                    if server.poll() is not None:
                        output.seek(0)
                        raise RuntimeError(output.read())
                    try:
                        with urllib.request.urlopen(address + "/health", timeout=.2) as response:
                            if response.read().strip() == b"ok":
                                break
                    except OSError:
                        time.sleep(.1)
                else:
                    raise RuntimeError("The isolated reader did not start")
                browser_env = dict(env, CAIRN_UX_URL=address + "/ui/", CAIRN_UX_FIXTURE_ROOT=str(root), CAIRN_UX_FIXTURE_ID=fixture_id)
                subprocess.run(["node", "ui/scripts/ux-smoke.mjs"], cwd=repo, env=browser_env, check=True, timeout=180)
            finally:
                server.terminate()
                try:
                    server.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()


if __name__ == "__main__":
    main()
