#!/usr/bin/env python3
"""Exercise a packaged Windows executable; --runner supports local Wine verification."""
import argparse
import json
import os
from pathlib import Path, PureWindowsPath
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("--runner")
    options = parser.parse_args()
    binary = options.binary.resolve()
    assert binary.read_bytes()[:2] == b"MZ", "Expected a Windows executable, not a renamed Unix binary"
    prefix = [options.runner, str(binary)] if options.runner else [str(binary)]

    def native(path):
        return "Z:" + str(path.resolve()).replace("/", "\\") if options.runner else str(path.resolve())

    with tempfile.TemporaryDirectory(prefix="cairn-windows-") as temporary:
        root = Path(temporary)
        profile = root / "profile"
        profile.mkdir()
        env = dict(os.environ, USERPROFILE=native(profile), CAIRN_SEEDS="off", CAIRN_BEACON_PORT="off", CAIRN_REQUIRE_SANDBOX="off")
        for name in ["HOME", "CAIRN_KEY", "CAIRN_SECRETS_DIR"]:
            env.pop(name, None)

        def run(*args, input=None):
            result = subprocess.run(prefix + list(args), input=input, text=True, capture_output=True, cwd=root, env=env, timeout=60)
            assert result.returncode == 0, (args, result.stdout[-2000:], result.stderr[-4000:])
            return result.stdout

        assert "cairn" in run("--version").lower()
        for command in ["run", "serve", "mcp", "lab", "work", "p2p", "gen-bootstrap"]:
            run(command, "--help")
        run("lab", "identity", "--out", native(root / "author.json"))
        assert json.loads((root / "author.json").read_text()), "Windows OS entropy/identity persistence failed"
        ping = run("--data-dir", native(root / "mcp"), "mcp", input='{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}\n')
        assert json.loads(ping)["result"] == {}, "MCP stdout framing changed"
        run("secret", "set", "WINDOWS_SMOKE_FIXTURE", "--stdin", input="fixture-value\n")
        effective_profile = profile
        if options.runner:
            # Wine supplies its emulated USERPROFILE during process startup;
            # query that OS value instead of assuming a Unix env override won.
            query = subprocess.run([options.runner, "cmd.exe", "/d", "/c", "echo %USERPROFILE%"], env=env, text=True, capture_output=True, timeout=30, check=True)
            windows_profile = PureWindowsPath(query.stdout.strip())
            if windows_profile.drive.upper() == "C:":
                effective_profile = Path(os.environ["WINEPREFIX"]) / "drive_c" / Path(*windows_profile.parts[1:])
            elif windows_profile.drive.upper() == "Z:":
                effective_profile = Path("/").joinpath(*windows_profile.parts[1:])
            else:
                raise AssertionError(f"Unsupported fixture drive: {windows_profile.drive}")
        assert (effective_profile / ".cairn/secrets/WINDOWS_SMOKE_FIXTURE").read_text().strip() == "fixture-value", "Windows secret storage did not use USERPROFILE without HOME"
        print("PASS Windows CLI, OS entropy, identity files and MCP framing", flush=True)

        repo = Path(__file__).resolve().parent.parent
        shutil.copytree(repo / "examples/collatz", root / "examples/collatz")
        objective = json.loads((root / "examples/collatz/objective.json").read_text())
        objective.update(goal="GOAL-windows-persistence-smoke", funder="windows-smoke-fixture")
        objective.pop("funding_signature", None)
        objective.pop("deadline", None)
        fixture = root / "objective.json"
        fixture.write_text(json.dumps(objective))
        run("--data-dir", native(root / "node"), "--root", native(root), "post", native(fixture))

        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        origin = f"http://127.0.0.1:{port}"

        def read(route):
            with urllib.request.urlopen(origin + route, timeout=2) as response:
                return response.read()

        # Open twice: a real admitted objective must survive a process restart.
        for attempt in range(2):
            log = root / f"node-{attempt}.log"
            with log.open("wb") as output:
                child = subprocess.Popen(prefix + ["--data-dir", native(root / "node"), "--root", native(root), "run", "--listen", "127.0.0.1:0", "--serve", f"127.0.0.1:{port}", "--no-mcp"], cwd=root, env=env, stdout=output, stderr=output)
                try:
                    deadline = time.monotonic() + 60
                    while True:
                        try:
                            assert read("/health").strip() == b"ok"
                            break
                        except (OSError, AssertionError):
                            if child.poll() is not None or time.monotonic() >= deadline:
                                raise AssertionError(log.read_text(errors="replace")[-6000:])
                            time.sleep(0.1)
                    for route in ["/ui/", "/ui/network/", "/ui/peers/", "/ui/diagnostics/"]:
                        assert b"<html" in read(route).lower(), route
                    network = json.loads(read("/network"))
                    assert network["node"]["hardware"]["os"] == "windows", network["node"]["hardware"]
                    assert any(row["goal"] == objective["goal"] for row in json.loads(read("/objectives"))["objectives"]), "The posted objective did not survive reopening the store"
                    verifiers = json.loads(read("/verifiers"))
                    assert verifiers["sandbox"]["required"] is True, "Windows must fail closed even with CAIRN_REQUIRE_SANDBOX=off"
                    assert verifiers["sandbox"]["mechanism"] == "none", "A supported Windows jail needs explicit qualification"
                    if attempt == 0 and os.environ.get("CAIRN_WINDOWS_BROWSER") == "1":
                        browser_env = dict(os.environ, CAIRN_WINDOWS_READER_URL=origin + "/ui/")
                        subprocess.run(["node", str(repo / "ui/scripts/windows-reader-smoke.mjs")], cwd=repo / "ui", env=browser_env, check=True, timeout=90)
                finally:
                    child.terminate()
                    try:
                        child.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait(timeout=15)
        print("PASS Windows executable: embedded UI, network, mandatory confinement and persistent restart")


if __name__ == "__main__":
    main()
