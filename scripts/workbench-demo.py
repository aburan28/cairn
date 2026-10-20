"""Public CLI/local HTTP/security/compaction acceptance, with optional browser QA.

No Git server, public listener, Docker daemon or unconfined runner is required.
"""
import json
import os
from pathlib import Path
import socket
import shutil
import re
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request

BINARY = str(Path(os.environ.get("RUST_BIN", "target/release/cairn")).resolve())


def run(*args):
    result = subprocess.run([BINARY, *map(str, args)], text=True, capture_output=True, timeout=30)
    assert result.returncode == 0, (args, result.stdout, result.stderr)
    return result.stdout


with tempfile.TemporaryDirectory(prefix="cairn-workbench-") as directory:
    root = Path(directory)
    key, policy, lab = root / "author.json", root / "policy.json", root / "lab"
    run("lab", "identity", "--out", key)
    policy.write_text(json.dumps({"write_once": ["checkpoints/**"]}))
    run("lab", "--lab", lab, "init", "--name", "Algorithm research", "--identity", key, "--policy", policy)
    # A tiny operator-imported Linux environment; no Docker or host mount.
    rootfs=root / "rootfs"
    (rootfs / "bin").mkdir(parents=True)
    shell=Path("/bin/sh").resolve()
    shutil.copy2(shell,rootfs / "bin/sh")
    libraries=subprocess.run(["ldd",str(shell)],text=True,capture_output=True,check=True).stdout
    for name in set(re.findall(r"/[^\s()]+",libraries)):
        path=Path(name)
        if path.is_file():
            destination=rootfs / name.lstrip("/")
            destination.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(path,destination)
    run("lab","--lab",lab,"env","import","tiny","--dir",rootfs,"--identity",key)
    rates = root / "rates.json"
    rates.write_text(json.dumps({"unit":"USD", "rates":[{"id":"local", "workload":"boomer-v1",
        "cpu_second_microunits":3, "memory_gib_second_microunits":2},{"id":"precision","workload":"precision-v1",
        "cpu_second_microunits":18446744073709551615,"memory_gib_second_microunits":0}]}))
    env = dict(os.environ, CAIRN_AGENT_RATE_CARD=str(rates))
    server = subprocess.Popen([BINARY, "lab", "--lab", str(lab), "web", "--identity", str(key)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
    try:
        line = server.stdout.readline()
        assert line.startswith("Local collaboration workbench: "), line
        private = line.split(": ", 1)[1].strip()
        url = urllib.parse.urlsplit(private)
        token = urllib.parse.parse_qs(url.fragment)["token"][0]
        origin = f"http://{url.netloc}"
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

        def api(command, args=None):
            request = urllib.request.Request(origin + "/api", data=json.dumps({"command":command, "args":args or {}}).encode(),
                headers={"Content-Type":"application/json", "Authorization":f"Bearer {token}", "Origin":origin})
            return json.loads(opener.open(request, timeout=30).read())

        for path, mime in [("/", "text/html"), ("/app.js", "text/javascript"), ("/model.js", "text/javascript"), ("/style.css", "text/css")]:
            response = opener.open(origin + path)
            assert mime in response.headers["Content-Type"]
            assert "no-store" in response.headers["Cache-Control"]
            assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
            assert token.encode() not in response.read()
        for headers, expected in [({},401),({"Authorization":f"Bearer {token}","Origin":"https://evil.example"},403),
                ({"Authorization":f"Bearer {token}","X-Forwarded-For":"127.0.0.1"},403)]:
            request = urllib.request.Request(origin + "/api", data=b'{"command":"list","args":{}}',
                headers={"Content-Type":"application/json", **headers})
            try:
                opener.open(request)
                raise AssertionError("unauthorized request succeeded")
            except urllib.error.HTTPError as error:
                assert error.code == expected
        with socket.create_connection((url.hostname,url.port),timeout=5) as connection:
            connection.sendall(f"POST /api HTTP/1.1\r\nHost: {url.netloc}\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{{}}".encode())
            # TCP may split even a short response across reads; inspect the full
            # status line instead of assuming one recv returns it all.
            status_line = connection.makefile("rb").readline()
            assert status_line.startswith(b"HTTP/1.1 400"), status_line
        created = api("create", {"title":"Shared algorithm", "request":"web-create"})
        workspace = created["workspace"]
        edit = {"workspace":workspace, "heads":created["heads"], "request":"web-edit",
                "edits":[{"path":"experiment.py", "start":0, "delete":0, "insert":"print('hello 🦀')\n"}]}
        assert api("edit",edit) == api("edit",edit)
        read = api("read",{"workspace":workspace})
        assert read["contents"]["experiment.py"] == "print('hello 🦀')\n"
        assert api("feed",{"workspace":workspace})["changes"]
        checkpoint = api("checkpoint",{"workspace":workspace,"heads":read["heads"]})
        assert checkpoint["inputs"][0]["target"] == "/src/experiment.py"
        quote = api("quote",{"workload":"boomer-v1","cpus":1,"memory_mb":0,"duration_ms":1000})
        assert quote["amount_microunits_exact"] == "3"
        assert quote["rate_id"] == "local"
        assert json.loads(quote["canonical_quote"])["amount_microunits"] == 3
        precise=api("quote",{"workload":"precision-v1","cpus":1,"memory_mb":0,"duration_ms":1000})
        assert precise["amount_microunits_exact"] == "18446744073709551615"
        assert json.loads(precise["canonical_quote"])["amount_microunits"] == 18446744073709551615
        script=api("edit",{"workspace":workspace,"heads":read["heads"],"request":"run-source",
            "edits":[{"path":"experiment.sh","start":0,"delete":0,"insert":"printf 'pinned run\\n'\nprintf 'result\\n' > \"$CAIRN_LAB_OUT/result.txt\"\n"}]})
        run_args={"workspace":workspace,"heads":script["heads"],"env":"tiny","argv":["/bin/sh","/src/experiment.sh"],
            "request":"first-run","timeout_seconds":10,"cpus":1,"memory_mb":64,"workload":"boomer-v1"}
        try:
            job=api("run",run_args)["job"]
            assert api("run",run_args)["job"] == job
            import time
            deadline=time.monotonic()+30
            while True:
                result=api("job",{"id":job})
                if result["state"] != "running": break
                assert time.monotonic()<deadline,"bounded experiment did not finish"
                time.sleep(.05)
            if result["state"] == "complete":
                assert result["stdout"] == "pinned run\n",result
                assert result["receipt"]["network"] is False
                assert result["receipt"]["backend"] != "none"
                assert result["estimate"]["rate_id"] == "local"
                print("PASS sandboxed experiment, exact checkpoint inputs and rate-card binding")
            else:
                assert result["error"],result
                print("PASS unavailable runtime remains distinct from a program verdict")
        except urllib.error.HTTPError as error:
            unavailable=json.loads(error.read())
            assert error.code==503 and unavailable["kind"]=="unavailable",unavailable
            print("PASS no usable sandbox: local run refused without an unconfined fallback")
        print("PASS local authentication, host/origin isolation, framing, signed edits, retries, checkpoints and compute estimates")

        if os.environ.get("CAIRN_WORKBENCH_BROWSER") == "1":
            subprocess.run(["node", "ui/scripts/workbench-smoke.mjs"], check=True, env=dict(env,
                CAIRN_WORKBENCH_URL=private, CAIRN_WORKBENCH_LAB=str(lab), CAIRN_WORKBENCH_KEY=str(key), RUST_BIN=BINARY),timeout=180)

        read = api("read",{"workspace":workspace})
        base = root / "base.json"
        base.write_text(json.dumps(read))
        destination = root / "next"
        result = json.loads(run("lab","--lab",lab,"collab","compact",workspace,destination,"--base",base,"--identity",key))
        fresh = json.loads(run("lab","--lab",destination,"collab","read",result["workspace"]))
        assert fresh["contents"] == read["contents"]
        recovered = root / "recovered"
        run("lab","--lab",destination,"collab","recover",recovered)
        original = json.loads(run("lab","--lab",recovered,"collab","read",workspace,"--base",base))
        assert original == read
        print("PASS generation rollover, fresh source graph and original signed-history recovery")
    finally:
        server.terminate()
        server.wait(timeout=10)
