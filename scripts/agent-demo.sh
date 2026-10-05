#!/usr/bin/env bash
# End-to-end check of `cairn agent` against a node it shares nothing with.
#
# The unit tests cover the probe's parsers, the sandbox choice, the engine
# command line and the roster. What they cannot cover is the thing the agent
# exists for: a separate process on a machine, given nothing but an address,
# registering what that machine *is* so the node's readers can see it -- and
# running a job it was handed, in whatever jail the host has, leaving a
# receipt that says which.
#
# So: serve a log, probe this host, register with `--once`, read the host back
# off GET /hosts and GET /network, run one job through the queue and one
# through `exec`, and show the unit `install` would write. On a runner with
# gVisor or bubblewrap the job runs jailed; on one without, the `auto` job
# must be refused with a receipt that says why, and only a job that asked for
# `none` runs -- the same branch lab-demo.sh takes. The operator's sandbox is a
# floor, so that job runs only because this agent's operator chose `none`; the
# last queue run shows a host at the default floor refusing it.
set -euo pipefail
cd "$(dirname "$0")/.."

RUST="${RUST_BIN:-./target/release/cairn}"

if [ ! -x "$RUST" ]; then
  echo "building release binary..." >&2
  cargo build --release
fi

rule() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$1" >&2; exit 1; }

WORK=$(mktemp -d /tmp/pw-agent-XXXXXX)
LOG="$WORK/cairn.jsonl"
DATA="$WORK/agent"
SERVER_PID=""
cleanup() {
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

rule "what this host is"
"$RUST" agent probe
"$RUST" agent probe --json > "$WORK/probe.json"
python3 - "$WORK/probe.json" <<'PY'
import json, sys
probe = json.load(open(sys.argv[1]))
hw = probe["hardware"]
assert hw["os"] == "linux" or hw["os"] == "macos", hw
assert isinstance(hw["cpus"], int) and hw["cpus"] > 0, hw
assert isinstance(hw["gpus"], list), hw
for name in ("kata", "runsc", "bwrap"):
    assert name in probe["sandboxes"], name
    assert isinstance(probe["sandboxes"][name]["usable"], bool)
print("  probe is well-formed:", hw["cpus"], "cpus,", hw["memory_mb"], "MiB,", len(hw["gpus"]), "gpu(s)")
usable = [n for n in ("kata", "runsc", "bwrap") if probe["sandboxes"][n]["usable"]]
open(sys.argv[1] + ".usable", "w").write(" ".join(usable))
PY
USABLE=$(cat "$WORK/probe.json.usable")
echo "  usable sandboxes: ${USABLE:-none}"

rule "serve a log"
"$RUST" --log "$LOG" --root . post examples/capset_progressive/objective.json >/dev/null
PORT=${CAIRN_AGENT_PORT:-38083}
"$RUST" --log "$LOG" --root . serve --listen "127.0.0.1:$PORT" >"$WORK/serve.out" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 50); do
  if python3 -c "
import socket,sys
s=socket.socket(); s.settimeout(0.2)
sys.exit(0 if s.connect_ex(('127.0.0.1',$PORT))==0 else 1)" 2>/dev/null; then break; fi
  sleep 0.1
done
kill -0 "$SERVER_PID" 2>/dev/null || { cat "$WORK/serve.out" >&2; fail "the server exited at startup"; }
echo "  serving on 127.0.0.1:$PORT"

rule "queue a job that must run anywhere, and one that needs a jail"
mkdir -p "$DATA/jobs/queue"
cat > "$WORK/unconfined.json" <<JSON
{"id":"demo-unconfined","rootfs":"/","argv":["/bin/sh","-c","echo hello from a job > \"\$CAIRN_LAB_OUT/hello\" && echo ran"],
 "sandbox":"none","timeout_seconds":60,"note":"explicitly unconfined; the receipt must say so"}
JSON
"$RUST" agent submit "$WORK/unconfined.json" --data-dir "$DATA"
cat > "$WORK/jailed.json" <<JSON
{"id":"demo-jailed","rootfs":"/","argv":["/bin/sh","-c","echo jailed > /out/jailed && cat /proc/1/comm"],
 "sandbox":"auto","timeout_seconds":120,"cpus":1,"memory_mb":512}
JSON
"$RUST" agent submit "$WORK/jailed.json" --data-dir "$DATA"
# A spec the agent must refuse and move aside rather than choke on.
echo '{"image":"x"}' > "$DATA/jobs/queue/broken.json"

rule "register once, run the queue, exit"
# `--sandbox none`: the operator's choice is a floor, and only an operator who
# chose `none` runs a job that asks for it. The `auto` job still asks for a jail.
set +e
"$RUST" agent run --node "http://127.0.0.1:$PORT" --name demo-host --roles executor \
  --data-dir "$DATA" --interval 5 --sandbox none --once > "$WORK/run.out" 2> "$WORK/run.err"
STATUS=$?
set -e
cat "$WORK/run.err"
cat "$WORK/run.out"
# Exit 1 is a failed job, which the jailed job is on a host with no jail;
# anything else is the agent itself failing.
[ "$STATUS" -eq 0 ] || [ "$STATUS" -eq 1 ] || fail "agent run exited $STATUS"
grep -q "registered with 1 node" "$WORK/run.out" || fail "the agent did not report registering"

rule "the node shows the host, and the log is untouched"
python3 - "$PORT" <<'PY'
import json, sys, urllib.request
port = sys.argv[1]
def get(path):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=10) as r:
        return json.loads(r.read())
hosts = get("/hosts")
assert hosts["live"] == 1, hosts
row = hosts["hosts"][0]
assert row["host"] == "demo-host", row
assert row["roles"] == ["executor"], row
assert row["hardware"]["cpus"] > 0, row
assert "kata" in row["sandboxes"] and "runsc" in row["sandboxes"], row
assert row["jobs"]["capacity"] == 1, row
assert row["jobs"]["completed"] + row["jobs"]["failed"] >= 1, row
print("  GET /hosts lists demo-host:", row["hardware"]["cpus"], "cpus,", row["usable_sandboxes"] or "no usable sandbox")
network = get("/network")
assert network["compute"]["hosts"]["live"] == 1, network["compute"]["hosts"]
assert network["compute"]["hosts"]["cpus"] == row["hardware"]["cpus"]
assert network["compute"]["live"] == 0, "a host is not a worker"
print("  GET /network sums it under compute.hosts")
chain = get("/chain")
assert chain["height"] == 1, chain
print("  the log has exactly the objective in it; registrations wrote nothing")
PY

rule "the receipts say which jail each job got"
"$RUST" agent jobs --data-dir "$DATA"
python3 - "$DATA" "$USABLE" <<'PY'
import json, os, sys
data, usable = sys.argv[1], sys.argv[2].split()
done = os.path.join(data, "jobs", "done")
assert os.path.exists(os.path.join(done, "broken.json.invalid")), os.listdir(done)
print("  the unparsable spec was moved aside, not run")
unconfined = json.load(open(os.path.join(done, "demo-unconfined", "receipt.json")))
assert unconfined["sandbox"] == "none", unconfined
assert unconfined["succeeded"] is True, unconfined
assert open(os.path.join(done, "demo-unconfined", "out", "hello")).read().strip() == "hello from a job"
assert "unconfined" in " ".join(unconfined["unenforced"]), unconfined
print("  demo-unconfined: ran, exit 0, receipt says sandbox=none and lists isolation as unenforced")
jailed = json.load(open(os.path.join(done, "demo-jailed", "receipt.json")))
if usable:
    assert jailed["sandbox"] in usable, (jailed, usable)
    assert jailed["succeeded"] is True, jailed
    assert open(os.path.join(done, "demo-jailed", "out", "jailed")).read().strip() == "jailed"
    print("  demo-jailed: ran under", jailed["sandbox"], "via", jailed["via"])
else:
    assert jailed["sandbox"] == "none" and jailed["error"], jailed
    assert "no sandbox" in jailed["error"], jailed
    assert jailed["succeeded"] is False
    print("  demo-jailed: refused --", jailed["error"][:80], "...")
PY

rule "a job cannot go below the operator's sandbox"
cat > "$WORK/floor.json" <<JSON
{"id":"demo-floor","rootfs":"/","argv":["/bin/true"],"sandbox":"none","timeout_seconds":30}
JSON
"$RUST" agent submit "$WORK/floor.json" --data-dir "$DATA"
set +e
"$RUST" agent run --node "http://127.0.0.1:$PORT" --name demo-host --roles executor \
  --data-dir "$DATA" --interval 5 --once > "$WORK/floor.out" 2> "$WORK/floor.err"
STATUS=$?
set -e
[ "$STATUS" -eq 0 ] || [ "$STATUS" -eq 1 ] || { cat "$WORK/floor.err" >&2; fail "agent run exited $STATUS"; }
grep -q "runs jobs under at least .auto.; the job asked for .none." "$WORK/floor.err" \
  || { cat "$WORK/floor.err" >&2; fail "a host at the default floor did not refuse a job asking for none"; }
[ -e "$DATA/jobs/done/demo-floor.json.invalid" ] || fail "the refused job was not moved aside"
[ ! -e "$DATA/jobs/done/demo-floor" ] || fail "the refused job ran"
echo "  at the default floor, a job asking for none is moved aside and never run"

rule "exec runs one job now and prints its receipt"
"$RUST" agent exec --rootfs / --sandbox none --id demo-exec --timeout 30 --data-dir "$DATA" --json \
  -- /bin/sh -c 'echo exec' > "$WORK/exec.json"
python3 -c '
import json,sys
r=json.load(open(sys.argv[1]))
assert r["succeeded"] and r["sandbox"]=="none", r
print("  exec:", r["job_id"], "exit", r["exit_status"], "in", r["wall_ms"], "ms")
' "$WORK/exec.json"
set +e
"$RUST" agent exec --rootfs / --id demo-exec --data-dir "$DATA" -- /bin/true 2>/dev/null
[ $? -eq 2 ] || fail "a reused job id must be a usage error"
set -e
echo "  a reused id is refused"

rule "install --print shows the unit without writing it"
"$RUST" agent install --node "http://127.0.0.1:$PORT" --name demo-host --print > "$WORK/unit.out"
grep -q '^\[Service\]' "$WORK/unit.out" || fail "no [Service] section"
grep -q 'agent run$' "$WORK/unit.out" || fail "ExecStart does not run the agent"
grep -q "CAIRN_AGENT_NODES=\"http://127.0.0.1:$PORT\"" "$WORK/unit.out" || fail "the environment file lacks the node"
grep -q 'NoNewPrivileges=true' "$WORK/unit.out" || fail "the system-user unit is not hardened"
[ -e /etc/systemd/system/cairn-agent.service ] && [ ! -s /etc/cairn-agent/agent.env ] && fail "--print wrote a file" || true
echo "  unit and environment file rendered; nothing written"

rule "misuse"
set +e
"$RUST" agent run >/dev/null 2>&1; [ $? -eq 2 ] || fail "run without a node must exit 2"
"$RUST" agent exec --sandbox none -- /bin/true >/dev/null 2>&1; [ $? -eq 2 ] || fail "exec without image or rootfs must exit 2"
"$RUST" agent frobnicate >/dev/null 2>&1; [ $? -eq 2 ] || fail "an unknown command must exit 2"
"$RUST" agent --help >/dev/null 2>&1; [ $? -eq 0 ] || fail "--help must exit 0"
set -e
echo "  usage errors exit 2, help exits 0"

printf '\n\033[32magent demo passed\033[0m\n'
