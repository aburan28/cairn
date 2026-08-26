#!/usr/bin/env bash
# Produce the site's fallback snapshot from the settled log, using the node.
#
# # Why this is a shell script and not a JavaScript one
#
# The first version parsed `launch/cairn.jsonl` in Node and grouped records by
# objective. It could not work, and the way it failed is worth recording: a
# ledger entry's `hash` is the hash of the *entry*, while `frontier.objective_id`
# names the objective *record's* id, which is the digest of its canonical form.
# Relating the two means implementing canonical encoding in JavaScript -- a third
# implementation of a consensus rule that `src/` and `reference/rust/` already
# have to agree on byte for byte, in a language with neither's integer
# semantics. `ui/README.md` refuses that for the epoch chain and it is refused
# here for the same reason.
#
# So the node computes it. This starts the real server on the real log, asks the
# questions over HTTP exactly as any reader would, and saves the answers. The
# output is committed, so building the site needs Node and nothing else.
set -euo pipefail
cd "$(dirname "$0")/.."

SERVE="${SERVE_BIN:-./target/release/cairn-serve}"
LOG="${SNAPSHOT_LOG:-launch/cairn.jsonl}"
OUT="${SNAPSHOT_OUT:-ui/lib/snapshot.json}"
PORT="${SNAPSHOT_PORT:-38111}"

[ -x "$SERVE" ] || { echo "building..." >&2; cargo build --release; }

# The published log is plaintext and must stay readable by anyone, so this must
# not pick up an operator's at-rest key and hand back something sealed.
export CAIRN_KEY=/nonexistent/cairn-site-snapshot

"$SERVE" --log "$LOG" --root . --listen "127.0.0.1:$PORT" >/tmp/site-snapshot.log 2>&1 &
PID=$!
trap 'kill "$PID" 2>/dev/null || true' EXIT

for _ in $(seq 1 50); do
  curl -sf "http://127.0.0.1:$PORT/health" >/dev/null 2>&1 && break
  sleep 0.1
done
curl -sf "http://127.0.0.1:$PORT/health" >/dev/null || { cat /tmp/site-snapshot.log >&2; exit 1; }

python3 - "$PORT" "$OUT" "$LOG" <<'PY'
import json, sys, urllib.request

port, out, logpath = sys.argv[1], sys.argv[2], sys.argv[3]
base = f"http://127.0.0.1:{port}"

def get(path):
    with urllib.request.urlopen(base + path, timeout=10) as r:
        return json.loads(r.read())

objectives = get("/objectives")["objectives"]
chain = get("/chain")
signed = json.load(open("launch/checkpoint.json"))
checkpoint = signed["checkpoint"]

# Each objective's full record, for the statement and the ratchet a challenge
# page shows. The listing deliberately truncates; this does not.
for o in objectives:
    o["record"] = get("/objective/" + o["id"])["record"]

snapshot = {
    # Named so nothing downstream can render it as live by accident.
    "source": logpath,
    "generated_by": "scripts/site-snapshot.sh",
    # The flat keys predate the two objects below and are kept for whoever
    # still reads them; the site reads the objects. They are shaped like the
    # endpoints they came from, so a page falling back from `/chain` to the
    # snapshot handles one shape rather than two -- and so the ledger height
    # a checkpoint signs sits beside the link count it must not be compared
    # with, each under its own name.
    "merkle_root": checkpoint["root"],
    "head": checkpoint["head"],
    "height": checkpoint["height"],
    "issued_at": checkpoint["issued_at"],
    "links": chain["links"],
    "chain": {
        "head": chain["head"],
        "links": chain["links"],
        "height": chain["height"],
        "ledger_head": chain["ledger_head"],
    },
    "checkpoint": {
        "head": checkpoint["head"],
        "height": checkpoint["height"],
        "root": checkpoint["root"],
        "issued_at": checkpoint["issued_at"],
        "public_key": signed["public_key"],
    },
    "objectives": objectives,
}

# The one thing worth asserting here: the log the checkpoint was signed over
# is the log the node just served. A snapshot whose chain and checkpoint
# disagreed would teach the landing page to show a mismatch as normal.
assert chain["height"] == checkpoint["height"], (chain["height"], checkpoint["height"])
assert chain["ledger_head"] == checkpoint["head"], (chain["ledger_head"], checkpoint["head"])
with open(out, "w") as f:
    json.dump(snapshot, f, indent=2, sort_keys=True)
    f.write("\n")

settled = sum(1 for o in objectives if o.get("frontier"))
print(f"snapshot: {len(objectives)} objective(s), {settled} with a frontier, "
      f"{chain['links']} chain link(s), root {checkpoint['root'][:14]}…")
PY
