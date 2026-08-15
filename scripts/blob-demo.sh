#!/usr/bin/env bash
# A node with only the log fetches a pinned checker from a stranger, and verifies.
#
# This is the network's central promise done end to end by two processes that
# share nothing but a socket: "anyone can independently re-derive every settled
# result from the log" is false if re-deriving it also requires a copy of the
# bundle that nobody ships.
#
# It is here because the path had never been run. `swarm::tcp` was a complete,
# encrypted, end-to-end tested blob transfer with **no caller in any shipped
# binary**, and two bugs were waiting in the seam:
#
#   * `Handshake::encode` wrote a bare content address and `decode` returned it
#     `sha256:`-prefixed, so a caller holding a real address -- bare, which is
#     what every objective pin and `blobs::address` produce -- never matched a
#     single reply. The tests all used the prefixed spelling their own helpers
#     produced, so the subsystem agreed with itself and with nobody else.
#
#   * A blob's filename is its hash, so it never ends in `.py`, and Python's
#     `spec_from_file_location` returns None for an extension it does not
#     recognise. The content-addressed fallback -- the entire reason the blob
#     store exists -- could not load a single fetched checker.
#
# Both were invisible to unit tests of either side. Only running the two
# processes against each other finds a seam neither owns.
set -euo pipefail
cd "$(dirname "$0")/.."

RUST="${RUST_BIN:-./target/release/cairn}"
if [ ! -x "$RUST" ]; then
  echo "building release binary..." >&2
  cargo build --release
fi

rule() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$1" >&2; exit 1; }

WORK=$(mktemp -d /tmp/pw-blob-demo-XXXXXX)
SEED="$WORK/seed"
LEECH="$WORK/leech"
mkdir -p "$SEED" "$LEECH"
cleanup() {
  [ -n "${SEEDER_PID:-}" ] && kill "$SEEDER_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

export CAIRN_EPOCH_SECONDS=1
OBJECTIVE=examples/collatz/objective.json
ARTIFACT=examples/collatz/artifact.json

rule "the seed has the bundle, and publishes its pinned checker"
# The bundle is copied so the seed's root is genuinely its own; the leech never
# gets one, which is the whole point.
cp -r examples "$SEED/"
OID=$("$RUST" --log "$SEED/log.jsonl" --root "$SEED" post "$OBJECTIVE" | head -1 | awk '{print $2}')
echo "  objective $OID"
"$RUST" --log "$SEED/log.jsonl" --root "$SEED" blob publish | sed 's/^/  /'

rule "the leech has the log and nothing else"
cp "$SEED/log.jsonl" "$LEECH/log.jsonl"
NEED=$("$RUST" --log "$LEECH/log.jsonl" --root "$LEECH" blob need)
echo "$NEED" | sed 's/^/  /'
echo "$NEED" | grep -q "unavailable" \
  || fail "the leech should be missing the pinned checker"

rule "the leech cannot verify: no checker, so no verdict that settles"
"$RUST" --log "$LEECH/log.jsonl" --root "$LEECH" commit "$OID" \
  --submitter alice --artifact "$ARTIFACT" --nonce n1 >/dev/null
sleep 1.1
# Exit 3 is the correct answer and the reason the code exists: "we could not
# check" is not "we checked and it is wrong". Asserted rather than tolerated --
# a 0 here would mean the leech had settled something it cannot verify.
BEFORE=$("$RUST" --log "$LEECH/log.jsonl" --root "$LEECH" reveal "$OID" \
  --submitter alice --artifact "$ARTIFACT" --nonce n1) && CODE=0 || CODE=$?
echo "$BEFORE" | sed 's/^/  /'
[ "$CODE" = "3" ] || fail "a reveal that settles nothing should exit 3, got $CODE"
echo "$BEFORE" | grep -q "unavailable" \
  || fail "a node with no checker should answer unavailable, not settle"

rule "the seed serves"
"$RUST" --log "$SEED/log.jsonl" --root "$SEED" blob serve \
  --identity "$SEED/transport.json" --listen 127.0.0.1:0 > "$WORK/serve.log" 2>&1 &
SEEDER_PID=$!
# Generating a Classic McEliece identity is ~243 ms, and the endpoint is printed
# after it. Poll rather than sleep a guessed amount.
for _ in $(seq 1 100); do
  grep -q '^{"addr"' "$WORK/serve.log" 2>/dev/null && break
  sleep 0.2
done
grep -o '^{"addr".*}$' "$WORK/serve.log" > "$WORK/endpoint.json" \
  || fail "the seeder printed no endpoint"
head -3 "$WORK/serve.log" | sed 's/^/  /'
# The key is 261,120 bytes of McEliece public key, which is why a peer record
# carries its 32-byte id and not this.
echo "  endpoint file: $(wc -c < "$WORK/endpoint.json") bytes"

rule "the leech fetches what the log says it needs"
"$RUST" --log "$LEECH/log.jsonl" --root "$LEECH" blob fetch \
  --identity "$LEECH/transport.json" --peer "$WORK/endpoint.json" --timeout 60 \
  | sed 's/^/  /' \
  || fail "the fetch did not complete"

"$RUST" --log "$LEECH/log.jsonl" --root "$LEECH" blob need \
  | grep -q "available locally" \
  || fail "the pin is still missing after a successful fetch"

rule "and now it verifies, against a checker it got from a stranger"
"$RUST" --log "$LEECH/log.jsonl" --root "$LEECH" commit "$OID" \
  --submitter bob --artifact "$ARTIFACT" --nonce n2 >/dev/null
sleep 1.1
AFTER=$("$RUST" --log "$LEECH/log.jsonl" --root "$LEECH" reveal "$OID" \
  --submitter bob --artifact "$ARTIFACT" --nonce n2)
echo "$AFTER" | sed 's/^/  /'
echo "$AFTER" | grep -q "accept" \
  || fail "a fetched checker did not produce a settling verdict"

rule "the log still audits"
"$RUST" --log "$LEECH/log.jsonl" --root "$LEECH" audit | sed 's/^/  /'

printf '\n\033[32mBLOB DEMO OK: a node with only the log fetched its verifier and used it.\033[0m\n'
