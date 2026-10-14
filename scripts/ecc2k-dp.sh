#!/usr/bin/env bash
# Walk ECC2K-130 on this CPU, upload distinguished points, run the ingester.
#
# The paid path is cairn's orbit piecework objective
# (examples/certicom-ecdlp/objective-ecc2k130-orbit-batch.json). This script is
# the *campaign* path beside it: a CPU walker collects points, they land in the
# S3 corpus, dp_ingest.py folds them into the Postgres store, and the status
# pipeline publishes aggregates to https://aburan28.github.io/crypto/status/ —
# counts only, never the points themselves.
#
# End to end on a CPU-only machine, no AWS identity needed until upload:
#
#   ./scripts/ecc2k-dp.sh walk --seconds 120 --dp-file /tmp/dps.bin
#   ./scripts/ecc2k-dp.sh verify-local --dp-file /tmp/dps.bin
#   ./scripts/ecc2k-dp.sh strip --dp-file /tmp/dps.bin --out /tmp/dps-v1.bin
#   ./scripts/ecc2k-dp.sh witness --corpus /tmp/dps.bin --out-dir /tmp/claims
#   ./scripts/ecc2k-dp.sh upload --dp-file /tmp/dps.bin --slot 0   # needs AWS secrets
#   ./scripts/ecc2k-dp.sh ingest once                             # needs AWS + Postgres
#
# Credentials come from `cairn secret`, not from shell history:
#
#   cairn secret set AWS_ACCESS_KEY_ID --file …
#   cairn secret set AWS_SECRET_ACCESS_KEY --file …
#   cairn secret set ECC_BUCKET --value ecc2k130-<account>
#   cairn secret set DATABASE_URL --file …          # optional; else Secrets Manager
#   cairn secret set RHO_DB_HOST --value rho-dp.…   # when DATABASE_URL is unset
#
# Uploads go through cairn deposit, never boto3: the node mints a
# content-keyed object name the ingester recognises, signs the PUT, and writes
# the commit marker beside the body. The deposit is created on first upload
# (ECC_BUCKET names the bucket) and reused after.
#
# The crypto checkout holds the CPU walker, witness emitter, dp_ingest.py and
# ingest.sh. Point at one, or let walk clone it:
#
#   export CAIRN_CRYPTO_ROOT=/path/to/aburan28/crypto
#   # or pass --crypto /path/to/aburan28/crypto
#   # or pass nothing: a shallow clone lands in .local/crypto/
#
# Usage:
#   ./scripts/ecc2k-dp.sh secrets-check
#   ./scripts/ecc2k-dp.sh status              # live Pages snapshot (JSON)
#   ./scripts/ecc2k-dp.sh status-url
#   ./scripts/ecc2k-dp.sh walk --seconds N --dp-file F [--weight 34] [--launches L]
#   ./scripts/ecc2k-dp.sh verify-local --dp-file F [--slot N]
#   ./scripts/ecc2k-dp.sh strip --dp-file V2 --out V1
#   ./scripts/ecc2k-dp.sh witness --corpus F --out-dir D [--max N]
#   ./scripts/ecc2k-dp.sh upload --dp-file F [--slot N]
#   ./scripts/ecc2k-dp.sh ingest [once|pending|verify]
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CAIRN="${CAIRN_BIN:-$ROOT/target/release/cairn}"
if [[ ! -x "$CAIRN" ]]; then
  CAIRN="${CAIRN_BIN:-$ROOT/target/debug/cairn}"
fi
if [[ ! -x "$CAIRN" ]]; then
  echo "cairn binary not found; build with cargo build --release, or set CAIRN_BIN" >&2
  exit 2
fi

CRYPTO_ROOT="${CAIRN_CRYPTO_ROOT:-}"
STATUS_URL="${ECC2K130_STATUS_URL:-https://aburan28.github.io/crypto/status/status.json}"
ACTION=""
DP_FILE=""
OUT_FILE=""
OUT_DIR=""
SLOT=""
SECONDS=""
LAUNCHES=""
WEIGHT="34"
RUN_ID=""
MAX_POINTS=""
REBUILD=0
INGEST_MODE="once"

usage() {
  sed -n '2,44p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    upload|ingest|status-url|status|secrets-check|walk|strip|verify-local|witness) ACTION="$1"; shift ;;
    --crypto) CRYPTO_ROOT="$2"; shift 2 ;;
    --dp-file|--corpus) DP_FILE="$2"; shift 2 ;;
    --out) OUT_FILE="$2"; shift 2 ;;
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    --slot) SLOT="$2"; shift 2 ;;
    --seconds) SECONDS="$2"; shift 2 ;;
    --launches) LAUNCHES="$2"; shift 2 ;;
    --weight) WEIGHT="$2"; shift 2 ;;
    --run-id) RUN_ID="$2"; shift 2 ;;
    --max) MAX_POINTS="$2"; shift 2 ;;
    --rebuild) REBUILD=1; shift ;;
    once|pending|verify) INGEST_MODE="$1"; shift ;;
    -h|--help) usage ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
done

[[ -n "$ACTION" ]] || usage

# A crypto checkout, cloned on demand into .local/ (gitignored) when the
# operator did not point at one. The walker, the witness emitter and the
# ingester all live there; refusing without --crypto would make `walk` a
# two-step for everyone who only wants to run the search on their CPU.
ensure_crypto() {
  if [[ -z "$CRYPTO_ROOT" ]]; then
    CRYPTO_ROOT="$ROOT/.local/crypto"
    if [[ ! -d "$CRYPTO_ROOT/ecc2k130" ]]; then
      echo "fetching aburan28/crypto into $CRYPTO_ROOT (shallow; set CAIRN_CRYPTO_ROOT to use your own)" >&2
      mkdir -p "$ROOT/.local"
      # Sparse: the walk needs ecc2k130/ only, and the full tree is gigabytes.
      # Old git without --filter support falls back to a plain shallow clone.
      if ! (git clone --depth 1 --filter=blob:none --sparse https://github.com/aburan28/crypto "$CRYPTO_ROOT" >&2 \
            && git -C "$CRYPTO_ROOT" sparse-checkout set ecc2k130 >&2); then
        rm -rf "$CRYPTO_ROOT"
        git clone --depth 1 https://github.com/aburan28/crypto "$CRYPTO_ROOT" >&2
      fi
    fi
  fi
  if [[ ! -f "$CRYPTO_ROOT/ecc2k130/aws/dp_ingest.py" ]]; then
    echo "no ecc2k130/aws/dp_ingest.py under $CRYPTO_ROOT" >&2
    exit 2
  fi
}

need_crypto() {
  ensure_crypto
}

# The CPU walker, built once and reused. ECC_NO_CUDA, g++ and OpenMP only --
# no CUDA toolchain, no GPU. The default build carries the witness (v2
# records), which the campaign store refuses and cairn's objective requires;
# `strip` derives the uploadable v1 bytes from the same file, so one walk
# feeds both paths.
ensure_cpu_walker() {
  ensure_crypto
  local bin="$CRYPTO_ROOT/ecc2k130/ecc2k130-cpu"
  if [[ "$REBUILD" = "1" || ! -x "$bin" ]]; then
    echo "building the CPU walker in $CRYPTO_ROOT/ecc2k130 (g++, no CUDA)..." >&2
    make -C "$CRYPTO_ROOT/ecc2k130" cpu -j"$(nproc 2>/dev/null || echo 4)" >&2
  fi
  [[ -x "$bin" ]] || { echo "the CPU walker did not build at $bin" >&2; exit 2; }
  echo "$bin"
}

ensure_witness() {
  ensure_crypto
  local bin="$CRYPTO_ROOT/ecc2k130/build/witness"
  if [[ "$REBUILD" = "1" || ! -x "$bin" ]]; then
    echo "building the witness emitter in $CRYPTO_ROOT/ecc2k130..." >&2
    make -C "$CRYPTO_ROOT/ecc2k130" witness -j"$(nproc 2>/dev/null || echo 4)" >&2
  fi
  [[ -x "$bin" ]] || { echo "the witness emitter did not build at $bin" >&2; exit 2; }
  echo "$bin"
}

# Secrets the child needs. Missing ones are skipped so ingest.sh can fall
# back to instance profiles / Secrets Manager the way the crypto scripts do.
secret_names=(
  AWS_ACCESS_KEY_ID
  AWS_SECRET_ACCESS_KEY
  AWS_SESSION_TOKEN
  AWS_DEFAULT_REGION
  DATABASE_URL
  RHO_DB_HOST
  RHO_DB_SECRET
  RHO_DB_SSLMODE
  ECC_BUCKET
  RHO_BUCKET
  ECC_STATUS_BUCKET
  RHO_STATUS_BUCKET
  RHO_CAMPAIGN
  INGEST_THREADS
)

required_for_upload=(
  AWS_ACCESS_KEY_ID
  AWS_SECRET_ACCESS_KEY
)

with_secrets() {
  local present=()
  local name
  for name in "${secret_names[@]}"; do
    if "$CAIRN" secret get "$name" >/dev/null 2>&1; then
      present+=("$name")
    fi
  done
  if [[ ${#present[@]} -eq 0 ]]; then
    echo "no campaign secrets set; try:" >&2
    echo "  cairn secret set AWS_ACCESS_KEY_ID --file …" >&2
    echo "  cairn secret set AWS_SECRET_ACCESS_KEY --file …" >&2
    exit 2
  fi
  exec "$CAIRN" secret run "${present[@]}" -- "$@"
}

# One copy of the corpus framing both `strip`, `verify-local` and `upload`
# share: v1 is a headerless stream of 32-byte records, v2 is a 16-byte
# `ECC2KDP2` header plus 72-byte records (seed, iters, canon[3], counts[8]),
# v3 is a 16-byte `ECC2KDT3` header plus 32-byte records of the table walk.
# The campaign store takes 32-byte records only and refuses v2 outright
# (dp_ingest.py: "rebuild the client with WITNESS=0"); it strips a v3 header
# itself and checks signatures over the original bytes, so v3 uploads as-is
# and only v2 is stripped client-side.
FRAME_PRELUDE=$(cat <<'PY'
import hashlib, json, re, struct, sys

V2_MAGIC = b"ECC2KDP2"
V3_MAGIC = b"ECC2KDT3"
ORBIT_KEY_RE = re.compile(r"^dp/(slot-\d+)/([0-9a-f]{32})-(\d+)-([0-9a-f]{64})\.bin$")

def frame(body):
    if body[:8] == V2_MAGIC:
        if len(body) < 16:
            return ("bad", 0, "v2 header is truncated")
        version, stride = struct.unpack_from("<II", body, 8)
        if (version, stride) != (2, 72):
            return ("bad", 0, "v2 header says version=%d stride=%d, want 2/72" % (version, stride))
        if (len(body) - 16) % 72:
            return ("bad", 0, "v2 body length %d is not 16 + 72*N" % len(body))
        records = (len(body) - 16) // 72
        if not records:
            return ("bad", 0, "v2 file carries no records")
        return ("v2", records, "")
    if body[:8] == V3_MAGIC:
        if len(body) < 16 or struct.unpack_from("<II", body, 8) != (3, 32):
            return ("bad", 0, "v3 header is not version=3 stride=32")
        if (len(body) - 16) % 32:
            return ("bad", 0, "v3 body length %d is not 16 + 32*N" % len(body))
        records = (len(body) - 16) // 32
        if not records:
            return ("bad", 0, "v3 file carries no records")
        return ("v3", records, "")
    if len(body) % 32:
        return ("bad", 0, "length %d is not a multiple of 32 and has no v2/v3 magic" % len(body))
    if not body:
        return ("bad", 0, "file is empty")
    return ("v1", len(body) // 32, "")

def strip_v2(body):
    out = bytearray()
    for off in range(16, len(body), 72):
        rec = body[off:off + 72]
        out += rec[0:8] + rec[16:40]  # seed, canon[3]; iters and counts stay local
    return bytes(out)
PY
)

case "$ACTION" in
  secrets-check)
    echo "secrets directory: $($CAIRN secret path)"
    missing=0
    for name in "${required_for_upload[@]}"; do
      if "$CAIRN" secret get "$name" >/dev/null 2>&1; then
        echo "  $name: set"
      else
        echo "  $name: MISSING"
        missing=1
      fi
    done
    for name in DATABASE_URL RHO_DB_HOST RHO_WORK_FEED_URL AWS_DEFAULT_REGION ECC_BUCKET; do
      if "$CAIRN" secret get "$name" >/dev/null 2>&1; then
        echo "  $name: set (optional)"
      else
        echo "  $name: unset (optional)"
      fi
    done
    exit "$missing"
    ;;
  status-url)
    # The public page; the feed URL is optional and named so Pages can
    # publish without an AWS identity when RHO_WORK_FEED_URL is set in the
    # crypto repo's Actions secrets.
    echo "https://aburan28.github.io/crypto/status/"
    if "$CAIRN" secret get RHO_WORK_FEED_URL >/dev/null 2>&1; then
      echo "feed: $($CAIRN secret get RHO_WORK_FEED_URL)"
    fi
    ;;
  status)
    echo "GET $STATUS_URL"
    if command -v curl >/dev/null 2>&1; then
      curl -fsSL "$STATUS_URL" | python3 -m json.tool 2>/dev/null || curl -fsSL "$STATUS_URL"
    else
      python3 - "$STATUS_URL" <<'PY'
import json, sys, urllib.request
print(json.dumps(json.load(urllib.request.urlopen(sys.argv[1])), indent=2))
PY
    fi
    ;;
  ingest)
    need_crypto
    with_secrets "$CRYPTO_ROOT/ecc2k130/aws/ingest.sh" "$INGEST_MODE"
    ;;
  walk)
    walker=$(ensure_cpu_walker)
    if [[ -z "$DP_FILE" ]]; then
      DP_FILE="$ROOT/.local/dps/ecc2k130-$(date +%s).bin"
      echo "no --dp-file given; collecting into $DP_FILE" >&2
    fi
    mkdir -p "$(dirname "$DP_FILE")"
    if [[ -z "$RUN_ID" ]]; then
      RUN_ID="$RANDOM"
    fi
    if [[ -z "$SECONDS" && -z "$LAUNCHES" ]]; then
      SECONDS=120
    fi
    args=(--curve 131 --dp-weight "$WEIGHT" --dp-file "$DP_FILE"
          --run-id "$RUN_ID" --verify 0)
    [[ -n "$LAUNCHES" ]] && args+=(--launches "$LAUNCHES")
    echo "walking certicom ecc2k-130 on CPU: weight <= $WEIGHT, run-id $RUN_ID" >&2
    if [[ -n "$SECONDS" && -z "$LAUNCHES" ]]; then
      if command -v timeout >/dev/null 2>&1; then
        limit=(timeout "$SECONDS")
      elif command -v gtimeout >/dev/null 2>&1; then
        limit=(gtimeout "$SECONDS")
      else
        echo "no timeout(1) on this machine; pass --launches instead of --seconds" >&2
        exit 2
      fi
      # 124 is the deadline, not a failure: the walker checkpoints on
      # SIGTERM, so a timed run keeps what it collected.
      "${limit[@]}" "$walker" "${args[@]}" >&2 || code=$?
      code=${code:-0}
      if [[ "$code" != "0" && "$code" != "124" ]]; then
        echo "the walker exited $code" >&2
        exit "$code"
      fi
    else
      "$walker" "${args[@]}" >&2
    fi
    python3 -c "$FRAME_PRELUDE
body = open(sys.argv[1], 'rb').read()
kind, records, why = frame(body)
if kind == 'bad':
    sys.stderr.write('collected file is not a corpus: %s\n' % why)
    sys.exit(1)
print('collected %d bytes: %s, %d distinguished orbit(s) in %s' % (len(body), kind, records, sys.argv[1]))
print('next: verify-local to check it, strip for the campaign upload, witness for a cairn claim')
" "$DP_FILE"
    ;;
  strip)
    [[ -n "$DP_FILE" ]] || { echo "strip needs --dp-file (the v2 corpus)" >&2; exit 2; }
    [[ -f "$DP_FILE" ]] || { echo "no such file: $DP_FILE" >&2; exit 2; }
    [[ -n "$OUT_FILE" ]] || { echo "strip needs --out (where the v1 bytes go)" >&2; exit 2; }
    python3 -c "$FRAME_PRELUDE
body = open(sys.argv[1], 'rb').read()
kind, records, why = frame(body)
if kind == 'bad':
    sys.stderr.write('not a corpus: %s\n' % why)
    sys.exit(1)
if kind == 'v3':
    sys.stderr.write('not stripping: the ingester reads a v3 table corpus itself and checks it over the original bytes\n')
    sys.exit(1)
if kind == 'v1':
    open(sys.argv[2], 'wb').write(body)
    print('already v1: copied %d records unchanged to %s' % (records, sys.argv[2]))
else:
    open(sys.argv[2], 'wb').write(strip_v2(body))
    print('stripped v2 -> v1: %d records, seed+canon kept, iters+counts stay in %s' % (records, sys.argv[1]))
    print('wrote %s (%d bytes)' % (sys.argv[2], records * 32))
" "$DP_FILE" "$OUT_FILE"
    ;;
  verify-local)
    [[ -n "$DP_FILE" ]] || { echo "verify-local needs --dp-file" >&2; exit 2; }
    [[ -f "$DP_FILE" ]] || { echo "no such file: $DP_FILE" >&2; exit 2; }
    if [[ -z "$SLOT" ]]; then
      SLOT="${ECC_SLOT:-0}"
    fi
    python3 -c "$FRAME_PRELUDE
import time
body = open(sys.argv[1], 'rb').read()
kind, records, why = frame(body)
if kind == 'bad':
    sys.stderr.write('NOT UPLOADABLE: %s\n' % why)
    sys.exit(1)
if kind == 'v2':
    print('valid v2 corpus: %d records with carried witnesses (iters+counts)' % records)
    print('NOT UPLOADABLE as-is: the campaign store takes 32-byte records only and refuses v2;')
    print('run: ecc2k-dp.sh strip --dp-file <v2 corpus> --out <v1 file>')
    sys.exit(1)
digest = hashlib.sha256(body).hexdigest()
slot = int(sys.argv[2])
key = 'dp/slot-%05d/%s-0-%s.bin' % (slot, '0' * 32, digest)
assert ORBIT_KEY_RE.match(key), 'key shape drifted from dp_ingest ORBIT_KEY_RE'
print('format: %s, %d records, %d bytes' % (kind, records, len(body)))
print('sha256: %s' % digest)
print('marker: %s' % json.dumps({'sha256': digest, 'records': records, 'producedAt': int(time.time()), 'format': 'ecc2k130-gpu-packed32'}, separators=(',', ':')))
print('key shape: %s  (stream id is minted per grant)' % key)
print('UPLOADABLE: upload would put these bytes under dp/slot-%05d/' % slot)
" "$DP_FILE" "$SLOT"
    ;;
  witness)
    wit=$(ensure_witness)
    [[ -n "$DP_FILE" ]] || { echo "witness needs --corpus (the collected file)" >&2; exit 2; }
    [[ -f "$DP_FILE" ]] || { echo "no such file: $DP_FILE" >&2; exit 2; }
    [[ -n "$OUT_DIR" ]] || { echo "witness needs --out-dir (one batch-*.json per claim)" >&2; exit 2; }
    mkdir -p "$OUT_DIR"
    job="$ROOT/examples/certicom-ecdlp/jobs/ecc2k130.json"
    wargs=(--corpus "$DP_FILE" --job "$job" --out-dir "$OUT_DIR")
    [[ -n "$MAX_POINTS" ]] && wargs+=(--max "$MAX_POINTS")
    "$wit" "${wargs[@]}" >&2
    # Every emitted batch through cairn's own verifier, not just the emitter's
    # word for it: the emitter and the payer must agree, in this checkout.
    batches=("$OUT_DIR"/batch-*.json)
    [[ -e "${batches[0]}" ]] || { echo "the emitter wrote no batches" >&2; exit 1; }
    python3 "$ROOT/examples/certicom-ecdlp/tools/orbit_dp.py" verify --job "$job" "${batches[@]}"
    echo "claim-ready: ${#batches[@]} batch(es) in $OUT_DIR, each accepted by the pinned checker"
    ;;
  upload)
    [[ -n "$DP_FILE" ]] || { echo "upload needs --dp-file" >&2; exit 2; }
    [[ -f "$DP_FILE" ]] || { echo "no such file: $DP_FILE" >&2; exit 2; }
    if [[ -z "$SLOT" ]]; then
      SLOT="${ECC_SLOT:-0}"
    fi
    # Through `cairn deposit`, never boto3: the node mints a content-keyed
    # object name the ingester recognises, signs the PUT itself, and writes
    # the commit marker beside the body. AWS credentials stay in
    # `cairn secret`; no Python AWS stack and no keys in the environment.
    DEPOSIT="${ECC_DEPOSIT:-ecc2k130}"
    if ! "$CAIRN" secret get AWS_ACCESS_KEY_ID >/dev/null 2>&1 \
        || ! "$CAIRN" secret get AWS_SECRET_ACCESS_KEY >/dev/null 2>&1; then
      echo "no AWS credentials stored; try:" >&2
      echo "  cairn secret set AWS_ACCESS_KEY_ID --file …" >&2
      echo "  cairn secret set AWS_SECRET_ACCESS_KEY --file …" >&2
      exit 2
    fi
    # Use the same framing check as verify-local. V2 becomes v1 for the
    # campaign store; v3 keeps its signed header and uses proxy redemption so
    # the node can validate those bytes before it writes a commit marker.
    upload_py="$FRAME_PRELUDE
import tempfile
raw = open(sys.argv[1], 'rb').read()
kind, records, why = frame(raw)
if kind == 'bad':
    sys.stderr.write('not uploading: %s\n' % why)
    sys.exit(1)
stripped = ''
if kind == 'v2':
    body = strip_v2(raw)
    tmp = tempfile.NamedTemporaryFile(prefix='ecc2k-dp-v1-', suffix='.bin', delete=False)
    tmp.write(body)
    tmp.close()
    stripped = tmp.name
    sys.stderr.write('stripping v2 -> v1 for upload (%d records); the local file keeps its witnesses\n' % records)
else:
    body = raw
print('%s\t%d\t%d\t%s\t%s' % (hashlib.sha256(body).hexdigest(), len(body), records, kind, stripped))
"
    frame=$(python3 -c "$upload_py" "$DP_FILE") || exit 1
    IFS=$'\t' read -r SHA256 SIZE RECORDS KIND STRIPPED <<< "$frame"
    UPLOAD="$DP_FILE"
    if [[ -n "$STRIPPED" ]]; then
      UPLOAD="$STRIPPED"
      trap 'rm -f "$STRIPPED"' EXIT
    fi
    if "$CAIRN" deposit show "$DEPOSIT" >/dev/null 2>&1; then
      if ! "$CAIRN" deposit show "$DEPOSIT" | grep -q "key_shape: ecc2k-dp"; then
        echo "deposit $DEPOSIT exists but does not mint campaign keys; re-add it:" >&2
        echo "  cairn deposit add --name $DEPOSIT --provider s3 --bucket B --prefix dp/ \\" >&2
        echo "    --region R --key-shape ecc2k-dp" >&2
        exit 2
      fi
    else
      BUCKET="$("$CAIRN" secret get ECC_BUCKET 2>/dev/null || true)"
      [[ -n "$BUCKET" ]] || BUCKET="${ECC_BUCKET:-}"
      if [[ -z "$BUCKET" ]]; then
        echo "no campaign bucket configured; try:" >&2
        echo "  cairn secret set ECC_BUCKET --value ecc2k130-<account>" >&2
        exit 2
      fi
      REGION="$("$CAIRN" secret get AWS_DEFAULT_REGION 2>/dev/null || true)"
      [[ -n "$REGION" ]] || REGION="${AWS_DEFAULT_REGION:-us-west-2}"
      "$CAIRN" deposit add --name "$DEPOSIT" --provider s3 --bucket "$BUCKET" \
        --prefix dp/ --region "$REGION" --key-shape ecc2k-dp >&2
    fi
    grant_args=(--deposit "$DEPOSIT" --submitter "slot-$SLOT"
      --digest "$SHA256" --slot "$SLOT")
    if [[ "$KIND" != "v3" ]]; then
      grant_args+=(--size "$SIZE")
    fi
    GRANT_JSON=$("$CAIRN" deposit grant "${grant_args[@]}")
    GRANT_ID=$(echo "$GRANT_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["grant_id"])')
    RECEIPT=$("$CAIRN" deposit put --grant "$GRANT_ID" --file "$UPLOAD")
    KEY=$(echo "$RECEIPT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["key"])')
    echo "uploaded $KEY ($RECORDS records, sha256 $SHA256)"
    echo "status will move once dp_ingest runs; see https://aburan28.github.io/crypto/status/"
    ;;
esac
