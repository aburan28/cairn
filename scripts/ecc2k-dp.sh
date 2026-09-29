#!/usr/bin/env bash
# Upload ECC2K-130 distinguished points and run the campaign DP ingester.
#
# The paid path is cairn's orbit piecework objective
# (examples/certicom-ecdlp/objective-ecc2k130-orbit-batch.json). This script is
# the *campaign* path beside it: points land in the S3 corpus, dp_ingest.py
# folds them into the Postgres store, and the status pipeline publishes
# aggregates to https://aburan28.github.io/crypto/status/ — counts only, never
# the points themselves.
#
# Credentials come from `cairn secret`, not from shell history:
#
#   cairn secret set AWS_ACCESS_KEY_ID --file …
#   cairn secret set AWS_SECRET_ACCESS_KEY --file …
#   cairn secret set DATABASE_URL --file …          # optional; else Secrets Manager
#   cairn secret set RHO_DB_HOST --value rho-dp.…   # when DATABASE_URL is unset
#
# The crypto checkout that holds aws/dp_ingest.py and aws/ingest.sh:
#
#   export CAIRN_CRYPTO_ROOT=/path/to/aburan28/crypto
#   # or pass --crypto /path/to/aburan28/crypto
#
# Usage:
#   ./scripts/ecc2k-dp.sh secrets-check
#   ./scripts/ecc2k-dp.sh status              # live Pages snapshot (JSON)
#   ./scripts/ecc2k-dp.sh status-url
#   ./scripts/ecc2k-dp.sh upload --dp-file dps.bin [--slot N]
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
SLOT=""
INGEST_MODE="once"

usage() {
  sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    upload|ingest|status-url|status|secrets-check) ACTION="$1"; shift ;;
    --crypto) CRYPTO_ROOT="$2"; shift 2 ;;
    --dp-file) DP_FILE="$2"; shift 2 ;;
    --slot) SLOT="$2"; shift 2 ;;
    once|pending|verify) INGEST_MODE="$1"; shift ;;
    -h|--help) usage ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
done

[[ -n "$ACTION" ]] || usage

need_crypto() {
  if [[ -z "$CRYPTO_ROOT" ]]; then
    echo "set CAIRN_CRYPTO_ROOT or pass --crypto to the aburan28/crypto checkout" >&2
    exit 2
  fi
  if [[ ! -f "$CRYPTO_ROOT/ecc2k130/aws/dp_ingest.py" ]]; then
    echo "no ecc2k130/aws/dp_ingest.py under $CRYPTO_ROOT" >&2
    exit 2
  fi
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
  upload)
    need_crypto
    [[ -n "$DP_FILE" ]] || { echo "upload needs --dp-file" >&2; exit 2; }
    [[ -f "$DP_FILE" ]] || { echo "no such file: $DP_FILE" >&2; exit 2; }
    if [[ -z "$SLOT" ]]; then
      SLOT="${ECC_SLOT:-0}"
    fi
    # Upload one immutable object under dp/slot-N/, matching the legacy
    # worker key shape the ingester already recognises. The body's sha256
    # goes in a sibling .bin.json commit marker so a truncated put cannot
    # become a stored point.
    upload_py=$(cat <<'PY'
import hashlib, json, os, sys, time, urllib.parse
try:
    import boto3
except ImportError:
    sys.stderr.write("boto3 is required to upload: pip install boto3\n")
    sys.exit(2)

path, slot = sys.argv[1], sys.argv[2]
body = open(path, "rb").read()
if len(body) % 32:
    sys.stderr.write("dp file length %d is not a multiple of 32\n" % len(body))
    sys.exit(2)
records = len(body) // 32
if not records:
    sys.stderr.write("dp file is empty\n")
    sys.exit(2)

account = boto3.client("sts").get_caller_identity()["Account"]
bucket = os.environ.get("ECC_BUCKET") or os.environ.get("RHO_BUCKET") or ("ecc2k130-%s" % account)
region = os.environ.get("AWS_DEFAULT_REGION", "us-west-2")
epoch = int(time.time())
key = "dp/slot-%05d/%d-%016x.bin" % (int(slot), epoch, 0)
digest = hashlib.sha256(body).hexdigest()
marker = {
    "sha256": digest,
    "records": records,
    "producedAt": epoch,
    "format": "ecc2k130-gpu-packed32",
}
s3 = boto3.client("s3", region_name=region)
s3.put_object(Bucket=bucket, Key=key, Body=body, ContentType="application/octet-stream")
s3.put_object(
    Bucket=bucket,
    Key=key + ".json",
    Body=json.dumps(marker, separators=(",", ":")).encode(),
    ContentType="application/json",
)
print("uploaded s3://%s/%s (%d records)" % (bucket, key, records))
print("status will move once dp_ingest runs; see https://aburan28.github.io/crypto/status/")
PY
)
    with_secrets python3 -c "$upload_py" "$DP_FILE" "$SLOT"
    ;;
esac
