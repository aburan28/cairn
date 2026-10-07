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
#   cairn secret set ECC_BUCKET --value ecc2k130-<account>
#   cairn secret set DATABASE_URL --file …          # optional; else Secrets Manager
#   cairn secret set RHO_DB_HOST --value rho-dp.…   # when DATABASE_URL is unset
#
# Uploads go through `cairn deposit`, never boto3: the node mints a
# content-keyed object name the ingester recognises, signs the PUT, and writes
# the commit marker beside the body. The deposit is created on first upload
# (ECC_BUCKET names the bucket) and reused after.
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
    # A v2 corpus carries its witness (72-byte records); the campaign store
    # takes 32-byte records only, so it is stripped to a temp file first and
    # the local original keeps its counts for a cairn claim.
    STRIPPED=""
    frame=$(DP_FILE="$DP_FILE" python3 - <<'PY'
import hashlib, os, struct, sys, tempfile
body = open(os.environ["DP_FILE"], "rb").read()
if body[:8] == b"ECC2KDP2":
    if len(body) < 16 or struct.unpack_from("<II", body, 8) != (2, 72) \
            or (len(body) - 16) % 72 or len(body) <= 16:
        sys.stderr.write("not a corpus: bad v2 framing\n")
        sys.exit(1)
    out = bytearray()
    for off in range(16, len(body), 72):
        rec = body[off:off + 72]
        out += rec[0:8] + rec[16:40]  # seed, canon[3]
    tmp = tempfile.NamedTemporaryFile(prefix="ecc2k-dp-v1-", suffix=".bin", delete=False)
    tmp.write(bytes(out))
    tmp.close()
    sys.stderr.write(
        "stripping v2 -> v1 for upload (%d records); the local file keeps its witnesses\n"
        % (len(out) // 32))
    body, stripped = bytes(out), tmp.name
else:
    stripped = ""
if len(body) % 32 or not body:
    sys.stderr.write("not uploadable: length %d is not a positive multiple of 32\n" % len(body))
    sys.exit(1)
print("%s %d %d %s" % (hashlib.sha256(body).hexdigest(), len(body), len(body) // 32, stripped))
PY
) || exit 1
    SHA256=$(echo "$frame" | awk '{print $1}')
    SIZE=$(echo "$frame" | awk '{print $2}')
    RECORDS=$(echo "$frame" | awk '{print $3}')
    STRIPPED=$(echo "$frame" | awk '{print $4}')
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
    GRANT_JSON=$("$CAIRN" deposit grant --deposit "$DEPOSIT" --submitter "slot-$SLOT" \
      --size "$SIZE" --digest "$SHA256" --slot "$SLOT")
    GRANT_ID=$(echo "$GRANT_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["grant_id"])')
    RECEIPT=$("$CAIRN" deposit put --grant "$GRANT_ID" --file "$UPLOAD")
    KEY=$(echo "$RECEIPT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["key"])')
    echo "uploaded $KEY ($RECORDS records, sha256 $SHA256)"
    echo "status will move once dp_ingest runs; see https://aburan28.github.io/crypto/status/"
    ;;
esac
