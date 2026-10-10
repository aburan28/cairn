#!/usr/bin/env bash
# One audited service period: prepare, sign, settle, and independently audit.
set -euo pipefail
cd "$(dirname "$0")/.."

CAIRN="${CAIRN_BIN:-./target/debug/cairn}"
REF="${REF_BIN:-./reference/rust/target/debug/cairn-reference}"
[ -x "$CAIRN" ] || cargo build --locked
[ -x "$REF" ] || cargo build --locked --manifest-path reference/rust/Cargo.toml
WORK=$(mktemp -d /tmp/cairn-ingest-service-XXXXXX)
trap 'rm -rf "$WORK"' EXIT
export CAIRN_KEY="$WORK/absent.key"
export CAIRN_EPOCH_SECONDS=1
export CAIRN_FINALITY_EPOCHS=1
pw() { "$CAIRN" --log "$WORK/log.jsonl" --root "$WORK" "$@"; }

python3 - "$WORK" <<'PY'
import json
import pathlib
import sys
from datetime import datetime, timezone
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

root = pathlib.Path(sys.argv[1])
key = Ed25519PrivateKey.generate()
(root / "auditor.pem").write_bytes(key.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption()))
period = int(datetime.now(timezone.utc).timestamp()) // 3600 - 1
(root / "period.txt").write_text(str(period))
(root / "idle-period.txt").write_text(str(period - 1))
for name, offset, dps in (("before", 0, 100), ("after", 1, 101)):
    stamp = datetime.fromtimestamp((period + offset) * 3600, timezone.utc)
    status = {"campaign_id": "ecc2k-130", "generated_at": stamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
              "published_at": stamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
              "dps": dps, "ingest": {"outstanding_objects": 0, "unrecognised_objects": 0}}
    (root / (name + ".json")).write_text(json.dumps(status, sort_keys=True) + "\n")
idle_stamp = datetime.fromtimestamp((period - 1) * 3600, timezone.utc)
idle_status = {"campaign_id": "ecc2k-130",
               "generated_at": idle_stamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
               "published_at": idle_stamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
               "dps": 100, "ingest": {"outstanding_objects": 0, "unrecognised_objects": 0}}
(root / "idle-before.json").write_text(json.dumps(idle_status, sort_keys=True) + "\n")
(root / "idle-objects.json").write_text("[]\n")
(root / "idle-progress.json").write_text("[]\n")
(root / "objects.json").write_text(json.dumps([{"key": "dp/example.bin", "sha256": "ab" * 32,
                                                  "bytes": 64, "records": 2}]))
(root / "progress.json").write_text(json.dumps([{"key": "dp/example.bin", "records": 2,
                                                   "duplicates": 1}]))
PY

TOOL=examples/ecc2k-ingest-service/service.py
PUBLIC=$(python3 "$TOOL" public-key "$WORK/auditor.pem")
python3 "$TOOL" objective --auditor-public-key "$PUBLIC" \
    --input-bucket example-private-dp --unit-price 800000 \
    --periods 3 --funder treasury --created-at 2026-10-10T00:00:00Z \
    --out-dir "$WORK" >/dev/null
python3 "$TOOL" prepare --input-bucket example-private-dp \
    --period "$(cat "$WORK/period.txt")" \
    --operator ingester-operator --nonce "$(printf 'ab%.0s' {1..32})" --polls 3 \
    --objects "$WORK/objects.json" --progress "$WORK/progress.json" \
    --before "$WORK/before.json" --after "$WORK/after.json" \
    --out "$WORK/body.json" >/dev/null
python3 "$TOOL" sign --body "$WORK/body.json" --auditor-key "$WORK/auditor.pem" \
    --out "$WORK/receipt.json" >/dev/null
python3 - "$WORK/checker.py" "$WORK/receipt.json" <<'PY'
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("checker", sys.argv[1])
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)
ok, why = checker.check(json.load(open(sys.argv[2])))
assert ok, why
PY

echo "settling one audited ingester period"
OUT=$(pw try "$WORK/objective.json" --submitter ingester-operator \
    --artifact "$WORK/receipt.json" --settle)
echo "$OUT"
echo "$OUT" | grep -q 'reward 800000' || { echo "expected 800000-unit service payment" >&2; exit 1; }

echo "settling an earlier idle operating period with no new input objects"
python3 "$TOOL" prepare --input-bucket example-private-dp \
    --period "$(cat "$WORK/idle-period.txt")" \
    --operator ingester-operator --nonce "$(printf 'cd%.0s' {1..32})" --polls 3 \
    --objects "$WORK/idle-objects.json" --progress "$WORK/idle-progress.json" \
    --before "$WORK/idle-before.json" --after "$WORK/before.json" \
    --out "$WORK/idle-body.json" >/dev/null
python3 "$TOOL" sign --body "$WORK/idle-body.json" --auditor-key "$WORK/auditor.pem" \
    --out "$WORK/idle-receipt.json" >/dev/null
IDLE=$(pw try "$WORK/objective.json" --submitter ingester-operator \
    --artifact "$WORK/idle-receipt.json" --settle)
echo "$IDLE"
echo "$IDLE" | grep -q 'reward 800000' || { echo "expected idle-period service payment" >&2; exit 1; }

echo "auditing the settled log with the independent reference implementation"
"$REF" --log "$WORK/log.jsonl" --root "$WORK" audit --rerun | grep 'log verified'

echo "the same period has already been paid"
DUP=$(pw try "$WORK/objective.json" --submitter another-operator \
    --artifact "$WORK/receipt.json" --settle 2>&1 || true)
echo "$DUP"
echo "$DUP" | grep -q 'duplicate unit' || { echo "duplicate period was not detected" >&2; exit 1; }
