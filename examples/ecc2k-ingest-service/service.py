#!/usr/bin/env python3
"""Build a Cairn service objective and sign audited period receipts."""

import argparse
import hashlib
import json
import os
import re
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

DOMAIN = b"cairn/ecc2k130-ingest-service/v2\n"
MAX_RECEIPT_BODY_BYTES = 900_000
HERE = Path(__file__).resolve().parent


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def auditor_public_key(private_key):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = serialization.load_pem_private_key(Path(private_key).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("auditor key must be Ed25519")
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def objective(args):
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,79}", args.service):
        raise ValueError("service must be lowercase letters, digits, and hyphens")
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{2,62}", args.input_bucket):
        raise ValueError("input bucket must be a valid S3 bucket name")
    if args.period_seconds < 60 or args.period_seconds > 86400 or 86400 % args.period_seconds:
        raise ValueError("period must divide one day and be between 60 and 86400 seconds")
    if args.unit_price < 1 or args.funded_replica_periods < 1:
        raise ValueError("unit price and funded replica-periods must be positive")
    reward = args.unit_price * args.funded_replica_periods
    if reward >= 2**64:
        raise ValueError("reward does not fit Cairn's u64 amount")
    public_key = bytes.fromhex(args.auditor_public_key)
    if len(public_key) != 32:
        raise ValueError("auditor public key must be 32 bytes")
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    checker = (HERE / "checker.py.in").read_text(encoding="utf-8")
    checker = checker.replace("@AUDITOR_PUBLIC_KEY@", public_key.hex())
    checker = checker.replace("@SERVICE_ID@", args.service)
    checker = checker.replace("@INPUT_BUCKET@", args.input_bucket)
    checker = checker.replace("@PERIOD_SECONDS@", str(args.period_seconds))
    checker_bytes = checker.encode("utf-8")
    (out / "checker.py").write_bytes(checker_bytes)
    spec = {
        "created_at": args.created_at,
        "funder": args.funder,
        "goal": args.goal,
        "reward": reward,
        "piecework": {"key": "unit", "unit_price": args.unit_price},
        "statement": (
            "Pay one claim for each elapsed ECC2K-130 distinguished-point ingester "
            "replica-period approved by the pinned auditor. The receipt names the replica and intended "
            "operator; the auditor must deliver it privately until that operator commits, "
            "because the current checker cannot bind the outer submitter. A receipt includes S3 input-object "
            "digests, the matching RDS progress rows, and exact before/after public status JSON. "
            "The checker replays the auditor signature and receipt consistency. Private S3/RDS "
            "contents are checked by that auditor, so acceptance means auditor approval, not "
            "public verification of those private stores. The unit is a replica and period, including one "
            "with zero new points; distinguished-point production has a separate objective. "
            "Each period can be paid once across objectives with the same checker and piecework "
            "terms. The pool funds a configurable number of replica-periods, not a completion date."
        ),
        "artifact_schema": {
            "type": "object",
            "required": ["body", "unit", "signature"],
            "description": "Auditor-signed period receipt. See examples/ecc2k-ingest-service/README.md.",
        },
        "verifier": {
            "kind": "certificate",
            "checker": "checker.py",
            "checker_sha256": hashlib.sha256(checker_bytes).hexdigest(),
            "entrypoint": "check",
        },
    }
    write_json(out / "objective.json", spec)
    print(out / "objective.json")


def snapshot(path):
    raw = Path(path).read_bytes()
    if len(raw) > 1_000_000:
        raise ValueError("status snapshot exceeds 1 MB")
    raw.decode("utf-8")
    value = json.loads(raw)
    if (type(value) is not dict or value.get("campaign_id") != "ecc2k-130"
            or type(value.get("dps")) is not int
            or type(value.get("generated_at")) is not str
            or type(value.get("published_at")) is not str):
        raise ValueError("status must name the campaign and contain dps, generated_at, and published_at")
    if any(word in raw for word in (b"point_key", b"walk_seed", b"password", b"secret")):
        raise ValueError("refusing to include private point or credential fields in a receipt")
    return {"raw": raw.decode("utf-8"), "sha256": hashlib.sha256(raw).hexdigest()}


def prepare(args):
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,80}", args.replica_id):
        raise ValueError("replica id must be 1-80 ASCII letters, digits, dot, underscore, or hyphen")
    objects = load_json(args.objects)
    progress = load_json(args.progress)
    poll_export = load_json(args.polls_file)
    if type(objects) is not list or type(progress) is not list:
        raise ValueError("objects and progress must be arrays")
    start = args.period * args.period_seconds
    end = start + args.period_seconds
    if (type(poll_export) is not dict or set(poll_export) != {"replica_id", "start", "end", "events"}
            or poll_export["replica_id"] != args.replica_id
            or poll_export["start"] != start or poll_export["end"] != end
            or type(poll_export["events"]) is not list or not poll_export["events"]):
        raise ValueError("poll export does not match the replica and period")
    body = {
        "service": args.service,
        "input_bucket": args.input_bucket,
        "period": args.period,
        "replica_id": args.replica_id,
        "operator": args.operator,
        "nonce": args.nonce,
        "polls": len(poll_export["events"]),
        "poll_events": poll_export["events"],
        "input_objects": objects,
        "progress": progress,
        "before_status": snapshot(args.before),
        "after_status": snapshot(args.after),
    }
    if len(canonical(body)) > MAX_RECEIPT_BODY_BYTES:
        raise ValueError("receipt exceeds 900 kB; use shorter service periods before posting the objective")
    write_json(args.out, body)
    print(args.out)


def sign(args):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    body = load_json(args.body)
    key = serialization.load_pem_private_key(Path(args.auditor_key).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("auditor key must be Ed25519")
    signature = key.sign(DOMAIN + canonical(body)).hex()
    write_json(args.out, {"body": body,
                          "unit": f"{body['replica_id']}:{body['period']}",
                          "signature": signature})
    print(args.out)


def capture(args):
    """Archive exact public status bytes before they are overwritten."""
    with urllib.request.urlopen(args.url, timeout=20) as response:
        raw = response.read(1_000_001)
    if len(raw) > 1_000_000:
        raise ValueError("status response exceeds 1 MB")
    value = json.loads(raw)
    if type(value) is not dict or value.get("campaign_id") != "ecc2k-130" or type(value.get("dps")) is not int:
        raise ValueError("status response does not identify the ECC2K-130 campaign")
    if any(word in raw for word in (b"point_key", b"walk_seed", b"password", b"secret")):
        raise ValueError("refusing to archive private point or credential fields")
    Path(args.out).write_bytes(raw)
    print(f"{args.out} sha256={hashlib.sha256(raw).hexdigest()}")


def collect(args):
    """Read committed RDS progress and independently hash its private S3 inputs."""
    import boto3
    import psycopg

    if not re.fullmatch(r"[A-Za-z0-9._-]{1,80}", args.replica_id):
        raise ValueError("invalid replica id")

    def utc_stamp(value):
        if not value.endswith("Z"):
            raise ValueError("collect timestamps must be UTC and end in Z")
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
        if parsed.tzinfo != timezone.utc:
            raise ValueError("collect timestamps must be UTC")
        return parsed

    if utc_stamp(args.start) >= utc_stamp(args.end):
        raise ValueError("start must precede end")
    s3 = boto3.client("s3")
    objects = []
    progress = []
    with psycopg.connect(os.environ["DATABASE_URL"], autocommit=True) as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT object_key, records, duplicates, object_sha256, "
                "object_version_id, object_bytes, ingested_at FROM dp_ingest_progress "
                "WHERE campaign_id = %s AND ingester_id = %s "
                "AND ingested_at >= %s AND ingested_at < %s "
                "ORDER BY object_key",
                (args.campaign, args.replica_id, args.start, args.end),
            )
            rows = cursor.fetchall()
            cursor.execute(
                "SELECT completed_at, objects, rows_added FROM dp_ingest_polls "
                "WHERE campaign_id = %s AND ingester_id = %s "
                "AND completed_at >= %s AND completed_at < %s "
                "ORDER BY completed_at",
                (args.campaign, args.replica_id, args.start, args.end),
            )
            poll_rows = cursor.fetchall()
    if len(rows) > args.max_objects:
        raise ValueError(f"{len(rows)} input objects exceeds --max-objects")
    if not poll_rows or len(poll_rows) > args.max_polls:
        raise ValueError(f"{len(poll_rows)} completed polls outside allowed range")
    poll_events = []
    for completed_at, objects_done, rows_added in poll_rows:
        if (not isinstance(completed_at, datetime) or completed_at.tzinfo is None
                or type(objects_done) is not int or objects_done < 0
                or type(rows_added) is not int or rows_added < 0):
            raise ValueError("invalid completed poll row")
        poll_events.append({"completed_at": completed_at.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                            "objects": objects_done, "rows_added": rows_added})
    for key, records, duplicates, stored_digest, version_id, stored_bytes, ingested_at in rows:
        if not key.startswith("dp/") or records < 0 or duplicates < 0 or duplicates > records:
            raise ValueError(f"invalid progress row for {key}")
        if (not isinstance(stored_digest, str)
                or not re.fullmatch(r"[0-9a-f]{64}", stored_digest)
                or not isinstance(stored_bytes, int) or stored_bytes < 0
                or (version_id is not None and not isinstance(version_id, str))
                or not isinstance(ingested_at, datetime)
                or ingested_at.tzinfo is None):
            raise ValueError(f"missing or invalid ingestion-time source receipt for {key}")
        digest = hashlib.sha256()
        size = 0
        request = {"Bucket": args.bucket, "Key": key}
        if version_id is not None:
            request["VersionId"] = version_id
        response = s3.get_object(**request)
        stream = response["Body"]
        header = b""
        try:
            while chunk := stream.read(1024 * 1024):
                if len(header) < 16:
                    header += chunk[:16 - len(header)]
                digest.update(chunk)
                size += len(chunk)
        finally:
            stream.close()
        raw_records = size == records * 32
        table_records = (size == records * 32 + 16
                         and header == b"ECC2KDT3" + (3).to_bytes(4, "little")
                         + (32).to_bytes(4, "little"))
        if not (raw_records or table_records):
            raise ValueError(f"{key}: {size} bytes do not match {records} records")
        if size != stored_bytes or digest.hexdigest() != stored_digest:
            raise ValueError(f"{key}: S3 version differs from the committed progress receipt")
        stamp = ingested_at.astimezone(timezone.utc).replace(microsecond=0)
        progress.append({"key": key, "records": records, "duplicates": duplicates,
                         "sha256": stored_digest, "bytes": stored_bytes,
                         "version_id": version_id,
                         "ingested_at": stamp.isoformat().replace("+00:00", "Z")})
        objects.append({"key": key, "sha256": digest.hexdigest(), "bytes": size,
                        "records": records, "version_id": version_id})
    write_json(args.objects_out, objects)
    write_json(args.progress_out, progress)
    write_json(args.polls_out, {"replica_id": args.replica_id,
                                "start": int(utc_stamp(args.start).timestamp()),
                                "end": int(utc_stamp(args.end).timestamp()),
                                "events": poll_events})
    print(f"audited {len(rows)} committed input objects and {len(poll_rows)} completed polls")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    p = commands.add_parser("public-key", help="print the Ed25519 public key in hex")
    p.add_argument("private_key")
    p = commands.add_parser("objective", help="build a pinned checker and service objective")
    p.add_argument("--auditor-public-key", required=True)
    p.add_argument("--service", default="ecc2k130-dp-ingest-v2")
    p.add_argument("--input-bucket", required=True)
    p.add_argument("--period-seconds", type=int, default=3600)
    p.add_argument("--unit-price", type=int, required=True)
    p.add_argument("--funded-replica-periods", type=int, required=True)
    p.add_argument("--funder", required=True)
    p.add_argument("--goal", default="GOAL-certicom-ecc2k130")
    p.add_argument("--created-at", required=True)
    p.add_argument("--out-dir", required=True)
    p = commands.add_parser("prepare", help="combine audited source exports into a receipt body")
    p.add_argument("--service", default="ecc2k130-dp-ingest-v2")
    p.add_argument("--input-bucket", required=True)
    p.add_argument("--period", type=int, required=True)
    p.add_argument("--replica-id", required=True)
    p.add_argument("--operator", required=True)
    p.add_argument("--nonce", required=True)
    p.add_argument("--period-seconds", type=int, default=3600)
    p.add_argument("--polls-file", required=True)
    p.add_argument("--objects", required=True)
    p.add_argument("--progress", required=True)
    p.add_argument("--before", required=True)
    p.add_argument("--after", required=True)
    p.add_argument("--out", required=True)
    p = commands.add_parser("sign", help="sign a receipt body after independent source audit")
    p.add_argument("--body", required=True)
    p.add_argument("--auditor-key", required=True)
    p.add_argument("--out", required=True)
    p = commands.add_parser("capture", help="archive exact bytes of the current public status feed")
    p.add_argument("--url", required=True)
    p.add_argument("--out", required=True)
    p = commands.add_parser("collect", help="hash S3 inputs named by committed RDS progress rows")
    p.add_argument("--bucket", required=True)
    p.add_argument("--replica-id", required=True)
    p.add_argument("--campaign", default="ecc2k-130")
    p.add_argument("--start", required=True, help="UTC inclusive ISO timestamp")
    p.add_argument("--end", required=True, help="UTC exclusive ISO timestamp")
    p.add_argument("--max-objects", type=int, default=10000)
    p.add_argument("--max-polls", type=int, default=10000)
    p.add_argument("--objects-out", required=True)
    p.add_argument("--progress-out", required=True)
    p.add_argument("--polls-out", required=True)
    args = parser.parse_args()
    if args.command == "public-key":
        print(auditor_public_key(args.private_key))
    elif args.command == "objective":
        objective(args)
    elif args.command == "prepare":
        prepare(args)
    elif args.command == "sign":
        sign(args)
    elif args.command == "capture":
        capture(args)
    elif args.command == "collect":
        collect(args)


if __name__ == "__main__":
    main()
