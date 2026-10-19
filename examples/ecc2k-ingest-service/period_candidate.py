#!/usr/bin/env python3
"""Assemble unsigned ingester period candidates on an auditor-controlled host.

The operator's S3 journal is evidence to inspect, not authority to pay. This
process never holds the auditor key or sends a claim to Cairn.
"""

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import service


class MissingEvidence(Exception):
    pass


def iso(seconds):
    return datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def utc_second(value):
    if type(value) is not str or not value.endswith("Z"):
        raise ValueError("status timestamp must be UTC seconds")
    stamp = datetime.fromisoformat(value[:-1] + "+00:00")
    if stamp.tzinfo != timezone.utc or stamp.microsecond:
        raise ValueError("status timestamp must be UTC seconds")
    delta = stamp - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return delta.days * 86400 + delta.seconds


def check_status_bracket(before, after, start, end, seconds):
    for status in (before, after):
        health = status.get("ingest")
        if (type(status.get("dps")) is not int or status["dps"] < 0
                or type(health) is not dict
                or type(health.get("outstanding_objects")) is not int
                or health["outstanding_objects"] < 0
                or type(health.get("unrecognised_objects")) is not int
                or health["unrecognised_objects"] < 0):
            raise ValueError("status lacks the pinned checker's count or ingest health")
    if after["dps"] < before["dps"]:
        raise ValueError("status point count decreased")
    before_at, after_at = utc_second(before["generated_at"]), utc_second(after["generated_at"])
    before_pub = utc_second(before["published_at"])
    after_pub = utc_second(after["published_at"])
    if not (start - seconds <= before_at <= before_pub <= start
            and end <= after_at <= after_pub <= end + seconds):
        raise ValueError("status snapshots do not bracket the operating period")


def private_directory(path):
    path = Path(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink() or stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ValueError(f"{path}: candidate directory must be private")
    return path


def fetch(s3, bucket, key, limit):
    try:
        response = s3.get_object(Bucket=bucket, Key=key)
    except Exception as error:
        code = getattr(error, "response", {}).get("Error", {}).get("Code")
        if code in ("NoSuchKey", "404", "NotFound"):
            raise MissingEvidence(key) from error
        raise
    stream = response["Body"]
    try:
        raw = stream.read(limit + 1)
    finally:
        stream.close()
    if len(raw) > limit:
        raise ValueError(f"{key}: evidence exceeds {limit} bytes")
    return raw, response.get("VersionId")


def check_journal(journal, period, seconds, replica_id):
    start, end = period * seconds, (period + 1) * seconds
    required = {"schema", "replica_id", "period", "period_seconds", "started_at",
                "ended_at", "healthy_at_end", "events", "snapshots"}
    if (type(journal) is not dict or set(journal) != required
            or journal["schema"] != "cairn-dp-operator-period-v2"
            or journal["replica_id"] != replica_id or journal["period"] != period
            or journal["period_seconds"] != seconds
            or journal["healthy_at_end"] is not True
            or type(journal["started_at"]) is not int
            or type(journal["ended_at"]) is not int
            or not start <= journal["started_at"] <= start + 60
            or not end <= journal["ended_at"] <= end + 60):
        raise ValueError("period journal is incomplete or unhealthy")
    events = journal["events"]
    if (type(events) is not list or len(events) != 1 or type(events[0]) is not dict
            or set(events[0]) not in ({"at", "started_pid"}, {"at", "continued_pid"})
            or type(events[0]["at"]) is not int
            or not start <= events[0]["at"] <= start + 60
            or type(events[0].get("started_pid", events[0].get("continued_pid"))) is not int
            or events[0].get("started_pid", events[0].get("continued_pid")) <= 0):
        raise ValueError("period journal records a restart, error, or missing ingester")
    snapshots = journal["snapshots"]
    if type(snapshots) is not list or not 2 <= len(snapshots) <= 10000:
        raise ValueError("period journal lacks status observations")
    previous = None
    for item in snapshots:
        if (type(item) is not dict
                or set(item) != {"observed_at", "sha256", "file", "generated_at"}
                or type(item["observed_at"]) is not int
                or not start <= item["observed_at"] <= end + 60
                or (previous is not None and not previous <= item["observed_at"] <= previous + 120)
                or type(item["sha256"]) is not str
                or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])
                or item["file"] != "status-" + item["sha256"] + ".json"
                or type(item["generated_at"]) is not str):
            raise ValueError("period journal has a missing or malformed status observation")
        utc_second(item["generated_at"])
        previous = item["observed_at"]
    if snapshots[0]["observed_at"] > start + 60 or snapshots[-1]["observed_at"] < end - 60:
        raise ValueError("period journal does not cover both boundaries")
    return snapshots


def assemble(args, s3=None, database_url=None):
    if s3 is None:
        import boto3
        s3 = boto3.client("s3")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,80}", args.replica_id):
        raise ValueError("invalid replica id")
    if not args.evidence_prefix or not args.evidence_prefix.endswith("/"):
        raise ValueError("evidence prefix must end in /")
    if args.period_seconds < 60 or 86400 % args.period_seconds:
        raise ValueError("period length must divide a day and be at least 60 seconds")
    if args.period < 0:
        raise ValueError("period must be nonnegative")
    root = private_directory(args.out_dir)
    destination = root / f"{args.replica_id}-{args.period}"
    if destination.exists() or destination.is_symlink():
        if (destination.is_symlink() or not destination.is_dir()
                or not (destination / "candidate.json").is_file()
                or not (destination / "body.json").is_file()):
            raise ValueError(f"{destination}: incomplete prior candidate; inspect before retry")
        record = service.load_json(destination / "candidate.json")
        body = service.load_json(destination / "body.json")
        if (record.get("schema") != "cairn-dp-period-candidate-v1"
                or record.get("period") != args.period
                or record.get("replica_id") != args.replica_id
                or record.get("body_sha256") != hashlib.sha256(service.canonical(body)).hexdigest()):
            raise ValueError(f"{destination}: prior candidate changed; inspect before retry")
        return destination
    key = args.evidence_prefix + f"period-{args.period}.json"
    raw, journal_version = fetch(s3, args.bucket, key, 900_000)
    if not journal_version:
        raise ValueError(f"{key}: evidence bucket must return an immutable version id")
    journal = json.loads(raw)
    snapshots = check_journal(journal, args.period, args.period_seconds, args.replica_id)
    start = args.period * args.period_seconds
    end = start + args.period_seconds
    before = next((item for item in snapshots
                   if start - args.period_seconds <= utc_second(item["generated_at"]) <= start), None)
    if before is None:
        raise ValueError(f"{key}: completed journal has no status generated before the period boundary")
    after = next((item for item in snapshots if end <= utc_second(item["generated_at"])), None)
    after_journal = None
    if after is None:
        next_key = args.evidence_prefix + f"period-{args.period + 1}.json"
        next_raw, next_version = fetch(s3, args.bucket, next_key, 900_000)
        if not next_version:
            raise ValueError(f"{next_key}: evidence bucket must return an immutable version id")
        next_journal = json.loads(next_raw)
        if (type(next_journal) is not dict or next_journal.get("schema") != journal["schema"]
                or next_journal.get("replica_id") != args.replica_id
                or next_journal.get("period") != args.period + 1
                or type(next_journal.get("snapshots")) is not list):
            raise ValueError(f"{next_key}: next period journal is malformed")
        after = next((item for item in next_journal["snapshots"]
                      if type(item) is dict and type(item.get("generated_at")) is str
                      and end <= utc_second(item["generated_at"]) <= end + args.period_seconds), None)
        if after is None:
            raise ValueError(f"{next_key}: completed journal has no status generated after the period boundary")
        if (not re.fullmatch(r"[0-9a-f]{64}", after.get("sha256", ""))
                or after.get("file") != "status-" + after["sha256"] + ".json"):
            raise ValueError(f"{next_key}: after status reference is malformed")
        after_journal = (next_key, next_raw, next_version)
    with tempfile.TemporaryDirectory(prefix="candidate-", dir=root) as temporary:
        work = Path(temporary)
        (work / "journal.json").write_bytes(raw)
        if after_journal:
            (work / "after-journal.json").write_bytes(after_journal[1])
        status_versions = {}
        status_generated = {}
        status_parsed = {}
        for item in snapshots + [after]:
            name = item["file"]
            if name not in status_versions:
                value, version = fetch(s3, args.bucket, args.evidence_prefix + name, 1_000_000)
                if not version:
                    raise ValueError(f"{name}: evidence bucket must return an immutable version id")
                if hashlib.sha256(value).hexdigest() != item["sha256"]:
                    raise ValueError(f"{name}: archived status digest mismatch")
                (work / name).write_bytes(value)
                parsed = json.loads(service.snapshot(work / name)["raw"])
                status_generated[name] = parsed["generated_at"]
                status_parsed[name] = parsed
                status_versions[name] = version
            if status_generated[name] != item["generated_at"]:
                raise ValueError(f"{name}: generated_at differs from journal")
        check_status_bracket(status_parsed[before["file"]],
                             status_parsed[after["file"]],
                             start, end, args.period_seconds)
        service.collect(SimpleNamespace(
            bucket=args.bucket, replica_id=args.replica_id, campaign="ecc2k-130",
            start=iso(start), end=iso(end), max_objects=args.max_objects,
            max_polls=args.max_polls, allow_empty_polls=True,
            objects_out=work / "objects.json", progress_out=work / "progress.json",
            polls_out=work / "polls.json", database_url=database_url))
        service.prepare(SimpleNamespace(
            service=args.service, input_bucket=args.bucket, period=args.period,
            period_seconds=args.period_seconds, replica_id=args.replica_id,
            operator=args.operator, nonce=os.urandom(32).hex(),
            polls_file=work / "polls.json", journal_file=work / "journal.json",
            objects=work / "objects.json", progress=work / "progress.json",
            before=work / before["file"], after=work / after["file"],
            out=work / "body.json"))
        body_hash = hashlib.sha256(service.canonical(service.load_json(work / "body.json"))).hexdigest()
        service.write_json(work / "candidate.json", {
            "schema": "cairn-dp-period-candidate-v1", "period": args.period,
            "replica_id": args.replica_id, "body_sha256": body_hash,
            "journal_sha256": hashlib.sha256(raw).hexdigest(),
            "journal_s3_key": key, "journal_version_id": journal_version,
            "after_journal_s3_key": after_journal[0] if after_journal else key,
            "after_journal_version_id": after_journal[2] if after_journal else journal_version,
            "after_journal_sha256": hashlib.sha256(after_journal[1] if after_journal else raw).hexdigest(),
            "status_version_ids": status_versions,
            "decision": "unsigned; independent auditor review required"})
        os.rename(work, destination)
    return destination


def main(argv=None, database_url=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--evidence-prefix", required=True)
    parser.add_argument("--replica-id", required=True)
    parser.add_argument("--operator", required=True)
    parser.add_argument("--service", default="ecc2k130-dp-ingest-v2")
    parser.add_argument("--period-seconds", type=int, default=600)
    parser.add_argument("--period", type=int)
    parser.add_argument("--watch-from", type=int)
    parser.add_argument("--interval", type=int, default=30)
    parser.add_argument("--max-objects", type=int, default=10000)
    parser.add_argument("--max-polls", type=int, default=10000)
    parser.add_argument("--out-dir", required=True)
    args = parser.parse_args(argv)
    if (args.period is None) == (args.watch_from is None):
        parser.error("select exactly one of --period or --watch-from")
    if args.interval < 1 or args.max_objects < 1 or args.max_polls < 1:
        parser.error("interval and collection limits must be positive")
    watching = args.watch_from is not None
    period = args.period if not watching else args.watch_from
    last_missing = None
    while True:
        current = (time.time_ns() // 1_000_000_000) // args.period_seconds
        if period >= current:
            if not watching:
                parser.error("period has not closed")
        else:
            args.period = period
            try:
                print(assemble(args, database_url=database_url))
                period += 1
                last_missing = None
            except MissingEvidence as error:
                if not watching:
                    raise
                if str(error) != last_missing:
                    print(f"waiting for completed S3 evidence: {error}", file=sys.stderr)
                    last_missing = str(error)
        if not watching:
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    raise SystemExit(main())
