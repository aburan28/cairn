#!/usr/bin/env python3
"""Supervise the private DP ingester and retain operating-period evidence.

This process never signs Cairn receipts or submits payment claims. The auditor
reviews its journal alongside S3, RDS, and the public status feed first.
"""

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from urllib.request import urlopen


def atomic_json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    with open(temporary, "w", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def status_snapshot(url, directory, observed_at):
    with urlopen(url, timeout=15) as response:
        body = response.read(1 << 20)
        if response.read(1):
            raise ValueError("status body exceeds 1 MiB")
    parsed = json.loads(body)
    if not isinstance(parsed, dict):
        raise ValueError("status is not a JSON object")
    digest = hashlib.sha256(body).hexdigest()
    name = f"status-{digest}.json"
    destination = directory / name
    try:
        with open(destination, "xb") as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError:
        if hashlib.sha256(destination.read_bytes()).hexdigest() != digest:
            raise ValueError(f"existing snapshot {destination} is corrupt")
    return {"observed_at": observed_at, "sha256": digest, "file": name,
            "generated_at": parsed.get("generated_at")}


def run(args):
    directory = Path(args.evidence_dir)
    directory.mkdir(parents=True, exist_ok=True)
    lock = open(directory / "operator.lock", "a+", encoding="utf-8")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise SystemExit("ingester supervisor already owns this evidence directory")
    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise SystemExit("supply the ingester command after --")

    stopping = False
    child = None

    def stop(_signum, _frame):
        nonlocal stopping
        stopping = True
        if child is not None and child.poll() is None:
            child.terminate()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    period = int(time.time()) // args.period_seconds
    journal = {"schema": "cairn-dp-operator-period-v1",
               "period": period, "period_seconds": args.period_seconds,
               "started_at": int(time.time()), "events": [], "snapshots": []}
    current_path = directory / "current-period.json"
    if current_path.exists():
        previous = json.loads(current_path.read_text(encoding="utf-8"))
        if previous.get("schema") != "cairn-dp-operator-period-v1":
            raise SystemExit("unrecognized current-period journal; preserve it for review")
        if previous.get("period") == period:
            journal = previous
            journal["events"].append({"at": int(time.time()), "supervisor_restart": True})
        else:
            previous["incomplete"] = True
            old_path = directory / f"period-{previous['period']}.json"
            if not old_path.exists():
                atomic_json(old_path, previous)
    periods_written = 0
    next_launch = 0.0
    try:
        while not stopping:
            now = time.time()
            current = int(now) // args.period_seconds
            if current < period:
                raise RuntimeError("wall clock moved backward; preserve journal for audit")
            if current != period:
                if not any("started_pid" in event for event in journal["events"]):
                    period = current
                    journal = {"schema": "cairn-dp-operator-period-v1",
                               "period": period, "period_seconds": args.period_seconds,
                               "started_at": int(now), "events": [], "snapshots": []}
                    continue
                journal["ended_at"] = int(now)
                journal["healthy_at_end"] = child is not None and child.poll() is None
                try:
                    journal["snapshots"].append(
                        status_snapshot(args.status_url, directory, int(now)))
                except Exception as exc:
                    journal["events"].append({"at": int(now), "status_error": str(exc)})
                atomic_json(directory / f"period-{period}.json", journal)
                periods_written += 1
                if args.max_periods and periods_written >= args.max_periods:
                    break
                period = current
                journal = {"schema": "cairn-dp-operator-period-v1",
                           "period": period, "period_seconds": args.period_seconds,
                           "started_at": int(now), "events": [], "snapshots": []}
            if child is not None and child.poll() is not None:
                journal["events"].append({"at": int(now), "exit_code": child.returncode})
                child = None
                next_launch = now + args.restart_delay
            if child is None and now >= next_launch:
                child = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                         start_new_session=True)
                journal["events"].append({"at": int(now), "started_pid": child.pid})
            try:
                journal["snapshots"].append(
                    status_snapshot(args.status_url, directory, int(now)))
            except Exception as exc:
                journal["events"].append({"at": int(now), "status_error": str(exc)})
            atomic_json(current_path, journal)
            time.sleep(min(args.poll_seconds, max(0.05, (period + 1) * args.period_seconds - now)))
    finally:
        if child is not None and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=15)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        lock.close()
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", required=True)
    parser.add_argument("--status-url", required=True)
    parser.add_argument("--period-seconds", type=int, default=3600)
    parser.add_argument("--poll-seconds", type=float, default=15)
    parser.add_argument("--restart-delay", type=float, default=15)
    parser.add_argument("--max-periods", type=int, default=0,
                        help="local rehearsal only; 0 runs until stopped")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if args.period_seconds < 2 or args.poll_seconds <= 0 or args.restart_delay < 0:
        parser.error("period must be >=2 seconds, poll >0, and restart delay >=0")
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
