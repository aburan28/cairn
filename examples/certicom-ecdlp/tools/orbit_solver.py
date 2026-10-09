#!/usr/bin/env python3
"""Adapt an orbit job to the one-round JSON contract of ``cairn work``.

``orbit_dp.py walk`` prints one pretty-printed artifact. Cairn's generic
worker expects one compact JSON object per line and starts a fresh solver for
each round. The assignment and zero-based round number select a different
unit inside the worker's current slice.
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

import orbit_dp


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--job", required=True, type=Path)
    parser.add_argument("--count", type=int, default=1)
    args = parser.parse_args()
    if args.count < 1:
        parser.error("--count must be positive")

    try:
        assignment = json.loads(os.environ.get("CAIRN_ASSIGNMENT") or sys.stdin.readline())
        units = assignment["units"]
        first, end = units["first"], units["end"]
        round_number = int(os.environ.get("CAIRN_ROUND", "0"))
        if not all(isinstance(n, int) for n in (first, end, round_number)):
            raise ValueError("the unit range and round must be integers")
        if first < 0 or end <= first or round_number < 0:
            raise ValueError("the assignment has no usable unit range")
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        print(f"orbit_solver: bad assignment: {error}", file=sys.stderr)
        return 2

    unit = first + round_number % (end - first)
    walker = Path(__file__).with_name("orbit_dp.py")
    result = subprocess.run(
        [sys.executable, str(walker), "walk", "--job", str(args.job.resolve()),
         "--unit", str(unit), "--count", str(args.count)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.stderr:
        sys.stderr.write(result.stderr)
    if result.returncode != 0:
        return result.returncode
    try:
        artifact = json.loads(result.stdout)
        if not isinstance(artifact, dict):
            raise ValueError("walker returned no artifact object")
    except (ValueError, json.JSONDecodeError) as error:
        print(f"orbit_solver: bad walker output: {error}", file=sys.stderr)
        return 1
    job = orbit_dp.Job(orbit_dp.load_job(str(args.job.resolve())))
    accepted, reason = orbit_dp.verify_batch(job, artifact)
    if not accepted:
        print(f"orbit_solver: local witness check refused unit {unit}: {reason}", file=sys.stderr)
        return 1
    print(json.dumps(artifact, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
