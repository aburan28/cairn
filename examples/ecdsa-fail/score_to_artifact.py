#!/usr/bin/env python3
"""Convert an ecdsafail score.json into a proofwork artifact.

ecdsa.fail writes::

    {"score": <int>, "metrics": {"toffoli": <int>, "qubits": <int>}}

proofwork's pinned evaluator in this example expects::

    {"qubits": <int>, "toffoli": <int>, "score": <int>}  # score optional

This is a *shape* adapter only. It does not re-run benchmark.sh.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def convert(score_doc: dict) -> dict:
    if not isinstance(score_doc, dict):
        raise ValueError("score.json root must be an object")
    metrics = score_doc.get("metrics")
    if not isinstance(metrics, dict):
        raise ValueError("score.json needs a metrics object")
    qubits = metrics.get("qubits")
    toffoli = metrics.get("toffoli")
    if not isinstance(qubits, int) or isinstance(qubits, bool):
        raise ValueError("metrics.qubits must be an int")
    if not isinstance(toffoli, int) or isinstance(toffoli, bool):
        raise ValueError("metrics.toffoli must be an int")
    artifact = {"qubits": qubits, "toffoli": toffoli}
    claimed = score_doc.get("score")
    if claimed is not None:
        if not isinstance(claimed, int) or isinstance(claimed, bool):
            raise ValueError("score must be an int when present")
        artifact["score"] = claimed
    return artifact


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "score_json",
        type=Path,
        help="path to ecdsafail score.json (or - for stdin)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="write artifact JSON here (default: stdout)",
    )
    args = parser.parse_args()

    raw = sys.stdin.read() if str(args.score_json) == "-" else args.score_json.read_text()
    artifact = convert(json.loads(raw))
    text = json.dumps(artifact, indent=2) + "\n"
    if args.output:
        args.output.write_text(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"score_to_artifact: {exc}", file=sys.stderr)
        raise SystemExit(1)
