"""Derive the leaderboard from a cairn log, and from nothing else.

This is the point of the whole exercise. ProgramBench's three published
columns -- mean reward, almost, resolved -- are a pure function of the
scores recorded in verdicts, so anyone holding a copy of the log recomputes
the board and gets the same numbers without trusting whoever published it.
A published board that disagrees with the log is refuted by re-running this.

Rejected claims count. The evaluator records its score in the verdict's
evidence whether or not the score cleared the threshold, so a submission
that resolved nothing still contributes its partial credit to the mean --
which is what ProgramBench's mean reward column already means, and what
Terminal Tasks tracks internally while reporting the binary outcome.

Claim ids are re-derived with `cairn canon` rather than by reimplementing
canonical serialization here. A second implementation of that rule would be
a second answer to what a record's identity is.
"""
import json
import subprocess
import sys
import tempfile
from collections import defaultdict

RESOLVED = 10000
ALMOST = 9500
CAIRN = "cairn"


def claim_id(payload):
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
        json.dump(payload, handle)
        path = handle.name
    out = subprocess.run([CAIRN, "canon", "--input", path],
                         capture_output=True, text=True)
    if out.returncode != 0:
        return None
    return out.stdout.split()[1]


def main(path, cairn_bin):
    global CAIRN
    CAIRN = cairn_bin
    submitters, scores = {}, defaultdict(list)
    for line in open(path):
        line = line.strip()
        if not line:
            continue
        record = json.loads(line)
        payload = record.get("payload", {})
        if record.get("kind") == "claim":
            identifier = claim_id(payload)
            if identifier:
                submitters[identifier] = payload.get("submitter")
        elif record.get("kind") == "verdict":
            score = payload.get("verdict", {}).get("evidence", {}).get("score")
            who = submitters.get(payload.get("claim_id"))
            if isinstance(score, int) and who:
                scores[who].append(score)

    if not scores:
        print("  no scored verdicts in this log")
        return

    rows = []
    for who, values in scores.items():
        rows.append((
            sum(1 for v in values if v >= RESOLVED) * 10000 // len(values),
            sum(1 for v in values if v >= ALMOST) * 10000 // len(values),
            sum(values) // len(values), who, len(values),
        ))
    rows.sort(reverse=True)

    print(f"  {'#':<3}{'submitter':<14}{'mean':>8}{'almost':>9}{'resolved':>10}{'n':>4}")
    for rank, (resolved, almost, mean, who, n) in enumerate(rows, 1):
        print(f"  {rank:<3}{who:<14}{mean / 100:>7.1f}%{almost / 100:>8.1f}%"
              f"{resolved / 100:>9.1f}%{n:>4}")
    print("\n  Ranked by resolved, then almost, then mean -- ProgramBench's order.")
    print("  The submitter column is an identity, not a proof of provenance:")
    print("  see APPROACH.md, 'What the log cannot say'.")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "log.jsonl",
         sys.argv[2] if len(sys.argv) > 2 else "cairn")
