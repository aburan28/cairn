"""Check the pilot holds together. Run before posting anything.

Three checks, each for a way this example rots:

  1. The objective's `evaluator_sha256` still matches the evaluator on disk.
     A stale pin is worse than a missing example -- it is an open bounty
     nobody can ever satisfy, because the id covers the pin.
  2. The pinned machine code is the one the listing assembles.
  3. Every artifact still scores what this file says it does, including the
     two that must score zero. A screening that quietly stops screening
     looks exactly like a screening that works.
"""
import hashlib
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "evaluators"))
import programbench_pilot as evaluator  # noqa: E402

EXPECTED = {
    "resolved": 10000,
    "almost": 9900,
    "partial": 4700,
    "cheating": 0,   # ships the emulator
    "hanging": 0,    # never returns
}

failures = []

path = ROOT / "evaluators" / "programbench_pilot.py"
digest = hashlib.sha256(path.read_bytes()).hexdigest()
objective = json.loads((ROOT / "objectives" / "objective-pb-pilot-0001.json").read_text())
pinned = objective["verifier"]["evaluator_sha256"]
if pinned != digest:
    failures.append(f"pin is {pinned[:16]}..., evaluator hashes to {digest[:16]}...")
print(f"pin        {'ok' if pinned == digest else 'STALE'}  {digest[:16]}...")

assembled = subprocess.run([sys.executable, str(ROOT / "tools" / "assemble.py"), "--check"],
                           capture_output=True, text=True)
if assembled.returncode != 0:
    failures.append("pinned machine code does not match the listing")
print(f"machine code {assembled.stdout.strip().splitlines()[0]}")

for name, want in EXPECTED.items():
    artifact = json.loads((ROOT / "artifacts" / f"{name}.json").read_text())
    got = evaluator.score(artifact)
    mark = "ok" if got == want else "MISMATCH"
    if got != want:
        failures.append(f"{name}: scored {got}, expected {want}")
    print(f"{name:<10} {mark:>8}  {got:>5} bp")

if failures:
    print("\nFAIL")
    for line in failures:
        print(f"  {line}")
    sys.exit(1)
print("\nselftest ok")
