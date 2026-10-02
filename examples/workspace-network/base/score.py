"""Score a sorting network for 8 inputs: comparators x depth, lower is better.

Part of the pinned base tree and outside `editable_paths`, so a submission
cannot change how it is measured. The submission is *code* -- solution/build.py
prints the network -- and it runs as a separate process whose only channel back
is its stdout. That split is the same one ecdsa.fail makes between
build_circuit (untrusted) and eval_circuit (trusted), and it is what stops a
submission writing its own score.json.

Exits non-zero on anything wrong with the network, which the `workspace`
verifier reads as a rejection: the toolchain already ran on the base tree, so
a failure here is a fact about the submission.
"""

import itertools
import json
import os
import subprocess
import sys

N = 8


def fail(why):
    print(why, file=sys.stderr)
    sys.exit(1)


def main():
    if os.path.lexists("score.json"):
        os.remove("score.json")
    built = subprocess.run(
        [sys.executable, "solution/build.py"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if built.returncode != 0:
        fail("solution/build.py failed")
    try:
        network = json.loads(built.stdout)
    except ValueError:
        fail("solution/build.py did not print JSON")
    if not isinstance(network, list) or len(network) > 1000:
        fail("the network must be a list of at most 1000 comparators")
    for pair in network:
        if (
            not isinstance(pair, list)
            or len(pair) != 2
            or not all(type(wire) is int for wire in pair)
            or not 0 <= pair[0] < pair[1] < N
        ):
            fail(f"bad comparator {pair!r}")

    # The 0-1 principle: a network sorts every input iff it sorts every
    # sequence of zeros and ones.
    for bits in itertools.product((0, 1), repeat=N):
        wires = list(bits)
        for low, high in network:
            if wires[low] > wires[high]:
                wires[low], wires[high] = wires[high], wires[low]
        if wires != sorted(wires):
            fail(f"does not sort {bits}")

    layer = [0] * N
    for low, high in network:
        layer[low] = layer[high] = max(layer[low], layer[high]) + 1
    depth = max(layer) if network else 0
    with open("score.json", "w") as handle:
        json.dump({"score": len(network) * depth}, handle)


main()
