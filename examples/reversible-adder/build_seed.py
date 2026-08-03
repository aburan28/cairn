"""Emit the seed artifact: a Cuccaro ripple-carry adder, mod 2^k.

Not optimal, and deliberately so -- it is the baseline the objective ratchets
away from. Cuccaro-Draper-Kutin-Moulton (quant-ph/0410184) is the standard
one-ancilla ripple-carry construction, so starting here means an improvement
has to beat the textbook rather than beat nothing.

Run: python3 examples/reversible-adder/build_seed.py > artifact-cuccaro.json
"""
import json
import sys

BITS = 4
A = list(range(BITS))                      # wires 0..3   register A
B = list(range(BITS, 2 * BITS))            # wires 4..7   register B
CARRY = 2 * BITS                           # wire 8       the single ancilla
WIDTH = 2 * BITS + 1


def maj(c, b, a):
    """Majority-in-place: leaves the carry on wire `a`."""
    return [["CNOT", a, b], ["CNOT", a, c], ["CCX", c, b, a]]


def uma(c, b, a):
    """Un-majority and add: undoes `maj` while writing the sum bit to `b`."""
    return [["CCX", c, b, a], ["CNOT", a, c], ["CNOT", c, b]]


def build():
    gates = []
    # Forward sweep: the carry ripples up through the A register.
    gates += maj(CARRY, B[0], A[0])
    for i in range(1, BITS):
        gates += maj(A[i - 1], B[i], A[i])
    # No carry-out gate: the specification is mod 2^k, so the top carry is
    # discarded rather than written anywhere.
    #
    # Backward sweep: restores A and the ancilla while depositing the sum.
    for i in range(BITS - 1, 0, -1):
        gates += uma(A[i - 1], B[i], A[i])
    gates += uma(CARRY, B[0], A[0])
    return gates


if __name__ == "__main__":
    gates = build()
    json.dump({"qubits": WIDTH, "gates": gates}, sys.stdout, indent=2)
    sys.stdout.write("\n")
