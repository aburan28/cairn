"""Emit the two reference artifacts for the mod-P adder objective.

Not optimal, and deliberately so -- these are the baseline the objective
ratchets away from, and the first step off it. The construction is the
textbook one:

    1. ACC = A + B, as a 6-bit value, using a VBE ripple-carry adder.
    2. ACC += 2^6 - P. The adder's carry-out is exactly the predicate
       `A + B >= P`, so the flag costs nothing beyond the addition.
    3. Add P back when the flag says step 2 should not have fired. Adding
       back is used rather than subtracting because inverting a ripple-carry
       needs an incoming borrow this wire does not have; the control is
       applied by conditionally *loading* the constant into a scratch
       register, which keeps every gate inside a two-control gate set.
    4. Uncompute the flag. The reduced result is below A exactly when the
       reduction fired, so comparing the result with A recovers the flag
       without a spare copy of the condition that produced it. That
       uncomputation is the part that makes modular addition harder than the
       truncated addition in `../reversible-adder/`.

Two variants are emitted. They run the *same gates* and differ only in how
many wires they reserve: `vbe-seed` gives every stage its own carry ancillas,
`reused-ancillas` hands each stage back its ancillas once they are clean.
Nothing about the Toffoli count changes -- only the declared width, which the
score multiplies by. That is the objective's first available improvement, and
it is left in on purpose: an agent that finds it has found something real.

Run: python3 examples/secp256k1-modadd/build_seed.py
"""

import json
import sys

P = 29                                   # 2^5 - 2^1 - 1
BITS = 5


# -- gate helpers -------------------------------------------------------------

def inv(gates):
    """Reverse a gate list. Every gate here is its own inverse."""
    return list(reversed(gates))


def carry(cin, a, b, cout):
    return [["CCX", a, b, cout], ["CNOT", a, b], ["CCX", cin, b, cout]]


def total(cin, a, b):
    return [["CNOT", a, b], ["CNOT", cin, b]]


def add(a_w, b_w, c_w):
    """VBE ripple-carry: b += a over n bits, carry-out left in c_w[n].

    `c_w` must be n+1 zeroed ancillas, of which c_w[0..n-1] come back clean.
    The carry-out is *not* uncomputed -- it is the useful output, and every
    caller below consumes it as an overflow bit or a predicate.
    """
    n = len(a_w)
    assert len(b_w) == n and len(c_w) == n + 1
    gates = []
    for i in range(n):
        gates += carry(c_w[i], a_w[i], b_w[i], c_w[i + 1])
    gates += [["CNOT", a_w[n - 1], b_w[n - 1]]]
    gates += total(c_w[n - 1], a_w[n - 1], b_w[n - 1])
    for i in range(n - 2, -1, -1):
        gates += inv(carry(c_w[i], a_w[i], b_w[i], c_w[i + 1]))
        gates += total(c_w[i], a_w[i], b_w[i])
    return gates


def load(const, wires, ctrl=None):
    """Toggle `const` into zeroed `wires`, optionally controlled by `ctrl`."""
    return [(["X", w] if ctrl is None else ["CNOT", ctrl, w])
            for i, w in enumerate(wires) if const >> i & 1]


def compare(a_w, b_w, c_w, into):
    """XOR the carry-out of a + b into `into`, restoring a, b and c_w.

    Only the carry chain runs, then reverses -- the sum is never written, so
    this compares rather than adds.
    """
    n = len(a_w)
    chain = []
    for i in range(n):
        chain += carry(c_w[i], a_w[i], b_w[i], c_w[i + 1])
    return chain + [["CNOT", c_w[n], into]] + inv(chain)


# -- the circuit --------------------------------------------------------------

def build(a, b, t, s, c1, c2, c3, c4, flag, spare):
    """Assemble the modular adder from the wire assignment given.

    Every argument is a wire index or list of them, so the two variants below
    differ only in what they pass -- the gate sequence is identical.
    """
    acc = b + [t]
    gates = add(a, b, c1 + [t])                        # 1. carry-out is the overflow

    gates += load(2 ** (BITS + 1) - P, s)              # 2. carry-out is the flag
    gates += add(s, acc, c2 + [flag])
    gates += load(2 ** (BITS + 1) - P, s)

    gates += [["X", flag]]                             # 3. add P back if it should not have fired
    gates += load(P, s, ctrl=flag)
    gates += add(s, acc, c3 + [spare])
    # When the load fired, acc was in [2^6 - P, 2^6) and adding P always wraps,
    # so `spare` is 1 exactly when `flag` is -- and a CNOT clears it.
    gates += [["CNOT", flag, spare]]
    gates += load(P, s, ctrl=flag)
    gates += [["X", flag]]

    gates += [["X", w] for w in a]                     # 4. flag = (result < A)
    gates += [["X", c4[0]], ["X", flag]]               #    the +1 of ~A + 1 is a carry-in
    gates += compare(a, b, c4, into=flag)
    gates += [["X", c4[0]]]
    gates += [["X", w] for w in a]
    return gates


def simulate(state, gates):
    for gate in gates:
        name = gate[0]
        if name == "X":
            state ^= 1 << gate[1]
        elif name == "CNOT":
            if state >> gate[1] & 1:
                state ^= 1 << gate[2]
        elif name == "CCX":
            if (state >> gate[1] & 1) and (state >> gate[2] & 1):
                state ^= 1 << gate[3]
        else:
            x, y = gate[1], gate[2]
            if (state >> x & 1) != (state >> y & 1):
                state ^= (1 << x) | (1 << y)
    return state


def verify(width, gates):
    """Exhaustive check over every valid residue pair. Raises on any failure."""
    mask = (1 << BITS) - 1
    for a in range(P):
        for b in range(P):
            end = simulate(a | (b << BITS), gates)
            if end & mask != a:
                raise AssertionError(f"A clobbered at ({a}, {b})")
            if (end >> BITS) & mask != (a + b) % P:
                raise AssertionError(f"wrong sum at ({a}, {b})")
            if end >> (2 * BITS) != 0:
                raise AssertionError(f"ancillas dirty at ({a}, {b})")
    return width * sum(1 for gate in gates if gate[0] == "CCX")


VARIANTS = {
    # Every stage gets its own carry ancillas.
    "vbe-seed": dict(
        a=[0, 1, 2, 3, 4], b=[5, 6, 7, 8, 9], t=15,
        c1=[10, 11, 12, 13, 14], s=[16, 17, 18, 19, 20, 21],
        c2=[22, 23, 24, 25, 26, 27], flag=28,
        c3=[29, 30, 31, 32, 33, 34], spare=35,
        c4=[36, 37, 38, 39, 40, 41], width=42,
    ),
    # Each stage hands its ancillas back once they are clean.
    "reused-ancillas": dict(
        a=[0, 1, 2, 3, 4], b=[5, 6, 7, 8, 9], t=10,
        c1=[11, 12, 13, 14, 15], s=[19, 20, 21, 22, 23, 24],
        c2=[11, 12, 13, 14, 15, 16], flag=17,
        c3=[11, 12, 13, 14, 15, 16], spare=18,
        c4=[11, 12, 13, 14, 15, 16], width=25,
    ),
}


def main() -> int:
    for name, spec in VARIANTS.items():
        spec = dict(spec)
        width = spec.pop("width")
        gates = build(**spec)
        score = verify(width, gates)
        path = f"examples/secp256k1-modadd/artifacts/{name}.json"
        with open(path, "w") as handle:
            json.dump({"qubits": width, "gates": gates}, handle, indent=1)
            handle.write("\n")
        toffoli = sum(1 for gate in gates if gate[0] == "CCX")
        print(f"{name:16} width {width:3}  toffoli {toffoli:3}  score {score:5}  -> {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
