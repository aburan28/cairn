"""Evaluator: qubit x Toffoli cost of a *simulated* modular adder.

The ecdsa.fail shape -- minimize `peak_qubits x toffoli_count` for a reversible
arithmetic circuit -- on a sub-problem small enough that the score can be
**derived from the circuit rather than declared by the submitter**.

Why this problem
----------------
`examples/ecdsa-fail/` is a demo: it accepts `{"qubits": 8, "toffoli": 1250}`
and checks only that the product is arithmetic, so its optimum is reached by
typing two small integers. Its GAP.md names the reason -- a real accept needs
ecdsa.fail's 9024-shot simulation of a secp256k1 point-add, which is minutes of
compute and a large dependency graph, and cannot be a pinned Stage-0 evaluator.

`examples/reversible-adder/` closes that gap by shrinking the problem until
exhaustive simulation is free. This objective does the same thing one step
closer to the real target: modular addition is the primitive that dominates
elliptic-curve point-add cost, and it is strictly harder to build reversibly
than the truncated addition that example uses, because the conditional
reduction has to be uncomputed without a spare copy of its own condition.

The modulus is chosen to keep that structure rather than to be convenient:

    P = 29 = 2^5 - 2^1 - 1

is a pseudo-Mersenne prime of the same shape as secp256k1's

    p = 2^256 - 2^32 - 977

so a construction that exploits the shape here is exploiting the shape that
matters there. What does *not* carry over is scale: 5-bit registers make the
check total (841 input pairs), and 256-bit registers make it impossible. This
objective is a faithful sub-problem, not a miniature of the whole thing.

The specification
-----------------
Wires are indexed from 0:

    wires 0 .. 4      register A, little-endian (wire 0 is the LSB)
    wires 5 .. 9      register B, little-endian
    wires 10 .. n-1   ancillas, yours to use

    |A> |B> |0...0>   ->   |A> |(A + B) mod P> |0...0>

for **every** pair (A, B) with 0 <= A < P and 0 <= B < P. Three requirements:

* A is preserved. An adder that destroys its input is not composable, and
  composition is the only reason to build one.
* B holds the modular sum, already reduced into [0, P).
* **Ancillas return to zero.** This is what makes reversible arithmetic hard,
  and it is exactly what ecdsa.fail's forward-then-reverse check enforces. A
  circuit that borrows scratch and never returns it has moved its cost
  somewhere the score cannot see.

Inputs where A or B is at least P are **not** constrained. They are not valid
residues, so a correct circuit may do anything with them -- and demanding a
particular behaviour there would forbid constructions that are right about
everything the specification is about.

The gate set is classical-reversible, so a basis state maps to a basis state
and simulation is a loop over gates rather than over an amplitude vector.
Every gate is its own inverse, so reversibility is automatic; what is not
automatic, and is checked, is whether the permutation is the right one.

    ["X", a]            flip wire a
    ["CNOT", a, b]      flip b if a          (a != b)
    ["CCX", a, b, c]    flip c if a and b    (a, b, c distinct)
    ["SWAP", a, b]      exchange a and b     (a != b)

Only CCX counts toward the Toffoli total -- X, CNOT and SWAP are Clifford-cheap
and the published ecdsa.fail metric counts the non-Clifford work, which is
where the real cost lives on any error-corrected machine.

Score: `peak_qubits * toffoli_count`, lower is better. `peak_qubits` is the
declared width, not the count of wires the circuit happens to touch: reserving
a wire costs it whether or not you use it.

Returns an int, never a float -- see docs/verification.md. Malformed input
scores INVALID_SCORE rather than raising: a bad artifact is a rejection, an
exception is a broken verifier.
"""

# Above any threshold a sane objective would set on a minimize ratchet, so an
# invalid circuit can never clear one.
INVALID_SCORE = 10**18

# The modulus, and the register width that holds it. 2^(2*BITS) is 1024 states
# and only the P*P = 841 valid pairs are simulated, which is milliseconds and
# leaves no valid input untested. The point of a small P is that the check is
# total; raising it trades certainty for time.
P = 29
BITS = 5

# Ceilings, so a hostile artifact cannot bill the verifier for unbounded work.
MAX_GATES = 20_000
MAX_WIDTH = 64


def _is_int(value) -> bool:
    # bools are ints in Python and must not pass as wire indices or widths.
    return isinstance(value, int) and not isinstance(value, bool)


def _parse(artifact: dict):
    """Validate the artifact into (width, gates), or return None."""
    if not isinstance(artifact, dict):
        return None
    width = artifact.get("qubits")
    gates = artifact.get("gates")
    if not _is_int(width) or not isinstance(gates, list):
        return None
    # A width that cannot even hold the two operands is not an adder.
    if not (2 * BITS <= width <= MAX_WIDTH):
        return None
    if len(gates) > MAX_GATES:
        return None

    arity = {"X": 1, "CNOT": 2, "CCX": 3, "SWAP": 2}
    parsed = []
    for gate in gates:
        if not isinstance(gate, list) or not gate:
            return None
        name = gate[0]
        if name not in arity:
            return None
        operands = gate[1:]
        if len(operands) != arity[name]:
            return None
        for wire in operands:
            if not _is_int(wire) or not 0 <= wire < width:
                return None
        # Distinct operands: a CNOT controlled by its own target, or a Toffoli
        # sharing a control with its target, is not a reversible gate -- it is
        # a typo that would otherwise simulate as something subtly wrong.
        if len(set(operands)) != len(operands):
            return None
        parsed.append((name, operands))
    return width, parsed


def _run(state: int, gates) -> int:
    """Apply the gate list to a basis state held as a bitmask."""
    for name, operands in gates:
        if name == "X":
            (a,) = operands
            state ^= 1 << a
        elif name == "CNOT":
            a, b = operands
            if state >> a & 1:
                state ^= 1 << b
        elif name == "CCX":
            a, b, c = operands
            if (state >> a & 1) and (state >> b & 1):
                state ^= 1 << c
        else:  # SWAP
            a, b = operands
            bit_a = state >> a & 1
            bit_b = state >> b & 1
            if bit_a != bit_b:
                state ^= (1 << a) | (1 << b)
    return state


def score(artifact: dict) -> int:
    parsed = _parse(artifact)
    if parsed is None:
        return INVALID_SCORE
    width, gates = parsed

    mask = (1 << BITS) - 1
    for a in range(P):
        for b in range(P):
            # Ancillas start at zero, which is what lets the check below
            # demand they end there.
            start = a | (b << BITS)
            end = _run(start, gates)

            if end & mask != a:
                return INVALID_SCORE
            if (end >> BITS) & mask != (a + b) % P:
                return INVALID_SCORE
            if end >> (2 * BITS) != 0:
                return INVALID_SCORE

    toffoli = sum(1 for name, _ in gates if name == "CCX")
    # A modular adder with no Toffoli at all is not a counterexample worth
    # paying for -- addition is not linear over GF(2), so a circuit that passed
    # the simulation with zero non-Clifford gates means the specification above
    # is wrong, and a score of zero would then exhaust the whole pool. Refuse
    # rather than mint on a checker bug.
    if toffoli == 0:
        return INVALID_SCORE

    product = width * toffoli
    # i64 is the score ceiling; MAX_GATES x MAX_WIDTH cannot reach it, so this
    # is belt-and-braces against a future bound being raised carelessly.
    if product > (2**63 - 1):
        return INVALID_SCORE
    return product
