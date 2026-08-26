# Cheapest reversible modular adder, mod a secp256k1-shaped prime

An ecdsa.fail-shaped objective — minimize `width × Toffoli count` — one step
closer to the real target than [`../reversible-adder/`](../reversible-adder/),
and with the property that makes an objective safe to fund: **the score is
derived from the circuit rather than declared by the submitter.**

```
|A⟩ |B⟩ |0…0⟩   →   |A⟩ |(A + B) mod P⟩ |0…0⟩        P = 29 = 2⁵ − 2¹ − 1
```

## Why this problem

[`../ecdsa-fail/`](../ecdsa-fail/) is a demo, and says so: it accepts
`{"qubits": 8, "toffoli": 1250}` and checks only that the product is
arithmetic. Its optimum is reached by typing two small integers, which is not
a research result. Its `GAP.md` names the blocker — a real accept needs
ecdsa.fail's 9024-shot simulation of a secp256k1 point-add, minutes of compute
against a large dependency graph, which cannot be a pinned Stage-0 evaluator.

`../reversible-adder/` closes that gap by shrinking the problem until
exhaustive simulation is free. This objective does the same, on the primitive
that actually dominates elliptic-curve point-add cost.

Two things make it harder than the truncated addition next door:

- **The reduction is conditional.** `(A + B) mod P` has to subtract P exactly
  when the sum overflows it, and a reversible circuit cannot branch.
- **The condition has to be uncomputed.** Reversibility means the flag saying
  "the reduction fired" cannot simply be discarded, and there is no spare copy
  of it. Recovering it is the interesting part of the problem, and it is the
  same obligation ecdsa.fail's forward∘reverse check imposes.

The modulus is chosen for structure, not convenience. `P = 29 = 2⁵ − 2¹ − 1`
is a pseudo-Mersenne prime of the same shape as secp256k1's
`p = 2²⁵⁶ − 2³² − 977`, so a construction exploiting the shape here exploits
the shape that matters there. What does **not** carry over is scale: 5-bit
registers make the check total, 256-bit registers make it impossible. This is
a faithful sub-problem, not a miniature of the whole thing.

## The specification

```
wires 0 … 4      register A, little-endian (wire 0 is the LSB)
wires 5 … 9      register B, little-endian
wires 10 … n−1   ancillas, yours to use
```

For **every** pair `(A, B)` with `0 ≤ A < P` and `0 ≤ B < P`: A is preserved,
B holds the reduced sum, and every ancilla returns to zero. All 841 pairs are
simulated — the check is total, not a sample.

Inputs at or above P are **not** constrained. They are not valid residues, and
demanding a particular behaviour there would forbid constructions that are
right about everything the specification is about.

Only `CCX` counts toward the Toffoli total. `X`, `CNOT` and `SWAP` are
Clifford-cheap, and the published ecdsa.fail metric counts the non-Clifford
work, which is where the cost lives on any error-corrected machine. `qubits` is
the **declared** width, not the wires the circuit happens to touch: reserving a
wire costs it whether you use it or not.

## Run it

```bash
python3 examples/secp256k1-modadd/build_seed.py    # regenerates both artifacts, verifying each
```

```
vbe-seed         width  42  toffoli  82  score  3444
reused-ancillas  width  25  toffoli  82  score  2050
```

Both run the *same gates*. They differ only in how many wires they reserve, so
the first available improvement on this objective is pure bookkeeping — and it
is left in on purpose. An agent that finds it has found something real, and the
Toffoli count, which is the part that needs an idea, is untouched at 82.

## What the baseline is

A textbook construction, deliberately unoptimised:

1. `ACC = A + B` as a 6-bit value, VBE ripple-carry.
2. `ACC += 2⁶ − P`. The adder's carry-out **is** the predicate `A + B ≥ P`, so
   the flag costs nothing beyond the addition.
3. Add P back when the flag says step 2 should not have fired. Adding back
   rather than subtracting, because inverting a ripple-carry needs an incoming
   borrow this wire does not have; the control is applied by conditionally
   *loading* the constant into scratch, which keeps every gate inside a
   two-control gate set.
4. Uncompute the flag. The reduced result is below A exactly when the reduction
   fired, so comparing the result with A recovers the flag without a spare copy
   of the condition that produced it.

There is a lot left on the table. VBE spends roughly `4n` Toffolis per addition
where Cuccaro-Draper-Kutin-Moulton spends about `2n`, and steps 2–4 each run a
full-width adder where a purpose-built comparator would not.

## Why the check is the payment condition

The pinned evaluator simulates the submitted gate list on all 841 valid pairs
and counts CCX gates in it. A circuit that does not compute modular addition
scores as invalid whatever it claims about itself, so the cheapest way to score
well is to actually build a cheaper adder.

The artifact that wins `../ecdsa-fail/` is rejected here:

```
{"qubits": 10, "toffoli": 100, "score": 1000}   →   INVALID
```

In this project's terms: **the check is the payment condition.** An evaluator
that reads a number the submitter chose is not a check.
