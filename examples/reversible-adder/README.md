# Cheapest reversible 4-bit adder

An ecdsa.fail-shaped objective — minimize `width × Toffoli count` for a
reversible arithmetic circuit — where **the score is derived from the circuit
rather than declared by the submitter.**

That is the difference between this example and
[`../ecdsa-fail/`](../ecdsa-fail/), and it is the whole difference between a
demo and a bounty. The ecdsa-fail MVP accepts `{"qubits": 8, "toffoli": 1250}`
and checks only that the product is arithmetic, so anyone can type two small
integers and clear it. Here the artifact is a gate list, and the pinned
evaluator runs it on all 256 input pairs. A circuit that does not add scores as
invalid whatever it claims about itself, so the cheapest way to score well is
to actually build a cheaper adder.

In this project's terms: **the check is the payment condition.** An evaluator
that reads a number the submitter chose is not a check.

## The problem

```
wires 0..3    register A, little-endian
wires 4..7    register B, little-endian
wires 8+      ancillas, yours to use

|A⟩|B⟩|0…0⟩  ⟶  |A⟩|(A + B) mod 16⟩|0…0⟩     for all 256 pairs (A, B)
```

Three requirements, each load-bearing:

- **A is preserved.** An adder that destroys its input is not composable, and
  composition is the only reason to build one.
- **B receives the truncated sum.** Carry-out is discarded — this is mod 2⁴.
- **Ancillas return to zero.** The hard one, and the one the real ecdsa.fail
  harness enforces with its forward∘reverse check. Scratch you never clean
  cannot be reused by the next circuit, so a "cheap" circuit that leaves it
  dirty has moved its cost somewhere the score cannot see.

Gates are classical-reversible — `X`, `CNOT`, `CCX`, `SWAP` — so a basis state
maps to a basis state and simulation is a loop over gates, not over a 2ⁿ
amplitude vector. Reversibility is automatic; being the *right* permutation is
not, and that is what gets checked.

Only `CCX` counts. `X`/`CNOT`/`SWAP` are Clifford-cheap, and the published
ecdsa.fail metric counts the non-Clifford work because that is where the cost
lives on any error-corrected machine.

## The frontier, and that it moves

| circuit | width | Toffoli | score |
|---|---|---|---|
| [`artifact-cuccaro.json`](artifact-cuccaro.json) — textbook ripple-carry | 9 | 8 | **72** |
| [`artifact-truncated.json`](artifact-truncated.json) — top carry dropped | 9 | 6 | **54** |
| target | | | 24 |

The baseline is Cuccaro–Draper–Kutin–Moulton (`quant-ph/0410184`), the standard
one-ancilla construction, so an improvement has to beat the textbook rather
than beat nothing.

The second entry exists to show the bounty is not stuck, and the reasoning is
worth repeating because it is the shape of the whole game: the top carry is
discarded under mod 2⁴, so the top MAJ/UMA pair computes a value nobody reads.
`sum₃ = a₃ ⊕ b₃ ⊕ carry₃`, and `carry₃` is already sitting on wire 6 after the
forward sweep — two CNOTs, no Toffoli. That is 2 Toffolis saved by noticing
what the specification does *not* ask for.

Open from there: an ancilla-free construction would take the width to 8, and
whether 6 Toffolis is the floor at this width is not obvious.

```sh
python3 build_seed.py > artifact-cuccaro.json   # regenerate the baseline
```

## What this is not

It is **not** the ecdsa.fail challenge. That is a reversible secp256k1
point-add over 256-bit field arithmetic, scored by a multi-minute Rust
simulation with 9024-shot sampling, phase and reversibility checks, submitted
as a diff under `src/point_add/`. This is a 4-bit adder checked by exhaustive
classical simulation in milliseconds.

What transfers is the *shape*: minimize width × non-Clifford count for a
reversible circuit, on a progressive bounty where publishing beats hoarding and
an improvement must cite what it beat. What does not transfer is scale — and
running the real harness as a pinned verifier is `replay`-tier work needing a
sandboxed Rust toolchain, which [`../ecdsa-fail/GAP.md`](../ecdsa-fail/GAP.md)
files as Stage 1/2.

The 4-bit width is a deliberate choice rather than a limitation: at k=4 the
check is **total**, every input pair tested, nothing sampled. A verifier that
samples is a verifier an adversary can aim at.
