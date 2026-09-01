# Crypto autoresearcher

An unattended contributor to a cairn node, aimed at the cryptographic
objectives in `examples/`. It reads a node's open objectives, picks the ones
its repertoire covers, solves them, scores every candidate against the
objective's own pinned verifier, and submits through the ordinary
commit/reveal round.

```sh
gcc -O3 -march=native -pthread -o .autoresearcher/ecdlp_rho \
    research/crypto-autoresearcher/ecdlp_rho.c
cairn identity --out .autoresearcher/researcher.json
CAIRN_EPOCH_SECONDS=1 python3 research/crypto-autoresearcher/autoresearcher.py --once
```

Code lives here; runtime state — the identity key, the journal, the solver
binary, generated artifacts — lives in `.autoresearcher/`, which is not
tracked. The identity's secret half is the submitter name itself, so it is
never committed.

## What it decided, and what decided it

The researcher never grades its own work. Every candidate goes through
`cairn propose --dry-run`, which runs the pinned verifier and records nothing,
and only an `accept` is submitted. Instance parameters are read out of the
**pinned checker source**, never out of the statement: the statement is the
funder's prose and is untrusted, while the checker is the payment condition.
That is also what makes the ECDLP strategy general — a new rung on the ladder
needs no new code, only the same seven constants in the same file.

Work is estimated before it is spent, and an objective past the budget is
recorded as unreachable *with its reason* rather than skipped in silence or
retried forever.

## The engine

`ecdlp_rho.c` is parallel Pollard rho with distinguished points (van
Oorschot–Wiener) for prime-field ECDLP up to a 62-bit field. Two things carry
its throughput:

- **Batched inversion.** Affine addition is inversion-dominated, so `W` walks
  step in lockstep and share one inversion by Montgomery's trick — `W-1`
  multiplications each way instead of `W` exponentiations.
- **No restart at a distinguished point.** Once two trails merge they agree
  forever, so the first shared DP already reports one point under two
  different `(a, b)`. A self-collision reports the same DP with the
  coefficients shifted by the cycle delta, so rho cycles are productive; only
  a cycle shorter than the DP spacing is sterile, which the stall reset
  catches.

Measured here: ~1.0×10^8 group operations/second on four cores.

Both published test vectors were reproduced before any live instance was
attempted — `testvector-40` (`k = 1015864291073`) and `testvector-50`
(`k = 588682124876062`), the latter in about a second against the 221 seconds
the reference solve took.

## Results on this node

| objective | reward | outcome |
|---|---|---|
| `GOAL-ecdlp-intro` (45-bit) | 5,000 | solved in ~1s; independently reproduced the answer shipped in `examples/ecdlp/artifact.json` |
| `GOAL-ecdlp-nums-50` (50-bit, v2 seed, previously unsolved) | 120,000 | solved in ~1s, 5.0×10^7 steps |
| `GOAL-ecdlp-nums-60` (60-bit, previously unsolved) | 400,000 | solved in ~16s, 1.7×10^9 steps |
| `GOAL-certicom-eccp131` | 2,000,000 | declined: 131-bit field, ~2^65 group operations ≈ 11,000 years at this throughput |
| rank-31/32, rank-30 variants, AADP m=8, capset, collatz, reversible-adder | — | no strategy in this repertoire |

Every settled claim re-verified under `cairn audit`.

Both live ECDLP rungs on the ladder are now solved, which by this
repository's own convention retires them: an instance whose answer is
published settles instantly for the first copier and mints nothing, so it
belongs in `instances/` as a test vector rather than in an objective. The
`k` values are recorded in `results.json` for whoever does that.

## Adding a strategy

A strategy is a class with `applies(checker_source)` and
`solve(objective, checker_source)`, raising `OutOfReach(reason)` when the work
is past budget. Append it to `STRATEGIES`.
