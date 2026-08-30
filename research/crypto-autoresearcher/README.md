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

## SHA-1 differential paths

Two objectives in `examples/sha1-differential/`, two strategies here.

**`sha1-dv`** finds the differential path.  Usable disturbance vectors are a
null space — codewords of the message expansion whose local collisions all
close inside the 80 steps — and the score is weight in the probabilistic
window, so this is minimum-weight decoding.  `dv_basis.py` builds the space and
`dv_isd.c` searches it by information-set decoding: randomise the column order,
bring the generator to systematic form, read off the weight of every sum of one
or two rows, repeat.  It reached window weight **31** in the first round and
found nothing better in ~18,000 more, and an independent enumeration of the
classic single-bit-window family agrees on 31, which is the strongest evidence
available here that 31 is at or near the floor under this objective's closing
condition.  Dropping that condition admits 21, so 31 is not a bound.

**`sha1-collision`** finds a pair that realises one.  Two searches in series,
because they are two different problems: which differences *can* close by step
r is linear algebra (`dv_shift.py`, then the same ISD), and which message
realises one is a search over the 512 free bits (`path_climb.c`).  It settled a
pair re-converging at **34 steps**, against a free baseline of 15.

Three things had to be got right, and each was wrong first:

- **The frame.** The difference at step t is built from disturbances at steps
  t-5..t, so for the difference to satisfy the expansion from step 16 the
  vector must satisfy its recurrence from five steps earlier.  Indexed from
  step 0 it is false at steps 16..20 only — a boundary error that surfaces as a
  search that simply never finds anything.  `dv_shift.py` indexes from -5, and
  verifies the difference against the expansion rather than trusting the
  derivation.
- **The head.** A disturbance before step 0 presumes a state difference at the
  IV, and both messages start from the same IV.  Without that condition the
  path describes a pair that cannot exist.
- **The landscape.** Forcing the exact path one step at a time works until the
  state difference gets complicated — step 13 here — and then no choice of that
  step's word reaches it.  "Is this message on the path" is a cliff and a cliff
  has no gradient; scoring *how far* a message sits from the path turns the
  same search into a descent, and that is what found the pair.

Both were first submitted against objectives posted **without a ratchet**,
which meant no frontier existed and the first claim took the whole pool.  The
statements promised proportional payment; the records did not carry it.
Corrected objectives were posted and both artifacts re-submitted, paying
1,611,111 of 2,000,000 and 1,753,846 of 6,000,000 -- the distance each
actually moved from its baseline.  `examples/sha1-differential/README.md` has
the detail; the researcher now reads `min_improvement` and the direction from
the node before spending an entry it cannot win.

Neither result is close to the published state of the art.  Reduced-step SHA-1
collisions are known far deeper than 34, and the vectors of weight ~31 are the
classic family rather than a new one.  Both objectives are frontiers with the
room above them stated in their own baselines.

## Two things a first unattended sweep got wrong

Worth knowing before trusting a run of this thing.

A **randomised search that comes up empty is not an unreachable objective.**
The first sweep gave the collision climb one 90-second run per step count,
found nothing at any of them, and wrote the objective off as out of reach --
an objective a hand run had already settled at 34 steps. Descent settles into
whichever local minimum it started nearest, so restarts are the search, not a
retry of it. The strategy now restarts, and an empty run is recorded as
stalled and picked up next sweep; `OutOfReach` is kept for what is actually
permanent, like a 131-bit field in a 64-bit engine.

The **ledger takes one writer.** The MCP server wired into a Claude Code
session holds it for as long as the session does, so the CLI cannot post or
submit while it runs, and it comes back on its own after a restart. Two
daemons pointed at one log is the same hazard with none of the warning.

## Adding a strategy

A strategy is a class with `applies(checker_source)` and
`solve(objective, checker_source)`, raising `OutOfReach(reason)` when the work
is past budget. Append it to `STRATEGIES`.
