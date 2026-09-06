# Crypto autoresearcher

An unattended contributor to a cairn node, aimed at the cryptographic
objectives in `examples/`. It posts them to a log of its own, starts one node
over that log, picks the objectives its repertoire covers, solves them, scores
every candidate against the objective's own pinned verifier, and submits
through the ordinary commit/reveal round -- as an MCP client of the node it
runs, which is the loop `docs/agents.md` describes for any contributor.

```sh
make autoresearch            # build, post, research, audit -- one pass
research/crypto-autoresearcher/run.sh --loop    # keep sweeping
make autoresearch-gui        # the macOS app around the same loop (gui/macos)
```

`run.sh` builds `bin/cairn` with the embedded reader if it is missing (`cairn
run`, the one subcommand that serves MCP on its stdio, refuses to start
without it), compiles the solvers on first use, creates the researcher's
identity, posts `objectives.txt`, runs the loop, and audits the finished log
with the same epoch length the node used. The node answers on
`127.0.0.1:8090` (HTTP and the reader at `/ui/`) and `127.0.0.1:9010` (P2P) --
not 8080/9000, which are what an operator's own `cairn run` binds. It finds
other nodes on the LAN by itself (beacons, then a direct key request); set
`AR_BOOTSTRAP` to one or more bootstrap files, colon-separated, to reach a
seed elsewhere. Every path, port and budget is an environment variable; the
header of `autoresearcher.py` lists them.

Code lives here; runtime state -- the identity key, the node's log and keys,
the journal, `status.json`, the solver binaries, generated artifacts -- lives
in `.autoresearcher/`, which is not tracked. The identity's secret half is the
submitter name itself, so it is never committed.

## How it talks to the node

The researcher owns the node: it spawns `cairn run` with MCP on the child's
stdio and speaks JSON-RPC to it. `score_candidate` is the only judge of an
artifact, `submit_claim` is called twice per submission (commit, then reveal
once the epoch turns), and a citation is only ever the `{claim_id,
capability}` pair the server minted in `structuredContent` -- never an id read
out of prose. Reads go over the node's HTTP routes, because
`/objective/<id>` is JSON and the reader in a browser sees the same bytes.

A ledger has one writer, and this makes it the node: the researcher never
appends to the log itself, so a settled claim is already being served,
gossiped and checkpointed by the time the researcher reads the verdict.
Objectives are posted with the CLI *before* the node starts, since once
`cairn run` holds the lock nothing else can append; re-posting one already in
the log is refused by id, which is the correct answer and is journalled as
such.

## What it decided, and what decided it

The researcher never grades its own work. Every candidate goes through
`score_candidate`, which runs the pinned verifier and records nothing,
and only an `accept` is submitted. Instance parameters are read out of the
**pinned checker source**, never out of the statement: the statement is the
funder's prose and is untrusted, while the checker is the payment condition.
That is also what makes the ECDLP strategy general — a new rung on the ladder
needs no new code, only the same seven constants in the same file.

Work is estimated before it is spent, and an objective past the budget is
recorded as unreachable *with its reason* rather than skipped in silence or
retried forever.

## The engines

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

Measured here: ~6×10^7 group operations/second on fourteen cores.

`md5_birthday.c` is the generic birthday search for the truncated-digest rung
of `examples/hash-differential/`: prefix block compressed once, Brent's cycle
finding over the second block, about 2^24 compressions and no memory. The
full-width MD4/MD5/SHA-0/SHA-1 instances need a differential-path attack this
repertoire does not yet carry, and the researcher declines them saying so.

Both published test vectors were reproduced before any live instance was
attempted — `testvector-40` (`k = 1015864291073`) and `testvector-50`
(`k = 588682124876062`), the latter in about a second against the 221 seconds
the reference solve took.

## Results on this node

One pass of `make autoresearch` on 2026-09-05, five-second epochs, fourteen
threads; every settled claim re-verified under `cairn audit`, and the identity
finished with 530,000 spendable (details in `results.json`):

| objective | reward | outcome |
|---|---|---|
| `GOAL-ecdlp-intro` (45-bit) | 5,000 | solved in ~2s; reproduces the answer shipped in `examples/ecdlp/artifact.json` |
| `GOAL-ecdlp-nums-50` (50-bit) | 120,000 | solved in ~1s |
| `GOAL-ecdlp-nums-60` (60-bit) | 400,000 | solved in 12s, 7.6×10^8 steps |
| `GOAL-hash-collide-md5-48` | 5,000 | solved in 17s by birthday search, 9.2×10^7 compressions |
| `GOAL-certicom-eccp131` | 2,000,000 | declined: 131-bit field, ~2^65 group operations |
| first-blood 80/88/96/112/128-bit | — | declined: field exceeds the engine's 64-bit lanes, with the work estimate |
| collide-md4, -md5, -sha1-64, -sha0, -sha1 | — | declined: full-width collision needs a differential-path attack |
| dv-sha0, dv-sha1, secp256k1-modadd, ecdsa-fail | — | no strategy in this repertoire |

A declined objective is recorded with its reason in `state.json` and shown in
the app; nothing is skipped silently or retried forever.

## Adding a strategy

A strategy is a class with `applies(checker_source, checker_path)` and
`solve(objective, checker_source, checker_path)`, raising `OutOfReach(reason)`
when the work is past budget or outside what the engine can do. Append it to
`STRATEGIES`. Reading the pinned checker as a module is fine -- it is the
payment condition -- which is how the first-blood family's derived `Q` is
obtained.
