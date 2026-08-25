# ProgramBench Vetted, on cairn

An approach for running [Vetto](https://vetto.ai)'s Computer Anthology
benchmarks on this network, and a working pilot that does it for one
ProgramBench-shaped task.

**[APPROACH.md](APPROACH.md)** is the argument. The short version is one line:

> A verifier can be published for free exactly when checking is not solving.

ProgramBench Vetted asks for the *source* of a program the agent is handed as a
*runnable binary*, so its grading oracle is that binary — publishing the
evaluator gives a submitter nothing the task did not already give them. That is
what lets a held-out benchmark live on a log anyone can re-derive. Terminal
Tasks is the other case: its verifiers hold the answer key, so publishing one
burns the task, and only retirement changes that.

The second finding is the one to read before building anything: **the grading is
distributable and the attribution is not.** A settled claim proves what an
artifact scored. It cannot prove which model produced it, because this network
pays for artifacts and never for effort — so a leaderboard's model labels stay
attested by a signed identity, sitting on top of verified scores.

## Run it

From the repository root:

```sh
python3 examples/programbench-vetted/tools/selftest.py   # the pin, the machine code, every score
./examples/programbench-vetted/scripts/pilot.sh          # post, reveal, settle, audit, derive the board
```

The pilot funds nothing and reaches no network. It writes `log.jsonl` and
`board-input.jsonl` here and clears both on each run.

## What is in it

| file | what it is |
|---|---|
| `evaluators/programbench_pilot.py` | the grader. Carries the reference as a flat opcode list for the stack machine it also implements — the "runnable binary" — and scores basis points over 200 cases derived from the pinned seed |
| `objectives/objective-pb-pilot-0001.json` | the objective, evaluator pinned by hash, ratchet from baseline 100 to target 10000 |
| `artifacts/` | a correct reconstruction, a near miss, an honest wrong answer, a submission that ships the emulator, and one that never returns |
| `tools/board.py` | derives the leaderboard from the exported log and nothing else |
| `tools/assemble.py` | the listing the pinned machine code was assembled from; `--check` re-derives it |
| `tools/selftest.py` | pin, machine code, and every artifact's score |

## The three escape hatches, because they are the work

Authoring the evaluator is the scarce skill, and for a behavioural grader it is
mostly the list of ways to pass without doing the task:

1. **Ship the emulator.** Embed the opcode list and interpret it: the outputs
   match and nothing was reconstructed. A behavioural grader cannot see the
   difference from outputs alone, so this one is screened by reading the source.
2. **Reach outside the namespace.** Screened by a forbidden-token pass, with
   restricted builtins as a second layer. The only real boundary is the OS
   sandbox the node runs the whole file under.
3. **Never return.** A hang would surface as `UNAVAILABLE`, which settles
   nothing and leaves the objective open — free denial of service against a
   bounty. Bounded by a line budget, so a looping artifact scores zero instead.

All three score rather than raise. An invalid submission is a bad artifact; an
exception is a broken verifier, and confusing the two decides whether the
objective can be attacked with garbage.
