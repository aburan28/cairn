# Golomb rulers, order 11

A Golomb ruler has no two pairs of marks the same distance apart — every
pairwise difference is unique. Finding short ones is hard; checking one is a
double loop over `C(11,2) = 55` differences.

Optimal rulers are known only up to order 28, and several of those cost
distributed-computing projects years of wall time. That makes this an unusual
objective: the target is a *proved* optimum, so the pool is exhausted exactly
when the known answer is reached and not one step before.

## Scored on span, not on the largest mark

Translating a ruler does not change it, so the score is `max - min`. A ruler
that starts at 500 scores what it measures. Without that, an objective could be
gamed in the harmless-looking direction of "always start at zero" and would
reject correct answers for a formatting reason.

## The sentinel is not zero

This is a **minimise** objective. Zero is the best score expressible, so
returning it for an invalid ruler would give the frontier to garbage. `INVALID`
is therefore larger than any admissible span. See
[`../sorting-network/`](../sorting-network/), which has the same trap and the
same fix.

## No optimal artifact is shipped

`artifacts/greedy-96.json` is what a naive greedy construction reaches, and it
is there to exercise the pipeline. The 72 optimum is not in this directory —
the objective is funded to be worked, not read.

A useful thing to know while working it: the checker rejected a
plausible-looking "known optimal" ruler during development because it repeated
four distances. The ruler was wrong, not the checker. Score before you submit.

## Run it

```sh
export CAIRN_EPOCH_SECONDS=1
LOG=/tmp/pw-golomb.jsonl

OID=$(./target/release/cairn --log $LOG --root . \
        post examples/golomb-ruler/objective.json | head -1 | awk '{print $2}')

./target/release/cairn --log $LOG --root . try "$OID" \
  --submitter you --artifact examples/golomb-ruler/artifacts/greedy-96.json --settle

sleep 3 && ./target/release/cairn --log $LOG --root . settle
```

**The second call is not redundant.** A batch is not eligible until it has been
closed for `FINALITY_EPOCHS` further epochs, so `try --settle` reports `nothing
moved for this claim in the batch that just closed` — which reads like a
rejection and is not one. The claim settles on the next drain, here for 128571
of the 900000 pool: four steps of the twenty-eight between baseline and
optimum.
