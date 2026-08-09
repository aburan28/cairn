# Sorting networks on 8 wires

Sort 8 wires with as few compare-exchange comparators as possible. Oblivious
and branch-free: the same operations run whatever the data, which is what makes
the count a fixed property of the network rather than of its input.

## Why verification is complete rather than sampled

The **zero-one principle**: a comparator network that sorts every 0/1 vector
sorts every totally ordered input. So checking all `2^8 = 256` binary vectors
is a proof, not a spot check — 256 passes over a list of at most 512 pairs.

That is the property [`docs/consensus.md`](../../docs/consensus.md) says the
whole design rests on. Verification costing about one evaluation is what lets
this network avoid designing an incentive-compatible verification game at all.

## The sentinel is not zero, and that is the interesting part

This is a **minimise** objective, so zero is the *best* score expressible. An
evaluator that returned zero for an invalid network would hand the frontier —
and the entire pool behind it — to the shortest possible garbage: an empty
comparator list, which "sorts" nothing and would score better than the proved
optimum.

So `INVALID` is `MAX_COMPARATORS + 1`, worse than any honest answer. The same
trap is in [`../golomb-ruler/`](../golomb-ruler/), and it is worth knowing
before writing any minimise evaluator: *invalid input must score badly, and on
a minimise objective badly means large.*

## No optimal artifact is shipped, on purpose

`artifacts/bubble-56.json` is a valid network at the baseline, there so you can
exercise the pipeline end to end. The 19-comparator optimum is **not** in this
directory.

`capset_progressive` does ship its optimum, and that is right for a
demonstration of the ratchet. This objective is funded to be *worked*, and an
artifact in the repository that exhausts the pool for the price of `cat` would
make the frontier decorative.

## Run it

```sh
export PROOFWORK_EPOCH_SECONDS=1
LOG=/tmp/pw-sorting.jsonl

OID=$(./target/release/proofwork --log $LOG --root . \
        post examples/sorting-network/objective.json | head -1 | awk '{print $2}')

./target/release/proofwork --log $LOG --root . try "$OID" \
  --submitter you --artifact examples/sorting-network/artifacts/bubble-56.json --settle

sleep 3 && ./target/release/proofwork --log $LOG --root . settle
```

**The second call is not redundant.** `try --settle` waits out the reveal
epoch, but a batch is not eligible until it has been closed for
`FINALITY_EPOCHS` further epochs — so the first call reports `nothing moved for
this claim in the batch that just closed`, which reads like a rejection and is
not one. The claim settles on the next drain. See
[`docs/design/settlement-convergence.md`](../../docs/design/settlement-convergence.md)
for why eligibility is a function of the clock rather than of arrival.

That accepts at 56 against a baseline of 60 and moves the frontier four steps
of the forty-one between the baseline and the optimum. The remaining
thirty-seven are the actual problem.
