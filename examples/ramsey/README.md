# A witness for R(4,4) = 18

Colour the edges of `K_17` with two colours so that no four vertices are
mutually joined in a single colour. `R(4,4) = 18` says every 2-colouring of
`K_18` contains a monochromatic `K_4`, and that 17 is the largest complete
graph where one can be avoided.

## Why this is pass/fail and not a ratchet

There is no number to push. The question is answered by a **witness**, and a
witness either works or does not.

That shape is worth having in the examples alongside the scored objectives,
because not everything worth funding is a frontier. A certificate objective
settles once, for the whole reward, and then the objective is closed — which is
the correct behaviour for a question that has an answer rather than a record.

## The check is complete

All `C(17,4) = 2380` four-subsets, six edge lookups each. No sampling.

Two things the checker enforces that are easy to leave out:

- **Symmetry, with a zero diagonal.** An asymmetric matrix would let a
  submitter give one pair two different colours and dodge the clique test from
  one side. Checked rather than assumed.
- **Strict 0/1 values**, rejecting booleans. Python's `bool` is an `int`, so
  `isinstance(True, int)` is true, and a matrix of `True`/`False` would sail
  through a naive type check.

## The witness *is* shipped, unlike the other new examples

[`../sorting-network/`](../sorting-network/) and
[`../golomb-ruler/`](../golomb-ruler/) deliberately withhold their optima, so
that the frontier is worked rather than copied. This one ships
`artifacts/paley-17.json` in full.

The difference is that there is nothing here to protect. The Paley graph of
order 17 — join `i` and `j` when `i - j` is a quadratic residue mod 17 — is
three lines of arithmetic, and this is a witness to an established bound rather
than an open search. Withholding it would inconvenience a reader and stop
nobody.

## Run it

```sh
export PROOFWORK_EPOCH_SECONDS=1
LOG=/tmp/pw-ramsey.jsonl

OID=$(./target/release/proofwork --log $LOG --root . \
        post examples/ramsey/objective.json | head -1 | awk '{print $2}')

./target/release/proofwork --log $LOG --root . try "$OID" \
  --submitter you --artifact examples/ramsey/artifacts/paley-17.json --settle

sleep 3 && ./target/release/proofwork --log $LOG --root . settle
```

**The second call is not redundant.** A batch is not eligible until it has been
closed for `FINALITY_EPOCHS` further epochs, so `try --settle` reports `nothing
moved for this claim in the batch that just closed` — which reads like a
rejection and is not one. The certificate settles on the next drain, for the
whole 250000.
