# Citation-flow dilution: what the attack is, and how far a fix gets

Threat-model row **citation-flow dilution** is the one open item that is a
*soundness* problem rather than a missing feature: it overturns the payout
result the README advertises, and slicing is the dominant strategy rather than
an exotic attack. This note records a design exploration — what was measured,
which half of the attack a reward-weighted rule closes, and precisely why the
other half survives.

Nothing here is implemented. `scripts/citation-flow-harness.py` reproduces
every number below in exact rational arithmetic, so the next attempt starts
from ground rather than from prose.

## The attack

Citation flow decays δ per **hop**. Slicing one improvement into many adds
hops, and the pool telescopes so the slices cost the slicer nothing in direct
reward. On the README's own showcase (δ = 1/4, alice 300,000 · bob 400,000 ·
carol 400,000):

| bob submits as | alice ends with | bob ends with |
|---|---|---|
| one claim | 425,000 | 375,000 |
| four slices | 333,594 | 466,406 |
| sixteen slices | 308,331 | 491,669 |

Sixteen slices move 27% of alice's total to bob for work he had already done,
and invert the headline result the README uses to argue publishing pays.
`max_depth` is not a defence — decay is geometric *within* the chain, so depth
6 and 64 differ by under 0.1% — and raising δ does not help either.

## The candidate: reward-weighted ancestor attribution

Replace "δ split among direct citations, recursively" with **δ split among all
transitive ancestors, weighted by each ancestor's own settled reward.**

The appeal is that it needs no new input. On a ratchet a claim's settled reward
*is* the progress it moved, and telescoping guarantees the slices of one
improvement sum to the unsliced reward — so the weights are slicing-invariant
by construction. It also conserves exactly, which the existing integer
remainder rule already handles.

## What it fixes, and what it does not

| bob submits as | alice's inflow, current | reward-weighted |
|---|---|---|
| one claim | 425,000 | 442,857 |
| four slices | 333,594 | 414,107 |
| sixteen slices | 308,331 | 408,226 |
| **leak** | **27%** | **8%** |

Better, and **not a fix**. Splitting alice's inflow by who paid it shows the
two halves behave completely differently:

| bob submits as | alice receives from bob | from carol |
|---|---|---|
| one claim | 100,000 | 42,857 |
| four slices | 71,250 | **42,857** |
| sixteen slices | 65,368 | **42,857** |

**Carol's contribution is exactly invariant.** The downstream half of the
attack is fully closed: however bob chops his work, a later contributor
building on him pays alice the same. That is the half the weighting was
designed for and it works.

**Bob's own contribution still leaks**, and the mechanism is specific: each of
bob's later slices counts his *earlier* slices as ancestors, so alice's weight
is diluted by bob's own reward in the denominator. Unsliced, bob's only
ancestor is alice and she takes δ·400,000 = 100,000. Sliced four ways, slice
two sees ancestors {slice one, alice} with weights 100,000 and 300,000, so
alice takes only 300/400 of that slice's δ — and it worsens with each further
slice.

## Why the obvious repairs are wrong

**Collapse consecutive same-submitter citations into one hop.** Fixes the
measured attack exactly and is worthless: identities are a keypair, and
`proofwork identity` now makes minting one a single command. Bob slices under
four names and the defence evaporates. Any rule keyed on *who* submitted has
this shape.

**Exclude an ancestor whose reward came from the same chain.** Circular — that
is most of what a citation chain is — and it would penalise honest incremental
work by different people, which is the behaviour the ratchet exists to reward.

## Where the next attempt should start

The residual has a clean statement: bob's earlier slices are themselves built
on alice, so money reaching them *should* flow onward to her rather than
stopping. That points at a hybrid — reward-weighted for the split, but with the
weight of an ancestor inheriting the weight of its own ancestors, so a chain of
slices resolves to the same distribution as the single claim it replaced.
Whether that composes without reintroducing per-hop decay, and whether it still
conserves exactly in integers, is the open question.

Two constraints any candidate has to meet before it is worth implementing:

1. **Slicing-invariance for both payers**, measured with the harness, not
   argued. The table above is the test.
2. **Exact conservation at every δ and every reward**, in integers, with a
   deterministic rule for the odd unit. The existing property tests are the
   bar and they are not negotiable — attribution that conserves approximately
   is attribution that mints.

And one warning, because it is what makes this expensive rather than merely
hard: **this changes how settled money splits.** It moves the conformance
vectors and the Python reference with them, so it has to land before an
objective anyone cares about is funded, not after.
