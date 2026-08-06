# Citation-flow dilution: what the attack is, and how far a fix gets

Threat-model row **citation-flow dilution** is the one open item that is a
*soundness* problem rather than a missing feature: it overturns the payout
result the README advertises, and slicing is the dominant strategy rather than
an exotic attack. This note records a design exploration — what was measured,
which half of the attack a reward-weighted rule closes, and precisely why the
other half survives.

**The rule is the default** in the primary: `payouts_over` weights by settled
reward, and `tests/citation_flow.rs`, which used to pin the theft, now pins its
absence. The conformance vectors did not move — they fix record *encoding* and
the per-hop `flow` split, and this changes how settled money is divided rather
than what a record's bytes are.

The reference implements `flow`, the per-hop rule the vectors pin, and not the
weighted one: it has no settlement path to apply it on. So the vectors give
`flow` an independent check and the weighted rule has none, which is worth
knowing when changing it.

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

## The decisive measurement: bounded, not merely smaller

The 8% figure is not the interesting number. What matters is whether the
slicer's gain **converges**, and the two rules differ qualitatively rather
than by degree:

| slices | alice, current rule | alice, reward-weighted |
|---|---|---|
| 1 | 425,000 | 442,857 |
| 4 | 333,594 | 414,107 |
| 16 | 308,331 | 408,226 (408,225 in integers) |
| 64 | 302,083 | 406,853 |
| 256 | 300,521 | 406,510 |

Under the current rule alice tends to **300,521** — her own direct reward of
300,000 and essentially nothing else. Her citation flow is driven to *zero*.
The extraction is unbounded: a determined slicer takes all of it.

Under reward weighting she converges to **406,510** and stays there. She keeps
roughly three quarters of her flow however finely the work above her is
chopped, and the slicer's premium converges to about 10% rather than growing.

That reframes the residual. It is not a leak that a better rule would remove —
it is the mechanism correctly pricing a longer dependency chain, and it is
bounded. Two properties make that defensible rather than a rationalisation:

**It is identity-blind.** If bob's four slices were four different people, the
rule returns exactly the same numbers. Nothing keys on who submitted what, so
there is no sybil version of the attack — which matters more now than it did,
because `proofwork identity` makes minting a name one command.

**It rewards the behaviour the ratchet exists to encourage.** A small bounded
premium for publishing in many steps rather than one is not a bug in a system
whose entire design goal is to make publishing immediately profitable. The
current rule *punishes* incremental publication, which is backwards.

## Why the obvious repairs are wrong

**Collapse consecutive same-submitter citations into one hop.** Fixes the
measured attack exactly and is worthless: identities are a keypair, and
`proofwork identity` now makes minting one a single command. Bob slices under
four names and the defence evaporates. Any rule keyed on *who* submitted has
this shape.

**Exclude an ancestor whose reward came from the same chain.** Circular — that
is most of what a citation chain is — and it would penalise honest incremental
work by different people, which is the behaviour the ratchet exists to reward.

## Status: implemented in Rust, proven, not yet the default

`attribution::payouts_weighted` is the rule. Five tests pin what matters, and
each of them is a property rather than a golden number:

- **conserves exactly** at every slicing, in integers, with largest-remainder
  allocation resolved by sorted id so every node reproduces it;
- **a downstream citer's contribution is bounded** — within 10% however finely
  the middle is chopped, against unbounded loss today;
- **the slicer's gain converges** — under 1% movement between 16 and 256
  slices, where the current rule drives the upstream contributor's flow to
  zero;
- **identity-blind** — four slices by one submitter and four claims by four
  submitters give the same distribution;
- **a zero-reward ancestor cannot dilute** anyone, so a chain of claims that
  moved nothing is not a way to thin the people who did.

### The bug the tests caught, which is worth keeping

The first implementation bounded ancestor discovery by `max_depth`, by analogy
with the per-hop walk. That is wrong, and worse than what it replaced: at 256
slices the upstream contributor falls *past the horizon* and is cut to zero
outright. A cliff is sharper than a slope. `max_depth` belongs to per-hop
decay, where it caps how far compounding runs; under a flat split, letting hop
distance decide entitlement reintroduces exactly the attack being fixed.

Ancestor discovery is therefore over the whole closure, `O(edges)` — the same
order as the audit that re-derives the log anyway.

### Two things the switch turned up

**An unsettled ancestor takes no share.** The weights are settled rewards, so
a claim with nothing settled has no measured contribution and its share goes
to the ancestors that do have one. That is a statement about timing rather
than entitlement — `ledger_payouts` draws from the whole log, so a claim that
has settled at all is weighted — but it is a real semantic and it now has its
own test rather than being discovered by someone reading a number they did not
expect.

**The design note's 408,226 is exact-rational; the implementations produce
408,225.** Integer arithmetic floors. What matters is not which figure is
"right" but that both implementations floor *identically*, which they do —
checked against the reference implementation directly, and the odd unit has a
deterministic owner.

## Where the next attempt should start

Implement `payouts_over` against the transitive-ancestor set with reward
weights, in `src/attribution.rs`
together. The existing conservation machinery carries over unchanged — the odd
unit still needs its deterministic owner, and the property tests that pin
conservation across amounts and δs are the bar.

`tests/citation_flow.rs` currently *pins the attack*: its assertions encode
that slicing pays. Those assertions become the regression test for the fix,
inverted — alice's inflow must stay bounded as the slice count rises, and the
downstream citer's contribution must be exactly equal across every slicing.

One warning, because it is what makes this expensive rather than merely
hard: **this changes how settled money splits.** It moves the conformance
vectors and the reference implementation with them, so it has to land before an
objective anyone cares about is funded, not after.
