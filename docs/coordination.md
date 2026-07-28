# Coordination

Thousands of participants working the same objective have to avoid duplicating
each other, share what they find, and get paid for it. This is usually treated
as a distributed-systems problem and solved with machinery — work-unit
dispatchers, reservations, locks, a coordination service everyone agrees on.

Most of it is a self-inflicted wound. **The coordination problem is downstream
of the payment structure**, and fixing the payment structure removes most of the
coordination requirement rather than automating it.

## The hoarding trap

A winner-take-all bounty gives every participant a reason to hide their work. If
I publish an improvement so you can build on it, you extend it by epsilon and
take the entire prize. So nobody shares, everybody rediscovers the same partial
results independently, and aggregate throughput collapses toward that of the
single best solo participant. No amount of scheduling fixes this, because the
participants are behaving correctly — the incentive is the bug.

The fix is `proofwork/frontier.py`: an objective carries a monotone best-known
score, and whoever moves it from `s0` to `s1` is paid in proportion to the
distance moved.

```
cumulative(s) = reward * (clamp(s) - baseline) // (target - baseline)
payout(s0 → s1) = cumulative(s1) - cumulative(s0)
```

Payouts telescope, so the pool is exactly exhausted at the target no matter how
the curve is chopped up — one 100-point jump and a hundred 1-point steps pay the
same total. Three consequences:

- **Publishing immediately is optimal.** It is how you get paid, and the ledger
  records that you moved the frontier as a side effect of paying you.
- **Copying is worthless.** Resubmitting a known artifact moves the frontier
  zero and pays zero. The thing that made hoarding rational is gone.
- **Attribution is mechanical.** An improvement *must cite the frontier it
  improved on* — enforced at submission, not left to etiquette — so citation
  flow pays the previous holder automatically.

Duplicated work also mostly disappears, because the frontier is public and
nobody spends compute rediscovering something already beaten.

The cost, stated honestly: a ratchet needs a scalar progress measure, so it
applies to evaluator-scored objectives and not to pass/fail ones. A proof either
exists or does not; there is no frontier to advance. Those stay winner-take-all
and keep the hoarding incentive — mitigated only by the fact that a proof is
usually not decomposable enough for partial results to be worth hiding.

## Three kinds of shared state, three consistency requirements

The expensive mistake available here is running everything through one agreement
protocol.

| state | volume | needs | mechanism |
|---|---|---|---|
| **frontier** — who holds the best score | low: changes only on improvement | total order; payment depends on it | consensus |
| **population** — candidates worth mutating | high | convergence, eventually | CRDT + gossip |
| **work split** — which region a node searches | zero messages | nothing | pure function |

Pushing the population through consensus would cost orders of magnitude of
throughput to buy a property the workload does not want. Divergence between
nodes' populations is not a bug — it is the island model, and it preserves the
search diversity the whole method depends on.

### Population: `gossip.py`

A bounded join-semilattice. Merge is commutative, associative, and idempotent,
so any two nodes that have seen the same messages agree, with no rounds, no
leader, and no voting.

Retention is top-K per island, and pruning is safe: if a candidate is not in the
top K of `A ∪ B`, then K candidates beat it, all of which survive into
`A ∪ B ∪ C` — so dropping it early never changes the answer and merge stays
associative. Ties break on content hash so every node prunes identically.

Two subtleties that are easy to get wrong and were caught by the tests:

**Identity must include the claimed score.** Two peers can gossip the same
artifact with different scores — one honestly, one lying. If identity ignored
the score, merge would have to break a tie between two values that are equal
under the key, and *any* tiebreak not derived from the values themselves
(arrival order, sender, timestamp) destroys convergence silently. Including the
score makes disagreement representable: both entries survive side by side, which
is what lets a node notice a peer is lying instead of absorbing it.

**Gossip is untrusted.** A peer asserting `score = 10^9` would evict every
genuine candidate from a bounded population — a cheap denial of service against
the search itself. `gossip.ingest()` re-scores locally and drops what does not
reproduce. This is affordable for exactly the reason the whole network works:
checking costs one evaluation, which the node was going to spend on that
candidate anyway.

### Work split: `partition.py`

No dispatcher, because assignment does not need agreement. Two nodes searching
the same region is not an error — it is a little wasted compute, self-correcting
the moment either publishes.

```
partition = H(beacon(epoch) ‖ node_id ‖ objective_id) mod n
```

A pure function every node evaluates locally, and can evaluate for anyone else —
which makes "did you actually search your assigned region" a checkable question
later. The epoch beacon matters: without an epoch-varying input the mapping is
fixed forever, so an adversary grinds identities until one lands on a region it
wants starved, then does nothing. Rotation makes that cost a fresh grind every
epoch.

The beacon must be unpredictable before the epoch and verifiable after. The
implementation derives it from ledger heads and says plainly in its docstring
that a sequencer able to choose that value freely could grind it. That is
acceptable while the sequencer is a trusted single operator and must become a
VDF or threshold signature before it is not.

## Latency budget

"Real-time" is usually the wrong frame. What the system actually needs:

| event | frequency | tolerable latency |
|---|---|---|
| population gossip | continuous, high volume | best-effort, no finality, seconds |
| frontier advance | rare per objective — minutes to hours | seconds to tens of seconds |
| settlement finality | per improvement | minutes |
| work reassignment | per epoch | ~10 minutes |

Nothing here needs sub-second consensus. Reaching for a high-performance chain
because "coordination must be real-time" buys latency the workload cannot use,
at the cost of the property it does need, which is censorship resistance
([consensus.md](consensus.md)).

## In-flight front-running

Commit–reveal stops an observer stealing a *revealed* artifact. It does not stop
a subtler attack: I watch your submission land, tweak it marginally, and submit
a hair better before yours settles.

Two defences, neither implemented yet:

1. **Epoch-batched reveal.** Commits in epoch N, reveals in epoch N+1, order
   within the epoch fixed by the beacon rather than by arrival. Nobody sees a
   competitor's artifact while they can still act on it, and the sequencer
   cannot reorder for profit.
2. **Minimum improvement.** `Ratchet.min_improvement` makes an epsilon-better
   resubmission earn nothing. Already implemented, and a real tradeoff: raising
   it also blocks genuine small gains.

## What this does not solve

**Sharing a technique has no mechanical attribution.** If I tell you "try
simulated annealing on the third coordinate" and you win the objective, nothing
pays me. Citation flow tracks artifacts, because artifacts are checkable; ideas
are not. This is the judgement problem from
[verification.md](verification.md) resurfacing inside the coordination layer,
and it is the part of scientific collaboration this design captures worst.
Discussion, intuition, and negative results shared in passing — the things that
make a research group more than the sum of its members — remain unpriced.
