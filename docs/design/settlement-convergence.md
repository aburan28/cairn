# Settlement order convergence, and the epoch chain

The ordering invariant this network needs is one sentence:

> **Two nodes holding the same records pay the same claims in the same order.**

It did not hold, in three distinct ways. All three are now closed, and the
sentence needs one qualifier that is not decoration:

> **…provided every record for an epoch reaches every honest node within
> `FINALITY_EPOCHS` of that epoch closing.**

Outside that window it does not converge, and no constant makes it: agreeing
on the settled set when messages can be arbitrarily late is consensus, which
Stage 0 does not have. What the delay changes there is the *failure mode* — a
late record is refused and reported, instead of two logs auditing clean and
disagreeing about who got paid.

**Status: built, in both implementations.** Two mechanisms, landed separately:
the **epoch chain** (removes the ledger envelope from the anchor) and the
**finality delay** (removes arrival order from eligibility). Every
`#[ignore]`d divergence test in `tests/simulation.rs` is now a passing
convergence test; the file has no ignored tests left. `launch/` was
regenerated and re-signed for the epoch chain, and audits clean under the
delay without further change.

> **Correction, kept deliberately.** This document once said the epoch chain
> made settlement order converge, full stop. It did not — the induction was on
> *epoch index* while the fold ran over *file position* — and the error was
> caught by an adversarial review of the change rather than by the tests that
> shipped with it. The claim was wrong for about one commit. It is left on the
> record because the failure was not the bug, it was asserting convergence
> without a test that fails when convergence is removed. Every claim below is
> now tied to a named test, and each of those tests has been run with its
> mechanism disabled to confirm it fails. See [How each claim was
> checked](#how-each-claim-was-checked).

## It was measured, not argued

`tests/p2p_convergence.rs` holds the two tests that caught it. They failed
before the fix and pass after; they are the acceptance criterion, not a
description of one.

Alice authors six claims that settle in one batch. Bob is handed nothing but her
*inputs* — objectives, commitments, claims — and re-derives the rest, which is
the premise of the whole project. Before the fix they disagreed:

```
two_nodes_holding_the_same_records_settle_in_the_same_order
  left:  [6e0b399f…, 1b31f94a…, a294ccbb…, b2eebdb9…, 4c19d200…, 676e3875…]
  right: [b2eebdb9…, 1b31f94a…, 676e3875…, 4c19d200…, a294ccbb…, 6e0b399f…]

the_settlement_anchor_is_the_same_on_both_nodes
  left:  sha256:b4e8b974af95dbdd58430d69384517d40677158192372ac560fe766efde93647
  right: sha256:fe47bfaa38a5bb95c1d6b28bcf7d89ac07c810291b52dce8e763a3244494ded6
```

Near-reversed. **Both logs audit clean**, because each is internally consistent,
which is what makes this the quietest possible way for the network to fork: the
pool is finite, so this is a disagreement about who got money, and nothing
anywhere reports an error.

## Root cause

A batch settles in order of `H(beacon(epoch, anchor) ‖ commitment_hash)`. Three
inputs; two of them already converge.

| input | converges? | why |
|---|---|---|
| `epoch` | **yes** | derived from each record's own `created_at`, which every node sees identically (`p2p::service::apply_records` stamps a replayed record with its own instant, deliberately) |
| `commitment_hash` | **yes** | content-addressed |
| `anchor` | **no** | ← |

`Node::anchor_at` walks the local ledger and takes `entry.hash` of the last entry
before the epoch. A ledger entry's hash covers `{seq, prev, kind, payload, ts}`,
and **`seq`, `prev` and `ts` are all node-local**: `ts` is when *this* node wrote
the entry, `seq` is its position in *this* node's file, `prev` is *this* node's
chain. Two nodes holding byte-identical records still have different entry
hashes, because the envelope around a record is local by construction.

`scripts/p2p-demo.sh` already says the halves of this out loud — "the two logs'
Merkle roots *differ*, and that is correct" — and `p2p::service::apply_records`
names the consequence in its own doc comment: *"What it does not buy is
agreement on settlement order."* The gap was known. What was missing was a test
that fails.

## The fix: an epoch chain

Make the anchor a function of *shared, content-addressed* data instead of the
local envelope. Each link commits to the link before it, so the epochs form a
chain — which is what a node is really syncing when it syncs a peer's history:

```
link = H( canonical({ prev: <previous link>, epoch: e, claims: [sorted claim ids] }) )
anchor = the head of that chain over every batch written so far
```

The inputs are the `batch` records the log already contained — `{epoch, claims,
anchor}` — so nothing new is stored and no record kind was added. Claims are
**sorted**, so a link cannot depend on the very ordering it is used to produce.

It folds in **file order rather than epoch order**, which matters: sorting by
epoch would let a back-dated claim create an old epoch whose batch is written
last, changing a link an already-written batch committed to. That is the
retroactive-fault bug the position bounds exist to prevent, and folding in file
order avoids reintroducing it — a batch appended later lands after, leaving
earlier links untouched.

`Node::audit` re-derives the chain up to each batch's own position and compares
it against the anchor that batch recorded, so an auditor checks the chain rather
than trusting it.

**The induction, and where it fails.** Base case: the empty chain, identical
everywhere. Inductive step: if every epoch before `E` settled identically on
two nodes, `link(E-1)` is equal, so `anchor(E)` is equal, so the batch sorts
identically.

That induction is on the **epoch index**. The fold is over **file position**,
and the two are only the same thing if batches are always written in
non-decreasing epoch order — which nothing enforces, and which the paragraph
above deliberately allows to be violated. This was the error in the original
version of this note.

**Why it stays grind-resistant.** The property the current design protects —
"the anchor is public by the time anyone reveals, so any part of the sort key a
submitter can still choose is one they can re-roll" (`AGENTS.md`) — is
preserved: `link(E-1)` is fixed when epoch `E-1` drains, which is before any
reveal in `E` can be made.

**Why the frozen input is legal to depend on.** `Node::reveal` refuses a reveal
into an epoch that is already drained (`RuleViolation::EpochAlreadySettled`), so
a settled epoch's claim set cannot grow afterwards. That is what makes
`link(e)` stable once written, and it is why the chain is built from *settled
claims* rather than from all records with an earlier `created_at` — the latter
could still grow when a back-dated objective or peer record arrives late, which
would retroactively move a settled batch's anchor. That is exactly the bug
`anchor_of_epoch_within`'s position bound was added to prevent, and a naive
content-addressed anchor would reintroduce it.

## The second case, now closed: drain sequence

Found by adversarially reviewing the epoch-chain fix, and now pinned in the
other direction by
`draining_epochs_in_a_different_sequence_converges_under_the_finality_delay`
in `tests/simulation.rs`. The scenario below is unchanged from the
reproduction; only the timing rule and the direction of the assertion moved.

Two nodes, byte-identical records, two epochs `E1 < E2`:

- **A** learns the `E2` work first, drains `E2` (nothing else has settled, so
  its anchor is the empty chain), then learns the `E1` work and drains `E1` —
  anchored on `link(E2)`.
- **B** learns in epoch order: drains `E1` on the empty chain, then `E2`
  anchored on `link(E1)`.

Both settle the same claim set. Both audit clean. Both pay **both epochs in
the opposite order**:

```
epoch E1: A=[634c1cb1, 19206bee]  B=[19206bee, 634c1cb1]
epoch E2: A=[e6360f42, 9a7f8fcb]  B=[9a7f8fcb, e6360f42]
```

Distinct from the partial-view case below — nothing is missing and nothing is
refused — but the same root cause: the anchor must be fixed before anyone can
grind it, so it can only depend on what had already settled when the batch was
written, and *that* is what differs between nodes that learned in different
orders.

**Folding in epoch order does not fix it**, which is worth recording because it
is the obvious next idea. At the moment A drained `E2`, no batch for `E1`
existed on A at all, so any function of "batches for epochs before `E2`" is
empty on A and non-empty on B regardless of how the fold is sorted.

## The finality delay

Both remaining cases — a partial view at drain time, and two nodes draining in
different sequences — have the same shape. The anchor must be fixed before
anyone can grind it, so it can only depend on what had already settled when the
batch was written; and *what had already settled* is exactly what differs
between two nodes that heard about the work at different times.

Folding in epoch order does not fix it, which is worth recording because it is
the obvious next idea. At the moment node A drained `E2`, no batch for `E1`
existed on A at all, so any function of "batches for epochs before `E2`" is
empty on A and non-empty on B however the fold is sorted.

What does fix it is refusing to drain that early. `partition::FINALITY_EPOCHS`
makes eligibility a function of **the clock** instead of a function of
**arrival**:

```
epoch E may settle when   E + FINALITY_EPOCHS < now_epoch
```

One epoch, so ten minutes of slack against a network moving records of a few
kilobytes. By the time A may drain `E2`, it is holding `E1` too, and
`due_epochs` returns both in epoch order — the same order B uses. The partial
view closes for the same reason: the straggler that used to miss the boundary
drain now has a whole further epoch to arrive in.

### The bound, stated plainly

A record later than the window is a different situation and the delay does not
rescue it. Settlement is **monotonic**: an epoch older than one already paid is
refused, not settled out of order. Paying it would anchor it on a chain head
that already contains later epochs, silently re-ordering payouts an auditor has
already read.

So a node that misses the window pays a strict subset of what its peers paid.
That is a real cost and it is not hidden:

- `Node::late_epochs()` lists the stranded epochs.
- `audit` prints them, phrased so the reader is not left hunting for a fault in
  a log where every batch is correctly derived. The problem is not this log; it
  is that a peer paid claims this node never will.

This is the trade the delay actually makes: **liveness for that epoch, in
exchange for never forking silently.** Reorgs — re-deriving from the divergence
point, with a fork-choice rule — remain the larger change that would buy back
the liveness, and are still not proposed here.

## How each claim was checked

Every claim above names a test in `tests/simulation.rs`, and every one of those
tests was run with its mechanism disabled to confirm it fails. That procedure
exists because of the correction at the top of this note.

| claim | test | disabled how | result |
|---|---|---|---|
| drain sequence converges | `draining_epochs_in_a_different_sequence_converges_under_the_finality_delay` | `PROOFWORK_FINALITY_EPOCHS=0` | fails |
| partial view converges | `a_partial_view_at_drain_time_converges_once_the_epoch_waits` | `PROOFWORK_FINALITY_EPOCHS=0` | fails |
| late records are refused and reported | `a_record_arriving_after_the_finality_window_is_refused_not_silently_paid` | monotonicity filter removed from `due_epochs` | fails |

The middle row is the one that nearly shipped wrong twice. The first rewrite of
that test passed with the delay disabled — not because the delay was
unnecessary, but because the rewrite had quietly dropped the boundary drain
that made the scenario a partial view at all. It asserts the drain *happens*
and pays nothing, rather than asserting nothing was drained.

## What it cost

Not a refactor. A `batch` record names the anchor it used and `Node::audit`
re-derives and compares, so changing the derivation invalidates every log
written under the old rule. What that meant in practice:

1. **`launch/proofwork.jsonl` was invalidated and has been regenerated.** Its
   four `batch` records named old-style anchors, and after the change the
   published log failed its own audit with exactly the expected message —
   *"anchor … is not the epoch-chain head this batch was written against"* on
   all four. It was rebuilt and re-signed with `scripts/make-launch-log.sh`.
   **The published root changed**, so anyone who pinned the old one must
   re-pin; `launch/README.md` says so plainly rather than leaving it to be
   discovered.
2. **Moves both implementations together**, per `AGENTS.md`: `src/node.rs` and
   `reference/rust/src/node.rs` both derive anchors, and `scripts/differential.sh`
   requires they agree — including on inclusion proofs over the published log,
   which is the artifact in (1).
3. **Did not move `conformance/vectors.json`,** which was the thing most worth
   checking before starting. Its `partition` section pins
   `beacon`/`settlement_rank` against a literal `"anchor"` string, so it
   constrains the *function* and not how the anchor is derived. Confirmed after
   the change: *448 vectors reproduced independently*.

(3) is the important one: the identity scheme did not move, so no record id
changed and no live claim was orphaned. (1) is the real cost, paid once.

## Next

The convergence work is done for Stage 0. What remains is the case the delay
deliberately does not cover:

- **Reorgs.** A node that learns of an earlier epoch after paying a later one
  currently refuses it and says so. Re-deriving from the divergence point
  instead would recover those payouts, at the cost of a fork-choice rule and
  settlements that are not final when written. That is a Stage 1 change and a
  much larger one.
- **Choosing `FINALITY_EPOCHS` from evidence.** One epoch is a judgement, not a
  measurement. The number that belongs here is a function of observed sync
  latency across the real network, and there is not enough of a real network
  yet to measure. `tests/simulation.rs` can already sweep it — the tests derive
  their timing from `finality_epochs()` rather than hard-coding it, so raising
  the constant moves them with it.
