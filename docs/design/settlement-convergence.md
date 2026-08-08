# Settlement order convergence, and the epoch chain

The ordering invariant this network needs is one sentence:

> **Two nodes holding the same records pay the same claims in the same order.**

It did not hold. It now holds for one of the two ways it can break, and this
note records what was broken, how it was measured, what shipped, and the two
cases still open.

**Status: partially built, and this note has been corrected once — read the
caveat before relying on it.** The epoch chain is in both implementations, the
two deterministic-case tests below are no longer `#[ignore]`d, and `launch/`
was regenerated and re-signed because the change invalidates any log written
under the old rule.

> **Correction.** This document previously said the epoch chain made
> settlement order converge, full stop. It does not. It removes the dependence
> on the ledger *envelope*, which is real — two nodes that drain the same
> epochs **in the same sequence** now agree, where before they never could —
> but two nodes that drain the same epochs in a *different* sequence still
> fork, with no records lost and both logs auditing clean. See
> [Drain sequence](#the-second-open-case-drain-sequence) below. The claim was
> caught by an adversarial review of the change, not by the tests that shipped
> with it.

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

## The second open case: drain sequence

Found by adversarially reviewing the fix, and pinned by
`draining_epochs_in_a_different_sequence_forks_the_chain` in
`tests/simulation.rs` (run with `--ignored`).

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

## What the fix does *not* solve

**A partial view at drain time.** The induction assumes both nodes settled the
same set in every earlier epoch. A node that drains epoch `e` before sync has
delivered a claim belonging to `e` writes a different `link(e)`, and the two
chains diverge permanently from there. Nothing above fixes that; it is the
ordinary distributed-systems tradeoff between liveness and agreement, and the
honest options are the usual two:

> **Now reproducible on demand.** `tests/simulation.rs` — a deterministic
> discrete-event simulator over real nodes — pins this case as
> `a_partial_view_at_drain_time_forks_the_chain`, `#[ignore]`d because it
> asserts the divergence *happens*.
>
> It established one thing prose had not: **a node holding nothing for an
> epoch never drains it.** `Node::due_epochs` considers only epochs with
> accepted claims, so there is no batch and no drained marker, and a later
> arrival is admitted normally. That is why cold sync is safe, and why the
> fork needs a genuinely *partial* view — some of an epoch's claims present at
> drain time, one still in flight.
>
> The simulator also found a separate, fixable bug: `apply_records` replayed
> claims in id order, and a later-epoch reveal replayed first drains an
> earlier epoch as a side effect, refusing an epoch-N claim sitting in the
> same session. Replay now sorts by `created_at`
> (`p2p::service::replay_records`), and the simulator drives that exact
> function rather than a copy of it. Worth recording *how* that was pinned:
> the first test written for it passed with the sort removed — it used a cold
> sync, which the paragraph above explains is immune — so the claim that it
> was pinned was wrong until a test was built that fails without the fix.

- **A finality delay** — refuse to drain an epoch until it is old enough that
  sync has converged, trading settlement latency for agreement. Cheap, partial,
  and probably right for Stage 1.
- **Reorgs** — let a node that learns of an earlier claim re-derive from the
  divergence point, which is what a chain with a fork-choice rule does, and
  which is a much larger change.

This note proposes neither. It fixes the case where **the record sets already
agree and the order still does not**, which is the deterministic half and the
one a test can pin.

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

The **finality delay** from *What the fix does not solve* is the natural
follow-up and is deliberately not bundled here: refusing to drain an epoch until
it is old enough that sync has converged is a separate rule with its own
failure mode, and it deserves its own test for the partial-view case rather than
riding along with a change that is already protocol-breaking.
