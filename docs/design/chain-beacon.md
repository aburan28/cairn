# The epoch beacon, drawn where the sequencer cannot choose it

`partition.rs` derives the settlement beacon from a chain of ledger heads and
says so in its own module docs: *"any value the sequencer could have chosen
freely is a value the sequencer could have ground to place itself favourably."*

That was a work-assignment problem when it was written. Epoch-batched
settlement made it a payment problem — a batch settles in order of
`H(beacon(epoch, anchor) ‖ commitment_hash)`, so grinding the anchor picks who
is paid first, and on a progressive objective the first payment takes the whole
span while the second takes the remainder. [roadmap.md](../roadmap.md) moved
this from "should" to "must" for that reason.

## What the record is

One new kind. It carries the randomness an epoch's settlement is ordered
against, plus enough provenance for a reader who holds the chain to check it:

```json
{"kind": "beacon",
 "payload": {"orders": 2977059, "source": "ethereum",
             "block": 21456789, "value": "3f9a…"}}
```

`value` is opaque to the rules engine. It is fed to `partition::beacon` as a
string exactly as the epoch-chain head was, so no hashing, no encoding and no
existing id changes — which is why `conformance/vectors.json` still reproduces
all 448 vectors untouched.

## The timing is the whole security argument

A beacon must be drawn **in the epoch it orders**. Both directions are fatal
and the rule refuses both:

| drawn | who gains |
|---|---|
| before the epoch | a committer, who can grind a commitment hash against a value they already hold |
| after the epoch opens but late | the operator, who has read the reveals and is choosing the payment order |
| **in the epoch** | nobody |

That middle column is not new — it is the residual gap `Node::settle_due`
already documents: *"a submitter who lands the final append of their commit
epoch influences both halves of their own rank at once."* Drawing at the
boundary closes it, because at the instant epoch `E` opens, commitments for
reveal-in-`E` are closed and no reveal has been seen. Committers could not know
the value; revealers know it but their commitment hash was frozen an epoch
earlier.

The rule is enforced at **read** time as well as at admission. A record that
reached the log some other way — imported from a peer, hand-edited in — orders
nothing, or a sequencer refused by `record_beacon` would simply append straight
to the ledger instead.

One beacon per epoch, and a second is refused rather than tie-broken. Every
tie-break is a choice, and the choice belongs to nobody.

## What an auditor without a chain still gets

This is the constraint that shaped the design. The project's one guarantee is
that *anyone can re-derive every settled result from the log alone*, and
requiring an Ethereum RPC endpoint to audit would spend it.

So the split is deliberate:

- **Without chain access** — verify the order follows from the recorded beacon,
  that the beacon was drawn in the epoch it orders, and that there is exactly
  one. This is the same strength the epoch-chain anchor had, *plus* the
  knowledge that the value was not the sequencer's to pick.
- **With chain access** — additionally verify `value` really is the randomness
  at `block`, and that `block` is the one the epoch boundary selects.

A wrong `value` is therefore caught by anyone holding the chain, and never by
someone holding only the log. That is a real limit, stated rather than hidden:
the log-only auditor is trusting that *somebody* checked, which is the same
shape as the availability argument and no stronger.

## The fallback, and why it is not an audit fault

An epoch with no beacon settles against the epoch-chain head exactly as before.
Three reasons this is not optional:

- every log written before this record existed is in that state, including
  `launch/proofwork.jsonl`, which is published precisely so readers can check
  it;
- a node whose chain source is unreachable must not halt settlement for
  everyone. `Unavailable is never Reject` applies to a randomness source as
  much as to a verifier;
- `audit` is a fault channel and the CLI exits non-zero on it. Reporting a
  legal-but-weaker ordering there would train operators to ignore audit output,
  which costs more than it buys.

It is still **askable**, via `Node::epochs_without_beacon`. A log that mixes
strong and weak epochs reads as uniformly strong otherwise, and `AGENTS.md` is
explicit that overstating what is defended is the one thing this repository
cannot afford.

## Which chain, and what it is worth

Ethereum's RANDAO (`block.prevrandao`), read at the first block whose timestamp
is at or after the epoch boundary. Pinning the block to the boundary is what
stops the operator choosing *which* draw to use; without that rule the record
carries provenance for a value the operator picked from many.

Honest about the bias: RANDAO is biasable by a proposer who withholds a block,
one bit per consecutive slot they control. That is a bounded, well-studied bias
against an adversary who must control the right slots at the right moment. It
is not comparable to a sequencer with free choice of anchor, which is the
status quo.

Solana was considered and is the wrong fit — not on cost, but because slot
hashes are leader-influenceable and Solana offers no forced-inclusion path,
which [consensus.md](../consensus.md) names as the property worth spending on.

A VDF over the epoch-chain head is the alternative that keeps everything
self-contained and needs no chain at all. It is strictly more work and remains
the better answer if this network ever wants to settle without an external
dependency; the record shape here does not preclude it, since `source` is just
a string and a VDF output is just a `value`.

## Read [anchored-time.md](anchored-time.md) first

That note analysed this decision before this was built, and its recommendation
was **not** to slide an external beacon in: prefer the logical high-water mark,
and treat the beacon as a deliberate Stage 1+ choice weighed against
[consensus.md](../consensus.md), because it "converts a system that needs no
external agreement into one that cannot settle when an outside service is
unreachable."

The fallback answers that specific objection — an unreachable chain costs the
epoch its beacon, not its settlement — but it does not answer the *other* half
of the recommendation, which is that adopting this at all is a decision
somebody should make on purpose. Nothing here makes it. What is built is the
mechanism and the ability to require it; whether the network should is open.

The note's remaining prediction was checked and held: the vectors constrain the
*function*, not its inputs, so feeding it a different string moved no id. All
448 still reproduce.

## The fallback is an opt-out, and that is the honest limit

A sequencer who wants to grind records no beacon and orders against the epoch
chain head exactly as before. The fallback cannot be removed without
reintroducing the liveness dependency, and a beacon cannot be added late
without reintroducing the grinding it prevents — so the mechanism alone does
not close the hole, it only makes the hole *visible*.

`PROOFWORK_REQUIRE_BEACON=1` makes it refusable: an audit under that flag
reports every epoch settled on the fallback. It is a **reader's** policy and
deliberately does not gate settlement — a beacon is admissible only inside the
epoch it orders, so refusing to settle an epoch that already closed without one
would strand its claims rather than protect anyone.

So the honest summary is three states, not two: grinding is *closed* for an
epoch with a beacon, *visible* for one without, and *refusable* by a reader who
requires them.

## Status

Built and cross-checked in both implementations.

- record, both timing rules, anchor resolution with fallback, audit checks,
  `epochs_without_beacon`, `PROOFWORK_REQUIRE_BEACON` — `src/node.rs`
- the same rules, independently derived — `reference/rust/src/node.rs`
- `proofwork beacon --orders N --value HEX [--source NAME] [--block N]`

Verified: 79 node tests, 448 conformance vectors unmoved, `interop.sh` and
`differential.sh` pass, `launch/proofwork.jsonl` still audits clean in both
implementations, and both derive the identical Merkle root for a
beacon-ordered log. The split was demonstrated before it was fixed — with the
reference implementation reverted, the same log reports `batch anchor is
3f9a1c4e, expected ` and the two disagree about payment order.

Remaining:

- [ ] the fetcher: `proofwork beacon` currently takes `--value`, so something
      still has to supply the chain's randomness. Deliberately outside the
      rules engine, but until it exists the provenance fields are operator
      assertions
- [ ] `proofwork-p2p` drawing one per epoch on a timer
- [ ] whether to adopt this at all, per anchored-time.md's recommendation 3
