# Shard assignment: what erasure coding prices, and what it still does not

**Status: analysis only. Nothing here is built, and the headline result is
weaker than it first looks — the arithmetic in §2 is the point of the note.**

[`threat-model.md`](../threat-model.md) carried **availability sybils** as *not
handled* when this note was written: a fixed pot bounded a funder's cost however
many nodes appeared, but nothing priced identity, so ten keys behind one disk
answered ten samples from one copy and took ten shares.

**That has since changed at the whole-log level.** An undertaking carries a
`bond` backed by units the log says the identity earned, and the pool is split
in proportion to it, which makes the payout invariant to splitting one operator
into many. The row now reads *profit handled, existence not*. What is below
still stands: it is about pricing identity at *shard* granularity, and about the
harder half neither mechanism closes — that an answer proves the entry was
**produced**, not **stored**.

[`shards.md`](../shards.md) landed for unrelated reasons — durability per byte,
and blame at chunk granularity. This note records something it happens to buy
along the way, works out how much that is actually worth, and finds that the
interesting part is not the one that looked interesting.

Read [`shards.md`](../shards.md) first. This assumes the manifest and the
two-level tree.

## 1. The observation

A possession challenge is a function of the data. Under replication every
holder has all of it, so **one disk can answer as any number of identities** —
the marginal cost of the tenth key is zero, and no proof system changes that,
because it is a physical fact rather than a cryptographic one.

Under `(k, m)` coding the shards are distinct. If an identity may only be
challenged on *its own* shard, then answering as ten identities requires holding
ten distinct shards rather than one blob.

That is the whole idea, and stated that loosely it sounds like it prices
identity linearly. It does not.

## 2. The arithmetic, which is the reason to write this down

There are only `n = k + m` shards. Once a sybil holds all of them it can answer
for *any* identity, however many it registers, because every identity's assigned
shard is one it already has.

| | disk to be one honest holder | disk to be `N` identities | as `N` grows |
|---|---|---|---|
| replication | 1 blob | 1 blob | free |
| `(k, m)`, unassigned shards | 1/k blob | 1/k blob | free |
| `(k, m)`, shard bound to identity | 1/k blob | min(N, n)/k blob | free past `n` |

So binding shard to identity moves the sybil's fixed cost from **1 blob** to
**(k+m)/k blobs** — 1.5× at (4, 2) — and then stops. It is a constant-factor
tax on entry, not a per-identity price. Anyone who reads the first paragraph and
stops has overestimated it by an unbounded factor.

Worth saying plainly because the mistake is easy and attractive: *distinct
shards* is not the same property as *distinct identities cost distinct
resources*, and the gap between them is exactly the number of shards.

## 3. Where linearity actually comes from, and what it costs

There is a version that is linear, and it is not the coding — it is the
**settlement rule**.

> **Pay per shard covered, not per answer.**

An epoch's pot splits across the `n` shard positions rather than across the
identities that answered. Ten identities behind one disk, all assigned shard 0,
split one shard's share between them. The pot per blob is bounded by `n` shares
no matter how many keys appear, **by construction rather than by pricing** — and
a sybil's take stops growing the moment it stops adding shards.

This is the cheap half of the whole note. It needs no bond, no proof system, and
no new cryptography: it is a change to how a settlement divides, in the same
place `AvailabilityPool` already divides — which now divides by bond rather than
equally among answers, so the two rules compose rather than compete: the bond
bounds a sybil's take across the whole log, and per-shard settlement would bound
it per blob.

It also fixes something the equal-split rule gets wrong for honest nodes.
Three holders all keeping shard 0 and nobody keeping shard 5 is a blob one
disk away from unrecoverable, and today all three are paid in full for it.
Paying by position makes the payment track what the network actually wanted.

## 4. Assignment must be *stable*, which is backwards from the rest of the crate

`partition::assign(node_id, objective_id, epoch_beacon, partitions)` is the
obvious mechanism, and `Node::sampled_index` already reuses it for the
availability challenge:

```text
index = assign(identity, undertaking_id, beacon(epoch, anchor), height)
```

The trap is the beacon. Work assignment *must* rotate every epoch — the module
docs are explicit that a fixed mapping lets an adversary grind an identity onto
a region and leave it unsearched. Shard assignment must **not** rotate, because
a shard is not a search region: re-shuffling who holds what every ten minutes
means moving the bytes every ten minutes, and the whole point was to store them.

So reuse here means reusing the function with the anti-squatting property
deliberately removed — a stable key such as the manifest root in place of the
beacon:

```text
shard = assign(identity, manifest_root, manifest_root, k + m)
```

and squatting comes back: identities are free, so an adversary can grind keys
until they land on a shard it already holds. The §3 rule is what defuses that
too — grinding onto shard 0 alongside three other claimants divides shard 0's
share four ways, so the grind buys a smaller slice of the same money rather than
a second slice.

Two more consequences of stability, both real:

- **The challenge still has to rotate even though the assignment does not.**
  Which shard is mine is fixed; which *chunk* of it I am asked for must move
  each epoch, or the answer is knowable in advance and one cached chunk answers
  forever. That is `assign(identity, manifest_root, beacon(epoch, anchor),
  chunks)` — the same function, the beacon back in, a different question.
- **`MAX_SHARDS` is 255**, so this caps at 255 paid positions per blob. Beyond
  that the pot is shared within a position and the mechanism has nothing more to
  say. Not a problem at any scale Stage 0 contemplates; a limit rather than an
  omission.

## 5. What it does not buy, stated rather than left to be discovered

**It prices storage, not independence.** This is the one that matters. A holder
that keeps ten distinct shards on one disk has paid for ten shards and delivered
*one failure domain*. Availability payments are buying independence — ten
holders exist so that one fire, one landlord, or one jurisdiction does not take
all ten — and nothing here distinguishes ten machines from ten directories.
Latency probing and geographic attestation are the usual answers; the first is
defeated by a fast local partner and the second needs a party to attest.
**Nothing in this note reduces correlated failure, and a mechanism that paid as
though it did would be worse than the one we have.**

**It does not touch outsourcing.** A holder that fetches its chunk from a friend
when challenged produces an identical proof. Same bound `Availability` already
documents; ruling it out needs a time bound or sequential work, and Stage 0 has
neither.

**It does not make a bond unnecessary.** §3 bounds what sybils can *take* from
one blob's pot. It does not make lying costly, and a holder that stops answering
still loses nothing it had to put up.

**It needs a record, which the shards work deliberately did not add.** A
manifest is derived from bytes, so signing one signs an arithmetic fact — that
is why `src/shards/` introduces no record kind. A *promise* is different, and
this mechanism needs one: identity `K` undertook to hold shard `i` of manifest
root `R`. `records::Undertaking` is the same shape one level over, and it moves
canonical encoding and both implementations. Which is the argument for not
adding it yet rather than for adding it carefully.

## 6. Recommendation

1. **Nothing now.** The bond has since landed — `records::Undertaking` carries
   one, backed by units the log says the identity earned, and the pool is split
   in proportion to it — so the sybil *take* is already bounded at the whole-log
   level: splitting a stake across `n` keys earns what holding it under one
   earns. What is still missing is the shard-level version of the same idea, and
   the harder half either way is that an answer proves the entry was *produced*
   rather than *stored*. Until that is closed, every improvement here is to the
   pricing of a currency nobody is spending.
2. **When it does carry money, pay per shard covered before doing anything
   else.** It is a settlement rule, it bounds the sybil take by construction,
   and it corrects an honest-case error — paying three holders of shard 0 in
   full — that has nothing to do with attackers.
3. **Bind shard to identity in the same change, or not at all.** On its own it
   is a 1.5× tax and reads as more; together with (2) it is what makes "covered"
   mean something an identity cannot claim twice.
4. **Do not reach for a proof system for this.** The data is public, so
   zero-knowledge has nothing to hide, and a Merkle path is already `log n`
   hashes — succinctness would buy aggregation across many challenges, which is
   an optimisation to make when the bytes hurt. The property people hope a SNARK
   provides here, *a distinct physical copy*, comes from sequential encoding
   bound to an identity (Filecoin's PoRep), whose cost has produced a
   specialised hardware market and is wildly out of proportion to a 1 MiB blob
   cap. See [`consensus.md`](../consensus.md) for why the consensus version of
   the same idea is a separate mistake: storage proofs are a Sybil-resistance
   primitive, not an ordering one, and the bootstrap circularity does not care
   whether the scarce resource is hashpower, stake, or disk.
