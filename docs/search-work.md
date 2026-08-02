# Scalable computation: paying for a search, not just for finding

A search is the shape this network is built for — hard to find, cheap to check —
and it is also the shape that scales worst, because almost all of the work
produces nothing. This is what it would take to pay for that work.

## Finding already scales. Only the negative result does not.

[`partition.rs`](../src/partition.rs) assigns disjoint slices of a search space
from the epoch beacon with no coordinator, and it is already exposed to agents
as the `work_assignment` MCP tool:

```
node alice takes partition 3 of 8 for epoch 496011
node carol takes partition 4 of 8 for epoch 496011
node dave  takes partition 0 of 8 for epoch 496011
```

Point a hundred nodes at one ECDLP objective and whoever finds `k` submits the
ordinary `certificate` artifact. **Verification stays one scalar multiplication
however many nodes searched**, which is the scalability property that matters.
Nothing needs building for this.

Two things the mechanism does not promise, both visible above: assignment is a
hash and not a lock, so `alice` and `bob` can draw the same slice and duplicate
each other's work — likely by birthday well before the slices run out — and the
beacon is grindable by a sequencer (see [threat-model.md](threat-model.md)).

What does not work is the other ninety-nine nodes. Each has done real work and
holds a real result — *slice 5 contains no solution* — and there is no way to
pay for it, because:

> checking "`k` is the answer" is one scalar multiplication;
> checking "slice 5 is empty" is redoing the search.

That inverts the property everything here rests on. It is Nakamoto's fourth
work property in [economics.md](economics.md) — *trivially verifiable* — and it
is the same constraint [review-pcw.md](review-pcw.md) uses to reject Proof of
Adaptive Challenge Solving: verification cost must be far below `1/N` of the
work, or every node ends up redoing everything.

## Why spot-checking cannot certify a negative

The obvious cheap fix is to make the searcher commit to a transcript — a hash
chain over every candidate it tested — and have the verifier open `k` random
positions. It is worth being precise about what that buys, because it looks like
it works and does not.

Against a searcher who **skipped** a fraction `ε` of its slice, sampling is
excellent: each opened position catches the omission with probability `ε`, so
`k` openings catch it with probability `1 − (1−ε)^k`. Eighty openings against a
10% skip is a one-in-ten-thousand escape.

Against a searcher who **found a hit and reported empty**, sampling is useless.
There is one lying position among `N`, so the escape probability is `1 − k/N`.
At `N = 2^30` and `k = 80` that is `1 − 2^-24`: the liar is never caught.

The two cases are not variations on a theme. *Exhaustion is a claim about every
position*, and a claim about every position cannot be certified by opening a
constant number of them. Sampling can prove **effort**; it cannot prove **the
absence of a result**, which is exactly what a search wants paid.

That is also the cleanest explanation of why canaries exist. Planting a known
solution converts "hid a hit", which the verifier catches with probability
`k/N`, into "lied about a position the funder chose", which the funder catches at a
rate it sets. Canaries do not make sampling sound; they change what is being
sampled.

## What a succinct exhaustion proof actually costs

The sound alternative is to constrain every step rather than sample steps: a
proof over the whole search, verified in time independent of the search's
length. That is real, and two costs decide whether it is worth it.

**Prover overhead.** Proving a computation costs orders of magnitude more than
running it. The objective has to be worth that multiple, on top of the
decomposition floor already derived in [agent-market.md](agent-market.md):
`V_min = verifiers × verify_cost / (fee × verify_split)`, 800,000 units at
reference parameters. A search worth less than that should not be decomposed at
all, and one worth less than `overhead × V_min` should not be proved.

**Arithmetization.** The predicate has to be expressible as constraints over the
proof system's field, cheaply. This is where the first instance gets chosen, and
it argues against the obvious one: **secp256k1 ECDLP is close to the worst
case** — scalar multiplication over one prime field, proved inside another, is
non-native arithmetic at every step. A search whose predicate is already
algebraic, or an algebraic hash, is where this starts.

## The good news: this is not a protocol change

A proof verifier is a **pinned checker**, and pinned checkers are the thing this
repo already does. An exhaustion proof is an artifact; the verifier that checks
it is content-addressed by `checker_sha256` and fixed inside the objective's id,
so nobody can retarget a funded search at a weaker proof system, and an edit
forks the objective rather than rescoring work already done against it.

So adopting a proof system needs no consensus change, no new record kind, and no
conformance-vector movement. It also *helps* an open threat-model row rather
than worsening it: **verification-cost amplification** is partial today because
`p2p::sync` runs the verifier on every record it accepts, and a minutes-long
verifier turns one message into hours of CPU. A proof verifier is milliseconds
whatever it certifies, which is the direction that row needs to move.

## What does need a protocol change: partition-scoped settlement

One thing genuinely blocks this, and it is not cryptographic. A `certificate`
objective settles **once and then closes**:

```
$ proofwork reveal <settled-objective> …
refused: objective is already settled (sha256:067486fe)
```

A search over eight slices needs eight independent settlements against one
objective — one per slice, each paid for its own negative result, with the
objective closing only when a solution is found or the space is covered. A
ratchet objective already settles repeatedly, so the machinery for many accepted
claims against one objective exists; what it orders by is score improvement, and
a search wants disjoint coverage instead.

That is the smallest real increment, and it is worth building before any proof
system, because it is what every one of the four approaches needs.

### Sketch

```json
{
  "goal": "GOAL-search-…",
  "reward": 8000000,
  "verifier": {
    "kind": "search",
    "space": { "lo": "0x0", "hi": "0x10000000000", "partitions": 8 },
    "checker": "…/exhaustion_verifier.py",
    "checker_sha256": "…",
    "entrypoint": "check"
  }
}
```

An artifact names its slice and carries its evidence:

```json
{ "partition": 5, "result": "empty", "proof": "sha256:…" }
{ "partition": 3, "result": "found", "witness": { "k": 13327512 } }
```

`found` verifies as a certificate does — cheap, unchanged, and it closes the
objective. `empty` settles that partition alone. The proof itself is a blob in
the content-addressed store rather than an inline field, because proofs are
large and [`src/blobs.rs`](../src/blobs.rs) already moves large pinned bytes
between peers.

Three rules the sketch does not yet decide, and each is a real question:

- **Double payment.** Two nodes drawing slice 5 both hold a valid proof.
  Paying both is honest and wasteful; paying the first is a race the beacon can
  be ground to win.
- **Partial coverage.** A search abandoned at six of eight slices has consumed
  six eighths of the escrow and produced nothing anyone wanted. Whether the
  funder gets the remainder back is an escrow question, not a verifier one.
- **Slice size.** Small slices mean more proofs and more verification; large
  ones mean a node must finish a big chunk before it is paid anything.

## Honest summary

Sharded *finding* works today and needs nothing. Sharded *exhaustion* needs a
proof that constrains every step, because sampling provably cannot do it, and
that proof is affordable only for objectives large enough to clear
`overhead × V_min` and predicates friendly enough to arithmetize — which the
ECDLP instance shipped in `examples/` is not.

The part to build first is neither: it is letting one objective settle once per
partition, which every approach needs and none of them can work without.
