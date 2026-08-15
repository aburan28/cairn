# Erasure-coded shards, with a Merkle commitment per chunk

Holding a blob without holding all of it, and being able to prove you hold your
part.

```sh
cairn shard plan artifact.bin                        # what a cut would cost
cairn shard encode artifact.bin --keep 1,4           # cut it, keep your slice
cairn shard ls <address>                             # what is here, what is elsewhere
cairn shard prove <address> --shard 1 --chunk 7      # prove one chunk
cairn shard check proof.json --merkle-root sha256:…  # …and check it with no store
cairn shard reconstruct <address> --out artifact.bin # put it back together
```

[`src/shards/`](../src/shards/). Library plus CLI; **not wired into the network
transport**, which is stated again at the bottom rather than left to be
discovered.

`scripts/shard-demo.sh` is the whole of it end to end, in CI: six stores that
share nothing, one shard each, one holder gone and another lying, and the file
back byte for byte with the liar named.

## What it buys

To survive `f` holders vanishing, replication needs `f + 1` full copies.
A `(k, m)` code needs `(k + m) / k`, and survives any `m`:

| tolerate | replication | (4, 2) | (8, 4) | (10, 4) |
|---|---|---|---|---|
| 1 loss | 2.0× | 1.5× | 1.5× | 1.4× |
| 2 losses | 3.0× | 1.5× | 1.5× | 1.4× |
| 4 losses | 5.0× | — | 1.5× | 1.4× |

That is the headline. It is not the interesting half.

## The interesting half: coding is a downgrade without per-chunk commitments

Replication has a property so cheap nobody names it: **every copy is
self-checking.** A holder either hands you bytes that hash to the digest the log
pinned or it does not, you find out from the bytes alone, and a liar implicates
only itself.

Erasure coding destroys that property. A shard is not the blob and does not hash
to the blob's digest — it only means anything in combination with `k-1` others.
Feed one corrupt shard into that combination and **every** output byte is wrong,
because the linear algebra spreads the lie across the whole reconstruction. The
blob digest then tells you that *somebody* lied, which is the useless answer
[`swarm::piece`](../src/swarm/piece.rs) exists to avoid during a transfer —
except worse. With `n` holders and one liar there are `n choose k` subsets to
try and each retry is a full decode; at (10, 4) that is a thousand decodes to
find one bad byte.

So the commitments are not an optimisation layered on the coding. They are what
makes the coding safe to use at all:

> **Nothing enters a linear combination until it has been checked against the
> manifest.** `reconstruct` verifies each shard's chunks first, drops the ones
> that fail, and **names** them.

One liar costs its own shard and nothing else. `Reconstruction::rejected` is the
output that justifies the whole design — under replication a bad copy names
itself, under plain coding it does not, and that list is how it is made to. It
is what a peer scorer or a slashing rule would consume, with the root that
convicts the holder fixed before the transfer began.

`one_corrupt_shard_is_named_and_excluded_rather_than_corrupting_the_output`
pins it.

## The shape

```
blob ──split──▶ shard 0 ─┬─ chunk 0 ─▶ H ─┐
                         ├─ chunk 1 ─▶ H ─┼─▶ shard root 0 ─┐
                         └─ chunk 2 ─▶ H ─┘                 │
                shard 1 ─── … ──────────────▶ shard root 1 ─┼─▶ manifest root
                …                                           │
                shard n-1 ─ … ──────────────▶ shard root n-1┘
```

Two levels, and the second earns its place: a proof anchored at the manifest
root convinces a verifier who holds **only that root** — 32 bytes, the size of
something a record could one day commit to — rather than the whole list of shard
roots. A verifier who already has the manifest can skip the outer hop, and
`Manifest::verify_chunk` does.

Three things fall out of the layout rather than being designed in.

**A data shard's chunk is a contiguous slice of the original blob.** Shards are
cut as blocks, not interleaved by symbol, so chunk `c` of data shard `j` is
exactly `blob[j·shard_len + c·chunk_len …]`. A reader who wants one range of a
large artifact fetches one chunk, checks it against the root, and uses it — no
decode, no second holder. `Layout::blob_range` is that map, and
`a_data_shards_chunk_is_a_contiguous_slice_of_the_blob` is the test that stops
it quietly becoming untrue.

**The manifest is `O(n)`, not `O(chunks)`.** One root per shard, so a 1 GiB blob
at (4, 2) has a six-entry manifest. A piece manifest carries one digest per
piece and grows with the blob; this one does not, because the per-chunk hashes
are recomputed from the shard by whoever holds it.

**Sampling is `O(log)`.** Challenging a holder for one chunk costs it one chunk
plus `log₂(chunks) + log₂(n)` hashes, against a root fixed before the challenge
existed. That is the shape [node-incentives.md](node-incentives.md) wants for
availability, applied to content instead of to the log.

## The code

Systematic Cauchy Reed–Solomon over GF(2^8). Rows `0..k` of the generator are
the identity, so data shard `j` *is* the `j`-th block of the blob and a holder
with all `k` concatenates rather than decoding. Rows `k..k+m` are Cauchy:
`C[p][j] = 1 / (x_p ⊕ y_j)` with `x_p = k + p` and `y_j = j`, two disjoint sets,
so no denominator is zero.

**"Any `k` shards reconstruct" is not an assumption here.** It is precisely
"every `k` rows of `[I ; C]` are linearly independent". Expand the determinant
along the identity rows and it reduces to an `r × r` submatrix of `C`, where `r`
is how many parity rows were chosen. Every square submatrix of a Cauchy matrix
is Cauchy, and a Cauchy determinant is a product of differences of distinct
elements over a product of the same — nonzero in any field. The property holds
for all `C(n, k)` subsets by construction.

Cauchy was chosen over Vandermonde for one reason: Vandermonde has a mistake
available that Cauchy does not. A Vandermonde matrix made systematic *properly*
— multiply the whole matrix through by the inverse of its top `k × k` block — is
equally MDS. Made systematic by *replacing* rows with identity rows, which is
the tempting shortcut, it is not, and it fails only for some erasure patterns,
which means it passes the tests somebody wrote and loses data years later.

The tests check the property directly anyway, over every subset rather than a
sample: `every_k_by_k_submatrix_of_the_generator_inverts` (all 56 of C(8,5)) and
`every_subset_of_k_shards_reconstructs` (all 84 of C(9,6)).

### One field, not two

[`crypto::gf`](../src/crypto/gf.rs) is the only GF(2^8) in the crate, shared
with [`crypto::shamir`](../src/crypto/shamir.rs), which had it first.

The two callers want opposite things. Shamir multiplies **secret** bytes, so the
usual `EXP[LOG[a] + LOG[b]]` implementation is out: it indexes memory with the
secret and is observable by anything sharing the cache. Erasure coding
multiplies **public** bytes, hundreds of megabytes of them, where an eight-round
masked loop per byte is the difference between a command that finishes and one
that does not.

The usual answer is two implementations. This repository has already paid for
that answer once — *"the one part of a DHT that is genuinely subtle is the part
that must not"* drift — and a field is worse: two multiplies disagreeing on one
of 65,536 products produce shards that reconstruct to garbage on the node that
used the other one, and the digest check reports only that somebody lied.

So there is one multiply, and the fast path does not reimplement it. `gf::Row`
*calls* it 256 times to build a lookup table for one fixed coefficient.
Agreement is by construction — there is no second algorithm to agree with — and
`a_row_agrees_with_mul_on_all_65536_products` says so out loud anyway.

The safety condition travels with the type: a `Row` is indexed by the byte being
multiplied, so it must never be built over a secret coefficient or fed secret
bytes. That is a property of the caller, and nothing in the type can check it.

## Geometry

Every shard is the same length, parity included: `shard_len = ceil(total / k)`.
One chunk geometry then serves all of them. The cost is up to `k - 1` bytes of
zero padding on the last data shard; the alternative — ragged shards — needs a
second geometry for the short one and a special case in every proof.

`total` in the manifest is what removes the padding again, so a reconstruction
is the blob and not the blob plus a tail of zeros.

The last chunk of a shard is short rather than padded, which is the opposite
choice and made for the opposite reason: padding *chunks* up to `chunk_len`
would round a small blob's storage up to `k · chunk_len` — 384 KiB for a 1 KB
file at (4, 2) with 64 KiB chunks — and small files are exactly what a network
of pinned checkers is full of.

The empty blob has one chunk of length zero per shard rather than none, for the
reason a piece manifest gives: a tree with no leaves has no root, and a shard
with no root cannot be committed to or proved, so the empty blob would be
permanently unshardable for want of an edge case.

### Choosing a coding

`shard plan` answers this with numbers instead of prose:

```
$ cairn shard plan artifact.bin
fdb7dadce236… -- 300000 bytes, coding (4, 2) (any 4 of 6 rebuild it)
  6 shard(s) of 75000 bytes, 19 chunk(s) of up to 4096 bytes each
  450000 bytes across all holders, tolerating 2 loss(es)
```

`(4, 2)` is the default: 1.5× on disk for two tolerated losses, against the 3×
replication charges for the same. Nothing depends on it — the manifest records
what was actually used, and two nodes that choose differently for one blob are
not in conflict, because a manifest is checked against the blob digest and never
against another manifest.

The chunk length defaults to the smallest legal power of two that keeps a shard
under 1024 chunks, because a good chunk length for a 4 KiB checker and for a
400 MiB artifact are three orders of magnitude apart. It is bounded at
4 KiB…4 MiB and must be a power of two: a manifest is attacker-supplied, and
`chunk_len = 1` is a denial of service made of arithmetic.

## The manifest

```json
{"chunk_len":4096,"data":4,"digest":"sha256:…","parity":2,
 "shards":["sha256:…", …],"total":300000}
```

Untrusted by construction — anyone can compute one for any bytes, so holding one
proves nothing. `Manifest::describes` is the question that connects it to
something the log already fixed, and nothing should accept a manifest without
asking it first. That is the same trust story a piece manifest has, and it works
here for the same reason: **the objective is the metainfo.** The digest an
objective already commits to is what a manifest is checked against, so there is
no tracker and nothing to sign.

The manifest's id covers the *geometry* as well as the roots. The same shard
bytes read under a different chunk length are a different tree, and two
manifests sharing an id while disagreeing about that would be two readings of
one name.

### No new record kind, and that is a decision

A manifest is derived from bytes. Signing one would be signing an arithmetic
fact, and putting one in the log would move canonical bytes and both
implementations ([AGENTS.md](../AGENTS.md)) to gain nothing that
`Manifest::describes` does not already give.

What the log *could* one day carry is 32 bytes: a manifest root, inside a
promise to hold shard `i` of it. That is an availability undertaking about
content rather than about the log, it needs a record, and it needs something
that pays or slashes against it — which is why it belongs with the bonded
availability work in [roadmap.md](roadmap.md) rather than here. The outer Merkle
hop exists so that record, when it arrives, needs no other change: a chunk proof
already verifies against a bare root.

## Two checks, and the difference between them

| | checks | needs |
|---|---|---|
| `ChunkProof::verify(root)` | these bytes are the chunk at this position of *some* tree with that root | a root |
| `Manifest::verify_chunk(proof)` | that, **and** the geometry: the indices exist in this coding, the chunk is the length this layout says, the shard root is the one this manifest lists | the manifest |

The difference is real rather than a hedge. A root says nothing about how many
chunks a shard has, and two leaf counts that promote at the same levels produce
the same walk — `canonical::Inclusion` documents that its `leaves` field is a
shape parameter and not a commitment. So a one-chunk shard's proof also verifies
under a claim of two chunks; the manifest knows better, and refuses.
`verify_chunk_catches_a_geometry_the_root_alone_cannot` pins exactly that
boundary, and `cairn shard check` prints the caveat on every run rather than
leaving a reader to assume the stronger thing.

The leaf is recomputed from the chunk bytes rather than taken from the proof,
which keeps `Inclusion`'s second-preimage caveat off this path: a prover cannot
offer an internal node as a leaf when the verifier hashes the leaf itself.

A proof carries its bytes, not their digest. The reason is the one
[roadmap.md](roadmap.md) records for the availability answer: a response carrying
only a path can be produced by somebody holding the hashes and none of the
content.

## On disk

```
.cairn/shards/
  <64 hex characters of the blob's digest>/
    manifest      the canonical encoding, one line
    000, 001, …   shard bytes, filed under their index in the coding
```

A blob's name can be its own hash, so [`blobs`](../src/blobs.rs) re-hashes on
read and needs no second record to keep integrity in sync. A shard cannot do
that — a shard's own content address says nothing about which blob it belongs to
or which row of the generator produced it — so the manifest plays that role. It
is not the "second index" [storage.md](storage.md) refuses to introduce, because
it is derived from the bytes and checked against the blob digest: a wrong one is
detected rather than believed.

The invariant is the blob store's, one indirection deeper:

> **The store never returns bytes it has not just re-checked against a
> commitment.**

`put_shard` refuses a shard that does not rebuild its committed root, before
anything reaches the filesystem. A read re-derives the root and **deletes** a
shard that fails — otherwise it shadows the real one forever, since `held` would
go on reporting the index as present and the fetch that would replace it would
never be attempted. That is the same choice `BlobStore::read` makes, and it was
made there for the same reason.

Writes go through a temporary name and a rename, so a crash cannot leave a short
file under a real shard index — which would read back as corruption and cost a
shard that was never actually lost.

### At rest, and eviction

Not sealed, and on the record as not sealed in the table
[`store::exposure`](../src/store/exposure.rs) enforces: a shard is a linear
combination of a blob the network hands to any peer that asks, filed under that
blob's digest, so a stolen disk yields nothing there the network does not give
away for free. The residue is the same one the blob store has — the *set* of
digests a node holds content for — and [threat-model.md](threat-model.md)
already carries it.

Eviction is deliberately strict. Nothing here is under `cache/`, so
`Store::classify` calls it pinned and `store gc` refuses rather than deletes. A
shard is **not** reclaimable the way a blob is: dropping a blob costs a
re-download, dropping the `k`-th surviving shard costs the blob.

## What this does not do

- **No network transfer.** Shards are produced, stored, proved and reconstructed
  locally; moving one between peers is [`swarm`](../src/swarm/)'s job and is not
  wired up. Said plainly because this crate has been bitten before by a
  subsystem tested only against itself — see [storage.md](storage.md) on the two
  bugs that sat in the `swarm`/`blobs` seam with no caller to find them.
  `cairn shard` is the caller that keeps this module honest meanwhile.
- **No repair.** Regenerating a lost shard means reconstructing the blob and
  re-encoding. Regenerating codes that repair from less than `k` shards are a
  real improvement and a much larger one; they are not needed to hold six shards
  on six disks.
- **No streaming encoder.** `encode` holds the blob and every shard at once, so
  it is capped at 1 GiB. Raising the cap means making the encoder streaming
  first, not raising the constant.
- **No payment, and no challenge that costs anything.** A chunk proof is
  cheap to produce and free to check, and nothing yet issues one on a schedule
  or pays for the answer. Until that exists, the `rejected` list is evidence
  with nowhere to be spent.
  [design/shard-assignment.md](design/shard-assignment.md) works out what
  paying for it would price — including the part that looks like sybil
  resistance and is only a constant-factor tax — and why none of it should be
  built before the bond it depends on.
- **It does not prove a holder *stored* a shard.** Same bound the availability
  answer has: a holder that fetched the chunk from somebody else the moment it
  was asked produces an identical proof. Ruling that out needs a time bound or
  sequential work, and Stage 0 has neither. This catches a holder that has
  nothing *and* no source, which is the population worth excluding.
- **It does not make an unavailable blob available.** Coding changes the cost of
  durability; it does not conjure holders. Six shards on one disk are one disk.
