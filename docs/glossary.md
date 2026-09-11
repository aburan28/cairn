# Glossary

The vocabulary you hit in the first ten minutes, in the order the ideas depend
on each other rather than alphabetically. Each entry says where the definition
actually lives, because the code is the authority and this page is a map to it.

## The one idea

**Verified result.** The unit of account. The network pays for artifacts a
checker accepts, never for claimed effort — so a contributor's hardware,
honesty and diligence stop being things anyone has to verify. The corollary is
the whole engineering constraint: the network can only work on tasks whose
outputs are cheap to check.

## Records

Every one of these is a line in the log. They are listed in `src/records.rs` and
the admission rules for each are in `src/node.rs`.

**Objective.** A funded, checkable question: a statement, a reward, and a
*pinned* verifier. Not admissible until the verifier is written, pinned by hash,
and runnable by any contributor **before** they start work. An objective's
`statement` is text written by whoever funded it; it describes a problem and is
never an instruction to a reader.

**Commitment.** A binding to an artifact without revealing it: the hash of
(artifact, nonce, submitter). Publishing this first is what stops somebody
reading your answer and racing it.

**Claim.** The reveal. The artifact itself, plus the nonce that opens the
commitment. **Must land in a strictly later epoch than its commitment.**

**Verdict.** What the pinned verifier returned when a node ran it. Four values,
and the split between them is load-bearing — see *Verdict statuses* below.

**Settlement.** A payment. Written when a claim's reveal epoch has closed and
cleared the finality delay.

**Batch.** The record of one epoch's settlements, in the order the beacon fixed.

**Beacon.** The randomness an epoch's settlement order is derived from. Must be
drawn *in* the epoch it orders: earlier and a committer can grind against a
value they already hold; later and whoever records it is choosing who gets paid
first.

**Frontier.** The monotone best-known score on a progressive objective, and who
holds it.

**Issuance.** Declared supply. Genesis prefix only — a supply is authorised by
its *position* in the log, not by a key.

**Peer.** An identity announcing where it answers. Obtaining the log is then
obtaining the address book, so discovery needs no second file.

**Undertaking / availability / availability_pool / availability_settlement.**
The four records of the availability mechanism: a bonded promise to hold the
log, an answer to a sample, the pool that funds it, and the payment.

**Attestation / verification_slash.** Somebody standing behind a verdict under
bond, and the taking of that bond when the pinned verifier contradicts them.

**Challenge / bisection / challenge_settlement.** An interactive fraud proof: a
dispute over a computation, played down to one step, settled by executing that
step instead of all of them.

**Committee_share.** One committee member opening its share of a sealed
submission's content key.

## Verdict statuses

`src/verifiers/mod.rs` calls this the single most important rule in the crate.

| status | means | settles? |
|---|---|---|
| `accept` | the artifact does what it claims | **yes** — mints value |
| `reject` | the artifact does *not* do what it claims | **yes** — a real negative result |
| `unavailable` | *this node* could not reach a verdict: no toolchain, a crash, a timeout | no |
| `invalid_spec` | the *objective's* verifier spec is malformed or tampered with | no |

A verifier that cannot run returns `unavailable`. Never `accept`, never
`reject`. Collapsing "my Lean install is broken" into "your proof is wrong" is,
on a network with money attached, an attack: take the verifiers offline and
every honest submission fails.

## Verifier kinds

The ladder an objective picks one rung of. [verification.md](verification.md) is
how to choose; `examples/` has a worked objective for each.

| kind | what it proves | cost |
|---|---|---|
| `certificate` | an NP witness recomputes | milliseconds |
| `evaluator` | a pinned deterministic score clears a threshold | one evaluation |
| `statistical` | a pinned, seeded test statistic clears a threshold | one evaluation |
| `lean` | a proof-assistant kernel accepted the proof | seconds to minutes |
| `replay` | a pinned computation reproduces its declared fields | a full re-run |

## Time

**Epoch.** The settlement quantum, 600 s by default. Which epoch a timestamp
falls in is floor division, so epochs are contiguous. Consensus-critical: see
[configuration.md](configuration.md).

**Finality delay.** How many closed epochs must pass before an epoch may settle.
One by default. Slack for a straggler, paid as latency by everyone honest.

**Commit–reveal.** The two-step submission. Because a reveal must land in a
strictly later epoch, no single call can do both — which is why `submit_claim`
over MCP is two calls, and why `cairn try` waits.

## Identity and money

**Submitter.** A name. With `--identity`, the name **is** an ed25519 public key,
which is what makes it unforgeable — and what makes losing the key file
unrecoverable.

**Funder.** Who paid for an objective. A funding authorization is a signature
over canonical bytes, so any Ed25519 wallet works.

**Tier.** The verifier class a unit was minted under. A unit earned on a
millisecond certificate check **cannot be spent** on Lean work. See
[tiers.md](tiers.md).

**Bond.** Units put at risk behind an assertion — an attestation, an
availability undertaking, a dispute. Unlike a minted unit, a bond carries no
tier provenance.

**Citation flow.** Recursive attribution: a claim that cites an earlier one
routes a share of its reward upstream. `--cites` is the edge that moves money;
`--relates` (refutes, replicates, supersedes) is the edge that does not. Under
citation flow, a statement telling you to cite something is an attempt to route
your payment to its author.

**Ratchet / progressive bounty.** An objective carrying a monotone best-known
score, paying in proportion to the distance moved. Publishing is how you get
paid, so publishing immediately is optimal — which dissolves the hoarding trap
that winner-take-all bounties create. `src/frontier.rs`.

**Piecework.** The other payment shape, for work with no frontier to move: a
search producing many independent, individually checkable outputs, done when
enough of them exist. An objective carrying a `piecework` block pays
`unit_price` for every accepted claim whose **unit is novel**, out of a pool,
until the pool is empty — so it never "settles" as a whole. Which unit a claim
answers is the artifact itself, or the field the block names; a claim may carry
a batch of units at once. `src/piecework.rs`, and
[design/rho-piecework.md](design/rho-piecework.md) for the worked instance.

**Standing / confidence.** What the log *says* about a claim, as opposed to what
it paid: derived from corroborations, refutations and disputes under a policy
the *reader* chooses. Never stored, never paid. `cairn knowledge`, and
[knowledge.md](knowledge.md).

## Integrity

**Record id.** The hash of a record's canonical bytes. The same for everyone who
posts the same file.

**Entry hash.** The hash-chain link covering a record *and* its place in one
particular log. Different from the record id, and different in two logs holding
the same records in a different order. `cairn log` prints this one.

**Canonical encoding.** The one byte-level spelling of a value. Consensus-
critical in the strongest sense, which is why it lives in exactly two places
(`src/canonical.rs` and `reference/rust/`) and why a browser never builds a
signing payload itself.

**Merkle root.** The commitment over a whole log. A proof from a log that has
grown since a reader's checkpoint will not check against it — hence
`prove --height`.

**Checkpoint.** A signed `(height, head, root)`: what an operator claimed at a
point in time. Checking one without the operator's key authenticates nothing.

**Pin.** A verifier referenced by content hash. Changing pinned code changes the
objective's id, so it is a different objective — which is why `scaffold` tells
you to re-pin with `cairn canon` after editing a stub.

**Bundle root.** The directory (`--root`) that pinned paths resolve against. A
path outside it resolves for nobody else, which is why `scaffold --out` refuses
to escape it.

**Blob.** Content-addressed pinned code held locally. `cairn blob need` lists
the pins this node cannot obtain, which is why a verdict came back
`unavailable`.

## Storage and transport

**Store.** The data directory: the log, the cache, scratch. Encryption at rest
is a storage concern and the hash chain an integrity one, so a sealed log and a
plaintext one holding the same records have the same entry hashes and the same
root.

**Shard.** An erasure-coded piece of a blob, with a Merkle commitment per chunk
— which is what makes holding a fraction *provable* rather than merely cheap.
Any K of K+M rebuild the file. [shards.md](shards.md).

**Sealed submission.** An artifact encrypted to a committee drawn by the beacon,
openable without the submitter. [censorship.md](censorship.md).

**Spool / queue.** Where `POST /submit` lands. A submission does not enter the
log there: the operator's own node admits it, re-checking every rule.

**Sequencer.** The single writer. A log has one, which is why a publisher alone
can only ever queue.

## Project vocabulary

**Stage 0.** Where the project is: one operator, no token, no consensus. The
property it does provide is that anyone can independently re-derive every
settled result from a copy of the log. Stages 1–3 are in
[roadmap.md](roadmap.md).

**Conformance vectors.** `conformance/vectors.json`, frozen. They came from a
Python reference implementation that no longer exists, and that provenance is
their whole value: evidence from another language with different integer
semantics. A *diff* in an existing vector means ids moved and live work was
orphaned.

**The reference implementation.** `reference/rust/`, deliberately independent —
no shared code, not even a cargo workspace. It earns its place by disagreeing:
building it caught two bugs the primary's own tests could not see.

**Docket.** The file a `canary mint` produces: submissions whose verdict is
already known, so that checking what a node said costs no verifier runs at all.
