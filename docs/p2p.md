# Peer-to-peer

Stage 0 runs one operator and one append-only file. This document is the design
for removing the operator. The transport handshake, TCP framing, static
bootstrap address book, and set reconciliation are built. Dynamic peer
sampling and frontier-conflict surfacing are not, and are marked as such — a
p2p design that is half-implemented and fully described reads as finished if
you do not say which half.

## What actually needs agreement

The instinct is that peers must agree on the log. They must not, and assuming
they must is what makes people reach for a consensus protocol they don't need.

Three kinds of state, three requirements — the same split as
[consensus.md](consensus.md):

| state | needs agreement? | why | status |
|---|---|---|---|
| records — objectives, commitments, claims | **no** | content-addressed, and verification is a pure function of pinned inputs. Two honest peers holding the same claim reach the same verdict without talking | built (`p2p/sync.rs`) |
| candidate population | **no** | order-irrelevant, and divergence is *useful* — the island model preserves search diversity | built (`gossip.rs`) |
| work assignment | **no** | a pure function of an epoch beacon; overlap wastes compute and self-corrects | built (`partition.rs`) |
| **frontier order** — who improved first | **yes** | payment depends on it | **not solved p2p** |

So the shared object is not a chain, it is a **grow-only set of
content-addressed records**. Merge is union. Each peer derives its own state by
replaying its set through the same rules, and two peers with the same set derive
the same state — no protocol required, because the rules are deterministic and
every input is pinned.

A linear hash-linked log has exactly one writer by construction. Stage 0's
`Ledger` is that log. Going p2p does not mean making the chain concurrent; it
means recognising that the chain was a local ordering of a set, and the set is
what peers exchange.

### The part that stays hard

Frontier ordering is a real total-order problem and no amount of gossip solves
it. Two peers can each honestly believe a different claim moved the frontier
first, and both can be internally consistent. What a p2p layer can do is make
the disagreement **detectable** — both claims are in the set, both are valid,
and the conflict is visible to anyone who looks — rather than silently paying
the wrong person. What it cannot do is decide. That needs the base layer
[consensus.md](consensus.md) argues for, and nothing here changes that
conclusion.

## Transport security: Classic McEliece

Built: [`src/p2p/handshake.rs`](../src/p2p/handshake.rs).

Measured on the development machine, `mceliece348864`:

| operation | cost | size |
|---|---|---|
| keygen | 243 ms | public key **261,120 bytes** |
| encapsulate | 22 µs | ciphertext **96 bytes** |
| decapsulate | 12 ms | shared secret 32 bytes |

Those numbers determine the protocol, so they are worth stating before the
design rather than after.

**A 255 KB public key cannot travel in every handshake**, and a 243 ms keygen
cannot happen per connection. So a peer's public key is its **long-term
identity**: published once, fetched once, cached by id. A `PeerId` is the
SHA-256 of the key — 32 bytes — so peer references stay small everywhere, and
the id commits to the key, meaning "fetch the key for this id later" is safe.

After caching, a handshake is **96 bytes and 22 µs for the initiator**. That is
smaller than X25519 plus a certificate chain. The cost is entirely front-loaded
into a one-time key distribution, which suits gossip well: peers are long-lived,
connections are many.

### What the handshake gives you

- **Confidentiality against a quantum adversary.** Classic McEliece is the most
  conservative KEM available; its problem has resisted attack since 1978, which
  is the reason to accept the key size at all.
- **Implicit responder authentication.** Only the secret-key holder can
  decapsulate, so a session that decrypts proves who is on the other end.
- **Transcript binding.** Both peer ids and the ciphertext go into the KDF, so a
  shared secret is useless outside the exact handshake that produced it. A
  ciphertext replayed under a different claimed initiator derives different keys
  and every frame fails to authenticate.
- **Directional keys.** The nonce is a frame counter starting at zero on both
  sides, so a single key would have both peers using nonce 0 under it — the one
  failure ChaCha20-Poly1305 cannot survive. Two keys, one per direction.
- **Replay and reorder rejection.** Counters must strictly increase, and a
  *forged* frame does not advance the window, so an attacker cannot send garbage
  at a high counter to lock out the honest peer.

### What it does not give you

- **No forward secrecy.** The real cost of a static key. If a peer's McEliece
  secret leaks, every past session it accepted becomes readable to whoever
  recorded the traffic. Ephemeral keypairs would fix it at 243 ms and 255 KB per
  connection, which no gossip protocol can pay. The available mitigation is
  rotation, and a peer's id changes when it rotates.
- **No initiator authentication.** The KEM says nothing about who encapsulated.
  Peers that must prove identity sign the transcript with the ed25519 key in
  [`crypto/identity.rs`](../src/crypto/identity.rs); that layer already exists
  and the handshake deliberately does not duplicate it.
- **A 125,000× DoS amplification.** Encapsulation costs 22 µs, decapsulation
  12 ms. A 96-byte message buys that much CPU from the responder. Not a
  cryptographic weakness — a pricing problem the deployment must solve with rate
  limiting or a cheap-to-verify proof of work before decapsulating. **Nothing in
  the module does this for you**, and exposing `accept` to open traffic without
  it is a mistake.

## Set reconciliation

Built: [`src/p2p/sync.rs`](../src/p2p/sync.rs).

### Records cross the wire; entries do not

A `Ledger` entry's hash covers its `seq` and its `prev`, so it is
position-dependent: two peers holding the same records in different orders
compute different entry hashes for all of them. Entries are therefore not the
exchangeable unit. The unit is a **record** — a `(kind, payload)` pair whose id
is the payload's own content address, independent of where anyone filed it.

### Only inputs are exchanged

| kind | crosses the wire? | why |
|---|---|---|
| `objective`, `commitment`, `claim` | **yes** | primary inputs |
| `verdict`, `settlement`, `frontier` | **no** | derived by replaying the inputs |

This is the security argument of the whole layer. Importing a peer's verdict
would mean trusting its verification, which is exactly the trust this system
exists to remove. A peer that ships a `verdict` is confused or lying, and
`Peer::ingest` refuses it either way — as does `Peer::insert`, so the rule
cannot be dodged by seeding the set locally.

`tests/p2p_convergence.rs` checks the consequence end to end: a node given only
inputs re-derives every verdict, reward and settlement itself, and lands
byte-for-byte where the sender did — having been told none of it. It reaches
the same state whatever order the records arrive in, because a set has no
order.

### The exchange

```
A -> B   Inventory   256 x (count, xor)   fixed size, sparse on the wire
B -> A   Inventory
         BucketIds   only for buckets that differ
A -> B   Want        ids A lacks
B -> A   Records     the bodies
```

Ids are SHA-256 digests and so uniformly distributed; bucket by leading byte and
summarise each bucket with a count and an XOR of its ids. Peers already in sync
exchange two fixed-size messages and stop — the common case costs no per-record
traffic. Only buckets that actually differ escalate to id lists. Empty buckets
are omitted, so a peer with three records sends three bucket entries, not 256.

The XOR digest is an **optimisation, not a security boundary**. It reliably
catches accidental divergence; a malicious peer could craft a colliding bucket
and thereby hide its own records from you, which costs it its own gossip and
gains it nothing. Correctness rests on re-verification, never on the digest.

### Refusing a bad peer

- **Unsolicited records are refused**, even when they would verify. Otherwise a
  peer pushes whatever it likes at whatever volume. There is deliberately no
  separate "wrong body for this id" error: a record is keyed by the digest of
  the bytes actually received, so substitution produces an id that was never
  requested and surfaces as unsolicited. A distinct variant could never fire.
- **Message ceilings** on ids and records, checked before allocation.
- **One bad record does not poison a batch** — the rest still land.

## Implemented baseline

`p2p::discovery::AddressBook` stores non-consensus `PeerId` to socket-address
hints. `p2p::transport` performs the 32-byte-id/96-byte-ciphertext handshake and
length-bounded encrypted framing. `p2p::session` drives the inventory,
bucket-id, want, records, and done exchange, while `p2p::service::Service`
connects those pieces for bootstrap dialing and inbound accepts. The service
does one anti-entropy round at a time; a daemon can schedule retries and peer
sampling around it without changing the protocol.

The responder still cannot authenticate the initiator from the KEM alone. A
deployment that needs mutual authentication must restrict inbound ids to its
discovery/address-book policy or add a signed session greeting. The listener
also remains responsible for rate limiting before calling the expensive
McEliece decapsulation.

The `proofwork-p2p` binary is the runnable daemon wrapper. It persists a local
McEliece identity, opens the node ledger, accepts inbound sessions, periodically
dials every `--bootstrap` endpoint, and replays newly admitted objectives,
commitments, and claims through `Node`; verdicts and settlements are always
re-derived locally. A bootstrap file is canonical JSON of the form
`{"addr":"127.0.0.1:9001","public":"<hex public key>"}`.

```text
proofwork-p2p --identity node.json --listen 127.0.0.1:9000 \
  --log proofwork.jsonl --root . --bootstrap peer.json
```

## Still open

- **Peer sampling.** Random sampling is simple and Sybil-vulnerable; structured
  overlays resist that and are more work. The shipped service accepts static
  bootstrap endpoints, but does not choose or refresh a dynamic peer set.
- **Frontier conflict surfacing.** The record set merges cleanly, but two valid
  claims can each look like the first improvement. The layer should expose that
  rather than pick one, and the exposure format is undesigned. This is the piece
  that genuinely needs the base layer.
- **Record availability.** Content addressing makes withholding *detectable* —
  the id is known and the bytes are missing — but nothing here replicates
  aggressively enough to make it *hard*.
