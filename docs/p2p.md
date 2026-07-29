# Peer-to-peer

Stage 0 runs one operator and one append-only file. This document is the design
for removing the operator. Part of it is built; the rest is specified here and
marked as not built, because a p2p design that is half-implemented and fully
described reads as finished if you don't say which half.

## What actually needs agreement

The instinct is that peers must agree on the log. They must not, and assuming
they must is what makes people reach for a consensus protocol they don't need.

Three kinds of state, three requirements — the same split as
[consensus.md](consensus.md):

| state | needs agreement? | why | status |
|---|---|---|---|
| records — objectives, commitments, claims | **no** | content-addressed, and verification is a pure function of pinned inputs. Two honest peers holding the same claim reach the same verdict without talking | merge law built (`gossip.rs`), transport not |
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

## Set reconciliation — *not built*

The remaining piece, and the one [`roadmap.md`](roadmap.md) names: "the wire
protocol (peer sampling, anti-entropy, digest reconciliation) is not written."

The intended shape, so it is on record:

```
Hello      { peer_id }                     — 32 bytes; key fetched separately if unknown
Inventory  { buckets: [(prefix, count, digest)] }
Want       { ids: [...] }
Records    { entries: [...] }
```

- **Bucketed digests.** Group record ids by leading byte; exchange 256
  `(count, xor-of-ids)` pairs. Buckets that match are skipped entirely, so the
  common case — peers already in sync — costs one small message each way rather
  than a full id list.
- **Verify on ingest, never trust.** A received record is re-verified locally
  before it counts, exactly as `gossip::ingest` re-scores a candidate rather
  than believing a peer's claimed score. A peer's verdict is an assertion; the
  pinned verifier is the fact.
- **Merge is union.** No conflict resolution is needed for records, because
  content addressing means two peers holding "the same" record hold identical
  bytes.

Open questions worth settling before writing it:

- **Peer sampling.** Random sampling is simple and Sybil-vulnerable; structured
  overlays resist that and are more work.
- **Frontier conflict surfacing.** The set merges cleanly, but two valid claims
  can each look like the first improvement. The layer should expose that rather
  than pick, and the exposure format is undesigned.
- **Record availability.** Content addressing makes withholding *detectable* —
  the id is known and the bytes are missing — but nothing here replicates
  aggressively enough to make it *hard*.
