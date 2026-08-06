# Peer-to-peer

Stage 0 runs one operator and one append-only file. This document is the design
for removing the operator. The transport handshake, TCP framing, address book,
set reconciliation, population anti-entropy, and per-tick random peer sampling
are built. Peer *discovery* and frontier-conflict surfacing are not, and are
marked as such — a p2p design that is half-implemented and fully described
reads as finished if you do not say which half.

## What actually needs agreement

The instinct is that peers must agree on the log. They must not, and assuming
they must is what makes people reach for a consensus protocol they don't need.

Three kinds of state, three requirements — the same split as
[consensus.md](consensus.md):

| state | needs agreement? | why | status |
|---|---|---|---|
| records — objectives, commitments, claims | **no** | content-addressed, and verification is a pure function of pinned inputs. Two honest peers holding the same claim reach the same verdict without talking | built (`p2p/sync.rs`) |
| candidate population | **no** | order-irrelevant, and divergence is *useful* — the island model preserves search diversity | built (`gossip.rs`, on the wire in `p2p/pop.rs`) |
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

## Population anti-entropy

Built: [`src/p2p/pop.rs`](../src/p2p/pop.rs).

Candidates travel on the same session as records and share nothing else with
them. That separation is a security boundary, not tidiness.

```
A -> B   PopDigest   population digest + every candidate id
B -> A   PopDigest   equal digests: stop here
A -> B   PopWant     ids A lacks
B -> A   PopWant
A -> B   PopRecords  the bodies B asked for
B -> A   PopRecords
```

**Why not more record kinds.** The record path refuses `verdict`, `settlement`
and `frontier` outright, because importing a peer's conclusion is the trust this
project exists to remove. `peer` is the one kind added since, and it passes the
same test: it is a *claim by a key about itself*, checked by signature and by a
handshake that an impostor cannot complete, not a conclusion anybody has to
believe. A shared message enum would mean one decoder, one set
of ceilings and one `match` covering both families, and the next person to add a
variant would have to notice that half of them must never reach the record path.
So: separate type, separate limits, and a **separate AEAD context string**, which
means a frame sealed for one family cannot be opened as the other even by a peer
that wants to. `candidate` is also not an exchangeable record kind, so a body
that somehow arrived on the record path is refused there too. Both halves are
tested.

**No bucket scheme.** A population holds at most `islands × capacity`
candidates by construction — 256 with the defaults — so the whole id list fits
in one message and the XOR-bucket summary the record protocol needs would be
pure overhead. The digest still goes first, so two peers already in sync
exchange one message each way and stop.

**Scores are re-derived, never imported.** Every arriving candidate is re-scored
locally and dropped if the number does not reproduce, which is affordable for
the same reason everything else here is: checking costs one evaluation. A scorer
that *cannot* answer is a refusal, not an acceptance — the population layer's
version of `UNAVAILABLE` is never `ACCEPT`.

Two ordering facts that are easy to get wrong:

- **Records reconcile first, populations second, on the same connection.**
  Candidates are scored against objectives, so a node that has not yet heard of
  an objective cannot usefully score candidates for it.
- **A population failure does not undo the record round.** Gossiped candidates
  are a search optimisation; a peer that mishandles them must not cost this node
  the records it already imported. Likewise a candidate that fails to re-score
  drops the candidate and keeps the session — tearing the connection down over
  one bad candidate would be a cheap way to censor by annoyance.

## Peer sampling

Built: `AddressBook::sample`, used by `proofwork-p2p` each tick.

The daemon used to dial every endpoint in its book on every tick. That does not
survive a book of any size: the traffic is quadratic in the network, and the
last peer in a fixed iteration order is always the last to hear anything.
Sampling a random subset (default fanout 3, `--fanout` to change it) makes the
per-tick cost constant and the propagation delay logarithmic in the usual
epidemic way. One endpoint per peer, not per address — two addresses for one key
are two routes to one node.

The sample is drawn from the OS entropy source, and indices come from rejection
sampling rather than `next_u64() % n`. A modulo bias here would be tiny and
would still mean a peer-selection routine that quietly prefers the front of the
book, which is the failure it was written to avoid, only harder to notice.

**This is not Sybil resistance.** The sample is uniform over the book, so an
attacker holding *n* of the *m* entries gets *n/m* of every node's connections
and with enough entries eclipses a node outright. Uniform sampling is a
*liveness* mechanism. It fixes "who do I talk to this tick", not "who is allowed
in the book" — and see **Still open** below for the fact that nothing yet adds
anyone to the book but the operator.

## What is encrypted, and what is not

Every frame on a `p2p` connection — records, verifier code, DHT, populations —
is sealed with an AEAD keyed by the Classic McEliece handshake, with the
family's context string bound into the tag. Adding a round means adding a
context, not adding a socket write, and `p2p::dht` was added that way.

That claim is checked rather than asserted. `tests/wire_encryption.rs` puts a
recording relay between two real nodes, runs a session that carries an
objective, a blob and a DHT ask/tell, and asserts none of the content appears in
the captured bytes. It also asserts the initiator's peer id *is* visible, which
is the positive control: without it the test would pass on an empty capture.

**What an observer still learns.** Who talks to whom, how much, and when. The
handshake prefix is necessarily cleartext, because a responder must know which
peer to expect before a key exists. Unlinkability is a transport-layer problem —
onion routing, or rendezvous under a derived key — and is not solved here.

**`swarm::tcp` is not encrypted.** No handshake, no AEAD, no peer
authentication. It is behind the off-by-default `insecure-swarm-tcp` feature so
it cannot reach a binary by accident, and only the socket-facing part is gated:
`swarm::piece`, `swarm::wire`, `swarm::dht` and `swarm::discovery` are pure and
always compiled. The reason it never grew a handshake is the identity mismatch
this document keeps returning to — `swarm` records carry an ed25519 key, the
encrypted transport needs a 261,120-byte McEliece key — so closing it is the
fold-the-stacks work, not a missing call.

## Provider lookup

Built: `p2p::dht`, a Kademlia instance over `crate::dht`, exchanged once per
session and consulted by `Service::peers_for`.

Sampling answers *who do I talk to this tick* uniformly, which is the right
answer when a node has nothing particular to want. It is the wrong answer when
it does. `p2p::code` is need-driven fetch — a node asks for the checkers its own
log pins — but with no way to choose whom to ask, the want set goes to whoever
the sample turned up, and a blob held by one node in ten thousand is found by
luck. This closes that: a key is a blob's content address, a value is *this peer
holds it*, and the routing is Kademlia's.

**A peer id is already a node id.** `PeerId` is `sha256(McEliece public key)`,
which is exactly what a Kademlia id is supposed to be, so there is no second
hash. Two things follow. Identity is self-certifying without a signature —
completing a session *is* the proof, because the responder decapsulates with the
secret key or the channel never keys up. And grinding ids to surround a key
costs a McEliece keypair each, which is far from free. That second one is a real
cost and **not a defence**: it is a constant factor against an attacker willing
to spend, and constant factors do not scale into security.

**A contact cannot carry its key, and that is a design constraint rather than a
preference.** A McEliece public key is 261,120 bytes. A full routing table is
`K × 256` contacts, so inlining one per contact would cost about 1.3 GB for the
part of the system that is supposed to be cheap. A `PeerContact` is therefore an
id, an address and a sequence number — 58 bytes — and the key is resolved from
the address book at dial time.

The consequence is worth stating rather than discovering later: **a routing
answer from this stack is not self-proving.** It is a claim that a peer with that
id lives at that address, checked only when somebody dials it and the handshake
either derives the expected id or does not. Wrong answers cost a dial; they
cannot cost correctness. `swarm::dht` makes the opposite trade, inlining a signed
ed25519 record because at 32 bytes it can.

### Asked, not announced

There is no inventory message, and refusing one is not incidental — `p2p::code`
already refuses one, on the grounds that a list of the blobs a node holds is a
list of the objectives it is working on, which is a free traffic-analysis
signal. Building a DHT by publishing that list would buy routing with exactly
the privacy `code` declined to spend.

So holdership is **pulled**. `Ask` carries content addresses the asker wants;
`Tell` says which of *those* the responder holds, and `Directory::record_tell`
discards anything outside the asked set rather than trusting a peer not to
volunteer. The set asked is the set the code round already sent as a
`code_want`, threaded through rather than recomputed, so the round adds routing
knowledge at **no additional disclosure**.

Threading it rather than recomputing matters in the other direction too: the
still-missing set after a fetch excludes everything the peer just supplied, so a
successful code round would teach the node nothing about who holds what.

### First-hand claims are stored; relayed ones are used and dropped

This is the rule that replaces signatures.

A `Tell` is attributed to **the session's peer id**, never to an id in the
message — there is no such field to forge. A `Providers` response, which belongs
to the multi-hop lookup, is hearsay: a peer relaying "C holds D" cannot prove it
and the receiver cannot check it. Those records are used as lookup results and
**never entered into the local provider store**, so a lie dies with the lookup
that heard it.

Without the second half an unsigned DHT is an amplifier: claim a victim holds a
popular blob, let it propagate, and the network dials the victim. The cost of
closing it this way is that provider knowledge spreads one hop rather than
arbitrarily far — which costs nothing today, because the multi-hop driver that
would carry it further is not built. It is the reason to prefer signed records if
the network outgrows this.

### What this does not do yet

`peers_for` reorders the peers a node **already knows**; it cannot introduce new
ones, because a DHT candidate with no address-book entry has no key to dial with.
So provider lookup improves *whom you ask among your peers* and does not yet
improve *who your peers are*. The lookup itself is also one hop: `dht::Lookup` is
built and tested as a pure state machine, and nothing feeds it across
connections, so `O(log n)` routing is designed and not running.

## Implemented baseline

`p2p::discovery::AddressBook` stores non-consensus `PeerId` to socket-address
hints. `p2p::transport` performs the 32-byte-id/96-byte-ciphertext handshake and
length-bounded encrypted framing. `p2p::session` drives the inventory,
bucket-id, want, records, and done exchange — and, separately, the population
digest/want/records exchange — while `p2p::service::Service` connects those
pieces for dialing and inbound accepts. The service does one anti-entropy round
at a time; a daemon schedules retries around it without changing the protocol.

The responder still cannot authenticate the initiator from the KEM alone. A
deployment that needs mutual authentication must restrict inbound ids to its
discovery/address-book policy or add a signed session greeting. The listener
also remains responsible for rate limiting before calling the expensive
McEliece decapsulation.

The `proofwork-p2p` binary is the runnable daemon wrapper. It persists a local
McEliece identity, opens the node ledger, accepts inbound sessions, dials a
random subset of its address book each tick, and replays newly admitted
objectives, commitments, and claims through `Node`; verdicts and settlements are
always re-derived locally. It also persists a separate FIPS 204 ML-DSA-65 root
key and writes a signed checkpoint after each successful sync. A bootstrap file
is canonical JSON of the form
`{"addr":"127.0.0.1:9001","public":"<hex public key>"}`.

```text
proofwork-p2p --identity node.json --listen 127.0.0.1:9000 \
  --log proofwork.jsonl --root . --bootstrap peer.json \
  --population population.json --fanout 3
```

`--population` is optional and turns on the second half of each round. Given it,
the daemon loads the file at startup, reconciles populations after records on
every session, and writes the file back afterwards. Without it, no population
crosses the wire — a node that only audits has no candidates to offer and no use
for anyone else's. A missing file is a first run; a corrupt one is fatal at
startup rather than silently discarded, because throwing away a node's search
state is not something to do quietly.

The daemon re-scores arriving candidates with the objectives in its own log,
snapshotted after the record round so that candidates for an objective learned
in the same round can still be scored. A candidate for an objective this node
has never seen is refused, and reappears on a later tick once the objective
does.

## Still open

- **Peer discovery.** Sampling and provider lookup both choose *among* the peers
  the address book already holds; nothing adds to it but `--bootstrap` files the
  operator wrote. The design calls for a signed, size-capped peer-list exchange;
  `swarm::discovery` implements exactly that against a different identity scheme
  and is not wired in here, which is the "fold the two stacks together" item in
  [roadmap.md](roadmap.md). Until it is, the peer set is an operator configuration decision, which
  is a real limit and also the only thing currently standing between this node
  and an eclipse: uniform sampling over a book an attacker can fill is uniform
  sampling over the attacker. Structured overlays with identities that cost
  something are Stage 2, and no amount of better sampling substitutes for them.
- **Settlement order across peers.** Records converge and every node re-derives
  its own verdicts, but a batch's settlement order is keyed on that node's
  ledger head at the epoch boundary, and two independently ordered logs do not
  share one. Stage 0 has a single sequencer, so there is one order that matters;
  removing the sequencer means this needs the same answer as frontier order.
- **Frontier conflict surfacing.** The record set merges cleanly, but two valid
  claims can each look like the first improvement. The layer should expose that
  rather than pick one, and the exposure format is undesigned. This is the piece
  that genuinely needs the base layer.
- **Record availability.** Content addressing makes withholding *detectable* —
  the id is known and the bytes are missing — but nothing here replicates
  aggressively enough to make it *hard*.
