# Roadmap

Ordered by value delivered per unit of consensus complexity — roughly the
reverse of how these projects are usually built.

## Stage 0 — verifiable log, no token *(this repository)*

One operator. Objectives with runnable pinned verifiers, commit–reveal,
hash-linked append-only log, exact-conservation attribution, and an `audit` that
re-derives every settled result from the artifacts. Plus the coordination layer:
progressive bounties (`frontier.py`), a CRDT candidate population (`gossip.py`),
and coordinator-free work assignment (`partition.py`).

The property this buys is not "no one is in charge". It is **anyone can check**
— and that is most of the value of decentralization, at none of the cost.

The list below is what stood between Stage 0 and being usable by anyone but its
author. All of it is now built; what each item does *not* cover is stated on the
item rather than left to be discovered. Whether each rule is also *modelled* —
the third acceptance condition in `docs/design-stage0-completion.md` — is
tracked separately in [formal-model.md](formal-model.md); a box below means the
behaviour ships and is tested, not that TLC has checked it.

- [x] **Sandbox verifier execution.** Every spawn of objective-authored code
      runs in an OS jail — bubblewrap on Linux, a seatbelt profile on macOS —
      with no network, writes confined to a scratch directory, a wall-clock
      deadline, and best-effort `RLIMIT_CPU`/`RLIMIT_AS`. This is not the
      container/WASM boundary this line originally asked for: a kernel bug is
      still an escape, and on macOS reads are not confined. `PROOFWORK_REQUIRE_SANDBOX=1`
      turns a host with no jail mechanism into `UNAVAILABLE` rather than a
      silent unconfined run. [verification.md](verification.md#sandboxing) and
      the threat-model row name the four remaining gaps; VM-class isolation is
      Stage 2.
- [x] **Local store: encryption at rest, a chosen data directory, and a size
      cap** (`src/store/`). The log is sealed line-wise so appends stay appends,
      the key defaults to outside the data directory, `sync` mirrors ciphertext
      without ever carrying the key, and the cap refuses rather than pruning a
      hash-linked log. See [storage.md](storage.md).
- [x] Key rotation: `proofwork store rekey` re-seals every line under a fresh
      key and proves the new file re-derives the same entries and the same root
      *before* anything is swapped. The old key is kept at `<key>.previous`,
      because copies made earlier — a `sync` mirror, a backup — are still sealed
      under it; the old ciphertext is not kept, because keeping it would leave a
      readable copy under the key being retired. `--new-passphrase-file` is
      separate from `--passphrase-file` so a rotation prompted by a leaked
      secret is not forced to reuse it. See
      [storage.md](storage.md#rotating-the-key).
- [x] Signed checkpoints: publish `(merkle_root, height, signature)` with a
      separate FIPS 204 ML-DSA-65 root key so a reader can pin what the operator
      claimed at a point in time and detect a rewrite. The daemon writes one
      after each successful p2p synchronization.
- [x] `proofwork verify --from <checkpoint>` for readers who only have a log
      fragment: verifies the signature against a pinned root key, then recomputes
      head and Merkle root over the prefix of length `height`. A longer local log
      passes, a shorter one fails, and `--audit` re-derives the settlements in
      that prefix.
- [x] Objective schemas in `spec/` wired into `post` as a hard validation gate.
      The schema documents are the validator: both implementations interpret
      `spec/*.json` rather than reimplementing them, so the two cannot drift.
- [x] **Piece-level blob transfer** (`src/p2p/swarm/`), in the BitTorrent shape:
      pieces, a manifest of piece hashes, bitfields, rarest-first, bounded
      pipelining, tit-for-tat choking, endgame with cancels, and a TCP driver.
      Library-only. The driver ran plaintext behind an off-by-default feature
      until the transport was folded onto `p2p`'s; it is encrypted now.
      It reads and writes the same `src/blobs.rs` store `p2p::code` uses, and
      overlaps it: `p2p` already moves pinned code whole, which is adequate
      while `blobs::MAX_BLOB_BYTES` is 1 MiB — four pieces. The piece machinery
      is sized for artifacts that cap does not yet allow, so it is groundwork
      rather than a current need. The objective's digest *is* the swarm id, so
      the ledger does the tracker's job and there is nothing to sign.
- [x] **Erasure-coded shards, with a Merkle commitment per chunk**
      (`src/shards/`). A blob split into `k` data and `m` parity shards, any `k`
      of which rebuild it: `(k+m)/k` on disk against the `f+1` full copies
      replication charges for the same tolerance -- 1.5× at (4, 2) where
      replication wants 3×.
      **The commitments are not an optimisation on top of the coding, they are
      what makes the coding safe to use.** Replication has a property nobody
      names because it is free: every copy is self-checking. Coding destroys it
      — a shard does not hash to the blob's digest, and one corrupt shard makes
      *every* output byte wrong, with the digest reporting only that somebody
      lied. So nothing enters the linear combination until its chunks rebuild
      the root the manifest commits to; a liar is dropped and **named**, which
      is the `rejected` list a peer scorer or a slashing rule would consume.
      Two levels of tree, because the outer hop is what lets a chunk proof
      verify against a bare 32-byte root — the size of something a record could
      one day commit to — rather than against the whole manifest.
      Systematic Cauchy Reed–Solomon over GF(2^8), chosen over Vandermonde
      because Vandermonde has a mistake available that Cauchy does not:
      *replacing* rows with identity rows rather than transforming the matrix
      loses the MDS property for some erasure patterns only, so it passes the
      tests somebody wrote and loses data later. MDS is checked over every
      subset rather than a sample.
      One field, not two: `crypto::gf` is now the crate's only GF(2^8), shared
      with `crypto::shamir`, with the bulk table *built from* the branch-free
      multiply rather than beside it — two multiplies disagreeing on one of
      65,536 products would produce shards that reconstruct to garbage on the
      node that used the other one.
      Deliberately **no record kind**: a manifest is derived from bytes, so
      signing one would sign an arithmetic fact, and it is connected to the
      network the way a piece manifest is — by describing a digest the log
      already pinned. Deliberately **no transfer**: `proofwork shard` is the
      caller that keeps the module honest until `swarm` grows one, because a
      subsystem with no entry point is how the two `swarm`/`blobs` seam bugs
      survived, and `scripts/shard-demo.sh` drives six stores that share nothing
      in CI. See [shards.md](shards.md).
- [x] **Signed peer records** (`src/p2p/swarm/discovery.rs`) in the ENR shape --
      identity is an ed25519 key, location is a hint signed by it, `seq`
      supersedes -- plus peer exchange, so one address given once accumulates the
      rest. This is the answer to "learning new peers is bootstrap-file only" in
      the gossip entry above, and it is not yet wired into `p2p`'s address book.
      Every hint source is equal because none is trusted, which is what makes DNS
      optional rather than load-bearing. See [discovery.md](discovery.md).
- [x] **A Kademlia DHT** (`src/p2p/swarm/dht.rs`) for the question a fetch actually
      asks -- who holds digest `D` right now. Peer exchange answers which peers
      exist; without provider lookup a fetch floods everyone it knows. XOR
      metric, k-buckets with oldest-live-wins, provider store with expiry, and
      the iterative lookup as a pure state machine. Safe to get wrong here in a
      way it is not elsewhere: every answer is a hint and the digest decides, so
      eclipse costs liveness and never correctness.
- [x] **The multi-hop lookup driver** (`p2p::dht::Directory`). `Lookup` was a
      tested state machine with nothing feeding it across connections, so
      lookups stopped at the peers a node already had. `seek` starts a search,
      `next_hops` names whom to dial, `on_providers`/`on_unreachable` feed
      answers back, `take_finished` drains results — and a hop rides an ordinary
      session rather than opening its own, because a dedicated connection per
      hop would spend a McEliece handshake on two small messages.
      The enabling piece was `DhtMessage::GetKey`. A routing answer names a peer
      by id and address and *never* by key — a 261 KiB McEliece key cannot live
      in a routing table — so a contact heard of was undialable forever, and the
      DHT could only reorder peers a node already knew. Fetching one on demand
      costs 261 KiB once per peer actually dialled, and checking it needs no
      trust at all: a peer id *is* `sha256(public key)`.
      One rule holds it together, and it is stated on every method that assumes
      it: for each contact `next_hops` hands out, exactly one of `on_providers`
      or `on_unreachable` must follow. A contact left outstanding is a lookup
      that never terminates.
      **Bucket refresh**, in the shape this stack can pay for. Kademlia's
      oldest-live-wins policy needs somebody to probe the oldest contact in a
      full bucket, and nothing here will dial a peer purely to ask — so the
      failed dials the node was already making are the probe. Three consecutive
      failures with no answer in between drops a contact, any answer resets the
      count, and a newcomer parked by `saw` takes the freed slot. Before this
      nothing in `p2p` ever called `forget` or `replace`: a bucket that filled
      once stayed full of dead peers and every lookup routed through them. No
      periodic random lookups, because discovery already rides every lookup's
      `closer` contacts.
      **Provider republication and announcing to the `k` nearest are not
      wanted here**, and that is a decision rather than an omission. Both
      require *announcing*, and this stack is asked-not-announced on purpose:
      a list of the blobs a node holds is a list of the objectives it is
      working on, and publishing it to build a DHT would buy routing with
      exactly the privacy `p2p::code` declined to spend. Records stay fresh
      without it — a node re-asks for what it still needs every round, and each
      answer re-announces with a new expiry, so a record lapses exactly when
      nobody is asking for that blob any more.
- [x] **One Kademlia, not two** (`src/dht.rs`). The metric, the k-buckets, the
      iterative lookup and the provider store are generic over a contact type;
      `p2p::swarm::dht` and `p2p::dht` are instantiations. Written twice they would
      have drifted, and the one part of a DHT that is genuinely subtle is the
      part that must not.
- [x] **Provider lookup in the daemon** (`src/p2p/dht.rs`). `p2p::code` is
      need-driven fetch with no way to choose whom to ask, so the want set went
      to whatever the random dial sample turned up. Now a session asks which of
      those the peer holds, and `Service::peers_for` dials one that said yes. A
      `PeerId` is already `sha256(public key)`, so it is the Kademlia id
      unchanged -- and a contact deliberately does not carry the key, because a
      McEliece public key is 261,120 bytes and a full table would cost 1.3 GB.
      Holdership is pulled, not advertised: `p2p::code` refuses an inventory
      message on privacy grounds and this does not reintroduce one -- a `Tell`
      answers only what the peer asked, and the asked set is the `code_want`
      already sent on that connection. Answers are attributed to the session,
      never to the message body, which is what makes an unsigned record safe.
- [x] **`swarm`'s transport is encrypted** — it runs over `p2p::transport`,
      Classic McEliece to an AEAD channel, with its own context string so a
      blob frame cannot be opened as a record sync. The `insecure-swarm-tcp`
      gate is gone because the reason for it is.
      Two things had to exist first and neither was socket work.
      `discovery::PeerRecord` gained the 32-byte transport id, so the two
      identity schemes agree without a 261,120-byte key ever being relayed. And
      `Connection::split` made a session usable from two threads — the writer
      thread is deliberate, a `Connection` is `&mut self` on both halves, and a
      mutex would starve the writer whenever the reader blocked.
      `a_transfer_puts_no_plaintext_on_the_wire` asserts it of the *bytes*: a
      recording relay between leech and seed, and neither the blob nor its
      digest in the capture.
      **What it cost is stated rather than hidden.** An authenticated dial needs
      the responder's key, so `fetch` takes endpoints; a relayed record carries
      an id and not a key, so an address learned by peer exchange is now a hint
      something must complete. The second fetch on a node used to need no
      `--peer` and now needs the key too — and that is **given back** by
      `tcp::KeySource`, which `Service` implements over the address book
      `p2p::dht`'s `GetKey` already fills. `fetch_using` completes the book's
      hints through it, so a node handed one endpoint once needs none the second
      time. Deliberately a trait rather than a `WantKey` message: a second
      key-fetch inside `swarm` would double the duplication the fold exists to
      remove, and stating the need instead makes `swarm` a *consumer* of `p2p`,
      which is the direction the fold goes.
- [x] **Decided: at-rest encryption covers the log and stops there.** The
      threat is a copy of the data directory reaching somewhere the operator did
      not intend, and what sealing buys is that the copy is inert. The log is
      sealed because a stolen disk would otherwise yield the node's whole
      operating record in one readable file. The blob store is not, because
      every byte *and every name* in it is something the node hands to any peer
      that asks — a stolen disk yields nothing there the network does not give
      away for free. Same for the `--population` file, and `cache/`/`tmp/` are
      reclaimable by construction.
      The residue is real and is stated rather than waved away: the *set* is not
      the contents, so a disk discloses which objectives a node works on without
      the adversary having to ask a peer and be observed doing it. Filing blobs
      under `HMAC(key, address)` would close it and was rejected on the merits —
      it costs the property that the name *is* the hash, which is what lets a
      read re-hash and refuse mismatched bytes with no second index to keep in
      sync.
      The decision is enforced rather than merely written down:
      [`store::exposure`](../src/store/exposure.rs) classifies every file in a
      store as sealed, plaintext for a stated reason, a key that should not be
      there, or **unaccounted for**, and `store status` reports the last two and
      exits 1. A future feature that writes plaintext state into a data
      directory trips it instead of slipping past.
- [x] **`swarm` moved under `p2p`** (`src/p2p/swarm/`). The DHT was already
      shared, the transport was already shared, and `tcp::KeySource` already made
      blob transfer consume `p2p`'s key distribution rather than grow its own.
      What the move settles is the *graph*: `KeySource` is declared in the blob
      module and implemented by `p2p::service::Service`, so as siblings the two
      each named the other and which way the dependency really ran was something
      a reader had to reconstruct. It runs one way, and the tree says so.
      Nothing was deleted and no behaviour changed — every path is
      `crate::p2p::swarm::…` and `docs/discovery.md` had been claiming
      "library-only, no CLI subcommand drives it" for a while after
      `blob serve | fetch` shipped, which is a doc understating what is built
      rather than the usual failure of overstating it. Both are wrong.
- [ ] One *discovery* stack instead of two. What is genuinely left, and it
      deletes public API rather than moving it: `p2p::swarm::discovery`'s signed
      records overlap `records::PeerRecord` almost exactly (same shape, same
      transport id, same `seq`-supersedes rule), and keeping both means two
      places to change one rule. It is a scope decision rather than an
      engineering one, which is why it is still open — the liability that made
      it urgent, an unencrypted socket, is long gone.
- [x] **Peer identities in the log** (`records::PeerRecord`, `proofwork peer`).
      A fourth record kind binding a permanent ed25519 identity to the transport
      id it answers on, plus an address hint and a `seq` that supersedes — so
      obtaining the log *is* obtaining the address book, and finding the network
      stops being a second bootstrap problem solved by a separate file.
      The two identity schemes are reconciled rather than merged: ed25519 signs
      the record and is the authority, and what it vouches for is the 32-byte
      `sha256` of a McEliece transport key, not the key itself — a McEliece
      public key is 261,120 bytes and does not belong in a structure every node
      replicates. The transport key is fetched on demand and checked against the
      id, which needs no trust because the id is its hash.
      Provider records stay out, as this line always said: who *holds* a blob is
      a statement about right now, and an append-only log cannot say "no longer
      true". A false record costs a dial and never a wrong result — an impostor
      cannot produce a key hashing to a transport id they do not hold, so the
      handshake fails. `Service::seed_from_log` feeds the address book from the
      log at startup.
- [x] **Local multicast** (`p2p::multicast`), and it really was cheap — which
      is the payoff for every hint source being untrusted. A beacon is a peer id
      and a port on an administratively-scoped group at TTL 1, folded into the
      routing table by the same path a peer record takes.
      Three things it deliberately does not do. It carries **no IP address**:
      the address comes from the datagram's source, because an address in the
      body is a claim by the sender and would let one host point a whole segment
      at a third party. It is **announce-only**, so there is no query to spoof
      and therefore no reflector to rate-limit. And it carries **no inventory** —
      `p2p::code` refuses to publish which blobs a node holds, and a beacon
      listing them would undo that to a whole office, unauthenticated.
      Unsigned, because a false beacon names a transport id its sender cannot
      dial for: one wasted dial, never a wrong result.
      No `SO_REUSEADDR`, which costs two nodes on *one host* both hearing
      beacons — a development arrangement, not a deployment — and saves a
      dependency or sixty lines of `sockaddr_in` FFI. A host with no multicast
      route gets an error from `Responder::bind`, logs it, and runs from
      bootstrap addresses as before.
- [x] **NAT traversal, the half that costs nothing** (`p2p::portmap`). NAT-PMP
      (RFC 6886): a 12-byte UDP request to the default gateway asking it to
      forward a port, so a node behind a home router can seed and not only
      fetch. No dependency, no external service, no configuration.
      Chosen over the alternatives on cost. UPnP-IGD does the same job over SOAP
      and XML on HTTP discovered by SSDP — more routers, at the price of an XML
      parser and an HTTP client in a crate that has neither, to speak a protocol
      its own authors replaced. STUN plus hole punching is the only thing that
      works behind a NAT that refuses to map, and it needs a third party: a
      reachable server to reflect an address and a rendezvous peer to coordinate.
      That is **infrastructure this network does not have**, so it stays out
      until something reachable exists to host it — which is the honest
      remaining gap on this line rather than a silent one.
      Nothing here is trusted and it does not need to be. NAT-PMP has no
      authentication at all, so a reported external address is a claim checked by
      use: a peer either completes a McEliece handshake with this node or does
      not. A lie costs one node a wrong idea of its own address and nobody
      dialling — never a wrong result. Unsolicited replies are dropped, because
      the router's own "your address changed" announcement is exactly the shape
      an attacker would forge; renewal on a timer costs one packet and needs no
      announcement. When there is no gateway the node is where it was — able to
      fetch, unable to seed — but now says so instead of wondering why nobody
      dials it.
- [x] **Decided against as written: no `blob` record announcing who holds what.**
      This line contradicted [discovery.md](discovery.md), and the contradiction
      is the answer rather than something to resolve by building. "Who holds
      digest `D`" is a statement about *right now*: holders churn, and an
      append-only log has no way to say "no longer true", so a blob record would
      advertise a dead node forever and get less accurate the longer it ran.
      That is the same argument that keeps provider records out, and it does not
      stop applying because the record is called something else. The useful half
      is already built, in the structure that can express expiry: the DHT's
      provider store (`dht::Providers`), reached through `p2p::dht`.
      What the log *can* carry, because it is permanently true, is a **past
      undertaking**: identity `K` committed to seed digest `D` from time `T`. A
      claim about the past never needs retracting. That is not a discovery
      mechanism — it is an accountability one, and it is worth nothing until
      something pays or slashes against it, so it belongs to the next line
      rather than before it.
- [x] **Pay for availability.** Tit-for-tat covers the download phase and nothing covers
      a node that has finished; a swarm of pure leeches transfers nothing. This
      is the availability service in [node-incentives.md](node-incentives.md).
      This is where the seeding *undertaking* from the line above lands: a
      signed, permanent record of who committed to hold what, which availability
      sampling then challenges against a published checkpoint. Undertaking and
      settlement have to arrive together — a record nothing pays against is
      bookkeeping, and a payment with no record to challenge is unenforceable.
      Both halves are built, in one change because the line says they have to
      be. An `undertaking` is the signed permanent promise; the challenge is a
      pure function of the log —
      `assign(identity, undertaking, beacon(epoch, anchor), height)` — so
      nobody issues it and nobody can decline to; an `availability` record
      answers it with an inclusion path; and an `availability_pool` funds a
      settlement that pays the answers in equal integer shares and names every
      promise that stayed silent. `proofwork availability
      [undertake|answer|fund|settle|status]`. Both implementations audit the
      same log to the same root and refuse the same forged promise, checked by
      `scripts/differential.sh`.

      The pricing was wrong when it first landed and the attacks were run
      against it rather than argued about. Promising *one* entry paid what
      promising the whole log paid, so promising less was strictly dominant; and
      the answer carried only a path, so an answerer needed the entry hashes and
      no payloads at all — 10% of a log reproduced the honest answer byte for
      byte. A promise now covers the log as it stood, the share is weighted by
      the **bond** the promiser locked, and the answer carries the entry.
      Two consensus defects came out of the same review: the sampled index moved
      whenever the log grew, and it read `PROOFWORK_EPOCH_SECONDS`, so the same
      log audited clean or dirty depending on the auditor's environment — six
      times in ten. Both are pinned by injection and by a cross-configuration
      run in `scripts/differential.sh`.

      Identity is now *priced*, and not yet priced at anything. An undertaking
      carries a `bond` backed by units the log says the identity was **paid**;
      unaffordable bonds are refused on admission, filtered out of the list
      settlement divides by, and re-derived by the audit from the prefix below
      the record. The pot follows the bond rather than the head count, so an
      operator splitting a fixed stake across sixteen keys earns exactly what it
      earns holding it under one — measured both ways round in
      `splitting_a_stake_across_many_identities_earns_what_one_identity_earns`,
      where the old rule paid the splitter an 88% premium.

      **Three bounds remain, and the first is the one that matters.**
      `post_objective` takes no deposit, so a balance can be minted: post a
      bounty for any sum against a verifier you chose, answer it yourself,
      stake the proceeds, repeat per key.
      `minting_a_bond_is_free_because_an_objective_needs_no_deposit` does it for
      10^12 units and the log audits clean. Splitting is exactly neutral, which
      is the property a scarce stake needs and is not by itself resistance;
      closing it means debiting a reward from its funder's balance, which needs
      a genesis rule and moves both implementations. Second, the answer proves
      a node **produced** the challenged entry, not that it **stored** it —
      closing that needs proof of replication. Third, the bond is locked but
      never **slashed**: silence is recorded and the units are held, so a
      penalty has something to attach to, but nothing takes them. Stage 2
      finishes all three; **until then an availability pool should not carry
      real money.**
- [x] A V3 statistical verifier with the test statistic and rejection threshold
      registered *with the objective*, before any data exists.
- [x] Epoch-batched commit-reveal, so nobody sees a competitor's artifact while
      they can still act on it and the sequencer cannot reorder for profit.
- [x] A gossip transport. The wire protocol is written: anti-entropy and digest
      reconciliation for candidate populations on the existing McEliece sessions,
      and per-tick random peer sampling. Sampling chooses among the peers the
      address book already knows; **learning** new peers is still bootstrap-file
      only, and uniform sampling is not Sybil resistance. See
      [p2p.md](p2p.md#still-open).

### Added in the launch pass

- [x] **A remote surface** (`src/serve.rs`, `proofwork-serve`). `GET /log`
      returns the log byte for byte, with `/objectives`, `/objective/{id}`,
      `/frontier/{id}`, `/checkpoint` and `/health` as conveniences over it.
      This is what makes "anyone can re-derive every settled result from the
      log" reachable by somebody who is not the operator, and it was the item
      standing between Stage 0 and anyone outside using it. See
      [serving.md](serving.md).
- [x] **A submission queue** (`POST /submit`, `proofwork drain`). Records
      arriving over the network are spooled, not appended: a Ledger has one
      writer, and admission is decided against the whole log by the rules
      engine rather than in a request handler. This is the honest version of
      "Objective discovery API and a work queue" below, minus the identity
      half.
- [x] **One writer per log, enforced** (`Ledger::open_exclusive`). The type
      always said it; an advisory lock now means a second *process* cannot
      quietly fork the log either.
- [x] **A published log** (`launch/`), with the signed checkpoint and the key,
      built by `scripts/make-launch-log.sh`. `proofwork checkpoint` signs one
      from the CLI, which previously only the p2p daemon could do.
- [x] **Objective-declared artifact shape** (`artifact_schema`). Documentation
      rather than a rule -- the pinned verifier stays the only authority -- so
      an agent has a source for the shape that is not the attacker-authored
      statement.
- [x] **Typed claim relations and a derived knowledge view**
      (`Claim::relations`, `src/knowledge.rs`, `proofwork knowledge`). A
      verified artifact is not the end of a claim's life: it gets replicated,
      superseded, narrowed, retracted. The log now records those assertions as
      typed edges and anyone derives `Standing` and a confidence number from
      them under a policy **the reader chooses**, not one the network agrees on.
      Relations carry no money -- attribution, settlement and the frontier all
      read `cites` and none of them reads this -- which is what stops "I refute
      you" from being a way to bill somebody. The field is omitted when empty,
      so it moved no ids and the frozen vectors still pass. What it does *not*
      do is priced honestly in [knowledge.md](knowledge.md): it does not decide
      truth, does not pay for refutations, does not resolve a contest between
      two verified claims, and does not yet carry scope.

## Stage 1 — bounty market, real contributors

Escrowed rewards, an identity layer for submitters, and a proposer harness so
agents can pull open objectives and submit against them unattended. Still one
sequencer, still signed receipts, still no chain.

This is the stage that answers the only question that matters: **will strangers
point compute at these objectives.** If demand is zero, stop here — everything
downstream is unbacked.

- [x] Agent proposer loop. `proofwork propose <objective> --artifact F
      [--artifact G ...]` runs the pinned verifier locally on each candidate,
      reports what each scored, and submits only the best one that already
      passes — and on a ratchet, only one that actually beats the frontier,
      since a claim that verifies without improving mints nothing and still
      costs the network a verification. `--dry-run` is the same loop with the
      submission removed, which is what an agent iterating actually wants; it
      needs no identity, because scoring writes nothing. Exit code 2 when
      nothing passed, so a script can tell "not ready yet" from a crash.
- [x] Objective discovery API and a work queue. `proofwork-serve` publishes
      the log and the open objectives; `POST /submit` queues proposals that
      `proofwork drain` admits through the same rules engine. See
      [serving.md](serving.md).
- [~] Rate limiting and submission bonds against spam. The queue is bounded
      (`--max-queue`, 429 past it), body size, request time and concurrency are
      capped, and the spool de-duplicates by content -- so disk exhaustion is
      closed. Bonds are not built, so an attacker still costs the operator
      drains, and nothing distinguishes many honest submitters from one
      adversary.
- [ ] Sensitive-objective classes and an embargo path, **before** anything is
      published. This cannot be retrofitted.
- [ ] **Agent as funder** — bind `funder` to a submitter identity, prepay escrow
      from a settled balance, and size the posting bond against the verification
      the objective will cost. This is the whole of agent-to-agent payment: a
      trade expressed as an objective reuses escrow, settlement, audit and
      citation flow, and needs no transfer primitive. See
      [agent-market.md](agent-market.md).
- [x] **Reserved citation share**, and a discretionary split weighted by settled
      reward. The discretionary half was already shipped — δ splits among all
      transitive ancestors by settled reward, which is slicing-invariant and
      identity-blind. The reserve is the half that survives *manufactured*
      ancestors, which agent funding makes cheap: `FlowParams::with_reserved`
      holds a fraction of δ for the citation the protocol forced, and
      `Node::enforced_citations` re-derives which that was by reading the
      frontier as it stood below each claim's own entry — no new record, so no
      conformance vector moves. Measured both ways: with nothing reserved, 200
      manufactured ancestors leave the frontier holder **498 units of the
      100,000** she was owed; with half of δ reserved the floor is 50,000 at
      any fanout. Default zero, because a reserve moves settled money and
      `agent-market.md`'s question 3 — the smallest reserve that makes dilution
      unprofitable — is a question for the harness, not a constant to guess.
- [ ] Surface the **decomposition floor** at post time. A sub-objective the
      network verifies for more than it settles is subsidized by everything else;
      the break-even is a function of the objective's verifier tier and is
      computable before anything is funded.

- [x] **An adversarial arena** (`src/arena/`, [arena.md](arena.md)): attack
      strategies played *for money* against the real rules engine, with the
      payoff read out of settled balances. Partly discharges the largest
      antecedent in [proving-it.md](proving-it.md) -- that `src/incentive/` is a
      model rather than a code path.
      Every attack runs twice, with its defence and without, because a lone
      number has no scale. Six verdicts rather than a bool: CLOSED, NEUTRAL
      (the attacker earns no more than an honest player with the same
      resources -- stronger than unprofitable), REFUSED (no admissible form at
      all), PROTECTED (the victim is better off), OPEN, and INERT.
      INERT is the one that keeps it honest: three of the first five scenarios
      returned it, which correctly said *the scenario failed to set itself up*
      rather than *the defence works*.
      At seed 1: sybil splitting NEUTRAL (5,952 across eight keys against 5,994
      for one, where a head count would have paid 10,608); availability
      free-riding NEUTRAL (0 against 11,994); cheap-tier standing CLOSED (5,000
      untyped, 0 spendable where it was wanted); bonded griefing PROTECTED (the
      griefer forfeits 6,000 and its target ends 9,000 up instead of 3,000);
      griefing a plain objective REFUSED. Rubber-stamping was **OPEN** and pinned
      deliberately -- a docket named the stamper and took nothing, because
      nothing was staked on verification -- until bonded attestations landed;
      it now reports CLOSED at 8,000 undefended against -92,000 defended, the
      swing exactly two verification bonds. **No attack in the set is
      profitable against its defence.**
      It found a real defect on its first run against a griefer that opened
      objections and prosecuted none: at the start of a dispute both sides owe
      their endpoints, so nobody was ever overdue and a challenge nobody played
      stayed open forever with the bond locked. The burden of prosecution is now
      the challenger's.

## Stage 2 — permissionless verification

- [ ] Contributed inference verified with a TOPLOC-class scheme, for the
      objectives where effort must be bought rather than output.
- [x] **Bonded challenge windows and interactive fraud proofs over the replay
      trace** (`src/challenge.rs`, `records::Challenge`, `Node::settle_challenge`,
      `proofwork dispute`, [fraud-proofs.md](fraud-proofs.md)).
      Both parties commit to a Merkle root over the whole trace, then narrow
      their disagreement by binary search until it is one step wide, and one
      step of execution decides it. Every move opens a state against the
      *mover's own* committed root, so the losing side cannot answer with
      whatever state wins the current round -- which is the attack that would
      make the whole thing worthless.
      Measured on 256 states with the shipped Collatz stepper: 8 rounds of
      search in 7.7ms, one step of adjudication in 31ms, full replay in 8.10s.
      258x, and the ratio grows linearly with trace length because adjudication
      is flat. A million states is 20 rounds; the 2^24 cap is 24 rounds, 48
      records.
      What makes an objective bisectable is a **stepper** -- a pinned entrypoint
      from a state to the next one, since a command has an input and an output
      and nothing in between two parties can point at. So bisectability is a
      property an objective has or does not, and Collatz is the honest example
      rather than a flattering one: `n -> n/2 or 3n+1` is already a step
      function. `examples/collatz_bisectable/` pins one.
      Two preconditions were found by tests failing rather than by review, and
      both are now witnessed by the four moves a dispute opens with: a lie in
      the *first* step left the interval's lower bound at a state nobody had
      opened, so there was nothing to run; and two traces that diverge and
      rejoin end on the same state, so the search terminated on an interval
      whose endpoints both agree. The second is refused outright -- a challenger
      who reaches the same answer by another route has contradicted nothing.
      The money is wired: a challenger stakes a bond, which is committed the
      moment the objection is, so one balance cannot fund two simultaneous
      objections; the loser pays the winner; the audit re-derives every rule;
      and `reference/rust` accounts for both sides of a slash, because a second
      implementation that did not would report the winner as overdrawn and
      certify the loser as solvent. `scripts/dispute-demo.sh` runs it through
      the CLI and hands the finished log to the reference, which names an
      inadmissible challenge independently.
      What the two sides risk is asymmetric and stated rather than hidden: a
      challenger stakes a bond, a defender stakes the disputed claim's payout
      *capped at what they still hold*, so a defender who spends the reward
      before the window shuts keeps the difference. Closing that means holding a
      bisectable claim's payout until its window closes -- a settlement-path
      change in both implementations, and the same missing piece as bonded
      availability custody.
- [x] **Node-operator incentives designed and evaluated** (`src/incentive/`).
      Canaried bonded verification, availability sampling, and bonded share
      custody, with a harness that solves for the minimum canary rate, bond and
      committee shape. See [node-incentives.md](node-incentives.md).
- [x] **Canary objectives with known-verdict artifacts** (`src/canary.rs`,
      `proofwork canary mint|check`), so checking is the profitable strategy
      rather than the altruistic one. The generator never authors an artifact:
      it takes one a real contributor submitted and applies a single edit from a
      catalogue where every edit preserves the shape *and* the canonical byte
      length, so a canary and its parent agree on key paths, types, array
      lengths, integer widths, string character-class profiles and total size.
      Separating them requires running the verifier, which is the work being
      bought. The label is earned rather than asserted -- the generator runs the
      objective's own pinned verifier and keeps the mutant only if the verdict
      landed where asked -- so it works on every tier and knows nothing about
      cap sets or Collatz. A verifier that returns `unavailable` mints nothing,
      because a canary made against a broken toolchain accuses honest nodes.
      Both sides are minted, since only a known-*good* canary catches blind
      rejection.
      Measured: 1 verifier run for a bad collatz canary, 7 for a bad capset one,
      1 for a good capset one -- and a good *collatz* canary is not mintable at
      all, because when the whole artifact is one integer every edit to it is a
      different answer. Known-good canaries are cheap exactly when an artifact
      holds an unordered collection. Checking is free: 1.2 us for a docket
      against 16 verdicts, against 547 ms for the re-verifying audit that
      reaches the same conclusion, and the gap widens with the log.
      The money is now built too, in the entry below.
      Also fixed on the way past: `audit --no-rerun` printed "log verified:
      chain intact, every settled claim re-verified" over a log where no
      verifier had run, which was a false statement by the tool on exactly the
      path a rubber-stamper survives.
- [x] **Bonded verification: a signed statement of what a verifier returned,
      slashable on a canary catch** (`records::Attestation`,
      `Node::post_attestation`, `Node::slash_attestation`,
      `Docket::contradicted`, `pw attest`, `scripts/attestation-demo.sh`).
      The half the canary generator was missing. A docket always knew *which*
      verdicts were wrong for the price of a map lookup; it could not name a
      *party*, because a Stage-0 log has one writer and no record said who ran
      the checker. An attestation is that record: one identity, one claim, one
      status, signed, with 50,000 units behind it -- the reference network's
      catch bounty, since the catcher is paid the bond.
      Nothing at admission checks whether it is true, deliberately: asking would
      put the verification cost back exactly where the mechanism took it out of.
      The expensive question is asked once, by somebody who already has
      evidence, and a verifier that cannot run slashes nothing.
      The bond **returns** when its window shuts, and the first draft did not:
      a permanent lock would fix the network's whole verification capacity at
      `supply / bond` forever, which is a capital sink rather than a service
      market. The window closes on the highest epoch any `batch` record names --
      not on an entry's `ts`, which its own author writes, and not on log
      height, which anybody can advance for the price of an append.
      Both implementations re-derive every *slash* on the cheap audit path;
      whether an unslashed attestation is true is asked only under `--rerun`,
      which is the cost the bond exists so that nobody pays routinely. Two
      injection tests pin that split.
      The arena's rubber-stamping trial moved from OPEN to CLOSED, and on the
      way found that its own pinned checker turned on a *boolean* -- which the
      generator's shape-preserving edits cannot flip -- so the trial had been
      running against a docket with zero known-bad canaries. `Docket::mix`
      existed and said so; nothing was asking it.
- [ ] Availability sampling: Merkle challenges against a published checkpoint
      root, which is the cheap half of node incentives and needs the signed
      checkpoints in Stage 0 first.
- [x] **Bonded share custody, with the committee sized against the sealed value**
      rather than fixed (`Node::committee_size_at`, `Node::custody_guard`,
      `partition::threshold_for`). The *mechanism* now exists and runs
      (`records::CommitteeShare`, `Node::committee_for`, `Node::open_sealed`):
      seats are drawn per epoch from the log's peer records, a share published
      before the commitment's epoch closes is refused, and non-publication is
      attributable because the draw names every seat.
      The fixed `COMMITTEE_SIZE` is now a **floor**. Above it the committee
      grows while `V > t · d · S'` — the condition under which opening early
      pays, which [node-incentives.md](node-incentives.md) derives and says in
      bold the committee must grow to satisfy. Stake is a member's ordinary
      spendable balance, and a cartel is priced at the sum of its **cheapest**
      `t` members rather than `t` times an average: with one rich member and
      four poor ones the average reports a committee as safe that is not, and
      the cartel that actually forms is the cheap one.
      Measured against 1000-unit stakes at a detection rate of a half — 5 seats
      guard 1500, 6 guard 2000, 8 guard 2500, 12 guard 3500 — so a 2200-unit
      bounty draws 8 seats and not 5. A strict-majority threshold means an odd
      committee guards exactly what the even one below it does, so the rule
      always lands on an even size; a seventh seat buys liveness, not collusion
      resistance.
      The size comes from the epoch's **boundary prefix**, fixed before the
      epoch's first record exists, because a submitter seals at commit time and
      the committee opens an epoch later — a shape that moved in between would
      leave a correctly sealed submission unopenable, at the expense of the one
      party who sealed because they might not be able to come back. Both
      implementations derive it, since a crate still drawing five while the
      other drew eight would accuse an honest member of publishing from a seat
      that does not exist.
      A submission whose value outruns its already-fixed committee is **refused
      at seal time**, when the submitter can still wait for a later epoch or
      split the bounty, rather than handed a receipt for protection the
      arithmetic says they did not get. Only on a log that declares a supply: a
      log that has not claimed its units are scarce has not claimed this either.
      What is still missing is a *dedicated* custody bond. The stake measured is
      a member's whole balance, so it is not reserved against this duty and can
      be spent elsewhere between the draw and the reveal.
- [x] **Claim assets typed by verification tier, non-fungible across tiers**
      (`src/tier.rs`, [tiers.md](tiers.md)). A unit minted by settling a claim
      carries the tier of the objective's verifier and cannot be spent in
      another. Five kinds, five tiers, **no ordering and no exchange rate** -- a
      conversion however priced is a route by which the cheapest tier ends up
      valuing every other one, which is the thing being prevented.
      The attack it closes: run a cheap certificate mill, then spend the
      proceeds where expensive work is priced. Every bond here is drawn from a
      balance -- an availability undertaking, a dispute challenge, and the stake
      a committee is now *sized against* -- and until this landed a balance had
      no provenance. Sizing the committee against members' stakes made the
      attack more valuable rather than less.
      The tier is derived from the objective record rather than stored beside
      it: a stored field is a second place it could be wrong, and a settlement
      claiming a tier its verifier does not have is exactly the forgery. There
      is nothing to forge when the tier *is* the verifier.
      Genesis issuance stays **universal** and spends anywhere, which is a
      necessity rather than an exemption: a network whose founding supply were
      typed could never fund its first Lean objective, because the units to fund
      it could only come from settling a Lean objective nobody could fund.
      A commitment draws from its own tier first and the reserve after, so the
      reserve is shared and a per-tier balance cannot be independent columns:
      promising it to one tier has to move every other tier's column, or the
      same hundred units get offered five times. `tier::Ledger` is that
      arithmetic and `solvent()` is the per-identity statement.
      The whole-balance conservation check does not catch this -- an identity
      can hold exactly what it promised *in total* while having promised Lean
      units it earned on certificates. That log balances and is still a forgery,
      so `audit_tiers` walks it per tier in **both** crates.
      Not typed yet, and named rather than left to be discovered: service bonds
      are charged in universal, so a contributor with a large Lean balance
      cannot back a committee seat with it either. Closing that means deciding
      which tier a committee seat is denominated in, which is a question about
      what custody is rather than about arithmetic.
- [x] The **agent market sub-game** (`src/incentive/market.rs`,
      `proofwork incentives --market`). The gate on the rest of
      [agent-market.md](agent-market.md), and it has an answer.
      Four actions -- gossip, sell, hoard, publish -- scored on one option value
      and differing in how many **rivals** each creates: a hoarder none, a seller
      one and only if a buyer turns up, a gossiper or publisher the whole
      population. Without that term the model is incoherent rather than rough,
      because a sale is a *copy* and selling would dominate hoarding everywhere.
      **The commons survives.** Universal gossip is a strict equilibrium: a
      seller in a sharing population is selling what everybody already has, so
      the price collapses and only the forgone reciprocity is left. One seller is
      absorbed and the population heals from sixteen.
      **And universal selling is a strict equilibrium too**, so the market is
      bistable in exactly the way verification is without canaries. The finding
      nobody had guessed is that the barriers are asymmetric *and that the one
      knob a protocol has decides which way they lean*: how much of the gossip
      stream a transport can withhold from a taker. At a hundredth, 28 sellers
      break a 200-agent commons and 174 gossipers are needed to recover it; at a
      fifth the same measurement reverses to 151 against 51. The crossover is
      near a twentieth.
      So there are two numbers and quoting one for the other is a mistake.
      **7 parts in a thousand** makes gossip an equilibrium at all; **about a
      twentieth** makes it the one a network falls back into.
      Also worth the reporting discipline it forced: at twenty agents with a
      leaky commons the cheapest deviation from universal gossip is a single
      **hoarder**, not a seller. `MarketReport` carries the action rather than a
      count, because filtering for sellers would have called that "selling never
      profits".
      Splitting across identities buys exactly zero, because nothing keys on
      trade volume -- measured so that adding such a payment later fails a test
      rather than a network.
- [ ] Offers on the gossip transport, trades in the log — and purchased goods
      cited at submission, enforced the way the frontier citation already is.
- [x] A real randomness beacon. `src/vdf.rs` is a Wesolowski verifiable delay
      function over the RSA-2048 challenge modulus — a **nothing-up-my-sleeve**
      parameter, because a VDF over a modulus somebody knows the factorisation
      of is not a delay at all: the holder of `phi(N)` reduces the exponent and
      answers instantly.

      `proofwork beacon --orders E --delay T` computes `x^(2^T) mod N` over a
      seed derived from the log's own Merkle root, and records the answer with
      its proof. Grinding the anchor used to cost a hash per candidate ordering;
      it now costs `T` sequential squarings per candidate, and they cannot be
      parallelised. Better than the chain beacon in one further respect: a chain
      beacon is *provenance* — "this is what block N held" — and checking it
      needs an RPC endpoint, while a delay proof is checked against the log
      alone, which is the one guarantee this project spends everything else to
      keep.

      Verification is constant in `T`: two exponentiations by a 127-bit
      Fiat–Shamir prime, about 5ms whatever the difficulty, against 741ms to
      *produce* a beacon at T = 100,000. The first version of `verify` computed
      `2^T mod l` by doubling `T` times and so cost the same order as proving,
      which is the one thing a verifiable *delay* function must not do;
      `verifying_costs_the_same_at_any_difficulty` pins it.

      Underneath is `src/crypto/bignum.rs` — the crate's only arbitrary-precision
      arithmetic, Montgomery form, every operation pinned against vectors from
      Python's integers so a carry bug cannot agree with the test that checks
      it.

      What it does not do: bound *withholding*. A sequencer that dislikes the
      beacon it computed can still publish none, and the epoch settles under the
      documented fallback with `epochs_without_beacon` naming it —
      `PROOFWORK_REQUIRE_BEACON` makes that refusable rather than invisible.
      Refusing to settle instead would strand every claim in the epoch, which
      hands a censor a better weapon than the one being taken away.
- [ ] Forced inclusion via a base layer. Censorship is the primary threat --
      withholding a reveal steals a bounty -- and Stage 0 has no defence.

## Stage 3 — decentralized settlement

Not an L1. A rollup on an established chain: the bootstrap circularity (stake
value <- settled research <- chain) has no starting point, and the state
transition is already the pure function in `node.py` with `audit()` as the
re-derivation a fraud proof needs. See docs/consensus.md.

- [ ] Anchor commitments and settlement roots to a base layer.
- [ ] Staked judgement layer for V4 questions, with disputes and slashing —
      labeled as governance, never as verification.
- [ ] Retroactive prize pools.

Nothing above Stage 1 is worth building until Stage 1 has produced a result
somebody wanted.

## Non-goals

- Becoming a general compute marketplace. This buys artifacts, not hours.
- Verifying judgement. It cannot be done and the design says so.
- Distributed pretraining. Interconnect-bound and not self-verifying — a
  different system with a different threat model.
