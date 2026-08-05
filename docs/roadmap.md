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
- [x] **Piece-level blob transfer** (`src/swarm/`), in the BitTorrent shape:
      pieces, a manifest of piece hashes, bitfields, rarest-first, bounded
      pipelining, tit-for-tat choking, endgame with cancels, and a TCP driver.
      Library-only, and the driver sits behind the off-by-default
      `insecure-swarm-tcp` feature because it has no handshake and no AEAD.
      It reads and writes the same `src/blobs.rs` store `p2p::code` uses, and
      overlaps it: `p2p` already moves pinned code whole, which is adequate
      while `blobs::MAX_BLOB_BYTES` is 1 MiB — four pieces. The piece machinery
      is sized for artifacts that cap does not yet allow, so it is groundwork
      rather than a current need. The objective's digest *is* the swarm id, so
      the ledger does the tracker's job and there is nothing to sign.
- [x] **Signed peer records** (`src/swarm/discovery.rs`) in the ENR shape --
      identity is an ed25519 key, location is a hint signed by it, `seq`
      supersedes -- plus peer exchange, so one address given once accumulates the
      rest. This is the answer to "learning new peers is bootstrap-file only" in
      the gossip entry above, and it is not yet wired into `p2p`'s address book.
      Every hint source is equal because none is trusted, which is what makes DNS
      optional rather than load-bearing. See [discovery.md](discovery.md).
- [x] **A Kademlia DHT** (`src/swarm/dht.rs`) for the question a fetch actually
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
      `swarm::dht` and `p2p::dht` are instantiations. Written twice they would
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
- [ ] Encrypt `swarm`'s transport, which today means folding it onto `p2p`'s
      identity. `swarm::tcp` has no handshake and no AEAD; it is behind the
      off-by-default `insecure-swarm-tcp` feature so it cannot ship by accident,
      which contains the risk without removing it.
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
- [ ] Fold the rest of `src/swarm/` into `src/p2p/`. The DHT is shared now; the
      signed peer records and the piece machinery are not. `swarm::discovery` is
      exactly the peer-list exchange `p2p` is missing, against a different
      identity scheme, and the McEliece transport is what `swarm::tcp` lacks.
      Reviewed again in the launch pass and deliberately **not** attempted
      then: the two identity schemes (ed25519 for `swarm` peer records, a
      261,120-byte McEliece key for the encrypted transport) have to be
      reconciled before the merge means anything, and a rushed version would
      trade a contained duplication for an uncontained one. The containment
      -- `insecure-swarm-tcp` off by default, so the unencrypted socket cannot
      reach a binary by accident -- is what makes deferring it safe.
- [ ] Peer identities in the log, so *identity* discovery stops being a separate
      bootstrap problem from obtaining the log. Identity is permanent and belongs
      there; provider records are not and must not.
- [ ] Local multicast as a second hint source: genuinely zero-configuration on a
      LAN, and cheap now that every source is interchangeable.
- [ ] NAT traversal. Not discovery, and routinely confused with it -- knowing an
      address does not mean you can reach it. Until then a node behind a home
      router can fetch and cannot seed, which makes the network more centralised
      than the protocol suggests.
- [ ] A `blob` record kind announcing who holds what, which is the useful half —
      that a blob exists is already implied by the objective.
- [ ] Pay for seeding. Tit-for-tat covers the download phase and nothing covers
      a node that has finished; a swarm of pure leeches transfers nothing. This
      is the availability service in [node-incentives.md](node-incentives.md).
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

## Stage 1 — bounty market, real contributors

Escrowed rewards, an identity layer for submitters, and a proposer harness so
agents can pull open objectives and submit against them unattended. Still one
sequencer, still signed receipts, still no chain.

This is the stage that answers the only question that matters: **will strangers
point compute at these objectives.** If demand is zero, stop here — everything
downstream is unbacked.

- [ ] Agent proposer loop (propose → self-check against the pinned verifier →
      submit only what already passes locally). Free verification means the
      proposer can filter before it spends the network's time.
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
- [ ] **Reserved citation share**, and a discretionary split weighted by settled
      reward. Citation flow divides δ evenly, which is safe only while citable
      claims are scarce; agent funding makes them free to manufacture, and five
      citations recover four fifths of what the ratchet promised the frontier
      holder. A change to how settled money splits, so it lands *before* the
      first agent-funded objective, not after — and it moves the conformance
      vectors and the reference implementation with it.
- [ ] Surface the **decomposition floor** at post time. A sub-objective the
      network verifies for more than it settles is subsidized by everything else;
      the break-even is a function of the objective's verifier tier and is
      computable before anything is funded.

## Stage 2 — permissionless verification

- [ ] Contributed inference verified with a TOPLOC-class scheme, for the
      objectives where effort must be bought rather than output.
- [ ] Bonded challenge windows and interactive fraud proofs over the replay
      trace (the manifest already pins command, seed, and environment, which is
      what makes a trace bisectable).
- [x] **Node-operator incentives designed and evaluated** (`src/incentive/`).
      Canaried bonded verification, availability sampling, and bonded share
      custody, with a harness that solves for the minimum canary rate, bond and
      committee shape. See [node-incentives.md](node-incentives.md).
- [ ] Canary objectives with known-invalid artifacts, so checking is the
      profitable strategy rather than the altruistic one. The mechanism and its
      parameters exist; the generator, which must produce canaries a node cannot
      tell from real submissions, does not. That indistinguishability is the
      whole assumption -- at `canary_leak = 1` the harness reports that no
      canary rate works at all.
- [ ] Availability sampling: Merkle challenges against a published checkpoint
      root, which is the cheap half of node incentives and needs the signed
      checkpoints in Stage 0 first.
- [ ] Bonded share custody, with the committee sized against the largest sealed
      bounty rather than fixed.
- [ ] Claim assets typed by verification tier, non-fungible across tiers.
- [ ] The **agent market sub-game** in `src/incentive/`, and only build the market
      if it survives: candidates circulate through gossip because nothing prices
      them, so pricing them may starve the population the island model runs on.
      That is a payoff question, and the answer decides whether the rest of
      [agent-market.md](agent-market.md) is worth building.
- [ ] Offers on the gossip transport, trades in the log — and purchased goods
      cited at submission, enforced the way the frontier citation already is.
- [ ] A real randomness beacon (VDF or threshold signature) replacing the
      ledger-head derivation in `partition.py`, which a sequencer can grind.
      This got more load-bearing when epoch-batched settlement started ordering
      a batch by that beacon: grinding the anchor now moves money, not just
      work assignment.
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
