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

Remaining before Stage 0 is usable by anyone but its author:

- [ ] **Sandbox verifier execution** (container/WASM, no network, wall-clock cap).
      Launch blocker for third-party objectives.
- [x] **Local store: encryption at rest, a chosen data directory, and a size
      cap** (`src/store/`). The log is sealed line-wise so appends stay appends,
      the key defaults to outside the data directory, `sync` mirrors ciphertext
      without ever carrying the key, and the cap refuses rather than pruning a
      hash-linked log. See [storage.md](storage.md).
- [ ] Key rotation: re-key an existing store without a manual decrypt and
      re-seal. Cheap to add, and not yet needed by anyone.
- [ ] Signed checkpoints: publish `(merkle_root, height, signature)` so a reader
      can pin what the operator claimed at a point in time and detect a rewrite.
- [ ] `proofwork verify --from <checkpoint>` for readers who only have a log
      fragment.
- [ ] Objective schemas in `spec/` wired into `post` as a hard validation gate —
      on **admission only**. A schema that can reject a record already in the log
      rewrites history on a version bump. Plus `validate_spec` on the verifier
      registry, so a verifier block missing `evaluator_sha256` is refused at post
      time instead of becoming a funded bounty nobody can win. See
      [knowledge-store.md](knowledge-store.md).
- [x] **A content-addressed blob store** (`src/store/blobs.rs`). Pinned verifier
      code used to live outside the log, addressed by a relative path against a
      local `--root`, so "anyone can re-derive every result from nothing but a
      copy of the log" needed a copy of the verifier tree too. `evaluator_sha256`
      was already a content address; now it is also a *name*. Resolution is by
      hash before path, `proofwork blob put | ls | verify` manages the store, and
      the quota pins what the log needs so `gc` cannot evict an evaluator the node
      must still be able to run. Changed no id and no conformance vector.
- [x] **Peer-to-peer blob transfer** (`src/swarm/`), in the BitTorrent shape:
      pieces, a manifest of piece hashes, bitfields, rarest-first, bounded
      pipelining, tit-for-tat choking, endgame with cancels, and a TCP driver.
      `blob serve` and `blob fetch`. The objective's digest *is* the swarm id, so
      the ledger does the tracker's job and there is nothing to sign.
- [x] **Peer discovery** (`src/swarm/discovery.rs`). Signed peer records in the
      ENR shape -- identity is an ed25519 key, location is a hint signed by it,
      `seq` supersedes -- plus peer exchange, so one address given once
      accumulates the rest. Every hint source is equal because none is trusted,
      which is what makes DNS optional rather than load-bearing. See
      [discovery.md](discovery.md).
- [x] **A Kademlia DHT** (`src/swarm/dht.rs`) for the question a fetch actually
      asks -- who holds digest `D` right now. Peer exchange answers which peers
      exist; without provider lookup a fetch floods everyone it knows. XOR
      metric, k-buckets with oldest-live-wins, provider store with expiry, and
      the iterative lookup as a pure state machine. Safe to get wrong here in a
      way it is not elsewhere: every answer is a hint and the digest decides, so
      eclipse costs liveness and never correctness.
- [ ] The multi-hop lookup driver. `Lookup` is built and tested; nothing yet
      feeds it across connections, so lookups are one hop rather than `O(log n)`.
      Plus bucket refresh, provider republication, and announcing to the `k`
      nodes nearest a key rather than to whoever is on the line.
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
- [ ] A V3 statistical verifier with the test statistic and rejection threshold
      registered *with the objective*, before any data exists.
- [ ] Epoch-batched commit-reveal, so nobody sees a competitor's artifact while
      they can still act on it and the sequencer cannot reorder for profit.
- [ ] A gossip transport for the *candidate population*. `gossip.py` is the merge
      law and the data structure; the wire protocol (peer sampling, anti-entropy,
      digest reconciliation) is not written. `src/swarm/` moves blobs, which is a
      different problem with a different shape — one known digest, many peers —
      and does not subsume this.

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
- [ ] Objective discovery API and a work queue.
- [ ] Rate limiting and submission bonds against spam.
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
      vectors and the Python reference with it.
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
