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
- [ ] Key rotation: re-key an existing store without a manual decrypt and
      re-seal. Cheap to add, and not yet needed by anyone.
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
