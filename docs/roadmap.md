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
- [ ] **A content-addressed blob store.** Pinned verifier code lives outside the
      log, referenced by a relative path against a local `--root`, so "anyone can
      re-derive every result from nothing but a copy of the log" currently needs
      a copy of the verifier tree too. `evaluator_sha256` is already a content
      address; what is missing is a `blob` record kind, `cache/blobs/<sha256>`,
      and resolution by hash before path. Changes no id and no conformance vector.
- [ ] A pin set in the quota, so `store gc` cannot evict the evaluator of an
      objective the node must still be able to verify.
- [ ] A V3 statistical verifier with the test statistic and rejection threshold
      registered *with the objective*, before any data exists.
- [ ] Epoch-batched commit-reveal, so nobody sees a competitor's artifact while
      they can still act on it and the sequencer cannot reorder for profit.
- [ ] A gossip transport. `gossip.py` is the merge law and the data structure;
      the wire protocol (peer sampling, anti-entropy, digest reconciliation) is
      not written.

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
