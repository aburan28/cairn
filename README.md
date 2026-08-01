# distributed-researcher

**A research network where verified results are the unit of account.**

Anyone contributes compute toward shared objectives, AI agents do the work, and
payment is settled by a checker that anyone can re-run. No trust in the operator,
no trust in the contributor, no trust in the model that produced the answer.

This repository contains **proofwork**, the protocol implementation: a Rust
library and CLI, a Python reference implementation, and the conformance vectors
that bind them to the same answers.

Stage 0 — one operator, no token, no consensus. What it does provide is the
property that actually matters: *anyone can independently re-derive every result
the network has settled*, from nothing but a copy of the log.

```
$ ./scripts/interop.sh

== Python audits the Rust log
log verified: chain intact, every settled claim re-verified

== Rust audits the Python log
log verified: chain intact, every settled claim re-verified

== Merkle roots agree across implementations
  sha256:f0398c1ae67875b4ecc3c9c0d674f7b44b6876b77445a40e1d8ce7f6b331a168  (identical in both)

INTEROP OK: each implementation verifies the other.
```

That is the claim made concrete. "Anyone can re-derive every result" is worth
nothing if it means "anyone running my code"; two implementations written
separately in different languages, agreeing on every id and every Merkle root, is
what makes it real.

## The one idea

> **Pay for verified outputs. Never pay for claimed effort.**

Almost every hard problem in decentralized compute — did the node really run the
job, did it use the right model, did it burn the FLOPs it billed — exists only
because the network is trying to buy *work*. Buy *artifacts* instead and most of
it dissolves. Nobody can fake a Lean proof the kernel rejects, a counterexample
that fails recomputation, or a program that scores badly on a fixed evaluator.
The check *is* the payment condition, so a contributor's hardware, honesty, and
diligence stop being things anyone has to verify.

The corollary is the whole engineering constraint: **the network can only work on
tasks whose outputs are cheap to check.** That is a specification for what to
build, not a limitation to route around.

## Quick start

```sh
cargo build --release
cargo test                    # 876 tests, no network required
./scripts/demo.sh             # objectives, commit-reveal, audit, attribution
./scripts/ratchet-demo.sh     # progressive bounty: publishing beats hoarding
./scripts/interop.sh          # each implementation audits the other's log
./scripts/mcp-smoke.sh        # the MCP server, driven as a real process
proofwork incentives          # evaluate the node-operator game
proofwork incentives --robustness   # ...and how far each parameter can move before it breaks
```

### Start a p2p node

The easiest local launch is:

```sh
make p2p
```

On first run this creates `.local/node.identity.json`, `.local/root.key`, and
`.local/checkpoint.json`. The first two contain private key material; keep
`.local/` out of version control. The node listens on `127.0.0.1:9000` by
default, accepts inbound peers, periodically dials configured bootstrap files,
and re-derives received records locally.

To connect to a peer, provide a bootstrap file containing its address and
McEliece public key:

```json
{"addr":"127.0.0.1:9001","public":"<peer public-key hex>"}
```

Then launch with:

```sh
make p2p LISTEN=127.0.0.1:9000 BOOTSTRAP_ARGS='--bootstrap peer.json'
```

Use separate `LOCAL_DIR`, `LOG`, `IDENTITY`, `ROOT_KEY`, and `CHECKPOINT`
paths for each node. The root checkpoint key is ML-DSA-65 and is separate from
the transport identity.

Rust 1.85+ (verified in CI, not asserted). No network access needed at runtime.

## How it works

An **objective** is a funded question that comes with a runnable verifier, pinned
by hash:

```json
{
  "goal": "GOAL-capset-lower-bounds",
  "statement": "Exhibit a cap set in F_3^4 of size at least 20.",
  "verifier": {
    "kind": "evaluator",
    "evaluator": "examples/capset/evaluators/cap_set.py",
    "evaluator_sha256": "8f14e4...",
    "entrypoint": "score",
    "threshold": 20,
    "direction": "maximize"
  },
  "reward": 250000,
  "funder": "treasury",
  "created_at": "2026-07-28T00:00:00+00:00"
}
```

An objective's id **is** the hash of that whole record, verifier included. There
is no operation that changes the rules of a funded bounty — editing the evaluator
produces a different objective and the claims against the original stop
resolving. Mid-bounty rule changes aren't guarded against; they're
unrepresentable.

```sh
proofwork post   examples/capset/objective.json
proofwork commit <objective-id> --submitter bob --artifact solution.json --nonce s3cret
proofwork reveal <objective-id> --submitter bob --artifact solution.json --nonce s3cret
proofwork audit
proofwork attribute
```

### Four verifiers, four trust assumptions

| kind | checks | cost | trusts |
|---|---|---|---|
| `certificate` | recomputes an NP witness | ms | nothing |
| `evaluator` | scores a candidate against a pinned fitness function | 1 evaluation | evaluator is pinned and pure |
| `lean` | a proof assistant kernel accepts the proof | seconds | kernel soundness |
| `replay` | re-runs a pinned computation, compares declared fields | full re-run | bit-reproducibility |

Pinned verifier code runs as a **subprocess** with its hash checked first — a
step toward the sandboxing the roadmap flags as a launch blocker. The `lean`
verifier rejects `sorry`, `admit`, new `axiom`s, and `native_decide` before Lean
ever runs, because each produces a file the kernel accepts while proving nothing.

### Rules the code enforces

- **A verifier that cannot run returns `Unavailable` — never `Reject`.** A
  missing toolchain, a crashed checker, or a timeout is an infrastructure fact,
  not a fact about the artifact. Collapsing it into a rejection turns "my Lean
  install is broken" into "your proof is wrong", and hands an attacker a way to
  fail every honest submission by taking verifiers offline. Only `Accept` and
  `Reject` settle anything.
- **Floats are unrepresentable, not merely rejected.** `canonical::Value` has no
  float variant, so an object whose identity could differ between two honest
  nodes cannot be constructed. IEEE-754 doubles don't round-trip identically
  through every JSON implementation and don't reproduce bitwise across
  heterogeneous hardware.
- **Money arithmetic is checked.** `reward * progress` overflows `u64` at
  realistic values; every such path uses `u128` intermediates and returns an
  error rather than wrapping, with `overflow-checks` on in release too.
- **Novelty is necessary, never sufficient.** A duplicate artifact verifies fine
  and mints zero. Issuance is gated on funded demand.
- **Time is not reproducible.** `replay` refuses to treat wall-clock, memory, or
  FLOPs as a checkable field — those measure the host, not the computation.
- **Attribution conserves exactly.** Citation-flow payouts sum to the amount
  distributed, at any reward and any δ, with a deterministic rule for the odd
  unit in an uneven split.

## Coordination: don't schedule it, price it

Thousands of participants on one objective must avoid duplicating each other and
share what they find. That's usually attacked with machinery — dispatchers,
reservations, locks. Most of it is self-inflicted: **a winner-take-all bounty
gives everyone a reason to hoard**, so nobody shares and everyone rediscovers the
same partial results.

`frontier.rs` changes the payment structure instead. An objective carries a
monotone best-known score; whoever moves it is paid for the distance moved.
Payouts telescope, so the pool is exactly exhausted at the target however the
curve is chopped.

```
alice: 12-point cap set     reward 300000
eve:   copies alice         reward 0        (does not improve)
bob:   16, citing alice     reward 400000
carol: 20, citing bob       reward 400000   (pool exhausted)

after citation flow:  alice 425000 · bob 375000 · carol 300000
```

Alice ends up with the **largest total from the smallest direct reward**, because
two people built on her. Publishing immediately becomes the profitable move,
copying earns zero, and an improvement **must cite the frontier it beat** —
enforced at submission, so attribution needs no judgement.

### Three kinds of state, three consistency requirements

| state | volume | needs | mechanism |
|---|---|---|---|
| frontier — who holds the best score | low | total order | consensus |
| population — candidates worth mutating | high | eventual convergence | CRDT + gossip |
| work split — which region a node searches | zero messages | nothing | pure function |

The population is a bounded join-semilattice: merge is commutative, associative
and idempotent, so nodes converge with no rounds and no leader. Divergence is not
a bug — it's the island model preserving search diversity. **Gossip is
untrusted**: a peer asserting `score = 10^12` would evict every real candidate, so
`ingest()` re-scores locally and drops what doesn't reproduce.

## Agents paying agents

Every payment above points the same way: a funder escrows, an artifact verifies,
settlement releases, citation flow moves a fraction of that same money backwards.
Every unit that reaches a participant entered as somebody's bounty. Nothing pays
an agent for something another *agent* wanted — a decomposition, a sub-frontier
candidate, a branch somebody else explored.

The scope for closing that is [agent-market.md](docs/agent-market.md), and its
conclusion is that **the mechanism is already here**. `Objective::funder` is a
string, there is no balance and no transfer primitive anywhere in `src/`, and an
agent-to-agent payment is best expressed as an objective rather than a transfer:
escrow, verification, settlement, audit and citation flow then apply unchanged,
and fair exchange falls out instead of needing its own protocol.

What makes it tractable at all is an asymmetry that inverts the verifier's
dilemma. Nobody holds the right answer about an artifact, which is why
verification needs canaries — but

> **the buyer is the oracle.** An agent spending its own money on a good it wants
> is motivated to price it correctly, so the protocol enforces atomicity and never
> valuation.

That survives exactly one rule: **no protocol payment may ever be a function of
trade volume.** A sybil pair trades at any price for free, so a fee rebate or a
reputation that pays is the grinding attack with a market around it.

Three results the scope pins down:

- **The market cannot outbid the ratchet.** A buyer will not pay more than what
  publishing is worth to it, so `π < Δ + φ` and selling is dominated for anyone
  with standing to move the frontier. The market's whole domain is the goods the
  ratchet prices at *zero* — which is a boundary the payoffs already draw rather
  than one anybody has to enforce.
- **Even-splitting δ stops being safe.** Citation flow divides evenly across a
  claim's citations, which is fine while citable claims are scarce and is a free
  attack once an agent can fund cheap objectives its own identities settle. At
  δ = 1/4 and five citations, four fifths of what the ratchet promised the
  frontier holder is recoverable. This has to be fixed *before* agent funding,
  not after.
- **Decomposition has a floor, and it is high.** A sub-objective the network
  verifies for more than it settles is subsidized by everything else. At the
  reference parameters that break-even is 800,000 units per artifact under full
  redundancy, or 8,000·k under k-fold sampling — so subcontracting should be
  coarse, and sampled verification stops being optional.

And one risk that decides whether it is worth building at all: candidates
currently circulate through gossip *because* nothing prices them. Price them and
gossiping is giving away inventory, so a market for candidates may starve the
population the island model runs on. That is a payoff question, it is the highest-
value item in the scope, and it belongs in the harness before it belongs in code.

## Why anyone runs a node

Everything above pays *submitters*. Nothing in it pays the machines that re-run
the verifiers, hold the log, or custody the shares that open a sealed
submission — all public goods, all of which the dominant strategy is to leave to
somebody else.

The hard one is verification, and it is hard structurally rather than
quantitatively. Punish a node for accepting work that somebody *else* later
proves invalid, and

> **"everybody rubber-stamps" is a Nash equilibrium at any penalty** — if nobody
> checks, nobody is caught, so no penalty ever fires.

Raising the slash does not touch it. The mechanism has to manufacture its own
ground truth: **canaries**, artifacts whose verdict the protocol already knows,
mixed indistinguishably into each node's sample. Then the punishment is
unconditional and the equilibrium moves.

Availability and custody need no such trick, and the reason is the whole design
in one line: **the protocol already holds the right answer.** A Merkle challenge
is checked against a published root; a share that never appears names its
holder. Verification is the only service with no oracle.

`src/incentive/` is the mechanism and a harness that evaluates it — exact
rational payoffs (no floats, so "is this an equilibrium" is decidable), the full
ladder from individual rationality up to k-resilience and sybil-proofness, and
better-reply dynamics for where a population *lands* rather than where it could
rest.

```
$ proofwork incentives --canary-rate 0

verification -- honest action: verify
  honest profile                 strict Nash  ok
  pure equilibria                          2
  rival (strict) equilibria                1  FAIL
  smallest defection               100 nodes  FAIL
  free (zero-gain) drift                none  ok
  tipping point                    100 nodes  FAIL
  binding constraint        canary_rate must exceed 1/1425 (currently 0)
```

Three results worth stating plainly, each pinned by a test:

- **The reward pool decides how many nodes there are; it has no effect on
  whether they do the work.** A rubber-stamper collects the same share, so the
  pool cancels out of every honest-versus-lazy comparison. Paying operators more
  is never an answer to "nobody is checking".
- **Node rewards are a fee on settlement, not a mint** — the same demand-gating
  rule as everything else here, which means security spend is proportional to
  settled value and *zero at launch*. Stated, not solved.
- **The committee has to grow with the value it seals.** Raising the threshold
  makes early opening harder and censorship-by-withholding easier, so safety is
  a window; a shape safe for a small bounty is corruptible for a large one, with
  no code change in between.

Also stated rather than papered over: a committee member standing ready to
collude is behaviourally identical to an honest one, so the custody equilibrium
is **weak at every parameter set** and no bond makes it strict. What the bond
buys is that reaching the threshold does not pay.

## Local storage: encrypted, bounded, yours

Where a node's data lives is the operator's choice, and what leaks off their disk
is their risk. Three things, one command each:

```sh
proofwork keygen                                   # 32-byte key at ~/.proofwork/key, 0600
proofwork --data-dir /Volumes/ext/pw audit         # data wherever you want it
proofwork --data-dir /Volumes/ext/pw --max-size 20GB store gc
proofwork --data-dir /Volumes/ext/pw sync ~/Dropbox/pw-backup
```

**At rest, the log is sealed line by line** with ChaCha20-Poly1305. Per line, not
per file, because the log is append-only and encrypting it as a unit would make
every append an `O(n)` rewrite. The AEAD's associated data binds each line's
position, so a reordered or spliced log fails to decrypt at the exact line rather
than merely failing the chain later.

This does not contradict public verifiability, and the distinction is *whose
copy*: artifacts the network publishes stay readable — encrypt those and you are
back to trusting an operator — while a node's own disk is its own business. An
encrypting node serves exactly what a non-encrypting one serves, and

> **encryption changes no hash, no `prev` link, no Merkle root, and no audit
> result.** The chain covers plaintext; sealing is storage.

**The key defaults to outside the data directory** (`~/.proofwork/key`), because
a key beside its ciphertext looks fine right up until the folder is synced
somewhere else — and then it was never encryption. `sync` refuses to copy a key
it finds inside a store, detecting them by content rather than filename, and
withholds the plaintext backup `store encrypt` leaves behind. Optional argon2id
passphrase wrapping, with the cost parameters stored in the file so raising the
defaults later does not orphan existing keys.

**The size cap never evicts the log.** A cap on a store holding the only copy of
a hash-linked log is an instruction to destroy evidence, and "delete the oldest
thing" would eat the log first. Eviction touches re-fetchable content only; when
that is not enough the answer is a refusal, *before* anything is deleted:

```
error: store limit of 100 B cannot hold 1.8 KiB of data that must not be deleted
(the log and anything beside it). Raise the limit or move the store; proofwork
will not prune a hash-linked log to fit
```

A cap smaller than your log stops your node. It does not prune your log.

And the cost of eviction is not disk — it is that evicted content can no longer
answer an availability challenge, which in a network that pays for availability
is a slash. `store gc` names every path it dropped for exactly that reason.

## Censorship resistance

Assume censorship. But separate four properties that get bundled under "encrypt
it", because encryption delivers only one of them:

| property | mechanism |
|---|---|
| confidentiality — observers can't read | encryption |
| unlinkability — observers can't tell *who* | pseudonyms, ZK |
| censorship resistance — your submission gets included | forced/blind inclusion |
| availability — content can't be withheld | replication, gossip |

**Encrypting settled artifacts would destroy the project.** Public verifiability
requires them readable; encrypt them and you're back to trusting an operator.

The real censorship hole is elsewhere: **commit–reveal requires the submitter to
act twice.** An adversary who can't forge or steal your work can still take it by
stopping the second action — a DoS, a network block, a detention, or a sequencer
that drops your reveal until the deadline passes.

So submissions are **sealed**, and opened *without* the submitter:

```
commit    commitment = H(artifact ‖ submitter ‖ nonce)      (unchanged)
          envelope   = ChaCha20-Poly1305(K, {artifact, nonce})
          shares     = Shamir(K, t-of-n), each sealed via ephemeral X25519
epoch end ≥t committee members publish shares → anyone reconstructs → opens
```

You can be offline, jailed, or firewalled and still be paid. It also kills
in-flight front-running, and makes selective censorship visible — a sequencer
can't see what it's dropping, so it must include everything or censor
indiscriminately. The commitment binds the plaintext, so a submitter who seals
garbage is caught the moment the committee opens it.

Sealing moves **when** an artifact becomes public, never **whether**.

Two things are stated rather than papered over: **citation flow requires
linkage** — the pseudonym graph is public by construction because paying people
for being built upon is what it's for — and **encryption does not stop a
sequencer that includes nothing**, which needs forced inclusion on a base layer.

## Consensus: validators don't vote on truth

For a pure pinned verifier, correctness is **not** a consensus question — anyone
re-runs the checker and gets the same answer. What needs agreement is narrower:
**ordering** (who advanced the frontier first) and **data availability** (was this
published, or withheld).

That inverts the usual priorities. Throughput barely matters; frontier advances
are minutes apart. **Censorship resistance matters enormously**, because
withholding a competitor's reveal steals a bounty, and liveness is money.

So: don't write a consensus protocol, and don't run an L1. Use a rollup on an
established chain — the bootstrap circularity (stake value ← research ← chain)
has no starting point, and forced inclusion via a base layer delivers the primary
security property directly. The state transition is already the pure function in
`node.rs`, and `audit()` is already the re-derivation a fraud proof needs.

## Layout

```
src/                 Rust implementation (primary)
  canonical.rs       content addressing; the cross-implementation contract
  records.rs         Objective / Commitment / Claim
  ledger.rs          hash-linked append-only log
  node.rs            the rules engine and the audit
  frontier.rs        progressive bounties
  attribution.rs     recursive citation flow
  gossip.rs          the candidate population CRDT
  partition.rs       coordinator-free work assignment
  verifiers/         certificate, evaluator, lean, replay
  crypto/            Shamir, sealed envelopes, pseudonymous identity
  sealed.rs          sealed submissions, openable without the submitter
  incentive/         the node-operator mechanism, and the harness that evaluates it
  store/             at-rest encryption, the data directory, the size cap, the mirror
reference/python/    Python reference implementation (183 tests)
conformance/         cross-implementation vectors — the binding contract
docs/                the design notes
examples/            worked objectives with real artifacts
```

## Docs

- [diagrams.md](docs/diagrams.md) — architecture and detailed design, drawn from the code
- [architecture.md](docs/architecture.md) — the full design and which work shapes fit
- [verification.md](docs/verification.md) — the verification ladder; authoring verifiers
- [economics.md](docs/economics.md) — what mints, why demand-gating, citation flow
- [coordination.md](docs/coordination.md) — the hoarding trap, the ratchet, CRDT gossip
- [agent-market.md](docs/agent-market.md) — agent-to-agent rewards: what a peer-to-peer mechanism would be, and what it breaks
- [consensus.md](docs/consensus.md) — what validators are for, and why not to build a chain
- [censorship.md](docs/censorship.md) — confidentiality, unlinkability, sealed submissions
- [node-incentives.md](docs/node-incentives.md) — why anyone runs a node, and the game-theoretic evaluation
- [review-pcw.md](docs/review-pcw.md) — a review of Proof of Adaptive Challenge Solving as a consensus mechanism, and what to salvage from it
- [proving-it.md](docs/proving-it.md) — what a game-theoretic proof here would be, what it would not be, and where this one is weakest
- [storage.md](docs/storage.md) — encryption at rest, the data directory, the size cap, sync
- [threat-model.md](docs/threat-model.md) — attacks, and which are actually handled
- [p2p.md](docs/p2p.md) — removing the operator: what needs agreement, and the McEliece handshake
- [agents.md](docs/agents.md) — running Claude Code / Codex / OpenCode against the network over MCP
- [AGENTS.md](AGENTS.md) — instructions agents read: contributing here, and contributing *to* the network
- [roadmap.md](docs/roadmap.md) — what Stage 1–3 add, in the order worth doing
- [conformance/README.md](conformance/README.md) — the cross-implementation contract

## What this is not

- **Not a blockchain.** One sequencer, no consensus, no token. Deliberate: the
  valuable property is "anyone can check", not "no one is in charge".
- **Not sandboxed.** Pinned verifier code runs as a subprocess, which is better
  than in-process `exec` and is still not a jail. A launch blocker before
  objective authorship opens.
- **Not able to verify judgement.** Whether a direction is promising, whether a
  result is novel against the literature — no mechanism settles these.
- **Not able to pay fairly for effort that produced nothing**, which is most of
  real research. The deepest limitation, and not solved here.
- **Not able to price a shared technique.** Citation flow tracks artifacts,
  because artifacts are checkable. If you tell me "try annealing on the third
  coordinate" and I win, nothing pays you.
- **Not running the node mechanism.** `src/incentive/` is a mechanism and its
  evaluation, not a code path. No canary is generated, no bond is posted, no
  Merkle challenge is issued. It exists now because the parameters it demands
  are expensive to discover after launch.

## Prior art

[FunSearch / AlphaEvolve](https://deepmind.google/discover/blog/funsearch-making-new-discoveries-in-mathematical-sciences-using-large-language-models/)
for propose-and-evaluate, the
[Equational Theories Project](https://arxiv.org/html/2512.07087) for crowdsourced
kernel-verified mathematics, and
[INTELLECT-2 / TOPLOC](https://www.primeintellect.ai/blog/intellect-2) for
verifying permissionlessly contributed inference across non-deterministic GPUs.

## License

Apache-2.0
