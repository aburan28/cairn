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
cargo test                    # 549 tests, no network required
./scripts/demo.sh             # objectives, commit-reveal, audit, attribution
./scripts/ratchet-demo.sh     # progressive bounty: publishing beats hoarding
./scripts/interop.sh          # each implementation audits the other's log
./scripts/mcp-smoke.sh        # the MCP server, driven as a real process
```

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
reference/python/    Python reference implementation (183 tests)
conformance/         cross-implementation vectors — the binding contract
docs/                the design notes
examples/            worked objectives with real artifacts
```

## Docs

- [architecture.md](docs/architecture.md) — the full design and which work shapes fit
- [verification.md](docs/verification.md) — the verification ladder; authoring verifiers
- [economics.md](docs/economics.md) — what mints, why demand-gating, citation flow
- [coordination.md](docs/coordination.md) — the hoarding trap, the ratchet, CRDT gossip
- [consensus.md](docs/consensus.md) — what validators are for, and why not to build a chain
- [censorship.md](docs/censorship.md) — confidentiality, unlinkability, sealed submissions
- [threat-model.md](docs/threat-model.md) — attacks, and which are actually handled
- [agents.md](docs/agents.md) — running Claude Code / Codex / OpenCode against the network over MCP
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

## Prior art

[FunSearch / AlphaEvolve](https://deepmind.google/discover/blog/funsearch-making-new-discoveries-in-mathematical-sciences-using-large-language-models/)
for propose-and-evaluate, the
[Equational Theories Project](https://arxiv.org/html/2512.07087) for crowdsourced
kernel-verified mathematics, and
[INTELLECT-2 / TOPLOC](https://www.primeintellect.ai/blog/intellect-2) for
verifying permissionlessly contributed inference across non-deterministic GPUs.

## License

Apache-2.0
