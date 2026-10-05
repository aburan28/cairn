# cairn documentation

Forty-odd files live under `docs/`. This page is the map: what to read, in what
order, for the thing you are actually trying to do.

The [README](../README.md) is the argument — what the network is for, and why
it is shaped the way it is. [quickstart.md](quickstart.md) is the five minutes
that make it concrete against bytes already in this repository. Everything
below is either reference (what a command, a setting, or a word does) or design
(why a mechanism is the way it is, and what it still does not solve).

## Start here

| you want to | read |
|---|---|
| get `cairn` onto a machine | [install.md](install.md) |
| see it work, without building anything of your own | [quickstart.md](quickstart.md) |
| point an agent at open objectives and get paid | [agents.md](agents.md) |
| write an objective other people can solve | [verification.md](verification.md) |
| run a node strangers submit to | [serving.md](serving.md), then [storage.md](storage.md) |
| connect two nodes in two places, each behind its own router | [two-nodes.md](two-nodes.md) |
| run a leader that is paid, and machines that work for it from anywhere, rented GPUs included | [fleet.md](fleet.md) |
| see what the network is trying to beat, and post on a problem without inventing a second name for it | [goals.md](goals.md) |
| know what a command does | [cli.md](cli.md) |
| know what a setting does | [configuration.md](configuration.md) |
| know what a word means | [glossary.md](glossary.md) |
| fix something that is not working | [troubleshooting.md](troubleshooting.md) |
| understand the whole design | [architecture.md](architecture.md), then [diagrams.md](diagrams.md) |
| keep a research program's shared state without git, and run its experiments in sandboxes | [lab.md](lab.md) |
| put a Linux box with GPUs on the network as a place executor jobs run, under systemd | [agent.md](agent.md) |
| attack it | [threat-model.md](threat-model.md) |
| work on this repository | [../AGENTS.md](../AGENTS.md), [../CONTRIBUTING.md](../CONTRIBUTING.md) |

## Reference

The six pages a user needs and nothing else in this repository provides.

- [install.md](install.md) — the disk image, the `.deb`, the `.rpm` and the
  install script: what each puts where, what the packages recommend and why,
  the macOS approval dialog, and what none of their checksums prove.
- [quickstart.md](quickstart.md) — audit a real settled log, run one bounty
  round end to end, start a node. Every command in it was run to write it.
- [cli.md](cli.md) — every `cairn` subcommand, its flags, what it reads, what
  it writes, and what each exit code means.
- [configuration.md](configuration.md) — every environment variable and global
  flag, what it defaults to, and which of them are unsafe to change on a node
  that talks to other nodes.
- [glossary.md](glossary.md) — objective, claim, frontier, citation flow,
  standing, tier, docket, and the rest of the vocabulary, each pointing at the
  code that defines it.
- [troubleshooting.md](troubleshooting.md) — the failure modes that are
  designed-in and look like bugs, and the ones that are bugs.

## Using the network

- [agents.md](agents.md) — running Claude Code, Codex or OpenCode against the
  network over MCP: one config stanza, the ten tools, and why an objective's
  statement is untrusted input.
- [verification.md](verification.md) — the verification ladder, and how to
  author a verifier whose verdict anybody can reproduce.
- [agent.md](agent.md) — `cairn agent`: the host agent that probes a
  machine's CPUs, memory and GPUs, registers them with a node over
  `POST /hosts`, runs executor jobs under gVisor or Kata Containers with a
  receipt naming the jail, and installs itself as a hardened systemd unit.
- [serving.md](serving.md) — publishing a log over HTTP, the endpoints, why
  submissions queue instead of appending, and the progress route behind the
  reader's per-task dashboard: settled work from the log beside unverified
  worker heartbeats, kept apart.
- [storage.md](storage.md) — encryption at rest, the data directory, the size
  cap, and sync.
- [tiers.md](tiers.md) — why a unit earned on a millisecond certificate check
  is not a unit earned on a Lean proof, and cannot be spent as one.
- [design/rho-piecework.md](design/rho-piecework.md) — **piecework**: paying per
  verified unit of a divided problem, for searches that have no frontier to
  move. Built, and the worked instance is a distributed Pollard rho.
- [design/orbit-piecework.md](design/orbit-piecework.md) — the same, where the
  unit is an **orbit** and a point cannot carry its own certificate: ECC2K-130,
  and the eight-counter witness that makes one of its distinguished points
  something a network can pay for.
- [../examples/certicom-ecdlp/ECC2K130-CAMPAIGN.md](../examples/certicom-ecdlp/ECC2K130-CAMPAIGN.md)
  — paid orbits vs the unpaid corpus path that feeds
  [aburan28.github.io/crypto/status](https://aburan28.github.io/crypto/status/);
  `cairn secret` and `scripts/ecc2k-dp.sh`.
- [knowledge.md](knowledge.md) — typed relations, derived standing, and
  reader-chosen confidence: revising knowledge without rewriting history.
- [lab.md](lab.md) — **the lab**: a research program's working state (records,
  leases, messages, run outputs) as signed ops that merge like a CRDT, with no
  git and no server, and experiments run in content-addressed environments
  under gVisor. The notebook beside the ledger; it settles nothing.
- [../examples/README.md](../examples/README.md) — worked objectives with real
  artifacts, which is the fastest way to see what a checkable question is.

## Running a node

- [p2p.md](p2p.md) — removing the operator: what needs agreement, and the
  McEliece handshake.
- [discovery.md](discovery.md) — peer discovery without a name anybody owns.
- [two-nodes.md](two-nodes.md) — two machines behind two routers: port
  mapping, the seed, and reading whether it worked.
- [fleet.md](fleet.md) — one leader that signs and is paid, and the machines
  that work for it: invited and enrolled from anywhere, rented GPUs without a
  tunnel, revocation, the older network trust, and what no part of it does
  with money.
- [goals.md](goals.md) — goals and angles: one problem, many approaches, read
  off the handle every objective already carries; the alias catalog that
  joins two spellings; the `find_goal` tool a drafting agent calls first.
- [shards.md](shards.md) — erasure coding, and why per-chunk commitments are
  what make it safe rather than merely cheap.
- [censorship.md](censorship.md) — confidentiality, unlinkability, sealed
  submissions.
- [node-incentives.md](node-incentives.md) — why anyone runs a node, and the
  game-theoretic evaluation behind `cairn incentives`.
- [bonded-verification.md](bonded-verification.md) — who ran the checker, and
  what it costs them to lie.
- [fraud-proofs.md](fraud-proofs.md) — how a disputed computation is settled by
  executing one step instead of all of them.

## The design

- [architecture.md](architecture.md) — the full design, and which work shapes
  fit it.
- [diagrams.md](diagrams.md) — architecture and detailed design, drawn from the
  code.
- [economics.md](economics.md) — what mints, why demand-gating, citation flow.
- [coordination.md](coordination.md) — the hoarding trap, the ratchet, CRDT
  gossip.
- [consensus.md](consensus.md) — what validators are for, and why not to build
  a chain.
- [agent-market.md](agent-market.md) — agent-to-agent rewards: what a
  peer-to-peer mechanism would be, and what it breaks.
- [formal-model.md](formal-model.md) — which rules TLC actually checks, and
  which are only tested. See also [../spec/tla/README.md](../spec/tla/README.md).
- [proving-it.md](proving-it.md) — what a game-theoretic proof here would be,
  what it would not be, and where this one is weakest.
- [review-pcw.md](review-pcw.md) — a review of Proof of Adaptive Challenge
  Solving as a consensus mechanism, and what to salvage from it.
- [arena.md](arena.md) — attack strategies played for money against the real
  rules engine, and what each one earned.

## Status of the project

- [threat-model.md](threat-model.md) — every considered attack, marked
  **handled / partial / not handled / unsolvable**. Keeping it honest is a
  stated project rule; read it before trusting anything above.
- [roadmap.md](roadmap.md) — what Stage 1–3 add, in the order worth doing.
- [design-stage0-completion.md](design-stage0-completion.md) — what "Stage 0 is
  done" was defined to mean.
- [review/gui-assessment.md](review/gui-assessment.md) — the four readers (the
  embedded site, Cairn.app, the autoresearcher control surface, the iPhone)
  reviewed as one system: what each could show, what none could, what landed
  with the review and what is still only on paper.
- [launch-review.md](launch-review.md) — the pre-launch pass: what was fixed,
  and the gaps that remain, in priority order.
- [../conformance/README.md](../conformance/README.md) — the cross-implementation
  contract, and why the vectors are frozen.
- [../launch/README.md](../launch/README.md) — the published log, its
  checkpoint, and the two caveats that come with a sample artifact.

## Design notes

Everything under [`docs/design/`](design/) is a worked design review. Some of it
landed and some of it was examined and rejected, so each row says which — a
design that was rejected is worth more written down than re-derived, but only if
nobody mistakes it for a feature. Each file states its own status in its opening
lines; that is the authority, and this table is the index to it.

| note | status |
|---|---|
| [chain-beacon.md](design/chain-beacon.md) — a beacon the sequencer cannot grind | **built** — the `beacon` record, `cairn beacon` |
| [drand-beacon.md](design/drand-beacon.md) — a beacon a log-only auditor can check | **built**, in both implementations |
| [settlement-convergence.md](design/settlement-convergence.md) — the epoch chain | **built**, in both implementations |
| [citation-flow-dilution.md](design/citation-flow-dilution.md) — the slicing attack on attribution | **implemented, not the default**; the threat model still carries the row |
| [confidential-corpus.md](design/confidential-corpus.md) — material the network cannot read | storage and release **built** (`src/corpus.rs`); the rest deliberately undone |
| [inference-capabilities.md](design/inference-capabilities.md) — capability-aware scheduling | **built** (`src/compute.rs`), outside the ledger on purpose |
| [anchored-time.md](design/anchored-time.md) — what a shared clock would buy | analysis only; one part should probably never be built |
| [shard-assignment.md](design/shard-assignment.md) — what erasure coding prices | analysis only |
| [embargo-release.md](design/embargo-release.md) — holding an artifact the log already owes you | design only |
| [heir-fhe-compilation.md](design/heir-fhe-compilation.md) — buy the search, refuse the compute | integration review; half of it is refused on purpose |
| [workspace-benchmarks.md](design/workspace-benchmarks.md) — repository-shaped benchmarks | **verifier built**, in both implementations; `cairn bench` and MCP notes are not |
| [rho-piecework.md](design/rho-piecework.md) — distributed Pollard rho as piecework | **Stages A and B built** (`src/piecework.rs`); Stage C is not |
| [orbit-piecework.md](design/orbit-piecework.md) — ECC2K-130: paying per orbit, and the witness that makes one checkable | **built**, with no consensus change; the corpus still does not fit a log |
| [network-coordination.md](design/network-coordination.md) — live sessions over HTTP, the compute roster, advisory task leases, declared roles | **built** in the node and the reader (`src/p2p/sessions.rs`, `src/lease.rs`, `src/network.rs`); nothing in consensus, by design; gossiped leases and signed heartbeats are not |
| [fleet-enrollment.md](design/fleet-enrollment.md) — per-machine enrollment in place of network trust, so a rented GPU joins a fleet without a tunnel | Stage 1 built (no consensus change); Stage 2 is a consensus change and is not |
| [index-calculus-p224.md](design/index-calculus-p224.md) — index calculus as piecework | proposal; nothing here is built |
| [swarm-targeting.md](design/swarm-targeting.md) — aiming a swarm at one problem, and what ecdsa.fail's nonce grinding teaches | proposal; nothing here is built |

## Contributing

Two different things get called contributing here and they have almost nothing
in common — [../CONTRIBUTING.md](../CONTRIBUTING.md) splits them.
[../AGENTS.md](../AGENTS.md) is the binding version for both: section A is this
repository's rules, section B is the network's. [../SECURITY.md](../SECURITY.md)
has the private reporting channel, and
[../CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md) the behavioural one.
