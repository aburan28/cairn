# Plan: from a verified-results log to a volunteer research network

Written 2026-09-25 against `main` at `1715e4e`, as a holistic evaluation and
the work it implies. [roadmap.md](roadmap.md) is the record of what each stage
built and what it deliberately left out. This page is narrower and more
opinionated: what stands between the repository as it is and **a stranger who
launches the app, connects a model or a GPU, and contributes to somebody
else's research problem**. Idea people with no compute get their idea run.
People with compute share it. Nobody in the middle decides who gets paid.

Every claim about the current state below names the file it comes from. Where
the answer is "this cannot be done the way it was asked", the page says so and
says what can be done instead. Overstating what is solved is the one mistake
this repository cannot afford, and a plan is where that mistake is cheapest to
make.

## The short version

The core is strong, and it is not where the risk is. A log that anyone can
re-derive, two independent implementations held to frozen conformance vectors,
differential fuzzing between them, an adversarial arena that plays attacks for
money, bonded verification with canaries, and bisection fraud proofs: that
combination is rare. On `main` it passes 1,743 tests, and the reference
implementation's suite, the frozen conformance vectors and the interop script
pass beside them.

The risk is everything between that core and a newcomer:

1. **The network could not be found.** The one published seed
   (`44.251.117.84`) has not answered since 2026-09-11; the `node-sync`
   workflow has failed on every run since, and nothing alerted anyone. The
   macOS app never used the seed list at all: it runs `cairn run` with no
   `--bootstrap`, so every node it started was LAN-only.
   [#168](https://github.com/aburan28/cairn/pull/168) fixes the second half.
   The first half needs the host restarted, and then more than one host.
2. **It pays for artifacts, not for running somebody's computation, and says
   so.** This is a distributed Library of Alexandria: verified knowledge is the
   unit of account. "Becoming a general compute marketplace" is a roadmap
   non-goal. The ECC2K-130 piecework design is the bridge: it pays per
   *verified unit of a declared search* rather than per hour, which is the
   shape a job layer should keep.
3. **There is no path from "launch the app" to "contribute".** No provider
   login and no agent in the app. There is also no view of anybody's
   resources. Contribution today means configuring Claude Code, Codex or
   OpenCode against `cairn mcp` by hand, or running the deterministic
   autoresearcher script.
4. **Records are signed with ed25519 alone.** That is the largest quantum gap
   in the tree, larger than the KEM question, because those signatures move
   money. A node's identity is welded to its Classic McEliece key, which is
   why McEliece cannot currently be demoted. And every p2p session key rests
   on McEliece alone: the additive KEM bundle protects sealed submissions, and
   the handshake never uses it.
5. **Every piece of a currency exists except a rail**: issuance, escrow,
   tiers, bonds, slashing and conservation audits. The published log declares
   no supply, though, so none of that accounting is switched on there. There
   is also no way for many sponsors to fund one idea. And the citation income
   the agent guidance promises is computed by `cairn attribute` but never
   reaches a balance.
6. **Nobody has decided who orders a multi-operator network.** Every log has
   one writer. Two operators paying out on the same objective need an answer
   to "who was first" that the design explicitly does not have yet.

## Where things stand

| area | state | evidence | the gap |
|---|---|---|---|
| verifiable log and settlement | **strong** | `src/node.rs`, `reference/rust/`, `conformance/vectors.json`, `scripts/{interop,differential,fuzz-differential}.sh` | none that blocks this plan |
| incentive defences | **strong for what is modelled** | `src/arena/`, bonded attestations, canaries, `src/challenge.rs` | identities are free (Sybil) |
| transport and sync | **solid, closed to inbound** | `src/p2p/`: PQ handshake, set reconciliation, Kademlia, multicast, NAT-PMP, SOCKS5 | no hole punching, no forward secrecy, no pre-auth rate limit; the app binds loopback |
| discovery | **was broken in practice** | one seed, down; the app never read the list (fixed by #168) | more seeds; a rendezvous nobody operates |
| distributed computation | **early, well-founded** | `src/piecework.rs`, `docs/design/orbit-piecework.md`, `src/partition.rs`; `src/compute.rs` is written and has never been compiled | job layer, GPU sandbox, terabyte-scale result store |
| resource telemetry | **absent** | none | all of item 12 |
| onboarding and agents | **CLI and MCP only** | `src/mcp.rs` (ten tools), `gui/macos-app/` shows the node's web reader, `research/crypto-autoresearcher/` | provider login, in-app agent, budgets |
| cryptography | **PQ transport on one KEM, classical record signatures** | `src/p2p/handshake.rs` (McEliece only), `src/crypto/kem.rs` (the bundle, sealed path only), `src/crypto/identity.rs`, `src/crypto/envelope.rs`, `tests/cipher_policy.rs` | items 4–7 |
| money | **pieces present, no rail** | `records::Issuance`, escrow in `Node::post_objective`, `src/tier.rs` | rail, sponsorship; citation flow not in balances; objective deadlines unenforced; the launch log declares no supply |
| ordering across operators | **single writer per log** | [p2p.md](p2p.md#still-open) | item 8 |

**Stranded work worth reviving.** Branch
`claude/researcher-ideas-changes-y98etd` was never merged. It carries a
versioned algorithm registry (`crypto::policy`) with statuses (required,
accepted, deprecated, withdrawn) and a `min_families` knob. It also carries
`docs/agility.md`, which analyses what can and cannot be migrated, and claim
co-authorship `shares`. Item 4 starts from it rather than from nothing.

**Stale or overstated statements, corrected alongside this plan.**

- The `Undertaking::bond` doc comment in `src/records.rs` and the roadmap's
  "three bounds remain" paragraph both said `post_objective` takes no deposit,
  and named a test that no longer exists. It has escrowed the reward from the
  funder's balance, per tier, since #100 (`Node::afford`, `Node::afford_in`).
  On a log with no `issuance`, which includes the published one, escrow is
  still not enforced, and both now say exactly that.
- [p2p.md](p2p.md) said the KEM bundle is used by `src/p2p/handshake.rs`. The
  handshake takes only `kem::key_id` from it, to derive the same peer id; the
  session key is McEliece alone.
- `docs/README.md` and
  [design/inference-capabilities.md](design/inference-capabilities.md) called
  `src/compute.rs` built. It has never been declared as a module, so nothing
  compiles or tests it. Its request envelopes use X25519, which the crate
  removed and `tests/cipher_policy.rs` forbids, so it cannot simply be wired
  in.

## Answers to the questions asked

### Can WebRTC, STUN, TURN, a blockchain or MCP find peers without a single point of failure?

They answer different questions. Only one of them answers this one.

| technique | what it actually solves | verdict here |
|---|---|---|
| **STUN** | learning your own public address and port mapping | yes, as part of NAT traversal, and no third party is needed: any peer can echo the source address it observed during the handshake |
| **TURN** | relaying traffic when no direct path exists | yes, as **volunteer relays**: any reachable node forwards frames it cannot read, since the handshake is end to end. Rate-limited, and later paid like availability |
| **WebRTC** | browser-to-browser data channels, with ICE (STUN plus TURN) built in | only for browser light nodes, meaning the site or the iOS reader. Native nodes should not adopt it: its encryption is DTLS, `tests/cipher_policy.rs` bans TLS, and the transport already has a PQ handshake. It also needs a signalling rendezvous, so it does not solve discovery either |
| **a blockchain** | a globally agreed store | not for discovery. Each address update costs a fee in somebody's token and waits for a block, and it ties finding the network to holding a currency, the thing this plan keeps out. It **is** useful for *anchoring* checkpoints (item 8) and as a settlement rail (item 15) |
| **MCP** | connecting an AI host to tool servers over stdio or HTTP | not for discovery: it has no notion of peers, and the MCP Registry is one central directory. It is the right *agent interface*, which it already is (`src/mcp.rs`), and a public node can expose it over HTTP so an agent can use whichever node the DHT finds |
| **BitTorrent Mainline DHT** | a rendezvous on millions of nodes that nobody runs, with no token and no fees | **this one** (item 2) |

The Mainline DHT fits for a specific reason. BEP 5 lets any node announce
itself under a 20-byte key and look up everyone else announced there, so all
cairn nodes can meet under a key derived from the network's name. BEP 44 stores
small values signed by an ed25519 key with a sequence number that supersedes.
That is exactly the shape of `records::PeerRecord` (identity ed25519, address
as a signed hint, `seq` supersedes), and it is how pkarr publishes signed
records and how iroh finds nodes. Nothing new has to be trusted, for the same
reason nothing else in [discovery.md](discovery.md) is trusted: an answer is a
hint, and the handshake decides.

The discovery stack this plan ends with, in the order a node tries it:

1. the peers it reached last time (a peer cache, not built);
2. the LAN (`p2p::multicast`, built);
3. the seed list compiled into the binary (built in #168);
4. the Mainline DHT rendezvous (item 2);
5. peer exchange once anything answers (built);
6. operator-supplied hints: `--bootstrap`, `CAIRN_SEEDS` (built), and a
   signed seed list any mirror can serve (item 2).

Losing any one costs a hint source, never the network.

### Can Pollard rho on ECC2K-130 be scheduled?

**Partly, today, and the design is further along than it looks.**
`examples/certicom-ecdlp/objective-ecc2k130-orbit-batch.json` is a piecework
objective paid per verified **orbit**. On a Koblitz curve, collisions happen
between orbits under Frobenius and negation, not between points. The pieces:

- **Assignment.** `work_assignment` gives each node its slice of a `2^48`
  seed-slot space per epoch, derived from public inputs. There is no
  coordinator, and overlap wastes compute without harming correctness.
- **The unit.** An orbit is named by the least rotation of the normal-basis
  x-coordinate. Paying on that name makes the 262 relabellings of one orbit
  worth one payment, not 262.
- **The certificate.** Eight per-branch step counters collapse a trail to one
  scalar. Checking an orbit costs one double scalar multiplication, about 227
  group operations, where producing it costs about 4 × 10^7. Without the
  witness an orbit is free to invent; with it, faking one costs a real trail.
- **The residual fraud.** A walker that ignores the walk's branch rule
  produces orbits that verify and never collide. Sampled re-walks
  (`tools/orbit_dp.py audit`) catch it and feed `cairn attest slash`, so an
  attestor who vouched for the claim loses their bond. The submitter posts no
  bond in Stage 0 and keeps one payment; submission bonds are what would make
  it cost them (`docs/threat-model.md`, the private-walk row).
- **The payoff.** A second arrival at an orbit is the collision. Its finder
  commits the discrete log to the separate answer objective in the same epoch.
- **Try it:** `./scripts/orbit-demo.sh` runs the whole loop on a 21-bit
  instance: post, walk, submit, settle, collide, claim the answer.

What stops a real run:

1. **Storage.** The search produces about `2^35.5` orbits, roughly 6.8 TB as
   claim artifacts, and today every verifying node holds the whole log. So the
   posted objective funds a tranche: 2,097,152 orbits, about 1/24,000 of the
   search.
2. **Collision detection at that size** needs the orbit table sharded across
   nodes by orbit name. `src/shards/` has the erasure coding and per-chunk
   commitments, and is not on the network transport.
3. **The GPU client lives outside this repository** (`aburan28/crypto`,
   `ecc2k130/`) and must be changed to emit the witness counters.
4. **The sandbox has no GPU access** (`src/verifiers/sandbox.rs`). That is fine
   for piecework, whose checker verifies output rather than execution, and it
   matters for general work orders (item 10).

**Where memory comes in** is exactly that table. Walkers are compute-bound and
need little memory. The distinguished-orbit index, which is terabytes and hot
for collision checks, is what memory and disk contributors hold, and what
availability undertakings already know how to pay for. On the compute side:
at the client's stated 1.4 × 10^10 steps a second per GPU, the expected
`2^60.8`-step search is about 4.6 GPU-years. That is a question of hundreds of
GPUs, not of a national lab. The design note itself declines to claim that
rate once counters are added, so item 11 measures it before anything is
promised.

### Can a node prove its CPU, GPU, memory and bandwidth use? With a zero-knowledge proof?

**Not in the sense asked, and the plan does not pretend otherwise.**
Utilisation is a physical measurement taken by software the node controls. A
signature proves *who said* "71% CPU", not that it is true. A SNARK proves that
a given computation produced a given output, not how busy a machine was while
it happened. Proving costs orders of magnitude more than the computation it
proves, so zero-knowledge is for small, high-value checks. For ECC2K-130 the
orbit witness is already a far cheaper certificate than any SNARK would be.

What can be done, in increasing strength:

1. **Signed self-reports**: CPU model and cores, RAM, GPU and VRAM,
   utilisation. Signed by the node's identity, shown as *self-reported*, used
   for scheduling, **never for payment**.
2. **Capacity proofs by challenge**: answers that are only possible with the
   claimed resource, returned before a deadline.
   - GPU throughput: a large matrix product checked with Freivalds' algorithm,
     `O(n²)` to check an `O(n³)` answer.
   - Memory and disk: proofs of space.
   - Memory bandwidth: a latency-bound walk over a large buffer from a random
     seed.
   - Network: timed transfers of random data.

   These are statistical, and a resource can be rented for the length of a
   challenge, so they are good for reputation and scheduling, not payment.
3. **Hardware attestation**, where it exists: Intel TDX, AMD SEV-SNP and NVIDIA
   confidential computing can bind a report to real hardware under vendor
   trust. It is absent from most consumer machines, so it is optional.
4. **Pay for verified output only.** This is what the protocol already does
   (piecework, canaries, bonded attestations, fraud proofs), and it is the only
   layer that decides money. The dashboard's headline number is verified work;
   telemetry sits beside it, labelled.

### No built-in cryptocurrency, but every piece for one?

Most of the pieces are already built. Integer units under checked `u128`
arithmetic; a supply declared once, in the log's genesis prefix
(`records::Issuance`); rewards escrowed from the funder when a supply is
declared; per-tier non-fungible balances (`src/tier.rs`); bonds on
undertakings, challenges and attestations, with slashing; and conservation
audits in both implementations. What is missing is the **rail**, the seam
where external value enters and leaves, plus sponsorship. Items 14 and 15
design both. The default build ships no rail: a log's supply is whatever its
genesis declared, and a deposit is refused because no rail is declared to
attest it.

### Classic McEliece, lattices, SQIsign, "never just one", Threefish and Serpent

**What the repository records about McEliece.** Nothing on `main`. The
unmerged branch above cites the 2026 syzygy distinguisher and the
subexponential and quasipolynomial key-recovery results on Goppa codes that
followed. It also states that none of them is a practical break of the
`mceliece348864` parameters. There is no record of an AI-agent finding. So
item 4 starts by writing the finding down with its source: a scheme-level
break, a flaw in the `classic-mceliece-rust` crate, and a finding about how
cairn uses McEliece call for different responses. The plan does not depend on
which it was, because it stops depending on any one KEM either way.

**The instinct is right, and the tree is part of the way there.** For sealed
submissions, KEM legs already combine additively: a bundle is as strong as its
strongest leg, never negotiated down. The transport does not use the bundle,
so every p2p session key rests on McEliece alone. Signatures and the symmetric
layer each rest on one primitive, and identity rests on McEliece
specifically. Items 4–7 fix that in
order of consequence: registry, KEM and identity, record signatures, cipher
cascade. A caution on each of the requested primitives:

- **SQIsign** is attractive for its roughly 150-byte signatures. It is not
  standardised: it is in NIST's additional-signature process, implementations
  are research-grade, and there is no audited Rust. It is isogeny-based, and
  SIKE's 2022 collapse did not touch it but is a reason for humility. It
  enters as an optional *third* leg only, never as a replacement.
- **Serpent and Threefish** are both conservative. Serpent was designed for
  bitslicing and Threefish is add-rotate-xor, so both run in constant time
  without tables. That matters because the reason AES is banned here is
  table-lookup timing in software. They enter as a cascade in which either
  cipher alone suffices, with known-answer tests.
- **Skein** is a hash, as you said. Content addresses stay SHA-256 forever.
  Swapping them would move every id, so a migration re-commits under a new
  suite and never replaces.

## The fifteen items

Grouped into four phases by dependency, not by size. Items within a phase can
run in parallel. Each says why it matters, what exists today, what it takes,
when it is done, and which of the repository's invariants it touches.

### Phase 0: be findable, with no single point of failure

#### 1. Seeds that answer, and more than one

- **Why.** One seed is one machine. It has been down for two weeks, and every
  newcomer without a LAN peer has been alone for that time.
- **Today.** #168 compiles `launch/seeds.json` into the binary, has the
  daemon ask each seed for its key (kept only if it hashes to the listed id),
  runs that on its own thread, and logs a failure with the seed's name.
  `CAIRN_SEEDS` swaps or disables the list.
- **Work.**
  - Restart `us-west`.
  - Recruit at least three operators on different providers and continents.
    `cairn seeds publish` plus a pull request is the whole procedure.
  - Make `node-sync` failures alert a human instead of failing silently.
  - Add a peer cache so a node that connected once needs no seed again. It is
    a small file, and `store::exposure` must learn to classify it.
- **Done when.** A fresh app on a clean machine syncs the published log
  within a minute with any one seed down.
- **Touches.** No consensus.

#### 2. A rendezvous nobody operates: the Mainline DHT

- **Why.** Seeds are a better anchor than none, but each is still an operator.
  This is the answer to "no single point of failure".
- **Work.**
  - Announce and look up under a network key (BEP 5).
  - Publish the node's signed peer record as a BEP 44 mutable item under its
    ed25519 identity.
  - Publish the seed list as a BEP 44 item under a maintainer key, so it can
    change without a release and without GitHub.
  - Either adopt the `mainline` crate (check it against
    `tests/cipher_policy.rs` first) or write a minimal KRPC client.
  - SHA-1 infohashes are fine here: they are a meeting place, not a security
    boundary.
  - Rotate the announce key per epoch, as the beacon-derived rendezvous in
    [discovery.md](discovery.md) proposes, so a crawler cannot enumerate cairn
    nodes forever from one key. Offer an opt-out.
- **Done when.** With every seed down and no LAN, two fresh nodes on different
  networks find each other.
- **Touches.** No consensus. Threat-model rows: DHT eclipse (liveness only),
  and a new row for global enumeration.

#### 3. Reachable from behind a home router

- **Why.** A node that can only dial out can fetch and cannot serve. The
  network is then as centralised as the handful of public hosts, whatever the
  protocol says.
- **Today.** NAT-PMP exists (`p2p::portmap`). The app binds `127.0.0.1`. The
  handshake has no pre-authentication rate limit, and [p2p.md](p2p.md) says
  exposing `accept` without one is a mistake.
- **Work.**
  - The rate limit first, then have the app listen on all interfaces.
  - Observed-address echo in the handshake (the STUN role).
  - UPnP-IGD and PCP beside NAT-PMP.
  - TCP simultaneous-open hole punching, coordinated through a peer both
    sides can reach.
  - Volunteer relays for symmetric NATs (the TURN role).
  - **Owner decision (2026-09-25):** TLS and QUIC are allowed as a written
    exception for NAT traversal and hole-punching. The PQ KEM handshake remains
    peer authentication; TLS/QUIC is reachability, not a substitute. Prefer
    QUIC (`quinn` / iroh) for UDP + hole-punch, with the existing handshake
    still binding the peer id.
- **Done when.** Two home-NAT nodes with no public host sync directly, or
  through a volunteer relay when they cannot.
- **Touches.** No consensus. Threat-model rows for relay abuse and the DoS
  asymmetry. Item 5 shrinks that asymmetry: ML-KEM decapsulates in
  microseconds, where McEliece takes 12 ms.

### Phase 1: re-found the cryptography, before any real money

#### 4. Inventory, registry, and the McEliece question in writing

- **Work.**
  - Rebase the stranded registry branch onto `main`: policy versions, suite
    statuses, and `min_families = 2` for anything sealed.
  - A test that fails when a primitive is used outside the registry, extending
    `tests/cipher_policy.rs`.
  - A known-answer test for every primitive. Round trips prove
    self-consistency, never correctness (AGENTS.md).
  - A dated note of what was found against McEliece and by whom.
  - Mark what is quantum-vulnerable but acceptable: the RSA-group VDF and
    drand's BLS need only be unpredictable *at the time*.
- **Done when.** Every primitive in the tree is named in one registry with a
  status and a vector.

#### 5. Hybrid KEM with forward secrecy; identity no longer welded to one KEM

- **Why.** The handshake is McEliece alone: the bundle's optional ML-KEM and
  HQC legs never reach a session key, so every recorded session rests on one
  assumption. `PeerId = sha256(McEliece public key)`, so McEliece cannot be
  demoted without changing every peer id. Static keys give no forward secrecy
  (a stated weakness in [p2p.md](p2p.md)). And the 261 KiB cleartext hello is
  the most fingerprintable thing on the wire.
- **Work.**
  - Make identity the hash of a *signing* key, with signed rotation records,
    so KEM keys can change under it.
  - Mandatory legs: **ML-KEM-1024** (lattice, FIPS 203) and **HQC** (code
    based, but with no hidden Goppa structure; NIST selected it in 2025 as the
    second KEM).
  - McEliece becomes optional and deprecated for new identities, still
    verified on old material.
  - Add an **ephemeral** ML-KEM leg per session for forward secrecy.
    Generating an ML-KEM key takes microseconds, where McEliece takes 243 ms,
    which is why this was impossible before.
  - Consider X25519 as an extra leg. The current ban exists because X25519
    *alone* sealed submissions. Inside a combiner it cannot weaken anything,
    and it hedges against bugs in young PQ code. If adopted, the policy test
    changes to enforce "never alone" rather than "never".
- **Done when.** A session's key depends on at least two hardness families
  plus an ephemeral leg, and removing McEliece changes no identity.
- **Touches.** Transport-only: no record ids. Both implementations need the
  new identity derivation only where the log names transport ids.

#### 6. Hybrid signatures on every record, without moving an id

- **Why.** `submitter` is 64 hex characters, and those characters *are* an
  ed25519 key. Claims, attestations, challenges and funding signatures are
  therefore forgeable by a quantum adversary, and those records move money.
  Checkpoints use ML-DSA-65, also alone.
- **Work.**
  - Add a post-quantum signature field that is **omitted when absent**, so no
    existing id moves (the rule `Objective::confidentiality` set), carrying
    ML-DSA-65. Publish the ML-DSA key once, in an identity record, and
    reference it by hash, so it is not repeated per record.
  - A policy epoch after which admission requires both signatures.
  - The audit rule in **both** implementations, and new vectors **beside**
    the frozen ones. The reference verifies only ed25519 today (its crypto
    dependencies are `sha2`, `ed25519-dalek` and `bls12_381_plus`). It needs
    its own ML-DSA verifier, from a different library than the main crate's
    `ml-dsa`, the way drand is checked on two BLS libraries.
  - Rare, high-value signatures (checkpoints, the seed list, releases) use
    ML-DSA-87 plus SLH-DSA, the hash-based scheme and the most conservative
    assumption available.
  - **Owner decision (2026-09-25):** SQIsign **yes** as an experimental third
    leg behind a feature flag, once the hybrid ML-DSA field and registry are
    live. Not a sole signature.
  - Not FN-DSA (Falcon): its signing samples with floating point, and the
    repository forbids floats near identity.
- **Cost, stated.** About 3.3 KB per signed record with ML-DSA-65.
- **Done when.** A log in which every signature after the policy epoch is
  dual audits clean in both implementations, and one in which an ed25519-only
  record appears after it does not.
- **Touches.** **Consensus.** Both implementations, conformance vectors
  (added, never regenerated), `scripts/differential.sh` and the adversarial
  corpus.

#### 7. A symmetric cascade in which either cipher alone suffices

- **Work.**
  - Encrypt with two independent keystreams XORed together (ChaCha20, and
    Serpent-256 or Threefish-512 in counter mode), with keys split from the
    KEM combiner by separate KDF labels.
  - Two authentication tags (Poly1305 and HMAC-SHA-512), encrypt-then-MAC,
    both required.
  - At rest first, because a sealed store outlives the binary that wrote it;
    Threefish's tweak fits a sealed line naturally, with the line number as
    the tweak. Transport second.
  - Published vectors for each primitive (NESSIE for Serpent, the Skein
    submission's for Threefish), plus cascade vectors produced by an
    independent implementation, the way the conformance vectors were.
- **Cost, stated.** Two to three times the CPU on bulk transfer. The
  symmetric layer is the least likely to fail, so this buys insurance against
  unknown cryptanalysis and implementation bugs, not a fix for a known
  weakness.
- **Done when.** A store sealed by the cascade opens byte for byte against the
  independent vectors, and a store sealed before the change still opens.
- **Touches.** At-rest format, with a version byte and the old format still
  readable; the transport context strings. `tests/cipher_policy.rs` grows an
  allow-list for `serpent` and `threefish`.

### Phase 2: from bounties to distributed computation

#### 8. Decide who orders a multi-operator network

- **Why.** This gates money between operators. Records converge by union, but
  settlement order and "who moved the frontier first" are per-log, and
  [p2p.md](p2p.md#still-open) leaves both open.
- **Owner decision (2026-09-25).** Causal detection with Lamport / vector
  clocks (or the cite DAG), game-theoretically solid settlement that clocks
  **never** feed, per-objective sequencer for admission, surface frontier
  conflicts. Design note:
  [design/multi-operator-ordering.md](design/multi-operator-ordering.md).
- **Options.**
  - (a) One sequencer per objective, named in the objective by a field that
    is omitted when default. This is closest to today, and discretion is
    already small: commit-reveal hides content, and the beacon orders batches.
    The residual power is censorship, which sealed submissions and the
    committee already attack.
  - (b) A federation of sequencers under BFT agreement. No token, but it
    needs membership governance.
  - (c) Anchor settlement roots to an external chain. This is roadmap Stage 3,
    and it pays fees through a rail.
- **Recommendation.** **(a) now**, with vector-clock / cite conflict
  surfacing. Design (c) as an optional OpenTimestamps anchor. Take (b) only if
  cross-objective atomicity turns out to matter. Settlement order stays
  `H(beacon ‖ commitment_hash)` — never Lamport time, never arrival time.
- **Touches.** **Consensus.** Both implementations. The arena needs a
  sequencer-censorship scenario.

#### 9. Work orders: submit a computation, volunteers pick it up

- **Why.** This is the vision for *distributing research search*, not for
  renting GPUs. The owner lock: Cairn is a censorship-resistant knowledge
  network (Library of Alexandria), not a cloud provider. The resolution is to
  keep the principle, *pay for verified output, never for hours*, and add the
  layer that distributes work under it. The repository's thesis survives; the
  non-goal's wording names the marketplace so nobody builds one by accident.
- **The shape.** A work order is an objective carrying:
  - pinned code (a WASM module or a container image digest);
  - input blobs;
  - resource requirements (item 10);
  - a unit definition over an input range;
  - a price per verified unit;
  - a **verification strategy**, one of four:
    - an output checker, as with piecework today;
    - k-of-n replication with bonded attestations;
    - sampled re-execution, as with the orbit audit;
    - bisection over a stepper, as `src/challenge.rs` does.
- **What it reuses.** Leases are `work_assignment`. Results are blobs through
  `p2p::swarm` and `src/shards/`. Payment is `src/piecework.rs`.
- **Scope, stated.** Inputs are public. Confidential workloads need TEEs or
  FHE, and `sealed` confidentiality is already refused until ZK verification
  exists.
- **Done when.** Somebody who does not run a node posts a work order from the
  app, three volunteers' machines pick up its units, and the settled log
  shows which units each verified and who was paid.
- **Touches.** **Consensus** (a new objective shape), both implementations,
  `spec/`, and the arena for replication collusion.

#### 10. Resource-aware assignment and a GPU-capable sandbox

- **Work.**
  - Units declare CPU, RAM, VRAM and GPU class, disk and wall time. Nodes
    advertise capacity, signed and challenge-checked (item 12).
  - Assignment weights by capacity, with weighted rendezvous hashing over the
    same public inputs, so anyone can still recompute a peer's share.
  - `src/compute.rs` already has capability-aware worker routing, written and
    never compiled. Start from it once its request envelopes move from X25519
    onto the KEM bundle, and keep its own rule that capabilities are routing
    hints, not proof of work.
  - GPU work runs outside the bubblewrap jail, because passing `/dev/nvidia*`
    into it would void the jail. The options are a VM with device passthrough,
    or gVisor's GPU proxy. The threat model says plainly that GPU isolation is
    weak everywhere, so GPU units run only from objectives the contributor
    opted into.
- **Done when.** A unit needing 24 GB of VRAM is assigned only to nodes that
  proved 24 GB, and runs confined.
- **Touches.** Assignment is consensus-adjacent: it is derived, not stored,
  but two implementations must agree on it, so it gets conformance vectors.

#### 11. ECC2K-130 end to end: the model citizen

- **Work.**
  1. Measure the client's throughput *with* witness counters. Everything else
     waits on this number.
  2. Put the client, or a reference kernel, in a work pack the app can run.
  3. Wire `src/shards/` onto the network transport as a distinguished-orbit
     index, sharded by orbit name, erasure-coded, and paid through
     availability undertakings. This is the memory contribution.
  4. Stop claims carrying orbits in every node's log. The log carries batch
     commitments, and the index carries the orbits, checkable against those
     commitments.
  5. Detect a collision at the shard that owns the orbit, and hand it to the
     answer objective.
- **Done when.** A tranche larger than any one machine's disk runs across
  volunteers, and the synthetic 23-bit twin runs the whole pipeline in CI.
- **Touches.** **Consensus** for step 4. `docs/design/orbit-piecework.md` §6
  names exactly this gap.

### Phase 3: trust, onboarding, money

#### 12. Signed telemetry, capacity proofs, and a dashboard that pays on verified work

- **Work.**
  - Telemetry reports gossip as signed, expiring hints, like peer hints and
    never in the log, because "busy right now" is not permanently true.
  - Capacity challenges are recorded as attestations by the challenger:
    permanent, and slashable if forged.
  - A network page (the node's `/ui/` and the published site): per node,
    verified work first (orbits verified, claims settled, attestations
    unslashed, availability answered), then challenge results, then
    self-reports, each labelled for what it proves.
- **Done when.** A node claiming a GPU it does not have shows a failed
  challenge on the dashboard, and nobody's payout changed because of what it
  claimed.

#### 13. Launch, log in, contribute

- **Work.**
  - First run: data folder and limits (built, #164), join the network (items
    1–3), connect a model, set budgets, start.
  - **Connect a model:**
    - an API key for Anthropic, OpenAI, Fireworks, OpenRouter, or a local
      Ollama, llama.cpp or vLLM server, stored in the OS keychain;
    - OAuth where a provider supports third-party apps (OpenRouter's PKCE
      flow issues a user-scoped key);
    - or "use my agent", which writes the Claude Code or Codex MCP stanza
      (`scripts/mcp-config.sh` already does this).
  - An in-app agent loop over the existing tools: list, get, generate, score
    many times, commit, reveal after the epoch turns. The rules the MCP server
    enforces (score before submit, capability-bound citations, statements
    treated as untrusted) apply unchanged.
  - Daily and per-objective spend caps.
- **Stated, not buried.** Consumer subscriptions (Claude Pro/Max, ChatGPT)
  are licensed to a person, and their terms restrict third-party use of the
  login and sharing it. The design therefore has contributors run **their
  own** agents on public objectives with their own keys. It does not route
  other people's prompts through anyone's account.
- **Done when.** A new user goes from download to a revealed claim without a
  terminal.

#### 14. Ideas and sponsorship

- **Work.**
  - A `proposal` record: an objective draft with a funding target and a
    deadline.
  - `pledge` records, each locking a sponsor's balance like a bond.
  - Activation is **derived**, like a verdict, never stored: when pledges
    reach the target before the deadline, the objective is funded from them
    pro rata. Otherwise every pledge returns. This is an assurance contract.
  - Refunds need a rule, not just a record. Today an objective's escrow never
    returns, and its `deadline` field is enforced by nothing: it is part of
    the id, and no rule reads it. So "the deadline passed, the money goes
    back" is new consensus in both implementations. The simpler alternative is
    append-only `objective_funding` records that top up one objective from
    many funders. It needs no activation rule, and it offers no refund either.
  - Optionally, a proposer share of settlements, so an idea earns for its
    author the way a citation does.
  - "Approval" needs no committee, because the pinned verifier already
    decides truth, and money decides priority.
  - Quadratic funding later, and only with item 15, because it is
    Sybil-fragile.
- **Done when.** An identity with zero balance posts a proposal, three
  sponsors fund it, it settles, and a failed proposal returns every unit, all
  re-derived by both audits.
- **Touches.** **Consensus.** Both implementations, and the arena for pledge
  griefing and self-sponsorship.

#### 15. Settlement rails with no currency built in, citation flow that pays, and pricing identity

- **Rails.**
  - A genesis-declared rail key or keys.
  - `deposit` records (rail, external reference, holder, units, rail
    attestation) admissible only when a declared rail attests them.
  - `withdrawal` records that burn units and name the destination.
  - The audit extends conservation to *issued + deposited − withdrawn = held
    + escrowed + locked*.
  - The default build declares no rail. Adapters live out of tree: an L2
    escrow contract, Lightning, a custodial fiat processor. Each is a trust
    boundary the log names, never one it hides.
  - Declare a supply on the published log, so the accounting it already has
    is switched on.
  - The site already accepts Solana wallets as Ed25519 identities
    (`ui/lib/wallet.ts`). That is a signer, not a rail, but a Solana-based
    adapter would credit the very key a user already signs with.
- **Citation flow: make it pay, or stop calling it income.** A settlement
  credits the whole reward to the claim's submitter (`gross_paid_within`), and
  `cairn attribute` computes the citation split as a report that no balance
  reads. Crediting it is a consensus change in both implementations. The rule
  in `tests/knowledge.rs` that a relation never pays must survive it, since
  only `cites` may.
- **Identity cost (Sybil).** Price it per use rather than once:
  - stake through a rail, for committee seats;
  - capacity-proof identities, for eclipse resistance;
  - vouching with slashing, or external proof of personhood, for sponsorship
    matching.
- **Done when.** A deposit and a withdrawal through a test rail audit clean in
  both implementations, and a forged deposit does not. The arena shows a
  sixteen-key sponsor earning what a one-key sponsor earns. And
  `cairn balances` agrees with `cairn attribute` to the unit, or the guidance
  no longer promises citation income.
- **Touches.** **Consensus.** Both implementations, the arena, and
  `docs/threat-model.md` (a new row per rail).

## What to do first

1. **Operator actions, today.** Restart the `us-west` host. Recruit two more
   seed operators. Make `node-sync` alert.
2. **Merge [#168](https://github.com/aburan28/cairn/pull/168)**, so the app
   finds whatever seeds answer.
3. **In parallel (started on `cursor/plan-execution-phase0-50b2`):**
   - item 4 — algorithm registry (`crypto::policy`), `Family`, committee hedge
     check, [agility.md](agility.md);
   - item 8 design — [design/multi-operator-ordering.md](design/multi-operator-ordering.md);
   - gVisor jail path (`CAIRN_SANDBOX_MECHANISM=gvisor`);
   - Mainline UDP client behind `CAIRN_MAINLINE` (item 2): hints only, no CI
     dependency on the public DHT. Two fresh nodes finding each other with
     every seed down is still open.
   - still open: ECC2K-130 throughput measure (item 11 step 1). The orbit
     index lives under the shard store and keeps both witnesses; it is not
     on the swarm and it does not pay.
4. Hybrid ML-DSA-65 on a claim, omitted when absent (item 6). Admission does
   not yet require it. SQIsign level 1 is a third signature on the same
   claim, also omitted when absent, and it does not replace ed25519.
   The QUIC hole-punch is a long-header datagram, not `quinn`: linking a TLS
   stack would compile AES, which the cipher policy still refuses. The owner
   exception for TLS stands for a stack that can be ChaCha20-only.

## Owner decisions (locked 2026-09-25)

- **Ordering.** Causal clocks for conflict detection; settlement order stays
  beacon ⊕ commitment hash; per-objective sequencer for admission; surface
  concurrent frontiers. See
  [design/multi-operator-ordering.md](design/multi-operator-ordering.md).
  **Not** Lamport-ordered payouts — that is a free lottery.
- **Cryptographic policy.** SQIsign: **yes**, as an experimental / third-leg
  path once the registry and hybrid signature design land. Lattices
  (ML-KEM / ML-DSA) remain the hedge. No single suite alone. Cipher cascades
  (Serpent, Threefish) stay on the agility ladder; ChaCha20-Poly1305 remains
  the AEAD until a cascade is specified with known-answer tests.
- **Transport / TLS.** **Written exception:** TLS and QUIC are allowed for
  NAT traversal and hole-punching. The PQ KEM handshake remains the
  peer-authentication story; TLS/QUIC is the reachability layer, not a
  substitute for it.
- **Provider terms.** Contributors run **their own** agents with **their own**
  API keys. The network does not proxy or subsidize third-party LLM logins.
- **Isolation.** gVisor (`runsc`) is the stronger Linux jail; opt in with
  `CAIRN_SANDBOX_MECHANISM=gvisor`. Bubblewrap remains the default when both
  work.
- **Knowledge, not cloud.** Not a compute rental market. Distributed Library
  of Alexandria: pay for verified artifacts and knowledge, never for hours.
- **Citation flow / first rail.** Still open; not decided this turn.
- **X25519 as a combiner leg / ML-KEM-1024 vs 768 mandatory.** Still open;
  registry version 1 keeps McEliece structurally required and
  `min_families: 2`.
