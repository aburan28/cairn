# Threat model

What breaks this, and which parts Stage 0 actually handles. "Handled" below
means there is code and a test; everything else is named so it is not mistaken
for solved.

| attack | mechanism | status |
|---|---|---|
| **grinding** — flood cheap novel artifacts to inflate supply | demand-gated mint: no funded objective, no issuance. Duplicates verify and mint zero | handled |
| **front-running the reveal** — copy an artifact out of the mempool and submit it first | commit–reveal binding `H(artifact ‖ submitter ‖ nonce)`; the submitter is inside the hash so a commitment cannot be replayed under another name | handled |
| **mid-bounty rule change** — edit the evaluator after work has been done | the verifier is part of the objective's content-addressed id, so an edit forks the objective instead of rescoring it. Unrepresentable rather than guarded | handled |
| **log tampering** — rewrite a settled result | hash-linked entries; `audit` recomputes every hash and re-runs every settled verifier | handled |
| **log rollback/fork** — publish a shorter or alternate internally valid chain | daemon checkpoints sign height, head, and Merkle root with a separately pinned ML-DSA-65 root key, and `proofwork verify --from <checkpoint> --root-key <pinned>` checks the signature and recomputes head and root over the **prefix** of length `height`. A rewritten entry below the checkpoint, a truncated log, and a forked chain all fail. `--root-key` is what makes it a check: verifying against the key inside the same file authenticates nothing, so the reader must have the key out of band | handled |
| **checkpoint equivocation** — sign two different chains at the same height for two different readers | **not handled.** Each checkpoint is internally valid, so no reader detects it alone; only comparing checkpoints across readers does. Detection needs the checkpoints published somewhere append-only, which is the base-layer anchor Stage 3 argues for | **not handled** |
| **paying an unaccepted claim** | `audit` cross-checks every settlement against its recorded verdict | handled |
| **verifier-offline attack** — take checkers down so honest submissions "fail" | `UNAVAILABLE` never settles and never refutes; the objective stays open | handled |
| **verifier removal** — the *funder* deletes the pinned checker so nothing can ever settle | **not handled.** Pinning by hash prevents substitution, not removal. The checker is referenced by path, so a funder who deletes it makes every claim `UNAVAILABLE` and the escrow is never released. "The objective stays open" is the mitigation against one attacker and the attack itself from the other side. Fix: content-address pinned code and let anyone serve it | **not handled** |
| **impure verifier** — a checker reading unpinned external state passes today, fails tomorrow at the same hash | `audit` flags a settled claim that no longer re-verifies rather than reporting success | handled |
| **float divergence** — two honest nodes disagree on identity or on a threshold comparison | floats refused in canonical encoding and in evaluator scores/thresholds | handled |
| **time-as-evidence** — settle a cost claim denominated in wall-clock | `replay` refuses machine-dependent reproducible fields | handled |
| **rounding leak** in attribution | integer arithmetic, rational δ, exact-conservation tests across amounts and deltas | handled |
| **Merkle second-preimage** — two leaf sets, one root | odd nodes are promoted, not duplicated (Bitcoin CVE-2012-2459) | handled |
| **hoarding** — hide improvements so a competitor cannot extend them | progressive bounties pay for distance moved, so publishing is the profitable move and copying earns zero | handled |
| **frontier theft** — take credit for an improvement built on someone else's | an improvement must cite the frontier it beat, enforced at submission; citation flow pays the previous holder | handled |
| **epsilon-farming** — split one improvement into many to extract more *direct reward* | payouts telescope on a cumulative curve, so the pool is identical however the curve is chopped; `min_improvement` sets a floor | handled |
| **citation-flow dilution** — split one improvement into many to starve the contributor you built on | **not handled.** Telescoping protects the *direct* reward only. Citation flow decays per *hop*, not per unit of progress, so chopping is free in direct reward and strictly profitable in flow. On the README's own example, bob slicing 12→16 into four 1-point steps moves 91,408 from alice to himself — a 24% raise for work he had already done — and overturns the documented result that alice ends up ahead. Sixteen slices cost the upstream contributor 92% of their flow. `max_depth` is not a defence: decay is geometric *within* the chain, and depth 6 and 64 differ by under 0.1%. Raising δ does not help either. Pinned in `tests/incentives.rs`; the fix is distance-weighted attribution (see below) | **not handled** |
| **frontier rollback** — replay an old lower score as the current best | `audit` rejects a frontier that moves backwards, and a pool paid beyond its size | handled |
| **gossip score inflation** — assert a huge score to evict real candidates from a bounded population | `gossip.ingest` re-scores locally and drops what does not reproduce; verification costs one evaluation. Now enforced on the wire too: `p2p::pop` re-scores every arriving candidate and a scorer that cannot answer is a refusal, never an acceptance | handled |
| **population scoring amplification** — volunteer candidates so a peer burns evaluations on them | only candidates this node explicitly asked for in its `pop_want` are scored; anything else is dropped before the scorer runs, and message ceilings are checked against the declared array length before allocation. The bound that remains is the one the objective sets: a node that *has* asked for 512 candidates for an expensive objective still pays for 512 evaluations | partial |
| **population frame confusion** — smuggle candidates through the record path, or records through the population path | the two families use different AEAD context strings, so a frame sealed for one does not open as the other; and `candidate` is not an exchangeable record kind, so a body that somehow arrived on the record path is refused there too | handled |
| **eclipse via peer sampling** — surround a node with identities you control so it never hears an honest peer | **not handled.** The daemon dials a uniformly random subset of its address book each tick, which fixes the propagation problem (no peer is structurally last) and does nothing about Sybils: an attacker holding *n* of the *m* entries gets *n/m* of every node's connections. Entries are still bootstrap-file only, so today the operator chooses them, which is a configuration answer and not a protocol one. Resisting a forged peer set needs a structured overlay with identities that cost something — Stage 2 | **not handled** |
| **CRDT divergence** — nodes silently disagree after seeing the same messages | merge is commutative/associative/idempotent with pruning proven safe; identity includes the claimed score so disagreement is representable rather than order-resolved | handled |
| **verification-cost amplification** — offer a peer many records whose verifier is expensive | **partial.** `p2p::sync` caps records per message, but runs the verifier on every one. With a minutes-long verifier (the ECDLP cost challenge builds Rust and runs 32 trials) a single 512-record message buys hours of CPU. Relaying does not require verification — content addressing makes it safe — so the fix is to separate accept-for-relay from verify-for-settlement | partial |
| **handshake CPU amplification** — send cheap KEM ciphertexts to make a listener decapsulate | `p2p::transport` bounds frames, but the listener must rate-limit or authenticate sources before `accept`; the 12 ms McEliece decapsulation cost is intentionally not hidden in the library | partial |
| **unauthenticated initiator claim** — claim another peer id when opening an inbound stream | the KEM authenticates the responder only. `Service` exposes the claimed id and leaves admission to the deployment; signed mutual authentication is not wired in | partial |
| **verifier code unavailable to a peer** — a peer holds the objective but not the pinned checker | **not handled.** `p2p::sync` exchanges `objective`, `commitment` and `claim`; it does not exchange verifier code, which is referenced by local path. A peer without the file returns `UNAVAILABLE` and cannot derive settlement at all. `tests/p2p_convergence.rs` passes only because both nodes share a filesystem root — it demonstrates convergence *given* shared code, not code distribution | **not handled** |
| **region squatting** — grind an identity onto a region and leave it unsearched | assignment mixes a per-epoch beacon, so squatting costs a fresh grind every epoch | partial |
| **beacon grinding** — a sequencer picks the epoch anchor to place itself favourably | none. The beacon is derived from ledger heads and is grindable by a sequencer free to choose them. Needs a VDF or threshold signature. Now worth more than it was: the same beacon orders settlement within an epoch, so grinding the anchor moves money and not only work assignment | not handled |
| **in-flight front-running** — watch a submission land, submit marginally better | commit–reveal is epoch-batched: a reveal is refused unless its epoch is strictly later than its commitment's, so an artifact only becomes visible in an epoch where nobody can still commit against it. `min_improvement` raises the bar on top of that. What remains is the epoch boundary itself — an artifact revealed early in epoch N+1 can be committed against in N+2 like any other published result, which is the ratchet working rather than an attack | handled |
| **settlement reordering** — a sequencer orders same-epoch reveals to pay itself first | a closed epoch's accepted claims settle in order of `H(beacon(epoch, anchor) ‖ commitment_hash)`, not arrival, and `audit` recomputes that order and names a batch that deviates. Keyed on the *commitment* hash rather than the claim id on purpose: the anchor is public by reveal time, and a submitter who could restamp `created_at` or add a citation would be grinding their own rank | partial; the anchor is a ledger head and a sequencer can still grind **that** (see **beacon grinding**) |
| **censorship** — withhold a competitor's reveal past a deadline | none at Stage 0: one sequencer, no forced-inclusion path. This is the *primary* security property and the main argument for anchoring to a base layer | not handled |
| **malicious objective code** — author ships a checker that attacks contributors | **partial.** Every spawn of objective-authored code goes through an OS jail: bubblewrap on Linux, a seatbelt profile on macOS. No network of any kind, writes confined to a scratch directory deleted afterwards, a wall-clock deadline, best-effort `RLIMIT_CPU`/`RLIMIT_AS`, and a scrubbed environment for pinned pure functions. Four gaps remain and are named in `verifiers::SANDBOXING`: a kernel or policy bug is still an escape (gVisor/Firecracker/WASM would bound it); the seatbelt profile denies writes and network but **not reads**, so on macOS objective code can read anything the operator can, it just cannot transmit it; `replay` and `lean` inherit the operator's environment because their toolchains are configured through it; and on a host with neither mechanism the child runs unconfined unless `PROOFWORK_REQUIRE_SANDBOX=1`, which makes it `UNAVAILABLE`. The Python reference does **not** jail and says so | partial |
| **statement-borne prompt injection** — an objective's `statement` tells an agent reading it to cite the author's claim, or to submit elsewhere | `proofwork-mcp` tracks provenance: a claim id offered through a structured field is citable, an id seen only inside a rendered statement is not, and `submit_claim` refuses the difference. Statements are also fenced, labelled untrusted, and flattened so they cannot forge rows. This removes the path by which an attacker *plants* a citation; it does not make citations earned (see **spurious citations**) | handled |
| **verifier gaming** — satisfy the checker, miss the goal | partly: per-verifier screens (Lean escape hatches, invalid-input scoring). Structurally needs adversarial review of every verifier *before* funding, plus held-out tests and a paid red team | partial |
| **spurious citations** — cite everything to farm attribution | δ decays with depth, bounding the payoff. Validators slashing bad edges is designed, not built | partial |
| **self-dealing** — fund a bounty you have already solved | statement commitment must predate any witness; funder ≠ solver for protocol pools. Not enforced here (no identity layer) | not handled |
| **sybil on judgement stake** | operator attestation, concentration caps. Mitigation, never prevention | out of scope at Stage 0 |
| **rubber-stamp verification** — attest without checking (verifier's dilemma) | canaries, bonded challenge windows, interactive fraud proofs. Only arises when verification is expensive, i.e. Stage 2+ | out of scope at Stage 0 |
| **result withholding** — find something extraordinary and walk away | escrow makes it cost the bounty. Nothing makes it impossible | unsolvable |
| **post-hoc statistics** — choose the success criterion after seeing data | the `statistical` verifier puts the pinned statistic, its sha256, the threshold, the direction and the seed inside the objective, so all of them are part of its content-addressed id. Picking a criterion after seeing the data means posting a *different* objective with a different id, in public, after the fact | handled |
| **seed shopping** — rerun a Monte Carlo statistic until one draw clears the threshold | the seed is pinned in the objective and passed to `statistic(artifact, seed)`; the same artifact therefore always produces the same number on every honest node. A submitter can still search *artifacts* against a fixed seed, which is the objective doing its job | handled |
| **malformed objective input to a schema** — post a record that decodes but means something else | `post` and `reveal` validate the JSON body against `spec/objective.schema.json` / `spec/claim.schema.json` *before* decoding it, and refuse rather than append. Both implementations interpret the schema documents rather than reimplementing them, so a schema change cannot silently apply to one and not the other | handled |

## Slicing, and why telescoping is not enough

The ratchet was built on a specific promise: **chopping an improvement into
small steps pays exactly what one big step pays**, so publishing partial results
early costs nothing and the hoarding incentive disappears. `frontier.rs` proves
that for the direct reward, and the proof is correct.

It is only half the mechanism. A settled claim also *sends* value upstream, and
that flow decays per citation **hop**. Chopping adds hops. So:

| | alice | bob | carol |
|---|---|---|---|
| as published in the README | 425,000 | 375,000 | 300,000 |
| bob slices 12→16 into four 1-point steps | 333,592 | **466,408** | 300,000 |

bob does identical work for an identical direct reward and takes 91,408 from
alice. He is not exploiting a bug in the arithmetic — every claim is a genuine
improvement and every payment is conserved. He is responding to the incentive
the mechanism actually creates, which is not the one it was designed to create.
A participant who declines to slice is leaving money on the table, so this is
the dominant strategy rather than an exotic attack.

**The fix, and what it costs.** Attribution asks the citation DAG "how many hops
back?", when for a ratcheted objective the frontier ledger already records the
better answer: `(claim_id, holder, score, paid_cumulative)` gives the *distance*
each submitter moved, and distance is invariant to chopping by construction.
Weighting flow by distance rather than hop count makes slicing neutral, which is
what telescoping was already committed to.

The cost is that distance-weighting must aggregate per **submitter** to stop a
slicer's own steps paying each other — and that requires an identity layer.
Under sybils, one participant can present as several and the aggregation fails.
So this is a case where the roadmap ordering is load-bearing rather than
cosmetic: **identity is a prerequisite for fair attribution, not a later
convenience.** Slicing-invariance and sybil-resistance cannot both be had
without it.

## Agents as contributors

`proofwork-mcp` lets an agent pull objectives and submit against them. That is
mostly *good* for this threat model: an agent that hallucinates an answer gets a
`REJECT`, earns zero, and costs the network nothing. The design never needed the
contributor to be reliable — only the checker to be pinned — and a language
model is exactly the high-volume, sometimes-wrong producer it was built to
absorb.

Two things do get worse, and both are new rows above rather than existing ones
made larger:

- **Statement-borne prompt injection.** Under citation flow this is a financial
  attack: injected text that gets an agent to cite the attacker's claim routes
  real money upstream. It needs no code execution, so the verifier sandbox does
  not address it. Handled by provenance tracking in the MCP server — an id that
  appeared only in attacker-controlled prose cannot become a citation. Note the
  boundary: this stops a citation being *planted*, and says nothing about
  whether a citation the agent chose itself was earned.
- **Secrets in transcripts.** Agents log what they see. The MCP server therefore
  generates and consumes the commit–reveal nonce internally and never returns
  it; a nonce in a transcript is a broken commitment. The same argument will
  apply to signing keys when the identity layer lands — they must live behind
  the server, never in an agent's context.

See [agents.md](agents.md).

## Sensitive results

A network pointed at cryptographic or biological problems will eventually
verify a result that should not be published the moment it settles. **An
auto-publishing bounty contract is an auto-publishing zero-day pipeline.**

Embargo paths, sensitive-objective classes, and a coordinated-disclosure process
have to exist *before* the network has users, because they cannot be retrofitted
onto an immutable settlement layer. Stage 0 has one operator and a private log,
which is the only reason this is not yet urgent — it becomes urgent the moment
anything is published or permissionless.

**Partly addressed.** An objective now declares a confidentiality class
(`public` / `embargoed` / `sealed`) that is part of its content-addressed id, so
it cannot be changed mid-bounty and cannot be retrofitted — which is exactly why
it had to land before objectives are funded rather than after. `sealed` is
refused at validation rather than silently downgraded, so its cost is explicit.

What remains unbuilt is enforcement: nothing yet withholds an `embargoed`
artifact at settlement time. The class is declared and binding; the mechanism
that honours it is not wired up. Until it is, this row is **partial**, and an
`embargoed` objective offers a promise the code does not yet keep.

## What Stage 0 explicitly does not defend

There is no identity layer, no stake, no dispute mechanism, and no consensus.
A single operator can refuse to include a submission or can post objectives in
bad faith. What the operator *cannot* do is lie about a settled result: the log
is hash-linked and `proofwork audit` re-derives every verdict from the artifacts
themselves. That is the specific, narrow guarantee this stage makes, and
overstating it would be the first dishonest thing in the project.
