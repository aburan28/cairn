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
| **paying an unaccepted claim** | `audit` cross-checks every settlement against its recorded verdict | handled |
| **verifier-offline attack** — take checkers down so honest submissions "fail" | `UNAVAILABLE` never settles and never refutes; the objective stays open | handled |
| **impure verifier** — a checker reading unpinned external state passes today, fails tomorrow at the same hash | `audit` flags a settled claim that no longer re-verifies rather than reporting success | handled |
| **float divergence** — two honest nodes disagree on identity or on a threshold comparison | floats refused in canonical encoding and in evaluator scores/thresholds | handled |
| **time-as-evidence** — settle a cost claim denominated in wall-clock | `replay` refuses machine-dependent reproducible fields | handled |
| **rounding leak** in attribution | integer arithmetic, rational δ, exact-conservation tests across amounts and deltas | handled |
| **Merkle second-preimage** — two leaf sets, one root | odd nodes are promoted, not duplicated (Bitcoin CVE-2012-2459) | handled |
| **hoarding** — hide improvements so a competitor cannot extend them | progressive bounties pay for distance moved, so publishing is the profitable move and copying earns zero | handled |
| **frontier theft** — take credit for an improvement built on someone else's | an improvement must cite the frontier it beat, enforced at submission; citation flow pays the previous holder | handled |
| **epsilon-farming** — split one improvement into many to extract more | payouts telescope on a cumulative curve, so the pool is identical however the curve is chopped; `min_improvement` sets a floor | handled |
| **frontier rollback** — replay an old lower score as the current best | `audit` rejects a frontier that moves backwards, and a pool paid beyond its size | handled |
| **gossip score inflation** — assert a huge score to evict real candidates from a bounded population | `gossip.ingest` re-scores locally and drops what does not reproduce; verification costs one evaluation | handled |
| **CRDT divergence** — nodes silently disagree after seeing the same messages | merge is commutative/associative/idempotent with pruning proven safe; identity includes the claimed score so disagreement is representable rather than order-resolved | handled |
| **region squatting** — grind an identity onto a region and leave it unsearched | assignment mixes a per-epoch beacon, so squatting costs a fresh grind every epoch | partial |
| **beacon grinding** — a sequencer picks the epoch anchor to place itself favourably | none. The beacon is derived from ledger heads and is grindable by a sequencer free to choose them. Needs a VDF or threshold signature | not handled |
| **in-flight front-running** — watch a submission land, submit marginally better | `min_improvement` raises the bar. Epoch-batched commit-reveal is designed, not built | partial |
| **censorship** — withhold a competitor's reveal past a deadline | none at Stage 0: one sequencer, no forced-inclusion path. This is the *primary* security property and the main argument for anchoring to a base layer | not handled |
| **malicious objective code** — author ships a checker that attacks contributors | **not handled.** Pinned code runs in-process. Sandbox required before objective authorship opens | launch blocker |
| **statement-borne prompt injection** — an objective's `statement` tells an agent reading it to cite the author's claim, or to submit elsewhere | `proofwork-mcp` tracks provenance: a claim id offered through a structured field is citable, an id seen only inside a rendered statement is not, and `submit_claim` refuses the difference. Statements are also fenced, labelled untrusted, and flattened so they cannot forge rows. This removes the path by which an attacker *plants* a citation; it does not make citations earned (see **spurious citations**) | handled |
| **verifier gaming** — satisfy the checker, miss the goal | partly: per-verifier screens (Lean escape hatches, invalid-input scoring). Structurally needs adversarial review of every verifier *before* funding, plus held-out tests and a paid red team | partial |
| **spurious citations** — cite everything to farm attribution | δ decays with depth, bounding the payoff. Validators slashing bad edges is designed, not built | partial |
| **self-dealing** — fund a bounty you have already solved | statement commitment must predate any witness; funder ≠ solver for protocol pools. Not enforced here (no identity layer) | not handled |
| **sybil on judgement stake** | operator attestation, concentration caps. Mitigation, never prevention | out of scope at Stage 0 |
| **rubber-stamp verification** — attest without checking (verifier's dilemma) | canaries, bonded challenge windows, interactive fraud proofs. Only arises when verification is expensive, i.e. Stage 2+ | out of scope at Stage 0 |
| **result withholding** — find something extraordinary and walk away | escrow makes it cost the bounty. Nothing makes it impossible | unsolvable |
| **post-hoc statistics** — choose the success criterion after seeing data | test statistic and threshold registered with the objective. V3 not implemented | design only |

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
