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
| **unwinnable funded objective** — post a verifier block missing its per-kind fields, escrow against it, and no submission can ever settle | none. `post` checks the verifier *kind* is runnable, never that its spec is well-formed; per-kind fields are validated by the verifier at submission time, so the failure surfaces on the first submitter rather than the author. The registry already knows how to say `INVALID_SPEC` — it just is not asked until too late | not handled |
| **verifier-tree divergence** — two nodes with different `--root` contents reach different verdicts on the same claim | pinned code resolves from the content-addressed blob store first and by path only as a fallback, so an objective verifies on any node holding the bytes regardless of its directory layout. A node with neither still returns `Unavailable` rather than diverging, which is the `Unavailable`-never-settles rule earning its keep. What remains is distribution: `sync` carries blobs, nothing yet fetches one | handled |
| **corrupt pinned code** — the bytes on disk are not the bytes the objective named | the blob's filename *is* its digest, so `get` re-hashes on every read and refuses the bytes. Reported as `Unavailable`, never `Reject` or `INVALID_SPEC`: a damaged local cache is a fact about that disk, and letting it refute honest work or condemn a well-formed objective would be the same error in two directions | handled |
| **eviction of a live evaluator** — `store gc` reclaims the only local copy of an evaluator an objective depends on | a pin set computed from the log moves those blobs from reclaimable to pinned, so `gc` skips them and a cap that cannot be met without one is refused before anything is deleted. Every posted objective counts, settled or not, because `audit --rerun` re-verifies settled claims. Residual: the set comes from the node's own log, so `gc` against a stale log can still evict what the next sync makes load-bearing | handled |
| **verifier gaming** — satisfy the checker, miss the goal | partly: per-verifier screens (Lean escape hatches, invalid-input scoring). Structurally needs adversarial review of every verifier *before* funding, plus held-out tests and a paid red team | partial |
| **spurious citations** — cite everything to farm attribution | δ decays with depth, bounding the payoff. Validators slashing bad edges is designed, not built | partial |
| **citation dilution** — manufacture citable claims to shrink what the frontier holder receives | δ splits *evenly* across citations, so citing the mandatory frontier claim plus four self-funded ones recovers four fifths of it. Bounded today only because an agent cannot fund objectives; agent funding removes the bound and makes the supply free. Needs a reserved share for protocol-enforced citations, and a discretionary split weighted by settled reward — both before agent funding, since they re-price settled claims afterwards | design only |
| **gossip starvation** — price sub-frontier candidates and they stop circulating | none, and it may be a reason not to build the market at all. Candidates flow freely because the ratchet pays zero for them; a market makes gossiping one a giveaway of inventory, and the population is what the island model runs on | design only |
| **self-dealing** — fund a bounty you have already solved | statement commitment must predate any witness; funder ≠ solver for protocol pools. Not enforced here (no identity layer) | not handled |
| **sybil on judgement stake** | operator attestation, concentration caps. Mitigation, never prevention | out of scope at Stage 0 |
| **rubber-stamp verification** — attest without checking (verifier's dilemma) | canaries against a bonded stake. Conditional slashing provably cannot work: with no canaries, universal rubber-stamping is a Nash equilibrium at *any* penalty, because nobody is caught when nobody looks. Mechanism designed, parameters solved and tested in `src/incentive/`; not wired into settlement | designed, not built |
| **blind rejection** — reject everything without checking, collecting canary catches for free | valid canaries, plus the fact that the denied submitter is strictly motivated to dispute. False rejections police themselves; false acceptances do not | designed, not built |
| **sybil on node rewards** — present one machine as forty | pools split by stake, never per node: stake is conserved when divided, headcount is not. An even split is sybil-attracting by construction | designed, not built |
| **committee collusion** — `t` share-holders open a sealed submission early and front-run it | bonded custody: unprofitable when `V ≤ t·d·S'`. Note the residual — a sub-threshold cartel is behaviourally identical to honest members, so it assembles at zero cost and the honest profile is only ever a *weak* equilibrium | designed, not built |
| **committee censorship** — `n − t + 1` share-holders withhold, so the reveal never opens and a rival wins | attributable non-publication is slashable, and the threshold must sit in a window where neither this nor early opening pays. The window is empty for a committee too small for the value it seals | designed, not built |
| **result withholding** — find something extraordinary and walk away | escrow makes it cost the bounty. Nothing makes it impossible | unsolvable |
| **post-hoc statistics** — choose the success criterion after seeing data | test statistic and threshold registered with the objective. V3 not implemented | design only |

## The operator's own disk

Five rows above concern what the network can do to a node. These concern what
happens to a node's data when it stops being only on that node's disk -- a
backup, a synced folder, an external drive, a machine that is sold.

| attack | mechanism | status |
|---|---|---|
| **disk at rest** — a copy of the data directory is read by someone who should not | log sealed line-wise with ChaCha20-Poly1305; the chain still covers plaintext, so no hash, root or audit result changes | handled |
| **ciphertext reordering / splicing** — rearrange sealed lines, or graft one in from another log | the AEAD's associated data binds each line's position, so it fails to decrypt at that line rather than merely failing the chain afterwards | handled |
| **nonce reuse after truncation** — restore a backup, append again, reuse a nonce under one key | nonces are random per line and stored, never derived from the index. Deriving them would be smaller and would collapse the cipher on any truncate-and-reappend | handled |
| **the key travels with the data** — a key file copied into the same backup that holds the ciphertext | the default key path is *outside* the data directory; `sync` withholds key files, detected by content rather than filename, and reports them. `keygen` warns if you place one inside anyway | handled |
| **plaintext residue** — `store encrypt` leaves the unconverted original behind, and the mirror copies it | `sync` withholds `*.plaintext.bak`. **This was a real bug** in the first draft: the backup that made conversion safe was undoing the conversion at the destination | handled |
| **quota-driven data loss** — a size cap smaller than the log prunes the log to fit | the log is never an eviction candidate; the cap is refused, naming the pinned bytes, and refused *before* anything is deleted | handled |
| **live attacker on a running node** | none, and none is possible: the key must be readable for the node to work. At-rest encryption protects copies that leave the machine, and nothing else | out of scope |
| **key loss** | none. There is no recovery path, `keygen` says so, and adding an escrow would reintroduce the party the encryption exists to exclude | unsolvable |
| **key rotation** | not implemented. Re-keying means decrypting and re-sealing the whole log | design only |
| **two nodes on one synced folder** | none. One `Ledger` handle per log is the existing contract; a shared folder violates it and nothing detects that | not handled |

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


## Node operators

Five rows above are new and share a caveat worth stating once rather than five
times: they are **mechanism, not code**. `src/incentive/` contains the payoff
model, the solvers, and the parameters that make each attack unprofitable, all
tested; nothing in it runs at settlement time. A row marked *designed, not
built* means the attack has a worked answer and an unbuilt implementation --
which is better than an unanswered attack and considerably worse than a defended
one.

What the analysis adds beyond "here is a mitigation" is the size of the
parameters. A bond in the millions, a committee that grows with the largest
sealed bounty, and a canary pipeline indistinguishable from real submissions are
requirements that are cheap to discover now and very expensive to discover after
a network has operators. See [node-incentives.md](node-incentives.md).
