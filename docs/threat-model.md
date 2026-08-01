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
| **citation-flow dilution** — split one improvement into many to starve the contributor you built on | **not handled.** Telescoping protects the *direct* reward only. Citation flow decays per *hop*, not per unit of progress, so chopping is free in direct reward and strictly profitable in flow. On the README's own example, bob slicing 12→16 into four 1-point steps moves 91,408 from alice to himself — a 24% raise for work he had already done — and overturns the documented result that alice ends up ahead. Sixteen slices cost the upstream contributor 92% of their flow. `max_depth` is not a defence: decay is geometric *within* the chain, and depth 6 and 64 differ by under 0.1%. Raising δ does not help either. Pinned in `tests/citation_flow.rs`; the fix is distance-weighted attribution (see below) | **not handled** |
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
| **poisoned transfer** — a peer serves bytes that are not the blob | the manifest hashes every piece, so a bad piece is caught on arrival, discarded, and the peer dropped. The whole-blob digest is re-checked at the end, which is what catches a *bad manifest* rather than a bad piece. Piece hashes add no trust — anyone can make a manifest — they add **blame**: the lie is localised to one piece and one peer instead of costing the whole download | handled |
| **wrong-content manifest** — offer a manifest describing something else | checked against the digest the objective already committed to, before a byte is transferred. This is the step BitTorrent cannot take: a `.torrent` must be obtained out of band and believed, whereas here the ledger fixed the digest first | handled |
| **oversized-claim DoS** — announce a 64 GiB blob, or a 4 GiB frame | a frame's length prefix is checked before anything is allocated; a manifest above the node's own `max_blob` is refused; pieces are held individually as they arrive rather than preallocated from a declared length. A node that preallocates from a stranger's claim has been told how much memory to use | handled |
| **hostile address source** — a seized domain, a poisoned resolver, or a malicious relay substitutes a different machine | a peer record is signed by the key that *is* the peer, so editing an address invalidates it. Any source of hints is therefore equally safe and none is privileged: DNS, gossip and a pasted string land in the same table under the same check. A replayed old record cannot displace a newer one (`seq`), so a hostile carrier's only power is to withhold or be out of date | handled |
| **forged provider claim** — tell the network a victim holds a popular blob, so everyone dials the victim | a `Tell` is attributed to the peer id the *handshake* derived, and the message has no sender field, so a node can only ever speak for itself. Relayed provider records — the ones in a `Providers` answer — are used for the lookup that heard them and never entered into the local store, so a lie cannot be rebroadcast as first-hand. Between them these are what let the records be unsigned; the cost is that provider knowledge spreads one hop rather than arbitrarily far | handled |
| **inventory disclosure via the DHT** — learn which objectives a node is working on by reading what it advertises holding | there is no advertisement. `p2p::code` refuses an inventory message on exactly this ground, and the DHT round does not reintroduce one: holdership is pulled, a `Tell` answers only addresses the asker named, and the asked set is the same `code_want` already sent on that connection — so the round discloses nothing the session had not already disclosed. `Directory::record_tell` drops anything outside the asked set, so the rule is enforced rather than conventional. Residual: the want set itself is a signal, and it was one before this existed | handled |
| **poisoned p2p routing answer** — claim a peer id lives at an address it does not | a `p2p::dht` contact cannot carry its key — a McEliece public key is 261,120 bytes and a full routing table would cost 1.3 GB — so a routing answer is a claim, checked only when somebody dials it and the handshake derives the expected id or does not. Costs a wasted dial, never a wrong result. The narrower consequence is that this stack can learn *that* a peer holds a blob before it can learn how to reach it, so `peers_for` reorders known peers rather than introducing new ones | partial |
| **DHT eclipse** — surround a key with adversarial nodes so lookups for it fail | partial. Costs **liveness**, never correctness: a provider record is a hint and the blob digest, fixed by the log before the lookup, is what decides. Peer exchange and the address book remain as a path that does not route through the DHT. The k-bucket policy keeps the oldest still-live contact over any newcomer, so flooding fresh identities cannot displace incumbents, and node IDs are key hashes so each attempt costs a keypair and a signature. Not solved: IDs are bound to keys, which are cheap, rather than to stake, which is not | partial |
| **DHT poisoning** — announce provider records for content you do not hold | costs the asker one wasted dial. The transfer fails against a digest the log fixed, so a poisoned answer cannot become a wrong result — only a slow one. The provider store verifies every record's signature before holding it, so it never relays a claim it could not prove | handled |
| **topology mapping via peer exchange** — ask every node for its view and assemble the network graph | none. Sharing is bounded and deterministic, which limits the rate and not the eventual result. Unlinkability at the transport layer — onion routing, or rendezvous under a key derived from the blob digest — is the real answer and is not built | not handled |
| **lying bitfield** — advertise every piece, serve none | none. `have` and bitfield messages are unverified claims, and rarest-first is computed from them, so a peer that advertises everything distorts the schedule of every node that believes it. Timeouts and `remove_peer` bound the damage to a stalled request; nothing attributes it, and nothing stops the peer reconnecting | partial |
| **leech-only swarm** — take pieces, seed nothing | tit-for-tat choking covers the download phase: a peer that gives nothing gets one rotating optimistic slot and no more. It does **not** cover seeding, because a node that has finished has no reciprocal need — serving is then altruism and the dominant move is to stop. That is the availability service in [node-incentives.md](node-incentives.md), designed and not built | partial |
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
