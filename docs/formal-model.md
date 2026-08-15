# Formal model

The protocol is specified in TLA+ under `spec/tla/` and model-checked with TLC.
This file is the honest accounting of what that buys.

`docs/threat-model.md` marks each attack handled / partial / not handled /
unsolvable. The same discipline applies here, because overstating a model check
is the same failure as overstating a mitigation, and it is a more tempting one:
a green model checker looks like a proof and is not one.

Run it with `./scripts/tla.sh`. `spec/tla/README.md` covers the modules, the
bounds and how to run a single one.

---

## The three marks

| mark | what it means |
|---|---|
| **checked** | TLC explored the complete reachable state space of the configured instance, and the property held in every state — or over every step, for an action property. The instance's size is not a restriction on the property's *content*: enlarging it produces more instances of a case already covered. |
| **bounded-checked** | The same exhaustive exploration, but the property's content genuinely depends on a bound the implementation does not have — a log length, an epoch count, a number of nodes, the magnitude of an amount. A counterexample above the bound is not excluded. |
| **assumed** | Built into the model as a given. TLC says nothing whatever about it, and every result on this page is conditional on it. |

Three things are true of every row below, including the ones marked **checked**:

1. **These are finite instances, not proofs for all inputs.** TLC enumerates
   states; it does not do induction. "No counterexample at these bounds" is
   evidence, and it is much better evidence than a test suite, and it is not a
   theorem. Where a property is genuinely universal — merge associativity,
   the slice tiling — the quantifier still ranges over a finite universe fixed
   by the `.cfg`.

2. **Hashing is modelled as an injective abstract function.** An entry's hash is
   its body, verbatim, as a TLA+ tuple; a tuple is injective in its components,
   so it is a perfectly collision-free hash and nothing else. **Collision
   attacks are assumed away, not verified.** Every result that mentions an id,
   a head, a root, a commitment or a content address is conditional on SHA-256.

3. **The sandbox boundary cannot be modelled here at all.** `SANDBOXING` in
   `src/verifiers/mod.rs` is an operating-system property — namespaces, seccomp,
   filesystem visibility. There is nothing in TLA+ that corresponds to it, and
   nothing on this page says anything about whether pinned code can escape. See
   the **malicious objective code** row of `docs/threat-model.md`, which is a
   launch blocker and stays one regardless of anything here.

TLC also reports the probability that two distinct states collided in its
fingerprint table and one was therefore skipped. Across this suite the largest
optimistic estimate is `2.0e-7` (`Ledger`); by actual fingerprints, `6.6e-10`.
Small, and not zero.

---

## Properties, by module

### `Ledger` — the append-only hash-linked log

Bound: 2 payloads, `MaxLen = 4`. 292,578 distinct states.

| property | mark | note |
|---|---|---|
| an untouched log verifies and is what the operator wrote | bounded-checked | |
| **any divergence is caught by re-hashing *or* by the published head** | bounded-checked | the disjunction is not laziness. `verify_chain` alone misses truncation, since a prefix of a valid chain is a valid chain; the head alone misses an edit that leaves the recorded hash stale. Only together are they complete, and only at `MaxLen = 4` |
| a rewrite that repairs the chain has moved the head | bounded-checked | |
| the Merkle root pins a well-formed log | bounded-checked | note the guard: for a log that does *not* verify, the root proves nothing, because it is computed over the *recorded* hashes. That is a property of the mechanism, not a gap in the model |
| the operator never rewrites history | bounded-checked | action property |

The adversary may truncate, edit-and-keep-the-hash, delete an interior entry,
swap two entries, or **replace the file with any well-formed chain at all**. The
last one subsumes edit-and-re-hash and is strictly stronger: re-hashing after an
edit yields some well-formed chain, and the model offers every one of them.

Modelling re-hashing as its own step was tried and abandoned — each re-hash
mints hash values nesting the previous ones, so the reachable hash universe
grows by a factor of `|Payloads| * MaxLen` per step and TLC never finishes. The
replacement is not a weakening; it reaches strictly more files.

### `Checkpoint` — signed roots, and a reader holding a fragment

Bound: 2 payloads, `MaxLen = 3`. 3,600 distinct states.

| property | mark | note |
|---|---|---|
| **`verify --from` accepts iff the reader's prefix at `height` is the signed prefix** | bounded-checked | both directions. Left to right refuses a rollback or a fork; right to left is the one a naive implementation breaks, by rejecting a reader who has synced *past* the checkpoint |
| a reader holding less than `height` is refused rather than verifying what it has | bounded-checked | |
| a rollback is detected by any reader still holding the older checkpoint | bounded-checked | |
| a checkpoint signed by the wrong key is refused on the key alone | checked | the forgery modelled is the strongest available to an attacker who cannot sign: a checkpoint whose payload is exactly right for the reader's own log. It fails on the signer, which is why the key must be pinned out of band |
| ML-DSA-65 is unforgeable | **assumed** | a checkpoint carries its signer as a tag. Forgery is unrepresentable rather than hard. What is checked is that the protocol *uses* the signature |
| `issued_at` | not modelled | signed and carried through untouched; no property depends on it |

### `CommitReveal` — epoch batching, the front-runner, and the grinder

Bound: 2 agents, 3 artifacts, 4 epochs, 6 ordering keys. 424 distinct states.

Settlement order inside an epoch is `H(beacon(epoch, anchor) ‖ commitment_hash)`
ascending, ties broken by claim id — matching `Node::settle_due`. The key is the
**commitment hash and not the claim id**, and that distinction is the subject of
the last three rows.

| property | mark | note |
|---|---|---|
| binding: no reveal without a matching commitment in a strictly earlier epoch | bounded-checked | |
| **no in-flight front-running**: a derived artifact never settles ahead of the one it was derived from | bounded-checked | stated over the settlement *sequence*, not over epochs — "settles ahead of" is what pays, and an epoch comparison would assume the batch ordering it is supposed to check |
| settlement order within an epoch is a function of the beacon | bounded-checked | TLC explores every interleaving of commits and reveals, so the invariant holding in all of them *is* the statement that arrival-order permutations settle identically. It constrains the *sequencer* only, and holds just as well when the ranks it sorts are grindable — which is why the next two rows exist |
| nothing settles twice | bounded-checked | |
| every revealed claim settles by the end of its epoch | bounded-checked | liveness, under weak fairness on the epoch tick alone. Nobody is obliged to submit; an epoch that has begun must end |
| **the batch order is not influenced by anything a submitter chooses after the anchor is known** | bounded-checked | `OrderIsNotSubmitterChosen`. For every pair that settled in one batch, the later one could not have overtaken the earlier by *any* reveal-time key available to it. Falsifiable: `OrderKey = "claim"` |
| a submitter's reveal-time choices all earn the same rank | bounded-checked | `NothingToGrind`, the mechanism behind the row above. Stated over ranks rather than keys, so several claim ids that happen to rank alike are correctly not a violation |
| Eve cannot see an artifact before it is revealed | **assumed** | that is the commitment hash's job. Assuming it here is not circular: it depends on `Ledger` and on the hash, neither of which depends on this module |
| **the anchor is fixed before the epoch opens and outside anyone's choice** | **assumed** | and `not handled` in `docs/threat-model.md` under *beacon grinding*. The anchor is really the last entry of the previous epoch, so a submitter who lands the final append of their own commit epoch moves both halves of their rank at once. `src/node.rs` names this residual gap at `settle_due`; closing it needs a VDF or a threshold signature. A green run here is evidence about the **key**, not about the beacon it is hashed with |
| restamping is free and unlimited | **assumed**, and modelled as such | the model gives a submitter two or three reachable claim ids rather than the thirty `test_settlement_order_cannot_be_ground_out_at_reveal_time` tries. The property is that the set of reachable *ranks* is a singleton, and a second element falsifies that no less than a thirtieth would |

### `Verification` — the four-status taxonomy

Bound: 2 nodes, 2 artifacts, 2 seeds, 3 disruptions. 128,576 distinct states.

| property | mark | note |
|---|---|---|
| `Unavailable` and `InvalidSpec` never close an objective | checked | |
| **a verifier outage never becomes a rejection** | checked | stated as "no node in a broken condition can reach a settling status", over every reachable state, rather than as "a down node returns `Unavailable`". The first forbids the whole class of mistakes including one nobody named |
| a tampered pin is `InvalidSpec` on every node, including nodes that are themselves offline | checked | the pin's hash is verified before the subprocess is spawned, so a broken objective cannot hide behind a broken machine |
| two honest nodes agree on any settling verdict, including the seeded statistical kind | bounded-checked | 2 nodes, 2 seeds |
| the objective reopens once the outage ends | bounded-checked | liveness, and bounded by `MaxDisruptions = 3`. It asserts nothing about a *permanent* outage — which is the **verifier removal** row of `docs/threat-model.md`, marked not handled there and not addressed here |
| an unknown verifier kind is `Unavailable`, not `InvalidSpec` | not modelled | a real rule (`src/verifiers/mod.rs`: another node, or a later version, may know the kind) with no interesting interleaving; unit-tested |
| the pinned verifier is a deterministic function of `(spec, artifact, seed)` | **assumed** | verifier impurity is the **impure verifier** row of the threat model, handled by `audit --rerun` rather than by anything statable here |

### `Frontier` — the ratchet

Bound: 7 artifacts, span 6, reward 10, 6 submissions, `min_improvement = 2`.
87 distinct states.

| property | mark | note |
|---|---|---|
| the frontier is monotone | bounded-checked | action property, stated over `progress` rather than over the raw score so it reads the same under `minimize` |
| **payouts telescope exactly**: total paid equals the cumulative at the current frontier, on every path | bounded-checked | strictly stronger than checking that a few paths sum alike — it pins the total after every *prefix* of every path |
| the pool is never overspent however finely the curve is chopped | bounded-checked | |
| the pool is exactly exhausted at the target, not one unit short | bounded-checked | the numbers are chosen so truncation bites: reward 10 over span 6 gives 0, 1, 3, 5, 6, 8, 10, so five of six unit steps lose a fraction and the property is checking that the losses cancel |
| a duplicate never pays twice; a copy earns zero | bounded-checked | `dup3` shares a score with `a3`; whichever lands first is paid and the other earns nothing |
| `u64` / `u128` overflow on the money path | **not modelled** | TLA+ integers are unbounded, so this module *cannot* express the bug `Ratchet::cumulative` exists to prevent. A width bug is a property of a machine type, not of a protocol. Covered by `a_huge_reward_times_a_huge_progress_does_not_wrap` and `realistic_money_scale_stays_exact` in `src/frontier.rs` |
| `minimize` direction | bounded-checked, separately | the shipped `.cfg` is `maximize`. The module handles both, and the mirrored instance — baseline 6, target 0, `minimize` — was run by hand: 57 distinct states, no violation. Every property here is stated over `progress` rather than over the raw score, which is what makes the two directions one specification instead of two |

Also run at `min_improvement` 1 (362 distinct states) and 3 (47).

### `Attribution` — citation flow

Bound: 3 claims, δ = 1/2, `max_depth` 2, amounts {0, 7, 12}, 2 rewires.
789 distinct states.

| property | mark | note |
|---|---|---|
| citations point backwards, so an honest graph is acyclic | bounded-checked | *derived*, not assumed: the only way a claim acquires citations is an append whose guard is "already in the log", and TLC checks that no sequence of appends reaches a state where a claim reaches itself |
| **exact conservation** — payouts sum to precisely the amount settled | bounded-checked | asserted on **every** graph, including the ones the adversary rewired into cycles. Both halves matter: creation mints units the pool cannot fund, and a burned unit makes the ledger's totals stop adding up, which an auditor cannot distinguish from theft |
| nothing is paid a negative amount | bounded-checked | |
| decay is bounded — nobody beyond `max_depth` hops is paid | bounded-checked | |
| the settled claim always keeps a share, when δ < 1 | bounded-checked | |
| the walk terminates on an attacker-supplied DAG | **bounded-checked by observation** | this one is different in kind and worth saying plainly: TLC *evaluating* the recursive flow to completion at every reachable state is the evidence. If the ancestor filter were removed, TLC would fail to terminate rather than report a violation. So it is checked in the sense that it demonstrably finished, and not in the sense that a property was falsifiable |

Also run at the shipped defaults (δ = 1/4, depth 6) and at δ = 1/1, the boundary
where a claim passes on everything it received. Same state count, same result.

Citation *flow* is deliberately not recomposed in `Cairn`: it redistributes
an already-fixed settlement amount, so it cannot change the pool total.

**Not addressed here at all:** the **citation-flow dilution** row of
`docs/threat-model.md`. Conservation says the units all land somewhere; it says
nothing about whether the split is *fair*, and slicing an improvement to starve
an upstream contributor conserves perfectly while doing exactly that. A model
check of conservation is not a defence against dilution and must not be cited as
one.

### `Gossip` — the population CRDT

Bound: 3 nodes, 5 candidates, 2 islands, K = 2. 23,102 distinct states.

| property | mark | note |
|---|---|---|
| merge is commutative, associative, idempotent | bounded-checked | quantified over **all 32 subsets**, not over reachable node states — a merge that is only associative on the arguments this model happens to reach is not associative |
| **pruning early is indistinguishable from pruning late** | bounded-checked | the confluence lemma the module docs argue informally. Associativity is the sharper test: it is *false* for any retention rule that is not confluent, so a future tiebreak or arrival-dependent retention would fail here first |
| bounded memory: no island ever exceeds K, at any node, at any time | bounded-checked | including immediately after a merge that received more than K — which is why `from_value` re-prunes instead of trusting the sender |
| nothing good is lost: the union of node states has the same top K as everything ever generated | bounded-checked | |
| convergence under fair pairwise merge | bounded-checked | 3 nodes |
| the candidate order is total — no ties | **assumed** | the implementation orders by `(score, content hash)`, so ties are impossible and every node breaks them identically. `Rank` here is injective for that reason. With genuine ties "the top K" is not a function and pruning is not deterministic; modelling them would show the design failing for a reason the design already rules out |
| merge across different capacities takes the smaller | not modelled | a bound-negotiation rule, not a retention rule; unit-tested |

### `Sync` — record anti-entropy

Bound: 3 peers (one adversarial), 4 records, 2 buckets. 1,305 distinct states.

The adversary is maximal: **any record may arrive at any peer at any time, from
anywhere**, including messages no peer sent. That over-approximates the network
on purpose, so that every property rests on the receiver's checks and on nothing
else.

| property | mark | note |
|---|---|---|
| **derived records never cross the wire** | checked | Evil holds a `verdict` and advertises it through the ordinary bucket listing. Ids do not carry kinds, so an honest peer *does* solicit it and only learns what it is when the body arrives — the refusal has to happen at ingest, and does |
| unsolicited records are refused | checked | action property: every record admitted was outstanding an instant earlier |
| no records appear from nowhere | bounded-checked | |
| **a forged bucket digest costs the liar its own gossip** | bounded-checked | `Inventory::differing` is symmetric, so a bucket made to look settled is skipped in *both* directions. Concealment is self-defeating rather than free |
| honest peers converge, on everything honest peers hold, whatever Evil does | bounded-checked | a liar can withhold its own records; it cannot keep two honest peers apart |
| finding an XOR collision | **assumed possible, for free** | far more generous than reality. The digest is a XOR of SHA-256 ids; the model grants the collision rather than making the attacker earn it |
| a body that does not hash to the id it was requested under | folded into "unsolicited" | it is simply a different record, and that record is not outstanding. Sound only because ids are content addresses |
| 256 buckets | modelled as 2 | the bucket count is a message-size optimisation. Nothing depends on how many there are, only on "differ ⇒ exchange, match ⇒ skip" |

### `Partition` — coordinator-free assignment

Bound: space 16, 7 partition counts, 3 epochs, 12 timestamps. 4,368 distinct
states.

Be blunt about this module. The design's central quantitative claim — that
mixing a per-epoch beacon into the draw *spreads nodes out*, so squatting a
region costs a fresh grinding effort each epoch — is a statistical property of
HMAC-SHA256. It is not a protocol property and no model checker can establish
it.

| property | mark | note |
|---|---|---|
| **the slices tile the space** — every point in exactly one slice, for every partition count including those that do not divide it | bounded-checked | exhaustive over the configured counts. A gap leaves items nobody searches; an overlap makes two nodes provably responsible for the same item and destroys the "did you search your region?" check the scheme exists to enable |
| a malformed assignment covers nothing | bounded-checked | fail closed, rather than claiming somebody else's region |
| the draw lands inside the partition count | bounded-checked | |
| a published assignment stays verifiable after its epoch has passed | bounded-checked | this is the auditability claim: the record carries its own provenance |
| **an assignment cannot be replayed into another epoch** | bounded-checked | quantified over every record in the space, not only over records an honest node would produce. This is the mechanism behind "epoch rotation bounds squatting"; without it, rotation is decorative |
| `epoch_of` is monotone and its epochs are contiguous | bounded-checked | `CommitReveal`'s gate silently depends on both |
| **the beacon actually spreads assignments** | **assumed** | measured by `assignment_rotates_between_epochs` in `src/partition.rs`, not established here |
| purity of `assign` | checked, with a caveat | `Assign` reads no variable, so purity holds by construction of the model. What TLC establishes is that the protocol *around* it does not smuggle state in. That the Rust function is pure is a code property, not a modelled one |
| modulo bias | not modelled | real, on the order of `partitions / 2^64`, and irrelevant: assignment has to spread nodes out, not be uniform to the last bit |

### `Cairn` — the composition

Bound: 4 claims, 2 epochs, span 6, reward 10. 30 distinct states — small,
because the claims are few; the work is in the quantifier, which ranges over all
65 settlement sequences at every reachable log.

| property | mark | note |
|---|---|---|
| **the Stage 0 guarantee: exactly one settlement sequence survives a log-only audit** | bounded-checked | stated as *uniqueness*, not as "the canonical sequence passes". Those are different, and only the first is a guarantee: if two sequences both pass, the operator picks between them, and which one it picks decides who is paid |
| the canonical sequence does pass | bounded-checked | soundness, stated separately so that an audit accepting nothing at all cannot satisfy uniqueness vacuously |
| the pool is exactly conserved | bounded-checked | |
| nothing settles without an accepting verdict | bounded-checked | composed rather than assumed, so a settlement path that forgot to consult the verdict would show up here even though `Verification` passes in isolation |
| every settlement after the first cites the claim it displaced | bounded-checked | |
| the log is append-only and its contents are what they say | **assumed here, checked in `Ledger`** | |
| censorship by *withholding a reveal* | **not addressed** | the model's log contains what the operator appended. A claim that was never appended is invisible to any log-only audit, by construction. This is the **censorship** row of `docs/threat-model.md`, marked not handled, and nothing here improves it. What *is* checked is the weaker and still useful case: a claim that *was* appended and then not settled is detectable |

---

## Falsification: how we know the properties can fail

A property that passes against a deliberately broken model is checking nothing,
and it looks exactly like one that is checking something. Every headline
property below was confirmed falsifiable by breaking the mechanism it is about
in a scratch copy and watching TLC object. The first five rows below are four
permanent config switches — `OrderKey` falsifies two different properties at two
different depths — so those checks can be repeated in one line.

| what was broken | property that failed | trace length |
|---|---|---|
| `EpochBatched = FALSE` — reveal permitted in the same epoch as the commitment | `NoFrontRunning` | 7 states |
| `OrderKey = "claim"` — settlement keyed on the claim id, as §5 originally specified | `NothingToGrind` | 4 states |
| `OrderKey = "claim"`, with `NothingToGrind` removed so the deeper trace surfaces | `OrderIsNotSubmitterChosen` | 7 states |
| `SeedPinned = FALSE` — each node draws its own seed | `HonestNodesAgree` | 3 states |
| `RequireMaximal = FALSE` — the audit checks each settlement shown but never asks what was left out | `SettlementIsUniquelyDetermined` | 2 states |
| the acyclicity guard applied to rewired graphs too | `HonestCitationsAreAcyclic` | 3 states |
| `Slice`'s last-partition remainder absorption removed | `SlicesTile` | initial state |
| `ingest`'s derived-kind guard removed | `OnlyInputsAreHeld` | reachable |
| `ingest`'s solicited guard removed | `NoUnsolicitedAdmission` | reachable |

Those five rows are driven by `.cfg` constants, so the check is a one-line
`sed`. The last four required editing a scratch copy of the module, which is
the right cost for something that should never be true of the shipped code.

### The front-running trace, in prose

With `EpochBatched = FALSE`, TLC produces this in seven steps:

```
1.  epoch 0                       alice commits to a1
2.  epoch 0 -> 1                  the epoch turns
3.  epoch 1                       alice reveals a1
4.  epoch 1                       eve commits to d1, derived from a1
5.  epoch 1                       eve reveals d1
6.  epoch 1 -> 2                  the batch settles:
        settled = << d1 (eve), a1 (alice) >>
```

Eve saw `a1` land, derived `d1` from it, and committed *in the same epoch* —
and the beacon, which does not know or care who copied whom, put her first. She
is paid for `a1`'s content before `a1` is.

The rule that stops this is that a reveal must be in a **strictly later** epoch
than its own commitment: by the time Eve has seen `a1`, the epoch in which she
could have committed has closed. `src/node.rs` implements it —
`reveal_epoch <= commit_epoch` returns `RuleViolation::RevealBeforeEpoch` — and
settlement is deferred to the close of the reveal epoch and ordered by
`H(beacon(epoch, anchor) ‖ commitment_hash)`. **The shipped code and this model
agree.** The trace above is what the rule is worth, not a bug report.

### The grinding trace, in prose

The ordering keys in the model instance are chosen so that the commitments fix
one order and a restamped reveal can invert it. In epoch 1, `Rank(1, k)` is
`(k + 1) mod 6`:

| | commitment key | its rank | keys reachable by restamping | their ranks |
|---|---|---|---|---|
| alice's `a1` | 1 | **2** | 1, 3 | 2, 4 |
| eve's `a2` | 4 | **5** | 0, 2, 4 | **1**, 3, 5 |

The commitments say alice settles first (rank 2 against rank 5). Alice cannot
improve on that; her alternative stamp is worse. Eve can: one of her reachable
claim ids ranks 1, ahead of alice.

With `OrderKey = "claim"`, TLC settles it in seven steps:

```
1.  epoch 0                       alice commits to a1
2.  epoch 0                       eve commits to a2
3.  epoch 0 -> 1                  the epoch turns; the anchor is now public
4.  epoch 1                       eve reveals a2, choosing the stamp with key 0
5.  epoch 1                       alice reveals a1 with key 1
6.  epoch 1 -> 2                  the batch settles:
        settled = << a2 (eve), a1 (alice) >>
```

Nobody copied anything and nobody broke a hash. Eve simply picked, from the
claim ids her own submission could carry, the one that sorted first — a choice
she made *after* step 3 told her what the anchor was. On a progressive
objective that inversion decides which of the two is paid for the whole span
and which for the remainder, so it is a transfer and not a formatting detail.

`OrderIsNotSubmitterChosen` catches the weaker precondition too, and catches it
in the same seven steps: it fails on the state where eve settles *second* while
holding a key that would have put her first. Being able to overtake is the
violation; actually overtaking is only the cash-out.

`NothingToGrind` fails earlier still, at four steps — the first reveal by anyone
with more than one reachable rank. That is the mechanism-level statement, and it
names the field at fault rather than the victim.

Keying on the commitment hash removes the choice at its source: the value was
fixed an epoch before the anchor existed, so `AvailableKeys` is a singleton and
there is nothing for the existential in `Reveal` to range over. `src/node.rs`
sorts on `claim.commitment_hash()` and pins it with
`settlement_order_cannot_be_ground_out_at_reveal_time`. **Code and model agree.**

### The censorship trace

With `RequireMaximal = FALSE`: the log contains `k1`, which has an accepting
verdict, clears `min_improvement` and needs no citation because the frontier is
empty. The operator publishes the *empty* settlement sequence, and the weakened
audit accepts it — every settlement shown is justified, and there are none.
Nobody is paid, and the log-only reader sees nothing wrong.

The fix is that the audit must also ask what was left out, which
`Node::audit_batches` does: *"an accepted claim from the epoch is missing, which
is censorship by omission and pays whoever was behind it."* Again, code and
model agree.

---

## Divergences found between the specification and the code

**None between the model and the code.** Every property the design claims holds
at the stated bounds against the semantics `src/` currently implements,
including the three items of `docs/design-stage0-completion.md` that were
designed before they were built: epoch-batched commit–reveal (§5), the seeded
statistical verifier (§4), and the checkpoint fragment reader (§2). Those three
were modelled from the design document rather than from the code, and the code
has since caught up; the `.cfg` switches above are what makes it possible to say
that with a straight face rather than as an absence of evidence.

**One divergence between the design document and the code, and the model missed
it.** §5 originally specified the intra-epoch ordering key as
`H(beacon(reveal_epoch, anchor) ‖ claim_id)`. The implementation found that
grindable by the submitter and shipped the commitment hash instead; the design
document now carries a correction block saying so. This model did not catch it,
and the reason is worth recording because it is the failure mode the whole
falsification section exists to prevent: settlement order was modelled as
`Ord(e, cl) = (Slot(cl) + e) mod n`, a function of *fixed attributes of a
claim*. There was no action in which a submitter chose anything at reveal time,
so `SettlementIsBeaconOrdered` held no matter which field the key came from. The
invariant was true and was evidence for nothing. `OrderKey` and the existential
in `Reveal` are what make it evidence now.

If you change a record, a rule or an encoding, re-run `./scripts/tla.sh`. A
divergence between the specification and the code is a bug in one of them, to be
resolved rather than annotated.

---

## The complete list of assumptions

Every result on this page is conditional on all of these.

1. **SHA-256 is collision-free and second-preimage-free.** Hashes are modelled
   as tuples of their inputs, which is exactly a perfect hash.
2. **Canonical encoding is injective** — two objects with different content have
   different bytes. This is what makes an id an identity. `conformance/vectors.json`
   pins it across implementations; nothing here checks it.
3. **ML-DSA-65 is unforgeable.** Signatures are modelled as a signer tag.
4. **The commitment hash hides the artifact** until its reveal.
5. **HMAC-SHA256 spreads assignments** across partitions and rotates them across
   epochs.
6. **The beacon is not ground, by the sequencer or by a submitter.**
   `docs/threat-model.md` marks this **not handled**; at Stage 0 the sequencer
   is trusted not to. The submitter half is narrower but real: the anchor is the
   last entry of the previous epoch, so whoever lands that append moves their
   own rank. `CommitReveal` treats the anchor as given and checks only that the
   *key* hashed with it holds nothing the submitter can vary.
7. **Fixed-width arithmetic does not overflow.** TLA+ integers are unbounded, so
   no module here can express a `u64` wrap. The money paths guard themselves in
   `u128` and are unit-tested.
8. **The pinned verifier is a deterministic function of `(spec, artifact, seed)`.**
9. **Nodes agree about epoch boundaries.** `CAIRN_EPOCH_SECONDS` is a policy
   parameter; two nodes with different settings disagree about which reveals
   were legal, and that disagreement is outside every model here.
10. **The OS sandbox holds.** Unmodellable in TLA+, and a launch blocker in its
    own right.
11. **A settled result is only as good as its verifier.** Nothing here says an
    objective's pinned checker measures what its statement claims. That is the
    **verifier gaming** row of the threat model and it is a social problem with
    a partial technical answer.

---

## What a green run does and does not entitle you to say

It entitles you to say: *at these bounds, no interleaving of the modelled
actions — including the adversarial ones — reaches a state violating these
properties, given the assumptions above.*

It does not entitle you to say the protocol is proved correct, that the
implementation matches the specification (the specification is a separate
artifact, and only `scripts/interop.sh` and the conformance vectors keep the two
implementations honest about bytes), or that an attack absent from the model
does not exist. The modules encode the attacks somebody thought to encode. A
model checker exercises the interleavings nobody thought of; it does not invent
the threat model.
