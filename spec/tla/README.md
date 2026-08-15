# TLA+ specification

The protocol, written down in a language a machine can disagree with.

Eleven modules, each with a `.cfg` naming the finite instance it is checked at.
`docs/formal-model.md` is the honest summary — which properties are **checked**,
which are **bounded-checked**, and which are **assumed**. Read that before
quoting anything from here.

## Running it

```
./scripts/tla.sh
```

Three exit statuses, and the distinction is the point:

| status | meaning |
|---|---|
| `0` | every module was checked and every property held |
| `1` | a module was checked and a property was violated |
| `3` | nothing could be checked — no JDK and no cached `tla2tools.jar` |

Status `3` is a *skip*, not a pass. It is the same discipline as
`Status::Unavailable` in `src/verifiers/mod.rs`: a checker that could not run
says nothing about the thing it was asked to check, and collapsing that into
"passed" is the one failure this repository cannot afford. CI decides for itself
whether a skip is acceptable on a given runner.

The script finds a JDK in `JAVA_HOME`, then Homebrew's keg-only `openjdk@21`,
then `PATH` — in that order, because on macOS a bare `java` on `PATH` is Apple's
stub, which exists, is executable, and fails. Each candidate is probed by
running it rather than by testing for a file. `tla2tools.jar` is cached in
`.local/`, which is already gitignored, and fetched on first use.

To run one module by hand:

```
java -cp .local/tla2tools.jar tlc2.TLC \
     -config spec/tla/Frontier.cfg -deadlock spec/tla/Frontier.tla
```

`-deadlock` is not optional. Several modules reach terminal states by design —
a bounded log that is full, an epoch counter at its ceiling — and deadlock is
not the property under test in any of them, so leaving the check on reports an
exhausted bound as a failure.

## The modules

Read them in this order; each uses vocabulary the previous one introduced.

| module | models | what it establishes |
|---|---|---|
| `Hashing` | shared vocabulary, no behaviour | entry hashes, `verify_chain`, the Merkle root, and the set of well-formed chains. No `.cfg`: there is nothing to check, only definitions the other modules must agree about |
| `Ledger` | `src/ledger.rs` under an adversary who rewrites the file | a rewritten log is caught by re-hashing **or** by the published head; neither alone is enough, and the module says which attack each half misses |
| `Checkpoint` | `src/checkpoint.rs`, and `verify --from` | `verify --from` accepts exactly when the reader's prefix at `height` is the prefix that was signed — both directions, including a reader holding *more* than the checkpoint covers |
| `CommitReveal` | design §5 as shipped in `Node::settle_due`: commit in N, reveal in N+1, batch ordered by `H(beacon(epoch, anchor) ‖ commitment_hash)` | binding; **no in-flight front-running**; settlement order is a function of the beacon, so arrival-order permutations settle identically; and **the batch order is not influenced by anything a submitter chooses after the anchor is public**, which is why the key is the commitment hash and not the claim id |
| `Sealed` | `src/sealed.rs` over `src/crypto/{envelope,shamir,kem}.rs`, plus `Node::committee_for` and `check_committee_share` | the composition of four primitives, which none of their individual assumptions covers: binding survives a dishonest sealer, nothing opens below the threshold, an envelope cannot be lifted between submissions, a bystander cannot fill a seat, a share cannot land in its commitment's own epoch — and the point of the whole design, that a sealed submission **opens without the submitter ever acting again** |
| `Verification` | `src/verifiers/mod.rs` and the V3 statistical kind | `Unavailable` and `InvalidSpec` never settle; an outage never becomes a rejection; two honest nodes agree on any settling verdict; the objective reopens when the outage ends |
| `Frontier` | `src/frontier.rs`, truncating integer arithmetic and all | the frontier is monotone; payouts telescope *exactly*; the pool is never overspent however finely the curve is chopped; a duplicate never pays twice |
| `Attribution` | `src/attribution.rs`, on an attacker-supplied DAG | citations point backwards so honest graphs are acyclic; exact conservation on **every** graph, cycles included; decay is bounded |
| `Gossip` | `src/gossip.rs`, the population CRDT | merge is commutative, associative and idempotent; pruning early is indistinguishable from pruning late; convergence under fair pairwise merge |
| `Sync` | `src/p2p/sync.rs` record anti-entropy | derived records never cross the wire; unsolicited records are refused; a forged bucket digest costs the liar its own gossip; honest peers converge around it |
| `Partition` | `src/partition.rs` | the slices tile the space with no gaps and no overlaps; a malformed assignment covers nothing; an assignment cannot be replayed into another epoch; `epoch_of` is monotone and contiguous |
| `Cairn` | the composition | **the Stage 0 guarantee**: exactly one settlement sequence survives a log-only audit, and the pool is exactly conserved |

## State-space bounds, and why these ones

Every configuration is small on purpose. At ten modules the whole suite ran in
about **25 seconds** on a laptop, and that sentence used to end by saying the
two-minute budget left room for a future module without re-tuning the existing
ones. `Sealed` is that module, and it took the room as intended: about six
seconds of its own, none of the other ten touched. Still nothing near the
budget.

| module | bound | states (distinct / generated) | depth |
|---|---|---|---|
| `Ledger` | 2 payloads, `MaxLen = 4` | 292,578 / 12,967,507 | 16 |
| `Checkpoint` | 2 payloads, `MaxLen = 3` | 3,600 / 69,121 | 10 |
| `CommitReveal` | 2 agents, 3 artifacts, 4 epochs, 6 ordering keys | 424 / 544 | 12 |
| `Sealed` | 2 agents, 2 artifacts, 2-of-3 committee, 1 liar, 2 epochs | 3,506 / 11,630 | 12 |
| `Verification` | 2 nodes, 2 artifacts, 2 seeds, 3 disruptions | 128,576 / 628,993 | 21 |
| `Frontier` | 7 artifacts, span 6, reward 10, 6 submissions | 87 / 498 | 7 |
| `Attribution` | 3 claims, δ = 1/2, depth 2, 2 rewires | 789 / 6,382 | 6 |
| `Gossip` | 3 nodes, 5 candidates, 2 islands, K = 2 | 23,102 / 191,989 | 9 |
| `Sync` | 3 peers, 4 records, 2 buckets | 1,305 / 18,668 | 11 |
| `Partition` | space 16, 7 partition counts, 3 epochs | 4,368 / 17,745 | 15 |
| `Cairn` | 4 claims, 2 epochs, span 6, reward 10 | 30 / 30 | 6 |

Each `.cfg` carries the argument for its own numbers at the top of the file.
The reasoning is always the same shape — *what is the smallest instance in which
the attack is expressible?* — and it is worth being explicit about the three
places where the bound is doing real work:

- **`Ledger` at `MaxLen = 4`.** Four is the smallest length at which every
  adversarial action has a case the others do not cover: a middle delete needs
  an entry with both a predecessor and a successor, a swap needs two interior
  entries, and a truncation needs somewhere to land that is neither empty nor
  full. This is also the most expensive module in the suite, because
  `AdvForge` ranges over every well-formed chain, of which there are
  |Payloads|⁰ + … + |Payloads|⁴.
- **`Frontier` at reward 10 over a span of 6.** Chosen so that truncation
  actually bites: `cumulative` runs 0, 1, 3, 5, 6, 8, 10, so five of the six
  unit steps lose a fraction and the telescoping property is checking that the
  losses cancel. A reward divisible by the span would pass for the wrong reason.
- **`Partition` at space 16.** The tiling argument is about
  `step = space \div partitions` truncating and the last slice absorbing the
  remainder. Partition counts 3, 5 and 7 leave remainders against 16; 2³² would
  add four billion points to quantify over and no new case.

## Modules whose properties are not all about reachable states

`Gossip` quantifies the CRDT laws over **all 32 subsets** of the candidate set,
not over the populations the model happens to reach — a merge that is only
associative on reachable arguments is not associative. That is affordable
because `PruneTable` is a constant-level definition TLC evaluates once. Raising
the candidate count to 6 makes associativity 262,144 merges and the run stops
fitting the budget.

`Partition` is mostly arithmetic, and arithmetic has no state. Its tiling,
range and replay properties quantify over the whole record and partition space
rather than over the small behaviour the module carries; the state machine
exists for the one genuinely temporal claim, that an assignment recorded in an
early epoch still verifies after the epoch has moved on.

## Configuration switches that exist to make properties falsifiable

Four modules carry a constant whose *other* value produces a counterexample —
five switches in all. They are there because a property that would hold anyway
is not evidence for the design decision that was made to obtain it, and each one
is a two-line check that the corresponding rule is load-bearing:

| module | switch | shipped | what the other value does |
|---|---|---|---|
| `CommitReveal` | `EpochBatched` | `TRUE` | `FALSE` — same-epoch reveal — violates `NoFrontRunning` in 7 steps |
| `CommitReveal` | `OrderKey` | `"commitment"` | `"claim"` — the key §5 originally specified — violates `NothingToGrind` in 4 steps and `OrderIsNotSubmitterChosen` in 7 |
| `Verification` | `SeedPinned` | `TRUE` | `FALSE` violates `HonestNodesAgree` in 3 steps |
| `Cairn` | `RequireMaximal` | `TRUE` | `FALSE` violates `SettlementIsUniquelyDetermined` immediately |
| `Attribution` | `MaxRewires` | `2` | `0` makes the cycle defence untested |

`OrderKey` earns its place twice over: the module was written before the
implementation landed, keyed settlement on a fixed attribute of each claim, and
so passed `SettlementIsBeaconOrdered` whichever field the key came from. The
switch is what turned that invariant from a true statement into evidence.

The traces are written out in `docs/formal-model.md`.

## Editing these files

Keep the arguments next to the numbers. A bound with no stated reason is a
bound nobody can safely change: the next person either leaves it alone out of
superstition or raises it until the run stops finishing, and neither is
engineering.

If you add a property, check that it can fail. The cheapest way is to break the
mechanism it is about in a scratch copy and confirm TLC objects — several
properties here were found to be vacuous that way and had to be restated. A
property that passes against a deliberately broken model is checking nothing,
and it is worse than no property at all because it looks like one.
