# Causal replay and frontier promotion

**Status: proposal.** The lab's causal CRDT, multi-value registers and run
receipts exist. Conflict-aware document projection and execution preflight are
implemented. Materializing a historical run, reapplying a contribution to a
newer frontier, and scheduling those reapplications are not implemented.

## The problem

Seven contributors begin with the same algorithm. Alice changes its recurrence
and produces an improvement. Bob independently optimizes the old recurrence.
Their files can merge deterministically without Bob's optimization remaining
correct against Alice's recurrence. A shared ordering does not establish that
the two changes compose, and the newest file is not necessarily the best
algorithm.

The existing lab is the right transport for both investigations: signed ops,
causal dependencies, immutable blobs, visible sibling values and set-union
sync. What is missing is an explicit description of which research inputs a
candidate consumed and how that contribution can be tested on a new baseline.

This belongs above the CRDT. The lab's `deps` capture an author's observed
causal context, including unrelated messages, membership changes and files.
They are not a scientific dependency graph. A run appended after it finishes
can also depend on ops that arrived while it was executing but did not provide
its inputs.

## Three orders

| order | purpose | authority |
|---|---|---|
| causal order | a contribution names the work it consumed; prerequisites precede dependent work | signed lab ops and explicit research references |
| display order | replicas show the same siblings and history when they hold the same ops | the existing `(lamport, id)` rule |
| promotion order | one verified candidate replaces the accepted frontier; reward derivation uses that history | the settlement ledger |

Independent experiments need no shared sequence. Competing revisions remain
alternatives until a declared combination is checked. A display winner never
constitutes approval to use a revision as a research input.

Agreement on the best score does not establish agreement on contribution
credit: `0 -> 60 -> 80` attributes progress as `60 + 20`, while
`0 -> 80 -> 60` attributes it as `80 + 0`. The total telescopes, but its
allocation depends on order. A max register cannot replace settlement ordering.

## Immutable input snapshots

Before starting a run, publish a content-addressed snapshot manifest containing:

- The lab space and the heads observed at input selection time.
- Every selected path, its blob address, size, executable flag and version
  reference (`op#entry`), including which variant was explicitly chosen.
- The environment tree digest and manifest blob, the command, working
  directory, environment variables, random seeds and all runtime limits.
- The objective and evaluator identities, and the benchmark or dataset
  manifest consumed by the computation.
- Any nondeterminism the recipe permits, and which declared output fields are
  compared when replaying it.

The manifest is a blob, not only a fingerprint of a directory. A directory
digest can detect a mismatch without telling another node which historical
files to assemble. Host-mounted inputs must be ingested or explicitly marked
as unavailable for external replay; their hashes alone do not preserve them.
Environment root filesystems likewise need an obtainable archive or build
artifact matching the digest. The existing lab does not sync those trees.

Record the snapshot address in the run receipt. Capture it before execution;
the run op's completion-time `deps` still serve synchronization and authority,
but do not replace the input-selection snapshot. Preserve every original run
and output. A missing blob or environment is `Unavailable`, never evidence
that an experiment failed or that the artifact is wrong.

An input snapshot pins observed work. It does not imply that the replica has
received all other contributors' work or that the selected algorithm is valid.
The pinned verifier remains the check on the result.

## Candidate lineage

An immutable candidate manifest should identify:

- The objective and verifier under which it is assessed.
- The accepted frontier it began from, and explicit parent candidate ids.
- Its source snapshot, run recipe, input snapshot and resulting run receipts.
- The contributor and the change being proposed.
- Preconditions for reapplication: the input versions or interfaces the change
  expects, and the outputs it produces.

Start with write-once files in a lab space. This adds a research convention
without changing ledger record encodings, existing objective ids or the frozen
conformance vectors. A future typed op needs its own format and migration
review; it must not reinterpret an old receipt.

Research references describe provenance. Economic attribution remains in
`cites`, subject to the ledger's existing admission and payment rules. A lab
parent or a `relations` edge cannot acquire payout authority merely because a
scheduler found it useful.

## Exact replay and reapplication

**Exact replay** materializes the original input snapshot and environment,
runs the original recipe and compares its declared reproducible outputs. It
does not resolve inputs from today's mutable workspace or re-invoke a model
and assume it will regenerate the same answer. Recorded model outputs can be
inputs; a fresh generation is another experiment.

**Reapplication** tests a declared contribution against a newer baseline. It
creates a new candidate with two parents: the original contribution and the
new accepted frontier. It records a fresh snapshot, fresh receipts and a fresh
verification. It never edits the original candidate into looking as though it
was produced against the newer algorithm.

For the seven-contributor case:

1. Each contributor publishes a candidate rooted at verified baseline `F0`.
2. Alice's result passes the pinned verifier and is promoted as `F1`.
3. The scheduler finds contributions whose declared baseline inputs changed,
   including Bob's optimization of `F0`.
4. A worker checks Bob's recipe's preconditions against `F1`. If compatible,
   it reapplies the change and evaluates a new candidate with both parents.
   If incompatible, it records the reason and retains both alternatives.
5. An improved result becomes a promotion proposal. A successful run alone is
   not authority to move the frontier or settle a reward.

A new objective, benchmark or verifier is a new assessment, not an implicit
rebase. No algorithm can safely infer that arbitrary source changes commute;
an opaque change needs an explicit integration recipe or review.

A frontier advance does not invalidate an independently generated complete
algorithm assessed under the same objective and evaluator. It may already beat
the new frontier without reapplication. Reuse its permitted verification,
compare it with the current head, and submit with the original lineage and
the citations required by current admission. Reapply only when the proposed
combination actually changes declared computation inputs.

## Scheduling and reuse

Maintain a derived index from input version ids to candidate and run ids. A
frontier event schedules only contributions whose declared inputs changed and
their dependent computations. Changes to unrelated records do not invalidate
a run.

Deduplicate jobs by a digest of the contribution, destination frontier, recipe,
input snapshot and verifier. Retries may produce multiple receipts but must
not become multiple frontier promotions or rewards. Workers can use the lab's
existing advisory leases; overlapping execution during a partition is wasted
compute, not grounds to refuse an otherwise valid result.

Reuse an output only when the recipe explicitly permits deterministic reuse
and all its code, inputs, environment, parameters, seeds and evaluator match.
A content digest is a cache key, not a proof of execution or correctness.

Keep the index disposable and rebuildable from immutable manifests and
receipts. Preserve alternatives in the lab even when the bounded gossip
population no longer retains them. A useful optimization may combine with a
future candidate despite being inferior under today's scalar score.

## Frontier authority and finality

For Stage 0, make the objective's settlement authority explicit and pin its
checkpoint key. Contributors may explore and exchange candidates while
offline, but promotions follow that authority's ledger. The existing
commitment-based batch ordering remains the settlement rule; the lab's
Lamport order must not decide who gets paid.

Signed checkpoints expose an authority's conflicting histories; they do not
prevent equivocation or force inclusion of a withheld contribution. Stage 0
retains those authority and availability limits.

An expected-frontier check belongs at promotion admission. If the head has
moved, report that the proposal is stale and assess reapplication; do not
quietly claim that its original experiment ran against the new head.

Independent settlement authorities require a membership and agreement
protocol that certifies the epoch's included claim set, predecessor and
resulting frontier. Use an established protocol appropriate to the trust
model rather than treating a longer finality timeout as consensus. Without
the required agreement, research can continue but final promotion must wait.

The current [settlement convergence design](settlement-convergence.md) is
conditional on delivery within `FINALITY_EPOCHS`. A record beyond that window
can leave accepted claims unpaid on a node. This proposal does not close that
gap and does not introduce reorgs or change settled history.

## Acceptance criteria

- Seven isolated writers retain every candidate and conflict after shuffled,
  duplicated and partitioned delivery.
- A run refuses an observed conflict under its inputs before recording any
  execution; identical values and conflicts outside its inputs do not block it.
- Replaying a receipt after later edits, renames, deletions and mid-run sync
  selects its original blobs, permissions, environment and parameters.
- A peer with only the manifests and referenced artifacts can reconstruct the
  declared inputs; missing artifacts report `Unavailable`.
- Reapplication preserves both parents and re-verifies the result. An
  incompatible recipe cannot become an accepted frontier through a merge.
- Duplicate jobs and promotion retries cannot pay twice. Revoked authors and
  unavailable verifiers retain the existing authority and verdict semantics.
- Two nodes certify the same promotion history under the selected authority
  model. Delays beyond the Stage 0 window are a separate finality test, not a
  passing CRDT-convergence test.

Implement in stages: conflict-aware consumption; snapshot materialization and
exact replay; candidate lineage and selective reapplication; then any change
to distributed finality as a separately specified protocol change.
