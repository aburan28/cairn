# Design: completing Stage 0

Proposal for the six unchecked Stage 0 items in [roadmap.md](roadmap.md).
Ordered by independence and risk to existing ids / demos.

## Goals and non-goals

**Goal.** Stage 0 becomes usable by someone other than its author: a third party
can post an objective without owning every contributor's machine, a reader can
pin a log fragment to a signed checkpoint, schemas reject garbage before it
lands in the log, statistical claims cannot choose their criterion after data,
in-flight front-running is closed by epoch batching, and candidate populations
actually travel between peers.

**Non-goals.** Stage 1 escrow/bonds, Stage 2 committees / TOPLOC / forced
inclusion, Stage 3 settlement anchors. Those stay checklist items until Stage 1
has demand.

**Invariant.** No change may move a pre-existing record id. Optional fields stay
omitted-on-default. `Unavailable ≠ Reject`. No floats near money or identity.

---

## 1. Objective schemas as a hard `post` gate

**Today.** `spec/objective.schema.json` and `spec/claim.schema.json` exist and
are documentation. `Objective::validate` / `Claim::validate` already enforce
most of the same rules in code.

**Design.** On `post` (and claim construction used by `reveal`), parse the input
JSON and validate it against the schema *before* `from_value`. Failure is a
refusal (CLI exit 2), never a log append.

Implementation:

- Embed the schema documents (or load from `--root/spec/` with a fallback to
  the crate-relative `spec/`).
- Small structural validator matching draft 2020-12 features we actually use
  (`required`, `additionalProperties: false`, `enum`, `const`, `type`,
  `minLength`, `minimum`, `format: date-time` as a shape check). Avoid a full
  JSON-Schema engine unless it stays dependency-light.
- Align schema with code: `sealed` remains in the enum for documentation but
  validation continues to refuse it (`SealedNotImplemented`); document that in
  the schema `$comment` (already present).
- Python: same gate in `cli.post` / `Node.post_objective` entry.

**Not consensus-critical for ids** as long as accepted records still serialize
identically; the gate only rejects more inputs.

---

## 2. `proofwork verify --from <checkpoint>`

**Today.** ML-DSA-65 checkpoints bind `(height, head, merkle_root)`. Daemon
writes them. No reader CLI.

**Design.**

```text
proofwork verify --from checkpoint.json [--root-key pubkey.hex|file] [--log …] [--audit]
```

Semantics for a reader who may hold only a fragment or a longer log:

1. Parse `SignedCheckpoint`; verify the signature against the pinned root key
   (explicit `--root-key`, else the key embedded in the checkpoint file after
   the operator has published it out-of-band — still require an expected key so
   a rewritten file cannot swap both payload and key unnoticed when the reader
   pins the operator's key).
2. Require `ledger.len() >= height`. A shorter log cannot prove the checkpoint.
3. Take the **prefix** of length `height`, recompute head and Merkle root, and
   require equality with the checkpoint. A longer log is fine: the reader is
   verifying that their prefix matches what the operator signed, not that they
   have nothing after it.
4. Optionally `--audit` / `--audit --no-rerun` on that prefix (re-derive
   settlements for records present).
5. Exit 0 on success, 1 on mismatch/bad signature, 2 on usage/IO.

Add `Ledger::prefix_view(height)` (or equivalent) so Merkle/head are computed
without mutating the file. Threat-model row moves from *partial* to *handled*
for log rollback once this lands.

---

## 3. Sandbox verifier execution

**Today.** Subprocess + wall-clock kill. Child inherits user, FS, and network.
Documented launch blocker.

**Design.** OS-level jail around every pinned-code spawn (`run_pinned`, and any
other path that executes objective-authored code):

| Platform | Mechanism |
|---|---|
| Linux | `bwrap` when present: `--unshare-net`, `--die-with-parent`, RO binds for
interpreter + objective bundle + `/usr`/`/lib` as needed, tmpfs workdir, clear
env except `PATH`/`LANG`, soft output already capped by harvest parser |
| macOS | `sandbox-exec` seatbelt profile: deny network, restrict writes to the
workdir |
| Fallback | Current subprocess. If `PROOFWORK_REQUIRE_SANDBOX=1` (or the objective
is treated as untrusted), missing jail → `Unavailable`, never `Reject` |

Also:

- Memory / address-space soft limit via `RLIMIT_AS` / `RLIMIT_CPU` where the OS
  allows it (best-effort; failure to set is logged in evidence, not a reject).
- Update `SANDBOXING` to describe what is enforced and what still is not
  (no gVisor/Firecracker yet; path-pin / code-distribution still open).
- Reference implementation: document parity gap or spawn under the same wrappers when
  available; do not silently claim a jail it does not have.

Threat-model: malicious objective code moves from *launch blocker / not
handled* to *partial* (OS jail, not a VM boundary).

---

## 4. V3 statistical verifier

**Today.** Ladder row and threat-model row only.

**Design.** New kind `statistical`, locally checkable at Stage 0 (no committee):

```json
{
  "kind": "statistical",
  "statistic": { "path": "…", "sha256": "…" },
  "entrypoint": "statistic",
  "threshold": 50,
  "direction": "minimize",
  "seed": 0
}
```

Rules:

- The **test statistic and threshold are part of the objective** (hence of its
  id). Choosing them after seeing data requires posting a different objective.
- Pinned `statistic(artifact, seed) -> int` only. Floats are `InvalidSpec`.
- `direction` + `threshold` decide accept/reject exactly as `evaluator`.
- Any Monte Carlo inside the statistic must be driven by the pinned `seed`
  (default 0) so two honest nodes agree bitwise.
- Schema enum gains `statistical`. Conformance vectors regenerated; **old
  vectors unchanged**.

Committees for expensive resampling remain Stage 2; Stage 0 only admits
deterministic (seeded) statistics.

---

## 5. Epoch-batched commit–reveal

**Today.** Immediate reveal after matching commitment. `min_improvement` only.

**Design.**

1. `commit_epoch = epoch_of(unix(commitment.created_at), EPOCH_SECONDS)`.
2. On reveal, refuse unless `epoch_of(unix(reveal_ts), EPOCH_SECONDS) > commit_epoch`
   (`RuleViolation::RevealBeforeEpoch`). Nobody can act on a competitor's
   artifact inside the same epoch.
3. When multiple acceptable reveals for one progressive objective would settle
   in the same reveal epoch, **order by**
   `H(beacon(reveal_epoch, ledger_head_at_epoch_start) ‖ commitment_hash)`
   rather than append order, so the sequencer cannot reorder for profit inside
   the epoch. Plain (non-ratchet) objectives still settle once; first-by-beacon
   wins if several reveal in the same batch window.

   > **Corrected during implementation.** This originally said `claim_id`, and
   > that is grindable *by the submitter*. The anchor is public by the time
   > anyone reveals, so every input to the key that a submitter can still choose
   > is one they can re-roll until it sorts first — and a claim's id covers its
   > `created_at` and its `cites`, neither of which the commitment binds.
   > Restamping a reveal is free and unlimited. The commitment hash was fixed an
   > epoch earlier, before the anchor existed, so keying on it leaves the
   > submitter nothing to vary. Pinned by
   > `test_settlement_order_cannot_be_ground_out_at_reveal_time`.

Timestamps stay advisory for chain order; epoch membership is derived from the
**record's own `created_at` / command `ts`**, which are already in the log and
auditable.

**Demo / test impact.** Same-second commit+reveal fails. Tests and scripts must
commit in epoch N and reveal in N+1 (e.g. `created_at` at `t` and reveal `ts` at
`t + EPOCH_SECONDS`). Optional `PROOFWORK_EPOCH_SECONDS` overrides the constant
for local demos only; production default remains 600. Override does not change
canonical record bytes.

Sealed threshold-open remains complementary (censorship), not a substitute; wire
it later if time allows without blocking this item.

---

## 6. Population gossip transport

**Today.** `Population` CRDT + `digest()` locally. Record anti-entropy on
McEliece sessions. Populations do not cross the wire. Peer set is static
bootstrap.

**Design.** Parallel message family on the existing session, never mixed into
record buckets:

```text
PopDigest   -> population digest + candidate ids
PopWant     -> candidate ids lacking
PopRecords  -> Candidate bodies (cap count + bytes)
```

> **Narrowed during implementation.** `PopDigest` carries the population digest
> and the full id list, not per-island digests. A population holds at most
> `islands × capacity` candidates by construction — 256 at the defaults — so the
> id list fits in one message and an island-level summary would be a second
> round trip buying nothing. The digest is still sent first, so two peers
> already in sync exchange one message each way. Ids, not artifact ids: a
> candidate's identity includes its claimed score on purpose, so that two peers
> disagreeing about one artifact's score exchange both entries rather than
> silently picking one.

Rules:

- Always **re-score** on ingest (`ingest`), never trust the peer's score.
- Message ceilings before allocation (same DoS posture as records).
- **Peer sampling (Stage 0):** each tick, dial a random subset of the address
  book (and any peers learned from a signed, size-capped peer-list exchange).
  Sybil resistance stays weak and documented; structured overlays are Stage 2+.

  > **Partially delivered.** Random sampling of the address book is built
  > (`AddressBook::sample`, one endpoint per peer, rejection-sampled indices,
  > default fanout 3). The **peer-list exchange is not**, so the book still only
  > grows from `--bootstrap` files. `docs/p2p.md` lists it under *Still open*
  > rather than implying the peer set is dynamic.

Daemon optionally persists a population file and syncs it after record sync.

---

---

## 7. Formal model (TLA+) — required, not optional

Every protocol rule above is a claim about what can happen when messages
interleave, an operator is adversarial, and peers crash. Tests exercise the
paths someone thought of. A model checker exercises the ones nobody did, and
this repository's whole proposition is a property (*anyone can re-derive every
settled result*) that no unit test can state.

So: **the scheme is specified in TLA+ and model-checked, and the specification
ships in the repository.** A rule that is implemented but not modeled is
incomplete work, and a divergence between spec and code is a bug in one of
them — to be resolved, not annotated.

### Layout

```
spec/tla/
  Ledger.tla         Checkpoint.tla     CommitReveal.tla
  Verification.tla   Frontier.tla       Attribution.tla
  Gossip.tla         Sync.tla           Partition.tla
  Proofwork.tla      *.cfg              README.md
```

### What each module must state and check

| module | models | key properties |
|---|---|---|
| `Ledger` | append-only hash-linked log, adversarial rewrite | chain integrity; append-only; a rewritten suffix changes head |
| `Checkpoint` | signed `(height, head, root)`, reader with a fragment | a valid shorter prefix is **detected**; `verify --from` accepts iff the reader's prefix at `height` matches the signed anchor (item 2) |
| `CommitReveal` | epochs, commit in N / reveal in N+1, beacon ordering | binding (no reveal without a matching commitment); **no in-flight front-running** — an adversary who observes epoch N cannot settle a derived artifact ahead of the original; settlement order within an epoch is a function of the beacon, so arrival-order permutations settle identically (item 5) |
| `Verification` | the four-status taxonomy | `Unavailable` and `InvalidSpec` never settle; a verifier outage never becomes a rejection; the objective stays open (temporal liveness under outage); two honest nodes agree on any settling verdict — including the seeded statistical kind (item 4) |
| `Frontier` | ratchet, `min_improvement`, telescoping | frontier score is monotone; total paid over any improvement path equals the pool regardless of step count; `sum(paid) <= reward` always; a duplicate artifact never pays twice |
| `Attribution` | citation DAG, per-hop decay | citations point backwards only, so the DAG is acyclic and flow terminates; exact conservation — no value is created |
| `Gossip` | population CRDT with top-K pruning | merge commutative, associative, idempotent; pruning is confluent (dropping a candidate outside the top K never changes the union's top K); convergence under fair pairwise merge (item 6) |
| `Sync` | record anti-entropy over bucket digests | honest peers converge; **derived records never cross the wire**; unsolicited records are refused; a colliding digest costs the liar its own gossip and hides nothing from a re-verifying peer |
| `Partition` | coordinator-free assignment | assignment is a pure function of `(beacon, node, objective)`; slices cover the space; epoch rotation bounds squatting |
| `Proofwork` | composition of the above | the Stage 0 guarantee: **every settled result is re-derivable from the log alone**, and the objective pool is exactly conserved |

### Tooling

- `scripts/tla.sh` runs TLC over every module with its `.cfg`. It locates a JDK
  (`JAVA_HOME`, then Homebrew's unlinked `openjdk@21`, then `PATH`) and fetches
  `tla2tools.jar` into a gitignored cache if absent. No JDK and no cached jar
  means **skip with a clear message**, never a false pass — the same
  `Unavailable ≠ Reject` discipline the verifiers use.
- `make tla` and a CI job. CI failure on a violated invariant is the point.

### Honesty about what this buys

`docs/formal-model.md` marks every property **checked / bounded-checked /
assumed**, the way `threat-model.md` marks attacks. TLC results are for finite
instances at stated bounds, not proofs for all inputs; hashing is modeled as an
injective abstract function, so collision attacks are *assumed away* rather than
verified; the sandbox is an OS boundary and cannot be modeled as one. Say so.
Overstating a model check is the same failure as overstating a mitigation.

---

## Implementation order

1. Schema gate + `verify --from` (independent, low id risk).
2. Sandbox wrapper around existing spawn paths.
3. V3 kind + schema/conformance (consensus-critical; regenerate vectors carefully).
4. Epoch-batched reveal + test/demo timestamp updates.
5. Population wire protocol + simple sampling.
6. TLA+ modules and TLC configs, developed against the semantics above rather
   than against the code that happens to exist.
7. Update `roadmap.md`, `threat-model.md`, `verification.md`, `p2p.md`,
   `coordination.md`, `formal-model.md`; run `cargo test`,
   `interop.sh`, `tla.sh`.

Items 1–5 and item 6 are independent enough to proceed in parallel; the design
above is the contract between them.

## Acceptance

A Stage 0 checkbox in `docs/roadmap.md` means **two** things, and only two:

1. The behaviour is implemented in Rust *and* Python where both are affected.
2. Tests cover it, and `conformance/vectors.json` has no diff in pre-existing
   vectors.

Whether the rule is also *modelled* is tracked separately, in
`docs/formal-model.md`. This was originally written as a third condition on the
same checkbox and that was a mistake: "ships and is tested" and "TLC has checked
it at these bounds" are different claims with different strengths, and a single
tick that means both lets the weaker one borrow the authority of the stronger.
Keeping them apart is also what makes it possible to say a property is
implemented but *not yet* modelled without either lying or holding up the box.

Both remain required — a rule that is implemented but not modelled is
incomplete work, and a divergence between the specification and the code is a
bug in one of them, to be resolved rather than annotated. That last rule earned
its keep during implementation: the intra-epoch ordering key moved from the
claim id to the commitment hash (§5), and the model had to follow.

The threat-model status column is updated honestly — *partial* where the jail is
an OS boundary rather than a VM, and *bounded-checked* where a property holds
only at the model's stated bounds.
