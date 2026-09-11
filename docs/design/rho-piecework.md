# Distributed Pollard rho as a piecework objective

**Status: Stage A built** (`src/piecework.rs`, the `piecework` branch of
`settle_one` in both implementations, the `piecework` conformance section,
`examples/certicom-ecdlp/{jobs,checkers/*_rho_dp.py,tools/rho_dp.py}`,
`scripts/piecework-demo.sh`). Stages B and C below are still proposals. One
departure from §3 as first written: the walk is pinned by the *job document*
whose hash the checker carries, not derived from the objective id — the id
covers the checker, so the job is inside the id either way, and the `crypto`
implementation runs the same job file unchanged. Written against
[`node.rs::settle_one`](../../src/node.rs), [`partition.rs`](../../src/partition.rs),
[`frontier.rs`](../../src/frontier.rs) and
[`examples/certicom-ecdlp/`](../../examples/certicom-ecdlp/), and against the
collaborative rho in [`aburan28/crypto`](https://github.com/aburan28/crypto/pull/115)
(`src/cryptanalysis/pollard_collab/`, [design note](https://github.com/aburan28/crypto/blob/claude/pollard-p2p-collaborative-nq7ofh/docs/POLLARD_COLLAB_DESIGN.md)),
which is where the walk, the record format and the CRDT merge referred to
below live.

## 1. The gap this closes

cairn pays for verified outputs and never for claimed effort. An ECDLP is its
canonical objective: checking `k` is one scalar multiplication. But the only
instance worth a network is one nobody can solve alone, and
[`examples/certicom-ecdlp/README.md`](../../examples/certicom-ecdlp/README.md) says what that does to the bounty:
ECCp-131 is "posted as a benchmark rather than as work anyone expects to
finish". About 2^65 group operations, one artifact at the end, nothing
checkable in between. A winner-take-all certificate objective for that is a
lottery with a thousand-GPU-year ticket price, and nobody buys a ticket.

The collaborative rho in `crypto` shows the way out, because it already
has to solve the same problem for untrusted peers: **a distinguished point is
a verified output.** A record `(x, y, a, b)` with `a·P + b·Q = (x, y)` and the
low `d` bits of `x` zero costs `2^d` group operations to produce by the
cheapest known method, costs two scalar multiplications to check, and is the
exact piece of shared state the search runs on. It is proof of work that is
also the work. So the search decomposes into artifacts cairn can already pay
for, and the one thing cairn lacks is a way to pay for *many* of them on one
objective.

## 2. Concept map

| `pollard_collab` (crypto) | cairn | note |
|---|---|---|
| `JobSpec` (curve, `P`, `Q`, `n`, `dp_bits`, branches, seed) | the objective's pinned checker | constants baked into the checker file, so the job is inside the objective id |
| job id | objective id | derive the branch table and walker starts from the objective id instead of the spec hash |
| distinguished-point record | a claim's artifact | one DP per claim in Stage A; batches in Stage B |
| `DpRecord::verify` | the `certificate` checker | on curve, distinguished, canonical `y`, `a·P + b·Q = (x, y)`, `a, b ∈ [0, n)` |
| work unit (walker-index range) | `partition::assign` slice | `work_assignment` already hands every node a per-epoch slice of a `2^32` space; map walker indices onto it |
| check-in / CRDT merge | commit–reveal claim, then the log | the log *is* the DP table; every node's derived index of accepted DPs is the same table |
| lease expiry / resume | not needed | unfinished units cost nothing; a DP is paid whoever finishes the trail |
| collision → `k` | the existing certificate objective | whoever holds the colliding DP submits `k` |
| progress fraction | `GET /frontier/{id}` | derived: accepted DPs over expected DPs |
| mailbox / TCP gossip | `POST /submit` + `GET /log` | a third transport for `rho-collab work` |

## 3. Two objectives, linked by one checker

**The answer objective** already exists: `objective-certicom-eccp131.json`,
kind `certificate`, artifact `{"k": "<64 hex>"}`. Unchanged.

**The work objective** is new: kind `certificate`, with a checker that pins
the *same* curve, `P`, `Q`, `n` **plus** the walk parameters (`DP_BITS`,
`NUM_BRANCHES`, the derivation seed) and a `piecework` payout block:

```json
{
  "goal": "GOAL-certicom-eccp131",
  "statement": "Contribute distinguished points to the shared rho table for ECCp-131. Artifact: one point (x, y) with the low 44 bits of x zero, y <= (p-1)/2, and coefficients a, b in [0, n) with a*P + b*Q = (x, y). Each accepted point pays unit_price from the pool until it is exhausted. Points are the shared state of the search: whoever's point collides with one already in the log can compute k and claim GOAL-certicom-eccp131. The walk everyone must use is derived from this objective's id; see the checker.",
  "verifier": {
    "kind": "certificate",
    "checker": "examples/certicom-ecdlp/checkers/eccp131_rho_dp.py",
    "checker_sha256": "…",
    "entrypoint": "check"
  },
  "piecework": { "unit_price": 1000 },
  "reward": 2600000000,
  "funder": "treasury",
  "created_at": "…"
}
```

The artifact is exactly four hex strings, nothing else:

```json
{ "x": "…", "y": "…", "a": "…", "b": "…" }
```

Why nothing else: cairn's duplicate rule keys on the artifact digest
(`settle_one`: "duplicate artifact mints nothing"). For a fixed point
`(x, y)` the coefficient pair is unique unless you know `k`, so two honest
peers who reach the same DP produce byte-identical artifacts and the second
mints zero with **no new consensus state**. A walker index or step count in
the artifact would let a copier re-mint a public DP by relabelling it. The
checker also requires the canonical `y ≤ (p−1)/2`, so the negation-map
representative is unique too.

The checker is the same shape as `nums_dlog.py`: pure, integer-only, scores
malformed input as a rejection rather than raising, and it re-derives nothing
from the log. It is ~40 lines on top of the existing `_add`/`_mul`.

## 4. The one consensus change: `piecework`

Today a non-ratchet objective settles once (`settle_one` → "objective already
settled"), and the ratchet pays for moving a scalar frontier. A DP objective
needs a third branch:

```text
if objective.piecework:
    if artifact is a duplicate (existing rule):      mint nothing
    pay = min(unit_price, pool_remaining)
    if pay == 0:                                     unsettled, "pool exhausted"
    credit submitter `pay`; pool_remaining -= pay
```

- `piecework` sits beside `ratchet` in the record: omitted when absent, part
  of the id when present, validated by a `Piecework::from_value` the way
  `Ratchet` is. `piecework` and `ratchet` on one objective is `InvalidSpec`.
- Batch order inside an epoch is the existing beacon order, so who is paid
  from the last few units of a nearly-empty pool is not the sequencer's
  choice.
- Conservation holds trivially: the sum paid is `min(pool, unit_price ×
  accepted-novel-claims)`.
- A funder tops up by posting another piecework objective with the **same
  checker**. Because the checker pins the walk, both objectives are the same
  job; contributors point their lane at whichever has pool left. Duplicate
  detection is per objective today, so a DP paid under objective A could be
  re-submitted under top-up B. Fix in the same change: key
  `artifact_ids_before` on `checker_sha256` when the objective is piecework,
  so a top-up inherits the original's history.

Both implementations change together: `src/` and `reference/rust/`, new
conformance vectors added alongside the frozen ones, `differential.sh`
extended with a piecework log. This is a settlement rule, so
`docs/threat-model.md` gets a row and `cairn arena` gets a scenario (§7).

## 5. Work split: reuse `partition`, do not build a dispatcher

cairn already refuses to schedule work: `work_assignment` returns a node's
slice `[lo, hi)` of a `2^32` space for the epoch, as a pure function of the
beacon, node id and objective id. Walker indices map onto it directly:
walker `i` belongs to the node whose slice covers `position("rho|" + i)`.
A lane walks the indices in its slice, in order, and moves on when the epoch
turns.

Everything [`coordination.md`](../coordination.md) says then applies unchanged:

- Two nodes walking the same index produce the **same** DP; the second copy
  mints nothing. Overlap is wasted compute, self-correcting, never an error.
- Nothing needs agreement, so partition changes are free to rotate every
  epoch, and squatting a range buys nothing because an unwalked range costs
  the network nothing — a DP is a DP whatever index it came from.
- The `pollard_collab` leases and cursor resumption are unnecessary here and
  are dropped: cairn pays for the artifact, not for finishing a unit.

The only thing the walker index still buys is auditability (§7), which is
why Stage B puts it back into a *batch* artifact once the derived index
exists to dedup on the point rather than the bytes.

## 6. Collision, `k`, and progress

Every node that verifies the log holds every accepted DP, so every node can
keep a derived index `x → (a, b, y)` for each rho checker. That index is a
*view*, like `knowledge` over `relations`: it reads the log and moves no
money.

- **Finding `k`.** A contributor checks each new DP against the index before
  submitting. On a hit with different coefficients it computes `k` locally
  (`solve_collision` in `state.rs`, both same-point and negated-point
  cases), commits a claim to the answer objective **in the same epoch** as it
  commits the DP, and reveals both next epoch. Commit–reveal is what makes
  this safe: once the colliding DP is revealed anyone can compute `k`, but
  the finder's commitment is already an epoch old.
- **The rules engine does not compute `k`.** It could, but a payment that
  fires because a node ran a derivation the submitter never signed is a
  new thing in cairn; "an agent proposes, only the rules engine disposes"
  keeps `k` a claim like any other. A collision nobody claims stays visible
  in the index and is claimable by anyone.
- **Progress.** `GET /frontier/{id}` on a piecework objective reports
  `accepted / expected` where `expected = √(πn/2) / 2^d` (halved by `√2`
  under the negation map), and pool remaining. Same figure the
  `pollard_collab` status prints.

## 7. What this pays for, honestly

The argument that a DP is worth paying for is an argument about the cheapest
way to make one, and it has a hole that Stage B closes.

- **Honest walk.** `2^d` steps of the shared walk, in expectation. Yields a
  DP *and* `2^d` visited points under the shared function; any other trail
  entering those points merges and collides. This is the useful work.
- **Random sampling.** Pick random `(a, b)`, compute `a·P + b·Q`, hope `x`
  is distinguished: `2^d` trials, each costing two scalar multiplications —
  about a thousand times an honest walk step. Irrational.
- **Private walk.** Walk with a *different* step function until a DP.
  Costs the same `2^d` steps, verifies identically, pays the same, and
  contributes only the endpoint: no honest trail follows a private trail.
  A contributor gains nothing over honesty, so this is vandalism rather
  than fraud, but vandalism the pool pays for at cost.
- **Forged coefficients.** Impossible without `k`.
- **Relabelled copies.** Killed by the duplicate-artifact rule (§3).
- **Self-dealing.** Already handled for the ladder by nothing-up-my-sleeve
  instances; ECCp-131's `Q` is Certicom's.

Stage B closes the private-walk hole the way cairn closes verification
laziness: sampling and canaries. The batch artifact carries walker indices
and trail lengths; a sampled audit re-walks one trail from its derived start
(cost `2^d`, the same as the work, at a sampling rate ε) and a mismatch is a
bonded slash under `require_signed_submitter`. [`bonded-verification.md`](../bonded-verification.md)
is the mechanism; the DP re-walk is just its check.

`cairn incentives` should get the numbers before anything is funded: the
decomposition floor in [`incentive/design.rs`](../../src/incentive/design.rs) says a sub-artifact the
network verifies for more than it settles is subsidised by everything else,
and at reference parameters that is 800,000 units per artifact under full
redundancy or `8,000·k` under `k`-fold sampling. A DP check is two scalar
multiplications, but per-claim overhead (two records, a jailed subprocess
spawn) dominates at these sizes, which is the case for batching.

## 8. Sizing

`d` sets the trade between claim count (log size, verification overhead) and
the granularity of payment (how long a contributor works before being paid).

| instance | expected steps | `d` | expected DPs (claims) | work per DP |
|---|---|---|---|---|
| nums-50 (demo) | ≈ 2^25 | 16 | ≈ 600 | 2^16 steps, ~1 s in Rust |
| nums-60 | ≈ 2^30 | 20 | ≈ 1,300 | 2^20 steps |
| ECCp-131 | ≈ 2^65 | 44 | ≈ 2.6 M | 2^44 steps, hours on a GPU |

ECCp-131 at `d = 44` is a few million claims and a log in the low gigabytes
— which is why Stage B's batches (say 64 DPs per claim) matter there and not
for the ladder. The pool for ECCp-131 has to price 2^65 group operations;
Stage 0 rewards are notional, so the number is `unit_price × expected DPs`
and nothing more is claimed for it.

## 9. Staging

**Stage A — payable today with one rule.** `piecework` settlement; one DP per
claim; the existing duplicate rule for novelty; `work_assignment` for the
split; a derived DP index as a read-only view; `rho-collab work --cairn` in
`crypto` as the contributor. Demo on nums-50 with
`CAIRN_EPOCH_SECONDS` short: three nodes, a few hundred claims, and a
settled `k` on the answer objective, then `cairn audit` and the reference
implementation re-deriving every payment.

**Stage B — scale.** Batch artifacts `{ "dps": [ … ] }` with walker indices
and steps; the DP index becomes consensus state used for dedup on the
*point* (a relabelled DP in a new batch mints nothing) and the checker scores
the batch's valid, canonical, in-batch-distinct points; sampled re-walk
audits with bonds. This is the change that needs the reference
implementation to grow a DP index too, so it is a separate PR with its own
vectors.

**Stage C — beyond rho.** The same objective shape covers any search whose
partial outputs are certificates: Pollard kangaroo over an interval
([`crypto/gpu/btcpuzzle/`](https://github.com/aburan28/crypto/tree/main/gpu/btcpuzzle) produces exactly these records), multi-target rho, and
relation collection for index calculus or NFS, where a relation is a
certificate checked in microseconds. `piecework` is the primitive; the rho
checker is its first instance.

## 10. Concrete change list

Here (Stage A, done unless marked):

1. `records.rs`: optional `piecework` block on `Objective`, omitted when
   absent, inside the id when present; `spec/objective.schema.json` entry;
   `Piecework` type in `frontier.rs` (or a sibling module) with validation.
2. `node.rs::settle_one`: the piecework branch (§4); `settlement_of` and
   the frontier route report pool remaining.
3. `reference/rust/`: the same two; new conformance vectors added, none
   regenerated.
4. `examples/certicom-ecdlp/`: `checkers/eccp131_rho_dp.py`,
   `checkers/nums_50_rho_dp.py`, objectives, README section; the walk
   derivation (branch table and walker starts from the objective id) written
   down in the checker's docstring so a second implementation can match it.
5. [`threat-model.md`](../threat-model.md): rows for private-walk DPs (partial, Stage B) and
   piecework top-up dedup (handled); `docs/coordination.md`: the rho case as
   the worked example of "work split is a pure function".
6. `src/arena.rs`: a scenario where a submitter relabels public DPs, expected
   verdict CLOSED. *Not yet: the relabelling is refused by the checker's
   exact-keys rule and covered by `tools/rho_selftest.py`; an arena scenario
   is still worth adding.*

In [`crypto`](https://github.com/aburan28/crypto):

1. `pollard_collab::job`: accept an external job id (the objective id) in
   place of the spec hash.
2. `pollard_collab::cairn` transport: `publish` = commit then reveal a claim
   through `POST /submit`; `sync` = read `GET /log`, verify DPs, merge; the
   lane keeps `SharedState` as its local index and calls `solve_collision`
   before every submission.
3. `rho-collab work --cairn <url> --objective <id> --identity <file>`.
