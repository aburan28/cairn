# Multi-operator ordering: causal clocks without a pay-to-spam lottery

*Design note for plan item 8. Written 2026-09-25 after the owner decision:
Lamport / vector clocks, game-theoretically solid, no path for spam or
manipulation to reorder payouts.*

## The sentence that has to stay true

> Two nodes holding the same records pay the same claims in the same order.

That already holds for a **single writer** once the epoch chain and finality
delay landed — see [settlement-convergence.md](settlement-convergence.md). The
open question is what happens when **several operators** append to what is
logically one objective, and a submitter tries to game who was first.

## What Lamport / vector clocks give, and what they refuse to give

A **Lamport clock** is a total order over events that respects causality. It
does **not** decide which of two concurrent events "really happened first" in
wall time — it only invents a total order by breaking ties on process id. A
submitter who can choose their own process id, or spawn many, wins every tie
they care about. That is not game-theoretic solidity; that is a free lottery.

A **vector clock** (or any causal DAG: hash-linked cites, happens-before on
record ids) detects *concurrency*. Two frontier moves that neither cites the
other are concurrent. That is the useful signal. It does **not** pick a winner
between them. Picking a winner is a separate problem, and it is the one that
moves money.

So the protocol uses clocks for conflict **detection**, never for settlement
**priority**.

## The shape that is solid

Three layers, each with one job:

### 1. Causal DAG (vector clocks / content addresses)

Every record that depends on another **names it**. Claims already do this with
`cites`. Operator appends that advance a shared frontier must cite the prior
frontier claim. Two claims that both cite the same frontier and neither cites
the other are concurrent — the conflict is visible on every honest node.

Vector clocks are the compact encoding of that DAG when the set of writers is
known and small (one clock entry per operator identity). Content-addressed
`cites` already is the DAG when writers are open. Prefer the cite DAG for
open contribution; use vector clocks only for a closed operator set that needs
compact gossip of "I have seen your seq N".

### 2. Fair total order inside an epoch (already built)

Settlement order is

```text
H(beacon(epoch, anchor) ‖ commitment_hash)
```

not claim id, not arrival time, not Lamport time. The commitment hash is fixed
before the beacon is known, so a submitter cannot re-roll `created_at` or
`cites` to draw a better ticket. The beacon is public by reveal time. This is
the game-theoretic core that already exists; multi-operator work must not
replace it with a submitter-influenced clock.

See `AGENTS.md` ("Settlement order is keyed on the commitment hash") and
[settlement-convergence.md](settlement-convergence.md).

### 3. Who may append (sequencer or federation)

Causal detection plus fair batch order still need a rule for **admission**:
whose append is in the log. Options, ranked for this deployment:

| option | censorship resistance | complexity | when |
|---|---|---|---|
| **(a) One sequencer per objective**, named in the objective (omitted = poster) | residual: that sequencer can drop records; sealed submissions force indiscriminate drops | lowest | **now** |
| **(b) Operator federation** under BFT for append order | high among members | membership governance | when one sequencer is the complaint |
| **(c) External anchor** (OpenTimestamps / chain) of settlement roots | proves a checkpoint existed; does not by itself order live appends | fees / rail | optional Stage 3 |

Owner decision for the first cut: **(a)**, with vector-clock / cite conflict
surfacing so a sequencer that silently prefers one concurrent claim over
another is detectable, and with sealed submissions so targeted content
censorship stays expensive. Design (c) as optional later. Take (b) only if
cross-operator atomicity across objectives starts to matter.

## What "bullshit" this closes

| attack | defence |
|---|---|
| Re-stamp a claim until it sorts first | Settlement key is the commitment hash, which the stamp does not change |
| Invent a Lamport time that wins every tie | Clocks never feed settlement order |
| Concurrent frontier claims, silent pick | Surface the conflict; both verify; payout order still follows the beacon |
| Sequencer drops one submitter's reveals | Sealed path: committee opens without the submitter; indiscriminate drop is visible |
| Spam the log with junk | Existing admission rules (bonds, verification, duplicate-zero mint); clocks do not mint |

## What this deliberately does not do

- It does **not** invent a new token or a new chain for ordering.
- It does **not** let wall clocks or operator clocks decide who was paid first.
- It does **not** collapse `Unavailable` into `Reject` when an operator is
  offline — that hand an attacker a way to fail honest work by taking a
  verifier down.

## Implementation sketch (not yet built)

1. **Conflict record or derived view.** Given an objective's claim set, emit
   the concurrent frontier pairs (neither cites the other; both cite the same
   prior frontier). Readable from the log alone.
2. **Optional `CausalStamp` on operator-authored records** for closed
   multi-writer logs: `{operator_id → counter}` vector, verified against that
   operator's previous append. Refused if it claims to have seen a counter the
   log does not contain.
3. **Arena scenario.** Sequencer that reorders two concurrent improvements —
   verdict PROTECTED if payout order still matches the beacon, OPEN if a clock
   or arrival order leaked into settlement.
4. **Both implementations.** Any record shape that enters settlement must land
   in `src/` and `reference/rust/` together; frozen vectors stay frozen.

## Relation to existing docs

- [settlement-convergence.md](settlement-convergence.md) — same-records same
  order under one writer; this note extends the *multi-writer* case.
- [p2p.md](../p2p.md) — grow-only set sync; still does not order settlement.
- [censorship.md](../censorship.md) — sealed submissions attack targeted drop.
- Plan item 8 in [plan.md](../plan.md) — this is the design that item asked for
  before code.
