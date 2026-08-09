# Anchored time: what a shared clock would buy, and what it would cost

**Status: analysis only. Nothing here is built, and one part of it should
probably never be.**

"Replace the beacon with a VDF or threshold signature" has been on the list for
a long time — [`threat-model.md`](../threat-model.md) carries it as **beacon
grinding / not handled**, [`roadmap.md`](../roadmap.md) has it under Stage 1,
and [`coordination.md`](../coordination.md) and
[`formal-model.md`](../formal-model.md) both point at it. This note does not
propose it again.

What it records is that **the thing being asked for got larger**, and nobody
has written down the second and third reasons to want it. The beacon was filed
as an *anti-grinding* measure. Since
[`settlement-convergence.md`](settlement-convergence.md) landed it also bears on
*convergence*, and there is a third use — priority — that appears nowhere.

Read this after that note. It assumes the epoch chain.

## The undocumented half: the clock reaches settlement now

`src/time.rs` used to say that ordering comes from the hash chain and never from
the clock, so a wrong clock was cosmetic. That was true when it was written and
is no longer, and the comment has been corrected. The chain is:

```
proofwork-p2p / service.rs   settle_at(&timestamp())        ← local wall clock
Node::settle_at              epoch_of_timestamp(ts)          → now_epoch
Node::due_epochs             epoch < now_epoch               → which epochs drain
settlement-convergence       drain *sequence* fixes the anchor
partition::beacon            H("{epoch}:{anchor}")           → the settlement sort key
```

Every step there is in the code today. Put together: **two honest nodes whose
clocks disagree can drain the same epochs in different sequences, and pay the
same claims in different orders, with both logs auditing clean.** That is
`draining_epochs_in_a_different_sequence_forks_the_chain`, and clock skew is one
way to reach it.

This is not a new bug. It is the same open case that note already records, seen
from the direction nobody documented: the case is usually described as *learning
order*, and *clock skew* produces it just as well on nodes that learned
everything at the same time.

## Three problems, and how much of each a shared clock solves

| | what it is | does an anchored clock fix it |
|---|---|---|
| **beacon grinding** | a sequencer chooses ledger heads to place itself favourably | **yes, fully** — already the reason it is on the roadmap |
| **drain sequence** | nodes draining in different orders compute different anchors | **partly** — removes skew, leaves learning order |
| **priority** | `created_at` is submitter-chosen, so anything can be backdated | **yes**, and nothing else does |

### Priority is the one that is not written down anywhere

Commit–reveal stops a submitter copying somebody else's artifact. It does
nothing to stop them backdating their own, because `created_at` is a field they
choose, and `src/time.rs` is explicit that timestamps are advisory. There is no
way, today, for the log to establish that one claim preceded another except by
the order one node happened to write them.

For a network whose unit of account is *who got there first*, that is a larger
gap than it looks, and it is the one an anchored timestamp closes outright
rather than partially.

### Drain sequence: why "partly" is the honest answer

Gating drain on a shared value — "epoch `e` may drain once beacon round `r(e)`
is published" — makes every node's *trigger* identical, so skew stops
contributing. What remains is the case
[`settlement-convergence.md`](settlement-convergence.md) describes directly: a
node that has not yet *learned* an epoch's work cannot drain it on time no
matter what clock says so.

So the decomposition is:

- a shared clock removes **skew**,
- a finality delay removes **propagation lag**,
- neither removes **partial view**, which is the liveness/agreement tradeoff and
  has no cheap answer.

The finality delay in that note's *Next* section is a rule about time. This is
the clock it would be measured against, which is why the two belong in the same
decision rather than in sequence.

## The stronger move, and why it might be wrong

`partition::beacon` is `H("{epoch}:{anchor}")`, and `anchor` is the epoch-chain
head — local drain history. Replace that input with an external beacon value for
the epoch and **drain sequence stops mattering to the sort key at all**, because
the key is no longer a function of anything local. Case one of the two open
cases would not be narrowed; it would be gone.

It also *strengthens* the property `AGENTS.md` actually cares about. The
requirement is that the sort key be fixed before anyone reveals and not
re-rollable. Today's anchor satisfies that and is nonetheless **knowable in
advance** to anyone watching the log. A beacon round published at epoch end is
unknowable at commit time and fixed before reveal — strictly better on the
stated property.

**And it is probably still the wrong trade for Stage 0.** It converts a system
that needs no external agreement into one that cannot settle when an outside
service is unreachable. [`consensus.md`](../consensus.md) spends its length
arguing that correctness here is not a consensus question and that the narrow
thing needing agreement should be bought as cheaply as possible; introducing a
hard liveness dependency on a third party to fix an ordering edge case is not
obviously that. It should be a decision somebody makes on purpose, which is why
this note stops at describing it.

## The options, with their real costs

| | what it is | liveness cost | grind resistance | effort |
|---|---|---|---|---|
| **local wall clock** (today) | `SystemTime::now()` | none | none — the operator sets it | — |
| **logical high-water mark** | drain `e` once accepted claims exist in `e + k` | stalls on a quiet network; withholding delays settlement | good — a function of shared content | small |
| **external beacon** (drand-style) | cite a published round | cannot settle if unreachable | very good — unpredictable, publicly verifiable | medium |
| **self-hosted VDF** | sequential squaring, succinct proof | none external | very good | large, and someone must run it |
| **threshold signature** | committee signs each round | committee liveness | good, up to collusion | medium, needs a committee |

The **logical high-water mark** deserves more attention than it usually gets. It
needs no outside party, no new cryptography and no clock: an epoch becomes
drainable when the log itself has moved past it. It converges because it is a
function of content every node shares. Its failure mode is a quiet network never
advancing, and its attack is withholding to delay settlement — both real, both
smaller than a third-party dependency. If any of this gets built first, it
should probably be that.

## What this does not fix

**Partial view at drain time.** Nothing here touches it. A node that drains an
epoch before sync delivered one of its claims writes a different link, and the
chains diverge permanently. That is the ordinary liveness/agreement tradeoff and
the honest options remain the two that note names: a finality delay, or reorgs.

**Whether an assertion is true.** An anchored timestamp establishes that
something was *recorded* by a time, never that it is correct. That distinction
is the same one [`attested-fact`](../../examples/attested-fact/README.md) is
about, and it is worth keeping straight: a timestamped lie is a lie with a date.

## What would have to move together

Not a drop-in. `partition::beacon` feeds both settlement rank and work
assignment, `conformance/vectors.json` pins `beacon`/`settlement_rank` against a
literal `"anchor"` string, and both implementations derive it. Per `AGENTS.md`,
`src/` and `reference/rust/` change together.

The vectors are the thing to check first, and the news is better than expected:
settlement-convergence changed how the anchor is *derived* without moving them,
because they constrain the **function** and not its inputs. A beacon that is
still a string fed to the same function would very likely leave them alone too —
which would mean no record id moves and no live claim is orphaned. That should
be confirmed before anything is written, not assumed, because it is the
difference between a contained change and a protocol break.

## Recommendation

1. **Record the priority gap** in `threat-model.md`. It is a real hole with no
   row, and writing it down costs nothing.
2. **Prefer the logical high-water mark** if convergence is the goal. No
   external dependency, no new cryptography, and it converges by construction.
3. **Treat the external beacon as a Stage 1+ decision**, weighed against
   `consensus.md` rather than slid into. It is the strongest fix for grinding and
   the only fix for priority, and it buys those with a liveness dependency the
   project has so far deliberately avoided.
4. **Do not bundle it with the finality delay.** Two rules, two failure modes,
   two tests — and the delay is useful on its own.
