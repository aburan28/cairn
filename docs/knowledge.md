# The knowledge layer

*Evidence is immutable, consensus is versioned, knowledge is revisable.*

## The problem this closes

Everything else here is built to keep opinion out of settlement. A verifier's
`accept` mints value because it is reproducible; a majority's belief mints
nothing. That refusal is the design, and this document does not walk it back.

But it left a gap. A verified artifact is not the end of a claim's life. It gets
replicated, or it fails to replicate. It gets narrowed to the scope it actually
holds on. Its author withdraws it. A better result supersedes it. Before this
layer, the log recorded the original verdict and nothing else — so a reader
asking "is this still believed?" got the answer "it passed its checker in
2026", which is true, and is not the question.

An append-only log that records only the first verdict is not preserving that
history. It is hiding it behind whatever happened to settle first.

## The split

| | who decides | written to the log | moves money |
|---|---|---|---|
| **verdict** | the objective's pinned verifier | yes | yes |
| **relation** | the submitting claim, verified independently | yes | **no** |
| **standing** | derived, by anyone, from the two above | no | no |
| **confidence** | the **reader's** policy | no | no |

The log records *what was said and by whom*. `src/knowledge.rs` computes *what
to make of it*, under a policy the reader picks. Two readers with different
policies get different numbers from identical bytes, and neither is wrong — a
regulator demanding independent replication and a researcher scanning for leads
are asking different questions of one graph.

Nothing in the knowledge layer is written to the log, nothing in it moves money,
and nothing in it can change a settled payout. **If that ever stops being true,
the popularity contest is back.**

## Relations

Nine typed edges, carried on the claim that asserts them:

| kind | effect | means |
|---|---|---|
| `refutes` | contests | the target is wrong, and this claim is the demonstration |
| `fails_to_replicate` | contests | ran the target's procedure, did not get its result |
| `conflicts_with` | contests | both cannot hold; this claim does not settle which |
| `replicates` | corroborates | ran it, got it |
| `generalizes` | corroborates | holds more broadly than the target stated |
| `narrows` | supersedes | holds, on a smaller scope than the target stated |
| `corrects` | supersedes | fixes an error; what remains still stands |
| `supersedes` | supersedes | replaced wholesale |
| `retracts` | withdraws | the author takes back their own claim |

An evidence graph usually lists fourteen. "Supports", "depends on", "uses
dataset" and "uses methodology" are all **`cites`** — a second spelling for the
paying edge would mean two ways to say one thing, only one of which pays, and
submitters would learn which. "Reinterprets" has no distinct mechanical effect,
so it would be a comment with a schema, which is worse than a comment.

### Relations point backwards, and nothing enforces it

A claim's id covers its relations, so naming a target requires knowing the
target's id, which requires the target to already exist. Self-reference is
impossible for the same reason: computing your own id would need it as an input.
The hash-linking does the work a validity rule would otherwise have to do.

### One relation per target

Keyed on the target, not on the `(kind, target)` pair. Allowing two would mean
deciding what "refutes *and* replicates" means, and any such table is a rule two
implementations can read differently. A claim needing to say two things about
one target is two claims.

## Being heard costs a verified result

Anyone can append a claim saying "this refutes X". If that alone contested X,
contesting would be free and every frontier holder would wake up contested.

So: **a relation is heard only from a claim its objective's pinned verifier
accepted.** Asserting something about X costs whatever it costs to produce a
verified result, which is the only scarce thing this network recognizes.

Be precise about what that buys. The verifier checked the **artifact**, not the
relation. A claim that solves a Ramsey bound and declares `refutes` on an
unrelated claim has been verified for the bound and not for the refutation.
Acceptance is evidence the author did real work, not that the edge they drew is
true — which is exactly why the output is a *view* that reports who with
standing said what, rather than a verdict.

`retracts` is the exception and needs no verdict: it counts only from the
target's own submitter, so nobody else can spam it. The cost is real — a
per-objective pseudonym cannot retract work it did under a different pseudonym,
because that is the only place the same submitter string appears. The
alternative, letting a different name withdraw your work, is not a trade anyone
should want.

## Standing

Exactly one applies, resolved in this order:

1. `refuted` — the pinned verifier said `reject`. **A machine verdict, and the
   end of the discussion.** No quantity of claims asserting otherwise moves it.
2. `unverified` — no settling verdict. Includes `unavailable`, which is not a
   rejection: a verifier that could not run has refuted nothing, and collapsing
   the two here would reintroduce at this layer the attack `verifiers::Status`
   exists to close.
3. `withdrawn` — the submitter retracted it.
4. `superseded` — a verified claim supersedes, corrects, or narrows it.
5. `contested` — verified claims dispute it, unresolved.
6. `corroborated` — independently reproduced at least once.
7. `accepted` — verified, nothing further said. The resting state.

Two rules drive the order: the machine outranks the assertions, and among
assertions the narrower statement wins. `Standing::was_verified` stays true for
3–7, so a reader asking "did this pass its verifier" cannot have that answer
smuggled away by a later assertion. **A superseded claim is not a wrong claim.**

## Independence

Ten copies of one press release are not ten sources. Assertions merge into one
voice when they share:

1. **a submitter** — one party, one voice. Unconditional.
2. **an `artifact_id`** — the identical artifact under two names is one piece of
   evidence wearing two hats. The crate already computes this id to catch
   duplicate work.
3. **citation ancestry**, only when the reader asks for it.

Ancestry is off by default, and that is not laziness. At depth ≥ 1 every claim
on a ratcheted objective is correlated with every other one: the frontier
citation rule *requires* them all to cite the same claim, so ancestry overlap is
guaranteed by protocol and independence collapses to one class however many
genuinely separate parties contributed.

**None of this is sybil resistance and must not be sold as such.** A determined
attacker makes distinct identities submitting distinct artifacts citing nothing
in common, and every rule here passes them as independent. What this defeats is
the cheap version. What it buys against the expensive version is that each extra
voice now costs a separately verified result.

## Confidence

Parts per thousand, in a `u32`. A float would be the obvious choice and is
refused for the reason `canonical::Value` has no float variant: two nodes that
round differently report different confidence for one claim, and the first thing
anyone does with a confidence number is threshold it.

The order is load-bearing:

```
credit for the verdict
  + corroboration, capped        <- the cap is what stops a crowd voting a claim to certainty
  - refutations and disputes
  x superseded weight            <- applied AFTER the debit; before it, a superseded
  x unreproducible weight           claim would be harder to argue down, which is backwards
  x decay per elapsed period
```

Withdrawn is zero regardless of how well it verified: the author is the one
party whose say-so about their own work needs no corroboration, because they are
not asserting a fact about the world, they are declining to stand behind a
submission.

Decay is driven by an `as_of_epoch` **argument**, never a clock read — the rule
that holds everywhere in this crate, because a value derived from local time
makes two nodes disagree about a log they both hold whole. It is off by default.

## Availability is part of the knowledge state

The network's one guarantee is that anyone can independently re-derive every
settled result. That has a dependency nothing else tracks against a *claim*: the
objective's pinned verifier code must still be fetchable. A hash proves the bytes
you got are the bytes pinned; it does not conjure the bytes.

So a claim whose verifier code is missing is reported `re-derive: not-here` and
its confidence is weighted down. It is still in the log, still settled, still
paid — and no longer checkable, which a reader deciding whether to build on it
deserves to be told.

`not-here` is a statement about **this node**, never about the network. One
node's want set is not a global availability proof, and treating it as one would
let a node that has simply not finished syncing declare the network's evidence
lost.

## Using it

```sh
# assert what you found, alongside the citations that pay
proofwork reveal <objective-id> --submitter bob --artifact a.json --nonce n2 \
    --cites <frontier-claim> --relates refutes:<claim-id>

# read the graph back, under your own policy
proofwork knowledge <claim-id>
proofwork knowledge <claim-id> --demanding
proofwork knowledge <claim-id> --per-refutation 800 --independence-depth 1
```

`knowledge` reads the log, writes nothing, and always exits 0 — a contested
claim is not a fault in the log, it is the log working.

## What this does not do

- **It does not decide truth.** It reports who with standing said what, and
  arithmetic over that. The ledger can prove a community reached a conclusion
  under a rule set; it cannot make a claim true because signatures accumulated.
- **It does not price the relation itself.** A refutation is worth the same as
  any other verified result, and a genuinely valuable negative result is not yet
  paid as one. Paying for refutations means paying for an assertion, and the
  moment that pays, everything above needs re-deriving with money in it.
- **It does not resolve contests.** Two verified claims that `conflict_with` each
  other both stay contested forever. Resolving needs an objective whose verifier
  decides between them, which is a thing a funder can post today and the layer
  will not do on its own.
- **It does not carry scope or qualification.** A claim about "ibuprofen" cannot
  yet say *which population, dose, duration*. Scope belongs in the objective's
  statement and its `artifact_schema`, and typed scope is the natural next piece
  — `narrows` is a placeholder for a thing the system cannot yet express
  precisely.
