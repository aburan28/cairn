# Co-authorship: paying more than one party for one claim

*A design note. Nothing below is built.*

## The problem

`Claim.submitter` is one string. Settlement names it, `FrontierEntry.holder`
names it, and citation flow pays it. So two people who together produce **one
indivisible artifact** have to pick a name and settle up off-protocol — which
reintroduces exactly the trust relationship the rest of this design removes.

That is a real gap and not a hypothetical one. A proof where one person found
the construction and another discharged the verification conditions is one Lean
file. A search where one built the candidate generator and another ran it is one
artifact. Neither decomposes into two citable claims without inventing a
boundary that does not exist.

## What already covers part of it, and why it is not enough

Two mechanisms already make collaboration work, and they should be understood
before adding a third:

- **Citation flow** pays *sequential* collaboration. A settled claim keeps
  `1 - δ` and sends `δ` upstream to what it cited, recursively and forever. If
  the work decomposes, this is strictly better than co-authorship: contributors
  are paid on every downstream use rather than once.
- **Work assignment and gossip** cover *parallel* collaboration. `work_assignment`
  is a pure function of public inputs, so two nodes split a search space with no
  agreement at all, and the candidate population is a CRDT they can pool into
  without any of it becoming a claim.

Both assume the work **decomposes into citable units**. The gap is precisely the
work that does not. This is worth stating because the first instinct on reading
"we need co-authorship" is usually a problem that citation already solves better,
and the answer there is to split the objective rather than the payout.

## Design: one submitter, N consenting payees

Not "co-equal authors". The commit–reveal binding already names exactly one
party — `commitment_hash(objective_id, submitter, artifact, nonce)` — and that
binding is what stops an observer stealing a revealed artifact. Making it plural
would mean touching the most consensus-critical hash in the system.

So the submitter stays singular and unchanged, and a new field says **where the
money goes**:

```
Claim {
    submitter: String,          // unchanged: who committed and revealed
    shares: Vec<Share>,         // NEW, omitted when empty
    ...
}

Share { who: String, weight: u32, signature: String }
```

- **Omitted from the canonical form when empty**, exactly as `relations` is, so
  no existing id moves and the frozen vectors still reproduce. This is the only
  reason the field can be added at all.
- **`who` and `weight` are inside `signing_payload`**; the per-share
  `signature` is not, the same way `Claim.signature` is excluded from its own
  payload. The claim's id therefore covers who gets paid and how much, and does
  not cover the signatures that consent to it.
- **Empty `shares` means what it has always meant**: the submitter takes
  everything. There is no "implicit 100% share" record; absent and
  `[{submitter, 100%}]` must not be two spellings of one thing.

### Consent must be a signature, and that has a consequence

A payee signs the claim's signing payload. Without that, anyone could name
anyone as a payee.

The obvious objection is that naming a payee only *gives* them money, so who
cares. Two answers. First, association: being named on a fraudulent or
embarrassing claim is a cost in a research network, and there is no way to
decline it after the fact in an append-only log. Second, and more concretely,
`knowledge::KnowledgeGraph` merges independence classes on shared submitter — if
payees count for that (and they should, since a shared payee is a shared
interest), then naming a target as payee is a way to make the target's unrelated
claims look correlated and quietly deflate their corroboration.

Consent closes both, and it inherits a rule already established elsewhere: **a
payee must be key-shaped.** An unauthenticated nickname cannot sign, so it
cannot consent, so it cannot be a payee. That is the same conclusion
`knowledge::is_grounded` reached for retraction — an unauthenticated name has no
owner, so nobody can speak for it — and having the two rules agree is worth more
than the convenience of nickname payees.

### Weights are integers and conservation is exact

No floats, for the reason `canonical::Value` has none. `weight` is a `u32` and
shares are proportional to the sum, so `[1, 1]` and `[50, 50]` mean the same
split without anyone having to normalise to a magic denominator.

Splitting `reward` by weight is the same problem `attribution` already solved:
integer division leaves a remainder, and two nodes that resolve it differently
disagree about who was paid. **Reuse largest-remainder allocation resolved by
sorted payee id**, which is already implemented, already conformance-tested, and
already agreed on by both implementations. Do not invent a second rounding rule.

### Citation income splits by the same weights

If a co-authored claim is cited, `δ` flows to that claim and must then be split.
It splits by the same weights.

The alternative — direct reward splits, citation income goes to the submitter —
makes co-authorship a one-time payment and hands the submitter every future
penny the work earns. That is the hoarding incentive the ratchet exists to
remove, reintroduced one level down.

## The limitation that must be stated first, not last

**Co-authorship is enforceable once revealed. It is not enforceable before.**

The commitment binds `(objective_id, submitter, artifact, nonce)` and says
nothing about shares. So a submitter can gather a co-author's signature, then
reveal a claim with no `shares` at all and take everything. Nothing in the
protocol prevents it.

This is not fixable cheaply. Binding the split into `commitment_hash` would
change every commitment hash ever computed — the single most expensive change
available in this codebase. A cheaper variant is a *commitment to the split*:
the commitment record grows an optional `shares_digest`, and a reveal carrying
`shares` must match it when present. That costs a field on `Commitment`
(omitted when absent, so no ids move) and one rule, and it converts
"trust your collaborator until reveal" into "trust them until commit", which is
a much shorter window and one they cannot exploit unilaterally after the fact.

Recommend shipping without it and adding it if anyone is actually harmed —
stated here so that the first version's weakness is a decision rather than a
discovery.

## Attacks considered

| attack | answer |
|---|---|
| **Sybil split** — divide your reward across 100 identities you control | Not profitable. You already had 100%; splitting is neutral. Nothing in claim settlement pays per distinct identity. (Availability pools *do*, and are separately marked `open` in the threat model — do not let shares near them.) |
| **Forced association** — name a rival as payee on bad work | Refused: a payee's signature over the claim's payload is required, so consent is not optional. |
| **Independence deflation** — name a target as payee to correlate their unrelated claims in `knowledge` | Same answer. Consent required. |
| **Split-then-defect** — gather signatures, reveal without them | **Open**, and the section above says so. Mitigation is `shares_digest` on the commitment. |
| **Weight overflow** — weights summing past `u64` when multiplied by reward | `u128` intermediates and checked arithmetic, as everywhere money is handled here. |
| **Duplicate or zero-weight payee** | Refused at validation. A zero share is either a mistake or an attempt to record association without payment; if association is wanted, that is what `relations` is for. |
| **A payee who is also the submitter** | Allowed and normal — a submitter taking 60% and a collaborator 40% is the ordinary case. |

## Rejected alternatives

**Express it as a `Relation`.** The obvious shortcut and the wrong one.
Relations are load-bearing *because* they carry no money — `tests/knowledge.rs`
pins that two logs differing only by a `refutes` edge settle identically. A
paying relation would destroy the property that makes the knowledge layer safe
to accept from strangers.

**A shared group identity.** Two parties generate one keypair and submit as it.
Needs no protocol change, and needs threshold ed25519 (not built) to avoid
either party holding the whole key. Worse, the split is then entirely
off-protocol — the trust relationship this is meant to remove, with extra steps.

**Put the split in the `settlement` record.** Settlement is `{objective_id,
claim_id, submitter, reward}` and can stay that way: the split lives on the
claim, so anyone computing balances derives it. Duplicating it into settlement
means two places to disagree, and this repository's habit is to derive rather
than duplicate — `Availability` omits the sampled entry for the same reason.

## What this costs

A record change, which is the expensive kind:

- `Claim` in `src/records.rs` **and** `reference/rust/src/records.rs`
- `spec/claim.schema.json`
- New conformance vectors **added alongside** the frozen ones, never regenerated
- Boundary cases in `conformance/adversarial.jsonl`: null vs absent, duplicate
  payee, zero weight, unsigned share, nickname payee, weights that overflow
- An `interop.sh` round in both directions
- Settlement's payout derivation, and `attribution` learning that a claim's
  income divides before it flows

## What this does not solve

- **It does not price contribution.** Weights are declared, not measured.
  Nothing verifies that a 60/40 split reflects who did what, and nothing can —
  the same honest limit `attribution` states about citation flow, which prices
  *declared dependency* rather than importance.
- **It does not make co-authors equal.** One party commits, reveals, and can
  defect before reveal. Co-authorship here is a payment arrangement, not a
  symmetric authorship claim.
- **It does not help work that should have been two claims.** If the work
  decomposes, citation pays better and forever. Reach for this only when it
  genuinely does not.

## Order of work

1. **`shares` on `Claim`** — validation, signing payload, both implementations,
   schema. No settlement changes: a claim may carry shares that nothing reads.
   **Done.** Notes on what that step did and did not cover:
   - The frozen `vectors.json` was **not** touched. New vectors computed by
     either Rust implementation would carry that implementation's behaviour as
     their provenance, which is exactly what `conformance/README.md` says those
     vectors exist to avoid. Cross-implementation agreement is covered instead
     by 17 boundary cases in `conformance/adversarial.jsonl`, including a
     genuinely ed25519-signed 60/40 split that both implementations accept — so
     the accept path is exercised, not only the refusals.
   - There is **no interop round**, because neither CLI can write a share:
     gathering consent is a workflow rather than a flag, and the flag belongs
     with step 2 when settlement reads the field. `differential.sh` covers the
     encoding contract in both directions in the meantime.
   - `schema.rs` gained `maxItems`, so the published schema can state the
     `MAX_SHARES` bound the decoders enforce. A decoder stricter than the schema
     is the same defect as one laxer than it.
2. Settlement derives the split; `attribution` divides income by weight.
3. `knowledge` counts payees when merging independence classes.
4. `shares_digest` on `Commitment`, if the defection window turns out to matter.
