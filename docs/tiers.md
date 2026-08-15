# Claim assets, typed by verification tier

*Why a unit earned on a millisecond check is not a unit earned on a Lean proof.*

Implemented in [`src/tier.rs`](../src/tier.rs), enforced in
`Node::post_objective`, re-derived by `Node::audit` and by `reference/rust`.
`tests/tiers.rs` is the executable version of this page.

## The attack

Every bond in this repository is drawn from a balance:

| bond | drawn from | what it buys |
|---|---|---|
| availability undertaking | the promiser's balance | a share of the storage pool |
| dispute challenge | the challenger's balance | the right to object to a trace |
| committee stake | a member's balance | seats, and how many the epoch needs |
| verification bond | the attestor's balance | the right to be believed about a verdict |

Until this landed, a balance had no provenance. A thousand units earned by
passing certificate checks — milliseconds each — and a thousand earned by
passing Lean proofs printed identically and spent identically. So:

> **Run a cheap certificate mill, then spend the proceeds where expensive work
> is priced.**

Sizing the committee against members' stakes, which the previous change did,
made that attack *more* valuable rather than less: the cheapest possible
earnings now bought a say in how much collusion resistance the network thought
it had.

There is a second, softer effect. If a millisecond of certificate checking mints
what a minute of Lean checking mints, a rational contributor never runs Lean.
Gresham's law applies to verification effort exactly as it does to coin.

## The rule

**A unit minted by settling a claim carries the tier of the objective's
verifier, and cannot be spent in another tier.**

That is all of it. Five verifier kinds, five tiers, no ordering and no exchange
rate — a conversion, however priced, is a route by which the cheapest tier ends
up valuing every other one, which is the thing being prevented. Two tiers are
different assets that happen to share a ledger.

The tier is **derived from the objective record**, never stored beside it. A
stored field would be a second place the tier could be written down, and a
settlement claiming a tier its objective's verifier does not have is exactly the
forgery this rule exists to stop. There is nothing to forge when the tier *is*
the verifier.

## Genesis stays universal

`issuance` mints [`Tier::Universal`], which spends anywhere.

Not an exemption — a necessity. A network whose founding supply were typed could
never fund its first Lean objective, because the units to fund it could only
come from settling a Lean objective nobody could fund. The reserve a log
declares at genesis is deliberately fungible. What *work* pays out is not.

Availability payouts and both sides of a dispute slash are universal too, and
for a related reason: neither is verification, so there is no verifier whose
tier they could carry, and typing a storage payment by whatever happened to be
in the log that epoch would make it mean something about Lean.

## Spending order, and why one column is not enough

A commitment in tier `T` draws from `T`'s units first and falls back to the
universal reserve. Typed-first rather than reserve-first: universal units are
the only ones that can cover *any* tier, so spending them while typed units sit
idle destroys optionality the holder had.

That fallback is why a per-tier balance cannot be a set of independent columns.
The reserve is shared, so a promise made in one tier changes what is spendable
in every other:

```
held:      universal 100
spendable: lean 100, replay 100        ← both see the same reserve

promise 100 of lean work

spendable: lean 0, replay 0            ← replay's column had to move too
```

Independent columns would have offered the same hundred units to five tiers.
`tier::Ledger` computes each tier's shortfall against the one pool that can
cover it, and `solvent()` is the per-identity statement that the shortfalls add
up to no more than the reserve.

## What the audit adds

The whole-balance conservation check — `committed ≤ issued + settled`, in both
implementations — is not enough on its own. An identity can hold exactly what it
has promised *in total* while having promised Lean units it earned on
certificates. **That log balances and is still a forgery**, because the promise
it makes is one the units behind it cannot keep.

So `audit_tiers` walks the same arithmetic per tier, in both crates, from each
crate's own decoding of the records. Reverting either copy fails
`the_audit_names_a_funder_whose_units_were_the_wrong_kind`, which is the only
evidence that the check is load-bearing rather than decorative — and this
repository's characteristic bug is precisely a rule enforced at admission and
absent from the audit, so a log imported from a peer does not have it.

Silent on a log that declares no supply, like every other scarcity rule here: a
log that has not claimed its units are scarce has not claimed this either.

## What is *not* typed yet

**Service bonds.** An availability undertaking, a dispute challenge, a
verification bond, and the stake a committee seat is measured by are all charged
in universal. So cheap earnings still cannot buy them — universal units come
only from genesis and from service payments — but neither can *expensive*
earnings, which is a different limitation and a real one: a contributor with a
large Lean balance cannot use it to back a committee seat.

The verification bond makes that sharper rather than softer, and worth stating
plainly. Standing behind a Lean verdict and standing behind a certificate check
cost the same 50,000 universal units, so the bond does not price the difference
between checking a proof and checking an arithmetic identity. It prices being
*wrong*, which is the same size of lie either way — that is defensible, and it
is a choice rather than an oversight.

Closing that means deciding which tier a committee seat is denominated in, and
that is a question about what custody *is* rather than about arithmetic. It is
named here rather than left to be discovered.

**The `balances` total.** `proofwork balances` still prints one spendable
number per identity, because "how much does this identity have" remains a
question with an answer. The per-tier breakdown prints underneath it whenever
anything was *earned* — including when there is only one tier, which is the case
where the total misleads most: `spendable 100000` is true and says nothing about
what that hundred thousand can buy.
