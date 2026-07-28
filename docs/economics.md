# Economics

What mints, what does not, and why the obvious rule is fatal.

## The attack that kills the naive mint

The obvious rule — *mint on any novel verified artifact* — dies immediately.

I can generate unlimited fresh instances of a cheap problem, solve each one, and
submit the certificate. Every submission is genuinely novel (the statement hash
is new), genuinely verified (the witness is real), and genuinely worthless.
Supply becomes unbounded and the currency is worth nothing. Call it the
**grinding attack**; it is why "proof of useful work" has never shipped as a
mint.

The structural reason: Nakamoto consensus needs work that is (i) tunable to
arbitrary difficulty on demand, (ii) bound to the previous block so it cannot be
precomputed, (iii) progress-free, and (iv) trivially verifiable. Useful research
satisfies (iv) and fails (i), (ii), and (iii). You cannot order a research
instance of precisely 2.3× last week's difficulty, and you cannot bind a useful
instance to last block's hash without making it an instance nobody wanted.

## So issuance is demand-gated

> A claim mints if and only if a bounty was escrowed against that exact
> statement hash **before** any witness for it existed, and the artifact
> verifies at V0–V2.

Supply is then bounded by what someone was willing to pay to know. That is a
market clearing, not mining. It also gives the unit a demand side from day one,
which is the only thing that ever gives one value.

`proofwork` enforces the mechanical half of this:

- An artifact cannot be revealed against an objective that does not exist.
- An objective settles exactly once (`test_objective_settles_only_once`).
- A duplicate artifact verifies fine and mints zero
  (`test_duplicate_artifact_verifies_but_mints_nothing`). **Novelty is
  necessary, never sufficient.**
- Commitments are refused once an objective is settled.

Unsolicited discovery is the awkward case, and the honest one: the best results
are the ones nobody knew to ask for. Handle it with a **retroactive prize pool**
funded from protocol fees and allocated by staked judgement — explicitly a V4
process, explicitly not a mint, explicitly subjective. Do not pretend a formula
can price surprise.

## The three flows

Only the first is mechanical.

**1. Bounty settlement.** The verifier accepts, escrow releases. Deterministic,
instant for V0/evaluator objectives, no judgement involved. This should be the
overwhelming majority of value flow.

**2. Recursive citation flow.** Implemented in `proofwork/attribution.py`. A
settled claim keeps `1 − δ` and sends δ upstream along the claims it cites,
recursively, to `max_depth` hops.

Ordinary science has never solved attribution — authorship order is a social
negotiation, and whoever wrote the load-bearing lemma three papers back gets a
citation and nothing else. A hash-linked claim DAG makes a mechanical answer
possible, because every claim names what it built on and the edges are checkable.

Two properties are guaranteed and tested:

- **Conservation is exact.** Payouts sum to precisely the amount distributed, at
  every amount and every δ. All arithmetic is integer and δ is a rational
  `num/den`, never a float, so rounding never leaks or invents a unit. An
  unresolvable citation returns its share to the settling claim rather than
  burning it.
- **Determinism.** The odd unit in an uneven split goes to citations in sorted
  claim-id order, so every node agrees who got it.

What it does *not* do is price contribution correctly. Nothing does. It prices
**declared dependency**, which is checkable, rather than **importance**, which is
not. Spurious citations are a real attack (see threat-model.md); δ decaying with
depth bounds the payoff, and validators are expected to slash edges that do not
correspond to real dependency.

**3. Retroactive prizes.** For work nobody knew to fund. Allocated by staked
judgement, disputable, and labeled as subjective rather than dressed up as
verification.

## Negative results

"I searched this region and found nothing" is genuinely valuable, genuinely
unfakeable-except-by-effort, and therefore payable only through the expensive
attestation mechanisms — TOPLOC-class inference checks, redundancy, or TEE.
Fund it explicitly as exploration, at a lower rate, and never let it mint at the
same tier as a positive verified artifact. A network that pays well for "I
looked and found nothing" is paying for not looking.

## The deepest limitation

This design systematically favors work with crisp success criteria and
systematically underfunds the exploratory, taste-driven work that *produces*
crisp criteria in the first place. Most of real research is the latter.
Retroactive prizes are a patch, not a fix, and anyone building this should be
honest that it is unsolved rather than quietly hoping the market sorts it out.
