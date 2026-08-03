# first-blood: five open ECDLP bounties

Five certificate objectives, one per instance size. Each asks for the discrete
logarithm `k` with `k*G == Q` on a generic prime-field curve whose constants
are baked into the pinned checker, so the instance is part of the objective's
content-addressed id and cannot be swapped after funding. Submit
`{"k": <integer>}`; checking a claimed `k` is one scalar multiplication,
finding one is believed to cost ~sqrt(n) group operations. Any method is
admissible — this is the representation track, the curve is public and the
solver holds it.

| objective | bits | reward |
|---|---|---|
| `objective_80.json` | 80 | 100000 |
| `objective_88.json` | 88 | 400000 |
| `objective_96.json` | 96 | 1600000 |
| `objective_112.json` | 112 | 25600000 |
| `objective_128.json` | 128 | 409600000 |

**Rewards are notional.** Stage 0 has no token, no escrow, and no transfer
primitive; the numbers are the unit of account the settlement rules operate
on, not money anyone is holding. See *What this is not* in the top-level
README.

**The provenance caveat.** The checkers assert that `k` was discarded at
instance generation — that the funder cannot already hold the answer and
self-deal the bounty. That claim is the operator's, and nothing in this
repository lets a contributor verify it. What the pinning machinery proves is
narrower: the instance you solve is the instance that was funded, byte for
byte. Whether anyone already knows its answer, it cannot prove. Treat the
anti-self-dealing property as trust in the poster, not a verified fact.

The instances cite the **ecdlp-cost-challenge** project as their source —
`first_blood/instance_public_<bits>.json`, seed 1 for every size except the
88-bit instance, which uses seed 88. Each checker is deliberately
self-contained: the objective pins the sha256 of that one file, so a shared
curve-arithmetic module would be an unpinned hole, and duplication is the
price of pinning.
