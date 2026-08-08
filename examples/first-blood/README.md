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

**Provenance: nobody knows `k`, and you can check that yourself.** These
instances used to be `Q = k*G` for a random `k` the operator generated and said
they discarded — a claim nothing in this repository could verify, so the
anti-self-dealing property was trust in the poster.

It is now a fact you can re-derive. `Q` is **hashed to the curve** from a fixed
public seed rather than multiplied into existence:

```
x = sha256(SEED || bits || counter) mod p,   counter = 0, 1, 2, …
until x^3 + ax + b is a square;  y = its canonical root
```

Because `Q` is never constructed as a multiple of `G`, recovering `log_G(Q)` *is*
the ECDLP the bounty pays for — the funder has no more idea what `k` is than you
do. `_derive_q()` runs inside every check, and the checker is pinned by hash
inside the objective's id, so the derivation is part of what you are solving.
Run `scripts/derive-first-blood.py --check` to confirm the shipped files match
the derivation.

This is the standard nothing-up-my-sleeve construction — the same technique used
to derive the second generator `H` for Pedersen commitments on secp256k1.

*Grinding the seed gains an attacker nothing*, which is worth stating because it
is the obvious objection. To profit from trying many seeds you would have to
recognise a `Q` whose logarithm you already know — and recognising one means
solving the instance. A fixed published seed is therefore as good as an
unpredictable one, and has the advantage of being re-derivable by anyone,
forever.

**What this still does not prove.** The curve itself — `p`, `a`, `b`, `G` — is
the poster's choice. Each checker verifies that `N` is prime and that both `G`
and `Q` have order `N`, which rules out a smooth-order curve and therefore
Pohlig-Hellman; it does not rule out every weak-curve family (a low embedding
degree would admit MOV). Deriving the curve from the seed as well is the
stronger construction and is not done. That residue is trust in the poster; the
`k`-provenance half no longer is.

The instances cite the **ecdlp-cost-challenge** project as their source —
`first_blood/instance_public_<bits>.json`, seed 1 for every size except the
88-bit instance, which uses seed 88. Each checker is deliberately
self-contained: the objective pins the sha256 of that one file, so a shared
curve-arithmetic module would be an unpinned hole, and duplication is the
price of pinning.
