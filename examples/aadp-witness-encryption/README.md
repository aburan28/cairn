# AADP: recovering setup randomness from a published instance

The first objective in this repository whose *problem* came from outside it.

[alloc init](https://allocinit.notion.site/challenges) published cryptanalysis
challenges against AADP — arithmetic affine determinant programs, the witness
encryption scheme in [eprint 2026/175](https://eprint.iacr.org/2026/175),
extending [2020/889](https://eprint.iacr.org/2020/889). They pay $3k/$6k/$20k
for breaking the m=8/16/32 instances. This objective pins **their real m=8
instance** and settles the same arithmetic criterion their rules state.

```sh
cairn post examples/aadp-witness-encryption/objective.json
python3 examples/aadp-witness-encryption/tools/selftest.py
```

## Read this first: what this objective is not

**It is not alloc-init's bounty and it pays none of their money.** Claiming
their prize means emailing `challenges@allocinit.xyz` under their rules, which
also require the attack code, a written description, and publication within two
months. A verdict here is not a submission there.

**It decides one arithmetic identity over one instance.** Not that AADP is
broken in general, not that an approach is novel, not that a structural
observation is interesting. Their own program routes all of that to a
four-person external committee, which is the correct answer and the same one
[`verification.md`](../../docs/verification.md) gives: that is V4, and *nobody*
mechanizes it.

Their four submission types split cleanly along this repo's ladder, and the
split is the interesting part:

| their submission type | verifiable by a stranger? |
|---|---|
| full randomness recovery | **yes** — this objective |
| decryption | yes, if the funder publishes `H(msg)` at setup |
| *partial* randomness recovery | **no, as specified** — checked against the setup's own secret, which no verifier has. Merkle-committing the canonical secrets at setup would fix it, using `canonical::merkle_root` unchanged |
| structural observations | **no, ever** — "granted at our discretion" |

## What the checker decides

An AADP instance publishes `M^(0)..M^(n)` over the BN254 scalar field, built
from `m` gate matrices under secret masks:

```
M(X) = sum_i  L_i . U_i(X) . R_i
```

A submission qualifies when its `L_i`, `R_i`, `xi_i` reproduce that identity
coefficient-wise. Any valid tuple counts — the construction has a symmetry group
and the setup's own randomness is not privileged, which alloc-init's rules say
explicitly.

**Nothing secret is needed to decide it.** The constraint system `(A, B, C, D)`
is a deterministic function of `m` and the public target, and the target is the
first 32 bytes of the published instance. So the checker rebuilds the circuit
itself rather than being handed it. That is what makes this settle-able by
someone who does not trust whoever posted it — and it is why *this* submission
type was the one worth encoding.

The message is a by-product rather than a second check. `M^(0)` is published
with `msg` added to its bottom-right entry, so a correct recovery reproduces
`M^(0)` everywhere except there, and the difference at that one entry *is* the
decryption. The checker reports it.

## The residual risk, stated rather than buried

**The constraint-system convention is transcribed from alloc-init's published
sage, and cannot be confirmed end to end until somebody solves an instance.**

`tools/selftest.py` builds a small instance *from the same transcription*,
keeps the secrets, and requires the checker to accept them and recover the
message. That proves the verification logic and the byte layout. It does not
prove the transcription matches their sage, because generator and checker share
it — the "a subsystem tested only against itself agrees with itself and with
nobody else" hazard that [`docs/storage.md`](../../docs/storage.md) records from
the `swarm`/`blobs` seam.

What *is* independently confirmed against the real file:

- it is exactly 74,016 bytes, the size the published layout implies;
- it parses as 8 matrices of 17×17 with every entry inside the field;
- its target is a genuine quadratic non-residue, so no witness exists — the
  property their circuit design depends on, checked by Euler's criterion rather
  than taken on faith.

If the transcription is wrong, the failure is **safe in the direction that
matters**: a genuine break would be rejected, not a wrong one accepted. An
objective that under-pays is a disappointment; one that over-pays is a hole.

## Why the instance lives inside the checker

Embedded as base64, not fetched and not read from a path.
[`verification.md`](../../docs/verification.md) rule 4: a checker that reads an
unpinned file passes today and fails tomorrow at the same hash. And not carried
in the artifact either — the instance is identical for every submitter, so
shipping it per submission would put 74 KB in the log every time.

The consequence is a good one. `checker_sha256` now covers the instance, so the
objective's id does too: **the instance cannot be swapped without forking the
objective.** That is the same mechanism that makes a mid-bounty rule change
unrepresentable rather than merely forbidden.

## Sizes, and the one that does not fit

From the published layout — `n+1 = m` matrices, `k = 2m+1`, 32-byte entries —
plus the artifact each break would carry:

| m | k | instance | pinned checker | artifact |
|---|---|---|---|---|
| 8 | 17 | 72 KiB | 115 KiB (measured) | ~77 KB |
| 16 | 33 | 545 KiB | ~764 KiB | ~300 KB |
| **32** | 65 | **4.1 MiB** | **~5.7 MiB** | **~1.2 MB** |

`blobs::MAX_BLOB_BYTES` is 1 MiB, so **the $20,000 instance cannot be pinned
this way at all** — the checker alone is over five times the cap, and m=16 fits
with less headroom than it looks (base64 costs 4/3, so the checker is always
about 1.46x the instance). That is not a
limitation to route around here; it is precisely the case
[`src/shards/`](../../src/shards/) and [`src/swarm/`](../../src/swarm/) were
built for and which `docs/roadmap.md` describes as "sized for artifacts that cap
does not yet allow". The m=8 and m=16 instances fit today.

Field elements travel as exactly 64 lowercase hex characters, which is forced
rather than chosen: a BN254 element does not fit an `i128`, so it cannot be a
canonical integer at all, and two spellings of one value would be two artifacts
with two digests for one submission.

## What was checked before this shipped

- `tools/selftest.py`: a genuine solution accepted and its message recovered;
  each of `L`, `R`, `xi` perturbed and refused; eight malformed artifacts
  *scored* rather than raised (rule 3 — an exception is a broken verifier).
- The embedded instance byte-identical to the published file
  (sha256 `e5084e9b…c6ca`).
- End to end through the real rules engine: posted, committed, revealed. A
  wrong artifact returns `reject` with the checker's own reason and pays zero.
  The accept path was proven the same way against a temporary *solvable*
  instance — which was then deleted rather than committed, because an objective
  whose answer the poster already holds is the **self-dealing** row in
  [`threat-model.md`](../../docs/threat-model.md).

## Working it

Nothing in this repository helps you break AADP. The attack surface the authors
name is algebraic: relinearization, Gröbner-basis approaches, and the
commutator-based attack already reported against sparse circuits in May 2026.
Start from their paper.

If you do break it: alloc-init's rules are first-come-first-serve, adjudicated
by receipt order in an inbox. A commitment here timestamps priority in a
hash-linked log instead — which is the argument
[`design/anchored-time.md`](../../docs/design/anchored-time.md) makes about
**backdated priority**, with $20,000 riding on it. And their two-month
publication window is exactly the `embargoed` confidentiality class in
[`censorship.md`](../../docs/censorship.md) §6, arrived at independently.
