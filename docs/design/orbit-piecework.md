# ECC2K-130 as a piecework objective: paying for orbits

**Status: built.** `spec/search-job.schema.json` (version 2),
`examples/certicom-ecdlp/{jobs/ecc2k130.json,jobs/ecc2k-23.json}`, the checkers
`checkers/ecc2k130_orbit_batch.py`, `checkers/ecc2k130_dlog.py` and their
23-bit twins, the four objectives `objective-ecc2k130*.json` and
`objective-ecc2k-23*.json`, the contributor tool
`tools/orbit_dp.py`, and `scripts/orbit-demo.sh`, which runs the whole loop
— post, walk, submit, settle, collide, claim the answer — on an instance
that finishes in a second. **No consensus change.** `src/piecework.rs`
already pays per novel element of a batch and already lets the objective say
which field names the unit; what ECC2K-130 needed was for that field to name
the right thing, and for the thing it names to be checkable.

Written against [`rho-piecework.md`](rho-piecework.md), which is the version 1
design this one departs from, and against the ECC2K-130 client in
[`aburan28/crypto`](https://github.com/aburan28/crypto) (`ecc2k130/`), which is
where the walk, the bitsliced field arithmetic and the corpus format live.

## 1. Why the version 1 shape does not fit

[`rho-piecework.md`](rho-piecework.md) pays for a distinguished point of an
r-adding walk on a prime-field curve. Its whole argument rests on one sentence:
*a record `(x, y, a, b)` with `a·P + b·Q = (x, y)` costs `2^d` group operations
to produce and two scalar multiplications to check.* The point carries its own
certificate.

ECC2K-130 breaks that in three places at once, and each break changes what a
*unit* is rather than merely how one is encoded.

**The walk is on orbits, not points.** On `y² + xy = x³ + 1` over `GF(2^131)`,
`σ(x, y) = (x², y²)` is an endomorphism and negation is `(x, y) ↦ (x, x + y)`.
Together they generate a group of order `2m = 262` acting on the curve, and
Bailey et al.'s iteration function is defined on its *orbits*: two trails have
merged when they reach the same orbit, not when they reach the same point. A
unit keyed on a representative would be paid up to 262 times for one orbit, by
262 relabellings anybody can compute from one published record with 131
squarings.

**The distinguishing test is not a property of the polynomial-basis bytes.**
The iteration is `R ← R + σ^j(R)` with `j = 3 + ((HW(x_R)/2) mod 8)`, and a
point is distinguished when `HW(x_R) ≤ 34`. `HW` is the Hamming weight in a
**normal** basis, where `σ` is a cyclic rotation of the coordinates — which is
exactly why both the branch and the test are orbit-invariant and the iteration
is well defined on orbits at all. Read the same field element in the
polynomial basis and neither is invariant; there is no walk.

**A point cannot carry its own coefficients.** The step multiplies the
coefficient vector by `1 + s^j` mod `n`, a 129-bit modular multiplication, and
the client runs `1.4 × 10^10` steps a second by keeping the entire walk state
in bitsliced field elements and never touching an integer. So the corpus
record is `(seed, canonical x)` — 32 bytes, no relation — and recovering the
relation means re-walking the trail. Verification cost equals production cost,
which is not a certificate.

That last one is the fatal one, and it is worse than "expensive to check".
A canonical low-weight bit string is **free to invent**: pick 34 bits out of
131, rotate to the least rotation, submit. Under the version 1 rules that
artifact verifies against nothing, takes a unit's payment, and — because the
unit is the orbit — *takes the payment of whichever honest contributor reaches
that orbit later*. The cheapest attack on the objective costs nothing at all.

## 2. The unit is the orbit, and the orbit has one name

`σ` acts on the normal-basis coordinate string of `x` as a rotation, and
negation does not touch `x`. So the orbit of a point is named by

    x_canonical = the least of the m cyclic rotations of nb(x)

and the objective's piecework block keys novelty on exactly that field:

```json
"piecework": { "items": "dps", "key": ["x"], "unit_price": 1000, "units": 281474976710656 }
```

`key: ["x"]` and nothing else. The artifact's other two fields are
provenance — `seed` says which trail, `j` says how it got there — and a key
that included either would make one orbit a *new* unit once per trail that
reaches it. That is not a rounding error in the payout: the second trail to
reach an orbit is the collision the whole search is for, and a rule that
quietly paid it as fresh work would pay twice for the one event it most needs
to make visible. The novelty rule is where that is decided, and there is
exactly one right answer.

The representative is unique. A rotation class is ambiguous only when the
string is rotation-symmetric; `m = 131` is prime, so the only symmetric strings
are all-zeros and all-ones, which are the field elements `0` and `1`, and
neither is the abscissa of a point of odd order. `tools/orbit_dp.py selftest`
checks this on both instances rather than taking it on faith — including that
all 131 members of an orbit canonicalise to the same name, which is the
property the payment rule actually rests on.

**A second answer to one orbit is a collision, and it is right that it mints
nothing.** Before the search ends, every orbit is reached once; a second
arrival means two trails met, and what that is worth is the *answer*
objective's 2,000,000, not another 1,000 for a duplicate unit. The finder
commits the answer claim in the same epoch as the batch and reveals both in
the next, so revealing the collision does not hand it to an observer — the
window to commit against it closed an epoch earlier
([coordination.md](../coordination.md#in-flight-front-running)).

## 3. The witness: eight counters make the point checkable

The step is `R ↦ R + σ^j(R) = [1 + s^j]R`, where `s` is the Frobenius
eigenvalue on `⟨P⟩` — the root of `s² + s + 2 ≡ 0 (mod n)` that actually acts
as `σ`. Multiplication in the endomorphism ring is commutative, so a trail of
any length collapses to a single scalar and **the order of the steps does not
matter**:

    R_end = [μ] R_0,    μ = ∏_{j=3}^{10} (1 + s^j)^{n_j}

where `n_j` counts how many steps took branch `j`. Eight numbers. The start
point is `R_0 = Q + Σ_i c_i σ^i(P) = [α_0]P + Q` for an `α_0` the walker reads
straight off the seed, so the endpoint's relation is

    R_end = [μ·α_0] P + [μ] Q

and an artifact of `(x_canonical, seed, [n_3 … n_10])` is verified by one
double scalar multiplication: rebuild `μ`, form `[μ·α_0]P + [μ]Q`,
canonicalise its abscissa, and require it to equal `x`.

Measured, in CPython, against the shipped checker:

| | group operations | wall clock |
|---|---:|---:|
| produce one orbit (expected) | 4.05 × 10^7 | 2.9 ms of one 2026-class GPU |
| verify it from the witness | ~227 | 13.5 ms (a 64-point batch: 0.86 s) |
| verify it by re-walking | 4.05 × 10^7 | hours, in Python |

An asymmetry of `2^17.4` in group operations, which is what turns a trail into
something a network can pay for.

The counters are not free to the client. Walk state grows from 262 bits (two
field elements) to 502 with eight 30-bit counters, and for a kernel whose
working set is tuned against L2 residency that is the number to measure
first — this note does not measure it, and a throughput claim here would be
invented. There is a cheaper encoding if it matters: store the step count and
seven 16-bit *deviations* from `steps/8`, which is 142 bits instead of 240.
The eighth count is implied by the step total, so only seven are stored; a
trail any of whose seven strays more than 32768 from the mean cannot be
represented and is dropped like a capped one. By a Chernoff bound that
happens with probability below `4 × 10^-31` per trail, so over the whole
`2^35.5`-trail search the expected number lost is `2 × 10^-20`.

### What the witness does not prove

That the counters are the ones **this walk's own `j` rule** produces. A
contributor who applies `σ^3` at every step regardless of the weight produces
witnesses that verify perfectly and trails that merge with nobody: the network
pays for points that can never collide, and the search makes no progress.

Deciding that costs the trail again. So it is sampled, not checked:
`tools/orbit_dp.py audit` re-walks a deterministic sample of *paid* claims and
writes mismatches in the shape `cairn attest slash --docket` reads, which is
the mechanism [`bonded-verification.md`](../bonded-verification.md) already
defines. The sampling rate and the bond are the operator's dial, and the thing
the witness changes is what they have to cover: without it the cheapest attack
is free, so no finite bond deters it; with it the cheapest attack costs a full
honest trail, so a bond a small multiple of the batch payout is enough.

`selftest` pins both halves of this — that a private iteration rule passes the
witness, and that the audit catches it — so that nobody reads the certificate
as proving more than it does.

## 4. The job document, and why version 2 is a new shape

`spec/search-job.schema.json` now describes two versions under one `oneOf`.
Version 1 is byte-frozen: its ids are inside shipped checkers, and a field
added to it would move every one of them. Version 2 adds what the orbit walk
needs and nothing else:

| field | why it is pinned rather than derived |
|---|---|
| `nb_generator` | The normal element whose conjugates are the weight basis. Two implementations that *search* for one — "the type-II generator", "the sparsest" — can find different elements and then disagree about which orbit a point is on. Pinned by value; the tool checks it is normal. |
| `frobenius_eigenvalue` | Both roots of `s² + s + 2` satisfy the equation and only one acts as `σ`. An implementation that picked the wrong one would compute every witness wrong, silently, since the wrong root still yields a well-formed scalar. |
| `family` | One knob naming the whole walk shape — iteration, distinguishing test, equivalence group, canonical form, start-point construction. Five independent knobs can contradict each other, and a document declaring `equivalence: none` beside a Frobenius-invariant test describes no walk anyone can run. |
| `witness` | An enum with one member. The obvious alternative — endpoint and seed only, which is what the unmodified client writes — is not a payable mode, so it is absent rather than offered with a warning. |
| `max_batch` | Bounds what one claim costs *every verifying node*, so it belongs to the contract and not to the submitter. |

The id is SHA-256 over canonical `tag=value` lines, the same discipline as
version 1, and the checker carries it — so the job is inside the objective's
own id and the walk cannot be changed under a funded bounty.

For ECC2K-130 the constants are the challenge's own, and every one of them is
re-derived rather than transcribed: the reduction polynomial is checked
irreducible, `#E = 4n` comes out of the Frobenius recursion and `n` tests
prime, `P` and `Q` are checked on the curve and of order `n`, and `s` is
checked to act as `σ` on `⟨P⟩`. A corrupted digit could not have survived that.

## 5. Work split: unchanged

Nothing new. `work_assignment` hands a node its per-epoch slice `[first, end)`
of `units`, which here is the `2^48` seed-slot space the client's
`(runId, walkIndex)` layout already defines; the low `trail_bits` of a seed
count restarts within a slot, so one unit is a *family* of trails rather than
one payable item. Two nodes walking the same slot produce the same orbit and
the second mints nothing. A node that squats a slot it never walks costs the
network nothing, because an orbit is an orbit whichever seed reached it.

A capped trail — one that hits `max_steps_per_walker` without reaching weight
34 — earns nothing. The client reports it so it can restart the lane, but a
point that is not distinguished is not a unit, and paying for one would pay
for an unfinished trail.

## 6. What this does not solve

**The corpus does not fit in a log.** At weight 34 the search produces about
`2^35.54` orbits; as claim artifacts that is roughly 6.8 TB, and every node
that verifies the log holds all of it. Raising the cutoff is not available
either: the weight sets the trail length, and at `2^25.27` steps a trail
already takes about five hours on one of a GPU's 6.16 million lanes, so a
lower weight makes trails that no lane finishes. The two constraints leave
almost no room, and weight 34 is where the client already sits.

So the posted objective funds a **tranche**: 2,097,152 orbits, about `2^46.27`
iterations, roughly one part in 24,000 of the expected search, which is
32,768 claims at 64 orbits each. A top-up objective with the same checker
inherits its paid orbits (`piecework` keys novelty on the checker hash, not
the objective id), so tranches compose. What nobody has built is the thing
that would make the *whole* table live in this network:
[`shards.md`](../shards.md) is the right shape and says plainly that it is not
wired into the network transport. Until it is, ECC2K-130's full corpus is
larger than what cairn stores, and this note does not pretend otherwise.

**The client must change to earn.** `ecc2k130/` writes `(seed, canonical x)`
and would have to carry eight counters per walk and emit them. That is a real
cost in a kernel that has been tuned to the byte (`COMPACT-STATE.md`,
`TILED-STATE.md`), and it is the price of the point being payable rather than
merely produced.

**Fruitless cycles are the walk's problem, not the protocol's.** The iteration
is `R + σ^j(R)` rather than a table of random points, and the client handles a
stuck lane with a step cap and a reseed. This design inherits that: a capped
trail is unpaid, and nothing in the payment rules depends on cycles being
absent.

**Sharing a technique still pays nobody**, for the same reason it does in
[`coordination.md`](../coordination.md#what-this-does-not-solve).

## 7. Trying it

```sh
./scripts/orbit-demo.sh                                     # the whole loop, 21-bit instance
python3 examples/certicom-ecdlp/tools/orbit_dp.py selftest  # the protocol's own claims
python3 examples/certicom-ecdlp/tools/orbit_dp.py validate  # every job against the schema
python3 examples/certicom-ecdlp/tools/orbit_dp.py describe --job examples/certicom-ecdlp/jobs/ecc2k130.json
```
