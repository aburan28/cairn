# Elliptic-curve rank record challenges

Find elliptic curves over the rationals with large sets of rational points
proved linearly independent modulo torsion. These are open certificate and
exact-score objectives: every accepted artifact proves a rank lower bound,
never merely a numerical rank claim.

## The portfolio

| objective | required result | reward |
|---|---|---:|
| [`objective.json`](objective.json) | rank at least 31 | 31,000,000 |
| [`objective-rank-32.json`](objective-rank-32.json) | rank at least 32 | 64,000,000 |
| [`objective-rank-30-new-j.json`](objective-rank-30-new-j.json) | rank at least 30 with `j` different from curve #273 | 20,000,000 |
| [`objective-rank-30-lower-height.json`](objective-rank-30-lower-height.json) | rank at least 30 and exact invariant height below curve #273 | 25,000,000 |

The first objective requires exactly 31 points. The other three use separate
entrypoints in the same pinned evaluator: they score the number of submitted
points only after certifying the entire set independent, then enforce their
objective-specific threshold or record condition. A dependent extra point
makes the whole submitted set score zero; submit a certified independent
subset instead.

An accepted artifact proves, according to its threshold,

```text
rank E(Q) >= number of submitted points.
```

It does not prove the exact rank, the Birch and Swinnerton-Dyer conjecture, the
Generalized Riemann Hypothesis, or that ranks over Q are unbounded.

## Why 31, not the challenge in the screenshot

The screenshot records the solution of Epoch AI's former
[rank-at-least-30 problem][epoch]. On 2026-08-20, the
[ICARM Elliptic Curve Rank Leaderboard published curve #273][curve-273] with 30
independent rational points. Its equation begins

```text
y^2 + xy = x^3
  - 201769035260418549083594900060734240952308696994802735114305555 x
  + 1151107939141058565733479426024323225135665982951300586808823640527729578307228357301072889377.
```

The leaderboard entry names the submitter as `ranksunbounded`; its commentary
credits Claude, Levent Alpöge, and Ava Howell. That public solution makes a new
rank-30 bounty a copying contest, so this objective advances the threshold to
31, asks for rank 32 as a further milestone, and uses two orthogonal record
conditions to make rank-30 submissions non-copyable. The reported curve and
all 30 points are retained verbatim in
[`artifacts/rank-30-record.json`](artifacts/rank-30-record.json). The artifact
is a positive rank-certificate baseline at threshold 30, but it is rejected by
all four objectives: it is short of ranks 31 and 32, has its own `j`-invariant,
and equals rather than improves its own height bound.

Provenance captured on 2026-08-20:

- leaderboard JSON: <https://elliptic-rank.icarm.cloud/curve/273.json>
- SHA-256 of the response bytes: `1bb02ecafcb5d3bbc7069a34428b54e016725dd26b0de5185dff76647f18c413`
- leaderboard verifier source reviewed at commit
  [`a6750aaf50d2bce36946c56eeed3218f6e01e627`][icarm-verifier]

The response contains approximate height and regulator fields. They are not in
the retained artifact because neither is needed to prove a rank lower bound.

## Artifact

Submit exactly two fields:

```json
{
  "curve": ["a1", "a2", "a3", "a4", "a6"],
  "points": [
    ["x1", "y1"],
    ["x2", "y2"]
  ]
}
```

For `objective.json`, `points` must contain exactly 31 entries. The other
objectives accept the bounded ranges stated in their schemas, up to 64 points;
the two entries shown above only illustrate coordinate encoding. Curve
coefficients are canonical decimal integer strings. Coordinates are canonical
integer strings or reduced fractions such as `"-3/2"`. Approximate decimals,
JSON numbers, `4/2`, `5/1`, leading zeroes, and extra fields are rejected. Each
numerator and denominator is bounded to 256 digits so a certificate cannot
turn parsing into unbounded work.

## What the checker proves

Checking 31 points against the equation proves only that they are points. A
list containing the same point 31 times also clears that test. The payment
condition therefore has to prove independence.

The checker first transforms the submitted general integral Weierstrass model
exactly to

```text
Y^2 = X^3 - 27 c4 X - 54 c6.
```

At an odd prime of good reduction where the cubic has roots, each root gives a
quadratic-character homomorphism from `E(Q)/2E(Q)` to `F_2`. The checker stacks
the images of all 31 points at deterministic primes and requires the resulting
binary matrix to have row rank 31. This is the exact sufficient-certificate
direction of the [Cremona/Brumer method][cremona], also used by ICARM's
leaderboard verifier. It uses no floating-point arithmetic in the verdict.

There is one torsion detail that cannot be skipped. Independence of the point
rows modulo `2E(Q)` does not alone exclude a relation landing in even torsion.
The checker therefore also finds a good prime where the short cubic has no
root. A rational root of a monic integral cubic would be an integer and would
remain a root modulo every good prime, so one root-free reduction proves
`E(Q)[2] = 0`. The torsion subgroup then has odd order and its class modulo
`2E(Q)` is zero. Full character rank consequently proves independence modulo
torsion.

Both searches are bounded at `p <= 10000`. This makes verification fast and
total, at a deliberate cost: a genuine curve at one of these rank thresholds
with rational 2-torsion, or one whose character matrix needs larger primes,
does not satisfy this portfolio. It can support a successor objective with a
richer certificate; it must not be accepted here by weakening the pinned rule.

## The two non-copyable rank-30 variants

The `new-j` evaluator compares

```text
j(E) = c4^3 / Delta
```

to the baseline by exact integer cross multiplication. It excludes the entire
baseline `j`-class, not only the exact equation bytes: integral rescaling and
quadratic twisting therefore cannot disguise curve #273 as a new result. This
condition is stronger than Q-nonisomorphism—different `j` guarantees a new
Q-isomorphism class, while some genuinely different twists share `j` and are
deliberately outside this objective.

The `lower-height` evaluator compares the exact integer

```text
H(E) = max(|c4|^3, c6^2)
```

against curve #273, rather than comparing rounded logarithms. The pinned
baseline invariants are

```text
c4 = 9684913692500090356012555202915243565710817455750531285486666641
c6 = -994557259417874600793726224085029793887754159405457725835627998281306921883628926505055206421689
```

The submitted equation need not claim to be globally minimal. That does not
weaken acceptance: minimizing an integral model divides `c4` and `c6` by
fourth and sixth powers, so an integral submitted model already below the
baseline is sufficient evidence that its global-minimal model is below it too.

## Reproduce the baseline and attack tests

```sh
python3 examples/elliptic-rank/tools/selftest.py
```

The self-test requires the public 30-point record to achieve exact character
rank 30, pins its exact `c4`, `c6`, and discriminant, checks that it scores 30
for the generic rank evaluator and zero for both record variants, exercises
all three evaluator entrypoints on a small honest rank-one fixture without
pretending it is a research result, then tests rejection of:

- the 30-point baseline;
- a duplicated 31st point;
- the inverse of an existing point as the 31st point;
- an off-curve point;
- a singular equation;
- a curve with rational 2-torsion; and
- a non-canonical rational encoding.

The objective is not posted by the self-test. To check the network-facing
record locally:

```sh
./target/release/cairn --log /tmp/cairn-rank31.jsonl --root . \
  post examples/elliptic-rank/objective.json
```

The reward is notional, as with every Stage 0 example in this repository.

[cremona]: https://johncremona.github.io/papers/filter.pdf
[curve-273]: https://elliptic-rank.icarm.cloud/curve/273
[epoch]: https://epoch.ai/frontiermath/open-problems/elliptic-curve-rank
[icarm-verifier]: https://github.com/icarm/elliptic-rank/blob/a6750aaf50d2bce36946c56eeed3218f6e01e627/src/verify.ts
