# ECDLP: Certicom's frontier, and a ladder you can actually climb

```sh
proofwork post examples/certicom-ecdlp/objective-nums-50.json
python3 examples/certicom-ecdlp/tools/selftest.py
python3 examples/certicom-ecdlp/tools/nums.py verify examples/certicom-ecdlp/instances/nums-60.json
```

Three objectives: two solvable rungs, and one open Certicom instance posted as a
benchmark rather than as work anyone expects to finish.

## Why Certicom's own instances could not simply be posted

The [Certicom ECC Challenge](https://en.wikipedia.org/wiki/Elliptic_curve_cryptography)
is the obvious thing to put on a network that pays for verified results: ECDLP
is the canonical cheap-to-check problem, and Certicom defined a difficulty
ladder in 1997 that nobody here gets to argue with.

But **every one of their instances is degenerate as an objective**, in one of
two directions:

| | status | why it fails as an objective |
|---|---|---|
| ECCp-79/89/97, ECCp-109, ECC2-109, ECC2K-95/108 | solved, answers published | the first copier settles instantly. *"Copying earns exactly zero"* — nobody is paid for work |
| ECCp-131, ECC2-131, ECC2K-130 | **open** | ~2^65 group operations: **2,048×** the ECCp-109 effort, which took 549 days across ~10,000 machines |
| ECCp-163 … ECCp-359 | open | 1.3×10^8 to 4×10^37 times ECCp-109 |

There is no middle rung, and that is the whole reason this directory has two
kinds of objective in it.

Worth stating plainly: **Certicom's prizes are not claimable.** BlackBerry
retired the challenge and the pages are gone — the parameters here come from a
2016 snapshot in the Internet Archive. Nothing here pays Certicom's money.

## The frontier: ECCp-131, authenticated by arithmetic

`objective-certicom-eccp131.json` pins Certicom's real ECCp-131 and **is not
expected to settle.** It is posted because a research network should carry a
benchmark whose difficulty nobody local chose.

The parameters came from a web archive of a dead host, which sounds like a
provenance problem and is not one, because they are checkable:

```
p is prime · curve non-singular · P on the curve · Q on the curve
n is prime · n*P = O · n*Q = O
```

A single corrupted hex digit fails "on the curve" with probability
`1 - 2^-131`. `tools/validate_certicom.py` re-runs all seven checks over all six
prime-field instances, and all six pass. **The source stops mattering once the
arithmetic agrees** — the same reason a manifest from a stranger is safe in
`swarm::piece`, one field up.

The binary-field instances (`ECC2-*`, `ECC2K-*`) are not included: they need
GF(2^m) arithmetic for m up to 353, which is a different checker and no more
solvable than the prime-field ones.

## The ladder: nothing-up-my-sleeve instances

`objective-nums-50.json` and `objective-nums-60.json` are the rungs someone can
actually climb — about 2^25 and 2^30 group operations, minutes to hours.

The design problem they solve is that **an ECDLP objective is trivially
self-dealing.** Whoever picks `Q = kG` knows `k`. That is a row in
[`threat-model.md`](../../docs/threat-model.md), and the existing
[`examples/ecdlp/`](../ecdlp/) instance has exactly that shape — it pins a
scalar in a one-bit window on a 256-bit curve, so its author chose and holds the
answer.

Here nothing is chosen. The prime, the curve, `G` and `Q` are all SHA-256
outputs of a public seed string:

```
p = the largest prime below 2^bits with p = 3 mod 4
a, b = H(seed | "a" | i), H(seed | "b" | i)      first i giving prime #E
G    = hash_to_curve(seed | "G" | i)
Q    = hash_to_curve(seed | "Q" | i)
```

`tools/nums.py verify` re-derives every number and requires a match, so the
claim *nobody knows the answer* is checkable rather than asserted.

Two properties make this sound rather than merely tidy. **`#E` is prime**, so
the group is cyclic, every point lies in `<G>`, and the hashed `Q` is guaranteed
to have a logarithm — the instance cannot be quietly unsolvable. And `#E` is
computed by baby-step giant-step over the Hasse interval, then required to be
prime, so the order is *known*, not assumed.

`k` is required to lie in `[1, n)`. Without that the logarithm is only unique
modulo `n`, so `k + n` would be a second settling answer to one problem, with a
different artifact and a different digest.

## How acceptance was proven, given nothing pinned is solved

Running a checker against an unsolved instance only ever demonstrates
rejection, and a verifier shown only to reject is indistinguishable from one
that rejects everything. So two instances were derived identically and then
**actually solved**:

| vector | method | cost | result |
|---|---|---|---|
| `testvector-40` | baby-step giant-step | 2^20 steps, 3 s | `k = 1015864291073` |
| `testvector-50` | Pollard rho | 37,672,363 steps, 221 s | `k = 588682124876062` |

Rho landing within 10% of the predicted 2^25.3 is itself evidence the group
order is what the instance claims — a wrong `n` would not produce the right
running time.

Neither is an objective. Each retired to a test vector the moment its answer
was published, and the live 50-bit objective uses a **fresh v2 seed** whose
logarithm nobody has computed. That retirement is the point: an objective whose
answer its poster holds is self-dealing whether the poster chose it or merely
found it first.

## What was checked before this shipped

- `tools/selftest.py`: both solved vectors accepted and their `k` confirmed;
  `k+1` and `k+n` refused; seven malformed artifacts *scored* rather than
  raised (`verification.md` rule 3 — an exception is a broken verifier); all
  three pinned instances re-validated; all four ladder instances re-derived
  from their seeds.
- BSGS cross-checked against exhaustive point counts on four small curves —
  it had a sign error in the giant step, found exactly that way.
- End to end through the real rules engine: the rho solution posted, committed,
  revealed → `accept`, settled 120,000, and `audit` re-verified the chain. A
  wrong `k` against ECCp-131 → `reject: k*G does not equal the target point Q`,
  reward 0.

## Working on one

Pollard rho with distinguished points parallelises linearly and needs almost no
memory; BSGS is simpler but wants `sqrt(n)` of it, which is what makes it the
wrong tool past about 2^50. Nothing in this repository helps you solve these,
and the checker is deliberately indifferent to how you did.
