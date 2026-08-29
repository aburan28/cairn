# Differential paths for the MD4 family

```sh
cairn post examples/hash-differential/objective-collide-md4.json
python3 examples/hash-differential/tools/selftest.py
python3 examples/hash-differential/tools/search_dv.py --check
cairn try examples/hash-differential/objective-collide-md5-48.json \
  --submitter you --artifact examples/hash-differential/artifacts/md5-48.json
```

Eight objectives over four hash functions, in two shapes. Six pay for a
**conforming pair** -- two messages behind a pinned prefix whose digests agree.
Two pay for the **differential path** itself, as the object an attack is
actually built from: a low-weight codeword of the message expansion.

## Why the artifact is a pair and not a path

The obvious encoding is the one this directory does not use. Ask for a
differential path -- per-step state differences, message differences, the
conditions each step needs -- and you have an artifact nobody can settle. Deciding
whether a path is *satisfiable* is the search the attack performs; deciding
whether it is *good* means estimating a probability, and an estimate is a claim
about somebody's model rather than a fact two nodes can recompute. Neither is a
certificate.

A conforming pair is. It is one recomputation to check, it is unforgeable
without doing the work, and **the path falls out of it** -- the checker replays
both messages and reports the differential the pair actually follows, so the
path is derived rather than declared. An artifact that carries a path it does
not follow is not a different verdict here; it is the same verdict with a
different sentence attached.

The two disturbance-vector objectives take the other half of the problem, the
half that *is* mechanically decidable: not "is this path satisfiable" but "is
this codeword light", which is exact integer arithmetic over a linear code.
Between them they cover both things a real attack needs and neither of them
asks a verifier to have an opinion.

## The collision ladder

| objective | function | steps | bits | cost | status |
|---|---|---|---|---|---|
| [`collide-md5-48`](objective-collide-md5-48.json) | MD5 | 64 | 48 | ~2^24, generic birthday | **worked** — the answer ships |
| [`collide-md4`](objective-collide-md4.json) | MD4 | 48 | 128 | a few hundred MD4, with the published path | **open** |
| [`collide-md5`](objective-collide-md5.json) | MD5 | 64 | 128 | ~2^16–2^24, with published tooling | **open** |
| [`collide-sha1-64`](objective-collide-sha1-64.json) | SHA-1 | 64 | 160 | ~2^35 | **open** |
| [`collide-sha0`](objective-collide-sha0.json) | SHA-0 | 80 | 160 | ~2^33–2^39 | **open** |
| [`collide-sha1`](objective-collide-sha1.json) | SHA-1 | 80 | 160 | 2^61–2^63 | **open**, not expected to settle |

Costs are what the literature reports for these attacks, not measurements taken
here. The two cheap rungs are cheap on purpose: a ladder whose lowest rung is
2^35 is a ladder nobody starts.

**This pays nobody else's prize money.** These are not the SHAttered, Certicom
or alloc-init challenges and settling one claims nothing from anyone.

## Every one of these functions is already broken. So what is being bought?

Not novelty — *this* instance. Each objective pins a 64-byte prefix derived as
`sha512("cairn hash-differential v1 <name>")`, and 64 bytes is exactly one
message block for all four functions, so the chaining value an attack starts
from is one compression of a public constant with no partial block to fill.

Two consequences, and they are the whole design:

**Nothing published can be replayed.** Every published collision for MD4, MD5,
SHA-0 and SHA-1 starts from the function's standard IV behind a prefix its own
author chose. None of them begins with any of these prefixes, so none of them
verifies here. *"Copying earns exactly zero"* is usually a rule about
duplicates; here there is simply nothing to copy.

**Nobody can fund their own answer.** A funder who picks a prefix can pick one
whose chaining value they have already collided, collect their own bounty, and
leave nothing in the record that looks wrong — the self-dealing row in
[`threat-model.md`](../../docs/threat-model.md), and the same defect
`scripts/derive-first-blood.py` was written to remove from the ECDLP
instances. Deriving the prefix from a published seed removes the choice.
Grinding the seed buys nothing for the same reason it buys nothing there: to
gain you would have to *recognise* a chaining value you can already collide,
and recognising one means doing the work.

Equal length is required of the pair, which is not bookkeeping. A same-length
collision composes — `H(m || x) = H(m' || x)` for every `x`, because
Merkle-Damgård feeds the same chaining value into the same remaining blocks —
and that composability is the property a collision is worth paying for.
Different-length pairs do not have it.

## The disturbance-vector bounties, and the one line between them

An attack on a SHA-family compression function starts by choosing a difference
in the expanded message words that can be cancelled step by step: a
*disturbance* at step `i`, and corrections at steps `i+1..i+5` that undo it.
Expanded words are not free — they are determined by the first sixteen — so the
difference has to be a codeword of the message expansion. That codeword is the
disturbance vector, and its weight is roughly what the attack costs.

Both objectives ask for the same thing over the same recurrence:

```
score = sum of the Hamming weights of DV[20..79],  minimised
```

and the two expansions differ by one rotation.

| | expansion | the code | minimum weight |
|---|---|---|---|
| [`dv-sha0`](objective-dv-sha0.json) | `W[i] = W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16]` | 32 independent `[80, 16]` binary codes | **17, proved** |
| [`dv-sha1`](objective-dv-sha1.json) | `W[i] = ROTL1(...)` | one `[2560, 512]` code | unknown; **31** is the best found |

Without the rotation, XOR acts on each of the 32 bit positions separately. A
codeword is then 32 independent codewords of one length-80 binary code, weights
add, and the lightest vector overall must live in a single bit position —
because using a second only adds weight. One bit position has 2^16 codewords,
which is a loop. So SHA-0's optimum is *computed*: it is 17,
`tools/search_dv.py --check` re-derives it in about a second, the target is that
number, and [`artifacts/dv-sha0-optimal.json`](artifacts/dv-sha0-optimal.json)
reaches it and exhausts the pool.

Put the rotation back and the bit positions couple. The same argument collapses,
and finding a minimum-weight codeword becomes the hard problem it is everywhere
else. So `dv-sha1` ships with an **upper bound and no lower bound at all**:

| search | best |
|---|---|
| every single-bit window, at every offset | 31 |
| every pair of single-bit windows sharing an offset | 31 |
| sampled three- and four-bit windows | 31 |
| beam search over XOR combinations of those | 31 |
| hill-climbing from random codewords | ~800 |

The last row is the informative one. A random codeword of this code weighs
about half of 1760 bits, and descending from one gets nowhere near 31: light
codewords are not found by local search, they are the images of sparse windows.
Which is exactly why a better one is worth a bounty.

Baseline 31 is that upper bound, so **the vector this repository already holds
settles for nothing** and the pool pays only for beating it. Target 24 is a
construction target: nothing here says a vector that light exists.

### What the score is, and what it is not

It is the Hamming weight of a codeword over a stated range, decided exactly in
integer arithmetic. It is a *proxy* for attack cost — real cost also turns on
which bit positions are disturbed, on how local collisions overlap, and on how
far message modification actually reaches — and the objective says so rather
than implying otherwise. What is bought is a light codeword. Nothing here is a
claim about anybody's attack.

Two rules shape what counts:

- **A disturbance at step 75 or later is refused.** Its corrections would fall
  at steps 80..84 and there are none, so the vector cannot be completed into
  local collisions inside one compression. Multi-block attacks relax exactly
  this, letting an uncorrected tail become a near-collision the next block
  cancels; a vector refused here can still be useful there. These objectives
  buy single-block vectors and say so.
- **Steps 0..19 are not scored.** The first sixteen message words are chosen
  directly, so conditions there are met by construction rather than by search.

### Why an empty answer cannot take the pool

On a *minimise* objective, zero is the best score expressible, and the all-zero
vector is a codeword that weighs nothing and describes no attack. That is the
failure [`faster-algorithms`](../faster-algorithms/) has its own adversarial
battery for, and it is guarded here twice.

It is refused outright. And it could not have won anyway: the scored range is 60
words wide, the tail must be zero, and **any 16 consecutive zero words already
force the all-zero vector everywhere** — so a score of 0 is unreachable by the
geometry of the code rather than by the guard. That is the version of the
argument worth having, because it survives someone deleting the guard.

## Eight files that are nearly one file

Six checkers differ only in a pinned instance block; two evaluators differ only
in a boolean. Hand-maintaining eight copies of one argument is how five come
out right and the sixth quietly stops checking what its README says — so they
are generated, and `tools/build_pinned.py --check` re-renders and diffs every
one. That is the same guard `scripts/derive-first-blood.py --check` and
`examples/faster-algorithms/tools/build_baselines.py --check` put on their own
derived files.

They cannot share a module instead: `checker_sha256` covers one file, and
[`verification.md`](../../docs/verification.md) rule 4 is that a checker
reading an unpinned file passes today and fails tomorrow at the same hash. The
duplication is forced. The drift is not.

Regenerating moves every objective id, and that is correct rather than
unfortunate — an edited instance forks the objective instead of rescoring work
already done against it, which is what makes a mid-bounty rule change
unrepresentable rather than merely forbidden.

## How acceptance was proven, given every collision instance is open

Running a checker against an unsolved instance only ever demonstrates
rejection, and a verifier shown only to reject is indistinguishable from one
that rejects everything. The 48-bit MD5 rung exists to close that gap: it is
generic birthday work with no cryptanalysis in it, its answer was computed here
by Pollard rho over 25,751,494 evaluations
(`tools/solve_truncated.py`), and it ships. So one checker from this template is
observed accepting a real pair, and the same pair is observed being **refused**
by the full-MD5 checker generated from the same template.

`tools/selftest.py` is the rest of it, and it asserts:

- the committed pair passes its checker, and the three committed vectors score
  what their objectives were written for;
- a colliding pair moved behind a different prefix is refused — the
  anti-replay property, executable;
- all six prefixes are distinct, all re-derive from their published seeds, and
  all are exactly one block;
- MD5 and SHA-1 agree with `hashlib` on seven messages spanning both padding
  boundaries; **MD4 and SHA-0 are in no modern OpenSSL**, so they are pinned
  against the published RFC 1320 and FIPS 180 vectors instead — a transcription
  error there would otherwise stay invisible until it silently refused a
  correct break;
- SHA-0 is SHA-1 with the expansion rotation removed and *only* that;
- fifteen malformed artifacts and nineteen malformed vectors **score rather
  than raise** ([`verification.md`](../../docs/verification.md) rule 3: an
  exception out of pinned code is a broken verifier, and `Unavailable` is never
  `Reject`);
- `INVALID` is worse than the heaviest vector expressible, so nothing malformed
  can take a minimise pool;
- re-anchoring a vector at all 65 offsets, and rotating every word by 1..31,
  leave the score unchanged — both are symmetries of the code, and a submitter
  writing a published vector down at the offset it was published at must not be
  scored differently from one who re-anchored it by hand.

## Working on one

Nothing in this repository helps you find a collision, and the checkers are
deliberately indifferent to how you found one. The prefix is the only thing
that makes these instances different from the ones in the literature: take the
64 bytes out of the checker (or recompute them from the seed), run one
compression to get the chaining value, and point a published attack at it —
that chaining value is the parameter every implementation of these attacks
already takes.

For the vectors, `tools/search_dv.py --full` runs every search that has been
tried here and prints what each one reached. Beating 31 is a
minimum-weight-codeword problem over a 512-dimensional binary code, and the
structure worth knowing before starting is that rotating every word of a
codeword by the same amount gives another codeword of the same weight — ROTL
commutes with XOR and with ROTL1 — so bit position is free and only the pattern
matters.
