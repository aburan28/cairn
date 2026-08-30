# SHA-1: differential paths, and the pairs that prove one worked

Two objectives on the same attack, split where the honesty boundary is.

| objective | kind | score | baseline | ceiling |
|---|---|---|---|---|
| `objective-disturbance-vector.json` | minimize | disturbances in steps 20..74 | 60 | a construction target, not a bound |
| `objective-reduced-collision.json` | maximize | deepest step the two blocks agree at | 15 | 80, which is open |

A differential attack on SHA-1 begins with a **disturbance vector**: a pattern
of single-bit disturbances, each cancelled by corrections in the five following
steps.  The message expansion is linear over GF(2), so the vector is not free —
it has to be a codeword of the expansion, and finding a light one is
minimum-weight decoding.  The first objective scores the vector.  The second
scores the thing a vector is *for*: two message blocks that actually
re-converge.

## Why the checkers can be trusted with money

Both derive the score from the object and never read a number the submitter
chose — the distinction `examples/reversible-adder/` draws against
`examples/ecdsa-fail/`.

`dv_cost.py` takes sixteen words and expands them with SHA-1's own recurrence,
so a vector that is not a codeword cannot be declared into one.  Two structural
conditions carry the rest: the zero codeword is refused, and a disturbance in
steps 75..79 is refused because its local collision cannot close inside the 80
steps.  The metric cannot be dodged by hiding weight in the excluded early
steps — the expansion inverts, so sixty consecutive zero words force the whole
vector to zero, and the floor of 1 is real.

`reduced_collision.py` runs the real compression function on both blocks and
reports the deepest step at which the working states agree.  The **deepest**,
not the length of the agreeing prefix: a differential path works by letting the
states diverge and steering them back together, so a prefix measure would score
the thing being looked for at zero and score a pair that does nothing at
fifteen.  That the step function is SHA-1 and not a lookalike is checked
against `hashlib` in `tools/selftest.py`, not against a second copy of the same
assumption.

## What they do not decide

The first counts disturbances, not conditions, and says nothing about *where*
they sit — bit position 1 propagates carries, the four round functions cost
differently, adjacent disturbances interact.  A low-weight vector is not
automatically a usable attack, and that judgement is not arithmetic.

The second says a *reduced* SHA-1 has a collision at some step count.  It says
nothing about full SHA-1 and nothing about preimages.  Reaching 80 would be a
one-block SHA-1 collision; the published collisions (SHAttered, 2017) are
two-block chosen-prefix constructions and do not settle it.

## A ratchet is a record, not a sentence

Both objectives were first posted **without a `ratchet` stanza**, and the
mistake is worth keeping written down because nothing complained.  The
statements said payment is proportional to the distance the frontier moves and
that every submission must cite the frontier it beat.  The records did not say
it: with no ratchet there is no frontier, `frontier_status` reports "nothing to
cite", and the first accepted claim takes the whole pool.  A 34-step pair
collected six million where it had earned nineteen sixty-fifths of it.

That is exactly the split the repository keeps insisting on -- the statement is
prose a funder wrote, and the record is what the rules engine reads.  A
promise that lives only in the statement is not a promise.

The objectives here carry ratchets and are therefore *different objectives*:
the id covers the whole record, so adding one forks rather than edits, and the
first postings keep their settled claims.  The ids of both are in
`research/crypto-autoresearcher/results.json`.  With the ratchet in place the
same two artifacts paid 1,611,111 of 2,000,000 and 1,753,846 of 6,000,000 --
the distance each actually moved -- and the rest of both pools is still there
for whoever goes deeper.

## Checking it yourself

```sh
python3 examples/sha1-differential/tools/selftest.py
```

Both checkers against facts that do not come from them: the compression
function against `hashlib`, the expansion against its own inverse, the free
baseline of 15 against a pair anyone can type, and malformed artifacts against
the rule that a bad artifact scores rather than raises.
