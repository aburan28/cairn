# A measured ECDLP bound, scored against the generic floor

An objective whose artifact is not a construction but a **measurement**: a
sealed record of what an ECDLP method cost, scored by how close it came to the
bound every generic method shares. The evaluator rescores the record from its
own counts and accepts a self-consistent one in its domain; it does not, and
cannot, re-run the sessions the record names. Read the accept for exactly what
it is: a receipt for a well-formed frontier entry, not a replay.

Two real records ship, both measured by the same harness on the same four
prime curves: Pollard rho with the negation map at 1.466 times the floor, and
baby-step giant-step with the negation map at 1.154 times. They score 682064
and 866743.

## What a measured bound is

The record is the output of [ecbench, aburan28/crypto's ECDLP
harness](https://github.com/aburan28/crypto/blob/main/docs/bounds/README.md),
which runs a method on planted instances across curve sizes, counts its work
in **group-addition equivalents** (`gae`: every point addition, doubling and
canonicalisation charged under one stated cost model, never a clock), audits
the session with exact replays, and fits `gae = C · r^α` over the sizes. A
*bound* is that fit, sealed with an id (`ECBND1h…`, the SHA-256 of the record
with the id field empty) and carried with everything it was fitted from: per
size the group order `r`, the mean `gae`, `S = mean_gae / √r`, the generic
floor `√(π / 2A)` for the `A` automorphisms the method may use, and the ratio
of the two; the pooled ratio as the run-weighted mean over the sizes; and the
provenance -- session ids, the SHA-256 of each session's `records.jsonl`, the
audit that replayed it.

The floor is the yardstick, not a theorem about these curves: `√(π r / 2A)`
group operations is what a collision search costs in expectation when it
exploits `A` automorphisms and nothing else about the group. A method at the
floor scores 1 000 000; one above it is possible in principle, which is why
the ratchet's target is the floor and the curve pays nothing past it.

## What the evaluator checks, and what it cannot

Everything the record lets it recompute: every size's `S` from its `mean_gae`
and `r`; the floor from `A`; each ratio; the pooled ratio from the sizes,
weighted by verified runs; that every measured run verified; that
`constant.ratio_to_floor.value`, `dimensions.ops.value` and
`provenance.verified` agree with those sums; that the domain fields are this
objective's (`ecdlp.single_target`, `prime`, `planted`, `ecbench.gae`, `toy`,
one cold target, no precomputation); that no field is at most 32 bits wide
-- the toy tier; that the unit is counted and not clocked; and that the record
is admissible by its own account. A record whose stated figures disagree with
its own counts is refused: a better headline typed over a worse measurement
scores zero.

What it cannot check, stated plainly, because the accept must not be read as
more than it is:

- **That the sessions exist and replay.** A jailed evaluator has no filesystem
  and no `ecbench`. That check is the measuring repository's CI (`ecbench
  bound check`, `ecbench verify --replay-all`) and an independent runner's
  replay receipt, both cited by hash inside the record. A reader who wants the
  replay follows the hashes.
- **That the method is what it says.** `method.id` is a name. The counts are
  self-consistent whether or not the code that produced them was the
  algorithm the name suggests.
- **The record's own id.** `bound_id` is the hash of the measuring
  repository's bytes, and the artifact here is a rendering of them (below),
  so it is named and not recomputed.

So an accept means: *this is a well-formed, admissible, internally consistent
bound record in this domain and tier, and this is where its method stands
against the floor.* A research program that carries the receipt into its own
ledger must still decide on its own evidence whether to believe the
measurement; the autoresearcher's `docs/bounds-and-frontiers.md`, which this
objective comes from, says an accept here backs no direction on its own.

## The score

Parts per million of the floor achieved: `round(1 000 000 / pooled ratio)`,
maximised, capped at ten million so no crafted record can push an integer past
the 64 bits the frontier stores. `artifacts/prime-rho-neg.json` scores
**682064**, `artifacts/prime-bsgs-neg.json` **866743**.

An invalid record scores **zero and never raises**. The verifier's `threshold`
is 1, so zero is a `reject`; a raise would be `unavailable`, which settles
nothing and could be provoked at will by submitting garbage -- the same choice
[`../capset/`](../capset/) made first. `artifacts/tampered-mean-gae.json` is
the rho record with one size's `mean_gae` multiplied by 0.9 and nothing else
touched: its stated `S` no longer follows from its counts, and the node
reports `reject  score 0  (score 0 vs threshold 1 (maximize))`. The evaluator
also exposes `check(artifact) -> (bool, reason)` for a submitter who wants to
know *why*; the node never calls it.

Only the exceptions a hostile record can cause are caught. A bug in the
evaluator itself still propagates, so a broken evaluator reads as an outage
rather than as a rejection of every honest record.

## Floats travel as decimal strings

This network's canonical encoding has no float variant -- deliberately, since
an artifact's id is the digest of its bytes and doubles do not round-trip
identically through every JSON implementation. A bound record as ecbench
writes it has dozens of floats and is refused at `propose`, `commit` and
`score_candidate` before any verifier runs:

```
$.constant.declared_ratio_to_floor: float values are not canonically
serializable; carry a scaled integer or a decimal string instead
```

The artifact is therefore the record with every non-integer number carried as
its shortest round-trip decimal string, and nothing else changed: integers,
strings, booleans and nulls stay as they are, keys are sorted. Python's
`repr` writes that string and `float()` reads it back to the same double, so
the rendering is lossless:

```python
import json, sys
def render(v):
    if isinstance(v, float): return repr(v)
    if isinstance(v, list): return [render(x) for x in v]
    if isinstance(v, dict): return {k: render(x) for k, x in v.items()}
    return v
json.dump(render(json.load(sys.stdin)), sys.stdout, indent=2, sort_keys=True)
```

The evaluator reads both spellings, so it gives the same integer for the
record as committed and for the artifact as the node delivers it. The
autoresearcher's `tools/bound_artifact.py` is the same rendering with a
`check` that proves a given artifact reads back to a given record.

## The ratchet

```
baseline 500000      a method spending twice the floor's group additions
target   1000000     the floor itself; the curve pays no more past it
min_improvement 10000   one per cent of the floor
```

The verifier's threshold and the ratchet's baseline answer different
questions. The threshold says whether an artifact is a bound record at all;
the baseline says where paying starts. A slow but self-consistent method --
three times the floor, say -- is *accepted*, pays nothing, and does not take
the frontier. That is the right reading of each verdict: `reject` here always
means "not a bound record", never "slow".

On the shipped artifacts the curve pays `rho` 364128 of the notional
million-unit pool for moving the frontier from an empty start to 682064, then
`bsgs` 369358 for carrying it to 866743, and leaves 266514 for whoever gets
closer. The objective shuts for good once a frontier reaches 990001 or better,
which can strand at most 19998; `cairn post` prints that figure before
anything is funded, and `tests/example_bounties.rs` checks that neither
shipped artifact ends the bounty early.

`min_improvement` is an economic parameter -- the network's defence against
slicing one result into many paid steps -- and not a statistical one. Whether
a one-per-cent move is *real* is a question for the measuring repository's
paired challenge, which compares two methods on the same instances with
bootstrap intervals; the frontier here records who holds the best receipt and
in what order. The two shipped records happen not to overlap on their 95%
intervals (`constant.ratio_to_floor.ci95`), but the ratchet did not check
that and does not claim to.

## Run it

```sh
export CAIRN_EPOCH_SECONDS=1
LOG=/tmp/pw-bound-frontier.jsonl
CAIRN=./target/release/cairn

OID=$($CAIRN --log $LOG --root . \
        post examples/bound-frontier/objective-ecdlp-prime-toy.json | head -1 | awk '{print $2}')

# Score before you submit: the pinned evaluator, locally, writing nothing.
$CAIRN --log $LOG --root . propose "$OID" --dry-run \
  --artifact examples/bound-frontier/artifacts/prime-rho-neg.json \
  --artifact examples/bound-frontier/artifacts/prime-bsgs-neg.json \
  --artifact examples/bound-frontier/artifacts/tampered-mean-gae.json

# One round each: commit, wait out the epoch, reveal, wait out finality, settle.
# The second submitter must cite the frontier the first one set; `try` does it.
$CAIRN --log $LOG --root . try "$OID" \
  --submitter you --artifact examples/bound-frontier/artifacts/prime-rho-neg.json --settle
$CAIRN --log $LOG --root . try "$OID" \
  --submitter them --artifact examples/bound-frontier/artifacts/prime-bsgs-neg.json --settle
$CAIRN --log $LOG --root . audit
```

What that printed on 2026-10-06, abridged to the lines that carry a verdict:

```
objective sha256:afa1ed2096554e53522fadb3ee0c43f42e9f8f5182f900c6b05c27b3e820ef5d
  reward 1000000  verifier evaluator
  note: closes for good at score 990001, leaving up to 19998 of 1000000 unpaid. ...
  examples/bound-frontier/artifacts/prime-rho-neg.json: accept  score 682064
  examples/bound-frontier/artifacts/prime-bsgs-neg.json: accept  score 866743
  examples/bound-frontier/artifacts/tampered-mean-gae.json: reject  score 0  (score 0 vs threshold 1 (maximize))
  --dry-run: nothing was written
  verdict  accept: score 682064 vs threshold 1 (maximize)
  settled  true  reward 364128  (frontier advanced)
  citing the frontier sha256:08cc6e49...
  verdict  accept: score 866743 vs threshold 1 (maximize)
  settled  true  reward 369358  (frontier advanced)
log verified: chain intact, every settled claim re-verified
```

`try --settle` waits out the reveal epoch and the one-epoch finality delay
itself, so there is nothing left to drain afterwards; a `settle` run after it
says `no batch was due`. A real round takes real epochs -- 600 s each, two per
`try` -- so set `CAIRN_EPOCH_SECONDS` for a trial, and only against a log used
for nothing else. Submitting the tampered artifact through `try` reaches a
reveal and is refused there, `verdict reject: score 0 vs threshold 1
(maximize)`, `settled false reward 0`: a rejection is a real verdict, written
to the log, and the audit re-derives it.

## Post and fund it

Posting is funding: the record's `reward` is the pool, and `cairn post` writes
it to the log and prints the id everything else refers to. On a node that
declares a scarce supply the funder must be a signed identity --
`cairn post examples/bound-frontier/objective-ecdlp-prime-toy.json --identity
you.json` -- and `funding_signature` is then part of the record. Over MCP,
`post_objective` does the same and a reward above zero needs the operator's
`--max-spend`. Rewards here are notional, as everywhere under `examples/`.

One objective is one domain and one tier. The evaluator binds both by
constants in its own text, so a frontier for another family, target kind or
tier is a copy of the evaluator with other constants -- hence another hash,
hence another objective -- and never an argument on this one. Give it the same
goal key with its own angle (`GOAL-ecdlp-bound-frontier/<domain>`) so the
frontiers group under one problem.

## Where it comes from

The crypto-autoresearcher program keeps the same evaluator and objective at
`cairn/checkers/bound_frontier_prime_toy.py` and
`cairn/objectives/bound-frontier-ecdlp-prime-toy.json`, posted with
`reward: 0` and its own funder, and its `docs/bounds-and-frontiers.md` says
what a bound is allowed to mean in its ledger. The two objectives are
different records by construction: the evaluator's path and the funder are
inside the id. The code is the same.
