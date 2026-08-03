# A published log, and how to check it yourself

This directory holds one real, settled proofwork log, the signed checkpoint
over it, and the public key that signed it. It exists because the project's
whole claim is

> anyone can independently re-derive every settled result from the log alone

and that is worth nothing without a log anyone can actually get.

```
proofwork.jsonl    the log: objectives, commitments, claims, verdicts,
                   settlements, frontier moves, and the settlement batches
checkpoint.json    (height, head, merkle_root) signed with ML-DSA-65
root-key.pub       the public half, hex
```

## Check it

From a checkout of this repository, with `proofwork` built:

```sh
proofwork --log launch/proofwork.jsonl --root . audit
proofwork --log launch/proofwork.jsonl --root . verify \
    --from launch/checkpoint.json --root-key launch/root-key.pub --audit
proofwork --log launch/proofwork.jsonl --root . attribute
```

The first re-runs every pinned verifier against every settled artifact and
re-derives the settlement order from the epoch beacon. The second checks the
signature and recomputes the head and Merkle root over the signed prefix. The
third recomputes the citation-flow payouts.

And the check that actually matters — the Python reference implementation
re-deriving the same log, having shared no code with the Rust one:

```sh
PYTHONPATH=reference/python python3 -m proofwork.cli \
    --log launch/proofwork.jsonl --root . audit
```

Both print the same Merkle root. That is the claim made concrete: not "anyone
running my code can check this", but "two implementations written separately
in different languages agree on every id".

## What is in it

Two objectives from `examples/`:

- **collatz** — a pass/fail certificate objective. One submitter, one
  artifact, one settlement of the whole 100,000-unit reward.
- **capset_progressive** — a progressive bounty, ratcheted three times: alice
  reaches 12, bob 16 citing alice, carol 20 citing bob. Each is paid for the
  distance it moved, and each had to cite the frontier it beat, because that
  is enforced at submission rather than judged afterwards.

`attribute` then shows the point of the whole payout structure: **alice ends
up with the largest total from the smallest direct reward**, because two
people built on her. Publishing immediately is the profitable move.

## Two honest caveats

**The signing key is thrown away.** `scripts/make-launch-log.sh` generates it,
signs, writes the public half here, and deletes the secret with its temp file.
So this checkpoint can never be extended, and nobody can sign a *different*
log that verifies against `root-key.pub`. For a sample artifact that is the
right trade. A real operator keeps the key and publishes checkpoints as the
log grows.

**Getting the key from here proves nothing.** `root-key.pub` sits next to the
thing it authenticates, so a server that lied would simply have lied about
both. In a real deployment you get the operator's key from somewhere you
already trust — a signed release, a repository you follow, a person — and only
then does `verify --from` mean what it looks like it means. It is included
here because this is a sample you are reading inside the repository that
produced it, which is exactly the case where that does not matter.

## Rebuilding it

```sh
./scripts/make-launch-log.sh
```

Takes the better part of an hour, deliberately: it uses the **default**
600-second epoch length rather than the one-second epochs the demo scripts
use. Epochs are derived from record timestamps and never stored, so a log
built with `PROOFWORK_EPOCH_SECONDS=1` can only be audited by somebody who
sets the same value — and a published artifact that fails `proofwork audit`
for anyone running it with defaults would say the project's central claim is
false. (If you ever see every batch in a log fault at once, that is the first
thing to check; `audit` now says so.)

Re-running produces a *different* log with the same content — timestamps come
from the wall clock and nonces from the OS, so the ids move. What must not
change is that it audits, that both implementations agree on its root, and
that the payouts follow the ratchet.
