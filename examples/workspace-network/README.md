# Smallest sorting network for 8 inputs, as a `workspace` objective

A repository-shaped benchmark in miniature: the objective pins a base tree,
says which paths a solver may replace, and pins the command that scores the
result. It is the shape of [ecdsa.fail](https://ecdsa.fail) and
[Yukon](https://yukon.org), small enough to verify in a fraction of a second.
The design is [`docs/design/workspace-benchmarks.md`](../../docs/design/workspace-benchmarks.md).

```
base/score.py           pinned scorer: runs solution/build.py, checks the network, writes score.json
base/solution/build.py  the baseline a solver replaces: a bubble-sort network
base.manifest.json      {path: sha256} for the base tree, pinned by the objective
submissions/batcher/    Batcher's odd-even merge sort, the shipped improvement
artifact.json           a claim for it
pack.py                 directory -> manifest, writing every file to .cairn/blobs
```

Score is comparators × depth; lower is better. The baseline is 28 comparators at
depth 13 (364), and Batcher's network is 19 at depth 6 (114). That is the
floor: 19 comparators and depth 6 are both proven minimums for 8 inputs, so the
objective's target is 114 and the shipped improvement closes it. The example
exists to show the mechanism, not to leave a problem open.

## Try it

```bash
cargo build --release
python3 examples/workspace-network/pack.py examples/workspace-network/base >/dev/null
python3 examples/workspace-network/pack.py examples/workspace-network/submissions/batcher >/dev/null

export CAIRN_EPOCH_SECONDS=1 LOG=$(mktemp -u /tmp/cairn-ws-XXXXXX).jsonl
OID=$(./target/release/cairn --log $LOG --root . post examples/workspace-network/objective.json | awk 'NR==1 {print $2}')
./target/release/cairn --log $LOG --root . commit $OID --submitter you \
    --artifact examples/workspace-network/artifact.json --nonce n1
sleep 2
./target/release/cairn --log $LOG --root . reveal $OID --submitter you \
    --artifact examples/workspace-network/artifact.json --nonce n1
sleep 3 && ./target/release/cairn --log $LOG --root . settle
```

To submit your own network, put your `build.py` at `solution/build.py` in an
empty directory, run `pack.py` on that directory, and wrap its output as
`{"files": …, "results": {"score": N}}` with the score `score.py` prints.

## What the verifier checks

1. **Prepare** (none here) runs on the base tree alone. Failing there is
   `unavailable`: it is the objective's code, and says nothing about you.
2. **Apply.** `solution/` is removed and your files are written in its place.
   A path outside `solution/` is a rejection.
3. **Score.** `python3 score.py` runs in the tree, jailed with no network. A
   non-zero exit is a rejection, and so is a `score.json` whose integer differs
   from the one you claimed.

`score.py` runs your `build.py` as a separate process and reads only its
stdout. That split, the same one ecdsa.fail makes between `build_circuit` and
`eval_circuit`, is the objective's job and not the verifier's: a scorer that
imported submission code in-process would let it write its own score.

## What it does not show yet

There is no `cairn bench` command, so `pack.py` stands in for `bench init`; no
MCP surface shows a claim's `note` to the next solver; and `p2p::code` does not
move base or claim blobs between nodes, so a peer has to be given them.
