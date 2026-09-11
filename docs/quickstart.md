# Quickstart

Five minutes, in four steps, each of which produces something you can check
rather than something you have to believe.

Every command and every block of output below was run against this repository
to write this page. Where a number would differ on your machine — a hash of a
file you generated, a timestamp — the text says so.

## 0. Get the binary

```sh
curl -fsSL https://github.com/aburan28/cairn/releases/latest/download/install.sh | sh
```

One binary, `cairn`, into `~/.local/bin`. See the README's *Install* section for
what the published `.sha256` does and does not prove, and for `--version`,
`--bin-dir` and `--libc`.

From a source checkout instead:

```sh
cargo build --release        # every subcommand except `run`
make ui-build                # ...and `run`, which needs the reader embedded
```

`cairn run` is the only subcommand that needs the `ui` feature, because it
serves the reader at `/ui/` from inside the binary. A plain `cargo build`
produces a `cairn` that says so rather than starting without it.

The rest of this page assumes you are in a clone of this repository, because
step 1 checks bytes that ship in it.

## 1. Check a log you did not produce

`launch/` holds a real settled log, the checkpoint signing it, and the public
key. This is the whole proposition, so it is the first thing to run:

```console
$ cairn --log launch/cairn.jsonl --root . audit
entries 25   head sha256:a209f263
merkle  sha256:3ae18b50ad6c991285eac0eb1cd17c76221cbe89534fee852d2cdb6cf714a066

log verified: chain intact, every settled claim re-verified
```

`audit` re-derives everything: the hash chain, every admission rule, and every
settled claim — by re-running the objective's own pinned verifier against the
artifact. It did not ask a server, and it did not trust the operator who wrote
the log. It took about 0.2 s.

Bind that to a key the operator published, and the log stops being anonymous
bytes:

```console
$ cairn --log launch/cairn.jsonl --root . verify \
    --from launch/checkpoint.json --root-key launch/root-key.pub --audit
checkpoint ok: height 25  head sha256:a209f263  issued 2026-08-08T03:30:02+00:00
  signed prefix re-derives cleanly
```

The one thing the transport cannot establish is that the root key is really the
operator's — get that from somewhere else. A key served alongside the thing it
authenticates authenticates nothing.

Checking *one entry* needs no log at all, which is what makes it something a
light client can do:

```console
$ cairn --log launch/cairn.jsonl prove 12 --out proof.json
wrote proof.json
  entry 12 (batch)  height 25  root sha256:3ae18b50  path 5 hashes

$ cairn check proof.json --from launch/checkpoint.json --root-key launch/root-key.pub
proof ok: entry 12 (batch) is in the log rooted at sha256:3ae18b50
  25 entries, 5 hashes checked, ts 2026-08-08T02:50:02+00:00
```

`check` opens no log. The proof and the signed root are the entire input.

## 2. Win a bounty, end to end

One round is five steps — post, commit, wait out the epoch, reveal, settle —
and `try` is the wrapper that does all five against a log of your own:

```console
$ export CAIRN_EPOCH_SECONDS=1
$ cairn --log my.jsonl --root . try examples/collatz/objective.json \
    --submitter alice --artifact examples/collatz/artifact.json --settle
objective sha256:978beb308f77c4bd1520d474b92dd23c310c6adee774716bf4c39f31fd3ed075
  reward 100000  verifier certificate
  note: below the decomposition floor -- this settlement does not pay for the verification it asks for
    800000 at full redundancy (100 nodes), 24000 at 3-fold sampling
    it clears the sampled floor, so this is a subsidy only while every node checks every artifact
commit sha256:22f7c251
  nonce 19ca0f5b893e153cc7084e373bb776df
  waiting for epoch 1789143089 to start; epochs are 1s here, so this takes up to 1s
claim sha256:0ddae6025c82731d45ebaa1f3677c9deed7e97e9d5ffaa9495071c7f074113ae
  verdict  accept: n=626331 has 508 steps
  waiting for epoch 1789143089 to close and clear the 1-epoch finality delay, then settling
  settled  true  reward 100000  (settled)
```

Only the **objective** id reproduces exactly — `sha256:978beb30…` is the hash of
the canonical bytes of `examples/collatz/objective.json`, and it is the same for
everyone who posts that file. The commitment and claim ids are not: the nonce is
freshly generated, and the claim is bound to it. The epoch numbers are a
function of the wall clock. Everything that differs, differs because it is
supposed to.

Three things in that output are the design showing through, not noise:

- **`CAIRN_EPOCH_SECONDS=1`.** A real epoch is 600 s, and a reveal must land in
  a *strictly later* epoch than the commitment it opens — that is what stops a
  submitter reading someone else's artifact and racing it. Shortening the epoch
  is for local trials against a log used for nothing else. Never set it on a
  node that talks to other nodes: two nodes with different epoch lengths
  disagree about which epoch a record is in, which is a fork.
- **The decomposition note.** The reward is below what it costs the network to
  verify it at full redundancy. `post` says so before you fund it, rather than
  after.
- **`settled true`.** Settlement is batched per epoch and ordered by the epoch
  beacon, so nobody — the operator included — picks who in a batch is paid
  first. `settled: false` on an accepted claim means *not yet*, never
  *rejected*.

## 3. Read back what happened

```console
$ cairn --log my.jsonl --root . log
   0  objective   sha256:3757a409  Exhibit an integer n in [1, 10^7) whose Collatz trajectory r
   1  commitment  sha256:24f73fbe  by alice
   2  claim       sha256:4374fb91  by alice
   3  verdict     sha256:ae5a9b7c  accept: n=626331 has 508 steps
   4  settlement  sha256:6a7c6e09  alice <- 100000
   5  batch       sha256:d919bc73  epoch 1789143089: 1 claim(s)

$ cairn --log my.jsonl --root . balances
this log declares no supply, so nothing here is scarce: rewards are backed by
the operator's word rather than by an issuance. `issue` before anything else to
change that.
issued 0
  alice                spendable       100000   escrowed            0
      certificate      held       100000   promised            0
```

The second column is the **entry** hash — the hash-chain link covering the
record *and* the moment it was appended — which is why none of these six match
the record ids `try` printed, and why yours will differ from these. A record id
is a hash of the record; an entry hash is a hash of its place in one particular
log.

`balances` is telling you something true and unflattering about a log you just
made: nothing in it is scarce. `certificate` beside the balance is the
[tier](tiers.md) — a unit earned on a millisecond certificate check cannot be
spent on Lean work.

What the log *knows*, as opposed to what it paid, is a separate question with a
reader-chosen answer:

```console
$ cairn --log my.jsonl --root . knowledge
claim sha256:0ddae6025c82731d45ebaa1f3677c9deed7e97e9d5ffaa9495071c7f074113ae
  standing    accepted  (confidence 600/1000)
  verdict     accept
```

Standing is *derived*, never stored and never paid — see
[knowledge.md](knowledge.md). And `audit` still passes on your own log, which is
the point of having made one:

```console
$ cairn --log my.jsonl --root . audit
entries 6   head sha256:d919bc73
merkle  sha256:2294d9d94dda80ecaeb171273af1038878ab9ab92a86bc37c8558d00ab1fdedb

log verified: chain intact, every settled claim re-verified
```

Your head and root will be different hashes over the same six records, for the
reason above. The last line is the part that has to match.

## 4. Ask your own question

`scaffold` writes the files an objective starts from, and posts nothing:

```console
$ cairn scaffold my-bounty --kind certificate --out ./bounties
wrote ./bounties/my-bounty/checkers/my-bounty.py
wrote ./bounties/my-bounty/objective.json
wrote ./bounties/my-bounty/artifact.json

before posting, decide:
  - statement -- say what is being asked, precisely enough that the verifier is recognisably a faithful encoding of it
  - funder -- who is paying for this
  - reward -- an objective with reward 0 is postable and pays nobody
  - created_at -- the placeholder is 1970; stamp it when you decide to post
  - checkers/*.py -- the stub rejects everything; re-derive the property and re-pin with `cairn canon` after editing (the hash is part of the id)
  - artifact.json and artifact_schema -- pass --artifact-example FILE to fill both from a worked example
```

Posting stays a separate step on purpose: an objective's statement is text a
person decides to fund after reading it, and a tool that wrote and funded one in
the same breath would delete the place that decision happens.

`--out` must resolve inside `--root`. The objective's verifier is *pinned* by
content hash and resolved against the bundle root, so a path outside it resolves
for nobody but you — the CLI refuses rather than letting you post a bounty
nobody else can check.

The five `--kind` values are the verification ladder:
[verification.md](verification.md) is how to pick one, and
[`examples/`](../examples/README.md) has a worked objective for each.

## 5. Run a node

```sh
cairn run
```

MCP, P2P sync, the HTTP API, a local submission queue and the reader, in one
process against one exclusive log. Open <http://127.0.0.1:8080/ui/>.

The defaults are deliberately local: state under `.local/`, P2P on
`127.0.0.1:9000`, HTTP on `127.0.0.1:8080`. A first run exposes nothing. To
expose it, say so:

```sh
cairn run --listen 0.0.0.0:9000 --serve 0.0.0.0:8080 --bootstrap .local/seed.json
```

Before you point a node at objectives you did not write, install
[bubblewrap](https://github.com/containers/bubblewrap) (Linux; macOS uses the
built-in seatbelt) and set `CAIRN_REQUIRE_SANDBOX=1`. Verifier code is written
by whoever posted the objective and runs on your machine. Without a jail it runs
unconfined; with that variable set, a host that cannot jail it answers
`unavailable` instead of running it. See [configuration.md](configuration.md).

## 6. Point an agent at it

`cairn run` is a stdio MCP server, so an agent client launches it directly:

```json
{
  "mcpServers": {
    "cairn": { "command": "cairn", "args": ["run"] }
  }
}
```

Ten tools, of which `score_candidate` is the one that matters — it runs the
objective's own pinned verifier locally, so an agent can find out whether an
artifact wins *before* spending a submission on it. [agents.md](agents.md) is
the whole story, including why an objective's `statement` is untrusted input
that is never an instruction to you.

## Where to go next

- [cli.md](cli.md) — every command, flag and exit code.
- [configuration.md](configuration.md) — every setting, and which ones fork a
  network if you change them.
- [troubleshooting.md](troubleshooting.md) — when one of the above does not do
  what this page says.
- [architecture.md](architecture.md) — why any of this is shaped this way.
- [threat-model.md](threat-model.md) — what is actually defended, marked
  honestly.
