# CLI reference

Every `cairn` subcommand, what it reads, what it writes, and what it exits with.
`cairn help` is the same list in one screen; this page is the one with the flags
in it.

New here? [quickstart.md](quickstart.md) is the five commands that matter, in
order. Settings that are not flags — environment variables, file locations,
ports — are in [configuration.md](configuration.md).

## Shape of a command line

```
cairn [global options] <command> [command options]
```

Global options come **before** the command name:

| option | default | what it names |
|---|---|---|
| `--log PATH` | `$CAIRN_LOG_PATH`, else `cairn.jsonl` | the append-only log |
| `--root PATH` | `.` | the bundle root that pinned verifier paths resolve against |
| `--data-dir PATH` | `$CAIRN_DATA` | where node data lives |
| `--key-file PATH` | `$CAIRN_KEY`, else `~/.cairn/key` | the at-rest key |
| `--passphrase-file PATH` | `$CAIRN_PASSPHRASE` | passphrase for a wrapped key |
| `--max-size SIZE` | no cap | cap on the data directory, e.g. `20GB`, `20GiB` |

`mcp`, `p2p` and `serve` also accept `--log`, `--root` and `--key-file` *after*
their own name. That is not a second spelling for its own sake: those three were
separate binaries, and accepting the flags in the old position means a config
stanza written for `cairn-mcp --log X` still reads after changing the binary
name.

`-h`, `--help` and `help` are the same thing, as are `-V`, `--version` and
`version`; all six exit 0. `cairn --version` also reports whether the build
embedded the reader, because that one build-time choice decides whether `run`
starts:

```console
$ cairn --version
cairn 1.3.0
  ui       not embedded -- `cairn run` refuses; build with `make ui-build`
```

## Exit codes

| code | meaning |
|---|---|
| 0 | success |
| 1 | `audit` found problems, a checkpoint did not match, or `incentives` says the mechanism does not hold |
| 2 | the network refused the submission, or the input was bad |
| 3 | `reveal` produced a verdict that settles nothing |

Code 3 is the one that matters when scripting. A **rejected** claim exits 0 —
rejection is a real answer, reached by a verifier that ran. `unavailable` and
`invalid_spec` exit 3, because nothing was learned about the artifact. A caller
that collapses those two cannot tell "we checked and it is wrong" from "we could
not check", which is the exact confusion the verdict taxonomy exists to prevent.

`arena` exits 1 while any attack in its set is still profitable, so CI can gate
on it.

---

## Reading a log

Everything here reads. None of it appends, and none of it needs a network.

### `audit [--no-rerun]`

Re-derive the entire log: the hash chain, every admission rule, and every
settled claim, by re-running each objective's pinned verifier against the
artifact it settled. `--no-rerun` skips the verifier runs and checks structure
only — much faster, and a strictly weaker statement. Exits 1 on any problem.

### `verify --from CHECKPOINT [--root-key HEX|FILE] [--audit] [--no-rerun]`

Check a signed checkpoint against this log's prefix: the height, the head, and
the Merkle root the operator signed. `--audit` also re-derives the rules over
that prefix.

**Without `--root-key` this authenticates nothing.** It checks the checkpoint
against the key inside the checkpoint, which whoever wrote the checkpoint chose.
Get the key from somewhere that is not the same server.

### `prove <seq> [--height N] [--out FILE]`

Emit a Merkle inclusion proof for one entry. `--height` proves against the log's
first N entries instead of all of them — a root is over a whole log, so a proof
from a log that grew since the reader's checkpoint was signed will not check
against it. This is how the prover meets the reader where they are.

### `check FILE (--merkle-root sha256:HEX | --from CHECKPOINT [--root-key HEX|FILE])`

Check such a proof. **Opens no log and no bundle**, which is the point: whoever
runs this has no copy of the log, which is why they were sent a proof. Spelled
`--merkle-root` and not `--root` because `--root` is the global flag naming the
bundle directory, and two meanings for one flag is how a caller silently checks
against nothing.

### `log`

Print the log, one line per entry: sequence, kind, entry hash, summary. The hash
in column three is the **entry** hash — the chain link, which covers the append
timestamp — not the record id.

### `balances`

Who holds what, what is escrowed behind a promise to pay, and what the genesis
prefix issued. Balances are typed by verifier [tier](tiers.md): a unit earned on
a certificate check cannot be spent on Lean work.

### `knowledge [<claim-id>] [--demanding] [--<weight> N]`

What the log *says* about a claim, under a confidence policy you choose. Reads
the log, writes nothing, moves no money — standing is derived, never stored. See
[knowledge.md](knowledge.md).

Policy weights: `--verified`, `--per-corroboration`, `--max-corroboration`,
`--per-refutation`, `--per-dispute`, `--superseded-weight`,
`--unreproducible-weight`, `--independence-depth`, `--decay-period`,
`--decay-retention`. `--demanding` is a preset.

### `attribute [--delta-num N] [--delta-den N] [--max-depth N] [--reserved-num N] [--reserved-den N]`

Compute citation-flow payouts over the whole log. `--reserved-*` holds that
share of delta for the citation the rules forced, as opposed to the ones a
submitter chose. See [economics.md](economics.md), and
[design/citation-flow-dilution.md](design/citation-flow-dilution.md) for the
attack this rule does not yet defend against by default.

### `canon --input FILE`

Canonicalize one JSON value and print its digest. This is how you re-pin a
verifier after editing it: the pin is part of the objective's id.

### `decode <objective|commitment|claim|peer> --record FILE`

Decode one record and report whether it is admissible, and what its id is.
Needs no log, which makes it the cheapest way to find out why something was
refused.

---

## Taking part

### `post <objective.json> [--identity FILE]`

Fund a checkable question. With `--identity`, the record is signed and the
signing key's public half *is* the funder. Prints a decomposition note when the
reward is below what the network costs to verify it — before you fund it, not
after.

### `commit <objective-id> --submitter S --artifact FILE [--nonce N] [--identity FILE]`

Bind to an artifact without revealing it. A generated nonce is used when
`--nonce` is absent; keep it, because the reveal needs it. With `--identity` the
signing key's public half replaces `--submitter`: a signed record's submitter
*is* its key, so a name you sign for cannot be claimed by anyone else.

### `reveal <objective-id> --submitter S --artifact FILE --nonce N [--cites ID ...] [--relates KIND:CLAIM-ID ...] [--identity FILE]`

Reveal a committed artifact and verify it. **Must land in a strictly later epoch
than its commitment** — that rule is what stops a submitter reading someone
else's artifact and racing it.

`--cites` is the edge that moves money. `--relates` says what you found about an
earlier claim — refutes, replicates, supersedes — and pays nobody. They are
parsed into different fields on purpose: one of them is a payment instruction.

Exits 3 on `unavailable` or `invalid_spec`; see *Exit codes*.

### `settle`

Pay out every reveal epoch that has closed and cleared the finality delay.
Ordering inside a batch comes from the epoch beacon, so nobody chooses who is
paid first.

### `try <objective-id|objective.json> (--submitter WHO | --identity FILE) --artifact FILE [--nonce N] [--cites ID ...] [--settle]`

One round end to end: post if needed, commit, wait out the epoch boundary,
reveal, and with `--settle` also settle. A wrapper over the primitives above
and nothing more — no new record kind, no change to what `commit` and `reveal`
accept. A real round waits a real epoch (600 s); `CAIRN_EPOCH_SECONDS` shortens
it for a local trial against a log used for nothing else.

### `propose <objective> --artifact F [--artifact G ...] [--submitter WHO | --identity FILE] [--cites ID ...] [--dry-run] [--settle]`

Score candidates locally against the objective's own verifier and submit only
the best one that passes. The proposer loop. `--dry-run` scores and reports and
submits nothing — and is the one mode that needs no `--submitter` or
`--identity`, because nothing is going to be signed.

### `scaffold <name> --kind <certificate|evaluator|statistical|replay|lean> [--out DIR] [--artifact-example FILE] [--reward N] [--funder WHO] [--goal LABEL] [--statement TEXT] [--force]`

Write the files a new objective starts from, and post nothing. The posting stays
a separate, reviewed step: an objective's statement is untrusted text that a
person decides to fund after reading it.

`--out` must resolve inside `--root`. A pinned verifier is resolved against the
bundle root, so a path outside it resolves for nobody else. `--force` overwrites
existing files, and is off by default because the obvious mistake is scaffolding
over an objective already posted — whose pin is in the log and whose id covers
it.

### `identity --out FILE`

Create a submitter identity: an ed25519 keypair whose public half **is** the
submitter name. Refuses to overwrite an existing file. There is no recovery —
losing the file loses the name.

### `issue --holder NAME --units N`

Declare units into the log's supply. Genesis prefix only: a supply is authorised
by its *position* in the log, not by a key, because nothing else has been
written yet and a signature would only say who opened the log.

---

## Running a node

### `run [options]`

The complete local node in one process: MCP over stdio, P2P sync, the HTTP API,
a submission queue, and the embedded reader, against one exclusive log.
**Requires the `ui` feature** (`make ui-build`); a plain `cargo build` produces
a binary that says so rather than starting without the reader.

| flag | default |
|---|---|
| `--listen ADDR` | `127.0.0.1:9000` (P2P) |
| `--serve ADDR` (alias `--http`) | `127.0.0.1:8080` (HTTP + `/ui/`) |
| `--identity FILE` | `<data>/node.identity.json` |
| `--root-key FILE` | `<data>/root.key` |
| `--checkpoint FILE` | `<data>/checkpoint.json` |
| `--queue DIR` | `<data>/queue` |
| `--no-queue` | accept no submissions over HTTP |
| `--mcp-identity FILE` | unsigned MCP submissions |
| `--no-mcp` | when stdin belongs to something else, such as a service manager |
| `--bootstrap FILE` | repeatable dial hint |
| `--population FILE` | gossip population file |
| `--fanout N` | 3 |
| `--max-queue N` | 4096 |

The data directory is `--data-dir`, else `$CAIRN_DATA`, else `.local`. Closing
MCP stdin stops the node; an interactive operator stops it with Ctrl-C.

### `p2p --identity FILE --root-key FILE --checkpoint FILE --listen ADDR [options]`

The daemon alone: P2P sync, no reader, no MCP. `--serve ADDR` also publishes
over HTTP from the same process, which is what lets it admit what it queues — a
log has one writer.

Also takes `--bootstrap FILE` (repeatable), `--population FILE`, `--queue DIR`,
`--fanout N`, `--max-queue N`, `--key-file FILE`, and `--proxy URL` to route
every dial through a SOCKS5 proxy (a Tor client or obfs4 bridge).

### `serve [--listen ADDR] [--queue DIR] [--max-queue N] [--checkpoint FILE] [--key-file FILE]`

Publish a log over HTTP. Default `127.0.0.1:8080`. Without `--p2p-listen` this
is a **publisher**: it takes no lock, holds no rules engine, and re-reads the
log per request, so it is safe to point at a log another process is writing.
What it cannot do is admit anything — submissions queue, and `cairn drain`
or a daemon admits them.

With `--p2p-listen ADDR` (plus `--identity`, `--root-key` and `--checkpoint`) it
is the whole node instead, the same `daemon::run` that `p2p` and `run` use. The
publisher refuses `--identity`, `--root-key`, `--population`, `--fanout` and
`--bootstrap` rather than ignoring them: every one of those is somebody trying
to run a node, and silently dropping them would dial nobody and drain nothing
while looking started.

Endpoints are in [serving.md](serving.md).

### `mcp [--identity FILE] [--log FILE] [--root DIR]`

The standalone MCP server over stdio, on a log of its own. For an agent that
should work on a log deliberately offline from the network; `cairn run` serves
the same protocol from the daemon's process. Tools are listed in
[agents.md](agents.md).

### `drain --queue DIR [--dry-run]`

Admit records a server queued, re-checking every rule against the whole log.
Separate from the server on purpose: the server is a transport, this is the
rules engine. A queued record has been parsed and schema-checked and *nothing
else*.

### `checkpoint --root-key FILE [--out FILE]`

Sign the log's current height, head and Merkle root, so a reader can pin what
this operator claimed at a point in time. The counterpart to `verify --from`.

### `peer --identity FILE --transport PEER-ID --addr HOST:PORT [--seq N]`

Announce where your identity answers, or move it. Obtaining the log is then
obtaining the address book, so discovery needs no second file. Omitting `--seq`
means "one past whatever this identity has already said".

### `gen-bootstrap --addr HOST:PORT --out FILE [--identity-out FILE]`

Write a placeholder `--bootstrap` file with a freshly generated key standing in
until you have the peer's real public key. The address is only ever a hint — the
handshake authenticates the *key*, not the socket that answered — so this cannot
make a remote peer trustworthy. The daemon keeps warning while the placeholder
key is still in the file, and the warning clears itself when the real key is
pasted in.

### `seeds resolve --list FILE [--keys DIR] --out DIR`

Check a downloaded seed list against its key files and write a `--bootstrap`
file for every entry that verifies. Entries that do not verify are **refused**,
not skipped.

### `seeds publish --identity FILE --out DIR`

Write this node's own `<transport>.key`, to be added to a published list by
pull request.

The list itself is fetched by `./scripts/seeds-fetch.sh`, not by this binary:
`tests/cipher_policy.rs` fails the build if a TLS crate enters the tree, and an
HTTP client is how one arrives. Same split as the drand beacon — the binary
checks what it is handed, and downloading is somebody else's job.

### `beacon --orders EPOCH (--drand-signature HEX | --value HEX [--source NAME] [--block N]) [--delay N]`

Record the randomness an epoch's settlement is ordered against. **Must be drawn
in the epoch it orders**: earlier and a committer can grind against a value they
already hold, later and you are picking who gets paid first.

`--drand-signature` narrows "responsible for the value" to one thing — the chain
is pinned and the round is a function of the epoch, so a wrong signature is
falsifiable by anyone holding 96 bytes of public key. `--delay N` computes the
value as a verifiable delay of N sequential squarings instead of taking it from
the caller.

### `drand-round [--orders EPOCH]`

Which drand round an epoch settles against, and when it publishes. A query, so
it is not a mode of `beacon` that appends nothing.

### `drand-verify --round N --signature HEX`

Check a quicknet signature against the pinned key, and nothing else. Exit 0 for
verified, 1 for anything else, so a shell can branch on it.

---

## Bonded mechanisms

These four are what make a verdict cost something to get wrong. See
[bonded-verification.md](bonded-verification.md) and
[fraud-proofs.md](fraud-proofs.md).

### `attest stand --claim ID --status accept|reject --identity FILE`

Stand behind a verdict under bond. Nothing is checked here — the expensive
question is asked once, by whoever brings evidence.

### `attest slash (--attestation ID | --docket FILE) --catcher NAME`

Take the bond of somebody who stood behind a verdict the pinned verifier
contradicts. Exactly one of `--attestation` or `--docket`. A verifier that
cannot run takes nothing.

### `attest list`

Who has stood behind what, and whose bond is still live. The default action when
`attest` is given no verb.

### `canary mint --objective ID --from FILE [--count N] [--valid-share N/D] [--budget N] [--out FILE]`

Mutate a real artifact until the objective's own verifier lands on the wanted
side, producing submissions whose verdict is already known. Costs verifier runs
once, so that checking is free forever after.

### `canary check --docket FILE`

Compare a docket against every verdict the log recorded. Runs no verifier at
all; exits non-zero if a node said something it cannot mean.

### `availability undertake --identity FILE --bond N`

Promise to hold the log, under bond.

### `availability answer --identity FILE [--epoch N]`

Answer this epoch's availability sample.

### `availability fund --funder NAME --per-epoch N --from-epoch N --to-epoch N`

Fund the pool that pays holders over a span of epochs.

### `availability settle [--epoch N]` · `availability status`

Pay the epoch's answerers; report the undertakings, the pool and what is owed.
`status` is the default action.

### `dispute trace --objective ID --from FILE --out FILE [--steps N]`

Produce the committed execution trace a dispute is played over.

### `dispute open --claim ID --trace FILE --identity FILE [--bond N]`

Open a dispute against a claim, under bond.

### `dispute play --id ID --trace FILE --identity FILE`

Play one round of the bisection.

### `dispute settle --id ID` · `dispute status [--id ID]`

Execute the single disputed step and settle it; report open disputes.

---

## Storage and content

### `keygen [--passphrase]`

Create the at-rest key that seals the local store. `--passphrase` wraps it.

### `store status`

Where the store is, whether the log is sealed, which key is in use, and how much
space is used, pinned and reclaimable. The default action.

### `store gc` · `store encrypt` · `store rekey [--new-passphrase-file PATH]` · `store export --out FILE`

Reclaim space; seal an existing plaintext log; re-seal under a fresh key (the
old key is kept at `<key>.previous`, because older copies are still sealed under
it); write a plaintext copy for someone else to audit.

### `sync <dir> [--prune] [--dry-run]`

Copy the store to a directory of your choosing, still encrypted. Refuses to copy
the key file — a key beside its ciphertext looks fine right up until the
directory is synced somewhere else, and then it was never encryption at all.

### `blob [ls|need|publish|gc]`

The content-addressed store of pinned verifier code. `ls` (the default) lists
what is held; `need` lists the pins this node cannot obtain, which is why a
verdict came back `unavailable`; `publish` copies every pinned file the bundle
has into the store so peers can fetch it; `gc` drops blobs no objective pins.

Collection is a command rather than something a sync round does on its way past:
a node cannot distinguish a blob nobody wants from a blob pinned by an objective
it has not synced yet, so a timer-driven collector would delete exactly the code
its peers are about to ask for.

### `blob serve --identity FILE [--listen ADDR]` · `blob fetch --identity FILE --peer FILE [--peer FILE ...] [--timeout N]`

Seed this node's blobs to strangers over the encrypted transport, and fetch
every pin this log names and this node lacks. `--peer` takes the `{addr,
public}` file that `blob serve` printed.

### `shard plan <file> [--data K] [--parity M] [--chunk N]`

How a file *would* be erasure-coded and what it would cost on disk. Writes
nothing. A separate action rather than a `--dry-run`, because the question is
asked before the decision rather than instead of it — a coding is not something
you change your mind about cheaply once shards are spread across machines.

Defaults are `--data 4 --parity 2`: 1.5× on disk for two tolerated losses,
against 3× for the replication that buys the same. `--chunk` is derived from the
file's size when not given.

### `shard encode <file> [--data K] [--parity M] [--chunk N] [--keep 1,4]`

Cut a file into shards and keep the ones this node holds. Any K of the K+M
rebuild the file. `--keep` is how a holder says which slice is theirs — a node
that keeps all of them has bought the coding's overhead and none of its point.

### `shard ls [<address>]` · `shard prove <address> --shard I [--chunk C] [--out FILE]` · `shard check FILE --merkle-root sha256:HEX` · `shard reconstruct <address> --out FILE` · `shard rm <address>`

What is held; a proof that one chunk of one held shard is under the manifest
root; the check for such a proof (needs no store and no log); a rebuild from
whatever is held, naming a corrupt shard rather than using it; and a removal of
every shard of one blob.

---

## Analysis

Neither of these reads a log. They answer questions about the *rules*.

### `incentives [parameters]`

Evaluate the node-operator game at one parameter set. About 2 s. Exits non-zero
when the mechanism does not hold.

Parameters: `--nodes`, `--settled`, `--stake`, `--fee`, `--canary-rate`,
`--canary-leak`, `--catch-bounty`, `--slash-rate`, `--audit-rate`,
`--detection-rate`, `--fraud-rate`, `--verify-cost`, `--operating-cost`,
`--storage-cost`, `--per-node-rewards`, `--advance-rate`, `--committee`,
`--threshold`, `--sealed-value`, `--commons-value`.

`--robustness` also reports how far each parameter can move before the mechanism
breaks: seventeen parameters walked out along a twelve-rung ladder in both
directions, the whole mechanism re-evaluated at every rung. Opt-in because it is
hundreds of solver runs — about a minute and a half on an Apple M4 Pro.

### `incentives --sweep NAME=LO..HI[:STEPS] [--sweep ...] [--out FILE] [--format csv|jsonl]`

The same game across a grid, one row per point, so a threshold is visible
without comparing a hundred prose reports by eye. Repeatable:
`--sweep canary-rate=1/20..1/5:5 --sweep stake=1000..10000:4`.

### `incentives --market [--agents N] [--candidate-value N] [--exclusion N/D] [--buyer-share N/D]`

The agent-to-agent market sub-game instead: does a price for sub-frontier
candidates destroy the gossip population that feeds the search? Exits non-zero
when universal gossip is not a strict equilibrium. See
[agent-market.md](agent-market.md).

### `arena [--seed N]`

Play the attack strategies for money against the real rules engine. Every number
it prints except the modelled costs is read out of balances a real node settled.
Exits 1 while any attack in the set is still profitable, so CI can gate on it.
Takes seconds to minutes. See [arena.md](arena.md).
