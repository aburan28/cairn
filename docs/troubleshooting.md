# Troubleshooting

Most of what looks broken here is designed-in, and the designed-in cases have
sharp answers. This page is ordered by what you were doing when it happened.
Where a message is quoted, it is the message the code actually prints.

If your problem is not here and is about canonical encoding, record identity,
settlement order, or the verifier sandbox, treat it as security-relevant and use
[SECURITY.md](../SECURITY.md) rather than a public issue.

## The audit passed and it should not have

> ```
> entries 0   head -
> merkle  -
>
> log verified: chain intact, every settled claim re-verified
> ```

**A log that does not exist opens as an empty log, and an empty log audits
clean.** Nothing is wrong with the audit; you pointed it at the wrong file.
`entries 0` is the tell — check it before believing any clean result.

The classic way to arrive here is the deprecated `CAIRN_LOG` variable, which
used to mean the ledger *path* to the CLI and the stderr *level* to the daemons.
`CAIRN_LOG=debug cairn audit` audited a file named `debug`. The CLI now refuses
that rather than guessing; see [configuration.md](configuration.md). Use
`CAIRN_LOG_PATH` for the path and `CAIRN_LOG_LEVEL` for the level.

## `cairn run` will not start

> `run requires the embedded UI; build with `make ui-build` or `cargo build
> --release --features ui`, then run the resulting binary`

`run` serves the reader at `/ui/` out of the binary, so the reader has to be
compiled in. A plain `cargo build` gives you every other subcommand and a `run`
that refuses. `cairn --version` says which build you have:

```console
$ cairn --version
cairn 1.2.0
  ui       not embedded -- `cairn run` refuses; build with `make ui-build`
```

Published release tarballs are built with the feature on, so this only bites
from a source checkout.

## `another process is already writing …`

> `another process is already writing cairn.jsonl. Two writers fork a
> hash-linked log -- both would append entries claiming the same predecessor.
> Stop the other process, or give this one its own --log`

A log has exactly one writer, and the lock is the enforcement. The usual cause
is a daemon (`cairn run` or `cairn p2p`) already holding it. Readers are not
locked out — `cairn log`, `cairn audit` and `cairn serve` without `--p2p-listen`
all work against a log something else is writing.

Running several MCP clients at once hits this too: each client needs its own
`--log`. [agents.md](agents.md) has the arrangement.

## `… is sealed and no --key-file was given`

The CLI seals every log it creates whenever a key file exists, so a log made on
a machine that has run `cairn keygen` is ciphertext. Name the key with
`--key-file` or `$CAIRN_KEY`.

Related, and much more alarming than it deserves to be:

> `line 4 did not authenticate: wrong key, or the log has been altered,
> reordered, or spliced`

**The first clause is almost always the true one.** The decoder cannot tell a
missing key from a wrong one from real tampering, so it names all three. Check
which key sealed the log before concluding anything about the log. `cairn store
status` reports the key in use and whether the log is sealed.

The mirror image:

> `line 1 is not encrypted, but a key was supplied; this log is in plaintext --
> open it without a key, or run `cairn store encrypt` to convert it`

## A submission never appears in the log

Expected, if you submitted over HTTP to a plain `cairn serve`. A submission
lands in a spool directory and is **never appended by the server** — the
operator's own node admits it, re-checking every rule against the whole log. A
publisher holds no write lock, so it could not append even if it wanted to.

Two ways to get them admitted:

- run the node and the server in one process (`cairn run`, `cairn p2p --serve`,
  or `cairn serve --p2p-listen`), which drains the queue it fills every round;
- or drain by hand: `cairn drain --queue ./queue` (add `--dry-run` first to see
  what would be admitted).

If `POST /submit` is refused outright, check which refusal it is: **405** means
the server was started without `--queue` and is read-only by design; a rejection
past `--max-queue` (4096 undrained records by default) means the spool is full
and nothing is draining it. `GET /` says which of the two a node is, before you
post anything.

## `cairn serve: --identity has no effect without --p2p-listen`

Refused rather than ignored. Every one of `--identity`, `--root-key`,
`--population`, `--fanout` and `--bootstrap` is somebody trying to run a node; a
publisher that quietly dropped them would dial nobody and drain nothing while
looking like it had started. Add `--p2p-listen`, or drop the flags.

## It is just sitting there waiting for an epoch

> `waiting for epoch 1789143089 to start; epochs are 600s here, so this takes up
> to 600s`

Working as designed. A reveal must land in a **strictly later** epoch than the
commitment it opens — that rule is what stops somebody reading your artifact and
racing it — so a round genuinely cannot complete inside one epoch.

For a local trial, `CAIRN_EPOCH_SECONDS=1` against a log used for nothing else.
Never on a node that talks to other nodes: two nodes with different epoch
lengths disagree about which epoch a record is in, which is a fork, and nothing
in the log will tell you it happened.

## The claim was accepted but `settled` is false

`settled: false` on an accepted claim means **not yet**, never *rejected*.
Settlement waits for the reveal epoch to close *and* clear the finality delay,
and the order inside the batch comes from the epoch beacon so that nobody — the
operator included — picks who is paid first.

Whichever call touches the log next materialises the settlement, so polling
`frontier_status` (or running any command) is enough to be paid. `cairn settle`
forces the pass.

## The verdict is `unavailable`

`unavailable` blames **this node**, not the artifact: no toolchain, a missing
file, a crash, a timeout, unparseable output. Nothing was learned about the
artifact, nothing settles, and the objective stays open for a node that can
actually run the check. In a script, that is exit code 3, and it is deliberately
distinguishable from a `reject` (exit 0).

Work through, in order:

1. `cairn blob need` — the pins this node cannot obtain. If the verifier code is
   not here, nothing can run it. `cairn blob publish` copies pins the bundle
   has into the store; `cairn blob fetch --identity … --peer …` gets the rest
   from a peer that is serving them.
2. The toolchain the verifier needs — `python3`, `lean` — on `PATH`.
3. The sandbox. With `CAIRN_REQUIRE_SANDBOX=1` set and no jail mechanism
   installed, *every* verdict is `unavailable` by design. That is the switch
   working: install bubblewrap (Linux) or run on macOS, which has seatbelt.
4. `CAIRN_SANDBOX_MEMORY_MB` — a heavy verifier killed at the 4096 MiB cap
   reports `unavailable` on a node whose peers, with a larger cap, accept.

## The verdict is `invalid_spec`

This one blames the **objective**: a tampered pin, a non-integer threshold, a
field that cannot be compared reproducibly. It is not your artifact.

The objective needs fixing — and because the verifier is part of the objective's
identity, fixing it means posting a *different* objective. There is no editing a
posted one. `cairn decode objective --record file.json` tells you whether a draft
is admissible before you spend anything on it.

## A checker I edited stopped matching

The verifier is pinned by content hash and the pin is part of the objective's
id. Editing a checker after posting means the log names bytes you no longer
have. Re-pin with `cairn canon --input <file>` and post the corrected objective
as a new one — `scaffold` prints this warning for the same reason.

## `scaffold: "…" escapes the bundle root`

`--out` must resolve inside `--root`. A pinned path is resolved against the
bundle root by everyone who checks the objective, so a path outside it resolves
for you and for nobody else. The CLI refuses instead of letting you post a
bounty no one else can check.

## The HTTP server answered 503

> `too many connections, try again`

64 concurrent connections is the cap, and the server answers rather than
dropping — a silent close is indistinguishable from a broken server. Requests
also time out at 15 seconds.

## Peers never connect

- `--bootstrap` is a *hint*. The handshake authenticates the **key**, not the
  socket that answered, so a bootstrap file with a placeholder key cannot
  connect to a real peer. `gen-bootstrap` writes exactly such a placeholder and
  the daemon keeps warning while it is still in the file; the warning clears
  itself when the real public key is pasted in.
- The defaults bind loopback (`127.0.0.1:9000`). A node meant to be reachable
  needs `--listen 0.0.0.0:9000` and a path through whatever is in front of it.
- LAN discovery uses a multicast beacon on port 47396, which many networks drop.
  `CAIRN_BEACON_PORT=off` disables it if it is noisy.
- Behind a censor, `cairn p2p --proxy socks5://127.0.0.1:9050` routes dials
  through Tor or an obfs4 bridge. [censorship.md](censorship.md) says what that
  hides and what it does not.

## `incentives` or `arena` exited non-zero

That is the answer, not a crash. `incentives` exits 1 when the mechanism does
not hold at the parameters you gave it; `arena` exits 1 while any attack in its
set is still profitable. Both are meant to be gated on in CI.

## No release PR ever appears

Releases are cut by release-please from conventional commits. When no PR shows
up, the cause is almost always the repository switch that forbids Actions from
opening pull requests — separate from the workflow's own `permissions:` block:

> Settings → Actions → General → Workflow permissions →
> **Allow GitHub Actions to create and approve pull requests**

The run fails *after* committing the version bump, so the branch
`release-please--branches--main--components--cairn` sits there looking correct
while no PR exists. Nothing is lost: enable the setting and the next push to
`main` opens the PR from the branch that is already there.

Also worth knowing: a subject line with no recognised type (`feat:`, `fix:`,
`docs:`, …) is **not an error and not a release**. It ships to `main`, does not
appear in the changelog, and does not move the version. See
[CONTRIBUTING.md](../CONTRIBUTING.md).

## Still stuck

- `cairn --version` and `cairn store status` are the two commands worth pasting
  into any report.
- `CAIRN_LOG_LEVEL=debug` turns up the daemons. Output is stderr only, always,
  because stdout belongs to MCP's JSON-RPC.
- `cairn decode <kind> --record <file>` answers "is this record admissible, and
  what is its id" without a log.
- If two implementations disagree about a record, that is a consensus split and
  the repository has an issue template for exactly that:
  [interop_disagreement](../.github/ISSUE_TEMPLATE/interop_disagreement.md).
