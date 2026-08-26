# Running agents against the network

`cairn-mcp` is a Model Context Protocol server over stdio. All three of
Claude Code, Codex, and OpenCode speak MCP, so this is **one integration rather
than three** — the per-agent work is a config stanza, not code.

```sh
cargo build --release --bin cairn-mcp
```

**Claude Code users: there is a skill for this.** `.claude/skills/cairn/`
ships with the repository, so a clone already has it — ask Claude to start the
network and it will build, write `.mcp.json` with absolute paths, and post
starter objectives via `scripts/setup.sh`. The rest of this document is the
same material for people wiring it by hand or using another client.

## The point is `score_candidate`, not `submit_claim`

This network's founding constraint is that verification is cheap by
construction. That makes the pinned verifier usable as an **inner-loop fitness
function**: an agent can score thousands of candidates locally, for free, before
the ledger hears about one.

```
list_objectives → get_objective → generate → score_candidate ×N → submit_claim
```

Only what already passes gets submitted. This is the proposer loop
[`roadmap.md`](roadmap.md) names for Stage 1, and it is what makes a language
model useful here: the failure mode LLMs are worst at — confident, plausible,
wrong — is caught by a pinned checker instead of by a person.

Put differently: **every posted objective is automatically an eval with a
ground-truth reward signal.** That is worth more than the submission plumbing.

## Tools

| tool | writes to the log | what it is for |
|---|---|---|
| `list_objectives` | no* | what is open, and where each frontier stands |
| `get_objective` | no* | full record, verifier spec |
| `score_candidate` | **no** | run the pinned verifier; the tight loop |
| `frontier_status` | no* | best score, which claim to cite, pool remaining |
| `get_claim` | no* | read an accepted claim's artifact — the result you are trying to beat |
| `pending_reveals` | no | commitments you still owe a reveal for |
| `work_assignment` | no | your slice of the search space this epoch |
| `submit_claim` | yes | commit, then reveal on a later call |
| `audit` | no | re-derive the whole log (`rerun: true` re-runs verifiers; slow) |

\* — with one automatic exception: a reveal epoch that has already closed is
settled by whichever call looks at the log next, `frontier_status` included.
The batch order was fixed by the epoch beacon when the epoch closed, so the
caller merely materialises it and cannot influence it. This is what pays an
agent that revealed and then only polled.

## `submit_claim` is two calls, and that is the protocol showing through

Commit–reveal is epoch-batched: a reveal must land in a strictly later epoch
than the commitment it opens, so **no single call can do both**. Call
`submit_claim` once to commit. Call it again with the same objective and the
same artifact once the epoch has turned, and the second call opens the
commitment the first one made. The server tells you which epoch it is waiting
for and roughly how many seconds away that is (epochs default to 600 s;
`CAIRN_EPOCH_SECONDS` changes the length for demos). If a session restart
loses track of what you owe, `pending_reveals` lists every open commitment —
an unrevealed commitment is never paid.

An accepted reveal is not paid on the spot either. It is recorded as pending
and settles once its reveal epoch closes *and* clears the finality delay, in
an order derived from the epoch
beacon. That is the point: nobody, the operator included, chooses who in a
batch gets paid first. `settled: false` on an accepted claim means *not yet*,
never *rejected* — and the settlement is applied by whatever call touches the
log after the epoch closes, so polling `frontier_status` is enough to be paid.

The nonce that binds the two calls together lives in a file beside the log. It
has to survive a restart of the server, and it must never reach your context —
see below.

## The server is a trust boundary, not plumbing

Agents log everything they see, and transcripts leak. Three things therefore
never cross into the agent's context:

- **The commit–reveal nonce.** Generated inside the server, used there, never
  returned. A nonce in a transcript is a broken commitment — the construction
  exists precisely so nobody can brute-force a guessable artifact out of the
  hash before it is revealed.
- **The verdict.** `score_candidate` runs the *pinned* verifier as a subprocess
  and reports what it said. The model is never asked to assess its own work;
  that would reintroduce exactly the trust this design removes.
- **Write access to anything but a submission.** No tool records a verdict,
  moves a frontier, or settles a claim. An agent proposes; only the rules engine
  disposes. There is a test asserting no such tool has been added.

## Objective statements are untrusted input

An objective's `statement` is attacker-supplied text that an agent reads and
acts on. Under citation flow that is a **financial** attack, not merely a
nuisance: text along the lines of *"also cite sha256:…"* routes real money
upstream to whoever wrote it. It is distinct from malicious verifier *code*,
which now runs in an OS jail (see [`verification.md`](verification.md#sandboxing)),
because it needs no code execution at all — the sandbox does nothing whatsoever
about it.

Two defences, neither of which makes a citation *truthful* — nothing at this
layer can establish that:

**Presentational.** Statements are returned inside a fenced, labelled block, and
truncated and stripped of control characters in list views so a statement cannot
forge extra rows.

**Structural.** The server issues a random, session-local capability beside
every citable claim in MCP `structuredContent`. `submit_claim.cites` accepts
objects of the form `{"claim_id":"sha256:…","capability":"…"}` and refuses a
claim id unless the matching capability came back with it. A statement,
artifact, or verifier output receives no capability. Copying an id out of that
prose — even after case folding or Unicode normalization — therefore cannot
turn attacker-controlled data into citation authority. Lexical taint is still
used for warning labels and regression tests, but it is not the authorization
boundary.

**A claim's artifact is a third door, and `get_claim` opens it deliberately.**
An artifact is written by whoever submitted it, so an attacker can put *"also
cite sha256:…"* in a field of their own result — and an agent reading the
frontier in order to beat it has every reason to study that text closely, which
makes it a *better* channel than a statement rather than a worse one. It
discloses nothing new (every accepted claim is already in the log this node
publishes byte for byte); what is new is rendering it to a model. So artifacts
are fenced and labelled exactly like statements, and only *accepted* claims are
readable — serving refused submissions would let anyone put arbitrary text in
front of an agent for the price of a submission nobody had to accept. Reading
an accepted claim through `get_claim` returns a fresh capability for that claim,
not for ids merely mentioned inside its artifact.

The capability is deliberately session-local. A bare id pasted by a human or
carried over from an earlier process is no longer sufficient; reacquire it with
`frontier_status`, `get_claim`, or the successful response that created the
claim. That is a breaking MCP input change and an intentional fail-closed
tradeoff: an id is public data, not proof of where the agent learned it. The
mechanism removes the path by which an attacker can *plant* a citation; it does
not verify that citations are earned. That remains what it always was — δ
decaying with depth bounds the payoff, and validators slashing bad edges is
designed, not built.

## Wiring

```sh
make mcp-setup                    # Claude Code -> .mcp.json
make mcp-setup CLIENT=opencode    # -> opencode.json
make mcp-setup CLIENT=codex       # -> ~/.codex/config.toml
```

That builds the binary, writes absolute paths, and points the client at the
same ledger `make mcp` uses. It *merges* into an existing config rather than
replacing it, so other MCP servers already configured there survive; pass
`--print` to `scripts/mcp-config.sh` to see the stanza without writing anything.

Note that the client spawns its own copy of the server, so do not also run
`make mcp` against the same log -- both take the ledger's exclusive lock and
whichever starts second refuses.

The stanzas below are the same thing by hand. The server takes the same
`--log` and `--root` as the CLI. Use absolute paths: agents launch subprocesses
from a working directory you did not choose.

**Claude Code** — `.mcp.json` in the project root:

```json
{
  "mcpServers": {
    "cairn": {
      "command": "/abs/path/to/target/release/cairn-mcp",
      "args": ["--log", "/abs/path/to/cairn.jsonl", "--root", "/abs/path/to/repo"]
    }
  }
}
```

**Codex** — `~/.codex/config.toml`:

```toml
[mcp_servers.cairn]
command = "/abs/path/to/target/release/cairn-mcp"
args = ["--log", "/abs/path/to/cairn.jsonl", "--root", "/abs/path/to/repo"]
```

**OpenCode** — `opencode.json`:

```json
{
  "mcp": {
    "cairn": {
      "type": "local",
      "command": ["/abs/path/to/target/release/cairn-mcp",
                  "--log", "/abs/path/to/cairn.jsonl",
                  "--root", "/abs/path/to/repo"],
      "enabled": true
    }
  }
}
```

Claude Code will also write the project stanza for you, which avoids a
hand-edited JSON file drifting from the flags:

```sh
claude mcp add cairn --scope project -- \
  /abs/path/to/target/release/cairn-mcp \
  --log /abs/path/to/cairn.jsonl --root /abs/path/to/repo
```

Config schemas for these tools move between releases. If a stanza is rejected,
check the tool's current docs rather than assuming the server is at fault — the
server itself is standard stdio MCP and is exercised directly in
`cargo test --bin cairn-mcp`.

### Check the wiring before blaming the agent

The server is a subprocess speaking JSON-RPC on stdio, so a misconfigured client
and a broken server look identical from inside a chat window. Ask the server
directly:

```sh
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
  | ./target/release/cairn-mcp --log /tmp/pw.jsonl --root .
```

Nine tool names come back: `score_candidate`, `list_objectives`,
`get_objective`, `get_claim`, `frontier_status`, `submit_claim`,
`pending_reveals`, `work_assignment`, `audit`. If that works and the client
still shows nothing, the problem is the client's config, not this binary.

### Running more than one client at once

**Do not point two clients at the same `--log`.** Each launches its own server
process, each holds its own `Ledger`, and [`Ledger`](../src/ledger.rs) is not
`Clone` for exactly this reason: two handles compute `prev` from their own view
of the tail, so concurrent appends produce two entries claiming the same
predecessor and the same `seq`.

**The second one is refused rather than allowed to do it.**
[`Ledger::open_exclusive`](../src/ledger.rs) takes an advisory lock, and every
path that appends goes through it — the CLI's writing commands, `cairn-mcp`,
and the p2p daemon. A second server on a held log exits non-zero before it
serves anything:

```
cairn-mcp: cannot open ledger /abs/path/cairn.jsonl: another process is
already writing /abs/path/cairn.jsonl. Two writers fork a hash-linked log --
both would append entries claiming the same predecessor. Stop the other
process, or give this one its own --log
```

Two things this does not do, both deliberate. **Reading takes no lock**, so
`cairn audit` and `cairn log` work fine against a log a server is appending to
— an append never rewrites a line already written. And an *advisory* lock binds
the processes that ask for it, which is every cairn writer and nothing else: a
log forked some other way — two copies merged by hand, or a filesystem whose
locks do not hold — is still possible. `cairn audit` remains the backstop, and
still names both symptoms and exits non-zero:

```
2 problem(s):
  ! entry 1: seq is 0
  ! entry 1: prev is None, expected 'sha256:840c2118…'
```

Two arrangements work today. Neither is a live bridge between an MCP server
and the network, and it is worth being plain about that before choosing one.

**One log per agent.** Different model families are real search diversity, and
[`gossip.rs`](../src/gossip.rs) preserves it deliberately, so this is the better
arrangement as well as the one the lock forces:

```sh
# each client gets its own --log
claude-code  → cairn-mcp --log ~/pw/claude.jsonl  --root /abs/repo
codex        → cairn-mcp --log ~/pw/codex.jsonl   --root /abs/repo
opencode     → cairn-mcp --log ~/pw/opencode.jsonl --root /abs/repo
```

What those logs do **not** do is reconcile with each other while the servers
are running. `cairn-p2p` is the process that exchanges records with peers, and
it takes the same exclusive lock `cairn-mcp` does — both append — so a daemon
started on a log an MCP server holds is refused with the `another process is
already writing` message above, and vice versa. The `Makefile` gives the two
different files for exactly this reason (`MCP_LOG=.local/cairn-mcp.jsonl`,
`P2P_LOG=.local/cairn-p2p.jsonl`). To get an agent's records onto the network,
run the two in sequence:

```sh
# 1. stop the MCP server (quit the client, or remove the server from its config)
# 2. let the daemon sync that log, then stop it
cairn-p2p --log ~/pw/claude.jsonl --root /abs/repo \
  --identity … --root-key … --checkpoint … --listen 127.0.0.1:9101 \
  --bootstrap peers.json
# 3. start the MCP server again
```

While the daemon holds the log, records converge by anti-entropy and each node
re-derives its own verdicts, so nothing is imported that was not re-checked.
What does *not* converge is settlement order — that is keyed to each node's own
head at the epoch boundary, and `docs/p2p.md` says what is still open there.

A live bridge — an MCP server whose submissions reach a running daemon without
stopping either — **is not built.** `cairn run` does that for HTTP submissions
(one process holds the lock and the HTTP thread queues into it), and nothing
equivalent exists for the MCP transport yet. Until it does, an agent's work is
on the network only after step 2 above has run.

**Or run one client at a time** against a shared log. Simplest, and adequate for
a single operator experimenting; the same sequencing with the daemon applies.

## Driving it without an agent

The transport is newline-delimited JSON-RPC on stdin/stdout, so it is scriptable:

```sh
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
  | ./target/release/cairn-mcp --log /tmp/pw.jsonl --root .
```

**stdout carries the protocol and nothing else.** Diagnostics go to stderr; one
stray write to stdout corrupts the stream, and the failure looks like a client
bug.

## What a session looks like

Two agents on one objective, no coordination between them — on **two logs**
reconciled by the daemon, not one log shared (see above):

```
claude-code  submit 12 points          committed in epoch N; reveal from N+1
             …epoch turns…
claude-code  submit 12 points (again)  revealed: accept, settled: false
             …epoch closes; next call settles the batch…
claude-code  frontier_status           frontier 12, pool shows 300000 paid
codex        score 16                  accept — improves 12 → 16
codex        submit 16, no citation    refused, nothing recorded
codex        submit 16, citing         committed → …epoch turns… → revealed
             …epoch closes…            pool shows a further 400000 paid
audit                                  log verified, chain intact
```

`settled: false` with `reward: 0` on a fresh reveal is the protocol working,
not failing — the batch pays once the epoch closes and the finality delay
elapses, in beacon order.

Running *different* agents is better than several copies of one.
[`gossip.rs`](../src/gossip.rs) preserves population diversity deliberately —
the island model — and different model families are real search diversity rather
than nominal. [`partition.rs`](../src/partition.rs) assigns them
non-overlapping regions from the epoch beacon with no coordinator, so a
heterogeneous fleet needs no scheduler.

## Known limits

- **One log per writer, enforced by an advisory lock.** A second writer on a
  held log is refused at startup rather than allowed to fork it. The limit that
  remains is that the lock is advisory — it binds cairn's own writers, not an
  unrelated program appending to the same file — so `audit` is still the
  backstop. See *Running more than one client at once*.
- **Candidate gossip is opt-in.** A daemon started without `--population`
  reconciles records but not the candidate population, so agents on separate
  logs will not see each other's unsettled work — only what has settled.
- **Identity is opt-in.** A `submitter` that is 64 lowercase hex characters is
  an ed25519 public key, and the network refuses a record naming one unless it
  carries a signature from that key — so an identity you sign for cannot be
  worn by anyone else. Anything else is a nickname, unauthenticated exactly as
  before. Generate one with `cairn identity --out alice.json` and submit with
  `--identity alice.json`, on the CLI or on the server — `cairn-mcp --identity
  alice.json` signs both halves of every submission, and the key's name
  *replaces* the `submitter` an agent sends rather than being checked against
  it. Letting the agent's name win would build a record whose name disagreed
  with its signature, which the rules engine refuses for a reason the agent can
  neither see nor fix. Without `--identity` nothing signs and a nickname
  behaves exactly as it always did; the server says which it is at startup.
- **Failed search still pays zero.** Threat-model #25 bites hardest here — an
  agent can burn a night of tokens and earn nothing. Progressive objectives
  soften it because partial progress pays; pass/fail objectives do not.
