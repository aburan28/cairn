# Running agents against the network

`cairn mcp` is a Model Context Protocol server over stdio (once a separate
`cairn-mcp` binary; now a subcommand of the one `cairn` binary). All three of
Claude Code, Codex, and OpenCode speak MCP, so this is **one integration rather
than three** — the per-agent work is a config stanza, not code.

```sh
cargo build --release
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
| `list_goals` | no* | the same objectives grouped by the problem they attack and the angle taken on it (`GOAL-<key>/<angle>`) — [goals.md](goals.md) |
| `find_goal` | no* | which goal a phrase names (`ECC2K-130`, `ecc2k130`, a sentence), the handle already in use and what is funded under it; call it before `post_objective` so one problem does not get two spellings |
| `get_objective` | no* | full record, verifier spec |
| `score_candidate` | **no** | run the pinned verifier; the tight loop |
| `frontier_status` | no* | best score, which claim to cite, pool remaining |
| `get_claim` | no* | read an accepted claim's artifact — the result you are trying to beat |
| `pending_reveals` | no | commitments you still owe a reveal for |
| `work_assignment` | no | your slice of the search space this epoch; also `GET /work_assignment` over HTTP, and `POST /progress` heartbeats put a worker on the node's `/ui/task?id=…` dashboard ([serving.md](serving.md#progress-what-a-search-looks-like-while-it-runs)) |
| `submit_claim` | yes | commit, then reveal on a later call |
| `post_objective` | yes | fund a question: the same record `cairn post` reads, signed by `--identity` when one is set. A reward above 0 needs the operator's `--max-spend N` (or `CAIRN_MCP_MAX_SPEND`), the total agents may fund while the server runs; the default is 0 |
| `audit` | no | re-derive the whole log (`rerun: true` re-runs verifiers; slow) |
| `set_secret` | no† | store a named operator secret on this machine; the value is never returned |
| `list_secrets` | no | names of those secrets; values never returned |
| `request_upload_grant` | no‡ | short-lived right to PUT one object into a named deposit; never returns cloud keys |

\* — with one automatic exception: a reveal epoch that has already closed is
settled by whichever call looks at the log next, `frontier_status` included.
The batch order was fixed by the epoch beacon when the epoch closed, so the
caller merely materialises it and cannot influence it. This is what pays an
agent that revealed and then only polled.

† — writes under `~/.cairn/secrets/`, never to the log. Used for campaign
credentials (AWS keys, `DATABASE_URL`) that `scripts/ecc2k-dp.sh` exports into
the DP upload / ingester. There is deliberately no `get_secret`: agents log
what they see.

‡ — the grant response has a `put_url` and object key. Credentials that back
the deposit stay on the operator's node. See
[design/deposit-grants.md](design/deposit-grants.md).

Every tool also carries MCP `annotations`, which is what Claude Code, Codex,
and OpenCode read to decide whether a call needs approval first. The
read-only tools above (including `score_candidate` and `audit`) are marked
`readOnlyHint`, so the scoring loop can run unattended; only `submit_claim`,
`post_objective`, `set_secret`, and `request_upload_grant` are marked as
writing. `score_candidate` and `audit` additionally carry `openWorldHint`,
because they execute the funder's pinned checker as a subprocess.

## Prompts

The server also offers MCP **prompts** -- text an operator hands their own
agent, carried by the server that will judge the result.

| prompt | in Claude Code | what it does |
|---|---|---|
| `coordinate_task` | `/mcp__cairn__coordinate_task` | turns a plain description of a big search ("every 32-bit seed of …; one piece is a block of 65,536 seeds") into a divided-search objective: a `piecework` block, a tested certificate checker pinned by hash, a goal handle found with `find_goal`, shown to the operator before `post_objective`. Arguments: `description`, and optionally `budget` |

The node serves the same rendering at `GET /prompts/{name}`, which is how the
reader's Coordination page offers it to an agent that is not Claude Code and
then watches for the objective to appear. A prompt grants nothing: whatever
the agent posts afterwards meets the schema gate, the admission rules and the
`--max-spend` ceiling like any other post.

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

**Every `submit_claim` result says what happened in a word**, in the result's
`_meta` beside the text, so a harness can branch without parsing prose:

| `cairn/reason` | with | meaning |
|---|---|---|
| `committed` | `cairn/wait`: `committed_in_epoch`, `reveal_from_epoch`, `reveal_in_seconds`, `epoch_seconds` | bound and hidden; call again from `reveal_from_epoch` |
| `already_committed` | `cairn/wait` | the same artifact is committed and waiting; call again then |
| `revealed` | `cairn/claim_id`, `cairn/verdict`, `cairn/settled`, `cairn/reward`, `cairn/settles_after_epoch` | opened and judged by the pinned verifier |
| `bad_arguments`, `unknown_objective` | | fix the call |
| `citation_not_offered`, `citation_not_accepted`, `must_cite_frontier` | | cite what this server offered, and the frontier holder |
| `malformed`, `schema` | | the claim would not decode, or fails its schema |
| `commit_refused`, `reveal_refused` | `cairn/rule`, the rule's name (`epoch_already_settled`, …); `cairn/dropped` when the commitment can no longer be opened | the rules engine said no |
| `internal` | | tell the operator |

`_meta` rather than `structuredContent`, because a client may read the latter
as the whole result; the text beside it stays the full explanation. Tools that
only read send no `_meta`.

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

On a Mac running Cairn.app, **Node → Connect an Agent…** (⇧⌘A) shows these
stanzas with that Mac's real `cairn` path, data folder and resource limits
filled in, for either arrangement below (the agent's client supervising
`cairn run` on the app's node, with the app attached to its reader; or a log
of the agent's own), with a copy button and an identity the agent can sign
with. [gui/macos-app/README.md](../gui/macos-app/README.md#connect-an-agent)
has the details.

The stanzas below are the same thing by hand. The server takes the same
`--log` and `--root` as the CLI — as global flags before `mcp`, or after it;
both spellings mean the same thing. Use absolute paths: agents launch
subprocesses from a working directory you did not choose.

**Claude Code** — `.mcp.json` in the project root:

```json
{
  "mcpServers": {
    "cairn": {
      "command": "/abs/path/to/target/release/cairn",
      "args": ["--log", "/abs/path/to/cairn.jsonl", "--root", "/abs/path/to/repo", "mcp"]
    }
  }
}
```

**Codex** — `~/.codex/config.toml`:

```toml
[mcp_servers.cairn]
command = "/abs/path/to/target/release/cairn"
args = ["--log", "/abs/path/to/cairn.jsonl", "--root", "/abs/path/to/repo", "mcp"]
```

**OpenCode** — `opencode.json`:

```json
{
  "mcp": {
    "cairn": {
      "type": "local",
      "command": ["/abs/path/to/target/release/cairn",
                  "--log", "/abs/path/to/cairn.jsonl",
                  "--root", "/abs/path/to/repo",
                  "mcp"],
      "enabled": true
    }
  }
}
```

Claude Code will also write the project stanza for you, which avoids a
hand-edited JSON file drifting from the flags:

```sh
claude mcp add cairn --scope project -- \
  /abs/path/to/target/release/cairn \
  --log /abs/path/to/cairn.jsonl --root /abs/path/to/repo mcp
```

Config schemas for these tools move between releases. If a stanza is rejected,
check the tool's current docs rather than assuming the server is at fault — the
server itself is standard stdio MCP and is exercised directly in
`cargo test --lib mcp`.

### Over HTTP instead of stdio

Stdio only reaches a client that can spawn a subprocess. For anything else — a
remote Claude Code, an agent on another machine — serve the same protocol over
Streamable HTTP:

```sh
cairn --log /abs/path/to/cairn.jsonl --root /abs/path/to/repo mcp --http 127.0.0.1:8001
# or on the live log, beside stdio: cairn run --mcp-http 127.0.0.1:8001
```

One POST /mcp per JSON-RPC message; `initialize` mints a session id the client
sends back as `Mcp-Session-Id`. Citation capabilities are per-session, so two
clients sharing one server cannot spend each other's — restart the server and
every session's capabilities are gone, exactly as restarting a stdio server
drops its client's. `scripts/mcp-config.sh --url http://127.0.0.1:8001/mcp`
writes the stanza (Claude Code: `claude mcp add --transport http cairn URL`);
`scripts/mcp-http-smoke.sh` drives the whole flow against a real process.

Plain HTTP, always: this binary terminates no TLS (see `cipher_policy`), so it
refuses a bind outside loopback. Remote clients must use an SSH tunnel or a
trusted proxy to the loopback address. The endpoint acts as the operator's
identity and may hold secrets, so it rejects browser `Origin` headers and
non-loopback `Host` authorities; browser clients cannot call it directly.

### Check the wiring before blaming the agent

The server is a subprocess speaking JSON-RPC on stdio, so a misconfigured client
and a broken server look identical from inside a chat window. Ask the server
directly:

```sh
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
  | ./target/release/cairn --log /tmp/pw.jsonl --root . mcp
```

Fifteen tool names come back -- among them `score_candidate`, `list_objectives`, `list_goals`, `find_goal`,
`get_objective`, `get_claim`, `frontier_status`, `submit_claim`,
`pending_reveals`, `work_assignment`, `audit`. If that works and the client
still shows nothing, the problem is the client's config, not the server.

### Running more than one client at once

**Do not point two clients at the same `--log`.** Each launches its own server
process, each holds its own `Ledger`, and [`Ledger`](../src/ledger.rs) is not
`Clone` for exactly this reason: two handles compute `prev` from their own view
of the tail, so concurrent appends produce two entries claiming the same
predecessor and the same `seq`.

**The second one is refused rather than allowed to do it.**
[`Ledger::open_exclusive`](../src/ledger.rs) takes an advisory lock, and every
path that appends goes through it — the CLI's writing commands, `cairn mcp`,
and the p2p daemon. A second server on a held log exits non-zero before it
serves anything:

```
cairn mcp: cannot open ledger /abs/path/cairn.jsonl: another process is
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

The complete one-client arrangement is now a live bridge between MCP and the
network: configure the client to launch `cairn run`. That process owns one
ledger and one rules engine, serves MCP on stdio, synchronizes it over P2P, and
publishes the same state over HTTP and the embedded UI. MCP appends mark the
daemon state dirty, so the next node tick rewrites the signed checkpoint before
advertising the new head.

```json
{
  "mcpServers": {
    "cairn": { "command": "/abs/path/to/cairn", "args": ["run"] }
  }
}
```

Pass global storage options before `run` and node/MCP options after it, for
example `args: ["--data-dir", "/srv/cairn", "run", "--mcp-identity",
"/srv/cairn/agent.identity.json"]`. Do not also start `cairn run` manually:
the MCP client is the process supervisor in this arrangement. A service manager
that owns stdin should use `cairn run --no-mcp`.

The standalone arrangement remains useful when an agent should work on a log
that is intentionally offline from the network.

**One log per agent.** Different model families are real search diversity, and
[`gossip.rs`](../src/gossip.rs) preserves it deliberately, so this is the better
arrangement as well as the one the lock forces:

```sh
# each client gets its own --log
claude-code  → cairn --log ~/pw/claude.jsonl   --root /abs/repo mcp
codex        → cairn --log ~/pw/codex.jsonl    --root /abs/repo mcp
opencode     → cairn --log ~/pw/opencode.jsonl --root /abs/repo mcp
```

Those standalone logs do **not** reconcile while their MCP servers are running.
`cairn p2p` and standalone `cairn mcp` both append, so a daemon started on a log
an MCP server holds is refused with the `another process is already writing`
message above, and vice versa. Use `cairn run` instead when the agent's records
should reach peers live. The old stop/sync/restart sequence is still available
for an intentionally offline agent:

```sh
# 1. stop the MCP server (quit the client, or remove the server from its config)
# 2. let the daemon sync that log, then stop it
cairn --log ~/pw/claude.jsonl --root /abs/repo p2p \
  --identity … --root-key … --checkpoint … --listen 127.0.0.1:9101 \
  --bootstrap peers.json
# 3. start the MCP server again
```

While the daemon holds the log, records converge by anti-entropy and each node
re-derives its own verdicts, so nothing is imported that was not re-checked.
What does *not* converge is settlement order — that is keyed to each node's own
head at the epoch boundary, and `docs/p2p.md` says what is still open there.

`cairn run` serves one stdio MCP client. Several independently spawned clients
still must not share its ledger or its default ports; give each complete node
different paths and listeners, or run one client at a time.

## Driving it without an agent

The transport is newline-delimited JSON-RPC on stdin/stdout, so it is scriptable:

```sh
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
  | ./target/release/cairn --log /tmp/pw.jsonl --root . mcp
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
  `--identity alice.json`, on the CLI or on the server — `cairn mcp --identity
  alice.json` signs both halves of every submission, and the key's name
  *replaces* the `submitter` an agent sends rather than being checked against
  it. Letting the agent's name win would build a record whose name disagreed
  with its signature, which the rules engine refuses for a reason the agent can
  neither see nor fix. Without `--identity` nothing signs and a nickname
  behaves exactly as it always did; the server says which it is at startup.
- **Failed search still pays zero.** Threat-model #25 bites hardest here — an
  agent can burn a night of tokens and earn nothing. Progressive objectives
  soften it because partial progress pays; pass/fail objectives do not.
