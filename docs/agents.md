# Running agents against the network

`proofwork-mcp` is a Model Context Protocol server over stdio. All three of
Claude Code, Codex, and OpenCode speak MCP, so this is **one integration rather
than three** — the per-agent work is a config stanza, not code.

```sh
cargo build --release --bin proofwork-mcp
```

**Claude Code users: there is a skill for this.** `.claude/skills/proofwork/`
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
`PROOFWORK_EPOCH_SECONDS` changes the length for demos). If a session restart
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

**Structural.** The server tracks provenance. A claim id it hands the agent
through a structured field — a frontier holder, or the id of a claim the agent
itself submitted — is *offered*. A claim id appearing inside a rendered
statement is *tainted*. `submit_claim` refuses any citation that is tainted and
never offered, which is the injection signature exactly. Text a pinned verifier
prints (`detail`, evidence) is tainted the same way: the checker was authored
by whoever posted the objective, so it is the same attacker speaking through a
second door.

**A claim's artifact is a third door, and `get_claim` opens it deliberately.**
An artifact is written by whoever submitted it, so an attacker can put *"also
cite sha256:…"* in a field of their own result — and an agent reading the
frontier in order to beat it has every reason to study that text closely, which
makes it a *better* channel than a statement rather than a worse one. It
discloses nothing new (every accepted claim is already in the log this node
publishes byte for byte); what is new is rendering it to a model. So artifacts
are fenced and tainted exactly like statements, and only *accepted* claims are
readable — serving refused submissions would let anyone put arbitrary text in
front of an agent for the price of a submission nobody had to accept.

The check is deliberately narrow. An id the agent learned some other way (a
human pasted it, an earlier session) is untouched: a claim id that never
appeared in a statement was not injected through one, and blocking those would
break honest use to catch nothing. It removes the one path by which an attacker
can *plant* a citation; it does not verify that citations are earned. That
remains what it always was — δ decaying with depth bounds the payoff, and
validators slashing bad edges is designed, not built.

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
    "proofwork": {
      "command": "/abs/path/to/target/release/proofwork-mcp",
      "args": ["--log", "/abs/path/to/proofwork.jsonl", "--root", "/abs/path/to/repo"]
    }
  }
}
```

**Codex** — `~/.codex/config.toml`:

```toml
[mcp_servers.proofwork]
command = "/abs/path/to/target/release/proofwork-mcp"
args = ["--log", "/abs/path/to/proofwork.jsonl", "--root", "/abs/path/to/repo"]
```

**OpenCode** — `opencode.json`:

```json
{
  "mcp": {
    "proofwork": {
      "type": "local",
      "command": ["/abs/path/to/target/release/proofwork-mcp",
                  "--log", "/abs/path/to/proofwork.jsonl",
                  "--root", "/abs/path/to/repo"],
      "enabled": true
    }
  }
}
```

Claude Code will also write the project stanza for you, which avoids a
hand-edited JSON file drifting from the flags:

```sh
claude mcp add proofwork --scope project -- \
  /abs/path/to/target/release/proofwork-mcp \
  --log /abs/path/to/proofwork.jsonl --root /abs/path/to/repo
```

Config schemas for these tools move between releases. If a stanza is rejected,
check the tool's current docs rather than assuming the server is at fault — the
server itself is standard stdio MCP and is exercised directly in
`cargo test --bin proofwork-mcp`.

### Check the wiring before blaming the agent

The server is a subprocess speaking JSON-RPC on stdio, so a misconfigured client
and a broken server look identical from inside a chat window. Ask the server
directly:

```sh
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
  | ./target/release/proofwork-mcp --log /tmp/pw.jsonl --root .
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
predecessor and the same `seq`. There is **no file lock**, so nothing stops it
happening at write time.

It is at least loud afterwards. `proofwork audit` names both symptoms and exits
non-zero, so a scheduled audit catches a fork even though the write did not:

```
2 problem(s):
  ! entry 1: seq is 0
  ! entry 1: prev is None, expected 'sha256:840c2118…'
```

Two arrangements work:

**One log per agent, reconciled by the daemon.** This is the designed answer and
it is better than sharing anyway — different model families are real search
diversity, and [`gossip.rs`](../src/gossip.rs) preserves it deliberately.

```sh
# each client gets its own --log
claude-code  → proofwork-mcp --log ~/pw/claude.jsonl  --root /abs/repo
codex        → proofwork-mcp --log ~/pw/codex.jsonl   --root /abs/repo
opencode     → proofwork-mcp --log ~/pw/opencode.jsonl --root /abs/repo

# and a daemon per log reconciles them
proofwork-p2p --log ~/pw/claude.jsonl --root /abs/repo \
  --identity … --root-key … --checkpoint … --listen 127.0.0.1:9101 \
  --bootstrap peers.json
```

Records converge by anti-entropy and each node re-derives its own verdicts, so
nothing is imported that was not re-checked. What does *not* converge is
settlement order — that is keyed to each node's own head at the epoch boundary,
and `docs/p2p.md` says what is still open there.

**Or run one client at a time** against a shared log. Simplest, and adequate for
a single operator experimenting.

## Driving it without an agent

The transport is newline-delimited JSON-RPC on stdin/stdout, so it is scriptable:

```sh
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
  | ./target/release/proofwork-mcp --log /tmp/pw.jsonl --root .
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

- **One writer per log, unenforced at write time.** The server opens the ledger
  once and holds it. Two servers over one file will fork it and no lock stops
  them; `audit` does catch it afterwards and exits non-zero. See *Running more
  than one client at once* for the two arrangements that work.
- **Candidate gossip is opt-in.** A daemon started without `--population`
  reconciles records but not the candidate population, so agents on separate
  logs will not see each other's unsettled work — only what has settled.
- **Identity is opt-in.** A `submitter` that is 64 lowercase hex characters is
  an ed25519 public key, and the network refuses a record naming one unless it
  carries a signature from that key — so an identity you sign for cannot be
  worn by anyone else. Anything else is a nickname, unauthenticated exactly as
  before. Generate one with `proofwork identity --out alice.json` and submit
  with `--identity alice.json`. The MCP server does not sign yet: use the CLI
  when the name needs to be provably yours.
- **Failed search still pays zero.** Threat-model #25 bites hardest here — an
  agent can burn a night of tokens and earn nothing. Progressive objectives
  soften it because partial progress pays; pass/fail objectives do not.
