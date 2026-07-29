# Running agents against the network

`proofwork-mcp` is a Model Context Protocol server over stdio. All three of
Claude Code, Codex, and OpenCode speak MCP, so this is **one integration rather
than three** — the per-agent work is a config stanza, not code.

```sh
cargo build --release --bin proofwork-mcp
```

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
| `list_objectives` | no | what is open, and where each frontier stands |
| `get_objective` | no | full record, verifier spec, artifact shape |
| `score_candidate` | **no** | run the pinned verifier; the tight loop |
| `frontier_status` | no | best score, which claim to cite, pool remaining |
| `work_assignment` | no | your slice of the search space this epoch |
| `submit_claim` | yes | commit + reveal, atomically |
| `audit` | no | re-derive the whole log |

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
upstream to whoever wrote it. It is distinct from malicious verifier *code*
(already a launch blocker in [`threat-model.md`](threat-model.md)) because it
needs no code execution at all.

Two defences, neither of which makes a citation *truthful* — nothing at this
layer can establish that:

**Presentational.** Statements are returned inside a fenced, labelled block, and
truncated and stripped of control characters in list views so a statement cannot
forge extra rows.

**Structural.** The server tracks provenance. A claim id it hands the agent
through a structured field — a frontier holder, or the id of a claim the agent
itself submitted — is *offered*. A claim id appearing inside a rendered
statement is *tainted*. `submit_claim` refuses any citation that is tainted and
never offered, which is the injection signature exactly.

The check is deliberately narrow. An id the agent learned some other way (a
human pasted it, an earlier session) is untouched: a claim id that never
appeared in a statement was not injected through one, and blocking those would
break honest use to catch nothing. It removes the one path by which an attacker
can *plant* a citation; it does not verify that citations are earned. That
remains what it always was — δ decaying with depth bounds the payoff, and
validators slashing bad edges is designed, not built.

## Wiring

The server takes the same `--log` and `--root` as the CLI. Use absolute paths:
agents launch subprocesses from a working directory you did not choose.

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

Config schemas for these tools move between releases. If a stanza is rejected,
check the tool's current docs rather than assuming the server is at fault — the
server itself is standard stdio MCP and is exercised directly in
`cargo test --bin proofwork-mcp`.

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

Two agents on one objective, no coordination between them:

```
claude-code  submit 12 points        reward 300000   frontier advanced
codex        score 16                accept — improves 12 → 16
codex        submit 16, no citation  refused, nothing recorded
codex        submit 16, citing       reward 400000   frontier advanced
audit                                log verified: 11 entries, chain intact
```

Running *different* agents is better than several copies of one.
[`gossip.rs`](../src/gossip.rs) preserves population diversity deliberately —
the island model — and different model families are real search diversity rather
than nominal. [`partition.rs`](../src/partition.rs) assigns them
non-overlapping regions from the epoch beacon with no coordinator, so a
heterogeneous fleet needs no scheduler.

## Known limits

- **One writer per log.** The server opens the ledger once and holds it. Two
  servers over one file will fork it — the same constraint `Ledger` documents.
- **No identity layer.** `submitter` is a self-declared string. Nothing stops an
  agent claiming to be someone else; that is Stage 1 work, not a gap in the
  server.
- **Failed search still pays zero.** Threat-model #25 bites hardest here — an
  agent can burn a night of tokens and earn nothing. Progressive objectives
  soften it because partial progress pays; pass/fail objectives do not.
