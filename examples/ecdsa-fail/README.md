# ecdsa.fail MVP harness (cairn)

Runs an **ecdsa.fail-shaped** progressive minimize objective on a local
cairn log: pull objective → score candidates against a pinned evaluator →
commit–reveal → settle. Aligns the *agent loop* with
[`ecdsafail` CLI](https://ecdsa.fail) without claiming API settlement.

See [GAP.md](GAP.md) for what is deliberately not equivalent.

## Prerequisites

```bash
cargo build --release
# optional, for the adapter's ecdsafail side:
ecdsafail version   # login already configured if you use pull/benchmark
```

## Quick demo (cairn only)

```bash
./examples/ecdsa-fail/demo.sh
```

Uses 1-second epochs. Funds the objective, rejects a lying `score` field,
then ratchets baseline → mid → best with required frontier citations.

## Score a candidate (CLI)

```bash
LOG=$(mktemp -u /tmp/pw-ecdsa-XXXXXX.jsonl)
OID=$(./target/release/cairn --log "$LOG" --root . post examples/ecdsa-fail/objective.json | awk '{print $2}')
```

The CLI has no free-scoring subcommand — its verifier runs at reveal time.
Free local scoring without writing the log: use MCP (below) or the adapter:

```bash
./examples/ecdsa-fail/adapter.sh score examples/ecdsa-fail/artifacts/mid.json
```

## MCP (natural wiring — no new tools)

Point `cairn-mcp` at a log that already has this objective posted:

```json
{
  "mcpServers": {
    "cairn": {
      "command": "/ABS/distributed-researcher/target/release/cairn-mcp",
      "args": ["--log", "/tmp/pw-ecdsa.jsonl", "--root", "/ABS/distributed-researcher"]
    }
  }
}
```

Agent loop (same as `docs/agents.md`):

1. `list_objectives` / `get_objective`
2. `score_candidate` with `{qubits, toffoli}` (optional `score`)
3. `frontier_status` → cite holder
4. `submit_claim` twice (commit, then reveal after epoch turn)

Smoke without an agent UI:

```bash
./examples/ecdsa-fail/mcp-score.sh
```

## Relation to `ecdsafail` CLI

| You want | Use |
|---|---|
| Local cairn ratchet demo | `./examples/ecdsa-fail/demo.sh` |
| Map CLI concepts / import `score.json` shape | `./examples/ecdsa-fail/adapter.sh …` |
| Real benchmark + leaderboard | `ecdsafail clone` → edit → `run` → `submit` (see skill) |

```bash
./examples/ecdsa-fail/adapter.sh map
./examples/ecdsa-fail/adapter.sh import-score /path/to/score.json
# optional: ecdsafail benchmark (needs network + login)
./examples/ecdsa-fail/adapter.sh pull
```

`import-score` validates the product identity on real `score.json` values
(e.g. current best ≈ 1.488e9). Those will not clear this example's *toy*
threshold (100000); that is expected — leaderboard submit stays on `ecdsafail`.

Convert only:

```bash
python3 examples/ecdsa-fail/score_to_artifact.py /path/to/score.json
```

## Artifact shape

```json
{ "qubits": 80, "toffoli": 700, "score": 56000 }
```

`score` is optional; if present it must equal `qubits * toffoli`.
