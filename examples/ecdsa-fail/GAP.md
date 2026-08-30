# Gap analysis: cairn today vs ecdsa.fail needs

> **The verifier in this directory is a demo, not a bounty.** It accepts
> declared `{qubits, toffoli}` and checks only that the product is arithmetic,
> so anyone can type two small integers and clear it. For the same shape with a
> verifier that *derives* the score by simulating the submitted circuit — which
> is what makes an objective safe to fund — see
> [`../reversible-adder/`](../reversible-adder/). Read the two side by side:
> the difference is the entire thesis of this project.

Honest inventory for the MVP in this directory. **Implemented** means the
harness loop runs end-to-end on a local cairn log. **Design-only** means
documented mapping without claiming settlement equivalence to ecdsa.fail.

## What ecdsa.fail is

| Piece | ecdsa.fail (launch CLI) |
|---|---|
| Problem | Cheapest reversible quantum circuit for secp256k1 point add |
| Score | `peak_qubits × avg_toffoli` (minimize) |
| Artifact | Diff under `src/point_add/` (Rust circuit builder) |
| Local check | `ecdsafail setup` → `ecdsafail run` → `score.json` |
| Accept rule | Harness: 9024-shot sim, reversibility, phase, forward∘reverse |
| Submit | `ecdsafail submit --note-file … --model …` (API; promote if beats best) |
| Coordination | Public submissions / notes / sync to best promoted |

Pinned benchmark (CLI, no id argument): `gpsanant/ecdsafail-challenge`,
`editablePaths: ["src/point_add"]`, `scorePath: score.json`.

## What cairn already has

| Piece | cairn Stage 0 |
|---|---|
| Problem unit | Funded `Objective` with pinned verifier (content-addressed) |
| Score path | `evaluator` / `statistical` with integer scores; ratchet minimize exists |
| Artifact | JSON object in the log (not a git tree diff) |
| Local check | `score_candidate` (MCP) / registry run — free, records nothing |
| Accept rule | Pinned pure function; `UNAVAILABLE ≠ REJECT` |
| Submit | Epoch-batched commit → reveal → settle; cite frontier on ratchet |
| Agent surface | `cairn mcp`: list / get / score / frontier / submit / audit |

Existing close cousins: `examples/ecdlp/` and `examples/first-blood/` are
**certificate** (recover `k`); ecdsa.fail is **evaluator minimize** (circuit
cost). Cap-set progressive is the ratchet pattern this MVP copies, flipped to
minimize.

## Gaps (cairn → ecdsa.fail-type)

1. **Artifact shape.** ecdsa.fail submits editable Rust sources; cairn
   commits JSON. Bridging a full `src/point_add/` tree into a content-addressed
   claim without new record types is not done. MVP uses declared
   `{qubits, toffoli}` metrics only. A design for closing this — a `workspace`
   verifier kind whose artifact is a manifest of blob addresses rather than an
   archive — is in
   [`docs/design/workspace-benchmarks.md`](../../docs/design/workspace-benchmarks.md),
   which also says which half of Yukon (the platform now running ecdsa.fail)
   must not be copied.
2. **Verifier strength.** Real accept needs the Rust sim harness (~minutes,
   large dep graph). Pinning `benchmark.sh` as a Stage-0 evaluator is the wrong
   tier: that is closer to V2 `replay` with a pinned toolchain, and the Python
   reference does not jail. MVP evaluator checks product identity + toy bounds.
3. **External promotion API.** ecdsa.fail promotion is “beats current best” via
   their API. cairn settlement is local log + ratchet + citation flow. No
   shared ledger; the adapter only maps *workflow*.
4. **Commit–reveal vs archive upload.** cairn requires a later epoch to
   reveal; ecdsafail uploads a submission archive + public note in one shot.
5. **Notes / swarm memory.** `ecdsafail notes` has no cairn equivalent yet
   (design-only: keep using the CLI for swarm notes). The design puts a `note`
   and a self-declared `model` in the artifact, where they need no record change
   and the pinned verifier ignores them — and routes both through the MCP taint
   path, because a note is attacker-authored prose that an *agent* reads. See
   [`docs/design/workspace-benchmarks.md`](../../docs/design/workspace-benchmarks.md).
6. **MCP frontier messaging** previously assumed maximize (`score > best`).
   Fixed for ratchet-aware improve checks so minimize objectives are not lied
   to in `score_candidate` text. No consensus / record-id changes.

## Smallest path chosen (this directory)

| Deliverable | Status |
|---|---|
| Gap analysis (this file) | implemented |
| Example objective + pinned evaluator | implemented |
| Demo: post → score → commit → reveal → settle | implemented (`demo.sh`) |
| Thin ecdsafail ↔ cairn adapter | implemented (`adapter.sh`, `score_to_artifact.py`) |
| MCP wiring | natural: existing tools; `mcp-score.sh` smoke |
| Pin real `benchmark.sh` / submit to api.ecdsa.fail from cairn | **not** implemented — blockers below |
| Consensus / record schema changes | **out of scope** (deliberately untouched) |

## Blockers for a *real* ecdsa.fail submission from this harness

1. Must edit `src/point_add/` in a clone from `ecdsafail clone`, not a JSON
   metric blob.
2. Must pass `ecdsafail run` (full sim). Declared metrics alone are worthless on
   their API.
3. Must call `ecdsafail submit` with `--note-file` and `--model`; cairn
   commit–reveal does not reach their leaderboard.
4. Promotion requires beating the live best (currently ~1.488e9); sync often
   (`ecdsafail submissions --all` / `ecdsafail sync`).
5. Embedding their harness as a cairn verifier would need a pinned, sandboxed
   replay path and operator tooling — Stage 1/2 work, not this MVP.

**Unavailable ≠ Reject** still applies: if the real harness cannot run on a
node, that is infrastructure, not a failed circuit.
