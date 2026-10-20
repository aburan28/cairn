# Challenge-to-payment acceptance

`scripts/challenge-wargame.py` starts a real combined Cairn node, submits an
objective over Streamable HTTP MCP, joins a fresh participant over HTTP, and
checks the resulting payments with both ledger implementations. Every run uses
a new private data directory. It cannot attach to an operator's node.

Build the embedded reader and both binaries, then run:

```sh
npm --prefix ui ci
npm --prefix ui run build
cargo build --locked --features ui
cargo build --locked --manifest-path reference/rust/Cargo.toml
python3 scripts/challenge-wargame.py \
  --binary target/debug/cairn \
  --reference reference/rust/target/debug/cairn-reference \
  --out /path/to/new/acceptance-run
```

Python 3.9 or newer and a working verifier sandbox are required. The output
folder must not already exist. The runner requires the sandbox, disables public
peer discovery, uses loopback listeners and fresh test identities, and leaves
the ledger, node/participant logs, audit outputs and `report.json` for inspection.
It stops only the processes it started. It does not install a service or use
operator identities, funds, API keys or data directories.

The task computes the squares of integers 0 through 15. Its 160-unit test pool
pays 10 per distinct verified result. This bounded task makes full enumeration
and exact accounting practical while exercising the same submission, signing,
verification, commit/reveal and settlement paths used by larger challenges.

| Scenario | Required outcome |
| --- | --- |
| Fresh setup | Embedded node starts with private peering, HTTP and MCP |
| Post a challenge from an agent | MCP returns the objective id and other tools discover it |
| Funding limit | An over-budget first post records nothing; an admitted post consumes the shared ceiling |
| Checker correctness | All 16 correct results pass; empty, wrong, out-of-range, Boolean and string inputs fail; scoring writes nothing |
| Missing pinned code | Scoring reports `unavailable`, distinct from a rejected artifact |
| Browser and MCP boundaries | Simple browser writes and cross-origin MCP requests are refused |
| Admission tracking | A queued objective with an unknown verifier becomes a durable refusal |
| Recovery | Repeating a commitment is idempotent; restarting the node retains the pending reveal |
| Participant setup | A separate process creates its own signing identity, joins using the node URL and appears on the roster |
| Payment | The recovered answer earns 10; the fresh participant earns 150 under its public key; the copied unit and wrong answer earn nothing |
| Replay | Both implementations re-run the checkers and verify the completed ledger |

The report includes binary and ledger hashes. A failed run retains its evidence
and exits nonzero. Queue acceptance alone never counts as admission, verification
or payment.

## A draft from the configured AI provider

The native Coordination composer calls the provider configured in Settings → AI.
The app tests the checker before offering launch. JSON-mode providers may return
the artifact schema and example artifacts either as nested objects or as encoded
JSON strings; both forms receive the same size, shape and integer checks. Money
fields still require exact decimal strings.

The wargame can consume an independently checked native draft of the square task
without rewriting it:

```sh
python3 scripts/challenge-wargame.py \
  --binary target/debug/cairn \
  --reference reference/rust/target/debug/cairn-reference \
  --generated-manifest /path/to/draft-bundle/manifest.json \
  --out /path/to/new/provider-acceptance-run
```

The manifest contains `objective` (the path to the checked objective JSON), `id`
(the id returned by the native check), and provenance fields `provider`, `model`
and `requests`. Checker paths resolve relative to the manifest's directory. Use
exactly 16 units and a 160-unit pool at 10 per unit. Each artifact has integer
`unit` and `square` fields. Either field uniquely identifies a result over this
nonnegative domain. The runner requires the submitted id to equal the native
checked id, and applies the same exhaustive and payment assertions to the
provider's checker. API credentials do not belong in the manifest.

The hosted-provider acceptance on 2026-10-19 reproduced a Fireworks response that
returned nested objects for the three JSON fields. The original parser rejected
both the first response and its repair. After accepting both lossless
representations, the recorded response passed, a fresh provider request produced
a checked draft without repair, and that exact draft completed the signed-worker
and independent-audit wargame. This is functional evidence for that task, not a
proof that every generated checker faithfully expresses an arbitrary request.

## Browser and installation coverage

Run `scripts/reader-ux.py` against the embedded binary for actual form submission,
admission/refusal receipts, reload recovery and responsive layouts. The native
`CoordinationTests` cover the provider-to-preview-to-launch state machine and
provider response parsing; their verifier integration accepts
`CAIRN_DRAFT_TEST_BINARY` for a real checker run.

Keep the installed application, the binary its node runs, and the shell's `cairn`
consistent. Check `command -v cairn` and `cairn --version` if a command or tool is
missing. A second installation earlier on `PATH` can keep a terminal on an older
release even while the desktop app has been upgraded. See
[installation troubleshooting](install.md#two-copies-and-the-wrong-one-runs).

A process on the same host exercises protocol separation, not another machine's
firewall, platform, or resource limits. A local source build also does not update
an already installed desktop application. Check those deployment properties
separately before describing a fleet as ready.
