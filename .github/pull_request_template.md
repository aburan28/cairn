<!--
AGENTS.md section A is the contributor gate. This template is the short
version of it. Delete any section that genuinely does not apply.
-->

## What this changes, and why

<!-- The why matters more than the what; the diff already says the what. -->

## Consensus surface

Did this touch a record, a hash, or an encoding?

- [ ] No — skip the rest of this section.
- [ ] Yes, and **both** implementations changed together (Rust and
      `reference/rust/`).
- [ ] Yes, and `cairn-reference conformance conformance/vectors.json`
      still passes. Those vectors are **frozen** -- nothing regenerates them,
      because their value is that they came from an implementation in another
      language. A *diff* in an existing vector means ids moved and live claims
      are orphaned; say so explicitly if that was the intent.

## Checks

- [ ] `cargo test --all-targets`
- [ ] `cargo test --manifest-path reference/rust/Cargo.toml`
- [ ] `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings`
- [ ] `./scripts/interop.sh` — each implementation audits the other's log
- [ ] `./scripts/mcp-smoke.sh` (if `src/mcp.rs` or the `mcp` subcommand changed)
- [ ] `./scripts/serve-smoke.sh` (if `src/serve.rs`, the `serve` subcommand or the queue changed)
- [ ] `./scripts/demo.sh` and `./scripts/ratchet-demo.sh` (if the CLI or the
      rules changed — the only checks that cross a real epoch boundary)

## Threat model

- [ ] Not applicable.
- [ ] This adds an attack surface, and `docs/threat-model.md` has a new row.
- [ ] This implements a mitigation, and the affected row moved and says what
      still remains.
