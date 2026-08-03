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
      `reference/python/`).
- [ ] Yes, and `conformance/vectors.json` was regenerated with
      `scripts/gen_conformance.py`.
- [ ] Yes, and every **pre-existing** vector is unchanged byte for byte.
      *(A diff in an old vector means ids moved and live claims are orphaned.
      Say so explicitly if that was the intent.)*

## Checks

- [ ] `cargo test --all-targets`
- [ ] `cd reference/python && pytest -q`
- [ ] `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings`
- [ ] `./scripts/interop.sh` — each implementation audits the other's log
- [ ] `./scripts/mcp-smoke.sh` (if `src/bin/mcp.rs` changed)
- [ ] `./scripts/serve-smoke.sh` (if `src/bin/serve.rs` or the queue changed)
- [ ] `./scripts/demo.sh` and `./scripts/ratchet-demo.sh` (if the CLI or the
      rules changed — the only checks that cross a real epoch boundary)

## Threat model

- [ ] Not applicable.
- [ ] This adds an attack surface, and `docs/threat-model.md` has a new row.
- [ ] This implements a mitigation, and the affected row moved and says what
      still remains.
