# Collaboration workbench review — 2026-10-17

This follow-up to the live collaboration substrate adds an operator-local
graphical editor, recoverable generation rollover and experiment/price controls.
It also fixes a reproducible private-network sync lock cycle found during the
release checks. The existing ledger records, canonical encoders, conformance
vectors, reference implementation, settlement and balances are unchanged.

## Implemented boundaries

- Editing runs on a separate numeric-loopback listener. A random per-process
  credential, exact Host, same-origin checks and proxy-header refusal guard API
  calls. CSP, frame denial, no-store responses, strict duplicate/framing checks,
  timeouts and bounded connections/jobs apply. No host-path checkout endpoint,
  public write endpoint or browser signing-key export was added.
- Dirty drafts retain their original causal read. Incoming work cannot replace
  them. Retries/reload/export/import retain a frozen request. An initially
  refused save remains editable; an uncertain acknowledgement retains its id.
  Unicode positions, untouched CRLF/CR endings and prototype-named source paths
  are handled explicitly. Browser recovery storage is plaintext and tab-scoped.
- Forks and integration use the reviewed heads. Conflicts block checkpoints and
  experiments until an explicit observed resolution. Historical reads are read
  only. The cached index invalidates for every op, including revocation; current
  writer membership is checked again before writes or new runs.
- Runs pin exact file inputs and the selected environment tree. They require
  gVisor/bubblewrap and fresh capacity/ISA matching, permit no network or host
  mounts, and have explicit resource bounds. Exact replay uses recorded pins;
  applying a recipe to current source is a new explicit experiment. Process
  restart never silently resubmits a retained job. Receipts remain advisory
  execution evidence, not prescribed-execution proofs or payment authority.
- CPU/clock/ISA profiles are re-sampled for status, quotes and admission.
  Operator cards select workload-specific rates. Optional run estimates and
  requirements are retained in the receipt note. Quotes display/export exact
  integer microunits, reject unsupported allocations and discard stale results.
  Host ISA reports do not establish a virtualized sandbox's exposed ISA.
- Rollover requires a current admin/writer, creates a new directory/space,
  preserves roles and source bytes/modes, and keeps the original signed history
  in an immutable content-addressed archive. Recovery verifies signatures,
  referenced hashes, lab heads and the pinned source read. The old space remains
  available for late offline work; cross-generation integration and disk
  reclamation remain explicit operator work. There is no unsafe live-anchor GC.
- Graph indexing visits dependencies with a deterministic ready set. During
  daemon sync, authentication/allowlisting finishes before ledger-lock arbitration.
  Under contention, only lower-to-higher authenticated-peer waiting edges are
  admitted, breaking mutual and longer lock cycles. Idle nodes accept either
  direction. This changes scheduling, not record identities or ordering rules.

## Local evidence

- `cargo test --all-targets --locked`: **2,234 passed** across 36 suites; the
  existing fixture-generation test remains ignored by default. Focused final
  workbench (6) and compaction (4) tests passed after the final boundary guards.
- The old mutual-bootstrap test failed on unchanged base `d782a50` and on the
  initial follow-up. After the lock-cycle fix, it and the new three-node ring
  passed as part of the complete private-network suite and full Rust run. No
  timeout/assertion/gate was weakened.
- Reference tests passed **three times** (74 unit tests plus sealed fixtures);
  all **539 frozen vectors** reproduced independently. Interop, adversarial
  differential checks and **2,000 fuzz cases, seed 20261017**, passed.
- Formatting, clippy with warnings denied, all-feature rustdoc with warnings
  denied and MSRV **1.89** all-target/all-feature checks passed.
- **244 UI tests**, typechecking and the static production build passed. Eight
  standalone editor model tests passed. Actual browser checks covered
  **320/360/1280** widths, draft reload/export/import, concurrent work, a response
  lost after server acceptance, explicit conflict resolution, fork isolation,
  integration pinned before a later source edit, checkpoints, dialog focus,
  ISA rejection and exact display/export of **18446744073709551615** microunits.
- Existing reader browser acceptance, local HTTP/compaction demo, CLI/MCP and
  encrypted sync/reconnect demo, P2P verifier-transfer demo, serving/MCP smoke,
  and CLI/ratchet/try demos passed against disposable fixtures.
- RustSec audits of both lockfiles and the npm high-severity advisory gate were
  clean. There are no new third-party dependencies.

## Gates still required

1. Current-head CI for the complete stack, including all native/packaging jobs,
   and explicit human resolution of the previously flagged lab-payload hash
   scope in the parent collaboration PR. Old-head greens are not reusable.
2. The local Linux host cannot create a usable gVisor/bubblewrap sandbox. The
   real GUI demo verified a visible **unavailable** result and no unconfined
   fallback here. Execute a bounded run, pinned replay and a recipe on changed
   source on a host with a usable sandbox before treating that runtime path as
   release-QA complete. CI's demo exercises actual execution when available.
3. Final signed/notarized Mac artifacts, expected Developer ID, stapling and
   Gatekeeper checks, plus clean-Mac first launch/install/upgrade and identity
   recovery. Follow the existing
   [release checklist](release-readiness-2026-10.md); Linux checks do not satisfy
   these native release gates.
4. Operator-reviewed workload calibration/provenance before any real billing.
   These estimates reserve nothing, debit nothing and guarantee no throughput.

Usage and recovery procedures: [collaboration-workbench.md](../collaboration-workbench.md).
