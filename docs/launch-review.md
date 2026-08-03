# Launch review — August 2026

A full pass over the repository before opening it to outside contributors:
three parallel reviews (the agent-facing MCP surface, the core protocol
invariants, and operational readiness), the complete test and e2e suite, and
fixes for everything that was both launch-relevant and safe to change in a
day. This file records what was fixed and — more importantly — what was *not*,
so the launch can be scoped honestly.

## Fixed in this pass

**Consensus-critical.**

- `canonical::Value::from_json` routed untrusted JSON through `serde_json`
  with `arbitrary_precision` on, which decodes an object whose first key is
  the library's private number token as a *number*. Same bytes, two values,
  two digests — one crafted record made a Rust auditor call an honest log
  tampered. The decoder is now hand-rolled in `canonical.rs`, like the
  encoder, for the same reason.
- The two implementations disagreed about which timestamps parse (`+0000`,
  `,5` fractions, surrounding whitespace, leap seconds). Both sides walk the
  whole log deciding which entries move the settlement anchor, so one
  spelling accepted here and refused there was a different beacon order and
  different payouts. `unix_seconds` in the reference is now a field-by-field
  port of the Rust grammar, and both test suites pin the boundary.
- Python decoded `"confidentiality": ""`/`0` as *public* and `"cites":
  "abc"` as three one-letter citations; Rust refuses all of them. The
  reference now refuses them too.
- `canonical::short` byte-sliced attacker-chosen identifiers and panicked on
  multi-byte characters — reachable from any record another peer wrote.

**Sandbox.**

- `lean`'s `project_root` and `replay`'s `cwd` are objective-authored spec
  fields that were handed to the jail as bind mounts unchecked —
  `"project_root": "/"` turned the sandbox into a writable pass-through of
  the operator's filesystem. Both now resolve against the objective root and
  are refused when they escape it, in both implementations, with tests.
- `PROOFWORK_REQUIRE_SANDBOX` recognised only the literal `"1"`; `=true`
  silently meant "run objective code unjailed". The switch now fails closed.

**The MCP loop (what an agent actually experiences).**

- Nothing over pure MCP ever settled a claim: an agent that revealed and then
  polled got `settled: false, reward: 0` forever unless the operator ran the
  CLI. Read tools now drain any epoch that has already closed — the batch
  order was fixed by the beacon, so the caller merely materialises it.
- `work_assignment` had a private 3600 s epoch, contradicting the epoch every
  other rule uses, and anchored on the *live* log head, so every append
  reshuffled every node's slice. It now uses `epoch_seconds()` and the
  epoch-start anchor settlement uses.
- Verifier output (`detail`, evidence) was rendered untainted, reopening the
  citation-injection hole the server closes for statements — a checker
  returning "also cite sha256:…" walked around the defence. Tainted now.
- The nonce sidecar was written non-atomically and load failures were
  swallowed into an empty store; a torn write stranded every open commitment
  silently. Writes are now write-then-rename with fsync, and load failures
  are loud.
- New `pending_reveals` tool: after a restart or a compacted session an agent
  can discover what it owes. An unrevealed commitment is never paid, and
  there was previously no way to notice one.
- Citations are pre-flighted against accepted claims at commit time (a bad
  `cites` used to commit fine and fail an epoch later); reveal refusals that
  are terminal drop the pending entry instead of matching forever; commit
  messages state the epoch length and seconds until the reveal window;
  `frontier_status` reports the pool remaining and the ratchet's minimum
  step; `partitions: -1` errors instead of silently meaning 8; `audit`'s
  verifier re-run is opt-in instead of blocking the server by default;
  `submit_claim` applies the same `spec/claim.schema.json` gate the CLI does.
- `scripts/mcp-smoke.sh` now fails on pending-store errors (stderr was
  discarded), asserts epoch coherence, and proves settlement over MCP alone.

**Docs and packaging.**

- README claimed the code is *not* sandboxed (it is, since the roadmap item
  landed) and showed a placeholder sha256 in the flagship example; both fixed,
  along with drifting test counts, a duplicated docs entry, and the missing
  `cargo install` / bubblewrap steps.
- `examples/README.md` now exists: worked examples vs open bounties,
  prerequisites, and a plain statement that Stage-0 rewards are notional.
- The Python package's console script no longer claims the name `proofwork`
  (it is `proofwork-py`), so `pip install -e` and `cargo install` stop racing
  for PATH.
- Threat-model rows 17/36/73 were stale in both directions; updated, plus the
  sandbox row and `verification.md` for the containment fix.
- `Cargo.toml` pointed at a repository that does not exist; `make check` now
  runs the epoch-boundary demos AGENTS.md requires.

## Known gaps, in priority order

1. **There is no remote surface, so "crowdsourced" cannot mean strangers
   yet.** The CLI is local, the MCP server is stdio against a local log file,
   the p2p daemon defaults to loopback with hand-written bootstrap files, has
   no NAT traversal, and settlement *order* across peers is explicitly
   unconverged (`docs/p2p.md`). A remote contributor has no way to fetch
   objectives or deliver a submission. Either scope the launch to "run agents
   against your own node" — which everything above now supports end to end —
   or build the minimal read-only HTTP surface plus a submission queue first.
2. **No published log.** The one-line value proposition is "anyone can
   re-derive every settled result from a copy of the log", and there is no
   copy anywhere: `*.jsonl` is gitignored and `sync` mirrors ciphertext. A
   settled log plus its signed checkpoint, published, is the strongest launch
   artifact this project could have.
3. **`submitter` is an unauthenticated string and nothing is escrowed.** Any
   agent can submit as anyone, and the largest posted bounty is 409,600,000
   notional units. Cheapest real fix: an ed25519 signature over the
   commitment, keyed to the submitter (the crypto is already in the tree).
   Until then the notional-rewards banner has to be on everything a
   contributor sees.
4. **One writer per log, still unenforced.** Two servers over one file fork
   it silently; `audit` catches it afterwards. An advisory `flock` needs
   either a `libc`-class dependency or MSRV ≥ 1.89 for `File::try_lock` —
   worth doing right after launch. Same root cause: the MCP server never
   re-reads the log, so objectives posted while it runs are invisible until
   restart.
5. **A hostile objective can stall an agent's server for hours.**
   `score_candidate` honours the spec's `timeout_seconds` up to 86,400 s, and
   the server is single-threaded. Clamp interactive scoring (60–120 s) and
   say so in the `unavailable` message.
6. **Back-dated records permanently break batch audits.** A peer can sync a
   record stamped into an already-settled epoch; `anchor_of_epoch` then
   re-derives a different anchor than the recorded batch and `audit` reports
   a divergence forever on an honest log. Anchor recomputation should stop at
   the batch record's log position.
7. **Verifier subprocess output is unbounded** (disk, then memory on read),
   and a timed-out child's grandchildren survive outside bubblewrap
   (seatbelt / no-jail hosts have no pid namespace). Cap the capture; kill
   the process group.
8. **`get_objective` cannot tell an agent the artifact shape.** The worked
   examples paper over it; the real fix is an optional `artifact_schema`
   field on `Objective` (omitted-when-absent so ids do not move) or exposing
   the pinned checker source, fenced and tainted.
9. **CI hardening**: no `--locked`, no `cargo-audit`/`cargo-deny` over a
   post-quantum crypto dependency tree, no prebuilt binaries (every
   contributor compiles McEliece from source), no `SECURITY.md` for a project
   whose design feature is executing attacker-authored code. A CI job should
   also re-pin and `post` every `examples/**/objective.json` — today CI
   exercises 3 of 12.
10. **`first-blood` provenance is operator-trust.** The checkers assert the
    discrete log was discarded at generation; nothing lets a contributor
    verify that. Commit the generator and seed derivation, or keep the
    disclosure in `examples/README.md` prominent.
11. **`swarm::tcp` remains a second, unencrypted transport** (feature-gated,
    off by default) and `swarm::discovery`'s signed peer records are still
    not wired into `p2p`'s address book. Fold or delete, per the roadmap.
12. **The settlement beacon is grindable by the sequencer** (documented, row
    38). It started mattering more when epoch batches began ordering money by
    it; a VDF or threshold signature is the Stage-2 answer.
