# Release security and usability review — 16 October 2026

Scope: CAIRN at `4b8cafb` (10.0.0, including hardware profiles and swarm calls),
plus the fixes accompanying this review. The primary release journey assessed
is Cairn.app with a local node; shared HTTP, CLI, MCP, experiments and the other
readers are included at their trust boundaries.

**Decision: finish the fixes and current-head CI, then validate the actual Mac
release artifacts before a public launch.** The source changes and portable
checks alone do not certify an installer or native window behavior. Stage 0
remains one sequencer, without distributed consensus, a token or external-funds
settlement. A release number does not change those limits.

This is a source and dependency review with targeted adversarial tests and real
browser workflows. It is not an independent penetration test, a kernel sandbox
audit, an evaluation of scientific validity, or proof that every possible input
is safe. No production log, user credentials or live provider account was used.

## Findings fixed in this change

| Finding | Impact and scope | Change and regression evidence |
|---|---|---|
| Mac nodes did not require a sandbox | High consequence if a machine lost its jail: imported objective code could use the CLI's documented unconfined fallback. This is not a newly demonstrated sandbox escape. | `NodeSettings.environment` always requires isolation for foreground and launchd nodes. Missing isolation means `Unavailable`. `BackgroundServiceTests` pins the setting. The CLI compatibility policy remains explicit. |
| Swarm operator authority relied on a local socket | A proxy can connect from loopback without forwarding headers, allowing a remote request to steer advisory calls. Calls do not move ledger balances. | Controls are off without `CAIRN_SWARM_OPERATOR_TOKEN`. A random 32-byte Bearer credential, constant-time verifier, loopback and no forwarding headers are all required. The route test rejects anonymous, incorrect and forwarded credentials and exercises authenticated call/withdrawal with unchanged chain state. Invalid configuration refuses startup. |
| HTTP request boundaries were permissive | Duplicate decision headers, unsupported transfer encodings, incomplete headers and large aggregate headers invite parser disagreements and resource abuse. No remote code execution or ledger theft was demonstrated. | Both reader and MCP parsers require explicit framing, CRLF, supported versions and origin-form targets, reject ambiguous headers/encodings, and cap total headers at 32 KiB. Raw TCP regressions cover malformed requests, truncation and flooding; normal serving/MCP workflows remain exercised. |
| Provider requests could follow redirects beyond the configured endpoint | Keys in custom headers and private challenge text need an origin boundary, including HTTPS downgrade protection. | The provider session permits only the same scheme, host and effective port, rejects destination userinfo, and explains stopped redirects. API base URLs reject embedded credentials, queries and fragments. Policy tests cover downgrade/host/port/userinfo; actual URLSession tests verify no connection reaches another origin and same-origin redirects still work. |
| Verifier settings mixed local and attached-node evidence | A remote node could appear to have this Mac's tools and sandbox. Installing Lean locally would not repair that node. Late responses could overwrite a retargeted screen. | Remote attach mode shows the node's own `/verifiers`, its isolation policy and repair guidance. Local install actions stay available for the app's own foreground/login node only, with an exact service-URL ownership regression. Checks clear old reports and reject superseded responses. Existing login services get an explicit restart action to update their stored isolation policy. |
| Reader build dependency had a high advisory | `source-map-js` 1.2.1 was affected by [GHSA-68fv-2mgg-jv7q](https://github.com/advisories/GHSA-68fv-2mgg-jv7q), an event-loop DoS through indexed source-map offsets. The shipped reader is a static export, so the advisory does not establish an exposed production Node server. | Lockfile updated to 1.2.2. Fresh install, types, 239 tests and export passed. npm audit reports zero advisories. CI and release now gate on `npm audit --audit-level=high`, including build dependencies. |
| Rust lockfile contained a yanked crypto patch | `chacha20` 0.10.1 was yanked; cargo-audit reported no vulnerability advisory. This was a maintenance warning, not evidence of exploitable cryptography. | Updated only that crate to 0.10.2. The RFC 8439 known-answer test, sealed fixtures, independent conformance and interop retain their byte-level contracts. The reference has its own crypto implementation and no `chacha20` dependency; its lockfile is untouched. Both Rust audits now report zero advisories/warnings. |
| Installer and confidentiality documentation had drifted | The install page encouraged bypassing Gatekeeper and stated signing was unavailable even though the pipeline supports it. The threat model said all embargo enforcement was unbuilt despite committee-share delay checks. | Install guidance now requires checking the actual artifact and publisher. Threat-model wording distinguishes conditional Mac signing, unsigned assets, explicit committee delays, legacy objectives without a delay, and the limits of secrecy. No disclosure or settlement rule was changed. |

Reader responses also deny framing, disable MIME sniffing and suppress
referrers. The CSP restricts frames, base URLs and objects, but permits the
reader's inline bootstrap; it must not be advertised as general XSS protection.

## Trust boundaries assessed

| Surface | Evidence reviewed or exercised | Remaining boundary |
|---|---|---|
| Result identity and replay | Frozen vectors, independent reference, curated and random differential tests, cross-produced logs, existing signatures/epoch/settlement tests | One operator sequences this stage. A valid alternate or withheld log needs an independently trusted checkpoint/key; this is not Byzantine consensus. |
| Verifier execution | Sandbox and resource-limit implementation/tests, fail-closed app settings, `/verifiers` diagnostics | CLI operators must set `CAIRN_REQUIRE_SANDBOX=1`. Kernel/policy escapes remain possible. Installers must supply real interpreters rather than version-manager shims. |
| Reader writes and authorization | Host/content-type gates and refused cross-origin JSON preflights, raw framing tests, real wallet/form revision races, queue admission/refusal/reload recovery | Google sign-in is optional reader labeling, not fleet admission. A served node can lie about its reports; independent derivation establishes settled results. |
| MCP | Local bind and authority/origin refusal, spend/citation capability tests, stdio and HTTP smoke checks, strict request framing | Any process that can reach the operator's local MCP socket has the operator's configured tool authority. Use stdio or an authenticated SSH tunnel; never expose it through a public proxy. |
| Fleet and worker control | Enrollment, member request signatures, revocation and replay tests; progress/work demos | Use `CAIRN_FLEET=enrolled`. Legacy `private`, `loopback` and CIDR trust are not credentials and remain unsafe behind a proxy that hides callers. |
| Secrets and updates | Exclusive private writes, symlink-safe replacement/read checks, MCP non-disclosure, fixed update feed and dual-signature gate | Named secrets are permission-restricted plaintext, readable by the same OS user and included in home backups. Update authenticity does not authenticate the first installer. OS/publisher trust is still required. |
| Peer transport and content | AEAD, handshake identity/context tests, content hashes, bounded frames and peer/admission tests | Traffic timing and peer addresses leak; eclipse/availability attacks remain possible. Open networking is not a private research channel. |
| Lab collaboration and replay | Signed causal history, conflicting versions, receipt input pins, exact replay/reapply tests and browser workspace journey | Each participant needs a separate replica. Arbitrary concurrent algorithm changes are not automatically reconciled. Exact replay needs pinned inputs/images; network effects and nondeterminism are outside its guarantee. Lab ancestry never authorizes payment citations. |
| Lab publication and execution | Explicit publication, referenced blob/hash gates, host-input opt-in, runner and sandbox-policy tests | A published lab includes historical recipe variables and referenced bytes. Review the whole lab first. A secret copied into a snapshot or recipe is already disclosed. Host/network execution is an operator trust choice. |
| Hardware and prices | Runtime ISA gating, conservative capacities, requirements/rate-card/quote tests and host preflight | Remote CPU/ISA/clock reports are unverified. AVX-512 or clock speed does not prove workload throughput. Quotes reserve nothing, attest nothing and debit nothing. Calibration and authenticated measured billing need separate work. |
| Durability and recovery | Hash-linked log checks, torn-tail behavior, durable submission receipts, sealed-store/mirror/exposure tests | Give every node its own log. Concurrent writers on a synced folder remain unsupported. Use `CAIRN_LEDGER_FSYNC=1` where loss of the last submitted records is unacceptable; keep identity and at-rest key backups separate from data mirrors. Key loss has no recovery service. |
| Release supply chain | Exact/locked dependencies, dependency audits, protected-release-environment workflow, signing/notary/staple and installer verification scripts | The session could not inspect signing secret metadata (GitHub returned 403). Actual credentials, environment tag restrictions, immutable release settings and final downloaded artifacts need owner verification. Unsigned Linux assets still lack an independent publisher signature. |

Primary source pointers: `src/serve.rs`, `src/mcp.rs`, `src/fleet/`,
`src/verifiers/`, `src/lab/`, `src/secrets.rs`, `src/secret_file.rs`,
`src/store/`, `src/hardware.rs`, `src/pricing.rs`,
`gui/macos-app/Sources/Cairn/AIProvider.swift`, `VerifiersSettings.swift`,
`Updates.swift`, `UpdateSignature.swift`, `.github/workflows/ci.yml`,
`.github/workflows/release.yml`, and `packaging/macos/`.

## Verification record

Run against disposable fixtures on Linux on 16 October 2026:

- Rust all-target tests: 2,166 passed (one existing child-process helper marked ignored); formatting, all-feature clippy with warnings denied,
  and all-feature rustdoc with warnings denied.
- Rust 1.89 all-target/all-feature check.
- Independent reference: 74 tests; 539 frozen conformance vectors reproduced.
- Interop and curated differential scripts; 2,000 random values with seed
  `20261016` (1,569 parsed, 431 refused; every outcome agreed).
- Rust primary and reference `cargo-audit` 0.22.2: zero advisories/warnings.
- Reader fresh `npm ci`, TypeScript check, 27 test files / 239 tests, static
  export and zero-advisory audit; the new high-severity audit command passed.
- Chromium: all 19 routes at 320, 360 and 1280 px; keyboard/modal focus, stale
  recovery, wallet authorization races, candidate downloads, replay/reapply
  guidance, real queued/admitted/refused receipts and reload recovery; no
  browser exceptions or writes outside the temporary fixture.
- Named-secret CLI launch: invalid configuration fails without disclosure;
  anonymous/bad/forwarded operator calls refuse, authenticated calls route, and
  the log stays unchanged.
- Serving, combined node, stdio MCP, HTTP MCP, progress and worker smoke demos;
  62 example objectives and 61 pins; four-replica lab demo, key-rotation recovery
  and canary comparison demos.
- Swift 6.2 source parsing for all changed Swift files; five portable tests for
  provider policy/real redirects and the app's environment, plus six shared-kit
  tests. The Linux harness compiles the actual AI transport and NodeSettings
  struct, excluding unrelated Darwin-only disk-usage code. It does not build
  AppKit/SwiftUI/Sparkle or substitute for native CI.
- CI scope detector tests for the workflow edits. No conformance vector,
  reference implementation, record, encoding, settlement or balance rule changed.

Current-head GitHub CI, including the universal Mac app build and its complete
Swift test target, must finish successfully. The portable tests do not close
that gate. If CI cannot build any changed component, leave the PR for human
approval under `AGENTS.md`.

## Release gates for the next few days

| Gate | Concrete pass condition | Who can close it |
|---|---|---|
| Current source | All current-head checks green; every changed component built; no review requesting changes; clean merge | CI and delegated PR watcher |
| Publisher and installer | Final downloaded Intel and Apple Silicon artifacts match checksums; package/app have the expected Developer ID; Apple notarization is accepted, staples validate, and Gatekeeper accepts a browser-downloaded copy | Release owner with signing credentials and clean Macs |
| Protected publication | Signing/update secrets are in the `release` environment, allowed refs restricted to release tags, immutable-release protection verified; unsigned previews are explicitly identified | Repository owner; these are account settings, not code assertions |
| First-run experience | Fresh install launches, shows honest empty/offline/sync state, creates one identity, and explains missing Lean/Python/sandbox with a working remediation | Native QA on both architectures |
| Daily native workflow | Post/test a challenge, start/pause/resume/stop a worker, observe an admitted and a refused receipt, and attach to a node with different verifier capabilities without showing local evidence | Native QA with temporary nodes |
| Lifecycle and recovery | Quit/reopen, background login service on/off, upgrade from the prior release (including re-registering/restarting its saved environment), data-directory move/backup/restore and uninstall preserve documented data/keys and never start a second writer on the same log | Native QA with copied data and backed-up keys |
| Release claims | Clearly identify Stage 0/single sequencer, optional hosted-provider disclosure, public lab scope, unverified compute offers and non-paying quotes; do not promise private confidential verification or external-currency payouts | Release notes and product copy |

A green PR is permission to integrate these fixes, not evidence that these
artifact and clean-machine gates have passed. Do not publish a general Mac
release with those rows left unverified.

## Follow-on work after this release

1. Add measured, workload-specific hardware calibration and provenance before
   using remote compute offers for billing. Treat clock/ISA premiums as explicit
   operator rate cards until then.
2. Design automatic frontier-triggered reapply and semantic integration as a
   separate collaboration feature. Preserve causal parents and exact input pins;
   a CRDT can converge metadata without deciding which algorithm is correct.
3. Add independent artifact signatures/attestations for Linux and reproducible
   binary comparisons. Pinning and same-server checksums are useful but do not
   establish an independent publisher identity.
4. Improve writer exclusivity and recoverable key-management ergonomics before
   presenting shared-folder use as supported. Current separate-replica and
   separate-key-backup instructions are operational requirements.
