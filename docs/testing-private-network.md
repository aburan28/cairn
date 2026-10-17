# Private deployment testing

Private-network coverage has two layers. The normal Rust and Vitest suites test
policy, authentication and recovery state. The packaged-reader browser acceptance
is opt-in: it starts disposable native nodes and requires an actual embedded
reader, not just the `ui` build feature. It does not replace normal CI checks.

## Requirement-to-test coverage

| Requirement | Behavior checked | Check |
|---|---|---|
| Invalid configuration fails closed | Unknown and non-Unicode profiles, open or malformed private peering, and external Google sign-in are refused. Occupied listener ports and discovery helper traps make premature binding/probing observable. Expected refusal processes have deadlines, so an accidentally started server fails instead of hanging the suite. | Normal `tests/private_network.rs`: `invalid_configuration_is_refused_before_binding_or_running_discovery`, `a_non_unicode_profile_is_not_treated_as_the_public_default`, and existing refusal tests |
| Ambient public settings cannot weaken private policy | Public seed refresh URL, beacon and port-map settings are present; private startup still permits zero peers, reports mappings off, runs no curl/Tailscale helper, and rejects a real unknown peer. | Normal `private_leader_has_zero_peers_and_runs_no_public_discovery_helpers` |
| Explicit local discovery works | A malformed named seed file refuses startup and can be repaired without replacing identity. A local seed list connects an allowed identity while an excluded seed's TCP trap receives no connection. | Normal `an_invalid_local_seed_file_can_be_repaired_without_replacing_identity`, `explicit_local_seeds_dial_only_allowed_identities` |
| Peer identity is pinned, not inferred from an address | Two mutually bootstrapped nodes establish authenticated sessions. An impostor occupying the expected endpoint fails; restoring the original identity recovers connectivity, including after restarting the other peer. Identity and bootstrap bytes remain unchanged. | Normal `explicitly_bootstrapped_private_nodes_reach_each_other`, `pinned_peer_identity_survives_impostor_failure_and_restart` |
| Existing fleet credentials survive recovery | Signed member registration works before and after restart; anonymous use of its reserved name and a signature for another leader fail. Live revocation is observed and remains effective after another restart. Leader/member/transport/root-key files are unchanged. | Normal `private_fleet_credentials_and_revocation_survive_process_restarts` |
| Public operation remains available | Public mode retains open peer policy and its optional tailnet probe; the probe is a local trapped helper, not an external service. Public setup commands and recovery remain unchanged. | Normal Rust public-mode test, `ui/lib/deployment.test.ts`, and `ui/components/GetOnline.test.tsx` |
| Dismissal does not disable explicit recovery | Actual component buttons dismiss the automatic prompt, preserve that preference across remount, and reopen it repeatedly through the persistent trigger, in private/public modes and when storage is blocked. | Normal Vitest `ui/components/GetOnline.test.tsx` |
| Packaged reader contains usable assets | Version/startup readiness requires nonempty root HTML and JavaScript in the compiled table. Empty, partial and populated tables have normal unit coverage. Acceptance separately fetches real HTML and a nonempty local JavaScript bundle, with `no-store`; headless/missing-export binaries fail its preflight. | Normal `serve` readiness and CLI version tests; opt-in `npm run test:private-browser` |
| Private health failure cannot select a public seed | Browser health is forced to fail while the actual local empty seed-list response is used. Private guidance is shown, repeated explicit recovery works, and every attempted external request is recorded and fails acceptance. Public-mode HTML and guidance are checked separately. | Opt-in packaged-reader acceptance |

This is behavioral coverage, not a whole-project line or branch percentage.
No Rust coverage instrumentation tool or Vitest coverage provider is configured
in this repository. Test counts do not establish a numeric coverage percentage.
The matrix deliberately names requirements and their boundaries instead.

## Running the checks

Run the normal suites with the repository's supported Rust and Node toolchains:

```sh
cargo test --locked --all-targets
cargo test --locked --all-features --test private_network
cd ui
npm ci
npm test
npm run build
cd ..
cargo build --locked --features ui
```

Then run the packaged-reader acceptance against that exact binary:

```sh
CAIRN_BIN="$PWD/target/debug/cairn" npm --prefix ui run test:private-browser
```

Playwright must have a browser installed. `CAIRN_BROWSER_PATH` can select an
existing Chromium executable. `CAIRN_UX_NO_SANDBOX=1` is available only for an
isolated test executor that requires it; normal environments should retain the
browser sandbox. The acceptance creates its own temporary data directories and
nodes, never attaches to a production node, and keeps an `acceptance.json` report
in the printed temporary directory on failure. Expected rejection of headless or
missing-asset builds should be recorded as a negative check, not counted as a
passing reader acceptance run.

Default-feature Cargo checks can replace `target/debug/cairn` with a headless
binary. Preserve a validated embedded binary before those checks or rebuild with
`--features ui` afterward. `cairn --version` checks that compiled HTML and
JavaScript exist, but does not establish that they load and work together;
the packaged-browser acceptance verifies that separately.

The remaining checks in `AGENTS.md` still apply, including the independent
reference tests/conformance, formatting, clippy, strict rustdoc, interop and
differential checks. No test may be skipped or weakened to turn a failure green.

## Regression evidence

The recovery test was run against the original component: both private and
public dismissal/reopen cases failed. The actual previously embedded reader
also timed out reopening through its persistent trigger. The corrected component
passes these same tests; the storage-unavailable case remains covered too.

The existing broader `scripts/reader-ux.py` acceptance exposed a separate test
precondition: selecting an objective file does not wait for its asynchronous
read. One run captured an empty original pin, then mistook the loaded fixture's
real checker checksum for a late-file mutation. A single baseline replay passed;
that is not evidence of a reproducible baseline failure. A temporary diagnostic
control isolated the missing readiness barrier. The tracked browser harness now
waits for the actual loaded-objective note and original fixture checksum, then
asserts that exact pin before holding the second file's digest. All existing
authorization assertions remain in place; the Submit page is unchanged. The diagnostic is
separate from running the actual broader acceptance with the corrected harness.

Reader readiness is checked in three actual build configurations: default
headless, `ui` enabled with the export absent, and a complete embedded export.
The first two must reject `run` and browser preflight; the missing-export case
also proves refusal precedes binding an occupied port or creating node state.
The complete export must pass the real browser acceptance. Private policy tests
run in every configuration: source-only builds exercise the shared daemon via
`p2p`, and a complete embedded build exercises the combined `run` entry point.

The full native suite retains its existing ignored logging child helper. Its
parent test explicitly invokes that helper with `--ignored`; this change adds
no ignored tests. The three normal UI lifecycle cases and all native private
deployment cases run in their regular suites.

The 2026-10-17 follow-up verification recorded:

| Check | Result |
|---|---|
| Full normal Rust suite | 2,183 passed, zero failures |
| Private native scenarios | 13 passed with the feature-only empty table and with the complete embedded reader; readiness/version unit checks also passed |
| Normal UI suite | 244 passed across 29 files |
| Reference suite and frozen conformance | 74 tests passed on each of three runs; 539 vectors reproduced independently |
| Formatting, clippy and strict all-feature rustdoc | Passed |
| Interop, curated differential and random differential | Passed; 2,000 random values agreed, seed `429788226` |
| CLI demos | Demo, ratchet and try demos passed |
| UI installation and build | Locked installation, typecheck, production export, Node syntax and dependency audit passed; zero reported vulnerabilities |
| Packaged browsers | New private/public recovery acceptance and the actual corrected broader `scripts/reader-ux.py` command passed |

## Limits

These tests use loopback sockets and real Cairn authentication. They do not
establish WireGuard kernel routing, gateway forwarding, NAT traversal, firewall
denial policy, physical air-gap isolation, or enterprise workspace permissions.
Validate those separately on the deployment's real interfaces and policy.
