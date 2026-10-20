# Connection presentation and Windows portable node

This change separates a node's identity/status from the addresses its transport
uses. It also adds a Windows x64 executable and portable release package.

## User-facing behavior

- The web reader's source labels and status no longer use URLs as product
  identity. Status opens Diagnostics; Network and the command palette link to
  the same page. Diagnostics retains the actual source, listener endpoints,
  advertised URLs, peer endpoints and failure details.
- Network and the address book retain real peer IPs/ports and copy controls.
  Loopback and wildcard entries retain their peer identities but display
  `Local connection` / `Not advertised`, without offering those values to copy.
  IPv6, mapped IPv4, non-default ports and hostnames are covered.
- Native startup paths/URLs/log lines and listener details are collapsed.
  Shared Mac/iOS peer views use the same human-facing address policy. An owned
  Mac's wildcard IPv4 listener can share a concrete active interface with its
  actual bound port; loopback, stopped nodes and attached remote nodes never
  borrow a LAN address from the operator's computer.
- Manual agent commands are disclosed explicitly, primary agent status uses
  plain language, and the keyboard shortcut shows Ctrl K on Windows/Linux.
- First-run sharing guidance starts with local work and keeps port/bind commands
  behind Advanced network setup; the Windows browser check starts with a fresh
  browser profile and verifies this prompt too.

These are presentation changes. No bind, advertised record, peer identity,
admission rule, settlement rule or balance is rewritten by a label.

## Windows boundary and packaging

The Windows node embeds the reader and supports CLI/MCP, identity creation,
node reports, persistence/sync and in-process verification. Nonces use the OS
CSPRNG. Profile-based key/secret paths work without `HOME`; managed workers use
the platform's process APIs instead of unconditional Unix methods. Windows file
permissions inherit the containing directory's ACL; no Unix-mode guarantee is
claimed for a manually selected shared folder.

Windows always requires a qualified jail for objective-authored processes.
There is no native Windows backend yet, so those processes return `Unavailable`
even with `CAIRN_REQUIRE_SANDBOX=off`. Isolated lab execution needs a supported
Linux sandbox. This change does not add an execution proof or a Windows jail.

The native MSVC CI gate builds a static-CRT executable, tests canonical/crypto
and confinement/nonce behavior, packages/unpacks the ZIP and runs the actual
binary through identity, profile/secret, MCP, browser and persistent-restart
checks. Release dispatch adds the same Windows package/smoke path alongside the
existing Linux/macOS packages. Release notes link actual Windows assets and
name a missing ZIP rather than emitting a broken download link.

The ZIP contains `cairn.exe`, `Start Cairn.cmd`, README and license. It needs no
Rust, Node.js, administrator access, service or firewall change. The launcher
uses the user's Local AppData, checks its port before starting and opens the
reader in the browser. The package is unsigned; SHA-256 checks integrity, not
publisher identity. `.gitattributes` keeps pinned text/checker bytes LF on a
Windows checkout and the launcher CRLF in the package.

## Local verification

- 2,206 Rust tests passed with default features and with all features; formatting,
  clippy with warnings denied, all-feature rustdoc and MSRV 1.89 checks passed.
- Three reference runs passed (74 unit tests plus sealed fixtures), and all
  539 frozen vectors reproduced independently. Interop, differential and
  2,000 fuzz cases passed (seed 333516850). Existing CLI, ratchet, try and
  managed-work demos passed.
- 269 UI tests, typecheck and static production build passed. Browser acceptance
  covered 20 routes at 320/360/1280, including real IP preservation, hidden
  bind/loopback entries and Diagnostics, keyboard/modal recovery and posting.
- Shared Swift tests passed (11); changed native view sources parse with Swift
  6.2. Full native Mac/iOS compilation remains a CI gate.
- The preview x64 Windows PE was cross-built with LLVM-MinGW 20261006 and
  static CRT. Under Wine 10, 152 targeted Windows tests passed (confinement,
  canonical, crypto and nonces), and the real executable passed CLI, identity,
  profile-based secret storage, MCP framing, UI/network, mandatory-confinement
  and persisted-objective restart checks. Chromium exercised that Windows-served
  UI at three widths, Ctrl K and Diagnostics without browser exceptions.
- The PowerShell packager ran locally, including SHA-256 generation. Dependency
  audits passed. Native Windows CI, release dry-run packaging and full native
  Mac builds must pass on the final pushed head before integration; Wine is not
  a claim of clean-machine Windows installation QA. Signed/notarized Mac release
  and clean-Mac install/upgrade QA remain separate release gates.

No existing records, hashes, canonical encodings, reference implementation,
frozen conformance vectors, settlement or balance rules changed. The earlier
collaboration PRs and their stopped watchers were left alone.
