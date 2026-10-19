# Installing cairn

Every route below installs the same thing: one binary, `cairn`, whose
subcommands (`run`, `mcp`, `p2p`, `serve`, `gen-bootstrap`, `seeds`, `arena`)
are the whole project. They differ in where they put it and in who you have to
be to run them.

| you have | use | it lands in | needs root |
|---|---|---|---|
| macOS, Apple Silicon or Intel | the [`.dmg`](#macos-the-disk-image) | `/usr/local/bin/cairn`, and `/Applications/Cairn.app` | yes |
| Windows 10/11, x64 | the [portable ZIP](#windows-the-portable-zip) | the folder you extract it to | no |
| Debian 11+, Ubuntu 22.04+ | the [`.deb`](#debian-and-ubuntu-the-deb) | `/usr/bin/cairn` | yes |
| Fedora, RHEL / Alma / Rocky 9+ | the [`.rpm`](#fedora-and-the-rhel-family-the-rpm) | `/usr/bin/cairn` | yes |
| any Linux or macOS, or no root | the [install script](#anything-else-the-install-script) | `~/.local/bin/cairn` | no |
| Windows 10 2004+ or 11 | the [PowerShell script](#windows-through-wsl-2), which uses WSL 2 | `~/.local/bin/cairn` inside WSL | no |
| a Rust toolchain and an opinion | [source](../README.md#install) | wherever `cargo` puts it | no |

All of them are on the [releases page](https://github.com/aburan28/cairn/releases/latest).
There is no native Windows build, by decision, not oversight: the verifier
sandbox is seatbelt and bubblewrap, and a node that runs objective-authored code
without one is the configuration `CAIRN_REQUIRE_SANDBOX` exists to refuse. On
Windows the Linux release runs inside WSL 2, which has a real Linux kernel and
so the real jail. Native Windows packages include the node and web reader, but
external verifier programs require a qualified sandbox; Windows reports
`Unavailable` instead of executing them without confinement, even with
`CAIRN_REQUIRE_SANDBOX=off`.

**Pick one route per machine.** They install to different directories, and your
shell runs whichever comes first on `PATH` — see
[two copies](#two-copies-and-the-wrong-one-runs).

## Windows: the portable ZIP

Download `cairn-<version>-x86_64-pc-windows-msvc.zip`, verify its adjacent
`.sha256`, and extract the whole ZIP to a folder you own. Open **Start Cairn.cmd**
to start a local node and open the reader. Close the node console to stop it.
Your data remains in `%LOCALAPPDATA%\Cairn`; restarting reopens it. Nothing
adds a service, login item or firewall exception.

`cairn.exe` embeds the UI and works directly from PowerShell, for example
`.\cairn.exe --help` or `.\cairn.exe mcp`. If the launcher's default port is
occupied it refuses to start another node; the packaged README explains how to
select another port. Keep state and secrets in your own user profile, not a
shared folder. The portable package is unsigned; the checksum establishes
download integrity, not an Authenticode publisher signature.

The native Windows CI gate builds and unpacks the ZIP, tests OS entropy and
mandatory confinement, and exercises the actual executable's CLI, MCP, embedded
UI, network reports and persistent restart. External objective programs need a
supported verifier host; isolated lab experiments require a supported Linux
sandbox.

## What installation does

None of them starts a service, adds a login item, creates a user, or writes a
configuration file. Native packages and the install script put a program on
`PATH`; the Windows ZIP stays in the folder you choose.

That is deliberate. A node keeps its state in the directory it is started from
(`.local/`, or wherever `--data-dir` and `$CAIRN_DATA` say) and its at-rest key
at `~/.cairn/key`, and it verifies objectives against a `--root` holding their
pinned code. Where those three live is the operator's decision, and a package
that guessed would be guessing about where your identity key goes. Removing a
package therefore removes the program and none of your data.

If you do want a node under systemd or launchd, run `cairn run --no-mcp` (or
`cairn p2p --serve`): plain `run` also speaks MCP on stdin and stops when stdin
closes, which under a service manager is immediately. Units that do it are in
[`launch/`](../launch/): `seed.service` for a public seed, and
[`fleet/`](../launch/fleet/) for a leader and its workers
([fleet.md](fleet.md)). On a Mac, Cairn.app installs a per-user launchd agent
when you ask it to (Settings → *Keep the node running in the background*) and
removes it when you ask again; nothing installs one behind your back.

The one exception is explicit and yours to invoke: `sudo cairn agent install
--node http://node:8080` writes a systemd unit for the **host agent** -- the
process that registers this machine's CPUs, memory and GPUs with a node and
runs executor jobs under gVisor or Kata -- together with its environment file,
a system user and a data directory, and enables it. No package does that;
the command does, after you ran it, and `--print` shows the unit first.
[agent.md](agent.md).

## macOS: the disk image

Download `cairn-<version>-macos-universal.dmg`, open it, and run
**Install Cairn.pkg**. One image covers Apple Silicon and Intel.

It installs the program to `/usr/local/cairn/bin/cairn` and links it from
`/usr/local/bin/cairn`, which is on every Mac's default `PATH`. Open a *new*
terminal window and run `cairn --version`.

It also installs **Cairn.app** to `/Applications`: a window onto a node. Open
it and it runs `cairn run` on that same program, waits for the node to come up
and shows its reader; quit it and the node stops. It is the one exception to
[what no route does](#what-no-route-does) below, in one respect: an app has no
directory you started it from, so its node keeps its log, keys and queue in
`~/Library/Application Support/Cairn`. It uses the command line's ports,
8080 and 9000, when they are free and any free ones when they are not, so it
can run beside a `cairn run` of your own. P2P listens on loopback by default
(dial out, nothing dials in); Settings can bind every interface and attach
bootstrap files so the node reaches peers past the LAN. **Node → Open in
Browser** opens the same page in your browser; **Node → Show Data Folder**,
**Show Node Log** and **Copy Peer Id** are where to look when it will not
start or when someone else is adding this node.

**Check the release's signing status before installing.** The release pipeline
supports Apple Developer ID signing and notarization when the release
environment has the required credentials. A build without them is unsigned;
an available download alone is not evidence that Apple checked it. Public
Mac releases should identify their signing/notarization status in the release
notes and pass Gatekeeper on a freshly downloaded copy.

If macOS reports an unidentified developer or a damaged package, stop and check
the release notes and publisher. Do not switch to a shell installer to bypass
that warning. An unsigned development preview requires a separate, explicit
trust decision. Maintainers can inspect an installer with
`pkgutil --check-signature`, assess it with `spctl --assess --type install -vv`,
and validate stapled notarization with `xcrun stapler validate` on the app and
disk image. These checks complement the release's SHA-256 checksum; a checksum
served beside an artifact does not independently establish its publisher.

Cairn.app requires its verifier sandbox in both foreground and background
mode. Settings → Verifiers shows whether this node can actually verify. A
missing sandbox or interpreter makes verification unavailable until repaired;
it does not mean the submitted result is wrong. When attached to another node,
the same screen reports that node's capabilities and isolation policy.
After upgrading an existing background login service, use **Restart Node to
Require Sandbox** in that screen (or the app's Restart Node action) once. This
rewrites the service's stored environment; closing and reopening its window
does not restart the service.

To remove it:

```sh
sudo rm -rf /usr/local/cairn /usr/local/bin/cairn /Applications/Cairn.app
sudo pkgutil --forget org.cairn.cli
sudo pkgutil --forget org.cairn.app
```

That leaves the app's node in `~/Library/Application Support/Cairn`, identity
included; delete it too only if you mean to.

<details>
<summary>Why it installs to <code>/usr/local/cairn</code> and not straight into <code>/usr/local/bin</code></summary>

macOS's installer applies the owner and mode recorded in a package to every
directory the package names, including ones that already exist. A package
carrying `usr/local/bin/cairn` also carries `usr/local/bin` as `root:wheel`,
and installing it resets that directory. On an Intel Mac with Homebrew,
`/usr/local/bin` belongs to you, because that is where `brew` links things;
after such a package it belongs to root and the next `brew install` fails on
permissions. So the program goes in a directory nothing else uses, and the link
is made by a script that does not touch the directory it writes into. The
release build installs the package on a real Mac and checks `/usr/local/bin` is
unchanged afterwards.

</details>

## Debian and Ubuntu: the .deb

```sh
sudo apt install ./cairn_<version>-1_amd64.deb      # or _arm64.deb
```

Through `apt` rather than `dpkg -i`, so the recommended packages come too.

The package is the static musl build, so it depends on nothing and one file
covers every release. It *recommends* two packages, which `apt` installs unless
you have told it not to:

- **`bubblewrap`** — the jail objective-authored verifier code runs in. Without
  it that code runs unconfined; set `CAIRN_REQUIRE_SANDBOX=1` on any node that
  verifies objectives it did not write, which turns "unconfined" into
  `unavailable` instead of running it anyway.
- **`python3`** — what most pinned verifiers are written in. Without it
  `cairn audit` on the published launch log reports four claims it "can no
  longer re-verify".

They are recommendations and not requirements because `cairn check`, `prove`,
`verify` and `audit --no-rerun` run no verifier at all, and a light client that
only checks proofs should not have to install an interpreter to do it.

`dpkg --verify cairn` checks the installed binary against the package's own
record. To remove: `sudo apt remove cairn`.

The release build installs this package on **Debian 12** and **Ubuntu 24.04**
and audits the launch log with it. It is compressed with xz rather than the
zstd that Ubuntu's tools default to, specifically so that Debian 11's older
`dpkg` can open it; that was checked by hand and is not tested on every
release.

## Fedora and the RHEL family: the .rpm

```sh
sudo dnf install ./cairn-<version>-1.x86_64.rpm     # or .aarch64.rpm
```

The same static binary, the same two weak dependencies, for the same reasons.
`dnf` will note that it skipped OpenPGP checks: the package is not signed, and
[that is true of every route here](#what-a-checksum-does-and-does-not-prove).
To remove: `sudo dnf remove cairn`.

The release build installs this package on **AlmaLinux 9** and the current
**Fedora**, and audits the launch log with it.

**RHEL 8 and its rebuilds:** the package installs and `cairn` runs, but
`python3` there is 3.6 and the verifiers in this repository need 3.9, so
`cairn audit` reports the launch log's Python claims as unavailable. Install a
newer Python (`dnf install python39`) and make `python3` resolve to it, or use
RHEL 9. RHEL 7 cannot read the package at all.

**openSUSE:** untested. `zypper install --allow-unsigned-rpm` should work, and
nobody has checked.

## Anything else: the install script

```sh
curl -fsSL https://github.com/aburan28/cairn/releases/latest/download/install.sh | sh
```

Detects the platform, downloads the matching tarball, checks it against the
published `.sha256`, and installs to `~/.local/bin` with no root. `--version`
pins a release, `--bin-dir` picks another directory, and on Linux `--libc gnu`
takes the dynamically linked build instead of the static one. This is the route
for Alpine, Arch, NixOS, a machine you do not administer, and a CI job. To
remove: `rm ~/.local/bin/cairn`.

On Linux it tells you if `bubblewrap` is missing; it cannot install it for you.

## Windows, through WSL 2

```powershell
irm https://github.com/aburan28/cairn/releases/latest/download/install.ps1 | iex
```

Needs Windows 10 version 2004 or newer, or Windows 11. It finds a WSL 2 Linux
distribution (your default one, or `CAIRN_WSL_DISTRO`), runs the Linux
[install script](#anything-else-the-install-script) inside it, installs
`bubblewrap` as root so there is no `sudo` prompt, checks that the jail can be
created, and offers to start a node with `CAIRN_REQUIRE_SANDBOX=1`. The reader
is then a normal browser tab at <http://127.0.0.1:8080/ui/>; WSL 2 forwards
`localhost` to Windows.

If WSL has no distribution, run `wsl --install -d Ubuntu` in an Administrator
PowerShell (the script offers to when it is elevated), restart if asked, finish
Ubuntu's first-run setup, and run the command again. A WSL 1 distribution is
refused: it has no namespaces to jail verifiers in
(`wsl --set-version <name> 2`). `CAIRN_VERSION` pins a release and
`CAIRN_START=no` installs without starting.

Start it again later with
`wsl -d Ubuntu --cd ~ -- env CAIRN_REQUIRE_SANDBOX=1 .local/bin/cairn run`. The
node's state is in the distribution's home directory (`~/.local`, and the key at
`~/.cairn/key`), not under `C:\`; it is reachable from Explorer at
`\\wsl.localhost\Ubuntu\home`. Removing is `wsl -d Ubuntu -- rm ~/.local/bin/cairn`.
The node is not a Windows service: it runs while that window is open, and WSL
may stop an idle distribution.

## A cloud workspace: install it and dial the seed

```sh
scripts/cloud-setup.sh              # install, start a node, dial the seed, report
scripts/cloud-setup.sh install      # install only
```

For an ephemeral Linux container (a Claude cloud workspace was the case it was
written for) where there is no one to run `install.sh`, answer a package
prompt, or start a service. It needs only `curl` and `tar`, so it can be
fetched and run on its own. It installs the latest release's static build to
`~/.cairn/bin` after checking its `.sha256`, creates a signing identity, fetches
the repository at that release as the `--root` that pinned checkers resolve
against (without one every claim a node is asked to check answers
`unavailable`), installs `bubblewrap` where it can and sets
`CAIRN_REQUIRE_SANDBOX=1`, then starts `cairn run` with the seed list built into
the binary and prints who it reached. `install` alone starts nothing and does not
fail when the seed is unreachable, which is what makes it safe as an environment
setup script: a setup script that exits non-zero breaks every new session.

**It can only use the network the environment gives it.** Such a container
reaches the internet through a proxy, and when this was written only outbound
port 443 got through, while a seed's p2p port is not 443. The script's
preflight says which it is: it tests the seed, then tests other live non-web
ports, and reports a blocked port as a blocked port rather than as a seed that
is down. A node started where nothing outbound reaches the seed runs, retries
once a minute, and has no peers. `--require-seed` turns that into a non-zero
exit. The script posts nothing, funds nothing and submits no claim.

## Python

Both verifiers the published launch log pins need **Python 3.9 or later**, and
the rest of `examples/` is written the same way: they annotate with built-in
generics (`def check(artifact: dict) -> tuple[bool, str]`), which Python
evaluates when the function is defined and which is a `TypeError` before 3.9.
Measured, not assumed — the audit fails under 3.7 and 3.8 and passes under 3.9.

That is `python3` on Debian 11+, Ubuntu 22.04+, Fedora, RHEL 9+ and any current
macOS with the command line tools. It is *not* `python3` on Ubuntu 20.04 (3.8)
or RHEL 8 (3.6).

This is a fact about those verifiers and not about cairn: an objective pins
whatever code its author wrote. A verifier that cannot run is `unavailable`,
never `reject` — an old interpreter makes your node unable to check a claim, it
does not make the claim wrong.

## Upgrading

There is no apt or dnf repository, so nothing upgrades itself. Download the new
package and install it the same way; `apt`, `dnf` and the macOS installer all
treat a newer version as an upgrade. Re-run the install script to have it fetch
the latest.

## Two copies, and the wrong one runs

Each route installs somewhere different, so using two leaves two binaries, and
`cairn` means whichever your shell finds first. The usual case: the install
script was used once, `~/.local/bin` is early on `PATH`, and a package installed
later appears to have done nothing.

```sh
type -a cairn        # every copy, in the order your shell finds them
cairn --version      # which one actually ran
```

Remove the one you did not mean. An MCP client configured with an absolute path
keeps launching that path whatever `PATH` says, so check the client's stanza
too — `scripts/mcp-config.sh` writes one.

## What a checksum does and does not prove

Every download has a `.sha256` beside it. It comes from the same server as the
file, so it detects a corrupted download and nothing else: whoever could swap
one could swap both. Nothing here is signed by a key of this project's — not
the tarballs, not the packages, and not the macOS installer — and saying
otherwise would be worse than saying this.

The check that means something is the one this project exists for. It runs
offline, against bytes in the repository rather than a promise from a CDN:

```sh
git clone https://github.com/aburan28/cairn && cd cairn
cairn --log launch/cairn.jsonl --root . audit
```

If it passes, the binary computes what the published log says it should,
whoever served it to you. The release build runs exactly that with the binary
out of every package, after installing it on a clean machine.
