# Installing cairn

Every route below installs the same thing: one binary, `cairn`, whose
subcommands (`run`, `mcp`, `p2p`, `serve`, `gen-bootstrap`, `seeds`, `arena`)
are the whole project. They differ in where they put it and in who you have to
be to run them.

| you have | use | it lands in | needs root |
|---|---|---|---|
| macOS, Apple Silicon or Intel | the [`.dmg`](#macos-the-disk-image) | `/usr/local/bin/cairn`, and `/Applications/Cairn.app` | yes |
| Debian 11+, Ubuntu 22.04+ | the [`.deb`](#debian-and-ubuntu-the-deb) | `/usr/bin/cairn` | yes |
| Fedora, RHEL / Alma / Rocky 9+ | the [`.rpm`](#fedora-and-the-rhel-family-the-rpm) | `/usr/bin/cairn` | yes |
| any Linux or macOS, or no root | the [install script](#anything-else-the-install-script) | `~/.local/bin/cairn` | no |
| a Rust toolchain and an opinion | [source](../README.md#install) | wherever `cargo` puts it | no |

All of them are on the [releases page](https://github.com/aburan28/cairn/releases/latest).
Windows is absent by decision, not oversight: the verifier sandbox is seatbelt
and bubblewrap, and a node that runs objective-authored code without one is the
configuration `CAIRN_REQUIRE_SANDBOX` exists to refuse.

**Pick one route per machine.** They install to different directories, and your
shell runs whichever comes first on `PATH` — see
[two copies](#two-copies-and-the-wrong-one-runs).

## What no route does

None of them starts a service, adds a login item, creates a user, or writes a
configuration file. They put a program on `PATH` and stop.

That is deliberate. A node keeps its state in the directory it is started from
(`.local/`, or wherever `--data-dir` and `$CAIRN_DATA` say) and its at-rest key
at `~/.cairn/key`, and it verifies objectives against a `--root` holding their
pinned code. Where those three live is the operator's decision, and a package
that guessed would be guessing about where your identity key goes. Removing a
package therefore removes the program and none of your data.

If you do want a node under systemd or launchd, run `cairn p2p --serve`, not
`cairn run`: `run` also speaks MCP on stdin and stops when stdin closes, which
under a service manager is immediately.

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
can run beside a `cairn run` of your own. **Node → Open in Browser** opens the
same page in your browser; **Node → Show Data Folder** and **Show Node Log**
are where to look when it will not start.

**macOS will refuse to open it the first time.** The installer is not signed
with an Apple Developer ID, because this project does not have one, so macOS
cannot say who made it and says that instead of opening it.

- **macOS 15 and later:** System Settings → Privacy & Security, scroll to
  *Security*, and click **Open Anyway** beside the message about the package.
- **macOS 14 and earlier:** Control-click the package, choose **Open**, then
  **Open** again.
- **Or from a terminal**, with no dialog at all:

  ```sh
  sudo installer -pkg "/Volumes/Cairn <version>/Install Cairn.pkg" -target /
  ```

The [install script](#anything-else-the-install-script) never meets that
dialog, because `curl` does not mark a download the way a browser does. If the
dialog bothers you more than piping a script to a shell does, use that.

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
