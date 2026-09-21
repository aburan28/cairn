# packaging

What turns a tested `cairn` binary into something a person can double-click or
`apt install`. For *using* the results, see [docs/install.md](../docs/install.md);
this page is for whoever has to change or debug them.

```
version.sh              one release version -> each format's spelling of it (sourced)
release-notes.sh        the "Install" half of a release page, under the changelog
selftest.sh             everything here that can be checked without building a package
linux/common.sh         the guards both Linux builders apply to a binary (sourced)
linux/build-deb.sh      binary -> .deb            (needs dpkg-deb)
linux/build-rpm.sh      binary -> .rpm            (needs rpmbuild), from linux/cairn.spec
linux/verify.sh         install a package in a clean container and hold it to its claims
linux/verify-inside.sh  ...the half of that which runs inside the container
macos/build-dmg.sh      binaries -> universal binary -> installer .pkg -> .dmg
macos/verify-dmg.sh     mount it, take the installer apart, run what is inside
macos/postinstall       the one script any package here runs as root
macos/distribution.xml, resources/, dmg-README.txt, gatekeeper-*.txt   the installer's text
```

`release.yml` calls these; so do `make dmg`, `make deb` and `make rpm`. One code
path, so "it built on my machine" and "it built in the release" are the same
claim.

## The one rule: package the binary that was tested

Nothing here compiles. `release.yml`'s `build` job makes each tarball, unpacks
it, and proves that binary serves the reader, answers MCP and audits the
published log. The package jobs download *those tarballs* and wrap the binary
inside. `linux/verify.sh` then installs the package and compares the digest of
`/usr/bin/cairn` to the input, so "byte-identical to what was tested" is
checked, not intended. A packager that ran its own `cargo build` would ship a
second binary nothing had exercised.

macOS is the exception and says so: `lipo` wraps two binaries in a fat header
and `codesign` re-signs the result, so those are not the tested bytes.
`macos/verify-dmg.sh` runs the binary out of the finished image instead — both
slices, the Intel one under Rosetta where there is one.

## Decisions, and where each is argued

Each is a comment at the point it bites. In short:

| decision | because | argued in |
|---|---|---|
| Linux packages wrap the **musl** build and declare no `Depends` | a package states its dependencies, and the glibc build depends on a libc newer than most targets. The builders refuse a binary with a `PT_INTERP` | `linux/common.sh` |
| `bubblewrap` and `python3` are **Recommends**, not Depends | a node wants both; `check`, `prove`, `verify` and `audit --no-rerun` need neither | `linux/build-deb.sh` |
| `.deb` is **xz**, `.rpm` payload is **gzip**, both explicit | Ubuntu's `dpkg-deb` defaults to zstd, which Debian 11 cannot open; rpm's default depends on whose rpm it is. Both builders assert the result | `linux/build-deb.sh`, `linux/cairn.spec` |
| **no maintainer scripts** in the `.deb` or `.rpm`, enforced | installing one runs nothing as root. `docs/threat-model.md` relies on it, so the builders fail if one appears | both builders |
| **no systemd unit, no user, no config** | where a node's log, identity key and `--root` live is the operator's decision, and this project has never specified a system deployment. Also `cairn run` exits when stdin closes | `docs/install.md` |
| the `.dmg` holds an **installer .pkg**, not an app to drag | cairn is a command and needs to be on `PATH`; `gui/macos` drives a source checkout and would open onto failed setup checks | `macos/build-dmg.sh` |
| the payload goes to **`/usr/local/cairn`**, linked from `/usr/local/bin` by a script | `pkgbuild` writes `overwrite-permissions="true"` and records `usr/local/bin` as `root:wheel`, which breaks Homebrew on Intel Macs | `macos/postinstall` |
| **dpkg-deb, rpmbuild, pkgbuild, hdiutil** and nothing third-party | a static file and two documents do not need a build system, and a tool fetched at release time is one more party whose bytes end up in a release | `linux/build-deb.sh` |
| no Alpine, Arch, Homebrew, apt or dnf **repository** | each needs a signing key or a second repository to publish into; the musl tarball and `install.sh` already cover those systems | — |

## Trying a change

```sh
make packaging-check          # a second, anywhere: versions, guards, release notes, shellcheck
make dmg                      # on a Mac: builds and verifies a single-architecture image
make deb    make rpm          # on Linux: needs the musl target, musl-tools, and docker to verify
```

Then, for anything that touches this directory or `release.yml`, **dispatch a
dry run**: Actions → release → *Run workflow*, on your branch. It builds all six
targets, both packages on both architectures, the universal image, installs
every one of them on a clean machine, and publishes nothing. The run's summary
shows the release page the next tag would get. It is the only thing that runs
`verify-dmg.sh --install`, which needs a disposable Mac.

`make packaging-check` is also CI's `packaging` job. Mind that the runner's
shellcheck (0.9.0) is older than Homebrew's and objects to things that one lets
through.

## What has and has not been run

Said here because a release pipeline is exactly the code that is never run
until the moment it matters.

**Run, on real systems, before this was merged:** both Linux builders under
Ubuntu 24.04's `dpkg-deb` 1.22.6 and `rpmbuild` 4.18.2, for both architectures;
the `.deb` installed by `apt` on Debian 12 and Ubuntu 24.04 and the `.rpm` by
`dnf` on AlmaLinux 9 and Fedora, each auditing the launch log and removing
cleanly; the `.deb` opened and run on Debian 11; byte-for-byte reproducibility
of both packages with the build time pinned; the universal `.dmg` built and
verified on macOS 26, Intel slice under Rosetta; every guard fired on purpose
at least once (wrong architecture, glibc binary, smuggled `postinst` and
`%post`, a binary with no reader, a version the binary does not report).

**Not run until the first dry run:** the workflow YAML itself, which
`actionlint` passes but nothing has executed; `verify-dmg.sh --install`, and
with it the two claims only a real install can test — that `/usr/local/bin`
keeps its owner, and that `sudo installer` accepts the unsigned package from a
terminal; and the dispatch step in `release-please.yml`, which can only fire
when a release is actually cut.

**Never run, and will not be until there is a certificate:** Developer ID
signing and notarization, below.

## Signing the macOS installer

Unsigned is how every release has been built. Gatekeeper stops a user who
double-clicks the package, and the README inside the image tells them what to
do. Fixing that needs a paid Apple Developer ID. With one, add these repository
secrets and the `macos-dmg` job signs the binary, the package and the image,
then notarizes and staples the image:

| secret | what |
|---|---|
| `MACOS_CERTIFICATES_P12` | base64 of one `.p12` holding **both** the *Developer ID Application* and *Developer ID Installer* identities |
| `MACOS_CERTIFICATES_PASSWORD` | that file's password |
| `MACOS_CODESIGN_IDENTITY` | `Developer ID Application: NAME (TEAMID)` |
| `MACOS_INSTALLER_IDENTITY` | `Developer ID Installer: NAME (TEAMID)` |
| `MACOS_NOTARY_KEY_P8` | base64 of an App Store Connect API key |
| `MACOS_NOTARY_KEY_ID`, `MACOS_NOTARY_ISSUER` | that key's id and issuer |

All or none: `build-dmg.sh` refuses a partial set, because a signed package
that was never notarized is blocked exactly like an unsigned one and looks
finished. **Dry-run it before tagging.** It is Apple's and GitHub's documented
sequence and nothing has ever executed it.

## Known edges

- **A pre-release tag's packages get renamed by GitHub.** `v1.4.0-rc.1` becomes
  `1.4.0~rc.1` in a package version — the tilde is what makes it sort *before*
  1.4.0 — and GitHub replaces characters like `~` in asset names when they are
  uploaded. The file still installs and the release notes link whatever name it
  ended up with, but its `.sha256` names the original, so `sha256sum -c` will
  not find it. release-please cuts no pre-releases today, so this has not
  happened.
- **The images are not reproducible.** The `.deb` and `.rpm` are, given the
  same binary. `codesign` and `hdiutil` both stamp the `.dmg`.
- **A release can go out short.** `fail-fast: false` is deliberate, each job
  publishes its own assets, and the notes name whatever is missing. Re-running
  the failed job uploads it; the `notes` job then needs re-running too.
