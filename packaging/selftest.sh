#!/usr/bin/env bash
# The parts of packaging/ that can be checked without building a package:
# everything that is plain shell logic rather than a call into dpkg, rpm or
# hdiutil.
#
#   packaging/selftest.sh
#
# Building and installing real packages needs a release binary, docker and a
# Mac, and is what a `workflow_dispatch` dry run of release.yml is for. That is
# minutes, and manual. This is a second, on any machine, on every pull request
# -- so a broken version mapping or a release-notes script that stacks copies
# of itself is caught by the PR that broke it, not by the next release.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=packaging/version.sh
. "$HERE/version.sh"
# shellcheck source=packaging/linux/common.sh
. "$HERE/linux/common.sh"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/cairn-packaging.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

failures=0
ok()  { echo "  ok    $*"; }
bad() { echo "  FAIL  $*" >&2; failures=$((failures + 1)); }

# -- versions -------------------------------------------------------------------
echo "version.sh"
expect_versions() { # input, deb, rpm, macos
    if ! cairn_versions "$1" 2>/dev/null; then
        bad "$1 was refused"
    elif [ "$DEB_VERSION" != "$2" ] || [ "$RPM_VERSION-$RPM_RELEASE" != "$3" ] || [ "$MACOS_PKG_VERSION" != "$4" ]; then
        bad "$1 -> deb $DEB_VERSION, rpm $RPM_VERSION-$RPM_RELEASE, macos $MACOS_PKG_VERSION (wanted $2, $3, $4)"
    else
        ok "$1 -> $2, $3, $4"
    fi
}
expect_refused() {
    if cairn_versions "$1" 2>/dev/null; then bad "'$1' was accepted"; else ok "'$1' refused"; fi
}
expect_versions v1.4.0               1.4.0-1                  1.4.0-1                  1.4.0
expect_versions 1.4.0                1.4.0-1                  1.4.0-1                  1.4.0
expect_versions v1.4.0-rc.1          "1.4.0~rc.1-1"           "1.4.0~rc.1-1"           1.4.0
expect_versions v2.0.0-alpha-2       "2.0.0~alpha.2-1"        "2.0.0~alpha.2-1"        2.0.0
# What release.yml calls a dry run. If this stops parsing, every dry run fails.
expect_versions 0.0.0-dispatch.17788 "0.0.0~dispatch.17788-1" "0.0.0~dispatch.17788-1" 0.0.0
expect_refused vNEXT
expect_refused 1.4
expect_refused "v1.4.0+build"
expect_refused "v1.4.0-"
expect_refused "feat/some-branch"

# The point of the tilde, checked against the real comparison where there is
# one to ask: a release candidate has to be *older* than the release.
if command -v dpkg >/dev/null 2>&1; then
    if dpkg --compare-versions "1.4.0~rc.1-1" lt "1.4.0-1"; then
        ok "dpkg sorts 1.4.0~rc.1-1 before 1.4.0-1"
    else
        bad "dpkg does not sort the release candidate before the release"
    fi
fi

# -- the ELF guards ---------------------------------------------------------------
echo "linux/common.sh"
# Twenty bytes is enough header for elf_arch: the magic, then e_machine at 18.
# `%b` takes its octal escapes as \0NNN, unlike a format string's \NNN.
elf_stub() { printf '\177ELF\002\001\001\000\000\000\000\000\000\000\000\000\003\000'; printf '%b' "$1"; }
elf_stub '\0076\0000' >"$WORK/amd64"
elf_stub '\0267\0000' >"$WORK/arm64"
elf_stub '\0363\0000' >"$WORK/riscv"
printf '#!/bin/sh\necho not a binary\n' >"$WORK/script"

expect_arch() {
    local got; got="$(elf_arch "$WORK/$1")"
    if [ "$got" = "$2" ]; then ok "elf_arch $1 -> $2"; else bad "elf_arch $1 -> $got (wanted $2)"; fi
}
expect_arch amd64  amd64
expect_arch arm64  arm64
expect_arch riscv  unknown-f300
expect_arch script not-elf

# In a subshell, because require_arch exits on a mismatch -- which is the
# behaviour under test.
if ( require_arch "$WORK/arm64" arm64 ) 2>/dev/null; then ok "an arm64 binary passes as arm64"; else bad "an arm64 binary was refused as arm64"; fi
if ( require_arch "$WORK/arm64" amd64 ) 2>/dev/null; then bad "an arm64 binary was packaged as amd64"; else ok "an arm64 binary is refused as amd64"; fi
if ( require_arch "$WORK/script" amd64 ) 2>/dev/null; then bad "a shell script was packaged as a binary"; else ok "a shell script is refused"; fi

# -- release notes ------------------------------------------------------------------
echo "release-notes.sh"
cat >"$WORK/changelog.md" <<'EOF'
## [1.4.0](https://example.invalid/compare/v1.3.0...v1.4.0) (2026-01-01)

### Features

* something that changed
EOF
cat >"$WORK/assets.txt" <<'EOF'
cairn-v1.4.0-macos-universal.dmg
cairn-v1.4.0-x86_64-unknown-linux-musl.tar.gz
cairn_1.4.0-1_amd64.deb
cairn_1.4.0-1_arm64.deb
cairn-1.4.0-1.x86_64.rpm
cairn-1.4.0-1.aarch64.rpm
install.sh
EOF
notes() { "$HERE/release-notes.sh" --tag v1.4.0 --repo example/cairn --print "$@"; }

notes --assets-file "$WORK/assets.txt" --body-file "$WORK/changelog.md" >"$WORK/once.md"
notes --assets-file "$WORK/assets.txt" --body-file "$WORK/once.md"      >"$WORK/twice.md"

if grep -q 'something that changed' "$WORK/once.md"; then ok "the changelog survives"; else bad "the changelog was dropped -- this is the v1.2.0 bug"; fi
if [ "$(sed -n '1p' "$WORK/once.md")" = "$(sed -n '1p' "$WORK/changelog.md")" ]; then ok "the changelog stays on top"; else bad "something was written above the changelog"; fi
if cmp -s "$WORK/once.md" "$WORK/twice.md"; then ok "building a tag twice writes the same page"; else bad "a second run changed the page; it would grow on every rebuild"; fi
if [ "$(grep -c 'cairn:install-notes' "$WORK/twice.md")" = "1" ]; then ok "one marker after two runs"; else bad "the install section stacked"; fi
if grep -q 'Not in this release' "$WORK/once.md"; then bad "a complete release was described as missing something"; else ok "a complete release names nothing as missing"; fi
for file in cairn-v1.4.0-macos-universal.dmg cairn_1.4.0-1_arm64.deb cairn-1.4.0-1.aarch64.rpm; do
    if grep -q "releases/download/v1.4.0/$file" "$WORK/once.md"; then ok "links $file"; else bad "no link to $file"; fi
done

# A release that went out short: the page must not link to what is not there.
grep -v 'arm64\.deb' "$WORK/assets.txt" >"$WORK/partial.txt"
notes --assets-file "$WORK/partial.txt" --body-file "$WORK/changelog.md" >"$WORK/partial.md"
if grep -q 'Not in this release:.*the arm64 \.deb' "$WORK/partial.md"; then ok "a missing package is named as missing"; else bad "a missing package went unmentioned"; fi
if grep -q '_arm64\.deb' "$WORK/partial.md"; then bad "the page links to a package the release does not have"; else ok "and is not linked to"; fi

# With no release text at all, which is what a dry run hands it.
notes --assets-file "$WORK/assets.txt" --body-file /dev/null >"$WORK/empty.md"
if [ "$(sed -n '1p' "$WORK/empty.md" | cut -c1-24)" = "<!-- cairn:install-notes" ]; then ok "an empty body yields just the install section"; else bad "an empty body is mishandled"; fi

# -- lint -------------------------------------------------------------------------
# Here as well as in CI's own step, so `make packaging-check` on a laptop and
# the pull request gate cannot come to mean different things.
echo "shellcheck"
if command -v shellcheck >/dev/null 2>&1; then
    # -x follows the `.` of version.sh and common.sh, so a variable one file
    # sets and another reads is checked rather than assumed.
    if ( cd "$HERE/.." && shellcheck -x \
            packaging/*.sh packaging/linux/*.sh packaging/macos/*.sh \
            && shellcheck -s sh packaging/macos/postinstall ); then
        ok "every script lints"
    else
        bad "shellcheck has complaints, above"
    fi
else
    echo "  --    shellcheck is not installed; skipped here, and CI will not skip it"
fi

echo
if [ "$failures" -eq 0 ]; then
    echo "packaging selftest: all passed"
else
    echo "packaging selftest: $failures failed" >&2
    exit 1
fi
