#!/usr/bin/env bash
# Write the "how to install this" half of a release's page, under the
# changelog release-please already put there.
#
#   packaging/release-notes.sh --tag v1.4.0              # edit the release
#   packaging/release-notes.sh --tag v1.4.0 --print      # show it, change nothing
#
# Two rules, and each is here because the release page has broken the other way.
#
# It appends; it never replaces. release-please writes what changed, and that
# is the half a reader came for. The six-way build matrix used to pass `body:`
# to the upload action, which replaces, so the first target to finish erased
# the changelog: v1.2.0's page says how to install it and not one word about
# what it is. Everything from MARK down is this script's and is rewritten on
# every run, so building a tag twice does not stack two copies; everything
# above MARK is never touched.
#
# It describes the assets that exist, not the ones that should. The table is
# generated from the release's actual file list. `fail-fast: false` means a
# release can legitimately go out missing one package, and notes written from
# a template would then link to a 404 and tell an operator to install it. This
# repository has done the equivalent before -- `gen-bootstrap` was left out of
# a tarball while the shipped README told operators to run it. A missing
# package is named as missing instead.
#
# --assets-file and --body-file stand in for the two `gh` calls, so the text
# can be generated and read without a release, a token or a network.
set -euo pipefail

die() { echo "release-notes: $*" >&2; exit 1; }

MARK='<!-- cairn:install-notes -- everything from here down is rewritten by packaging/release-notes.sh each time this tag is built -->'

TAG="" REPO="${GITHUB_REPOSITORY:-aburan28/cairn}" PRINT=0 SIGNED=0 ASSETS_FILE="" BODY_FILE=""
while [ $# -gt 0 ]; do
    case "$1" in
        --tag)          [ $# -ge 2 ] || die "--tag needs a value";         TAG="$2";         shift 2 ;;
        --repo)         [ $# -ge 2 ] || die "--repo needs a value";        REPO="$2";        shift 2 ;;
        --assets-file)  [ $# -ge 2 ] || die "--assets-file needs a value"; ASSETS_FILE="$2"; shift 2 ;;
        --body-file)    [ $# -ge 2 ] || die "--body-file needs a value";   BODY_FILE="$2";   shift 2 ;;
        --macos-signed) SIGNED=1; shift ;;
        --print)        PRINT=1; shift ;;
        --help|-h)      sed -n '2,6p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done
[ -n "$TAG" ] || die "--tag is required"

if [ -n "$ASSETS_FILE" ]; then
    assets="$(cat "$ASSETS_FILE")"
else
    assets="$(gh release view "$TAG" --repo "$REPO" --json assets --jq '.assets[].name')"
fi
if [ -n "$BODY_FILE" ]; then
    body="$(cat "$BODY_FILE")"
else
    body="$(gh release view "$TAG" --repo "$REPO" --json body --jq '.body')"
fi

BASE="https://github.com/$REPO/releases/download/$TAG"

# The one asset matching a pattern, or nothing. Names are matched rather than
# computed because a package's file name follows its own format's rules for a
# version -- `1.4.0-1`, `1.4.0~rc.1` -- and re-deriving them here would be a
# second copy of version.sh that could come to disagree with the first.
asset() { printf '%s\n' "$assets" | grep -E "$1" | head -n 1 || true; }

DMG="$(asset '^cairn-.*-macos-universal\.dmg$')"
DEB_AMD64="$(asset '^cairn_.*_amd64\.deb$')"
DEB_ARM64="$(asset '^cairn_.*_arm64\.deb$')"
RPM_X86="$(asset '^cairn-.*\.x86_64\.rpm$')"
RPM_ARM="$(asset '^cairn-.*\.aarch64\.rpm$')"
INSTALLER="$(asset '^install\.sh$')"

missing=""
note_missing() { missing="$missing${missing:+, }$1"; }
[ -n "$DMG" ]       || note_missing "the macOS disk image"
[ -n "$DEB_AMD64" ] || note_missing "the amd64 .deb"
[ -n "$DEB_ARM64" ] || note_missing "the arm64 .deb"
[ -n "$RPM_X86" ]   || note_missing "the x86_64 .rpm"
[ -n "$RPM_ARM" ]   || note_missing "the aarch64 .rpm"
[ -n "$INSTALLER" ] || note_missing "install.sh"

row() { # label, file, what to do with it
    # shellcheck disable=SC2016  # the backticks are Markdown, not a command
    [ -z "$2" ] || printf '| %s | [`%s`](%s/%s) | %s |\n' "$1" "$2" "$BASE" "$2" "$3"
}

install_notes() {
    echo "$MARK"
    echo
    echo "## Install"
    echo
    echo "| you have | download | then |"
    echo "|---|---|---|"
    row "**macOS** — Apple Silicon or Intel" "$DMG" "open it and run *Install Cairn.pkg*"
    row "**Debian 11+, Ubuntu 22.04+** — amd64" "$DEB_AMD64" "\`sudo apt install ./$DEB_AMD64\`"
    row "**Debian 11+, Ubuntu 22.04+** — arm64" "$DEB_ARM64" "\`sudo apt install ./$DEB_ARM64\`"
    row "**Fedora, RHEL / Alma / Rocky 9+** — x86_64" "$RPM_X86" "\`sudo dnf install ./$RPM_X86\`"
    row "**Fedora, RHEL / Alma / Rocky 9+** — aarch64" "$RPM_ARM" "\`sudo dnf install ./$RPM_ARM\`"
    if [ -n "$INSTALLER" ]; then
        # The pipe is escaped because this is a table cell, and GitHub splits
        # cells on a bare one even inside a code span.
        echo "| anything else, or no root | — | \`curl -fsSL https://github.com/$REPO/releases/latest/download/install.sh \\| sh\` |"
    fi
    echo

    if [ -n "$missing" ]; then
        echo "**Not in this release:** $missing. That part of the build failed, and the rest"
        echo "went out rather than wait for it${GITHUB_RUN_ID:+; [the run](https://github.com/$REPO/actions/runs/$GITHUB_RUN_ID) says why}."
        echo
    fi

    cat <<EOF
Every route installs the same one binary, \`cairn\`. The CLI, the MCP server
(\`cairn mcp\`), the p2p daemon (\`cairn p2p\`), the HTTP publisher
(\`cairn serve\`), the bootstrap generator (\`cairn gen-bootstrap\`) and the
complete local node (\`cairn run\`) are all subcommands of it. No route
installs a service or creates a user: a node keeps its state wherever you
start it. [docs/install.md](https://github.com/$REPO/blob/$TAG/docs/install.md)
covers upgrading, removing, and what to do when two routes have both been used.

EOF

    if [ -n "$DEB_AMD64$DEB_ARM64$RPM_X86$RPM_ARM" ]; then
        cat <<EOF
**The Linux packages** wrap the static musl build byte for byte, so they have
no library dependencies and one file covers every release of a distribution.
They *recommend* \`bubblewrap\` and \`python3\` — the jail that
objective-authored verifier code runs in, and the language most verifiers are
written in — and your package manager installs those unless you have told it
not to.

EOF
    fi

    if [ -n "$DMG" ]; then
        if [ "$SIGNED" -eq 1 ]; then
            cat <<EOF
**The macOS installer** is signed with an Apple Developer ID and notarized, and
puts \`cairn\` at \`/usr/local/bin/cairn\`.

EOF
        else
            cat <<EOF
**The macOS installer is not signed**, because this project has no Apple
Developer ID, so macOS will refuse to open it the first time. The \`README.txt\`
in the disk image says how to allow it on each macOS version, and how to
install from a terminal instead. \`install.sh\` never meets that dialog: curl
does not mark a download the way a browser does.

EOF
        fi
    fi

    cat <<EOF
**The install script** detects the platform, downloads the right tarball,
checks it against the published \`.sha256\`, and installs to \`~/.local/bin\`.
Pin a version or a directory with \`--version\` / \`--bin-dir\`; on Linux it
takes the static musl build unless you pass \`--libc gnu\`.

| tarball | target |
|---|---|
| Linux amd64 | \`x86_64-unknown-linux-gnu\`, \`…-musl\` (static) |
| Linux arm64 | \`aarch64-unknown-linux-gnu\`, \`…-musl\` (static) |
| macOS Apple Silicon | \`aarch64-apple-darwin\` |
| macOS Intel | \`x86_64-apple-darwin\` |

By hand, if you would rather not pipe a script to a shell:

\`\`\`sh
tar -xzf cairn-$TAG-<target>.tar.gz
sha256sum -c cairn-$TAG-<target>.tar.gz.sha256
./cairn --help
\`\`\`

**A checksum beside a download proves neither came from us** — the same server
serves both, and that is as true of a \`.deb\` as of a tarball. It detects
corruption, not substitution, and nothing here is signed by a key of ours. The
check that means something runs offline, against bytes in the repository, and
re-deriving them is the point of the whole project:

\`\`\`sh
git clone https://github.com/$REPO && cd $(basename "$REPO")
cairn --log launch/cairn.jsonl --root . audit
cairn --log launch/cairn.jsonl --root . verify \\
    --from launch/checkpoint.json --root-key launch/root-key.pub --audit
\`\`\`
EOF
}

# What release-please wrote: everything above MARK, or all of it on a first
# run. `awk` exits at the marker rather than deleting a range, so a marker
# that somehow appears twice cannot leave the text between them behind.
changelog="$(printf '%s\n' "$body" | awk -v mark="$MARK" '$0 == mark { exit } { print }')"

OUT="$(mktemp "${TMPDIR:-/tmp}/cairn-packaging.XXXXXX")"
trap 'rm -f "$OUT"' EXIT
{
    # `$(...)` has already dropped the trailing blank lines, so re-running
    # does not grow the gap above the marker by one line each time.
    if [ -n "$changelog" ]; then printf '%s\n\n' "$changelog"; fi
    install_notes
} >"$OUT"

if [ "$PRINT" -eq 1 ]; then
    cat "$OUT"
else
    gh release edit "$TAG" --repo "$REPO" --notes-file "$OUT" >/dev/null
    echo "release-notes: wrote the install section of $TAG${missing:+ (missing: $missing)}"
fi
