#!/bin/sh
# Install cairn from a published release.
#
#   curl -fsSL https://raw.githubusercontent.com/aburan28/distributed-researcher/main/scripts/install.sh | sh
#
# What this does and does not prove
# ---------------------------------
# It downloads a tarball and the `.sha256` beside it and checks one against the
# other. That detects a truncated or corrupted download. It does **not**
# authenticate anything: both files come from the same server, so whoever could
# swap one could swap the other. There is no signing key here yet, and pretending
# otherwise would be worse than saying so.
#
# The real check is the one this project exists for, and it runs offline against
# bytes that ship in the repository rather than against a promise from a CDN:
#
#     cairn --log launch/cairn.jsonl --root . audit
#
# That re-derives every settled result. If it passes, the binary computes what
# the published log says it should, whoever served it to you.
#
# Environment
# -----------
#   CAIRN_VERSION   tag to install (default: latest release)
#   CAIRN_BIN       install directory (default: ~/.local/bin)
#   CAIRN_LIBC      on Linux, `musl` (default) or `gnu`
#
# Flags mirror the variables: --version, --bin-dir, --libc, --help.

set -eu

REPO="aburan28/distributed-researcher"
# One binary: `cairn mcp`, `cairn p2p`, `cairn serve` and `cairn gen-bootstrap`
# are subcommands of it, not executables of their own.
BINS="cairn"
# Names this project used to install, removed on upgrade. An MCP stanza written
# against an older release still spawns `cairn-mcp` by name, so leaving the old
# executable in place means the client keeps talking to the previous server and
# the operator believes they upgraded.
OBSOLETE_BINS="cairn-mcp cairn-p2p cairn-serve cairn-gen-bootstrap"

VERSION="${CAIRN_VERSION:-}"
BIN_DIR="${CAIRN_BIN:-}"
LIBC="${CAIRN_LIBC:-musl}"

die() { echo "install.sh: $*" >&2; exit 1; }
say() { echo "==> $*"; }

usage() {
    cat <<'EOF'
Install cairn from a published release.

USAGE
    install.sh [--version <tag>] [--bin-dir <dir>] [--libc musl|gnu]

    --version   release tag to install, e.g. v0.2.0 (default: latest)
    --bin-dir   where to put the binary (default: ~/.local/bin)
    --libc      on Linux, link against musl (static, default) or glibc

Prefer musl unless you have a reason not to: it links statically, so there is
no glibc version on the host to match. Use gnu if you need to dlopen something
from the same process.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --version) [ $# -ge 2 ] || die "--version needs a value"; VERSION="$2"; shift 2 ;;
        --bin-dir) [ $# -ge 2 ] || die "--bin-dir needs a value"; BIN_DIR="$2"; shift 2 ;;
        --libc)    [ $# -ge 2 ] || die "--libc needs a value";    LIBC="$2";    shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) usage >&2; die "unknown argument: $1" ;;
    esac
done

command -v curl >/dev/null 2>&1 || die "curl is required and was not found on PATH"
command -v tar  >/dev/null 2>&1 || die "tar is required and was not found on PATH"

# -- which build ------------------------------------------------------------

os="$(uname -s)"
arch="$(uname -m)"

case "$LIBC" in
    musl|gnu) ;;
    *) die "--libc must be musl or gnu, not '$LIBC'" ;;
esac

case "$os" in
    Linux)
        case "$arch" in
            x86_64|amd64)  target="x86_64-unknown-linux-$LIBC" ;;
            aarch64|arm64) target="aarch64-unknown-linux-$LIBC" ;;
            *) die "unsupported Linux architecture: $arch" ;;
        esac
        ;;
    Darwin)
        # No musl on macOS, and no choice of libc to make. Saying so beats
        # silently ignoring a flag the caller set on purpose.
        case "$arch" in
            arm64)  target="aarch64-apple-darwin" ;;
            x86_64) target="x86_64-apple-darwin" ;;
            *) die "unsupported macOS architecture: $arch" ;;
        esac
        ;;
    *)
        # Windows is absent from the release matrix by decision, not oversight:
        # the verifier sandbox is seatbelt and bubblewrap, and a node that runs
        # objective-authored code without one is the configuration
        # CAIRN_REQUIRE_SANDBOX exists to refuse.
        die "unsupported operating system: $os (this project ships Linux and macOS only)"
        ;;
esac

# -- which version ----------------------------------------------------------

if [ -z "$VERSION" ]; then
    say "resolving the latest release"
    # The asset names embed the tag, so the tag has to be known before a URL can
    # be built -- which rules out /releases/latest/download/<name> for them. The
    # redirect on /releases/latest carries it and needs no API token and no JSON
    # parser, so no jq and no rate limit.
    resolved="$(curl -fsSLI -o /dev/null -w '%{url_effective}' \
        "https://github.com/$REPO/releases/latest" 2>/dev/null)" \
        || die "cannot reach github.com to resolve the latest release"
    case "$resolved" in
        */releases/tag/*) VERSION="${resolved##*/}" ;;
        *) die "no published release found for $REPO (pass --version to pin one)" ;;
    esac
fi

name="cairn-$VERSION-$target"
base="https://github.com/$REPO/releases/download/$VERSION"

# -- download and check -----------------------------------------------------

tmp="$(mktemp -d)"
# Cleans up on failure too, which matters because the checksum check below is
# meant to exit before anything is installed.
trap 'rm -rf "$tmp"' EXIT INT TERM

say "downloading $name"
curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp/$name.tar.gz" "$base/$name.tar.gz" \
    || die "cannot download $base/$name.tar.gz
       If $VERSION is a real release, this platform may not be in its matrix."
curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp/$name.tar.gz.sha256" "$base/$name.tar.gz.sha256" \
    || die "cannot download the checksum for $name"

if command -v sha256sum >/dev/null 2>&1; then
    got="$(sha256sum "$tmp/$name.tar.gz" | cut -d' ' -f1)"
elif command -v shasum >/dev/null 2>&1; then
    got="$(shasum -a 256 "$tmp/$name.tar.gz" | cut -d' ' -f1)"
else
    die "neither sha256sum nor shasum is available; refusing to install unchecked bytes"
fi
want="$(cut -d' ' -f1 <"$tmp/$name.tar.gz.sha256")"

[ -n "$want" ] || die "the published checksum file is empty"
if [ "$got" != "$want" ]; then
    die "checksum mismatch for $name.tar.gz
       published $want
       computed  $got
       Nothing was installed."
fi
say "checksum ok"

# -- install ----------------------------------------------------------------

if [ -z "$BIN_DIR" ]; then
    BIN_DIR="$HOME/.local/bin"
fi

mkdir -p "$BIN_DIR" || die "cannot create $BIN_DIR"
[ -w "$BIN_DIR" ] || die "$BIN_DIR is not writable.
       Pick another with --bin-dir, or re-run with sudo if you meant a system path."

tar -C "$tmp" -xzf "$tmp/$name.tar.gz"

for bin in $BINS; do
    [ -f "$tmp/$bin" ] || die "the release tarball is missing $bin"
done
for bin in $BINS; do
    # install(1) is not on every minimal image; cp + chmod is.
    cp "$tmp/$bin" "$BIN_DIR/$bin.new" || die "cannot write to $BIN_DIR"
    chmod 755 "$BIN_DIR/$bin.new"
    # Rename last, so an interrupted install cannot leave a half-written binary
    # under a name somebody's service file already points at.
    mv "$BIN_DIR/$bin.new" "$BIN_DIR/$bin"
done

# Only after the new binary is in place: an interrupted install must never
# leave a directory with neither the old names nor the new one.
for bin in $OBSOLETE_BINS; do
    if [ -e "$BIN_DIR/$bin" ]; then
        rm -f "$BIN_DIR/$bin" || die "cannot remove the superseded $BIN_DIR/$bin"
        say "removed $BIN_DIR/$bin (now \`cairn ${bin#cairn-}\`)"
    fi
done

say "installed $VERSION ($target) to $BIN_DIR"

# -- what next --------------------------------------------------------------

case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *)
        echo
        echo "    $BIN_DIR is not on your PATH. Add it:"
        echo
        echo "        export PATH=\"$BIN_DIR:\$PATH\""
        echo
        ;;
esac

if [ "$os" = "Linux" ] && ! command -v bwrap >/dev/null 2>&1; then
    cat <<'EOF'
    bubblewrap is not installed. Without it, objective-authored verifier code
    runs unconfined. Install it (`apt install bubblewrap`, `dnf install
    bubblewrap`) and set CAIRN_REQUIRE_SANDBOX=1 on any node that verifies
    objectives it did not write -- that turns "unconfined" into Unavailable
    rather than running it anyway.

EOF
fi

cat <<EOF
    Check it before you trust it. This re-derives a real settled log:

        git clone https://github.com/$REPO
        cd distributed-researcher
        $BIN_DIR/cairn --log launch/cairn.jsonl --root . audit

EOF
