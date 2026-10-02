#!/usr/bin/env bash
# The signed feed Cairn.app's Check for Updates… reads (Sparkle's appcast).
#
#   packaging/macos/updates.sh generate-key | gh secret set SPARKLE_ED_PRIVATE_KEY
#   SPARKLE_ED_PRIVATE_KEY=... packaging/macos/updates.sh public-key
#   SPARKLE_ED_PRIVATE_KEY=... packaging/macos/updates.sh appcast \
#       --dmg dist/cairn-v1.9.0-macos-universal.dmg --version v1.9.0 \
#       --repo aburan28/cairn [--notes-html notes.html] --out appcast.xml
#   packaging/macos/updates.sh verify --appcast appcast.xml --dmg <file> --public-key <base64>
#
# One secret, SPARKLE_ED_PRIVATE_KEY, and everything else is derived from it:
# release.yml writes its public half into Cairn.app as SUPublicEDKey, and signs
# each release's .dmg with it. The app installs an update only if the
# signature in the feed matches the key it was built with.
#
# **Keep a copy of the key.** An app in the field trusts exactly one key, the
# one its release was built with. Lose or replace the secret and every
# installed copy refuses every later update, and each user has to install the
# next .dmg by hand once.
#
# The key is Ed25519, which is what Sparkle signs with, in either spelling:
# base64 of the 32-byte seed (what `generate-key` prints, and what Sparkle's
# own `generate_keys -x` exports), or a PEM private key from
# `openssl genpkey -algorithm ed25519`. Signing and checking need OpenSSL 3;
# Ubuntu has it, and macOS's LibreSSL does not, which is why release.yml does
# this on Linux. `generate-key` falls back to Swift's CryptoKit on a Mac.
set -euo pipefail

die() { echo "updates: $*" >&2; exit 1; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/cairn-updates.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# PKCS#8 and SubjectPublicKeyInfo headers for Ed25519 (RFC 8410): the DER
# forms are these bytes followed by the 32-byte seed or public key.
PRIV_DER_PREFIX="302e020100300506032b657004220420"
PUB_DER_PREFIX="302a300506032b6570032100"

have_openssl3() {
    openssl genpkey -algorithm ed25519 -out "$WORK/probe.pem" >/dev/null 2>&1
}

hex_to_bin() { printf '%b' "$(sed 's/../\\x&/g')"; }

# $SPARKLE_ED_PRIVATE_KEY -> $WORK/key.pem
load_key() {
    local key="${SPARKLE_ED_PRIVATE_KEY:-}"
    [ -n "$key" ] || die "SPARKLE_ED_PRIVATE_KEY is not set"
    if printf '%s' "$key" | grep -q -- '-----BEGIN'; then
        printf '%s\n' "$key" >"$WORK/key.pem"
    else
        printf '%s' "$key" | tr -d ' \n\r' | base64 -d >"$WORK/seed.bin" 2>/dev/null \
            || die "SPARKLE_ED_PRIVATE_KEY is neither a PEM key nor base64"
        [ "$(wc -c <"$WORK/seed.bin" | tr -d ' ')" -eq 32 ] \
            || die "SPARKLE_ED_PRIVATE_KEY decodes to $(wc -c <"$WORK/seed.bin" | tr -d ' ') bytes, not a 32-byte Ed25519 seed. (A key exported by Sparkle before 2.0 is 96 bytes and cannot be used; make a new one with \`$0 generate-key\`.)"
        { printf '%s' "$PRIV_DER_PREFIX" | hex_to_bin; cat "$WORK/seed.bin"; } >"$WORK/key.der"
        openssl pkey -inform DER -in "$WORK/key.der" -out "$WORK/key.pem" 2>/dev/null \
            || die "OpenSSL cannot read that key (it needs OpenSSL 3 for Ed25519)"
    fi
    openssl pkey -in "$WORK/key.pem" -noout -text 2>/dev/null | grep -q 'ED25519' \
        || die "SPARKLE_ED_PRIVATE_KEY is not an Ed25519 key"
}

public_key() {
    openssl pkey -in "$WORK/key.pem" -pubout -outform DER | tail -c 32 | base64 | tr -d '\n'
}

xml_escape() { sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g'; }

cmd_generate_key() {
    if have_openssl3; then
        openssl pkey -in "$WORK/probe.pem" -outform DER | tail -c 32 | base64 | tr -d '\n'
        echo
        return
    fi
    command -v swift >/dev/null 2>&1 \
        || die "need OpenSSL 3 (brew install openssl@3) or Swift (xcode-select --install) to make a key"
    cat >"$WORK/gen.swift" <<'SWIFT'
import CryptoKit
print(Curve25519.Signing.PrivateKey().rawRepresentation.base64EncodedString())
SWIFT
    swift "$WORK/gen.swift"
}

cmd_public_key() {
    load_key
    public_key
    echo
}

cmd_appcast() {
    local dmg="" version="" repo="" notes="" out=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --dmg)        dmg="$2"; shift 2 ;;
            --version)    version="$2"; shift 2 ;;
            --repo)       repo="$2"; shift 2 ;;
            --notes-html) notes="$2"; shift 2 ;;
            --out)        out="$2"; shift 2 ;;
            *) die "appcast: unknown argument $1" ;;
        esac
    done
    [ -f "$dmg" ] || die "appcast: --dmg names no file: $dmg"
    if [ -z "$version" ] || [ -z "$repo" ] || [ -z "$out" ]; then
        die "appcast: --version, --repo and --out are required"
    fi

    # shellcheck source=packaging/version.sh
    . "$(cd "$(dirname "$0")/.." && pwd)/version.sh"
    cairn_versions "$version"

    load_key
    # Sparkle checks a signature over the whole file, exactly as served.
    local sig length name pubdate
    sig="$(openssl pkeyutl -sign -inkey "$WORK/key.pem" -rawin -in "$dmg" | base64 | tr -d '\n')"
    length="$(wc -c <"$dmg" | tr -d ' ')"
    name="$(basename "$dmg")"
    pubdate="$(LC_ALL=C date -u '+%a, %d %b %Y %H:%M:%S +0000')"

    local description=""
    if [ -n "$notes" ] && [ -s "$notes" ]; then
        # CDATA cannot hold its own terminator; split it if the notes do.
        description="<description><![CDATA[$(sed 's/]]>/]]]]><![CDATA[>/g' "$notes")]]></description>"
    else
        description="<sparkle:releaseNotesLink>https://github.com/$repo/releases/tag/$version</sparkle:releaseNotesLink>"
    fi

    # sparkle:version is compared with the installed CFBundleVersion, which
    # build-dmg.sh sets to the same MACOS_PKG_VERSION. installationType
    # "package" because the image holds an installer, not an app: Sparkle
    # runs it with an administrator's authorization, and it replaces the
    # command and the app together.
    cat >"$out" <<XML
<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle">
  <channel>
    <title>Cairn</title>
    <link>https://github.com/$repo/releases</link>
    <item>
      <title>Cairn $(printf '%s' "$UPSTREAM_VERSION" | xml_escape)</title>
      <pubDate>$pubdate</pubDate>
      <sparkle:version>$MACOS_PKG_VERSION</sparkle:version>
      <sparkle:shortVersionString>$(printf '%s' "$UPSTREAM_VERSION" | xml_escape)</sparkle:shortVersionString>
      <sparkle:minimumSystemVersion>13.0</sparkle:minimumSystemVersion>
      $description
      <enclosure url="https://github.com/$repo/releases/download/$version/$name"
                 length="$length"
                 type="application/octet-stream"
                 sparkle:installationType="package"
                 sparkle:edSignature="$sig"/>
    </item>
  </channel>
</rss>
XML
    echo "wrote $out for $name ($length bytes), signed by $(public_key)"
}

cmd_verify() {
    local appcast="" dmg="" pub=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --appcast)    appcast="$2"; shift 2 ;;
            --dmg)        dmg="$2"; shift 2 ;;
            --public-key) pub="$2"; shift 2 ;;
            *) die "verify: unknown argument $1" ;;
        esac
    done
    if [ ! -f "$appcast" ] || [ ! -f "$dmg" ] || [ -z "$pub" ]; then
        die "verify: --appcast, --dmg and --public-key are required"
    fi
    local sig length
    sig="$(sed -n 's/.*sparkle:edSignature="\([^"]*\)".*/\1/p' "$appcast")"
    length="$(sed -n 's/.*length="\([0-9]*\)".*/\1/p' "$appcast")"
    [ -n "$sig" ] || die "verify: no sparkle:edSignature in $appcast"
    [ "$length" = "$(wc -c <"$dmg" | tr -d ' ')" ] || die "verify: the feed's length is not the image's"
    { printf '%s' "$PUB_DER_PREFIX" | hex_to_bin; printf '%s' "$pub" | base64 -d; } >"$WORK/pub.der"
    openssl pkey -pubin -inform DER -in "$WORK/pub.der" -out "$WORK/pub.pem"
    printf '%s' "$sig" | base64 -d >"$WORK/sig.bin"
    openssl pkeyutl -verify -pubin -inkey "$WORK/pub.pem" -rawin -in "$dmg" -sigfile "$WORK/sig.bin" >/dev/null \
        || die "verify: the signature in $appcast does not match $dmg under that key"
    echo "verified: $(basename "$dmg") is signed by $pub"
}

case "${1:-}" in
    generate-key) shift; cmd_generate_key "$@" ;;
    public-key)   shift; cmd_public_key "$@" ;;
    appcast)      shift; cmd_appcast "$@" ;;
    verify)       shift; cmd_verify "$@" ;;
    --help|-h|"") sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; [ -n "${1:-}" ] ;;
    *) die "unknown command: $1" ;;
esac
