#!/usr/bin/env bash
# The signed feed Cairn.app's Check for Updates… reads (Sparkle's appcast).
#
#   packaging/macos/updates.sh generate-key | gh secret set CAIRN_UPDATES_KEY
#   CAIRN_UPDATES_KEY=... packaging/macos/updates.sh public-key       # Ed25519, for SUPublicEDKey
#   CAIRN_UPDATES_KEY=... packaging/macos/updates.sh pq-public-key    # ML-DSA-87, for CairnMLDSA87PublicKey
#   CAIRN_UPDATES_KEY=... packaging/macos/updates.sh appcast \
#       --dmg dist/cairn-v1.9.0-macos-universal.dmg --version v1.9.0 \
#       --repo aburan28/cairn [--notes-html notes.html] --out appcast.xml
#   packaging/macos/updates.sh verify --appcast appcast.xml --dmg <file> \
#       --public-key <base64> --pq-public-key <base64>
#
# Two signatures on every update, and the app installs nothing that fails
# either:
#
#   * Sparkle's own, Ed25519 over the .dmg (`sparkle:edSignature`). Sparkle
#     checks it against SUPublicEDKey and will not run without one.
#   * Ours, ML-DSA-87 (FIPS 204, NIST's post-quantum signature at its
#     strongest level) over the feed item's version, URL, length and that
#     Ed25519 signature (`cairn:mlDSA87Signature`). The app checks it before
#     it downloads anything, against CairnMLDSA87PublicKey.
#
# Why sign the Ed25519 signature rather than the image: Sparkle never hands
# the app the bytes it downloaded, so the app cannot check a second signature
# over them directly. But Ed25519 is deterministic and ends in SHA-512, so the
# one signature value that ML-DSA vouches for is a value no other image can
# carry without a SHA-512 collision -- and that stays out of reach of a
# quantum computer, which is the attacker the ML-DSA layer is there for. A
# forger with the Ed25519 private key still cannot make the app accept an
# image, because the signature on it is not the one ML-DSA signed.
#
# One secret, CAIRN_UPDATES_KEY: 32 random bytes, base64. Both signing keys are
# derived from it (SHA-256 under a label each, as the seed of each algorithm),
# release.yml writes both public halves into Cairn.app, and the app installs
# only an update signed by the keys it was built with.
#
# **Keep a copy of the key.** An app in the field trusts exactly the keys its
# release was built with. Lose or replace the secret and every installed copy
# refuses every later update, and each user has to install the next .dmg by
# hand once.
#
# Signing and checking need OpenSSL 3.5 or newer, the first with ML-DSA.
# macOS's LibreSSL has neither it nor Ed25519; Homebrew's openssl@3 has both,
# and release.yml runs this on a macOS runner for that reason. Set OPENSSL to
# point at one somewhere else. Making a key needs no OpenSSL at all.
set -euo pipefail

die() { echo "updates: $*" >&2; exit 1; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/cairn-updates.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# The ML-DSA signature covers this, with this context string (FIPS 204's
# domain separator), and gui/macos-app/Sources/Cairn/UpdateSignature.swift
# builds the same bytes from the feed item it was handed. Change one, change
# both, and the tests there, which hold a feed this script signed.
SIGNED_MESSAGE_HEADER="cairn-update/1"
SIGNATURE_CONTEXT="cairn-update"
FEED_NAMESPACE="https://github.com/aburan28/cairn/xml-namespaces/updates"

# PKCS#8 and SubjectPublicKeyInfo headers (RFC 8410, and the ML-DSA OID from
# FIPS 204's draft X.509 profile): the DER forms are these bytes followed by
# the raw key. OpenSSL reads and writes the same, which is how the raw keys
# in Info.plist and the feed get to and from it.
ED_PRIV_DER_PREFIX="302e020100300506032b657004220420"
ED_PUB_DER_PREFIX="302a300506032b6570032100"
PQ_PUB_DER_PREFIX="30820a32300b060960864801650304031303820a2100"
PQ_PUB_LEN=2592

hex_to_bin() { printf '%b' "$(sed 's/../\\x&/g')"; }
b64() { base64 | tr -d '\n'; }

# OpenSSL with ML-DSA: $OPENSSL, else Homebrew's, else whatever is on PATH.
find_openssl() {
    local candidates=()
    [ -n "${OPENSSL:-}" ] && candidates+=("$OPENSSL")
    if command -v brew >/dev/null 2>&1; then
        local prefix
        prefix="$(brew --prefix openssl@3 2>/dev/null || true)"
        [ -n "$prefix" ] && candidates+=("$prefix/bin/openssl")
    fi
    candidates+=(openssl)
    local c
    for c in "${candidates[@]}"; do
        if "$c" genpkey -algorithm ML-DSA-87 -out "$WORK/probe.pem" >/dev/null 2>&1; then
            OPENSSL="$c"
            return
        fi
    done
    die "need OpenSSL 3.5 or newer, which has ML-DSA (brew install openssl@3; or set OPENSSL=/path/to/openssl)"
}

# $CAIRN_UPDATES_KEY -> $WORK/ed.pem, $WORK/pq.pem
load_key() {
    find_openssl
    local key="${CAIRN_UPDATES_KEY:-}"
    [ -n "$key" ] || die "CAIRN_UPDATES_KEY is not set"
    printf '%s' "$key" | tr -d ' \n\r' | base64 -d >"$WORK/seed.bin" 2>/dev/null \
        || die "CAIRN_UPDATES_KEY is not base64"
    [ "$(wc -c <"$WORK/seed.bin" | tr -d ' ')" -eq 32 ] \
        || die "CAIRN_UPDATES_KEY decodes to $(wc -c <"$WORK/seed.bin" | tr -d ' ') bytes, not 32 (make one with \`$0 generate-key\`)"

    # Each algorithm's seed is a hash of the master seed under its own label:
    # neither can be told from the other's, and neither gives the master away.
    { printf 'cairn-updates/ed25519'; cat "$WORK/seed.bin"; } \
        | "$OPENSSL" dgst -sha256 -binary >"$WORK/ed-seed.bin"
    { printf 'cairn-updates/ml-dsa-87'; cat "$WORK/seed.bin"; } \
        | "$OPENSSL" dgst -sha256 -binary >"$WORK/pq-seed.bin"

    { printf '%s' "$ED_PRIV_DER_PREFIX" | hex_to_bin; cat "$WORK/ed-seed.bin"; } >"$WORK/ed.der"
    "$OPENSSL" pkey -inform DER -in "$WORK/ed.der" -out "$WORK/ed.pem" 2>/dev/null \
        || die "OpenSSL cannot make the Ed25519 key"
    # FIPS 204's key generation is a function of a 32-byte seed, so the same
    # seed gives the same key here and in any other conforming library.
    "$OPENSSL" genpkey -algorithm ML-DSA-87 -pkeyopt "hexseed:$(xxd -p -c 64 "$WORK/pq-seed.bin")" \
        -out "$WORK/pq.pem" 2>/dev/null \
        || die "OpenSSL cannot make the ML-DSA-87 key"
}

ed_public_key() {
    "$OPENSSL" pkey -in "$WORK/ed.pem" -pubout -outform DER | tail -c 32 | b64
}

pq_public_key() {
    "$OPENSSL" pkey -in "$WORK/pq.pem" -pubout -outform DER | tail -c "$PQ_PUB_LEN" | b64
}

xml_escape() { sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g'; }

# What the ML-DSA signature is over: one line each, in this order, as the
# strings stand in the feed. The app reads them back from the same feed.
signed_message() { # version url length edSignature
    printf '%s\nversion=%s\nurl=%s\nlength=%s\ned25519=%s\n' \
        "$SIGNED_MESSAGE_HEADER" "$1" "$2" "$3" "$4"
}

cmd_generate_key() {
    head -c 32 /dev/urandom | b64
    echo
}

cmd_public_key() {
    load_key
    ed_public_key
    echo
}

cmd_pq_public_key() {
    load_key
    pq_public_key
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
    local sig length name url pubdate
    sig="$("$OPENSSL" pkeyutl -sign -inkey "$WORK/ed.pem" -rawin -in "$dmg" | b64)"
    length="$(wc -c <"$dmg" | tr -d ' ')"
    name="$(basename "$dmg")"
    url="https://github.com/$repo/releases/download/$version/$name"
    pubdate="$(LC_ALL=C date -u '+%a, %d %b %Y %H:%M:%S +0000')"

    # Ours, over the item as the app will read it back.
    local pqsig
    signed_message "$MACOS_PKG_VERSION" "$url" "$length" "$sig" >"$WORK/message.bin"
    pqsig="$("$OPENSSL" pkeyutl -sign -inkey "$WORK/pq.pem" -rawin -in "$WORK/message.bin" \
        -pkeyopt "context-string:$SIGNATURE_CONTEXT" | b64)"

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
    # command and the app together. The URL is not escaped: a repository and
    # a tag hold nothing XML minds, and the app must see these exact bytes.
    cat >"$out" <<XML
<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle"
     xmlns:cairn="$FEED_NAMESPACE">
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
      <enclosure url="$url"
                 length="$length"
                 type="application/octet-stream"
                 sparkle:installationType="package"
                 sparkle:edSignature="$sig"/>
      <cairn:mlDSA87Signature>$pqsig</cairn:mlDSA87Signature>
    </item>
  </channel>
</rss>
XML
    echo "wrote $out for $name ($length bytes), signed by Ed25519 $(ed_public_key) and ML-DSA-87 $(pq_public_key | cut -c1-16)…"
}

# One attribute or element's text out of the feed, by the same literal
# reading the app does of the parsed item. The feed is this script's own
# output, one item, one line per field; sed is enough.
feed_field() { # file, sed expression
    sed -n "$2" "$1" | head -n 1
}

cmd_verify() {
    local appcast="" dmg="" pub="" pqpub=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --appcast)       appcast="$2"; shift 2 ;;
            --dmg)           dmg="$2"; shift 2 ;;
            --public-key)    pub="$2"; shift 2 ;;
            --pq-public-key) pqpub="$2"; shift 2 ;;
            *) die "verify: unknown argument $1" ;;
        esac
    done
    if [ ! -f "$appcast" ] || [ ! -f "$dmg" ] || [ -z "$pub" ] || [ -z "$pqpub" ]; then
        die "verify: --appcast, --dmg, --public-key and --pq-public-key are required"
    fi
    find_openssl
    local sig length url version pqsig
    sig="$(feed_field "$appcast" 's/.*sparkle:edSignature="\([^"]*\)".*/\1/p')"
    length="$(feed_field "$appcast" 's/.*length="\([0-9]*\)".*/\1/p')"
    url="$(feed_field "$appcast" 's/.*<enclosure url="\([^"]*\)".*/\1/p')"
    version="$(feed_field "$appcast" 's/.*<sparkle:version>\([^<]*\)<.*/\1/p')"
    pqsig="$(feed_field "$appcast" 's/.*<cairn:mlDSA87Signature>\([^<]*\)<.*/\1/p')"
    [ -n "$sig" ] || die "verify: no sparkle:edSignature in $appcast"
    [ -n "$pqsig" ] || die "verify: no cairn:mlDSA87Signature in $appcast"
    [ "$length" = "$(wc -c <"$dmg" | tr -d ' ')" ] || die "verify: the feed's length is not the image's"

    { printf '%s' "$ED_PUB_DER_PREFIX" | hex_to_bin; printf '%s' "$pub" | base64 -d; } >"$WORK/ed-pub.der"
    "$OPENSSL" pkey -pubin -inform DER -in "$WORK/ed-pub.der" -out "$WORK/ed-pub.pem"
    printf '%s' "$sig" | base64 -d >"$WORK/ed-sig.bin"
    "$OPENSSL" pkeyutl -verify -pubin -inkey "$WORK/ed-pub.pem" -rawin -in "$dmg" -sigfile "$WORK/ed-sig.bin" >/dev/null \
        || die "verify: the Ed25519 signature in $appcast does not match $dmg under that key"

    { printf '%s' "$PQ_PUB_DER_PREFIX" | hex_to_bin; printf '%s' "$pqpub" | base64 -d; } >"$WORK/pq-pub.der"
    [ "$(wc -c <"$WORK/pq-pub.der" | tr -d ' ')" -eq $((PQ_PUB_LEN + 22)) ] \
        || die "verify: --pq-public-key is not a $PQ_PUB_LEN-byte ML-DSA-87 key"
    "$OPENSSL" pkey -pubin -inform DER -in "$WORK/pq-pub.der" -out "$WORK/pq-pub.pem"
    printf '%s' "$pqsig" | base64 -d >"$WORK/pq-sig.bin"
    signed_message "$version" "$url" "$length" "$sig" >"$WORK/message.bin"
    "$OPENSSL" pkeyutl -verify -pubin -inkey "$WORK/pq-pub.pem" -rawin -in "$WORK/message.bin" \
        -sigfile "$WORK/pq-sig.bin" -pkeyopt "context-string:$SIGNATURE_CONTEXT" >/dev/null \
        || die "verify: the ML-DSA-87 signature in $appcast does not match its item under that key"
    echo "verified: $(basename "$dmg") is signed by Ed25519 $pub, and its feed item by ML-DSA-87 $(printf '%s' "$pqpub" | cut -c1-16)…"
}

case "${1:-}" in
    generate-key)  shift; cmd_generate_key "$@" ;;
    public-key)    shift; cmd_public_key "$@" ;;
    pq-public-key) shift; cmd_pq_public_key "$@" ;;
    appcast)       shift; cmd_appcast "$@" ;;
    verify)        shift; cmd_verify "$@" ;;
    --help|-h|"")  sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; [ -n "${1:-}" ] ;;
    *) die "unknown command: $1" ;;
esac
