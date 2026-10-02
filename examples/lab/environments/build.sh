#!/bin/sh
# Build a lab environment image from the recipe beside this script.
#
#   examples/lab/environments/build.sh numtheory
#   examples/lab/environments/build.sh sage        # builds numtheory first
#
# Then name it in a space (this copies the image's root filesystem into the
# lab and records its tree digest):
#
#   cairn lab env import NAME --docker cairn-lab/NAME:latest --identity ID
#
# Behind a TLS-re-terminating proxy, set HTTPS_PROXY and point CAIRN_BUILD_CA
# (or SSL_CERT_FILE) at the proxy's CA bundle; the build passes both through
# and runs on the host network so a proxy on 127.0.0.1 is reachable. Without
# them it is a plain `docker build`.
set -eu

name="${1:?usage: build.sh numtheory|sage}"
here="$(cd "$(dirname "$0")" && pwd)"
engine="${CAIRN_BUILD_ENGINE:-docker}"

set --
if [ -n "${HTTPS_PROXY:-${https_proxy:-}}" ]; then
    proxy="${HTTPS_PROXY:-${https_proxy:-}}"
    set -- "$@" --network host --build-arg "HTTPS_PROXY=$proxy" --build-arg "https_proxy=$proxy"
fi
ca="${CAIRN_BUILD_CA:-${SSL_CERT_FILE:-}}"
if [ -n "$ca" ] && [ -s "$ca" ]; then
    set -- "$@" --secret "id=ca,src=$ca"
fi

if [ "$name" = "sage" ]; then
    "$0" numtheory
fi

echo "building cairn-lab/$name from $here/$name"
DOCKER_BUILDKIT=1 "$engine" build "$@" -t "cairn-lab/$name:latest" "$here/$name"
echo
echo "next: cairn lab env import $name --docker cairn-lab/$name:latest --identity YOUR.identity.json"
