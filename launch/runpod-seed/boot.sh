#!/bin/bash
# What a cairn seed does inside the pod, as pid 1's script.
#
# A Runpod pod is a container, so launch/seed.service (a systemd unit for
# a machine) does not apply. The loop at the bottom is that unit's
# Restart=always. The binary is the musl release, checked against the
# published sha256, because compiling cairn on a 2-vCPU pod is most of
# the bill and a swapped download would be the seed.
#
# The public transport key is written to its own directory and served on
# 8090. The identity file holds the secret half and stays out of that
# directory; 8090 exists so the operator can take the public half without
# an SSH key, which is the same material GitHub Pages already serves.

set -euo pipefail

log() { printf 'cairn-seed: %s\n' "$*" >&2; }

export DEBIAN_FRONTEND=noninteractive
ver="${CAIRN_VERSION:-1.17.0}"
# Pinned. "latest" would let a bad release become the network's first hop
# the next time the pod restarts.
tarball="cairn-v${ver}-x86_64-unknown-linux-musl.tar.gz"
base="https://github.com/aburan28/cairn/releases/download/v${ver}"

workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT
curl -fsSL -o "$workdir/$tarball" "$base/$tarball"
curl -fsSL -o "$workdir/$tarball.sha256" "$base/$tarball.sha256"
(
  cd "$workdir"
  sha256sum -c "$tarball.sha256"
  tar -xzf "$tarball"
)
install -m 0755 "$workdir/cairn" /usr/local/bin/cairn
rm -rf "$workdir"
trap - EXIT
/usr/local/bin/cairn --version

if ! id cairn >/dev/null 2>&1; then
  useradd --system --home /var/lib/cairn --create-home --shell /bin/false cairn
fi
install -d -o cairn -g cairn -m 0750 /var/lib/cairn
install -d -o cairn -g cairn -m 0755 /var/lib/cairn/public-seed

# The bundle: the files an objective's pinned checkers live in. A node runs a
# checker from the path the objective pins, resolved against --root, and hashes
# the file against the pin first. --root defaults to the working directory, and
# a container's is usually /, which holds none of the repository: a seed
# started without a bundle answers every claim `unavailable` ("this node could
# not check", never "rejected"), so nothing gets verified or paid. The
# published log showed exactly that, 222 claims all answered
#   cannot load checker: No such file or directory (os error 2)
#   (/examples/certicom-ecdlp/checkers/ecc2k23_orbit_batch.py)
# See launch/seed.service, "The bundle", for the long version.
#
# Taken from the same release as the binary, so the two agree. It needs no
# checksum of its own: the node refuses any file that does not hash to the pin,
# so a bad download costs liveness and cannot change what runs. A failed fetch
# must not take the seed down either, since the log it holds and serves matters
# more than the checks; the daemon says how many pins are unmet when it starts
# (`verifier code: <n> servable, <m> unmet`).
bundle=/var/lib/cairn/bundle
install -d -o cairn -g cairn -m 0755 "$bundle"
if curl -fsSL "https://github.com/aburan28/cairn/archive/refs/tags/v${ver}.tar.gz" \
    | tar -xz -C "$bundle" --strip-components=1
then
  chown -R cairn:cairn "$bundle"
else
  log "bundle fetch failed; claims will answer unavailable until ${bundle} holds the repository"
fi

# A seed verifies objectives it did not write, so the code it now has the means
# to run (the bundle, and anything a peer sends that hashes to a pin) runs
# jailed or not at all: docs/configuration.md, "The two refusal switches".
# Where the container cannot build the jail this fails closed, every claim
# answers `unavailable`, and the daemon's startup line says `sandbox none`.
# That is the old behaviour, not a new one; it is safe, and it is the
# operator's call whether to relax it.
export CAIRN_REQUIRE_SANDBOX=1
if ! apt-get install -y -qq bubblewrap; then
  log "bubblewrap did not install; claims will answer unavailable until a jail works"
fi

export CAIRN_DATA=/var/lib/cairn
export CAIRN_LOG_LEVEL="${CAIRN_LOG_LEVEL:-info}"
# Off while this pod is a seed: dialing the published list includes
# itself, which is one timeout a minute. Same reason as seed.service.
export CAIRN_SEEDS=off
export CAIRN_BEACON_PORT=off
export CAIRN_PORTMAP=off
export CAIRN_ROLES="${CAIRN_ROLES:-relay}"

hosts="${CAIRN_HTTP_HOSTS:-}"
if [[ -n "${DDNS_HOST:-}" ]]; then
  hosts="${hosts:+$hosts,}${DDNS_HOST}"
elif [[ -n "${DUCKDNS_SUBDOMAIN:-}" && -n "${DUCKDNS_TOKEN:-}" ]]; then
  hosts="${hosts:+$hosts,}${DUCKDNS_SUBDOMAIN}.duckdns.org"
fi
export CAIRN_HTTP_HOSTS="$hosts"

python3 /usr/local/bin/cairn-ddns.py --watch &
ddns_pid=$!

cairn_loop() {
  while true; do
    # preserve-environment: runuser otherwise drops CAIRN_DATA and the
    # log lands in the user's home, which is the same directory only by
    # coincidence of --home.
    set +e
    runuser -u cairn --preserve-environment -- \
      /usr/local/bin/cairn --root "$bundle" run --no-mcp \
      --listen 0.0.0.0:9000 \
      --serve 0.0.0.0:8080
    code=$?
    set -e
    log "cairn exited ${code}; restarting in 5s"
    sleep 5
  done
}
cairn_loop &
loop_pid=$!

stop() {
  kill "$loop_pid" "$ddns_pid" "${key_pid:-}" 2>/dev/null || true
  wait "$loop_pid" 2>/dev/null || true
  exit 0
}
trap stop TERM INT

identity=/var/lib/cairn/node.identity.json
for _ in $(seq 1 60); do
  if [[ -f "$identity" ]]; then
    break
  fi
  sleep 2
done
if [[ ! -f "$identity" ]]; then
  log "identity did not appear; the public key is not being served"
else
  # A failed publish must not take the seed down with it. The node is the
  # thing other people dial; the key file is how we hand them the id.
  if ! runuser -u cairn --preserve-environment -- \
    /usr/local/bin/cairn seeds publish \
    --identity "$identity" \
    --out /var/lib/cairn/public-seed
  then
    log "seeds publish failed; the node stays up and 8090 will have no key"
  fi
  key=""
  for path in /var/lib/cairn/public-seed/*.key; do
    if [[ -f "$path" ]]; then
      key=$(basename "$path")
      break
    fi
  done
  if [[ -n "$key" ]]; then
    printf 'transport=%s\n' "${key%.key}" > /var/lib/cairn/public-seed/entry.txt
    chown cairn:cairn /var/lib/cairn/public-seed/entry.txt
    log "publish-entry-begin"
    cat /var/lib/cairn/public-seed/entry.txt >&2
    log "publish-entry-end"
  fi
fi

# Only the public-seed directory. python's http.server will list it;
# the identity file is not in it.
(
  cd /var/lib/cairn/public-seed
  exec python3 -m http.server 8090 --bind 0.0.0.0
) &
key_pid=$!

wait "$loop_pid"
