# A cairn seed on a cheap CPU pod

A seed is one `cairn run` and a published transport key.
It holds the log and lets two nodes that cannot see each other reconcile
through it. It does not use a GPU. Renting one to run it pays for a device
the process never opens.

This directory rents the smallest Runpod **CPU** pod that can do the job,
and keeps a **hostname** pointed at whatever address that pod has today.
The hostname is a dial hint. The peer id is `sha256` of the transport key,
so a wrong name fails the handshake and does not make a stranger into this
seed. That split is [docs/discovery.md](../../docs/discovery.md) and
[docs/p2p.md](../../docs/p2p.md), *Running a seed on a public host*.

On 2026-10-05 a connect to the published `us-west` seed
(`44.251.117.84:8080`) timed out from a cloud agent. This launcher does
not replace that entry. Nothing here is a seed until `cairn seeds publish`
has been reviewed into [`../seeds.json`](../seeds.json).

## What it rents

| | |
| --- | --- |
| Machine | CPU, 2 vCPU, general-purpose flavor first (`cpu3g`, then `cpu3c`, then `cpu5c`) |
| Cloud | Community, which is the cheaper tier and the one whose public IP moves |
| Disk | 10 GB container disk, **no volume** |
| Ports | `9000/tcp` p2p, `8080/tcp` HTTP, `8090/tcp` the public key only |
| Image | `ubuntu:24.04`, then the pinned musl release of `cairn` |
| Cap | Delete the pod if Runpod quotes more than **$0.10/hour** |

`volumeInGb` is sent as 0 and checked on the way back. The API's default
is 20 GB, and a volume keeps billing after the compute stops. Zero means
the container disk is wiped when the pod restarts, and the node identity
with it. A restart is a new peer. Publish again, or don't restart.

Two vCPUs is the smallest count that API documents (a power of two). The
binary is the release tarball, checked with the published sha256, so the
pod does not spend an hour compiling.

A full month, if you leave it running, is `costPerHr × 730`. At the cap
that is about $73, plus about $1 of container disk while it runs
($0.10/GB/month, not charged while stopped). `create.py` prints the quote
Runpod actually returned. A quote above the cap is deleted before the
summary, and the pod's id is in the error so you can see that it was
removed. Raise the cap with `CAIRN_SEED_MAX_USD_PER_HOUR` only when you
mean to.

Interruptible (spot) pods are cheaper and can be taken back at any moment.
A seed that is down costs every new node its first dial, which is why
[`../seed.service`](../seed.service) exists. Spot stays off unless you set
`CAIRN_SEED_INTERRUPTIBLE=1`.

## Why a hostname, on a different site

Community pods do not keep their public IP across a move. `launch/seeds.json`
is compiled into the binary (`src/p2p/seeds.rs`). An IP in that file is
stale for every node already built, and `make seeds` is the only refresh
that does not require a release. A hostname in the same file is resolved
when the node dials. Updating the DNS record updates the hint. The record
is not authority: [docs/discovery.md](../../docs/discovery.md) is why a
hostile answer costs one failed handshake.

The name has to live somewhere that is not this repository. GitHub Pages
serves the seed *list*; it does not host A records. Three updaters are in
[`ddns.py`](ddns.py), and the pod runs whichever you configured, every five
minutes:

| You have | Set | Name strangers dial |
| --- | --- | --- |
| Nothing yet | a free name at [DuckDNS](https://www.duckdns.org) | `<sub>.duckdns.org` |
| A zone on Cloudflare | `CF_API_TOKEN`, `CF_ZONE_ID`, `DDNS_HOST` | that hostname |
| A zone on Bunny | `BUNNY_ACCESS_KEY`, `BUNNY_ZONE_ID`, `DDNS_HOST` | that hostname |
| Some other dynamic DNS | `DDNS_UPDATE_URL` containing the literal `{ip}` | whatever that URL updates |

DuckDNS is the one that does not need a domain you bought. Sign in there,
create a subdomain (for example `cairn-seed`), and copy the token. The pod
calls `https://www.duckdns.org/update` when its address changes. The token
is a pod environment variable, not a file in this repository.

```sh
export DUCKDNS_SUBDOMAIN=cairn-seed
export DUCKDNS_TOKEN=...   # from duckdns.org, not committed
```

`aburan.com` is a different site from GitHub Pages. Its nameservers are
`ns3-1.cvtdns.com` and the zone SOA is `hostmaster.bunny.net`, so a record
such as `seed.aburan.com` is created in that DNS host, then kept current
by the Bunny updater (`DDNS_HOST=seed.aburan.com`). The record name sent to
Bunny is the first label (`seed`), not the full name. A name with more
than three labels is not guessed; set `BUNNY_RECORD_NAME`.

Cloudflare's proxy is forced **off**. The proxy is an HTTP middlebox, and
a p2p dial that lands on it looks like a dead seed. TTL is 60 seconds, so
a moved IP is stale for about a minute plus the five-minute check.

With no updater configured the pod still runs. The dial hint is then the
raw IP, and this script says so. Do not put that IP into `seeds.json` if
you can put a name there instead.

Runpod also offers `https://<pod-id>-<port>.proxy.runpod.net`. That name
follows the pod, and it is the wrong transport for this: it terminates
TLS, speaks HTTP, and closes idle connections around 100 seconds. p2p is
a long-lived TCP session on the mapped public port. The HTTP half is
mapped the same way (`8080/tcp`) so `node-sync` can `curl` it directly.

The external port is assigned by Runpod and **changes when the pod is
reset**. Combined with the wiped disk, a reset is a new seed: new key,
new port, new publish. Stopping without a volume deletes the machine.
`down.sh` is the way to stop paying.

## Launch

```sh
export RUNPOD_API_KEY=...          # https://console.runpod.io/user/settings
export DUCKDNS_SUBDOMAIN=cairn-seed
export DUCKDNS_TOKEN=...
python3 launch/runpod-seed/create.py --dry-run   # prints the request, rents nothing
python3 launch/runpod-seed/create.py
```

`--dry-run` needs no key. The real command refuses to start without
`RUNPOD_API_KEY` and prints `Nothing was rented`.

A cloud agent does not have that key unless it is set under Cursor
Dashboard → Cloud Agents → Secrets. The same launch is
`.github/workflows/seed-pod.yml`, run by hand (`workflow_dispatch`), which
reads `RUNPOD_API_KEY` from the repository's Actions secrets and the DNS
tokens from secrets of the same names. The pull-request half of that
workflow only runs the tests.

If a pod named `cairn-seed` already exists, another one is not rented.
A GPU pod of that name is refused rather than reused. `CAIRN_SEED_NAME`
picks a different name. `CAIRN_SEED_CLOUD=SECURE` asks for the stable-IP
tier, which costs more; the cap still applies.

The summary on stdout is safe to keep. It has the pod id, the quote, the
dial hint, and — once the node is answering — the path of the public key
it fetched. DNS tokens are not in that summary. `RUNPOD_API_KEY` is not
put in the pod's environment.

## Check it from somewhere else

`create.py` waits until `GET /health` on the mapped HTTP port returns
`ok`, then downloads the public key from port 8090 and checks that the
file's name is `sha256` of the bytes it decodes to. That is the same
check `cairn seeds resolve` makes. The key is public by design; 8090
serves only the directory the publish command wrote, not the identity
file.

From any other machine, with the host and ports from the summary:

```sh
curl -fsS "http://HOST:HTTP_PORT/health"    # ok
curl -fsS "http://IP:KEY_PORT/entry.txt"    # transport=<64 hex>
```

Port 8090 is reached by IP because the key download happens before you
need the name. p2p and the node HTTP port are what the hostname is for.

## Publish

`launch/runpod-seed/out/` (gitignored) holds `<transport>.key` and
`seeds-entry.json`. Copy the key to [`../seeds/`](../seeds/) under the
same name, and add the entry to [`../seeds.json`](../seeds.json). Put the
hostname in `addr` (`cairn-seed.duckdns.org:<mapped p2p port>`), not the
raw IP, when DuckDNS or another updater is configured. `http` is
`http://<same host>:<mapped http port>`.

Open a pull request with both. There is still no upload endpoint. A
reviewed change to the repository is what keeps the list replaceable by
someone other than whoever holds the server.

Then point `.github/workflows/node-sync.yml`'s `SEED_NODE` at that `http`
URL. It is a constant in the workflow on purpose: a job that mirrored
whatever `seeds.json` said would let an edit of that file aim a runner at
an arbitrary host. Change it in the same pull request that adds the seed,
once `curl` of `/health` has returned `ok`.

The pod logs the publish entry between `publish-entry-begin` and
`publish-entry-end` if you would rather read it there. The identity file
stays on the pod, in `/var/lib/cairn/node.identity.json`.

## Tear it down

```sh
export RUNPOD_API_KEY=...
python3 launch/runpod-seed/down.sh
```

That deletes the pod named `cairn-seed`. There is no volume to survive
it. The DuckDNS name keeps resolving to the old address until the token
stops updating it; a dial there fails the handshake, because the key that
hashed to the published id is gone with the disk. Remove the `seeds.json`
entry in the same breath, or every new node spends a dial timeout on it.

## What this does not do

- It does not make the hostname trusted. The hash decides.
- It does not replace the published `us-west` entry by itself.
- It does not keep the peer id across a restart. No volume was the point.
- It does not open the Runpod HTTP proxy. That proxy cannot carry p2p.
- It does not use spot capacity unless `CAIRN_SEED_INTERRUPTIBLE=1`.
- A missing `RUNPOD_API_KEY` rents nothing. There is no fallback account.
