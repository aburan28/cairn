# Two nodes, two places

The walk-through for the first thing anyone tries after `cairn run` works on
one machine: a second node, somewhere else, and the two of them reconciling.
It is written for the three arrangements that come up, in the order they get
harder, and it ends with how to read whether it worked — which is the part
that was missing, because for a long time the honest answer to "are we
connected" was "read the log and guess".

One fact shapes everything below. The handshake authenticates the **key**, not
the address: a peer id is the hash of its McEliece transport key, and a dial
that reaches the wrong machine fails at a cost of one timeout, never a session
with the wrong peer. So every address in this document is a *hint*, and the
only question the network cannot answer for you is whether a packet can reach
the other machine at all. That question has three answers, and each has a
section.

## Before either node starts

- **Build with the reader.** `cairn run` needs the `ui` feature (`make
  ui-build`, or a release binary, which has it). A plain `cargo build` says
  so rather than starting without it.
- **Listen past loopback.** The defaults bind `127.0.0.1:9000`, which nothing
  outside the host can reach. Both nodes need `--listen 0.0.0.0:9000`. In
  Cairn.app that is **Settings → P2P → accept inbound**; the app's default is
  loopback and its status line says *Listening on this Mac only* while it is.
  macOS asks for local-network permission the first time a node binds past
  loopback, and a refusal there looks like silence.
- **The published seed may be down.** The seed list compiled into the binary
  names one seed (`us-west`, `44.251.117.84:9000`). As of 2026-10-04 it
  answers nothing: the site's mirror job (`.github/workflows/node-sync.yml`)
  has been red on every five-minute run, and from a GitHub runner `curl
  http://44.251.117.84:8080/health` times out. A node still starts without it
  and says `seeds: us-west at 44.251.117.84:9000 did not hand over its key`
  once a minute; `CAIRN_SEEDS=off` silences that for a test that does not
  need it. Check it yourself from either machine:

  ```sh
  nc -vz 44.251.117.84 9000
  ```

  A seed that is down *drops* rather than refuses, so this takes a few seconds
  to say so. Bringing it back is the last section.

Everything below reads the node's own answer at `GET /sessions` (and the
Network page, `/ui/network`, which renders the same). Two fields matter:

- `this_node.external` — what the router in front of this node said when the
  daemon asked it to forward the p2p port. **A claim.**
- `this_node.inbound_from_public_at` — when a peer from outside every private
  address range last completed a handshake *inbound*. **The evidence.**

A quick way to read them:

```sh
curl -s http://127.0.0.1:8080/sessions | python3 -c '
import json, sys
d = json.load(sys.stdin)
t = d["this_node"]
print("peer id       ", t["peer_id"])
print("external      ", json.dumps(t["external"]))
print("inbound from outside at", t["inbound_from_public_at"])
for p in d["peers"]:
    print(p["status"], p["last_direction"], p["addr"], p["peer_id"][:16])'
```

## One LAN, two machines

Nothing to configure. Each node announces its peer id and port on the local
segment every thirty seconds (a multicast beacon on port 47396), and a node
that hears an id it holds no key for asks that machine for its key directly.
Within a minute each `GET /sessions` shows the other as `reached`, one with
`last_direction: inbound` and the other `outbound`.

If it does not:

- **The network drops multicast.** Guest and "client isolation" Wi-Fi do, and
  so do most corporate segments. The beacon socket reports a bind error in the
  log when it cannot bind at all; when it binds and nobody hears, the log is
  quiet. Fall back to a bootstrap file — the next section, with the other
  machine's LAN address in place of the external one.
- **Both nodes ask the router for the same port.** Two nodes behind one router
  both ask it to forward 9000. NAT-PMP may grant the second a different
  external port, which the node reports; UPnP refuses the second with a
  conflict, and it says `failed`. If both should be reachable from outside,
  give the second a different `--listen` port. If only the LAN matters, ignore
  it — the LAN session does not use the mapping.

## Two homes, two routers

Each node sits behind a router that translates addresses on the way out and
drops anything inbound that no outbound flow asked for. Each can dial out;
neither can be dialled. The daemon's answer is to ask its router to forward
the p2p port — NAT-PMP first, then UPnP IGD — and **only one of the two nodes
needs this to work**, because once B can dial A, A has a session with B and
both reconcile over it. Pick the home whose router is more cooperative to be
A.

### 1. Start A and read what its router said

```sh
cairn run --listen 0.0.0.0:9000 --serve 127.0.0.1:8080 --no-mcp
```

The log says `portmap: auto (CAIRN_PORTMAP=auto); asking the router to
forward port 9000` and, within a few seconds, one line about the outcome.
`GET /sessions` carries it as `this_node.external`:

| `status` | `public` | meaning | what to do |
|---|---|---|---|
| `mapped` | `true` | the router forwards `address` to this node | that `address` is what B dials. Still a claim until step 4 |
| `mapped` | `false` | the router agreed, but its own address is private: a second router or a carrier-grade NAT is in front of it | forward the port on the outer router too, or swap roles and let B be the one that is dialled, or use a seed (next section) |
| `failed`, *no gateway answered* | — | the router speaks neither protocol, or has both switched off | turn UPnP on in the router, or forward TCP 9000 to this machine's LAN address by hand. The daemon asks again every five minutes, and step 4 still tells you whether a hand-made forward works |
| `failed`, *a gateway answered and refused* | — | the protocol is present and disabled, or the port is taken | the `detail` names the protocol and the gateway; enable it there, or change `--listen` |
| `off` | — | not asked, and `detail` says why | a loopback listen, `CAIRN_PORTMAP=off`, or dials through `--proxy` |
| `searching` | — | the first attempt has not finished | wait a few seconds |

`CAIRN_PORTMAP=upnp` or `natpmp` asks one protocol only, which is useful when
a router answers one of them wrongly.

### 2. Hand A's key to B

The bootstrap file B needs carries A's address *and* A's transport key, and
the key is the part that matters. On A, against the identity the daemon
persists (`.local/node.identity.json` unless `--data-dir` or `--identity`
moved it):

```sh
cairn seeds publish --identity .local/node.identity.json --out /tmp/seed-a
```

That writes `/tmp/seed-a/<transport>.key` — the public key, named for its
own hash — and prints the list entry to go with it. Put that entry in a
one-seed list, with the `address` from step 1 in `addr`:

```sh
cat > /tmp/seed-a/seeds.json <<'EOF'
{
  "version": 1,
  "seeds": [
    {
      "name": "alice",
      "addr": "203.0.113.7:9000",
      "transport": "<the transport id seeds publish printed>",
      "http": null,
      "operator": "alice",
      "note": "home node"
    }
  ]
}
EOF
```

Copy the directory to B by any means at all. Everything in it is public, and
a tampered copy is refused on B rather than trusted: the key file is named for
the hash of the bytes inside it, and that hash *is* the peer id, so the one
thing a hostile copy cannot do is put a different key under the same name.

### 3. Start B with the bootstrap

```sh
cairn seeds resolve --list /tmp/seed-a/seeds.json --keys /tmp/seed-a --out .local/seeds
cairn run --listen 0.0.0.0:9000 --serve 127.0.0.1:8080 --no-mcp \
  --bootstrap .local/seeds/alice.json
```

`resolve` re-derives the id from the key bytes before it writes a bootstrap
file, and refuses an entry that does not verify. B dials A on its first tick.

### 4. Read both rosters

- On **B**, `GET /sessions` lists A as `reached`, `last_direction: outbound`.
- On **A**, it lists B as `reached`, `last_direction: inbound`, and
  `this_node.inbound_from_public_at` is now set. That timestamp is the
  evidence the mapping lacked: a machine outside A's LAN completed a
  handshake through it. The Network page's *from outside* row moves from
  *mapped to …* to *reachable at …* on the same fact, and it does the same
  for a port forwarded by hand with no mapping at all.

If B's log says the dial timed out, the router's claim was wrong or
something upstream drops the port; B's dial is the only test there is, so
check `A`'s `external` again (the external address moves when the ISP
renews it, and the daemon logs the move), then the router's own forwarding
table, then the outer router if `public` was `false`.

## Through a seed on a public host

When neither router cooperates — both behind a carrier-grade NAT, say — the
answer is a third machine with a public address. Both nodes dial it, it holds
the log, and they reconcile through it: records are content-addressed and
independently verifiable, so the seed can relay them without being trusted
for anything but availability.

A seed is an ordinary node with `--listen 0.0.0.0:9000`, the port open
inbound in whatever stands in front of it, and a published key.
[p2p.md](p2p.md), *Running a seed on a public host*, covers the three ways a
cloud instance breaks the loopback assumptions. [`launch/seed.service`](../launch/seed.service)
is a systemd unit that keeps one up across reboots and crashes, which is the
difference between a seed and a shell window somebody closed. To publish it so
every build finds it, `cairn seeds publish` as above and open a pull request
adding the key file and the entry ([launch/seeds/README.md](../launch/seeds/README.md)).

Bringing the published `us-west` seed back is the same unit on that host, and
the site's `/node/` mirror goes green on the first five-minute run after it
answers. Nothing in this repository can restart it; a `nc -vz` from somewhere
else is the test.

## What the fields mean, read together

| `external.status` | `inbound_from_public_at` | the Network page says |
|---|---|---|
| `mapped`, `public: true` | unset | **mapped to** *address* — a claim, until a peer outside dials in |
| `mapped`, `public: true` | set | **reachable at** *address* |
| `mapped`, `public: false` | — | **mapped, but** *address* **is not public** — double NAT |
| `failed` | unset | **not reachable from outside**, with the router's answer and when it asks again |
| `failed` | set | **reachable without a mapping** — a port forwarded by hand, probably |
| `off` | unset | **not asked**, with the reason |
| anything | set | reachable: the evidence outranks the claim |

The asymmetry is deliberate. A router can say anything; a completed McEliece
handshake from a public address cannot be faked by the router, by a host on
the LAN that answered in its place, or by the node itself. The reader shows
the claim so you can act on it and the evidence so you can believe it.

## What this does not do

- **No hole punching, no relay.** Two nodes behind routers that both refuse
  to map need the third machine above. STUN-style traversal needs a reachable
  server to reflect addresses and a rendezvous to coordinate, which is
  infrastructure this network does not have; [roadmap.md](roadmap.md) says
  why it stays out until something reachable exists to host it.
- **IPv4 only.** Both mapping protocols are, and so is the external address
  they report. An IPv6 peer that dials in still counts as evidence.
- **A mapping is not a record.** It is forgotten on restart, gossiped to
  nobody, read by nothing that pays, and renewed only while the daemon runs.
  A node that exits leaves a lease the router expires within the hour, except
  a router that only grants permanent leases, which the daemon asked for
  because the router left it no choice.
