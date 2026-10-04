# A fleet: one leader, many workers, your network only

The arrangement most operators actually want: a Mac on the desk that runs the
node, holds the identity, and collects the pay; a rack of Linux boxes -- some
with GPUs, some in another region -- that do the walking and are reachable by
nobody but you. This page is how to set that up, what each part is, and what
it does **not** do, with the money said plainly at the end.

```
            your network (LAN, VPC, or a WireGuard mesh across regions)
   ┌──────────────────────────────────────────────────────────────────────┐
   │   leader ── cairn run --mcp-identity leader.identity.json           │
   │   (Mac or Linux)   CAIRN_FLEET=private  --serve 0.0.0.0:8080         │
   │        ▲ POST /submit, /progress, /hosts, /lease  (plaintext HTTP)   │
   │        │                                                             │
   │   gpu-box-1: cairn agent ──┐   gpu-box-2: cairn agent ──┐            │
   │             worker@…  ─────┤              worker@…  ────┤            │
   └──────────────────────────────────────────────────────────────────────┘
                 │ p2p (McEliece handshake, AEAD) -- the leader's choice
                 ▼
          the public network, or nobody
```

## The three parts

| part | what it is | runs where | holds a key? |
|---|---|---|---|
| **leader** | a node: holds the log, runs verifiers, serves HTTP to the fleet, signs the fleet's records, is paid | the Mac (Cairn.app, Settings → Fleet) or a Linux host ([`launch/fleet/leader.service`](../launch/fleet/leader.service)) | yes: the ed25519 identity the fleet is paid to |
| **host agent** | `cairn agent`: registers what a machine is (CPUs, GPUs, sandboxes), runs sandboxed executor jobs from its spool, leases the task it is on | every Linux box, under systemd (`cairn agent install`) | no |
| **worker** | a search loop: asks the leader for its slice each epoch, heartbeats, submits what it found | every box with something to walk ([`launch/fleet/worker@.service`](../launch/fleet/worker@.service), or your own GPU client) | no |

Nothing but the leader touches the key. Nothing but the leader can reach, or
be reached from, outside your network. [agent.md](agent.md) is the host agent
in full; this page is about joining the parts.

## How the pay lands on the leader

A claim is paid to the `submitter` it names, and a submitter that is a 64-hex
ed25519 key must be signed by that key ([serving.md](serving.md)). A fleet
worker does not hold the key. So it names the leader and does not sign, and
the leader signs on the way in:

1. The leader runs with `CAIRN_FLEET=<networks>` and an identity
   (`--mcp-identity FILE`, or `CAIRN_FLEET_IDENTITY=FILE`). `GET /network`
   publishes both as `node.fleet.sources` and `node.fleet.signs_as`.
2. A worker inside one of those networks posts a commitment or a claim whose
   `submitter` is `signs_as` and which carries no `signature`. Its commitment
   hash was computed with that submitter, because the hash binds the name.
3. The leader's `POST /submit` signs the record with the identity before
   queuing it and answers `202` with `"signed_as": "<the id>"`. From there the
   record meets every rule any record meets: epoch, schema, duplicates, the
   pinned verifier. Signing says whose result it is, not that it is right.
4. When the claim settles, the settlement names the leader. `cairn balances`
   on the leader, `GET /progress/{id}` → `derived.workers[]`, and the Network
   page's evidenced executors all say so.

The same record from **outside** the fleet's networks is refused with `403`
rather than queued to fail at drain time, where the sender would never learn
why. A worker's own nickname passes through untouched and is paid to the
nickname; a record somebody signed themselves passes through untouched.

**Workers keep their own names for everything else.** `GET /work_assignment`
derives the slice from `node_id`, so a fleet of workers all asking under the
leader's id would all walk the same slice. The reference worker takes
`--worker gpu-box-1 --submitter <signs_as>` for exactly this reason:

```sh
python3 examples/certicom-ecdlp/tools/orbit_worker.py \
  --node http://10.0.0.5:8080 --objective sha256:… --job jobs/ecc2k130.json \
  --worker gpu-box-1 --submitter $(curl -s http://10.0.0.5:8080/network | python3 -c 'import json,sys; print(json.load(sys.stdin)["node"]["fleet"]["signs_as"])')
```

Heartbeats carry the worker's name, so the Network page shows eight workers;
the pay shows one submitter.

## Setting it up

### The leader on a Mac

Cairn.app, **Settings → Fleet → Lead a fleet**. That does four things to the
node the app runs: serves HTTP on every interface instead of loopback alone
(so the boxes can reach it), sets `CAIRN_FLEET` to the networks you list
(`private` by default), creates `leader.identity.json` in the data folder on
first use and passes it as `--mcp-identity`, and shows the `signs_as` id to
copy into your workers. Turn on **Keep the node running in the background**
beside it and the node outlives the window: it is a launchd agent then, and
starts again when you log in. The Mac's firewall must admit port 8080 from
your network; the app's connectivity check says whether it does.

The HTTP side is plaintext by design, so "every interface" must mean "your
network". On a laptop that joins coffee-shop Wi-Fi, turn fleet leading off
first, or lead from a Linux host instead.

### The leader on Linux

[`launch/fleet/leader.service`](../launch/fleet/leader.service): a `cairn run
--no-mcp` with `CAIRN_FLEET=private`, an identity made once with `cairn
identity --out`, HTTP on the wildcard, and p2p on loopback -- a leader that
peers with nobody. The unit's comments say which lines to change for a leader
that also joins the public network.

### Each Linux box

```sh
sudo cairn agent install --node http://10.0.0.5:8080 --roles executor
```

That is [agent.md](agent.md): the box is on the leader's Network page within
a minute, with its hardware and its jails, and executor jobs dropped into its
spool run inside gVisor or Kata. For a walker, install
[`launch/fleet/worker@.service`](../launch/fleet/worker@.service) with an
environment file per instance
([`worker.env.example`](../launch/fleet/worker.env.example)): the leader's
URL, the objective, the job file, the leader's `signs_as`, and this worker's
own name. Replace its `ExecStart` with your own client -- the GPU walker from
the ECC2K-130 campaign, say -- as long as it speaks the same four routes.

### Across regions: the tunnel

The leader's HTTP side is plaintext and never crosses the open internet in
the clear. Between a leader in one region and boxes in another, the fleet's
network *is* a tunnel:

- **WireGuard**, the usual answer: give the leader and every box an address
  on `wg0`, and set `CAIRN_FLEET` to that subnet (`10.99.0.0/24`), not to
  `private`, so a box that is on the LAN but not in the mesh is not a member.
  Workers use the leader's `wg0` address.
- **SSH**, for one box: `ssh -N -L 8080:127.0.0.1:8080 leader` on the box, and
  the worker uses `http://127.0.0.1:8080`. The leader sees the request arrive
  from loopback, so `CAIRN_FLEET=loopback` (or `private`) admits it.
- **A cloud VPC with peering** between regions is a private network already;
  `private` covers it, and the security groups decide who else is in it.

### Two fleet nodes that peer with each other, and nobody else

A fleet can have a node per region -- a leader in `us-east-1` and a relay
node in `us-west-2` whose workers submit to it locally -- peering over the
transport, which authenticates both ends with the McEliece handshake and
encrypts everything after. To make that peering private:

```sh
# on each node: dial and accept only the peers named by the bootstrap files
CAIRN_PEERS=bootstrap CAIRN_SEEDS=off CAIRN_BEACON_PORT=off CAIRN_PORTMAP=off \
  cairn run --no-mcp --listen 0.0.0.0:9000 --serve 0.0.0.0:8080 --bootstrap other-node.json
```

`CAIRN_PEERS=bootstrap` (or a list of peer ids) makes the node refuse every
other peer the moment its handshake has named it, dial nobody else, and
learn no stranger from a beacon, a seed or a gossiped hint. `GET /network`
says `node.peers_policy: {"policy": "allowlist", "allowed": 1}`. The
relay signs for nobody unless it is given `CAIRN_FLEET` and the leader's
identity file too -- and then it is a second leader, which is a choice, not
an accident: the file is the thing to copy, and the page you are reading is
the reason to think twice.

## Checking it

| question | where the answer is |
|---|---|
| is the leader leading? | `GET /network` → `node.fleet.sources`, `node.fleet.signs_as`; the leader's log says `fleet: unsigned records from … are signed here with …` at start |
| did my record get signed? | the `202` body: `"signed_as": "<id>"`; `null` means it was queued as sent |
| why was it refused? | `403` with the networks the leader signs for and the address it saw you from |
| which boxes are here? | `GET /hosts`, and the Network page's *Registered hosts* |
| who is walking what? | `GET /progress/{objective}` → `reported` (heartbeats, by worker name) and `derived` (what the log paid, by submitter) |
| whom does the node peer with? | `GET /network` → `node.peers_policy`; `GET /sessions` for the sessions themselves |
| is the pay landing? | `cairn balances` on the leader; `GET /network` → `roles.executors` |

## What this does not do

- **No external currency.** Settlements credit the network's own unit of
  account to the submitter they name, and that is all a balance is. Nothing
  in this repository moves Bitcoin, Ether or anything else, in or out; the
  only wallet involvement anywhere is a Solana key signing a funding
  authorization. A payout rail is a separate design, not a setting, and
  nothing here pretends otherwise. What the fleet does is make the leader
  the one identity every settlement names, so that when such a rail exists
  there is one place to attach it.
- **No authentication on the HTTP side beyond the network.** Inside
  `CAIRN_FLEET`, anyone who can reach the leader can have records signed in
  its name. That is the deal a private network makes; it is why the
  networks are listed explicitly, why `private` is wrong on a laptop that
  roams, and why the tunnel is not optional across the internet. A signed
  record still proves nothing: a bad claim is rejected by the verifier and
  costs the leader its standing, not its balance.
- **No dispatcher.** The leader hands out no work. Each worker derives its
  slice from its own name and the epoch, as [coordination.md](coordination.md)
  explains; the host agent's spool is filled by whatever the operator trusts
  to fill it. Leases stay advisory.
- **No relaying of the fleet's HTTP.** Two fleet nodes share the *log* over
  p2p; a worker still submits to the node it can reach over HTTP, and that
  node signs if it holds the identity. Put the leader where the workers are,
  or give each region a node and decide which of them signs.
