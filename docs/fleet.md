# A fleet: one leader, many machines, from anywhere

The arrangement most operators actually want: a node that holds the identity
and collects the pay, and machines that do the walking. The Mac on the desk,
a rack of Linux boxes behind it, or GPUs rented by the hour in somebody else's
data centre. This page is how to set that up, what each part is, and what it
does **not** do, with the money said plainly at the end.

```
   leader ── cairn run --mcp-identity leader.identity.json
   (Mac or Linux)   CAIRN_FLEET=enrolled   --serve 0.0.0.0:8080
        ▲ POST /submit, /progress, /hosts, /lease   (plaintext HTTP,
        │   each signed: Authorization: CairnMember <member key> …)
        │
   ┌────┴──────────────┬─────────────────────────┬──────────────────────┐
   gpu-box-1 (your LAN)   rented-3f9a2c1b0d4e (a cloud)   rented-77e0…  (another)
   cairn agent --fleet    cairn work --fleet               orbit_worker.py --fleet
        │
        │ p2p (McEliece handshake, AEAD) -- the leader's choice
        ▼
   the public network, or nobody
```

## The parts

| part | what it is | runs where | holds |
|---|---|---|---|
| **leader** | a node: holds the log, runs verifiers, serves HTTP, signs the fleet's records, is paid; keeps the member registry beside its log | the Mac (Cairn.app, Settings → Fleet) or a Linux host ([`launch/fleet/leader.service`](../launch/fleet/leader.service)) | the ed25519 identity the fleet is paid to |
| **member** | a machine the operator invited: it joined once with a token and proves its own key on every request | anywhere that can reach the leader's HTTP port | its own member key, in the member file `cairn fleet join` wrote (mode 0600). Never the leader's |
| **host agent** | `cairn agent`: registers what a machine is (CPUs, GPUs, sandboxes), runs sandboxed executor jobs from its spool, leases the task it is on | every Linux box, under systemd (`cairn agent install`) | nothing of its own; `--fleet` signs as the member |
| **worker** | a search loop: asks the leader for its slice each epoch, heartbeats, submits what it found | every box with something to walk ([`launch/fleet/worker@.service`](../launch/fleet/worker@.service), `cairn work`, or your own GPU client) | nothing of its own; `--fleet` signs as the member |

Nothing but the leader touches the leader's key, and no secret ever crosses
the HTTP side. [design/fleet-enrollment.md](design/fleet-enrollment.md) is the
design in full, with the threat analysis; [agent.md](agent.md) is the host
agent.

## How the pay lands on the leader

A claim is paid to the `submitter` it names, and a submitter that is a 64-hex
ed25519 key must be signed by that key ([serving.md](serving.md)). A fleet
member does not hold the key. So it names the leader and does not sign the
record; it signs the *request*, with its own member key, and the leader signs
the record on the way in:

1. The leader runs with `CAIRN_FLEET=enrolled` and an identity
   (`--mcp-identity FILE`, or `CAIRN_FLEET_IDENTITY=FILE`). `GET /network`
   publishes `node.fleet.sources: ["enrolled"]`, the `signs_as` id, and how
   many members there are -- counts, never names.
2. The operator invites a machine (`cairn fleet invite`). The token it prints
   carries the leader's key, which the member pins: it never learns whom to
   pay from an answer on the wire, so nobody who can rewrite one can redirect
   the pay.
3. The machine joins (`cairn fleet join`), which makes its member key on the
   machine itself and proves it to the leader. From then on every POST it
   makes carries `Authorization: CairnMember <member key> <time> <signature>`
   over the method, the path, the body's hash and the leader's key.
4. A member posts a commitment or a claim whose `submitter` is `signs_as` and
   which carries no `signature`. Its commitment hash was computed with that
   submitter, because the hash binds the name. The leader verifies the
   request, signs the record, queues it, journals which member it was for,
   and answers `202` with `"signed_as": "<the id>"` and `"member": "<name>"`.
   From there the record meets every rule any record meets: epoch, schema,
   duplicates, the pinned verifier. Signing says whose result it is, not
   that it is right.
5. When the claim settles, the settlement names the leader. `cairn balances`
   on the leader, `GET /progress/{id}` → `derived.workers[]`, and the Network
   page's evidenced executors all say so. Which member found what is in
   `<log dir>/fleet/journal.jsonl`, on the leader alone.

The same record from anyone else is refused with `403` and
`"reason": "not_a_member"` rather than queued to fail at drain time, where the
sender would never learn why. A record under a worker's own nickname, or one
somebody signed themselves, passes through untouched.

**A member keeps its own name for everything else.** `GET /work_assignment`
derives the slice from `node_id`, so workers all asking under the leader's id
would all walk the same slice. A member reports as its own name, or as
`name/<suffix>` for one of several workers on one box -- `gpu-box-1/gpu0`
through `gpu-box-1/gpu3`, four slices under one membership -- and the leader
**reserves** those names: a heartbeat, lease or registration under them that
the member did not sign is refused with `403` and `"reason": "name_reserved"`.

## Setting it up

### The leader

**On a Mac**: Cairn.app, **Settings → Fleet → Lead a fleet**, with *Who may
join* left at **Machines I invite**. That serves HTTP on every interface,
sets `CAIRN_FLEET=enrolled`, creates `leader.identity.json` in the data
folder on first start and passes it as `--mcp-identity`, and lists the
members with **Invite a machine…** and **Revoke** beside them. Turn on **Keep
the node running in the background** and the node outlives the window as a
launchd agent.

**On Linux**: [`launch/fleet/leader.service`](../launch/fleet/leader.service),
a `cairn run --no-mcp` with `CAIRN_FLEET=enrolled`, an identity made once with
`cairn identity --out`, HTTP on the wildcard, and p2p on loopback -- a leader
that peers with nobody. The unit's comments say which lines to change for a
leader that also joins the public network.

The registry is `<log dir>/fleet/`, beside the log the node writes. `cairn
fleet` finds it the way `cairn run` finds its log, so give both the same
`--data-dir` (or `CAIRN_DATA`) and they agree; every command names the
directory it used.

### Inviting

```sh
# one machine, by name
cairn fleet invite --identity leader.identity.json --name gpu-box-1 --node http://203.0.113.7:8080
# a batch of rented machines: each named rented-<first 12 hex of its key>,
# each membership over twelve hours after it joined
cairn fleet invite --identity leader.identity.json --prefix rented --uses 16 \
    --expires 24h --member-ttl 12h --node http://203.0.113.7:8080
```

It prints the join line once. The token in it is a secret -- whoever holds it
can join until it is used up or expires -- so hand it over out of band: a
paste, cloud-init, a secret store. `--json` prints the same for a program;
Cairn.app's *Invite a machine…* is a form over it. Nothing secret is kept on
the leader: a lost token is replaced, not recovered.

An operator who wants no token on any wire at all enrolls by hand instead:
`cairn fleet join --manual --node URL --leader <signs_as> --name gpu-box-1` on
the machine prints a `cairn fleet admit --key … --name gpu-box-1` line to run
on the leader.

### Joining

```sh
cairn fleet join --node http://203.0.113.7:8080 "$CAIRN_INVITE"
```

checks that the node is the leader the token names and that it takes members,
makes a member key, joins, and writes `~/.cairn/fleet.json` (mode 0600, or
`--out FILE`, or `$CAIRN_FLEET_FILE`). With no token argument it reads
`$CAIRN_INVITE`, and `-` reads it from stdin, so it need not appear on a
command line. A join whose answer was lost is retried with the same key and
finds the same membership.

### Working

Every client takes the member file and does the rest: the submitter is the
leader's key from the file, the node is the file's, the name is the member's,
and every POST is signed.

```sh
cairn work --fleet ~/.cairn/fleet.json --objective sha256:… --worker gpu0 -- ./my-solver
python3 examples/certicom-ecdlp/tools/orbit_worker.py --fleet ~/.cairn/fleet.json \
    --objective sha256:… --job jobs/ecc2k130.json --worker gpu0
sudo cairn agent install --fleet /etc/cairn/fleet.json --roles executor
```

`--worker` is a suffix under the member's name: the lines above report as
`gpu-box-1/gpu0`. `orbit_worker.py` signs through `cairn fleet sign`, one
subprocess per request, rather than in Python, whose big-integer arithmetic is
not constant-time. `cairn agent install --fleet` hands the member file to the
service with `LoadCredential=`, so the key is in neither the unit nor its
environment file; [`worker@.service`](../launch/fleet/worker@.service) does
the same for a walker.

A client in another language signs the request string in
[design/fleet-enrollment.md](design/fleet-enrollment.md) §6 and checks itself
against the golden signature the tests pin (`src/fleet/auth.rs`), or shells
out to `cairn fleet sign --member FILE --method POST --target PATH` with the
body on stdin, which prints the header.

### Rented GPUs

"No tunnel" holds when members can reach the leader's HTTP port. Members dial
out; the leader never dials them.

- **A leader with a public address** -- a small cloud VM, a VPS -- needs
  nothing else, and is the recommended shape for a rented fleet. Its HTTP side
  is then what any public seed's is: the log, the reader, submissions under
  their submitters' own names, heartbeats and leases within their caps. With
  `CAIRN_FLEET=enrolled`, none of that gets anything signed.
- **A leader behind a home router** -- the Mac on the desk -- needs its HTTP
  port forwarded. `CAIRN_PORTMAP_HTTP=on` asks the router for it with NAT-PMP
  and then UPnP, as the node already does for its p2p port, and `GET
  /network` reports the result as `node.reach.external`. That makes the node
  reachable from the internet, which is why it is never on by default. Behind
  carrier-grade NAT, or a router that refuses, use a cloud leader or a tunnel.

**A machine you do not trust is a machine that can read your answers.**
Enrollment authenticates the box to the leader. It does nothing about the
box's owner, who on a marketplace that rents out strangers' GPUs can read the
member key and every artifact the walker finds before it is committed, and
race it under their own name. Rent from providers you would trust with the
answer.

### Revoking

```sh
cairn fleet list                       # members, with expiry and state
cairn fleet revoke gpu-box-1           # or a key; its next request is refused, forever
cairn fleet revoke --invite 3f9a2c1b   # every member that invite admitted, and the invite
cairn fleet revoke-invite 3f9a2c1b     # nobody joins with it any more; members stay
```

Revocation is by key, takes effect at the member's next request, and is
sticky: a revoked key cannot rejoin through any invite. A membership made
with `--member-ttl` ends by itself. Neither touches any other member. No
route over the network can invite, admit or revoke; only files on the
leader's disk and the one join route, which needs a token minted there.

### The older way: trusting a network

`CAIRN_FLEET` still takes networks -- `private` (every RFC 1918 block,
loopback, IPv6 unique-local), `loopback`, or CIDRs -- and signs for any
request from inside them with no header at all. The leader says at start that
it is trusting a network. It is how fleets ran before enrollment, and a
setting somebody typed is kept, but it makes the address the credential: a
guest on the Wi-Fi, a compromised printer, a laptop on the office VPN can each
have records signed in the leader's name. `enrolled,loopback` keeps that
convenience for this host alone. Two consequences if you use networks:

- Workers name the leader with `--worker gpu-box-1 --submitter <signs_as>`,
  and must learn `signs_as` from somewhere they trust. The HTTP side is
  plaintext, so anyone who can rewrite `GET /network` on the way can put
  their own key in it. Copy it from the leader's Settings, or from `GET
  /network` run on the leader itself.
- Across the internet the fleet's network *is* a tunnel. **WireGuard**: give
  the leader and every box an address on `wg0` and set `CAIRN_FLEET` to that
  subnet (`10.99.0.0/24`), not `private`. **SSH**, for one box: `ssh -N -L
  8080:127.0.0.1:8080 leader`, and `CAIRN_FLEET=loopback` admits it. **A cloud
  VPC with peering** is a private network already; the security groups decide
  who else is in it.

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
other peer the moment its handshake has named it, dial nobody else, and learn
no stranger from a beacon, a seed or a gossiped hint. `GET /network` says
`node.peers_policy: {"policy": "allowlist", "allowed": 1}`. The relay signs
for nobody unless it is given `CAIRN_FLEET` and the leader's identity file
too -- and then it is a second leader, which is a choice, not an accident.
A member belongs to one leader: its requests name that leader's key, so a
second leader enrolls it with an invite of its own.

## Checking it

| question | where the answer is |
|---|---|
| is the leader leading? | `GET /network` → `node.fleet.sources`, `node.fleet.signs_as`, `node.fleet.members`; the leader's log says `fleet: unsigned records from … are signed here with …` at start |
| who are the members? | `cairn fleet list` on the leader, or Cairn.app's Fleet settings; never a public route |
| did my record get signed? | the `202` body: `"signed_as": "<id>"` and `"member": "<name>"`; `null` means it was queued as sent |
| why was it refused? | the `reason` beside the `error`: `not_a_member`, `name_reserved`, `name_not_yours`, `member_revoked`, `member_expired`, `clock_skew` (the two clocks are in the message), `bad_signature`, … |
| which machines are here? | `GET /hosts`, and the Network page's *Registered hosts*; members are badged |
| who is walking what? | `GET /progress/{objective}` → `reported` (heartbeats, by worker name, `member: true` when signed) and `derived` (what the log paid, by submitter) |
| which member found what? | `<log dir>/fleet/journal.jsonl` on the leader |
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
  there is one place to attach it. [design/external-payouts.md](design/external-payouts.md)
  is the design for one: an escrow per objective, released to the address
  the leader bound.
- **No encryption on the HTTP side.** A member's requests are signed, not
  sealed: anyone on the path sees commitments (hashes), claims (public on
  admission anyway, and protected from copying by commit–reveal), heartbeats,
  and so the fleet's size and rate. No secret crosses it -- invite seeds and
  member keys never do.
- **No protection from a machine's owner.** See *Rented GPUs* above.
- **No per-member rate limit, and no pay split.** The settlement names the
  leader; the journal says which member found what. If the members belong to
  other people, how the operator shares out is between them.
- **No dispatcher.** The leader hands out no work. Each worker derives its
  slice from its own name and the epoch, as [coordination.md](coordination.md)
  explains. Leases stay advisory.
- **No members that cannot reach the leader.** A member submits to its leader
  over HTTP. Members that work through any node, while the leader is offline
  or unreachable, need leader-signed delegations -- a consensus change,
  Stage 2 of [design/fleet-enrollment.md](design/fleet-enrollment.md), and not
  built.
