# Fleet members: enrollment in place of network trust

**Status: Stage 1 is built** -- `src/fleet/`, `POST /fleet/join`, `cairn
fleet`, `--fleet` on `cairn work`, `cairn agent` and `orbit_worker.py`, the
units, `CAIRN_PORTMAP_HTTP`, and Cairn.app's Fleet settings; [fleet.md](../fleet.md)
is how to use it. It changes no record, hash or rule. Stage 2 (§15) is a
consensus change, needs its own review, and is not built. Written against [fleet.md](../fleet.md) and
`src/fleet.rs`, which this revises, and against the threat-model row *a
stranger on the fleet network*, which Stage 1 closes for any fleet that turns
network trust off.

## 1. The gap

A fleet leader signs a commitment or claim that names its identity and carries
no signature when the request comes from an address in `CAIRN_FLEET`
(`Serving::fleet_sign` in `src/serve.rs`). Making the source address the
credential has three consequences.

**Anyone inside the listed networks is a member.** A guest on the Wi-Fi, a
compromised printer, a laptop on the office VPN: each can have records signed
in the leader's name. The threat model carries the row as *partial*, and the
only advice it can give is to list networks narrowly.

**A rented GPU cannot be a member without a tunnel.** A box rented by the hour
reaches the leader from a public address that changes with every rental, and
that some providers share among tenants behind one NAT, so listing it would
admit the neighbours. Today the answer is WireGuard or `ssh -L` per box, which
is the setup cost that makes renting for an afternoon not worth doing.

**The worker learns whom to pay from an unauthenticated answer.**
[fleet.md](../fleet.md) tells a worker to read `signs_as` off `GET /network`
and submit under it. The HTTP side is plaintext by policy, so anyone who can
rewrite that one response can substitute their own key. The worker then
commits under the attacker's id; the leader passes those records through
untouched, because they do not name it; and the attacker, who sees them go by,
signs them and submits them itself. On a switched LAN that takes ARP spoofing.
Across the internet it takes being on the path. The fix is the same as for the
first two problems: the worker must learn the leader's key out of band, from
something the operator handed it.

## 2. What it must guarantee

| | property |
|---|---|
| **G1** | The leader signs for a request only if a key the operator enrolled made it, from any address. |
| **G2** | No secret ever crosses the HTTP side. It stays plaintext, so everything on it is assumed read and rewritable. |
| **G3** | A worker submits under a leader key it was given out of band, never one it fetched. |
| **G4** | Revoking one machine is immediate and touches no other; a rented machine's membership can end by itself when the rental does. |
| **G5** | Every record the leader signs for a member is attributable to that member, on the leader, without touching the log. |
| **G6** | No record, hash, encoding or rule changes. The reference implementation and the frozen conformance vectors are untouched. |

G2 is not a compromise. Everything a member sends is a commitment (a hash), a
claim (an artifact that becomes public at the next drain, when it is admitted,
and that commit–reveal already protects from copying: the commitment is an
epoch older than any copy could be), or self-reported telemetry. What has to
change is *who may make the leader sign*, and that is authentication, not
secrecy.

## 3. The design

```
operator, on the leader                     the worker box
───────────────────────                     ──────────────
cairn fleet invite --prefix rented          cairn fleet join --node http://L:8080 <token>
  -> mints an invite keypair                  -> parses the token: leader key L, invite seed
  -> keeps only its PUBLIC half               -> makes a member keypair m/M on this box
  -> prints the token:                        -> POST /fleet/join, signed with the invite
     cairn-invite1.<L>.<invite seed>             seed AND with m (proof of possession)
           │                                  <- 201: name, expiry
           └──── out of band: a paste,        -> writes the member file: L, name, m
                 cloud-init, a secret store
                                            every later POST carries
                                              Authorization: CairnMember <M> <time> <sig>
                                            and the leader signs as L for it, from anywhere
```

Three keys, three jobs:

- The **leader key** `L` is what settlements pay, as today. It never leaves the
  leader and signs nothing new.
- An **invite key** is minted per invitation. Its seed exists only inside the
  token, the leader keeps its public half, and its only use is to sign joins.
- A **member key** `m` is made on the worker box at join and never leaves it.
  It signs requests to one leader and nothing else; its public half `M` is what
  the leader enrolls.

All three are ed25519 through the existing `crate::crypto::identity`:
`sign_bytes`, and `verify_bytes`, which verifies strictly and refuses weak
keys. Each message below opens with its own domain line (`cairn-fleet-join/1`,
`cairn-fleet-request/1`) that can never be the canonical encoding of a record,
so no invite or member key can be turned into a signer of records. The
cross-protocol hazard the identity module warns about does not arise, and
would not arise anyway, since these keys sign only strings their holder built.

## 4. Invites and the token

`cairn fleet invite` mints an ed25519 keypair, writes the invite's public key
and terms to the leader's fleet directory, prints the token once, and forgets
the seed:

```
cairn-invite1.<leader key: 64 hex>.<invite seed: 64 hex>
```

The leader half is the pin (G3). It is `signs_as`, so the operator can compare
it with the leader's Settings by eye. The seed half is the authority to join.

| term | default | meaning |
|---|---|---|
| `uses` | 1 | how many member keys may join with it; an autoscaling group baked into one image wants more |
| `expires` | 24 h | after this the invite admits nobody |
| `name` or `prefix` | the name the worker asks for, by default its hostname | `--name gpu-box-1` admits exactly that name, once; `--prefix rented` names each member `rented-<first 12 hex of its key>`, stable for as long as the box keeps its key |
| `member_ttl` | none | a membership made with this invite ends this long after it was made: a rental that ends by itself |

Nothing secret is stored on the leader. A token the operator loses is
replaced, not recovered.

## 5. Joining

The worker parses the token, reads `GET /network`, and stops if
`node.fleet.signs_as` is not the token's leader key or `node.fleet.sources`
lacks `enrolled`. That is a check against the wrong node, not against an
attacker: one who answers in the leader's place gains nothing, because the join
below is bound to `L` and the worker's records will name `L` whatever the
answer said.

It then makes a member keypair and builds the join string, lines joined by
`\n` with no trailing newline, hex in lowercase, time in canonical decimal
seconds:

```
cairn-fleet-join/1
leader <L>
invite <invite public key>
member <M>
name <requested name, or nothing>
time <unix seconds>
```

and posts it, signed twice:

```http
POST /fleet/join
{"invite": "<K>", "member": "<M>", "name": "gpu-box-1", "time": 1791234567,
 "invite_signature": "<by the invite seed>", "member_signature": "<by m>"}
```

The leader rebuilds the string with its own `L` and admits the member when the
invite exists, has not expired and has a use left; both signatures verify; the
time is within five minutes of its own; `M` is not revoked, is not `L`, and is
not already a member under another name; and the name is the invite's, or fits
its prefix, and is free. Names are `[A-Za-z0-9._-]`, at most 40 characters, so
that one member can run several workers under `name/…` (§7). The leader answers
`201` with the name and the expiry, and the worker writes its member file --
node URL, `L`, name, `M`, the member secret -- with mode `0600`.

**Why two signatures.** The invite signature proves the joiner holds the token
without sending it: over plaintext, a seed sent once is a seed everyone on the
path now holds, and with a multi-use invite they could enroll their own keys
until it ran out. The member signature is proof of possession, so nobody can
enroll a key they do not hold. A replayed join yields the same membership; a
single-use invite already spent by this key returns that membership, and by any
other key it is refused.

**Manual enrollment**, for an operator who wants no token on any wire:
`cairn fleet join --manual --node URL --leader L --name gpu-box-1` writes the
member file and prints `cairn fleet admit --key <M> --name gpu-box-1`, which the
operator runs on the leader. One copy in the other direction, and no shared
secret anywhere.

## 6. Signed requests

Every request a member wants attributed to it carries

```
Authorization: CairnMember <M> <time> <signature>
```

over the request string

```
cairn-fleet-request/1
leader <L>
member <M>
time <unix seconds>
method <POST>
target <the request-target exactly as on the request line>
body <SHA-256 of the exact body bytes, 64 hex>
```

The leader looks `M` up and refuses it if revoked or expired; refuses a time
more than two minutes from its own, answering with both clocks so a skewed box
can see why; hashes the body it read; rebuilds the string with its own `L` and
the request line it received; and verifies. Binding the leader stops a member
enrolled with two leaders having its requests to one replayed to the other.
Binding method, target and body stops a signature lifted off a heartbeat from
authorizing a submission.

**A header that is present and fails is a `401`, never a fallback to
anonymous.** A request with no header is what it is today, and meets the
address rules for the sources that still have them (§8).

Requests are not encrypted, and a replay inside the two-minute window is
possible; §7 shows every route is idempotent or advisory under replay, and
closes the one that was not. The clock assumption is not new: an epoch is 600 s
by default (`partition::EPOCH_SECONDS`), and `cairn work` already stops posting
eight seconds before one ends. A proxy that rewrites the request-target breaks
signatures, so nothing that normalizes URLs should sit between members and the
leader.

## 7. What a member gets, route by route

| route | for a verified member | replayed inside the window |
|---|---|---|
| `POST /submit` | a commitment or claim naming `L` with no signature is signed as `L` from any address and journaled (§9); the `202` carries `"signed_as"` and `"member"`. Anything else passes through untouched, as today. | the spool treats a resend as the same submission, and ed25519 signatures are deterministic, so re-signing yields the identical record |
| `POST /progress` | `worker` must be the member's name or `name/…`; the roster entry is marked `member` | restates a report made under two minutes ago |
| `POST /lease`, `POST /lease/release` | `holder` must be the member's name or `name/…` | a claim older than that holder's last release of the same task is ignored |
| `POST /hosts` | `host` must be the member's name; marked `member` | restates a registration |
| `POST /fleet/join` | not a member request | the same membership |
| every `GET` | unchanged, public | -- |

**Names are reserved.** A heartbeat, lease or registration that carries no
header and uses an enrolled member's name, or any name under it, is refused
with `403`. That closes, for every enrolled name, the name-spoofing gap the
threat model records for forged progress, lease squatting and forged hosts.
Strangers keep the public roster under names nobody enrolled, as today. The
`name/…` namespace exists because the work slice is a function of the worker's
name (`GET /work_assignment`): one box with four GPUs runs `gpu-box-1/gpu0`
through `gpu-box-1/gpu3`, four slices under one membership.

## 8. Sources: `enrolled` beside the networks

`CAIRN_FLEET` keeps its grammar and gains one word:

| value | signs for |
|---|---|
| `enrolled` | verified members, from any address. **The recommended setting, and Cairn.app's default for a new fleet.** |
| `enrolled,loopback` | members, and anything on this host: an `ssh -L` tunnel, the Mac's own tools |
| `private`, `loopback`, CIDRs | anything on those networks with no header, as today. Kept for compatibility; the leader says at start that it is trusting a network. |

`GET /network` adds `node.fleet.members: {"enrolled": n, "live": k}`, counts
only. Names and keys stay off the public route, because who is in a fleet is
the operator's business; `cairn fleet list` and Cairn.app read the directory.

## 9. Revocation, expiry, and the journal

`cairn fleet revoke gpu-box-1` (or a key, or `--invite K` for every member one
invite made) writes a tombstone keyed by member key. It is checked on every
request, takes effect on the next one, and is sticky: a revoked key cannot
rejoin through any invite, so a replayed join of a revoked member stays
refused. A membership with a `member_ttl` ends by itself. Neither touches any
other member (G4).

Every record the leader signs for a member appends one line to
`fleet/journal.jsonl`: time, member, name, kind, record id, objective. It stays
on the leader (G5). It is what tells the operator which box found what; the log
still names `L`, and only `L`.

## 10. Where the state lives

Beside the log, as `deposits/` is, in `<log dir>/fleet/` with mode `0700`:

| path | written by | holds |
|---|---|---|
| `invites/<K>.json` | `cairn fleet invite` | the invite's public key and terms |
| `invites/<K>.used/<M>` | the node, at join | one empty file per use, created exclusively, so two concurrent joins cannot both take the last use |
| `members/<M>.json` | the node at join, or `cairn fleet admit` | name, invite, joined, expires |
| `revoked/<M>.json` | `cairn fleet revoke` | when and why |
| `journal.jsonl` | the node | §9 |

One file per fact, so the CLI and the node never rewrite each other's files;
the node rescans a directory when its modification time changes. Nothing in the
directory is secret.

Membership changes only through files on the leader's own disk and the one
join route, which needs a token minted there. No route over the network can
invite, admit or revoke.

## 11. The commands and the clients

```text
cairn fleet invite [--name NAME | --prefix P] [--uses N] [--expires 24h] [--member-ttl 12h] [--note TEXT]
cairn fleet join   --node URL [--name NAME] [--out FILE] TOKEN
cairn fleet join   --node URL --leader KEY --name NAME --manual    # prints the admit line
cairn fleet admit  --key KEY --name NAME [--ttl 12h]
cairn fleet list | invites
cairn fleet revoke NAME | KEY | --invite KEY
cairn fleet sign   --member FILE --method POST --target PATH       # body on stdin; prints the header
```

- **`cairn work --fleet FILE`** takes the leader key from the file as the
  submitter (G3: never fetched), the member name as the worker, `--worker gpu0`
  as a suffix under it, and signs every POST. `--submitter` and `--identity`
  conflict with it.
- **`cairn agent --fleet FILE`** signs its registrations. `install` writes the
  unit with `LoadCredential=`, so the member file is not in the unit's
  environment.
- **`orbit_worker.py --fleet FILE`** signs through `cairn fleet sign`, one
  subprocess per request, a few a minute. `cairn fleet sign` is not a signing
  oracle: it signs only the request string it builds. A pure-Python ed25519
  would drop the dependency on the binary and is not proposed, because
  big-integer arithmetic in Python is not constant-time and a rented box has
  neighbours.
- **`launch/fleet/worker@.service`** reads `CAIRN_FLEET_FILE` in place of
  `CAIRN_SUBMITTER`.
- **Cairn.app**, Settings → Fleet: *Who may join* (`Machines I invite` by
  default, or `Anything on my network`), *Invite a machine…* (one, or many with
  a count and an expiry, showing the join line with a Copy button), and the
  members with their expiry, whether they are live, and Revoke.

Ed25519 signatures are deterministic, so a fixed member seed and a fixed
request string give a fixed signature. The tests pin one, and every client in
every language checks itself against it.

## 12. Rented GPUs, concretely

"No tunnel" holds when members can reach the leader's HTTP port. Members dial
out; the leader never dials them.

**A leader with a public address**, such as a small cloud VM or a VPS, needs
nothing else, and is the recommended shape for a rented fleet. Its HTTP side is
then reachable by everyone, which is a public seed's surface: the log, the
reader, submissions under their submitters' own names, heartbeats and leases
within their caps. With `CAIRN_FLEET=enrolled`, none of that gets anything
signed.

**A leader behind NAT**, such as the Mac on the desk, needs its HTTP port
forwarded. The node already asks the router to forward its p2p port, with
NAT-PMP and then UPnP (`src/p2p/reach.rs`), and `reach::map` takes any internal
port. So `CAIRN_PORTMAP_HTTP=on`, off by default, forwards the HTTP port the
same way, `GET /network` reports the external HTTP address beside the p2p one,
and `cairn fleet invite` prints it in the join line. The Settings switch says
what it means: this Mac becomes a public seed, reachable from the internet.
Behind carrier-grade NAT, or a router that refuses, no forwarding works; use a
cloud leader, a tunnel, or Stage 2.

**A worker box, start to finish:**

```sh
# once, on the leader
cairn fleet invite --prefix rented --uses 16 --expires 24h --member-ttl 12h
# on each rented box, at boot, with the token from a secret store rather than a command line
cairn fleet join --node http://203.0.113.7:8080 "$CAIRN_INVITE"
cairn work --fleet ~/.cairn/fleet.json --objective sha256:… --worker gpu0 -- ./walker --gpu 0
```

The membership ends twelve hours after the box joined, whether or not anyone
remembers to revoke it. On SF Compute's Autoresearch, for instance, a node's
commands take secrets by reference through `env`, which keeps the token off
the recorded command line, and the member file survives a stop on the node's
persistent disk.

**A machine you do not trust is a machine that can read your answers.**
Enrollment authenticates the box to the leader. It does nothing about the
box's owner, who on a marketplace that rents out strangers' GPUs can read the
member key and, worse, every artifact the walker finds before it is committed,
and race it under their own name. Both commitments land in the same epoch, a
batch settles in beacon order that neither party controls, and so the thief
wins roughly half the races, and every race in which the solver holds a find
across an epoch boundary, where the thief commits first. No protocol fixes
that; it is what running on someone else's computer means. Rent from
providers you would trust with the answer, or from confidential-computing
instances with an attested GPU, which are outside this design.

## 13. Threat analysis

| adversary | can | cannot | after Stage 1 |
|---|---|---|---|
| a stranger on the internet | what a stranger can do at any public seed | get anything signed | -- |
| a stranger on the fleet's LAN | the same, with `enrolled` only | get anything signed | **the open row closes**, for fleets that turn network trust off |
| a passive eavesdropper | read commitments (hashes), claims (public on admission; copying blocked by commit–reveal), heartbeats and registrations (the fleet's size and rate) | learn a secret: invite seeds and member keys never cross the wire | the fleet's composition and rate are visible on the path; stated, not closed |
| an active on-path attacker | drop, delay or rewrite responses, a denial of service it could cause by dropping packets anyway; replay requests inside the window (§7) | redirect pay, since the leader key is pinned from the token (G3); enroll its own key; forge a request | today's `signs_as` redirection closes |
| a stolen member key | until revoked or expired, have commitments and claims signed as `L`. Claims still meet the pinned verifier, and neither kind carries a bond (bonds belong to other record kinds, which the leader never signs for a member), so the harm is standing, not balance | sign any other kind; read `L`; enroll others | the old row's harm, scoped to one key, revocable at once, expiring, and journaled by name |
| a leaked token | enroll keys until its uses run out or it expires | outlive `revoke-invite`, or `revoke --invite` of what it enrolled | single-use by default |
| the owner of a rented machine | everything in §12's last paragraph | -- | **not closed**; out of scope |
| a compromised leader | everything, as today: it holds `L` | -- | unchanged; the member registry holds no secret worth taking |

Cost to the leader per request: one SHA-256 over at most the body cap, and one
ed25519 verification, the same order as parsing the JSON it already parses.
Per-member rate limits are not part of Stage 1 (§17).

## 14. Alternatives, and why not

- **TLS, or mutual TLS.** No TLS crate may enter the tree
  (`tests/cipher_policy.rs`), deliberately. TLS by itself authenticates the
  server; authenticating the worker is mutual TLS, which is a certificate
  authority. Signed requests are the authentication half of mutual TLS without
  the confidentiality half, which this traffic does not need (§2).
- **One shared fleet secret on every request.** Over plaintext, the secret
  crosses the wire every time, so everyone on the path becomes a member. There
  is no per-machine revocation either.
- **HMAC with a key per member.** Python's standard library could compute it,
  which is the only argument for it. The leader would hold every member's
  secret; a multi-use invite cannot give each member its own key without key
  agreement, which is X25519 in every client; and a second leader could not
  check members without being handed their secrets. Ed25519 makes the registry
  public data.
- **Listing rented boxes' addresses in `CAIRN_FLEET`.** The address changes
  per rental, and a provider that puts tenants behind shared egress addresses
  makes every other tenant a member.
- **The p2p transport as the members' channel.** It would bring
  confidentiality and mutual authentication for free, McEliece handshake and
  ChaCha20-Poly1305, over a port the node already forwards. It would also put a
  McEliece client in every worker, in every language, with handshake keys
  hundreds of kilobytes long, to protect traffic that becomes public anyway.
  Worth revisiting only if in-flight confidentiality starts to matter, and
  sealed envelopes already encrypt at the record layer where an objective
  needs it.

## 15. Stage 2: members that need no route to the leader

Stage 1 needs the leader reachable. Stage 2 removes that, at the price of a
consensus change.

The leader signs a short-lived **delegation** for a member, and the member
signs its records itself:

```json
"delegation": {"leader": "<L>", "member": "<M>", "kinds": ["commitment", "claim"],
               "not_after_epoch": 4312, "signature": "<by L, under its own domain line>"}
```

The rule becomes: a record whose `submitter` is the key `L` and whose
signature verifies under `M` instead is admitted when it carries a delegation
signed by `L` that names `M`, its kind is in scope, and its epoch is at most
`not_after_epoch`. The pay still goes to `L`. A member then submits through
any node, such as a seed in its own region, and a leader behind carrier-grade
NAT, or offline for a day, still gets paid.

What it costs, which is why it is a separate stage:

- **Both implementations, and new conformance vectors.** The field is absent
  from every existing record and is inserted only when present, as `envelope`
  is, so the frozen vectors do not move; but the rule is new in `src/node.rs`
  and in `reference/rust/`.
- **Expiry by epoch, never by clock.** Validity must be a function of the log
  for every node to reach one verdict, so it is an epoch number, not a time.
- **Revocation becomes expiry.** A delegation in the wild stays valid until it
  lapses. Delegations must therefore be short, hours, and re-issued over the
  Stage 1 channel. A revocation record would be one more consensus element and
  is not proposed.
- **A signature means something new.** Today only the process holding `L`
  makes `L` speak. After Stage 2 any delegate in scope does too, and anything
  that reads a signature as "the holder of `L` made this" has to learn that.

Build it when a leader cannot be made reachable, or when members should keep
working through a leader outage. Stage 1's member keys and invites are exactly
what Stage 2 delegates to, so nothing is thrown away.

## 16. Building Stage 1

In three pieces, each of which leaves the tree working:

1. **The node.** `src/fleet.rs` becomes `src/fleet/`: the policy with the
   `enrolled` source; `members.rs` for the directory, invites, revocation and
   the journal; `auth.rs` for the token, the two strings and their
   verification. `src/serve.rs` keeps the raw request-target and the
   `authorization` header in `Request`, reads bodies as bytes before parsing
   them, verifies members, reserves names in the roster routes, serves
   `POST /fleet/join`, and counts members on `GET /network`. `cairn fleet` in
   the CLI.
2. **The clients.** `src/agent/http.rs` takes an optional signer; then
   `cairn work --fleet`, `cairn agent --fleet`, `orbit_worker.py --fleet`, and
   the units.
3. **The surfaces.** Cairn.app's Fleet section; `CAIRN_PORTMAP_HTTP`; members
   marked on the reader's roster; fleet.md, configuration.md, serving.md and
   the glossary; and the threat-model row, which moves and says what remains
   (§13).

Tests, beyond each module's own: the golden request signature (§11); a request
refused for each part of the string altered (leader, member, time, method,
target, body), for a revoked key, an expired membership, a weak key and a stale
clock; a present but bad header that answers `401` and is never anonymous; a
multi-use invite under concurrent joins that admits exactly its uses; a revoked
key that cannot rejoin through a fresh invite; names reserved across
heartbeats, leases and hosts; and a replayed submission that queues the same
record. Then `scripts/fleet-demo.sh` in CI: a leader with
`CAIRN_FLEET=enrolled`, an invite, a join, `cairn work --fleet` through a
commit and a reveal, a settlement that names the leader, a revoke, and the
next request refused. `node-smoke.sh`'s fleet section moves to an enrolled
member.

Compatibility: `private`, `loopback` and CIDRs keep working, and
`--submitter` with them. A Settings value somebody typed is kept; only the
default for a new fleet changes.

## 17. What this does not do

- **Encrypt the HTTP side.** §2 says why it does not need to, and §13 what the
  path still sees.
- **Protect a worker from its machine's owner** (§12).
- **Authenticate responses.** A rewritten response is a denial of service, and
  dropping the packet is the same one.
- **Rate-limit per member.** A token bucket per member key on `POST /submit`
  is the obvious next step, and cheap, but separate.
- **Split pay among members.** The settlement names `L`; the journal says
  which member found what. If the members belong to other people, that is a
  mining pool's shape, and how its operator shares out is between them and
  outside the rules.
- **Share members between leaders.** A member's requests name its leader's
  key, so a member belongs to one leader. A second leader enrolls it with an
  invite of its own.
