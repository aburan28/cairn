# Peer discovery without a name anybody owns

`blob fetch --peer host:port` was honest about a network with nowhere to look an
address up. This is the design that replaces it, and it starts by splitting the
question in two — because the split is most of the answer.

## Discovery is two problems

> **identity** — is the thing I reached the thing I meant to reach?
>
> **location** — what address is it at today?

Almost every discovery scheme conflates them, and that conflation is exactly what
makes DNS feel load-bearing. If a hostname is how you *identify* a peer, whoever
controls the name controls the network: a registrar seizure, a hijacked resolver,
a poisoned cache — each substitutes a different machine and nothing downstream
can tell.

Separate them and the difficulty collapses. Here a peer's identity is an
**ed25519 public key**, and its address is a *hint signed by that key*. Then:

- a lie about location is detectable on connection and costs one failed dial;
- **any source of hints is acceptable**, because none is trusted. A DNS record, a
  gossiped record, a QR code, a pasted string and a file on a USB stick are all
  exactly as safe as each other;
- a peer can move without warning, because a newer signed record supersedes an
  older one and the key did not change.

This is the same move the blob store already makes. `evaluator` is a path and a
hint; `evaluator_sha256` is the identity. Nobody worries about a hostile
filesystem layout, because the hash decides. Nobody need worry about hostile DNS
once the key decides.

## Why encrypted DNS does not answer this

DoH, DoT and DoQ encrypt the *query*. That is a real property, and it is a
different property from the one you want.

| what you might hope | what encrypted DNS gives |
|---|---|
| nobody can tell which peers I look up | ✅ — hidden from an on-path observer |
| nobody can take the name away | ❌ — a registrar still owns it |
| I do not have to hardcode a trust anchor | ❌ — now you hardcode a resolver *and* a name |
| a wrong answer is detectable | ❌ — unless the record is separately signed |

Worse for this threat model specifically: the resolvers people actually use are a
handful of large providers, so encrypting to them **concentrates** the
observation point that plaintext DNS at least spread across every recursive
resolver on the path. You have traded many observers who see a little for one who
sees everything, and gained nothing against seizure.

DNSSEC gets you the last row — a verifiable answer — at the cost of trusting the
DNS root, which is a different hierarchy with the same shape.

None of which makes DNS useless. Under the split above it is a perfectly good
**hint source**: cheap, universally reachable, already deployed, and losing it
costs a hint rather than the network. The rule is:

> **DNS may carry signed records. It may never be the thing that decides.**

## The anchor nobody escapes

A node with no information cannot find a network. Every real system hides an
anchor somewhere:

| system | anchor |
|---|---|
| Bitcoin | hardcoded DNS seeds **and** a fallback IP list in the source |
| IPFS / libp2p | hardcoded bootstrap multiaddrs |
| Ethereum discv5 | hardcoded bootnode ENRs |
| Tor | hardcoded directory authorities, keys in the binary |
| BitTorrent DHT | hardcoded routers (`router.bittorrent.com`) |

Claims of zero-configuration discovery are claims about where the anchor is
hidden, usually in a package the user installed. So the goal is not to remove it.
It is to make it:

1. **a key rather than an address**, so the operator can move;
2. **replaceable without a code change**, so seizing one is survivable;
3. **serving self-verifying data**, so a compromised anchor can lie about who is
   *reachable* and never about who is *who*.

Signed peer records give (1) and (3). Treating every hint source as equal, with
none privileged in code, gives (2).

## The techniques, assessed

**Peer exchange (PEX).** Ask peers you already have about peers they have. The
cheapest possible mechanism and the highest-value one, because it turns bootstrap
from a recurring problem into a once-ever one. *Built.*

**Records in the log.** This project's specific advantage, and the one worth
taking seriously before reaching for anything fancier. Every node already
replicates a hash-linked log, so **discovery is not a new bootstrap problem — it
is the same one as obtaining the log.** Solving it twice is the mistake. The
split that makes it work: *identity* is permanent and belongs in the log;
*location* is ephemeral and does not, because the log is append-only and an IP is
not. *Not built; the natural next step.*

**Kademlia DHT with provider records.** *Built — `src/swarm/dht.rs`.* The
standard answer to "who has content X", and the right one: `blob fetch` wants
exactly a provider lookup, and without one it dials every peer it knows and asks
each. That is flooding — fine at ten peers, hopeless at ten thousand, and worse
exactly as the network becomes worth using.

I argued against this earlier on the grounds that the log does the same job with
no new bootstrap. That was wrong, and the error is worth naming because it is the
same conflation this document opens with. The log can carry **peer identity**,
which is permanent. It cannot carry **provider records**, which expire and are
revoked by silence — an append-only structure has no way to say *no longer true*
and would advertise a dead node forever. They are different problems and they
want different structures:

| | churn | belongs in |
|---|---|---|
| peer identity | permanent | the log |
| who holds digest `D` right now | constant | the DHT |

The bootstrap objection also dissolves: the DHT bootstraps from the address book,
which is already there.

And the security objection is much weaker here than where DHTs earned their
reputation, because of work already done. **Every DHT answer is a hint; the
digest decides.** A provider record that lies costs one wasted dial, checked
against a digest the log fixed before the lookup started — where BitTorrent's DHT
can hand you a poisoned answer you cannot check. So eclipse costs *liveness*, not
correctness, and peer exchange remains as a fallback that does not route through
the DHT at all. Node IDs are hashes of ed25519 public keys, so claiming an ID
costs a keypair and a signature — S/Kademlia's crypto-ID mitigation, obtained for
free from the identity layer. Binding IDs to stake rather than keys is the
stronger version and is not built.

**Local multicast (mDNS-style).** Genuinely zero-configuration on a LAN: no DNS,
no hardcoded address, no anchor at all. Limited to a broadcast domain, and often
disabled in exactly the container environments a node runs in. Cheap to add and
worth having as one hint source among several.

**Ethereum's discv5 / ENR.** The closest thing to state of the art for this exact
problem, and the design the records here follow: a signed key-value record
identified by a public key, with a monotonic `seq` so a newer record supersedes
an older one and a replayed one is merely out of date. Worth copying, and copied.

**Onion services / self-certifying overlay addresses.** A `.onion` address *is* a
public key — no DNS, no registrar, no IP, and NAT traversal for free. The
strongest available answer to "no hardcoded IPs and no DNS", at the cost of
latency and a dependency on the Tor network's own directory authorities, which is
an anchor with extra steps. A good option to offer, a bad one to require.

**Rendezvous derived from a beacon.** Peers interested in blob `D` announce at a
location derived from `H(D ‖ epoch)`. Gives unlinkability — an observer who does
not know `D` cannot find the swarm — and this repo already has the ingredient, in
the epoch beacon `partition.rs` uses for work assignment. Interesting once there
is a DHT or similar to announce *into*.

**NAT traversal** — hole punching, circuit relay, AutoNAT. Not discovery, and
routinely confused with it: knowing an address does not mean you can reach it.
Unaddressed here, and the reason a node behind a home router cannot yet seed.

## What is built

`src/swarm/discovery.rs` and peer exchange over the connection `swarm::tcp`
already opens.

```sh
proofwork blob serve --listen 0.0.0.0:9797   # announces itself, learns from callers
proofwork blob fetch <digest> --peer HOST:PORT
proofwork blob peers                          # who this node knows how to reach
```

Told one address, once, a node accumulates the rest by asking. Three nodes,
verified end to end:

```
B holds the blob, serving on :9801
A holds nothing, was told about B once, serving on :9802
C knows nobody, and is told about A only

$ proofwork --data-dir c blob fetch sha256:05ad14fa… --peer 127.0.0.1:9802
blob sha256:05ad14fa
  1.8 KiB -> c/cache/blobs

$ proofwork --data-dir c blob peers
da256588ed83a46b  seq 1785515728  127.0.0.1:9801     <- learned from A
ddc5711bca6b4099  seq 1785515729  127.0.0.1:9802
2 peers known
```

C was never told B existed, and A could not serve the blob itself.

**One design consequence worth stating, because getting it wrong is natural.** An
earlier version hung up on a peer asking for a digest it did not hold — the
transfer-shaped decision, and correct for transfers. It broke discovery
completely: **the node that does not have your blob is often the best node to ask
who does.** Refusing to talk to it forfeits exactly the hop that makes bootstrap
a once-ever problem. So a digest this store does not hold now gets no bytes and
peer exchange anyway, bounded by a message budget so it cannot be used as a free
socket.

## What iterates, and what does not yet

Precision matters here, because "we have a DHT" can mean several things.

**Built and tested**: the XOR metric, the k-bucket routing table with the
oldest-live-wins policy, the provider store with expiry, and `Lookup` — the
iterative α-parallel lookup as a pure state machine, with convergence and
termination asserted against a synthetic 200-node network built from real routing
tables.

**Wired**: nodes answer `FIND_NODE` with their nearest contacts and any providers
they know, learn from being asked (XOR symmetry means the table fills itself),
and a fetch issues a single-hop provider query on every connection it opens. A
node without the blob answers routing too — see the design note above.

**Not wired**: the multi-hop driver. `Lookup` is ready and nothing yet feeds it
across connections, so lookups are one hop rather than `O(log n)`. That is
already better than flooding for the common case — a peer you reach knows a
provider — and it is not the asymptotic claim. Also unbuilt: bucket refresh,
provider republication, and announcing to the `k` nodes nearest a key rather than
to whoever you happen to be talking to.

## Where this is wrong

- **The anchor is still there.** It is now one address you are told once instead
  of a name in the source, which is better and is not nothing. A node with an
  empty address book and no `--peer` still cannot start.
- **No NAT traversal.** A node behind a home router can fetch and cannot seed,
  which quietly makes the network more centralised than the protocol suggests.
- **`seq` is wall-clock seconds.** It only has to increase, and a clock that goes
  backwards costs that node announcements until it catches up. Cheap failure,
  deliberately not engineered around.
- **Nothing expires.** A record stays until the book is full, so a long-dead peer
  is dialled forever at the cost of one timeout. Eviction is by lowest `seq`,
  which is a proxy for staleness and not a measurement of it.
- **Peer exchange is a mapping oracle.** Anyone can ask any node for its view and
  assemble the topology. Sharing is bounded and deterministic, which limits the
  rate and not the eventual result. Unlinkability at the transport layer — onion
  routing, or rendezvous under a derived key — is the real answer and is not
  here.
- **A peer record proves identity, not honesty.** It says the key holder claims
  this address. Whether that node serves what it advertises is the bitfield
  problem in [knowledge-store.md](knowledge-store.md), and it is unattributed.
