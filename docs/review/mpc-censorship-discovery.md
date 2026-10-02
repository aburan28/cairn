# Review: threshold escrow, censorship resistance, discovery

October 2026. A step back over the three subsystems that decide whether a
running node can keep a submission alive against a censor and find its peers
without anyone's permission, read with compute cost in mind. The fixes small
enough to land safely went in alongside this note; everything below is what
remains, most important first.

The short version: the cryptography is careful and the documents are candid,
but the **sealed-submission path is library-only**, so the censorship
guarantee `docs/censorship.md` marks *built* is not yet delivered by any
running node; and several loops that run every tick or every session were
quadratic, or held the node lock across a network dial.

## Landed with this note

| area | change | cost before |
|---|---|---|
| sync | `replay_records_with_horizon` digests the log once per session, not once per offered record | O(L²) canonical encodes + SHA-256 per session, under the daemon lock, even between peers already in step |
| transport | inbound sessions run off the accept thread, at most 16 in progress | one socket that connects and sends nothing every 10 s blocked all inbound peers |
| MPC | `committee_size_at` derives balances once per draw, not once per seat per size | ~2,000 full ledger replays per committee draw at the 64-seat maximum |
| MPC | sealing hashes each member's 261 KB McEliece key once, not inside the pairwise duplicate check | ~1 GB of SHA-256 per seal at 64 seats |
| MPC | `open_with_any_subset` documents its real bound (see §1) | doc claimed "ten checks" |
| discovery | key requests cap *requests*, not contacts looked at | the first four keyless peers held every slot forever |
| discovery | LAN beacons are polled outside the node lock and announced every 30 s | a beacon-triggered key dial held the lock; beacons sent 6x the documented rate |

## Larger changes recommended

### 1. Make each published committee share checkable on its own (MPC, consensus)

`open_with_any_subset` tries t-subsets until the AEAD opens. With one garbage
share published first, that is `C(n-1, t-1)` failed opens: measured at 1 ms for
n=9, 42 ms for n=15, 735 ms for n=19; about 40 minutes at n=31 and never at the
64-seat maximum `committee_size_at` grows towards. **Any single seat-holder can
stall the reveal of a large committee**, which is the censorship the feature
exists to defeat.

No discrete-log VSS is needed. Each share is already sealed to its member
under a one-time key from `derive_share_key`. Have the member publish that
per-share key with its `CommitteeShare`; any reader re-opens that member's
`SealedShare` from the envelope and checks the Poly1305 tag. Bad shares are
then identified and attributable, and the reveal takes the first `t` valid
ones: one combine, one open. The key is fresh per encapsulation, so nothing
long-lived leaks. Also bind `CommitteeShare.x` to the seat, so a member cannot
collide with an honest member's index.

Changes a record, so `src/` and `reference/rust/` together, plus new
conformance vectors alongside the frozen ones.

### 2. Wire the sealed path into the running node (censorship) — done

Landed in a follow-up. `committee_share` is exchangeable and replays; `cairn
run` publishes the shares its seats owe (`--committee-identity`) and opens
every reveal that has reached its threshold, each tick; the transport key
doubles as the committee key (`CommitteeKey::from_transport`); and `cairn commit
--sealed` seals a signed claim to the epoch's committee. The subset search is
capped at `MAX_SUBSET_TRIALS`, so a bad share costs a node one bounded search
per new share rather than an unbounded one per tick. Still open: `commit
--sealed` does not route key fetches through `--proxy`, and MCP has no sealed
submit.

### 3. Draw the committee from drand, not the log anchor (MPC, consensus)

`committee_for` keys on `beacon(epoch, anchor)` where the anchor is the last
log hash, which whoever orders the log can grind to seat a colluding majority.
The crate already verifies drand quicknet rounds offline (`drand.rs`); feed the
recorded round into the draw.

### 4. Make an unopenable sealed commitment slashable (MPC, incentives)

The submitter deals its own shares and nothing checks them. Honest shares to an
accomplice plus `t-1` others and garbage to the rest restores the
reveal-or-withhold option sealing was meant to remove. With §1 in place the bad
shares become provable, so a commitment whose published valid shares number at
least `t` but still fail to open is evidence against the dealer. Run
`cairn arena` with a scenario for it.

### 5. Discovery: let peers move, and let the routing table forget

- **Fixed in a follow-up:** a peer that moved is now dialled at its new
  address (a superseding signed record promotes the endpoint in the address
  book); a sighting no longer clears a contact's failure count, and running out
  of deferrals counts as a failure, so dead and keyless contacts are evicted;
  key wants rotate and are capped at `MAX_KEY_WANTS`; and the daemon calls
  `Directory::expire` each tick, which also drops failure counts and parked
  newcomers for contacts the table no longer holds.
- **Sybil records own both signed-record stores.** The swarm `AddressBook`
  evicts lowest `seq`, which the signer chooses (`u64::MAX` is never evicted);
  `peers::Hints` refuses everything after 512 records and never expires.
  Bound `seq` against local time and evict by locally observed age.
- **The rest of the lock problem.** `seed_from_log` and `seed_from_hints` still
  request keys, and resolve hostnames, under the node lock. Move key fetches to
  the worker the seed list already uses.
- **Duplication.** `src/dht.rs` is the one Kademlia; the duplication is in the
  peer stores (`peers::Hints` vs `swarm::discovery::AddressBook`, with different
  eviction) and the swarm provider store, which nothing outside tests announces
  to. Merge the stores' policy; wire or delete the provider store, and correct
  `docs/discovery.md`, which calls it built. `p2p/portmap.rs` is not wired.

### 6. Censorship: proxy leaks and fingerprints

- **Partly fixed in a follow-up:** a proxied node no longer resolves hostnames
  itself (`discovery::dialable_via` skips names in gossip, log and seed hints,
  and a bootstrap file naming a host is refused with an explanation), and LAN
  beacons default to off behind a proxy. Still open: `cairn blob fetch` and
  `cairn commit --sealed` have no `--proxy`, and `Proxy::dial` takes only a
  socket address, so a proxied node cannot use names at all rather than
  handing them to the proxy as `socks5h` would.
- **Active probing**: a listener answers 261,216 random bytes with a well-formed
  reply, so any public listener is confirmable with no prior knowledge. Needs a
  pre-shared token (from the peer record or out of band) before the listener
  reveals anything.
- **Metadata**: commitments carry `objective_id` and `submitter` in plaintext,
  so a sequencer can drop a topic or a pseudonym wholesale; "cannot drop only
  the submissions it dislikes" holds per artifact, not per topic. Nothing pads
  envelopes or transport frames. Bucket-pad both.
- A commitment delayed across an epoch boundary is refused permanently
  (`Node::commit` requires the declared epoch); a censor who can only delay can
  thereby deny.

### 7. Compute, smaller

- `committee_shares_for` re-runs the full committee check (commitment scan,
  objective decode, committee draw, every peer signature) per share; compute the
  commitment's committee once and memoise draws by `(epoch, positions)`.
  `committee_for` also builds and discards a full ranking (`let _ = ranked`).
- `Node::peers()` re-verifies every peer record ever posted, every tick; cache
  by ledger length and compare `seq` before checking a signature (also in
  `Hints::admit` and the swarm `offer`).
- Gossip keeps no memory of rejected candidates, so the same ones are fetched
  and re-scored every session; keep a bounded set of refused ids.
- VDF: `Montgomery::mul` allocates three `Vec`s per squaring; a fixed-width
  in-place multiply is likely 2-3x. `drand::verify` rebuilds `G2Prepared(-g2)`
  every call.

## What is already right

Shamir over GF(2^8) is constant-time, rejects zero and duplicate indices and
bad thresholds, and zeroizes; the envelope binds every KEM leg, the recipient
and the index into each share key; the McEliece handshake confirms keys both
ways with per-direction keys and strictly increasing counters; frame lengths
are checked before allocation; reads use absolute deadlines; relayed DHT
provider claims are never stored; peer records stay out of the log, which keeps
free identities off committees.
