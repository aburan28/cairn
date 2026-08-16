//! Kademlia, once: the metric, the routing table, the lookup, the provider store.
//!
//! Two stacks in this repo need to answer *who holds digest `D` right now* --
//! [`crate::p2p`], which is what the daemon runs, and [`crate::p2p::swarm`], which is
//! the piece-level transfer built beside it. They disagree about almost
//! everything below the question: different identities, different key sizes,
//! different transports, different provenance rules for an answer.
//!
//! They do not disagree about Kademlia. The XOR metric, the `k`-bucket eviction
//! policy and the iterative lookup are the same algorithm in both, and writing
//! it twice would mean maintaining two copies of the one part of a DHT that is
//! genuinely subtle -- and, worse, letting them drift. So the algorithm lives
//! here, generic over a [`Contact`], and each stack supplies its own notion of
//! what a contact *is*.
//!
//! # What the generic parameter is hiding, and why it has to
//!
//! A contact is "an id, a freshness counter, and enough to dial it". The last
//! part is the one that cannot be shared, and the reason is a factor of five
//! thousand:
//!
//! | stack | identity | bytes to carry a key |
//! |---|---|---|
//! | [`crate::p2p::swarm`] | ed25519, signed peer record | 32 |
//! | [`crate::p2p`] | Classic McEliece KEM public key | **261,120** |
//!
//! A routing table is `K` contacts across up to [`ID_BITS`] buckets. Inlining a
//! McEliece key in each would cost a quarter of a gigabyte for a table that is
//! supposed to be the cheap part, so `p2p` stores an id and an address and
//! resolves the key from its address book at dial time. `swarm` inlines the
//! signed record, because at 32 bytes it can, and because carrying the signature
//! is what lets a routing answer be *relayed* without becoming hearsay.
//!
//! That difference is real, load-bearing, and invisible from up here -- which is
//! exactly what a type parameter is for.
//!
//! # What is deliberately *not* here
//!
//! No clock, no randomness, no I/O. A [`Lookup`] is a pure state machine:
//! responses in, next queries out. Convergence, termination and the `alpha`
//! parallelism are asserted on exact output rather than observed on a live
//! network and hoped about. Real Kademlia randomises bucket-refresh targets;
//! that belongs in a driver with a clock, and each stack has its own.
//!
//! Verification is not here either, and that is the sharper omission. A
//! [`Provider`] can only be constructed by the stack that defines it, so the
//! rule "a store never holds a claim it could not prove" is enforced at that
//! constructor rather than by a check in [`ProviderStore::announce`]. Moving it
//! into a trait method would mean this module deciding what counts as proof for
//! two identity schemes it deliberately knows nothing about.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use sha2::{Digest as _, Sha256};

/// Contacts kept per distance band. Kademlia's `k`.
///
/// Twenty is the paper's number and the one every deployment kept, for a reason
/// worth stating: it is chosen so that with high probability at least one contact
/// per bucket is still alive after an hour of churn. It is a redundancy
/// parameter, not a performance one.
pub const K: usize = 20;

/// Lookups in flight at once. Kademlia's `alpha`.
///
/// Three, again from the paper. Above one it hides a slow peer; too far above it
/// and a lookup floods more of the network than it saves.
pub const ALPHA: usize = 3;

/// Bits in a node id, and therefore the number of buckets.
pub const ID_BITS: usize = 256;

/// Provider records one node will hold for one key.
pub const MAX_PROVIDERS: usize = 20;

/// Keys one node will hold provider records for.
pub const MAX_KEYS: usize = 4096;

/// A point in the 256-bit keyspace: a node, or a blob.
///
/// One type for both on purpose. Kademlia's trick is that content and nodes share
/// a metric space, so "who is near this blob" is the same computation as "who is
/// near this node" and one routing table serves both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct NodeId([u8; 32]);

impl NodeId {
    /// The id of a node holding this public key.
    ///
    /// Takes a slice rather than a fixed array because the two callers' keys
    /// differ in size by four orders of magnitude. Hashing is what makes that
    /// irrelevant: a 261 KiB McEliece key and a 32-byte ed25519 key land in the
    /// same keyspace, uniformly, and neither can choose where.
    pub fn of_key(public_key: &[u8]) -> NodeId {
        let mut hasher = Sha256::new();
        hasher.update(public_key);
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        NodeId(out)
    }

    /// The keyspace point of a blob, from its `sha256:` digest.
    ///
    /// The digest *is* the key -- no second hash. Hashing it again would put the
    /// blob at a point nobody could compute without this crate, and the whole
    /// value of content addressing is that anybody can.
    pub fn of_digest(digest: &str) -> Option<NodeId> {
        let hex = digest.strip_prefix("sha256:").unwrap_or(digest);
        if hex.len() != 64 {
            return None;
        }
        let mut out = [0u8; 32];
        for (index, slot) in out.iter_mut().enumerate() {
            *slot = u8::from_str_radix(hex.get(index * 2..index * 2 + 2)?, 16).ok()?;
        }
        Some(NodeId(out))
    }

    /// A raw keyspace point, as it travels on the wire.
    ///
    /// Also the constructor for an identity that is *already* a hash of a key:
    /// [`crate::p2p::handshake::PeerId`] is `sha256(public key)`, so hashing it
    /// again here would put a peer at a point its own handshake cannot derive.
    pub fn from_bytes(bytes: [u8; 32]) -> NodeId {
        NodeId(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// XOR distance.
    ///
    /// The metric the whole design rests on, and its properties are why: it is
    /// symmetric (`d(a,b) == d(b,a)`, so a node learns about the peers that
    /// query it and the table fills itself), and unidirectional (for any point
    /// and any distance there is exactly one node at it, so lookups from
    /// different starts converge on the same path and caching works).
    pub fn distance(self, other: NodeId) -> Distance {
        let mut out = [0u8; 32];
        for (index, slot) in out.iter_mut().enumerate() {
            *slot = self.0[index] ^ other.0[index];
        }
        Distance(out)
    }

    /// Which bucket `other` falls in, or `None` for oneself.
    ///
    /// The index of the highest differing bit, so bucket `i` holds nodes sharing
    /// exactly `255 - i` leading bits. Distant nodes share a bucket and near ones
    /// are finely divided, which is what makes the table `O(log n)` in size while
    /// still resolving the neighbourhood a lookup terminates in.
    pub fn bucket(self, other: NodeId) -> Option<usize> {
        let distance = self.distance(other);
        let leading = distance.leading_zeros();
        if leading == ID_BITS {
            return None;
        }
        Some(ID_BITS - 1 - leading)
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", &self.to_hex()[..16])
    }
}

/// An XOR distance, ordered as a big-endian 256-bit number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Distance([u8; 32]);

impl Distance {
    pub fn leading_zeros(&self) -> usize {
        let mut count = 0;
        for byte in self.0 {
            if byte == 0 {
                count += 8;
            } else {
                count += byte.leading_zeros() as usize;
                break;
            }
        }
        count
    }

    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|b| *b == 0)
    }
}

/// What the routing table needs from a contact, and nothing more.
///
/// Two methods, and the second is the one that is easy to leave out. `seq` is a
/// monotonic freshness counter, and without it a table has no way to tell a peer
/// that *moved* from a peer being *impersonated* by a stale record: readmitting
/// an old address for a known id would let an attacker who once saw a record
/// keep steering traffic at an address the peer has left.
pub trait Contact: Clone {
    fn id(&self) -> NodeId;

    /// Higher supersedes. A stack with no notion of record freshness may return
    /// a constant, which makes "seen again" mean "keep what we have".
    fn seq(&self) -> u64;
}

/// What the provider store needs from a provider record.
///
/// Deliberately not `verify()`. A `Provider` is constructible only by the stack
/// that defines it, so validity is a property of *having* one rather than
/// something re-checked on every insert -- which is the difference between an
/// invariant and a habit.
pub trait Provider: Clone {
    /// Who is claiming to hold the key. Also the deduplication key: one record
    /// per provider per blob, so a peer announcing itself a thousand times
    /// occupies one slot.
    fn provider(&self) -> NodeId;
}

/// What happened when a contact was offered to the table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Insertion<C> {
    /// New, and there was room.
    Added,
    /// Already known; moved to the most-recently-seen end.
    Refreshed,
    /// The bucket is full. **Probe this contact.** If it answers, discard the
    /// newcomer; if it does not, call [`RoutingTable::replace`].
    ///
    /// Returned rather than decided internally because the decision needs a
    /// network round trip, and a data structure that performed one could not be
    /// tested without a network.
    Pending { probe: Box<C> },
    /// The contact is this node.
    Ignored,
}

/// `K` contacts per distance band, oldest-live-wins.
#[derive(Debug, Clone)]
pub struct RoutingTable<C> {
    local: NodeId,
    /// Least-recently-seen first, so the head is the eviction candidate and the
    /// tail is the freshest -- which is the order Kademlia's policy reads in.
    buckets: Vec<Vec<C>>,
}

impl<C: Contact> RoutingTable<C> {
    pub fn new(local: NodeId) -> RoutingTable<C> {
        RoutingTable {
            local,
            buckets: (0..ID_BITS).map(|_| Vec::new()).collect(),
        }
    }

    pub fn local(&self) -> NodeId {
        self.local
    }

    pub fn len(&self) -> usize {
        self.buckets.iter().map(Vec::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Offer a contact.
    pub fn insert(&mut self, contact: C) -> Insertion<C> {
        let Some(index) = self.local.bucket(contact.id()) else {
            return Insertion::Ignored;
        };
        let bucket = &mut self.buckets[index];
        if let Some(position) = bucket.iter().position(|held| held.id() == contact.id()) {
            // Seen again: move to the fresh end, and take the newer record. A
            // peer that moved is the same peer.
            let mut existing = bucket.remove(position);
            if contact.seq() >= existing.seq() {
                existing = contact;
            }
            bucket.push(existing);
            return Insertion::Refreshed;
        }
        if bucket.len() < K {
            bucket.push(contact);
            return Insertion::Added;
        }
        // Full. The oldest contact gets right of first refusal, which is the
        // anti-eclipse rule: longevity is the one thing an attacker flooding
        // fresh identities cannot manufacture.
        Insertion::Pending {
            probe: Box::new(bucket[0].clone()),
        }
    }

    /// Evict a contact that failed its probe, and admit `contact` in its place.
    ///
    /// Returns whether the eviction happened. A `dead` that is no longer in the
    /// table means somebody else already handled it, which is not an error.
    pub fn replace(&mut self, dead: &NodeId, contact: C) -> bool {
        let Some(index) = self.local.bucket(*dead) else {
            return false;
        };
        let bucket = &mut self.buckets[index];
        let Some(position) = bucket.iter().position(|held| held.id() == *dead) else {
            return false;
        };
        bucket.remove(position);
        bucket.push(contact);
        true
    }

    /// Drop a contact known to be gone.
    pub fn remove(&mut self, id: &NodeId) -> bool {
        let Some(index) = self.local.bucket(*id) else {
            return false;
        };
        let bucket = &mut self.buckets[index];
        match bucket.iter().position(|held| held.id() == *id) {
            Some(position) => {
                bucket.remove(position);
                true
            }
            None => false,
        }
    }

    /// The `count` contacts nearest `target`, nearest first.
    ///
    /// The one query the routing table exists to answer: it is what a node
    /// returns for `FIND_NODE`, and what seeds a [`Lookup`].
    pub fn closest(&self, target: NodeId, count: usize) -> Vec<C> {
        let mut all: Vec<(Distance, &C)> = self
            .buckets
            .iter()
            .flatten()
            .map(|contact| (contact.id().distance(target), contact))
            .collect();
        // Distance first; id breaks ties so the answer is total and reproducible
        // rather than dependent on bucket iteration order.
        all.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.id().cmp(&b.1.id())));
        all.into_iter()
            .take(count)
            .map(|(_, contact)| contact.clone())
            .collect()
    }

    pub fn contacts(&self) -> impl Iterator<Item = &C> {
        self.buckets.iter().flatten()
    }
}

/// One iterative lookup, as a pure state machine.
///
/// Kademlia's convergence argument in code: repeatedly query the `alpha` closest
/// unqueried nodes, keep the `k` closest seen, and stop when a round produces
/// nothing nearer. Each hop at least halves the distance in expectation, so the
/// whole thing terminates in `O(log n)` rounds.
#[derive(Debug, Clone)]
pub struct Lookup<C, P> {
    target: NodeId,
    /// Everything heard of, keyed by distance so the closest is always first.
    shortlist: BTreeMap<Distance, C>,
    queried: BTreeSet<NodeId>,
    in_flight: BTreeSet<NodeId>,
    /// Provider records collected on the way, for a `GET_PROVIDERS` lookup.
    providers: Vec<P>,
    alpha: usize,
    k: usize,
}

impl<C: Contact, P: Provider> Lookup<C, P> {
    pub fn new(target: NodeId, seeds: Vec<C>) -> Lookup<C, P> {
        Lookup::with(target, seeds, ALPHA, K)
    }

    pub fn with(target: NodeId, seeds: Vec<C>, alpha: usize, k: usize) -> Lookup<C, P> {
        let mut lookup = Lookup {
            target,
            shortlist: BTreeMap::new(),
            queried: BTreeSet::new(),
            in_flight: BTreeSet::new(),
            providers: Vec::new(),
            alpha: alpha.max(1),
            k: k.max(1),
        };
        for seed in seeds {
            lookup.consider(seed);
        }
        lookup
    }

    pub fn target(&self) -> NodeId {
        self.target
    }

    fn consider(&mut self, contact: C) {
        let distance = contact.id().distance(self.target);
        self.shortlist.entry(distance).or_insert(contact);
    }

    /// The next contacts to query: up to `alpha` unqueried nodes among the `k`
    /// closest known.
    ///
    /// Restricting to the `k` closest is what keeps a lookup from wandering: a
    /// malicious peer returning a thousand distant contacts cannot make this node
    /// query them, because they never enter the frontier.
    pub fn next_queries(&mut self) -> Vec<C> {
        let frontier: Vec<C> = self
            .shortlist
            .values()
            .take(self.k)
            .filter(|contact| {
                !self.queried.contains(&contact.id()) && !self.in_flight.contains(&contact.id())
            })
            .take(self.alpha.saturating_sub(self.in_flight.len()))
            .cloned()
            .collect();
        for contact in &frontier {
            self.in_flight.insert(contact.id());
        }
        frontier
    }

    /// Fold in an answer.
    pub fn on_response(&mut self, from: NodeId, closer: Vec<C>, providers: Vec<P>) {
        self.in_flight.remove(&from);
        self.queried.insert(from);
        for contact in closer {
            self.consider(contact);
        }
        for record in providers {
            if !self
                .providers
                .iter()
                .any(|held| held.provider() == record.provider())
            {
                self.providers.push(record);
            }
        }
    }

    /// A peer that did not answer.
    ///
    /// Marked queried, not forgotten: retrying a silent node is how a lookup
    /// stops terminating.
    pub fn on_timeout(&mut self, from: NodeId) {
        self.in_flight.remove(&from);
        self.queried.insert(from);
    }

    /// A peer that could not be asked *yet*, and should be offered again.
    ///
    /// The difference from [`Lookup::on_timeout`] is the whole point: a timeout
    /// says "this peer had its turn", a deferral says "this peer has not had a
    /// turn at all". The case is a contact whose address is known and whose key
    /// is not — it cannot be dialled this round, and marking it queried would
    /// write it off a round before the key that makes it reachable arrives.
    ///
    /// **A deferral on its own does not terminate**, and the caller owns that:
    /// a contact deferred forever is offered forever. [`crate::p2p::dht`] bounds
    /// it by counting deferrals per contact and converting to a timeout.
    pub fn defer(&mut self, from: NodeId) {
        self.in_flight.remove(&from);
    }

    /// True when nothing is outstanding and the `k` closest have all been asked.
    pub fn is_done(&self) -> bool {
        if !self.in_flight.is_empty() {
            return false;
        }
        self.shortlist
            .values()
            .take(self.k)
            .all(|contact| self.queried.contains(&contact.id()))
    }

    /// The `k` closest contacts found.
    pub fn closest(&self) -> Vec<C> {
        self.shortlist.values().take(self.k).cloned().collect()
    }

    /// Provider records collected, in the order first heard.
    pub fn providers(&self) -> &[P] {
        &self.providers
    }
}

/// Who claims to hold what, with an expiry.
///
/// Expiry is the reason this cannot live in the log. A provider that goes away
/// stops republishing and its record lapses; an append-only structure has no way
/// to express "no longer true", and would advertise a dead node forever.
///
/// Time is supplied by the caller rather than read here, so the store stays as
/// testable as everything else in this module -- and because a node's clock is
/// not evidence, which is the same rule `replay` enforces on verification.
#[derive(Debug, Clone)]
pub struct ProviderStore<P> {
    keys: BTreeMap<NodeId, Vec<(P, u64)>>,
}

impl<P> Default for ProviderStore<P> {
    fn default() -> ProviderStore<P> {
        ProviderStore {
            keys: BTreeMap::new(),
        }
    }
}

impl<P: Provider> ProviderStore<P> {
    pub fn new() -> ProviderStore<P> {
        ProviderStore::default()
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Record that `record`'s provider holds `key`, until `expires_at`.
    ///
    /// Returns whether anything was stored. There is no verification step here
    /// and that is not an omission -- see [`Provider`]: a record that exists has
    /// already been proved by whoever constructed it.
    pub fn announce(&mut self, key: NodeId, record: &P, expires_at: u64) -> bool {
        if self.keys.len() >= MAX_KEYS && !self.keys.contains_key(&key) {
            return false;
        }
        let entries = self.keys.entry(key).or_default();
        if let Some(existing) = entries
            .iter_mut()
            .find(|(held, _)| held.provider() == record.provider())
        {
            existing.0 = record.clone();
            existing.1 = existing.1.max(expires_at);
            return true;
        }
        if entries.len() >= MAX_PROVIDERS {
            // Drop the soonest to expire, which is the one least likely to still
            // be there -- never "whatever arrived last", which a flooder picks.
            if let Some(position) = entries
                .iter()
                .enumerate()
                .min_by_key(|(_, (_, at))| *at)
                .map(|(index, _)| index)
            {
                if entries[position].1 >= expires_at {
                    return false;
                }
                entries.remove(position);
            }
        }
        entries.push((record.clone(), expires_at));
        true
    }

    /// Who holds `key`, as of `now`.
    pub fn providers(&self, key: NodeId, now: u64) -> Vec<P> {
        self.keys
            .get(&key)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|(_, at)| *at > now)
                    .map(|(record, _)| record.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Drop everything that has lapsed. Returns how many records went.
    pub fn expire(&mut self, now: u64) -> usize {
        let mut dropped = 0;
        for entries in self.keys.values_mut() {
            let before = entries.len();
            entries.retain(|(_, at)| *at > now);
            dropped += before - entries.len();
        }
        self.keys.retain(|_, entries| !entries.is_empty());
        dropped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The smallest thing that satisfies both traits, so the algorithm is tested
    /// without either stack's identity scheme in the way.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Probe {
        id: NodeId,
        seq: u64,
    }

    impl Probe {
        fn at(byte: u8) -> Probe {
            let mut raw = [0u8; 32];
            raw[0] = byte;
            Probe {
                id: NodeId::from_bytes(raw),
                seq: 0,
            }
        }

        fn wide(first: u8, second: u8) -> Probe {
            let mut raw = [0u8; 32];
            raw[0] = first;
            raw[1] = second;
            Probe {
                id: NodeId::from_bytes(raw),
                seq: 0,
            }
        }
    }

    impl Contact for Probe {
        fn id(&self) -> NodeId {
            self.id
        }
        fn seq(&self) -> u64 {
            self.seq
        }
    }

    impl Provider for Probe {
        fn provider(&self) -> NodeId {
            self.id
        }
    }

    #[test]
    fn distance_is_symmetric_and_zero_only_to_oneself() {
        let a = Probe::at(0x0f).id;
        let b = Probe::at(0xf0).id;
        assert_eq!(a.distance(b), b.distance(a));
        assert!(a.distance(a).is_zero());
        assert!(!a.distance(b).is_zero());
    }

    #[test]
    fn a_node_is_in_no_bucket_of_its_own_table() {
        let local = Probe::at(1).id;
        assert_eq!(local.bucket(local), None);
    }

    #[test]
    fn a_blob_digest_is_its_own_keyspace_point_with_no_second_hash() {
        let hex = "ab".repeat(32);
        let with = NodeId::of_digest(&format!("sha256:{hex}")).expect("parses");
        let without = NodeId::of_digest(&hex).expect("parses");
        assert_eq!(with, without);
        assert_eq!(with.to_hex(), hex);
    }

    #[test]
    fn a_malformed_digest_is_refused_rather_than_hashed_into_the_keyspace() {
        assert_eq!(NodeId::of_digest("sha256:short"), None);
        assert_eq!(NodeId::of_digest(&"zz".repeat(32)), None);
    }

    #[test]
    fn keys_of_wildly_different_sizes_land_in_the_same_keyspace() {
        // The whole reason `of_key` takes a slice: 32 bytes and 261,120 bytes
        // are both just preimages.
        let small = NodeId::of_key(&[7u8; 32]);
        let large = NodeId::of_key(&vec![7u8; 261_120]);
        assert_ne!(small, large);
        assert_eq!(small.as_bytes().len(), large.as_bytes().len());
    }

    #[test]
    fn a_full_bucket_offers_the_oldest_contact_for_probing_rather_than_evicting_it() {
        let mut table: RoutingTable<Probe> = RoutingTable::new(NodeId::default());
        // All of these share a bucket: they differ from the local id only in the
        // top byte's high bit region.
        for index in 0..K {
            let contact = Probe::wide(0x80, index as u8);
            assert_eq!(table.insert(contact), Insertion::Added);
        }
        let newcomer = Probe::wide(0x80, 0xff);
        match table.insert(newcomer.clone()) {
            Insertion::Pending { probe } => {
                assert_eq!(probe.id, Probe::wide(0x80, 0).id, "the oldest is offered");
            }
            other => panic!("expected a pending probe, got {other:?}"),
        }
        assert_eq!(
            table.len(),
            K,
            "nothing was evicted behind the caller's back"
        );
    }

    #[test]
    fn a_probe_that_fails_lets_the_newcomer_in_and_one_that_answers_does_not() {
        let mut table: RoutingTable<Probe> = RoutingTable::new(NodeId::default());
        for index in 0..K {
            table.insert(Probe::wide(0x80, index as u8));
        }
        let newcomer = Probe::wide(0x80, 0xff);
        let dead = Probe::wide(0x80, 0).id;
        assert!(table.replace(&dead, newcomer.clone()));
        assert_eq!(table.len(), K);
        assert!(table.contacts().any(|c| c.id == newcomer.id));
        assert!(!table.contacts().any(|c| c.id == dead));
        // And a second attempt against the same, now-absent, id is a no-op
        // rather than a corruption.
        assert!(!table.replace(&dead, Probe::wide(0x80, 0xfe)));
    }

    #[test]
    fn seeing_a_known_contact_again_takes_the_newer_record_and_never_the_older() {
        let mut table: RoutingTable<Probe> = RoutingTable::new(NodeId::default());
        let mut contact = Probe::at(0x80);
        contact.seq = 5;
        table.insert(contact.clone());

        let mut newer = contact.clone();
        newer.seq = 9;
        assert_eq!(table.insert(newer), Insertion::Refreshed);
        assert_eq!(table.contacts().next().expect("held").seq, 9);

        let mut stale = contact;
        stale.seq = 1;
        assert_eq!(table.insert(stale), Insertion::Refreshed);
        assert_eq!(
            table.contacts().next().expect("held").seq,
            9,
            "a replayed old record must not displace a newer one"
        );
    }

    #[test]
    fn closest_is_ordered_by_xor_distance_and_not_by_bucket_order() {
        let mut table: RoutingTable<Probe> = RoutingTable::new(NodeId::default());
        for byte in [0x01u8, 0x40, 0x80, 0xc0] {
            table.insert(Probe::at(byte));
        }
        let target = Probe::at(0x81).id;
        let near = table.closest(target, 2);
        assert_eq!(near.len(), 2);
        assert_eq!(near[0].id, Probe::at(0x80).id);
        // 0x80^0x81 = 0x01 is nearest; 0xc0^0x81 = 0x41 beats 0x40^0x81 = 0xc1.
        assert_eq!(near[1].id, Probe::at(0xc0).id);
    }

    #[test]
    fn a_lookup_asks_at_most_alpha_at_a_time_and_terminates() {
        let seeds: Vec<Probe> = (1..=8).map(Probe::at).collect();
        let mut lookup: Lookup<Probe, Probe> = Lookup::with(Probe::at(0xff).id, seeds, 3, K);
        let first = lookup.next_queries();
        assert_eq!(first.len(), 3, "alpha bounds the round");
        assert!(lookup.next_queries().is_empty(), "already in flight");
        assert!(!lookup.is_done());

        let mut rounds = 0;
        let mut pending = first;
        while !pending.is_empty() {
            rounds += 1;
            assert!(rounds < 100, "a lookup that does not terminate");
            for contact in pending {
                lookup.on_response(contact.id, Vec::new(), Vec::new());
            }
            pending = lookup.next_queries();
        }
        assert!(lookup.is_done());
    }

    #[test]
    fn a_peer_returning_distant_contacts_cannot_widen_the_frontier() {
        let target = Probe::at(0xff).id;
        let mut lookup: Lookup<Probe, Probe> = Lookup::with(target, vec![Probe::at(0xfe)], 3, 1);
        let first = lookup.next_queries();
        assert_eq!(first.len(), 1);
        // A thousand far-away contacts, offered as "closer".
        let flood: Vec<Probe> = (1..=200).map(|n| Probe::wide(n, 0)).collect();
        lookup.on_response(first[0].id, flood, Vec::new());
        assert!(
            lookup.next_queries().is_empty(),
            "k=1 means only the nearest is ever a candidate, and it was queried"
        );
        assert!(lookup.is_done());
    }

    #[test]
    fn a_silent_peer_is_marked_queried_so_the_lookup_still_finishes() {
        let mut lookup: Lookup<Probe, Probe> =
            Lookup::with(Probe::at(0xff).id, vec![Probe::at(1)], 3, K);
        let first = lookup.next_queries();
        lookup.on_timeout(first[0].id);
        assert!(
            lookup.is_done(),
            "a timeout must not leave a lookup hanging"
        );
        assert!(lookup.next_queries().is_empty());
    }

    #[test]
    fn providers_collected_across_hops_are_deduplicated_by_provider() {
        let mut lookup: Lookup<Probe, Probe> =
            Lookup::with(Probe::at(0xff).id, vec![Probe::at(1), Probe::at(2)], 3, K);
        let round = lookup.next_queries();
        let holder = Probe::at(0x55);
        for contact in &round {
            lookup.on_response(contact.id, Vec::new(), vec![holder.clone()]);
        }
        assert_eq!(lookup.providers().len(), 1, "two hops, one holder");
    }

    #[test]
    fn a_provider_record_lapses_rather_than_being_advertised_forever() {
        let mut store: ProviderStore<Probe> = ProviderStore::new();
        let key = NodeId::of_digest(&"cd".repeat(32)).expect("parses");
        assert!(store.announce(key, &Probe::at(3), 100));
        assert_eq!(store.providers(key, 50).len(), 1);
        assert_eq!(store.providers(key, 100).len(), 0, "expiry is exclusive");
        assert_eq!(store.expire(100), 1);
        assert!(store.is_empty(), "an empty key is dropped, not kept");
    }

    #[test]
    fn re_announcing_extends_an_expiry_and_never_shortens_it() {
        let mut store: ProviderStore<Probe> = ProviderStore::new();
        let key = NodeId::of_digest(&"cd".repeat(32)).expect("parses");
        store.announce(key, &Probe::at(3), 100);
        store.announce(key, &Probe::at(3), 50);
        assert_eq!(
            store.providers(key, 75).len(),
            1,
            "a shorter re-announcement must not cut a live record short"
        );
        assert_eq!(store.len(), 1, "one key, one provider, announced twice");
    }

    #[test]
    fn a_flood_of_providers_for_one_key_evicts_the_soonest_to_expire() {
        let mut store: ProviderStore<Probe> = ProviderStore::new();
        let key = NodeId::of_digest(&"cd".repeat(32)).expect("parses");
        for index in 0..MAX_PROVIDERS {
            // Later indices expire later, so index 0 is the eviction candidate.
            store.announce(key, &Probe::at(index as u8 + 1), 100 + index as u64);
        }
        assert_eq!(store.providers(key, 0).len(), MAX_PROVIDERS);

        let soonest = Probe::at(1).provider();
        assert!(store.announce(key, &Probe::at(200), 500));
        let held = store.providers(key, 0);
        assert_eq!(held.len(), MAX_PROVIDERS);
        assert!(
            !held.iter().any(|p| p.provider() == soonest),
            "the record least likely to still be live is the one that goes"
        );

        // And an arrival that would expire sooner than everything held is
        // refused outright, so a flooder cannot churn the set.
        assert!(!store.announce(key, &Probe::at(201), 1));
    }

    #[test]
    fn the_key_ceiling_bounds_memory_but_never_blocks_a_key_already_held() {
        let mut store: ProviderStore<Probe> = ProviderStore::new();
        for index in 0..MAX_KEYS {
            let mut raw = [0u8; 32];
            raw[0..8].copy_from_slice(&(index as u64).to_be_bytes());
            store.announce(NodeId::from_bytes(raw), &Probe::at(1), 100);
        }
        assert_eq!(store.len(), MAX_KEYS);

        let fresh = NodeId::from_bytes([0xff; 32]);
        assert!(!store.announce(fresh, &Probe::at(1), 100), "ceiling holds");

        let known = NodeId::from_bytes([0u8; 32]);
        assert!(
            store.announce(known, &Probe::at(2), 100),
            "a key already held keeps accepting providers, or a popular blob \
             would stop being findable the moment the table filled"
        );
    }
}
