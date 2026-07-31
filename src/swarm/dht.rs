//! Kademlia: finding *who has a blob* in `O(log n)` instead of by asking everyone.
//!
//! [`super::discovery`] answers "which peers exist". This answers the question
//! `blob fetch` actually has -- **who holds digest `D` right now** -- and the two
//! are different problems that want different structures:
//!
//! | | churn | shape | where it belongs |
//! |---|---|---|---|
//! | peer identity | permanent | a key that never changes | the log, eventually |
//! | provider records | constant | expires, republished, revoked by silence | **here**, and never in an append-only log |
//!
//! Without this, a fetch dials every peer in the address book and asks each one.
//! That is flooding: fine at ten peers, hopeless at ten thousand, and it gets
//! worse exactly as the network gets more useful. Kademlia turns it into
//! `O(log n)` hops by making *distance* something you can compute.
//!
//! # Why this is safe here in a way it usually is not
//!
//! DHTs have a bad security reputation, and it is deserved in the systems that
//! made it. BitTorrent's DHT can hand you a poisoned answer and you have no way
//! to know until much later. That failure mode does not exist here, and the
//! reason is work already done:
//!
//! > **Every DHT answer is a hint. The digest decides.**
//!
//! A provider record says "this peer claims to hold `D`". If it lies, the
//! transfer fails against a digest the *log* fixed before the lookup started, and
//! the cost is one wasted dial. So the classic attacks degrade politely:
//!
//! - **Eclipse** -- surround a key with adversarial nodes so lookups fail. Costs
//!   **liveness**, never correctness, and the address book and peer exchange are
//!   still there as a fallback path that does not route through the DHT at all.
//! - **Poisoning** -- announce provider records for content you do not have.
//!   Costs the asker a dial and costs the liar its reputation with that asker.
//! - **Sybil** -- flood node IDs. Mitigated below, and bounded by the same
//!   observation: a sybil that wins the routing table still cannot produce bytes
//!   that hash correctly.
//!
//! That is the argument for building it: the content addressing and the signed
//! records make a DHT *safe to get wrong*, which is not true of most places one
//! is deployed.
//!
//! # Node IDs are public keys, which is S/Kademlia's fix for free
//!
//! A [`NodeId`] is the SHA-256 of an ed25519 public key, and every contact
//! carries the signed record that proves it. So a node cannot claim an ID it does
//! not hold the key for, and the "generate IDs until one lands next to the key I
//! want to eclipse" attack costs a keypair *and a signature* per attempt rather
//! than a counter increment. S/Kademlia proposes crypto puzzles for exactly this;
//! here the identity layer already provided it.
//!
//! Binding IDs to something genuinely scarce -- the bond in
//! [`crate::incentive`] -- is the stronger version and is not built. Keys are
//! cheap; stake is not.
//!
//! # The k-bucket policy is the anti-eclipse mechanism, not the routing
//!
//! Kademlia's routing table keeps `K` contacts per distance band, and the rule
//! that matters is what happens when a bucket is **full**: the *oldest still-live*
//! contact wins and the newcomer is discarded. That is backwards from every cache
//! anyone writes by reflex, and it is the whole defence -- an attacker flooding
//! fresh identities cannot displace nodes that have been reachable for hours,
//! because longevity is the one thing flooding cannot manufacture.
//!
//! [`RoutingTable::insert`] therefore does not silently evict. It returns
//! [`Insertion::Pending`] naming the contact to probe, and the caller decides
//! after actually trying it. Keeping that decision out of the data structure is
//! what makes the policy testable without a network.
//!
//! # Determinism
//!
//! No clock and no randomness, like [`super::Swarm`]. A [`Lookup`] is a pure
//! state machine -- responses in, next queries out -- so convergence, termination
//! and the `alpha` parallelism are asserted on exact output rather than observed
//! on a live network and hoped about. Real Kademlia randomises bucket refresh
//! targets; that belongs in the driver with the clock.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use sha2::{Digest as _, Sha256};

use super::discovery::{DiscoveryError, PeerRecord};
use crate::crypto::identity::SignedRecord;

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
    pub fn of_key(public_key: &[u8; 32]) -> NodeId {
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

/// A peer in the routing table: where it is, and the proof it said so.
///
/// The signed record travels with the contact so a routing answer can be
/// *relayed*. A DHT whose contacts were bare addresses would make every hop
/// hearsay, and the asker would have to trust the whole path rather than none of
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contact {
    pub id: NodeId,
    pub record: PeerRecord,
    pub signed: SignedRecord,
}

impl Contact {
    /// Verify a signed record and turn it into a contact.
    pub fn open(signed: &SignedRecord) -> Result<Contact, DiscoveryError> {
        let record = PeerRecord::open(signed)?;
        Ok(Contact {
            id: NodeId::of_key(&signed.public_key),
            record,
            signed: signed.clone(),
        })
    }
}

/// What happened when a contact was offered to the table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Insertion {
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
    Pending { probe: Box<Contact> },
    /// The contact is this node.
    Ignored,
}

/// `K` contacts per distance band, oldest-live-wins.
#[derive(Debug, Clone)]
pub struct RoutingTable {
    local: NodeId,
    /// Least-recently-seen first, so the head is the eviction candidate and the
    /// tail is the freshest -- which is the order Kademlia's policy reads in.
    buckets: Vec<Vec<Contact>>,
}

impl RoutingTable {
    pub fn new(local: NodeId) -> RoutingTable {
        RoutingTable {
            local,
            buckets: vec![Vec::new(); ID_BITS],
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
    pub fn insert(&mut self, contact: Contact) -> Insertion {
        let Some(index) = self.local.bucket(contact.id) else {
            return Insertion::Ignored;
        };
        let bucket = &mut self.buckets[index];
        if let Some(position) = bucket.iter().position(|held| held.id == contact.id) {
            // Seen again: move to the fresh end, and take the newer record. A
            // peer that moved is the same peer.
            let mut existing = bucket.remove(position);
            if contact.record.seq >= existing.record.seq {
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
    pub fn replace(&mut self, dead: &NodeId, contact: Contact) -> bool {
        let Some(index) = self.local.bucket(*dead) else {
            return false;
        };
        let bucket = &mut self.buckets[index];
        let Some(position) = bucket.iter().position(|held| held.id == *dead) else {
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
        match bucket.iter().position(|held| held.id == *id) {
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
    pub fn closest(&self, target: NodeId, count: usize) -> Vec<Contact> {
        let mut all: Vec<(Distance, &Contact)> = self
            .buckets
            .iter()
            .flatten()
            .map(|contact| (contact.id.distance(target), contact))
            .collect();
        // Distance first; id breaks ties so the answer is total and reproducible
        // rather than dependent on bucket iteration order.
        all.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.id.cmp(&b.1.id)));
        all.into_iter()
            .take(count)
            .map(|(_, contact)| contact.clone())
            .collect()
    }

    pub fn contacts(&self) -> impl Iterator<Item = &Contact> {
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
pub struct Lookup {
    target: NodeId,
    /// Everything heard of, keyed by distance so the closest is always first.
    shortlist: BTreeMap<Distance, Contact>,
    queried: BTreeSet<NodeId>,
    in_flight: BTreeSet<NodeId>,
    /// Provider records collected on the way, for a `GET_PROVIDERS` lookup.
    providers: Vec<SignedRecord>,
    alpha: usize,
    k: usize,
}

impl Lookup {
    pub fn new(target: NodeId, seeds: Vec<Contact>) -> Lookup {
        Lookup::with(target, seeds, ALPHA, K)
    }

    pub fn with(target: NodeId, seeds: Vec<Contact>, alpha: usize, k: usize) -> Lookup {
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

    fn consider(&mut self, contact: Contact) {
        let distance = contact.id.distance(self.target);
        self.shortlist.entry(distance).or_insert(contact);
    }

    /// The next contacts to query: up to `alpha` unqueried nodes among the `k`
    /// closest known.
    ///
    /// Restricting to the `k` closest is what keeps a lookup from wandering: a
    /// malicious peer returning a thousand distant contacts cannot make this node
    /// query them, because they never enter the frontier.
    pub fn next_queries(&mut self) -> Vec<Contact> {
        let frontier: Vec<Contact> = self
            .shortlist
            .values()
            .take(self.k)
            .filter(|contact| {
                !self.queried.contains(&contact.id) && !self.in_flight.contains(&contact.id)
            })
            .take(self.alpha.saturating_sub(self.in_flight.len()))
            .cloned()
            .collect();
        for contact in &frontier {
            self.in_flight.insert(contact.id);
        }
        frontier
    }

    /// Fold in an answer.
    pub fn on_response(
        &mut self,
        from: NodeId,
        closer: Vec<Contact>,
        providers: Vec<SignedRecord>,
    ) {
        self.in_flight.remove(&from);
        self.queried.insert(from);
        for contact in closer {
            self.consider(contact);
        }
        for record in providers {
            if !self
                .providers
                .iter()
                .any(|held| held.public_key == record.public_key)
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

    /// True when nothing is outstanding and the `k` closest have all been asked.
    pub fn is_done(&self) -> bool {
        if !self.in_flight.is_empty() {
            return false;
        }
        self.shortlist
            .values()
            .take(self.k)
            .all(|contact| self.queried.contains(&contact.id))
    }

    /// The `k` closest contacts found.
    pub fn closest(&self) -> Vec<Contact> {
        self.shortlist.values().take(self.k).cloned().collect()
    }

    /// Provider records collected, in the order first heard.
    pub fn providers(&self) -> &[SignedRecord] {
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
#[derive(Debug, Clone, Default)]
pub struct ProviderStore {
    keys: BTreeMap<NodeId, Vec<(SignedRecord, u64)>>,
}

impl ProviderStore {
    pub fn new() -> ProviderStore {
        ProviderStore::default()
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Record that the signer of `record` holds `key`, until `expires_at`.
    ///
    /// Verified here, so a store never holds a claim it could not prove. Returns
    /// whether anything was stored.
    pub fn announce(
        &mut self,
        key: NodeId,
        record: &SignedRecord,
        expires_at: u64,
    ) -> Result<bool, DiscoveryError> {
        PeerRecord::open(record)?;
        if self.keys.len() >= MAX_KEYS && !self.keys.contains_key(&key) {
            return Ok(false);
        }
        let entries = self.keys.entry(key).or_default();
        if let Some(existing) = entries
            .iter_mut()
            .find(|(held, _)| held.public_key == record.public_key)
        {
            existing.0 = record.clone();
            existing.1 = existing.1.max(expires_at);
            return Ok(true);
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
                    return Ok(false);
                }
                entries.remove(position);
            }
        }
        entries.push((record.clone(), expires_at));
        Ok(true)
    }

    /// Who holds `key`, as of `now`.
    pub fn providers(&self, key: NodeId, now: u64) -> Vec<SignedRecord> {
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
    use crate::crypto::identity::Identity;
    use std::net::SocketAddr;

    fn identity(n: u64) -> Identity {
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&(n + 1).to_be_bytes());
        Identity::from_secret_bytes(seed)
    }

    fn addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().expect("an address")
    }

    fn contact(n: u64) -> Contact {
        let id = identity(n);
        let signed = PeerRecord::sign(&id, &[addr(9000 + (n as u16 % 1000))], 1).expect("signs");
        Contact::open(&signed).expect("verifies")
    }

    #[test]
    fn xor_distance_is_symmetric_and_zero_only_to_itself() {
        // The two properties the whole design rests on. Symmetry is why a node
        // learns from the peers that query it, so the table fills itself.
        let a = contact(1).id;
        let b = contact(2).id;
        assert_eq!(a.distance(b), b.distance(a));
        assert!(a.distance(a).is_zero());
        assert!(!a.distance(b).is_zero());
        assert_eq!(a.bucket(a), None, "a node is in no bucket of its own");
        assert!(a.bucket(b).is_some());
    }

    #[test]
    fn the_bucket_index_is_the_highest_differing_bit() {
        let zero = NodeId([0u8; 32]);
        // Flipping the top bit is the most distant band.
        let mut top = [0u8; 32];
        top[0] = 0x80;
        assert_eq!(zero.bucket(NodeId(top)), Some(255));
        // Flipping the bottom bit is the nearest.
        let mut bottom = [0u8; 32];
        bottom[31] = 0x01;
        assert_eq!(zero.bucket(NodeId(bottom)), Some(0));
        let mut mid = [0u8; 32];
        mid[0] = 0x01;
        assert_eq!(zero.bucket(NodeId(mid)), Some(248));
    }

    #[test]
    fn a_blob_digest_is_its_own_keyspace_point() {
        // No second hash. Hashing the digest again would put the blob somewhere
        // nobody could compute without this crate, and the value of content
        // addressing is that anybody can.
        let digest = crate::canonical::digest_bytes(b"an evaluator");
        let key = NodeId::of_digest(&digest).expect("a digest");
        assert_eq!(
            key,
            NodeId::of_digest(digest.strip_prefix("sha256:").expect("prefixed")).expect("bare hex"),
            "both spellings name one point"
        );
        assert_eq!(format!("sha256:{}", key.to_hex()), digest);
        assert_eq!(NodeId::of_digest("nonsense"), None);
        assert_eq!(NodeId::of_digest(&"z".repeat(64)), None);
    }

    #[test]
    fn a_full_bucket_defers_to_the_oldest_contact_rather_than_evicting_it() {
        // The anti-eclipse rule, and it is backwards from every cache written by
        // reflex: an attacker flooding fresh identities cannot displace nodes
        // that have been reachable for hours, because longevity is the one thing
        // flooding cannot manufacture.
        let local = NodeId([0u8; 32]);
        let mut table = RoutingTable::new(local);

        // Fill one bucket. Contacts whose ids share a top bit land together.
        let mut placed: Vec<Contact> = Vec::new();
        let mut n = 0u64;
        while placed.len() < K {
            let candidate = contact(n);
            n += 1;
            if local.bucket(candidate.id) == Some(255) {
                assert_eq!(table.insert(candidate.clone()), Insertion::Added);
                placed.push(candidate);
            }
        }
        let oldest = placed[0].clone();

        // The next one into that bucket is deferred, not admitted.
        let newcomer = loop {
            let candidate = contact(n);
            n += 1;
            if local.bucket(candidate.id) == Some(255) {
                break candidate;
            }
        };
        match table.insert(newcomer.clone()) {
            Insertion::Pending { probe } => assert_eq!(*probe, oldest, "the oldest is probed"),
            other => panic!("expected Pending, got {other:?}"),
        }
        assert_eq!(table.len(), K, "and nothing was evicted on its own");

        // Only when the probe fails does the newcomer get in.
        assert!(table.replace(&oldest.id, newcomer.clone()));
        assert_eq!(table.len(), K);
        assert!(table.contacts().any(|c| c.id == newcomer.id));
        assert!(!table.contacts().any(|c| c.id == oldest.id));
    }

    #[test]
    fn seeing_a_contact_again_refreshes_it_and_takes_the_newer_record() {
        let local = NodeId([1u8; 32]);
        let mut table = RoutingTable::new(local);
        let first = contact(5);
        assert_eq!(table.insert(first.clone()), Insertion::Added);

        let moved =
            Contact::open(&PeerRecord::sign(&identity(5), &[addr(4444)], 9).expect("signs"))
                .expect("verifies");
        assert_eq!(table.insert(moved.clone()), Insertion::Refreshed);
        assert_eq!(table.len(), 1, "one peer, however many records");
        let held = table.contacts().next().expect("present");
        assert_eq!(held.record.addrs, vec![addr(4444)], "the peer moved");

        // An older record does not undo that.
        assert_eq!(table.insert(first), Insertion::Refreshed);
        let held = table.contacts().next().expect("present");
        assert_eq!(held.record.addrs, vec![addr(4444)]);
    }

    #[test]
    fn a_node_is_never_a_contact_of_itself() {
        let me = contact(11);
        let mut table = RoutingTable::new(me.id);
        assert_eq!(table.insert(me), Insertion::Ignored);
        assert!(table.is_empty());
    }

    #[test]
    fn closest_is_ordered_by_distance_and_is_reproducible() {
        let local = NodeId([0u8; 32]);
        let mut table = RoutingTable::new(local);
        for n in 0..60 {
            table.insert(contact(n));
        }
        let target = contact(7).id;
        let near = table.closest(target, 5);
        assert_eq!(near.len(), 5);
        for pair in near.windows(2) {
            assert!(
                pair[0].id.distance(target) <= pair[1].id.distance(target),
                "closest is not sorted"
            );
        }
        assert_eq!(near[0].id, target, "the target itself is nearest to itself");
        assert_eq!(
            table.closest(target, 5),
            near,
            "the answer is reproducible, not iteration-order dependent"
        );
    }

    #[test]
    fn a_lookup_converges_on_the_nearest_node_and_terminates() {
        // Kademlia's convergence argument, run against a synthetic network: each
        // round queries the closest unqueried nodes, and each answer hands back
        // its own nearest neighbours.
        let population: Vec<Contact> = (0..200).map(contact).collect();
        let target = population[137].id;

        // Each node gets a real routing table over the whole population. That
        // matters: a table is K contacts *per distance band*, not the K nearest
        // neighbours, and it is precisely that spread across scales that lets
        // every hop halve the remaining distance. A model where nodes knew only
        // their own neighbourhood could not converge, and would be testing a
        // different algorithm.
        let tables: BTreeMap<NodeId, RoutingTable> = population
            .iter()
            .map(|node| {
                let mut table = RoutingTable::new(node.id);
                for other in &population {
                    table.insert(other.clone());
                }
                (node.id, table)
            })
            .collect();

        // What a node answers to FIND_NODE(target): the contacts *it* knows that
        // are nearest the target -- never the ones nearest itself.
        let view = |who: NodeId| -> Vec<Contact> {
            tables
                .get(&who)
                .map(|table| table.closest(target, K))
                .unwrap_or_default()
        };

        let seeds: Vec<Contact> = population.iter().take(3).cloned().collect();
        let mut lookup = Lookup::new(target, seeds);
        let mut rounds = 0;
        while !lookup.is_done() {
            let queries = lookup.next_queries();
            if queries.is_empty() {
                break;
            }
            assert!(queries.len() <= ALPHA, "alpha bounds the parallelism");
            for contact in queries {
                let closer = view(contact.id);
                lookup.on_response(contact.id, closer, Vec::new());
            }
            rounds += 1;
            assert!(rounds < 64, "a lookup that does not terminate");
        }
        assert!(lookup.is_done());
        assert_eq!(
            lookup.closest().first().map(|c| c.id),
            Some(target),
            "the lookup found the target"
        );
        // O(log n): 200 nodes is under 8 bits of keyspace to resolve.
        assert!(rounds <= 20, "took {rounds} rounds, expected O(log n)");
    }

    #[test]
    fn a_peer_returning_a_flood_of_distant_contacts_cannot_redirect_the_lookup() {
        // Restricting the frontier to the k closest is what stops a lookup
        // wandering: a hostile answer enters the shortlist and is never queried,
        // because it never reaches the front.
        let target = contact(1).id;
        let seeds = vec![contact(2)];
        let mut lookup = Lookup::with(target, seeds, 2, 3);

        let first = lookup.next_queries();
        assert_eq!(first.len(), 1);

        // Answer with many contacts, all of them far away.
        let far: Vec<Contact> = (100..160).map(contact).collect();
        lookup.on_response(first[0].id, far.clone(), Vec::new());

        let asked: Vec<NodeId> = lookup.next_queries().iter().map(|c| c.id).collect();
        assert!(asked.len() <= 2, "alpha still bounds it");
        let frontier: Vec<NodeId> = lookup.closest().iter().map(|c| c.id).collect();
        for id in &asked {
            assert!(
                frontier.contains(id),
                "queried a contact outside the k closest"
            );
        }
    }

    #[test]
    fn a_silent_peer_is_marked_queried_rather_than_retried() {
        // Retrying a silent node is how a lookup stops terminating.
        let target = contact(1).id;
        let mut lookup = Lookup::with(target, vec![contact(2), contact(3)], 1, 2);
        let first = lookup.next_queries();
        assert_eq!(first.len(), 1);
        lookup.on_timeout(first[0].id);
        let second = lookup.next_queries();
        assert_eq!(second.len(), 1);
        assert_ne!(
            second[0].id, first[0].id,
            "the silent one is not asked again"
        );
        lookup.on_timeout(second[0].id);
        assert!(lookup.is_done(), "a lookup where nobody answers still ends");
    }

    #[test]
    fn providers_are_collected_across_hops_without_duplicates() {
        let target = contact(1).id;
        let mut lookup = Lookup::with(target, vec![contact(2), contact(3)], 2, 4);
        let holder = PeerRecord::sign(&identity(50), &[addr(1234)], 1).expect("signs");
        let queries = lookup.next_queries();
        for query in &queries {
            lookup.on_response(query.id, Vec::new(), vec![holder.clone()]);
        }
        assert_eq!(
            lookup.providers().len(),
            1,
            "one holder heard twice is one holder"
        );
        assert_eq!(lookup.providers()[0].public_key, holder.public_key);
    }

    #[test]
    fn a_provider_record_expires_and_is_gone() {
        // The reason this cannot live in the log: a provider that goes away
        // stops republishing, and an append-only structure has no way to say
        // "no longer true".
        let key = NodeId::of_digest(&crate::canonical::digest_bytes(b"blob")).expect("a digest");
        let mut store = ProviderStore::new();
        let holder = PeerRecord::sign(&identity(9), &[addr(5555)], 1).expect("signs");

        assert!(store.announce(key, &holder, 100).expect("verifies"));
        assert_eq!(store.providers(key, 50).len(), 1);
        assert_eq!(store.providers(key, 100).len(), 0, "expiry is exclusive");
        assert_eq!(store.expire(100), 1);
        assert!(store.is_empty(), "and the key goes with its last record");
    }

    #[test]
    fn an_unverifiable_announcement_is_refused() {
        let key = NodeId::of_digest(&crate::canonical::digest_bytes(b"blob")).expect("a digest");
        let mut store = ProviderStore::new();
        let mut forged = PeerRecord::sign(&identity(9), &[addr(5555)], 1).expect("signs");
        forged.record = crate::canonical::Value::object([
            ("type", crate::canonical::Value::string("peer")),
            (
                "addrs",
                crate::canonical::Value::array([crate::canonical::Value::string("10.0.0.1:1")]),
            ),
            ("seq", crate::canonical::Value::Int(1)),
        ]);
        assert!(store.announce(key, &forged, 100).is_err());
        assert!(store.is_empty(), "a store never holds what it cannot prove");
    }

    #[test]
    fn a_key_holds_a_bounded_number_of_providers_and_drops_the_soonest_to_lapse() {
        let key = NodeId::of_digest(&crate::canonical::digest_bytes(b"blob")).expect("a digest");
        let mut store = ProviderStore::new();
        for n in 0..MAX_PROVIDERS as u64 {
            let record = PeerRecord::sign(&identity(n), &[addr(1000)], 1).expect("signs");
            assert!(store.announce(key, &record, 1_000 + n).expect("verifies"));
        }
        assert_eq!(store.providers(key, 0).len(), MAX_PROVIDERS);

        // A longer-lived announcement displaces the one lapsing soonest.
        let fresh = PeerRecord::sign(&identity(999), &[addr(2000)], 1).expect("signs");
        assert!(store.announce(key, &fresh, 9_999).expect("verifies"));
        assert_eq!(store.providers(key, 0).len(), MAX_PROVIDERS);
        assert!(store
            .providers(key, 0)
            .iter()
            .any(|r| r.public_key == fresh.public_key));

        // One lapsing sooner than everything held does not.
        let stale = PeerRecord::sign(&identity(998), &[addr(3000)], 1).expect("signs");
        assert!(!store.announce(key, &stale, 1).expect("verifies"));
    }

    #[test]
    fn re_announcing_extends_rather_than_duplicates() {
        let key = NodeId::of_digest(&crate::canonical::digest_bytes(b"blob")).expect("a digest");
        let mut store = ProviderStore::new();
        let holder = PeerRecord::sign(&identity(9), &[addr(5555)], 1).expect("signs");
        store.announce(key, &holder, 100).expect("verifies");
        store.announce(key, &holder, 500).expect("verifies");
        assert_eq!(store.providers(key, 200).len(), 1, "still one provider");
        assert_eq!(store.providers(key, 400).len(), 1, "with a later expiry");
    }
}
