//! Kademlia over signed peer records: `swarm`'s instantiation of [`crate::dht`].
//!
//! [`super::discovery`] answers "which peers exist". This answers the question a
//! fetch actually has -- **who holds digest `D` right now** -- and the two are
//! different problems that want different structures:
//!
//! | | churn | shape | where it belongs |
//! |---|---|---|---|
//! | peer identity | permanent | a key that never changes | the log, eventually |
//! | provider records | constant | expires, republished, revoked by silence | **here**, and never in an append-only log |
//!
//! Without this, a fetch dials every peer in the address book and asks each one.
//! That is flooding: fine at ten peers, hopeless at ten thousand, and it gets
//! worse exactly as the network gets more useful.
//!
//! # What is here, and what moved
//!
//! The algorithm is not here. The XOR metric, the `k`-bucket policy, the
//! iterative lookup and the provider store live in [`crate::dht`], because
//! [`crate::p2p::dht`] needs the same ones and two copies of a subtle algorithm
//! become two different algorithms. What is here is the part that is genuinely
//! this stack's: **what a contact is**, and **what makes a provider record
//! believable**.
//!
//! # A contact carries its own proof
//!
//! A [`Contact`] is a signed peer record. The signature travels with it so a
//! routing answer can be *relayed*: a DHT whose contacts were bare addresses
//! would make every hop hearsay, and the asker would have to trust the whole path
//! rather than none of it. At 32 bytes of key and 64 of signature that is cheap
//! here -- [`crate::p2p::dht`] cannot afford the same trick and the contrast is
//! documented there.
//!
//! # Why this is safe in a way DHTs usually are not
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
//! # Node IDs are public keys, which is S/Kademlia's fix for free
//!
//! A node id is the SHA-256 of an ed25519 public key, and every contact carries
//! the signed record that proves it. So a node cannot claim an ID it does not
//! hold the key for, and the "generate IDs until one lands next to the key I want
//! to eclipse" attack costs a keypair *and a signature* per attempt rather than a
//! counter increment. S/Kademlia proposes crypto puzzles for exactly this; here
//! the identity layer already provided it.
//!
//! Binding IDs to something genuinely scarce -- the bond in
//! [`crate::incentive`] -- is the stronger version and is not built. Keys are
//! cheap; stake is not.

use super::discovery::{DiscoveryError, PeerRecord};
use crate::crypto::identity::SignedRecord;

pub use crate::dht::{Distance, Insertion, NodeId, ALPHA, ID_BITS, K, MAX_KEYS, MAX_PROVIDERS};

/// A peer in the routing table: where it is, and the proof it said so.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contact {
    pub id: NodeId,
    pub record: PeerRecord,
    pub signed: SignedRecord,
}

impl Contact {
    /// Verify a signed record and turn it into a contact.
    ///
    /// The only constructor, which is what makes "every contact in the table was
    /// proved once" a property of the type rather than of the call sites.
    pub fn open(signed: &SignedRecord) -> Result<Contact, DiscoveryError> {
        let record = PeerRecord::open(signed)?;
        Ok(Contact {
            id: NodeId::of_key(&signed.public_key),
            record,
            signed: signed.clone(),
        })
    }
}

impl crate::dht::Contact for Contact {
    fn id(&self) -> NodeId {
        self.id
    }

    /// The record's own sequence number, so a peer that moved supersedes itself
    /// and a replayed old record never displaces a newer one.
    fn seq(&self) -> u64 {
        self.record.seq
    }
}

/// A verified claim that some peer holds a blob.
///
/// A newtype rather than a bare [`SignedRecord`] for one reason: a `SignedRecord`
/// can be decoded without being checked, and [`crate::dht::ProviderStore`] does
/// not verify on insert. Making [`ProviderRecord::open`] the only way to obtain
/// one moves "a store never holds a claim it could not prove" from a check that
/// could be forgotten to an invariant that cannot be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderRecord {
    id: NodeId,
    signed: SignedRecord,
}

impl ProviderRecord {
    pub fn open(signed: &SignedRecord) -> Result<ProviderRecord, DiscoveryError> {
        PeerRecord::open(signed)?;
        Ok(ProviderRecord {
            id: NodeId::of_key(&signed.public_key),
            signed: signed.clone(),
        })
    }

    pub fn signed(&self) -> &SignedRecord {
        &self.signed
    }
}

impl crate::dht::Provider for ProviderRecord {
    fn provider(&self) -> NodeId {
        self.id
    }
}

/// `K` contacts per distance band, oldest-live-wins. See [`crate::dht`].
pub type RoutingTable = crate::dht::RoutingTable<Contact>;

/// One iterative lookup, as a pure state machine.
///
/// A thin wrapper rather than a type alias so the provider type stays
/// [`SignedRecord`] at the boundary: callers on this side of the crate speak
/// signed records, and the verified [`ProviderRecord`] is an internal detail of
/// how the store keeps its invariant.
#[derive(Debug, Clone)]
pub struct Lookup {
    inner: crate::dht::Lookup<Contact, ProviderRecord>,
    providers: Vec<SignedRecord>,
}

impl Lookup {
    pub fn new(target: NodeId, seeds: Vec<Contact>) -> Lookup {
        Lookup::with(target, seeds, ALPHA, K)
    }

    pub fn with(target: NodeId, seeds: Vec<Contact>, alpha: usize, k: usize) -> Lookup {
        Lookup {
            inner: crate::dht::Lookup::with(target, seeds, alpha, k),
            providers: Vec::new(),
        }
    }

    pub fn target(&self) -> NodeId {
        self.inner.target()
    }

    pub fn next_queries(&mut self) -> Vec<Contact> {
        self.inner.next_queries()
    }

    /// Fold in an answer.
    ///
    /// Unverifiable provider records are **dropped, not refused**, and the
    /// distinction matters: a hop that mixes one forged record into nine good
    /// ones should cost the forgery and not the lookup.
    pub fn on_response(
        &mut self,
        from: NodeId,
        closer: Vec<Contact>,
        providers: Vec<SignedRecord>,
    ) {
        let opened: Vec<ProviderRecord> = providers
            .iter()
            .filter_map(|signed| ProviderRecord::open(signed).ok())
            .collect();
        let before = self.inner.providers().len();
        self.inner.on_response(from, closer, opened);
        for record in &self.inner.providers()[before..] {
            self.providers.push(record.signed.clone());
        }
    }

    pub fn on_timeout(&mut self, from: NodeId) {
        self.inner.on_timeout(from);
    }

    pub fn is_done(&self) -> bool {
        self.inner.is_done()
    }

    pub fn closest(&self) -> Vec<Contact> {
        self.inner.closest()
    }

    pub fn providers(&self) -> &[SignedRecord] {
        &self.providers
    }
}

/// Who claims to hold what, with an expiry.
///
/// Wraps [`crate::dht::ProviderStore`] to keep the verifying boundary: `announce`
/// takes a raw [`SignedRecord`] and returns an error rather than a `false` when
/// it cannot be proved, because "I refused this" and "I had no room" are
/// different answers and a caller that conflates them cannot tell a hostile peer
/// from a full table.
#[derive(Debug, Clone, Default)]
pub struct ProviderStore {
    inner: crate::dht::ProviderStore<ProviderRecord>,
}

impl ProviderStore {
    pub fn new() -> ProviderStore {
        ProviderStore::default()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Record that the signer of `record` holds `key`, until `expires_at`.
    pub fn announce(
        &mut self,
        key: NodeId,
        record: &SignedRecord,
        expires_at: u64,
    ) -> Result<bool, DiscoveryError> {
        let opened = ProviderRecord::open(record)?;
        Ok(self.inner.announce(key, &opened, expires_at))
    }

    /// Who holds `key`, as of `now`.
    pub fn providers(&self, key: NodeId, now: u64) -> Vec<SignedRecord> {
        self.inner
            .providers(key, now)
            .into_iter()
            .map(|record| record.signed)
            .collect()
    }

    /// Drop everything that has lapsed. Returns how many records went.
    pub fn expire(&mut self, now: u64) -> usize {
        self.inner.expire(now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::identity::Identity;
    use std::collections::BTreeMap;
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
        let zero = NodeId::from_bytes([0u8; 32]);
        // Flipping the top bit is the most distant band.
        let mut top = [0u8; 32];
        top[0] = 0x80;
        assert_eq!(zero.bucket(NodeId::from_bytes(top)), Some(255));
        // Flipping the bottom bit is the nearest.
        let mut bottom = [0u8; 32];
        bottom[31] = 0x01;
        assert_eq!(zero.bucket(NodeId::from_bytes(bottom)), Some(0));
        let mut mid = [0u8; 32];
        mid[0] = 0x01;
        assert_eq!(zero.bucket(NodeId::from_bytes(mid)), Some(248));
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
        let local = NodeId::from_bytes([0u8; 32]);
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
        let local = NodeId::from_bytes([1u8; 32]);
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
        let local = NodeId::from_bytes([0u8; 32]);
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
