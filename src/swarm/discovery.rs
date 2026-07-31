//! Finding peers without a name anybody owns.
//!
//! `blob fetch --peer host:port` is honest about a network with nowhere to look
//! an address up, and it is not a design. This module is the design, and it
//! starts by refusing the question as usually asked.
//!
//! # Discovery is two problems, and only one of them is hard
//!
//! > **identity** — is the thing I reached the thing I meant to reach?
//! >
//! > **location** — what address is it at today?
//!
//! Almost every discovery scheme conflates them, and that conflation is what
//! makes DNS feel load-bearing. If a hostname is how you *identify* a peer, then
//! whoever controls the name controls the network: a registrar seizure, a
//! hijacked resolver or a poisoned cache substitutes a different machine and
//! nothing downstream can tell.
//!
//! Separate them and the difficulty collapses. A peer's identity here is an
//! **ed25519 public key**, and its address is a *hint* signed by that key. Then:
//!
//! - a lie about location is detectable on connection and costs one failed dial;
//! - **any source of hints is acceptable**, because none of them is trusted. A
//!   DNS record, a gossiped record, a QR code, a pasted string and a file on a
//!   USB stick are all exactly as safe as each other;
//! - a peer can move without telling anyone in advance, because a newer signed
//!   record supersedes an older one and the key did not change.
//!
//! This is the same move the blob store makes. `evaluator` is a path and a hint;
//! `evaluator_sha256` is the identity. Nobody worries about a hostile filesystem
//! layout, because the hash decides. Nobody need worry about hostile DNS once
//! the key decides.
//!
//! # Why encrypted DNS is not the answer to this question
//!
//! DoH, DoT and DoQ encrypt the *query*. That is a real property and it is a
//! different property: it hides which name you asked for from an on-path
//! observer, and it does nothing about the two things that matter here.
//!
//! - **The namespace still has an owner.** A domain can be seized, expired,
//!   or served differently to different askers, and encryption does not change
//!   who is authoritative.
//! - **The trust anchor is still hardcoded**, and encrypting the transport moves
//!   it rather than removing it: you now hardcode a resolver as well as a name.
//!
//! It is arguably worse for a censorship-resistant network than plain DNS,
//! because the resolvers people actually use are a handful of large providers,
//! so encrypting to them *concentrates* the observation point that plaintext DNS
//! at least spread across every recursive resolver on the path.
//!
//! None of which makes DNS useless. Under the split above it is a perfectly good
//! **hint source** — cheap, universally reachable, and already deployed — and
//! losing it costs a hint rather than the network. That is the rule: *DNS may
//! carry signed records; it may never be the thing that decides.*
//!
//! # The anchor nobody escapes
//!
//! A node with no information cannot find a network. Bitcoin hardcodes DNS seeds
//! *and* a fallback IP list; IPFS hardcodes bootstrap multiaddrs; Tor hardcodes
//! directory authorities. Every claim of zero-configuration discovery is hiding
//! an anchor somewhere, usually in a package the user installed.
//!
//! So the goal is not to remove the anchor. It is to make it
//!
//! 1. **a key rather than an address**, so the operator can move;
//! 2. **replaceable without a code change**, so seizing one is survivable;
//! 3. **serving self-verifying data**, so a compromised anchor can lie about who
//!    is *reachable* and never about who is *who*.
//!
//! This module gives (1) and (3) directly, and [`AddressBook`] gives (2) by
//! treating every source as equal and none as privileged.
//!
//! # Where the hints come from, in order of preference
//!
//! | source | needs | what it costs when it fails |
//! |---|---|---|
//! | **peer exchange** — ask peers you already have | one peer, ever | nothing; other peers still answer |
//! | **the log** — identities announced in a record everybody already replicates | a copy of the log, which you needed anyway | nothing, and this is the one that removes the *separate* bootstrap problem |
//! | **local multicast** — mDNS-style, link-local | a LAN | nothing off-LAN |
//! | **out of band** — a pasted address, a checkpoint file | a human | a human |
//! | **DNS, encrypted or not** | a registrar | one hint |
//!
//! The second row is the interesting one and it is specific to this project.
//! **Discovery is not a new bootstrap problem; it is the same one as obtaining
//! the log.** A node that has the log has, by construction, every peer identity
//! the log announced — so solving bootstrap twice, once for records and once for
//! peers, is the mistake. Identity belongs in the log because it is permanent;
//! *location* does not, because the log is append-only and an IP is not.
//!
//! # What is here and what is not
//!
//! Here: signed peer records, an address book that verifies and supersedes them,
//! and peer exchange over the connection [`super::tcp`] already opens.
//!
//! Not here: a Kademlia DHT, local multicast, and log-borne identity records.
//! Each is a source of hints, all three are interchangeable under the identity
//! layer above, and none of them is needed to make the layer correct — which is
//! the point of building it first. See `docs/discovery.md`.

use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;

use crate::canonical::Value;
use crate::crypto::identity::{Identity, IdentityError, SignedRecord};

/// Addresses one record may advertise.
///
/// A peer legitimately has several — v4 and v6, a LAN address and a public one —
/// and an unbounded list is a way to make a reader's address book expensive from
/// one signature.
pub const MAX_ADDRS: usize = 8;

/// Records one address book will hold.
///
/// Bounded because records arrive from strangers. Eviction is by expiry and then
/// by age, never by "whatever arrived last", so a peer cannot flush the book by
/// flooding it.
pub const MAX_RECORDS: usize = 1024;

/// Records handed over in one peer-exchange answer.
pub const MAX_SHARED: usize = 32;

/// A peer record that cannot be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryError {
    /// The signature does not check out, or the record is not a record.
    Identity(IdentityError),
    /// A field is missing or the wrong type.
    Malformed { field: &'static str },
    /// More than [`MAX_ADDRS`] addresses, or none at all.
    BadAddrCount { count: usize },
    /// An address that does not parse as `host:port`.
    BadAddr { addr: String },
}

impl fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DiscoveryError::Identity(error) => write!(f, "{error}"),
            DiscoveryError::Malformed { field } => {
                write!(f, "peer record field {field:?} is missing or malformed")
            }
            DiscoveryError::BadAddrCount { count } => write!(
                f,
                "peer record advertises {count} addresses; expected 1..={MAX_ADDRS}"
            ),
            DiscoveryError::BadAddr { addr } => write!(f, "{addr:?} is not a host:port address"),
        }
    }
}

impl std::error::Error for DiscoveryError {}

impl From<IdentityError> for DiscoveryError {
    fn from(error: IdentityError) -> DiscoveryError {
        DiscoveryError::Identity(error)
    }
}

/// Where a peer says it can be reached, signed by the key that *is* the peer.
///
/// The signature is the whole design. It means this record can be relayed by
/// anyone, cached by anyone, and served by a hostile party, and the worst any of
/// them can do is withhold it or replay an old one — never substitute a
/// different machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRecord {
    /// Hex of the ed25519 public key. The peer's identity, and the address book's
    /// key.
    pub peer: String,
    /// Advertised addresses, in the peer's own order of preference.
    pub addrs: Vec<SocketAddr>,
    /// Monotonic per-peer version.
    ///
    /// A peer that moves publishes a higher `seq`, and readers keep the highest
    /// they have seen. This is what makes an *old* record harmless: replaying one
    /// cannot displace a newer one, so a relay's only power is to be out of date.
    /// Ethereum's ENR uses the same construction for the same reason.
    pub seq: u64,
}

impl PeerRecord {
    /// Build and sign a record.
    pub fn sign(
        identity: &Identity,
        addrs: &[SocketAddr],
        seq: u64,
    ) -> Result<SignedRecord, DiscoveryError> {
        if addrs.is_empty() || addrs.len() > MAX_ADDRS {
            return Err(DiscoveryError::BadAddrCount { count: addrs.len() });
        }
        let body = Value::object([
            ("type", Value::string("peer")),
            (
                "addrs",
                Value::array(addrs.iter().map(|a| Value::string(a.to_string()))),
            ),
            ("seq", Value::Int(i128::from(seq))),
        ]);
        Ok(SignedRecord::sign(identity, body))
    }

    /// Verify a record and decode it.
    ///
    /// Signature first, then shape. A malformed record from a valid signer is a
    /// different problem from a forgery, and checking in this order means the
    /// error says which.
    pub fn open(signed: &SignedRecord) -> Result<PeerRecord, DiscoveryError> {
        signed.verify()?;
        let raw = signed
            .record
            .get("addrs")
            .and_then(Value::as_array)
            .ok_or(DiscoveryError::Malformed { field: "addrs" })?;
        if raw.is_empty() || raw.len() > MAX_ADDRS {
            return Err(DiscoveryError::BadAddrCount { count: raw.len() });
        }
        let mut addrs = Vec::with_capacity(raw.len());
        for item in raw {
            let text = item
                .as_str()
                .ok_or(DiscoveryError::Malformed { field: "addrs" })?;
            let addr: SocketAddr = text.parse().map_err(|_| DiscoveryError::BadAddr {
                addr: text.to_string(),
            })?;
            addrs.push(addr);
        }
        let seq = signed
            .record
            .get("seq")
            .and_then(Value::as_u64)
            .ok_or(DiscoveryError::Malformed { field: "seq" })?;
        Ok(PeerRecord {
            peer: signed.submitter_id(),
            addrs,
            seq,
        })
    }
}

/// One entry: the decoded record and the signed bytes it came from.
///
/// The signed form is kept so the book can *relay* what it holds. A book that
/// only stored decoded records could tell a peer what it believed but could not
/// prove it, and peer exchange would degrade into hearsay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub record: PeerRecord,
    pub signed: SignedRecord,
}

/// Verified peer records, newest-per-peer.
///
/// Every source of hints feeds this and none of them is privileged: a record
/// pasted by a human, gossiped by a stranger, or read out of DNS lands in the
/// same table under the same check. That is what makes the sources
/// interchangeable, and it is the property that lets a network survive losing
/// any one of them.
#[derive(Debug, Clone, Default)]
pub struct AddressBook {
    entries: BTreeMap<String, Entry>,
}

impl AddressBook {
    pub fn new() -> AddressBook {
        AddressBook::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get(&self, peer: &str) -> Option<&Entry> {
        self.entries.get(peer)
    }

    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.entries.values()
    }

    /// Every address currently known, in peer order.
    ///
    /// What a fetch actually wants. Deduplicated, because two peers behind one
    /// NAT legitimately advertise the same address and dialling it twice is a
    /// wasted connection rather than an error.
    pub fn addrs(&self) -> Vec<SocketAddr> {
        let mut seen = Vec::new();
        for entry in self.entries.values() {
            for addr in &entry.record.addrs {
                if !seen.contains(addr) {
                    seen.push(*addr);
                }
            }
        }
        seen
    }

    /// Take a record from anywhere, verify it, and keep it if it is newer.
    ///
    /// Returns whether the book changed. The `seq` comparison is the whole
    /// replay defence: an attacker who captured an old record can offer it
    /// forever and never displace the newer one a peer has already seen.
    pub fn offer(&mut self, signed: &SignedRecord) -> Result<bool, DiscoveryError> {
        let record = PeerRecord::open(signed)?;
        match self.entries.get(&record.peer) {
            // Strictly newer, so a replay of an equal-seq record is also refused.
            // Equal seq with different contents is a peer signing two things at
            // one version, which is the peer's bug, and taking the first is the
            // rule that does not depend on arrival order.
            Some(existing) if existing.record.seq >= record.seq => return Ok(false),
            _ => {}
        }
        if self.entries.len() >= MAX_RECORDS && !self.entries.contains_key(&record.peer) {
            // Full. Drop the lowest-`seq` entry rather than the oldest-arrived:
            // a peer that never republishes is the one least likely to still be
            // reachable, and arrival order is something a flooder controls.
            if let Some(stalest) = self
                .entries
                .values()
                .min_by_key(|entry| entry.record.seq)
                .map(|entry| entry.record.peer.clone())
            {
                self.entries.remove(&stalest);
            }
        }
        self.entries.insert(
            record.peer.clone(),
            Entry {
                record,
                signed: signed.clone(),
            },
        );
        Ok(true)
    }

    /// Forget a peer.
    pub fn remove(&mut self, peer: &str) -> bool {
        self.entries.remove(peer).is_some()
    }

    /// Up to [`MAX_SHARED`] records to hand a peer that asked.
    ///
    /// Highest `seq` first, which is a rough proxy for "most recently alive" and
    /// costs nothing to compute. Deliberately not random: a deterministic answer
    /// is reproducible in a test, and the cases where randomness matters -- an
    /// attacker mapping the network by asking repeatedly -- are not solved by
    /// shuffling a list they can ask for again.
    pub fn share(&self, exclude: &str) -> Vec<SignedRecord> {
        let mut candidates: Vec<&Entry> = self
            .entries
            .values()
            .filter(|entry| entry.record.peer != exclude)
            .collect();
        candidates.sort_by(|a, b| {
            b.record
                .seq
                .cmp(&a.record.seq)
                .then_with(|| a.record.peer.cmp(&b.record.peer))
        });
        candidates
            .into_iter()
            .take(MAX_SHARED)
            .map(|entry| entry.signed.clone())
            .collect()
    }

    /// Wire and on-disk form: an array of signed records.
    pub fn to_value(&self) -> Value {
        Value::array(self.entries.values().map(|entry| entry.signed.to_value()))
    }

    /// Decode a book, keeping what verifies and counting what did not.
    ///
    /// Partial success on purpose. An address book is a cache of hints from
    /// strangers, and refusing to load a hundred good records because one is
    /// corrupt would turn a stale file into a node that cannot start.
    pub fn from_value(value: &Value) -> (AddressBook, usize) {
        let mut book = AddressBook::new();
        let mut rejected = 0;
        for item in value.as_array().unwrap_or(&[]) {
            match SignedRecord::from_value(item) {
                Ok(signed) => match book.offer(&signed) {
                    Ok(_) => {}
                    Err(_) => rejected += 1,
                },
                Err(_) => rejected += 1,
            }
        }
        (book, rejected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::identity::Identity;

    fn identity(seed: u8) -> Identity {
        Identity::from_secret_bytes([seed; 32])
    }

    fn addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().expect("an address")
    }

    fn record(seed: u8, port: u16, seq: u64) -> SignedRecord {
        PeerRecord::sign(&identity(seed), &[addr(port)], seq).expect("signs")
    }

    #[test]
    fn a_record_is_self_certifying_and_survives_relaying() {
        // The whole design: this record can be carried by a hostile party and
        // the worst they can do is withhold it.
        let signed = record(1, 9797, 1);
        let opened = PeerRecord::open(&signed).expect("verifies");
        assert_eq!(opened.addrs, vec![addr(9797)]);
        assert_eq!(opened.seq, 1);
        assert_eq!(opened.peer, signed.submitter_id());

        // Round-trips through the wire form without needing a trusted carrier.
        let relayed = SignedRecord::from_value(&signed.to_value()).expect("decodes");
        assert_eq!(PeerRecord::open(&relayed).expect("verifies"), opened);
    }

    #[test]
    fn a_tampered_address_is_refused_rather_than_believed() {
        // A relay's only power. Editing the address invalidates the signature,
        // so substituting a different machine is not something a carrier can do.
        let signed = record(1, 9797, 1);
        let mut forged = signed.clone();
        forged.record = Value::object([
            ("type", Value::string("peer")),
            ("addrs", Value::array([Value::string("10.0.0.1:1234")])),
            ("seq", Value::Int(1)),
        ]);
        assert!(matches!(
            PeerRecord::open(&forged),
            Err(DiscoveryError::Identity(_))
        ));

        let mut book = AddressBook::new();
        assert!(book.offer(&forged).is_err());
        assert!(book.is_empty(), "nothing unverified reaches the book");
    }

    #[test]
    fn a_newer_record_supersedes_an_older_one_and_a_replay_does_not() {
        // The replay defence. An attacker holding a captured record can offer it
        // forever; the most it achieves is being out of date.
        let mut book = AddressBook::new();
        assert!(book.offer(&record(1, 9797, 1)).expect("verifies"));
        assert!(book.offer(&record(1, 9898, 2)).expect("verifies"));
        assert_eq!(book.addrs(), vec![addr(9898)], "the peer moved");

        assert!(
            !book.offer(&record(1, 9797, 1)).expect("verifies"),
            "an old record is refused"
        );
        assert!(
            !book.offer(&record(1, 7777, 2)).expect("verifies"),
            "and so is an equal-seq one, so arrival order cannot decide"
        );
        assert_eq!(book.addrs(), vec![addr(9898)]);
        assert_eq!(book.len(), 1, "one peer, however many records");
    }

    #[test]
    fn one_key_is_one_peer_however_many_addresses_it_moves_through() {
        let mut book = AddressBook::new();
        for (seq, port) in [(1u64, 1000u16), (2, 2000), (3, 3000)] {
            book.offer(&record(7, port, seq)).expect("verifies");
        }
        assert_eq!(book.len(), 1);
        assert!(book.get(&record(7, 0, 0).submitter_id()).is_some());
    }

    #[test]
    fn a_record_may_carry_several_addresses_but_not_unboundedly_many() {
        // A peer legitimately has v4, v6, a LAN address and a public one. An
        // unbounded list is a way to make a reader's book expensive from one
        // signature.
        let addrs: Vec<SocketAddr> = (0..MAX_ADDRS as u16).map(|i| addr(9000 + i)).collect();
        let signed = PeerRecord::sign(&identity(2), &addrs, 1).expect("signs");
        assert_eq!(PeerRecord::open(&signed).expect("verifies").addrs, addrs);

        let too_many: Vec<SocketAddr> = (0..=MAX_ADDRS as u16).map(|i| addr(9000 + i)).collect();
        assert!(matches!(
            PeerRecord::sign(&identity(2), &too_many, 1),
            Err(DiscoveryError::BadAddrCount { .. })
        ));
        assert!(matches!(
            PeerRecord::sign(&identity(2), &[], 1),
            Err(DiscoveryError::BadAddrCount { count: 0 })
        ));
    }

    #[test]
    fn a_full_book_drops_the_stalest_rather_than_the_oldest_arrival() {
        // Arrival order is something a flooder controls; `seq` is something the
        // peer itself asserted, and a peer that never republishes is the one
        // least likely to still be reachable.
        let mut book = AddressBook::new();
        for seed in 0..MAX_RECORDS {
            let id = Identity::from_secret_bytes(seed_bytes(seed));
            let signed = PeerRecord::sign(&id, &[addr(1000)], (seed as u64) + 10).expect("signs");
            book.offer(&signed).expect("verifies");
        }
        assert_eq!(book.len(), MAX_RECORDS);
        let stalest = book
            .entries()
            .min_by_key(|e| e.record.seq)
            .expect("non-empty")
            .record
            .peer
            .clone();

        let newcomer = Identity::from_secret_bytes(seed_bytes(MAX_RECORDS + 1));
        let signed = PeerRecord::sign(&newcomer, &[addr(2000)], 1_000_000).expect("signs");
        book.offer(&signed).expect("verifies");

        assert_eq!(book.len(), MAX_RECORDS, "the bound holds");
        assert!(book.get(&stalest).is_none(), "the stalest went");
        assert!(book.get(&signed.submitter_id()).is_some());
    }

    fn seed_bytes(n: usize) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&(n as u64 + 1).to_be_bytes());
        bytes
    }

    #[test]
    fn sharing_is_bounded_excludes_the_asker_and_is_deterministic() {
        let mut book = AddressBook::new();
        for seed in 0..(MAX_SHARED + 5) {
            let id = Identity::from_secret_bytes(seed_bytes(seed));
            let signed = PeerRecord::sign(&id, &[addr(1000)], seed as u64 + 1).expect("signs");
            book.offer(&signed).expect("verifies");
        }
        let asker = Identity::from_secret_bytes(seed_bytes(0)).public().to_hex();
        let shared = book.share(&asker);
        assert_eq!(shared.len(), MAX_SHARED);
        assert!(
            shared.iter().all(|r| r.submitter_id() != asker),
            "telling a peer about itself is a wasted slot"
        );
        assert_eq!(
            shared.iter().map(|r| r.submitter_id()).collect::<Vec<_>>(),
            book.share(&asker)
                .iter()
                .map(|r| r.submitter_id())
                .collect::<Vec<_>>(),
            "the answer is reproducible"
        );
    }

    #[test]
    fn a_book_round_trips_and_loads_partially_rather_than_failing_whole() {
        // An address book is a cache of hints from strangers. Refusing to load a
        // hundred good records because one is corrupt turns a stale file into a
        // node that cannot start.
        let mut book = AddressBook::new();
        book.offer(&record(1, 1111, 1)).expect("verifies");
        book.offer(&record(2, 2222, 1)).expect("verifies");

        let (reloaded, rejected) = AddressBook::from_value(&book.to_value());
        assert_eq!(rejected, 0);
        assert_eq!(reloaded.len(), 2);
        assert_eq!(reloaded.addrs(), book.addrs());

        let mut mixed = book.to_value().as_array().expect("array").to_vec();
        mixed.push(Value::string("not a record"));
        mixed.push(Value::object([("type", Value::string("nonsense"))]));
        let (partial, rejected) = AddressBook::from_value(&Value::array(mixed));
        assert_eq!(rejected, 2);
        assert_eq!(partial.len(), 2, "the good records still loaded");
    }

    #[test]
    fn addresses_are_deduplicated_across_peers() {
        // Two peers behind one NAT legitimately advertise one address, and
        // dialling it twice is a wasted connection rather than an error.
        let mut book = AddressBook::new();
        book.offer(&record(1, 5000, 1)).expect("verifies");
        book.offer(&record(2, 5000, 1)).expect("verifies");
        assert_eq!(book.len(), 2, "two distinct peers");
        assert_eq!(book.addrs(), vec![addr(5000)], "one address to dial");
    }

    #[test]
    fn a_record_that_is_not_an_address_is_refused() {
        let id = identity(3);
        let body = Value::object([
            ("type", Value::string("peer")),
            ("addrs", Value::array([Value::string("example.com:80")])),
            ("seq", Value::Int(1)),
        ]);
        let signed = SignedRecord::sign(&id, body);
        // A hostname is not refused because hostnames are bad -- it is refused
        // because resolving one is a step this layer deliberately does not have,
        // and accepting it would smuggle a name lookup into a module whose whole
        // argument is that names do not decide.
        assert!(matches!(
            PeerRecord::open(&signed),
            Err(DiscoveryError::BadAddr { .. })
        ));

        let missing = SignedRecord::sign(&id, Value::object([("type", Value::string("peer"))]));
        assert!(matches!(
            PeerRecord::open(&missing),
            Err(DiscoveryError::Malformed { field: "addrs" })
        ));
    }
}
