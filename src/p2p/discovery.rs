//! Bootstrap and local peer discovery.
//!
//! Discovery is deliberately outside the ledger. Addresses are hints, not
//! consensus data: a peer can disappear, change address, or be advertised by
//! an untrusted source without changing any record id or settlement.

use super::handshake::{peer_id_hex, PeerId, PeerPublic};
use rand_core::RngCore;
use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;

/// A dialable address together with the key expected at that address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub addr: SocketAddr,
    pub peer: PeerPublic,
}

impl Endpoint {
    pub fn new(addr: SocketAddr, peer: PeerPublic) -> Endpoint {
        Endpoint { addr, peer }
    }
}

/// Errors while decoding peer ids or registering an endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DiscoveryError {
    BadPeerId { value: String },
}

impl fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DiscoveryError::BadPeerId { value } => write!(f, "invalid peer id: {value:?}"),
        }
    }
}

impl std::error::Error for DiscoveryError {}

/// Parse the lowercase hexadecimal representation used in configuration and
/// logs. The handshake derives the id from the public key; this parser is only
/// for lookup and never lets a caller manufacture a `PeerPublic`.
pub fn parse_peer_id(text: &str) -> Result<PeerId, DiscoveryError> {
    if text.len() != 64 {
        return Err(DiscoveryError::BadPeerId { value: text.into() });
    }
    let mut id = [0u8; 32];
    for (i, byte) in id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16)
            .map_err(|_| DiscoveryError::BadPeerId { value: text.into() })?;
    }
    Ok(id)
}

/// Human-readable peer id for configuration and diagnostics.
pub fn peer_id_string(id: &PeerId) -> String {
    peer_id_hex(id)
}

/// In-memory address book. A production deployment can replace this with a
/// signed rendezvous or DHT backend without changing the transport API.
#[derive(Clone, Debug, Default)]
pub struct AddressBook {
    peers: BTreeMap<PeerId, Vec<Endpoint>>,
}

impl AddressBook {
    pub fn new() -> AddressBook {
        AddressBook::default()
    }

    pub fn insert(&mut self, endpoint: Endpoint) {
        let entries = self.peers.entry(endpoint.peer.id()).or_default();
        if !entries
            .iter()
            .any(|existing| existing.addr == endpoint.addr)
        {
            entries.push(endpoint);
        }
    }

    pub fn remove(&mut self, peer: &PeerId, addr: SocketAddr) -> bool {
        let mut removed = false;
        let mut empty = false;
        if let Some(entries) = self.peers.get_mut(peer) {
            let before = entries.len();
            entries.retain(|entry| entry.addr != addr);
            removed = before != entries.len();
            empty = entries.is_empty();
        }
        if empty {
            self.peers.remove(peer);
        }
        removed
    }

    pub fn endpoints(&self) -> impl Iterator<Item = &Endpoint> {
        self.peers.values().flat_map(|entries| entries.iter())
    }

    pub fn for_peer(&self, peer: &PeerId) -> &[Endpoint] {
        self.peers.get(peer).map(Vec::as_slice).unwrap_or(&[])
    }

    pub fn len(&self) -> usize {
        self.peers.values().map(Vec::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// A random subset of at most `fanout` endpoints, one per peer.
    ///
    /// Dialling the whole book every tick is what the daemon used to do, and it
    /// does not survive a book of any size: the traffic is quadratic in the
    /// network and the last peer in a fixed iteration order is always the last
    /// to hear anything. Sampling makes the cost per tick constant and the
    /// propagation delay logarithmic in the usual epidemic way.
    ///
    /// **This is not Sybil resistance and must not be mistaken for it.** The
    /// sample is uniform over the book, so an attacker who can insert `n`
    /// identities gets `n` times the share of everyone's connections, and with
    /// enough of them can eclipse a node entirely. Uniform sampling is a
    /// *liveness* mechanism; resisting a forged majority of the peer set needs
    /// a structured overlay with identities that cost something, which is Stage
    /// 2 work. `docs/p2p.md` states this in the same terms.
    ///
    /// One endpoint per peer, not per address: two addresses for the same key
    /// are two routes to one node, and dialling both wastes a slot in the
    /// sample on a peer already covered.
    pub fn sample<R: RngCore>(&self, fanout: usize, rng: &mut R) -> Vec<Endpoint> {
        let mut chosen: Vec<Endpoint> = self
            .peers
            .values()
            .filter_map(|entries| {
                let index = pick(entries.len(), rng)?;
                entries.get(index).cloned()
            })
            .collect();
        // Partial Fisher-Yates: only the prefix that will be returned needs to
        // be shuffled, and stopping early keeps the cost proportional to the
        // fanout rather than to the size of the book.
        let take = fanout.min(chosen.len());
        for i in 0..take {
            if let Some(j) = pick(chosen.len() - i, rng) {
                chosen.swap(i, i + j);
            }
        }
        chosen.truncate(take);
        chosen
    }
}

/// A uniform index below `bound`, or `None` when there is nothing to pick from.
///
/// Rejection sampling rather than `next_u64() % bound`, which is biased towards
/// low indices whenever `bound` does not divide 2^64. The bias would be tiny
/// here, but a peer-selection routine that quietly prefers the first entries in
/// the book is the same failure as not sampling at all, only harder to notice.
fn pick<R: RngCore>(bound: usize, rng: &mut R) -> Option<usize> {
    if bound == 0 {
        return None;
    }
    let bound = bound as u64;
    let limit = u64::MAX - (u64::MAX % bound) - 1;
    loop {
        let draw = rng.next_u64();
        if draw <= limit {
            return Some((draw % bound) as usize);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    /// A counter dressed as an RNG. Deterministic, so a sampling bug is a
    /// reproducible failure and not a flake somebody reruns until it passes.
    struct Counter(u64);

    impl RngCore for Counter {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }
        fn next_u64(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            self.0
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(8) {
                let bytes = self.next_u64().to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    fn book_of(n: u8) -> AddressBook {
        let mut book = AddressBook::new();
        for i in 0..n {
            let key = PeerPublic::from_bytes(&[i; classic_mceliece_rust::CRYPTO_PUBLICKEYBYTES])
                .expect("test key has the right length");
            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1000 + u16::from(i));
            book.insert(Endpoint::new(addr, key));
        }
        book
    }

    #[test]
    fn sampling_returns_at_most_the_fanout() {
        let book = book_of(20);
        let mut rng = Counter(1);
        assert_eq!(book.sample(4, &mut rng).len(), 4);
        assert_eq!(book.sample(0, &mut rng).len(), 0);
        // A fanout wider than the book is not an error: you dial everyone.
        assert_eq!(book.sample(100, &mut rng).len(), 20);
        assert_eq!(AddressBook::new().sample(4, &mut rng).len(), 0);
    }

    #[test]
    fn sampling_does_not_return_the_same_peer_twice() {
        let book = book_of(10);
        let mut rng = Counter(7);
        for _ in 0..50 {
            let sample = book.sample(5, &mut rng);
            let unique: std::collections::BTreeSet<PeerId> =
                sample.iter().map(|e| e.peer.id()).collect();
            assert_eq!(unique.len(), sample.len(), "a peer was dialled twice");
        }
    }

    #[test]
    fn sampling_reaches_every_peer_eventually() {
        // The property that matters for propagation: no peer is structurally
        // last. A fixed iteration order over the book would fail this.
        let book = book_of(12);
        let mut rng = Counter(99);
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..200 {
            for endpoint in book.sample(3, &mut rng) {
                seen.insert(endpoint.peer.id());
            }
        }
        assert_eq!(seen.len(), 12, "some peer was never sampled");
    }

    #[test]
    fn address_book_deduplicates_and_removes_endpoints() {
        let identity = PeerPublic::from_bytes(&[7u8; classic_mceliece_rust::CRYPTO_PUBLICKEYBYTES])
            .expect("test key has the right length");
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234);
        let mut book = AddressBook::new();
        book.insert(Endpoint::new(addr, identity.clone()));
        book.insert(Endpoint::new(addr, identity.clone()));
        assert_eq!(book.len(), 1);
        assert!(book.remove(&identity.id(), addr));
        assert!(book.is_empty());
    }
}
