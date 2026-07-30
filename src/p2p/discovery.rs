//! Bootstrap and local peer discovery.
//!
//! Discovery is deliberately outside the ledger. Addresses are hints, not
//! consensus data: a peer can disappear, change address, or be advertised by
//! an untrusted source without changing any record id or settlement.

use super::handshake::{peer_id_hex, PeerId, PeerPublic};
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

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
