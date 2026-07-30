//! High-level bootstrap and session orchestration.

use super::discovery::{AddressBook, Endpoint};
use super::handshake::{PeerId, PeerIdentity};
use super::session::{self, SessionError};
use super::sync::{Peer, SyncError};
use super::transport::{self, TransportError};
use crate::node::Node;
use crate::records::{Claim, Commitment, Objective};
use crate::time::timestamp;
use std::fmt;
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;

#[derive(Debug)]
pub enum ServiceError {
    Transport(TransportError),
    Session(SessionError),
    UnknownPeer(PeerId),
}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceError::Transport(e) => write!(f, "{e}"),
            ServiceError::Session(e) => write!(f, "{e}"),
            ServiceError::UnknownPeer(id) => write!(f, "unknown peer {:02x?}", &id[..4]),
        }
    }
}
impl std::error::Error for ServiceError {}
impl From<TransportError> for ServiceError {
    fn from(value: TransportError) -> Self {
        ServiceError::Transport(value)
    }
}
impl From<SessionError> for ServiceError {
    fn from(value: SessionError) -> Self {
        ServiceError::Session(value)
    }
}

/// Owns the local identity and the non-consensus address book.
pub struct Service {
    identity: Arc<PeerIdentity>,
    book: AddressBook,
}

impl Service {
    pub fn new(identity: Arc<PeerIdentity>) -> Service {
        Service {
            identity,
            book: AddressBook::new(),
        }
    }

    pub fn identity(&self) -> PeerId {
        self.identity.id()
    }

    pub fn address_book(&self) -> &AddressBook {
        &self.book
    }

    pub fn add_bootstrap(&mut self, endpoint: Endpoint) {
        if endpoint.peer.id() != self.identity.id() {
            self.book.insert(endpoint);
        }
    }

    /// Bind a listener. The caller may run `accept_once` in a loop and apply
    /// admission/rate limits between `accept` and the expensive handshake.
    pub fn listen(&self, addr: SocketAddr) -> Result<TcpListener, ServiceError> {
        transport::listen(addr).map_err(Into::into)
    }

    /// Dial one configured endpoint and run one anti-entropy round.
    pub fn dial_once<F>(
        &self,
        endpoint: &Endpoint,
        peer: &mut Peer,
        verify: F,
    ) -> Result<(), ServiceError>
    where
        F: FnMut(&super::sync::Record) -> Result<(), SyncError>,
    {
        let mut connection = transport::connect(&endpoint.peer, endpoint.addr, &self.identity)?;
        session::reconcile(&mut connection, peer, verify).map_err(Into::into)
    }

    /// Accept one inbound stream and run one anti-entropy round.
    pub fn accept_once<F>(
        &self,
        listener: &TcpListener,
        peer: &mut Peer,
        verify: F,
    ) -> Result<PeerId, ServiceError>
    where
        F: FnMut(&super::sync::Record) -> Result<(), SyncError>,
    {
        let (stream, _) = listener.accept().map_err(TransportError::from)?;
        let mut connection = transport::accept(stream, &self.identity)?;
        let remote = connection.remote();
        session::reconcile(&mut connection, peer, verify)?;
        Ok(remote)
    }

    /// Look up a bootstrap endpoint by id. This keeps callers from reaching
    /// into the address-book representation when scheduling retries.
    pub fn endpoints_for(&self, peer: &PeerId) -> &[Endpoint] {
        self.book.for_peer(peer)
    }

    /// Synchronize a live node and replay newly admitted inputs into its own
    /// rules engine. Derived verdicts and settlements are never imported.
    pub fn dial_node_once(&self, endpoint: &Endpoint, node: &mut Node) -> Result<(), ServiceError> {
        let mut peer = records_from_node(node);
        self.dial_once(endpoint, &mut peer, decode_record)?;
        apply_records(node, &peer);
        Ok(())
    }

    pub fn accept_node_once(
        &self,
        listener: &TcpListener,
        node: &mut Node,
    ) -> Result<PeerId, ServiceError> {
        let mut peer = records_from_node(node);
        let remote = self.accept_once(listener, &mut peer, decode_record)?;
        apply_records(node, &peer);
        Ok(remote)
    }
}

fn records_from_node(node: &Node) -> Peer {
    let mut peer = Peer::new();
    for entry in node.ledger().entries() {
        if ["objective", "commitment", "claim"].contains(&entry.kind.as_str()) {
            let _ = peer.insert(super::sync::Record::new(
                entry.kind.clone(),
                entry.payload.clone(),
            ));
        }
    }
    peer
}

fn decode_record(record: &super::sync::Record) -> Result<(), SyncError> {
    let result = match record.kind.as_str() {
        "objective" => Objective::from_value(&record.payload).map(|_| ()),
        "commitment" => Commitment::from_value(&record.payload).map(|_| ()),
        "claim" => Claim::from_value(&record.payload).map(|_| ()),
        other => return Err(SyncError::NotExchangeable { kind: other.into() }),
    };
    result.map_err(|error| SyncError::MalformedMessage {
        detail: error.to_string(),
    })
}

fn apply_records(node: &mut Node, peer: &Peer) {
    for kind in ["objective", "commitment", "claim"] {
        for id in peer.ids() {
            let Some(record) = peer.get(&id) else {
                continue;
            };
            if record.kind != kind
                || node.ledger().entries().iter().any(|entry| {
                    entry.kind == record.kind && entry.payload.digest() == record.payload.digest()
                })
            {
                continue;
            }
            let stamp = timestamp();
            match kind {
                "objective" => {
                    if let Ok(value) = Objective::from_value(&record.payload) {
                        let _ = node.post_objective(&value, &stamp);
                    }
                }
                "commitment" => {
                    if let Ok(value) = Commitment::from_value(&record.payload) {
                        let _ = node.commit(&value, &stamp);
                    }
                }
                "claim" => {
                    if let Ok(value) = Claim::from_value(&record.payload) {
                        let _ = node.reveal(&value, &stamp);
                    }
                }
                _ => {}
            }
        }
    }
}
