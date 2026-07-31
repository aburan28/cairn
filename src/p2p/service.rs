//! High-level bootstrap and session orchestration.

use super::code::{CodeLimits, CodeReport};
use super::discovery::{AddressBook, Endpoint};
use super::handshake::{PeerId, PeerIdentity};
use super::pop::{PopLimits, PopReport};
use super::session::{self, SessionError};
use super::sync::{Peer, SyncError};
use super::transport::{self, Connection, TransportError};
use crate::gossip::{Candidate, Population};
use crate::node::Node;
use crate::records::{Claim, Commitment, Objective};
use crate::time::timestamp;
use rand_core::OsRng;
use std::collections::BTreeSet;
use std::fmt;
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;

/// Endpoints dialled per tick when the caller does not choose.
///
/// Small on purpose. Epidemic propagation needs a fanout above one, not a
/// fanout near the size of the network; three gets a message everywhere in
/// `O(log n)` rounds while keeping the per-tick cost of a node constant.
pub const DEFAULT_FANOUT: usize = 3;

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

    /// The peers to dial this tick: a random subset of the address book.
    ///
    /// Drawn from the OS entropy source rather than a seeded generator, because
    /// a predictable sample is a schedule an adversary can position itself in
    /// front of. See [`AddressBook::sample`] for what this does *not* defend
    /// against — a forged majority of the book itself.
    pub fn sample_peers(&self, fanout: usize) -> Vec<Endpoint> {
        self.book.sample(fanout, &mut OsRng)
    }

    /// Dial one endpoint and reconcile records, then verifier code, then
    /// populations.
    ///
    /// Three rounds on one connection, in that order, and each boundary carries
    /// a dependency:
    ///
    /// - **records before code.** The set of blobs to ask for is derived from the
    ///   objectives in hand, so fetching first would ask for last round's pins.
    /// - **code before the records are applied.** A claim verified while its
    ///   objective's checker is still missing gets `Unavailable` — correct, but
    ///   sticky: the claim is in the log with a non-settling verdict and nothing
    ///   re-runs it until some later round. Landing the code first means the
    ///   first verdict this node ever records for the claim is the real one.
    /// - **code before populations.** Candidates are scored by running the
    ///   pinned evaluator, so a node without the code re-scores nothing and
    ///   drops every candidate it was offered.
    ///
    /// Failures are contained rather than cascading. A code or population failure
    /// is reported but does not undo the record round, which has already been
    /// applied; a code failure does skip the population round, because the two
    /// share a connection whose message sequence is no longer where the peer
    /// thinks it is.
    ///
    /// `rescore` is handed the node rather than closing over it, because it is
    /// called only after the record round has landed and must see the
    /// objectives that round imported.
    pub fn dial_node_and_population<F>(
        &self,
        endpoint: &Endpoint,
        node: &mut Node,
        population: &mut Population,
        limits: PopLimits,
        mut rescore: F,
    ) -> Result<PopReport, ServiceError>
    where
        F: FnMut(&Node, &Candidate) -> Option<i64>,
    {
        let mut connection = transport::connect(&endpoint.peer, endpoint.addr, &self.identity)?;
        exchange_records_and_code(&mut connection, node)?;
        let settled: &Node = node;
        session::reconcile_population(&mut connection, population, limits, |candidate| {
            rescore(settled, candidate)
        })
        .map_err(Into::into)
    }

    /// Accept one inbound stream and reconcile records, then verifier code, then
    /// populations.
    pub fn accept_node_and_population<F>(
        &self,
        listener: &TcpListener,
        node: &mut Node,
        population: &mut Population,
        limits: PopLimits,
        mut rescore: F,
    ) -> Result<(PeerId, PopReport), ServiceError>
    where
        F: FnMut(&Node, &Candidate) -> Option<i64>,
    {
        let (stream, _) = listener.accept().map_err(TransportError::from)?;
        let mut connection = transport::accept(stream, &self.identity)?;
        let remote = connection.remote();
        exchange_records_and_code(&mut connection, node)?;
        let settled: &Node = node;
        let report =
            session::reconcile_population(&mut connection, population, limits, |candidate| {
                rescore(settled, candidate)
            })?;
        Ok((remote, report))
    }

    /// Synchronize a live node and replay newly admitted inputs into its own
    /// rules engine. Derived verdicts and settlements are never imported.
    ///
    /// Verifier code travels in the same session, before the records are
    /// applied — a node that imported the inputs and not the checker would hold
    /// the log and still be unable to re-derive it, which is the whole gap this
    /// exists to close.
    pub fn dial_node_once(&self, endpoint: &Endpoint, node: &mut Node) -> Result<(), ServiceError> {
        let mut connection = transport::connect(&endpoint.peer, endpoint.addr, &self.identity)?;
        exchange_records_and_code(&mut connection, node)?;
        Ok(())
    }

    pub fn accept_node_once(
        &self,
        listener: &TcpListener,
        node: &mut Node,
    ) -> Result<PeerId, ServiceError> {
        let (stream, _) = listener.accept().map_err(TransportError::from)?;
        let mut connection = transport::accept(stream, &self.identity)?;
        let remote = connection.remote();
        exchange_records_and_code(&mut connection, node)?;
        Ok(remote)
    }
}

/// Records, then verifier code, then apply — the ordering every node path
/// shares, in one place so the three callers cannot drift apart on it.
///
/// The record round lands in a staging [`Peer`] rather than in the log, which is
/// what makes the code round possible at all: the want set is computed from the
/// staged objectives, so this round's arrivals are covered, and the code is on
/// disk before any claim against them is verified.
fn exchange_records_and_code(
    connection: &mut Connection,
    node: &mut Node,
) -> Result<CodeReport, ServiceError> {
    let mut peer = records_from_node(node);
    session::reconcile(connection, &mut peer, decode_record)?;
    let needs = needed_code(node, &peer);
    let store = node.registry().blobs().clone();
    let code = session::reconcile_code(connection, &store, &needs, CodeLimits::default());
    // Applied whatever the code round did. The records are already reconciled
    // and refusing to apply them because a blob did not arrive would throw away
    // work this node accepted; a claim whose checker is still missing simply
    // records `Unavailable`, which is the truth and leaves the objective open.
    apply_records(node, &peer);
    code.map_err(Into::into)
}

/// The content addresses this node will need once `peer`'s objectives are
/// applied.
///
/// Both halves matter. The log's own unmet pins are included because a blob may
/// have been unavailable for many rounds and this peer may be the first that
/// holds it; the staged objectives are included because otherwise the first
/// round that learns an objective could not fetch its checker, and every claim
/// in that same round would be verified without it.
fn needed_code(node: &Node, peer: &Peer) -> BTreeSet<String> {
    let mut needs = node.missing_code();
    for id in peer.ids() {
        let Some(record) = peer.get(&id) else {
            continue;
        };
        if record.kind != "objective" {
            continue;
        }
        if let Ok(objective) = Objective::from_value(&record.payload) {
            needs.extend(node.registry().missing_code(&objective.verifier));
        }
    }
    needs
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

/// Replay a peer's inputs through this node's own rules engine.
///
/// Each record is stamped with its **own** `created_at`, not with the local
/// clock, and that is load-bearing rather than tidy. A reveal must land in a
/// strictly later epoch than the commitment it opens; stamping both with
/// `timestamp()` on the way in puts them in the same epoch, so every replayed
/// claim would be refused and record sync would quietly stop importing work.
///
/// Using the record's own instant also makes the replay deterministic: two
/// nodes handed the same records assign every one of them to the same epoch,
/// which is what lets them agree on which reveals were legal. It is what
/// `docs/design-stage0-completion.md` §5 means by epoch membership coming from
/// the record rather than from a clock.
///
/// What it does *not* buy is agreement on settlement *order*. That is derived
/// from each node's own log head at the epoch boundary, which two independently
/// ordered logs do not share. Stage 0 has one sequencer, so there is one order
/// that matters; `docs/p2p.md` says what is still open here.
fn apply_records(node: &mut Node, peer: &Peer) {
    let held = |field: &str, payload: &crate::canonical::Value| -> String {
        payload
            .get(field)
            .and_then(crate::canonical::Value::as_str)
            .map(str::to_string)
            // A record with no readable instant still has to go somewhere, and
            // the local clock is the only remaining answer. The rules engine
            // refuses it a moment later if that instant does not work.
            .unwrap_or_else(timestamp)
    };
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
            let stamp = held("created_at", &record.payload);
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
    // Replaying the inputs is only half of re-deriving the state: settlement is
    // deferred to the close of the reveal epoch, so a node that never drains
    // holds a log full of accepted claims that nobody was ever paid for.
    let _ = node.settle_at(&timestamp());
}
