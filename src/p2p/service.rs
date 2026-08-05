//! High-level bootstrap and session orchestration.

use super::code::{CodeLimits, CodeReport};
use super::dht::{Directory, NodeId, PeerContact};
use super::discovery::{AddressBook, Endpoint};
use super::handshake::{PeerId, PeerIdentity, PeerPublic};
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
use std::sync::Mutex;

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

/// Owns the local identity, the non-consensus address book, and the DHT view.
pub struct Service {
    identity: Arc<PeerIdentity>,
    /// Whom this node can dial, and the public key needed to do it.
    ///
    /// Behind a `Mutex` for the same reason the directory is: a DHT round can
    /// *learn a peer* now — a verified public key turns a contact the routing
    /// table only heard about into one this node can reach — and the dial and
    /// accept paths that learn it hold `&self`.
    book: Mutex<AddressBook>,
    /// Who holds which blob, and whom to route through to find out.
    ///
    /// Behind a `Mutex` because every dial and accept path takes `&self` — a
    /// session is a read of the service and a write of what it learned, and
    /// threading `&mut self` through would make two concurrent sessions
    /// impossible for a reason that has nothing to do with correctness.
    directory: Mutex<Directory>,
}

impl Service {
    pub fn new(identity: Arc<PeerIdentity>) -> Service {
        let local = identity.id();
        Service {
            identity,
            book: Mutex::new(AddressBook::new()),
            directory: Mutex::new(Directory::new(local)),
        }
    }

    pub fn identity(&self) -> PeerId {
        self.identity.id()
    }

    /// Read the address book briefly. Held behind a lock; see [`Service::book`].
    pub fn with_book<T>(&self, f: impl FnOnce(&mut AddressBook) -> T) -> T {
        let mut guard = self.book.lock().unwrap_or_else(|e| e.into_inner());
        f(&mut guard)
    }

    /// How many peers this node can dial.
    pub fn known_peers(&self) -> usize {
        self.with_book(|book| book.len())
    }

    pub fn add_bootstrap(&mut self, endpoint: Endpoint) {
        if endpoint.peer.id() != self.identity.id() {
            // Into the routing table as well as the book. A bootstrap peer is
            // the only thing a fresh node can route through, and leaving it out
            // would mean the DHT stayed empty until somebody else volunteered.
            self.note_contact(endpoint.peer.id(), endpoint.addr);
            self.with_book(|book| book.insert(endpoint));
        }
    }

    /// The DHT view. Held behind a lock; callers take it briefly.
    pub fn with_directory<T>(&self, f: impl FnOnce(&mut Directory) -> T) -> T {
        let mut guard = self.directory.lock().unwrap_or_else(|e| e.into_inner());
        f(&mut guard)
    }

    /// Note that a peer is reachable at an address.
    ///
    /// `seq` is the routing table's tiebreak between two records for one peer,
    /// and this stack has no signed record to take one from. Zero is honest
    /// about that: every contact is equally fresh, so "seen again" keeps what is
    /// already held rather than pretending the newest arrival is the truest.
    /// Wiring [`super::discovery`]'s signed records through would give it a real
    /// value; see `docs/discovery.md`.
    pub fn note_contact(&self, peer: PeerId, addr: SocketAddr) {
        if peer == self.identity.id() {
            return;
        }
        self.with_directory(|directory| {
            directory.saw(PeerContact::new(peer, addr, 0));
        });
    }

    /// The endpoints worth dialling when specific blobs are missing.
    ///
    /// In priority order:
    ///
    /// 1. **Peers that said, first-hand, that they hold it.** Strictly better
    ///    than anything routing can offer — asking a holder gets the bytes;
    ///    asking a router gets a pointer.
    /// 2. **The next hop of a lookup**, for the addresses no holder is known
    ///    for. This is what makes a lookup *multi*-hop: `next_hops` names the
    ///    peers the iterative search wants to query, so the next session this
    ///    node opens is the next hop, and the answer rides that session.
    /// 3. **Peers near the key**, then the random sample. The fallback is not a
    ///    formality: it is what runs when nothing has been announced yet, which
    ///    is every node's first tick.
    ///
    /// **A DHT candidate that is not in the address book is skipped**, and that
    /// is the cost of a contact not carrying its key. A 261 KiB McEliece public
    /// key cannot live in a routing table (see [`super::dht`]), so this stack
    /// can learn *that* a peer holds a blob before it can learn how to talk to
    /// it. The key is now fetched on demand — [`DhtMessage::GetKey`] — so the
    /// gap closes after a round rather than never, and a contact that is still
    /// keyless this tick is skipped this tick and queued for a key.
    ///
    /// # The contract this owes the driver
    ///
    /// Every contact taken from [`Directory::next_hops`] is resolved before this
    /// returns: dialable ones into the result, undialable ones through
    /// [`Directory::on_unreachable`]. A contact left outstanding is a lookup
    /// that never terminates. The caller owes the other half — a failed dial
    /// must come back through [`Service::unreachable`].
    ///
    /// [`DhtMessage::GetKey`]: super::dht::DhtMessage::GetKey
    pub fn peers_for(&self, needs: &BTreeSet<String>, fanout: usize) -> Vec<Endpoint> {
        if needs.is_empty() {
            return self.sample_peers(fanout);
        }
        let now = crate::time::unix_seconds();
        let mut chosen: Vec<Endpoint> = Vec::new();
        let mut seen: BTreeSet<PeerId> = BTreeSet::new();

        // 1. Known holders, and the addresses that have none.
        let mut unheld: Vec<&String> = Vec::new();
        for address in needs {
            let (holders, _) = self.with_directory(|d| d.lookup_providers(address, now));
            if holders.is_empty() {
                unheld.push(address);
                continue;
            }
            for holder in holders {
                if let Some(endpoint) =
                    self.with_book(|book| book.for_peer(&holder.peer_id()).first().cloned())
                {
                    if seen.insert(endpoint.peer.id()) {
                        chosen.push(endpoint);
                    }
                }
            }
        }

        // 2. One hop of a lookup, for what no holder is known for. Bounded by
        //    the remaining capacity so every contact handed out is resolved
        //    here rather than dropped by a later truncation.
        let remaining = fanout.saturating_sub(chosen.len());
        if remaining > 0 {
            for address in &unheld {
                self.with_directory(|directory| directory.seek(address));
            }
            let dialable: BTreeSet<NodeId> = self.with_book(|book| {
                book.endpoints()
                    .map(|endpoint| NodeId::from_bytes(endpoint.peer.id()))
                    .collect()
            });
            // "Dialable" is "its key is in the address book". A contact that
            // fails it is deferred and its key queued, inside `next_hops` — not
            // written off here, because the key it is waiting for arrives on a
            // later round and a peer marked queried never gets another turn.
            let hops = self.with_directory(|directory| {
                directory.next_hops(remaining, |peer| {
                    // The book is a separate lock, so it is read into a set the
                    // predicate can consult without nesting the two.
                    dialable.contains(&peer)
                })
            });
            for contact in hops {
                if let Some(endpoint) =
                    self.with_book(|book| book.for_peer(contact.id.as_bytes()).first().cloned())
                {
                    if seen.insert(endpoint.peer.id()) {
                        chosen.push(endpoint);
                    }
                }
            }
        }
        if chosen.len() >= fanout {
            chosen.truncate(fanout);
            return chosen;
        }

        // 3. Peers near the key, then the sample.
        for address in needs {
            for candidate in self.with_directory(|d| d.candidates(address, now)) {
                let Some(endpoint) = self.with_book(|book| {
                    book.endpoints()
                        .find(|held| held.addr == candidate)
                        .cloned()
                }) else {
                    continue;
                };
                if seen.insert(endpoint.peer.id()) {
                    chosen.push(endpoint);
                }
                if chosen.len() >= fanout {
                    return chosen;
                }
            }
        }
        for endpoint in self.sample_peers(fanout) {
            if seen.insert(endpoint.peer.id()) {
                chosen.push(endpoint);
            }
            if chosen.len() >= fanout {
                break;
            }
        }
        chosen
    }

    /// Report that a dial failed, so the lookups waiting on that peer move on.
    ///
    /// The other half of [`Service::peers_for`]'s contract. A driver that
    /// dialled and forgot would leave the peer marked in-flight in every lookup
    /// that chose it, and those lookups would never terminate — the failure
    /// would look like a DHT that simply stops answering rather than like the
    /// missing call it is.
    pub fn unreachable(&self, peer: PeerId) {
        self.with_directory(|directory| directory.on_unreachable(NodeId::from_bytes(peer)));
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
    ///
    /// Cloned rather than borrowed: the book is behind a lock, and handing out
    /// a reference into it would mean holding that lock for as long as the
    /// caller kept the slice.
    pub fn endpoints_for(&self, peer: &PeerId) -> Vec<Endpoint> {
        self.with_book(|book| book.for_peer(peer).to_vec())
    }

    /// The peers to dial this tick: a random subset of the address book.
    ///
    /// Drawn from the OS entropy source rather than a seeded generator, because
    /// a predictable sample is a schedule an adversary can position itself in
    /// front of. See [`AddressBook::sample`] for what this does *not* defend
    /// against — a forged majority of the book itself.
    pub fn sample_peers(&self, fanout: usize) -> Vec<Endpoint> {
        self.with_book(|book| book.sample(fanout, &mut OsRng))
    }

    /// Dial one endpoint and reconcile records, then verifier code, then the
    /// DHT, then populations.
    ///
    /// Four rounds on one connection, in that order, and each boundary carries
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
    /// - **the DHT round after the code round, on the code round's want set.**
    ///   It asks who holds the blobs this node asked for, so it must run once
    ///   that set exists — and it must use *that* set rather than what is still
    ///   missing afterwards, or a peer that supplied everything would teach this
    ///   node nothing about who holds what.
    ///
    /// Failures are contained rather than cascading. A code, DHT or population
    /// failure is reported but does not undo the record round, which has already
    /// been applied; any of them does skip what follows it, because they share a
    /// connection whose message sequence is no longer where the peer thinks it
    /// is.
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
        let (_, wanted) = exchange_records_and_code(&mut connection, node)?;
        self.exchange_dht_round(&mut connection, node, &wanted, Some(endpoint.addr))?;
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
        let (_, wanted) = exchange_records_and_code(&mut connection, node)?;
        self.exchange_dht_round(&mut connection, node, &wanted, self.dialable(&remote))?;
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
        let (_, wanted) = exchange_records_and_code(&mut connection, node)?;
        self.exchange_dht_round(&mut connection, node, &wanted, Some(endpoint.addr))?;
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
        let (_, wanted) = exchange_records_and_code(&mut connection, node)?;
        self.exchange_dht_round(&mut connection, node, &wanted, self.dialable(&remote))?;
        Ok(remote)
    }

    /// An address this node could use to *reach* `peer`, if it knows one.
    ///
    /// Only the address book can answer this. An inbound connection's source
    /// port is not it — see [`session::exchange_dht`].
    fn dialable(&self, peer: &PeerId) -> Option<SocketAddr> {
        self.with_book(|book| book.for_peer(peer).first().map(|held| held.addr))
    }

    /// Ask the peer which of this node's pins it holds, and answer the same
    /// question.
    ///
    /// `wanted` is the set the code round already asked for, threaded through
    /// rather than recomputed, and the choice is load-bearing in both
    /// directions. Recomputing would ask about what is *still* missing after the
    /// fetch — which excludes everything the peer just supplied, so a successful
    /// code round would teach this node nothing about who holds what. And
    /// reusing the code round's set is exactly what keeps the disclosure at
    /// zero: it is the identical list, already sent as a `code_want` on this
    /// connection.
    fn exchange_dht_round(
        &self,
        connection: &mut Connection,
        node: &Node,
        wanted: &BTreeSet<String>,
        dialable: Option<SocketAddr>,
    ) -> Result<(), ServiceError> {
        let held: BTreeSet<String> = node.registry().blobs().addresses().into_iter().collect();
        let now = crate::time::unix_seconds();
        if let Some(addr) = dialable {
            self.note_contact(connection.remote(), addr);
        }
        // Serving a key means handing out somebody else's public key, which is
        // public by construction — it is what every dialer needs and what the
        // peer id is derived from. The book is read here rather than inside the
        // session so the session keeps no view of the address book at all.
        let round = self.with_directory(|directory| {
            session::exchange_dht(
                connection,
                directory,
                wanted,
                &held,
                dialable,
                now,
                |peer| {
                    self.with_book(|book| {
                        book.endpoints()
                            .find(|endpoint| NodeId::from_bytes(endpoint.peer.id()) == peer)
                            .map(|endpoint| endpoint.peer.as_bytes().to_vec())
                    })
                },
            )
        })?;
        self.adopt(round);
        Ok(())
    }

    /// Take what a DHT round learned into the parts of the service that hold it.
    ///
    /// A learned key is what turns a contact the routing table heard about into
    /// a peer this node can dial — the step that makes the DHT able to
    /// *introduce* a peer rather than only reorder the ones already known. The
    /// key was verified against the id before it got here, so adopting it needs
    /// no further check.
    fn adopt(&self, round: session::DhtRound) {
        for (peer, key) in round.learned {
            let Ok(public) = PeerPublic::from_bytes(&key) else {
                continue;
            };
            // The address comes from the routing table, which is where the
            // contact was heard of. A key with no address is not yet an
            // endpoint, and is dropped rather than guessed at.
            let addr = self.with_directory(|directory| {
                directory
                    .routing()
                    .contacts()
                    .find(|contact| contact.id == peer)
                    .map(|contact| contact.addr)
            });
            if let Some(addr) = addr {
                self.with_book(|book| book.insert(Endpoint::new(addr, public)));
            }
        }
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
) -> Result<(CodeReport, BTreeSet<String>), ServiceError> {
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
    code.map(|report| (report, needs)).map_err(Into::into)
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
