//! High-level bootstrap and session orchestration.

use super::code::{CodeLimits, CodeReport};
use super::dht::{Directory, NodeId, PeerContact};
use super::discovery::{AddressBook, Endpoint};
use super::handshake::{PeerId, PeerIdentity, PeerPublic};
use super::multicast;
use super::pop::{PopLimits, PopReport};
use super::session::{self, SessionError};
use super::sync::{Peer, SyncError};
use super::transport::{self, Connection, TransportError};
use crate::gossip::{Candidate, Population};
use crate::node::Node;
use crate::records::{Claim, Commitment, Objective, PeerRecord};
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
    /// Holders a finished lookup found, keyed by content address.
    ///
    /// Deliberately **not** in the provider store: these are relayed claims,
    /// and the rule that keeps an unsigned DHT from being an amplifier is that
    /// a relayed claim is never re-served. Kept here they are consulted by this
    /// node's own dialling and answered to nobody, and consumed on use, so a
    /// wrong one costs exactly one dial. See `Service::adopt`.
    hints: Mutex<std::collections::BTreeMap<String, Vec<super::dht::Holder>>>,
    /// Keys served that did not hash to the id asked for.
    bad_keys: std::sync::atomic::AtomicUsize,
}

impl Service {
    pub fn new(identity: Arc<PeerIdentity>) -> Service {
        let local = identity.id();
        Service {
            identity,
            book: Mutex::new(AddressBook::new()),
            directory: Mutex::new(Directory::new(local)),
            hints: Mutex::new(std::collections::BTreeMap::new()),
            bad_keys: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub fn identity(&self) -> PeerId {
        self.identity.id()
    }

    /// Read the address book briefly. Held behind a lock; see `Service::book`.
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

    /// Note that a peer is reachable at an address, with no freshness claim.
    ///
    /// For the hint sources that genuinely have none: a bootstrap file, a
    /// multicast beacon, the source address of an inbound connection. Zero is
    /// honest about that.
    ///
    /// It is *not* honest for a hint that came from a signed record, and
    /// [`Service::note_contact_at`] is what those use.
    pub fn note_contact(&self, peer: PeerId, addr: SocketAddr) {
        self.note_contact_at(peer, addr, 0);
    }

    /// Note a peer, carrying the freshness its record claimed.
    ///
    /// # Why the sequence has to travel
    ///
    /// [`crate::dht::Contact::seq`] says it plainly: without a freshness
    /// counter "a table has no way to tell a peer that *moved* from a peer
    /// being *impersonated* by a stale record". The routing table takes the new
    /// contact when `seq >= held`, so with everything pinned at zero **a
    /// replayed old record always wins** — anyone who once saw a peer record can
    /// re-offer the address that peer has left and go on steering traffic at it.
    ///
    /// The value was available and simply not passed. `peer` records in the log
    /// carry a signed, monotonic `seq`; [`Node::peers`] already resolves them
    /// highest-seq-wins, and the audit reports one that does not advance. All of
    /// that protection stopped at the edge of the routing table, because
    /// `seed_from_log` called the seq-less form.
    pub fn note_contact_at(&self, peer: PeerId, addr: SocketAddr, seq: u64) {
        if peer == self.identity.id() {
            return;
        }
        self.with_directory(|directory| {
            directory.saw(PeerContact::new(peer, addr, seq));
        });
    }

    /// The endpoints worth dialling when specific blobs are missing.
    ///
    /// In priority order:
    ///
    /// 1. **Peers that said, first-hand, that they hold it.** Strictly better
    ///    than anything routing can offer — asking a holder gets the bytes;
    ///    asking a router gets a pointer.
    /// 2. **Holders a previous lookup found.** Relayed claims, so they are
    ///    consumed on use rather than stored — see `Service::adopt`.
    /// 3. **The next hop of a lookup**, for the addresses no holder is known
    ///    for. This is what makes a lookup *multi*-hop: `next_hops` names the
    ///    peers the iterative search wants to query, so the next session this
    ///    node opens is the next hop, and the answer rides that session.
    /// 4. **Peers near the key**, then the random sample. The fallback is not a
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

        // 2. Holders a previous lookup found. Consumed on use: they are
        //    relayed claims, so one wrong one costs a dial and is gone rather
        //    than being retried for ever.
        if !unheld.is_empty() {
            let taken: Vec<Vec<super::dht::Holder>> = {
                let mut hints = self.hints.lock().unwrap_or_else(|e| e.into_inner());
                unheld
                    .iter()
                    .filter_map(|address| hints.remove(address.as_str()))
                    .collect()
            };
            for holder in taken.into_iter().flatten() {
                if let Some(endpoint) =
                    self.with_book(|book| book.for_peer(&holder.peer_id()).first().cloned())
                {
                    if seen.insert(endpoint.peer.id()) {
                        chosen.push(endpoint);
                    }
                }
            }
        }

        // 3. One hop of a lookup, for what no holder is known for. Bounded by
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

        // 4. Peers near the key, then the sample.
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

    /// Seed the routing table from the peer records in a log.
    ///
    /// This is what makes finding the network part of *obtaining the log*
    /// rather than a second bootstrap problem: a node handed a log is handed
    /// every identity that ever announced itself, with a transport id and an
    /// address hint for each.
    ///
    /// What it cannot do is finish the job on its own, and the reason is the
    /// one [`super::dht`] gives at length: a record carries a transport *id*,
    /// not the 261 KiB McEliece key needed to dial it. So each peer enters the
    /// routing table and its key is queued, and one round with any peer that
    /// has it turns the contact into an endpoint. Records for identities this
    /// node can already dial cost nothing and are still noted, because the
    /// address may have moved.
    ///
    /// Returns how many contacts were taken.
    pub fn seed_from_log(&self, node: &Node) -> usize {
        let mut seeded = 0;
        for record in node.peers().values() {
            let Some(transport) = decode_peer_id(&record.transport) else {
                continue;
            };
            if transport == self.identity.id() {
                continue;
            }
            // The address is a hint and this is the one place it is resolved.
            // The record format deliberately does not decide what a valid
            // address is -- see `records::MAX_PEER_ADDR` -- so a form this
            // build cannot dial is skipped here rather than refused there.
            //
            // `dialable` accepts a hostname as well as a literal, which is what
            // lets a peer record name a host whose address moves. It is safe to
            // take from a stranger for the reason `discovery::dialable` gives:
            // the peer id is the hash of the key, so a hostile answer costs a
            // failed handshake and never a wrong peer.
            let Some(addr) = crate::p2p::discovery::dialable(&record.addr) else {
                continue;
            };
            // The record's own signed sequence, not zero. `Node::peers` has
            // already resolved highest-seq-wins across every peer record in the
            // log, so this is the freshest claim that identity has made and the
            // signature is what makes it worth anything.
            self.note_contact_at(transport, addr, record.seq);
            let node_id = NodeId::from_bytes(transport);
            if self.with_book(|book| book.for_peer(&transport).is_empty()) {
                self.with_directory(|directory| directory.wants_key(node_id));
            }
            seeded += 1;
        }
        seeded
    }

    /// Fold beacons heard on the local segment into the routing table.
    ///
    /// The third hint source, and interchangeable with the other two by
    /// construction: a beacon is an address and a transport id, which is exactly
    /// what a peer record carries and exactly what a DHT contact carries. None
    /// of them is trusted, so none of them needs a different code path -- the
    /// handshake decides, and a wrong hint costs one dial.
    ///
    /// Takes the [`multicast::Responder`] rather than owning it, because whether
    /// a node has one at all depends on the host: `Responder::bind` fails on a
    /// container with no multicast route, and that is a node without LAN
    /// discovery rather than a node that cannot run.
    ///
    /// Returns how many contacts were taken.
    pub fn absorb_beacons(&self, responder: &multicast::Responder, limit: usize) -> usize {
        let mut taken = 0;
        for (peer, addr) in responder.poll(limit) {
            if peer == self.identity.id() {
                continue;
            }
            self.note_contact(peer, addr);
            // Same as `seed_from_log`: a beacon carries a transport *id*, not
            // the 261 KiB key needed to dial it, so the key is queued and one
            // round with any peer that has it turns the contact into an
            // endpoint.
            if self.with_book(|book| book.for_peer(&peer).is_empty()) {
                self.with_directory(|directory| directory.wants_key(NodeId::from_bytes(peer)));
            }
            taken += 1;
        }
        taken
    }

    /// The transport key this node holds for `peer`, if any.
    ///
    /// The address book is already the cache: an endpoint is an address *and* a
    /// key, and `p2p::dht`'s `GetKey` is what fills it. This exposes that cache
    /// so a subsystem holding only an id can complete it -- see
    /// [`crate::swarm::tcp::KeySource`], which `Service` implements over this.
    pub fn key_for(&self, peer: &PeerId) -> Option<PeerPublic> {
        self.with_book(|book| book.for_peer(peer).first().map(|e| e.peer.clone()))
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
        rescore: F,
    ) -> Result<(PeerId, PopReport), ServiceError>
    where
        F: FnMut(&Node, &Candidate) -> Option<i64>,
    {
        let (stream, _) = listener.accept().map_err(TransportError::from)?;
        self.serve_node_and_population(stream, node, population, limits, rescore)
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
        self.serve_node_once(stream, node)
    }

    /// The same, on a stream the caller already accepted.
    ///
    /// # Why this split exists
    ///
    /// `listener.accept()` blocks. A caller that holds a lock over its node
    /// while calling [`Service::accept_node_once`] therefore holds it until an
    /// inbound connection arrives — which, on a node nobody is dialling, is
    /// forever. `cairn-p2p` did exactly that, and the effect was that its
    /// main loop ran **once** and then waited on a mutex for the rest of the
    /// process's life: no dialling, no peer seeding, no beacons, no DHT, no
    /// fetching of missing verifier code. It looked healthy because the single
    /// pass at startup is enough to sync from a bootstrap peer.
    ///
    /// Accepting outside the lock and passing the stream in is the whole fix.
    /// The blocking wait happens with nothing held; the lock is taken only for
    /// the session, which is bounded by the transport's own timeouts.
    pub fn serve_node_once(
        &self,
        stream: std::net::TcpStream,
        node: &mut Node,
    ) -> Result<PeerId, ServiceError> {
        let mut connection = transport::accept(stream, &self.identity)?;
        let remote = connection.remote();
        let (_, wanted) = exchange_records_and_code(&mut connection, node)?;
        self.exchange_dht_round(&mut connection, node, &wanted, self.dialable(&remote))?;
        Ok(remote)
    }

    /// [`Service::accept_node_and_population`], on an accepted stream.
    ///
    /// Split for the reason [`Service::serve_node_once`] gives at length.
    pub fn serve_node_and_population<F>(
        &self,
        stream: std::net::TcpStream,
        node: &mut Node,
        population: &mut Population,
        limits: PopLimits,
        mut rescore: F,
    ) -> Result<(PeerId, PopReport), ServiceError>
    where
        F: FnMut(&Node, &Candidate) -> Option<i64>,
    {
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
        if connection.remote_authenticated() {
            if let Some(addr) = dialable {
                self.note_contact(connection.remote(), addr);
            }
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
    ///
    /// A finished lookup's holders become **dial hints**, and where they are
    /// kept is the whole point. They are relayed claims: a peer said "C holds
    /// D" and could not prove it, so [`super::dht`] refuses to enter them in the
    /// provider store. That refusal is what stops an unsigned DHT being an
    /// amplifier — name a victim as the holder of a popular blob and the network
    /// dials the victim — and it turns on *never re-serving* a relayed claim,
    /// not on never acting on one. So the hints live here, are consulted only by
    /// this node's own dialling, are answered to nobody, and are consumed on
    /// use: a wrong one costs one dial and is gone.
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
        if !round.finished.is_empty() {
            let mut hints = self.hints.lock().unwrap_or_else(|e| e.into_inner());
            for (address, holders) in round.finished {
                if !holders.is_empty() {
                    hints.insert(address, holders);
                }
            }
        }
        if round.bad_keys > 0 {
            self.bad_keys
                .fetch_add(round.bad_keys, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Adopt a finished lookup's holders without a live connection.
    ///
    /// The same path `Service::adopt` takes, reachable from a test that
    /// drives the directory directly. The alternative is a test that stands up
    /// three real McEliece sessions to assert a `BTreeMap` insert, which would
    /// take a minute to run and test the transport rather than the rule.
    pub fn adopt_for_test(&self, finished: Vec<(String, Vec<super::dht::Holder>)>) {
        self.adopt(session::DhtRound {
            finished,
            ..session::DhtRound::default()
        });
    }

    /// How many addresses currently have a lookup hint waiting.
    ///
    /// Reporting, and the only way to observe consumption from outside: once a
    /// hint has been used the peer it named may still be dialled for other
    /// reasons, so dial order cannot distinguish "the hint was consumed" from
    /// "the sample happened to pick the same peer".
    pub fn pending_hints(&self) -> usize {
        self.hints.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Keys served that did not hash to the id asked for, since start.
    ///
    /// A peer doing this is broken or lying, and either way it is the kind of
    /// thing an operator should be able to see a number for rather than guess
    /// at. Never zeroed: a rate is what matters and the caller can difference
    /// it.
    pub fn bad_keys_seen(&self) -> usize {
        self.bad_keys.load(std::sync::atomic::Ordering::Relaxed)
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
        if ["objective", "commitment", "claim", "peer"].contains(&entry.kind.as_str()) {
            let _ = peer.insert(super::sync::Record::new(
                entry.kind.clone(),
                entry.payload.clone(),
            ));
        }
    }
    peer
}

/// A 64-character hex peer id as bytes.
///
/// `None` for anything else. The record layer already enforces the shape, so
/// reaching `None` here means a log assembled by other means -- and skipping
/// one contact is a better failure than refusing to read the log.
fn decode_peer_id(hex: &str) -> Option<PeerId> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(hex.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

fn decode_record(record: &super::sync::Record) -> Result<(), SyncError> {
    let result = match record.kind.as_str() {
        "objective" => Objective::from_value(&record.payload).map(|_| ()),
        "commitment" => Commitment::from_value(&record.payload).map(|_| ()),
        "claim" => Claim::from_value(&record.payload).map(|_| ()),
        // Peer records travel, and that is the point of them: a node that
        // obtains the log obtains the network with it, rather than needing an
        // address list from somewhere else.
        "peer" => PeerRecord::from_value(&record.payload).map(|_| ()),
        other => return Err(SyncError::NotExchangeable { kind: other.into() }),
    };
    result.map_err(|error| SyncError::MalformedMessage {
        detail: error.to_string(),
    })
}

/// Replay a batch of exchangeable records through a node's own rules engine.
///
/// **This is the one replay implementation.** The daemon reaches it through
/// `apply_records` after every sync session, and `tests/simulation.rs` calls
/// it directly, so the simulator exercises the code the daemon runs rather
/// than a copy that could drift.
///
/// Each record is stamped with its **own** `created_at`, not with the local
/// clock, and that is load-bearing rather than tidy. A reveal must land in a
/// strictly later epoch than the commitment it opens; stamping both with
/// `timestamp()` on the way in puts them in the same epoch, so every replayed
/// claim would be refused and record sync would quietly stop importing work.
/// The record's own instant is also what makes the replay deterministic: two
/// nodes handed the same records assign every one to the same epoch. Epoch
/// *membership* from the record, settlement *order* from the epoch chain —
/// see `docs/design/settlement-convergence.md`.
///
/// Within a kind, records replay in `created_at` order rather than id order.
/// For objectives and commitments that is cosmetic; for claims it is not.
/// Replaying a reveal drains every epoch before the reveal's own —
/// `Node::reveal` calls `settle_due` before admitting, deliberately — so a
/// claim from epoch N+2 replayed *before* a claim from epoch N pays epoch N's
/// batch without it, and the epoch-N claim is then refused a moment later with
/// "epoch already settled", out of the very same session. Which claims a node
/// kept depended on how a content hash happened to sort in `Peer::ids()`.
///
/// **The precondition is narrow and worth stating exactly**, because a first
/// attempt at describing this got it wrong. It bites only when the node
/// *already holds* an accepted claim for the earlier epoch: `Node::due_epochs`
/// considers only epochs that have accepted claims, so an epoch this node
/// knows nothing about is never due, never drained, and a later arrival for it
/// is admitted normally. A cold sync — empty node, whole history in one
/// session — is therefore safe with or without this sort. A node that synced
/// partway and then received more history is not.
///
/// Pinned by `replay_does_not_lose_a_claim_to_the_order_records_arrive_in` in
/// `tests/simulation.rs`, which constructs the adverse order rather than
/// hoping for it, and which was verified to fail when this sort is removed.
pub fn replay_records(node: &mut Node, records: &[(String, crate::canonical::Value)]) {
    replay_records_with_horizon(node, records, None);
}

/// Replay records without allowing their author-controlled timestamps to move
/// this node's wall clock into a later epoch.
fn replay_records_at(node: &mut Node, records: &[(String, crate::canonical::Value)], now: &str) {
    let now_epoch = crate::time::parse_rfc3339(now)
        .and_then(|seconds| u64::try_from(seconds).ok())
        .map(|seconds| crate::partition::epoch_of(seconds, crate::partition::epoch_seconds()));
    replay_records_with_horizon(node, records, now_epoch);
}

/// Shared replay machinery.
///
/// `now_epoch` is present only at the live network boundary.  The public
/// deterministic replay helper deliberately has no wall-clock horizon: it is
/// used for cold sync, historical reconstruction, and virtual-clock tests,
/// none of which may depend on the machine's current time.  Live sessions go
/// through `apply_records` and always supply a trusted local horizon.
fn replay_records_with_horizon(
    node: &mut Node,
    records: &[(String, crate::canonical::Value)],
    now_epoch: Option<u64>,
) {
    let held = |payload: &crate::canonical::Value| -> String {
        payload
            .get("created_at")
            .and_then(crate::canonical::Value::as_str)
            .map(str::to_string)
            // A record with no readable instant still has to go somewhere,
            // and the local clock is the only remaining answer. The rules
            // engine refuses it a moment later if that instant does not work.
            .unwrap_or_else(timestamp)
    };
    for kind in ["objective", "commitment", "claim"] {
        let mut batch: Vec<&(String, crate::canonical::Value)> =
            records.iter().filter(|(k, _)| k == kind).collect();
        batch.sort_by_key(|(_, payload)| held(payload));
        for (_, payload) in batch {
            if node
                .ledger()
                .entries()
                .iter()
                .any(|entry| entry.kind == *kind && entry.payload.digest() == payload.digest())
            {
                continue;
            }
            let stamp = held(payload);
            let record_epoch = crate::time::parse_rfc3339(&stamp)
                .and_then(|seconds| u64::try_from(seconds).ok())
                .map(|seconds| {
                    crate::partition::epoch_of(seconds, crate::partition::epoch_seconds())
                });
            // Future records are retained by the peer and will be offered on a
            // later sync. Admitting one now would pass its timestamp into
            // `settle_due` and let an untrusted peer manufacture finality.
            if matches!((record_epoch, now_epoch), (Some(record), Some(local)) if record > local) {
                continue;
            }
            match kind {
                "objective" => {
                    if let Ok(value) = Objective::from_value(payload) {
                        let _ = node.post_objective(&value, &stamp);
                    }
                }
                "commitment" => {
                    if let Ok(value) = Commitment::from_value(payload) {
                        let _ = node.commit(&value, &stamp);
                    }
                }
                "claim" => {
                    if let Ok(value) = Claim::from_value(payload) {
                        let _ = node.reveal(&value, &stamp);
                    }
                }
                _ => {}
            }
        }
    }
}

/// Replay a sync peer's records, then settle whatever came due.
///
/// A `"peer"`-kind match arm used to sit in the replay loop and was
/// unreachable: the loop iterates `["objective", "commitment", "claim"]`, and
/// `sync::EXCHANGEABLE` has never included `"peer"` — peer records travel by
/// obtaining the log itself, not by anti-entropy. Whether they *should* be
/// exchangeable is a real question (the roadmap's "obtaining the log is
/// obtaining the address book" argues yes), but it is a sync-admission change,
/// not something to smuggle in through dead code.
fn apply_records(node: &mut Node, peer: &Peer) {
    let records: Vec<(String, crate::canonical::Value)> = peer
        .ids()
        .into_iter()
        .filter_map(|id| peer.get(&id).map(|r| (r.kind.clone(), r.payload.clone())))
        .collect();
    let now = timestamp();
    replay_records_at(node, &records, &now);
    // Replaying the inputs is only half of re-deriving the state: settlement is
    // deferred to the close of the reveal epoch, so a node that never drains
    // holds a log full of accepted claims that nobody was ever paid for.
    let _ = node.settle_at(&now);
}

/// `Service` is the key source `swarm` needs.
///
/// This is the fold arriving as an interface rather than a deletion: `swarm`
/// stops having its own answer to "where does a transport key come from" and
/// consumes `p2p`'s, which is the direction `docs/roadmap.md` asks for.
impl crate::swarm::tcp::KeySource for Service {
    fn key_for(&self, peer: &PeerId) -> Option<PeerPublic> {
        Service::key_for(self, peer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::Value;
    use crate::ledger::Ledger;

    #[test]
    fn a_future_record_cannot_advance_the_local_settlement_clock() {
        let root =
            std::env::temp_dir().join(format!("cairn-p2p-future-clock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let ledger = Ledger::open(root.join("log.jsonl")).unwrap();
        let mut node = Node::new(ledger, &root);
        let objective = Objective::new(
            "GOAL-future",
            "must wait for its epoch",
            Value::object([
                ("kind", Value::string("certificate")),
                ("checker", Value::string("checker.py")),
                ("checker_sha256", Value::string("aa".repeat(32))),
                ("entrypoint", Value::string("check")),
            ]),
            1,
            "treasury",
            "9999-01-01T00:00:00+00:00",
            None,
            None,
        )
        .unwrap();
        replay_records_at(
            &mut node,
            &[("objective".into(), objective.to_value())],
            "2026-08-18T00:00:00+00:00",
        );
        assert!(node.ledger().is_empty());
        let _ = std::fs::remove_dir_all(root);
    }
}
