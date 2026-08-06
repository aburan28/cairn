//! The part with sockets in it.
//!
//! [`crate::swarm::Swarm`] is a pure state machine: messages in, [`Action`]s out, no
//! clock and no randomness. This is the driver that gives it a network -- one
//! thread per connection, blocking reads, and a ticker for the choking rounds.
//!
//! Threads rather than an async runtime, because the alternative is a dependency
//! the size of the rest of this crate to manage a few dozen sockets that spend
//! their lives blocked on a peer. The concurrency here is not the interesting
//! part and should not cost the most.
//!
//! # The split is the point
//!
//! Everything that can fail for reasons that are **nobody's fault** lives here:
//! a refused connection, a timeout, a half-closed socket, a DNS answer that
//! changed. None of it reaches [`crate::swarm::Swarm`], and none of it produces a
//! [`crate::swarm::Dropped`] -- which is the same rule the verification ladder runs on.
//! A peer that cannot be reached has not misbehaved, exactly as a verifier that
//! cannot run has not refuted anything.
//!
//! The inverse also holds: every `Dropped` this module acts on came from the
//! state machine and describes something the peer *did*, so closing that socket
//! is a judgement rather than a retry.
//!
//! # Timeouts are the whole liveness story
//!
//! A blocking read on a peer that has gone quiet is a thread that never returns
//! and a piece that is never reassigned. Every socket gets a read and write
//! timeout, and a peer that trips one is disconnected -- at which point
//! [`crate::swarm::Swarm::remove_peer`] returns its reservations to the pool and the
//! transfer continues without it. That is the only reason a stalled peer is
//! survivable, and it is why the timeout is not a tunable nicety.

use std::collections::BTreeMap;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use super::dht::{Contact, NodeId, ProviderStore, RoutingTable};
use super::discovery::AddressBook;
use super::piece::DEFAULT_PIECE_LEN;
use super::wire::{check_frame_len, Handshake, Message, PEER_ID_LEN};
use super::{Action, Dropped, Limits, PeerId, Swarm};
use crate::blobs::{self, BlobStore};
use crate::p2p::discovery::Endpoint;
use crate::p2p::handshake::PeerIdentity;
use crate::p2p::transport::{self, Connection, Receiver as SealedReceiver, Sender as SealedSender};

/// The AEAD context every frame on a swarm session is sealed under.
///
/// Its own string, not `p2p::code`'s or `p2p::sync`'s, for the reason
/// [`crate::p2p`] gives at length: a frame sealed for one subsystem cannot be
/// opened as another's even by a peer that wants to. A blob transfer and a
/// record sync run over the same transport and must not be confusable.
pub const CONTEXT: &[u8] = b"proofwork/swarm/v1";

/// How long a socket may be silent before it is considered gone.
pub const IO_TIMEOUT: Duration = Duration::from_secs(30);
/// How often the choking round advances.
pub const TICK: Duration = Duration::from_millis(200);

/// A transfer that did not complete.
#[derive(Debug)]
pub enum TransferError {
    /// Nothing to talk to: every peer refused, timed out, or was unreachable.
    ///
    /// Deliberately not a per-peer error list. A transfer is not a peer's
    /// business, and the caller's next move -- try again later, try other peers
    /// -- is the same whichever socket failed.
    NoPeers,
    /// The deadline passed with the blob incomplete. Carries how far it got, so
    /// a caller can tell "nobody had it" from "nearly there".
    Incomplete { have: u32, want: u32 },
    /// Local I/O -- binding a listener, writing the finished blob.
    Io(io::Error),
}

impl std::fmt::Display for TransferError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransferError::NoPeers => f.write_str("no peer could be reached"),
            TransferError::Incomplete { have, want } => {
                write!(f, "transfer stalled with {have} of {want} pieces")
            }
            TransferError::Io(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for TransferError {}

impl From<io::Error> for TransferError {
    fn from(error: io::Error) -> TransferError {
        TransferError::Io(error)
    }
}

/// Outbound queues, keyed by peer.
///
/// An [`Action`] may name a peer other than the one whose message produced it --
/// a `have` goes to everybody, an endgame `cancel` goes to the loser -- so
/// dispatch cannot be "write to the socket I am reading from".
type Outbox = Arc<Mutex<BTreeMap<PeerId, Sender<Message>>>>;

/// The node's address book, shared across every connection and every swarm.
///
/// Node-wide rather than per-blob on purpose: a peer that has one blob is a peer
/// worth knowing about for all of them, and a book per swarm would be several
/// views of the same network that drift apart.
pub type Book = Arc<Mutex<AddressBook>>;

/// A fresh, empty address book.
pub fn new_book() -> Book {
    Arc::new(Mutex::new(AddressBook::new()))
}

/// This node's routing table and what it has been told others hold.
///
/// Node-wide like the address book, and for the same reason: the DHT is one
/// overlay, not one per blob.
#[derive(Clone)]
pub struct Dht {
    pub table: Arc<Mutex<RoutingTable>>,
    pub providers: Arc<Mutex<ProviderStore>>,
    /// This node's own signed record, offered when answering so the asker learns
    /// about us. Kademlia's tables fill themselves because XOR distance is
    /// symmetric; this is the message that makes that happen.
    pub me: Option<crate::crypto::identity::SignedRecord>,
}

impl Dht {
    pub fn new(local: NodeId) -> Dht {
        Dht {
            table: Arc::new(Mutex::new(RoutingTable::new(local))),
            providers: Arc::new(Mutex::new(ProviderStore::new())),
            me: None,
        }
    }

    pub fn with_record(mut self, record: crate::crypto::identity::SignedRecord) -> Dht {
        self.me = Some(record);
        self
    }
}

/// Answer a routing query, and learn from having been asked.
///
/// Both halves matter. The answer is what makes lookups converge; the *learning*
/// is what makes a routing table fill itself without any bootstrap traffic of its
/// own, and it works because XOR distance is symmetric -- a node near enough to
/// ask me is a node I want in the same bucket.
fn on_dht(peer: PeerId, message: &Message, dht: &Dht, now: u64) -> Vec<Action> {
    match message {
        Message::FindNode { key } => {
            let key = NodeId::from_bytes(*key);
            let closer: Vec<crate::crypto::identity::SignedRecord> = dht
                .table
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .closest(key, super::dht::K)
                .into_iter()
                .map(|contact| contact.signed)
                .collect();
            let providers = dht
                .providers
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .providers(key, now);
            vec![Action::Send(peer, Message::Nodes { closer, providers })]
        }
        Message::Nodes { closer, providers } => {
            let mut table = dht.table.lock().unwrap_or_else(|e| e.into_inner());
            for signed in closer {
                // Verified here. An unverifiable contact is dropped and costs
                // nothing, which is the right price for an unprovable hint.
                if let Ok(contact) = Contact::open(signed) {
                    // A full bucket defers to its oldest contact, and probing
                    // that one needs a connection this function does not have.
                    // Leaving it un-inserted is the conservative answer: it
                    // keeps the incumbent, which is the anti-eclipse behaviour.
                    let _ = table.insert(contact);
                }
            }
            let _ = providers;
            Vec::new()
        }
        Message::Announce { key } => {
            // An announcement is only as good as the record that carries it, and
            // this message does not carry one -- the announcer's record arrives
            // via peer exchange on the same connection. Without it there is
            // nothing verifiable to store, so nothing is stored.
            let _ = key;
            Vec::new()
        }
        _ => Vec::new(),
    }
}

/// Handle peer exchange, which the swarm state machine deliberately does not.
///
/// Returns the replies to send. Records are *verified here* -- by
/// [`AddressBook::offer`], which checks the signature -- so a relayed record is
/// evidence rather than hearsay and a hostile relay's only power is to withhold
/// or be out of date.
fn on_peer_exchange(peer: PeerId, message: &Message, book: &Book) -> Vec<Action> {
    match message {
        Message::WantPeers => {
            let shared = book.lock().unwrap_or_else(|e| e.into_inner()).share("");
            if shared.is_empty() {
                return Vec::new();
            }
            vec![Action::Send(peer, Message::Peers(shared))]
        }
        Message::Peers(records) => {
            let mut guard = book.lock().unwrap_or_else(|e| e.into_inner());
            for record in records {
                // A record that does not verify is dropped and nothing else
                // happens. It costs the sender nothing and it costs us nothing,
                // which is the right price for an unverifiable hint.
                let _ = guard.offer(record);
            }
            Vec::new()
        }
        _ => Vec::new(),
    }
}

/// A running seeder.
///
/// Serves any blob the store holds, to anyone who asks for it by digest. Drop it
/// or call [`Listener::shutdown`] to stop.
pub struct Listener {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
}

impl Listener {
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Stop accepting. Connections already open finish what they are doing.
    pub fn shutdown(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Serve every blob in `blobs` to anyone who connects.
///
/// Returns once the socket is bound, so a caller can read [`Listener::addr`] --
/// which matters for binding to port 0 and letting the OS choose.
pub fn serve(
    addr: impl ToSocketAddrs,
    identity: Arc<PeerIdentity>,
    blobs: BlobStore,
    limits: Limits,
) -> Result<Listener, TransferError> {
    serve_with(addr, identity, blobs, limits, new_book())
}

/// Serve, against an address book the caller owns.
///
/// The book is how a seeder learns about other seeders: every connection asks,
/// and the answers accumulate. A caller that persists it across restarts never
/// has to be told an address twice.
pub fn serve_with(
    addr: impl ToSocketAddrs,
    identity: Arc<PeerIdentity>,
    blobs: BlobStore,
    limits: Limits,
    book: Book,
) -> Result<Listener, TransferError> {
    serve_full(
        addr,
        identity,
        blobs,
        limits,
        book,
        Dht::new(NodeId::default()),
    )
}

/// Serve, against an address book and a routing table the caller owns.
pub fn serve_full(
    addr: impl ToSocketAddrs,
    identity: Arc<PeerIdentity>,
    blobs: BlobStore,
    limits: Limits,
    book: Book,
    dht: Dht,
) -> Result<Listener, TransferError> {
    let listener = std::net::TcpListener::bind(addr)?;
    let bound = listener.local_addr()?;
    listener.set_nonblocking(true)?;
    let stop = Arc::new(AtomicBool::new(false));

    let stop_thread = Arc::clone(&stop);
    let identity = Arc::clone(&identity);
    thread::spawn(move || {
        // One swarm per digest being served, shared across the connections that
        // want it -- choking has to allocate slots across peers, so a swarm per
        // connection would make every peer look like the only peer.
        let swarms: Arc<Mutex<BTreeMap<String, Arc<Mutex<Swarm>>>>> =
            Arc::new(Mutex::new(BTreeMap::new()));
        let outboxes: Arc<Mutex<BTreeMap<String, Outbox>>> = Arc::new(Mutex::new(BTreeMap::new()));
        let next_peer = Arc::new(AtomicU64::new(1));

        while !stop_thread.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let ctx = Serving {
                        blobs: blobs.clone(),
                        swarms: Arc::clone(&swarms),
                        outboxes: Arc::clone(&outboxes),
                        next_peer: Arc::clone(&next_peer),
                        limits,
                        book: Arc::clone(&book),
                        dht: dht.clone(),
                    };
                    let identity = Arc::clone(&identity);
                    thread::spawn(move || {
                        // The McEliece decapsulation happens here, on the
                        // connection thread rather than the accept loop: it
                        // costs ~12 ms, and a handshake that blocked the
                        // listener would let one slow peer stop every other.
                        // The amplification this exposes is named in
                        // `p2p::handshake` and is the responder's to price.
                        let Ok(connection) = transport::accept(stream, &identity) else {
                            return;
                        };
                        let _ = serve_one(connection, ctx);
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(TICK);
                }
                // An accept that fails for any other reason is this machine's
                // problem, not a peer's, and retrying is the only sane response.
                Err(_) => thread::sleep(TICK),
            }
        }
    });

    Ok(Listener { addr: bound, stop })
}

/// Everything a served connection needs that is not the socket.
///
/// A struct rather than eight parameters, and cloned per connection: every field
/// is either an `Arc` or cheap, so the clone is a handful of refcount bumps and
/// each thread gets a value it owns rather than a lifetime to thread through.
#[derive(Clone)]
struct Serving {
    blobs: BlobStore,
    swarms: Arc<Mutex<BTreeMap<String, Arc<Mutex<Swarm>>>>>,
    outboxes: Arc<Mutex<BTreeMap<String, Outbox>>>,
    next_peer: Arc<AtomicU64>,
    limits: Limits,
    book: Book,
    dht: Dht,
}

fn serve_one(mut connection: Connection, ctx: Serving) -> io::Result<()> {
    let Serving {
        blobs,
        swarms,
        outboxes,
        next_peer,
        limits,
        book,
        dht,
    } = ctx;
    // The transport handshake already ran, so the peer is authenticated before
    // a swarm byte moves. What is exchanged here is only *which blob* the
    // session is about.
    let Ok(head) = connection.receive(CONTEXT) else {
        return Ok(());
    };
    let Ok(their) = Handshake::decode(&head) else {
        return Ok(());
    };
    let ours = Handshake {
        digest: their.digest.clone(),
        // Self-asserted and never used: the transport derives the real peer id
        // from the handshake, so this field survives only as wire compatibility
        // and is deliberately left empty rather than filled with a claim.
        peer_id: [0u8; PEER_ID_LEN],
    };
    if connection.send(&ours.encode(), CONTEXT).is_err() {
        return Ok(());
    }

    // Do we even have it? A digest this store does not hold gets no error
    // message: there is nothing useful to say, and a node that enumerated what
    // it does *not* have would be volunteering a map of the network's gaps.
    //
    // But hanging up here would be wrong, and the reason is the whole of why
    // discovery is a separate concern from transfer. **The node that does not
    // have your blob is often the best node to ask who does.** Refusing to talk
    // to it forfeits exactly the hop that makes bootstrap a once-ever problem.
    // So: no bytes, no transfer, and peer exchange anyway.
    // `crate::blobs` addresses are bare lowercase hex; this protocol carries the
    // `sha256:` spelling the records use. One strip at the boundary rather than
    // two spellings loose in the module.
    let wanted = their
        .digest
        .strip_prefix("sha256:")
        .unwrap_or(&their.digest)
        .to_string();
    let Ok(bytes) = blobs.read(&wanted) else {
        return serve_peers_only(connection, &book, &dht);
    };

    let swarm = {
        let mut table = swarms.lock().unwrap_or_else(|e| e.into_inner());
        match table.get(&their.digest) {
            Some(existing) => Arc::clone(existing),
            None => {
                let Ok(fresh) = Swarm::seed(&bytes, DEFAULT_PIECE_LEN, limits) else {
                    return Ok(());
                };
                let fresh = Arc::new(Mutex::new(fresh));
                table.insert(their.digest.clone(), Arc::clone(&fresh));
                Arc::clone(&fresh)
            }
        }
    };
    let outbox: Outbox = {
        let mut table = outboxes.lock().unwrap_or_else(|e| e.into_inner());
        Arc::clone(
            table
                .entry(their.digest.clone())
                .or_insert_with(|| Arc::new(Mutex::new(BTreeMap::new()))),
        )
    };

    // One ticker per served digest would be tidier; one per connection is
    // harmless because `tick` only emits messages when a choking decision
    // actually changes, and it keeps the lifetime tied to something that ends.
    let ticker_swarm = Arc::clone(&swarm);
    let ticker_outbox = Arc::clone(&outbox);
    let ticking = Arc::new(AtomicBool::new(true));
    let ticking_thread = Arc::clone(&ticking);
    thread::spawn(move || {
        while ticking_thread.load(Ordering::SeqCst) {
            thread::sleep(TICK);
            let actions = {
                let mut swarm = ticker_swarm.lock().unwrap_or_else(|e| e.into_inner());
                swarm.tick()
            };
            dispatch(&actions, &ticker_outbox);
        }
    });

    let peer = PeerId(next_peer.fetch_add(1, Ordering::SeqCst));
    let result = run_peer(connection, peer, &swarm, &outbox, &book, &dht);
    ticking.store(false, Ordering::SeqCst);
    {
        let mut swarm = swarm.lock().unwrap_or_else(|e| e.into_inner());
        swarm.remove_peer(peer);
    }
    outbox
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&peer);
    result
}

/// Answer peer exchange for a blob this node does not hold, then hang up.
///
/// Bounded by a message budget rather than by a timeout alone: a peer that keeps
/// asking is a peer using this node as a free socket, and there is nothing here
/// worth more than a handful of frames.
fn serve_peers_only(mut connection: Connection, book: &Book, dht: &Dht) -> io::Result<()> {
    const BUDGET: u32 = 4;

    // Ask as well as answer. A node reached by a stranger has just learned that
    // stranger exists, and the exchange is cheaper in one round trip than two.
    if connection
        .send(&Message::WantPeers.encode(), CONTEXT)
        .is_err()
    {
        return Ok(());
    }

    for _ in 0..BUDGET {
        let Ok(body) = connection.receive(CONTEXT) else {
            break;
        };
        if check_frame_len(body.len() as u32).is_err() {
            break;
        }
        // No manifest on this path, so a bitfield cannot be sized and is
        // refused -- which is correct, because there is no transfer to have.
        let Ok(message) = Message::decode(&body, None) else {
            break;
        };
        match message {
            Message::WantPeers => {
                let shared = book.lock().unwrap_or_else(|e| e.into_inner()).share("");
                if !shared.is_empty()
                    && connection
                        .send(&Message::Peers(shared).encode(), CONTEXT)
                        .is_err()
                {
                    break;
                }
            }
            Message::Peers(records) => {
                let mut guard = book.lock().unwrap_or_else(|e| e.into_inner());
                for record in &records {
                    let _ = guard.offer(record);
                }
            }
            // A node without the blob is exactly the node a lookup wants to
            // reach, so routing is answered on this path too.
            Message::FindNode { .. } => {
                for action in on_dht(PeerId(0), &message, dht, unix_now()) {
                    if let Action::Send(_, reply) = action {
                        if connection.send(&reply.encode(), CONTEXT).is_err() {
                            return Ok(());
                        }
                    }
                }
            }
            // Anything else on this connection is a transfer message for a blob
            // this node does not have. Silently ignored: the peer is not
            // misbehaving, it just asked the wrong node.
            _ => {}
        }
    }
    Ok(())
}

/// Somewhere to get the transport key for a peer this node only has an id for.
///
/// # Why this is a trait and not a message
///
/// Encrypting the transport cost peer exchange its self-sufficiency: a relayed
/// record names a peer and where it was, and an authenticated dial needs the
/// responder's 261,120-byte McEliece key, which no record carries. Something has
/// to close that gap.
///
/// The obvious move — add a `WantKey`/`Key` pair to [`super::wire::Message`] —
/// is the wrong one. [`crate::p2p::dht`] already fetches keys on demand over an
/// existing session, and a second implementation of exactly that inside `swarm`
/// is the duplication `docs/roadmap.md` wants removed rather than doubled.
///
/// So this module states what it *needs* and lets the stack that already has it
/// supply the answer. `Service` implements this over its own address book, which
/// makes `swarm` a consumer of `p2p` rather than a parallel stack beside it —
/// the direction the fold is going, arrived at one interface rather than one
/// large deletion.
///
/// # Nothing here is trusted
///
/// A key that comes back is checked by the handshake: a peer id *is* the
/// `sha256` of a public key, so a wrong key derives a wrong id and the session
/// never opens. An implementation that lied would cost a failed dial, which is
/// the bound every hint in this crate carries.
pub trait KeySource {
    /// The transport key for `peer`, if this source has one.
    fn key_for(
        &self,
        peer: &crate::p2p::handshake::PeerId,
    ) -> Option<crate::p2p::handshake::PeerPublic>;
}

/// A source that knows nothing, for a caller with no `p2p` stack.
///
/// Named rather than an `Option`, because "I have no way to resolve keys" is a
/// real configuration and should read as one at the call site.
pub struct NoKeys;

impl KeySource for NoKeys {
    fn key_for(
        &self,
        _peer: &crate::p2p::handshake::PeerId,
    ) -> Option<crate::p2p::handshake::PeerPublic> {
        None
    }
}

/// Complete the address book's hints into dialable endpoints.
///
/// A book entry names a peer and an address; `keys` supplies the rest. Entries
/// whose key is unavailable are skipped rather than dialled, because a dial
/// without the responder's key cannot complete a handshake and would only spend
/// a connection to find that out.
///
/// This is what restores the property encryption cost: with a source that can
/// answer, a node that learned an address by asking can use it, and the second
/// fetch needs no endpoint handed to it.
pub fn complete(book: &Book, keys: &dyn KeySource) -> Vec<Endpoint> {
    let mut out = Vec::new();
    let records = book.lock().unwrap_or_else(|e| e.into_inner()).share("");
    for signed in &records {
        let Ok(record) = super::discovery::PeerRecord::open(signed) else {
            continue;
        };
        let Some(transport) = record.transport.as_deref() else {
            // An address with no transport id can never become a dial, whatever
            // fetches the key: there is nothing to look the key up by and
            // nothing to check a fetched one against.
            continue;
        };
        let Some(id) = decode_transport_id(transport) else {
            continue;
        };
        let Some(public) = keys.key_for(&id) else {
            continue;
        };
        for addr in &record.addrs {
            out.push(Endpoint::new(*addr, public.clone()));
        }
    }
    out
}

/// Hex to a 32-byte transport id.
fn decode_transport_id(text: &str) -> Option<crate::p2p::handshake::PeerId> {
    if text.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, pair) in text.as_bytes().chunks(2).enumerate() {
        let value = |byte: u8| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        };
        out[index] = (value(pair[0])? << 4) | value(pair[1])?;
    }
    Some(out)
}

/// Fetch `digest` from `peers`, writing it into `blobs` on success.
///
/// Returns the bytes as well as storing them, because the caller usually wants
/// both and re-reading a blob it just wrote would be the only other way to get
/// them.
pub fn fetch(
    digest: &str,
    peers: &[Endpoint],
    local: Arc<PeerIdentity>,
    blobs: &BlobStore,
    limits: Limits,
    deadline: Duration,
) -> Result<Vec<u8>, TransferError> {
    fetch_with(digest, peers, local, blobs, limits, deadline, new_book())
}

/// Fetch, against an address book the caller owns.
///
/// # What encryption cost peer exchange, stated plainly
///
/// Before the transport was sealed, a dial needed only an address, so every
/// address the book accumulated was immediately usable and the *second* fetch
/// on a node needed no `--peer` at all. An authenticated dial needs the
/// responder's 261,120-byte McEliece key as well, and a relayed peer record
/// carries only the 32-byte id of one — deliberately, because relaying a
/// quarter-megabyte per peer would cost more than the transfers peer exchange
/// exists to bootstrap.
///
/// So a book entry is now a *hint* rather than a dialable endpoint: it names a
/// peer and where it was, and something has to supply the key before it can be
/// used. `p2p::dht`'s `GetKey` already does exactly that over an existing
/// session, and wiring this module to it is the fold `docs/roadmap.md` tracks.
/// Until then this dials the endpoints it was given and lets the book
/// accumulate for the caller that can complete them.
pub fn fetch_with(
    digest: &str,
    peers: &[Endpoint],
    local: Arc<PeerIdentity>,
    blobs: &BlobStore,
    limits: Limits,
    deadline: Duration,
    book: Book,
) -> Result<Vec<u8>, TransferError> {
    fetch_using(digest, peers, local, blobs, limits, deadline, book, &NoKeys)
}

/// Fetch, completing the address book's hints through `keys`.
///
/// The form that restores what encryption cost. Everything the book learned by
/// asking is dialled alongside `peers`, for every entry whose transport key
/// `keys` can supply — so a node handed one endpoint once needs none the second
/// time, which is the entire point of peer exchange.
#[allow(clippy::too_many_arguments)]
pub fn fetch_using(
    digest: &str,
    peers: &[Endpoint],
    local: Arc<PeerIdentity>,
    blobs: &BlobStore,
    limits: Limits,
    deadline: Duration,
    book: Book,
    keys: &dyn KeySource,
) -> Result<Vec<u8>, TransferError> {
    let mut peers: Vec<Endpoint> = peers.to_vec();
    for endpoint in complete(&book, keys) {
        if !peers.iter().any(|known| known.addr == endpoint.addr) {
            peers.push(endpoint);
        }
    }
    let peers = &peers[..];
    if peers.is_empty() {
        return Err(TransferError::NoPeers);
    }
    let swarm = Arc::new(Mutex::new(Swarm::leech(digest, limits)));
    let outbox: Outbox = Arc::new(Mutex::new(BTreeMap::new()));
    // A routing table for the duration of the fetch. Contacts learned here are
    // not yet persisted -- the address book is what survives the process, and
    // the records land there too.
    let dht = Dht::new(NodeId::default());
    let (done_tx, done_rx): (Sender<()>, Receiver<()>) = mpsc::channel();
    let connected = Arc::new(AtomicU64::new(0));

    for (index, endpoint) in peers.iter().enumerate() {
        let endpoint = endpoint.clone();
        let digest = digest.to_string();
        let swarm = Arc::clone(&swarm);
        let outbox = Arc::clone(&outbox);
        let done = done_tx.clone();
        let connected = Arc::clone(&connected);
        let book = Arc::clone(&book);
        let dht = dht.clone();
        let local = Arc::clone(&local);
        thread::spawn(move || {
            // The endpoint carries the responder's McEliece key, so this dial
            // is authenticated before a swarm byte moves: a peer at that
            // address that cannot decapsulate gets no session at all.
            let Ok(mut connection) = transport::connect(&endpoint.peer, endpoint.addr, &local)
            else {
                return;
            };
            let hello = Handshake {
                digest: digest.clone(),
                peer_id: [0u8; PEER_ID_LEN],
            };
            if connection.send(&hello.encode(), CONTEXT).is_err() {
                return;
            }
            let Ok(head) = connection.receive(CONTEXT) else {
                return;
            };
            match Handshake::decode(&head) {
                // A peer answering about other content is answering a question
                // nobody asked. Nothing to transfer, so hang up.
                Ok(their) if their.digest == digest => {}
                _ => return,
            }
            connected.fetch_add(1, Ordering::SeqCst);

            // Peer ids are this node's own numbering: the index of the address
            // we dialled. The claimed id in the handshake is never used, because
            // it is self-asserted and free to forge.
            let peer = PeerId(index as u64);
            let _ = run_peer(connection, peer, &swarm, &outbox, &book, &dht);
            {
                let mut swarm = swarm.lock().unwrap_or_else(|e| e.into_inner());
                swarm.remove_peer(peer);
            }
            outbox
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&peer);
            let _ = done.send(());
        });
    }
    drop(done_tx);

    let started = Instant::now();
    loop {
        {
            let mut guard = swarm.lock().unwrap_or_else(|e| e.into_inner());
            if guard.is_complete() {
                if let Some(bytes) = guard.finish() {
                    drop(guard);
                    blobs
                        .put(&blobs::address(&bytes), &bytes)
                        .map_err(|error| TransferError::Io(io::Error::other(error.to_string())))?;
                    return Ok(bytes);
                }
            }
            let actions = guard.tick();
            drop(guard);
            dispatch(&actions, &outbox);
        }
        if started.elapsed() >= deadline {
            let (have, want) = swarm
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .progress()
                .unwrap_or((0, 0));
            if connected.load(Ordering::SeqCst) == 0 {
                return Err(TransferError::NoPeers);
            }
            return Err(TransferError::Incomplete { have, want });
        }
        // Every connection thread has ended and the blob is still not here.
        if done_rx.recv_timeout(TICK) == Err(mpsc::RecvTimeoutError::Disconnected) {
            let guard = swarm.lock().unwrap_or_else(|e| e.into_inner());
            if guard.is_complete() {
                if let Some(bytes) = guard.finish() {
                    drop(guard);
                    blobs
                        .put(&blobs::address(&bytes), &bytes)
                        .map_err(|error| TransferError::Io(io::Error::other(error.to_string())))?;
                    return Ok(bytes);
                }
            }
            let (have, want) = guard.progress().unwrap_or((0, 0));
            if connected.load(Ordering::SeqCst) == 0 {
                return Err(TransferError::NoPeers);
            }
            return Err(TransferError::Incomplete { have, want });
        }
    }
}

/// Read frames from one peer until the socket or the state machine says stop.
fn run_peer(
    connection: Connection,
    peer: PeerId,
    swarm: &Arc<Mutex<Swarm>>,
    outbox: &Outbox,
    book: &Book,
    dht: &Dht,
) -> io::Result<()> {
    let (tx, rx) = mpsc::channel::<Message>();
    outbox
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(peer, tx);

    // A writer thread, so a slow peer blocks its own socket rather than the
    // state machine every other peer is also waiting on. This is the reason
    // `Connection::split` exists: `&mut self` on both halves made one
    // connection in two threads impossible, and a mutex around it would starve
    // the writer whenever the reader blocked.
    let (mut writer, receiver): (SealedSender, SealedReceiver) = connection
        .split()
        .map_err(|error| io::Error::other(error.to_string()))?;
    let write_thread = thread::spawn(move || {
        while let Ok(message) = rx.recv() {
            if writer.send(&message.encode(), CONTEXT).is_err() {
                break;
            }
        }
    });

    let mut opening = {
        let mut guard = swarm.lock().unwrap_or_else(|e| e.into_inner());
        guard.add_peer(peer)
    };
    // Ask on every connection. One answer is what turns bootstrap from a
    // recurring problem into a once-ever one.
    opening.push(Action::Send(peer, Message::WantPeers));
    // And ask who holds what we came for. A single hop, not an iterative
    // lookup -- see the module docs for what that does and does not buy.
    {
        let guard = swarm.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(key) = NodeId::of_digest(guard.digest()) {
            opening.push(Action::Send(
                peer,
                Message::FindNode {
                    key: *key.as_bytes(),
                },
            ));
        }
    }
    dispatch(&opening, outbox);

    let mut reader = receiver;
    // The transport frames and authenticates; this layer sees a body or
    // nothing.
    while let Ok(body) = reader.receive(CONTEXT) {
        // `check_frame_len` still runs, because the transport's ceiling is the
        // *transport's* -- a 16 MiB frame is legal there and absurd here, and
        // the swarm's own limit is what bounds an allocation this state machine
        // will make.
        if let Err(error) = check_frame_len(body.len() as u32) {
            let actions = {
                let guard = swarm.lock().unwrap_or_else(|e| e.into_inner());
                guard.on_protocol_error(peer, error.to_string())
            };
            dispatch(&actions, outbox);
            break;
        }

        let pieces = {
            let guard = swarm.lock().unwrap_or_else(|e| e.into_inner());
            guard.manifest().map(|manifest| manifest.pieces())
        };
        let message = match Message::decode(&body, pieces) {
            Ok(message) => message,
            Err(error) => {
                let actions = {
                    let guard = swarm.lock().unwrap_or_else(|e| e.into_inner());
                    guard.on_protocol_error(peer, error.to_string())
                };
                dispatch(&actions, outbox);
                break;
            }
        };

        let exchange = on_peer_exchange(peer, &message, book);
        if !exchange.is_empty() {
            dispatch(&exchange, outbox);
        }
        let routing = on_dht(peer, &message, dht, unix_now());
        if !routing.is_empty() {
            dispatch(&routing, outbox);
        }
        // Provider records arrive on the routing path and belong in the address
        // book too: knowing who holds a blob is only useful with somewhere to
        // dial, and both facts came in the same verified record.
        if let Message::Nodes { providers, .. } = &message {
            let mut guard = book.lock().unwrap_or_else(|e| e.into_inner());
            for record in providers {
                let _ = guard.offer(record);
            }
        }
        let actions = {
            let mut guard = swarm.lock().unwrap_or_else(|e| e.into_inner());
            guard.on_message(peer, message)
        };
        let hung_up = actions
            .iter()
            .any(|action| matches!(action, Action::Drop(who, _) if *who == peer));
        dispatch(&actions, outbox);
        if hung_up {
            break;
        }
    }

    outbox
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&peer);
    let _ = write_thread.join();
    Ok(())
}

/// Route actions to the peers they name.
///
/// [`Action::Drop`] closes a queue rather than reporting anything: by the time
/// an action says to drop a peer, the state machine has already decided the peer
/// misbehaved, and there is no second opinion to collect.
fn dispatch(actions: &[Action], outbox: &Outbox) {
    let mut table = outbox.lock().unwrap_or_else(|e| e.into_inner());
    for action in actions {
        match action {
            Action::Send(peer, message) => {
                if let Some(sender) = table.get(peer) {
                    // A closed queue is a peer that has already gone. Nothing to
                    // do about it here, and the reader thread is what notices.
                    let _ = sender.send(message.clone());
                }
            }
            // Removing the queue *is* the disconnect: dropping the last `Sender`
            // makes the writer thread's `recv` fail, which closes the socket and
            // in turn unblocks the reader. Anything gentler would leave a peer
            // the state machine has already judged still able to talk.
            Action::Drop(peer, _) => {
                table.remove(peer);
            }
            Action::Complete => {}
        }
    }
}

/// Seconds since the epoch, for provider expiry.
///
/// The one clock reading in this module. A node's clock is not evidence -- which
/// is why [`super::dht::ProviderStore`] takes the time as an argument rather than
/// reading it -- and this is the boundary where a real one is allowed in.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// Human-readable reason a peer was dropped, for a caller that wants to log it.
pub fn describe(dropped: &Dropped) -> String {
    dropped.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blobs::{self, BlobStore};
    use crate::canonical::digest_bytes;
    use std::fs;
    use std::path::PathBuf;

    fn scratch(tag: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "proofwork-swarm-{}-{nanos}-{n}-{tag}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create scratch dir");
        path
    }

    fn store(dir: &std::path::Path, name: &str) -> BlobStore {
        BlobStore::at(dir.join(name))
    }

    // `crate::blobs` addresses are bare hex; this protocol speaks the `sha256:`
    // spelling the records use. Three shims rather than the prefix scattered
    // through every assertion.
    fn put(store: &BlobStore, bytes: &[u8]) -> String {
        let address = blobs::address(bytes);
        store.put(&address, bytes).expect("puts");
        format!("sha256:{address}")
    }

    fn holds(store: &BlobStore, digest: &str) -> bool {
        store.holds(digest.strip_prefix("sha256:").unwrap_or(digest))
    }

    fn read(store: &BlobStore, digest: &str) -> Option<Vec<u8>> {
        store
            .read(digest.strip_prefix("sha256:").unwrap_or(digest))
            .ok()
    }

    /// A seeder with its own transport identity, and the endpoint to dial it.
    ///
    /// An endpoint rather than an address, because the dial is authenticated
    /// now: the caller needs the responder's McEliece key, and pairing the two
    /// here keeps every test from restating it.
    fn seeder_at(blobs: BlobStore) -> (Listener, Endpoint) {
        let identity = Arc::new(PeerIdentity::generate());
        let public = identity.to_public();
        let listener = serve("127.0.0.1:0", identity, blobs, Limits::default()).expect("serves");
        let endpoint = Endpoint::new(listener.addr(), public);
        (listener, endpoint)
    }

    /// An identity for a leech. Generation costs ~243 ms, which is why tests
    /// make one rather than one per dial.
    fn leech_identity() -> Arc<PeerIdentity> {
        Arc::new(PeerIdentity::generate())
    }

    fn evaluator(size: usize) -> Vec<u8> {
        let mut source = b"def score(artifact):\n    return len(artifact)\n".to_vec();
        while source.len() < size {
            source.extend_from_slice(b"# padding to make this worth cutting into pieces\n");
        }
        source
    }

    #[test]
    fn a_blob_moves_between_two_nodes_over_a_real_socket() {
        let dir = scratch("transfer");
        let seeder = store(&dir, "seed");
        let leecher = store(&dir, "leech");

        let data = evaluator(80_000);
        let digest = put(&seeder, &data);
        assert!(!holds(&leecher, &digest), "the leech starts with nothing");

        let (listener, endpoint) = seeder_at(seeder);
        let got = fetch(
            &digest,
            &[endpoint],
            leech_identity(),
            &leecher,
            Limits::default(),
            Duration::from_secs(20),
        )
        .expect("transfers");

        assert_eq!(got, data);
        assert!(holds(&leecher, &digest), "and it landed in the store");
        assert_eq!(read(&leecher, &digest), Some(data));
        // Main's store hashes on read and refuses a mismatch, so a successful
        // read *is* the integrity check.
        assert!(holds(&leecher, &digest));
        listener.shutdown();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_leech_pulls_from_several_seeds_at_once() {
        let dir = scratch("multi");
        let data = evaluator(120_000);
        let digest = digest_bytes(&data);

        let mut endpoints = Vec::new();
        let mut listeners = Vec::new();
        for index in 0..3 {
            let seeder = store(&dir, &format!("seed{index}"));
            put(&seeder, &data);
            let (listener, endpoint) = seeder_at(seeder);
            endpoints.push(endpoint);
            listeners.push(listener);
        }

        let leecher = store(&dir, "leech");
        let got = fetch(
            &digest,
            &endpoints,
            leech_identity(),
            &leecher,
            Limits::default(),
            Duration::from_secs(20),
        )
        .expect("transfers");
        assert_eq!(got, data);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_dead_peer_among_live_ones_does_not_stop_the_transfer() {
        // The reason timeouts and `remove_peer` exist: an unreachable address is
        // nobody's fault and must not cost the transfer.
        let dir = scratch("mixed");
        let data = evaluator(50_000);
        let seeder = store(&dir, "seed");
        let digest = put(&seeder, &data);
        let (_listener, endpoint) = seeder_at(seeder);

        // A port nothing is listening on, first in the list. It borrows the
        // live peer's key, so what fails is the connection and not the
        // handshake -- which is the case this test is about.
        let dead = Endpoint::new(
            "127.0.0.1:1".parse().expect("an address"),
            endpoint.peer.clone(),
        );
        let leecher = store(&dir, "leech");
        let got = fetch(
            &digest,
            &[dead, endpoint],
            leech_identity(),
            &leecher,
            Limits::default(),
            Duration::from_secs(20),
        )
        .expect("transfers anyway");
        assert_eq!(got, data);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn asking_a_node_for_a_blob_it_does_not_have_fails_without_hanging() {
        let dir = scratch("absent");
        let seeder = store(&dir, "seed");
        put(&seeder, b"something else");
        let (listener, endpoint) = seeder_at(seeder);

        let leecher = store(&dir, "leech");
        let error = fetch(
            &digest_bytes(b"nobody has this"),
            &[endpoint],
            leech_identity(),
            &leecher,
            Limits::default(),
            Duration::from_secs(5),
        )
        .expect_err("nothing to transfer");
        // The peer answered the handshake and then hung up, which is a peer that
        // could not help rather than a peer that misbehaved.
        assert!(
            matches!(
                error,
                TransferError::Incomplete { .. } | TransferError::NoPeers
            ),
            "unexpected {error:?}"
        );
        listener.shutdown();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn peer_exchange_still_spreads_addresses_but_a_dial_now_needs_a_key_too() {
        // This test used to assert that C's *second* fetch needed no `--peer`
        // at all: it heard about B from A and dialled straight away. Encrypting
        // the transport took that away and the honest thing is to assert what
        // is now true rather than to weaken the name.
        //
        // What survives: peer exchange works, records are verified, and C ends
        // up knowing where B is having been told only about A.
        //
        // What it costs: an authenticated dial needs B's 261,120-byte McEliece
        // key, and a relayed record carries only the 32-byte id of one. So a
        // learned address is a *hint* that something must complete before it is
        // dialable. `p2p::dht`'s `GetKey` already fetches keys on demand over an
        // existing session; wiring this module to it is the fold the roadmap
        // tracks, and it is what restores the old property.
        use crate::crypto::identity::Identity;
        use crate::swarm::discovery::PeerRecord;

        let dir = scratch("pex");
        let only_b = evaluator(40_000);
        let digest = crate::canonical::digest_bytes(&only_b);

        // B holds the blob and serves it.
        let b_store = store(&dir, "b");
        put(&b_store, &only_b);
        let (b, b_endpoint) = seeder_at(b_store);

        // A holds nothing, but knows where B is -- and will say so when asked.
        // The record names B's transport id, which is the field that makes a
        // relayed record enough to *complete* rather than only to locate.
        let a_book = new_book();
        let b_transport = crate::p2p::handshake::peer_id_hex(&b_endpoint.peer.id());
        let b_record = PeerRecord::sign_for(
            &Identity::from_secret_bytes([9u8; 32]),
            &[b.addr()],
            1,
            Some(&b_transport),
        )
        .expect("signs");
        assert!(a_book
            .lock()
            .expect("lock")
            .offer(&b_record)
            .expect("verifies"));
        let a_identity = Arc::new(PeerIdentity::generate());
        let a_public = a_identity.to_public();
        let a = serve_with(
            "127.0.0.1:0",
            a_identity,
            store(&dir, "a"),
            Limits::default(),
            a_book,
        )
        .expect("serves");
        let a_endpoint = Endpoint::new(a.addr(), a_public);

        // C is told about A only. A does not have the blob, so this fails --
        // and on the way, C learns about B.
        let c_book = new_book();
        let c_store = store(&dir, "c");
        let _ = fetch_with(
            &digest,
            &[a_endpoint],
            leech_identity(),
            &c_store,
            Limits::default(),
            Duration::from_secs(5),
            Arc::clone(&c_book),
        );

        let learned = c_book.lock().expect("lock").addrs();
        assert!(
            learned.contains(&b.addr()),
            "C never learned B's address by asking A"
        );

        // And the record C learned carries B's transport id, so the hint is
        // completable rather than a dead end -- an address with no id could
        // never become a dial no matter what fetched the key.
        let records = c_book.lock().expect("lock").share("");
        let for_b = records
            .iter()
            .filter_map(|signed| PeerRecord::open(signed).ok())
            .find(|record| record.addrs.contains(&b.addr()))
            .expect("C holds a record for B");
        assert_eq!(
            for_b.transport.as_deref(),
            Some(b_transport.as_str()),
            "the learned record cannot name the transport to dial"
        );

        // Given the key, that hint dials and transfers. This is the step the
        // fold will make automatic.
        let second = fetch_with(
            &digest,
            &[b_endpoint],
            leech_identity(),
            &c_store,
            Limits::default(),
            Duration::from_secs(20),
            c_book,
        )
        .expect("a completed hint fetches");
        assert_eq!(second, only_b);

        a.shutdown();
        b.shutdown();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_record_relayed_by_a_stranger_is_verified_rather_than_believed() {
        // A relay's only power. C is handed a record whose address was edited;
        // the signature no longer checks out, so it never reaches the book and C
        // dials nothing.
        use crate::crypto::identity::Identity;
        use crate::swarm::discovery::PeerRecord;

        let signed = PeerRecord::sign(
            &Identity::from_secret_bytes([4u8; 32]),
            &["127.0.0.1:9999".parse().expect("addr")],
            1,
        )
        .expect("signs");
        let mut forged = signed.clone();
        forged.record = crate::canonical::Value::object([
            ("type", crate::canonical::Value::string("peer")),
            (
                "addrs",
                crate::canonical::Value::array([crate::canonical::Value::string("10.0.0.1:1")]),
            ),
            ("seq", crate::canonical::Value::Int(1)),
        ]);

        let book = new_book();
        let actions = on_peer_exchange(PeerId(1), &Message::Peers(vec![forged]), &book);
        assert!(actions.is_empty());
        assert!(
            book.lock().expect("lock").is_empty(),
            "an unverifiable hint costs nothing and buys nothing"
        );

        // The genuine article does land.
        on_peer_exchange(PeerId(1), &Message::Peers(vec![signed]), &book);
        assert_eq!(book.lock().expect("lock").len(), 1);
    }

    #[test]
    fn fetching_with_no_peers_is_refused_rather_than_waited_out() {
        let dir = scratch("nopeers");
        let leecher = store(&dir, "leech");
        assert!(matches!(
            fetch(
                &digest_bytes(b"x"),
                &[],
                leech_identity(),
                &leecher,
                Limits::default(),
                Duration::from_secs(1)
            ),
            Err(TransferError::NoPeers)
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_transfer_puts_no_plaintext_on_the_wire() {
        // The claim the whole port exists to make, asserted rather than
        // assumed. A recording relay sits between leech and seed; afterwards
        // neither the blob's bytes nor its digest may appear in the capture.
        //
        // The same shape as `tests/wire_encryption.rs` does for `p2p`, and for
        // the same reason: "we call the sealed API now" is a statement about
        // the code, and this is a statement about the bytes.
        use std::io::{Read as _, Write as _};
        use std::net::{TcpListener, TcpStream};

        let dir = scratch("sealed");
        let seeder = store(&dir, "seed");
        // A payload with a distinctive marker, so finding it in the capture is
        // unambiguous rather than a coincidence of common bytes.
        let mut data = b"MARKER-swarm-plaintext-canary-".to_vec();
        data.extend_from_slice(&evaluator(20_000));
        let digest = put(&seeder, &data);
        let (listener, endpoint) = seeder_at(seeder);

        // The relay: accept one connection, splice both ways, keep a copy.
        let relay = TcpListener::bind("127.0.0.1:0").expect("binds");
        let relay_addr = relay.local_addr().expect("addr");
        let upstream = endpoint.addr;
        let captured: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&captured);
        thread::spawn(move || {
            while let Ok((mut inbound, _)) = relay.accept() {
                let Ok(mut outbound) = TcpStream::connect(upstream) else {
                    continue;
                };
                let (Ok(mut in2), Ok(mut out2)) = (inbound.try_clone(), outbound.try_clone())
                else {
                    continue;
                };
                let seen = Arc::clone(&recorder);
                thread::spawn(move || {
                    let mut buffer = [0u8; 8192];
                    while let Ok(read) = inbound.read(&mut buffer) {
                        if read == 0 || outbound.write_all(&buffer[..read]).is_err() {
                            break;
                        }
                        seen.lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .extend_from_slice(&buffer[..read]);
                    }
                });
                let seen = Arc::clone(&recorder);
                thread::spawn(move || {
                    let mut buffer = [0u8; 8192];
                    while let Ok(read) = out2.read(&mut buffer) {
                        if read == 0 || in2.write_all(&buffer[..read]).is_err() {
                            break;
                        }
                        seen.lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .extend_from_slice(&buffer[..read]);
                    }
                });
            }
        });

        let leecher = store(&dir, "leech");
        let through_relay = Endpoint::new(relay_addr, endpoint.peer.clone());
        let got = fetch(
            &digest,
            &[through_relay],
            leech_identity(),
            &leecher,
            Limits::default(),
            Duration::from_secs(30),
        )
        .expect("transfers through the relay");
        assert_eq!(got, data, "the relay broke the transfer");

        let capture = captured.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert!(
            !capture.is_empty(),
            "the relay recorded nothing, so this test proves nothing"
        );
        assert!(
            !contains(&capture, b"MARKER-swarm-plaintext-canary-"),
            "the blob's bytes travelled in the clear"
        );
        let bare = digest.strip_prefix("sha256:").unwrap_or(&digest);
        assert!(
            !contains(&capture, bare.as_bytes()),
            "the digest travelled in the clear, so an observer learns which \
             objective this node is working on"
        );
        listener.shutdown();
        let _ = fs::remove_dir_all(&dir);
    }

    /// Substring search over bytes. `Vec` has no `contains` for slices.
    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn a_key_source_restores_the_fetch_that_needs_no_endpoint() {
        // The property encryption cost, given back. C learns B's address by
        // asking A, and with something that can supply B's transport key it
        // fetches from B having been *handed* nothing -- which is what peer
        // exchange was always for.
        use crate::crypto::identity::Identity;
        use crate::swarm::discovery::PeerRecord;

        struct OneKey(
            crate::p2p::handshake::PeerId,
            crate::p2p::handshake::PeerPublic,
        );
        impl KeySource for OneKey {
            fn key_for(
                &self,
                peer: &crate::p2p::handshake::PeerId,
            ) -> Option<crate::p2p::handshake::PeerPublic> {
                (peer == &self.0).then(|| self.1.clone())
            }
        }

        let dir = scratch("keysource");
        let only_b = evaluator(30_000);
        let digest = crate::canonical::digest_bytes(&only_b);

        let b_store = store(&dir, "b");
        put(&b_store, &only_b);
        let (b, b_endpoint) = seeder_at(b_store);
        let b_id = b_endpoint.peer.id();

        // A book holding what peer exchange would have taught: an address and a
        // transport id, and no key.
        let book = new_book();
        let record = PeerRecord::sign_for(
            &Identity::from_secret_bytes([12u8; 32]),
            &[b.addr()],
            1,
            Some(&crate::p2p::handshake::peer_id_hex(&b_id)),
        )
        .expect("signs");
        assert!(book.lock().expect("lock").offer(&record).expect("verifies"));

        // Without a key source the hint stays a hint: nothing to dial.
        assert!(
            complete(&book, &NoKeys).is_empty(),
            "a hint became an endpoint with no key to complete it"
        );

        // With one, it is an endpoint -- and the fetch needs no `peers` at all.
        let keys = OneKey(b_id, b_endpoint.peer.clone());
        assert_eq!(complete(&book, &keys).len(), 1);
        let c_store = store(&dir, "c");
        let got = fetch_using(
            &digest,
            &[],
            leech_identity(),
            &c_store,
            Limits::default(),
            Duration::from_secs(20),
            book,
            &keys,
        )
        .expect("a completed hint needs no endpoint handed in");
        assert_eq!(got, only_b);

        b.shutdown();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_record_with_no_transport_id_is_never_completed() {
        // An address with nothing to look a key up by, and nothing to check a
        // fetched one against, can never become a dial however good the source.
        use crate::crypto::identity::Identity;
        use crate::swarm::discovery::PeerRecord;

        struct Anything(crate::p2p::handshake::PeerPublic);
        impl KeySource for Anything {
            fn key_for(
                &self,
                _peer: &crate::p2p::handshake::PeerId,
            ) -> Option<crate::p2p::handshake::PeerPublic> {
                Some(self.0.clone())
            }
        }

        let book = new_book();
        let record = PeerRecord::sign(
            &Identity::from_secret_bytes([13u8; 32]),
            &["127.0.0.1:9999".parse().expect("addr")],
            1,
        )
        .expect("signs");
        assert!(book.lock().expect("lock").offer(&record).expect("verifies"));
        let source = Anything(PeerIdentity::generate().to_public());
        assert!(
            complete(&book, &source).is_empty(),
            "an id-less record was completed into something dialable"
        );
    }
}
