//! The part with sockets in it.
//!
//! [`super::Swarm`] is a pure state machine: messages in, [`Action`]s out, no
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
//! changed. None of it reaches [`super::Swarm`], and none of it produces a
//! [`super::Dropped`] -- which is the same rule the verification ladder runs on.
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
//! [`super::Swarm::remove_peer`] returns its reservations to the pool and the
//! transfer continues without it. That is the only reason a stalled peer is
//! survivable, and it is why the timeout is not a tunable nicety.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
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
    blobs: BlobStore,
    limits: Limits,
) -> Result<Listener, TransferError> {
    serve_with(addr, blobs, limits, new_book())
}

/// Serve, against an address book the caller owns.
///
/// The book is how a seeder learns about other seeders: every connection asks,
/// and the answers accumulate. A caller that persists it across restarts never
/// has to be told an address twice.
pub fn serve_with(
    addr: impl ToSocketAddrs,
    blobs: BlobStore,
    limits: Limits,
    book: Book,
) -> Result<Listener, TransferError> {
    serve_full(addr, blobs, limits, book, Dht::new(NodeId::default()))
}

/// Serve, against an address book and a routing table the caller owns.
pub fn serve_full(
    addr: impl ToSocketAddrs,
    blobs: BlobStore,
    limits: Limits,
    book: Book,
    dht: Dht,
) -> Result<Listener, TransferError> {
    let listener = TcpListener::bind(addr)?;
    let bound = listener.local_addr()?;
    listener.set_nonblocking(true)?;
    let stop = Arc::new(AtomicBool::new(false));

    let stop_thread = Arc::clone(&stop);
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
                    thread::spawn(move || {
                        let _ = serve_one(stream, ctx);
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

fn serve_one(mut stream: TcpStream, ctx: Serving) -> io::Result<()> {
    let Serving {
        blobs,
        swarms,
        outboxes,
        next_peer,
        limits,
        book,
        dht,
    } = ctx;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;

    let mut head = [0u8; Handshake::LEN];
    stream.read_exact(&mut head)?;
    let Ok(their) = Handshake::decode(&head) else {
        return Ok(());
    };
    let ours = Handshake {
        digest: their.digest.clone(),
        peer_id: [0u8; PEER_ID_LEN],
    };
    stream.write_all(&ours.encode())?;

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
        return serve_peers_only(stream, &book, &dht);
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
    let result = run_peer(stream, peer, &swarm, &outbox, &book, &dht);
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
fn serve_peers_only(mut stream: TcpStream, book: &Book, dht: &Dht) -> io::Result<()> {
    const BUDGET: u32 = 4;

    // Ask as well as answer. A node reached by a stranger has just learned that
    // stranger exists, and the exchange is cheaper in one round trip than two.
    stream.write_all(&Message::WantPeers.frame())?;

    let mut header = [0u8; 4];
    for _ in 0..BUDGET {
        if stream.read_exact(&mut header).is_err() {
            break;
        }
        let Ok(len) = check_frame_len(u32::from_be_bytes(header)) else {
            break;
        };
        let mut body = vec![0u8; len];
        if stream.read_exact(&mut body).is_err() {
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
                if !shared.is_empty() && stream.write_all(&Message::Peers(shared).frame()).is_err()
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
                        if stream.write_all(&reply.frame()).is_err() {
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

/// Fetch `digest` from `peers`, writing it into `blobs` on success.
///
/// Returns the bytes as well as storing them, because the caller usually wants
/// both and re-reading a blob it just wrote would be the only other way to get
/// them.
pub fn fetch(
    digest: &str,
    peers: &[SocketAddr],
    blobs: &BlobStore,
    limits: Limits,
    deadline: Duration,
) -> Result<Vec<u8>, TransferError> {
    fetch_with(digest, peers, blobs, limits, deadline, new_book())
}

/// Fetch, against an address book the caller owns.
///
/// Addresses already in the book are dialled alongside `peers`, and every peer
/// reached adds what it knows. So the *second* fetch on a node needs no `--peer`
/// at all, which is the entire point of peer exchange: bootstrap is a problem
/// you have once.
pub fn fetch_with(
    digest: &str,
    peers: &[SocketAddr],
    blobs: &BlobStore,
    limits: Limits,
    deadline: Duration,
    book: Book,
) -> Result<Vec<u8>, TransferError> {
    let mut peers: Vec<SocketAddr> = peers.to_vec();
    for known in book.lock().unwrap_or_else(|e| e.into_inner()).addrs() {
        if !peers.contains(&known) {
            peers.push(known);
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

    for (index, addr) in peers.iter().enumerate() {
        let addr = *addr;
        let digest = digest.to_string();
        let swarm = Arc::clone(&swarm);
        let outbox = Arc::clone(&outbox);
        let done = done_tx.clone();
        let connected = Arc::clone(&connected);
        let book = Arc::clone(&book);
        let dht = dht.clone();
        thread::spawn(move || {
            let Ok(stream) = TcpStream::connect_timeout(&addr, IO_TIMEOUT) else {
                return;
            };
            if stream.set_read_timeout(Some(IO_TIMEOUT)).is_err()
                || stream.set_write_timeout(Some(IO_TIMEOUT)).is_err()
            {
                return;
            }
            let mut stream = stream;
            let hello = Handshake {
                digest: digest.clone(),
                peer_id: [0u8; PEER_ID_LEN],
            };
            if stream.write_all(&hello.encode()).is_err() {
                return;
            }
            let mut head = [0u8; Handshake::LEN];
            if stream.read_exact(&mut head).is_err() {
                return;
            }
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
            let _ = run_peer(stream, peer, &swarm, &outbox, &book, &dht);
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
    stream: TcpStream,
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
    // state machine every other peer is also waiting on.
    let mut writer = stream.try_clone()?;
    let write_thread = thread::spawn(move || {
        while let Ok(message) = rx.recv() {
            if writer.write_all(&message.frame()).is_err() {
                break;
            }
        }
        let _ = writer.flush();
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

    let mut reader = stream;
    let mut header = [0u8; 4];
    loop {
        if reader.read_exact(&mut header).is_err() {
            break;
        }
        let declared = u32::from_be_bytes(header);
        let len = match check_frame_len(declared) {
            Ok(len) => len,
            Err(error) => {
                // Refused before a byte of it is allocated, which is the whole
                // point of checking the header separately.
                let actions = {
                    let guard = swarm.lock().unwrap_or_else(|e| e.into_inner());
                    guard.on_protocol_error(peer, error.to_string())
                };
                dispatch(&actions, outbox);
                break;
            }
        };
        let mut body = vec![0u8; len];
        if reader.read_exact(&mut body).is_err() {
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

        let listener = serve("127.0.0.1:0", seeder, Limits::default()).expect("serves");
        let got = fetch(
            &digest,
            &[listener.addr()],
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

        let mut addrs = Vec::new();
        let mut listeners = Vec::new();
        for index in 0..3 {
            let seeder = store(&dir, &format!("seed{index}"));
            put(&seeder, &data);
            let listener = serve("127.0.0.1:0", seeder, Limits::default()).expect("serves");
            addrs.push(listener.addr());
            listeners.push(listener);
        }

        let leecher = store(&dir, "leech");
        let got = fetch(
            &digest,
            &addrs,
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
        let listener = serve("127.0.0.1:0", seeder, Limits::default()).expect("serves");

        // A port nothing is listening on, first in the list.
        let dead: SocketAddr = "127.0.0.1:1".parse().expect("an address");
        let leecher = store(&dir, "leech");
        let got = fetch(
            &digest,
            &[dead, listener.addr()],
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
        let listener = serve("127.0.0.1:0", seeder, Limits::default()).expect("serves");

        let leecher = store(&dir, "leech");
        let error = fetch(
            &digest_bytes(b"nobody has this"),
            &[listener.addr()],
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
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_node_learns_addresses_by_asking_and_needs_no_address_the_second_time() {
        // The claim discovery is for, end to end and over real sockets. Node C
        // is told about A. A knows about B. C ends up able to fetch a blob only
        // B has, having never been given B's address by anyone -- which is what
        // "no hardcoded IPs" means in practice: you are told one thing, once.
        use crate::crypto::identity::Identity;
        use crate::swarm::discovery::PeerRecord;

        let dir = scratch("pex");
        let only_b = evaluator(40_000);
        let digest = crate::canonical::digest_bytes(&only_b);

        // B holds the blob and serves it.
        let b_store = store(&dir, "b");
        put(&b_store, &only_b);
        let b = serve("127.0.0.1:0", b_store, Limits::default()).expect("serves");

        // A holds nothing, but knows where B is -- and will say so when asked.
        let a_book = new_book();
        let b_record = PeerRecord::sign(&Identity::from_secret_bytes([9u8; 32]), &[b.addr()], 1)
            .expect("signs");
        assert!(a_book
            .lock()
            .expect("lock")
            .offer(&b_record)
            .expect("verifies"));
        let a =
            serve_with("127.0.0.1:0", store(&dir, "a"), Limits::default(), a_book).expect("serves");

        // C is told about A only. A does not have the blob.
        let c_book = new_book();
        let c_store = store(&dir, "c");
        let got = fetch_with(
            &digest,
            &[a.addr()],
            &c_store,
            Limits::default(),
            Duration::from_secs(20),
            Arc::clone(&c_book),
        );

        // Whether that first attempt completes is a race: C has to hear about B
        // from A and dial it before the deadline. What must hold either way is
        // that C now *knows* about B, learned from a signed record it verified.
        let learned = c_book.lock().expect("lock").addrs();
        assert!(
            learned.contains(&b.addr()),
            "C never learned B's address by asking A"
        );

        // And with that, C fetches without being given any address at all.
        let second = fetch_with(
            &digest,
            &[],
            &c_store,
            Limits::default(),
            Duration::from_secs(20),
            c_book,
        )
        .expect("the second fetch needs no --peer");
        assert_eq!(second, only_b);
        let _ = got;

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
                &leecher,
                Limits::default(),
                Duration::from_secs(1)
            ),
            Err(TransferError::NoPeers)
        ));
        let _ = fs::remove_dir_all(&dir);
    }
}
