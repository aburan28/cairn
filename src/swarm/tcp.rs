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

use super::piece::DEFAULT_PIECE_LEN;
use super::wire::{check_frame_len, Handshake, Message, PEER_ID_LEN};
use super::{Action, Dropped, Limits, PeerId, Swarm};
use crate::store::blobs::BlobStore;

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
                    let blobs = blobs.clone();
                    let swarms = Arc::clone(&swarms);
                    let outboxes = Arc::clone(&outboxes);
                    let next_peer = Arc::clone(&next_peer);
                    thread::spawn(move || {
                        let _ = serve_one(stream, blobs, swarms, outboxes, next_peer, limits);
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

fn serve_one(
    mut stream: TcpStream,
    blobs: BlobStore,
    swarms: Arc<Mutex<BTreeMap<String, Arc<Mutex<Swarm>>>>>,
    outboxes: Arc<Mutex<BTreeMap<String, Outbox>>>,
    next_peer: Arc<AtomicU64>,
    limits: Limits,
) -> io::Result<()> {
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

    // Do we even have it? A digest this store does not hold is answered by
    // hanging up rather than by an error message: there is nothing useful to
    // say, and a node that enumerated what it does *not* have would be
    // volunteering a map of the network's gaps.
    let Ok(Some(bytes)) = blobs.get(&their.digest) else {
        return Ok(());
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
    let result = run_peer(stream, peer, &swarm, &outbox);
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
    if peers.is_empty() {
        return Err(TransferError::NoPeers);
    }
    let swarm = Arc::new(Mutex::new(Swarm::leech(digest, limits)));
    let outbox: Outbox = Arc::new(Mutex::new(BTreeMap::new()));
    let (done_tx, done_rx): (Sender<()>, Receiver<()>) = mpsc::channel();
    let connected = Arc::new(AtomicU64::new(0));

    for (index, addr) in peers.iter().enumerate() {
        let addr = *addr;
        let digest = digest.to_string();
        let swarm = Arc::clone(&swarm);
        let outbox = Arc::clone(&outbox);
        let done = done_tx.clone();
        let connected = Arc::clone(&connected);
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
            let _ = run_peer(stream, peer, &swarm, &outbox);
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
                        .put(&bytes)
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
                        .put(&bytes)
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

    let opening = {
        let mut guard = swarm.lock().unwrap_or_else(|e| e.into_inner());
        guard.add_peer(peer)
    };
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

/// Human-readable reason a peer was dropped, for a caller that wants to log it.
pub fn describe(dropped: &Dropped) -> String {
    dropped.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::digest_bytes;
    use crate::store::blobs::BlobStore;
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
        let blobs = BlobStore::new(dir.join(name));
        blobs.prepare().expect("prepares");
        blobs
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
        let digest = seeder.put(&data).expect("puts");
        assert!(!leecher.has(&digest), "the leech starts with nothing");

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
        assert!(leecher.has(&digest), "and it landed in the store");
        assert_eq!(leecher.get(&digest).expect("gets"), Some(data));
        assert!(
            leecher.verify().expect("verifies").is_empty(),
            "filed under a name its bytes actually hash to"
        );
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
            seeder.put(&data).expect("puts");
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
        let digest = seeder.put(&data).expect("puts");
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
        seeder.put(b"something else").expect("puts");
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
