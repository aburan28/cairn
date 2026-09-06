//! TCP transport and the wire framing around an encrypted channel.

use super::handshake::{
    Channel, HandshakeError, Opener, PeerId, PeerIdentity, PeerPublic, Sealer, CIPHERTEXT_BYTES,
    PUBLIC_KEY_BYTES,
};
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

const HELLO_BYTES: usize = PUBLIC_KEY_BYTES + CIPHERTEXT_BYTES;
const CONFIRM_CONTEXT: &[u8] = b"proofwork/p2p/transport/key-confirmation/v2";
const RESPONDER_CONFIRMED: &[u8] = b"proofwork responder confirmed";
const INITIATOR_CONFIRMED: &[u8] = b"proofwork initiator confirmed";
const CONFIRM_MAX_FRAME: u32 = 1024;
/// Largest frame this transport will read, unless a caller lowers it.
///
/// Generous, because the transport does not know what any subsystem sends. A
/// subsystem that *does* know should say so — see [`Connection::set_max_frame`].
pub const MAX_FRAME: u32 = 16 * 1024 * 1024;

/// How long a dial may spend waiting for the SYN to be answered.
///
/// `TcpStream::connect` has no deadline of its own, and what it does when
/// nothing answers depends on the *kind* of nothing. A host that refuses sends
/// an RST and the call returns in microseconds — which is every local test, a
/// LAN peer that is down, and the reason this was never noticed. A host whose
/// packets are **dropped** answers nothing at all, so the kernel retransmits
/// on its own schedule: ~127 s on Linux defaults, and no error until then.
///
/// Dropping rather than refusing is the normal state of a public cloud host:
/// an EC2 security group that does not admit the p2p port is a silent DROP.
/// The daemon dials each endpoint holding its node mutex, so one such address
/// froze the whole process for two minutes per tick — no accepts, no queue
/// drain, no beacons — which is indistinguishable from a node that simply does
/// not work.
pub const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// How long any single read or write on an established session may block.
///
/// Same failure, one layer up: a peer that completes a handshake and then
/// stops sending holds a `read_exact` forever, and the daemon holds its node
/// mutex for exactly as long. Per *call*, not per session, so a large frame
/// that keeps arriving is never cut off.
pub const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// How long an accepted stream has to produce its public-key-and-ciphertext hello.
///
/// Shorter than [`IO_TIMEOUT`] because this one is reachable by anybody who
/// can open a TCP connection, before any authentication has happened. A public
/// address is port-scanned within minutes of existing, and a scanner that
/// connects and sends nothing is the cheapest possible way to hold the accept
/// path — which, in the daemon (`cairn p2p`), holds the node mutex. A real peer has its
/// hello in flight before the connection completes, so this is generous for
/// every honest case.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub enum TransportError {
    Io(io::Error),
    Handshake(HandshakeError),
    /// The proxy interposed on the dial refused or misbehaved. Distinct from
    /// [`TransportError::Io`] so "the peer is down" reads differently from "the
    /// egress proxy would not carry the connection".
    Proxy(super::proxy::ProxyError),
    FrameTooLarge {
        size: u32,
    },
    FrameTruncated,
    /// The connection was a [`request_key`] and this side answered it. Not a
    /// session and not a failure: the caller should note it and move on.
    KeyServed,
    /// A key request named some other peer's id; nothing was sent.
    KeyRefused,
    /// The bytes a peer returned to [`request_key`] do not hash to the id
    /// asked for. Whoever answered is not who the beacon said, or lied.
    WrongKey,
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::Io(e) => write!(f, "transport I/O: {e}"),
            TransportError::Handshake(e) => write!(f, "handshake: {e}"),
            TransportError::Proxy(e) => write!(f, "proxy: {e}"),
            TransportError::FrameTooLarge { size } => write!(f, "frame too large: {size} bytes"),
            TransportError::FrameTruncated => f.write_str("truncated transport frame"),
            TransportError::KeyServed => f.write_str("served our transport key to a key request"),
            TransportError::KeyRefused => f.write_str("key request named another peer; refused"),
            TransportError::WrongKey => {
                f.write_str("the key returned does not hash to the id asked for")
            }
        }
    }
}

impl std::error::Error for TransportError {}
impl From<io::Error> for TransportError {
    fn from(value: io::Error) -> Self {
        TransportError::Io(value)
    }
}
impl From<HandshakeError> for TransportError {
    fn from(value: HandshakeError) -> Self {
        TransportError::Handshake(value)
    }
}
impl From<super::proxy::ProxyError> for TransportError {
    fn from(value: super::proxy::ProxyError) -> Self {
        TransportError::Proxy(value)
    }
}

/// A connected stream whose two long-term peer identities and fresh session
/// keys have both been confirmed.
pub struct Connection {
    stream: TcpStream,
    channel: Channel,
    local: PeerId,
    remote: PeerId,
    remote_authenticated: bool,
    max_frame: u32,
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection")
            .field("remote", &self.remote)
            .field("remote_authenticated", &self.remote_authenticated)
            .finish()
    }
}

impl Connection {
    pub fn remote(&self) -> PeerId {
        self.remote
    }

    pub fn local(&self) -> PeerId {
        self.local
    }

    /// Whether the remote id was authenticated by the handshake.
    ///
    /// Mutual key confirmation completes before either side receives a
    /// `Connection`, so every successfully constructed connection returns true.
    pub fn remote_authenticated(&self) -> bool {
        self.remote_authenticated
    }

    pub fn send(&mut self, plaintext: &[u8], context: &[u8]) -> Result<(), TransportError> {
        let (counter, ciphertext) = self.channel.seal(plaintext, context)?;
        let size = u32::try_from(8usize + ciphertext.len())
            .map_err(|_| TransportError::FrameTooLarge { size: u32::MAX })?;
        self.stream.write_all(&size.to_be_bytes())?;
        self.stream.write_all(&counter.to_be_bytes())?;
        self.stream.write_all(&ciphertext)?;
        self.stream.flush()?;
        Ok(())
    }

    pub fn receive(&mut self, context: &[u8]) -> Result<Vec<u8>, TransportError> {
        let mut size_bytes = [0u8; 4];
        read_exact_resilient(&mut self.stream, &mut size_bytes).map_err(|e| {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                TransportError::FrameTruncated
            } else {
                TransportError::Io(e)
            }
        })?;
        let size = u32::from_be_bytes(size_bytes);
        if !(8..=self.max_frame).contains(&size) {
            return Err(TransportError::FrameTooLarge { size });
        }
        let mut frame = vec![0u8; size as usize];
        read_exact_resilient(&mut self.stream, &mut frame).map_err(|e| {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                TransportError::FrameTruncated
            } else {
                TransportError::Io(e)
            }
        })?;
        let mut counter_bytes = [0u8; 8];
        counter_bytes.copy_from_slice(&frame[..8]);
        let counter = u64::from_be_bytes(counter_bytes);
        Ok(self.channel.open(counter, &frame[8..], context)?)
    }

    /// Lower the ceiling on an incoming frame.
    ///
    /// The default is [`MAX_FRAME`], which is what a transport that knows
    /// nothing about its payload has to allow. A subsystem with a real limit
    /// should set it, because the check happens on the **declared length,
    /// before the buffer is allocated** — a peer that says "16 MiB" gets a
    /// refusal rather than 16 MiB of this node's memory.
    ///
    /// That the peer is authenticated does not make this unnecessary. An
    /// authenticated peer is not a trusted one, which is the premise the whole
    /// crate runs on; a handshake raises the price of the attack and does not
    /// remove it.
    pub fn set_max_frame(&mut self, bytes: u32) {
        self.max_frame = bytes.min(MAX_FRAME);
    }

    /// Bound how long a read or a write may block.
    ///
    /// [`IO_TIMEOUT`] by default on every connection this module produces, so
    /// this is for a subsystem that wants a *different* bound rather than for
    /// one that wants any bound at all — a long-lived transfer, where a peer
    /// that goes quiet mid-piece must not hold a thread and its reservations,
    /// is the case that asks; see [`crate::p2p::swarm::tcp`]. Set before
    /// [`Connection::split`] so both halves inherit it.
    ///
    /// `None` restores blocking-forever behaviour and is almost never what a
    /// caller wants: the default exists because an unbounded read is how a
    /// single unreachable or silent peer stops a daemon that dials under a
    /// lock.
    pub fn set_timeouts(&self, read: Option<Duration>, write: Option<Duration>) -> io::Result<()> {
        self.stream.set_read_timeout(read)?;
        self.stream.set_write_timeout(write)
    }

    /// Split into halves that can live on different threads.
    ///
    /// The reason this exists is [`crate::p2p::swarm`]: a blob transfer needs a
    /// writer thread, so a peer that stops reading blocks its own socket rather
    /// than the state machine every other peer is waiting on. `&mut self` on
    /// both `send` and `receive` makes that impossible on one `Connection`, and
    /// wrapping it in a mutex would be worse than impossible — a reader blocked
    /// in `receive` holding the lock would starve the writer forever.
    ///
    /// Sound because the session's two directions share no state; see
    /// [`Channel::split`]. The socket is `try_clone`d, which duplicates the
    /// descriptor rather than the connection, so both halves drive the same TCP
    /// stream and dropping either leaves the other working.
    pub fn split(self) -> Result<(Sender, Receiver), TransportError> {
        let writer = self.stream.try_clone()?;
        let (sealer, opener) = self.channel.split();
        Ok((
            Sender {
                stream: writer,
                sealer,
            },
            Receiver {
                stream: self.stream,
                opener,
                remote: self.remote,
                max_frame: self.max_frame,
            },
        ))
    }
}

/// The sending half of a split [`Connection`].
#[derive(Debug)]
pub struct Sender {
    stream: TcpStream,
    sealer: Sealer,
}

impl Sender {
    /// As [`Connection::send`].
    pub fn send(&mut self, plaintext: &[u8], context: &[u8]) -> Result<(), TransportError> {
        let (counter, ciphertext) = self.sealer.seal(plaintext, context)?;
        let size = u32::try_from(8usize + ciphertext.len())
            .map_err(|_| TransportError::FrameTooLarge { size: u32::MAX })?;
        self.stream.write_all(&size.to_be_bytes())?;
        self.stream.write_all(&counter.to_be_bytes())?;
        self.stream.write_all(&ciphertext)?;
        self.stream.flush()?;
        Ok(())
    }
}

/// The receiving half of a split [`Connection`].
#[derive(Debug)]
pub struct Receiver {
    stream: TcpStream,
    opener: Opener,
    remote: PeerId,
    max_frame: u32,
}

impl Receiver {
    pub fn remote(&self) -> PeerId {
        self.remote
    }

    /// As [`Connection::receive`].
    pub fn receive(&mut self, context: &[u8]) -> Result<Vec<u8>, TransportError> {
        let mut size_bytes = [0u8; 4];
        read_exact_resilient(&mut self.stream, &mut size_bytes).map_err(|e| {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                TransportError::FrameTruncated
            } else {
                TransportError::Io(e)
            }
        })?;
        let size = u32::from_be_bytes(size_bytes);
        if !(8..=self.max_frame).contains(&size) {
            return Err(TransportError::FrameTooLarge { size });
        }
        let mut frame = vec![0u8; size as usize];
        read_exact_resilient(&mut self.stream, &mut frame).map_err(|e| {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                TransportError::FrameTruncated
            } else {
                TransportError::Io(e)
            }
        })?;
        let mut counter_bytes = [0u8; 8];
        counter_bytes.copy_from_slice(&frame[..8]);
        let counter = u64::from_be_bytes(counter_bytes);
        Ok(self.opener.open(counter, &frame[8..], context)?)
    }
}

/// Bind a listener. The caller controls the accept loop and can rate-limit
/// before invoking the expensive McEliece decapsulation in `accept`.
pub fn listen(addr: SocketAddr) -> Result<TcpListener, TransportError> {
    Ok(TcpListener::bind(addr)?)
}

/// Read one exact transport field while tolerating a spurious timed-read wake.
///
/// On macOS/BSD a blocking `TcpStream` with `SO_RCVTIMEO` can occasionally
/// return `WouldBlock` immediately when another thread owns a cloned write half.
/// Treating that single wake as a disconnect made every real swarm transfer
/// lose its peer before the first piece. Retry only within the configured
/// timeout, measured from the start of the field. Progress does not reset the
/// deadline: otherwise a peer that drips one byte per timeout can hold the
/// daemon's session lock indefinitely.
fn read_exact_resilient(stream: &mut TcpStream, buffer: &mut [u8]) -> io::Result<()> {
    let timeout = stream.read_timeout()?;
    let mut offset = 0usize;
    let started = Instant::now();
    while offset < buffer.len() {
        if timeout.is_some_and(|bound| started.elapsed() >= bound) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "transport field exceeded its absolute read deadline",
            ));
        }
        match stream.read(&mut buffer[offset..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "transport field ended early",
                ))
            }
            Ok(read) => {
                offset += read;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) && timeout.is_some_and(|bound| started.elapsed() < bound) =>
            {
                // Avoid a busy loop on a host that repeatedly reports the
                // spurious readiness state. One millisecond is negligible
                // beside even the handshake's ten-second timeout.
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Dial a known endpoint and complete the initiator side of the handshake.
///
/// The direct path. [`connect_through`] is the same with a proxy interposed;
/// this delegates to it so there is one handshake body, not two.
pub fn connect(
    endpoint: &PeerPublic,
    addr: SocketAddr,
    local: &PeerIdentity,
) -> Result<Connection, TransportError> {
    connect_through(&super::proxy::Proxy::Direct, endpoint, addr, local)
}

/// Dial a known endpoint through a proxy, completing the initiator handshake.
///
/// The only difference from [`connect`] is *how the TCP stream is obtained* —
/// straight, or through a SOCKS5 proxy that puts the peer's address on the far
/// side of a firewall. Everything after the connect is identical, because the
/// McEliece handshake runs end to end over whatever stream it is handed and a
/// proxy is just another untrusted hop: it sees ciphertext and the peer-id
/// fingerprint, and cannot forge an identity whose hash it does not hold. See
/// [`super::proxy`] for what this defends and what it does not.
pub fn connect_through(
    proxy: &super::proxy::Proxy,
    endpoint: &PeerPublic,
    addr: SocketAddr,
    local: &PeerIdentity,
) -> Result<Connection, TransportError> {
    let mut stream = proxy.dial(addr, DIAL_TIMEOUT)?;
    // Before the write, not after: a peer that
    // accepted the connection and then stalled would otherwise hold this
    // thread in `write_all` with the caller's lock still taken.
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;
    let (ciphertext, first) = endpoint.initiate(local.id());
    let mut hello = vec![0u8; HELLO_BYTES];
    hello[..PUBLIC_KEY_BYTES].copy_from_slice(local.public_key());
    hello[PUBLIC_KEY_BYTES..].copy_from_slice(&ciphertext);
    stream.write_all(&hello)?;
    stream.flush()?;

    let mut reverse = [0u8; CIPHERTEXT_BYTES];
    read_exact_resilient(&mut stream, &mut reverse)?;
    let second = local.accept(endpoint.id(), &reverse)?;
    let mut connection = Connection {
        stream,
        channel: first.mix(second),
        local: local.id(),
        remote: endpoint.id(),
        remote_authenticated: true,
        max_frame: CONFIRM_MAX_FRAME,
    };
    if connection.receive(CONFIRM_CONTEXT)? != RESPONDER_CONFIRMED {
        return Err(HandshakeError::NotAuthentic.into());
    }
    connection.send(INITIATOR_CONFIRMED, CONFIRM_CONTEXT)?;
    connection.max_frame = MAX_FRAME;
    connection.set_timeouts(Some(IO_TIMEOUT), Some(IO_TIMEOUT))?;
    Ok(connection)
}

/// Prefix of a key request: a hello-sized frame that asks for the responder's
/// public key instead of opening a session.
///
/// # Why a session cannot be the only way to learn a key
///
/// The initiator's hello carries *its* public key in the clear, so a responder
/// always learns who is calling. The reverse is the problem: to encapsulate
/// to a peer at all, the initiator must already hold that peer's 261 KiB key,
/// and until now the only source was [`super::dht::DhtMessage::GetKey`] over
/// an existing session with some peer that had it. Two fresh nodes on a LAN
/// heard each other's beacons every tick and could never connect, because a
/// beacon carries an id and neither side had a session to ask through. A
/// bootstrap file breaks that circle by shipping the key by hand; this
/// message breaks it on the wire.
///
/// # What it costs and what it exposes
///
/// The key is public by definition -- it is the thing bootstrap files hand
/// out -- so serving it authenticates nobody and reveals nothing. The
/// responder does no decapsulation for a key request, so it is *cheaper* than
/// a hello, and the answer is the same size as the request (both are one
/// hello), so there is no amplification, and TCP means no spoofed source. The
/// requester checks `sha256(bytes) == id`, so a wrong or hostile answer costs
/// one failed dial and never a wrong peer -- the property every hint source
/// in this stack already relies on.
///
/// Same length as a hello so `accept` reads one fixed frame and then decides,
/// rather than growing a length field on an unauthenticated path. A genuine
/// McEliece key beginning with these eight bytes is a probability of 2^-64 and
/// would only make its owner's hello read as a key request, which serves
/// them a public key and drops the connection: an inconvenience to that one
/// peer, not a hole.
pub const KEY_REQUEST_MAGIC: [u8; 8] = *b"PWKEYRQ1";

/// Ask the node at `addr` for its transport public key, and check that it
/// hashes to `expected` before returning it.
pub fn request_key(addr: SocketAddr, expected: PeerId) -> Result<PeerPublic, TransportError> {
    let mut stream = TcpStream::connect_timeout(&addr, DIAL_TIMEOUT)?;
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;
    let mut request = vec![0u8; HELLO_BYTES];
    request[..KEY_REQUEST_MAGIC.len()].copy_from_slice(&KEY_REQUEST_MAGIC);
    request[KEY_REQUEST_MAGIC.len()..KEY_REQUEST_MAGIC.len() + 32].copy_from_slice(&expected);
    stream.write_all(&request)?;
    stream.flush()?;
    let mut key = vec![0u8; PUBLIC_KEY_BYTES];
    read_exact_resilient(&mut stream, &mut key).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            TransportError::KeyRefused
        } else {
            TransportError::Io(e)
        }
    })?;
    let public = PeerPublic::from_bytes(&key)?;
    if public.id() != expected {
        return Err(TransportError::WrongKey);
    }
    Ok(public)
}

/// An inbound connection whose first frame has been read but not yet acted
/// on: either a hello, or a key request.
///
/// Split from [`accept`] so a caller can find out *which* before it commits
/// anything expensive -- in the daemon, the node lock. Answering a key
/// request needs no lock, and taking one first is a deadlock: two fresh nodes
/// that discover each other in the same tick each hold their own lock while
/// waiting for the other's key, until a handshake timeout breaks it.
pub struct Inbound {
    stream: TcpStream,
    hello: Vec<u8>,
}

impl Inbound {
    /// Read the first frame, under the handshake timeout.
    pub fn read(mut stream: TcpStream) -> Result<Inbound, TransportError> {
        stream.set_nonblocking(false)?;
        let mut hello = vec![0u8; HELLO_BYTES];
        // The tight one first, then the session default once a hello has
        // actually arrived: an unauthenticated stranger gets
        // `HANDSHAKE_TIMEOUT` to say something, and a peer that has said
        // something gets `IO_TIMEOUT` per call for the rest of the session.
        stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
        stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;
        read_exact_resilient(&mut stream, &mut hello).map_err(|e| {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                TransportError::FrameTruncated
            } else {
                TransportError::Io(e)
            }
        })?;
        Ok(Inbound { stream, hello })
    }

    /// Whether the frame is a key request rather than a hello.
    pub fn is_key_request(&self) -> bool {
        self.hello[..KEY_REQUEST_MAGIC.len()] == KEY_REQUEST_MAGIC
    }

    /// Answer a key request: `Ok(true)` when it named `local` and the key was
    /// sent, `Ok(false)` when it named someone else and nothing was.
    pub fn answer_key_request(mut self, local: &PeerIdentity) -> Result<bool, TransportError> {
        let asked = &self.hello[KEY_REQUEST_MAGIC.len()..KEY_REQUEST_MAGIC.len() + 32];
        if asked != local.id() {
            return Ok(false);
        }
        self.stream.write_all(local.public_key())?;
        self.stream.flush()?;
        Ok(true)
    }

    /// Finish the responder side of the handshake for a hello.
    pub fn complete(self, local: &PeerIdentity) -> Result<Connection, TransportError> {
        let Inbound { mut stream, hello } = self;
        if hello[..KEY_REQUEST_MAGIC.len()] == KEY_REQUEST_MAGIC {
            return Err(TransportError::KeyRefused);
        }
        let remote_public = PeerPublic::from_bytes(&hello[..PUBLIC_KEY_BYTES])?;
        let remote = remote_public.id();
        let first = local.accept(remote, &hello[PUBLIC_KEY_BYTES..])?;
        let (reverse, second) = remote_public.initiate(local.id());
        stream.write_all(&reverse)?;
        stream.flush()?;
        let mut connection = Connection {
            stream,
            channel: first.mix(second),
            local: local.id(),
            remote,
            remote_authenticated: true,
            max_frame: CONFIRM_MAX_FRAME,
        };
        connection.send(RESPONDER_CONFIRMED, CONFIRM_CONTEXT)?;
        if connection.receive(CONFIRM_CONTEXT)? != INITIATOR_CONFIRMED {
            return Err(HandshakeError::NotAuthentic.into());
        }
        connection.max_frame = MAX_FRAME;
        connection.set_timeouts(Some(IO_TIMEOUT), Some(IO_TIMEOUT))?;
        Ok(connection)
    }
}

/// Accept an inbound connection only after authenticating the initiator's
/// public key and completing encrypted key confirmation in both directions.
///
/// A frame that begins with [`KEY_REQUEST_MAGIC`] is not a hello: if it names
/// this node's id, the public key is written back and the connection is done
/// (`Err(KeyServed)`); if it names someone else, nothing is written
/// (`Err(KeyRefused)`). Both are outcomes for the caller to log, not sessions.
/// A caller that must not hold a lock across a key request reads an
/// [`Inbound`] first and decides for itself.
pub fn accept(stream: TcpStream, local: &PeerIdentity) -> Result<Connection, TransportError> {
    let inbound = Inbound::read(stream)?;
    if inbound.is_key_request() {
        return Err(if inbound.answer_key_request(local)? {
            TransportError::KeyServed
        } else {
            TransportError::KeyRefused
        });
    }
    inbound.complete(local)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    /// A connected pair over loopback.
    fn pair() -> (Connection, Connection) {
        let responder = Arc::new(PeerIdentity::generate());
        let public = responder.to_public();
        let listener = listen("127.0.0.1:0".parse().expect("addr")).expect("binds");
        let addr = listener.local_addr().expect("addr");
        let accepted = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            accept(stream, &responder).expect("handshake")
        });
        let initiator = PeerIdentity::generate();
        let dialed = connect(&public, addr, &initiator).expect("connects");
        (dialed, accepted.join().expect("accept thread"))
    }

    /// Both ends of a completed handshake carry a session timeout.
    ///
    /// Checked on the socket rather than through a hang, because the honest
    /// way to observe the absence of a timeout is to wait out a read that
    /// never returns, and a test that waits `IO_TIMEOUT` to prove
    /// `IO_TIMEOUT` is a slow test that proves it twice.
    #[test]
    fn a_session_never_starts_out_able_to_block_forever() {
        let (dialed, accepted) = pair();
        for (side, connection) in [("initiator", &dialed), ("responder", &accepted)] {
            assert_eq!(
                connection.stream.read_timeout().expect("read timeout"),
                Some(IO_TIMEOUT),
                "{side} would block forever on a peer that goes quiet"
            );
            assert_eq!(
                connection.stream.write_timeout().expect("write timeout"),
                Some(IO_TIMEOUT),
                "{side} would block forever on a peer that stops reading"
            );
        }
    }

    /// The circle a beacon could not close: a key learned from nothing but an
    /// id and an address, checked against the id, and usable for a real dial.
    #[test]
    fn a_key_request_returns_the_responders_key_and_opens_no_session() {
        let responder = Arc::new(PeerIdentity::generate());
        let expected = responder.to_public();
        let listener = listen("127.0.0.1:0".parse().expect("addr")).expect("binds");
        let addr = listener.local_addr().expect("addr");
        let served = {
            let responder = Arc::clone(&responder);
            thread::spawn(move || {
                let (stream, _) = listener.accept().expect("accepts");
                accept(stream, &responder)
            })
        };
        let key = request_key(addr, expected.id()).expect("the key is served");
        assert_eq!(key.id(), expected.id());
        assert!(
            matches!(
                served.join().expect("accept thread"),
                Err(TransportError::KeyServed)
            ),
            "a key request must end the connection without a session"
        );
        // And the key really dials: the whole point of fetching it.
        let listener = listen("127.0.0.1:0".parse().expect("addr")).expect("binds");
        let addr = listener.local_addr().expect("addr");
        let accepted = {
            let responder = Arc::clone(&responder);
            thread::spawn(move || {
                let (stream, _) = listener.accept().expect("accepts");
                accept(stream, &responder).expect("handshake")
            })
        };
        let initiator = PeerIdentity::generate();
        let dialed = connect(&key, addr, &initiator).expect("connects with the fetched key");
        assert!(dialed.remote_authenticated());
        accepted.join().expect("accept thread");
    }

    /// A request for somebody else's key gets nothing: the responder is not a
    /// directory, and a wrong id is a wrong beacon.
    #[test]
    fn a_key_request_naming_another_peer_is_refused() {
        let responder = PeerIdentity::generate();
        let listener = listen("127.0.0.1:0".parse().expect("addr")).expect("binds");
        let addr = listener.local_addr().expect("addr");
        let served = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            accept(stream, &responder)
        });
        let other = PeerIdentity::generate().id();
        assert!(matches!(
            request_key(addr, other),
            Err(TransportError::KeyRefused)
        ));
        assert!(matches!(
            served.join().expect("accept thread"),
            Err(TransportError::KeyRefused)
        ));
    }

    #[test]
    fn both_transport_identities_are_authenticated() {
        let (dialed, accepted) = pair();
        assert!(dialed.remote_authenticated());
        assert!(accepted.remote_authenticated());
    }

    /// A stranger that connects and says nothing must not hold the accept path.
    ///
    /// This is what a public address costs: an EC2 instance is port-scanned
    /// within minutes of getting one, and the daemon (`cairn p2p`) runs `accept` with
    /// the node mutex held. An unbounded `read_exact` here is a seed that
    /// wedges on the first scan and never talks to anybody again.
    #[test]
    fn a_silent_stranger_cannot_hold_the_accept_path() {
        let responder = PeerIdentity::generate();
        let listener = listen("127.0.0.1:0".parse().expect("addr")).expect("binds");
        let addr = listener.local_addr().expect("addr");
        // Connected from this thread and kept alive to the end: the connection
        // completes through the listener's backlog without anybody accepting
        // it, and a socket that *closed* would give `accept` an EOF and prove
        // nothing.
        let scanner = TcpStream::connect(addr).expect("connects");
        let (stream, _) = listener.accept().expect("accepts");
        let started = std::time::Instant::now();
        let outcome = accept(stream, &responder);
        assert!(outcome.is_err(), "a mute stranger completed a handshake");
        assert!(
            started.elapsed() < HANDSHAKE_TIMEOUT * 2,
            "accept took {:?}, so the handshake read is unbounded",
            started.elapsed()
        );
        drop(scanner);
    }

    /// A dial to an address that drops packets gives up on a schedule this
    /// crate chose, not on the kernel's SYN-retransmit schedule.
    ///
    /// `192.0.2.0/24` is TEST-NET-1 and is not routed. Whether it blackholes
    /// or is rejected outright depends on the host, so the assertion is the
    /// one that matters either way: bounded, and an error rather than a
    /// connection.
    #[test]
    fn a_dial_into_a_blackhole_gives_up() {
        let responder = PeerIdentity::generate().to_public();
        let initiator = PeerIdentity::generate();
        let started = std::time::Instant::now();
        let outcome = connect(&responder, "192.0.2.1:9".parse().expect("addr"), &initiator);
        assert!(outcome.is_err(), "connected to an unroutable address");
        assert!(
            started.elapsed() < DIAL_TIMEOUT * 2,
            "dial took {:?}, so it is on the kernel's schedule",
            started.elapsed()
        );
    }

    #[test]
    fn a_lowered_ceiling_refuses_a_frame_the_default_would_allow() {
        // The check is on the *declared* length and happens before the buffer
        // is allocated, which is the whole reason a subsystem with a real limit
        // should set one: a peer claiming a size gets a refusal rather than
        // that many bytes of this node's memory.
        let (mut sender, mut receiver) = pair();
        receiver.set_max_frame(4096);

        // Comfortably under the transport's own ceiling, comfortably over the
        // one this receiver was given.
        let payload = vec![7u8; 64 * 1024];
        let sent = thread::spawn(move || sender.send(&payload, b"ctx"));

        match receiver.receive(b"ctx") {
            Err(TransportError::FrameTooLarge { size }) => {
                assert!(size > 4096, "refused a frame that was within the limit");
            }
            other => panic!("expected FrameTooLarge, got {other:?}"),
        }
        let _ = sent.join();
    }

    #[test]
    fn a_frame_within_the_lowered_ceiling_still_arrives() {
        // The other half. A limit that refused everything would pass the test
        // above while breaking the transport.
        let (mut sender, mut receiver) = pair();
        receiver.set_max_frame(4096);
        let payload = vec![3u8; 1024];
        let expected = payload.clone();
        let sent = thread::spawn(move || sender.send(&payload, b"ctx"));
        assert_eq!(receiver.receive(b"ctx").expect("opens"), expected);
        let _ = sent.join();
    }

    #[test]
    fn the_ceiling_can_be_lowered_and_never_raised() {
        // `set_max_frame` clamps to `MAX_FRAME`. A caller that could raise it
        // would be able to undo the transport's own bound, which is the one
        // limit that applies when a subsystem has said nothing.
        let (mut connection, _other) = pair();
        connection.set_max_frame(u32::MAX);
        assert_eq!(connection.max_frame, MAX_FRAME);
        connection.set_max_frame(1024);
        assert_eq!(connection.max_frame, 1024);
    }

    #[test]
    fn a_split_receiver_inherits_the_ceiling() {
        // The split happens after a subsystem has configured the connection, so
        // a ceiling that did not survive it would be silently the default again
        // on exactly the long-lived transfers that wanted it lowered.
        let (mut connection, _other) = pair();
        connection.set_max_frame(2048);
        let (_sender, receiver) = connection.split().expect("splits");
        assert_eq!(receiver.max_frame, 2048);
    }
}
