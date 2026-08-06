//! TCP transport and the wire framing around an encrypted channel.

use super::handshake::{Channel, HandshakeError, Opener, PeerId, PeerIdentity, PeerPublic, Sealer};
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

const CIPHERTEXT_BYTES: usize = 96;
const HANDSHAKE_BYTES: usize = 32 + CIPHERTEXT_BYTES;
/// Largest frame this transport will read, unless a caller lowers it.
///
/// Generous, because the transport does not know what any subsystem sends. A
/// subsystem that *does* know should say so — see [`Connection::set_max_frame`].
pub const MAX_FRAME: u32 = 16 * 1024 * 1024;

#[derive(Debug)]
pub enum TransportError {
    Io(io::Error),
    Handshake(HandshakeError),
    FrameTooLarge { size: u32 },
    FrameTruncated,
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::Io(e) => write!(f, "transport I/O: {e}"),
            TransportError::Handshake(e) => write!(f, "handshake: {e}"),
            TransportError::FrameTooLarge { size } => write!(f, "frame too large: {size} bytes"),
            TransportError::FrameTruncated => f.write_str("truncated transport frame"),
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

/// A connected, authenticated (responder) or expected (initiator) stream.
pub struct Connection {
    stream: TcpStream,
    channel: Channel,
    local: PeerId,
    remote: PeerId,
    max_frame: u32,
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection")
            .field("remote", &self.remote)
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
        self.stream.read_exact(&mut size_bytes).map_err(|e| {
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
        self.stream.read_exact(&mut frame).map_err(|e| {
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
    /// Off by default, which is right for the daemon: its sessions are short,
    /// request-response, and driven by a loop that already decides when to give
    /// up. It is *not* right for a long-lived transfer, where a peer that goes
    /// quiet mid-piece would otherwise hold a thread forever and never return
    /// its reservations — see [`crate::swarm::tcp`], whose liveness story this
    /// is. Set before [`Connection::split`] so both halves inherit it.
    pub fn set_timeouts(&self, read: Option<Duration>, write: Option<Duration>) -> io::Result<()> {
        self.stream.set_read_timeout(read)?;
        self.stream.set_write_timeout(write)
    }

    /// Split into halves that can live on different threads.
    ///
    /// The reason this exists is [`crate::swarm`]: a blob transfer needs a
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
        self.stream.read_exact(&mut size_bytes).map_err(|e| {
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
        self.stream.read_exact(&mut frame).map_err(|e| {
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

/// Dial a known endpoint and complete the initiator side of the handshake.
pub fn connect(
    endpoint: &PeerPublic,
    addr: SocketAddr,
    local: &PeerIdentity,
) -> Result<Connection, TransportError> {
    let mut stream = TcpStream::connect(addr)?;
    let (ciphertext, channel) = endpoint.initiate(local.id());
    let mut hello = [0u8; HANDSHAKE_BYTES];
    hello[..32].copy_from_slice(&local.id());
    hello[32..].copy_from_slice(&ciphertext);
    stream.write_all(&hello)?;
    stream.flush()?;
    Ok(Connection {
        stream,
        channel,
        local: local.id(),
        remote: endpoint.id(),
        max_frame: MAX_FRAME,
    })
}

/// Accept an inbound connection. The claimed initiator id is returned as the
/// remote id; callers that need initiator authentication must bind it to a
/// previously discovered key or add a signature at the session layer.
pub fn accept(mut stream: TcpStream, local: &PeerIdentity) -> Result<Connection, TransportError> {
    let mut hello = [0u8; HANDSHAKE_BYTES];
    stream.read_exact(&mut hello).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            TransportError::FrameTruncated
        } else {
            TransportError::Io(e)
        }
    })?;
    let remote: PeerId = hello[..32].try_into().expect("fixed handshake header");
    let channel = local.accept(remote, &hello[32..])?;
    Ok(Connection {
        stream,
        channel,
        local: local.id(),
        remote,
        max_frame: MAX_FRAME,
    })
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
