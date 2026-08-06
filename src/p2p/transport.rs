//! TCP transport and the wire framing around an encrypted channel.

use super::handshake::{Channel, HandshakeError, Opener, PeerId, PeerIdentity, PeerPublic, Sealer};
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};

const CIPHERTEXT_BYTES: usize = 96;
const HANDSHAKE_BYTES: usize = 32 + CIPHERTEXT_BYTES;
const MAX_FRAME: u32 = 16 * 1024 * 1024;

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
        if !(8..=MAX_FRAME).contains(&size) {
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
        if !(8..=MAX_FRAME).contains(&size) {
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
    })
}
