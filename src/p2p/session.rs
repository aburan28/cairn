//! Message driver for one encrypted connection.

use super::sync::{Message, Peer, SyncError};
use super::transport::{Connection, TransportError};
use std::fmt;

const CONTEXT: &[u8] = b"proofwork/p2p/sync/v1";

#[derive(Debug)]
pub enum SessionError {
    Transport(TransportError),
    Sync(SyncError),
    Protocol(String),
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionError::Transport(e) => write!(f, "{e}"),
            SessionError::Sync(e) => write!(f, "sync: {e}"),
            SessionError::Protocol(e) => write!(f, "protocol: {e}"),
        }
    }
}
impl std::error::Error for SessionError {}
impl From<TransportError> for SessionError {
    fn from(e: TransportError) -> Self {
        Self::Transport(e)
    }
}
impl From<SyncError> for SessionError {
    fn from(e: SyncError) -> Self {
        Self::Sync(e)
    }
}

fn send(connection: &mut Connection, message: Message) -> Result<(), SessionError> {
    connection
        .send(&message.encode(), CONTEXT)
        .map_err(Into::into)
}

fn receive(connection: &mut Connection) -> Result<Message, SessionError> {
    Message::decode(&connection.receive(CONTEXT)?).map_err(Into::into)
}

fn expect<T>(
    message: Message,
    kind: &str,
    take: impl FnOnce(Message) -> Option<T>,
) -> Result<T, SessionError> {
    take(message).ok_or_else(|| SessionError::Protocol(format!("expected {kind}")))
}

/// Run one complete, symmetric anti-entropy exchange.
pub fn reconcile<F>(
    connection: &mut Connection,
    peer: &mut Peer,
    mut verify: F,
) -> Result<(), SessionError>
where
    F: FnMut(&super::sync::Record) -> Result<(), SyncError>,
{
    send(
        connection,
        Message::Hello {
            peer: super::handshake::peer_id_hex(&connection.local()),
            records: u64::try_from(peer.len())
                .map_err(|_| SessionError::Protocol("record count exceeds u64".into()))?,
        },
    )?;
    send(connection, Message::Inventory(Box::new(peer.inventory())))?;
    let hello = expect(receive(connection)?, "hello", |m| {
        if matches!(m, Message::Hello { .. }) {
            Some(m)
        } else {
            None
        }
    })?;
    let _remote_inventory = expect(receive(connection)?, "inventory", |m| {
        if let Message::Inventory(i) = m {
            Some(i)
        } else {
            None
        }
    })?;
    let remote_inventory = match hello {
        Message::Hello { .. } => _remote_inventory,
        _ => unreachable!(),
    };
    let differing = peer.inventory().differing(&remote_inventory);
    let mut want = Vec::new();
    for bucket in differing {
        send(
            connection,
            Message::BucketIds {
                bucket,
                ids: peer.bucket_ids(bucket),
            },
        )?;
        let ids = expect(receive(connection)?, "bucket_ids", |m| {
            if let Message::BucketIds { bucket: b, ids } = m {
                (b == bucket).then_some(ids)
            } else {
                None
            }
        })?;
        want.extend(peer.want_from(&ids)?);
    }
    send(connection, Message::Want { ids: want })?;
    let remote_want = expect(receive(connection)?, "want", |m| {
        if let Message::Want { ids } = m {
            Some(ids)
        } else {
            None
        }
    })?;
    send(
        connection,
        Message::Records {
            records: peer.serve(&remote_want)?,
        },
    )?;
    let incoming = expect(receive(connection)?, "records", |m| {
        if let Message::Records { records } = m {
            Some(records)
        } else {
            None
        }
    })?;
    let report = peer.ingest(incoming, &mut verify);
    if !report.is_clean() {
        return Err(SessionError::Sync(
            report.refused.into_iter().next().map(|(_, e)| e).unwrap_or(
                SyncError::MalformedMessage {
                    detail: "record refused".into(),
                },
            ),
        ));
    }
    send(connection, Message::Done)?;
    expect(receive(connection)?, "done", |m| {
        matches!(m, Message::Done).then_some(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::Value;
    use crate::p2p::handshake::PeerIdentity;
    use crate::p2p::sync::Record;
    use crate::p2p::transport::{accept, connect, listen};
    use std::net::SocketAddr;
    use std::thread;

    fn claim(n: i128) -> Record {
        Record::new("claim", Value::object([("n", Value::Int(n))]))
    }

    #[test]
    fn encrypted_tcp_session_converges() {
        let alice = PeerIdentity::generate();
        let bob = PeerIdentity::generate();
        let bob_public = bob.to_public();
        let listener = listen("127.0.0.1:0".parse::<SocketAddr>().unwrap()).unwrap();
        let addr = listener.local_addr().unwrap();
        let bob_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut connection = accept(stream, &bob).unwrap();
            let mut peer = Peer::new();
            peer.insert(claim(2)).unwrap();
            reconcile(&mut connection, &mut peer, |_| Ok::<(), SyncError>(())).unwrap();
            peer.len()
        });

        let mut connection = connect(&bob_public, addr, &alice).unwrap();
        let mut peer = Peer::new();
        peer.insert(claim(1)).unwrap();
        reconcile(&mut connection, &mut peer, |_| Ok::<(), SyncError>(())).unwrap();
        assert_eq!(peer.len(), 2);
        assert_eq!(bob_thread.join().unwrap(), 2);
    }
}
