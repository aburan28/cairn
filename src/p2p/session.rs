//! Message driver for one encrypted connection.
//!
//! Five families run over the same session and never share a frame. Records use
//! [`RECORD_CONTEXT`], populations use [`super::pop::CONTEXT`], verifier code
//! uses [`super::code::CONTEXT`], provider lookup uses [`super::dht::CONTEXT`],
//! peer hints use [`super::peers::CONTEXT`], and the AEAD binds the context
//! into the tag — so a frame sealed for one family cannot be opened as another
//! even by a peer that wants to. See [`super::pop`] and [`super::code`] for why
//! that separation is a security boundary rather than housekeeping.
//!
//! The order on one connection is records, then code, then the DHT, then peer
//! hints, then populations, and it is not arbitrary — see [`reconcile_code`]
//! for the first boundary and [`exchange_dht`] for the third.

use super::code::{self, CodeError, CodeLimits, CodeMessage, CodeReport};
use super::dht::{
    DhtError, DhtMessage, Directory, NodeId, MAX_ASK_ADDRESSES, MAX_KEYS_PER_MESSAGE,
};
use super::peers::{self, PeerHintLimits, PeersError, PeersMessage, PeersReport};
use super::pop::{self, PopError, PopLimits, PopMessage, PopReport};
use super::sync::{Message, Peer, SyncError};
use super::transport::{Connection, TransportError};
use crate::blobs::BlobStore;
use crate::gossip::{Candidate, Population};
use std::collections::BTreeSet;
use std::fmt;

/// AEAD context for record frames.
pub const RECORD_CONTEXT: &[u8] = b"proofwork/p2p/sync/v1";

// -- protocol tracing --------------------------------------------------------
//
// Every p2p protocol message, both directions, at `debug`. This is the one
// place all four families pass through, so it is the one place that can make
// that claim -- and each `describe_*` below is an **exhaustive** match on
// purpose: adding a message to any of the four enums stops compiling until
// somebody says how it logs, so "all the messages" stays true rather than
// being true on the day it was written.
//
// Counts and sizes, not contents. A record sync moves whole claims and a code
// reply moves blobs; putting those in a log line would produce megabytes per
// round and, for the population family, dump other people's candidate
// artifacts into an operator's terminal. What a reader of these lines actually
// needs is shape and direction -- which peer, which way, how much -- and the
// ledger itself is where the contents already are.

/// Which way a frame went, for one consistent arrow in the output.
#[derive(Clone, Copy)]
enum Dir {
    Send,
    Recv,
}

impl fmt::Display for Dir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Dir::Send => "->",
            Dir::Recv => "<-",
        })
    }
}

fn describe_record(message: &Message) -> String {
    match message {
        Message::Hello { peer, records } => format!("Hello peer={peer} records={records}"),
        // `total`, not a bucket count: the bucket count is the constant 256 on
        // every inventory ever sent, so it distinguishes nothing.
        Message::Inventory(inventory) => format!("Inventory records={}", inventory.total()),
        Message::BucketIds { bucket, ids } => {
            format!("BucketIds bucket={bucket} ids={}", ids.len())
        }
        Message::Want { ids } => format!("Want ids={}", ids.len()),
        Message::Records { records } => format!("Records n={}", records.len()),
        Message::Done => "Done".to_string(),
    }
}

fn describe_code(message: &CodeMessage) -> String {
    match message {
        CodeMessage::Want { addresses } => format!("code.Want addresses={}", addresses.len()),
        CodeMessage::Blobs { blobs } => format!(
            "code.Blobs n={} bytes={}",
            blobs.len(),
            blobs.iter().map(Vec::len).sum::<usize>()
        ),
        CodeMessage::Done => "code.Done".to_string(),
    }
}

fn describe_pop(message: &PopMessage) -> String {
    match message {
        PopMessage::Digest { digest, ids } => format!(
            "pop.Digest digest={} ids={}",
            crate::canonical::short(digest),
            ids.len()
        ),
        PopMessage::Want { ids } => format!("pop.Want ids={}", ids.len()),
        PopMessage::Records { candidates } => format!("pop.Records n={}", candidates.len()),
        PopMessage::Done => "pop.Done".to_string(),
    }
}

fn describe_peers(message: &PeersMessage) -> String {
    match message {
        PeersMessage::Digest { digest, ids } => format!(
            "peers.Digest digest={} ids={}",
            crate::canonical::short(digest),
            ids.len()
        ),
        PeersMessage::Want { ids } => format!("peers.Want ids={}", ids.len()),
        PeersMessage::Records { records } => format!("peers.Records n={}", records.len()),
    }
}

fn describe_dht(message: &DhtMessage) -> String {
    match message {
        // `NodeId`'s Display is already truncated to 16 hex characters.
        DhtMessage::FindNode { target } => format!("dht.FindNode target={target}"),
        DhtMessage::Nodes { contacts } => format!("dht.Nodes contacts={}", contacts.len()),
        DhtMessage::GetProviders { addresses } => {
            format!("dht.GetProviders addresses={}", addresses.len())
        }
        DhtMessage::Providers { answers } => format!("dht.Providers answers={}", answers.len()),
        DhtMessage::GetKey { peers } => format!("dht.GetKey peers={}", peers.len()),
        DhtMessage::Keys { keys } => format!("dht.Keys keys={}", keys.len()),
        DhtMessage::Ask { addresses } => format!("dht.Ask addresses={}", addresses.len()),
        DhtMessage::Tell { addresses } => format!("dht.Tell addresses={}", addresses.len()),
    }
}

/// Send a DHT message, logging it. The DHT round sends inline rather than
/// through one helper -- it is a fixed six-step handshake, not a loop -- so
/// this exists to keep those six sites from each needing their own trace call.
fn send_dht(connection: &mut Connection, message: DhtMessage) -> Result<(), SessionError> {
    trace(connection, Dir::Send, describe_dht(&message));
    connection
        .send(&message.encode(), super::dht::CONTEXT)
        .map_err(Into::into)
}

fn receive_dht(connection: &mut Connection) -> Result<DhtMessage, SessionError> {
    let message = DhtMessage::decode(&connection.receive(super::dht::CONTEXT)?)?;
    trace(connection, Dir::Recv, describe_dht(&message));
    Ok(message)
}

/// One protocol line. The transport authenticates either direction before a
/// connection reaches this function; the trace keeps that fact explicit.
fn trace(connection: &Connection, dir: Dir, described: String) {
    log::debug!(
        target: "proofwork::p2p",
        "{} auth={} {dir} {described}",
        crate::p2p::discovery::peer_id_string(&connection.remote()),
        connection.remote_authenticated()
    );
}

#[derive(Debug)]
pub enum SessionError {
    Transport(TransportError),
    Sync(SyncError),
    Pop(PopError),
    Code(CodeError),
    Dht(DhtError),
    Peers(PeersError),
    Protocol(String),
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionError::Transport(e) => write!(f, "{e}"),
            SessionError::Sync(e) => write!(f, "sync: {e}"),
            SessionError::Pop(e) => write!(f, "population: {e}"),
            SessionError::Code(e) => write!(f, "verifier code: {e}"),
            SessionError::Dht(e) => write!(f, "dht: {e}"),
            SessionError::Peers(e) => write!(f, "peer hints: {e}"),
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
impl From<PopError> for SessionError {
    fn from(e: PopError) -> Self {
        Self::Pop(e)
    }
}
impl From<CodeError> for SessionError {
    fn from(e: CodeError) -> Self {
        Self::Code(e)
    }
}
impl From<DhtError> for SessionError {
    fn from(e: DhtError) -> Self {
        Self::Dht(e)
    }
}
impl From<PeersError> for SessionError {
    fn from(e: PeersError) -> Self {
        Self::Peers(e)
    }
}

fn send(connection: &mut Connection, message: Message) -> Result<(), SessionError> {
    trace(connection, Dir::Send, describe_record(&message));
    connection
        .send(&message.encode(), RECORD_CONTEXT)
        .map_err(Into::into)
}

fn receive(connection: &mut Connection) -> Result<Message, SessionError> {
    let message = Message::decode(&connection.receive(RECORD_CONTEXT)?)?;
    trace(connection, Dir::Recv, describe_record(&message));
    Ok(message)
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

fn send_code(connection: &mut Connection, message: CodeMessage) -> Result<(), SessionError> {
    trace(connection, Dir::Send, describe_code(&message));
    connection
        .send(&message.encode(), code::CONTEXT)
        .map_err(Into::into)
}

fn receive_code(
    connection: &mut Connection,
    limits: CodeLimits,
) -> Result<CodeMessage, SessionError> {
    let message = CodeMessage::decode(&connection.receive(code::CONTEXT)?, limits)?;
    trace(connection, Dir::Recv, describe_code(&message));
    Ok(message)
}

/// Run one complete, symmetric verifier-code exchange.
///
/// # Why this runs between the record round and the population round
///
/// Not because of anything about populations, but because of what happens on
/// *either* side of it:
///
/// - **after records.** The want set is derived from the log's objectives, so it
///   cannot include an objective this node has not received yet. Fetching code
///   before reconciling records would ask for last round's pins.
/// - **before the caller applies claims.** A claim verified while its
///   objective's checker is still missing gets `Unavailable`, which is correct
///   but sticky: the claim is in the log with a non-settling verdict and nothing
///   re-runs it until the next round. Callers that apply records themselves
///   should therefore reconcile records into a staging peer, run this, and only
///   then apply — which is exactly what [`super::service`] does.
///
/// Symmetric, because both sides may lack code the other holds and a
/// one-directional fetch would make availability depend on who dialled.
///
/// The early-out is *both* want sets being empty, which both sides can see from
/// the pair of `Want` messages they have already exchanged, so neither is left
/// waiting for a message the other will not send. There is no digest early-out
/// as populations have, because holdings are not supposed to converge: an empty
/// want set is the steady state, not an equal one.
pub fn reconcile_code(
    connection: &mut Connection,
    store: &BlobStore,
    needs: &BTreeSet<String>,
    limits: CodeLimits,
) -> Result<CodeReport, SessionError> {
    send_code(connection, code::want_message(needs, limits))?;
    let their_want = match receive_code(connection, limits)? {
        CodeMessage::Want { addresses } => addresses,
        _ => return Err(SessionError::Protocol("expected code_want".into())),
    };
    if needs.is_empty() && their_want.is_empty() {
        return Ok(CodeReport::default());
    }

    let served = code::serve(store, &their_want, limits);
    let served_count = served.len();
    send_code(connection, CodeMessage::Blobs { blobs: served })?;
    let incoming = match receive_code(connection, limits)? {
        CodeMessage::Blobs { blobs } => blobs,
        _ => return Err(SessionError::Protocol("expected code_blobs".into())),
    };

    // A refusal is not a session error, for the same reason as a population
    // refusal: a peer whose blob does not hash to a pin we asked for has told us
    // nothing we needed, and tearing the connection down over it would let one
    // bad blob cost the peer its record sync too.
    let mut report = code::admit(store, needs, incoming);
    report.served = served_count;
    Ok(report)
}

/// Ask a peer which of the blobs this node needs it holds, and answer the same
/// question in return.
///
/// Four messages, mirroring [`reconcile_code`]: ask, ask, tell, tell. The shape
/// is deliberate and it is not an announcement round — see [`super::dht`]. A
/// node discloses holdership only for addresses the peer explicitly named, and
/// in a session it has already named them, because the identical set went out as
/// a `code_want` moments earlier. So this round adds routing knowledge at no
/// additional disclosure, which is what lets it coexist with [`super::code`]'s
/// refusal to offer an inventory.
///
/// # Why the answer is not believed about anybody else
///
/// A first-hand `Tell` is stored only when `connection.remote_authenticated()`
/// is true. On a dialled connection the handshake derived that id from the
/// responder key this node selected. On an accepted connection the initiator
/// id is merely claimed, so its answer is read to keep the symmetric protocol
/// moving but is not attributed or re-served.
///
/// # `dialable` is not the socket's peer address
///
/// It is the address this node would use to *reach* the peer, which for an
/// inbound connection is not the source port the kernel reports — that is an
/// ephemeral port belonging to a socket about to close. A caller with no
/// dialable address passes `None`, and the answer is read and dropped rather
/// than stored: a provider record nobody can act on is worse than none, because
/// it occupies a slot a usable one could have had.
///
/// Runs even when `needs` is empty, because the peer's own ask still deserves an
/// answer — a node that stopped talking the moment it wanted nothing would be
/// useless to every peer that wants something from it.
///
/// # The lookup hop, and why it rides this round rather than its own connection
///
/// After the ask/tell pair the round carries one hop of every lookup in flight:
/// a `GetProviders` naming the addresses this peer was chosen to answer, and the
/// answer folded back through [`Directory::on_providers`]. A dedicated
/// connection per hop would be the textbook shape and would cost a McEliece
/// handshake — tens of milliseconds and 261 KiB of key material — for two small
/// messages. Riding the session the daemon was opening anyway makes a hop free,
/// and [`Directory::next_hops`] is what steers *which* session gets opened.
///
/// The last pair fetches a public key. A routing answer names a peer by id and
/// address and never by key, so a newly-heard-of contact is undialable until its
/// key arrives; without this the DHT could only ever reorder peers a node
/// already knew. Verified against the id asked for, which needs no trust: a peer
/// id is `sha256(public key)`.
///
/// All three pairs are exchanged unconditionally, empty when there is nothing to
/// ask. Skipping a pair would need both ends to agree it is being skipped, and
/// they cannot — each side independently has or has not a lookup in flight.
///
/// Returns what the round learned.
pub fn exchange_dht<K>(
    connection: &mut Connection,
    directory: &mut Directory,
    needs: &BTreeSet<String>,
    held: &BTreeSet<String>,
    dialable: Option<std::net::SocketAddr>,
    now: u64,
    key_of: K,
) -> Result<DhtRound, SessionError>
where
    K: Fn(NodeId) -> Option<Vec<u8>>,
{
    let remote = connection.remote();
    let remote_id = NodeId::from_bytes(remote);
    let asked: BTreeSet<String> = needs.iter().take(MAX_ASK_ADDRESSES).cloned().collect();

    send_dht(
        connection,
        DhtMessage::Ask {
            addresses: asked.iter().cloned().collect(),
        },
    )?;
    let their_ask = match receive_dht(connection)? {
        DhtMessage::Ask { addresses } => addresses,
        _ => return Err(SessionError::Protocol("expected dht_ask".into())),
    };
    send_dht(
        connection,
        DhtMessage::Tell {
            addresses: Directory::answer_ask(&their_ask, held),
        },
    )?;
    let their_tell = match receive_dht(connection)? {
        DhtMessage::Tell { addresses } => addresses,
        _ => return Err(SessionError::Protocol("expected dht_tell".into())),
    };

    // -- one hop of every lookup this peer was chosen for -------------------
    let seeking = directory.ask_of(remote_id);
    send_dht(
        connection,
        DhtMessage::GetProviders {
            addresses: seeking.clone(),
        },
    )?;
    let their_seek = match receive_dht(connection)? {
        DhtMessage::GetProviders { addresses } => addresses,
        _ => return Err(SessionError::Protocol("expected dht_get_providers".into())),
    };
    send_dht(
        connection,
        DhtMessage::Providers {
            answers: directory.answer_get_providers(&their_seek, now),
        },
    )?;
    let their_answers = match receive_dht(connection)? {
        DhtMessage::Providers { answers } => answers,
        _ => return Err(SessionError::Protocol("expected dht_providers".into())),
    };

    // -- one public key, so a contact heard of can become one dialled -------
    let wanted_keys = directory.key_wants();
    send_dht(
        connection,
        DhtMessage::GetKey {
            peers: wanted_keys.clone(),
        },
    )?;
    let their_key_want = match receive_dht(connection)? {
        DhtMessage::GetKey { peers } => peers,
        _ => return Err(SessionError::Protocol("expected dht_get_key".into())),
    };
    send_dht(
        connection,
        DhtMessage::Keys {
            keys: their_key_want
                .iter()
                .filter_map(|peer| key_of(*peer).map(|bytes| super::dht::encode_key(&bytes)))
                .take(MAX_KEYS_PER_MESSAGE)
                .collect(),
        },
    )?;
    let their_keys = match receive_dht(connection)? {
        DhtMessage::Keys { keys } => keys,
        _ => return Err(SessionError::Protocol("expected dht_keys".into())),
    };

    // Every message is in before any state changes, so a peer that hangs up
    // mid-round leaves this node exactly as it was.
    let mut round = DhtRound::default();

    // A key is matched against the ids this node asked for, in order, and
    // checked by re-deriving the id from the bytes. An answer for a peer
    // nobody asked about has nowhere to land.
    for (peer, hex) in wanted_keys.iter().zip(their_keys.iter()) {
        match super::dht::decode_key(*peer, hex) {
            Some(bytes) => {
                directory.resolved_key(*peer);
                round.learned.push((*peer, bytes));
            }
            // Wrong bytes for the id asked for. Dropped without ceremony: the
            // want stays queued and some other peer may answer it correctly.
            None => round.bad_keys += 1,
        }
    }

    directory.on_providers(remote_id, &their_answers);
    round.finished = directory.take_finished();

    round.stored = record_authenticated_tell(
        directory,
        connection.remote_authenticated(),
        remote,
        dialable,
        &asked,
        &their_tell,
        now,
    );
    Ok(round)
}

fn record_authenticated_tell(
    directory: &mut Directory,
    remote_authenticated: bool,
    remote: super::handshake::PeerId,
    dialable: Option<std::net::SocketAddr>,
    asked: &BTreeSet<String>,
    told: &[String],
    now: u64,
) -> usize {
    match (remote_authenticated, dialable) {
        (true, Some(addr)) => directory.record_tell(remote, addr, asked, told, now),
        _ => 0,
    }
}

/// What one DHT round learned.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DhtRound {
    /// First-hand provider records stored from the peer's `Tell`.
    pub stored: usize,
    /// Public keys learned and verified, ready for the address book.
    pub learned: Vec<(NodeId, Vec<u8>)>,
    /// Lookups that completed this round, with the holders they found.
    pub finished: Vec<(String, Vec<super::dht::Holder>)>,
    /// Keys the peer answered that did not hash to the id asked for.
    ///
    /// Counted rather than ignored: a peer doing this is broken or hostile, and
    /// a number an operator can see is the difference between diagnosing that
    /// and guessing.
    pub bad_keys: usize,
}

fn send_peers(connection: &mut Connection, message: PeersMessage) -> Result<(), SessionError> {
    trace(connection, Dir::Send, describe_peers(&message));
    connection
        .send(&message.encode(), peers::CONTEXT)
        .map_err(Into::into)
}

fn receive_peers(
    connection: &mut Connection,
    limits: PeerHintLimits,
) -> Result<PeersMessage, SessionError> {
    let message = PeersMessage::decode(&connection.receive(peers::CONTEXT)?, limits)?;
    trace(connection, Dir::Recv, describe_peers(&message));
    Ok(message)
}

/// Run one complete, symmetric peer-hint exchange.
///
/// Runs after [`exchange_dht`] on the same connection and is skipped entirely
/// when the two digests match — the common steady state costs one message each
/// way. It runs *before* the population round for a liveness reason rather
/// than a data dependency: populations are optional (a node that only audits
/// carries none), and a discovery round that only ran on candidate-gossiping
/// nodes would leave exactly the auditors dependent on their bootstrap files.
///
/// The store decides what to believe — signature, sequence, cap — and a
/// refused record is not a session error, for the reason a refused candidate
/// is not: tearing the connection down over one bad record would let it cost
/// the peer its record sync too, which is a cheap way to censor by annoyance.
/// See [`super::peers`] for why accepted hints feed routing and never the
/// ledger.
pub fn exchange_peer_hints(
    connection: &mut Connection,
    hints: &mut peers::Hints,
    limits: PeerHintLimits,
) -> Result<PeersReport, SessionError> {
    send_peers(
        connection,
        PeersMessage::Digest {
            digest: hints.digest(),
            ids: hints.ids(),
        },
    )?;
    let (theirs, offered) = match receive_peers(connection, limits)? {
        PeersMessage::Digest { digest, ids } => (digest, ids),
        _ => return Err(SessionError::Protocol("expected peers_digest".into())),
    };
    if theirs == hints.digest() {
        // Equal digests mean equal id sets: nothing to ask for and nothing to
        // serve, and both sides reach that conclusion from the same
        // comparison, so neither is left waiting for a message the other will
        // not send.
        return Ok(PeersReport::default());
    }

    let want = hints.missing_from(&offered);
    send_peers(connection, PeersMessage::Want { ids: want.clone() })?;
    let their_want = match receive_peers(connection, limits)? {
        PeersMessage::Want { ids } => ids,
        _ => return Err(SessionError::Protocol("expected peers_want".into())),
    };
    send_peers(
        connection,
        PeersMessage::Records {
            records: hints.serve(&their_want, limits),
        },
    )?;
    let incoming = match receive_peers(connection, limits)? {
        PeersMessage::Records { records } => records,
        _ => return Err(SessionError::Protocol("expected peers_records".into())),
    };

    let wanted: BTreeSet<String> = want.into_iter().collect();
    Ok(peers::ingest_hints(hints, &wanted, incoming))
}

fn send_pop(connection: &mut Connection, message: PopMessage) -> Result<(), SessionError> {
    trace(connection, Dir::Send, describe_pop(&message));
    connection
        .send(&message.encode(), pop::CONTEXT)
        .map_err(Into::into)
}

fn receive_pop(connection: &mut Connection, limits: PopLimits) -> Result<PopMessage, SessionError> {
    let message = PopMessage::decode(&connection.receive(pop::CONTEXT)?, limits)?;
    trace(connection, Dir::Recv, describe_pop(&message));
    Ok(message)
}

/// Run one complete, symmetric population exchange.
///
/// Runs *after* [`reconcile`] on the same connection, and is skipped entirely
/// when the two digests match — the common steady state costs one message each
/// way. It is a separate function rather than a phase of `reconcile` because a
/// node may legitimately carry records and not populations: gossiping
/// candidates is a search optimisation, and a node that only audits has no
/// population to offer.
///
/// A population failure must not be able to undo a record round. Both are
/// driven separately by the caller for that reason, and the record round is
/// already committed by the time this runs.
pub fn reconcile_population<F>(
    connection: &mut Connection,
    population: &mut Population,
    limits: PopLimits,
    rescore: F,
) -> Result<PopReport, SessionError>
where
    F: FnMut(&Candidate) -> Option<i64>,
{
    send_pop(connection, pop::digest_message(population))?;
    let (theirs, offered) = match receive_pop(connection, limits)? {
        PopMessage::Digest { digest, ids } => (digest, ids),
        _ => return Err(SessionError::Protocol("expected pop_digest".into())),
    };
    if theirs == population.digest() {
        // Equal digests mean equal id sets. Nothing to ask for and nothing to
        // serve, and both sides reach that conclusion from the same comparison,
        // so neither is left waiting for a message the other will not send.
        return Ok(PopReport::default());
    }

    let want = pop::missing_from(population, &offered);
    send_pop(connection, PopMessage::Want { ids: want.clone() })?;
    let their_want = match receive_pop(connection, limits)? {
        PopMessage::Want { ids } => ids,
        _ => return Err(SessionError::Protocol("expected pop_want".into())),
    };
    send_pop(
        connection,
        PopMessage::Records {
            candidates: pop::serve(population, &their_want, limits),
        },
    )?;
    let incoming = match receive_pop(connection, limits)? {
        PopMessage::Records { candidates } => candidates,
        _ => return Err(SessionError::Protocol("expected pop_records".into())),
    };

    let wanted: BTreeSet<String> = want.into_iter().collect();
    // A refusal here is not a session error. A peer whose candidate does not
    // re-score is wrong about that candidate, and dropping it is the protocol
    // working -- tearing the connection down over it would let one bad
    // candidate cost a peer its record sync too.
    Ok(pop::ingest_candidates(
        population, &wanted, incoming, rescore,
    ))
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
    fn an_unauthenticated_inbound_claim_cannot_seed_provider_state() {
        let local = PeerIdentity::generate().id();
        let claimed = PeerIdentity::generate().id();
        let address = crate::blobs::address(b"checker");
        let asked: BTreeSet<String> = [address.clone()].into_iter().collect();
        let told = vec![address.clone()];
        let addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let mut directory = Directory::new(local);

        assert_eq!(
            record_authenticated_tell(&mut directory, false, claimed, Some(addr), &asked, &told, 1,),
            0
        );
        let key = NodeId::of_digest(&address).unwrap();
        assert!(directory.providers_store().providers(key, 1).is_empty());

        assert_eq!(
            record_authenticated_tell(&mut directory, true, claimed, Some(addr), &asked, &told, 1,),
            1
        );
        assert_eq!(directory.providers_store().providers(key, 1).len(), 1);
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

    fn candidate(n: i128, score: i64) -> Candidate {
        Candidate::new("obj", Value::object([("n", Value::Int(n))]), score, "who")
    }

    /// The honest scorer for the fixture: the score *is* `n`.
    fn honest(candidate: &Candidate) -> Option<i64> {
        candidate
            .artifact
            .get("n")
            .and_then(Value::as_i128)
            .and_then(|n| i64::try_from(n).ok())
    }

    #[test]
    fn records_and_populations_converge_over_one_session() {
        // Both families on one connection, in the order the daemon runs them.
        // The population half must not disturb the record half, and vice versa.
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
            let mut population = Population::default();
            population.add(candidate(2, 2));
            reconcile_population(
                &mut connection,
                &mut population,
                PopLimits::default(),
                honest,
            )
            .unwrap();
            (peer.len(), population.len(), population.digest())
        });

        let mut connection = connect(&bob_public, addr, &alice).unwrap();
        let mut peer = Peer::new();
        peer.insert(claim(1)).unwrap();
        reconcile(&mut connection, &mut peer, |_| Ok::<(), SyncError>(())).unwrap();
        let mut population = Population::default();
        population.add(candidate(1, 1));
        let report = reconcile_population(
            &mut connection,
            &mut population,
            PopLimits::default(),
            honest,
        )
        .unwrap();

        assert_eq!(report.accepted, 1);
        assert_eq!(peer.len(), 2);
        assert_eq!(population.len(), 2);
        let (their_records, their_population, their_digest) = bob_thread.join().unwrap();
        assert_eq!(their_records, 2);
        assert_eq!(their_population, 2);
        assert_eq!(their_digest, population.digest());
    }

    #[test]
    fn a_peer_that_lies_about_a_score_loses_the_candidate_and_keeps_the_session() {
        // Dropping the candidate is the protocol working. Tearing the
        // connection down over it would let one bad candidate cost the peer its
        // record sync too, which is a cheap way to censor by annoyance.
        let alice = PeerIdentity::generate();
        let bob = PeerIdentity::generate();
        let bob_public = bob.to_public();
        let listener = listen("127.0.0.1:0".parse::<SocketAddr>().unwrap()).unwrap();
        let addr = listener.local_addr().unwrap();

        let bob_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut connection = accept(stream, &bob).unwrap();
            let mut population = Population::default();
            population.add(candidate(2, 1_000_000));
            reconcile_population(
                &mut connection,
                &mut population,
                PopLimits::default(),
                honest,
            )
            .is_ok()
        });

        let mut connection = connect(&bob_public, addr, &alice).unwrap();
        let mut population = Population::default();
        population.add(candidate(1, 1));
        let report = reconcile_population(
            &mut connection,
            &mut population,
            PopLimits::default(),
            honest,
        )
        .expect("a lie is not a session failure");

        assert_eq!(report.accepted, 0);
        assert_eq!(report.refused, 1);
        assert_eq!(population.len(), 1, "the inflated candidate was kept");
        assert!(bob_thread.join().unwrap());
    }

    #[test]
    fn synced_populations_stop_after_one_message_each_way() {
        let alice = PeerIdentity::generate();
        let bob = PeerIdentity::generate();
        let bob_public = bob.to_public();
        let listener = listen("127.0.0.1:0".parse::<SocketAddr>().unwrap()).unwrap();
        let addr = listener.local_addr().unwrap();

        let bob_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut connection = accept(stream, &bob).unwrap();
            let mut population = Population::default();
            population.add(candidate(1, 1));
            reconcile_population(
                &mut connection,
                &mut population,
                PopLimits::default(),
                |_| panic!("a synced pair must not score anything"),
            )
            .unwrap()
        });

        let mut connection = connect(&bob_public, addr, &alice).unwrap();
        let mut population = Population::default();
        population.add(candidate(1, 1));
        let report = reconcile_population(
            &mut connection,
            &mut population,
            PopLimits::default(),
            |_| panic!("a synced pair must not score anything"),
        )
        .unwrap();
        assert_eq!(report, PopReport::default());
        assert_eq!(bob_thread.join().unwrap(), PopReport::default());
    }
}
