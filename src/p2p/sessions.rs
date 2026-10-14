//! The peer sessions this process has run, as a roster a reader can see.
//!
//! For as long as the HTTP half of a node has existed, `docs/serving.md` has
//! said the same sentence about `GET /peers`: *live session state lives in the
//! p2p service, which serves no HTTP*. Every reader -- the page at `/ui/peers`,
//! both Mac apps, the phone -- rendered the log's address book under a
//! disclaimer, because the daemon knew whom it had reached and the server did
//! not. This module is the daemon telling the server.
//!
//! # What a session is here
//!
//! Not a held connection. A cairn session is one exchange: dial or accept,
//! handshake, reconcile records (and the population when it is on), close.
//! The daemon ticks every five seconds and dials a fanout of three, so a peer
//! in a small mesh is reached every few ticks and a peer in a large one less
//! often. "Connected" is therefore a window rather than a socket: a peer is
//! **reached** when a session with it succeeded within [`REACHED_SECONDS`],
//! **recent** within [`RECENT_SECONDS`], and **lost** after that -- the same
//! three-step reading the heartbeat roster in [`crate::progress`] gives a
//! worker, and for the same reason: the question a reader has is "is this
//! still true", and the honest answer is "as of this long ago".
//!
//! # What it is not
//!
//! **Not a record.** Never appended, never gossiped, forgotten on restart,
//! like a heartbeat. A reader comparing two nodes' rosters is comparing two
//! processes' memories, and the page says so.
//!
//! **Not the address book.** The book is the [`super::service::Service`]'s:
//! whom this node *could* dial, with the keys to do it. This is what happened
//! when the book was used. The two sizes are carried here as counts so one
//! route can say both, but a hint is not a session and the payload keeps them
//! in different fields.
//!
//! **Not evidence of anything but reachability.** A peer that reached us
//! proved it holds the McEliece key its id names, because the handshake
//! authenticates that key and nothing else. It did not prove it holds the log
//! (that is the availability mechanism), ran a verifier (that is an
//! attestation), or is honest. A failed inbound handshake names nobody at all:
//! the initiator's id is derived from a key this node never finished checking,
//! so it is counted and not attributed -- attributing it would let anyone
//! write a stranger's id into this roster with one garbage frame.
//!
//! # Bounds
//!
//! One row per peer id, [`MAX_PEERS`] rows, rows forgotten after
//! [`FORGET_SECONDS`] without a session. A peer id is the hash of a 261 KiB
//! key that cost 243 ms to make, so flooding this table means minting
//! identities at that price and completing a handshake with each; the cap is
//! there so the memory is bounded anyway, and refusal past it loses the
//! newest stranger rather than evicting a peer this node has actually spoken
//! to.

use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;

use super::handshake::{peer_id_hex, PeerId};
use super::reach;
use super::sync::About;
use crate::canonical::Value;
use crate::time::format_iso8601_utc;

/// A session this recent means the peer is reached. Two dozen ticks: in a
/// mesh of a few dozen peers at fanout three, a random sample reaches each
/// peer about this often, and an inbound peer dials on its own schedule.
pub const REACHED_SECONDS: u64 = 120;
/// Beyond this a peer is lost rather than recent. Half an hour, the same as
/// a stale worker: long enough that one node restarting is not a peer
/// disappearing, short enough that a page does not show last night as now.
pub const RECENT_SECONDS: u64 = 1800;
/// Rows without a session for a day are dropped.
pub const FORGET_SECONDS: u64 = 86_400;
/// Most peer rows held. See the module docs for why refusal beats eviction.
pub const MAX_PEERS: usize = 4096;

/// Which side opened the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// A peer dialled this node.
    Inbound,
    /// This node dialled the peer.
    Outbound,
}

impl Direction {
    pub fn as_str(self) -> &'static str {
        match self {
            Direction::Inbound => "inbound",
            Direction::Outbound => "outbound",
        }
    }
}

/// Reached, recent or lost, by the age of the last successful session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    Reached,
    Recent,
    Lost,
}

impl Reach {
    pub fn of_age(age: u64) -> Reach {
        if age <= REACHED_SECONDS {
            Reach::Reached
        } else if age <= RECENT_SECONDS {
            Reach::Recent
        } else {
            Reach::Lost
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Reach::Reached => "reached",
            Reach::Recent => "recent",
            Reach::Lost => "lost",
        }
    }
}

/// What a successful session changed about a peer.
///
/// Sessions are an exchange every few ticks, not a held connection, so
/// "connected" is not an event a session can report on its own. These are the
/// transitions worth telling a person about: a peer reached for the first
/// time, and a peer back after long enough silent to have counted as lost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Contact {
    /// No session with this peer had succeeded before.
    First,
    /// The last success was at least [`RECENT_SECONDS`] ago: the peer read as
    /// lost, and is back.
    Back { silent_for: u64 },
    /// An ordinary session with a peer already reached.
    Again,
}

/// Everything this process knows about one peer, from its own sessions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerStanding {
    pub peer: PeerId,
    /// The address of the last session, whichever way it ran. An inbound
    /// peer's address is its ephemeral source port and says little about
    /// where it listens; the field is what was seen, not what to dial.
    pub addr: Option<SocketAddr>,
    pub first_seen_at: u64,
    pub last_ok_at: Option<u64>,
    pub last_failed_at: Option<u64>,
    pub last_error: Option<String>,
    pub last_direction: Direction,
    pub inbound_ok: u64,
    pub outbound_ok: u64,
    pub failures: u64,
    /// This node's ledger length after the last successful session, which is
    /// the one number a session changes that a reader can check against
    /// `/chain`.
    pub entries_after: Option<usize>,
    /// What the peer said it is in its last hello: roles, verifier kinds and
    /// version. Its word, unchecked -- see [`About`]. `None` from a peer
    /// older than the field, or one this node has only failed to reach.
    pub about: Option<About>,
}

impl PeerStanding {
    /// Age of the last successful session, if there was one.
    fn ok_age(&self, now: u64) -> Option<u64> {
        self.last_ok_at.map(|at| now.saturating_sub(at))
    }

    /// Reached, recent or lost -- and `None` for a peer this node has only
    /// ever failed to reach, which is a different fact from a peer it has
    /// lost and is reported as such.
    pub fn reach(&self, now: u64) -> Option<Reach> {
        self.ok_age(now).map(Reach::of_age)
    }

    /// The most recent event of either kind, for forgetting.
    fn last_event_at(&self) -> u64 {
        self.last_ok_at
            .into_iter()
            .chain(self.last_failed_at)
            .max()
            .unwrap_or(self.first_seen_at)
    }
}

/// The roster is full; the peer was not kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterFull;

impl fmt::Display for RosterFull {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "this node is holding standing for as many peers as it will; a new one is not kept \
             until an old one is forgotten"
        )
    }
}

impl std::error::Error for RosterFull {}

/// What the daemon learned about the address book on its last tick.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BookSizes {
    /// Endpoints with a key this node could dial now.
    pub endpoints: usize,
    /// Signed peer hints learned over the mesh, dialable once a key arrives.
    pub hints: usize,
    pub noted_at: Option<u64>,
}

/// Every peer session this process has run and not yet forgotten.
#[derive(Debug)]
pub struct Sessions {
    peers: BTreeMap<PeerId, PeerStanding>,
    started_at: u64,
    /// This node's own transport id and listen address, once it is bound.
    this: Option<(PeerId, SocketAddr)>,
    book: BookSizes,
    /// Inbound handshakes that failed before naming anyone. See the module
    /// docs for why these are counted and never attributed.
    anonymous_inbound_failures: u64,
    /// What the port-mapping thread last said about this node's reachability
    /// from outside its router. `None` until the daemon decides whether to
    /// ask; a plain publisher never sets it. See [`reach`].
    external: Option<reach::Report>,
    /// The last successful inbound session from an address outside every
    /// private range: the one piece of evidence that a stranger can dial
    /// this node, as opposed to a router's claim that one could.
    inbound_from_public_at: Option<u64>,
}

impl Sessions {
    pub fn new(now: u64) -> Sessions {
        Sessions {
            peers: BTreeMap::new(),
            started_at: now,
            this: None,
            book: BookSizes::default(),
            anonymous_inbound_failures: 0,
            external: None,
            inbound_from_public_at: None,
        }
    }

    /// Who this node is on the wire, once the listener is bound.
    pub fn identify(&mut self, peer: PeerId, listen: SocketAddr) {
        self.this = Some((peer, listen));
    }

    /// What the port-mapping thread last reported. See [`reach`].
    pub fn set_external(&mut self, report: reach::Report) {
        self.external = Some(report);
    }

    pub fn external(&self) -> Option<&reach::Report> {
        self.external.as_ref()
    }

    /// When a peer from outside every private range last reached this node
    /// inbound, if ever.
    pub fn inbound_from_public_at(&self) -> Option<u64> {
        self.inbound_from_public_at
    }

    /// A session with `peer` completed. `entries` is this node's ledger
    /// length afterwards.
    ///
    /// Returns what the session changed about the peer, for a caller that
    /// narrates changes rather than sessions -- see [`Contact`].
    pub fn succeeded(
        &mut self,
        peer: PeerId,
        addr: Option<SocketAddr>,
        direction: Direction,
        entries: usize,
        now: u64,
    ) -> Result<Contact, RosterFull> {
        let contact = match self.peers.get(&peer).and_then(|s| s.last_ok_at) {
            None => Contact::First,
            Some(at) if now.saturating_sub(at) >= RECENT_SECONDS => Contact::Back {
                silent_for: now.saturating_sub(at),
            },
            Some(_) => Contact::Again,
        };
        let standing = self.row(peer, addr, direction, now)?;
        standing.last_ok_at = Some(now);
        standing.entries_after = Some(entries);
        match direction {
            Direction::Inbound => standing.inbound_ok += 1,
            Direction::Outbound => standing.outbound_ok += 1,
        }
        // The evidence a port mapping lacks. A LAN peer dialling in says
        // nothing about the router, and dialling *out* to a public address
        // says nothing about inbound; only a public address that reached
        // this node does, and `addr` is the accepted socket's remote end.
        if direction == Direction::Inbound && addr.is_some_and(|addr| reach::is_public(addr.ip())) {
            self.inbound_from_public_at = Some(now);
        }
        Ok(contact)
    }

    /// What `peer` said it is, in the hello of a session that completed.
    /// Kept beside the standing and replaced by the next hello, so the
    /// roster says what the peer last claimed, not what it ever claimed. A
    /// peer this node has no row for is not given one: a declaration is
    /// worth keeping only beside a session that proved the key behind it.
    pub fn learned(&mut self, peer: PeerId, about: About) {
        if let Some(standing) = self.peers.get_mut(&peer) {
            standing.about = Some(about);
        }
    }

    /// A session with `peer` failed. For an inbound failure the peer is not
    /// known -- see [`Sessions::inbound_failed`].
    ///
    /// Returns whether this failure starts a streak: the first ever with this
    /// peer, or the first since a session last succeeded. A seed that is down
    /// fails every tick, and a reader wants to hear that once.
    pub fn failed(
        &mut self,
        peer: PeerId,
        addr: Option<SocketAddr>,
        direction: Direction,
        error: &str,
        now: u64,
    ) -> Result<bool, RosterFull> {
        let news = match self.peers.get(&peer) {
            None => true,
            Some(standing) => match (standing.last_ok_at, standing.last_failed_at) {
                (_, None) => true,
                (Some(ok), Some(failed)) => failed < ok,
                (None, Some(_)) => false,
            },
        };
        let standing = self.row(peer, addr, direction, now)?;
        standing.last_failed_at = Some(now);
        standing.failures += 1;
        // Bounded, because the text is a peer's to shape: a transport error
        // carries the address it was dialling, never the remote's words, but
        // a cap costs nothing and a roster is not a log.
        standing.last_error = Some(error.chars().take(200).collect());
        Ok(news)
    }

    /// An inbound handshake failed before the remote was authenticated.
    pub fn inbound_failed(&mut self) {
        self.anonymous_inbound_failures += 1;
    }

    /// How big the address book is, as of the daemon's last look.
    pub fn note_book(&mut self, endpoints: usize, hints: usize, now: u64) {
        self.book = BookSizes {
            endpoints,
            hints,
            noted_at: Some(now),
        };
    }

    fn row(
        &mut self,
        peer: PeerId,
        addr: Option<SocketAddr>,
        direction: Direction,
        now: u64,
    ) -> Result<&mut PeerStanding, RosterFull> {
        self.forget(now);
        if !self.peers.contains_key(&peer) && self.peers.len() >= MAX_PEERS {
            return Err(RosterFull);
        }
        let standing = self.peers.entry(peer).or_insert(PeerStanding {
            peer,
            addr: None,
            first_seen_at: now,
            last_ok_at: None,
            last_failed_at: None,
            last_error: None,
            last_direction: direction,
            inbound_ok: 0,
            outbound_ok: 0,
            failures: 0,
            entries_after: None,
            about: None,
        });
        if addr.is_some() {
            standing.addr = addr;
        }
        standing.last_direction = direction;
        Ok(standing)
    }

    /// Drop rows nothing has touched for [`FORGET_SECONDS`].
    fn forget(&mut self, now: u64) {
        self.peers
            .retain(|_, standing| now.saturating_sub(standing.last_event_at()) <= FORGET_SECONDS);
    }

    /// Rows, for a caller that wants to count or filter them itself.
    pub fn peers(&self) -> impl Iterator<Item = &PeerStanding> {
        self.peers.values()
    }

    /// Reached, recent and lost peers, plus peers only ever failed.
    pub fn tally(&self, now: u64) -> Tally {
        let mut tally = Tally::default();
        for standing in self.peers.values() {
            match standing.reach(now) {
                Some(Reach::Reached) => tally.reached += 1,
                Some(Reach::Recent) => tally.recent += 1,
                Some(Reach::Lost) => tally.lost += 1,
                None => tally.unreached += 1,
            }
        }
        tally
    }

    /// The summary a composite route carries: counts and the book, no rows.
    pub fn summary(&self, now: u64) -> Value {
        let tally = self.tally(now);
        Value::object([
            ("available", Value::Bool(true)),
            ("reached", Value::Int(i128::from(tally.reached))),
            ("recent", Value::Int(i128::from(tally.recent))),
            ("lost", Value::Int(i128::from(tally.lost))),
            ("unreached", Value::Int(i128::from(tally.unreached))),
            ("address_book", self.book_value()),
            ("this_node", self.this_value(now)),
        ])
    }

    /// The whole roster, as `GET /sessions` answers it.
    pub fn report(&self, now: u64) -> Value {
        let mut rows: Vec<&PeerStanding> = self.peers.values().collect();
        // Reached first, then by most recent success, then by id -- the order
        // a reader scans for "who is here".
        rows.sort_by(|a, b| {
            b.last_ok_at
                .cmp(&a.last_ok_at)
                .then_with(|| a.peer.cmp(&b.peer))
        });
        let peers = rows
            .into_iter()
            .map(|standing| peer_value(standing, now))
            .collect();
        let tally = self.tally(now);
        Value::object([
            ("available", Value::Bool(true)),
            ("peers", Value::Array(peers)),
            ("reached", Value::Int(i128::from(tally.reached))),
            ("recent", Value::Int(i128::from(tally.recent))),
            ("lost", Value::Int(i128::from(tally.lost))),
            ("unreached", Value::Int(i128::from(tally.unreached))),
            (
                "anonymous_inbound_failures",
                Value::Int(i128::from(self.anonymous_inbound_failures)),
            ),
            ("address_book", self.book_value()),
            ("this_node", self.this_value(now)),
            (
                "reached_within_seconds",
                Value::Int(i128::from(REACHED_SECONDS)),
            ),
            (
                "recent_within_seconds",
                Value::Int(i128::from(RECENT_SECONDS)),
            ),
            (
                "note",
                Value::string(
                    "Sessions this process ran, from its own memory: a cairn session is one \
                     exchange (handshake, reconcile, close), not a held connection, so a peer \
                     is `reached` when one succeeded recently and nothing here is a record. \
                     A reached peer proved it holds the key its id names and nothing else: \
                     its `about` -- roles, verifier kinds, version -- is what it said in \
                     its hello, declared and unchecked, like `CAIRN_ROLES` on its own \
                     /network. `address_book` is whom this node could dial; `GET /peers` \
                     is whom the log announces; neither is a session.",
                ),
            ),
        ])
    }

    fn book_value(&self) -> Value {
        Value::object([
            (
                "endpoints",
                Value::Int(i128::from(self.book.endpoints as u64)),
            ),
            ("hints", Value::Int(i128::from(self.book.hints as u64))),
            (
                "noted_at",
                match self.book.noted_at {
                    Some(at) => Value::string(iso(at)),
                    None => Value::Null,
                },
            ),
        ])
    }

    fn this_value(&self, now: u64) -> Value {
        let (peer_id, listen) = match &self.this {
            Some((id, listen)) => (
                Value::string(peer_id_hex(id)),
                Value::string(listen.to_string()),
            ),
            None => (Value::Null, Value::Null),
        };
        Value::object([
            ("peer_id", peer_id),
            ("listen", listen),
            ("started_at", Value::string(iso(self.started_at))),
            (
                "uptime_seconds",
                Value::Int(i128::from(now.saturating_sub(self.started_at))),
            ),
            (
                "external",
                match &self.external {
                    Some(report) => report.to_value(),
                    None => Value::Null,
                },
            ),
            (
                "inbound_from_public_at",
                match self.inbound_from_public_at {
                    Some(at) => Value::string(iso(at)),
                    None => Value::Null,
                },
            ),
        ])
    }
}

/// Counts by reach.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Tally {
    pub reached: u64,
    pub recent: u64,
    pub lost: u64,
    /// Peers this node has dialled and never once reached.
    pub unreached: u64,
}

fn peer_value(standing: &PeerStanding, now: u64) -> Value {
    let opt_time = |at: Option<u64>| match at {
        Some(at) => Value::string(iso(at)),
        None => Value::Null,
    };
    Value::object([
        ("peer_id", Value::string(peer_id_hex(&standing.peer))),
        (
            "status",
            Value::string(match standing.reach(now) {
                Some(reach) => reach.as_str(),
                None => "unreached",
            }),
        ),
        (
            "addr",
            match standing.addr {
                Some(addr) => Value::string(addr.to_string()),
                None => Value::Null,
            },
        ),
        (
            "last_direction",
            Value::string(standing.last_direction.as_str()),
        ),
        ("first_seen_at", Value::string(iso(standing.first_seen_at))),
        ("last_ok_at", opt_time(standing.last_ok_at)),
        (
            "age_seconds",
            match standing.ok_age(now) {
                Some(age) => Value::Int(i128::from(age)),
                None => Value::Null,
            },
        ),
        ("last_failed_at", opt_time(standing.last_failed_at)),
        (
            "last_error",
            match &standing.last_error {
                Some(error) => Value::string(error.clone()),
                None => Value::Null,
            },
        ),
        ("inbound_ok", Value::Int(i128::from(standing.inbound_ok))),
        ("outbound_ok", Value::Int(i128::from(standing.outbound_ok))),
        ("failures", Value::Int(i128::from(standing.failures))),
        (
            "entries_after",
            match standing.entries_after {
                Some(entries) => Value::Int(i128::from(entries as u64)),
                None => Value::Null,
            },
        ),
        (
            "about",
            match &standing.about {
                Some(about) => about.to_value(),
                None => Value::Null,
            },
        ),
    ])
}

fn iso(unix: u64) -> String {
    format_iso8601_utc(i64::try_from(unix).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> PeerId {
        [byte; 32]
    }

    fn addr(port: u16) -> SocketAddr {
        format!("10.0.0.1:{port}").parse().expect("addr")
    }

    #[test]
    fn a_session_moves_a_peer_through_reached_recent_and_lost() {
        let mut sessions = Sessions::new(1_000);
        sessions
            .succeeded(id(1), Some(addr(9000)), Direction::Outbound, 12, 1_000)
            .expect("kept");
        let standing = sessions.peers().next().expect("one row");
        assert_eq!(
            standing.reach(1_000 + REACHED_SECONDS),
            Some(Reach::Reached)
        );
        assert_eq!(
            standing.reach(1_000 + REACHED_SECONDS + 1),
            Some(Reach::Recent)
        );
        assert_eq!(
            standing.reach(1_000 + RECENT_SECONDS + 1),
            Some(Reach::Lost)
        );
        assert_eq!(standing.entries_after, Some(12));
        assert_eq!(standing.outbound_ok, 1);
        assert_eq!(standing.inbound_ok, 0);
    }

    #[test]
    fn a_peer_only_ever_failed_is_unreached_not_lost() {
        let mut sessions = Sessions::new(0);
        sessions
            .failed(
                id(2),
                Some(addr(9001)),
                Direction::Outbound,
                "Connection refused",
                5,
            )
            .expect("kept");
        let tally = sessions.tally(10);
        assert_eq!(tally.unreached, 1);
        assert_eq!(tally.lost, 0);
        let report = sessions.report(10);
        let row = &report.get("peers").unwrap().as_array().unwrap()[0];
        assert_eq!(row.get("status").unwrap().as_str(), Some("unreached"));
        assert_eq!(
            row.get("last_error").unwrap().as_str(),
            Some("Connection refused")
        );
        assert_eq!(row.get("last_ok_at").unwrap(), &Value::Null);
    }

    #[test]
    fn a_session_says_first_contact_and_return_once_and_failures_once_per_streak() {
        let mut sessions = Sessions::new(0);
        let out = Direction::Outbound;
        // A seed that is down fails every tick; only the first is news.
        assert_eq!(sessions.failed(id(9), None, out, "refused", 5), Ok(true));
        assert_eq!(sessions.failed(id(9), None, out, "refused", 10), Ok(false));
        // Its first success is first contact, however many failures came first.
        assert_eq!(
            sessions.succeeded(id(9), None, out, 3, 20),
            Ok(Contact::First)
        );
        assert_eq!(
            sessions.succeeded(id(9), None, out, 3, 25),
            Ok(Contact::Again)
        );
        // A failure after a success starts a new streak, and is news again.
        assert_eq!(sessions.failed(id(9), None, out, "reset", 30), Ok(true));
        assert_eq!(sessions.failed(id(9), None, out, "reset", 35), Ok(false));
        // Silent long enough to have read as lost: back, with how long.
        let later = 25 + RECENT_SECONDS;
        assert_eq!(
            sessions.succeeded(id(9), None, out, 4, later),
            Ok(Contact::Back {
                silent_for: RECENT_SECONDS
            })
        );
        // Merely recent is not a return: in a big mesh that is every peer.
        assert_eq!(
            sessions.succeeded(id(9), None, out, 4, later + REACHED_SECONDS + 5),
            Ok(Contact::Again)
        );
    }

    #[test]
    fn both_directions_count_on_one_row_and_the_report_orders_by_last_success() {
        let mut sessions = Sessions::new(0);
        sessions
            .succeeded(id(3), Some(addr(1)), Direction::Inbound, 1, 10)
            .expect("kept");
        sessions
            .succeeded(id(3), Some(addr(2)), Direction::Outbound, 2, 20)
            .expect("kept");
        sessions
            .succeeded(id(4), Some(addr(3)), Direction::Outbound, 3, 15)
            .expect("kept");
        assert_eq!(sessions.peers().count(), 2);
        let report = sessions.report(30);
        let peers = report.get("peers").unwrap().as_array().unwrap();
        assert_eq!(
            peers[0].get("peer_id").unwrap().as_str(),
            Some(peer_id_hex(&id(3)).as_str())
        );
        assert_eq!(peers[0].get("inbound_ok").unwrap(), &Value::Int(1));
        assert_eq!(peers[0].get("outbound_ok").unwrap(), &Value::Int(1));
        assert_eq!(
            peers[0].get("last_direction").unwrap().as_str(),
            Some("outbound")
        );
        assert_eq!(report.get("reached").unwrap(), &Value::Int(2));
    }

    #[test]
    fn rows_are_forgotten_after_a_day_and_the_roster_refuses_past_the_cap() {
        let mut sessions = Sessions::new(0);
        sessions
            .succeeded(id(5), None, Direction::Outbound, 1, 0)
            .expect("kept");
        // Touching the roster a day and a second later forgets the row.
        sessions
            .succeeded(id(6), None, Direction::Outbound, 1, FORGET_SECONDS + 1)
            .expect("kept");
        assert_eq!(sessions.peers().count(), 1);

        let mut full = Sessions::new(0);
        for n in 0..MAX_PEERS {
            let mut peer = [0u8; 32];
            peer[..8].copy_from_slice(&(n as u64).to_be_bytes());
            full.succeeded(peer, None, Direction::Inbound, 1, 1)
                .expect("kept");
        }
        assert_eq!(
            full.succeeded(id(255), None, Direction::Inbound, 1, 1),
            Err(RosterFull)
        );
        // A peer already on the roster is still updated when it is full.
        let mut known = [0u8; 32];
        known[..8].copy_from_slice(&7u64.to_be_bytes());
        full.succeeded(known, None, Direction::Outbound, 9, 2)
            .expect("an existing row is not a new one");
    }

    #[test]
    fn what_a_peer_said_it_is_rides_beside_its_session_and_only_there() {
        let mut sessions = Sessions::new(0);
        let about = About {
            version: "1.17.0".into(),
            roles: vec!["relay".into()],
            verifiers: vec!["certificate".into()],
        };
        // Nothing to attach to: a declaration from a peer with no session
        // makes no row.
        sessions.learned(id(9), about.clone());
        assert!(sessions.peers().next().is_none());

        sessions
            .succeeded(id(1), Some(addr(1)), Direction::Outbound, 1, 10)
            .expect("kept");
        sessions
            .succeeded(id(2), Some(addr(2)), Direction::Inbound, 1, 10)
            .expect("kept");
        sessions.learned(id(1), about.clone());
        let report = sessions.report(11);
        let peers = report.get("peers").unwrap().as_array().unwrap();
        let said = peers
            .iter()
            .find(|row| row.get("peer_id").unwrap().as_str() == Some(&peer_id_hex(&id(1))))
            .unwrap();
        assert_eq!(said.get("about").unwrap(), &about.to_value());
        let silent = peers
            .iter()
            .find(|row| row.get("peer_id").unwrap().as_str() == Some(&peer_id_hex(&id(2))))
            .unwrap();
        assert_eq!(
            silent.get("about").unwrap(),
            &Value::Null,
            "an older peer says nothing"
        );

        // The next hello replaces the last: the roster is what the peer
        // last claimed.
        sessions.learned(
            id(1),
            About {
                roles: vec![],
                ..about.clone()
            },
        );
        let row = sessions.peers().find(|p| p.peer == id(1)).unwrap();
        assert!(row.about.as_ref().unwrap().roles.is_empty());
    }

    #[test]
    fn anonymous_inbound_failures_name_nobody() {
        let mut sessions = Sessions::new(0);
        sessions.inbound_failed();
        sessions.inbound_failed();
        let report = sessions.report(1);
        assert_eq!(
            report.get("anonymous_inbound_failures").unwrap(),
            &Value::Int(2)
        );
        assert!(report.get("peers").unwrap().as_array().unwrap().is_empty());
    }

    #[test]
    fn the_summary_carries_the_book_and_this_node() {
        let mut sessions = Sessions::new(100);
        sessions.identify(id(9), addr(9000));
        sessions.note_book(3, 40, 150);
        let summary = sessions.summary(160);
        assert_eq!(summary.get("available").unwrap(), &Value::Bool(true));
        let book = summary.get("address_book").unwrap();
        assert_eq!(book.get("endpoints").unwrap(), &Value::Int(3));
        assert_eq!(book.get("hints").unwrap(), &Value::Int(40));
        let this = summary.get("this_node").unwrap();
        assert_eq!(
            this.get("peer_id").unwrap().as_str(),
            Some(peer_id_hex(&id(9)).as_str())
        );
        assert_eq!(this.get("listen").unwrap().as_str(), Some("10.0.0.1:9000"));
        assert_eq!(this.get("uptime_seconds").unwrap(), &Value::Int(60));
    }

    #[test]
    fn an_inbound_session_from_outside_is_the_evidence_a_mapping_lacks() {
        let mut sessions = Sessions::new(100);
        let private: SocketAddr = "192.168.1.20:50000".parse().unwrap();
        let public: SocketAddr = "203.0.113.7:50000".parse().unwrap();
        // Nothing yet, and the roster says so in both fields.
        let summary = sessions.summary(100);
        let this = summary.get("this_node").unwrap();
        assert_eq!(this.get("external").unwrap(), &Value::Null);
        assert_eq!(this.get("inbound_from_public_at").unwrap(), &Value::Null);
        // A LAN peer dialling in proves nothing about the router.
        sessions
            .succeeded(id(1), Some(private), Direction::Inbound, 1, 110)
            .unwrap();
        assert_eq!(sessions.inbound_from_public_at(), None);
        // Dialling out to a public address proves nothing about inbound.
        sessions
            .succeeded(id(2), Some(public), Direction::Outbound, 1, 120)
            .unwrap();
        assert_eq!(sessions.inbound_from_public_at(), None);
        // A public address dialling in is the evidence.
        sessions
            .succeeded(id(3), Some(public), Direction::Inbound, 1, 130)
            .unwrap();
        assert_eq!(sessions.inbound_from_public_at(), Some(130));

        sessions.set_external(reach::Report::off(
            reach::Mode::Off,
            "off (CAIRN_PORTMAP)".into(),
            100,
        ));
        let report = sessions.report(140);
        let this = report.get("this_node").unwrap();
        assert_eq!(
            this.get("external")
                .unwrap()
                .get("status")
                .unwrap()
                .as_str(),
            Some("off")
        );
        assert_eq!(
            this.get("inbound_from_public_at").unwrap().as_str(),
            Some("1970-01-01T00:02:10+00:00")
        );
    }
}
