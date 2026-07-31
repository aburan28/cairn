//! Peer-to-peer blob transfer, in the BitTorrent shape.
//!
//! [`crate::store::blobs`] made a blob's digest its *name*, which fixed where a
//! blob lives once a node has one and left the harder question open: how does a
//! node that needs an evaluator get it from a node that has it? `sync` copies a
//! whole store between two directories one operator controls. Between strangers
//! there was nothing.
//!
//! This is that, and the shape is BitTorrent's because the problem is
//! BitTorrent's: many peers, none trusted, each holding part of a file everybody
//! wants, and no server worth paying for. Pieces, bitfields, rarest-first,
//! choking, endgame.
//!
//! ```text
//!   leech                                   seed
//!     |-- handshake(digest, peer_id) ------->|
//!     |<------- handshake(digest, peer_id) --|
//!     |-- want-manifest -------------------->|
//!     |<--------------- manifest(pieces...) -|  checked against the log's digest
//!     |-- bitfield(empty) ------------------>|
//!     |<------------------- bitfield(full) --|
//!     |-- interested ----------------------->|
//!     |<------------------------- unchoke ---|
//!     |-- request(rarest) ------------------>|
//!     |<------------------- piece(index, …) -|  verified against the manifest
//!     |-- have(index) --------------------->|
//! ```
//!
//! # What is different here, and it is the good part
//!
//! BitTorrent's weakest joint is the metainfo. A `.torrent` has to be obtained
//! out of band and *believed*: the infohash is the root of trust and nothing in
//! the protocol establishes it, which is why trackers, signed feeds and magnet
//! links all exist and all pass the problem somewhere else.
//!
//! > **This network already agreed on the digest.** An objective commits to
//! > `evaluator_sha256` as part of its content-addressed id, so every node with
//! > a copy of the log knows the true digest of every blob the network needs.
//!
//! There is nothing to trust and nothing to sign. A manifest is fetched from a
//! stranger and checked against a digest the log fixed before the transfer
//! started; a peer that offers a manifest for the wrong content is caught on
//! arrival rather than after a download. The tracker's job is done by the ledger,
//! and it was done before this module existed.
//!
//! # What the mechanism buys, stated narrowly
//!
//! Piece hashes are **not** a second source of truth. Anyone can compute a
//! manifest for any bytes, so holding one proves nothing. What they buy is
//! *blame*: a peer that sends a piece not matching the manifest has provably
//! misbehaved on that piece, so it is dropped and its bytes discarded while the
//! rest of the transfer continues. Without them, one bad peer costs the whole
//! download and leaves no evidence about who.
//!
//! That matters more here than in BitTorrent, because this network *pays for
//! availability* ([`crate::incentive`]). Attributable failure is the currency
//! that mechanism runs on, and piece-level verification is what makes a failure
//! attributable at all.
//!
//! # Choking, and the thing choking cannot do
//!
//! Tit-for-tat unchoking is what you build when there is no payment layer: serve
//! the peers who serve you, rotate an optimistic slot so newcomers can start.
//! It works, it needs no identity, and it has a known hole -- **a seed gets
//! nothing back.** A node that has finished has no reciprocal need, so serving is
//! pure altruism and the dominant move is to stop.
//!
//! That is exactly the public-goods problem [`crate::incentive`] exists for, and
//! it is not solved here. Choking is implemented because it is free and helps
//! during the download phase; seeding stays a public good priced by the
//! availability pool, which is designed and not built. Saying otherwise would be
//! claiming a mechanism the code does not have.
//!
//! # Determinism
//!
//! Nothing in [`Swarm`] reads a clock or a random number generator. BitTorrent
//! picks its optimistic unchoke at random; this rotates it by round number
//! instead, which gives every peer the same eventual turn and makes a transfer a
//! pure function of the messages that arrived. That is what lets the scheduling
//! rules -- rarest-first, endgame, choking -- be tested by asserting on exact
//! output rather than by running a network and hoping.
//!
//! [`tcp`] is where the clock, the sockets and the threads live, and it is the
//! only part of this module that can fail for reasons that are nobody's fault.

pub mod dht;
pub mod discovery;
pub mod piece;
pub mod tcp;
pub mod wire;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use piece::{Bitfield, Manifest, PieceError};
use wire::Message;

pub use dht::{Contact, Lookup, NodeId, ProviderStore, RoutingTable};
pub use discovery::{AddressBook, PeerRecord};
pub use piece::{Layout, Manifest as PieceManifest, DEFAULT_PIECE_LEN};
pub use tcp::{fetch, serve, Listener, TransferError};
pub use wire::{Handshake, WireError};

/// A peer, as this node knows it.
///
/// Assigned by whatever accepted the connection, **never** taken from the
/// handshake. A peer id on the wire is self-asserted and free to forge, so two
/// connections claiming one id are two peers here; the connection is the
/// identity, and the claimed id is a display string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerId(pub u64);

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "peer{}", self.0)
    }
}

/// Why a peer was dropped.
///
/// Every variant is something the peer *did*, not something that went wrong.
/// Transport failures are [`tcp`]'s business and never reach here, for the same
/// reason a verifier that cannot run returns `Unavailable` rather than `Reject`:
/// an infrastructure fact is not evidence about anybody.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dropped {
    /// Offered a manifest for content this swarm is not transferring. Provable
    /// against a digest the log already fixed.
    WrongManifest,
    /// Sent a piece that does not match the manifest. The one failure piece
    /// hashes exist to attribute.
    BadPiece { index: u32 },
    /// Sent a piece nobody asked it for.
    UnsolicitedPiece { index: u32 },
    /// Sent a message that does not decode, or one that makes no sense yet.
    Protocol { detail: String },
    /// Too many peers; this one arrived last.
    TooManyPeers,
}

impl fmt::Display for Dropped {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Dropped::WrongManifest => f.write_str("offered a manifest for other content"),
            Dropped::BadPiece { index } => write!(f, "piece {index} did not match the manifest"),
            Dropped::UnsolicitedPiece { index } => write!(f, "sent piece {index} unrequested"),
            Dropped::Protocol { detail } => write!(f, "protocol error: {detail}"),
            Dropped::TooManyPeers => f.write_str("peer limit reached"),
        }
    }
}

/// What the driver should do next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Put this message on that peer's connection.
    Send(PeerId, Message),
    /// Close that peer's connection, and do not reconnect to it for this blob.
    Drop(PeerId, Dropped),
    /// Every piece has arrived and verified. [`Swarm::finish`] has the bytes.
    Complete,
}

/// Tunables, all of them bounds on what a stranger can make this node do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Outstanding requests per peer. Pipelining: one request at a time wastes a
    /// round trip per piece, and unbounded requests let a peer with a slow link
    /// reserve the whole file and deliver none of it.
    pub max_in_flight: u32,
    /// Peers unchoked at once, the tit-for-tat slots.
    pub unchoke_slots: usize,
    /// Connections accepted for one blob.
    pub max_peers: usize,
    /// Remaining pieces at which endgame starts -- duplicate requests, so the
    /// tail of a transfer is not held up by one slow peer.
    pub endgame_at: u32,
    /// Largest blob this node will start a transfer for.
    ///
    /// Distinct from [`piece::MAX_BLOB_LEN`], which is what the format permits.
    /// This is what *this node* is willing to spend memory on, and it exists
    /// because a manifest is a claim about size made by a stranger.
    pub max_blob: u64,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            max_in_flight: 4,
            unchoke_slots: 4,
            max_peers: 32,
            endgame_at: 4,
            max_blob: 1 << 30,
        }
    }
}

/// One peer's half of the conversation.
#[derive(Debug, Clone)]
struct Peer {
    /// What they say they hold. `None` until a bitfield arrives.
    have: Option<Bitfield>,
    /// They will not serve us.
    chokes_us: bool,
    /// We will not serve them.
    we_choke: bool,
    /// They want something we hold.
    interested_in_us: bool,
    /// We have told them we want something.
    we_interested: bool,
    /// Pieces requested from this peer and not yet delivered.
    in_flight: BTreeSet<u32>,
    /// Verified bytes received. The tit-for-tat currency, and the only thing
    /// unchoking is a function of.
    served_us: u64,
}

impl Peer {
    fn new() -> Peer {
        Peer {
            have: None,
            // Both directions start choked, as in BitTorrent. A connection that
            // began unchoked would serve a peer that has not asked and may not
            // want anything.
            chokes_us: true,
            we_choke: true,
            interested_in_us: false,
            we_interested: false,
            in_flight: BTreeSet::new(),
            served_us: 0,
        }
    }

    fn holds(&self, index: u32) -> bool {
        self.have
            .as_ref()
            .is_some_and(|field| field.contains(index))
    }
}

/// One blob's transfer, as a pure state machine.
///
/// Messages go in, [`Action`]s come out. No sockets, no clock, no randomness --
/// see the module docs for why that is worth the small awkwardness of a driver.
#[derive(Debug, Clone)]
pub struct Swarm {
    digest: String,
    manifest: Option<Manifest>,
    have: Bitfield,
    /// Verified pieces, held individually until the blob is complete.
    ///
    /// **Not** one preallocated buffer of the declared length. A manifest is a
    /// claim about size made by a stranger, and a node that preallocates from it
    /// has let that stranger choose how much memory to use. Holding pieces as
    /// they arrive makes the footprint track what was actually delivered and
    /// verified.
    pieces: BTreeMap<u32, Vec<u8>>,
    peers: BTreeMap<PeerId, Peer>,
    /// How many peers hold each piece. The rarest-first index, maintained
    /// incrementally because recomputing it per request is quadratic in the
    /// swarm and this runs on every scheduling decision.
    availability: Vec<u32>,
    limits: Limits,
    round: u64,
    complete: bool,
}

impl Swarm {
    /// A swarm for a blob this node wants, with no manifest yet.
    pub fn leech(digest: impl Into<String>, limits: Limits) -> Swarm {
        Swarm {
            digest: digest.into(),
            manifest: None,
            // A placeholder until the manifest fixes the piece count. Nothing
            // consults it before then: `on_message` refuses bitfields and pieces
            // while `manifest` is `None`.
            have: Bitfield::new(0),
            pieces: BTreeMap::new(),
            peers: BTreeMap::new(),
            availability: Vec::new(),
            limits,
            round: 0,
            complete: false,
        }
    }

    /// A swarm for a blob this node already holds in full.
    pub fn seed(data: &[u8], piece_len: u32, limits: Limits) -> Result<Swarm, PieceError> {
        let manifest = Manifest::of(data, piece_len)?;
        let pieces = (0..manifest.pieces())
            .map(|index| {
                (
                    index,
                    manifest.layout().slice(data, index).unwrap_or(&[]).to_vec(),
                )
            })
            .collect();
        let count = manifest.pieces();
        Ok(Swarm {
            digest: manifest.digest().to_string(),
            have: Bitfield::full(count),
            manifest: Some(manifest),
            pieces,
            peers: BTreeMap::new(),
            availability: vec![0; count as usize],
            limits,
            round: 0,
            complete: true,
        })
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn manifest(&self) -> Option<&Manifest> {
        self.manifest.as_ref()
    }

    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// Pieces held out of pieces known, or `None` before the manifest arrives.
    pub fn progress(&self) -> Option<(u32, u32)> {
        self.manifest
            .as_ref()
            .map(|manifest| (self.have.count(), manifest.pieces()))
    }

    pub fn is_complete(&self) -> bool {
        self.manifest.is_some() && self.complete
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// The assembled blob, once every piece has arrived and verified.
    ///
    /// Re-checks the whole digest rather than trusting that verified pieces
    /// compose into the right blob. They do -- but the cheap check at the end is
    /// what makes a *bad manifest* a caught error rather than a silent one, and
    /// the manifest is the one input here that nothing else validates.
    pub fn finish(&self) -> Option<Vec<u8>> {
        let manifest = self.manifest.as_ref()?;
        if !self.have.is_complete() {
            return None;
        }
        let mut out = Vec::with_capacity(self.pieces.values().map(Vec::len).sum());
        for index in 0..manifest.pieces() {
            out.extend_from_slice(self.pieces.get(&index)?);
        }
        if !manifest.describes(&crate::canonical::digest_bytes(&out)) {
            return None;
        }
        Some(out)
    }

    /// Register a connection and emit the opening messages.
    pub fn add_peer(&mut self, peer: PeerId) -> Vec<Action> {
        if self.peers.len() >= self.limits.max_peers {
            return vec![Action::Drop(peer, Dropped::TooManyPeers)];
        }
        self.peers.insert(peer, Peer::new());
        let mut actions = Vec::new();
        match &self.manifest {
            Some(manifest) => {
                // A peer that has the manifest sends it unprompted. It costs one
                // message and saves a round trip on every new connection, and a
                // peer that already had it simply checks that it agrees.
                actions.push(Action::Send(
                    peer,
                    Message::Manifest(Box::new(manifest.clone())),
                ));
                actions.push(Action::Send(peer, Message::Bitfield(self.have.clone())));
            }
            None => actions.push(Action::Send(peer, Message::WantManifest)),
        }
        actions
    }

    /// Forget a peer that has gone away, returning its reservations to the pool.
    ///
    /// The `in_flight` pieces are the point. Dropping a peer without releasing
    /// them leaves those pieces permanently reserved to a connection that no
    /// longer exists, and the transfer stalls a few pieces short of done with
    /// every peer idle -- the classic way this kind of scheduler hangs.
    pub fn remove_peer(&mut self, peer: PeerId) {
        if let Some(state) = self.peers.remove(&peer) {
            if let Some(field) = state.have {
                for index in 0..field.len() {
                    if field.contains(index) {
                        self.decrement(index);
                    }
                }
            }
        }
    }

    /// Handle one message from one peer.
    pub fn on_message(&mut self, peer: PeerId, message: Message) -> Vec<Action> {
        if !self.peers.contains_key(&peer) {
            return Vec::new();
        }
        match message {
            Message::WantManifest => match &self.manifest {
                Some(manifest) => vec![Action::Send(
                    peer,
                    Message::Manifest(Box::new(manifest.clone())),
                )],
                // Two leeches meeting. Neither can help, and neither has done
                // anything wrong, so nobody is dropped.
                None => Vec::new(),
            },
            Message::Manifest(manifest) => self.on_manifest(peer, *manifest),
            Message::Bitfield(field) => self.on_bitfield(peer, field),
            Message::Have(index) => self.on_have(peer, index),
            Message::Interested(yes) => {
                if let Some(state) = self.peers.get_mut(&peer) {
                    state.interested_in_us = yes;
                }
                Vec::new()
            }
            Message::Choke(yes) => {
                if let Some(state) = self.peers.get_mut(&peer) {
                    state.chokes_us = yes;
                    if yes {
                        // A choke cancels everything outstanding. Leaving the
                        // requests booked would reserve pieces against a peer
                        // that has just said it will not answer.
                        state.in_flight.clear();
                    }
                }
                self.schedule()
            }
            Message::Request(index) => self.on_request(peer, index),
            Message::Cancel(_) => Vec::new(),
            Message::Piece { index, bytes } => self.on_piece(peer, index, bytes),
            // Peer exchange is about the *node*, not about this blob, so it is
            // handled by the driver that owns the address book. A swarm holding
            // one would be a per-blob copy of node-wide state, which is how two
            // views of the same peers start disagreeing.
            // Peer exchange and DHT routing are about the *node*, not this
            // blob, so the driver that owns the routing table handles them. A
            // swarm holding one would be a per-blob copy of node-wide state,
            // which is how two views of the same network start disagreeing.
            Message::WantPeers
            | Message::Peers(_)
            | Message::FindNode { .. }
            | Message::Nodes { .. }
            | Message::Announce { .. } => Vec::new(),
        }
    }

    /// A protocol failure the driver detected while decoding.
    pub fn on_protocol_error(&self, peer: PeerId, detail: impl Into<String>) -> Vec<Action> {
        vec![Action::Drop(
            peer,
            Dropped::Protocol {
                detail: detail.into(),
            },
        )]
    }

    /// Advance the choking round and re-schedule.
    ///
    /// Called periodically by the driver -- every ten seconds in BitTorrent, and
    /// the exact period is the driver's business because it is the one thing
    /// here that needs a clock.
    pub fn tick(&mut self) -> Vec<Action> {
        self.round = self.round.wrapping_add(1);
        let mut actions = self.rechoke();
        actions.extend(self.schedule());
        actions
    }

    // -- message handlers --------------------------------------------------

    fn on_manifest(&mut self, peer: PeerId, manifest: Manifest) -> Vec<Action> {
        if !manifest.describes(&self.digest) {
            // The one lie this protocol can catch instantly, because the log
            // fixed the digest before the transfer began.
            return vec![Action::Drop(peer, Dropped::WrongManifest)];
        }
        if self.manifest.is_some() {
            // Already have one. Two manifests for one digest can legitimately
            // differ in piece length, and the one already in use wins -- there
            // is no dispute to resolve, because both are checkable against the
            // same content.
            return Vec::new();
        }
        if manifest.layout().total() > self.limits.max_blob {
            return vec![Action::Drop(
                peer,
                Dropped::Protocol {
                    detail: format!(
                        "manifest declares {} bytes, above this node's {} limit",
                        manifest.layout().total(),
                        self.limits.max_blob
                    ),
                },
            )];
        }

        let count = manifest.pieces();
        self.have = Bitfield::new(count);
        self.availability = vec![0; count as usize];
        self.complete = false;
        self.manifest = Some(manifest);

        // Everyone connected now needs our (empty) bitfield. Announcing to all
        // rather than just to the sender removes an ordering hazard that would
        // otherwise depend on which peer spoke first.
        let peers: Vec<PeerId> = self.peers.keys().copied().collect();
        let mut actions: Vec<Action> = peers
            .into_iter()
            .map(|other| Action::Send(other, Message::Bitfield(self.have.clone())))
            .collect();
        actions.extend(self.schedule());
        actions
    }

    fn on_bitfield(&mut self, peer: PeerId, field: Bitfield) -> Vec<Action> {
        let Some(manifest) = &self.manifest else {
            // A bitfield before a manifest cannot be sized, so the decoder
            // refused it and this is unreachable through the wire. A no-op
            // rather than a panic, because feeding this state machine directly
            // is a legitimate thing for a caller to do.
            return Vec::new();
        };
        if field.len() != manifest.pieces() {
            return vec![Action::Drop(
                peer,
                Dropped::Protocol {
                    detail: format!(
                        "bitfield of {} pieces against a manifest of {}",
                        field.len(),
                        manifest.pieces()
                    ),
                },
            )];
        }
        let previous = self
            .peers
            .get_mut(&peer)
            .and_then(|state| state.have.replace(field.clone()));
        if let Some(old) = previous {
            for index in 0..old.len() {
                if old.contains(index) {
                    self.decrement(index);
                }
            }
        }
        for index in 0..field.len() {
            if field.contains(index) {
                self.increment(index);
            }
        }
        self.schedule()
    }

    fn on_have(&mut self, peer: PeerId, index: u32) -> Vec<Action> {
        let Some(manifest) = &self.manifest else {
            return Vec::new();
        };
        let pieces = manifest.pieces();
        if index >= pieces {
            return vec![Action::Drop(
                peer,
                Dropped::Protocol {
                    detail: format!("have {index} of {pieces} pieces"),
                },
            )];
        }
        let newly = match self.peers.get_mut(&peer) {
            Some(state) => state
                .have
                .get_or_insert_with(|| Bitfield::new(pieces))
                .insert(index),
            None => false,
        };
        if newly {
            self.increment(index);
        }
        self.schedule()
    }

    fn on_request(&mut self, peer: PeerId, index: u32) -> Vec<Action> {
        // Serving a choked peer would make choking decorative. Silently ignored
        // rather than punished: a request racing an in-flight choke is normal.
        let choked = self.peers.get(&peer).is_none_or(|state| state.we_choke);
        if choked || !self.have.contains(index) {
            return Vec::new();
        }
        match self.pieces.get(&index) {
            Some(bytes) => vec![Action::Send(
                peer,
                Message::Piece {
                    index,
                    bytes: bytes.clone(),
                },
            )],
            None => Vec::new(),
        }
    }

    fn on_piece(&mut self, peer: PeerId, index: u32, bytes: Vec<u8>) -> Vec<Action> {
        let Some(manifest) = self.manifest.clone() else {
            return vec![Action::Drop(
                peer,
                Dropped::Protocol {
                    detail: "piece before manifest".to_string(),
                },
            )];
        };
        let requested = self
            .peers
            .get_mut(&peer)
            .is_some_and(|state| state.in_flight.remove(&index));
        if !requested {
            // Unsolicited data is how a peer makes a node spend memory it never
            // agreed to spend, so it costs the connection.
            return vec![Action::Drop(peer, Dropped::UnsolicitedPiece { index })];
        }
        if self.have.contains(index) {
            // An endgame duplicate that lost the race. Not misbehaviour, and the
            // bytes are simply dropped.
            return self.schedule();
        }
        if !manifest.verify_piece(index, &bytes) {
            // The whole reason piece hashes exist: a lie localised to one piece
            // and one peer, with the rest of the transfer unaffected.
            return vec![Action::Drop(peer, Dropped::BadPiece { index })];
        }

        let len = bytes.len() as u64;
        if let Some(state) = self.peers.get_mut(&peer) {
            state.served_us = state.served_us.saturating_add(len);
        }
        self.pieces.insert(index, bytes);
        self.have.insert(index);

        // Announce to everyone, and cancel the endgame duplicates that are now
        // pointless. Cancelling matters: without it the tail of a transfer costs
        // every peer a redundant piece.
        let mut actions = Vec::new();
        let peers: Vec<PeerId> = self.peers.keys().copied().collect();
        for other in peers {
            actions.push(Action::Send(other, Message::Have(index)));
            let outstanding = self
                .peers
                .get_mut(&other)
                .is_some_and(|state| state.in_flight.remove(&index));
            if outstanding {
                actions.push(Action::Send(other, Message::Cancel(index)));
            }
        }

        if self.have.is_complete() && !self.complete {
            self.complete = true;
            actions.push(Action::Complete);
            return actions;
        }
        actions.extend(self.schedule());
        actions
    }

    // -- scheduling --------------------------------------------------------

    /// Issue requests, and say what we are interested in.
    ///
    /// Rarest-first: of the pieces we lack and a peer holds, ask for the one the
    /// fewest peers have. This is not an optimisation, it is what stops a swarm
    /// converging on a state where one piece exists on a single node and its
    /// departure strands everybody -- the same last-copy failure the availability
    /// mechanism in [`crate::incentive`] pays to prevent, avoided here for free
    /// by choosing what to ask for.
    ///
    /// Ties break on the lowest index so the schedule is a pure function of what
    /// arrived, which is what makes it testable without a network.
    fn schedule(&mut self) -> Vec<Action> {
        let Some(manifest) = &self.manifest else {
            return Vec::new();
        };
        if self.complete {
            return Vec::new();
        }
        let pieces = manifest.pieces();
        let remaining = pieces.saturating_sub(self.have.count());
        let endgame = remaining <= self.limits.endgame_at;

        // Pieces already booked. In endgame this is deliberately ignored, so the
        // tail is asked for more than once and one slow peer cannot hold the
        // whole transfer at 99%.
        let mut booked: BTreeSet<u32> = BTreeSet::new();
        if !endgame {
            for state in self.peers.values() {
                booked.extend(state.in_flight.iter().copied());
            }
        }

        let mut actions = Vec::new();
        let peer_ids: Vec<PeerId> = self.peers.keys().copied().collect();
        for peer in peer_ids {
            let Some(state) = self.peers.get(&peer) else {
                continue;
            };
            // Interest is about the peer's whole holding, not about what we can
            // ask for now -- a choked peer still needs to know we want something,
            // or it will never have a reason to unchoke us.
            let wants = (0..pieces).any(|index| !self.have.contains(index) && state.holds(index));
            if wants != state.we_interested {
                actions.push(Action::Send(peer, Message::Interested(wants)));
                if let Some(state) = self.peers.get_mut(&peer) {
                    state.we_interested = wants;
                }
            }
            let Some(state) = self.peers.get(&peer) else {
                continue;
            };
            if state.chokes_us || !wants {
                continue;
            }

            let mut in_flight = state.in_flight.len() as u32;
            while in_flight < self.limits.max_in_flight {
                let Some(index) = self.rarest(peer, &booked) else {
                    break;
                };
                booked.insert(index);
                if let Some(state) = self.peers.get_mut(&peer) {
                    state.in_flight.insert(index);
                }
                actions.push(Action::Send(peer, Message::Request(index)));
                in_flight += 1;
            }
        }
        actions
    }

    /// The piece this peer holds, we lack, and fewest peers have.
    fn rarest(&self, peer: PeerId, booked: &BTreeSet<u32>) -> Option<u32> {
        let state = self.peers.get(&peer)?;
        let mut best: Option<(u32, u32)> = None;
        for index in 0..self.have.len() {
            if self.have.contains(index) || booked.contains(&index) || !state.holds(index) {
                continue;
            }
            if state.in_flight.contains(&index) {
                continue;
            }
            let count = self.availability.get(index as usize).copied().unwrap_or(0);
            // Strictly less, so ties keep the lowest index and the schedule stays
            // a pure function of what arrived.
            if best.is_none_or(|(_, seen)| count < seen) {
                best = Some((index, count));
            }
        }
        best.map(|(index, _)| index)
    }

    /// Decide who may ask us for pieces this round.
    ///
    /// Tit-for-tat: the peers who have given us the most get the slots. Plus one
    /// rotating slot so a peer that has given us nothing yet -- which is every
    /// peer, once -- gets a chance to start.
    ///
    /// BitTorrent picks that last slot at random. Rotating it by round number
    /// gives the same eventual-turn property and makes a transfer reproducible
    /// from its message history. See the module docs.
    fn rechoke(&mut self) -> Vec<Action> {
        let mut ranked: Vec<(PeerId, u64)> = self
            .peers
            .iter()
            .filter(|(_, state)| state.interested_in_us)
            .map(|(peer, state)| (*peer, state.served_us))
            .collect();
        // Most generous first; PeerId breaks ties so the order is total.
        ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

        let mut unchoked: BTreeSet<PeerId> = ranked
            .iter()
            .take(self.limits.unchoke_slots.saturating_sub(1))
            .map(|(peer, _)| *peer)
            .collect();

        // The optimistic slot, taken from the peers that did not earn one.
        let hopefuls: Vec<PeerId> = ranked
            .iter()
            .map(|(peer, _)| *peer)
            .filter(|peer| !unchoked.contains(peer))
            .collect();
        if !hopefuls.is_empty() {
            let pick = (self.round as usize) % hopefuls.len();
            unchoked.insert(hopefuls[pick]);
        }

        let mut actions = Vec::new();
        let peers: Vec<PeerId> = self.peers.keys().copied().collect();
        for peer in peers {
            let should_choke = !unchoked.contains(&peer);
            let changed = match self.peers.get_mut(&peer) {
                Some(state) if state.we_choke != should_choke => {
                    state.we_choke = should_choke;
                    true
                }
                _ => false,
            };
            if changed {
                actions.push(Action::Send(peer, Message::Choke(should_choke)));
            }
        }
        actions
    }

    fn increment(&mut self, index: u32) {
        if let Some(slot) = self.availability.get_mut(index as usize) {
            *slot = slot.saturating_add(1);
        }
    }

    fn decrement(&mut self, index: u32) {
        if let Some(slot) = self.availability.get_mut(index as usize) {
            *slot = slot.saturating_sub(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::digest_bytes;
    use piece::MIN_PIECE_LEN;

    const PIECE: u32 = MIN_PIECE_LEN;

    fn blob(pieces: usize) -> Vec<u8> {
        (0..PIECE as usize * pieces)
            .map(|i| (i % 251) as u8)
            .collect()
    }

    fn sends(actions: &[Action]) -> Vec<(PeerId, &Message)> {
        actions
            .iter()
            .filter_map(|action| match action {
                Action::Send(peer, message) => Some((*peer, message)),
                _ => None,
            })
            .collect()
    }

    fn requests(actions: &[Action]) -> Vec<(PeerId, u32)> {
        actions
            .iter()
            .filter_map(|action| match action {
                Action::Send(peer, Message::Request(index)) => Some((*peer, *index)),
                _ => None,
            })
            .collect()
    }

    /// Wire a leech to a seed and run to completion, returning the bytes.
    fn transfer(data: &[u8], limits: Limits) -> Option<Vec<u8>> {
        let mut seed = Swarm::seed(data, PIECE, limits).expect("valid");
        let mut leech = Swarm::leech(digest_bytes(data), limits);
        let seed_side = PeerId(1);
        let leech_side = PeerId(2);

        let mut to_leech: Vec<Message> = Vec::new();
        let mut to_seed: Vec<Message> = Vec::new();
        let pump = |actions: Vec<Action>, out: &mut Vec<Message>| {
            for action in actions {
                if let Action::Send(_, message) = action {
                    out.push(message);
                }
            }
        };
        pump(seed.add_peer(leech_side), &mut to_leech);
        pump(leech.add_peer(seed_side), &mut to_seed);

        for _ in 0..10_000 {
            if to_leech.is_empty() && to_seed.is_empty() {
                // Quiet: run a choking round, which is what a real driver does on
                // a timer and the only thing that can unstick a choked start.
                let before = to_leech.len();
                pump(seed.tick(), &mut to_leech);
                pump(leech.tick(), &mut to_seed);
                if to_leech.len() == before && to_seed.is_empty() {
                    break;
                }
            }
            for message in std::mem::take(&mut to_seed) {
                for action in seed.on_message(leech_side, message) {
                    match action {
                        Action::Send(_, message) => to_leech.push(message),
                        Action::Drop(_, why) => panic!("seed dropped the leech: {why}"),
                        Action::Complete => {}
                    }
                }
            }
            for message in std::mem::take(&mut to_leech) {
                for action in leech.on_message(seed_side, message) {
                    match action {
                        Action::Send(_, message) => to_seed.push(message),
                        Action::Drop(_, why) => panic!("leech dropped the seed: {why}"),
                        Action::Complete => return leech.finish(),
                    }
                }
            }
        }
        leech.finish()
    }

    #[test]
    fn a_leech_pulls_a_whole_blob_from_a_seed() {
        let data = blob(5);
        assert_eq!(transfer(&data, Limits::default()), Some(data.clone()));
    }

    #[test]
    fn a_blob_with_a_short_last_piece_transfers_intact() {
        // The off-by-one a fixed-size test never catches.
        let mut data = blob(3);
        data.extend_from_slice(b"tail");
        assert_eq!(transfer(&data, Limits::default()), Some(data.clone()));
    }

    #[test]
    fn a_single_piece_blob_transfers() {
        let data = b"def score(artifact):\n    return 0\n".to_vec();
        assert_eq!(transfer(&data, Limits::default()), Some(data.clone()));
    }

    #[test]
    fn the_empty_blob_transfers() {
        assert_eq!(transfer(&[], Limits::default()), Some(Vec::new()));
    }

    #[test]
    fn a_manifest_for_other_content_is_caught_on_arrival() {
        // The advantage this network has over BitTorrent, as a test: the log
        // fixed the digest before the transfer began, so a wrong manifest costs
        // a connection rather than a download.
        let mut leech = Swarm::leech(digest_bytes(b"what we want"), Limits::default());
        leech.add_peer(PeerId(1));
        let liar = Manifest::of(b"something else entirely", PIECE).expect("valid");
        assert_eq!(
            leech.on_message(PeerId(1), Message::Manifest(Box::new(liar))),
            vec![Action::Drop(PeerId(1), Dropped::WrongManifest)]
        );
        assert!(leech.manifest().is_none(), "and nothing was adopted");
    }

    #[test]
    fn a_manifest_above_this_nodes_limit_is_refused() {
        // A manifest is a claim about size made by a stranger. The format allows
        // 64 GiB; what this node will spend memory on is its own decision.
        let data = blob(2);
        let limits = Limits {
            max_blob: 1,
            ..Limits::default()
        };
        let mut leech = Swarm::leech(digest_bytes(&data), limits);
        leech.add_peer(PeerId(1));
        let manifest = Manifest::of(&data, PIECE).expect("valid");
        assert!(matches!(
            leech
                .on_message(PeerId(1), Message::Manifest(Box::new(manifest)))
                .as_slice(),
            [Action::Drop(_, Dropped::Protocol { .. })]
        ));
    }

    #[test]
    fn a_bad_piece_costs_the_peer_and_not_the_transfer() {
        // What piece hashes are actually for. The lie is localised to one piece
        // and one peer; every other piece and every other peer is unaffected.
        let data = blob(3);
        let manifest = Manifest::of(&data, PIECE).expect("valid");
        let mut leech = Swarm::leech(digest_bytes(&data), Limits::default());
        leech.add_peer(PeerId(1));
        leech.on_message(PeerId(1), Message::Manifest(Box::new(manifest.clone())));
        leech.on_message(
            PeerId(1),
            Message::Bitfield(Bitfield::full(manifest.pieces())),
        );
        let actions = leech.on_message(PeerId(1), Message::Choke(false));
        let asked = requests(&actions);
        assert!(!asked.is_empty(), "an unchoked peer with pieces gets asked");

        let (peer, index) = asked[0];
        let dropped = leech.on_message(
            peer,
            Message::Piece {
                index,
                bytes: vec![0; PIECE as usize],
            },
        );
        assert_eq!(
            dropped,
            vec![Action::Drop(peer, Dropped::BadPiece { index })]
        );
        assert_eq!(leech.progress(), Some((0, 3)), "and nothing was accepted");
    }

    #[test]
    fn an_unsolicited_piece_costs_the_connection() {
        // How a peer would otherwise make a node spend memory it never agreed
        // to spend.
        let data = blob(2);
        let manifest = Manifest::of(&data, PIECE).expect("valid");
        let mut leech = Swarm::leech(digest_bytes(&data), Limits::default());
        leech.add_peer(PeerId(1));
        leech.on_message(PeerId(1), Message::Manifest(Box::new(manifest.clone())));
        let piece = manifest
            .layout()
            .slice(&data, 0)
            .expect("in range")
            .to_vec();
        assert_eq!(
            leech.on_message(
                PeerId(1),
                Message::Piece {
                    index: 0,
                    bytes: piece
                }
            ),
            vec![Action::Drop(
                PeerId(1),
                Dropped::UnsolicitedPiece { index: 0 }
            )],
            "even a *valid* piece nobody asked for"
        );
    }

    #[test]
    fn requests_go_to_the_rarest_piece_first() {
        // Not an optimisation: it is what stops a swarm converging on a state
        // where one piece lives on a single node whose departure strands
        // everybody.
        let data = blob(4);
        let manifest = Manifest::of(&data, PIECE).expect("valid");
        let mut leech = Swarm::leech(
            digest_bytes(&data),
            Limits {
                max_in_flight: 1,
                ..Limits::default()
            },
        );
        for peer in 1..=3 {
            leech.add_peer(PeerId(peer));
        }
        leech.on_message(PeerId(1), Message::Manifest(Box::new(manifest.clone())));

        // Pieces 0,1,2 are common; piece 3 is held by one peer only.
        let mut common = Bitfield::new(4);
        common.insert(0);
        common.insert(1);
        common.insert(2);
        leech.on_message(PeerId(1), Message::Bitfield(Bitfield::full(4)));
        leech.on_message(PeerId(2), Message::Bitfield(common.clone()));
        leech.on_message(PeerId(3), Message::Bitfield(common));

        let actions = leech.on_message(PeerId(1), Message::Choke(false));
        assert_eq!(
            requests(&actions),
            vec![(PeerId(1), 3)],
            "the piece only one peer holds is asked for first"
        );
    }

    #[test]
    fn pipelining_is_bounded_and_two_peers_are_not_asked_for_the_same_piece() {
        let data = blob(8);
        let manifest = Manifest::of(&data, PIECE).expect("valid");
        let limits = Limits {
            max_in_flight: 2,
            endgame_at: 0,
            ..Limits::default()
        };
        let mut leech = Swarm::leech(digest_bytes(&data), limits);
        leech.add_peer(PeerId(1));
        leech.add_peer(PeerId(2));
        leech.on_message(PeerId(1), Message::Manifest(Box::new(manifest.clone())));
        leech.on_message(PeerId(1), Message::Bitfield(Bitfield::full(8)));
        leech.on_message(PeerId(2), Message::Bitfield(Bitfield::full(8)));

        let mut asked: Vec<u32> = Vec::new();
        for peer in [PeerId(1), PeerId(2)] {
            let actions = leech.on_message(peer, Message::Choke(false));
            let mine: Vec<u32> = requests(&actions)
                .into_iter()
                .filter(|(who, _)| *who == peer)
                .map(|(_, index)| index)
                .collect();
            assert!(
                mine.len() <= limits.max_in_flight as usize,
                "pipelining is bounded"
            );
            asked.extend(mine);
        }
        let unique: BTreeSet<u32> = asked.iter().copied().collect();
        assert_eq!(
            unique.len(),
            asked.len(),
            "outside endgame, no piece is booked twice"
        );
    }

    #[test]
    fn endgame_duplicates_the_tail_and_cancels_the_losers() {
        // The last few pieces are where a transfer stalls behind one slow peer.
        let data = blob(3);
        let manifest = Manifest::of(&data, PIECE).expect("valid");
        let limits = Limits {
            max_in_flight: 1,
            endgame_at: 8,
            ..Limits::default()
        };
        let mut leech = Swarm::leech(digest_bytes(&data), limits);
        leech.add_peer(PeerId(1));
        leech.add_peer(PeerId(2));
        leech.on_message(PeerId(1), Message::Manifest(Box::new(manifest.clone())));
        leech.on_message(PeerId(1), Message::Bitfield(Bitfield::full(3)));
        leech.on_message(PeerId(2), Message::Bitfield(Bitfield::full(3)));

        let first = leech.on_message(PeerId(1), Message::Choke(false));
        let second = leech.on_message(PeerId(2), Message::Choke(false));
        let a = requests(&first);
        let b = requests(&second);
        assert_eq!(a.len(), 1);
        assert_eq!(b.len(), 1);
        assert_eq!(
            a[0].1, b[0].1,
            "in endgame both peers are asked for the same piece"
        );

        let index = a[0].1;
        let bytes = manifest
            .layout()
            .slice(&data, index)
            .expect("in range")
            .to_vec();
        let actions = leech.on_message(PeerId(1), Message::Piece { index, bytes });
        assert!(
            sends(&actions)
                .iter()
                .any(|(peer, message)| *peer == PeerId(2) && **message == Message::Cancel(index)),
            "the loser is cancelled rather than left to send a redundant piece"
        );
    }

    #[test]
    fn a_departing_peer_releases_the_pieces_it_had_reserved() {
        // The classic way this kind of scheduler hangs: a few pieces short of
        // done, every peer idle, every remaining piece booked to a connection
        // that no longer exists.
        let data = blob(4);
        let manifest = Manifest::of(&data, PIECE).expect("valid");
        let limits = Limits {
            max_in_flight: 4,
            endgame_at: 0,
            ..Limits::default()
        };
        let mut leech = Swarm::leech(digest_bytes(&data), limits);
        leech.add_peer(PeerId(1));
        leech.add_peer(PeerId(2));
        leech.on_message(PeerId(1), Message::Manifest(Box::new(manifest.clone())));
        leech.on_message(PeerId(1), Message::Bitfield(Bitfield::full(4)));
        leech.on_message(PeerId(2), Message::Bitfield(Bitfield::full(4)));

        let booked = requests(&leech.on_message(PeerId(1), Message::Choke(false)));
        assert_eq!(booked.len(), 4, "peer 1 reserved everything");
        assert!(
            requests(&leech.on_message(PeerId(2), Message::Choke(false))).is_empty(),
            "so peer 2 has nothing left to ask for"
        );

        leech.remove_peer(PeerId(1));
        let after = requests(&leech.tick());
        assert_eq!(after.len(), 4, "and the pieces return to the pool");
        assert!(after.iter().all(|(peer, _)| *peer == PeerId(2)));
    }

    #[test]
    fn a_choke_releases_reservations_too() {
        let data = blob(4);
        let manifest = Manifest::of(&data, PIECE).expect("valid");
        let limits = Limits {
            max_in_flight: 4,
            endgame_at: 0,
            ..Limits::default()
        };
        let mut leech = Swarm::leech(digest_bytes(&data), limits);
        leech.add_peer(PeerId(1));
        leech.add_peer(PeerId(2));
        leech.on_message(PeerId(1), Message::Manifest(Box::new(manifest.clone())));
        leech.on_message(PeerId(1), Message::Bitfield(Bitfield::full(4)));
        leech.on_message(PeerId(2), Message::Bitfield(Bitfield::full(4)));
        leech.on_message(PeerId(1), Message::Choke(false));

        // Peer 1 books everything, then says it will not answer after all.
        let after = requests(&leech.on_message(PeerId(1), Message::Choke(true)));
        assert!(after.is_empty(), "peer 1 is choked and asks for nothing");
        let moved = requests(&leech.on_message(PeerId(2), Message::Choke(false)));
        assert_eq!(moved.len(), 4, "the work moves to the peer that will serve");
    }

    #[test]
    fn tit_for_tat_unchokes_the_peers_that_gave_the_most() {
        let data = blob(2);
        let limits = Limits {
            unchoke_slots: 2,
            ..Limits::default()
        };
        let mut swarm = Swarm::seed(&data, PIECE, limits).expect("valid");
        for peer in 1..=4 {
            swarm.add_peer(PeerId(peer));
            swarm.on_message(PeerId(peer), Message::Interested(true));
        }
        // Peer 3 has been the most generous, peer 4 next.
        swarm.peers.get_mut(&PeerId(3)).expect("present").served_us = 900;
        swarm.peers.get_mut(&PeerId(4)).expect("present").served_us = 400;

        let actions = swarm.tick();
        let unchoked: BTreeSet<PeerId> = actions
            .iter()
            .filter_map(|action| match action {
                Action::Send(peer, Message::Choke(false)) => Some(*peer),
                _ => None,
            })
            .collect();
        assert!(
            unchoked.contains(&PeerId(3)),
            "the best contributor is served"
        );
        assert_eq!(unchoked.len(), 2, "one earned slot and one optimistic slot");
    }

    #[test]
    fn the_optimistic_slot_rotates_so_every_peer_gets_a_turn() {
        // BitTorrent picks this at random. Rotating by round number gives the
        // same eventual-turn property and keeps a transfer reproducible from its
        // message history.
        let data = blob(2);
        let limits = Limits {
            unchoke_slots: 1,
            ..Limits::default()
        };
        let mut swarm = Swarm::seed(&data, PIECE, limits).expect("valid");
        for peer in 1..=3 {
            swarm.add_peer(PeerId(peer));
            swarm.on_message(PeerId(peer), Message::Interested(true));
        }
        let mut seen: BTreeSet<PeerId> = BTreeSet::new();
        for _ in 0..6 {
            for action in swarm.tick() {
                if let Action::Send(peer, Message::Choke(false)) = action {
                    seen.insert(peer);
                }
            }
        }
        assert_eq!(seen.len(), 3, "every peer is eventually given a chance");
    }

    #[test]
    fn a_seed_serves_only_unchoked_peers() {
        let data = blob(2);
        let manifest = Manifest::of(&data, PIECE).expect("valid");
        let mut seed = Swarm::seed(&data, PIECE, Limits::default()).expect("valid");
        seed.add_peer(PeerId(1));
        assert!(
            seed.on_message(PeerId(1), Message::Request(0)).is_empty(),
            "a choked peer gets nothing, or choking is decorative"
        );

        seed.on_message(PeerId(1), Message::Interested(true));
        seed.tick();
        let served = seed.on_message(PeerId(1), Message::Request(0));
        assert_eq!(
            served,
            vec![Action::Send(
                PeerId(1),
                Message::Piece {
                    index: 0,
                    bytes: manifest
                        .layout()
                        .slice(&data, 0)
                        .expect("in range")
                        .to_vec()
                }
            )]
        );
        assert!(
            seed.on_message(PeerId(1), Message::Request(99)).is_empty(),
            "and a request past the end is ignored rather than panicking"
        );
    }

    #[test]
    fn the_peer_limit_is_enforced() {
        let data = blob(1);
        let limits = Limits {
            max_peers: 2,
            ..Limits::default()
        };
        let mut swarm = Swarm::seed(&data, PIECE, limits).expect("valid");
        swarm.add_peer(PeerId(1));
        swarm.add_peer(PeerId(2));
        assert_eq!(
            swarm.add_peer(PeerId(3)),
            vec![Action::Drop(PeerId(3), Dropped::TooManyPeers)]
        );
        assert_eq!(swarm.peer_count(), 2);
    }

    #[test]
    fn two_leeches_meeting_do_not_punish_each_other() {
        // Neither can help and neither has misbehaved.
        let mut a = Swarm::leech(digest_bytes(b"x"), Limits::default());
        a.add_peer(PeerId(1));
        assert!(a.on_message(PeerId(1), Message::WantManifest).is_empty());
    }

    #[test]
    fn finish_refuses_to_hand_back_an_incomplete_or_unstarted_blob() {
        // Verified pieces do compose into the right blob -- but the manifest is
        // the one input nothing else validates, so the cheap check at the end is
        // what makes a bad manifest a caught error rather than a silent one.
        let data = blob(2);
        let mut leech = Swarm::leech(digest_bytes(&data), Limits::default());
        assert_eq!(leech.finish(), None, "nothing before a manifest");
        leech.add_peer(PeerId(1));
        leech.on_message(
            PeerId(1),
            Message::Manifest(Box::new(Manifest::of(&data, PIECE).expect("valid"))),
        );
        assert_eq!(leech.finish(), None, "nothing before the pieces");
    }
}
