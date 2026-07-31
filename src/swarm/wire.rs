//! The message set two peers exchange, and its framing.
//!
//! Length-prefixed binary frames, in the BitTorrent shape and with the same
//! division of labour: a handshake that names what is being transferred, a
//! bitfield exchanged once, `have` announcements as pieces land, `interested` /
//! `choke` to negotiate who may ask, and `request` / `piece` to move bytes.
//!
//! # Why not the canonical JSON encoder
//!
//! [`crate::canonical`] is the identity format: it exists so two implementations
//! in different languages hash the same bytes, and every design choice in it
//! serves that. None of those choices help here. A `piece` message is a quarter
//! megabyte of arbitrary binary, which JSON can only carry base64-encoded at a
//! third again the size, and nothing on this path is hashed *as a message* --
//! what gets hashed is the piece content, by [`super::piece::Manifest`], in a
//! format the canonical encoder already defines.
//!
//! So this is a wire format, not a record format, and the distinction is worth
//! keeping sharp: **nothing encoded here is ever an identity.** A manifest
//! travels as its canonical JSON *inside* a frame, because that one is a record.
//!
//! # Decoding is the attack surface
//!
//! Every frame arrives from a stranger. Three rules, each of which is a class of
//! bug that has sunk a peer-to-peer implementation before:
//!
//! - **The length prefix is checked before anything is allocated.** A four-byte
//!   header claiming 4 GiB must cost four bytes of work, not four gigabytes of
//!   memory. [`MAX_FRAME`] is derived from the largest legal piece rather than
//!   picked, so the two cannot drift apart.
//! - **Every field is bounds-checked against the frame, not the claim.** A
//!   truncated frame is a decode failure, never a short read of whatever
//!   happened to be next in the buffer.
//! - **Unknown tags are refused rather than skipped.** This protocol has no
//!   version negotiation yet, so a tolerant decoder would be guessing at a
//!   meaning it does not have. Refusing is the honest answer and leaves room to
//!   add one deliberately.

use std::fmt;

use super::piece::{Bitfield, Manifest, MAX_PIECE_LEN};
use crate::canonical::Value;

/// Protocol identifier, sent first and matched exactly.
pub const PROTOCOL: &[u8; 8] = b"pwswarm1";

/// Largest frame body this decoder will accept.
///
/// The biggest legal message is a `Piece`: one tag, a four-byte index, and up to
/// [`MAX_PIECE_LEN`] of content. The slack covers the manifest, whose size is
/// bounded by the piece count and is far smaller than this at any legal piece
/// length. Derived rather than chosen, so raising `MAX_PIECE_LEN` cannot leave a
/// frame limit behind that silently rejects legal traffic.
pub const MAX_FRAME: usize = MAX_PIECE_LEN as usize + 1024;

/// Bytes a peer identifier occupies on the wire.
pub const PEER_ID_LEN: usize = 20;

/// A frame that cannot be decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// The frame body exceeds [`MAX_FRAME`].
    TooLong { declared: usize },
    /// The frame ended in the middle of a field.
    Truncated { message: &'static str },
    /// A tag byte this build does not know.
    UnknownTag(u8),
    /// Trailing bytes after a complete message.
    ///
    /// Refused rather than ignored: two encodings of one message is exactly what
    /// the canonical format exists to prevent, and a wire format gets the same
    /// treatment even though nothing here is hashed.
    Trailing { message: &'static str, extra: usize },
    /// The peer speaks something else.
    NotOurProtocol,
    /// A bitfield whose byte count or padding is wrong for the piece count.
    BadBitfield,
    /// A manifest that is not valid JSON, or not a valid manifest.
    BadManifest,
    /// A peer-exchange answer that is not a list of signed records.
    BadPeers,
    /// A string field that is not UTF-8.
    NotUnicode { message: &'static str },
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireError::TooLong { declared } => {
                write!(f, "frame of {declared} bytes exceeds the {MAX_FRAME} limit")
            }
            WireError::Truncated { message } => write!(f, "{message} frame ended early"),
            WireError::UnknownTag(tag) => write!(
                f,
                "unknown message tag {tag}; this build has no version negotiation, \
                 so an unrecognised message is refused rather than guessed at"
            ),
            WireError::Trailing { message, extra } => {
                write!(f, "{extra} trailing bytes after a complete {message} frame")
            }
            WireError::NotOurProtocol => write!(
                f,
                "peer is not speaking {}",
                String::from_utf8_lossy(PROTOCOL)
            ),
            WireError::BadBitfield => write!(f, "bitfield does not match the piece count"),
            WireError::BadManifest => write!(f, "manifest is not decodable"),
            WireError::BadPeers => write!(f, "peer list is not decodable"),
            WireError::NotUnicode { message } => write!(f, "{message} carried a non-UTF-8 string"),
        }
    }
}

impl std::error::Error for WireError {}

/// The opening message, which names what the connection is for.
///
/// Carries the blob digest rather than a swarm id, because the digest *is* the
/// swarm id -- there is no tracker to allocate one and no metainfo to hash. A
/// peer that opens with a digest this node does not want is answered and dropped
/// rather than served, which is a policy decision and lives in [`super::Swarm`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handshake {
    pub digest: String,
    pub peer_id: [u8; PEER_ID_LEN],
}

impl Handshake {
    /// Fixed-width encoding: protocol tag, then a 32-byte digest as raw hex
    /// bytes, then the peer id. Fixed width because a handshake is the one
    /// message read before the peer has proved anything at all, and a
    /// length-prefixed field there is a length a stranger chose.
    pub fn encode(&self) -> Vec<u8> {
        let hex = self.digest.strip_prefix("sha256:").unwrap_or(&self.digest);
        let mut out = Vec::with_capacity(PROTOCOL.len() + 64 + PEER_ID_LEN);
        out.extend_from_slice(PROTOCOL);
        let mut padded = [b'0'; 64];
        let bytes = hex.as_bytes();
        padded[..bytes.len().min(64)].copy_from_slice(&bytes[..bytes.len().min(64)]);
        out.extend_from_slice(&padded);
        out.extend_from_slice(&self.peer_id);
        out
    }

    pub const LEN: usize = PROTOCOL.len() + 64 + PEER_ID_LEN;

    pub fn decode(bytes: &[u8]) -> Result<Handshake, WireError> {
        if bytes.len() != Handshake::LEN {
            return Err(WireError::Truncated {
                message: "handshake",
            });
        }
        if &bytes[..PROTOCOL.len()] != PROTOCOL {
            return Err(WireError::NotOurProtocol);
        }
        let hex =
            std::str::from_utf8(&bytes[PROTOCOL.len()..PROTOCOL.len() + 64]).map_err(|_| {
                WireError::NotUnicode {
                    message: "handshake",
                }
            })?;
        if !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(WireError::NotUnicode {
                message: "handshake",
            });
        }
        let mut peer_id = [0u8; PEER_ID_LEN];
        peer_id.copy_from_slice(&bytes[PROTOCOL.len() + 64..]);
        Ok(Handshake {
            digest: format!("sha256:{hex}"),
            peer_id,
        })
    }
}

/// Everything a peer can say after the handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// "Here is the piece map of this blob." Sent by whoever has it, in answer
    /// to [`Message::WantManifest`] or unprompted by a seed.
    Manifest(Box<Manifest>),
    /// "I do not have the manifest yet." A leech's first move.
    WantManifest,
    /// "These are the pieces I hold." Sent once, immediately after the manifest
    /// is known, and superseded by `Have` afterwards.
    Bitfield(Bitfield),
    /// "I now hold this piece." The incremental form, and the one that keeps
    /// rarest-first counts current.
    Have(u32),
    /// "I want something you have." / "I no longer do."
    Interested(bool),
    /// "You may not ask me for pieces." / "You may."
    Choke(bool),
    /// "Send me this piece."
    Request(u32),
    /// "Never mind." Endgame sends duplicate requests; this withdraws the losers.
    Cancel(u32),
    /// "Here it is."
    Piece { index: u32, bytes: Vec<u8> },
    /// "Tell me about other peers." Peer exchange, which is what reduces
    /// bootstrap from a recurring problem to a once-ever one.
    WantPeers,
    /// Signed peer records, relayable because each one carries its own proof.
    ///
    /// Not `Vec<PeerRecord>`: the *signed* form is what travels, so a node that
    /// relays a record is passing on evidence rather than hearsay. See
    /// [`super::discovery`].
    Peers(Vec<crate::crypto::identity::SignedRecord>),
    /// Kademlia `FIND_NODE` / `GET_PROVIDERS`, which are one message here.
    ///
    /// A single round trip returns both the contacts nearest the key *and* any
    /// providers known for it, because a lookup wants both and splitting them
    /// would double the hops for no gain -- the answering node consults one
    /// routing table either way.
    FindNode { key: [u8; 32] },
    /// The answer: contacts nearer the key, and who is known to hold it.
    ///
    /// Both are signed records, so the whole answer is relayable evidence and a
    /// hostile hop can withhold but not substitute.
    Nodes {
        closer: Vec<crate::crypto::identity::SignedRecord>,
        providers: Vec<crate::crypto::identity::SignedRecord>,
    },
    /// "I hold this key." A provider announcement, signed by the announcer.
    Announce { key: [u8; 32] },
}

// Tags. Explicit rather than derived from declaration order, because a wire
// format whose numbering moves when somebody reorders an enum is a wire format
// that breaks silently between two versions of the same code.
const TAG_MANIFEST: u8 = 1;
const TAG_WANT_MANIFEST: u8 = 2;
const TAG_BITFIELD: u8 = 3;
const TAG_HAVE: u8 = 4;
const TAG_INTERESTED: u8 = 5;
const TAG_NOT_INTERESTED: u8 = 6;
const TAG_CHOKE: u8 = 7;
const TAG_UNCHOKE: u8 = 8;
const TAG_REQUEST: u8 = 9;
const TAG_CANCEL: u8 = 10;
const TAG_PIECE: u8 = 11;
const TAG_WANT_PEERS: u8 = 12;
const TAG_PEERS: u8 = 13;
const TAG_FIND_NODE: u8 = 14;
const TAG_NODES: u8 = 15;
const TAG_ANNOUNCE: u8 = 16;

impl Message {
    /// A name for logs and errors.
    pub fn name(&self) -> &'static str {
        match self {
            Message::Manifest(_) => "manifest",
            Message::WantManifest => "want-manifest",
            Message::Bitfield(_) => "bitfield",
            Message::Have(_) => "have",
            Message::Interested(_) => "interested",
            Message::Choke(_) => "choke",
            Message::Request(_) => "request",
            Message::Cancel(_) => "cancel",
            Message::Piece { .. } => "piece",
            Message::WantPeers => "want-peers",
            Message::Peers(_) => "peers",
            Message::FindNode { .. } => "find-node",
            Message::Nodes { .. } => "nodes",
            Message::Announce { .. } => "announce",
        }
    }

    /// Encode the body, without the length prefix.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Message::Manifest(manifest) => {
                out.push(TAG_MANIFEST);
                out.extend_from_slice(&manifest.to_value().canonical_bytes());
            }
            Message::WantManifest => out.push(TAG_WANT_MANIFEST),
            Message::Bitfield(field) => {
                out.push(TAG_BITFIELD);
                out.extend_from_slice(field.as_bytes());
            }
            Message::Have(index) => {
                out.push(TAG_HAVE);
                out.extend_from_slice(&index.to_be_bytes());
            }
            Message::Interested(yes) => out.push(if *yes {
                TAG_INTERESTED
            } else {
                TAG_NOT_INTERESTED
            }),
            Message::Choke(yes) => out.push(if *yes { TAG_CHOKE } else { TAG_UNCHOKE }),
            Message::Request(index) => {
                out.push(TAG_REQUEST);
                out.extend_from_slice(&index.to_be_bytes());
            }
            Message::Cancel(index) => {
                out.push(TAG_CANCEL);
                out.extend_from_slice(&index.to_be_bytes());
            }
            Message::Piece { index, bytes } => {
                out.push(TAG_PIECE);
                out.extend_from_slice(&index.to_be_bytes());
                out.extend_from_slice(bytes);
            }
            Message::WantPeers => out.push(TAG_WANT_PEERS),
            Message::Peers(records) => {
                out.push(TAG_PEERS);
                let body = Value::array(records.iter().map(|r| r.to_value()));
                out.extend_from_slice(&body.canonical_bytes());
            }
            Message::FindNode { key } => {
                out.push(TAG_FIND_NODE);
                out.extend_from_slice(key);
            }
            Message::Nodes { closer, providers } => {
                out.push(TAG_NODES);
                let body = Value::object([
                    ("closer", Value::array(closer.iter().map(|r| r.to_value()))),
                    (
                        "providers",
                        Value::array(providers.iter().map(|r| r.to_value())),
                    ),
                ]);
                out.extend_from_slice(&body.canonical_bytes());
            }
            Message::Announce { key } => {
                out.push(TAG_ANNOUNCE);
                out.extend_from_slice(key);
            }
        }
        out
    }

    /// A complete frame: a four-byte big-endian length, then the body.
    pub fn frame(&self) -> Vec<u8> {
        let body = self.encode();
        let mut out = Vec::with_capacity(4 + body.len());
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    /// Decode a frame body.
    ///
    /// `pieces` is the piece count from the manifest, needed to size a
    /// `Bitfield` -- and taken from the caller rather than the wire, which is
    /// what stops a peer choosing an allocation. A node that has no manifest yet
    /// passes `None` and thereby refuses bitfields, which is correct: a bitfield
    /// before a manifest is a bitfield of unknown length.
    pub fn decode(body: &[u8], pieces: Option<u32>) -> Result<Message, WireError> {
        let (&tag, rest) = body
            .split_first()
            .ok_or(WireError::Truncated { message: "message" })?;
        match tag {
            TAG_MANIFEST => {
                let text = std::str::from_utf8(rest).map_err(|_| WireError::BadManifest)?;
                let value = Value::from_json(text).map_err(|_| WireError::BadManifest)?;
                let manifest = Manifest::from_value(&value).map_err(|_| WireError::BadManifest)?;
                Ok(Message::Manifest(Box::new(manifest)))
            }
            TAG_WANT_MANIFEST => empty(rest, "want-manifest").map(|()| Message::WantManifest),
            TAG_BITFIELD => {
                let pieces = pieces.ok_or(WireError::BadBitfield)?;
                Bitfield::decode(rest, pieces)
                    .map(Message::Bitfield)
                    .ok_or(WireError::BadBitfield)
            }
            TAG_HAVE => index_only(rest, "have").map(Message::Have),
            TAG_INTERESTED => empty(rest, "interested").map(|()| Message::Interested(true)),
            TAG_NOT_INTERESTED => empty(rest, "interested").map(|()| Message::Interested(false)),
            TAG_CHOKE => empty(rest, "choke").map(|()| Message::Choke(true)),
            TAG_UNCHOKE => empty(rest, "choke").map(|()| Message::Choke(false)),
            TAG_REQUEST => index_only(rest, "request").map(Message::Request),
            TAG_CANCEL => index_only(rest, "cancel").map(Message::Cancel),
            TAG_PIECE => {
                let (head, bytes) = rest
                    .split_at_checked(4)
                    .ok_or(WireError::Truncated { message: "piece" })?;
                let index = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
                if bytes.len() > MAX_PIECE_LEN as usize {
                    return Err(WireError::TooLong {
                        declared: bytes.len(),
                    });
                }
                Ok(Message::Piece {
                    index,
                    bytes: bytes.to_vec(),
                })
            }
            TAG_WANT_PEERS => empty(rest, "want-peers").map(|()| Message::WantPeers),
            TAG_PEERS => {
                let text = std::str::from_utf8(rest).map_err(|_| WireError::BadPeers)?;
                let value = Value::from_json(text).map_err(|_| WireError::BadPeers)?;
                let items = value.as_array().ok_or(WireError::BadPeers)?;
                if items.len() > super::discovery::MAX_SHARED {
                    return Err(WireError::TooLong {
                        declared: items.len(),
                    });
                }
                let mut records = Vec::with_capacity(items.len());
                for item in items {
                    // Decoded here, *verified* by the address book. Splitting the
                    // two keeps this codec free of any opinion about trust.
                    records.push(
                        crate::crypto::identity::SignedRecord::from_value(item)
                            .map_err(|_| WireError::BadPeers)?,
                    );
                }
                Ok(Message::Peers(records))
            }
            TAG_FIND_NODE => key_only(rest, "find-node").map(|key| Message::FindNode { key }),
            TAG_ANNOUNCE => key_only(rest, "announce").map(|key| Message::Announce { key }),
            TAG_NODES => {
                let text = std::str::from_utf8(rest).map_err(|_| WireError::BadPeers)?;
                let value = Value::from_json(text).map_err(|_| WireError::BadPeers)?;
                Ok(Message::Nodes {
                    closer: records_at(&value, "closer")?,
                    providers: records_at(&value, "providers")?,
                })
            }
            other => Err(WireError::UnknownTag(other)),
        }
    }
}

/// Check a declared frame length before a byte of it is read.
///
/// Split out and public so a reader can refuse the allocation rather than
/// perform it and then complain: the whole point is that a four-byte header
/// claiming 4 GiB costs four bytes of work.
pub fn check_frame_len(declared: u32) -> Result<usize, WireError> {
    let declared = declared as usize;
    if declared > MAX_FRAME {
        return Err(WireError::TooLong { declared });
    }
    Ok(declared)
}

fn empty(rest: &[u8], message: &'static str) -> Result<(), WireError> {
    if rest.is_empty() {
        Ok(())
    } else {
        Err(WireError::Trailing {
            message,
            extra: rest.len(),
        })
    }
}

/// A fixed 32-byte key field, with nothing after it.
fn key_only(rest: &[u8], message: &'static str) -> Result<[u8; 32], WireError> {
    let head = rest.get(..32).ok_or(WireError::Truncated { message })?;
    if rest.len() > 32 {
        return Err(WireError::Trailing {
            message,
            extra: rest.len() - 32,
        });
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(head);
    Ok(key)
}

/// A bounded list of signed records under `field`.
///
/// Bounded by [`super::dht::K`] rather than trusted: an answer claiming ten
/// thousand contacts is a peer trying to make this node verify ten thousand
/// signatures, and the routing table would keep at most `K` of them anyway.
fn records_at(
    value: &Value,
    field: &'static str,
) -> Result<Vec<crate::crypto::identity::SignedRecord>, WireError> {
    let items = value
        .get(field)
        .and_then(Value::as_array)
        .ok_or(WireError::BadPeers)?;
    if items.len() > super::dht::K {
        return Err(WireError::TooLong {
            declared: items.len(),
        });
    }
    items
        .iter()
        .map(|item| {
            crate::crypto::identity::SignedRecord::from_value(item).map_err(|_| WireError::BadPeers)
        })
        .collect()
}

fn index_only(rest: &[u8], message: &'static str) -> Result<u32, WireError> {
    let head = rest.get(..4).ok_or(WireError::Truncated { message })?;
    if rest.len() > 4 {
        return Err(WireError::Trailing {
            message,
            extra: rest.len() - 4,
        });
    }
    Ok(u32::from_be_bytes([head[0], head[1], head[2], head[3]]))
}

#[cfg(test)]
mod tests {
    use super::super::piece::{Manifest, MIN_PIECE_LEN};
    use super::*;

    fn manifest() -> Manifest {
        let data: Vec<u8> = (0..MIN_PIECE_LEN as usize * 2 + 3)
            .map(|i| (i % 251) as u8)
            .collect();
        Manifest::of(&data, MIN_PIECE_LEN).expect("valid")
    }

    fn round_trip(message: &Message, pieces: Option<u32>) {
        let frame = message.frame();
        let declared = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
        let len = check_frame_len(declared).expect("within the limit");
        assert_eq!(len, frame.len() - 4);
        assert_eq!(
            Message::decode(&frame[4..], pieces).expect("decodes"),
            *message,
            "{} did not survive a round trip",
            message.name()
        );
    }

    #[test]
    fn every_message_survives_a_round_trip() {
        let manifest = manifest();
        let pieces = Some(manifest.pieces());
        let record = crate::swarm::discovery::PeerRecord::sign(
            &crate::crypto::identity::Identity::from_secret_bytes([3u8; 32]),
            &["127.0.0.1:9797".parse().expect("addr")],
            1,
        )
        .expect("signs");
        for message in [
            Message::WantPeers,
            Message::Peers(vec![record.clone()]),
            Message::FindNode { key: [7u8; 32] },
            Message::Announce { key: [0u8; 32] },
            Message::Nodes {
                closer: vec![record.clone()],
                providers: vec![record],
            },
            Message::Nodes {
                closer: Vec::new(),
                providers: Vec::new(),
            },
            Message::Manifest(Box::new(manifest.clone())),
            Message::WantManifest,
            Message::Bitfield(super::super::piece::Bitfield::full(manifest.pieces())),
            Message::Have(7),
            Message::Have(u32::MAX),
            Message::Interested(true),
            Message::Interested(false),
            Message::Choke(true),
            Message::Choke(false),
            Message::Request(0),
            Message::Cancel(3),
            Message::Piece {
                index: 1,
                bytes: vec![9; MIN_PIECE_LEN as usize],
            },
            Message::Piece {
                index: 2,
                bytes: Vec::new(),
            },
        ] {
            round_trip(&message, pieces);
        }
    }

    #[test]
    fn a_frame_longer_than_the_limit_is_refused_before_it_is_allocated() {
        // The bug that has sunk more than one peer-to-peer implementation: a
        // four-byte header claiming 4 GiB must cost four bytes of work.
        assert!(matches!(
            check_frame_len(u32::MAX),
            Err(WireError::TooLong { .. })
        ));
        assert!(matches!(
            check_frame_len(MAX_FRAME as u32 + 1),
            Err(WireError::TooLong { .. })
        ));
        assert_eq!(check_frame_len(MAX_FRAME as u32), Ok(MAX_FRAME));
        assert_eq!(check_frame_len(0), Ok(0));
    }

    #[test]
    fn an_oversized_piece_body_is_refused_even_inside_a_legal_frame() {
        // MAX_FRAME has slack above MAX_PIECE_LEN for the manifest, so a frame
        // can be legal while the piece inside it is not. Checked separately
        // rather than assumed away by the frame limit.
        let mut body = vec![TAG_PIECE];
        body.extend_from_slice(&0u32.to_be_bytes());
        body.extend_from_slice(&vec![0; MAX_PIECE_LEN as usize + 1]);
        assert!(matches!(
            Message::decode(&body, None),
            Err(WireError::TooLong { .. })
        ));
    }

    #[test]
    fn an_unknown_tag_is_refused_rather_than_skipped() {
        // No version negotiation exists, so a tolerant decoder would be guessing
        // at a meaning it does not have.
        assert_eq!(
            Message::decode(&[200], None),
            Err(WireError::UnknownTag(200))
        );
        assert_eq!(Message::decode(&[0], None), Err(WireError::UnknownTag(0)));
        assert_eq!(
            Message::decode(&[], None),
            Err(WireError::Truncated { message: "message" })
        );
    }

    #[test]
    fn truncated_and_padded_frames_are_both_refused() {
        // Two encodings of one message is what the canonical format exists to
        // prevent; a wire format gets the same treatment even though nothing
        // here is hashed.
        assert!(matches!(
            Message::decode(&[TAG_HAVE, 0, 0], None),
            Err(WireError::Truncated { message: "have" })
        ));
        assert!(matches!(
            Message::decode(&[TAG_HAVE, 0, 0, 0, 1, 99], None),
            Err(WireError::Trailing {
                message: "have",
                ..
            })
        ));
        assert!(matches!(
            Message::decode(&[TAG_INTERESTED, 1], None),
            Err(WireError::Trailing { .. })
        ));
        assert!(matches!(
            Message::decode(&[TAG_PIECE, 0, 0], None),
            Err(WireError::Truncated { message: "piece" })
        ));
    }

    #[test]
    fn a_bitfield_needs_a_manifest_before_it_can_mean_anything() {
        // A bitfield before a manifest is a bitfield of unknown length, and the
        // length must never come from the peer -- that would be letting a
        // stranger choose an allocation.
        let manifest = manifest();
        let field = super::super::piece::Bitfield::full(manifest.pieces());
        let body = Message::Bitfield(field).encode();
        assert_eq!(Message::decode(&body, None), Err(WireError::BadBitfield));
        assert!(Message::decode(&body, Some(manifest.pieces())).is_ok());
        assert_eq!(
            Message::decode(&body, Some(manifest.pieces() + 64)),
            Err(WireError::BadBitfield),
            "and a count that does not match the bytes is refused"
        );
    }

    #[test]
    fn a_routing_answer_claiming_more_contacts_than_k_is_refused() {
        // An answer claiming ten thousand contacts is a peer trying to make this
        // node verify ten thousand signatures. The routing table would keep at
        // most K of them anyway, so the bound costs nothing legitimate.
        let record = crate::swarm::discovery::PeerRecord::sign(
            &crate::crypto::identity::Identity::from_secret_bytes([5u8; 32]),
            &["127.0.0.1:1234".parse().expect("addr")],
            1,
        )
        .expect("signs");
        let too_many: Vec<Value> = (0..crate::swarm::dht::K + 1)
            .map(|_| record.to_value())
            .collect();
        let body = Value::object([
            ("closer", Value::array(too_many)),
            ("providers", Value::array([])),
        ]);
        let mut frame = vec![TAG_NODES];
        frame.extend_from_slice(&body.canonical_bytes());
        assert!(matches!(
            Message::decode(&frame, None),
            Err(WireError::TooLong { .. })
        ));
    }

    #[test]
    fn a_key_field_is_exactly_thirty_two_bytes() {
        let mut short = vec![TAG_FIND_NODE];
        short.extend_from_slice(&[0u8; 31]);
        assert!(matches!(
            Message::decode(&short, None),
            Err(WireError::Truncated { .. })
        ));
        let mut long = vec![TAG_ANNOUNCE];
        long.extend_from_slice(&[0u8; 33]);
        assert!(matches!(
            Message::decode(&long, None),
            Err(WireError::Trailing { .. })
        ));
    }

    #[test]
    fn a_manifest_that_is_not_one_is_refused() {
        assert_eq!(
            Message::decode(&[TAG_MANIFEST, b'{'], None),
            Err(WireError::BadManifest)
        );
        let mut body = vec![TAG_MANIFEST];
        body.extend_from_slice(br#"{"digest":"sha256:00","total":1,"piece_len":3,"pieces":[]}"#);
        assert_eq!(Message::decode(&body, None), Err(WireError::BadManifest));
    }

    #[test]
    fn a_handshake_is_fixed_width_and_names_the_blob() {
        // Fixed width because this is the one message read before the peer has
        // proved anything, and a length-prefixed field there is a length a
        // stranger chose.
        let shake = Handshake {
            digest: crate::canonical::digest_bytes(b"a blob"),
            peer_id: [7; PEER_ID_LEN],
        };
        let encoded = shake.encode();
        assert_eq!(encoded.len(), Handshake::LEN);
        assert_eq!(Handshake::decode(&encoded), Ok(shake.clone()));

        let mut wrong = encoded.clone();
        wrong[0] = b'X';
        assert_eq!(Handshake::decode(&wrong), Err(WireError::NotOurProtocol));
        assert!(matches!(
            Handshake::decode(&encoded[..Handshake::LEN - 1]),
            Err(WireError::Truncated { .. })
        ));

        let mut not_hex = encoded.clone();
        not_hex[PROTOCOL.len()] = b'z';
        assert!(matches!(
            Handshake::decode(&not_hex),
            Err(WireError::NotUnicode { .. })
        ));
    }
}
