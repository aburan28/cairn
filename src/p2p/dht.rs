//! Provider lookup for the daemon: `p2p`'s instantiation of [`crate::dht`].
//!
//! [`super::code`] is need-driven fetch — a node asks for the checkers its own
//! log pins. What it does not have is any way to choose *whom to ask*, so it
//! asks whoever [`super::service`] happened to dial this tick. That is flooding
//! with extra steps: the want set goes to every peer in the sample, and a blob
//! held by one node in ten thousand is found by luck or not at all.
//!
//! This is the missing half. A key is a blob's content address, a value is "this
//! peer says it holds it", and the routing is [`crate::dht`]'s.
//!
//! # A peer id is already a node id, and that is not a coincidence
//!
//! [`PeerId`] is `sha256(McEliece public key)` — see [`super::handshake`]. That
//! is *exactly* what a Kademlia node id is supposed to be, so there is no second
//! hash here and [`NodeId::from_bytes`] takes the peer id unchanged. Hashing it
//! again would put a peer at a keyspace point its own handshake could not
//! derive.
//!
//! Two things fall out of it, and the second is the interesting one:
//!
//! - **Self-certifying, without a signature.** Completing a session *is* the
//!   proof of identity: the responder decapsulates with the secret key or the
//!   channel does not key up. [`super::super::swarm::dht`] needs a signature on
//!   every contact for the same guarantee.
//! - **A Sybil costs a McEliece keypair.** Grinding node ids to surround a key
//!   means generating keys, and `mceliece348864` keygen is orders of magnitude
//!   more expensive than ed25519's. This is a real cost and it is **not a
//!   defence**: it is a constant factor against an attacker who is willing to
//!   spend, and constant factors do not scale into security. Binding ids to the
//!   bond in [`crate::incentive`] is the version that would.
//!
//! # What a contact deliberately does not carry
//!
//! A [`PeerContact`] is an id, an address and a sequence number: 58 bytes. It
//! does **not** carry the public key, and that is a hard constraint rather than
//! a preference. A McEliece public key is 261,120 bytes, so a full routing table
//! that inlined one per contact would cost about 1.3 GB. The key is resolved
//! from [`super::discovery::AddressBook`] at dial time, where one copy per peer
//! is kept regardless.
//!
//! The consequence is worth stating plainly: **a routing answer from this stack
//! is not self-proving.** A relayed contact is a claim that a peer with that id
//! lives at that address, and it is only checked when somebody dials it and the
//! handshake either derives the expected id or does not. Wrong answers cost a
//! dial. They cannot cost correctness, because the handshake is the check.
//!
//! It also used to mean a contact heard of could never be *reached*: no key, no
//! session. That is what [`DhtMessage::GetKey`] closes. A key is fetched on
//! demand from a peer that has one, and checking it needs no trust at all —
//! a peer id *is* `sha256(public key)`, so the bytes hash to the id asked for or
//! they are discarded. 261 KiB once per peer actually dialled is affordable
//! where 261 KiB per routing-table entry was not, and it is the difference
//! between a DHT that can introduce a peer and one that can only reorder the
//! peers a node already knew.
//!
//! # Asked, not announced
//!
//! There is no inventory message, and the reason is the one [`super::code`]
//! already gives for refusing one: a list of the blobs a node holds is a list of
//! the objectives it is working on, which is a free traffic-analysis signal.
//! Publishing that to build a DHT would buy routing with exactly the privacy
//! `code` declined to spend.
//!
//! So holdership is **pulled**. [`DhtMessage::Ask`] carries content addresses the
//! asker wants; [`DhtMessage::Tell`] says which of *those* the responder holds.
//! A node therefore discloses its holdership only for blobs the peer had already
//! named — and in a session it has already named them, because the same set went
//! out as a `code_want` a moment earlier. The round adds routing knowledge at no
//! additional disclosure.
//!
//! # First-hand claims are stored; relayed ones are used and dropped
//!
//! This is the rule that replaces `swarm`'s signatures.
//!
//! - A [`DhtMessage::Tell`] is attributed to **the session's peer id**, never to
//!   an id in the message body — there is no such field. The handshake already
//!   proved who is talking, so a node can only ever speak for itself and cannot
//!   point the network at a victim.
//! - A [`DhtMessage::Providers`] *response*, which belongs to the multi-hop
//!   lookup, is hearsay: a peer relaying "C holds D" cannot prove it and the
//!   receiver cannot check it. Those records are handed back as lookup results
//!   and are **never entered into the local [`Providers`] store**, so a lie dies
//!   with the lookup that heard it.
//!
//! Without the second half an unsigned DHT is an amplifier: claim a victim holds
//! a popular blob, let it propagate, and the network dials the victim. The cost
//! of closing it this way is that provider knowledge spreads **one hop**: a
//! lookup uses what it is told and forgets it, so what a node stores is only
//! ever what it heard first-hand. That is a real limit now that the multi-hop
//! driver exists — a lie no longer dies for lack of anywhere to go, it dies
//! because nobody writes it down — and it is the reason to prefer signed records
//! if the network outgrows this.
//!
//! # The multi-hop driver
//!
//! [`crate::dht::Lookup`] is the iterative search as a pure state machine: it
//! says whom to ask and folds in what comes back. The half that was missing is
//! the half that touches connections, and it lives on [`Directory`]:
//! [`Directory::seek`] starts a search, [`Directory::next_hops`] names the peers
//! to dial next, [`Directory::on_providers`] and [`Directory::on_unreachable`]
//! feed answers back, and [`Directory::take_finished`] drains the results.
//!
//! A hop rides an ordinary session rather than opening its own connection. A
//! dedicated connection per hop is the textbook shape and would spend a McEliece
//! handshake on two small messages; instead [`super::service::Service::peers_for`]
//! asks the driver whom to dial, and [`super::session::exchange_dht`] carries the
//! query on the session that was being opened anyway. The lookup steers the
//! dialling, and the dialling advances the lookup.
//!
//! One rule holds the whole thing together, and every method assumes it:
//! **for each contact [`Directory::next_hops`] hands out, exactly one of
//! [`Directory::on_providers`] or [`Directory::on_unreachable`] must follow.**
//! A caller that dials some and forgets the rest leaves those peers marked
//! in-flight, and the lookups waiting on them never terminate — which presents
//! as a DHT that quietly stopped answering rather than as the missing call it
//! is.
//!
//! # Determinism
//!
//! No clock and no randomness, as everywhere else. Expiry times arrive as
//! arguments. A node's clock is not evidence.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::SocketAddr;

use crate::blobs;
use crate::canonical::Value;
use crate::dht::{self, Contact as _, Provider as _};
use crate::obj;

use super::handshake::PeerId;

pub use crate::dht::{Distance, Insertion, NodeId, ALPHA, ID_BITS, K, MAX_KEYS, MAX_PROVIDERS};

/// AEAD context for DHT frames.
///
/// Its own context for the same mechanical reason as populations and code: a
/// DHT frame cannot be opened as a record frame, so no confusion attack reaches
/// a decoder that was expecting something settlement is derived from.
pub const CONTEXT: &[u8] = b"proofwork/p2p/dht/v1";

/// How long a first-hand announcement is trusted, in seconds.
///
/// Short on purpose. A provider record is a statement about the present, and the
/// failure mode of a long expiry is a node confidently directing traffic at a
/// peer that left an hour ago. Republication is cheap — it rides a session the
/// daemon was opening anyway — so there is no reason to trade freshness for it.
pub const PROVIDER_TTL_SECS: u64 = 1_800;

/// Contacts in one `Nodes` answer. Kademlia's `k`, and a bound on a peer's
/// ability to make this node do work by answering generously.
pub const MAX_CONTACTS_PER_MESSAGE: usize = K;

/// Addresses one `Ask` or `Tell` may carry.
///
/// A node asks for the pins its own log carries and cannot serve, which is
/// bounded by that log. A thousand is far above the honest case and far below
/// anything that costs memory. The same ceiling covers `Tell`, which is a subset
/// of an `Ask` by construction.
pub const MAX_ASK_ADDRESSES: usize = 1_024;

/// Addresses one `GetProviders` may carry, and answers one `Providers` may.
///
/// Far below [`MAX_ASK_ADDRESSES`] because these are different questions. An
/// `Ask` is "which of my pins do you have", bounded by the log; this is "route
/// me toward these keys", and each answer carries up to `K` contacts and
/// [`MAX_PROVIDERS`] holders. Eight keeps the worst-case answer to a few
/// kilobytes while leaving a node room to pursue several lookups at once.
pub const MAX_LOOKUP_ADDRESSES: usize = 8;

/// Public keys one `Keys` answer may carry.
///
/// **One**, and the number is the whole design. A McEliece public key is
/// 261,120 bytes, which is 522,240 characters of hex — half a megabyte on the
/// wire for a single key. A node learns one new dialable peer per round, which
/// is plenty when rounds are frequent, and a peer cannot turn a routing question
/// into a multi-megabyte answer.
pub const MAX_KEYS_PER_MESSAGE: usize = 1;

/// Characters in a hex-encoded McEliece public key.
///
/// Checked before decoding, so a peer claiming a key cannot make this node
/// allocate for one it did not send.
pub const KEY_HEX_LEN: usize = 261_120 * 2;

/// Rounds a contact may be passed over for want of a key before a lookup gives
/// up on it.
///
/// Three, because the key request rides an ordinary session: the contact has to
/// survive long enough for this node to talk to a peer that has the key and be
/// answered, and one round is not enough when only some peers know it. Beyond
/// that it is a peer nobody will vouch for, and a lookup that kept offering it
/// would never terminate.
pub const MAX_DEFERRALS: u32 = 3;

/// Why a DHT message was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhtError {
    /// A message did not decode.
    Malformed { detail: String },
    /// More items in one message than the ceiling allows, refused against the
    /// declared count before anything was built.
    TooMany { limit: usize, got: usize },
    /// Something in a key field that is not a content address.
    NotAnAddress { address: String },
    /// An address that is not a socket address.
    BadAddress { value: String },
}

impl fmt::Display for DhtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DhtError::Malformed { detail } => write!(f, "malformed dht message: {detail}"),
            DhtError::TooMany { limit, got } => {
                write!(f, "dht message carries {got} items, limit is {limit}")
            }
            DhtError::NotAnAddress { address } => {
                write!(f, "{address:?} is not a content address")
            }
            DhtError::BadAddress { value } => write!(f, "{value:?} is not a socket address"),
        }
    }
}

impl std::error::Error for DhtError {}

/// A peer in the routing table: who, and where. Not *what key*.
///
/// See the module docs: 58 bytes rather than 261 KiB, and the key comes from the
/// address book at dial time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerContact {
    pub id: NodeId,
    pub addr: SocketAddr,
    /// Freshness. Higher supersedes, so a peer that moved replaces itself and a
    /// replayed old address cannot displace a newer one.
    pub seq: u64,
}

impl PeerContact {
    /// A contact for a peer whose id the handshake derived.
    ///
    /// Takes a [`PeerId`] rather than a [`NodeId`] so a caller cannot invent a
    /// keyspace position: the only [`PeerId`] values in circulation come from
    /// [`super::handshake::PeerPublic::id`], which computes them from the key.
    pub fn new(peer: PeerId, addr: SocketAddr, seq: u64) -> PeerContact {
        PeerContact {
            id: NodeId::from_bytes(peer),
            addr,
            seq,
        }
    }

    pub fn peer_id(&self) -> PeerId {
        *self.id.as_bytes()
    }

    fn to_value(&self) -> Value {
        obj! {
            "id" => Value::string(self.id.to_hex()),
            "addr" => Value::string(self.addr.to_string()),
            "seq" => Value::Int(self.seq as i128),
        }
    }

    fn from_value(value: &Value) -> Result<PeerContact, DhtError> {
        let bad = |detail: &str| DhtError::Malformed {
            detail: detail.to_string(),
        };
        let id = value
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| bad("contact has no id"))?;
        let addr = value
            .get("addr")
            .and_then(Value::as_str)
            .ok_or_else(|| bad("contact has no addr"))?;
        let seq = match value.get("seq") {
            Some(Value::Int(seq)) if *seq >= 0 => {
                u64::try_from(*seq).map_err(|_| bad("seq is out of range"))?
            }
            _ => return Err(bad("contact has no seq")),
        };
        Ok(PeerContact {
            id: parse_node_id(id)?,
            addr: addr.parse().map_err(|_| DhtError::BadAddress {
                value: addr.to_string(),
            })?,
            seq,
        })
    }
}

impl dht::Contact for PeerContact {
    fn id(&self) -> NodeId {
        self.id
    }

    fn seq(&self) -> u64 {
        self.seq
    }
}

/// A claim that some peer holds a blob.
///
/// Unsigned, and the module docs explain why that is safe here: a first-hand
/// claim was proved by the session that carried it, and a relayed one is never
/// stored. The worst a wrong holder costs is a dial that fails against a digest
/// the log fixed first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Holder {
    pub id: NodeId,
    pub addr: SocketAddr,
}

impl Holder {
    pub fn new(peer: PeerId, addr: SocketAddr) -> Holder {
        Holder {
            id: NodeId::from_bytes(peer),
            addr,
        }
    }

    pub fn peer_id(&self) -> PeerId {
        *self.id.as_bytes()
    }

    fn to_value(&self) -> Value {
        obj! {
            "id" => Value::string(self.id.to_hex()),
            "addr" => Value::string(self.addr.to_string()),
        }
    }

    fn from_value(value: &Value) -> Result<Holder, DhtError> {
        let bad = |detail: &str| DhtError::Malformed {
            detail: detail.to_string(),
        };
        let id = value
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| bad("holder has no id"))?;
        let addr = value
            .get("addr")
            .and_then(Value::as_str)
            .ok_or_else(|| bad("holder has no addr"))?;
        Ok(Holder {
            id: parse_node_id(id)?,
            addr: addr.parse().map_err(|_| DhtError::BadAddress {
                value: addr.to_string(),
            })?,
        })
    }
}

/// One address's worth of answer inside a [`DhtMessage::Providers`].
///
/// Holders and closer contacts together on purpose: a lookup that got holders is
/// finished, and one that did not needs somewhere to go next. Splitting them
/// would cost a round trip on every miss, which is the common case near the
/// start of a lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderAnswer {
    pub address: String,
    pub holders: Vec<Holder>,
    pub closer: Vec<PeerContact>,
}

impl ProviderAnswer {
    fn to_value(&self) -> Value {
        obj! {
            "address" => Value::string(self.address.clone()),
            "holders" => Value::Array(self.holders.iter().map(Holder::to_value).collect()),
            "closer" => Value::Array(self.closer.iter().map(PeerContact::to_value).collect()),
        }
    }

    fn from_value(value: &Value) -> Result<ProviderAnswer, DhtError> {
        let address = value
            .get("address")
            .and_then(Value::as_str)
            .ok_or_else(|| DhtError::Malformed {
                detail: String::from("answer has no address"),
            })?;
        if !blobs::is_address(address) {
            return Err(DhtError::NotAnAddress {
                address: address.to_string(),
            });
        }
        let bounded =
            |field: &str, limit: usize| -> Result<&[Value], DhtError> {
                let items = value.get(field).and_then(Value::as_array).ok_or_else(|| {
                    DhtError::Malformed {
                        detail: format!("{field} is not an array"),
                    }
                })?;
                if items.len() > limit {
                    return Err(DhtError::TooMany {
                        limit,
                        got: items.len(),
                    });
                }
                Ok(items)
            };
        let holder_items = bounded("holders", MAX_PROVIDERS)?;
        let mut holders = Vec::with_capacity(holder_items.len());
        for item in holder_items {
            holders.push(Holder::from_value(item)?);
        }
        let closer_items = bounded("closer", MAX_CONTACTS_PER_MESSAGE)?;
        let mut closer = Vec::with_capacity(closer_items.len());
        for item in closer_items {
            closer.push(PeerContact::from_value(item)?);
        }
        Ok(ProviderAnswer {
            address: address.to_string(),
            holders,
            closer,
        })
    }
}

impl dht::Provider for Holder {
    fn provider(&self) -> NodeId {
        self.id
    }
}

fn parse_node_id(text: &str) -> Result<NodeId, DhtError> {
    if text.len() != 64 {
        return Err(DhtError::Malformed {
            detail: format!("{text:?} is not a 256-bit id"),
        });
    }
    let mut raw = [0u8; 32];
    for (index, slot) in raw.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).map_err(|_| {
            DhtError::Malformed {
                detail: format!("{text:?} is not hexadecimal"),
            }
        })?;
    }
    Ok(NodeId::from_bytes(raw))
}

/// Hex-encode a public key for a [`DhtMessage::Keys`].
pub fn encode_key(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(nibble(byte >> 4));
        out.push(nibble(byte & 0x0f));
    }
    out
}

fn nibble(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        _ => (b'a' + value - 10) as char,
    }
}

/// Decode a hex public key and check it is the one asked for.
///
/// `None` on any failure, and the caller drops it. There is deliberately no
/// error detail: a peer that answers with the wrong key is either broken or
/// lying, the response is the same either way, and **the check needs no trust
/// at all** — a peer id *is* `sha256(public key)`, so the bytes either hash to
/// the id that was asked for or they do not.
pub fn decode_key(claimed: NodeId, hex: &str) -> Option<Vec<u8>> {
    if hex.len() != KEY_HEX_LEN {
        return None;
    }
    let bytes = hex.as_bytes();
    let mut out = Vec::with_capacity(hex.len() / 2);
    for pair in bytes.chunks(2) {
        let value = |byte: u8| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        };
        out.push((value(pair[0])? << 4) | value(pair[1])?);
    }
    let derived = super::handshake::PeerPublic::from_bytes(&out).ok()?;
    (NodeId::from_bytes(derived.id()) == claimed).then_some(out)
}

/// `K` contacts per distance band, oldest-live-wins. See [`crate::dht`].
pub type RoutingTable = dht::RoutingTable<PeerContact>;

/// One iterative lookup. See [`crate::dht`].
pub type Lookup = dht::Lookup<PeerContact, Holder>;

/// Who holds what, first-hand only. See [`crate::dht`] and the module docs.
pub type Providers = dht::ProviderStore<Holder>;

/// A DHT protocol message.
///
/// Note what is absent: no message names its own sender. A peer's id comes from
/// the session that carried the frame, so there is no field to forge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhtMessage {
    /// "Which peers do you know nearest this point?"
    FindNode { target: NodeId },
    /// The answer: up to `k` contacts, nearest first.
    Nodes { contacts: Vec<PeerContact> },
    /// "Who holds these blobs?" Keyed by content address, not by an opaque id,
    /// so the key is one anybody can compute from the log.
    ///
    /// A **list**, and an empty one is the common case rather than an error: the
    /// round is symmetric, so both ends send this whether or not they have a
    /// lookup in flight, and "nothing to ask" has to be sayable without a
    /// sentinel address that decoders would have to special-case.
    GetProviders { addresses: Vec<String> },
    /// One answer per address asked, in the order asked.
    Providers { answers: Vec<ProviderAnswer> },
    /// "Send me the public keys of these peers."
    ///
    /// What makes the DHT able to introduce a peer rather than only reorder the
    /// ones already known. A [`PeerContact`] cannot carry its key — a McEliece
    /// public key is 261,120 bytes and a full routing table would cost about
    /// 1.3 GB — so a contact learned from a routing answer was, until this
    /// message existed, undialable forever.
    ///
    /// Fetching one on demand costs 261 KiB once per peer instead of per table
    /// entry, which is the difference between impossible and merely large.
    GetKey { peers: Vec<NodeId> },
    /// Public keys, hex, in the order asked. A key the responder does not have
    /// is simply absent — the answer is a subset, never padded.
    ///
    /// **Needs no trust.** A peer id *is* `sha256(public key)`, so the asker
    /// derives the id from the bytes and compares. A relayed key is either the
    /// one it claims to be or it is discarded; there is nothing in between and
    /// nothing to sign.
    Keys { keys: Vec<String> },
    /// "Which of these do you hold?" Content addresses only.
    ///
    /// The asker's want set, which in a session it has already disclosed as a
    /// `code_want`. Asking is what makes the answer free of new disclosure.
    Ask { addresses: Vec<String> },
    /// "Of what you asked, I hold these."
    ///
    /// A subset of the `Ask`, never a superset — a responder volunteering an
    /// address nobody asked about would be publishing the inventory this
    /// protocol exists to avoid publishing, and [`Directory::record_tell`]
    /// discards anything unasked rather than trusting it not to.
    Tell { addresses: Vec<String> },
}

impl DhtMessage {
    pub fn to_value(&self) -> Value {
        match self {
            DhtMessage::FindNode { target } => obj! {
                "t" => Value::string("dht_find_node"),
                "target" => Value::string(target.to_hex()),
            },
            DhtMessage::Nodes { contacts } => obj! {
                "t" => Value::string("dht_nodes"),
                "contacts" => Value::Array(contacts.iter().map(PeerContact::to_value).collect()),
            },
            DhtMessage::GetProviders { addresses } => obj! {
                "t" => Value::string("dht_get_providers"),
                "addresses" => Value::Array(
                    addresses.iter().map(|a| Value::string(a.clone())).collect()
                ),
            },
            DhtMessage::Providers { answers } => obj! {
                "t" => Value::string("dht_providers"),
                "answers" => Value::Array(answers.iter().map(ProviderAnswer::to_value).collect()),
            },
            DhtMessage::GetKey { peers } => obj! {
                "t" => Value::string("dht_get_key"),
                "peers" => Value::Array(
                    peers.iter().map(|p| Value::string(p.to_hex())).collect()
                ),
            },
            DhtMessage::Keys { keys } => obj! {
                "t" => Value::string("dht_keys"),
                "keys" => Value::Array(keys.iter().map(|k| Value::string(k.clone())).collect()),
            },
            DhtMessage::Ask { addresses } => obj! {
                "t" => Value::string("dht_ask"),
                "addresses" => Value::Array(
                    addresses.iter().map(|a| Value::string(a.clone())).collect()
                ),
            },
            DhtMessage::Tell { addresses } => obj! {
                "t" => Value::string("dht_tell"),
                "addresses" => Value::Array(
                    addresses.iter().map(|a| Value::string(a.clone())).collect()
                ),
            },
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        self.to_value().canonical_string().into_bytes()
    }

    pub fn decode(bytes: &[u8]) -> Result<DhtMessage, DhtError> {
        let text = std::str::from_utf8(bytes).map_err(|_| DhtError::Malformed {
            detail: "not UTF-8".into(),
        })?;
        let value = Value::from_json(text).map_err(|error| DhtError::Malformed {
            detail: error.to_string(),
        })?;
        DhtMessage::from_value(&value)
    }

    /// Decode, enforcing every ceiling **before** building any vector.
    ///
    /// The ordering is the point. Checking a declared count after allocating for
    /// it is not a defence against a peer whose plan is to make you allocate.
    pub fn from_value(value: &Value) -> Result<DhtMessage, DhtError> {
        let bad = |detail: String| DhtError::Malformed { detail };
        let array = |field: &str, limit: usize| -> Result<&[Value], DhtError> {
            let items = value
                .get(field)
                .and_then(Value::as_array)
                .ok_or_else(|| bad(format!("{field} is not an array")))?;
            if items.len() > limit {
                return Err(DhtError::TooMany {
                    limit,
                    got: items.len(),
                });
            }
            Ok(items)
        };
        /// Every address-bearing field decodes through here: the shape check is
        /// what keeps `"../../../etc/passwd"` from reaching a path join in
        /// [`crate::blobs`], and one copy of it means no message can be added
        /// that forgets.
        fn addresses(items: &[Value]) -> Result<Vec<String>, DhtError> {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                let text = item.as_str().ok_or_else(|| DhtError::Malformed {
                    detail: String::from("addresses contains a non-string"),
                })?;
                if !blobs::is_address(text) {
                    return Err(DhtError::NotAnAddress {
                        address: text.to_string(),
                    });
                }
                out.push(text.to_string());
            }
            Ok(out)
        }

        match value.get("t").and_then(Value::as_str) {
            Some("dht_find_node") => {
                let target = value
                    .get("target")
                    .and_then(Value::as_str)
                    .ok_or_else(|| bad("target is not a string".into()))?;
                Ok(DhtMessage::FindNode {
                    target: parse_node_id(target)?,
                })
            }
            Some("dht_nodes") => {
                let items = array("contacts", MAX_CONTACTS_PER_MESSAGE)?;
                let mut contacts = Vec::with_capacity(items.len());
                for item in items {
                    contacts.push(PeerContact::from_value(item)?);
                }
                Ok(DhtMessage::Nodes { contacts })
            }
            Some("dht_get_providers") => Ok(DhtMessage::GetProviders {
                addresses: addresses(array("addresses", MAX_LOOKUP_ADDRESSES)?)?,
            }),
            Some("dht_providers") => {
                let items = array("answers", MAX_LOOKUP_ADDRESSES)?;
                let mut answers = Vec::with_capacity(items.len());
                for item in items {
                    answers.push(ProviderAnswer::from_value(item)?);
                }
                Ok(DhtMessage::Providers { answers })
            }
            Some("dht_get_key") => {
                let items = array("peers", MAX_KEYS_PER_MESSAGE)?;
                let mut peers = Vec::with_capacity(items.len());
                for item in items {
                    let text = item
                        .as_str()
                        .ok_or_else(|| bad("peers contains a non-string".into()))?;
                    peers.push(parse_node_id(text)?);
                }
                Ok(DhtMessage::GetKey { peers })
            }
            Some("dht_keys") => {
                let items = array("keys", MAX_KEYS_PER_MESSAGE)?;
                let mut keys = Vec::with_capacity(items.len());
                for item in items {
                    let text = item
                        .as_str()
                        .ok_or_else(|| bad("keys contains a non-string".into()))?;
                    // Length before content, and before anything is copied: a
                    // peer that answers a 64-byte question with a gigabyte of
                    // hex must be refused by the check rather than by the
                    // allocator.
                    if text.len() != KEY_HEX_LEN {
                        return Err(DhtError::Malformed {
                            detail: format!(
                                "a public key is {KEY_HEX_LEN} hex characters, got {}",
                                text.len()
                            ),
                        });
                    }
                    keys.push(text.to_string());
                }
                Ok(DhtMessage::Keys { keys })
            }
            Some(kind @ ("dht_ask" | "dht_tell")) => {
                let addresses = addresses(array("addresses", MAX_ASK_ADDRESSES)?)?;
                Ok(match kind {
                    "dht_ask" => DhtMessage::Ask { addresses },
                    _ => DhtMessage::Tell { addresses },
                })
            }
            other => Err(bad(format!("unknown dht message {other:?}"))),
        }
    }
}

/// A node's view of the DHT: whom it can route through, and who holds what.
///
/// One object rather than two loose ones because the two are updated together on
/// every message — a peer that announces a blob is also a peer worth routing
/// through — and keeping them apart is how a routing table ends up knowing about
/// peers the provider store has never heard of, and vice versa.
#[derive(Debug, Clone)]
pub struct Directory {
    routing: RoutingTable,
    providers: Providers,
    /// Lookups in flight, keyed by the content address being sought.
    ///
    /// A map rather than one at a time: a node that is missing four checkers
    /// wants all four found, and the hops overlap — the same peer is frequently
    /// the next step for several keys, so one dial can advance several lookups.
    lookups: BTreeMap<String, Lookup>,
    /// Which addresses each peer currently owes an answer for.
    ///
    /// The bookkeeping that makes [`Directory::on_unreachable`] able to resolve
    /// every lookup a dead peer was holding up. Without it a failed dial would
    /// leave that peer marked in-flight inside each lookup and none of them
    /// would ever reach [`Lookup::is_done`].
    outstanding: BTreeMap<NodeId, BTreeSet<String>>,
    /// How many rounds each contact has been passed over for want of a key.
    ///
    /// The bound that makes deferral safe. Without it a contact whose key never
    /// arrives is offered every round forever and its lookup never terminates.
    deferrals: BTreeMap<NodeId, u32>,
    /// Peers a lookup wants to reach and this node cannot dial.
    ///
    /// A routing answer names a peer by id and address, never by key (see the
    /// module docs), so a newly-heard-of contact is undialable until its key
    /// arrives. This is the queue [`DhtMessage::GetKey`] drains.
    key_wants: BTreeSet<NodeId>,
}

impl Directory {
    /// A directory for a node with this peer id.
    pub fn new(local: PeerId) -> Directory {
        Directory {
            routing: RoutingTable::new(NodeId::from_bytes(local)),
            providers: Providers::new(),
            lookups: BTreeMap::new(),
            deferrals: BTreeMap::new(),
            outstanding: BTreeMap::new(),
            key_wants: BTreeSet::new(),
        }
    }

    pub fn local(&self) -> NodeId {
        self.routing.local()
    }

    pub fn routing(&self) -> &RoutingTable {
        &self.routing
    }

    pub fn providers_store(&self) -> &Providers {
        &self.providers
    }

    /// Note that a peer is reachable. Returns what the table decided.
    ///
    /// [`Insertion::Pending`] is not handled here for the reason
    /// [`crate::dht::RoutingTable::insert`] gives: deciding it needs a round
    /// trip, and a data structure that performed one could not be tested without
    /// a network. The driver probes and calls [`Directory::replace`].
    pub fn saw(&mut self, contact: PeerContact) -> Insertion<PeerContact> {
        self.routing.insert(contact)
    }

    /// Evict a contact that failed its probe, admitting the newcomer instead.
    pub fn replace(&mut self, dead: &NodeId, contact: PeerContact) -> bool {
        self.routing.replace(dead, contact)
    }

    /// Drop a peer known to be gone, from both halves.
    pub fn forget(&mut self, id: &NodeId) -> bool {
        self.routing.remove(id)
    }

    /// Record a **first-hand** claim of holdership.
    ///
    /// `from` is the session's peer id, which the handshake derived from a key
    /// the peer had to hold. That is the whole authentication story, and it is
    /// why this takes a [`PeerId`] and an address separately rather than a
    /// [`Holder`] a caller might have decoded from a message body.
    ///
    /// `asked` is what this node actually requested. An address outside it is
    /// **discarded**, which is the enforcement half of "no inventory message":
    /// without it a peer could volunteer its whole store and the protocol would
    /// have the property it was designed not to have, by convention only.
    ///
    /// Addresses that are not content addresses are skipped rather than refused:
    /// the decoder already rejects those, so reaching one here would mean an
    /// internal caller, and dropping a blob is a better failure than dropping the
    /// peer.
    pub fn record_tell(
        &mut self,
        from: PeerId,
        addr: SocketAddr,
        asked: &BTreeSet<String>,
        told: &[String],
        now: u64,
    ) -> usize {
        let holder = Holder::new(from, addr);
        let mut stored = 0;
        for address in told {
            if !asked.contains(address) {
                continue;
            }
            let Some(key) = NodeId::of_digest(address) else {
                continue;
            };
            if self
                .providers
                .announce(key, &holder, now + PROVIDER_TTL_SECS)
            {
                stored += 1;
            }
        }
        stored
    }

    /// Which of `asked` this node can serve, as an answer to an [`DhtMessage::Ask`].
    ///
    /// The intersection, never more: a responder that added anything would be
    /// publishing an inventory.
    pub fn answer_ask(asked: &[String], held: &BTreeSet<String>) -> Vec<String> {
        asked
            .iter()
            .filter(|address| held.contains(*address))
            .cloned()
            .collect()
    }

    /// Answer a `GetProviders`: who this node knows holds `address`, plus the
    /// contacts nearest it either way.
    pub fn lookup_providers(&self, address: &str, now: u64) -> (Vec<Holder>, Vec<PeerContact>) {
        let Some(key) = NodeId::of_digest(address) else {
            return (Vec::new(), Vec::new());
        };
        (
            self.providers.providers(key, now),
            self.routing.closest(key, K),
        )
    }

    /// Answer a `FindNode`.
    pub fn closest(&self, target: NodeId, count: usize) -> Vec<PeerContact> {
        self.routing.closest(target, count)
    }

    /// Start a lookup for the peers holding `address`, seeded from the local
    /// table.
    pub fn lookup(&self, address: &str) -> Option<Lookup> {
        let key = NodeId::of_digest(address)?;
        Some(Lookup::new(key, self.routing.closest(key, K)))
    }

    /// Drop lapsed provider records. Returns how many went.
    pub fn expire(&mut self, now: u64) -> usize {
        self.providers.expire(now)
    }

    // -- the multi-hop driver ----------------------------------------------
    //
    // `Lookup` is a pure state machine: it says whom to ask and folds in what
    // comes back, and knows nothing about connections. The methods below are
    // the half that was missing — they run several lookups at once, hand the
    // service the contacts to dial, and route each answer back to every lookup
    // that was waiting on it.
    //
    // The contract with the caller is one sentence, and every method here
    // depends on it: **for each contact `next_hops` hands out, exactly one of
    // `on_providers` or `on_unreachable` must follow.** A caller that dials
    // some and forgets the rest leaves those peers marked in-flight and the
    // lookups they belong to never finish.

    /// Begin looking for the peers holding `address`, if one is not already
    /// running. Returns whether a lookup is now in flight.
    ///
    /// Seeded from the local routing table, which is what makes the first hop
    /// free: a node with peers already knows somewhere to start, and one with
    /// none gets `false` rather than a lookup that can never move.
    pub fn seek(&mut self, address: &str) -> bool {
        if self.lookups.contains_key(address) {
            return true;
        }
        let Some(lookup) = self.lookup(address) else {
            return false;
        };
        // A lookup with no seeds is not a lookup. Refusing it here means
        // `next_hops` never returns nothing forever, and a node with an empty
        // table falls back to the dial sample as it did before.
        if lookup.closest().is_empty() {
            return false;
        }
        self.lookups.insert(address.to_string(), lookup);
        true
    }

    /// Whether any lookup is in flight.
    pub fn seeking(&self) -> bool {
        !self.lookups.is_empty()
    }

    /// The addresses currently being sought, for reporting.
    pub fn sought(&self) -> Vec<String> {
        self.lookups.keys().cloned().collect()
    }

    /// Advance every lookup and return the contacts to query next, deduplicated
    /// across lookups.
    ///
    /// Deduplicated because one dial can carry several questions: the peers
    /// nearest two different keys overlap heavily, and asking the same node
    /// twice in one round would spend a McEliece handshake to learn nothing.
    ///
    /// `dialable` says whether this node can actually open a session to a
    /// contact — in practice, whether its public key is in the address book. A
    /// contact that fails it is **deferred rather than timed out**: its address
    /// is known and only its key is missing, so writing it off would discard the
    /// peer one round before [`DhtMessage::GetKey`] makes it reachable. The
    /// deferral is bounded by [`MAX_DEFERRALS`], because a contact whose key
    /// never arrives would otherwise be offered forever and its lookup would
    /// never terminate.
    pub fn next_hops(
        &mut self,
        limit: usize,
        dialable: impl Fn(NodeId) -> bool,
    ) -> Vec<PeerContact> {
        let mut chosen: Vec<PeerContact> = Vec::new();
        let mut seen: BTreeSet<NodeId> = BTreeSet::new();
        let mut deferred: Vec<NodeId> = Vec::new();
        for (address, lookup) in &mut self.lookups {
            for contact in lookup.next_queries() {
                if !dialable(contact.id()) {
                    let attempts = self.deferrals.entry(contact.id()).or_insert(0);
                    *attempts += 1;
                    if *attempts > MAX_DEFERRALS {
                        // The key never came. Treat it as the silent peer it
                        // has turned out to be, or this lookup never ends.
                        lookup.on_timeout(contact.id());
                    } else {
                        lookup.defer(contact.id());
                        deferred.push(contact.id());
                    }
                    continue;
                }
                self.outstanding
                    .entry(contact.id())
                    .or_default()
                    .insert(address.clone());
                if seen.insert(contact.id()) {
                    chosen.push(contact);
                }
            }
        }
        for peer in deferred {
            self.wants_key(peer);
        }
        // Nearest to *some* target first. A total order across lookups with
        // different targets does not exist, so this orders by how many
        // questions the contact answers -- the dial that advances three
        // lookups is worth more than the one that advances one.
        chosen.sort_by_key(|contact| {
            std::cmp::Reverse(
                self.outstanding
                    .get(&contact.id())
                    .map(BTreeSet::len)
                    .unwrap_or(0),
            )
        });
        chosen.truncate(limit);
        chosen
    }

    /// What to put in a `GetProviders` when talking to `peer`.
    ///
    /// Capped at [`MAX_LOOKUP_ADDRESSES`], which is also what the decoder
    /// enforces on the other end: asking more than a peer will decode would
    /// make the round fail rather than answer less.
    pub fn ask_of(&self, peer: NodeId) -> Vec<String> {
        self.outstanding
            .get(&peer)
            .map(|addresses| {
                addresses
                    .iter()
                    .take(MAX_LOOKUP_ADDRESSES)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Answer a `GetProviders` for every address asked.
    pub fn answer_get_providers(&self, addresses: &[String], now: u64) -> Vec<ProviderAnswer> {
        addresses
            .iter()
            .take(MAX_LOOKUP_ADDRESSES)
            .map(|address| {
                let (holders, closer) = self.lookup_providers(address, now);
                ProviderAnswer {
                    address: address.clone(),
                    holders,
                    closer,
                }
            })
            .collect()
    }

    /// Fold a peer's answers into the lookups that were waiting on it.
    ///
    /// **Relayed holders are lookup results and never enter the provider
    /// store.** That is the rule the module header opens with: a peer saying
    /// "C holds D" cannot prove it, and storing it would make this an
    /// amplifier — name a victim as the holder of a popular blob and the
    /// network dials the victim. A lie dies with the lookup that heard it.
    ///
    /// Contacts *are* entered into the routing table, because a wrong one costs
    /// only a dial: the handshake derives the id or the session does not key up.
    pub fn on_providers(&mut self, from: NodeId, answers: &[ProviderAnswer]) {
        let owed = self.outstanding.remove(&from).unwrap_or_default();
        for answer in answers {
            // An answer for something this node did not ask this peer is
            // discarded, for the reason `record_tell` discards an unasked
            // `Tell`: otherwise a peer chooses what enters this node's state.
            if !owed.contains(&answer.address) {
                continue;
            }
            for contact in &answer.closer {
                self.saw(contact.clone());
                if !self
                    .routing
                    .contacts()
                    .any(|held| held.id() == contact.id())
                {
                    // Heard of but not admitted -- the bucket was full. Still
                    // worth a key, because the probe that might admit it has to
                    // be able to dial it.
                    self.key_wants.insert(contact.id());
                }
            }
            if let Some(lookup) = self.lookups.get_mut(&answer.address) {
                lookup.on_response(from, answer.closer.clone(), answer.holders.clone());
            }
        }
        // Any address this peer owed and did not answer is a non-answer for
        // that lookup, not a silent hole.
        for address in owed {
            if answers.iter().any(|answer| answer.address == address) {
                continue;
            }
            if let Some(lookup) = self.lookups.get_mut(&address) {
                lookup.on_timeout(from);
            }
        }
    }

    /// A peer that could not be reached, or that failed mid-round.
    ///
    /// Resolves it in every lookup that was waiting on it. Marked queried
    /// rather than forgotten, for [`Lookup::on_timeout`]'s reason: retrying a
    /// silent node is how a lookup stops terminating.
    pub fn on_unreachable(&mut self, peer: NodeId) {
        for address in self.outstanding.remove(&peer).unwrap_or_default() {
            if let Some(lookup) = self.lookups.get_mut(&address) {
                lookup.on_timeout(peer);
            }
        }
    }

    /// Take the finished lookups: the address sought and the holders found.
    ///
    /// Draining rather than peeking, because a finished lookup that stayed in
    /// the map would be re-reported every round and would block a fresh attempt
    /// for the same address.
    pub fn take_finished(&mut self) -> Vec<(String, Vec<Holder>)> {
        let done: Vec<String> = self
            .lookups
            .iter()
            .filter(|(_, lookup)| lookup.is_done())
            .map(|(address, _)| address.clone())
            .collect();
        let mut out = Vec::new();
        for address in done {
            if let Some(lookup) = self.lookups.remove(&address) {
                out.push((address, lookup.providers().to_vec()));
            }
        }
        out
    }

    /// Peers whose public key this node wants, so it can dial them.
    pub fn key_wants(&self) -> Vec<NodeId> {
        self.key_wants
            .iter()
            .take(MAX_KEYS_PER_MESSAGE)
            .copied()
            .collect()
    }

    /// Record that a key is now held, or that asking for it is pointless.
    pub fn resolved_key(&mut self, peer: NodeId) -> bool {
        self.key_wants.remove(&peer)
    }

    /// Note that a contact is undialable, so its key is worth fetching.
    pub fn wants_key(&mut self, peer: NodeId) {
        if peer != self.local() {
            self.key_wants.insert(peer);
        }
    }

    /// Whom to ask for `address`, nearest-first, without a multi-hop lookup.
    ///
    /// The one-hop answer, and the one [`super::service`] uses today: known
    /// holders first, then the peers nearest the key as somewhere to ask. It is
    /// strictly better than asking the dial sample — it asks nodes with a reason
    /// to know — and it is strictly worse than the iterative lookup, which is
    /// built in [`crate::dht::Lookup`] and not yet driven across connections.
    pub fn candidates(&self, address: &str, now: u64) -> Vec<SocketAddr> {
        let (holders, closer) = self.lookup_providers(address, now);
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        for holder in holders {
            if seen.insert(holder.provider()) {
                out.push(holder.addr);
            }
        }
        for contact in closer {
            if seen.insert(contact.id()) {
                out.push(contact.addr);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(n: u8) -> PeerId {
        let mut id = [0u8; 32];
        id[0] = n;
        id
    }

    fn addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().expect("an address")
    }

    fn address(byte: u8) -> String {
        format!("{:02x}", byte).repeat(32)
    }

    #[test]
    fn a_peer_id_is_the_node_id_with_no_second_hash() {
        // If this ever stops holding, a peer occupies a keyspace point its own
        // handshake cannot compute, and every lookup for it goes to the wrong
        // neighbourhood.
        let id = peer(0xab);
        let contact = PeerContact::new(id, addr(9000), 1);
        assert_eq!(contact.id.as_bytes(), &id);
        assert_eq!(contact.peer_id(), id);
    }

    #[test]
    fn a_contact_is_tiny_because_it_cannot_afford_to_carry_a_mceliece_key() {
        // The constraint this module is shaped by. A McEliece public key is
        // 261,120 bytes; a full table is K * ID_BITS contacts.
        assert!(
            std::mem::size_of::<PeerContact>() < 128,
            "a contact grew a key: {} bytes",
            std::mem::size_of::<PeerContact>()
        );
    }

    fn asked(one: &str) -> BTreeSet<String> {
        let mut set = BTreeSet::new();
        set.insert(one.to_string());
        set
    }

    #[test]
    fn a_told_holding_is_attributed_to_the_session_and_not_to_the_message() {
        // The anti-amplification rule. There is no id field on `Tell`, so this
        // test asserts the shape of the API: the only way to record a provider
        // is to pass the peer id the caller was actually talking to.
        let mut directory = Directory::new(peer(1));
        let held = address(0xaa);
        assert_eq!(
            directory.record_tell(
                peer(2),
                addr(9002),
                &asked(&held),
                std::slice::from_ref(&held),
                0
            ),
            1
        );

        let (holders, _) = directory.lookup_providers(&held, 0);
        assert_eq!(holders.len(), 1);
        assert_eq!(holders[0].peer_id(), peer(2));
        assert_eq!(holders[0].addr, addr(9002));
    }

    #[test]
    fn a_peer_volunteering_an_unasked_holding_is_ignored() {
        // The enforcement half of "no inventory message". Without this a peer
        // could answer a one-address ask with its entire store, and the privacy
        // property `code` refuses to spend would be spent by convention only.
        let mut directory = Directory::new(peer(1));
        let wanted = address(0xaa);
        let volunteered = address(0xbb);
        let stored = directory.record_tell(
            peer(2),
            addr(9002),
            &asked(&wanted),
            &[wanted.clone(), volunteered.clone()],
            0,
        );
        assert_eq!(stored, 1, "only the asked-for address is recorded");
        assert!(directory.lookup_providers(&volunteered, 0).0.is_empty());
    }

    #[test]
    fn an_answer_is_the_intersection_and_never_a_superset() {
        let held: BTreeSet<String> = [address(0xaa), address(0xbb)].into_iter().collect();
        let answer = Directory::answer_ask(&[address(0xaa), address(0xcc)], &held);
        assert_eq!(
            answer,
            vec![address(0xaa)],
            "a responder that added anything would be publishing an inventory"
        );
    }

    #[test]
    fn a_provider_record_lapses_so_a_departed_peer_stops_being_advertised() {
        let mut directory = Directory::new(peer(1));
        let held = address(0xaa);
        directory.record_tell(
            peer(2),
            addr(9002),
            &asked(&held),
            std::slice::from_ref(&held),
            0,
        );

        assert_eq!(
            directory
                .lookup_providers(&held, PROVIDER_TTL_SECS - 1)
                .0
                .len(),
            1
        );
        assert_eq!(
            directory.lookup_providers(&held, PROVIDER_TTL_SECS).0.len(),
            0,
            "expiry is exclusive"
        );
        assert_eq!(directory.expire(PROVIDER_TTL_SECS), 1);
    }

    #[test]
    fn re_announcing_extends_the_record_rather_than_duplicating_the_peer() {
        let mut directory = Directory::new(peer(1));
        let held = address(0xaa);
        let want = asked(&held);
        directory.record_tell(peer(2), addr(9002), &want, std::slice::from_ref(&held), 0);
        directory.record_tell(
            peer(2),
            addr(9002),
            &want,
            std::slice::from_ref(&held),
            1_000,
        );

        let (holders, _) = directory.lookup_providers(&held, PROVIDER_TTL_SECS + 500);
        assert_eq!(holders.len(), 1, "one peer, announced twice");
    }

    #[test]
    fn candidates_prefer_known_holders_and_fall_back_to_the_nearest_peers() {
        let mut directory = Directory::new(peer(1));
        let held = address(0xaa);
        directory.saw(PeerContact::new(peer(0x10), addr(9010), 1));
        directory.saw(PeerContact::new(peer(0x20), addr(9020), 1));
        directory.record_tell(
            peer(0x30),
            addr(9030),
            &asked(&held),
            std::slice::from_ref(&held),
            0,
        );
        directory.saw(PeerContact::new(peer(0x30), addr(9030), 1));

        let candidates = directory.candidates(&held, 0);
        assert_eq!(candidates[0], addr(9030), "the known holder is asked first");
        assert_eq!(candidates.len(), 3, "and the rest are somewhere to ask");
        // No peer appears twice, even though 0x30 is both a holder and a contact.
        let unique: BTreeSet<_> = candidates.iter().collect();
        assert_eq!(unique.len(), candidates.len());
    }

    #[test]
    fn a_blob_nobody_has_announced_still_yields_somewhere_to_ask() {
        let mut directory = Directory::new(peer(1));
        directory.saw(PeerContact::new(peer(0x10), addr(9010), 1));
        let candidates = directory.candidates(&address(0xbb), 0);
        assert_eq!(
            candidates,
            vec![addr(9010)],
            "a miss returns the nearest peers, or a lookup could never start"
        );
    }

    #[test]
    fn an_address_that_is_not_a_digest_stores_nothing_rather_than_panicking() {
        let mut directory = Directory::new(peer(1));
        let stored = directory.record_tell(
            peer(2),
            addr(9002),
            &asked("not-a-digest"),
            &["not-a-digest".into()],
            0,
        );
        assert_eq!(stored, 0);
        assert!(directory.providers_store().is_empty());
    }

    #[test]
    fn every_message_round_trips_through_canonical_form() {
        let messages = vec![
            DhtMessage::FindNode {
                target: NodeId::of_digest(&address(0xaa)).expect("a digest"),
            },
            DhtMessage::Nodes {
                contacts: vec![PeerContact::new(peer(2), addr(9002), 7)],
            },
            DhtMessage::GetProviders {
                addresses: vec![address(0xaa), address(0xbb)],
            },
            // Empty is the common case, not an error: the round is symmetric
            // and both ends send this whether or not they are looking for
            // anything.
            DhtMessage::GetProviders {
                addresses: Vec::new(),
            },
            DhtMessage::Providers {
                answers: vec![ProviderAnswer {
                    address: address(0xaa),
                    holders: vec![Holder::new(peer(3), addr(9003))],
                    closer: vec![PeerContact::new(peer(4), addr(9004), 1)],
                }],
            },
            DhtMessage::Providers {
                answers: Vec::new(),
            },
            DhtMessage::GetKey {
                peers: vec![NodeId::from_bytes(peer(5))],
            },
            DhtMessage::Keys {
                keys: vec!["ab".repeat(KEY_HEX_LEN / 2)],
            },
            DhtMessage::Ask {
                addresses: vec![address(0xaa), address(0xbb)],
            },
            DhtMessage::Tell {
                addresses: vec![address(0xaa)],
            },
        ];
        for message in messages {
            let decoded = DhtMessage::from_value(&message.to_value()).expect("decodes");
            assert_eq!(decoded, message);
        }
    }

    #[test]
    fn an_oversized_answer_is_refused_against_its_declared_count() {
        let contacts: Vec<Value> = (0..MAX_CONTACTS_PER_MESSAGE + 1)
            .map(|n| PeerContact::new(peer(n as u8), addr(9000 + n as u16), 1).to_value())
            .collect();
        let value = obj! {
            "t" => Value::string("dht_nodes"),
            "contacts" => Value::Array(contacts),
        };
        assert_eq!(
            DhtMessage::from_value(&value),
            Err(DhtError::TooMany {
                limit: MAX_CONTACTS_PER_MESSAGE,
                got: MAX_CONTACTS_PER_MESSAGE + 1,
            })
        );
    }

    #[test]
    fn a_key_that_is_not_a_content_address_is_refused_rather_than_ignored() {
        // Refused because a key is used to index a store and a peer sending
        // something else is probing, not confused -- the same rule
        // `super::code` applies to blob addresses.
        let value = obj! {
            "t" => Value::string("dht_get_providers"),
            "addresses" => Value::Array(vec![Value::string("../../etc/passwd")]),
        };
        assert!(matches!(
            DhtMessage::from_value(&value),
            Err(DhtError::NotAnAddress { .. })
        ));
        // The same rule inside a `Providers` answer. Every address-bearing
        // field goes through one decoder, so a message added later cannot
        // forget the check -- but the answer nests one level deeper than the
        // rest and is worth pinning separately.
        let nested = obj! {
            "t" => Value::string("dht_providers"),
            "answers" => Value::Array(vec![obj! {
                "address" => Value::string("../../etc/passwd"),
                "holders" => Value::Array(Vec::new()),
                "closer" => Value::Array(Vec::new()),
            }]),
        };
        assert!(matches!(
            DhtMessage::from_value(&nested),
            Err(DhtError::NotAnAddress { .. })
        ));
    }

    #[test]
    fn a_contact_with_an_unparseable_address_is_refused() {
        let value = obj! {
            "t" => Value::string("dht_nodes"),
            "contacts" => Value::Array(vec![obj! {
                "id" => Value::string(NodeId::from_bytes(peer(2)).to_hex()),
                "addr" => Value::string("not-an-address"),
                "seq" => Value::Int(1),
            }]),
        };
        assert!(matches!(
            DhtMessage::from_value(&value),
            Err(DhtError::BadAddress { .. })
        ));
    }

    #[test]
    fn a_negative_sequence_number_is_refused_rather_than_wrapping() {
        // `seq` is a u64 in memory and an i64 on the wire. Casting a negative
        // through would produce a contact no later record could ever supersede.
        let value = obj! {
            "t" => Value::string("dht_nodes"),
            "contacts" => Value::Array(vec![obj! {
                "id" => Value::string(NodeId::from_bytes(peer(2)).to_hex()),
                "addr" => Value::string("127.0.0.1:9002"),
                "seq" => Value::Int(-1),
            }]),
        };
        assert!(matches!(
            DhtMessage::from_value(&value),
            Err(DhtError::Malformed { .. })
        ));
    }

    #[test]
    fn an_unknown_message_type_is_refused() {
        let value = obj! { "t" => Value::string("dht_something_else") };
        assert!(matches!(
            DhtMessage::from_value(&value),
            Err(DhtError::Malformed { .. })
        ));
    }

    #[test]
    fn a_stale_contact_never_displaces_a_newer_one_for_the_same_peer() {
        let mut directory = Directory::new(peer(1));
        directory.saw(PeerContact::new(peer(2), addr(9002), 9));
        directory.saw(PeerContact::new(peer(2), addr(7777), 3));
        let held: Vec<_> = directory.routing().contacts().collect();
        assert_eq!(held.len(), 1);
        assert_eq!(
            held[0].addr,
            addr(9002),
            "a replayed old address is ignored"
        );
    }

    // -- the multi-hop driver ----------------------------------------------

    /// One answer, as a peer would send it.
    fn answer(address: &str, holders: Vec<Holder>, closer: Vec<PeerContact>) -> ProviderAnswer {
        ProviderAnswer {
            address: address.to_string(),
            holders,
            closer,
        }
    }

    #[test]
    fn a_lookup_walks_from_one_peer_to_the_next_until_it_finds_a_holder() {
        // The whole point of the item this closes. Before it, a node asked
        // whoever it had and stopped; the blob held by a peer two hops away was
        // found by luck or not at all.
        let target = address(0xff);
        let mut directory = Directory::new(peer(1));
        directory.saw(PeerContact::new(peer(2), addr(9002), 0));
        assert!(directory.seek(&target));

        // Hop one: peer 2 knows nothing but points at peer 3.
        let first = directory.next_hops(3, |_| true);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].id, NodeId::from_bytes(peer(2)));
        assert_eq!(directory.ask_of(first[0].id), vec![target.clone()]);
        directory.on_providers(
            first[0].id,
            &[answer(
                &target,
                Vec::new(),
                vec![PeerContact::new(peer(3), addr(9003), 0)],
            )],
        );
        assert!(
            directory.take_finished().is_empty(),
            "a lookup with somewhere left to go is not finished"
        );

        // Hop two: peer 3 names the holder. This hop exists only because hop
        // one taught the lookup about peer 3.
        let second = directory.next_hops(3, |_| true);
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].id, NodeId::from_bytes(peer(3)));
        directory.on_providers(
            second[0].id,
            &[answer(
                &target,
                vec![Holder::new(peer(9), addr(9009))],
                Vec::new(),
            )],
        );

        let finished = directory.take_finished();
        assert_eq!(finished.len(), 1);
        assert_eq!(finished[0].0, target);
        assert_eq!(finished[0].1, vec![Holder::new(peer(9), addr(9009))]);
        assert!(!directory.seeking(), "a finished lookup is drained");
    }

    #[test]
    fn a_relayed_holder_is_a_result_and_never_enters_the_provider_store() {
        // The rule that makes an unsigned DHT safe. A peer saying "C holds D"
        // cannot prove it; storing it would let an attacker name a victim as
        // the holder of a popular blob and have the network dial the victim.
        let target = address(0xff);
        let mut directory = Directory::new(peer(1));
        directory.saw(PeerContact::new(peer(2), addr(9002), 0));
        directory.seek(&target);
        let hop = directory.next_hops(3, |_| true);
        directory.on_providers(
            hop[0].id,
            &[answer(
                &target,
                vec![Holder::new(peer(9), addr(9009))],
                Vec::new(),
            )],
        );

        assert_eq!(
            directory.take_finished()[0].1.len(),
            1,
            "returned to the caller"
        );
        assert!(
            directory.providers_store().is_empty(),
            "a relayed claim was stored; this is the amplification bug"
        );
    }

    #[test]
    fn an_answer_for_something_this_peer_was_not_asked_is_discarded() {
        // Otherwise the peer, not this node, chooses what enters its state --
        // the same rule `record_tell` applies to an unasked `Tell`. The
        // contact inside such an answer is the payload: admitting it would let
        // any peer write into this node's routing table by volunteering.
        let sought = address(0xaa);
        let unasked = address(0xbb);
        let mut directory = Directory::new(peer(1));
        directory.saw(PeerContact::new(peer(2), addr(9002), 0));
        directory.seek(&sought);
        let hops = directory.next_hops(3, |_| true);

        directory.on_providers(
            hops[0].id,
            &[
                answer(&sought, Vec::new(), Vec::new()),
                // Never asked for. Everything in it must be dropped.
                answer(
                    &unasked,
                    vec![Holder::new(peer(8), addr(9008))],
                    vec![PeerContact::new(peer(3), addr(9003), 0)],
                ),
            ],
        );

        let known: Vec<NodeId> = directory.routing().contacts().map(|c| c.id).collect();
        assert!(
            !known.contains(&NodeId::from_bytes(peer(3))),
            "a contact volunteered under an unasked address entered the table"
        );
        assert_eq!(known.len(), 1, "only the peer that was actually dialled");
    }

    #[test]
    fn a_partial_answer_does_not_leave_the_unanswered_lookups_hanging() {
        // A peer asked about two keys that answers about one has said nothing
        // about the other. Treating the silence as "still waiting" would leave
        // it marked in-flight and that lookup would never terminate.
        let answered = address(0xaa);
        let ignored = address(0xbb);
        let mut directory = Directory::new(peer(1));
        directory.saw(PeerContact::new(peer(2), addr(9002), 0));
        directory.seek(&answered);
        directory.seek(&ignored);
        let hops = directory.next_hops(3, |_| true);
        assert_eq!(directory.ask_of(hops[0].id).len(), 2);

        directory.on_providers(hops[0].id, &[answer(&answered, Vec::new(), Vec::new())]);

        let finished = directory.take_finished();
        assert_eq!(
            finished.len(),
            2,
            "the ignored lookup is still waiting on a peer that already replied"
        );
    }

    #[test]
    fn an_unreachable_peer_resolves_every_lookup_that_was_waiting_on_it() {
        // Without this the peer stays marked in-flight in each lookup and none
        // of them ever reaches `is_done` -- a DHT that looks like it simply
        // stopped answering.
        let one = address(0xaa);
        let two = address(0xbb);
        let mut directory = Directory::new(peer(1));
        directory.saw(PeerContact::new(peer(2), addr(9002), 0));
        directory.seek(&one);
        directory.seek(&two);
        let hops = directory.next_hops(4, |_| true);
        assert_eq!(
            hops.len(),
            1,
            "one contact, deduplicated across two lookups"
        );

        directory.on_unreachable(hops[0].id);
        let finished = directory.take_finished();
        assert_eq!(finished.len(), 2, "both lookups terminated");
        assert!(finished.iter().all(|(_, holders)| holders.is_empty()));
    }

    #[test]
    fn a_contact_answering_more_questions_is_dialled_first() {
        // One dial, several hops. The peers nearest two different keys overlap
        // heavily, so ordering by how many lookups a contact advances is what
        // makes a fanout of three worth more than three separate searches.
        let mut directory = Directory::new(peer(1));
        // More contacts than ALPHA, so each lookup picks the three nearest
        // *its own* target and the chosen sets genuinely differ. With three
        // contacts and three lookups every count would be three and the
        // assertion below would hold whether or not anything was sorted.
        for n in 2..12u8 {
            directory.saw(PeerContact::new(peer(n), addr(9000 + n as u16), 0));
        }
        for byte in [0x11, 0x55, 0x99, 0xcc] {
            directory.seek(&address(byte));
        }
        let hops = directory.next_hops(16, |_| true);
        let counts: Vec<usize> = hops
            .iter()
            .map(|contact| directory.ask_of(contact.id).len())
            .collect();
        assert!(
            counts.iter().any(|count| *count != counts[0]),
            "the fixture does not discriminate: every contact answers {counts:?}"
        );
        assert!(
            counts.windows(2).all(|pair| pair[0] >= pair[1]),
            "hops are not ordered by how much they advance: {counts:?}"
        );
    }

    #[test]
    fn seeking_a_key_with_nothing_to_route_through_does_not_start_a_lookup() {
        // A lookup with no seeds can never move, and one that sat in the map
        // would make `next_hops` return nothing forever while `seeking` said
        // work was in progress. The caller falls back to its random sample.
        let mut directory = Directory::new(peer(1));
        assert!(!directory.seek(&address(0xaa)));
        assert!(!directory.seeking());
        assert!(directory.next_hops(3, |_| true).is_empty());
    }

    #[test]
    fn a_contact_with_no_key_is_deferred_rather_than_written_off() {
        // The bug this exists to prevent: treating "I cannot dial you yet" as a
        // timeout marks the contact queried, so when its key arrives one round
        // later the lookup has already given up on it -- and the multi-hop
        // search stops at exactly the peers the node started with.
        let target = address(0xff);
        let mut directory = Directory::new(peer(1));
        directory.saw(PeerContact::new(peer(2), addr(9002), 0));
        directory.seek(&target);

        // Round one: not dialable. Offered again, and its key is queued.
        assert!(directory.next_hops(3, |_| false).is_empty());
        assert!(directory.key_wants().contains(&NodeId::from_bytes(peer(2))));
        assert!(
            directory.take_finished().is_empty(),
            "a deferred contact ended the lookup"
        );

        // Round two: the key arrived, and the contact is still available.
        let hops = directory.next_hops(3, |_| true);
        assert_eq!(hops.len(), 1);
        assert_eq!(hops[0].id, NodeId::from_bytes(peer(2)));
    }

    #[test]
    fn a_key_that_never_arrives_does_not_stall_the_lookup_forever() {
        // The other half. A deferral that is never converted to a timeout is a
        // contact offered every round for ever, and a lookup that never
        // terminates -- which presents as a DHT that quietly stopped working.
        let target = address(0xff);
        let mut directory = Directory::new(peer(1));
        directory.saw(PeerContact::new(peer(2), addr(9002), 0));
        directory.seek(&target);

        for _ in 0..MAX_DEFERRALS {
            assert!(directory.next_hops(3, |_| false).is_empty());
            assert!(directory.take_finished().is_empty());
        }
        // One past the bound: given up on, and the lookup terminates with
        // nothing rather than hanging.
        assert!(directory.next_hops(3, |_| false).is_empty());
        let finished = directory.take_finished();
        assert_eq!(finished.len(), 1, "the lookup never terminated");
        assert!(finished[0].1.is_empty());
    }

    #[test]
    fn a_key_answer_must_hash_to_the_id_it_was_asked_for() {
        // The whole authentication story for a relayed key, and it needs no
        // signature: a peer id *is* `sha256(public key)`.
        let wrong = "ab".repeat(KEY_HEX_LEN / 2);
        assert_eq!(
            decode_key(NodeId::from_bytes(peer(7)), &wrong),
            None,
            "a key that does not hash to the id asked for was accepted"
        );
        // And a real one round-trips.
        let identity = crate::p2p::handshake::PeerIdentity::generate();
        let hex = encode_key(identity.public_key().as_ref());
        assert_eq!(hex.len(), KEY_HEX_LEN);
        assert_eq!(
            decode_key(NodeId::from_bytes(identity.id()), &hex).as_deref(),
            Some(identity.public_key().as_ref() as &[u8])
        );
        // Wrong length is refused before anything is copied.
        assert_eq!(decode_key(NodeId::from_bytes(identity.id()), "abcd"), None);
    }

    #[test]
    fn an_undialable_contact_queues_its_key_and_the_queue_is_bounded() {
        let mut directory = Directory::new(peer(1));
        for n in 2..10u8 {
            directory.wants_key(NodeId::from_bytes(peer(n)));
        }
        assert_eq!(
            directory.key_wants().len(),
            MAX_KEYS_PER_MESSAGE,
            "a round must not be able to ask for megabytes of keys"
        );
        assert!(directory.resolved_key(directory.key_wants()[0]));
        // A node never asks for its own key.
        directory.wants_key(directory.local());
        assert!(!directory
            .key_wants()
            .contains(&Directory::new(peer(1)).local()));
    }
}
