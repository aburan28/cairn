//! Peer-hint anti-entropy: gossiping signed peer records, as routing hints.
//!
//! This is the "signed, size-capped peer-list exchange" that `docs/p2p.md` has
//! carried under *Still open* since the address book existed. Without it a
//! node's peer set grows only from the bootstrap files its operator wrote and
//! from the log those seeds serve — so blocking a handful of seed addresses
//! partitions every newcomer, which hands a censor a chokepoint the rest of the
//! design spends heavily to avoid. With it, any one reachable peer re-supplies
//! the whole peer set: a [`crate::records::PeerRecord`] posted in anyone's log
//! spreads epidemically, and the network's reachability heals through the mesh
//! rather than through an operator.
//!
//! # Why these records must never reach the ledger
//!
//! The obvious design — make `peer` an exchangeable kind on the record path, so
//! synced records replay into the log like a claim does — is a trap, and
//! `docs/censorship.md` names it: **the sealed-submission committee is drawn
//! from the log's peer records**. Today nothing appends one but the operator's
//! own `cairn peer`, and that is exactly what makes a five-seat committee
//! meaningful. The moment a stranger's record can enter the log over sync, an
//! attacker who registers enough free identities owns a majority of every
//! drawn committee — early decryption and stalled reveals, which are the two
//! censorship attacks the committee exists to kill. So hints travel in their
//! own message family, land in a bounded store on the *routing* side, and the
//! ledger — and therefore [`crate::node::Node::peers`] and every committee
//! draw — never hears about them.
//!
//! The same separation is what bounds the damage of a flood. A ledger is
//! append-only and identities are free, so ledger admission would hand anyone
//! unbounded permanent writes; the hint store is capped and refuses new
//! identities past the cap instead.
//!
//! # What a lie costs
//!
//! The record format's own argument ([`crate::records::PeerRecord`]) carries
//! over unchanged: a hint is signed by the identity it speaks for, a stale
//! replay loses to the signed `seq`, and a fabricated address costs the dialler
//! one failed handshake — the peer id is the hash of the transport key, so no
//! impostor can answer for it. What signing does *not* bound is volume, which
//! is what [`MAX_HINTS`] and the per-message ceilings are for.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::canonical::Value;
use crate::obj;
use crate::records::PeerRecord;

/// AEAD context for peer-hint frames.
///
/// Distinct from every other family's, so a hint frame cannot be opened as a
/// record, code, DHT or population frame even by a peer that wants to — the
/// same mechanical boundary [`super::pop::CONTEXT`] documents.
// Spelled `proofwork/` and not `cairn/` for the reason `pop::CONTEXT` gives:
// a wire constant, not a brand.
pub const CONTEXT: &[u8] = b"proofwork/p2p/peers/v1";

/// Most identities the hint store holds beyond what the log pins.
///
/// A cap, and *refusal* past it rather than eviction — an evicting store lets
/// whoever sends last wash out every entry that came before, which turns a
/// flood into an eclipse of exactly the peers a node could still dial. Refusal
/// means a flood can squat the free slots and can never displace a peer the
/// log vouched for or one learned before the flood began. That is honest
/// flood *containment*, not Sybil resistance: identities are free, so a fast
/// attacker still fills the unpinned half. Structured overlays with identities
/// that cost something remain Stage 2, and `docs/p2p.md` says so in the same
/// breath as this constant.
pub const MAX_HINTS: usize = 512;

/// Why a peer-hint message or record was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeersError {
    /// A message did not decode.
    Malformed { detail: String },
    /// A peer offered more than the configured ceiling in one message.
    TooMany { limit: usize, got: usize },
    /// A record body was not decodable as a peer record.
    BadRecord { detail: String },
}

impl fmt::Display for PeersError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeersError::Malformed { detail } => write!(f, "malformed peer-hint message: {detail}"),
            PeersError::TooMany { limit, got } => {
                write!(f, "peer-hint message carries {got} items, limit is {limit}")
            }
            PeersError::BadRecord { detail } => write!(f, "not a peer record: {detail}"),
        }
    }
}

impl std::error::Error for PeersError {}

/// Ceilings, checked *before* allocating — same discipline as
/// [`super::pop::PopLimits`].
///
/// The defaults are generous against an honest store bounded by [`MAX_HINTS`]
/// and tight against a peer that has decided to send a million of something.
#[derive(Debug, Clone, Copy)]
pub struct PeerHintLimits {
    pub max_ids_per_message: usize,
    pub max_records_per_message: usize,
    /// Longest canonical encoding one record may have. A valid record is a few
    /// hundred bytes — two 64-hex keys, an address capped at
    /// [`crate::records::MAX_PEER_ADDR`], a timestamp and a signature — so
    /// anything near this bound is not one.
    pub max_record_bytes: usize,
}

impl Default for PeerHintLimits {
    fn default() -> PeerHintLimits {
        PeerHintLimits {
            max_ids_per_message: 2_048,
            max_records_per_message: 512,
            max_record_bytes: 1_024,
        }
    }
}

/// A peer-hint protocol message.
///
/// A separate type from [`super::sync::Message`] and [`super::pop::PopMessage`]
/// for the reason those two are separate from each other: a shared enum would
/// mean one decoder, one set of ceilings and one `match` covering families
/// with different trust rules, and the next variant added would have to be
/// kept out of the wrong half by vigilance rather than by type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeersMessage {
    /// "Here is my hint digest and every record id in it."
    ///
    /// The digest is the early-out: equal digests mean equal id sets, and the
    /// exchange stops at one message each way. The ids travel with it rather
    /// than in a second round because the store is bounded by construction.
    Digest { digest: String, ids: Vec<String> },
    /// "Send me these." Record ids the sender does not hold.
    Want { ids: Vec<String> },
    /// The bodies.
    Records { records: Vec<PeerRecord> },
}

impl PeersMessage {
    pub fn to_value(&self) -> Value {
        let strings = |ids: &Vec<String>| {
            Value::Array(ids.iter().map(|i| Value::string(i.clone())).collect())
        };
        match self {
            PeersMessage::Digest { digest, ids } => obj! {
                "t" => Value::string("peers_digest"),
                "digest" => Value::string(digest.clone()),
                "ids" => strings(ids),
            },
            PeersMessage::Want { ids } => obj! {
                "t" => Value::string("peers_want"),
                "ids" => strings(ids),
            },
            PeersMessage::Records { records } => obj! {
                "t" => Value::string("peers_records"),
                "records" => Value::Array(records.iter().map(PeerRecord::to_value).collect()),
            },
        }
    }

    /// Decode, enforcing `limits` **before** building any vector.
    pub fn from_value(value: &Value, limits: PeerHintLimits) -> Result<PeersMessage, PeersError> {
        let bad = |detail: String| PeersError::Malformed { detail };
        let ids = |field: &str, limit: usize| -> Result<Vec<String>, PeersError> {
            let items = value
                .get(field)
                .and_then(Value::as_array)
                .ok_or_else(|| bad(format!("{field} is not an array")))?;
            if items.len() > limit {
                return Err(PeersError::TooMany {
                    limit,
                    got: items.len(),
                });
            }
            items
                .iter()
                .map(|item| {
                    item.as_str()
                        .map(str::to_string)
                        .ok_or_else(|| bad(format!("{field} contains a non-string")))
                })
                .collect()
        };
        match value.get("t").and_then(Value::as_str) {
            Some("peers_digest") => Ok(PeersMessage::Digest {
                digest: value
                    .get("digest")
                    .and_then(Value::as_str)
                    .ok_or_else(|| bad("peers_digest has no digest".into()))?
                    .to_string(),
                ids: ids("ids", limits.max_ids_per_message)?,
            }),
            Some("peers_want") => Ok(PeersMessage::Want {
                ids: ids("ids", limits.max_ids_per_message)?,
            }),
            Some("peers_records") => {
                let items = value
                    .get("records")
                    .and_then(Value::as_array)
                    .ok_or_else(|| bad("records is not an array".into()))?;
                if items.len() > limits.max_records_per_message {
                    return Err(PeersError::TooMany {
                        limit: limits.max_records_per_message,
                        got: items.len(),
                    });
                }
                let mut records = Vec::with_capacity(items.len());
                for item in items {
                    // The count ceiling has passed, so this per-item measure
                    // allocates at most `max_records_per_message` bounded
                    // strings. A record over the byte cap cannot be a valid
                    // peer record at all -- see `PeerHintLimits`.
                    let size = item.canonical_string().len();
                    if size > limits.max_record_bytes {
                        return Err(PeersError::TooMany {
                            limit: limits.max_record_bytes,
                            got: size,
                        });
                    }
                    records.push(PeerRecord::from_value(item).map_err(|e| {
                        PeersError::BadRecord {
                            detail: e.to_string(),
                        }
                    })?);
                }
                Ok(PeersMessage::Records { records })
            }
            other => Err(bad(format!("unknown peer-hint message type {other:?}"))),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        self.to_value().canonical_string().into_bytes()
    }

    pub fn decode(bytes: &[u8], limits: PeerHintLimits) -> Result<PeersMessage, PeersError> {
        let text = std::str::from_utf8(bytes).map_err(|_| PeersError::Malformed {
            detail: "not UTF-8".into(),
        })?;
        let value = Value::from_json(text).map_err(|e| PeersError::Malformed {
            detail: e.to_string(),
        })?;
        PeersMessage::from_value(&value, limits)
    }
}

/// Why a record was not taken into the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HintRefusal {
    /// Structurally invalid — [`PeerRecord::validate`] said no.
    Inadmissible { detail: String },
    /// Unsigned, or signed by a key that is not the record's `identity`.
    BadSignature { detail: String },
    /// The identity has already said something at least as fresh.
    Stale { seq: u64, held: u64 },
    /// The store is full and this identity is new to it.
    Full,
}

impl fmt::Display for HintRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HintRefusal::Inadmissible { detail } => write!(f, "inadmissible: {detail}"),
            HintRefusal::BadSignature { detail } => write!(f, "bad signature: {detail}"),
            HintRefusal::Stale { seq, held } => {
                write!(f, "seq {seq} does not advance {held}")
            }
            HintRefusal::Full => write!(f, "hint store is full"),
        }
    }
}

/// What [`Hints::insert`] did with a record it accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admitted {
    /// New, or fresher than what was held.
    Taken,
    /// Byte-identical to what was already held.
    Duplicate,
}

struct Entry {
    record: PeerRecord,
    /// Pinned entries came from this node's own log and are exempt from
    /// [`MAX_HINTS`]: the log already admitted them under `post_peer`'s rules,
    /// and a gossip flood must not be able to crowd out a peer the log vouches
    /// for.
    pinned: bool,
}

/// The bounded, signature-checked store of gossiped peer records.
///
/// One record per identity, highest `seq` wins — the same resolution rule as
/// [`crate::node::Node::peers`], applied to records that never reach a ledger.
#[derive(Default)]
pub struct Hints {
    held: BTreeMap<String, Entry>,
    /// Record id → identity, so a `Want` can be served without a scan.
    by_id: BTreeMap<String, String>,
}

impl Hints {
    pub fn new() -> Hints {
        Hints::default()
    }

    /// How many identities beyond the pinned ones count against [`MAX_HINTS`].
    fn unpinned(&self) -> usize {
        self.held.values().filter(|entry| !entry.pinned).count()
    }

    /// Take a gossiped record. Signature and freshness rules are the record's
    /// own; the cap is this store's.
    pub fn insert(&mut self, record: PeerRecord) -> Result<Admitted, HintRefusal> {
        self.admit(record, false)
    }

    /// Take a record from this node's own log, exempt from the cap.
    ///
    /// Idempotent per tick by construction: a record already held is a
    /// [`Admitted::Duplicate`], and re-pinning an entry a flood arrived before
    /// upgrades it rather than duplicating it.
    pub fn pin(&mut self, record: PeerRecord) -> Result<Admitted, HintRefusal> {
        self.admit(record, true)
    }

    fn admit(&mut self, record: PeerRecord, pinned: bool) -> Result<Admitted, HintRefusal> {
        // The same order as `Node::post_peer`, for the same reason: a record
        // that does not prove who it speaks for is refused before its contents
        // are consulted at all.
        record.validate().map_err(|e| HintRefusal::Inadmissible {
            detail: e.to_string(),
        })?;
        record
            .verify_signature()
            .map_err(|e| HintRefusal::BadSignature {
                detail: e.to_string(),
            })?;
        match self.held.get_mut(&record.identity) {
            Some(entry) => {
                if entry.record.seq == record.seq && entry.record == record {
                    // Pinning an entry gossip delivered first still upgrades
                    // its standing even though the bytes are already held.
                    entry.pinned |= pinned;
                    return Ok(Admitted::Duplicate);
                }
                if record.seq <= entry.record.seq {
                    return Err(HintRefusal::Stale {
                        seq: record.seq,
                        held: entry.record.seq,
                    });
                }
                self.by_id.remove(&entry.record.id());
                self.by_id.insert(record.id(), record.identity.clone());
                entry.pinned |= pinned;
                entry.record = record;
                Ok(Admitted::Taken)
            }
            None => {
                if !pinned && self.unpinned() >= MAX_HINTS {
                    return Err(HintRefusal::Full);
                }
                self.by_id.insert(record.id(), record.identity.clone());
                self.held
                    .insert(record.identity.clone(), Entry { record, pinned });
                Ok(Admitted::Taken)
            }
        }
    }

    /// Every record id held, sorted.
    pub fn ids(&self) -> Vec<String> {
        self.by_id.keys().cloned().collect()
    }

    /// Content address of the whole store — the early-out for reconciliation,
    /// computed exactly the way [`crate::gossip::Population::digest`] is: over
    /// the sorted ids alone, so it is independent of arrival order.
    pub fn digest(&self) -> String {
        Value::Array(
            self.by_id
                .keys()
                .map(|id| Value::string(id.clone()))
                .collect(),
        )
        .digest()
    }

    /// Which of a peer's offered ids this store lacks.
    pub fn missing_from(&self, offered: &[String]) -> Vec<String> {
        offered
            .iter()
            .filter(|id| !self.by_id.contains_key(*id))
            .cloned()
            .collect()
    }

    /// Answer a `Want`, skipping ids not held.
    ///
    /// A peer asking for a record that has since been superseded is out of
    /// date, not hostile: ids legitimately disappear when a fresher record for
    /// the same identity lands.
    pub fn serve(&self, ids: &[String], limits: PeerHintLimits) -> Vec<PeerRecord> {
        ids.iter()
            .filter_map(|id| self.by_id.get(id))
            .filter_map(|identity| self.held.get(identity).map(|entry| entry.record.clone()))
            .take(limits.max_records_per_message)
            .collect()
    }

    /// The freshest record per identity, for whoever folds hints into routing.
    pub fn records(&self) -> impl Iterator<Item = &PeerRecord> {
        self.held.values().map(|entry| &entry.record)
    }

    pub fn len(&self) -> usize {
        self.held.len()
    }

    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }
}

/// What an ingest actually did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeersReport {
    /// Records that verified, advanced their identity's `seq`, and were kept.
    pub accepted: usize,
    /// Records refused: unsolicited, unsigned, stale, or past the cap.
    pub refused: usize,
    /// Records already held byte for byte.
    pub duplicates: usize,
}

/// Take records from a peer.
///
/// `wanted` is the id set this side actually asked for; anything outside it is
/// dropped unverified — the same unsolicited-record rule every other family
/// enforces, because a peer that can make a node do signature checks by
/// volunteering records has a small denial of service whether or not any are
/// kept.
pub fn ingest_hints(
    hints: &mut Hints,
    wanted: &BTreeSet<String>,
    records: Vec<PeerRecord>,
) -> PeersReport {
    let mut report = PeersReport::default();
    for record in records {
        if !wanted.contains(&record.id()) {
            report.refused += 1;
            continue;
        }
        match hints.insert(record) {
            Ok(Admitted::Taken) => report.accepted += 1,
            Ok(Admitted::Duplicate) => report.duplicates += 1,
            Err(_) => report.refused += 1,
        }
    }
    report
}

/// Run a full hint reconciliation between two local stores.
///
/// The reference driver, and what the tests check convergence against. It also
/// documents the message order the networked implementation follows; see
/// [`super::session::exchange_peer_hints`].
pub fn reconcile(
    a: &mut Hints,
    b: &mut Hints,
    limits: PeerHintLimits,
) -> (PeersReport, PeersReport) {
    if a.digest() == b.digest() {
        return (PeersReport::default(), PeersReport::default());
    }
    let (ids_a, ids_b) = (a.ids(), b.ids());
    let want_a = a.missing_from(&ids_b);
    let want_b = b.missing_from(&ids_a);
    let to_a = b.serve(&want_a, limits);
    let to_b = a.serve(&want_b, limits);
    let set_a: BTreeSet<String> = want_a.into_iter().collect();
    let set_b: BTreeSet<String> = want_b.into_iter().collect();
    let report_a = ingest_hints(a, &set_a, to_a);
    let report_b = ingest_hints(b, &set_b, to_b);
    (report_a, report_b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::identity::Identity;

    const TS: &str = "2026-08-18T00:00:00+00:00";

    fn signer(byte: u8) -> Identity {
        Identity::from_secret_bytes([byte; 32])
    }

    fn hint(byte: u8, seq: u64, addr: &str) -> PeerRecord {
        let identity = signer(byte);
        PeerRecord::new(identity.submitter_id(), "ab".repeat(32), addr, seq, TS)
            .signed_with(&identity)
    }

    fn store_of(bytes: std::ops::Range<u8>) -> Hints {
        let mut hints = Hints::new();
        for byte in bytes {
            hints
                .insert(hint(byte, 1, "203.0.113.1:9000"))
                .expect("fixture record admits");
        }
        hints
    }

    // -- the boundary between families ---------------------------------------

    #[test]
    fn peer_hint_frames_use_a_different_aead_context_than_records() {
        // The mechanical half of "hints never reach the ledger": a hint frame
        // does not even open under the record family's context, so a confusion
        // attack fails before any decoder sees the bytes.
        use crate::p2p::handshake::PeerIdentity;
        let responder = PeerIdentity::generate();
        let initiator = [3u8; 32];
        let (ct, mut client) = responder.to_public().initiate(initiator);
        let mut server = responder.accept(initiator, &ct).unwrap();

        let message = PeersMessage::Want {
            ids: vec![hint(1, 1, "203.0.113.1:9000").id()],
        };
        let (n, frame) = client.seal(&message.encode(), CONTEXT).unwrap();
        assert!(
            server
                .open(n, &frame, crate::p2p::session::RECORD_CONTEXT)
                .is_err(),
            "a peer-hint frame opened as a record frame"
        );
        let plain = server.open(n, &frame, CONTEXT).unwrap();
        assert_eq!(
            PeersMessage::decode(&plain, PeerHintLimits::default()).unwrap(),
            message
        );
    }

    #[test]
    fn a_peer_record_is_still_not_an_exchangeable_record() {
        // The other half, and the one `docs/censorship.md` insists on: the
        // committee for sealed submissions is drawn from the log's peer
        // records, so a peer record must never enter the log over sync. Even
        // if a hint body reached the record path, `peer` is not exchangeable
        // there.
        let record =
            crate::p2p::sync::Record::new("peer", hint(1, 1, "203.0.113.1:9000").to_value());
        assert!(matches!(
            crate::p2p::sync::Peer::new().insert(record),
            Err(crate::p2p::sync::SyncError::NotExchangeable { .. })
        ));
    }

    // -- admission ------------------------------------------------------------

    #[test]
    fn an_unsigned_or_forged_record_is_refused() {
        let mut hints = Hints::new();
        let identity = signer(1);
        let unsigned = PeerRecord::new(identity.submitter_id(), "ab".repeat(32), "a:1", 1, TS);
        assert!(matches!(
            hints.insert(unsigned),
            Err(HintRefusal::BadSignature { .. })
        ));

        // Signed, then tampered: the signature no longer covers the bytes.
        let mut forged = hint(1, 1, "203.0.113.1:9000");
        forged.addr = "198.51.100.9:9000".into();
        assert!(matches!(
            hints.insert(forged),
            Err(HintRefusal::BadSignature { .. })
        ));
        assert!(hints.is_empty());
    }

    #[test]
    fn a_replayed_record_loses_to_the_signed_sequence() {
        // The attack the `seq` exists for: anyone who once saw a peer record
        // can re-offer the address that peer has left. The store keeps the
        // freshest signed statement and the stale one is refused, so a replay
        // steers nothing.
        let mut hints = Hints::new();
        hints.insert(hint(1, 2, "203.0.113.2:9000")).unwrap();
        assert!(matches!(
            hints.insert(hint(1, 1, "203.0.113.1:9000")),
            Err(HintRefusal::Stale { seq: 1, held: 2 })
        ));
        assert!(matches!(
            hints.insert(hint(1, 2, "198.51.100.7:9000")),
            Err(HintRefusal::Stale { seq: 2, held: 2 })
        ));

        // A fresher record supersedes, and the superseded id stops being
        // offered -- the store advertises one record per identity, not a
        // history.
        let old_id = hint(1, 2, "203.0.113.2:9000").id();
        hints.insert(hint(1, 3, "198.51.100.7:9000")).unwrap();
        assert_eq!(hints.len(), 1);
        assert!(!hints.ids().contains(&old_id));
        assert_eq!(
            hints.records().next().unwrap().addr,
            "198.51.100.7:9000".to_string()
        );
    }

    #[test]
    fn a_full_store_refuses_new_identities_and_still_takes_updates_and_pins() {
        let mut hints = Hints::new();
        for n in 0..MAX_HINTS {
            // Distinct identities from distinct seeds. `u8` wraps at 256, so
            // vary the second byte too.
            let mut secret = [0u8; 32];
            secret[0] = (n % 256) as u8;
            secret[1] = (n / 256) as u8;
            let identity = Identity::from_secret_bytes(secret);
            let record = PeerRecord::new(identity.submitter_id(), "ab".repeat(32), "a:1", 1, TS)
                .signed_with(&identity);
            hints.insert(record).expect("below the cap");
        }
        assert_eq!(hints.len(), MAX_HINTS);

        // A flood past the cap is refused rather than evicting anyone --
        // eviction would let whoever sends last wash out every peer learned
        // before the flood.
        let newcomer = {
            let mut secret = [0u8; 32];
            secret[2] = 9; // outside the seed range the fixtures used
            let identity = Identity::from_secret_bytes(secret);
            PeerRecord::new(identity.submitter_id(), "ab".repeat(32), "a:1", 1, TS)
                .signed_with(&identity)
        };
        assert!(matches!(
            hints.insert(newcomer.clone()),
            Err(HintRefusal::Full)
        ));

        // An identity already held may still move house.
        let mut secret = [0u8; 32];
        secret[0] = 5;
        let held = Identity::from_secret_bytes(secret);
        let moved =
            PeerRecord::new(held.submitter_id(), "ab".repeat(32), "b:2", 2, TS).signed_with(&held);
        assert_eq!(hints.insert(moved), Ok(Admitted::Taken));

        // And the log's own records are never crowded out: a pin is exempt
        // from the cap, because the log already admitted it under
        // `post_peer`'s rules.
        assert_eq!(hints.pin(newcomer), Ok(Admitted::Taken));
        assert_eq!(hints.len(), MAX_HINTS + 1);
    }

    #[test]
    fn pinning_a_record_gossip_delivered_first_upgrades_it() {
        // A record can arrive by gossip before this node's own log learns it.
        // Re-offering it as a pin must not duplicate it, and must exempt it
        // from the cap from then on.
        let mut hints = Hints::new();
        let record = hint(1, 1, "203.0.113.1:9000");
        assert_eq!(hints.insert(record.clone()), Ok(Admitted::Taken));
        assert_eq!(hints.pin(record), Ok(Admitted::Duplicate));
        assert_eq!(hints.len(), 1);
        assert_eq!(hints.unpinned(), 0);
    }

    // -- ingest ---------------------------------------------------------------

    #[test]
    fn unsolicited_records_are_dropped_before_the_signature_is_checked() {
        let mut hints = Hints::new();
        let report = ingest_hints(&mut hints, &BTreeSet::new(), vec![hint(1, 1, "a:1")]);
        assert_eq!(report.refused, 1);
        assert!(hints.is_empty());
    }

    // -- convergence ----------------------------------------------------------

    #[test]
    fn disjoint_stores_converge() {
        let mut a = store_of(0..10);
        let mut b = store_of(10..20);
        let (ra, rb) = reconcile(&mut a, &mut b, PeerHintLimits::default());
        assert_eq!(ra.refused, 0);
        assert_eq!(rb.refused, 0);
        assert_eq!(a.digest(), b.digest());
        assert_eq!(a.len(), 20);
    }

    #[test]
    fn already_synced_stores_send_nothing_and_reconciliation_is_idempotent() {
        let mut a = store_of(0..5);
        let mut b = store_of(5..10);
        reconcile(&mut a, &mut b, PeerHintLimits::default());
        let before = a.digest();
        let (ra, rb) = reconcile(&mut a, &mut b, PeerHintLimits::default());
        assert_eq!(ra, PeersReport::default());
        assert_eq!(rb, PeersReport::default());
        assert_eq!(a.digest(), before);
    }

    #[test]
    fn a_moved_peer_propagates_its_newest_address() {
        // The whole point of the exchange: identity 1 moved, one store heard,
        // and after a round both answer the new address.
        let mut a = store_of(0..3);
        let mut b = store_of(0..3);
        b.insert(hint(1, 5, "198.51.100.7:9000")).unwrap();
        reconcile(&mut a, &mut b, PeerHintLimits::default());
        assert_eq!(a.digest(), b.digest());
        let moved = a
            .records()
            .find(|record| record.identity == signer(1).submitter_id())
            .expect("identity 1 is held");
        assert_eq!(moved.addr, "198.51.100.7:9000");
        assert_eq!(moved.seq, 5);
    }

    // -- ceilings -------------------------------------------------------------

    #[test]
    fn oversized_messages_are_refused_before_allocation() {
        let limits = PeerHintLimits {
            max_ids_per_message: 4,
            max_records_per_message: 2,
            max_record_bytes: 1_024,
        };
        let ids = PeersMessage::Want {
            ids: (0..10).map(|n| hint(n, 1, "a:1").id()).collect(),
        };
        assert!(matches!(
            PeersMessage::decode(&ids.encode(), limits),
            Err(PeersError::TooMany { limit: 4, got: 10 })
        ));

        let bodies = PeersMessage::Records {
            records: (0..10).map(|n| hint(n, 1, "a:1")).collect(),
        };
        assert!(matches!(
            PeersMessage::decode(&bodies.encode(), limits),
            Err(PeersError::TooMany { limit: 2, got: 10 })
        ));
    }

    // -- framing --------------------------------------------------------------

    #[test]
    fn every_message_round_trips_through_canonical_bytes() {
        let limits = PeerHintLimits::default();
        let store = store_of(0..3);
        for message in [
            PeersMessage::Digest {
                digest: store.digest(),
                ids: store.ids(),
            },
            PeersMessage::Want {
                ids: vec![hint(1, 1, "a:1").id()],
            },
            PeersMessage::Records {
                records: vec![hint(1, 1, "a:1"), hint(2, 1, "a:1")],
            },
        ] {
            let bytes = message.encode();
            assert_eq!(PeersMessage::decode(&bytes, limits).unwrap(), message);
            assert_eq!(message.encode(), bytes);
        }
    }

    #[test]
    fn malformed_frames_are_refused_not_guessed() {
        let limits = PeerHintLimits::default();
        for bad in [
            &b"not json"[..],
            b"{}",
            br#"{"t":"want","ids":[]}"#,
            br#"{"t":"peers_want","ids":[1]}"#,
            br#"{"t":"peers_digest","ids":[]}"#,
            br#"{"t":"peers_records","records":[{"identity":"x"}]}"#,
        ] {
            assert!(
                PeersMessage::decode(bad, limits).is_err(),
                "{:?} should not decode",
                std::str::from_utf8(bad)
            );
        }
    }
}
