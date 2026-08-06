//! Set reconciliation: the gossip wire protocol.
//!
//! # Records cross the wire, entries do not
//!
//! A [`Ledger`](crate::ledger::Ledger) entry's hash covers its `seq` and its
//! `prev`, so it is position-dependent: two peers holding the same records in
//! different orders compute different entry hashes for all of them. Entries are
//! therefore *not* the exchangeable unit — a peer's chain is a **local ordering
//! of a set**, and the set is what peers reconcile.
//!
//! The exchangeable unit is a [`Record`]: a `(kind, payload)` pair whose id is
//! the payload's own content address, independent of where anyone filed it.
//!
//! # Only inputs are exchanged. Outputs are re-derived.
//!
//! | kind | crosses the wire? | why |
//! |---|---|---|
//! | `objective`, `commitment`, `claim` | **yes** | primary inputs, signed by nobody's opinion |
//! | `verdict`, `settlement`, `frontier` | **no** | derived by replaying the inputs |
//!
//! This is the whole security argument of the layer. Importing a peer's verdict
//! would mean trusting its verification, which is precisely the trust this
//! system exists to remove. A peer that ships you a `verdict` record is either
//! confused or lying, and [`Peer::ingest`] refuses it either way. Every honest
//! peer re-runs the pinned verifier and reaches the same conclusion without
//! being told, because verification is a pure function of pinned inputs.
//!
//! # Reconciliation
//!
//! Ids are uniformly distributed (they are SHA-256 digests), so bucket by
//! leading byte and summarise each bucket with a count and an XOR of its ids:
//!
//! ```text
//! A -> B   Inventory   256 x (count, xor)     ~8 KB, fixed
//! B -> A   Inventory
//!          BucketIds   only for buckets that differ
//! A -> B   Want        ids A lacks
//! B -> A   Records     the bodies
//! ```
//!
//! Peers already in sync exchange two fixed-size messages and stop — the common
//! case costs no per-record traffic at all. Only buckets that actually differ
//! escalate to id lists.
//!
//! The XOR digest is an *optimisation*, not a security boundary. It reliably
//! catches accidental divergence; a malicious peer could in principle craft a
//! bucket that collides and thereby hide its own records from you, which costs
//! it its own gossip and gains it nothing. Correctness rests on
//! [`Peer::ingest`] re-verifying every record, never on the digest.

use crate::canonical::Value;
use crate::obj;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Buckets in an inventory: one per leading byte of the id.
pub const BUCKETS: usize = 256;

/// Record kinds that may cross the wire. Everything else is derived locally.
pub const EXCHANGEABLE: &[&str] = &["objective", "commitment", "claim"];

/// A record as it travels: the kind, and the canonical body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub kind: String,
    pub payload: Value,
}

impl Record {
    pub fn new(kind: impl Into<String>, payload: Value) -> Record {
        Record {
            kind: kind.into(),
            payload,
        }
    }

    /// Content address of the body. Independent of any peer's ordering.
    pub fn id(&self) -> String {
        self.payload.digest()
    }

    pub fn to_value(&self) -> Value {
        obj! { "kind" => Value::string(self.kind.clone()), "payload" => self.payload.clone() }
    }

    pub fn from_value(value: &Value) -> Option<Record> {
        Some(Record {
            kind: value.get("kind")?.as_str()?.to_string(),
            payload: value.get("payload")?.clone(),
        })
    }
}

/// Why a message or record was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncError {
    /// A record of a kind that is derived, not exchanged.
    NotExchangeable { kind: String },
    /// A peer asked for, or offered, an id that is not a `sha256:` digest.
    MalformedId { id: String },
    /// A message did not decode.
    MalformedMessage { detail: String },
    /// A peer sent a record nobody asked for.
    ///
    /// This also covers substitution, and there is deliberately no separate
    /// "wrong body for this id" variant: a record is keyed by the digest of the
    /// body actually received, so a peer answering a `Want` with different
    /// bytes produces a different id, which was never requested. The
    /// substitution surfaces here, and a distinct variant could never fire.
    Unsolicited { id: String },
    /// A peer offered more than the configured ceiling in one message.
    TooMany { limit: usize, got: usize },
}

impl fmt::Display for SyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SyncError::NotExchangeable { kind } => write!(
                f,
                "record kind {kind:?} is derived locally and is never accepted from a peer"
            ),
            SyncError::MalformedId { id } => write!(f, "not a record id: {id:?}"),
            SyncError::MalformedMessage { detail } => write!(f, "malformed message: {detail}"),
            SyncError::Unsolicited { id } => write!(f, "unsolicited record {id}"),
            SyncError::TooMany { limit, got } => {
                write!(f, "message carries {got} items, limit is {limit}")
            }
        }
    }
}

impl std::error::Error for SyncError {}

/// The 32 id bytes behind a `sha256:<hex>` string.
fn id_bytes(id: &str) -> Option<[u8; 32]> {
    let hex = id.strip_prefix("sha256:")?;
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// A compact summary of which records a peer holds.
///
/// Fixed size — 256 buckets regardless of how many records exist — so two
/// synced peers reconcile in constant traffic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inventory {
    counts: [u32; BUCKETS],
    xors: [[u8; 32]; BUCKETS],
}

impl Default for Inventory {
    fn default() -> Inventory {
        Inventory {
            counts: [0; BUCKETS],
            xors: [[0u8; 32]; BUCKETS],
        }
    }
}

impl Inventory {
    /// Summarise a set of record ids. Malformed ids are refused rather than
    /// bucketed somewhere arbitrary.
    pub fn of<'a, I: IntoIterator<Item = &'a str>>(ids: I) -> Result<Inventory, SyncError> {
        let mut inv = Inventory::default();
        for id in ids {
            let bytes =
                id_bytes(id).ok_or_else(|| SyncError::MalformedId { id: id.to_string() })?;
            let bucket = bytes[0] as usize;
            inv.counts[bucket] += 1;
            for (slot, byte) in inv.xors[bucket].iter_mut().zip(bytes.iter()) {
                *slot ^= byte;
            }
        }
        Ok(inv)
    }

    /// Total records summarised.
    pub fn total(&self) -> u64 {
        self.counts.iter().map(|c| u64::from(*c)).sum()
    }

    /// Buckets where the two peers disagree, and which therefore need id lists.
    ///
    /// A bucket matching on both count and XOR is treated as identical. See the
    /// module docs on why that is safe to assume for correctness.
    pub fn differing(&self, other: &Inventory) -> Vec<u8> {
        (0..BUCKETS)
            .filter(|&b| self.counts[b] != other.counts[b] || self.xors[b] != other.xors[b])
            .map(|b| b as u8)
            .collect()
    }

    /// True when the two summaries agree everywhere.
    pub fn agrees_with(&self, other: &Inventory) -> bool {
        self.differing(other).is_empty()
    }

    pub fn to_value(&self) -> Value {
        // Only non-empty buckets travel: a peer with 40 records sends 40
        // entries, not 256. An empty bucket is implied.
        let entries: Vec<Value> = (0..BUCKETS)
            .filter(|&b| self.counts[b] != 0)
            .map(|b| {
                Value::Array(vec![
                    Value::Int(b as i128),
                    Value::Int(i128::from(self.counts[b])),
                    Value::string(hex(&self.xors[b])),
                ])
            })
            .collect();
        obj! { "buckets" => Value::Array(entries) }
    }

    pub fn from_value(value: &Value) -> Result<Inventory, SyncError> {
        let bad = |detail: &str| SyncError::MalformedMessage {
            detail: detail.to_string(),
        };
        let entries = value
            .get("buckets")
            .and_then(Value::as_array)
            .ok_or_else(|| bad("inventory has no buckets array"))?;
        let mut inv = Inventory::default();
        for entry in entries {
            let row = entry
                .as_array()
                .ok_or_else(|| bad("bucket is not an array"))?;
            if row.len() != 3 {
                return Err(bad("bucket must be [index, count, xor]"));
            }
            let index = row[0]
                .as_i128()
                .ok_or_else(|| bad("bucket index not an integer"))?;
            let count = row[1]
                .as_i128()
                .ok_or_else(|| bad("bucket count not an integer"))?;
            let xor = row[2]
                .as_str()
                .ok_or_else(|| bad("bucket xor not a string"))?;
            if !(0..BUCKETS as i128).contains(&index) {
                return Err(bad("bucket index out of range"));
            }
            let count = u32::try_from(count).map_err(|_| bad("bucket count out of range"))?;
            let xor = unhex(xor).ok_or_else(|| bad("bucket xor is not 32 hex bytes"))?;
            let b = index as usize;
            if inv.counts[b] != 0 {
                return Err(bad("duplicate bucket index"));
            }
            inv.counts[b] = count;
            inv.xors[b] = xor;
        }
        Ok(inv)
    }
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// A protocol message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// Opening greeting. The peer id is the SHA-256 of a McEliece public key —
    /// see [`super::handshake`].
    Hello { peer: String, records: u64 },
    /// "Here is everything I hold, summarised."
    Inventory(Box<Inventory>),
    /// "Here are my ids in these buckets." Sent only for buckets that differ.
    BucketIds { bucket: u8, ids: Vec<String> },
    /// "Send me these."
    Want { ids: Vec<String> },
    /// The bodies.
    Records { records: Vec<Record> },
    /// Nothing further.
    Done,
}

impl Message {
    pub fn to_value(&self) -> Value {
        match self {
            Message::Hello { peer, records } => obj! {
                "t" => Value::string("hello"),
                "peer" => Value::string(peer.clone()),
                "records" => Value::Int(i128::from(*records)),
            },
            Message::Inventory(inv) => obj! {
                "t" => Value::string("inventory"),
                "inventory" => inv.to_value(),
            },
            Message::BucketIds { bucket, ids } => obj! {
                "t" => Value::string("bucket_ids"),
                "bucket" => Value::Int(i128::from(*bucket)),
                "ids" => Value::Array(ids.iter().map(|i| Value::string(i.clone())).collect()),
            },
            Message::Want { ids } => obj! {
                "t" => Value::string("want"),
                "ids" => Value::Array(ids.iter().map(|i| Value::string(i.clone())).collect()),
            },
            Message::Records { records } => obj! {
                "t" => Value::string("records"),
                "records" => Value::Array(records.iter().map(Record::to_value).collect()),
            },
            Message::Done => obj! { "t" => Value::string("done") },
        }
    }

    pub fn from_value(value: &Value) -> Result<Message, SyncError> {
        let bad = |detail: String| SyncError::MalformedMessage { detail };
        let strings = |v: &Value, field: &str| -> Result<Vec<String>, SyncError> {
            let arr = v
                .get(field)
                .and_then(Value::as_array)
                .ok_or_else(|| bad(format!("{field} is not an array")))?;
            arr.iter()
                .map(|i| {
                    i.as_str()
                        .map(str::to_string)
                        .ok_or_else(|| bad(format!("{field} contains a non-string")))
                })
                .collect()
        };
        match value.get("t").and_then(Value::as_str) {
            Some("hello") => Ok(Message::Hello {
                peer: value
                    .get("peer")
                    .and_then(Value::as_str)
                    .ok_or_else(|| bad("hello has no peer".into()))?
                    .to_string(),
                records: value
                    .get("records")
                    .and_then(Value::as_i128)
                    .and_then(|n| u64::try_from(n).ok())
                    .ok_or_else(|| bad("hello has no record count".into()))?,
            }),
            Some("inventory") => Ok(Message::Inventory(Box::new(Inventory::from_value(
                value
                    .get("inventory")
                    .ok_or_else(|| bad("inventory message has no inventory".into()))?,
            )?))),
            Some("bucket_ids") => {
                let bucket = value
                    .get("bucket")
                    .and_then(Value::as_i128)
                    .filter(|b| (0..BUCKETS as i128).contains(b))
                    .ok_or_else(|| bad("bucket index missing or out of range".into()))?;
                Ok(Message::BucketIds {
                    bucket: bucket as u8,
                    ids: strings(value, "ids")?,
                })
            }
            Some("want") => Ok(Message::Want {
                ids: strings(value, "ids")?,
            }),
            Some("records") => {
                let arr = value
                    .get("records")
                    .and_then(Value::as_array)
                    .ok_or_else(|| bad("records is not an array".into()))?;
                let mut records = Vec::with_capacity(arr.len());
                for item in arr {
                    records.push(
                        Record::from_value(item)
                            .ok_or_else(|| bad("record is not {kind, payload}".into()))?,
                    );
                }
                Ok(Message::Records { records })
            }
            Some("done") => Ok(Message::Done),
            other => Err(bad(format!("unknown message type {other:?}"))),
        }
    }

    /// Canonical bytes, ready to seal over a [`super::handshake::Channel`].
    pub fn encode(&self) -> Vec<u8> {
        self.to_value().canonical_string().into_bytes()
    }

    /// Decode what [`Message::encode`] produced.
    pub fn decode(bytes: &[u8]) -> Result<Message, SyncError> {
        let text = std::str::from_utf8(bytes).map_err(|_| SyncError::MalformedMessage {
            detail: "not UTF-8".into(),
        })?;
        let value = Value::from_json(text).map_err(|e| SyncError::MalformedMessage {
            detail: e.to_string(),
        })?;
        Message::from_value(&value)
    }
}

/// Where a held record stands with *this* node.
///
/// Admission and verification are separate on purpose. A record is
/// content-addressed, so storing and relaying one is safe whatever it says —
/// you cannot be made to misrepresent it, because its id is the hash of its
/// bytes. Running a verifier over it is a different act with a different cost,
/// and for some objectives that cost is minutes of CPU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Standing {
    /// Admitted and relayable. Says nothing about whether it is any good.
    Unverified,
    /// This node ran the check and accepted it. Only these may be used to
    /// derive settlement.
    Verified,
    /// This node ran the check and refused it. Kept, because a peer may ask
    /// for it and the refusal is this node's opinion, not a fact about the
    /// bytes — another node with a different verifier may conclude otherwise.
    Refused(String),
}

impl Standing {
    pub fn is_verified(&self) -> bool {
        matches!(self, Standing::Verified)
    }
}

/// What an admission actually did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IngestReport {
    /// Records admitted and added, in [`Standing::Unverified`].
    pub accepted: Vec<String>,
    /// Records already held.
    pub duplicates: usize,
    /// Records refused, with the reason.
    pub refused: Vec<(String, SyncError)>,
}

impl IngestReport {
    pub fn is_clean(&self) -> bool {
        self.refused.is_empty()
    }
}

/// Limits, so one peer cannot make another allocate without bound.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_ids_per_message: usize,
    pub max_records_per_message: usize,
    /// Canonical bytes a single record may occupy.
    ///
    /// This existed on the HTTP path and not here, which made one record
    /// admissible at two different sizes depending on how it arrived:
    /// [`crate::serve::MAX_BODY_BYTES`] caps a submission from a stranger at a
    /// mebibyte, while a peer over `p2p` was bounded only by the transport's
    /// generic frame ceiling -- sixteen times larger, and a number chosen by a
    /// module that knows nothing about records.
    ///
    /// Two ingress paths with different admission rules is a policy split, not
    /// a consensus one: both nodes still agree about any record they both hold.
    /// It is still wrong. Whether a record may enter the log is a rules
    /// question and the answer should not depend on which socket it came
    /// through, so the bound is the same number, named in one place.
    pub max_record_bytes: usize,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            max_ids_per_message: 10_000,
            max_records_per_message: 512,
            max_record_bytes: crate::serve::MAX_BODY_BYTES as usize,
        }
    }
}

/// One side of a reconciliation, over one connection.
///
/// Transport-agnostic on purpose: it consumes and produces [`Message`]s and
/// touches no sockets, so the protocol is testable without a network. Framing
/// and encryption are [`super::handshake::Channel`]'s job.
#[derive(Debug)]
pub struct Peer {
    /// Records this side holds, by id.
    held: BTreeMap<String, Record>,
    /// Where each held record stands with this node. Every id in `held` has an
    /// entry; a record is admitted long before it is checked, if it ever is.
    standing: BTreeMap<String, Standing>,
    /// Ids this side has asked for and not yet received. A record arriving
    /// outside this set is unsolicited and refused, so a peer cannot push
    /// unbounded data by volunteering it.
    outstanding: BTreeSet<String>,
    limits: Limits,
}

impl Peer {
    pub fn new() -> Peer {
        Peer::with_limits(Limits::default())
    }

    pub fn with_limits(limits: Limits) -> Peer {
        Peer {
            held: BTreeMap::new(),
            standing: BTreeMap::new(),
            outstanding: BTreeSet::new(),
            limits,
        }
    }

    /// Seed the local set. Refuses derived kinds, same as the wire path.
    pub fn insert(&mut self, record: Record) -> Result<String, SyncError> {
        if !EXCHANGEABLE.contains(&record.kind.as_str()) {
            return Err(SyncError::NotExchangeable {
                kind: record.kind.clone(),
            });
        }
        let id = record.id();
        self.held.insert(id.clone(), record);
        self.standing
            .entry(id.clone())
            .or_insert(Standing::Unverified);
        Ok(id)
    }

    pub fn len(&self) -> usize {
        self.held.len()
    }

    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }

    pub fn holds(&self, id: &str) -> bool {
        self.held.contains_key(id)
    }

    pub fn ids(&self) -> Vec<String> {
        self.held.keys().cloned().collect()
    }

    pub fn get(&self, id: &str) -> Option<&Record> {
        self.held.get(id)
    }

    /// This side's summary.
    pub fn inventory(&self) -> Inventory {
        Inventory::of(self.held.keys().map(String::as_str))
            .expect("ids in the local set are well formed by construction")
    }

    /// The ids held in one bucket, for a peer that reported a difference there.
    pub fn bucket_ids(&self, bucket: u8) -> Vec<String> {
        self.held
            .keys()
            .filter(|id| id_bytes(id).map(|b| b[0]) == Some(bucket))
            .cloned()
            .collect()
    }

    /// Given a peer's id list for a bucket, what to ask for.
    ///
    /// Records the request, so anything arriving unrequested is refused.
    pub fn want_from(&mut self, ids: &[String]) -> Result<Vec<String>, SyncError> {
        if ids.len() > self.limits.max_ids_per_message {
            return Err(SyncError::TooMany {
                limit: self.limits.max_ids_per_message,
                got: ids.len(),
            });
        }
        let mut want = Vec::new();
        for id in ids {
            if id_bytes(id).is_none() {
                return Err(SyncError::MalformedId { id: id.clone() });
            }
            if !self.held.contains_key(id) && self.outstanding.insert(id.clone()) {
                want.push(id.clone());
            }
        }
        Ok(want)
    }

    /// Serve a `Want`. Silently skips ids not held — a peer asking for
    /// something absent is not an error, it is just out of date.
    pub fn serve(&self, ids: &[String]) -> Result<Vec<Record>, SyncError> {
        if ids.len() > self.limits.max_records_per_message {
            return Err(SyncError::TooMany {
                limit: self.limits.max_records_per_message,
                got: ids.len(),
            });
        }
        Ok(ids
            .iter()
            .filter_map(|id| self.held.get(id).cloned())
            .collect())
    }

    /// Take records from a peer.
    ///
    /// `verify` decides whether a record is acceptable *on its merits* — for a
    /// claim that means re-running the pinned verifier. It is a parameter
    /// rather than a hard-coded call because this module must not depend on
    /// `node`, and because the caller owns the verifier registry.
    ///
    /// Three refusals happen before `verify` is consulted, and all three are
    /// about the peer rather than the record:
    ///
    /// * a derived kind, which no peer may ever supply;
    /// * a body whose digest is not the id it was requested under;
    /// * a record nobody asked for.
    pub fn ingest<F>(&mut self, records: Vec<Record>, mut verify: F) -> IngestReport
    where
        F: FnMut(&Record) -> Result<(), SyncError>,
    {
        let mut report = IngestReport::default();
        if records.len() > self.limits.max_records_per_message {
            report.refused.push((
                String::new(),
                SyncError::TooMany {
                    limit: self.limits.max_records_per_message,
                    got: records.len(),
                },
            ));
            return report;
        }

        for record in records {
            let id = record.id();

            // Size before anything else that touches the payload. A record is
            // measured by its *canonical* bytes rather than by whatever the
            // sender's encoding happened to cost, because the canonical form is
            // the one every node agrees on -- measuring the wire form would
            // make admission depend on a peer's whitespace.
            let size = record.payload.canonical_string().len();
            if size > self.limits.max_record_bytes {
                report.refused.push((
                    id,
                    SyncError::TooMany {
                        limit: self.limits.max_record_bytes,
                        got: size,
                    },
                ));
                continue;
            }

            if !EXCHANGEABLE.contains(&record.kind.as_str()) {
                report.refused.push((
                    id,
                    SyncError::NotExchangeable {
                        kind: record.kind.clone(),
                    },
                ));
                continue;
            }
            // Unsolicited records are refused even when they would verify:
            // otherwise a peer can push whatever it likes at whatever volume.
            if !self.outstanding.remove(&id) {
                if self.held.contains_key(&id) {
                    report.duplicates += 1;
                } else {
                    report
                        .refused
                        .push((id.clone(), SyncError::Unsolicited { id }));
                }
                continue;
            }
            if self.held.contains_key(&id) {
                report.duplicates += 1;
                continue;
            }
            if let Err(e) = verify(&record) {
                report.refused.push((id, e));
                continue;
            }
            self.held.insert(id.clone(), record);
            report.accepted.push(id);
        }
        report
    }

    /// Ids requested and not yet delivered.
    pub fn outstanding(&self) -> usize {
        self.outstanding.len()
    }
}

impl Default for Peer {
    fn default() -> Peer {
        Peer::new()
    }
}

/// Run a full reconciliation between two local [`Peer`]s.
///
/// The reference driver: it is what the tests check convergence against, and it
/// documents the message order a networked implementation must follow.
/// `verify` is applied on both sides.
pub fn reconcile<F>(a: &mut Peer, b: &mut Peer, mut verify: F) -> (IngestReport, IngestReport)
where
    F: FnMut(&Record) -> Result<(), SyncError>,
{
    let (inv_a, inv_b) = (a.inventory(), b.inventory());
    let differing = inv_a.differing(&inv_b);

    // Each side asks for what the other has in the differing buckets.
    let mut want_a = Vec::new();
    let mut want_b = Vec::new();
    for bucket in differing {
        let theirs = b.bucket_ids(bucket);
        want_a.extend(a.want_from(&theirs).unwrap_or_default());
        let mine = a.bucket_ids(bucket);
        want_b.extend(b.want_from(&mine).unwrap_or_default());
    }

    let to_a = b.serve(&want_a).unwrap_or_default();
    let to_b = a.serve(&want_b).unwrap_or_default();

    let report_a = a.ingest(to_a, &mut verify);
    let report_b = b.ingest(to_b, &mut verify);
    (report_a, report_b)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(kind: &str, n: i128) -> Record {
        Record::new(kind, obj! { "n" => Value::Int(n) })
    }

    fn claim(n: i128) -> Record {
        record("claim", n)
    }

    fn accept_all(_: &Record) -> Result<(), SyncError> {
        Ok(())
    }

    fn peer_with(range: std::ops::Range<i128>) -> Peer {
        let mut p = Peer::new();
        for n in range {
            p.insert(claim(n)).expect("claims are exchangeable");
        }
        p
    }

    // -- what may cross the wire -------------------------------------------

    #[test]
    fn derived_records_are_never_accepted_from_a_peer() {
        // The security argument of the whole layer. A verdict is what *this*
        // node concluded by re-running the verifier; taking one from a peer
        // would be taking its word for a verification.
        for kind in ["verdict", "settlement", "frontier"] {
            let mut p = Peer::new();
            assert_eq!(
                p.insert(record(kind, 1)),
                Err(SyncError::NotExchangeable {
                    kind: kind.to_string()
                })
            );

            // And not through the wire path either, even if solicited.
            let mut q = Peer::new();
            let r = record(kind, 1);
            q.outstanding.insert(r.id());
            let report = q.ingest(vec![r], accept_all);
            assert!(matches!(
                report.refused.as_slice(),
                [(_, SyncError::NotExchangeable { .. })]
            ));
            assert_eq!(q.len(), 0);
        }
    }

    #[test]
    fn the_exchangeable_kinds_are_exactly_the_inputs() {
        assert_eq!(EXCHANGEABLE, &["objective", "commitment", "claim"]);
        for kind in EXCHANGEABLE {
            assert!(Peer::new().insert(record(kind, 1)).is_ok(), "{kind}");
        }
    }

    // -- inventories --------------------------------------------------------

    #[test]
    fn identical_sets_agree_and_disjoint_sets_do_not() {
        let a = peer_with(0..50);
        let b = peer_with(0..50);
        assert!(a.inventory().agrees_with(&b.inventory()));
        assert_eq!(a.inventory().total(), 50);

        let c = peer_with(50..100);
        assert!(!a.inventory().agrees_with(&c.inventory()));
    }

    #[test]
    fn a_swap_that_preserves_count_still_shows_up() {
        // The reason a bucket carries an XOR and not just a count.
        let mut a = Peer::new();
        let mut b = Peer::new();
        let (x, y) = (claim(1), claim(2));
        // Force both into one bucket only if they happen to share a leading
        // byte; otherwise the counts differ anyway. Either way the summaries
        // must not agree.
        a.insert(x).unwrap();
        b.insert(y).unwrap();
        assert!(!a.inventory().agrees_with(&b.inventory()));
    }

    #[test]
    fn only_differing_buckets_need_id_lists() {
        // The property that makes a synced pair cheap: nearly all buckets
        // match, so nearly no ids travel.
        let a = peer_with(0..200);
        let mut b = peer_with(0..200);
        b.insert(claim(999)).unwrap();
        let differing = a.inventory().differing(&b.inventory());
        assert_eq!(
            differing.len(),
            1,
            "one extra record should disturb one bucket"
        );
    }

    #[test]
    fn an_empty_inventory_agrees_only_with_another_empty_one() {
        let empty = Peer::new().inventory();
        assert!(empty.agrees_with(&Inventory::default()));
        assert_eq!(empty.total(), 0);
        assert!(!empty.agrees_with(&peer_with(0..1).inventory()));
    }

    #[test]
    fn inventories_round_trip_through_the_wire_form() {
        let inv = peer_with(0..300).inventory();
        let back = Inventory::from_value(&inv.to_value()).unwrap();
        assert_eq!(inv, back);
        assert!(inv.agrees_with(&back));
    }

    #[test]
    fn a_sparse_inventory_does_not_send_256_buckets() {
        let inv = peer_with(0..3).inventory();
        let buckets = inv
            .to_value()
            .get("buckets")
            .unwrap()
            .as_array()
            .unwrap()
            .len();
        assert!(buckets <= 3, "sent {buckets} buckets for 3 records");
    }

    #[test]
    fn malformed_ids_are_refused_rather_than_bucketed_somewhere() {
        assert!(matches!(
            Inventory::of(["not-an-id"]),
            Err(SyncError::MalformedId { .. })
        ));
        assert!(matches!(
            Inventory::of(["sha256:tooshort"]),
            Err(SyncError::MalformedId { .. })
        ));
    }

    // -- reconciliation -----------------------------------------------------

    #[test]
    fn disjoint_peers_converge() {
        let mut a = peer_with(0..40);
        let mut b = peer_with(40..80);
        let (ra, rb) = reconcile(&mut a, &mut b, accept_all);
        assert!(ra.is_clean() && rb.is_clean());
        assert_eq!(a.len(), 80);
        assert_eq!(b.len(), 80);
        assert!(a.inventory().agrees_with(&b.inventory()));
    }

    #[test]
    fn overlapping_peers_converge_and_do_not_refetch() {
        let mut a = peer_with(0..60);
        let mut b = peer_with(40..100);
        let (ra, rb) = reconcile(&mut a, &mut b, accept_all);
        assert_eq!(a.len(), 100);
        assert_eq!(b.len(), 100);
        // Each side fetched only what it lacked.
        assert_eq!(ra.accepted.len(), 40);
        assert_eq!(rb.accepted.len(), 40);
    }

    #[test]
    fn already_synced_peers_exchange_no_records_at_all() {
        let mut a = peer_with(0..50);
        let mut b = peer_with(0..50);
        assert!(a.inventory().differing(&b.inventory()).is_empty());
        let (ra, rb) = reconcile(&mut a, &mut b, accept_all);
        assert!(ra.accepted.is_empty() && rb.accepted.is_empty());
    }

    #[test]
    fn reconciliation_is_idempotent() {
        let mut a = peer_with(0..30);
        let mut b = peer_with(30..60);
        reconcile(&mut a, &mut b, accept_all);
        let (before_a, before_b) = (a.ids(), b.ids());
        reconcile(&mut a, &mut b, accept_all);
        assert_eq!(a.ids(), before_a);
        assert_eq!(b.ids(), before_b);
        assert_eq!(a.outstanding(), 0);
    }

    #[test]
    fn a_third_peer_converges_through_either_of_the_others() {
        let mut a = peer_with(0..20);
        let mut b = peer_with(20..40);
        let mut c = peer_with(40..60);
        reconcile(&mut a, &mut b, accept_all);
        reconcile(&mut b, &mut c, accept_all);
        reconcile(&mut a, &mut b, accept_all);
        assert_eq!(a.len(), 60);
        assert!(a.inventory().agrees_with(&c.inventory()));
    }

    // -- refusing bad peers -------------------------------------------------

    #[test]
    fn a_substituted_body_is_caught_by_its_own_digest() {
        let mut a = Peer::new();
        let wanted = claim(1);
        a.outstanding.insert(wanted.id());
        // The peer answers with a different record than the one requested.
        let report = a.ingest(vec![claim(2)], accept_all);
        assert!(matches!(
            report.refused.as_slice(),
            [(_, SyncError::Unsolicited { .. })]
        ));
        assert_eq!(a.len(), 0);
    }

    #[test]
    fn unsolicited_records_are_refused_even_when_they_would_verify() {
        // Otherwise a peer pushes whatever it likes, at whatever volume.
        let mut a = Peer::new();
        let report = a.ingest(vec![claim(7)], accept_all);
        assert!(matches!(
            report.refused.as_slice(),
            [(_, SyncError::Unsolicited { .. })]
        ));
        assert_eq!(a.len(), 0);
    }

    #[test]
    fn a_record_that_fails_verification_is_refused() {
        let mut a = Peer::new();
        let r = claim(1);
        a.outstanding.insert(r.id());
        let report = a.ingest(vec![r], |_| {
            Err(SyncError::MalformedMessage {
                detail: "verifier said no".into(),
            })
        });
        assert_eq!(report.accepted.len(), 0);
        assert_eq!(report.refused.len(), 1);
        assert_eq!(a.len(), 0);
    }

    #[test]
    fn one_bad_record_does_not_poison_the_batch() {
        let mut a = Peer::new();
        let good = claim(1);
        let bad = claim(2);
        a.outstanding.insert(good.id());
        a.outstanding.insert(bad.id());
        let bad_id = bad.id();
        let report = a.ingest(vec![good.clone(), bad], |r| {
            if r.id() == bad_id {
                Err(SyncError::MalformedMessage {
                    detail: "no".into(),
                })
            } else {
                Ok(())
            }
        });
        assert_eq!(report.accepted, vec![good.id()]);
        assert_eq!(report.refused.len(), 1);
        assert!(a.holds(&good.id()));
    }

    #[test]
    fn oversized_messages_are_refused_before_allocation() {
        let limits = Limits {
            max_ids_per_message: 4,
            max_records_per_message: 2,
            ..Limits::default()
        };
        let mut a = Peer::with_limits(limits);
        let ids: Vec<String> = (0..10).map(|n| claim(n).id()).collect();
        assert!(matches!(a.want_from(&ids), Err(SyncError::TooMany { .. })));

        let many: Vec<Record> = (0..10).map(claim).collect();
        let report = a.ingest(many, accept_all);
        assert!(matches!(
            report.refused.as_slice(),
            [(_, SyncError::TooMany { .. })]
        ));
    }

    #[test]
    fn serving_an_id_we_do_not_hold_is_not_an_error() {
        // A peer asking for something we lack is out of date, not hostile.
        let a = peer_with(0..3);
        let served = a.serve(&[claim(99).id()]).unwrap();
        assert!(served.is_empty());
    }

    #[test]
    fn duplicates_are_counted_not_refused() {
        let mut a = peer_with(0..3);
        let dup = claim(1);
        a.outstanding.insert(dup.id());
        let report = a.ingest(vec![dup], accept_all);
        assert_eq!(report.duplicates, 1);
        assert!(report.is_clean());
    }

    // -- framing ------------------------------------------------------------

    #[test]
    fn every_message_round_trips_through_canonical_bytes() {
        let inv = peer_with(0..5).inventory();
        let messages = vec![
            Message::Hello {
                peer: "sha256:aa".into(),
                records: 42,
            },
            Message::Inventory(Box::new(inv)),
            Message::BucketIds {
                bucket: 7,
                ids: vec![claim(1).id()],
            },
            Message::Want {
                ids: vec![claim(1).id(), claim(2).id()],
            },
            Message::Records {
                records: vec![claim(1), claim(2)],
            },
            Message::Done,
        ];
        for m in messages {
            let bytes = m.encode();
            assert_eq!(Message::decode(&bytes).unwrap(), m, "round trip failed");
            // Canonical: encoding twice gives identical bytes.
            assert_eq!(m.encode(), bytes);
        }
    }

    #[test]
    fn malformed_frames_are_refused_not_guessed() {
        for bad in [
            &b"not json"[..],
            b"{}",
            br#"{"t":"nope"}"#,
            br#"{"t":"want","ids":[1,2]}"#,
            br#"{"t":"bucket_ids","bucket":999,"ids":[]}"#,
            br#"{"t":"inventory","inventory":{"buckets":[[0,1]]}}"#,
        ] {
            assert!(
                Message::decode(bad).is_err(),
                "{:?} should not decode",
                std::str::from_utf8(bad)
            );
        }
    }

    #[test]
    fn a_message_survives_the_encrypted_channel() {
        // The two halves compose: canonical bytes in, sealed frame out.
        use crate::p2p::handshake::PeerIdentity;
        let responder = PeerIdentity::generate();
        let initiator_id = [9u8; 32];
        let (ct, mut client) = responder.to_public().initiate(initiator_id);
        let mut server = responder.accept(initiator_id, &ct).unwrap();

        let msg = Message::Want {
            ids: vec![claim(1).id()],
        };
        let (n, frame) = client.seal(&msg.encode(), b"sync").unwrap();
        let plain = server.open(n, &frame, b"sync").unwrap();
        assert_eq!(Message::decode(&plain).unwrap(), msg);
    }

    #[test]
    fn one_record_is_admissible_at_one_size_however_it_arrived() {
        // `serve` capped a submitted record at a mebibyte; this path capped
        // nothing and inherited the transport's generic sixteen. Two ingress
        // paths with different admission rules is not a consensus split -- both
        // nodes agree about any record they both hold -- but whether a record
        // may enter the log is a rules question, and the answer should not
        // depend on which socket it came through.
        assert_eq!(
            Limits::default().max_record_bytes,
            crate::serve::MAX_BODY_BYTES as usize,
            "the two ingress paths disagree about how big a record may be"
        );
    }

    #[test]
    fn an_oversized_record_is_refused_and_the_rest_of_the_batch_survives() {
        // Refused per record rather than per message: one peer sending one
        // absurd claim alongside good ones must not cost the good ones. That
        // is the same rule the verdict taxonomy runs on -- a fact about one
        // artifact is not a fact about the others.
        let limits = Limits {
            max_record_bytes: 512,
            ..Limits::default()
        };
        let mut peer = Peer::with_limits(limits);

        let small = record_of("claim", "small");
        let big = record_of("claim", &"x".repeat(4096));
        let (small_id, big_id) = (small.id(), big.id());
        peer.outstanding.insert(small_id.clone());
        peer.outstanding.insert(big_id.clone());

        let report = peer.ingest(vec![big, small], |_| Ok(()));
        assert_eq!(report.accepted, vec![small_id], "the good record was lost");
        assert!(
            report
                .refused
                .iter()
                .any(|(id, error)| id == &big_id && matches!(error, SyncError::TooMany { .. })),
            "the oversized record was not refused: {:?}",
            report.refused
        );
    }

    /// A record whose canonical bytes grow with `filler`.
    fn record_of(kind: &str, filler: &str) -> Record {
        Record {
            kind: kind.to_string(),
            payload: crate::canonical::Value::object([
                ("objective_id", crate::canonical::Value::string("obj")),
                ("submitter", crate::canonical::Value::string("alice")),
                ("artifact", crate::canonical::Value::string(filler)),
            ]),
        }
    }
}
