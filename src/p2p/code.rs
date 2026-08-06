//! Verifier code exchange: pinned checkers as content-addressed blobs.
//!
//! # Why this is a third message family
//!
//! [`super::sync`] reconciles the log's inputs and [`super::pop`] gossips
//! candidates. Neither shape fits code:
//!
//! - a blob is not a record. Records are what settlement is derived *from*, and
//!   the record path exists to refuse anything derived. A blob is neither — it is
//!   the *tool* settlement is derived *with*, and it is already pinned inside a
//!   record, so it needs no id scheme, no digest reconciliation and no
//!   exchangeability check.
//! - a blob is not a candidate. Populations converge towards a common set; blob
//!   holdings deliberately do not. A node wants exactly the code its own log's
//!   objectives pin, which for two nodes tracking different objectives is two
//!   different sets, and a protocol that converged them would have every node
//!   storing every checker on the network.
//!
//! So this is need-driven fetch, not anti-entropy: **want first**, and a peer
//! sends only what it was asked for. There is no inventory message, because
//! offering an inventory of held blobs would be offering a list of the
//! objectives a node is working on — a free traffic-analysis signal, paid for in
//! bandwidth, for a set the asking side can already compute from the log it just
//! reconciled.
//!
//! Its own AEAD context ([`CONTEXT`]) for the same mechanical reason as
//! populations: a code frame cannot be opened as a record frame, so no confusion
//! attack reaches a decoder.
//!
//! # A blob is untrusted input, twice over
//!
//! **Before allocating.** A hex body's declared length is halved and checked
//! against [`blobs::MAX_BLOB_BYTES`] before it is decoded, and the number of
//! bodies is checked before any of them are. Refusing after allocating is not a
//! defence against a peer whose plan is to make you allocate.
//!
//! **Before storing.** [`admit`] keeps a body only if it hashes to an address
//! this node *asked for*. Both halves matter and they stop different attacks:
//!
//! - the hash check stops substitution. A peer that sends different code under
//!   the right address is refused before the bytes acquire a filename, so
//!   "verify before execute" is enforced at the boundary rather than trusted to
//!   the verifier. Because a blob's identity *is* its hash, this is the same
//!   check as "it matches the pin".
//! - the want check stops deposit. A peer allowed to push arbitrary blobs can
//!   fill a disk with well-formed garbage; the want set is the only thing that
//!   bounds what it may leave behind.
//!
//! What is *not* defended: a peer can decline to serve, and a node whose peers
//! all decline stays unable to verify. That is `Unavailable` — correct, and not
//! a rejection. Availability is not a property this protocol can guarantee, and
//! `docs/threat-model.md` says so.

use std::collections::BTreeSet;
use std::fmt;

use crate::blobs::{self, BlobStore};
use crate::canonical::Value;
use crate::obj;

/// AEAD context for verifier-code frames.
pub const CONTEXT: &[u8] = b"proofwork/p2p/code/v1";

/// Why a code message was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodeError {
    /// A message did not decode.
    Malformed { detail: String },
    /// More addresses or bodies in one message than the ceiling allows.
    TooMany { limit: usize, got: usize },
    /// A body over the per-blob ceiling, refused against its declared length.
    TooLarge { limit: usize, got: usize },
    /// Something in an address field that is not a content address. Refused
    /// rather than ignored: an address is used as a filename, and a peer sending
    /// `"../../etc/passwd"` is probing, not confused.
    NotAnAddress { address: String },
}

impl fmt::Display for CodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodeError::Malformed { detail } => write!(f, "malformed code message: {detail}"),
            CodeError::TooMany { limit, got } => {
                write!(f, "code message carries {got} items, limit is {limit}")
            }
            CodeError::TooLarge { limit, got } => {
                write!(f, "code body declares {got} bytes, limit is {limit}")
            }
            CodeError::NotAnAddress { address } => {
                write!(f, "{address:?} is not a content address")
            }
        }
    }
}

impl std::error::Error for CodeError {}

/// Ceilings, checked *before* allocating.
///
/// Sized for the honest case: an objective pins one checker, so a node syncing a
/// few hundred objectives it has never seen needs a few hundred addresses in
/// flight, and 32 bodies per message at a mebibyte each bounds one message at 32
/// MiB of decoded blob — large, but the sender only ever fills it with blobs the
/// receiver asked for, and the receiver's want set is bounded by its own log.
#[derive(Debug, Clone, Copy)]
pub struct CodeLimits {
    pub max_addresses_per_message: usize,
    pub max_blobs_per_message: usize,
    pub max_blob_bytes: usize,
}

impl Default for CodeLimits {
    fn default() -> CodeLimits {
        CodeLimits {
            max_addresses_per_message: 1_024,
            max_blobs_per_message: 32,
            max_blob_bytes: blobs::MAX_BLOB_BYTES,
        }
    }
}

/// A verifier-code protocol message.
///
/// Two messages and a terminator. There is no `Have` or `Inventory`: see the
/// module docs on why advertising held blobs is a privacy cost with no protocol
/// benefit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodeMessage {
    /// "Send me the code behind these pins." Content addresses only.
    Want { addresses: Vec<String> },
    /// The bodies, in no particular order and not necessarily all of them.
    ///
    /// Bodies rather than (address, body) pairs, deliberately: the address is
    /// recomputed from the bytes on arrival, so a declared one would be either
    /// redundant or a lie, and a decoder that carried both would invite somebody
    /// to trust the cheap one.
    Blobs { blobs: Vec<Vec<u8>> },
    /// Nothing further.
    Done,
}

impl CodeMessage {
    pub fn to_value(&self) -> Value {
        match self {
            CodeMessage::Want { addresses } => obj! {
                "t" => Value::string("code_want"),
                "addresses" => Value::Array(
                    addresses.iter().map(|a| Value::string(a.clone())).collect()
                ),
            },
            CodeMessage::Blobs { blobs } => obj! {
                "t" => Value::string("code_blobs"),
                "blobs" => Value::Array(blobs.iter().map(|b| Value::string(hex(b))).collect()),
            },
            CodeMessage::Done => obj! { "t" => Value::string("code_done") },
        }
    }

    /// Decode, enforcing `limits` **before** building any vector.
    pub fn from_value(value: &Value, limits: CodeLimits) -> Result<CodeMessage, CodeError> {
        let bad = |detail: String| CodeError::Malformed { detail };
        let array = |field: &str, limit: usize| -> Result<&[Value], CodeError> {
            let items = value
                .get(field)
                .and_then(Value::as_array)
                .ok_or_else(|| bad(format!("{field} is not an array")))?;
            if items.len() > limit {
                return Err(CodeError::TooMany {
                    limit,
                    got: items.len(),
                });
            }
            Ok(items)
        };
        match value.get("t").and_then(Value::as_str) {
            Some("code_want") => {
                let items = array("addresses", limits.max_addresses_per_message)?;
                let mut addresses = Vec::with_capacity(items.len());
                for item in items {
                    let address = item
                        .as_str()
                        .ok_or_else(|| bad("addresses contains a non-string".into()))?;
                    if !blobs::is_address(address) {
                        return Err(CodeError::NotAnAddress {
                            address: address.to_string(),
                        });
                    }
                    addresses.push(address.to_string());
                }
                Ok(CodeMessage::Want { addresses })
            }
            Some("code_blobs") => {
                let items = array("blobs", limits.max_blobs_per_message)?;
                let mut bodies = Vec::with_capacity(items.len());
                for item in items {
                    let text = item
                        .as_str()
                        .ok_or_else(|| bad("blobs contains a non-string".into()))?;
                    // The ceiling against the *declared* length, before the
                    // allocation the decode would perform.
                    if text.len() / 2 > limits.max_blob_bytes {
                        return Err(CodeError::TooLarge {
                            limit: limits.max_blob_bytes,
                            got: text.len() / 2,
                        });
                    }
                    bodies.push(unhex(text).ok_or_else(|| bad("blob body is not hex".into()))?);
                }
                Ok(CodeMessage::Blobs { blobs: bodies })
            }
            Some("code_done") => Ok(CodeMessage::Done),
            other => Err(bad(format!("unknown code message type {other:?}"))),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        self.to_value().canonical_string().into_bytes()
    }

    pub fn decode(bytes: &[u8], limits: CodeLimits) -> Result<CodeMessage, CodeError> {
        let text = std::str::from_utf8(bytes).map_err(|_| CodeError::Malformed {
            detail: "not UTF-8".into(),
        })?;
        let value = Value::from_json(text).map_err(|error| CodeError::Malformed {
            detail: error.to_string(),
        })?;
        CodeMessage::from_value(&value, limits)
    }
}

/// Hex, because [`Value`] has no byte-string variant and adding one would touch
/// the canonical encoding, which is consensus-critical. A code frame is not part
/// of any record's identity, so the 2x cost buys immunity from ever having to
/// change `canonical::Value` for a network convenience.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit((byte >> 4) as u32, 16).expect("nibble"));
        out.push(char::from_digit((byte & 0x0f) as u32, 16).expect("nibble"));
    }
    out
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let raw = text.as_bytes();
    let mut out = Vec::with_capacity(raw.len() / 2);
    for pair in raw.chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

/// The want message for a node's unmet pins, capped at the ceiling.
///
/// Truncation is fine and needs no cursor: the want set is recomputed from the
/// log every round, so a pin that did not fit in this message is simply asked
/// for in the next one.
pub fn want_message(needs: &BTreeSet<String>, limits: CodeLimits) -> CodeMessage {
    CodeMessage::Want {
        addresses: needs
            .iter()
            .filter(|address| blobs::is_address(address))
            .take(limits.max_addresses_per_message)
            .cloned()
            .collect(),
    }
}

/// Answer a `Want` from the store, skipping what is not held.
///
/// Only the store, never the bundle. A node serves what it has published, and
/// publishing is what an operator does deliberately — it means "I stand behind
/// making this code available", and it keeps a peer from being able to name
/// arbitrary bundle-relative paths through an address lookup.
///
/// A blob that is absent is silently skipped rather than reported. Saying "I do
/// not have that" would tell the asker which objectives this node is *not*
/// tracking, and the asker learns the same thing from the blob not arriving.
pub fn serve(store: &BlobStore, addresses: &[String], limits: CodeLimits) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut budget = limits
        .max_blob_bytes
        .saturating_mul(limits.max_blobs_per_message);
    for address in addresses {
        if out.len() >= limits.max_blobs_per_message {
            break;
        }
        let Ok(bytes) = store.read(address) else {
            continue;
        };
        // A whole-message budget on top of the per-blob and per-count ceilings,
        // so serving cannot be turned into an amplifier by a peer that asks for
        // thirty-two maximum-sized blobs at once.
        if bytes.len() > budget {
            break;
        }
        budget -= bytes.len();
        out.push(bytes);
    }
    out
}

/// What a code exchange actually did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CodeReport {
    /// Blobs that matched a wanted pin and were stored.
    pub accepted: usize,
    /// Blobs refused: unsolicited, oversized, or not hashing to any wanted pin.
    pub refused: usize,
    /// Blobs handed to the peer.
    pub served: usize,
    /// Pins still unmet after the exchange.
    pub outstanding: usize,
}

/// Store the blobs a peer sent, keeping only what was asked for.
///
/// The order is: hash the bytes, check the resulting address against the want
/// set, then store. Hashing first is what makes the address unforgeable, and
/// checking the want set before storing is what bounds a hostile peer's ability
/// to leave things on this disk.
///
/// A blob that fails either check is counted and dropped. There is no penalty
/// and no disconnection: a peer whose store changed between our want and its
/// serve is out of date, not hostile, and the population protocol next door
/// makes the same allowance for the same reason.
pub fn admit(store: &BlobStore, wanted: &BTreeSet<String>, bodies: Vec<Vec<u8>>) -> CodeReport {
    let mut report = CodeReport::default();
    let mut got: BTreeSet<String> = BTreeSet::new();
    for body in bodies {
        let address = blobs::address(&body);
        if !wanted.contains(&address) {
            report.refused += 1;
            continue;
        }
        match store.put(&address, &body) {
            Ok(_) => {
                report.accepted += 1;
                got.insert(address);
            }
            // A mismatch is unreachable here — the address was just computed
            // from these bytes — so what is left is the ceiling and the
            // filesystem. Both are refusals rather than errors: a blob this node
            // could not store is a blob it does not have, which is `Unavailable`
            // and nothing worse.
            Err(_) => report.refused += 1,
        }
    }
    report.outstanding = wanted.difference(&got).count();
    report
}

/// Run a full code exchange between two local stores.
///
/// The reference driver, and the message order a networked implementation must
/// follow; see [`super::session::reconcile_code`]. Symmetric, because both sides
/// may be missing code the other has and a one-directional fetch would make
/// convergence depend on who dialled.
pub fn reconcile(
    mine: &BlobStore,
    my_needs: &BTreeSet<String>,
    theirs: &BlobStore,
    their_needs: &BTreeSet<String>,
    limits: CodeLimits,
) -> (CodeReport, CodeReport) {
    let want_mine = want_message(my_needs, limits);
    let want_theirs = want_message(their_needs, limits);
    let addresses_of = |message: &CodeMessage| match message {
        CodeMessage::Want { addresses } => addresses.clone(),
        _ => Vec::new(),
    };
    let to_mine = serve(theirs, &addresses_of(&want_mine), limits);
    let to_theirs = serve(mine, &addresses_of(&want_theirs), limits);

    let served_mine = to_theirs.len();
    let served_theirs = to_mine.len();
    let mut report_mine = admit(mine, my_needs, to_mine);
    let mut report_theirs = admit(theirs, their_needs, to_theirs);
    report_mine.served = served_mine;
    report_theirs.served = served_theirs;
    (report_mine, report_theirs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::{Path, PathBuf};

    fn scratch(name: &str) -> PathBuf {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("code-tests")
            .join(name);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    const CHECKER: &[u8] = b"def check(artifact):\n    return artifact.get('n') == 42\n";
    const OTHER: &[u8] = b"def check(artifact):\n    return True\n";

    fn store(name: &str) -> BlobStore {
        BlobStore::at(scratch(name))
    }

    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    // -- the boundary between the message families -------------------------

    #[test]
    fn code_frames_use_a_different_aead_context_than_records() {
        // The mechanical half of keeping the families apart: a frame sealed for
        // one does not open under the other, so a confusion attack fails before
        // any decoder sees the bytes.
        use crate::p2p::handshake::PeerIdentity;
        let responder = PeerIdentity::generate();
        let initiator = [7u8; 32];
        let (ciphertext, mut client) = responder.to_public().initiate(initiator);
        let mut server = responder.accept(initiator, &ciphertext).unwrap();

        let message = CodeMessage::Want {
            addresses: vec![blobs::address(CHECKER)],
        };
        let (nonce, frame) = client.seal(&message.encode(), CONTEXT).unwrap();
        assert!(
            server
                .open(nonce, &frame, crate::p2p::session::RECORD_CONTEXT)
                .is_err(),
            "a code frame opened as a record frame"
        );
        assert!(
            server
                .open(nonce, &frame, crate::p2p::pop::CONTEXT)
                .is_err(),
            "a code frame opened as a population frame"
        );
        let plain = server.open(nonce, &frame, CONTEXT).unwrap();
        assert_eq!(
            CodeMessage::decode(&plain, CodeLimits::default()).unwrap(),
            message
        );
    }

    // -- admission ---------------------------------------------------------

    #[test]
    fn a_wanted_blob_is_stored_and_becomes_resolvable() {
        let mine = store("wanted");
        let address = blobs::address(CHECKER);
        let report = admit(&mine, &set(&[&address]), vec![CHECKER.to_vec()]);
        assert_eq!(report.accepted, 1);
        assert_eq!(report.refused, 0);
        assert_eq!(report.outstanding, 0);
        assert_eq!(mine.read(&address).unwrap(), CHECKER);
    }

    #[test]
    fn substituted_code_is_refused_because_its_address_is_different() {
        // The substitution attack, and why the hash check and the "matches the
        // pin" check are one check: a blob's identity *is* its hash, so bytes
        // that are not the pinned code simply are not the address anybody asked
        // for.
        let mine = store("substituted");
        let wanted = blobs::address(CHECKER);
        let report = admit(&mine, &set(&[&wanted]), vec![OTHER.to_vec()]);
        assert_eq!(report.accepted, 0);
        assert_eq!(report.refused, 1);
        assert_eq!(report.outstanding, 1);
        assert!(mine.is_empty(), "substituted code reached the store");
        assert!(!mine.holds(&blobs::address(OTHER)));
    }

    #[test]
    fn an_unsolicited_blob_is_dropped_rather_than_cached() {
        // A peer allowed to deposit arbitrary well-formed blobs can fill a disk.
        // The want set is the only thing bounding what it may leave behind.
        let mine = store("unsolicited");
        let report = admit(&mine, &BTreeSet::new(), vec![CHECKER.to_vec()]);
        assert_eq!(report.accepted, 0);
        assert_eq!(report.refused, 1);
        assert!(mine.is_empty());
    }

    #[test]
    fn an_oversized_blob_never_reaches_the_store() {
        let mine = store("oversized");
        let huge = vec![b'x'; blobs::MAX_BLOB_BYTES + 1];
        let address = blobs::address(&huge);
        let report = admit(&mine, &set(&[&address]), vec![huge]);
        assert_eq!(report.accepted, 0);
        assert_eq!(report.refused, 1);
        assert!(mine.is_empty());
    }

    // -- serving -----------------------------------------------------------

    #[test]
    fn serving_answers_only_what_is_held_and_says_nothing_about_the_rest() {
        let mine = store("serve");
        let held = blobs::address(CHECKER);
        let absent = blobs::address(OTHER);
        mine.put(&held, CHECKER).unwrap();
        let bodies = serve(
            &mine,
            &[held.clone(), absent.clone()],
            CodeLimits::default(),
        );
        assert_eq!(bodies, vec![CHECKER.to_vec()]);
    }

    #[test]
    fn serving_is_capped_by_count() {
        let mine = store("serve-cap");
        let mut addresses = Vec::new();
        for n in 0..8u8 {
            let body = vec![n; 16];
            let address = blobs::address(&body);
            mine.put(&address, &body).unwrap();
            addresses.push(address);
        }
        let limits = CodeLimits {
            max_blobs_per_message: 3,
            ..CodeLimits::default()
        };
        assert_eq!(serve(&mine, &addresses, limits).len(), 3);
    }

    // -- convergence -------------------------------------------------------

    #[test]
    fn a_peer_with_no_bundle_obtains_the_code_from_one_that_has_it() {
        // The whole point: re-derivation must not require a shared filesystem.
        let funder = store("converge-funder");
        let auditor = store("converge-auditor");
        let address = blobs::address(CHECKER);
        funder.put(&address, CHECKER).unwrap();

        let needs = set(&[&address]);
        let (mine, theirs) = reconcile(
            &auditor,
            &needs,
            &funder,
            &BTreeSet::new(),
            CodeLimits::default(),
        );
        assert_eq!(mine.accepted, 1);
        assert_eq!(mine.outstanding, 0);
        assert_eq!(theirs.served, 1);
        assert_eq!(auditor.read(&address).unwrap(), CHECKER);
    }

    #[test]
    fn a_pin_nobody_holds_stays_outstanding_and_is_not_an_error() {
        // Unavailable, never a refusal of the artifact: a blob no peer has says
        // nothing at all about anybody's work.
        let mine = store("nobody-holds-mine");
        let theirs = store("nobody-holds-theirs");
        let needs = set(&[&blobs::address(CHECKER)]);
        let (report, _) = reconcile(
            &mine,
            &needs,
            &theirs,
            &BTreeSet::new(),
            CodeLimits::default(),
        );
        assert_eq!(report.accepted, 0);
        assert_eq!(report.refused, 0);
        assert_eq!(report.outstanding, 1);
    }

    #[test]
    fn an_exchange_between_synced_stores_moves_nothing() {
        let a = store("synced-a");
        let b = store("synced-b");
        let address = blobs::address(CHECKER);
        a.put(&address, CHECKER).unwrap();
        b.put(&address, CHECKER).unwrap();
        let (ra, rb) = reconcile(
            &a,
            &BTreeSet::new(),
            &b,
            &BTreeSet::new(),
            CodeLimits::default(),
        );
        assert_eq!(ra, CodeReport::default());
        assert_eq!(rb, CodeReport::default());
    }

    #[test]
    fn both_sides_fetch_in_one_exchange() {
        let a = store("both-a");
        let b = store("both-b");
        let (from_a, from_b) = (blobs::address(CHECKER), blobs::address(OTHER));
        a.put(&from_a, CHECKER).unwrap();
        b.put(&from_b, OTHER).unwrap();
        let (ra, rb) = reconcile(
            &a,
            &set(&[&from_b]),
            &b,
            &set(&[&from_a]),
            CodeLimits::default(),
        );
        assert_eq!((ra.accepted, rb.accepted), (1, 1));
        assert_eq!(a.addresses(), b.addresses());
    }

    // -- ceilings and framing ----------------------------------------------

    #[test]
    fn oversized_messages_are_refused_before_allocation() {
        let limits = CodeLimits {
            max_addresses_per_message: 2,
            max_blobs_per_message: 2,
            max_blob_bytes: 8,
        };
        let want = CodeMessage::Want {
            addresses: (0..5u8).map(|n| blobs::address(&[n])).collect(),
        };
        assert!(matches!(
            CodeMessage::decode(&want.encode(), limits),
            Err(CodeError::TooMany { limit: 2, got: 5 })
        ));

        let bodies = CodeMessage::Blobs {
            blobs: (0..5u8).map(|n| vec![n]).collect(),
        };
        assert!(matches!(
            CodeMessage::decode(&bodies.encode(), limits),
            Err(CodeError::TooMany { limit: 2, got: 5 })
        ));

        let big = CodeMessage::Blobs {
            blobs: vec![vec![0u8; 9]],
        };
        assert!(matches!(
            CodeMessage::decode(&big.encode(), limits),
            Err(CodeError::TooLarge { limit: 8, got: 9 })
        ));
    }

    #[test]
    fn a_want_field_that_is_not_a_content_address_is_refused() {
        // Load-bearing: the address becomes a filename on the serving side.
        let limits = CodeLimits::default();
        let probe = obj! {
            "t" => Value::string("code_want"),
            "addresses" => Value::Array(vec![Value::string("../../../../etc/passwd")]),
        };
        assert!(matches!(
            CodeMessage::decode(probe.canonical_string().as_bytes(), limits),
            Err(CodeError::NotAnAddress { .. })
        ));
    }

    #[test]
    fn every_message_round_trips_through_canonical_bytes() {
        let limits = CodeLimits::default();
        for message in [
            CodeMessage::Want {
                addresses: vec![blobs::address(CHECKER)],
            },
            CodeMessage::Blobs {
                blobs: vec![CHECKER.to_vec(), OTHER.to_vec()],
            },
            CodeMessage::Blobs { blobs: vec![] },
            CodeMessage::Done,
        ] {
            let bytes = message.encode();
            assert_eq!(CodeMessage::decode(&bytes, limits).unwrap(), message);
            assert_eq!(message.encode(), bytes);
        }
    }

    #[test]
    fn hex_round_trips_every_byte() {
        let all: Vec<u8> = (0..=255u8).collect();
        assert_eq!(unhex(&hex(&all)).unwrap(), all);
        assert_eq!(hex(&[0x0a, 0xff]), "0aff");
        assert!(unhex("abc").is_none());
        assert!(unhex("zz").is_none());
    }

    #[test]
    fn malformed_frames_are_refused_not_guessed() {
        let limits = CodeLimits::default();
        for bad in [
            &b"not json"[..],
            b"{}",
            br#"{"t":"want","addresses":[]}"#,
            br#"{"t":"code_want","addresses":[1]}"#,
            br#"{"t":"code_want"}"#,
            br#"{"t":"code_blobs","blobs":["zz"]}"#,
            br#"{"t":"code_blobs","blobs":[1]}"#,
        ] {
            assert!(
                CodeMessage::decode(bad, limits).is_err(),
                "{:?} should not decode",
                std::str::from_utf8(bad)
            );
        }
    }
}
