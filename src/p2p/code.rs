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
//!
//! # Solver packages ride the same exchange
//!
//! An objective may pin the program contributors run as well as the checker
//! that scores them ([`crate::solver`]), and a node that synced the objective
//! but not the package cannot offer anyone a Start button. The want is the same
//! shape -- content addresses the log already fixed, asked for, never
//! advertised -- so it travels in the same `code_want`, in a `packages` field.
//! An older peer ignores the field, which is what makes its **presence** the
//! capability: the package round below runs only when both wants carried one,
//! and both sides see both wants before deciding, exactly as for the early-out.
//! [`crate::solver::sync`] decides what a node wants, what it serves and what it
//! keeps.
//!
//! **Chunked, not a bigger cap.** A package file may be 32 MiB
//! ([`crate::solver::manifest::MAX_FILE_BYTES`]) and the blob ceiling is one,
//! deliberately and for every node at once. A separate, larger per-message cap
//! was the obvious alternative and the transport rules it out:
//! [`super::transport::MAX_FRAME`] is 16 MiB, it bounds every family's
//! allocation before a frame is even decrypted, and a 32 MiB file is 64 MiB of
//! hex. Raising it for one family raises it for all. So a file travels as
//! `code_part`s of at most [`PART_BYTES`] -- the blob ceiling, so a part frame
//! is no larger than a blob frame -- and the cap on the whole file is the size
//! its *manifest* pins, which a hash already fixed, checked against the declared
//! size before any part is kept. Parts are not individually verifiable (the
//! manifest pins whole files, and adding piece hashes would change every v1
//! package id), so a file is assembled **in memory within one session** and
//! hashed whole before a byte of it is written; no unverified byte reaches a
//! disk, and an interrupted file is fetched again rather than resumed. Whole
//! files that did arrive are kept, so a package resumes at file granularity.
//! [`PACKAGE_SESSION_BYTES`] bounds one direction of one session at one file
//! of the largest size plus a manifest.
//!
//! **One direction at a time.** The blob round has both sides write a `Blobs`
//! frame and then read one; that is safe for frames a socket buffer can hold
//! and would deadlock for tens of mebibytes, each side blocked writing to a
//! peer blocked writing back. The package round takes turns instead: the side
//! with the lower peer id streams its answer, ending in `code_done`, while the
//! other only reads, and then they swap. A connection to oneself skips it,
//! since both ends would wait to go second.

use std::collections::BTreeSet;
use std::fmt;

use crate::blobs::{self, BlobStore};
use crate::canonical::Value;
use crate::obj;

/// AEAD context for verifier-code frames.
// Spelled `proofwork/` and not `cairn/`: this is a wire constant, not a
// brand. It is mixed into a hash or a KDF, so changing it changes the
// values every peer already computed -- the project rename left it alone
// deliberately, exactly as it left the `pwenc1:` on-disk marker alone.
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
    /// Body of one `code_part`.
    pub max_part_bytes: usize,
    /// The whole item a part belongs to, as the part declares it: the
    /// largest file a solver package may contain.
    pub max_package_file_bytes: u64,
    /// Package bytes one side sends, and accepts, in one session.
    pub max_package_session_bytes: u64,
    /// Parts one side accepts in one session, so a stream of one-byte parts
    /// cannot be made to cost a frame per byte.
    pub max_parts_per_session: usize,
}

/// Largest `code_part` body: the blob ceiling, so a part frame is never
/// larger than the blob frames every node already accepts.
pub const PART_BYTES: usize = blobs::MAX_BLOB_BYTES;

/// One direction of one session's package round: the largest file a package
/// may hold, plus the largest manifest, so a package pinned by a newly synced
/// objective can arrive with the session that brought the objective whenever
/// it fits, and any single file always fits.
pub const PACKAGE_SESSION_BYTES: u64 =
    crate::solver::manifest::MAX_FILE_BYTES + crate::solver::manifest::MAX_MANIFEST_BYTES as u64;

impl Default for CodeLimits {
    fn default() -> CodeLimits {
        CodeLimits {
            max_addresses_per_message: 1_024,
            max_blobs_per_message: 32,
            max_blob_bytes: blobs::MAX_BLOB_BYTES,
            max_part_bytes: PART_BYTES,
            max_package_file_bytes: crate::solver::manifest::MAX_FILE_BYTES,
            max_package_session_bytes: PACKAGE_SESSION_BYTES,
            // The byte ceiling allows 33 full parts; the rest are one short
            // part per item, and a manifest names at most 256 files. The
            // sender holds itself to the same count, so an honest answer is
            // never cut off by it.
            max_parts_per_session: 1_024,
        }
    }
}

/// A verifier-code protocol message.
///
/// Three messages and a terminator. There is no `Have` or `Inventory`: see the
/// module docs on why advertising held blobs is a privacy cost with no protocol
/// benefit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodeMessage {
    /// "Send me the code behind these pins." Content addresses only.
    ///
    /// `packages` is the solver-package want: package ids and package file
    /// hashes, bare hex. `None` is a peer that predates packages and sends no
    /// such field; `Some` of an empty list is a peer that speaks the package
    /// round and needs nothing.
    Want {
        addresses: Vec<String>,
        packages: Option<Vec<String>>,
    },
    /// The bodies, in no particular order and not necessarily all of them.
    ///
    /// Bodies rather than (address, body) pairs, deliberately: the address is
    /// recomputed from the bytes on arrival, so a declared one would be either
    /// redundant or a lie, and a decoder that carried both would invite somebody
    /// to trust the cheap one.
    Blobs { blobs: Vec<Vec<u8>> },
    /// One piece of one solver-package item: bytes `at..at + body.len()` of
    /// an item `size` bytes long whose SHA-256 is `of`.
    ///
    /// Here `of` *is* declared, unlike a blob's address, because parts must be
    /// grouped before there is a whole to hash. It is a grouping key and
    /// nothing more: the receiver hashes the assembled item and keeps it under
    /// the address it computed, so a lie in `of` costs the liar the item.
    Part {
        of: String,
        size: u64,
        at: u64,
        body: Vec<u8>,
    },
    /// Nothing further: ends a stream of parts.
    Done,
}

impl CodeMessage {
    pub fn to_value(&self) -> Value {
        match self {
            CodeMessage::Want {
                addresses,
                packages,
            } => {
                let list = |items: &[String]| {
                    Value::Array(items.iter().map(|a| Value::string(a.clone())).collect())
                };
                let mut value = obj! {
                    "t" => Value::string("code_want"),
                    "addresses" => list(addresses),
                };
                // Absent, not empty, when this side does not speak packages:
                // the field's presence is the capability.
                if let (Some(packages), Value::Object(map)) = (packages, &mut value) {
                    map.insert("packages".into(), list(packages));
                }
                value
            }
            CodeMessage::Blobs { blobs } => obj! {
                "t" => Value::string("code_blobs"),
                "blobs" => Value::Array(blobs.iter().map(|b| Value::string(hex(b))).collect()),
            },
            CodeMessage::Part { of, size, at, body } => obj! {
                "t" => Value::string("code_part"),
                "of" => Value::string(of.clone()),
                "size" => Value::Int(i128::from(*size)),
                "at" => Value::Int(i128::from(*at)),
                "body" => Value::string(hex(body)),
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
                let addresses_in = |field: &str| -> Result<Vec<String>, CodeError> {
                    let items = array(field, limits.max_addresses_per_message)?;
                    let mut addresses = Vec::with_capacity(items.len());
                    for item in items {
                        let address = item
                            .as_str()
                            .ok_or_else(|| bad(format!("{field} contains a non-string")))?;
                        if !blobs::is_address(address) {
                            return Err(CodeError::NotAnAddress {
                                address: address.to_string(),
                            });
                        }
                        addresses.push(address.to_string());
                    }
                    Ok(addresses)
                };
                let addresses = addresses_in("addresses")?;
                let packages = match value.get("packages") {
                    None => None,
                    Some(_) => Some(addresses_in("packages")?),
                };
                Ok(CodeMessage::Want {
                    addresses,
                    packages,
                })
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
            Some("code_part") => {
                let of = value
                    .get("of")
                    .and_then(Value::as_str)
                    .ok_or_else(|| bad("of is not a string".into()))?;
                if !blobs::is_address(of) {
                    return Err(CodeError::NotAnAddress {
                        address: of.to_string(),
                    });
                }
                let number = |field: &str| {
                    value
                        .get(field)
                        .and_then(Value::as_u64)
                        .ok_or_else(|| bad(format!("{field} is not a non-negative integer")))
                };
                let (size, at) = (number("size")?, number("at")?);
                let big = |n: u64| usize::try_from(n).unwrap_or(usize::MAX);
                if size > limits.max_package_file_bytes {
                    return Err(CodeError::TooLarge {
                        limit: big(limits.max_package_file_bytes),
                        got: big(size),
                    });
                }
                let text = value
                    .get("body")
                    .and_then(Value::as_str)
                    .ok_or_else(|| bad("body is not a string".into()))?;
                // Declared length again, before the decode allocates.
                if text.len() / 2 > limits.max_part_bytes {
                    return Err(CodeError::TooLarge {
                        limit: limits.max_part_bytes,
                        got: text.len() / 2,
                    });
                }
                let body = unhex(text).ok_or_else(|| bad("part body is not hex".into()))?;
                if at
                    .checked_add(body.len() as u64)
                    .is_none_or(|end| end > size)
                {
                    return Err(bad("a part runs past the size it declares".into()));
                }
                Ok(CodeMessage::Part {
                    of: of.to_string(),
                    size,
                    at,
                    body,
                })
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
    want_message_with(needs, None, limits)
}

/// [`want_message`] with a package want, `None` for a node that does not take
/// part in the package round. Capped the same way, for the same reason.
pub fn want_message_with(
    needs: &BTreeSet<String>,
    packages: Option<&BTreeSet<String>>,
    limits: CodeLimits,
) -> CodeMessage {
    let capped = |set: &BTreeSet<String>| -> Vec<String> {
        set.iter()
            .filter(|address| blobs::is_address(address))
            .take(limits.max_addresses_per_message)
            .cloned()
            .collect()
    };
    CodeMessage::Want {
        addresses: capped(needs),
        packages: packages.map(capped),
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
    /// The addresses this exchange wrote that were not on disk before it.
    ///
    /// What a caller needs to undo the exchange: the want set can include pins
    /// of objectives that were only *staged* when it was computed, and an
    /// objective the rules then refuse leaves its blob here with nothing
    /// pinning it. See `service::exchange_records_and_code`.
    pub stored: BTreeSet<String>,
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
        let held_before = store.holds(&address);
        match store.put(&address, &body) {
            Ok(_) => {
                report.accepted += 1;
                if !held_before {
                    report.stored.insert(address.clone());
                }
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
        CodeMessage::Want { addresses, .. } => addresses.clone(),
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
            packages: None,
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
        assert_eq!(
            report.stored,
            set(&[&address]),
            "the write was not reported"
        );

        // A blob already on disk is accepted again and not reported as
        // written: the caller may remove what a round wrote, and must never
        // remove what was there before it.
        let again = admit(&mine, &set(&[&address]), vec![CHECKER.to_vec()]);
        assert_eq!(again.accepted, 1);
        assert!(again.stored.is_empty());
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
            ..CodeLimits::default()
        };
        let want = CodeMessage::Want {
            addresses: (0..5u8).map(|n| blobs::address(&[n])).collect(),
            packages: None,
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
                packages: None,
            },
            CodeMessage::Want {
                addresses: vec![],
                packages: Some(vec![blobs::address(OTHER)]),
            },
            CodeMessage::Want {
                addresses: vec![],
                packages: Some(vec![]),
            },
            CodeMessage::Part {
                of: blobs::address(CHECKER),
                size: CHECKER.len() as u64,
                at: 4,
                body: CHECKER[4..9].to_vec(),
            },
            CodeMessage::Part {
                of: blobs::address(b""),
                size: 0,
                at: 0,
                body: vec![],
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

    // -- the package want and its parts --------------------------------------

    #[test]
    fn a_want_without_a_package_field_is_a_peer_that_predates_packages() {
        // The capability is the field's presence, so "absent" and "empty"
        // must survive the wire as different things, and an old peer's frame
        // -- which has no such field -- must still decode.
        let limits = CodeLimits::default();
        let old = br#"{"addresses":[],"t":"code_want"}"#;
        assert_eq!(
            CodeMessage::decode(old, limits).unwrap(),
            CodeMessage::Want {
                addresses: vec![],
                packages: None
            }
        );
        let speaks = CodeMessage::Want {
            addresses: vec![],
            packages: Some(vec![]),
        };
        assert!(String::from_utf8(speaks.encode())
            .unwrap()
            .contains("\"packages\":[]"));
        assert_eq!(
            CodeMessage::decode(&speaks.encode(), limits).unwrap(),
            speaks
        );
        // And an old decoder reads only `addresses`, so the package want rides
        // along unseen: a new node's frame costs an old peer nothing.
        let mixed = CodeMessage::Want {
            addresses: vec![blobs::address(CHECKER)],
            packages: Some(vec![blobs::address(OTHER)]),
        };
        let value = Value::from_json(std::str::from_utf8(&mixed.encode()).unwrap()).unwrap();
        assert_eq!(
            value
                .get("addresses")
                .and_then(Value::as_array)
                .map(<[_]>::len),
            Some(1)
        );
    }

    #[test]
    fn a_package_want_is_held_to_the_same_address_rule() {
        let probe = obj! {
            "t" => Value::string("code_want"),
            "addresses" => Value::Array(vec![]),
            "packages" => Value::Array(vec![Value::string("../solver.json")]),
        };
        assert!(matches!(
            CodeMessage::decode(probe.canonical_string().as_bytes(), CodeLimits::default()),
            Err(CodeError::NotAnAddress { .. })
        ));
        let too_many = CodeMessage::Want {
            addresses: vec![],
            packages: Some((0..5u8).map(|n| blobs::address(&[n])).collect()),
        };
        let limits = CodeLimits {
            max_addresses_per_message: 2,
            ..CodeLimits::default()
        };
        assert!(matches!(
            CodeMessage::decode(&too_many.encode(), limits),
            Err(CodeError::TooMany { limit: 2, got: 5 })
        ));
    }

    #[test]
    fn a_part_is_refused_against_its_declared_sizes_before_its_body_is_decoded() {
        let limits = CodeLimits {
            max_part_bytes: 4,
            max_package_file_bytes: 16,
            ..CodeLimits::default()
        };
        let part = |size: u64, at: u64, body: &[u8]| CodeMessage::Part {
            of: blobs::address(b"whatever"),
            size,
            at,
            body: body.to_vec(),
        };
        // A body over the part ceiling.
        assert!(matches!(
            CodeMessage::decode(&part(16, 0, b"12345").encode(), limits),
            Err(CodeError::TooLarge { limit: 4, got: 5 })
        ));
        // An item over the file ceiling, whatever the body.
        assert!(matches!(
            CodeMessage::decode(&part(17, 0, b"1").encode(), limits),
            Err(CodeError::TooLarge { limit: 16, got: 17 })
        ));
        // A part that runs past the end of the item it says it belongs to.
        assert!(matches!(
            CodeMessage::decode(&part(5, 3, b"123").encode(), limits),
            Err(CodeError::Malformed { .. })
        ));
        // `of` becomes a lookup key; it is an address or the frame is refused.
        let probe = obj! {
            "t" => Value::string("code_part"),
            "of" => Value::string("../../etc/passwd"),
            "size" => Value::Int(1),
            "at" => Value::Int(0),
            "body" => Value::string("00"),
        };
        assert!(matches!(
            CodeMessage::decode(probe.canonical_string().as_bytes(), limits),
            Err(CodeError::NotAnAddress { .. })
        ));
        assert!(CodeMessage::decode(&part(16, 12, b"1234").encode(), limits).is_ok());
    }

    #[test]
    fn a_part_frame_is_no_larger_than_a_full_blob_frame() {
        // The reason parts exist: whatever a package holds, no frame of this
        // family is ever bigger than the ones every node already accepts.
        let full_part = CodeMessage::Part {
            of: blobs::address(b"x"),
            size: crate::solver::manifest::MAX_FILE_BYTES,
            at: 0,
            body: vec![0xab; PART_BYTES],
        };
        let one_blob = CodeMessage::Blobs {
            blobs: vec![vec![0xab; blobs::MAX_BLOB_BYTES]],
        };
        assert!(full_part.encode().len() < one_blob.encode().len() + 256);
        assert!(full_part.encode().len() < super::super::transport::MAX_FRAME as usize);
    }
}
