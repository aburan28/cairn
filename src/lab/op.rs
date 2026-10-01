//! A lab op: one signed, content-addressed change to a space.
//!
//! Every view of a space — its files, conflicts, leases, inboxes and run
//! receipts — is a deterministic function of the *set* of ops a replica holds.
//! This module is the shape of one element of that set: how it is encoded, how
//! its identity is derived, how its signature is checked, and which bodies it
//! may carry. Nothing here decides whether an op is *authorised*; that needs
//! the causal past, which is [`super::store`]'s business.
//!
//! # Identity covers the envelope, not the signature
//!
//! An op's id is the digest of its canonical envelope (`src/canonical.rs`, the
//! same encoder every ledger record uses). The signature travels beside the
//! envelope and is not inside the id. Ed25519 under `verify_strict` admits one
//! signature per message and key, so this costs nothing in malleability, and
//! it means the id of a change is fixed before anyone signs it.
//!
//! # The signature is domain separated, deliberately
//!
//! [`Identity::sign_value`] signs a record's canonical bytes with no prefix, so
//! that any implementation following "sign the canonical bytes" can check it.
//! The identity module's own docs say the price: a signature over bytes that
//! happen to be a canonical *ledger* record is a signature on that record. A
//! lab op is therefore signed over [`SIGNING_DOMAIN`] followed by the canonical
//! envelope, so no lab signature can ever be replayed as a ledger signature, or
//! the other way round, whatever the envelope contains.
//!
//! # Unknown bodies are kept, not refused
//!
//! A space is causally closed: a replica stores an op only after its
//! dependencies. Refusing an op because a *newer* implementation wrote a body
//! kind this one does not know would therefore refuse everything anyone later
//! built on top of it, and a version skew would quietly stop sync. So an
//! unknown kind, or any body under a newer envelope `version`, parses as
//! [`Body::Unknown`]: stored, synced, signature-checked, and ignored by every
//! view. A *known* kind with a malformed field is refused — that is an author
//! error, and nothing honest depends on it because nothing honest could ingest
//! it.

use std::collections::BTreeSet;
use std::fmt;

use crate::canonical::Value;
use crate::crypto::identity::{verify_bytes, Identity, Signature};
use crate::hex;

/// The envelope's `type` field. Structural domain separation on top of
/// [`SIGNING_DOMAIN`]: no ledger record has this key/value pair.
pub const OP_TYPE: &str = "cairn.lab.op";

/// The envelope version this implementation writes and fully understands.
pub const OP_VERSION: i128 = 1;

/// Prefix of every signed message. See the module docs for why.
pub const SIGNING_DOMAIN: &[u8] = b"cairn/lab/op/v1\n";

/// Largest encoded op line accepted from anywhere. A `files` op carrying a
/// few thousand entries is a few hundred KiB; this bounds what a peer can make
/// a replica allocate for one line.
pub const MAX_OP_BYTES: usize = 8 * 1024 * 1024;

/// Most entries one `files` or `doc` op may carry. Large commits are split.
pub const MAX_ENTRIES: usize = 4096;

/// Most dependencies one op may name. An author with more heads than this
/// names the newest; every head is still reachable from later ops.
pub const MAX_DEPS: usize = 64;

/// Longest path, in bytes, the lab will store.
pub const MAX_PATH_BYTES: usize = 4096;

/// Longest lease, in seconds: thirty days. A lease that outlives a month is a
/// lock somebody forgot about.
pub const MAX_TTL_SECONDS: u64 = 30 * 24 * 60 * 60;

/// Bounds on free text that lands in every replica.
const MAX_SHORT_TEXT: usize = 512;
const MAX_LONG_TEXT: usize = 256 * 1024;
const MAX_LIST: usize = 256;

/// Why an op could not be parsed or does not verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpError(pub String);

impl fmt::Display for OpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for OpError {}

fn err<T>(message: impl Into<String>) -> Result<T, OpError> {
    Err(OpError(message.into()))
}

// -- small shared shapes -----------------------------------------------------

/// A role a member holds in a space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Role {
    /// May change membership and policy. Implies nothing else: an admin who
    /// should also write is listed with `writer` too.
    Admin,
    /// May write files, docs, leases, messages, environments and runs.
    Writer,
    /// May sync. Holds no write authority at all.
    Reader,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Writer => "writer",
            Role::Reader => "reader",
        }
    }

    pub fn parse(text: &str) -> Result<Role, OpError> {
        match text {
            "admin" => Ok(Role::Admin),
            "writer" => Ok(Role::Writer),
            "reader" => Ok(Role::Reader),
            other => err(format!("unknown role {other:?}")),
        }
    }
}

/// A member as admitted: an ed25519 key, its roles, and the transport peer ids
/// (`cairn p2p` identities) allowed to sync on its behalf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub key: String,
    pub roles: BTreeSet<Role>,
    pub peers: BTreeSet<String>,
}

impl Member {
    fn to_value(&self) -> Value {
        let mut pairs = vec![
            ("key", Value::string(&self.key)),
            (
                "roles",
                Value::array(self.roles.iter().map(|r| Value::string(r.as_str()))),
            ),
        ];
        // Omitted when empty, the crate-wide rule for optional fields: absent
        // and empty must not be two encodings of one member.
        if !self.peers.is_empty() {
            pairs.push(("peers", Value::array(self.peers.iter().map(Value::string))));
        }
        Value::object(pairs)
    }

    fn from_value(value: &Value) -> Result<Member, OpError> {
        let key = key_hex(field_str(value, "key")?)?;
        let roles_value = value
            .get("roles")
            .and_then(Value::as_array)
            .ok_or_else(|| OpError("member needs a roles array".into()))?;
        let mut roles = BTreeSet::new();
        for role in roles_value {
            let text = role
                .as_str()
                .ok_or_else(|| OpError("a role must be a string".into()))?;
            roles.insert(Role::parse(text)?);
        }
        if roles.is_empty() {
            return err("a member needs at least one role");
        }
        let mut peers = BTreeSet::new();
        if let Some(list) = value.get("peers") {
            let list = list
                .as_array()
                .ok_or_else(|| OpError("member peers must be an array".into()))?;
            if list.len() > MAX_LIST {
                return err("too many peers on one member");
            }
            for peer in list {
                let text = peer
                    .as_str()
                    .ok_or_else(|| OpError("a peer id must be a string".into()))?;
                peers.insert(key_hex(text)?);
            }
        }
        Ok(Member { key, roles, peers })
    }
}

/// Path rules for a space. Globs use `*`, `?` and `**`; see [`super::glob`].
///
/// Precedence is `ignore` > `mutable` > `write_once` > the default, which is
/// mutable. A general-purpose space wants files that can be edited; a research
/// program whose records are immutable says `write_once: ["**"]` and lists the
/// few mutable heads.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    pub write_once: Vec<String>,
    pub mutable: Vec<String>,
    pub ignore: Vec<String>,
}

impl Policy {
    pub fn to_value(&self) -> Value {
        let list = |items: &[String]| Value::array(items.iter().map(Value::string));
        let mut pairs = Vec::new();
        if !self.write_once.is_empty() {
            pairs.push(("write_once", list(&self.write_once)));
        }
        if !self.mutable.is_empty() {
            pairs.push(("mutable", list(&self.mutable)));
        }
        if !self.ignore.is_empty() {
            pairs.push(("ignore", list(&self.ignore)));
        }
        Value::object(pairs)
    }

    pub fn from_value(value: &Value) -> Result<Policy, OpError> {
        if value.as_object().is_none() {
            return err("policy must be an object");
        }
        let globs = |name: &str| -> Result<Vec<String>, OpError> {
            let Some(list) = value.get(name) else {
                return Ok(Vec::new());
            };
            let list = list
                .as_array()
                .ok_or_else(|| OpError(format!("policy {name} must be an array")))?;
            if list.len() > MAX_LIST {
                return err(format!("policy {name} has too many globs"));
            }
            let mut out = Vec::with_capacity(list.len());
            for item in list {
                let glob = item
                    .as_str()
                    .ok_or_else(|| OpError(format!("policy {name} entries must be strings")))?;
                if glob.is_empty() || glob.len() > MAX_SHORT_TEXT || glob.contains('\0') {
                    return err(format!("policy {name} glob {glob:?} is not usable"));
                }
                out.push(glob.to_string());
            }
            Ok(out)
        };
        Ok(Policy {
            write_once: globs("write_once")?,
            mutable: globs("mutable")?,
            ignore: globs("ignore")?,
        })
    }

    /// How this policy treats `path`.
    pub fn mode(&self, path: &str) -> PathMode {
        let matches = |globs: &[String]| globs.iter().any(|g| super::glob::matches(g, path));
        if matches(&self.ignore) {
            PathMode::Ignored
        } else if matches(&self.mutable) {
            PathMode::Mutable
        } else if matches(&self.write_once) {
            PathMode::WriteOnce
        } else {
            PathMode::Mutable
        }
    }
}

/// What a space's policy says about one path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathMode {
    Mutable,
    WriteOnce,
    Ignored,
}

/// A reference to one entry of one op: `"<op id>#<index>"`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EntryRef {
    pub op: String,
    pub index: u32,
}

impl EntryRef {
    pub fn parse(text: &str) -> Result<EntryRef, OpError> {
        let Some((op, index)) = text.rsplit_once('#') else {
            return err(format!("entry reference {text:?} has no '#index'"));
        };
        let op = op_id(op)?;
        let index = index
            .parse::<u32>()
            .map_err(|_| OpError(format!("entry reference {text:?} has a bad index")))?;
        Ok(EntryRef { op, index })
    }
}

impl fmt::Display for EntryRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}#{}", self.op, self.index)
    }
}

fn refs_to_value(refs: &[EntryRef]) -> Value {
    Value::array(refs.iter().map(|r| Value::string(r.to_string())))
}

fn refs_from_value(value: Option<&Value>) -> Result<Vec<EntryRef>, OpError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let list = value
        .as_array()
        .ok_or_else(|| OpError("pred must be an array".into()))?;
    if list.len() > MAX_LIST {
        return err("pred names too many entries");
    }
    let mut out = Vec::with_capacity(list.len());
    for item in list {
        let text = item
            .as_str()
            .ok_or_else(|| OpError("pred entries must be strings".into()))?;
        out.push(EntryRef::parse(text)?);
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// One file write: a path, the blob it now holds (or `None` for a deletion),
/// and the entries it replaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    pub path: String,
    pub blob: Option<String>,
    pub size: u64,
    pub exec: bool,
    pub pred: Vec<EntryRef>,
}

impl FileEntry {
    pub fn to_value(&self) -> Value {
        let mut pairs = vec![
            ("path", Value::string(&self.path)),
            (
                "blob",
                match &self.blob {
                    Some(address) => Value::string(address),
                    None => Value::Null,
                },
            ),
            ("size", Value::Int(i128::from(self.size))),
        ];
        if self.exec {
            pairs.push(("exec", Value::Bool(true)));
        }
        if !self.pred.is_empty() {
            pairs.push(("pred", refs_to_value(&self.pred)));
        }
        Value::object(pairs)
    }

    pub fn from_value(value: &Value) -> Result<FileEntry, OpError> {
        let path = normalize_path(field_str(value, "path")?)?;
        let blob = match value.get("blob") {
            Some(Value::Null) => None,
            Some(Value::String(address)) => Some(blob_address(address)?),
            _ => return err(format!("{path}: blob must be an address or null")),
        };
        let size = value
            .get("size")
            .and_then(Value::as_u64)
            .ok_or_else(|| OpError(format!("{path}: size must be a non-negative integer")))?;
        if blob.is_none() && size != 0 {
            return err(format!("{path}: a deletion has size 0"));
        }
        let exec = match value.get("exec") {
            None => false,
            Some(Value::Bool(true)) => true,
            // `false` is the default and is encoded by omission; accepting it
            // would give one entry two encodings and two ids.
            Some(_) => return err(format!("{path}: exec is either true or absent")),
        };
        let pred = refs_from_value(value.get("pred"))?;
        Ok(FileEntry {
            path,
            blob,
            size,
            exec,
            pred,
        })
    }
}

/// One field write in a doc: a key, its new value (`Null` deletes it), and the
/// entries it replaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub key: String,
    pub value: Value,
    pub pred: Vec<EntryRef>,
}

/// How a lease ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Outcome {
    Completed,
    Failed,
    Abandoned,
}

impl Outcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Outcome::Completed => "completed",
            Outcome::Failed => "failed",
            Outcome::Abandoned => "abandoned",
        }
    }

    pub fn parse(text: &str) -> Result<Outcome, OpError> {
        match text {
            "completed" => Ok(Outcome::Completed),
            "failed" => Ok(Outcome::Failed),
            "abandoned" => Ok(Outcome::Abandoned),
            other => err(format!(
                "unknown outcome {other:?} (completed, failed, abandoned)"
            )),
        }
    }
}

// -- bodies -------------------------------------------------------------------

/// What an op changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    Genesis {
        name: String,
        members: Vec<Member>,
        policy: Policy,
    },
    Members {
        admit: Vec<Member>,
        revoke: Vec<String>,
    },
    Policy(Policy),
    Files {
        entries: Vec<FileEntry>,
    },
    Doc {
        doc: String,
        fields: Vec<Field>,
    },
    Claim {
        task: String,
        holder: String,
        ttl: u64,
        note: Option<String>,
    },
    Release {
        claim: String,
        outcome: Outcome,
        note: Option<String>,
    },
    Msg {
        to: Vec<String>,
        from: Option<String>,
        subject: String,
        body: String,
        refs: Vec<String>,
    },
    Ack {
        msg: String,
        address: String,
    },
    Env {
        name: String,
        tree: String,
        manifest: String,
        pred: Vec<EntryRef>,
    },
    /// An execution receipt and the files it produced, as one op. The receipt
    /// is kept as a canonical object rather than a struct: it is a
    /// measurement, read by people and tools, and no view folds over its
    /// fields except `files`.
    Run {
        receipt: Value,
        files: Vec<FileEntry>,
    },
    /// A body this implementation does not understand. Stored and synced,
    /// ignored by every view; see the module docs.
    Unknown {
        kind: String,
    },
}

impl Body {
    pub fn kind(&self) -> &str {
        match self {
            Body::Genesis { .. } => "genesis",
            Body::Members { .. } => "members",
            Body::Policy(_) => "policy",
            Body::Files { .. } => "files",
            Body::Doc { .. } => "doc",
            Body::Claim { .. } => "claim",
            Body::Release { .. } => "release",
            Body::Msg { .. } => "msg",
            Body::Ack { .. } => "ack",
            Body::Env { .. } => "env",
            Body::Run { .. } => "run",
            Body::Unknown { kind } => kind,
        }
    }

    /// The role an author needs for this body. `None` for [`Body::Genesis`],
    /// which is checked against its own member list, and for
    /// [`Body::Unknown`], which any member may carry because no view reads it.
    pub fn required_role(&self) -> Option<Role> {
        match self {
            Body::Genesis { .. } | Body::Unknown { .. } => None,
            Body::Members { .. } | Body::Policy(_) => Some(Role::Admin),
            _ => Some(Role::Writer),
        }
    }

    /// File entries this body carries, if any.
    pub fn file_entries(&self) -> &[FileEntry] {
        match self {
            Body::Files { entries } => entries,
            Body::Run { files, .. } => files,
            _ => &[],
        }
    }

    pub fn to_value(&self) -> Value {
        let kind = Value::string(self.kind());
        match self {
            Body::Genesis {
                name,
                members,
                policy,
            } => Value::object([
                ("kind", kind),
                ("name", Value::string(name)),
                (
                    "members",
                    Value::array(members.iter().map(Member::to_value)),
                ),
                ("policy", policy.to_value()),
            ]),
            Body::Members { admit, revoke } => {
                let mut pairs = vec![("kind", kind)];
                if !admit.is_empty() {
                    pairs.push(("admit", Value::array(admit.iter().map(Member::to_value))));
                }
                if !revoke.is_empty() {
                    pairs.push(("revoke", Value::array(revoke.iter().map(Value::string))));
                }
                Value::object(pairs)
            }
            Body::Policy(policy) => {
                let mut value = policy.to_value();
                if let Value::Object(map) = &mut value {
                    map.insert("kind".into(), kind);
                }
                value
            }
            Body::Files { entries } => Value::object([
                ("kind", kind),
                (
                    "entries",
                    Value::array(entries.iter().map(FileEntry::to_value)),
                ),
            ]),
            Body::Doc { doc, fields } => Value::object([
                ("kind", kind),
                ("doc", Value::string(doc)),
                (
                    "fields",
                    Value::array(fields.iter().map(|field| {
                        let mut pairs = vec![
                            ("key", Value::string(&field.key)),
                            ("value", field.value.clone()),
                        ];
                        if !field.pred.is_empty() {
                            pairs.push(("pred", refs_to_value(&field.pred)));
                        }
                        Value::object(pairs)
                    })),
                ),
            ]),
            Body::Claim {
                task,
                holder,
                ttl,
                note,
            } => {
                let mut pairs = vec![
                    ("kind", kind),
                    ("task", Value::string(task)),
                    ("holder", Value::string(holder)),
                    ("ttl", Value::Int(i128::from(*ttl))),
                ];
                if let Some(note) = note {
                    pairs.push(("note", Value::string(note)));
                }
                Value::object(pairs)
            }
            Body::Release {
                claim,
                outcome,
                note,
            } => {
                let mut pairs = vec![
                    ("kind", kind),
                    ("claim", Value::string(claim)),
                    ("outcome", Value::string(outcome.as_str())),
                ];
                if let Some(note) = note {
                    pairs.push(("note", Value::string(note)));
                }
                Value::object(pairs)
            }
            Body::Msg {
                to,
                from,
                subject,
                body,
                refs,
            } => {
                let mut pairs = vec![
                    ("kind", kind),
                    ("to", Value::array(to.iter().map(Value::string))),
                    ("subject", Value::string(subject)),
                    ("body", Value::string(body)),
                ];
                if let Some(from) = from {
                    pairs.push(("from", Value::string(from)));
                }
                if !refs.is_empty() {
                    pairs.push(("refs", Value::array(refs.iter().map(Value::string))));
                }
                Value::object(pairs)
            }
            Body::Ack { msg, address } => Value::object([
                ("kind", kind),
                ("msg", Value::string(msg)),
                ("as", Value::string(address)),
            ]),
            Body::Env {
                name,
                tree,
                manifest,
                pred,
            } => {
                let mut pairs = vec![
                    ("kind", kind),
                    ("name", Value::string(name)),
                    ("tree", Value::string(tree)),
                    ("manifest", Value::string(manifest)),
                ];
                if !pred.is_empty() {
                    pairs.push(("pred", refs_to_value(pred)));
                }
                Value::object(pairs)
            }
            Body::Run { receipt, files } => {
                let mut pairs = vec![("kind", kind), ("receipt", receipt.clone())];
                if !files.is_empty() {
                    pairs.push(("files", Value::array(files.iter().map(FileEntry::to_value))));
                }
                Value::object(pairs)
            }
            // Never written by this implementation; an unknown body is only
            // ever re-encoded from its original envelope, which `Op` keeps.
            Body::Unknown { .. } => Value::object([("kind", kind)]),
        }
    }

    /// Parse a body. `version` is the envelope's: a newer one makes every body
    /// [`Body::Unknown`], because this implementation cannot know what a later
    /// version changed about a kind it does recognise.
    pub fn from_value(value: &Value, version: i128) -> Result<Body, OpError> {
        let kind = field_str(value, "kind")?.to_string();
        if version > OP_VERSION {
            return Ok(Body::Unknown { kind });
        }
        let body = match kind.as_str() {
            "genesis" => {
                let name = short_text(field_str(value, "name")?, "name")?;
                let members = list(value, "members")?
                    .iter()
                    .map(Member::from_value)
                    .collect::<Result<Vec<_>, _>>()?;
                if members.is_empty() {
                    return err("genesis needs at least one member");
                }
                let policy = match value.get("policy") {
                    Some(policy) => Policy::from_value(policy)?,
                    None => Policy::default(),
                };
                Body::Genesis {
                    name,
                    members,
                    policy,
                }
            }
            "members" => {
                let admit = optional_list(value, "admit")?
                    .iter()
                    .map(Member::from_value)
                    .collect::<Result<Vec<_>, _>>()?;
                let revoke = optional_list(value, "revoke")?
                    .iter()
                    .map(|item| {
                        item.as_str()
                            .ok_or_else(|| OpError("revoke entries must be keys".into()))
                            .and_then(key_hex)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                if admit.is_empty() && revoke.is_empty() {
                    return err("a members op admits or revokes somebody");
                }
                Body::Members { admit, revoke }
            }
            "policy" => Body::Policy(Policy::from_value(value)?),
            "files" => {
                let entries = list(value, "entries")?
                    .iter()
                    .map(FileEntry::from_value)
                    .collect::<Result<Vec<_>, _>>()?;
                if entries.is_empty() {
                    return err("a files op carries at least one entry");
                }
                if entries.len() > MAX_ENTRIES {
                    return err("a files op carries too many entries");
                }
                Body::Files { entries }
            }
            "doc" => {
                let doc = short_text(field_str(value, "doc")?, "doc")?;
                let fields_value = list(value, "fields")?;
                if fields_value.is_empty() || fields_value.len() > MAX_ENTRIES {
                    return err("a doc op carries between one and MAX_ENTRIES fields");
                }
                let mut fields = Vec::with_capacity(fields_value.len());
                for item in fields_value {
                    let key = short_text(field_str(item, "key")?, "key")?;
                    let field_value = item
                        .get("value")
                        .cloned()
                        .ok_or_else(|| OpError(format!("doc field {key:?} has no value")))?;
                    fields.push(Field {
                        key,
                        value: field_value,
                        pred: refs_from_value(item.get("pred"))?,
                    });
                }
                Body::Doc { doc, fields }
            }
            "claim" => {
                let ttl = value
                    .get("ttl")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| OpError("claim ttl must be seconds".into()))?;
                if ttl == 0 || ttl > MAX_TTL_SECONDS {
                    return err(format!("claim ttl must be 1..={MAX_TTL_SECONDS} seconds"));
                }
                Body::Claim {
                    task: short_text(field_str(value, "task")?, "task")?,
                    holder: short_text(field_str(value, "holder")?, "holder")?,
                    ttl,
                    note: optional_text(value, "note", MAX_LONG_TEXT)?,
                }
            }
            "release" => Body::Release {
                claim: op_id(field_str(value, "claim")?)?,
                outcome: Outcome::parse(field_str(value, "outcome")?)?,
                note: optional_text(value, "note", MAX_LONG_TEXT)?,
            },
            "msg" => {
                let to = list(value, "to")?
                    .iter()
                    .map(|item| {
                        item.as_str()
                            .ok_or_else(|| OpError("msg recipients must be strings".into()))
                            .and_then(|text| short_text(text, "to"))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                if to.is_empty() || to.len() > MAX_LIST {
                    return err("a msg needs between one and 256 recipients");
                }
                let refs = optional_list(value, "refs")?
                    .iter()
                    .map(|item| {
                        item.as_str()
                            .ok_or_else(|| OpError("msg refs must be strings".into()))
                            .and_then(|text| short_text(text, "refs"))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Body::Msg {
                    to,
                    from: optional_text(value, "from", MAX_SHORT_TEXT)?,
                    subject: short_text(field_str(value, "subject")?, "subject")?,
                    body: long_text(field_str(value, "body")?, "body")?,
                    refs,
                }
            }
            "ack" => Body::Ack {
                msg: op_id(field_str(value, "msg")?)?,
                address: short_text(field_str(value, "as")?, "as")?,
            },
            "env" => Body::Env {
                name: short_text(field_str(value, "name")?, "name")?,
                tree: digest(field_str(value, "tree")?)?,
                manifest: blob_address(field_str(value, "manifest")?)?,
                pred: refs_from_value(value.get("pred"))?,
            },
            "run" => {
                let receipt = value
                    .get("receipt")
                    .cloned()
                    .ok_or_else(|| OpError("a run carries a receipt".into()))?;
                if receipt.as_object().is_none() {
                    return err("a run receipt is an object");
                }
                let files = optional_list(value, "files")?
                    .iter()
                    .map(FileEntry::from_value)
                    .collect::<Result<Vec<_>, _>>()?;
                if files.len() > MAX_ENTRIES {
                    return err("a run publishes too many files in one op");
                }
                Body::Run { receipt, files }
            }
            _ => Body::Unknown { kind },
        };
        Ok(body)
    }
}

// -- the op -------------------------------------------------------------------

/// One signed change to a space, with its derived id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Op {
    pub id: String,
    pub space: Option<String>,
    pub author: String,
    pub lamport: u64,
    pub deps: Vec<String>,
    pub time: String,
    pub version: i128,
    pub body: Body,
    pub signature: Signature,
    /// The envelope exactly as signed. Kept so an op is always re-encoded from
    /// what its author signed — including bodies this implementation parsed as
    /// [`Body::Unknown`] — and never from a struct that may have dropped a field.
    envelope: Value,
}

impl Op {
    /// Build and sign a new op.
    ///
    /// The caller supplies `lamport` and `deps`; [`super::store::Lab::append`]
    /// is the one place that picks them, from the replica's heads, and checks
    /// the result is authorised before it is written.
    pub fn sign(
        identity: &Identity,
        space: Option<&str>,
        lamport: u64,
        deps: Vec<String>,
        time: String,
        body: Body,
    ) -> Result<Op, OpError> {
        let mut deps = deps;
        deps.sort();
        deps.dedup();
        let author = identity.submitter_id();
        let mut pairs = vec![
            ("type", Value::string(OP_TYPE)),
            ("version", Value::Int(OP_VERSION)),
            ("author", Value::string(&author)),
            ("lamport", Value::Int(i128::from(lamport))),
            ("deps", Value::array(deps.iter().map(Value::string))),
            ("time", Value::string(&time)),
            ("body", body.to_value()),
        ];
        if let Some(space) = space {
            pairs.push(("space", Value::string(space)));
        }
        let envelope = Value::object(pairs);
        let signature = identity.sign_bytes(&signed_message(&envelope));
        // Round-trip through the parser: one validation path for ops this
        // replica wrote and ops a peer sent, so a body that could not be read
        // back is refused here rather than written and then refused by everyone.
        Op::from_parts(envelope, signature)
    }

    /// Parse one stored or received line.
    pub fn from_line(line: &str) -> Result<Op, OpError> {
        if line.len() > MAX_OP_BYTES {
            return err(format!(
                "op line is {} bytes; the limit is {MAX_OP_BYTES}",
                line.len()
            ));
        }
        let value = Value::from_json(line).map_err(|e| OpError(format!("not an op: {e}")))?;
        let envelope = value
            .get("op")
            .cloned()
            .ok_or_else(|| OpError("op line has no \"op\"".into()))?;
        let signature = value
            .get("sig")
            .and_then(Value::as_str)
            .ok_or_else(|| OpError("op line has no \"sig\"".into()))
            .and_then(|text| {
                Signature::from_hex(text).map_err(|e| OpError(format!("bad signature: {e}")))
            })?;
        if value.as_object().map(|map| map.len()) != Some(2) {
            return err("an op line has exactly \"op\" and \"sig\"");
        }
        Op::from_parts(envelope, signature)
    }

    /// The one line this op is stored and sent as.
    pub fn to_line(&self) -> String {
        Value::object([
            ("op", self.envelope.clone()),
            ("sig", Value::string(self.signature.to_hex())),
        ])
        .canonical_string()
    }

    pub fn envelope(&self) -> &Value {
        &self.envelope
    }

    pub fn is_genesis(&self) -> bool {
        matches!(self.body, Body::Genesis { .. })
    }

    /// Seconds since the epoch this op claims to have been written at.
    pub fn unix_time(&self) -> Option<i64> {
        crate::time::parse_rfc3339(&self.time)
    }

    fn from_parts(envelope: Value, signature: Signature) -> Result<Op, OpError> {
        if envelope.as_object().is_none() {
            return err("op envelope must be an object");
        }
        if envelope.get("type").and_then(Value::as_str) != Some(OP_TYPE) {
            return err(format!("op type must be {OP_TYPE:?}"));
        }
        let version = envelope
            .get("version")
            .and_then(Value::as_i128)
            .ok_or_else(|| OpError("op version must be an integer".into()))?;
        if version < 1 {
            return err("op version must be at least 1");
        }
        let author = key_hex(field_str(&envelope, "author")?)?;
        let lamport = envelope
            .get("lamport")
            .and_then(Value::as_u64)
            .filter(|n| *n >= 1)
            .ok_or_else(|| OpError("lamport must be a positive integer".into()))?;
        let deps_value = list(&envelope, "deps")?;
        if deps_value.len() > MAX_DEPS {
            return err(format!("an op names at most {MAX_DEPS} dependencies"));
        }
        let mut deps = Vec::with_capacity(deps_value.len());
        for dep in deps_value {
            let text = dep
                .as_str()
                .ok_or_else(|| OpError("deps must be op ids".into()))?;
            deps.push(op_id(text)?);
        }
        // Sorted and unique on the wire, not merely after parsing: otherwise
        // two byte strings with one meaning would carry two ids.
        if deps.windows(2).any(|pair| pair[0] >= pair[1]) {
            return err("deps must be sorted and unique");
        }
        let time = field_str(&envelope, "time")?.to_string();
        if crate::time::parse_rfc3339(&time).is_none() {
            return err(format!("time {time:?} is not RFC 3339"));
        }
        let space = match envelope.get("space") {
            None => None,
            Some(Value::String(text)) => Some(op_id(text)?),
            Some(_) => return err("space must be an op id"),
        };
        let body_value = envelope
            .get("body")
            .ok_or_else(|| OpError("op has no body".into()))?;
        let body = Body::from_value(body_value, version)?;

        let genesis = matches!(body, Body::Genesis { .. });
        if genesis && (space.is_some() || !deps.is_empty() || lamport != 1) {
            return err("genesis has no space, no deps, and lamport 1");
        }
        if !genesis && (space.is_none() || deps.is_empty()) {
            return err("every op but genesis names its space and its deps");
        }

        let mut key = [0u8; 32];
        let bytes = hex::decode(&author).ok_or_else(|| OpError("author is not hex".into()))?;
        key.copy_from_slice(&bytes);
        verify_bytes(&key, &signed_message(&envelope), &signature)
            .map_err(|e| OpError(format!("signature does not verify: {e}")))?;

        Ok(Op {
            id: envelope.digest(),
            space,
            author,
            lamport,
            deps,
            time,
            version,
            body,
            signature,
            envelope,
        })
    }
}

fn signed_message(envelope: &Value) -> Vec<u8> {
    let canonical = envelope.canonical_bytes();
    let mut message = Vec::with_capacity(SIGNING_DOMAIN.len() + canonical.len());
    message.extend_from_slice(SIGNING_DOMAIN);
    message.extend_from_slice(&canonical);
    message
}

// -- validation helpers -------------------------------------------------------

fn field_str<'a>(value: &'a Value, name: &str) -> Result<&'a str, OpError> {
    value
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| OpError(format!("{name} must be a string")))
}

fn list<'a>(value: &'a Value, name: &str) -> Result<&'a [Value], OpError> {
    value
        .get(name)
        .and_then(Value::as_array)
        .ok_or_else(|| OpError(format!("{name} must be an array")))
}

fn optional_list<'a>(value: &'a Value, name: &str) -> Result<&'a [Value], OpError> {
    match value.get(name) {
        None => Ok(&[]),
        Some(item) => item
            .as_array()
            .ok_or_else(|| OpError(format!("{name} must be an array"))),
    }
}

fn optional_text(value: &Value, name: &str, limit: usize) -> Result<Option<String>, OpError> {
    match value.get(name) {
        None => Ok(None),
        Some(Value::String(text)) if text.len() <= limit => Ok(Some(text.clone())),
        Some(Value::String(_)) => err(format!("{name} is longer than {limit} bytes")),
        Some(_) => err(format!("{name} must be a string")),
    }
}

fn short_text(text: &str, name: &str) -> Result<String, OpError> {
    if text.is_empty() || text.len() > MAX_SHORT_TEXT || text.contains('\0') {
        return err(format!(
            "{name} must be 1..={MAX_SHORT_TEXT} bytes without NUL"
        ));
    }
    Ok(text.to_string())
}

fn long_text(text: &str, name: &str) -> Result<String, OpError> {
    if text.len() > MAX_LONG_TEXT {
        return err(format!("{name} is longer than {MAX_LONG_TEXT} bytes"));
    }
    Ok(text.to_string())
}

/// 64 lowercase hex characters: an ed25519 key or a transport peer id.
pub fn key_hex(text: &str) -> Result<String, OpError> {
    if text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(text.to_string())
    } else {
        err(format!("{text:?} is not 64 lowercase hex characters"))
    }
}

/// `sha256:` and 64 lowercase hex characters.
pub fn digest(text: &str) -> Result<String, OpError> {
    match text.strip_prefix(crate::canonical::DIGEST_PREFIX) {
        Some(hex) if key_hex(hex).is_ok() => Ok(text.to_string()),
        _ => err(format!("{text:?} is not a sha256: digest")),
    }
}

/// An op id. Same shape as any digest; named for what it refers to.
pub fn op_id(text: &str) -> Result<String, OpError> {
    digest(text)
}

/// A blob address. Same shape as any digest; named for what it refers to.
pub fn blob_address(text: &str) -> Result<String, OpError> {
    digest(text)
}

/// Check a path is one the lab will store, and return it.
///
/// Paths arrive in ops written by other people and become file names on
/// checkout, so this is a security boundary, not tidiness: no absolute paths,
/// no `..`, no `.`, no empty segments, no backslashes (a Windows peer would
/// read `a\..\b` as a traversal), and no NUL. Nothing is *normalised* — a
/// path that would need fixing is refused, so one file never has two names.
pub fn normalize_path(path: &str) -> Result<String, OpError> {
    if path.is_empty() || path.len() > MAX_PATH_BYTES {
        return err(format!(
            "path must be 1..={MAX_PATH_BYTES} bytes, got {}",
            path.len()
        ));
    }
    if path.contains('\\') || path.contains('\0') {
        return err(format!("path {path:?} contains a backslash or NUL"));
    }
    if path.chars().any(char::is_control) {
        return err(format!("path {path:?} contains a control character"));
    }
    for segment in path.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." || segment.len() > 255 {
            return err(format!(
                "path {path:?} has an empty, '.', '..' or over-long segment"
            ));
        }
    }
    Ok(path.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(seed: u8) -> Identity {
        Identity::from_secret_bytes([seed; 32])
    }

    fn genesis(id: &Identity) -> Op {
        Op::sign(
            id,
            None,
            1,
            Vec::new(),
            "2026-10-01T00:00:00+00:00".into(),
            Body::Genesis {
                name: "test".into(),
                members: vec![Member {
                    key: id.submitter_id(),
                    roles: [Role::Admin, Role::Writer].into_iter().collect(),
                    peers: BTreeSet::new(),
                }],
                policy: Policy::default(),
            },
        )
        .expect("genesis signs")
    }

    #[test]
    fn an_op_round_trips_through_its_line_with_the_same_id() {
        let id = identity(7);
        let op = genesis(&id);
        let parsed = Op::from_line(&op.to_line()).expect("parses");
        assert_eq!(parsed.id, op.id);
        assert_eq!(parsed, op);
    }

    #[test]
    fn a_tampered_envelope_fails_its_signature() {
        let op = genesis(&identity(7));
        let line = op.to_line().replace("\"test\"", "\"tset\"");
        let error = Op::from_line(&line).expect_err("tamper must not verify");
        assert!(error.0.contains("signature"), "{error}");
    }

    #[test]
    fn a_lab_signature_is_not_a_signature_over_the_bare_envelope() {
        // The domain prefix is what stops a lab signature doubling as a
        // signature on a ledger record with the same canonical bytes.
        let id = identity(7);
        let op = genesis(&id);
        let bare = crate::crypto::identity::verify_value(
            id.public().as_bytes(),
            op.envelope(),
            &op.signature,
        );
        assert!(bare.is_err(), "the signature must cover the domain prefix");
    }

    #[test]
    fn unknown_kinds_parse_as_unknown_rather_than_failing() {
        let id = identity(9);
        let op = Op::sign(
            &id,
            Some(&genesis(&id).id),
            2,
            vec![genesis(&id).id],
            "2026-10-01T00:00:00+00:00".into(),
            Body::Files {
                entries: vec![FileEntry {
                    path: "a".into(),
                    blob: None,
                    size: 0,
                    exec: false,
                    pred: Vec::new(),
                }],
            },
        )
        .expect("signs");
        let mut body = op.envelope().get("body").cloned().expect("body");
        if let Value::Object(map) = &mut body {
            map.insert("kind".into(), Value::string("from-the-future"));
        }
        let parsed = Body::from_value(&body, OP_VERSION).expect("unknown kind parses");
        assert_eq!(
            parsed,
            Body::Unknown {
                kind: "from-the-future".into()
            }
        );
        // A newer envelope version makes even a known kind opaque.
        let known = op.envelope().get("body").cloned().expect("body");
        assert!(matches!(
            Body::from_value(&known, OP_VERSION + 1).expect("parses"),
            Body::Unknown { .. }
        ));
    }

    #[test]
    fn paths_that_could_escape_a_checkout_are_refused() {
        for bad in [
            "",
            "/etc/passwd",
            "../x",
            "a/../b",
            "a//b",
            "a/./b",
            "a\\b",
            "a/",
            "a\0b",
            "a\nb",
        ] {
            assert!(normalize_path(bad).is_err(), "{bad:?} must be refused");
        }
        for good in ["a", "ledger/goals/GOAL-X.yaml", "a/b.c/d", "ünï/ç"] {
            assert_eq!(normalize_path(good).expect("ok"), good);
        }
    }

    #[test]
    fn entry_references_round_trip() {
        let op = format!("sha256:{}", "ab".repeat(32));
        let text = format!("{op}#17");
        let parsed = EntryRef::parse(&text).expect("parses");
        assert_eq!(parsed.index, 17);
        assert_eq!(parsed.to_string(), text);
        assert!(EntryRef::parse(&op).is_err());
        assert!(EntryRef::parse(&format!("{op}#-1")).is_err());
    }

    #[test]
    fn an_explicit_false_exec_is_refused_so_an_entry_has_one_encoding() {
        let value = Value::object([
            ("path", Value::string("a")),
            ("blob", Value::Null),
            ("size", Value::Int(0)),
            ("exec", Value::Bool(false)),
        ]);
        assert!(FileEntry::from_value(&value).is_err());
    }

    #[test]
    fn policy_precedence_is_ignore_then_mutable_then_write_once() {
        let policy = Policy {
            write_once: vec!["**".into()],
            mutable: vec!["ledger/goals/*.yaml".into()],
            ignore: vec!["knowledge/INDEX.md".into()],
        };
        assert_eq!(policy.mode("knowledge/INDEX.md"), PathMode::Ignored);
        assert_eq!(policy.mode("ledger/goals/GOAL-A.yaml"), PathMode::Mutable);
        assert_eq!(
            policy.mode("ledger/decisions/DEC-1.yaml"),
            PathMode::WriteOnce
        );
        assert_eq!(Policy::default().mode("anything"), PathMode::Mutable);
    }
}
