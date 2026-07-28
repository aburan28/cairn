//! Append-only hash-linked log.
//!
//! Stage 0 has one sequencer and no consensus. That is deliberate: the property
//! that actually matters is not "no one is in charge" but **anyone can check**.
//! A single operator who publishes a hash-linked log plus a re-runnable verifier
//! gives every reader the ability to independently confirm every claim the
//! network has settled -- which is most of the value of decentralization, at
//! none of the cost. Consensus replaces the operator later, and changes nothing
//! below.
//!
//! Storage is JSONL, one entry per line, each carrying the hash of its
//! predecessor. Tampering with entry *n* invalidates every hash from *n* onward.
//!
//! # What the chain does and does not prove
//!
//! [`Ledger::verify_chain`] proves that the log you are holding is internally
//! consistent: no entry's contents were edited, none was removed from the
//! middle, and the sequence numbers count up from zero. It cannot prove that
//! nobody *truncated the tail*, because a shorter prefix of a valid chain is
//! itself a valid chain. That gap is closed outside this module, by publishing
//! [`Ledger::head`] and [`Ledger::root`]: a reader who remembers yesterday's
//! root and cannot find it inside today's log has caught a rollback.

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::canonical::{merkle_root, CanonicalError, Value};

/// A single record in the log.
///
/// Fields are public because every consumer of the log -- attribution, audit,
/// the CLI -- reads them, and because an `Entry` handed out by this module is
/// already a snapshot: mutating your copy cannot alter the file or the ledger's
/// own view. What mutating your copy *does* do is invalidate [`Entry::hash`],
/// which is exactly what [`Entry::recompute_hash`] exists to detect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Position in the log, counting from zero. Equals the number of entries
    /// that preceded it, so a gap is detectable without any external state.
    pub seq: u64,
    /// Hash of the predecessor; `None` at genesis, serialized as JSON `null`.
    pub prev: Option<String>,
    /// Record type -- `objective`, `commitment`, `claim`, `verdict`,
    /// `settlement`, `frontier`. Deliberately an open set of strings rather
    /// than an enum: the log is a dumb, schema-agnostic transport, and the
    /// rules about which kinds may follow which live in `node`, where they can
    /// be changed without rewriting history that this module must still read.
    pub kind: String,
    /// The record body. Any canonical value; the log never inspects it.
    pub payload: Value,
    /// Operator-supplied timestamp. Advisory only -- ordering comes from the
    /// hash chain, never from the clock, because a clock is not evidence.
    pub ts: String,
    /// `sha256:` digest of [`Entry::body`].
    pub hash: String,
}

impl Entry {
    /// The exact object the entry hash covers: `{seq, prev, kind, payload, ts}`.
    ///
    /// `hash` is deliberately absent -- a digest cannot cover itself. Everything
    /// else is included, so editing any one of the five fields after the fact
    /// breaks the entry and, through `prev`, every entry after it.
    pub fn body(&self) -> Value {
        Value::object([
            ("seq", Value::Int(i128::from(self.seq))),
            (
                "prev",
                match &self.prev {
                    Some(hash) => Value::String(hash.clone()),
                    // Genesis. JSON `null`, not the empty string: an absent
                    // predecessor and a predecessor whose hash happens to be
                    // empty must not produce the same bytes.
                    None => Value::Null,
                },
            ),
            ("kind", Value::String(self.kind.clone())),
            ("payload", self.payload.clone()),
            ("ts", Value::String(self.ts.clone())),
        ])
    }

    /// Recompute the hash from the current contents.
    ///
    /// If this differs from [`Entry::hash`], the entry was modified after it was
    /// written. This is the whole tamper-evidence mechanism, in one line.
    pub fn recompute_hash(&self) -> String {
        self.body().digest()
    }

    /// The stored form: the hashed body plus the `hash` field, as one JSON line.
    ///
    /// The trailing newline that separates records on disk is added by
    /// [`Ledger::append`], not here.
    ///
    /// The on-disk line does not have to be canonical -- only the *hashed body*
    /// does -- but writing canonical bytes costs nothing and makes the file
    /// byte-reproducible from the entries alone. Key order and string escaping
    /// therefore match the reference implementation exactly; whitespace does
    /// not (the reference emits `json.dumps` defaults, with a space after each
    /// comma and colon). Both are the same JSON object, and either loads in
    /// either implementation -- which is the only interop property that matters,
    /// since nothing hashes this line.
    pub fn to_json_line(&self) -> String {
        let record = match self.body() {
            Value::Object(mut map) => {
                map.insert(String::from("hash"), Value::String(self.hash.clone()));
                Value::Object(map)
            }
            // Unreachable: `body` always builds an object. Expressed as a
            // fallback rather than an `unwrap` because this crate does not
            // panic in library code.
            other => other,
        };
        record.canonical_string()
    }

    /// Parse one stored line into an entry.
    ///
    /// Stricter than the reference implementation, in the two places where
    /// Python's unbounded integers hid a decision Rust has to make explicitly:
    /// a `seq` that is negative or larger than `u64` is refused here rather
    /// than wrapping into a plausible-looking number, and a payload integer
    /// outside the canonical 128-bit range is refused rather than degrading to
    /// a float and hashing differently than it did when it was written.
    fn parse(value: &Value, location: &str) -> Result<Entry, LedgerError> {
        let bad = |field: &str| LedgerError::Malformed {
            location: location.to_string(),
            reason: format!("missing or invalid field {field:?}"),
        };
        let seq = value
            .get("seq")
            .and_then(Value::as_u64)
            .ok_or_else(|| bad("seq"))?;
        let prev = match value.get("prev") {
            Some(Value::Null) => None,
            Some(Value::String(hash)) => Some(hash.clone()),
            _ => return Err(bad("prev")),
        };
        let kind = value
            .get("kind")
            .and_then(Value::as_str)
            .ok_or_else(|| bad("kind"))?
            .to_string();
        let payload = value
            .get("payload")
            .cloned()
            .ok_or_else(|| bad("payload"))?;
        let ts = value
            .get("ts")
            .and_then(Value::as_str)
            .ok_or_else(|| bad("ts"))?
            .to_string();
        let hash = value
            .get("hash")
            .and_then(Value::as_str)
            .ok_or_else(|| bad("hash"))?
            .to_string();
        Ok(Entry {
            seq,
            prev,
            kind,
            payload,
            ts,
            hash,
        })
    }
}

/// Something went wrong reading or extending the log.
///
/// `Clone` and `PartialEq` are not derived: [`std::io::Error`] is neither, and
/// replacing it with a comparable shim would discard the OS-level detail that
/// makes a write failure diagnosable. An error here is reported, not compared.
#[derive(Debug)]
pub enum LedgerError {
    /// The log file could not be read, created, or extended.
    Io {
        context: String,
        source: std::io::Error,
    },
    /// A stored line is not a well-formed ledger entry: bad JSON, a missing
    /// field, or a field of the wrong type.
    Malformed { location: String, reason: String },
    /// A stored line is JSON but holds a value this format cannot represent --
    /// a float, or an integer outside the canonical range.
    ///
    /// The reference implementation raises the equivalent error on *append*
    /// too. Here it cannot: [`Value`] has no float variant, so a payload built
    /// in Rust is canonically serializable by construction and only a line
    /// written by hand or by a non-conforming implementation can carry one.
    Canonical {
        location: String,
        source: CanonicalError,
    },
}

impl fmt::Display for LedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LedgerError::Io { context, source } => write!(f, "{context}: {source}"),
            LedgerError::Malformed { location, reason } => write!(f, "{location}: {reason}"),
            LedgerError::Canonical { location, source } => write!(f, "{location}: {source}"),
        }
    }
}

impl std::error::Error for LedgerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            LedgerError::Io { source, .. } => Some(source),
            LedgerError::Canonical { source, .. } => Some(source),
            LedgerError::Malformed { .. } => None,
        }
    }
}

fn io_error(context: impl Into<String>, source: std::io::Error) -> LedgerError {
    LedgerError::Io {
        context: context.into(),
        source,
    }
}

/// A hash-linked append-only log backed by a JSONL file.
///
/// Not `Clone`, and that is a design decision rather than an oversight. Two
/// handles to one file would each compute `prev` from their own view of the
/// tail, so concurrent appends would produce two entries claiming the same
/// predecessor and the same `seq` -- a forked log written by a single honest
/// operator. Stage 0 has one sequencer; the type says so.
#[derive(Debug)]
pub struct Ledger {
    path: PathBuf,
    entries: Vec<Entry>,
}

impl Ledger {
    /// Open the log at `path`, loading it if it exists.
    ///
    /// A missing file is not an error -- it is an empty log, and the first
    /// [`append`](Ledger::append) creates it. Opening deliberately does *not*
    /// verify the chain: a caller that wants that guarantee asks for it with
    /// [`verify_chain`](Ledger::verify_chain), and a caller repairing a damaged
    /// log needs to be able to read it first.
    pub fn open(path: impl Into<PathBuf>) -> Result<Ledger, LedgerError> {
        let mut ledger = Ledger {
            path: path.into(),
            entries: Vec::new(),
        };
        if ledger.path.exists() {
            ledger.load()?;
        }
        Ok(ledger)
    }

    // -- storage ---------------------------------------------------------

    fn load(&mut self) -> Result<(), LedgerError> {
        let where_ = self.path.display().to_string();
        let raw = fs::read(&self.path).map_err(|e| io_error(format!("reading {where_}"), e))?;
        let text = String::from_utf8(raw).map_err(|_| LedgerError::Malformed {
            location: where_.clone(),
            reason: String::from("log file is not valid UTF-8"),
        })?;

        // Line numbers count blank lines, so a diagnostic points at the line a
        // text editor shows, not at the n-th non-empty line.
        for (index, line) in text.lines().enumerate() {
            let lineno = index.saturating_add(1);
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let location = format!("{where_}:{lineno}");
            let value = Value::from_json(line).map_err(|e| match e {
                CanonicalError::Malformed(why) => LedgerError::Malformed {
                    location: location.clone(),
                    reason: format!("malformed JSON: {why}"),
                },
                source => LedgerError::Canonical {
                    location: location.clone(),
                    source,
                },
            })?;
            let entry = Entry::parse(&value, &location)?;
            self.entries.push(entry);
        }
        Ok(())
    }

    /// Append a record and return it.
    ///
    /// Ordering is load-bearing. The entry is built and serialized **before**
    /// the filesystem is touched, so a record that cannot be encoded never
    /// leaves a half-written line behind for the next reader to choke on; and
    /// the in-memory tail is extended only **after** the write succeeds, so a
    /// failed append leaves the ledger exactly as it was rather than handing
    /// out a `prev` hash for an entry that is not on disk.
    ///
    /// The write is not `fsync`ed, matching the reference implementation: a
    /// power loss can lose the tail, which is a durability question, not an
    /// integrity one. A *torn* tail -- a partially written line -- is caught on
    /// the next [`open`](Ledger::open) as malformed JSON.
    pub fn append(&mut self, kind: &str, payload: Value, ts: &str) -> Result<&Entry, LedgerError> {
        let prev = self.entries.last().map(|entry| entry.hash.clone());
        // `seq` is the count of everything already in the log. The conversion
        // cannot fail on any platform this runs on, but it is checked rather
        // than cast, because a silently truncated sequence number would forge a
        // valid-looking chain.
        let seq = u64::try_from(self.entries.len()).map_err(|_| LedgerError::Malformed {
            location: self.path.display().to_string(),
            reason: String::from("log is too long to number"),
        })?;

        let mut entry = Entry {
            seq,
            prev,
            kind: kind.to_string(),
            payload,
            ts: ts.to_string(),
            hash: String::new(),
        };
        // Safe to fill in afterwards precisely because the hash does not cover
        // itself -- `body()` ignores the field being assigned here.
        entry.hash = entry.recompute_hash();
        let line = format!("{}\n", entry.to_json_line());

        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .map_err(|e| io_error(format!("creating {}", parent.display()), e))?;
            }
        }
        let mut handle = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| io_error(format!("opening {} for append", self.path.display()), e))?;
        handle
            .write_all(line.as_bytes())
            .map_err(|e| io_error(format!("appending to {}", self.path.display()), e))?;

        self.entries.push(entry);
        self.entries.last().ok_or_else(|| LedgerError::Malformed {
            location: self.path.display().to_string(),
            reason: String::from("internal: appended entry is missing"),
        })
    }

    // -- reading ---------------------------------------------------------

    /// Path of the backing file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Every entry, in log order.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Every entry of one kind, in log order.
    pub fn entries_of_kind(&self, kind: &str) -> Vec<&Entry> {
        self.entries
            .iter()
            .filter(|entry| entry.kind == kind)
            .collect()
    }

    /// Hash of the most recent entry -- the value a reader pins to detect a
    /// rewritten log. `None` when the log is empty.
    pub fn head(&self) -> Option<&str> {
        self.entries.last().map(|entry| entry.hash.as_str())
    }

    /// Merkle root over entry hashes -- a single value that pins the whole log.
    ///
    /// Unlike [`head`](Ledger::head), this supports proving that one specific
    /// entry is in the log without shipping the log, which is what a third
    /// party auditing a single settlement actually needs.
    pub fn root(&self) -> Option<String> {
        let hashes: Vec<String> = self
            .entries
            .iter()
            .map(|entry| entry.hash.clone())
            .collect();
        merkle_root(&hashes)
    }

    // -- integrity -------------------------------------------------------

    /// Return every integrity problem found. An empty vector means intact.
    ///
    /// Three independent checks, because they fail on different attacks:
    ///
    /// - **`seq`** counts from zero with no gaps, so removing an entry from the
    ///   middle is caught even though the surviving entries are each perfectly
    ///   well-formed.
    /// - **`prev`** links each entry to its predecessor's hash, so reordering
    ///   or splicing is caught.
    /// - **Recomputing the hash** catches an edit to an entry's contents. Note
    ///   that an attacker who can rewrite the file can also re-hash the entry
    ///   they edited -- which is why this check does not stand alone: re-hashing
    ///   entry *n* changes its hash, so every `prev` from *n+1* onward is now
    ///   wrong, and repairing those changes their hashes in turn. Rewriting one
    ///   entry means rewriting the entire suffix, and the published head or
    ///   root no longer matches.
    ///
    /// Returning a list rather than a bool is deliberate: an audit reports
    /// everything that is wrong, not just the first thing.
    pub fn verify_chain(&self) -> Vec<String> {
        let mut problems: Vec<String> = Vec::new();
        let mut expected_prev: Option<&str> = None;
        for (i, entry) in self.entries.iter().enumerate() {
            if usize::try_from(entry.seq).ok() != Some(i) {
                problems.push(format!("entry {i}: seq is {}", entry.seq));
            }
            if entry.prev.as_deref() != expected_prev {
                problems.push(format!(
                    "entry {i}: prev is {}, expected {}",
                    render_prev(entry.prev.as_deref()),
                    render_prev(expected_prev)
                ));
            }
            if entry.recompute_hash() != entry.hash {
                problems.push(format!(
                    "entry {i}: hash mismatch -- content was modified after it was written"
                ));
            }
            expected_prev = Some(entry.hash.as_str());
        }
        problems
    }
}

/// Render a `prev` link for a diagnostic, mirroring the reference
/// implementation's wording so audit output is comparable across
/// implementations.
fn render_prev(prev: Option<&str>) -> String {
    match prev {
        Some(hash) => format!("'{hash}'"),
        None => String::from("None"),
    }
}

impl<'a> IntoIterator for &'a Ledger {
    type Item = &'a Entry;
    type IntoIter = std::slice::Iter<'a, Entry>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    // Golden values produced by the Python reference implementation. They pin
    // the hashed body across languages; if these drift, the two implementations
    // disagree about identity and nothing else in the system can be trusted.
    const GOLDEN_E0: &str =
        "sha256:26f56730d43e820ae01ec17423f98349f4af70e0a8cfc1fb343719663f3c6356";
    const GOLDEN_E1: &str =
        "sha256:0780a4309538c8fc88e209681d263f8015f533b33ded45d0acba4d03d0a79ecf";
    const GOLDEN_ROOT: &str =
        "sha256:b7804ea06cd496c616fefd41d7d24b698ab190cf1fa7bbc1636d9b9d033c4446";

    /// Exactly what the Python implementation writes for those two entries,
    /// spaces and all.
    const PYTHON_WRITTEN_LOG: &str = concat!(
        r#"{"hash": "sha256:26f56730d43e820ae01ec17423f98349f4af70e0a8cfc1fb343719663f3c6356", "kind": "note", "payload": {"i": 0}, "prev": null, "seq": 0, "ts": "2026-07-28T00:00:00+00:00"}"#,
        "\n",
        r#"{"hash": "sha256:0780a4309538c8fc88e209681d263f8015f533b33ded45d0acba4d03d0a79ecf", "kind": "claim", "payload": {"msg": "héllo", "n": -3, "ok": true, "z": null}, "prev": "sha256:26f56730d43e820ae01ec17423f98349f4af70e0a8cfc1fb343719663f3c6356", "seq": 1, "ts": "t"}"#,
        "\n",
    );

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(tag: &str) -> TempDir {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let mut path = std::env::temp_dir();
            path.push(format!(
                "proofwork-ledger-{}-{nanos}-{n}-{tag}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("create temp dir");
            TempDir { path }
        }

        fn file(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn note(i: i128) -> Value {
        Value::object([("i", Value::Int(i))])
    }

    fn read_lines(path: &Path) -> Vec<String> {
        fs::read_to_string(path)
            .expect("read log")
            .lines()
            .map(String::from)
            .collect()
    }

    fn write_lines(path: &Path, lines: &[String]) {
        let mut text = lines.join("\n");
        text.push('\n');
        fs::write(path, text).expect("write log");
    }

    #[test]
    fn chain_verifies_when_intact() {
        let dir = TempDir::new("intact");
        let mut ledger = Ledger::open(dir.file("log.jsonl")).expect("open");
        for i in 0..5 {
            ledger
                .append("note", note(i), "2026-07-28T00:00:00+00:00")
                .expect("append");
        }
        assert_eq!(ledger.verify_chain(), Vec::<String>::new());
        assert_eq!(ledger.len(), 5);
        assert!(!ledger.is_empty());
    }

    #[test]
    fn entries_link_to_predecessor() {
        let dir = TempDir::new("link");
        let mut ledger = Ledger::open(dir.file("log.jsonl")).expect("open");
        let first = ledger.append("note", note(0), "t").expect("append").clone();
        let second = ledger.append("note", note(1), "t").expect("append").clone();
        assert_eq!(first.prev, None);
        assert_eq!(second.prev.as_deref(), Some(first.hash.as_str()));
        assert_eq!(first.seq, 0);
        assert_eq!(second.seq, 1);
    }

    #[test]
    fn empty_ledger_has_no_head_or_root() {
        let dir = TempDir::new("empty");
        let ledger = Ledger::open(dir.file("missing.jsonl")).expect("open");
        assert!(ledger.is_empty());
        assert_eq!(ledger.head(), None);
        assert_eq!(ledger.root(), None);
        assert_eq!(ledger.verify_chain(), Vec::<String>::new());
    }

    #[test]
    fn reload_from_disk_preserves_chain() {
        let dir = TempDir::new("reload");
        let path = dir.file("log.jsonl");
        let mut ledger = Ledger::open(&path).expect("open");
        ledger.append("note", note(0), "t").expect("append");
        ledger.append("note", note(1), "t").expect("append");
        let head = ledger.head().map(String::from);
        let root = ledger.root();

        let reloaded = Ledger::open(&path).expect("reopen");
        assert_eq!(reloaded.head().map(String::from), head);
        assert_eq!(reloaded.root(), root);
        assert_eq!(reloaded.verify_chain(), Vec::<String>::new());
        assert_eq!(reloaded.entries(), ledger.entries());
    }

    #[test]
    fn entry_hashes_match_the_python_reference() {
        let dir = TempDir::new("golden");
        let mut ledger = Ledger::open(dir.file("log.jsonl")).expect("open");
        let e0 = ledger
            .append("note", note(0), "2026-07-28T00:00:00+00:00")
            .expect("append")
            .clone();
        assert_eq!(e0.hash, GOLDEN_E0);

        let payload = Value::object([
            ("msg", Value::string("héllo")),
            ("n", Value::Int(-3)),
            ("ok", Value::Bool(true)),
            ("z", Value::Null),
        ]);
        let e1 = ledger
            .append("claim", payload, "t")
            .expect("append")
            .clone();
        assert_eq!(e1.hash, GOLDEN_E1);
        assert_eq!(ledger.root().as_deref(), Some(GOLDEN_ROOT));
    }

    #[test]
    fn a_log_written_by_the_python_implementation_loads_and_verifies() {
        let dir = TempDir::new("interop");
        let path = dir.file("log.jsonl");
        fs::write(&path, PYTHON_WRITTEN_LOG).expect("write");

        let ledger = Ledger::open(&path).expect("open");
        assert_eq!(ledger.len(), 2);
        assert_eq!(ledger.verify_chain(), Vec::<String>::new());
        assert_eq!(ledger.head(), Some(GOLDEN_E1));
        assert_eq!(ledger.root().as_deref(), Some(GOLDEN_ROOT));
        // Non-ASCII survives the round trip as raw UTF-8, not as an escape.
        let claims = ledger.entries_of_kind("claim");
        assert_eq!(claims.len(), 1);
        let msg = claims[0].payload.get("msg").and_then(Value::as_str);
        assert_eq!(msg, Some("héllo"));
    }

    #[test]
    fn our_lines_are_readable_as_the_same_entries() {
        let dir = TempDir::new("roundtrip");
        let path = dir.file("log.jsonl");
        let mut ledger = Ledger::open(&path).expect("open");
        ledger.append("note", note(7), "t").expect("append");
        let written = ledger.entries().first().cloned().expect("one entry");

        let reloaded = Ledger::open(&path).expect("reopen");
        assert_eq!(reloaded.entries().first(), Some(&written));
        // The stored line is exactly what `to_json_line` produced.
        assert_eq!(read_lines(&path), vec![written.to_json_line()]);
    }

    #[test]
    fn genesis_prev_is_json_null() {
        let entry = Entry {
            seq: 0,
            prev: None,
            kind: String::from("note"),
            payload: note(0),
            ts: String::from("t"),
            hash: String::from("sha256:whatever"),
        };
        assert!(entry.to_json_line().contains(r#""prev":null"#));
        assert_eq!(entry.body().get("prev"), Some(&Value::Null));
    }

    #[test]
    fn the_hash_does_not_cover_itself() {
        let mut entry = Entry {
            seq: 3,
            prev: Some(String::from("sha256:aa")),
            kind: String::from("note"),
            payload: note(1),
            ts: String::from("t"),
            hash: String::new(),
        };
        let with_empty = entry.recompute_hash();
        entry.hash = String::from("sha256:something-else-entirely");
        assert_eq!(entry.recompute_hash(), with_empty);
        assert_eq!(entry.body().get("hash"), None);
    }

    #[test]
    fn the_hash_covers_every_other_field() {
        let base = Entry {
            seq: 3,
            prev: Some(String::from("sha256:aa")),
            kind: String::from("note"),
            payload: note(1),
            ts: String::from("t"),
            hash: String::new(),
        };
        let original = base.recompute_hash();

        let mut variants = Vec::new();
        let mut v = base.clone();
        v.seq = 4;
        variants.push(v);
        let mut v = base.clone();
        v.prev = None;
        variants.push(v);
        let mut v = base.clone();
        v.kind = String::from("claim");
        variants.push(v);
        let mut v = base.clone();
        v.payload = note(2);
        variants.push(v);
        let mut v = base.clone();
        v.ts = String::from("u");
        variants.push(v);

        for (i, variant) in variants.iter().enumerate() {
            assert_ne!(
                variant.recompute_hash(),
                original,
                "field {i} is not covered"
            );
        }
    }

    #[test]
    fn tampering_with_payload_is_detected() {
        let dir = TempDir::new("tamper");
        let path = dir.file("log.jsonl");
        let mut ledger = Ledger::open(&path).expect("open");
        ledger
            .append("note", Value::object([("amount", Value::Int(1))]), "t")
            .expect("append");
        ledger
            .append("note", Value::object([("amount", Value::Int(2))]), "t")
            .expect("append");
        let original = ledger.entries().first().cloned().expect("first entry");

        // Rewrite entry 0's payload but keep its recorded hash -- the forgery a
        // naive "the file says so" reader would accept.
        let mut lines = read_lines(&path);
        let doctored = Entry {
            payload: Value::object([("amount", Value::Int(1_000_000))]),
            ..original
        };
        lines[0] = doctored.to_json_line();
        write_lines(&path, &lines);

        let problems = Ledger::open(&path).expect("reopen").verify_chain();
        assert!(
            problems.iter().any(|p| p.contains("hash mismatch")),
            "expected a hash mismatch, got {problems:?}"
        );
    }

    #[test]
    fn deleting_an_entry_breaks_the_chain() {
        let dir = TempDir::new("delete");
        let path = dir.file("log.jsonl");
        let mut ledger = Ledger::open(&path).expect("open");
        for i in 0..4 {
            ledger.append("note", note(i), "t").expect("append");
        }

        let mut lines = read_lines(&path);
        lines.remove(1);
        write_lines(&path, &lines);

        let problems = Ledger::open(&path).expect("reopen").verify_chain();
        assert!(
            !problems.is_empty(),
            "removing an entry must not go unnoticed"
        );
        // Every surviving line still hashes correctly; what gives it away is
        // the sequence gap and the broken link.
        assert!(
            problems.iter().any(|p| p.contains("seq is 2")),
            "{problems:?}"
        );
        assert!(
            problems.iter().any(|p| p.contains("expected")),
            "{problems:?}"
        );
        assert!(
            !problems.iter().any(|p| p.contains("hash mismatch")),
            "{problems:?}"
        );
    }

    #[test]
    fn reordering_entries_breaks_the_chain() {
        let dir = TempDir::new("reorder");
        let path = dir.file("log.jsonl");
        let mut ledger = Ledger::open(&path).expect("open");
        for i in 0..3 {
            ledger.append("note", note(i), "t").expect("append");
        }
        let mut lines = read_lines(&path);
        lines.swap(0, 1);
        write_lines(&path, &lines);

        let problems = Ledger::open(&path).expect("reopen").verify_chain();
        assert!(!problems.is_empty(), "{problems:?}");
    }

    #[test]
    fn malformed_line_is_an_error() {
        let dir = TempDir::new("malformed");
        let path = dir.file("log.jsonl");
        fs::write(&path, "{not json}\n").expect("write");
        match Ledger::open(&path) {
            Err(LedgerError::Malformed { location, reason }) => {
                assert!(location.ends_with(":1"), "{location}");
                assert!(reason.contains("malformed JSON"), "{reason}");
            }
            other => panic!("expected a malformed-line error, got {other:?}"),
        }
    }

    #[test]
    fn line_numbers_count_blank_lines() {
        let dir = TempDir::new("lineno");
        let path = dir.file("log.jsonl");
        fs::write(&path, "\n\n{oops}\n").expect("write");
        match Ledger::open(&path) {
            Err(LedgerError::Malformed { location, .. }) => {
                assert!(location.ends_with(":3"), "{location}");
            }
            other => panic!("expected a malformed-line error, got {other:?}"),
        }
    }

    #[test]
    fn blank_lines_are_skipped() {
        let dir = TempDir::new("blank");
        let path = dir.file("log.jsonl");
        let mut text = String::from("\n");
        text.push_str(PYTHON_WRITTEN_LOG);
        text.push_str("\n   \n");
        fs::write(&path, text).expect("write");

        let ledger = Ledger::open(&path).expect("open");
        assert_eq!(ledger.len(), 2);
        assert_eq!(ledger.verify_chain(), Vec::<String>::new());
    }

    #[test]
    fn a_missing_field_is_an_error_not_a_default() {
        let dir = TempDir::new("field");
        let path = dir.file("log.jsonl");
        // A record with no `hash` would otherwise verify against whatever we
        // defaulted to, which is the difference between an audit and a ritual.
        fs::write(
            &path,
            "{\"seq\":0,\"prev\":null,\"kind\":\"note\",\"payload\":{},\"ts\":\"t\"}\n",
        )
        .expect("write");
        match Ledger::open(&path) {
            Err(LedgerError::Malformed { reason, .. }) => {
                assert!(reason.contains("hash"), "{reason}")
            }
            other => panic!("expected a malformed-field error, got {other:?}"),
        }
    }

    #[test]
    fn a_negative_seq_is_refused_rather_than_wrapping() {
        // In Python this loads as -1 and shows up as a `verify_chain` problem.
        // In Rust the field is `u64`, so the only two honest options are "refuse"
        // and "wrap"; wrapping would turn -1 into 18446744073709551615 and hash
        // it as such, so we refuse.
        let dir = TempDir::new("negseq");
        let path = dir.file("log.jsonl");
        fs::write(
            &path,
            "{\"seq\":-1,\"prev\":null,\"kind\":\"n\",\"payload\":{},\"ts\":\"t\",\"hash\":\"sha256:x\"}\n",
        )
        .expect("write");
        match Ledger::open(&path) {
            Err(LedgerError::Malformed { reason, .. }) => {
                assert!(reason.contains("seq"), "{reason}")
            }
            other => panic!("expected a malformed-seq error, got {other:?}"),
        }
    }

    #[test]
    fn an_oversized_seq_is_refused_rather_than_truncating() {
        let dir = TempDir::new("bigseq");
        let path = dir.file("log.jsonl");
        // 2^64 -- one past the top of `u64`, and comfortably inside i128 so the
        // canonical parser hands it over intact for us to reject.
        fs::write(
            &path,
            "{\"seq\":18446744073709551616,\"prev\":null,\"kind\":\"n\",\"payload\":{},\"ts\":\"t\",\"hash\":\"sha256:x\"}\n",
        )
        .expect("write");
        match Ledger::open(&path) {
            Err(LedgerError::Malformed { reason, .. }) => {
                assert!(reason.contains("seq"), "{reason}")
            }
            other => panic!("expected a malformed-seq error, got {other:?}"),
        }
    }

    #[test]
    fn a_maximal_seq_still_hashes_without_overflow() {
        // `seq` widens to i128 for hashing, so the top of the u64 range is not
        // a special case.
        let entry = Entry {
            seq: u64::MAX,
            prev: None,
            kind: String::from("note"),
            payload: note(0),
            ts: String::from("t"),
            hash: String::new(),
        };
        assert_eq!(
            entry.body().get("seq"),
            Some(&Value::Int(i128::from(u64::MAX)))
        );
        assert!(entry.recompute_hash().starts_with("sha256:"));
    }

    #[test]
    fn seq_that_exceeds_usize_is_reported_not_compared_lossily() {
        // `verify_chain` compares `seq` against the index by widening the index,
        // never by narrowing `seq` -- a narrowing cast could make a forged
        // 2^32-style sequence number compare equal on a 32-bit target.
        let entry = Entry {
            seq: u64::MAX,
            prev: None,
            kind: String::from("note"),
            payload: note(0),
            ts: String::from("t"),
            hash: String::new(),
        };
        let hash = entry.recompute_hash();
        let ledger = Ledger {
            path: PathBuf::from("unused"),
            entries: vec![Entry { hash, ..entry }],
        };
        let problems = ledger.verify_chain();
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(
            problems[0].contains("seq is 18446744073709551615"),
            "{problems:?}"
        );
    }

    #[test]
    fn a_stored_float_is_refused_rather_than_silently_reinterpreted() {
        // Nothing in this crate can write one, but a hand-edited or foreign log
        // can contain one, and it must not be loaded and re-hashed as something
        // else.
        let dir = TempDir::new("float");
        let path = dir.file("log.jsonl");
        fs::write(
            &path,
            "{\"seq\":0,\"prev\":null,\"kind\":\"n\",\"payload\":{\"score\":0.5},\"ts\":\"t\",\"hash\":\"sha256:x\"}\n",
        )
        .expect("write");
        match Ledger::open(&path) {
            Err(LedgerError::Canonical { source, .. }) => {
                assert!(matches!(source, CanonicalError::Float(_)), "{source:?}");
            }
            other => panic!("expected a canonical error, got {other:?}"),
        }
    }

    #[test]
    fn a_stored_bignum_payload_is_refused_rather_than_degrading_to_a_float() {
        let dir = TempDir::new("bignum");
        let path = dir.file("log.jsonl");
        let huge = "1".repeat(60);
        fs::write(
            &path,
            format!(
                "{{\"seq\":0,\"prev\":null,\"kind\":\"n\",\"payload\":{{\"n\":{huge}}},\"ts\":\"t\",\"hash\":\"sha256:x\"}}\n"
            ),
        )
        .expect("write");
        match Ledger::open(&path) {
            Err(LedgerError::Canonical { source, .. }) => {
                assert!(
                    matches!(source, CanonicalError::IntegerOutOfRange(_)),
                    "{source:?}"
                );
            }
            other => panic!("expected a canonical error, got {other:?}"),
        }
    }

    #[test]
    fn a_failed_append_changes_nothing() {
        let dir = TempDir::new("failed");
        // A regular file where the log's parent directory should be, so
        // `create_dir_all` fails and the write never happens.
        let blocker = dir.file("blocker");
        fs::write(&blocker, "not a directory").expect("write");
        let path = blocker.join("log.jsonl");

        let mut ledger = Ledger::open(&path).expect("open");
        assert!(ledger.append("note", note(0), "t").is_err());
        assert_eq!(ledger.len(), 0);
        assert_eq!(ledger.head(), None);
        assert!(!path.exists());
    }

    #[test]
    fn append_creates_missing_parent_directories() {
        let dir = TempDir::new("mkdir");
        let path = dir.file("nested").join("deeper").join("log.jsonl");
        let mut ledger = Ledger::open(&path).expect("open");
        ledger.append("note", note(0), "t").expect("append");
        assert!(path.exists());
        assert_eq!(Ledger::open(&path).expect("reopen").len(), 1);
    }

    #[test]
    fn appending_to_a_bare_filename_does_not_try_to_create_an_empty_directory() {
        // `Path::parent` of "log.jsonl" is the empty path; treating that as a
        // directory to create would fail on every relative log path, which is
        // why `append` skips `create_dir_all` for it.
        let parent = Path::new("log.jsonl").parent();
        assert_eq!(parent, Some(Path::new("")));
        assert_eq!(parent.map(|p| p.as_os_str().is_empty()), Some(true));
    }

    #[test]
    fn entries_of_kind_filters_in_log_order() {
        let dir = TempDir::new("kinds");
        let mut ledger = Ledger::open(dir.file("log.jsonl")).expect("open");
        ledger.append("claim", note(0), "t").expect("append");
        ledger.append("verdict", note(1), "t").expect("append");
        ledger.append("claim", note(2), "t").expect("append");

        let claims = ledger.entries_of_kind("claim");
        assert_eq!(claims.len(), 2);
        assert_eq!(claims.first().map(|e| e.seq), Some(0));
        assert_eq!(claims.get(1).map(|e| e.seq), Some(2));
        assert!(ledger.entries_of_kind("settlement").is_empty());
        assert_eq!(ledger.entries().len(), 3);
        assert_eq!((&ledger).into_iter().count(), 3);
    }

    #[test]
    fn merkle_root_changes_with_every_append() {
        let dir = TempDir::new("roots");
        let mut ledger = Ledger::open(dir.file("log.jsonl")).expect("open");
        let mut roots: Vec<String> = Vec::new();
        for i in 0..6 {
            ledger.append("note", note(i), "t").expect("append");
            let root = ledger.root().expect("non-empty log has a root");
            assert!(
                !roots.contains(&root),
                "root repeated after {} appends",
                i + 1
            );
            roots.push(root);
        }
        assert_eq!(roots.len(), 6);
    }

    #[test]
    fn invalid_utf8_is_reported_as_a_data_problem() {
        let dir = TempDir::new("utf8");
        let path = dir.file("log.jsonl");
        fs::write(&path, [0xff, 0xfe, b'\n']).expect("write");
        match Ledger::open(&path) {
            Err(LedgerError::Malformed { reason, .. }) => {
                assert!(reason.contains("UTF-8"), "{reason}")
            }
            other => panic!("expected a UTF-8 error, got {other:?}"),
        }
    }

    #[test]
    fn errors_display_with_their_location() {
        let err = LedgerError::Malformed {
            location: String::from("/tmp/log.jsonl:7"),
            reason: String::from("malformed JSON: trailing comma"),
        };
        assert_eq!(
            err.to_string(),
            "/tmp/log.jsonl:7: malformed JSON: trailing comma"
        );
    }
}
