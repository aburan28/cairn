//! Append-only hash-linked log.
//!
//! JSONL, one entry per line, each carrying the hash of its predecessor.
//! Tampering with entry *n* invalidates every hash from *n* onward, which is
//! what makes "anyone can check" mechanical rather than a promise.

use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::canonical::{merkle_proof, short, Inclusion, Value};

/// The first entry's `prev` is JSON **null**, not an empty string.
///
/// Absent and null and "" are three different byte strings in a
/// content-addressed format, so this is not a stylistic choice -- picking the
/// wrong one changes the genesis entry's hash and therefore every subsequent
/// `prev`, while the stored Merkle root still matches because the stored
/// hashes were never recomputed. The log looks fine until somebody audits it.
pub fn genesis_prev() -> Value {
    Value::Null
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub seq: u64,
    pub prev: Option<String>,
    pub kind: String,
    pub payload: Value,
    pub ts: String,
    pub hash: String,
}

impl Entry {
    fn body(seq: u64, prev: &Option<String>, kind: &str, payload: &Value, ts: &str) -> Value {
        Value::object([
            ("seq", Value::Int(i128::from(seq))),
            (
                "prev",
                match prev {
                    Some(prev) => Value::string(prev.clone()),
                    None => genesis_prev(),
                },
            ),
            ("kind", Value::string(kind)),
            ("payload", payload.clone()),
            ("ts", Value::string(ts)),
        ])
    }

    /// The hash this entry *should* have, given its contents. `audit` compares
    /// it against the stored one; a mismatch is a rewritten entry.
    pub fn recompute_hash(&self) -> String {
        Entry::body(self.seq, &self.prev, &self.kind, &self.payload, &self.ts).digest()
    }

    pub fn to_value(&self) -> Value {
        let mut value = Entry::body(self.seq, &self.prev, &self.kind, &self.payload, &self.ts);
        if let Value::Object(map) = &mut value {
            map.insert("hash".into(), Value::string(self.hash.clone()));
        }
        value
    }

    fn from_value(value: &Value) -> Result<Entry, String> {
        let text = |name: &str| -> Result<String, String> {
            value
                .get(name)
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| format!("entry field {name:?} must be a string"))
        };
        Ok(Entry {
            seq: value
                .get("seq")
                .and_then(Value::as_u64)
                .ok_or("entry needs an integer seq")?,
            // `prev` is a string for every entry including genesis, where it
            // is empty. A null would be a different byte string.
            prev: match value.get("prev") {
                Some(Value::String(prev)) => Some(prev.clone()),
                Some(Value::Null) | None => None,
                Some(_) => return Err("entry prev must be a string or null".into()),
            },
            kind: text("kind")?,
            payload: value
                .get("payload")
                .cloned()
                .ok_or("entry needs a payload")?,
            ts: text("ts")?,
            hash: text("hash")?,
        })
    }
}

pub struct Ledger {
    path: PathBuf,
    entries: Vec<Entry>,
}

impl Ledger {
    pub fn open(path: impl Into<PathBuf>) -> Result<Ledger, String> {
        let path = path.into();
        let mut entries = Vec::new();
        if path.exists() {
            let text = std::fs::read_to_string(&path)
                .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
            for (index, line) in text.lines().enumerate() {
                if line.trim().is_empty() {
                    continue;
                }
                let value = Value::from_json(line)
                    .map_err(|error| format!("line {}: {error}", index + 1))?;
                entries.push(
                    Entry::from_value(&value)
                        .map_err(|error| format!("line {}: {error}", index + 1))?,
                );
            }
        }
        Ok(Ledger { path, entries })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn head(&self) -> Option<&str> {
        self.entries.last().map(|entry| entry.hash.as_str())
    }

    pub fn entries_of_kind(&self, kind: &str) -> Vec<&Entry> {
        self.entries.iter().filter(|e| e.kind == kind).collect()
    }

    pub fn append(&mut self, kind: &str, payload: Value, ts: &str) -> Result<Entry, String> {
        let prev = self.head().map(str::to_string);
        let seq = self.entries.len() as u64;
        let hash = Entry::body(seq, &prev, kind, &payload, ts).digest();
        let entry = Entry {
            seq,
            prev,
            kind: kind.to_string(),
            payload,
            ts: ts.to_string(),
            hash,
        };
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
        }
        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(&self.path)
            .map_err(|error| format!("cannot append to {}: {error}", self.path.display()))?;
        writeln!(file, "{}", entry.to_value().canonical_string()).map_err(|e| e.to_string())?;
        self.entries.push(entry.clone());
        Ok(entry)
    }

    /// Every way the chain can be broken, named.
    pub fn verify_chain(&self) -> Vec<String> {
        let mut problems = Vec::new();
        let mut expected_prev: Option<String> = None;
        for (index, entry) in self.entries.iter().enumerate() {
            if entry.seq != index as u64 {
                problems.push(format!("entry {index}: seq is {}", entry.seq));
            }
            if entry.prev != expected_prev {
                let render = |value: &Option<String>| match value {
                    Some(hash) => short(hash),
                    None => "none".to_string(),
                };
                problems.push(format!(
                    "entry {index}: prev is {}, expected {}",
                    render(&entry.prev),
                    render(&expected_prev)
                ));
            }
            let recomputed = entry.recompute_hash();
            if recomputed != entry.hash {
                problems.push(format!(
                    "entry {index}: hash is {}, recomputes to {}",
                    short(&entry.hash),
                    short(&recomputed)
                ));
            }
            expected_prev = Some(entry.hash.clone());
        }
        problems
    }

    pub fn merkle_root(&self) -> Option<String> {
        crate::canonical::merkle_root(&self.leaf_hashes())
    }

    /// The Merkle root over the first `height` entries, or `None` when the log
    /// is shorter than that.
    ///
    /// Shorter is `None` rather than "the root of what there is": a promise
    /// about a taller log than this one is a promise this copy cannot check,
    /// and answering it with the root of a prefix would silently agree to the
    /// wrong question.
    pub fn root_at(&self, height: usize) -> Option<String> {
        if self.entries.len() < height {
            return None;
        }
        let leaves: Vec<String> = self
            .entries
            .iter()
            .take(height)
            .map(|e| e.hash.clone())
            .collect();
        crate::canonical::merkle_root(&leaves)
    }

    fn leaf_hashes(&self) -> Vec<String> {
        self.entries.iter().map(|e| e.hash.clone()).collect()
    }

    /// The proof that entry `seq` is under [`Ledger::merkle_root`], with the
    /// entry itself so the reader can check the leaf rather than be told it.
    pub fn prove(&self, seq: u64) -> Option<Proof> {
        let index = usize::try_from(seq).ok()?;
        Some(Proof {
            entry: self.entries.get(index)?.clone(),
            inclusion: merkle_proof(&self.leaf_hashes(), index)?,
        })
    }
}

/// One entry, plus the path that puts it under a Merkle root.
///
/// A reader with a signed checkpoint and one of these can settle "is this
/// entry in the log" in `log2(n)` hashes without holding the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    pub entry: Entry,
    pub inclusion: Inclusion,
}

impl Proof {
    /// Check against a root. `Err` carries which of the three checks failed --
    /// an edited entry, a path for the wrong slot, and a path that does not
    /// reach the root accuse different people.
    pub fn check(&self, root: &str) -> Result<(), String> {
        let recomputed = self.entry.recompute_hash();
        if recomputed != self.entry.hash {
            return Err(format!(
                "the entry does not hash to the digest it carries \
                 (says {}, hashes to {})",
                self.entry.hash, recomputed
            ));
        }
        if u64::try_from(self.inclusion.index).ok() != Some(self.entry.seq) {
            return Err(format!(
                "the path is for leaf {} but the entry's seq is {}",
                self.inclusion.index, self.entry.seq
            ));
        }
        if !self.inclusion.verify(&recomputed, root) {
            return Err(format!("the path does not reach root {root}"));
        }
        Ok(())
    }

    /// `{entry, index, leaves, siblings}` -- flat, and byte-identical to what
    /// the primary implementation emits.
    pub fn to_value(&self) -> Value {
        let mut value = self.inclusion.to_value();
        if let Value::Object(map) = &mut value {
            map.insert("entry".into(), self.entry.to_value());
        }
        value
    }

    /// Assemble a proof from an entry value and a derived path shape.
    ///
    /// The index and leaf count are the *caller's*, never the record's: an
    /// availability answer that could name its own index would answer whichever
    /// entry the answerer happened to keep rather than the one it was asked
    /// for.
    pub fn from_parts(
        entry: &Value,
        index: usize,
        leaves: usize,
        siblings: Vec<String>,
    ) -> Option<Proof> {
        Some(Proof {
            entry: Entry::from_value(entry).ok()?,
            inclusion: Inclusion {
                index,
                leaves,
                siblings,
            },
        })
    }

    pub fn from_value(value: &Value) -> Result<Proof, String> {
        Ok(Proof {
            entry: Entry::from_value(value.get("entry").ok_or("a proof needs an entry")?)?,
            inclusion: Inclusion::from_value(value)?,
        })
    }
}
