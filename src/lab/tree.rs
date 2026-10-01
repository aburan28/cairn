//! A working copy: the space's files on disk, for tools that read files.
//!
//! The research program's tooling — validators, dispatchers, the run harness —
//! reads and writes ordinary files, and should not have to know the lab
//! exists. So the lab checks files out into a directory, the tools do what they
//! always did, and `commit` turns what changed into signed ops.
//!
//! # Commit supersedes what you saw, not what is there now
//!
//! The index (`.cairn-lab-checkout.json`) remembers, per path, which register
//! values were current when the file was checked out. Editing a mutable file
//! and committing writes an entry whose `pred` is exactly those values. If
//! somebody else changed the file in the meantime and their change arrived
//! after the checkout, it is *not* in `pred` — so the two become siblings and
//! `cairn lab conflicts` shows them. Taking `pred` from the space at commit
//! time instead would silently overwrite a change the committer never saw,
//! which is the failure this whole design exists to remove.
//!
//! Checking out a conflicted file and committing an edit to it supersedes every
//! value the checkout showed — the main file and each `.lab-conflict-` sidecar
//! — which is how a conflict is resolved: by somebody who saw all sides.
//!
//! # Write-once paths are refused before anything is signed
//!
//! Editing or deleting a write-once file is refused locally with the reason
//! (add a correction instead). The space would exclude such an entry anyway;
//! refusing here means the mistake never becomes a signed op on anybody's disk.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use super::op::{self, Body, EntryRef, FileEntry, PathMode, MAX_ENTRIES};
use super::state::State;
use super::store::Lab;
use super::LabError;
use crate::canonical::Value;
use crate::crypto::identity::Identity;

/// The index file at the top of a working copy.
pub const INDEX_FILE: &str = ".cairn-lab-checkout.json";

/// Marker in the name of a conflict sidecar.
pub const CONFLICT_MARK: &str = ".lab-conflict-";

/// Paths never committed, whatever the filter says: version-control and lab
/// metadata, and the checkout's own sidecars.
const ALWAYS_EXCLUDED: &[&str] = &[
    ".git/**",
    ".cairn-lab/**",
    INDEX_FILE,
    "**/*.lab-conflict-*",
];

/// Soft cap on the encoded size of one commit op, under [`op::MAX_OP_BYTES`].
const OP_BYTES: usize = 6 * 1024 * 1024;

/// Which paths an operation covers.
#[derive(Debug, Clone, Default)]
pub struct Filter {
    /// Globs a path must match one of. Empty means every path.
    pub include: Vec<String>,
    /// Globs that exclude a path even if included.
    pub exclude: Vec<String>,
}

impl Filter {
    pub fn admits(&self, path: &str) -> bool {
        if ALWAYS_EXCLUDED
            .iter()
            .any(|glob| super::glob::matches(glob, path))
        {
            return false;
        }
        let included = self.include.is_empty()
            || self
                .include
                .iter()
                .any(|glob| super::glob::matches(glob, path) || super::state::under(path, glob));
        included
            && !self
                .exclude
                .iter()
                .any(|glob| super::glob::matches(glob, path) || super::state::under(path, glob))
    }
}

/// What the index remembers about one checked-out path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexEntry {
    pub blob: String,
    /// The register values current when this path was last checked out or
    /// committed. What a commit of an edit supersedes.
    pub seen: Vec<EntryRef>,
    pub size: u64,
    /// Nanoseconds since the epoch, for the stat fast path. A hint, never
    /// evidence: a mismatch only means "hash it".
    pub mtime: i128,
}

/// The working copy's index.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Index {
    pub space: String,
    pub entries: BTreeMap<String, IndexEntry>,
}

impl Index {
    pub fn load(dir: &Path) -> Result<Index, LabError> {
        let path = dir.join(INDEX_FILE);
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Index::default()),
            Err(e) => return Err(LabError::Io(format!("{}: {e}", path.display()))),
        };
        let value = Value::from_json(&text)
            .map_err(|e| LabError::Corrupt(format!("{}: {e}", path.display())))?;
        let space = value
            .get("space")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let mut entries = BTreeMap::new();
        if let Some(Value::Object(map)) = value.get("entries") {
            for (path, entry) in map {
                let blob = entry
                    .get("blob")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let seen = entry
                    .get("seen")
                    .and_then(Value::as_array)
                    .unwrap_or(&[])
                    .iter()
                    .filter_map(|r| r.as_str().and_then(|s| EntryRef::parse(s).ok()))
                    .collect();
                entries.insert(
                    path.clone(),
                    IndexEntry {
                        blob,
                        seen,
                        size: entry.get("size").and_then(Value::as_u64).unwrap_or(0),
                        mtime: entry.get("mtime").and_then(Value::as_i128).unwrap_or(0),
                    },
                );
            }
        }
        Ok(Index { space, entries })
    }

    pub fn save(&self, dir: &Path) -> Result<(), LabError> {
        let entries = self
            .entries
            .iter()
            .map(|(path, entry)| {
                (
                    path.clone(),
                    Value::object([
                        ("blob", Value::string(&entry.blob)),
                        (
                            "seen",
                            Value::array(entry.seen.iter().map(|r| Value::string(r.to_string()))),
                        ),
                        ("size", Value::Int(i128::from(entry.size))),
                        ("mtime", Value::Int(entry.mtime)),
                    ]),
                )
            })
            .collect();
        let value = Value::object([
            ("space", Value::string(&self.space)),
            ("entries", Value::Object(entries)),
        ]);
        let path = dir.join(INDEX_FILE);
        let tmp = dir.join(format!("{INDEX_FILE}.tmp"));
        fs::write(&tmp, value.canonical_string())?;
        fs::rename(&tmp, &path)?;
        Ok(())
    }

    fn check_space(&mut self, lab: &Lab) -> Result<(), LabError> {
        if self.space.is_empty() {
            self.space = lab.space().to_string();
            return Ok(());
        }
        if self.space != lab.space() {
            return Err(LabError::Refused(format!(
                "this working copy belongs to space {}, not {}",
                self.space,
                lab.space()
            )));
        }
        Ok(())
    }
}

/// What differs between a working copy and its index.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Changes {
    /// Path, blob address, size, executable.
    pub added: Vec<(String, String, u64, bool)>,
    pub modified: Vec<(String, String, u64, bool)>,
    pub deleted: Vec<String>,
    /// Files whose bytes already match the space but were not in the index:
    /// adopted rather than re-committed.
    pub adopted: Vec<(String, String, u64)>,
    pub unchanged: usize,
    /// Paths that cannot be stored (see [`op::normalize_path`]) or are not
    /// regular files.
    pub skipped: Vec<(String, String)>,
}

impl Changes {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.modified.is_empty() && self.deleted.is_empty()
    }
}

/// Compare a working copy with its index, hashing only what the stat fast path
/// cannot rule out. Blobs for changed files are stored as a side effect, so a
/// commit that follows does not read them twice.
pub fn status(lab: &Lab, state: &State, dir: &Path, filter: &Filter) -> Result<Changes, LabError> {
    let index = Index::load(dir)?;
    let mut changes = Changes::default();
    let mut on_disk = BTreeSet::new();
    let lab_root = fs::canonicalize(lab.root()).ok();
    scan(
        dir,
        dir,
        lab_root.as_deref(),
        &mut |relative, path, meta| {
            if !filter.admits(relative) {
                return Ok(());
            }
            if state.policy.mode(relative) == PathMode::Ignored {
                return Ok(());
            }
            if !meta.file_type().is_file() {
                changes
                    .skipped
                    .push((relative.to_string(), "not a regular file".into()));
                return Ok(());
            }
            let path_ok = match op::normalize_path(relative) {
                Ok(p) => p,
                Err(e) => {
                    changes.skipped.push((relative.to_string(), e.0));
                    return Ok(());
                }
            };
            on_disk.insert(path_ok.clone());
            let size = meta.len();
            let mtime = mtime_ns(meta);
            let exec = is_executable(meta);
            if let Some(entry) = index.entries.get(&path_ok) {
                if entry.size == size && entry.mtime == mtime {
                    changes.unchanged += 1;
                    return Ok(());
                }
                let (blob, _) = lab.blobs().put_file(path)?;
                if blob == entry.blob {
                    changes.unchanged += 1;
                } else {
                    changes.modified.push((path_ok, blob, size, exec));
                }
                return Ok(());
            }
            let (blob, _) = lab.blobs().put_file(path)?;
            let matches_space = state.files.get(&path_ok).is_some_and(|values| {
                values
                    .iter()
                    .any(|v| v.blob.as_deref() == Some(blob.as_str()))
            });
            if matches_space {
                changes.adopted.push((path_ok, blob, size));
            } else {
                changes.added.push((path_ok, blob, size, exec));
            }
            Ok(())
        },
    )?;
    for path in index.entries.keys() {
        if filter.admits(path) && !on_disk.contains(path) {
            changes.deleted.push(path.clone());
        }
    }
    Ok(changes)
}

/// What a commit wrote.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommitReport {
    pub ops: Vec<String>,
    pub written: usize,
    pub deleted: usize,
    pub adopted: usize,
    /// Changes refused before signing, with the reason.
    pub refused: Vec<(String, String)>,
}

/// Turn a working copy's changes into signed ops.
pub fn commit(
    lab: &mut Lab,
    identity: &Identity,
    dir: &Path,
    filter: &Filter,
) -> Result<CommitReport, LabError> {
    lab.refresh()?;
    let state = State::of(lab);
    let mut index = Index::load(dir)?;
    index.check_space(lab)?;
    let changes = status(lab, &state, dir, filter)?;
    let mut report = CommitReport::default();

    let mut entries: Vec<FileEntry> = Vec::new();
    for (path, blob, size, exec) in &changes.added {
        // A path the space already holds but this working copy never checked
        // out. Committing over it blind would supersede what nobody here saw,
        // so it is written with an empty `pred`: if the bytes differ, the two
        // become a visible conflict instead of a silent overwrite.
        let mode = state.policy.mode(path);
        let exists = state
            .files
            .get(path)
            .is_some_and(|values| !values.is_empty());
        if exists && mode == PathMode::WriteOnce {
            report.refused.push((
                path.clone(),
                "write-once path already exists in the space with different content".into(),
            ));
            continue;
        }
        entries.push(FileEntry {
            path: path.clone(),
            blob: Some(blob.clone()),
            size: *size,
            exec: *exec,
            pred: Vec::new(),
        });
    }
    for (path, blob, size, exec) in &changes.modified {
        if state.policy.mode(path) == PathMode::WriteOnce {
            report.refused.push((
                path.clone(),
                "write-once: an immutable record is never edited; add a correction instead".into(),
            ));
            continue;
        }
        let seen = index
            .entries
            .get(path)
            .map(|entry| entry.seen.clone())
            .unwrap_or_default();
        entries.push(FileEntry {
            path: path.clone(),
            blob: Some(blob.clone()),
            size: *size,
            exec: *exec,
            pred: seen,
        });
    }
    for path in &changes.deleted {
        if state.policy.mode(path) == PathMode::WriteOnce {
            report.refused.push((
                path.clone(),
                "write-once: an immutable record is never deleted".into(),
            ));
            continue;
        }
        let seen = index
            .entries
            .get(path)
            .map(|entry| entry.seen.clone())
            .unwrap_or_default();
        entries.push(FileEntry {
            path: path.clone(),
            blob: None,
            size: 0,
            exec: false,
            pred: seen,
        });
    }

    // Batch under both the entry and the byte ceiling.
    let mut batches: Vec<Vec<FileEntry>> = Vec::new();
    let mut current: Vec<FileEntry> = Vec::new();
    let mut bytes = 0usize;
    for entry in entries {
        let size = entry.to_value().canonical_bytes().len() + 1;
        if !current.is_empty() && (current.len() >= MAX_ENTRIES || bytes + size > OP_BYTES) {
            batches.push(std::mem::take(&mut current));
            bytes = 0;
        }
        bytes += size;
        current.push(entry);
    }
    if !current.is_empty() {
        batches.push(current);
    }

    for batch in batches {
        let op = lab.append(
            identity,
            Body::Files {
                entries: batch.clone(),
            },
        )?;
        for (n, entry) in batch.iter().enumerate() {
            let reference = EntryRef {
                op: op.id.clone(),
                index: n as u32,
            };
            match &entry.blob {
                Some(blob) => {
                    let meta = fs::metadata(dir.join(&entry.path))?;
                    index.entries.insert(
                        entry.path.clone(),
                        IndexEntry {
                            blob: blob.clone(),
                            seen: vec![reference],
                            size: entry.size,
                            mtime: mtime_ns(&meta),
                        },
                    );
                    report.written += 1;
                }
                None => {
                    index.entries.remove(&entry.path);
                    report.deleted += 1;
                }
            }
        }
        report.ops.push(op.id.clone());
    }
    for (path, blob, size) in &changes.adopted {
        let seen = state
            .files
            .get(path)
            .map(|values| values.iter().map(|v| v.version.entry.clone()).collect())
            .unwrap_or_default();
        let meta = fs::metadata(dir.join(path))?;
        index.entries.insert(
            path.clone(),
            IndexEntry {
                blob: blob.clone(),
                seen,
                size: *size,
                mtime: mtime_ns(&meta),
            },
        );
        report.adopted += 1;
    }
    index.save(dir)?;
    Ok(report)
}

/// What a checkout did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CheckoutReport {
    pub written: usize,
    pub removed: usize,
    pub unchanged: usize,
    /// Paths with local changes that were left alone.
    pub kept: Vec<String>,
    /// Conflict sidecars written.
    pub conflicts: Vec<PathBuf>,
    /// Paths whose blob this replica does not hold yet.
    pub missing: Vec<String>,
}

/// Bring a working copy up to date with the space.
///
/// Local changes are never overwritten unless `force`: a modified file stays
/// as it is and is reported, and its index entry still names what was seen
/// *before* the edit, so a later commit still supersedes only that.
pub fn checkout(
    lab: &Lab,
    state: &State,
    dir: &Path,
    filter: &Filter,
    force: bool,
) -> Result<CheckoutReport, LabError> {
    fs::create_dir_all(dir)?;
    let mut index = Index::load(dir)?;
    index.check_space(lab)?;
    let mut report = CheckoutReport::default();
    let changes = status(lab, state, dir, filter)?;
    let locally_changed: BTreeSet<&str> = changes
        .modified
        .iter()
        .map(|(p, ..)| p.as_str())
        .chain(changes.added.iter().map(|(p, ..)| p.as_str()))
        .chain(changes.deleted.iter().map(String::as_str))
        .collect();

    for (path, values) in &state.files {
        if !filter.admits(path) {
            continue;
        }
        let target = dir.join(path);
        let winner = &values[0];
        let seen: Vec<EntryRef> = values.iter().map(|v| v.version.entry.clone()).collect();
        if locally_changed.contains(path.as_str()) && !force {
            report.kept.push(path.clone());
            continue;
        }
        match &winner.blob {
            None => {
                if target.is_file() {
                    fs::remove_file(&target)?;
                    report.removed += 1;
                }
                index.entries.remove(path);
            }
            Some(blob) => {
                let current = index.entries.get(path);
                let up_to_date =
                    current.is_some_and(|entry| entry.blob == *blob) && target.is_file();
                if up_to_date {
                    report.unchanged += 1;
                } else if !lab.blobs().has(blob) {
                    report.missing.push(path.clone());
                    continue;
                } else {
                    lab.blobs().copy_to(blob, &target)?;
                    set_executable(&target, winner.exec)?;
                    report.written += 1;
                }
                let meta = fs::metadata(&target)?;
                index.entries.insert(
                    path.clone(),
                    IndexEntry {
                        blob: blob.clone(),
                        seen: seen.clone(),
                        size: meta.len(),
                        mtime: mtime_ns(&meta),
                    },
                );
            }
        }
        // Sidecars for every other distinct value, so all sides are on disk.
        let mut written_blobs: BTreeSet<&str> = winner.blob.as_deref().into_iter().collect();
        for value in &values[1..] {
            let Some(blob) = &value.blob else { continue };
            if !written_blobs.insert(blob.as_str()) || !lab.blobs().has(blob) {
                continue;
            }
            let short = value
                .version
                .entry
                .op
                .trim_start_matches(crate::canonical::DIGEST_PREFIX)
                .chars()
                .take(12)
                .collect::<String>();
            let sidecar = dir.join(format!("{path}{CONFLICT_MARK}{short}"));
            lab.blobs().copy_to(blob, &sidecar)?;
            report.conflicts.push(sidecar);
        }
    }

    // Paths the index holds that the space no longer has at all.
    let gone: Vec<String> = index
        .entries
        .keys()
        .filter(|path| filter.admits(path) && !state.files.contains_key(*path))
        .cloned()
        .collect();
    for path in gone {
        if locally_changed.contains(path.as_str()) && !force {
            report.kept.push(path);
            continue;
        }
        let target = dir.join(&path);
        if target.is_file() {
            fs::remove_file(&target)?;
            report.removed += 1;
        }
        index.entries.remove(&path);
    }
    index.save(dir)?;
    Ok(report)
}

/// Walk regular files and symlinks under `dir`, skipping the lab directory
/// itself if it lives inside the working copy.
fn scan(
    root: &Path,
    dir: &Path,
    lab_root: Option<&Path>,
    visit: &mut dyn FnMut(&str, &Path, &fs::Metadata) -> Result<(), LabError>,
) -> Result<(), LabError> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => return Err(LabError::Io(format!("{}: {e}", dir.display()))),
    };
    let mut entries: Vec<_> = entries.filter_map(Result::ok).collect();
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        if lab_root.is_some_and(|lab| fs::canonicalize(&path).ok().as_deref() == Some(lab)) {
            continue;
        }
        let meta = fs::symlink_metadata(&path)
            .map_err(|e| LabError::Io(format!("{}: {e}", path.display())))?;
        let relative = path
            .strip_prefix(root)
            .map_err(|_| LabError::Io("walked outside the working copy".into()))?
            .to_string_lossy()
            .replace(std::path::MAIN_SEPARATOR, "/");
        if meta.file_type().is_dir() {
            // Prune whole directories the always-excluded globs name, so a
            // working copy inside a git checkout never walks `.git`.
            if relative == ".git" || relative == ".cairn-lab" {
                continue;
            }
            scan(root, &path, lab_root, visit)?;
        } else {
            visit(&relative, &path, &meta)?;
        }
    }
    Ok(())
}

fn mtime_ns(meta: &fs::Metadata) -> i128 {
    meta.modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|elapsed| elapsed.as_nanos() as i128)
        .unwrap_or(0)
}

#[cfg(unix)]
fn is_executable(meta: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    meta.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_meta: &fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn set_executable(path: &Path, exec: bool) -> Result<(), LabError> {
    use std::os::unix::fs::PermissionsExt as _;
    let mut permissions = fs::metadata(path)?.permissions();
    let mode = permissions.mode();
    permissions.set_mode(if exec { mode | 0o755 } else { mode & !0o111 });
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_executable(_path: &Path, _exec: bool) -> Result<(), LabError> {
    Ok(())
}
