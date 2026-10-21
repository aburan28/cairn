//! Solver packages between nodes: the store's half of the p2p code exchange.
//!
//! Every Cairn.app user runs their own node, so a package that exists only on
//! the node its author added it to is a package almost no contributor can
//! reach: their node synced the objective over p2p, `GET /solvers` on it says
//! the pin is not here, and Start stays grey. Pinned checkers had the same gap
//! and [`crate::p2p::code`] closed it; packages now ride that exchange. The
//! wire half (want, parts, the turn order) is there; this is what a node
//! wants, what it serves, and what it does with what arrives.
//!
//! # Pins travel, approaches do not
//!
//! A node wants exactly the packages its log's objectives pin, the way it
//! wants exactly the checkers they pin. A pin is inside the objective's id and
//! under its funder's signature: the author chose that program, every node
//! that holds the objective agrees on which bytes it is, and fetching it asks
//! no one to trust anybody new.
//!
//! An *approach* (a package that names an objective in `solver.json`, offered
//! for an objective that pinned none) is deliberately not synced. Which
//! approach a node offers is its operator's decision: `--package auto` runs
//! the newest approach that passed there, so a node that took approaches from
//! peers would let any stranger choose what runs on that node's contributors'
//! machines, for every objective without a pin, by publishing a newer one.
//! Nothing in the log bounds the set either -- anyone may write an approach to
//! anything -- so the only way to learn them would be an inventory, which
//! [`crate::p2p::code`] refuses to send for privacy reasons that apply here
//! unchanged. An operator who wants an approach adds it (`cairn solver add`);
//! an author who wants their solver to travel pins it.
//!
//! # Nothing is offered until it passes here
//!
//! The store's rule holds for a package that came over the wire exactly as
//! for one an operator added: it is filed only if its tests pass on this node,
//! or, when none of its targets runs here, on format and hashes alone (and the
//! report says so). A package arrives into a staging directory beside the
//! store, `.incoming/<id>`, which nothing serves and nothing runs from except
//! the check itself. [`settle`] runs the check outside any p2p session --
//! tests can take minutes, and a session holds the node and a peer -- and
//! then files it ([`Store::add`]), records that it failed (`.failed/<id>`,
//! never fetched again unless an operator deletes the marker), or leaves it
//! staged to try again later when the check could not be decided.
//! `Unavailable` is never a failure: a node with no jail, or without the
//! objective's checker yet, says nothing about the package.
//!
//! # Verified before it is written
//!
//! A manifest is kept only if its bytes hash to a package id this node wants
//! (which also makes them its canonical form, so it is the manifest every
//! node agrees on), and a file only if its bytes hash to the SHA-256 a staged
//! manifest of a wanted package pins, at the size it pins. Both checks run on
//! the whole item in memory before anything reaches a filename. A file is
//! written under a hidden temporary name and renamed into place, so a reader
//! sees it whole or not at all.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use super::check::{Outcome, Report};
use super::manifest::{FileEntry, Manifest};
use super::package::{self, Package};
use super::store::Store;
use super::MANIFEST_FILE;
use crate::blobs;
use crate::canonical::{Value, DIGEST_PREFIX};
use crate::records::Objective;

/// Where packages wait for their check, under the store.
pub const INCOMING_DIR: &str = ".incoming";
/// Where a package that failed here is remembered, under the store.
pub const FAILED_DIR: &str = ".failed";
/// How long a check that could not be decided waits before it is run again.
/// A check runs every test on every target this host can, in the jail; doing
/// that every few seconds for a package that is waiting on a checker blob or
/// a jail would be most of what the node did.
pub const RETRY_SECONDS: u64 = 600;

static TEMPORARY: AtomicU64 = AtomicU64::new(0);

fn id_of(hex: &str) -> String {
    format!("{DIGEST_PREFIX}{hex}")
}

fn hex_of(id: &str) -> Option<&str> {
    id.strip_prefix(DIGEST_PREFIX)
        .filter(|h| blobs::is_address(h))
}

/// The staging area beside a node's store.
#[derive(Debug, Clone)]
pub struct Incoming {
    store: Store,
    dir: PathBuf,
    failed: PathBuf,
}

impl Incoming {
    pub fn under(root: &Path) -> Incoming {
        let store = Store::under(root);
        let dir = store.dir().join(INCOMING_DIR);
        let failed = store.dir().join(FAILED_DIR);
        Incoming { store, dir, failed }
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The manifest staged for `hex`, if one is and it still hashes to it.
    pub fn staged(&self, hex: &str) -> Option<Manifest> {
        let text = fs::read_to_string(self.dir.join(hex).join(MANIFEST_FILE)).ok()?;
        let manifest = Manifest::from_json(&text).ok()?;
        (manifest.id() == id_of(hex)).then_some(manifest)
    }

    /// Why `id` failed on this node, if it did.
    pub fn failure(&self, id: &str) -> Option<String> {
        let hex = hex_of(id)?;
        let text = fs::read_to_string(self.failed.join(format!("{hex}.json"))).ok()?;
        let value = Value::from_json(&text).ok()?;
        Some(
            value
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or("it failed here")
                .to_string(),
        )
    }

    /// Whether this node would take `id` from a peer: it does not hold it,
    /// and it has not seen it fail.
    pub fn needs(&self, id: &str) -> bool {
        hex_of(id).is_some() && self.store.get(id).is_none() && self.failure(id).is_none()
    }

    fn fail(&self, id: &str, reason: &str, report: Option<&Report>) {
        let Some(hex) = hex_of(id) else {
            return;
        };
        let mut fields = vec![
            ("package", Value::string(id)),
            ("reason", Value::string(reason)),
            ("at", Value::string(crate::time::timestamp())),
        ];
        if let Some(report) = report {
            fields.push(("report", report.to_value()));
        }
        let _ = write_new(
            &self.failed.join(format!("{hex}.json")),
            &Value::object(fields).canonical_bytes(),
            false,
        );
    }

    /// Whether `hex` has a staged copy of `path` that matches its pin.
    fn holds_file(&self, hex: &str, path: &str, entry: &FileEntry) -> bool {
        package::verify_file(&self.dir.join(hex), path, entry).is_ok()
    }

    fn tried_marker(&self, hex: &str) -> PathBuf {
        self.dir.join(format!("{hex}.tried"))
    }

    fn tried_recently(&self, hex: &str) -> bool {
        fs::metadata(self.tried_marker(hex))
            .and_then(|m| m.modified())
            .ok()
            .and_then(|at| at.elapsed().ok())
            .is_some_and(|age| age.as_secs() < RETRY_SECONDS)
    }

    fn drop_staged(&self, hex: &str) {
        let _ = fs::remove_dir_all(self.dir.join(hex));
        let _ = fs::remove_file(self.tried_marker(hex));
    }
}

/// What one exchange moved, for a log line and a test.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Transfer {
    /// Manifests and files that matched a want and were staged.
    pub accepted: usize,
    /// Items refused: unsolicited, the wrong bytes, or cut short.
    pub refused: usize,
    /// Items sent to the peer.
    pub served: usize,
    /// Bytes staged, and bytes sent.
    pub bytes_in: u64,
    pub bytes_out: u64,
    /// Packages whose every file is now staged, ready for [`settle`].
    pub complete: BTreeSet<String>,
}

/// One item a node will send: a manifest, or a file of a package it holds.
#[derive(Debug, Clone)]
pub struct Outgoing {
    /// Bare hex SHA-256 of the bytes.
    pub address: String,
    source: Source,
}

#[derive(Debug, Clone)]
enum Source {
    Bytes(Vec<u8>),
    File { path: PathBuf, size: u64 },
}

impl Outgoing {
    /// The bytes, held to their address once more. A store is an ordinary
    /// directory and its files can be edited or rot; the receiver would
    /// refuse the wrong bytes anyway, but a node should not spend a peer's
    /// bandwidth on them.
    pub fn read(&self) -> Option<Vec<u8>> {
        let bytes = match &self.source {
            Source::Bytes(bytes) => bytes.clone(),
            Source::File { path, size } => {
                let mut bytes = Vec::new();
                fs::File::open(path)
                    .ok()?
                    .take(size.saturating_add(1))
                    .read_to_end(&mut bytes)
                    .ok()?;
                if bytes.len() as u64 != *size {
                    return None;
                }
                bytes
            }
        };
        (blobs::address(&bytes) == self.address).then_some(bytes)
    }
}

/// One node's side of one package exchange.
///
/// Built before the session from the pins this node holds, so what it asks
/// for and what it will accept are the same set.
#[derive(Debug, Clone)]
pub struct Exchange {
    incoming: Incoming,
    /// Bare hex ids of the packages a manifest is accepted for.
    pins: BTreeSet<String>,
    /// Manifests on hand for those pins: staged earlier, or this session.
    staged: BTreeMap<String, Manifest>,
    report: Transfer,
}

impl Exchange {
    /// `pins` are package ids (`sha256:…`) the node's objectives pin. Those
    /// it holds or saw fail are dropped here.
    pub fn new(root: &Path, pins: impl IntoIterator<Item = String>) -> Exchange {
        let incoming = Incoming::under(root);
        let mut wanted = BTreeSet::new();
        let mut staged = BTreeMap::new();
        for id in pins {
            if !incoming.needs(&id) {
                continue;
            }
            let Some(hex) = hex_of(&id) else {
                continue;
            };
            if let Some(manifest) = incoming.staged(hex) {
                staged.insert(hex.to_string(), manifest);
            }
            wanted.insert(hex.to_string());
        }
        Exchange {
            incoming,
            pins: wanted,
            staged,
            report: Transfer::default(),
        }
    }

    /// The package ids, bare hex, this node is still waiting for.
    pub fn pins(&self) -> &BTreeSet<String> {
        &self.pins
    }

    /// What to ask a peer for: the manifest of every pin with none staged,
    /// and every file of a staged manifest that is not here yet.
    ///
    /// Recomputed from the disk each session, like the blob want set, so an
    /// interrupted transfer resumes at the first file that did not arrive and
    /// nothing is remembered that could go stale.
    pub fn wants(&self) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for hex in &self.pins {
            match self.staged.get(hex) {
                Some(manifest) => {
                    for (path, entry) in &manifest.files {
                        if !self.incoming.holds_file(hex, path, entry) {
                            out.insert(entry.hex());
                        }
                    }
                }
                None => {
                    out.insert(hex.clone());
                }
            }
        }
        out
    }

    /// What to send for a peer's want: at most `budget` bytes of it, in at
    /// most `parts` parts of `part_bytes`, the ceilings the receiver holds
    /// the stream to.
    ///
    /// Only the store, never the staging area: a package nobody has checked
    /// here is not one this node offers, to a worker or to a peer. A package
    /// id asked for brings its manifest and then its files, in order, so a
    /// receiver that knew only the pin can stage the whole package in one
    /// session when it fits; files that do not fit come next session, asked
    /// for by hash. Anything not held is skipped without a word, for the
    /// reason [`crate::p2p::code::serve`] gives.
    pub fn plan(
        &self,
        asked: &[String],
        budget: u64,
        parts: usize,
        part_bytes: usize,
    ) -> Vec<Outgoing> {
        let part_bytes = part_bytes.max(1) as u64;
        let listed = self.incoming.store.list();
        let mut files: BTreeMap<String, (PathBuf, u64)> = BTreeMap::new();
        for stored in &listed {
            for (path, entry) in &stored.manifest.files {
                files
                    .entry(entry.hex())
                    .or_insert_with(|| (stored.dir.join(path), entry.size));
            }
        }
        let mut out: Vec<Outgoing> = Vec::new();
        let mut queued: BTreeSet<String> = BTreeSet::new();
        let mut spent: u64 = 0;
        let mut counted: usize = 0;
        let mut push = |out: &mut Vec<Outgoing>, address: String, source: Source, size: u64| {
            if queued.contains(&address) {
                return true;
            }
            let cost = usize::try_from(size.div_ceil(part_bytes).max(1)).unwrap_or(usize::MAX);
            if spent.saturating_add(size) > budget || counted.saturating_add(cost) > parts {
                return false;
            }
            spent += size;
            counted += cost;
            queued.insert(address.clone());
            out.push(Outgoing { address, source });
            true
        };
        for hex in asked {
            if !blobs::is_address(hex) {
                continue;
            }
            let id = id_of(hex);
            if let Some(stored) = listed.iter().find(|s| s.id() == id) {
                let bytes = stored.manifest.to_value().canonical_bytes();
                let size = bytes.len() as u64;
                if !push(&mut out, hex.clone(), Source::Bytes(bytes), size) {
                    continue;
                }
                for (path, entry) in &stored.manifest.files {
                    let source = Source::File {
                        path: stored.dir.join(path),
                        size: entry.size,
                    };
                    push(&mut out, entry.hex(), source, entry.size);
                }
            } else if let Some((path, size)) = files.get(hex) {
                let source = Source::File {
                    path: path.clone(),
                    size: *size,
                };
                push(&mut out, hex.clone(), source, *size);
            }
        }
        out
    }

    /// Keep one item a peer sent, if it is one this node asked for.
    ///
    /// The address is computed from the bytes here, whatever the peer said
    /// it was, and nothing is written before both the hash and the want
    /// have been checked.
    pub fn admit(&mut self, bytes: &[u8]) -> bool {
        let address = blobs::address(bytes);
        let kept = if self.pins.contains(&address) && !self.staged.contains_key(&address) {
            self.admit_manifest(&address, bytes)
        } else {
            self.admit_file(&address, bytes)
        };
        if kept {
            self.report.accepted += 1;
            self.report.bytes_in += bytes.len() as u64;
        } else {
            self.report.refused += 1;
        }
        kept
    }

    fn admit_manifest(&mut self, hex: &str, bytes: &[u8]) -> bool {
        let id = id_of(hex);
        // These bytes hash to the pin, so they are *the* manifest: nobody can
        // produce other bytes that do. One that does not parse here never
        // will on this build, and fetching it again every round would be a
        // loop; it is filed as failed, with the reason, instead.
        let parsed = std::str::from_utf8(bytes)
            .map_err(|_| "its manifest is not UTF-8".to_string())
            .and_then(|text| Manifest::from_json(text).map_err(|e| e.0));
        let manifest = match parsed {
            Ok(manifest) if manifest.id() == id => manifest,
            Ok(_) => {
                self.incoming
                    .fail(&id, "its manifest is not in canonical form", None);
                return false;
            }
            Err(why) => {
                self.incoming
                    .fail(&id, &format!("its manifest is not valid here: {why}"), None);
                return false;
            }
        };
        let path = self.incoming.dir.join(hex).join(MANIFEST_FILE);
        if write_new(&path, bytes, false).is_err() {
            return false;
        }
        self.staged.insert(hex.to_string(), manifest);
        self.note_complete(hex);
        true
    }

    fn admit_file(&mut self, address: &str, bytes: &[u8]) -> bool {
        let mut kept = false;
        let mut touched = Vec::new();
        for (hex, manifest) in &self.staged {
            for (path, entry) in &manifest.files {
                if entry.hex() != address || entry.size != bytes.len() as u64 {
                    continue;
                }
                if self.incoming.holds_file(hex, path, entry) {
                    kept = true;
                    continue;
                }
                let to = self.incoming.dir.join(hex).join(path);
                // A copy that is here but wrong is replaced rather than
                // trusted; it is what made this file wanted again.
                let _ = fs::remove_file(&to);
                if write_new(&to, bytes, package::executable(manifest, path)).is_ok() {
                    kept = true;
                    touched.push(hex.clone());
                }
            }
        }
        for hex in touched {
            self.note_complete(&hex);
        }
        kept
    }

    fn note_complete(&mut self, hex: &str) {
        let Some(manifest) = self.staged.get(hex) else {
            return;
        };
        if manifest
            .files
            .iter()
            .all(|(path, entry)| self.incoming.holds_file(hex, path, entry))
        {
            self.report.complete.insert(id_of(hex));
        }
    }

    /// Count an item that arrived incomplete or out of turn.
    pub fn refused_one(&mut self) {
        self.report.refused += 1;
    }

    /// Count an item sent.
    pub fn served(&mut self, bytes: u64) {
        self.report.served += 1;
        self.report.bytes_out += bytes;
    }

    pub fn report(&self) -> &Transfer {
        &self.report
    }
}

/// The package ids, bare hex, this node can serve: everything in its store.
/// What the DHT round answers "do you hold it?" from.
pub fn held(root: &Path) -> Vec<String> {
    Store::under(root)
        .list()
        .iter()
        .filter_map(|s| hex_of(&s.id()).map(str::to_string))
        .collect()
}

/// What [`settle`] did with one staged package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Settled {
    /// Checked and filed in the store, so this node now offers it.
    Offered { id: String, verdict: Outcome },
    /// A test failed here, or the package is malformed; never offered, and
    /// not fetched again.
    Failed { id: String, why: String },
    /// Not decided yet: files still to come, or a check that could not run.
    Waiting { id: String, why: String },
    /// Removed: held already, failed already, or pinned by nothing in the log.
    Dropped { id: String },
}

/// Check every staged package that is complete and file the ones that pass.
///
/// `pinned` is the node's log: each package id an objective pins, with that
/// objective, whose verifier scores the package's `verify: "accept"` tests
/// exactly as `cairn solver add --objective` would. A staged package nothing
/// pins is removed; its objective may have been refused when the records it
/// arrived with were applied.
///
/// Slow by nature -- it runs the tests -- so callers run it outside any p2p
/// session and outside the node's lock.
pub fn settle(root: &Path, pinned: &BTreeMap<String, (String, Objective)>) -> Vec<Settled> {
    let incoming = Incoming::under(root);
    let Ok(entries) = fs::read_dir(&incoming.dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|name| blobs::is_address(name))
        .collect();
    names.sort();
    let mut out = Vec::new();
    for hex in names {
        let id = id_of(&hex);
        let pin = pinned.get(&id);
        let manifest = incoming.staged(&hex);
        let (Some((objective_id, objective)), Some(manifest), true) =
            (pin, manifest, incoming.needs(&id))
        else {
            incoming.drop_staged(&hex);
            out.push(Settled::Dropped { id });
            continue;
        };
        let dir = incoming.dir.join(&hex);
        let missing = manifest
            .files
            .iter()
            .filter(|(path, entry)| package::verify_file(&dir, path, entry).is_err())
            .count();
        if missing > 0 {
            out.push(Settled::Waiting {
                id,
                why: format!("{missing} file(s) still to come"),
            });
            continue;
        }
        if incoming.tried_recently(&hex) {
            out.push(Settled::Waiting {
                id,
                why: "its last check could not be decided; trying again later".into(),
            });
            continue;
        }
        // Entry formats are a fact about the bytes the pin names, so a
        // package that fails them here fails them everywhere.
        let package = match Package::at(&dir, manifest) {
            Ok(package) => package,
            Err(why) => {
                incoming.fail(&id, &why.0, None);
                incoming.drop_staged(&hex);
                out.push(Settled::Failed { id, why: why.0 });
                continue;
            }
        };
        let report = super::cli::check_package(
            &package,
            Some((objective_id.as_str(), objective)),
            root,
            false,
            true,
        );
        let verdict = report.verdict();
        if verdict == Outcome::Fail {
            let why = report
                .tests
                .iter()
                .find(|t| t.outcome == Outcome::Fail)
                .map(|t| format!("test {:?} failed: {}", t.name, t.detail))
                .unwrap_or_else(|| "its tests failed here".into());
            incoming.fail(&id, &why, Some(&report));
            incoming.drop_staged(&hex);
            out.push(Settled::Failed { id, why });
            continue;
        }
        match incoming.store.add(&package, &report) {
            Ok(_) => {
                incoming.drop_staged(&hex);
                out.push(Settled::Offered { id, verdict });
            }
            // Unavailable on a host that can run a target: no jail, or the
            // objective's checker not here yet. Nothing about the package.
            Err(why) => {
                let _ = fs::remove_file(incoming.tried_marker(&hex));
                let _ = write_new(
                    &incoming.tried_marker(&hex),
                    &report.to_value().canonical_bytes(),
                    false,
                );
                out.push(Settled::Waiting { id, why });
            }
        }
    }
    out
}

/// Write `bytes` at `path` under a hidden temporary name, then rename it into
/// place unless something is there already. Package paths are never hidden
/// ([`super::manifest::valid_path`]), so the temporary name cannot be one.
fn write_new(path: &Path, bytes: &[u8], executable: bool) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("no parent directory"))?;
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(
        ".tmp-{}-{}",
        std::process::id(),
        TEMPORARY.fetch_add(1, Ordering::Relaxed)
    ));
    let written = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        package::set_mode(&temporary, executable)?;
        if fs::symlink_metadata(path).is_ok() {
            return Err(io::Error::from(io::ErrorKind::AlreadyExists));
        }
        fs::rename(&temporary, path)
    })();
    if written.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    written
}
