//! The packages a node offers, under its bundle root.
//!
//! Beside the blob store (`.cairn/blobs`) and for the same reason: the root is
//! what an objective's pins resolve against. Not *in* the blob store, because
//! a blob is a source file read by an interpreter, is never executable and is
//! never over a mebibyte (`blobs::MAX_BLOB_BYTES`), and a solver package is a
//! program that may be all three.
//!
//! Only a package whose tests passed on this node goes in, unless none of its
//! targets can run here at all, in which case what went in was checked for
//! format and hashes and the report says so. Every worker re-runs the tests on
//! its own platform before it runs a round, which is what covers the targets
//! this node could not.

use std::fs;
use std::path::{Path, PathBuf};

use super::check::{Outcome, Report};
use super::manifest::{self, Manifest};
use super::package::{self, Package};
use super::MANIFEST_FILE;
use crate::canonical::Value;
use crate::records::Objective;
use crate::scheduling::{ObjectiveCapabilities, WorkerRequirement};

pub const STORE_DIR: &str = ".cairn/solvers";
const REPORT_FILE: &str = "report.json";

#[derive(Debug, Clone)]
pub struct Store {
    dir: PathBuf,
}

/// A package as the store holds it.
#[derive(Debug, Clone)]
pub struct Stored {
    pub dir: PathBuf,
    pub manifest: Manifest,
    pub report: Report,
}

impl Stored {
    pub fn id(&self) -> String {
        self.manifest.id()
    }

    /// What a listing says about it. The manifest itself is one more request
    /// away; a list of every file hash is not what a picker needs.
    pub fn summary(&self) -> Value {
        let m = &self.manifest;
        Value::object([
            ("id", Value::string(self.id())),
            ("abi", Value::string(manifest::ABI)),
            ("name", Value::string(&m.name)),
            ("version", Value::string(&m.version)),
            ("summary", Value::string(&m.summary)),
            (
                "objective",
                m.objective
                    .clone()
                    .map(Value::string)
                    .unwrap_or(Value::Null),
            ),
            (
                "platforms",
                Value::array(
                    m.targets
                        .keys()
                        .map(|p| Value::string(p.as_str()))
                        .chain(m.other_targets.iter().map(Value::string)),
                ),
            ),
            ("bytes", Value::Int(i128::from(m.total_bytes()))),
            ("memory_mb", Value::Int(i128::from(m.resources.memory_mb))),
            (
                "round_seconds",
                Value::Int(i128::from(m.resources.round_seconds)),
            ),
            ("tests", Value::Int(m.tests.len() as i128)),
            ("verdict", Value::string(self.report.verdict().as_str())),
            ("checked_at", Value::string(&self.report.checked_at)),
            ("sandbox", Value::string(&self.report.sandbox)),
        ])
    }
}

impl Store {
    pub fn under(root: &Path) -> Store {
        Store {
            dir: root.join(STORE_DIR),
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn slot(&self, id: &str) -> Option<PathBuf> {
        let hex = id.strip_prefix(crate::canonical::DIGEST_PREFIX)?;
        crate::blobs::is_address(hex).then(|| self.dir.join(hex))
    }

    /// File a checked package. Refuses one whose tests failed here; a report
    /// that could not decide anything is accepted only when no target runs
    /// on this host, because then deciding was never possible here.
    pub fn add(&self, package: &Package, report: &Report) -> Result<PathBuf, String> {
        match report.verdict() {
            Outcome::Pass => {}
            Outcome::Fail => return Err("its tests failed; see the report".into()),
            Outcome::Unavailable if package::runnable_here(&package.manifest).is_empty() => {}
            Outcome::Unavailable => return Err(
                "its tests could not run here, so this node cannot vouch for it; see the report"
                    .into(),
            ),
        }
        let id = package.id();
        let slot = self.slot(&id).ok_or("not a package id")?;
        fs::create_dir_all(&self.dir).map_err(|e| format!("{}: {e}", self.dir.display()))?;
        // A copy already filed is held to the manifest again rather than
        // trusted: the report written below vouches for the bytes in this
        // slot, and a slot edited since it was filed would be vouched for by
        // a check it never had. Set aside, not deleted, for whoever asks why.
        if slot.exists() && Package::at(&slot, package.manifest.clone()).is_err() {
            let aside = self.dir.join(format!(
                ".bad-{}-{}",
                slot.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("package"),
                crate::time::unix_seconds()
            ));
            fs::rename(&slot, &aside).map_err(|e| format!("{}: {e}", slot.display()))?;
        }
        if !slot.exists() {
            let partial = self.dir.join(format!(
                ".partial-{}-{}",
                std::process::id(),
                crate::time::unix_seconds()
            ));
            let _ = fs::remove_dir_all(&partial);
            package::install(package, &partial).map_err(|e| e.0)?;
            if let Err(error) = fs::rename(&partial, &slot) {
                let _ = fs::remove_dir_all(&partial);
                if !slot.exists() {
                    return Err(format!("{}: {error}", slot.display()));
                }
            }
        }
        let temporary = slot.join(format!(".{REPORT_FILE}.{}", std::process::id()));
        fs::write(&temporary, report.to_value().canonical_bytes())
            .and_then(|()| fs::rename(&temporary, slot.join(REPORT_FILE)))
            .map_err(|e| format!("{}: {e}", slot.display()))?;
        Ok(slot)
    }

    /// One package, by id. Its manifest must still hash to its name: a store
    /// edited by hand is refused rather than served.
    pub fn get(&self, id: &str) -> Option<Stored> {
        let dir = self.slot(id)?;
        let text = fs::read_to_string(dir.join(MANIFEST_FILE)).ok()?;
        let manifest = Manifest::from_json(&text).ok()?;
        if manifest.id() != id {
            return None;
        }
        let report = fs::read_to_string(dir.join(REPORT_FILE))
            .ok()
            .and_then(|t| Value::from_json(&t).ok())
            .and_then(|v| Report::from_value(&v))?;
        Some(Stored {
            dir,
            manifest,
            report,
        })
    }

    pub fn list(&self) -> Vec<Stored> {
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return Vec::new();
        };
        let mut found: Vec<Stored> = entries
            .filter_map(Result::ok)
            .filter_map(|entry| {
                let name = entry.file_name().into_string().ok()?;
                self.get(&format!("{}{name}", crate::canonical::DIGEST_PREFIX))
            })
            .collect();
        found.sort_by(|a, b| b.report.checked_at.cmp(&a.report.checked_at));
        found
    }

    /// The on-disk path of one file of one package, if the package lists it.
    pub fn file(&self, id: &str, path: &str) -> Option<(PathBuf, u64)> {
        let stored = self.get(id)?;
        let entry = stored.manifest.files.get(path)?;
        Some((stored.dir.join(path), entry.size))
    }
}

/// The package an objective pins, if it pins one.
pub fn pinned(objective: &Objective) -> Option<String> {
    match ObjectiveCapabilities::for_objective(objective).worker {
        WorkerRequirement::Package { id } => Some(id),
        _ => None,
    }
}

/// What a node offers for one objective.
#[derive(Debug, Clone)]
pub struct Offers {
    /// The objective's own pin, whether or not this node holds it.
    pub pinned: Option<String>,
    /// The pin if held; otherwise the newest approach written for this
    /// objective that passed here. A pin this node lacks is *not* replaced
    /// by an approach: the author chose that program, and a node quietly
    /// substituting another is the thing a pin exists to prevent.
    pub recommended: Option<String>,
    pub packages: Vec<Stored>,
}

impl Offers {
    pub fn for_objective(store: &Store, objective: &Objective) -> Offers {
        Offers::among(&store.list(), objective)
    }

    /// [`Offers::for_objective`] over a listing already read, for a caller
    /// answering for every objective at once.
    pub fn among(listed: &[Stored], objective: &Objective) -> Offers {
        let pinned = pinned(objective);
        let id = objective.id();
        let mut packages: Vec<Stored> = listed
            .iter()
            .filter(|s| {
                Some(s.id()) == pinned || s.manifest.objective.as_deref() == Some(id.as_str())
            })
            .cloned()
            .collect();
        // The pin first, then newest.
        packages.sort_by_key(|s| Some(s.id()) != pinned);
        let recommended = match &pinned {
            Some(pin) => packages.iter().find(|s| &s.id() == pin).map(Stored::id),
            None => packages
                .iter()
                .find(|s| s.report.verdict() == Outcome::Pass)
                .map(Stored::id),
        };
        Offers {
            pinned,
            recommended,
            packages,
        }
    }

    pub fn to_value(&self, objective: &str) -> Value {
        Value::object([
            ("objective", Value::string(objective)),
            (
                "pinned",
                self.pinned
                    .clone()
                    .map(Value::string)
                    .unwrap_or(Value::Null),
            ),
            (
                "recommended",
                self.recommended
                    .clone()
                    .map(Value::string)
                    .unwrap_or(Value::Null),
            ),
            (
                "packages",
                Value::array(self.packages.iter().map(|s| {
                    let mut v = s.summary();
                    if let Value::Object(map) = &mut v {
                        map.insert("pinned".into(), Value::Bool(Some(s.id()) == self.pinned));
                    }
                    v
                })),
            ),
        ])
    }

    /// The short form an objective row carries, so a picker can say "ready"
    /// without a second request.
    pub fn row(&self) -> Value {
        let chosen = self
            .recommended
            .as_ref()
            .and_then(|id| self.packages.iter().find(|s| &s.id() == id));
        match (chosen, &self.pinned) {
            (Some(s), _) => Value::object([
                ("package", Value::string(s.id())),
                ("name", Value::string(&s.manifest.name)),
                ("version", Value::string(&s.manifest.version)),
                ("pinned", Value::Bool(Some(s.id()) == self.pinned)),
                ("ready", Value::Bool(true)),
            ]),
            (None, Some(pin)) => Value::object([
                ("package", Value::string(pin)),
                ("pinned", Value::Bool(true)),
                ("ready", Value::Bool(false)),
            ]),
            (None, None) => Value::Null,
        }
    }
}
