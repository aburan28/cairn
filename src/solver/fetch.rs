//! A worker's side: ask the node which package to run, download it, and hold
//! every byte to its pin before anything executes.
//!
//! The node is not trusted for the bytes. The package id is the digest of the
//! manifest, the manifest names every file by hash, and a file that does not
//! hash to its name is refused before it is written where the jail can see
//! it. What the node *is* trusted for is the choice, when an objective pinned
//! nothing: it names an approach somebody published there. The jail is what
//! bounds a bad choice, and the worker's own run of the package's tests is
//! what catches a broken one before it costs a round.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::manifest::{self, Manifest};
use super::package::{self, Package};
use super::MANIFEST_FILE;
use crate::agent::http::{self, NodeUrl};
use crate::canonical::Value;

const TIMEOUT: Duration = Duration::from_secs(60);

/// Where a worker keeps downloaded packages: `$CAIRN_SOLVER_CACHE`, else
/// `~/.cairn/solvers`. One directory per package id, never rewritten.
pub fn default_cache() -> Option<PathBuf> {
    std::env::var_os("CAIRN_SOLVER_CACHE")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cairn/solvers")))
}

/// One package as `GET /solvers?objective=` lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    pub id: String,
    pub name: String,
    pub version: String,
    pub summary: String,
    pub pinned: bool,
    pub verdict: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offers {
    pub pinned: Option<String>,
    pub recommended: Option<String>,
    pub packages: Vec<Offer>,
}

pub fn offers(node: &NodeUrl, objective: &str) -> Result<Offers, String> {
    let response = http::get(node, &format!("/solvers?objective={objective}"), TIMEOUT)
        .map_err(|e| e.to_string())?;
    if response.status == 404 && response.body.get("objective").is_none() {
        return Err(format!(
            "{} does not serve solver packages (it predates them, or does not know objective {objective})",
            node.as_str()
        ));
    }
    if !response.ok() {
        return Err(response.error_text());
    }
    let body = &response.body;
    let text = |v: &Value, key: &str| v.get(key).and_then(Value::as_str).unwrap_or("").to_string();
    let id = |key: &str| {
        body.get(key)
            .and_then(Value::as_str)
            .filter(|id| manifest::is_record_id(id))
            .map(str::to_string)
    };
    Ok(Offers {
        pinned: id("pinned"),
        recommended: id("recommended"),
        packages: body
            .get("packages")
            .and_then(Value::as_array)
            .unwrap_or(&[])
            .iter()
            .filter(|p| {
                p.get("id")
                    .and_then(Value::as_str)
                    .is_some_and(manifest::is_record_id)
            })
            .map(|p| Offer {
                id: text(p, "id"),
                name: text(p, "name"),
                version: text(p, "version"),
                summary: text(p, "summary"),
                pinned: p.get("pinned").and_then(Value::as_bool).unwrap_or(false),
                verdict: text(p, "verdict"),
            })
            .collect(),
    })
}

/// Which package `wanted` means for this objective: `auto` is the node's
/// recommendation; an id must be one the node lists for the objective, so a
/// typo cannot fetch an unrelated program.
pub fn choose(offers: &Offers, wanted: &str, objective: &str) -> Result<String, String> {
    if wanted == "auto" {
        return match (&offers.recommended, &offers.pinned) {
            (Some(id), _) => Ok(id.clone()),
            (None, Some(pin)) => Err(format!(
                "objective {objective} pins solver package {pin}, but this node does not have \
                 it; ask its operator to `cairn solver add` it"
            )),
            (None, None) => Err(format!(
                "no solver has been published for objective {objective} on this node. Its \
                 author can publish one (`cairn solver add`, docs/solvers.md); until then, \
                 run your own with `cairn work … -- PROGRAM`"
            )),
        };
    }
    if !manifest::is_record_id(wanted) {
        return Err(format!(
            "--package is `auto` or a package id (sha256:…), not {wanted:?}"
        ));
    }
    if offers.packages.iter().any(|p| p.id == wanted) {
        Ok(wanted.to_string())
    } else {
        Err(format!(
            "this node offers no package {wanted} for objective {objective}"
        ))
    }
}

/// The package `id`, from the cache if a verified copy is there, else from
/// the node. Either way every file is hashed against the manifest before this
/// returns.
pub fn fetch(node: &NodeUrl, id: &str, cache: &Path) -> Result<Package, String> {
    let hex = id
        .strip_prefix(crate::canonical::DIGEST_PREFIX)
        .filter(|h| crate::blobs::is_address(h))
        .ok_or_else(|| format!("{id:?} is not a package id"))?;
    let slot = cache.join(hex);
    if slot.exists() {
        match open_cached(&slot, id) {
            Ok(package) => return Ok(package),
            // A copy that no longer matches its name was tampered with or
            // rotted. Set aside rather than deleted, for whoever wants to
            // know which.
            Err(why) => {
                let aside = cache.join(format!("{hex}.bad-{}", crate::time::unix_seconds()));
                fs::rename(&slot, &aside).map_err(|e| format!("{}: {e}", slot.display()))?;
                eprintln!(
                    "cairn: the cached copy of {id} failed its check ({why}); set aside at {} and fetching again",
                    aside.display()
                );
            }
        }
    }

    let response =
        http::get(node, &format!("/solvers/{id}"), TIMEOUT).map_err(|e| e.to_string())?;
    if !response.ok() {
        return Err(format!("GET /solvers/{id}: {}", response.error_text()));
    }
    let raw = response
        .body
        .get("manifest")
        .ok_or("the node's answer has no manifest")?;
    if raw.digest() != id {
        return Err(format!(
            "the node served a manifest that hashes to {}, not {id}; refusing it",
            raw.digest()
        ));
    }
    let manifest = Manifest::from_value(raw).map_err(|e| format!("its manifest: {e}"))?;

    fs::create_dir_all(cache).map_err(|e| format!("{}: {e}", cache.display()))?;
    let partial = cache.join(format!(".partial-{hex}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&partial);
    fs::create_dir(&partial).map_err(|e| format!("{}: {e}", partial.display()))?;
    let result = download(node, id, &manifest, &partial).and_then(|()| {
        fs::write(partial.join(MANIFEST_FILE), raw.canonical_bytes())
            .map_err(|e| format!("{}: {e}", partial.display()))?;
        Package::at(&partial, manifest.clone()).map_err(|e| e.0)
    });
    if let Err(error) = result {
        let _ = fs::remove_dir_all(&partial);
        return Err(error);
    }
    if fs::rename(&partial, &slot).is_err() {
        // Another worker on this machine got there first; theirs was checked
        // the same way, but check it again rather than assume.
        let _ = fs::remove_dir_all(&partial);
    }
    open_cached(&slot, id)
}

fn download(node: &NodeUrl, id: &str, manifest: &Manifest, into: &Path) -> Result<(), String> {
    for (path, entry) in &manifest.files {
        let (status, bytes) = http::get_bytes(
            node,
            &format!("/solvers/{id}/files/{path}"),
            entry.size,
            TIMEOUT,
        )
        .map_err(|e| format!("{path}: {e}"))?;
        if status != 200 {
            return Err(format!("{path}: the node answered HTTP {status}"));
        }
        // Checked in memory, before the bytes reach a path the jail reads.
        let actual = crate::blobs::address(&bytes);
        if bytes.len() as u64 != entry.size || actual != entry.hex() {
            return Err(format!(
                "{path}: the node served {} bytes hashing to {actual}; the package pins {} bytes \
                 hashing to {}",
                bytes.len(),
                entry.size,
                entry.hex()
            ));
        }
        let to = into.join(path);
        if let Some(parent) = to.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        }
        fs::write(&to, &bytes).map_err(|e| format!("{}: {e}", to.display()))?;
        package::set_mode(&to, package::executable(manifest, path))
            .map_err(|e| format!("{}: {e}", to.display()))?;
    }
    Ok(())
}

fn open_cached(slot: &Path, id: &str) -> Result<Package, String> {
    let package = Package::open(slot).map_err(|e| e.0)?;
    if package.id() != id {
        return Err(format!("its manifest hashes to {}", package.id()));
    }
    Ok(package)
}
