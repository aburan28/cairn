//! The `workspace` verifier, derived independently of the primary.
//!
//! A solver replaces declared paths in a pinned base tree and a pinned command
//! scores the result. The primary is `src/verifiers/workspace.rs` and the
//! design is `docs/design/workspace-benchmarks.md`; this file shares neither
//! code nor helpers with them, and agrees with them only because both follow
//! the same rules:
//!
//! * The spec is checked first, then the base manifest, then the artifact, then
//!   the blobs. A broken spec is `InvalidSpec` whatever the artifact says.
//! * A path in the base manifest or the artifact is relative POSIX with no
//!   empty, `.`, `..` or `.git` component, no backslash and no NUL, and no
//!   path may be both a file and a directory.
//! * An artifact file outside `editable_paths`, over `max_files` or over
//!   `max_bytes`, or without an integer `results.score`, is `Reject`.
//! * A blob this node does not hold is `Unavailable`.
//! * Prepare runs on the base tree alone; anything wrong there is
//!   `Unavailable`. Then every editable path is removed and the artifact's
//!   files written. A non-zero exit from the score command is `Reject`; a
//!   score file that is missing, not canonical JSON, or without an integer
//!   `score` is `Reject`; a score that differs from the claim is `Reject`.
//!
//! **No jail here**, as with `replay`. This crate is a second opinion on the
//! rules, not a hardened node: do not point it at an objective you have not
//! read. It has no wall-clock bound either, for the same reason `replay` has
//! none here.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest as _, Sha256};

use crate::canonical::Value;
use crate::verifiers::{Status, Verdict};

const BLOB_STORE: &str = ".cairn/blobs";
const DEFAULT_MAX_FILES: i64 = 256;
const DEFAULT_MAX_BYTES: i64 = 8 * 1024 * 1024;
const MAX_TIMEOUT_SECONDS: i64 = 86_400;
const MAX_BLOB_BYTES: u64 = 1024 * 1024;
const MAX_SCORE_FILE_BYTES: u64 = 64 * 1024;

fn invalid(detail: impl Into<String>) -> Verdict {
    Verdict::new(Status::InvalidSpec, detail, empty())
}

fn reject(detail: impl Into<String>) -> Verdict {
    Verdict::new(Status::Reject, detail, empty())
}

fn unavailable(detail: impl Into<String>) -> Verdict {
    Verdict::new(Status::Unavailable, detail, empty())
}

fn empty() -> Value {
    Value::object(Vec::<(String, Value)>::new())
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn is_address(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// The path rules, returning the components of a good path.
fn components(path: &str) -> Option<Vec<&str>> {
    if path.is_empty() || path.starts_with('/') || path.contains('\\') || path.contains('\0') {
        return None;
    }
    let parts: Vec<&str> = path.split('/').collect();
    if parts
        .iter()
        .any(|part| matches!(*part, "" | "." | ".." | ".git"))
    {
        return None;
    }
    Some(parts)
}

/// `inner` equals `outer` or lies beneath it, component by component.
fn beneath(inner: &str, outer: &str) -> bool {
    inner == outer || inner.starts_with(&format!("{outer}/"))
}

/// A `{path: address}` object. `fault` decides whose fault a bad entry is.
fn manifest(
    files: Option<&Value>,
    what: &str,
    fault: fn(String) -> Verdict,
) -> Result<BTreeMap<String, String>, Verdict> {
    let Some(Value::Object(files)) = files else {
        return Err(fault(format!("{what} 'files' must be an object")));
    };
    let mut out = BTreeMap::new();
    for (path, address) in files {
        if components(path).is_none() {
            return Err(fault(format!("{what}: bad path {path:?}")));
        }
        match address.as_str() {
            Some(address) if is_address(address) => {
                out.insert(path.clone(), address.to_string());
            }
            _ => return Err(fault(format!("{what}: {path:?} needs a bare sha256"))),
        }
    }
    let all: BTreeSet<&str> = out.keys().map(String::as_str).collect();
    for path in &all {
        if all
            .iter()
            .any(|other| other != path && other.starts_with(&format!("{path}/")))
        {
            return Err(fault(format!(
                "{what}: {path:?} is both a file and a directory"
            )));
        }
    }
    Ok(out)
}

fn strings(spec: &Value, key: &str) -> Result<Option<Vec<String>>, Verdict> {
    match spec.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(items)) if !items.is_empty() => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                match item.as_str() {
                    Some(text) => out.push(text.to_string()),
                    None => return Err(invalid(format!("{key} must hold only strings"))),
                }
            }
            Ok(Some(out))
        }
        Some(_) => Err(invalid(format!(
            "{key} must be a non-empty list of strings"
        ))),
    }
}

fn positive(spec: &Value, key: &str, default: i64, ceiling: i64) -> Result<i64, Verdict> {
    match spec.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(value) => match value.as_i64() {
            Some(number) if number > 0 && number <= ceiling => Ok(number),
            _ => Err(invalid(format!("{key} must be a positive integer"))),
        },
    }
}

fn read_blob(root: &Path, path: &str, address: &str) -> Result<Vec<u8>, Verdict> {
    let at = root.join(BLOB_STORE).join(address);
    let too_big = std::fs::metadata(&at)
        .map(|meta| meta.len() > MAX_BLOB_BYTES)
        .unwrap_or(false);
    if too_big {
        return Err(unavailable(format!(
            "blob {address} for {path:?} is oversized"
        )));
    }
    let bytes = std::fs::read(&at)
        .map_err(|error| unavailable(format!("no blob {address} for {path:?}: {error}")))?;
    if sha256_hex(&bytes) != address {
        return Err(unavailable(format!(
            "blob {address} for {path:?} is damaged"
        )));
    }
    Ok(bytes)
}

fn gather(
    root: &Path,
    files: &BTreeMap<String, String>,
    max_bytes: i64,
    over: fn(String) -> Verdict,
) -> Result<Vec<(String, Vec<u8>)>, Verdict> {
    let mut total: i64 = 0;
    let mut out = Vec::new();
    for (path, address) in files {
        let bytes = read_blob(root, path, address)?;
        total = total.saturating_add(i64::try_from(bytes.len()).unwrap_or(i64::MAX));
        if total > max_bytes {
            return Err(over(format!("more than {max_bytes} bytes")));
        }
        out.push((path.clone(), bytes));
    }
    Ok(out)
}

/// Create `tree/relative`, making each ancestor a real directory and refusing
/// to pass through anything that is not one.
fn place(tree: &Path, relative: &str, bytes: &[u8]) -> Result<(), String> {
    let parts: Vec<&str> = relative.split('/').collect();
    let mut at = tree.to_path_buf();
    for part in &parts[..parts.len() - 1] {
        at.push(part);
        match std::fs::symlink_metadata(&at) {
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => return Err(format!("{} is not a directory", at.display())),
            Err(_) => std::fs::create_dir(&at).map_err(|error| error.to_string())?,
        }
    }
    at.push(parts[parts.len() - 1]);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&at)
        .map_err(|error| error.to_string())?;
    file.write_all(bytes).map_err(|error| error.to_string())
}

/// Delete an editable path without ever following a link.
fn clear(tree: &Path, relative: &str) -> Result<(), String> {
    let mut at = tree.to_path_buf();
    let parts: Vec<&str> = relative.split('/').collect();
    for (index, part) in parts.iter().enumerate() {
        at.push(part);
        let Ok(meta) = std::fs::symlink_metadata(&at) else {
            return Ok(());
        };
        if index + 1 < parts.len() {
            if !meta.is_dir() {
                return Err(format!("{} is not a directory", at.display()));
            }
            continue;
        }
        return if meta.is_dir() {
            std::fs::remove_dir_all(&at).map_err(|error| error.to_string())
        } else {
            std::fs::remove_file(&at).map_err(|error| error.to_string())
        };
    }
    Ok(())
}

fn on_path(program: &str) -> bool {
    if program.contains('/') {
        return Path::new(program).is_file();
    }
    std::env::var_os("PATH").is_some_and(|path| {
        std::env::split_paths(&path)
            .any(|dir| !dir.as_os_str().is_empty() && dir.join(program).is_file())
    })
}

/// Run one phase in the tree. `Ok(true)` is a zero exit, `Ok(false)` a
/// non-zero one, `Err` a phase that never ran.
fn phase(argv: &[String], tree: &Path, home: &Path) -> Result<bool, String> {
    let mut command = Command::new(&argv[0]);
    command.args(&argv[1..]).current_dir(tree);
    crate::verifiers::scrub(&mut command, home);
    command
        .output()
        .map(|output| output.status.success())
        .map_err(|error| error.to_string())
}

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn scratch(label: &str) -> Result<Scratch, Verdict> {
    let dir = std::env::temp_dir().join(format!(
        "cairn-reference-workspace-{label}-{}-{}",
        std::process::id(),
        crate::verifiers::scratch_counter()
    ));
    std::fs::create_dir_all(&dir)
        .map_err(|error| unavailable(format!("cannot create a scratch directory: {error}")))?;
    Ok(Scratch(dir))
}

fn score_in(tree: &Path, score_path: &str) -> Result<i64, String> {
    let tree = std::fs::canonicalize(tree).map_err(|error| error.to_string())?;
    let file = std::fs::canonicalize(tree.join(score_path))
        .map_err(|_| format!("no {score_path} after the scored run"))?;
    if !file.starts_with(&tree) {
        return Err(format!("{score_path} leaves the tree"));
    }
    let meta = std::fs::symlink_metadata(&file).map_err(|error| error.to_string())?;
    if !meta.is_file() || meta.len() > MAX_SCORE_FILE_BYTES {
        return Err(format!("{score_path} is not a small regular file"));
    }
    let text = std::fs::read_to_string(&file).map_err(|error| error.to_string())?;
    let value = Value::from_json(text.trim()).map_err(|error| error.to_string())?;
    value
        .get("score")
        .and_then(Value::as_i64)
        .ok_or_else(|| format!("{score_path} holds no integer score"))
}

pub fn workspace(root: &Path, spec: &Value, artifact: &Value) -> Verdict {
    // -- the spec ---------------------------------------------------------
    let (Some(base), Some(base_sha256)) = (
        spec.get("base").and_then(Value::as_str),
        spec.get("base_sha256").and_then(Value::as_str),
    ) else {
        return invalid("base and base_sha256 must be strings");
    };
    if !is_address(base_sha256) {
        return invalid("base_sha256 must be a bare sha256");
    }
    let editable = match spec.get("editable_paths") {
        Some(Value::Array(items)) if !items.is_empty() => {
            let mut out: Vec<String> = Vec::new();
            for item in items {
                let Some(path) = item.as_str() else {
                    return invalid("editable_paths must hold only strings");
                };
                if components(path).is_none() {
                    return invalid(format!("editable path {path:?} breaks the path rules"));
                }
                if out
                    .iter()
                    .any(|seen| beneath(path, seen) || beneath(seen, path))
                {
                    return invalid(format!("editable path {path:?} overlaps another"));
                }
                out.push(path.to_string());
            }
            out
        }
        _ => return invalid("editable_paths must be a non-empty list of strings"),
    };
    let Some(score_path) = spec.get("score_path").and_then(Value::as_str) else {
        return invalid("score_path must be a string");
    };
    if components(score_path).is_none() {
        return invalid(format!("score_path {score_path:?} breaks the path rules"));
    }
    if editable
        .iter()
        .any(|path| beneath(score_path, path) || beneath(path, score_path))
    {
        return invalid("score_path overlaps an editable path");
    }
    let prepare = match strings(spec, "prepare_command") {
        Ok(prepare) => prepare,
        Err(verdict) => return verdict,
    };
    let score_command = match strings(spec, "score_command") {
        Ok(Some(command)) => command,
        Ok(None) => return invalid("score_command is required"),
        Err(verdict) => return verdict,
    };
    let max_files = match positive(spec, "max_files", DEFAULT_MAX_FILES, i64::MAX) {
        Ok(limit) => limit,
        Err(verdict) => return verdict,
    };
    let max_bytes = match positive(spec, "max_bytes", DEFAULT_MAX_BYTES, i64::MAX) {
        Ok(limit) => limit,
        Err(verdict) => return verdict,
    };
    if let Err(verdict) = positive(spec, "timeout_seconds", 1, MAX_TIMEOUT_SECONDS) {
        return verdict;
    }

    // -- the base manifest ----------------------------------------------------
    let manifest_at = match crate::verifiers::pinned_path(root, base, base_sha256) {
        Ok(path) => path,
        Err(verdict) => return verdict,
    };
    let Ok(raw) = std::fs::read(&manifest_at) else {
        return unavailable("cannot read the base manifest");
    };
    let parsed = match std::str::from_utf8(&raw).ok().map(Value::from_json) {
        Some(Ok(parsed)) => parsed,
        _ => return invalid("base manifest is not canonical JSON"),
    };
    let base_files = match manifest(parsed.get("files"), "base manifest", invalid) {
        Ok(files) => files,
        Err(verdict) => return verdict,
    };
    if base_files.len() as i64 > max_files {
        return invalid("base manifest has more than max_files files");
    }

    // -- the artifact -----------------------------------------------------
    let submitted = match manifest(artifact.get("files"), "artifact", reject) {
        Ok(files) => files,
        Err(verdict) => return verdict,
    };
    if submitted.len() as i64 > max_files {
        return reject("artifact has more than max_files files");
    }
    if let Some(outside) = submitted
        .keys()
        .find(|path| !editable.iter().any(|allowed| beneath(path, allowed)))
    {
        return reject(format!(
            "artifact writes {outside:?}, outside editable_paths"
        ));
    }
    let Some(claimed) = artifact
        .get("results")
        .and_then(|results| results.get("score"))
        .and_then(Value::as_i64)
    else {
        return reject("artifact has no integer results.score");
    };

    // -- the bytes ----------------------------------------------------------
    let base_bytes = match gather(root, &base_files, max_bytes, |why| {
        invalid(format!("base tree has {why}"))
    }) {
        Ok(bytes) => bytes,
        Err(verdict) => return verdict,
    };
    let submitted_bytes = match gather(root, &submitted, max_bytes, |why| {
        reject(format!("artifact has {why}"))
    }) {
        Ok(bytes) => bytes,
        Err(verdict) => return verdict,
    };

    // -- phase 1: the base tree alone -------------------------------------------
    let tree = match scratch("tree") {
        Ok(tree) => tree,
        Err(verdict) => return verdict,
    };
    let home = match scratch("home") {
        Ok(home) => home,
        Err(verdict) => return verdict,
    };
    for (path, bytes) in &base_bytes {
        if let Err(why) = place(&tree.0, path, bytes) {
            return unavailable(format!("cannot write the base tree: {why}"));
        }
    }
    if !on_path(&score_command[0]) {
        return unavailable(format!("{} is not on PATH", score_command[0]));
    }
    if let Some(verdict) = crate::verifiers::refuse_unconfined() {
        return verdict;
    }
    if let Some(prepare) = &prepare {
        if !on_path(&prepare[0]) {
            return unavailable(format!("{} is not on PATH", prepare[0]));
        }
        match phase(prepare, &tree.0, &home.0) {
            Ok(true) => {}
            Ok(false) => return unavailable("prepare failed on the base tree"),
            Err(why) => return unavailable(format!("prepare did not run: {why}")),
        }
    }

    // -- phase 2: the submission's editable files, and only those ---------------
    for path in &editable {
        if let Err(why) = clear(&tree.0, path) {
            return invalid(format!("prepare left {path:?} unremovable: {why}"));
        }
    }
    for (path, bytes) in &submitted_bytes {
        if let Err(why) = place(&tree.0, path, bytes) {
            return invalid(format!("cannot apply {path:?}: {why}"));
        }
    }

    // -- phase 3: score -----------------------------------------------------------
    match phase(&score_command, &tree.0, &home.0) {
        Ok(true) => {}
        Ok(false) => return reject("the score command failed on the submission"),
        Err(why) => return unavailable(format!("the score command did not run: {why}")),
    }
    let observed = match score_in(&tree.0, score_path) {
        Ok(observed) => observed,
        Err(why) => return reject(why),
    };
    if observed != claimed {
        return Verdict::new(
            Status::Reject,
            "the scored run disagrees with the claimed score",
            Value::object([
                ("claimed", Value::Int(i128::from(claimed))),
                ("observed", Value::Int(i128::from(observed))),
            ]),
        );
    }
    Verdict::new(
        Status::Accept,
        format!("reproduced score {observed}"),
        Value::object([("score", Value::Int(i128::from(observed)))]),
    )
}
