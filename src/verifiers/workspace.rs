//! The `workspace` verifier: a solver replaces declared paths in a pinned base
//! tree, and a pinned command scores the result.
//!
//! Designed in `docs/design/workspace-benchmarks.md`, which is the authority on
//! *why*; this file is the *what*. It is the shape of a repository benchmark
//! (ecdsa.fail, Yukon) without the part that makes those an oracle: the tree,
//! the commands and the score are all re-derivable from the log and the blob
//! store, by anyone, offline.
//!
//! # The artifact is a manifest
//!
//! ```json
//! { "files": { "src/point_add/mod.rs": "<sha256>" },
//!   "results": { "score": 1571592960 },
//!   "note": "optional, ignored here", "model": "optional, ignored here" }
//! ```
//!
//! A map of path to blob address is canonical already, where an archive is
//! not. The bytes live in the blob store. A claim's files are applied over the
//! **base** tree, never over another claim's, so verification is O(1) in the
//! length of the frontier.
//!
//! # Three phases, and the only honest split
//!
//! 1. **Prepare.** The base tree, with the artifact *not yet applied*, gets
//!    `prepare_command`. Anything that goes wrong is `Unavailable`: the base is
//!    the objective's own code, and its failure says nothing about a
//!    submission nobody has looked at yet.
//! 2. **Apply.** Every editable path is removed, then the artifact's files are
//!    written. The candidate is the base plus the submission's editable files
//!    and nothing else.
//! 3. **Score.** `score_command` runs. Phase 1 proved the toolchain is here,
//!    so a non-zero exit now *is* a fact about the artifact: `Reject`. A
//!    timeout stays `Unavailable`; a timeout is not a refutation.
//!
//! The score file must hold a canonical object with an integer `score`, and
//! that integer must equal the artifact's `results.score` exactly. Anything
//! else the scored run leaves behind -- no file, a float, a symlink -- is a
//! `Reject`. The design note called a float `InvalidSpec`; it is a `Reject`
//! here because the scored run executed submission code, so what it left in
//! the score file cannot be attributed to the objective alone.
//!
//! # Where this differs from `replay`'s confinement
//!
//! The tree is bound **writable** -- a build has to write -- and it is the
//! child's `cwd`. The jail's scratch directory is separate, so the capture
//! files `run_bounded` writes can never collide with a path in the tree. There
//! is still no network: `prepare_command` cannot download anything, and a base
//! tree with dependencies must vendor them.
//!
//! Both implementations change together: `reference/rust/src/verifiers.rs`
//! derives the same verdicts independently.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::blobs::{self, BlobError};
use crate::canonical::Value;

use super::sandbox::{self, Confinement};
use super::{
    run_bounded, spec_timeout, which, RunFailure, Status, TempDir, Verdict, VerifierRegistry,
};

/// The default wall-clock bound per phase. A build plus a simulation is the
/// expected workload, so this is longer than `replay`'s.
pub const DEFAULT_WORKSPACE_TIMEOUT_SECONDS: u64 = 1800;

/// Default ceiling on the number of files in an artifact or a base tree.
pub const DEFAULT_MAX_FILES: i64 = 256;

/// Default ceiling on the total bytes of an artifact or a base tree.
pub const DEFAULT_MAX_BYTES: i64 = 8 << 20;

/// The largest score file this node will read. It holds one integer.
const MAX_SCORE_FILE_BYTES: u64 = 64 << 10;

/// Check one tree path against the rules every path in a workspace obeys.
///
/// Relative POSIX only: no leading `/`, no backslash, no NUL, no empty, `.` or
/// `..` component, and no `.git` component anywhere. These are security rules
/// rather than style -- every one of them is a way for a path to land
/// somewhere other than where it reads.
pub fn path_components(path: &str) -> Result<Vec<&str>, String> {
    if path.is_empty() {
        return Err("a path may not be empty".to_string());
    }
    if path.starts_with('/') {
        return Err(format!("{path:?} is absolute"));
    }
    if path.contains('\\') || path.contains('\0') {
        return Err(format!("{path:?} contains a backslash or a NUL"));
    }
    let parts: Vec<&str> = path.split('/').collect();
    for part in &parts {
        match *part {
            "" => return Err(format!("{path:?} has an empty component")),
            "." | ".." => return Err(format!("{path:?} has a '{part}' component")),
            ".git" => return Err(format!("{path:?} reaches into .git")),
            _ => {}
        }
    }
    Ok(parts)
}

/// Whether `path` is `prefix` or lies beneath it, component-wise -- so
/// `src/point_addx` is not inside `src/point_add`.
pub fn within(path: &[&str], prefix: &[&str]) -> bool {
    path.len() >= prefix.len() && path[..prefix.len()] == *prefix
}

/// Find a pair of paths where one would have to be both a file and a
/// directory: `a/b` beside `a/b/c`.
fn collision<'a>(paths: impl Iterator<Item = &'a str> + Clone) -> Option<(String, String)> {
    let all: std::collections::BTreeSet<&str> = paths.clone().collect();
    for path in paths {
        let parts: Vec<&str> = path.split('/').collect();
        for end in 1..parts.len() {
            let prefix = parts[..end].join("/");
            if all.contains(prefix.as_str()) {
                return Some((prefix, path.to_string()));
            }
        }
    }
    None
}

/// A positive integer limit field, or its default.
fn limit(spec: &Value, key: &str, default: i64) -> Result<i64, Verdict> {
    match spec.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(value) => match value.as_i64() {
            Some(limit) if limit > 0 => Ok(limit),
            _ => Err(Verdict::invalid_spec(format!(
                "{key} must be a positive integer"
            ))),
        },
    }
}

/// A non-empty list of strings.
fn command(spec: &Value, key: &str) -> Result<Option<Vec<String>>, Verdict> {
    let parts = match spec.get(key) {
        None | Some(Value::Null) => return Ok(None),
        Some(parts) => parts,
    };
    let bad = || Verdict::invalid_spec(format!("{key} must be a non-empty list of strings"));
    let parts = parts.as_array().ok_or_else(bad)?;
    if parts.is_empty() {
        return Err(bad());
    }
    parts
        .iter()
        .map(|part| part.as_str().map(str::to_string).ok_or_else(bad))
        .collect::<Result<Vec<String>, Verdict>>()
        .map(Some)
}

/// A `{path: address}` object, with every path and address checked. `fault`
/// builds the verdict for a bad entry: `InvalidSpec` for the base, `Reject`
/// for an artifact.
fn manifest(
    files: &Value,
    what: &str,
    fault: fn(String) -> Verdict,
) -> Result<BTreeMap<String, String>, Verdict> {
    let Some(files) = files.as_object() else {
        return Err(fault(format!("{what} 'files' must be an object")));
    };
    let mut out = BTreeMap::new();
    for (path, address) in files {
        if let Err(why) = path_components(path) {
            return Err(fault(format!("{what}: {why}")));
        }
        match address.as_str() {
            Some(address) if blobs::is_address(address) => {
                out.insert(path.clone(), address.to_string());
            }
            _ => {
                return Err(fault(format!(
                    "{what}: {path:?} must map to a bare lowercase sha256"
                )))
            }
        }
    }
    if let Some((file, under)) = collision(out.keys().map(String::as_str)) {
        return Err(fault(format!(
            "{what}: {file:?} cannot be a file and also contain {under:?}"
        )));
    }
    Ok(out)
}

/// Everything a workspace spec says, validated.
struct Spec {
    base: String,
    base_sha256: String,
    editable: Vec<String>,
    prepare: Option<Vec<String>>,
    score: Vec<String>,
    score_path: String,
    max_files: i64,
    max_bytes: i64,
    timeout: Duration,
}

fn parse_spec(spec: &Value) -> Result<Spec, Verdict> {
    let text = |key: &str| {
        spec.get(key)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| Verdict::invalid_spec(format!("{key} must be a string")))
    };
    let base = text("base")?;
    let base_sha256 = text("base_sha256")?;
    if !blobs::is_address(&base_sha256) {
        return Err(Verdict::invalid_spec(
            "base_sha256 must be a bare lowercase sha256",
        ));
    }

    let editable: Vec<String> = match spec.get("editable_paths").and_then(Value::as_array) {
        Some(paths) if !paths.is_empty() => paths
            .iter()
            .map(|path| {
                path.as_str().map(str::to_string).ok_or_else(|| {
                    Verdict::invalid_spec("editable_paths must be a list of strings")
                })
            })
            .collect::<Result<_, _>>()?,
        _ => {
            return Err(Verdict::invalid_spec(
                "editable_paths must be a non-empty list of strings",
            ))
        }
    };
    for (index, path) in editable.iter().enumerate() {
        let parts = path_components(path)
            .map_err(|why| Verdict::invalid_spec(format!("editable_paths: {why}")))?;
        for other in &editable[..index] {
            let other_parts: Vec<&str> = other.split('/').collect();
            if within(&parts, &other_parts) || within(&other_parts, &parts) {
                return Err(Verdict::invalid_spec(format!(
                    "editable_paths {other:?} and {path:?} overlap"
                )));
            }
        }
    }

    let score_path = text("score_path")?;
    let score_parts = path_components(&score_path)
        .map_err(|why| Verdict::invalid_spec(format!("score_path: {why}")))?;
    for path in &editable {
        let parts: Vec<&str> = path.split('/').collect();
        if within(&score_parts, &parts) || within(&parts, &score_parts) {
            return Err(Verdict::invalid_spec(format!(
                "score_path {score_path:?} overlaps editable path {path:?}; a \
                 submission could write its own score"
            )));
        }
    }

    let prepare = command(spec, "prepare_command")?;
    let score = command(spec, "score_command")?.ok_or_else(|| {
        Verdict::invalid_spec("score_command must be a non-empty list of strings")
    })?;
    let max_files = limit(spec, "max_files", DEFAULT_MAX_FILES)?;
    let max_bytes = limit(spec, "max_bytes", DEFAULT_MAX_BYTES)?;
    let timeout = spec_timeout(spec, DEFAULT_WORKSPACE_TIMEOUT_SECONDS)?;
    Ok(Spec {
        base,
        base_sha256,
        editable,
        prepare,
        score,
        score_path,
        max_files,
        max_bytes,
        timeout,
    })
}

/// Read one file's bytes from the blob store. Absent or damaged is this node's
/// problem: `Unavailable`.
fn blob(registry: &VerifierRegistry, path: &str, address: &str) -> Result<Vec<u8>, Verdict> {
    registry.blobs.read(address).map_err(|error| match error {
        BlobError::Absent { .. } => Verdict::unavailable(format!(
            "this node does not hold blob {address} for {path:?}"
        )),
        other => Verdict::unavailable(format!("cannot read blob {address} for {path:?}: {other}")),
    })
}

/// Read every blob a manifest names, refusing as soon as the running total
/// passes `max_bytes` rather than after allocating all of it.
fn contents(
    registry: &VerifierRegistry,
    files: &BTreeMap<String, String>,
    max_bytes: i64,
    over: impl Fn(String) -> Verdict,
) -> Result<Vec<(String, Vec<u8>)>, Verdict> {
    let mut total: u64 = 0;
    let mut out = Vec::with_capacity(files.len());
    for (path, address) in files {
        let bytes = blob(registry, path, address)?;
        total = total.saturating_add(bytes.len() as u64);
        if total > max_bytes as u64 {
            return Err(over(format!("more than {max_bytes} bytes")));
        }
        out.push((path.clone(), bytes));
    }
    Ok(out)
}

/// Make every ancestor of `relative` a real directory under `tree`, refusing
/// to traverse anything else. A symlink left by `prepare_command` would
/// otherwise steer the unjailed parent's writes outside the tree.
fn ensure_parents(tree: &Path, relative: &str) -> Result<PathBuf, String> {
    let parts: Vec<&str> = relative.split('/').collect();
    let mut at = tree.to_path_buf();
    for part in &parts[..parts.len().saturating_sub(1)] {
        at.push(part);
        match fs::symlink_metadata(&at) {
            Ok(meta) if meta.file_type().is_dir() => {}
            Ok(_) => return Err(format!("{} is not a directory", at.display())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&at).map_err(|error| error.to_string())?;
            }
            Err(error) => return Err(error.to_string()),
        }
    }
    Ok(tree.join(relative))
}

/// Write one file, refusing to follow or replace anything already there.
fn write_new(tree: &Path, relative: &str, bytes: &[u8]) -> Result<(), String> {
    let full = ensure_parents(tree, relative)?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&full)
        .map_err(|error| format!("{}: {error}", full.display()))?;
    file.write_all(bytes).map_err(|error| error.to_string())
}

/// Remove an editable path from the tree without following a symlink.
fn remove(tree: &Path, relative: &str) -> Result<(), String> {
    let mut at = tree.to_path_buf();
    let parts: Vec<&str> = relative.split('/').collect();
    for (index, part) in parts.iter().enumerate() {
        at.push(part);
        let meta = match fs::symlink_metadata(&at) {
            Ok(meta) => meta,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.to_string()),
        };
        let last = index + 1 == parts.len();
        if !last && !meta.file_type().is_dir() {
            // An ancestor is a file or a link: nothing of ours lies beneath it.
            return Err(format!("{} is not a directory", at.display()));
        }
        if last {
            return if meta.file_type().is_dir() {
                fs::remove_dir_all(&at).map_err(|error| error.to_string())
            } else {
                fs::remove_file(&at).map_err(|error| error.to_string())
            };
        }
    }
    Ok(())
}

/// What a phase's command did.
enum Ran {
    Exited(Option<i32>),
    /// Could not run or did not finish. Never evidence about the artifact.
    Failed(String),
}

impl VerifierRegistry {
    fn run_phase(&self, phase: &str, argv: &[String], tree: &Path, timeout: Duration) -> Ran {
        let Some(program) = argv.first() else {
            return Ran::Failed(format!("{phase} command is empty"));
        };
        let Some(resolved) = which(program) else {
            return Ran::Failed(format!(
                "{phase} command '{program}' is not on PATH; this node cannot run it"
            ));
        };
        let scratch = match TempDir::new("cairn-workspace-scratch") {
            Ok(scratch) => scratch,
            Err(error) => {
                return Ran::Failed(format!("cannot create a scratch directory: {error}"))
            }
        };
        let rest = sandbox::argv(argv.get(1..).unwrap_or(&[]));
        let plan = Confinement::new(scratch.path(), tree, timeout.as_secs())
            .reading(&resolved)
            .reading(&self.root)
            .writing(tree)
            .scrubbed();
        let jailed = match sandbox::confine(&resolved, &rest, &plan) {
            Ok(jailed) => jailed,
            Err(sandbox::Unavailable(why)) => {
                return Ran::Failed(format!("cannot jail the {phase} command: {why}"))
            }
        };
        let mut command = jailed.command;
        match run_bounded(&mut command, scratch.path(), None, timeout, plan.limits()) {
            Ok(completed) => Ran::Exited(completed.code),
            Err(RunFailure::TimedOut(throttled)) => Ran::Failed(format!(
                "{phase} exceeded {}s{}; a timeout is not a refutation",
                timeout.as_secs(),
                RunFailure::throttle_note(throttled)
            )),
            Err(RunFailure::Spawn(error)) | Err(RunFailure::Io(error)) => {
                Ran::Failed(format!("cannot run the {phase} command: {error}"))
            }
        }
    }

    /// Workspace verification. See the module documentation.
    ///
    /// Spec: `{kind, base, base_sha256, editable_paths, prepare_command?,
    /// score_command, score_path, max_files?, max_bytes?, timeout_seconds?}`.
    pub(super) fn verify_workspace(&self, spec: &Value, artifact: &Value) -> Verdict {
        let spec = match parse_spec(spec) {
            Ok(spec) => spec,
            Err(verdict) => return verdict,
        };

        // The base manifest: a pinned file, so a tampered one is the
        // objective's fault and an absent one is this node's.
        let manifest_path = match self.pinned("base manifest", &spec.base, &spec.base_sha256) {
            Ok(path) => path,
            Err(verdict) => return verdict,
        };
        let text = match fs::read(&manifest_path) {
            Ok(bytes) => bytes,
            Err(error) => {
                return Verdict::unavailable(format!("cannot read the base manifest: {error}"))
            }
        };
        let base = match std::str::from_utf8(&text)
            .map_err(|error| error.to_string())
            .and_then(|text| Value::from_json(text).map_err(|error| error.to_string()))
        {
            Ok(base) => base,
            Err(why) => {
                return Verdict::invalid_spec(format!("base manifest is not canonical JSON: {why}"))
            }
        };
        let base_files = match manifest(
            base.get("files").unwrap_or(&Value::Null),
            "base manifest",
            Verdict::invalid_spec,
        ) {
            Ok(files) => files,
            Err(verdict) => return verdict,
        };
        if base_files.len() as u64 > spec.max_files as u64 {
            return Verdict::invalid_spec(format!(
                "base manifest has {} files, more than max_files {}",
                base_files.len(),
                spec.max_files
            ));
        }

        // The artifact: everything wrong with it from here on is a `Reject`.
        let submitted = match manifest(
            artifact.get("files").unwrap_or(&Value::Null),
            "artifact",
            Verdict::reject,
        ) {
            Ok(files) => files,
            Err(verdict) => return verdict,
        };
        if submitted.len() as u64 > spec.max_files as u64 {
            return Verdict::reject(format!(
                "artifact has {} files, more than max_files {}",
                submitted.len(),
                spec.max_files
            ));
        }
        let editable: Vec<Vec<&str>> = spec
            .editable
            .iter()
            .map(|path| path.split('/').collect())
            .collect();
        for path in submitted.keys() {
            let parts: Vec<&str> = path.split('/').collect();
            if !editable.iter().any(|prefix| within(&parts, prefix)) {
                return Verdict::reject(format!(
                    "artifact writes {path:?}, which is outside editable_paths"
                ));
            }
        }
        let claimed = match artifact
            .get("results")
            .and_then(|results| results.get("score"))
            .and_then(Value::as_i64)
        {
            Some(claimed) => claimed,
            None => return Verdict::reject("artifact has no integer results.score"),
        };

        let base_bytes = match contents(self, &base_files, spec.max_bytes, |why| {
            Verdict::invalid_spec(format!("base tree has {why} (max_bytes)"))
        }) {
            Ok(bytes) => bytes,
            Err(verdict) => return verdict,
        };
        let submitted_bytes = match contents(self, &submitted, spec.max_bytes, |why| {
            Verdict::reject(format!("artifact has {why} (max_bytes)"))
        }) {
            Ok(bytes) => bytes,
            Err(verdict) => return verdict,
        };

        // Phase 1: the base tree, alone.
        let tree = match TempDir::new("cairn-workspace") {
            Ok(tree) => tree,
            Err(error) => {
                return Verdict::unavailable(format!("cannot create a working tree: {error}"))
            }
        };
        for (path, bytes) in &base_bytes {
            if let Err(why) = write_new(tree.path(), path, bytes) {
                return Verdict::unavailable(format!("cannot materialize the base tree: {why}"));
            }
        }
        // Fail fast on a missing scorer, before spending a build on it.
        if let Some(program) = spec.score.first() {
            if which(program).is_none() {
                return Verdict::unavailable(format!(
                    "score command '{program}' is not on PATH; this node cannot run it"
                ));
            }
        }
        if let Some(prepare) = &spec.prepare {
            match self.run_phase("prepare", prepare, tree.path(), self.bounded(spec.timeout)) {
                Ran::Exited(Some(0)) => {}
                Ran::Exited(code) => {
                    return Verdict::unavailable(format!(
                        "prepare exited {} on the base tree, before any submission was \
                         applied; that is not evidence about the artifact",
                        code.map_or_else(|| "on a signal".to_string(), |code| code.to_string())
                    ))
                }
                Ran::Failed(why) => return Verdict::unavailable(why),
            }
        }

        // Phase 2: the editable paths become the submission's, and only its.
        for path in &spec.editable {
            if let Err(why) = remove(tree.path(), path) {
                return Verdict::invalid_spec(format!("prepare left {path:?} unremovable: {why}"));
            }
        }
        for (path, bytes) in &submitted_bytes {
            if let Err(why) = write_new(tree.path(), path, bytes) {
                return Verdict::invalid_spec(format!(
                    "cannot apply {path:?} over the prepared tree: {why}"
                ));
            }
        }

        // Phase 3: score it.
        match self.run_phase(
            "score",
            &spec.score,
            tree.path(),
            self.bounded(spec.timeout),
        ) {
            Ran::Exited(Some(0)) => {}
            Ran::Exited(code) => {
                return Verdict::reject(format!(
                    "score command exited {} on the submission; the toolchain already \
                     ran on the base tree",
                    code.map_or_else(|| "on a signal".to_string(), |code| code.to_string())
                ))
            }
            Ran::Failed(why) => return Verdict::unavailable(why),
        }

        let observed = match read_score(tree.path(), &spec.score_path) {
            Ok(observed) => observed,
            Err(why) => return Verdict::reject(why),
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
}

/// Read the integer score the scored run left behind.
///
/// The scored run executed submission code, which can leave a symlink where the
/// score file should be. The path is resolved and must stay inside the tree,
/// and must end at a regular file, before this unjailed process opens it.
fn read_score(tree: &Path, score_path: &str) -> Result<i64, String> {
    let full = tree.join(score_path);
    let canonical_tree = fs::canonicalize(tree).map_err(|error| error.to_string())?;
    let canonical =
        fs::canonicalize(&full).map_err(|_| format!("the scored run left no {score_path}"))?;
    if !canonical.starts_with(&canonical_tree) {
        return Err(format!("{score_path} resolves outside the tree"));
    }
    let meta = fs::symlink_metadata(&canonical).map_err(|error| error.to_string())?;
    if !meta.file_type().is_file() {
        return Err(format!("{score_path} is not a regular file"));
    }
    if meta.len() > MAX_SCORE_FILE_BYTES {
        return Err(format!(
            "{score_path} is larger than {MAX_SCORE_FILE_BYTES} bytes"
        ));
    }
    let text = fs::read_to_string(&canonical).map_err(|error| error.to_string())?;
    let value = Value::from_json(text.trim())
        .map_err(|error| format!("{score_path} is not canonical JSON: {error}"))?;
    value
        .get("score")
        .and_then(Value::as_i64)
        .ok_or_else(|| format!("{score_path} has no integer 'score'"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_rules_refuse_every_way_out_of_the_tree() {
        for bad in [
            "",
            "/etc/passwd",
            "a//b",
            "a/./b",
            "../x",
            "a/..",
            "a\\b",
            ".git/config",
            "src/.git",
            "a/",
            "a\0b",
        ] {
            assert!(path_components(bad).is_err(), "{bad:?} was admitted");
        }
        assert_eq!(path_components("src/point_add/mod.rs").unwrap().len(), 3);
    }

    #[test]
    fn within_is_component_wise() {
        assert!(within(&["src", "a", "b"], &["src", "a"]));
        assert!(within(&["src", "a"], &["src", "a"]));
        assert!(!within(&["src", "ab"], &["src", "a"]));
        assert!(!within(&["src"], &["src", "a"]));
    }

    #[test]
    fn a_path_cannot_be_both_a_file_and_a_directory() {
        let files = ["a/b", "a/b/c"];
        assert!(collision(files.iter().copied()).is_some());
        let files = ["a/b", "a/b-x", "a/b/c"];
        assert!(
            collision(files.iter().copied()).is_some(),
            "sorting put a/b-x between"
        );
        let files = ["a/b", "a/bc"];
        assert!(collision(files.iter().copied()).is_none());
    }
}
