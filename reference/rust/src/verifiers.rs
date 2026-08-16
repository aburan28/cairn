//! Pinned verifiers: `certificate`, `evaluator`, `statistical`, `replay`, `lean`.
//!
//! Every kind the primary implementation settles, so that a claim it settled
//! can be re-derived here rather than skipped. A kind missing from this list
//! answers `Unavailable`, which settles nothing and is correct -- and is
//! exactly how a kind can end up with no cross-implementation coverage while
//! every audit reports success. `every_kind_the_primary_settles_is_implemented_here`
//! is the test that stops the list going stale.
//!
//! A verifier is objective-authored code pinned by SHA-256. The hash is
//! checked *before* the code runs, so editing a checker does not silently
//! rescore work already done against it -- it forks the objective.
//!
//! Two statuses settle and two do not, and the distinction is load-bearing:
//! **`unavailable` is never `reject`.** A missing toolchain or a crashed
//! checker is a fact about this node, not about the artifact. Collapsing them
//! would let an attacker fail every honest submission by taking verifiers
//! offline.

use std::path::{Component, Path, PathBuf};
use std::process::Command;

use sha2::{Digest as _, Sha256};

use crate::canonical::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Accept,
    Reject,
    Unavailable,
    InvalidSpec,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Accept => "accept",
            Status::Reject => "reject",
            Status::Unavailable => "unavailable",
            Status::InvalidSpec => "invalid_spec",
        }
    }

    pub fn parse(text: &str) -> Option<Status> {
        match text {
            "accept" => Some(Status::Accept),
            "reject" => Some(Status::Reject),
            "unavailable" => Some(Status::Unavailable),
            "invalid_spec" => Some(Status::InvalidSpec),
            _ => None,
        }
    }

    /// Only accept and reject move money or close an objective.
    pub fn settles(self) -> bool {
        matches!(self, Status::Accept | Status::Reject)
    }
}

#[derive(Debug, Clone)]
pub struct Verdict {
    pub status: Status,
    pub detail: String,
    pub evidence: Value,
}

impl Verdict {
    pub fn new(status: Status, detail: impl Into<String>, evidence: Value) -> Verdict {
        Verdict {
            status,
            detail: detail.into(),
            evidence,
        }
    }

    fn plain(status: Status, detail: impl Into<String>) -> Verdict {
        Verdict::new(status, detail, Value::object(Vec::<(String, Value)>::new()))
    }

    pub fn accepted(&self) -> bool {
        self.status == Status::Accept
    }

    pub fn score(&self) -> Option<i64> {
        self.evidence.get("score").and_then(Value::as_i64)
    }

    pub fn to_value(&self) -> Value {
        Value::object([
            ("status", Value::string(self.status.as_str())),
            ("detail", Value::string(self.detail.clone())),
            ("evidence", self.evidence.clone()),
        ])
    }

    pub fn from_value(value: &Value) -> Option<Verdict> {
        Some(Verdict {
            status: Status::parse(value.get("status")?.as_str()?)?,
            detail: value
                .get("detail")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            evidence: value
                .get("evidence")
                .cloned()
                .unwrap_or_else(|| Value::object(Vec::<(String, Value)>::new())),
        })
    }
}

/// Where a node keeps blobs it obtained by content address.
///
/// The same relative location the primary uses, because it is the same
/// directory on the same disk -- this crate is a second reader of one node's
/// state, not a second node.
const BLOB_STORE: &str = ".proofwork/blobs";

/// Resolve a pinned path against the bundle root and check its hash.
///
/// Containment first, then the hash. A pin whose path leaves the bundle is a
/// malformed objective and content-addressing must not rescue it: otherwise an
/// objective could name `../../.ssh/id_rsa` and start resolving the day
/// somebody's node happened to hold a blob at that address.
///
/// # The bundle, then the blob store
///
/// The bundle file is consulted first so that an operator who edits a checker
/// in place is told their edit no longer matches the pin, rather than having a
/// cached blob silently stand in for the file they are looking at.
///
/// The fallback is not an optimization. A node that learned an objective over
/// the wire has **no bundle at all** -- it has the log and a blob it fetched by
/// hash -- and that is the normal state of every peer that did not author the
/// objective. Without this, auditing such a node reported *"was settled but can
/// no longer be re-verified"* for claims that re-verify perfectly, which is the
/// independent check failing on exactly the nodes that most need one. Found by
/// running two `proofwork-p2p` daemons and auditing the one that synced.
///
/// Containment does not apply to the store: its filenames are hashes, not
/// paths, and the hash check below is what makes a fetched blob admissible.
fn pinned(root: &Path, relative: &str, declared: &str) -> Result<PathBuf, Verdict> {
    let root = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let joined = normalize(&root.join(relative));
    if !joined.starts_with(&root) {
        return Err(Verdict::plain(
            Status::InvalidSpec,
            format!("pinned path escapes the objective root: {relative}"),
        ));
    }
    let (joined, source) = match std::fs::read(&joined) {
        Ok(source) => (joined, source),
        Err(bundle_error) => {
            let blob = root.join(BLOB_STORE).join(declared);
            match std::fs::read(&blob) {
                Ok(source) => (blob, source),
                // Cannot read is a fact about this node, not about the
                // artifact. Both places are named: an operator staring at this
                // needs to know the store was tried too.
                Err(store_error) => {
                    return Err(Verdict::plain(
                        Status::Unavailable,
                        format!(
                            "cannot load pinned code {relative}: {bundle_error}; \
                             and no blob {declared} in {BLOB_STORE}: {store_error}"
                        ),
                    ))
                }
            }
        }
    };
    let mut hasher = Sha256::new();
    hasher.update(&source);
    let actual: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if actual != declared {
        return Err(Verdict::plain(
            Status::InvalidSpec,
            format!("pinned code {relative} has sha256 {actual}, objective declares {declared}"),
        ));
    }
    Ok(joined)
}

/// Lexical normalization -- never `canonicalize`, which resolves symlinks and
/// so would let a link inside the bundle change what containment means.
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if matches!(out.components().next_back(), Some(Component::Normal(_))) {
                    out.pop();
                } else {
                    out.push("..");
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn required<'a>(spec: &'a Value, name: &str) -> Result<&'a str, Verdict> {
    spec.get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| Verdict::plain(Status::InvalidSpec, format!("missing spec field {name:?}")))
}

/// Run a pinned entrypoint and read back what it returned.
///
/// A subprocess rather than anything in-process. This crate audits logs whose
/// objectives were written by strangers; the primary implementation jails the
/// same call, and this one is documented as the weaker of the two rather than
/// pretending otherwise.
fn run_pinned(path: &Path, entrypoint: &str, artifact: &Value) -> Result<Value, Verdict> {
    run_pinned_seeded(path, entrypoint, artifact, None)
}

fn run_pinned_seeded(
    path: &Path,
    entrypoint: &str,
    artifact: &Value,
    seed: Option<i64>,
) -> Result<Value, Verdict> {
    const DRIVER: &str = r#"
import json, sys, importlib.machinery, importlib.util
# The loader is named rather than inferred from the extension: a blob's
# filename is its hash, so it never ends in `.py`, and `spec_from_file_location`
# returns None for an extension it does not recognise. Without this the
# content-addressed fallback -- the whole reason a blob store exists -- cannot
# load a checker a node fetched from a peer.
loader = importlib.machinery.SourceFileLoader("pinned", sys.argv[1])
spec = importlib.util.spec_from_file_location("pinned", sys.argv[1], loader=loader)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
artifact = json.loads(sys.stdin.read())
func = getattr(module, sys.argv[2])
# A third argument is the statistical kind's pinned seed, passed as a second
# parameter. argv-carried rather than folded into the artifact, because the
# seed belongs to the objective and the artifact belongs to the submitter --
# merging them would let a submitter choose the seed.
seed = int(sys.argv[3]) if len(sys.argv) > 3 else None
print(json.dumps({"ok": func(artifact) if seed is None else func(artifact, seed)}))
"#;
    let mut args: Vec<String> = vec![
        String::from("-c"),
        String::from(DRIVER),
        path.to_string_lossy().into_owned(),
        entrypoint.to_string(),
    ];
    if let Some(seed) = seed {
        args.push(seed.to_string());
    }
    let mut child = Command::new("python3")
        .args(&args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|error| {
            Verdict::plain(Status::Unavailable, format!("cannot run python3: {error}"))
        })?;
    {
        use std::io::Write as _;
        let stdin = child.stdin.as_mut().expect("piped");
        stdin
            .write_all(artifact.canonical_string().as_bytes())
            .map_err(|e| {
                Verdict::plain(Status::Unavailable, format!("cannot send artifact: {e}"))
            })?;
    }
    let output = child
        .wait_with_output()
        .map_err(|e| Verdict::plain(Status::Unavailable, format!("verifier failed: {e}")))?;
    if !output.status.success() {
        return Err(Verdict::plain(
            Status::Unavailable,
            format!(
                "pinned code raised: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        ));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let parsed = Value::from_json(text.trim())
        .map_err(|e| Verdict::plain(Status::Unavailable, format!("verifier output: {e}")))?;
    parsed
        .get("ok")
        .cloned()
        .ok_or_else(|| Verdict::plain(Status::Unavailable, "verifier returned nothing".to_string()))
}

/// Every kind this crate can verify.
///
/// One list, because two lists become two different lists. There used to be a
/// second one in `node.rs` deciding which objectives could be *posted*, and it
/// still named only `certificate` and `evaluator` long after three more kinds
/// were implemented -- so this crate could verify a kind it refused to accept,
/// and the interop script could only ever drive those kinds in one direction.
pub const KINDS: &[&str] = &["certificate", "evaluator", "statistical", "replay", "lean"];

pub fn implements(kind: &str) -> bool {
    KINDS.contains(&kind)
}

pub fn run(root: &Path, spec: &Value, artifact: &Value) -> Verdict {
    match spec.get("kind").and_then(Value::as_str) {
        Some("certificate") => certificate(root, spec, artifact),
        Some("evaluator") => evaluator(root, spec, artifact),
        Some("statistical") => statistical(root, spec, artifact),
        Some("replay") => replay(root, spec, artifact),
        Some("lean") => lean(root, spec, artifact),
        // An unknown kind says nothing about the artifact: another node may
        // well implement it.
        Some(other) => Verdict::plain(
            Status::Unavailable,
            format!("no verifier registered for kind {other:?}"),
        ),
        None => Verdict::plain(Status::InvalidSpec, "verifier spec needs a 'kind'"),
    }
}

fn certificate(root: &Path, spec: &Value, artifact: &Value) -> Verdict {
    let (checker, declared, entrypoint) = match (
        required(spec, "checker"),
        required(spec, "checker_sha256"),
        required(spec, "entrypoint"),
    ) {
        (Ok(a), Ok(b), Ok(c)) => (a, b, c),
        (Err(v), _, _) | (_, Err(v), _) | (_, _, Err(v)) => return v,
    };
    let path = match pinned(root, checker, declared) {
        Ok(path) => path,
        Err(verdict) => return verdict,
    };
    let outcome = match run_pinned(&path, entrypoint, artifact) {
        Ok(outcome) => outcome,
        Err(verdict) => return verdict,
    };
    let evidence = Value::object([("checker_sha256", Value::string(declared))]);
    match outcome {
        Value::Bool(true) => Verdict::new(Status::Accept, "checker accepted", evidence),
        Value::Bool(false) => Verdict::new(Status::Reject, "checker rejected", evidence),
        // `(bool, detail)` is the shipped checkers' richer form.
        Value::Array(pair) if pair.len() == 2 => {
            let detail = pair[1].as_str().unwrap_or_default().to_string();
            match pair[0] {
                Value::Bool(true) => Verdict::new(Status::Accept, detail, evidence),
                Value::Bool(false) => Verdict::new(Status::Reject, detail, evidence),
                _ => Verdict::plain(Status::Unavailable, "checker returned a non-boolean"),
            }
        }
        _ => Verdict::plain(Status::Unavailable, "checker returned a non-boolean"),
    }
}

/// Tokens that disqualify a Lean proof before the kernel is ever asked.
///
/// Each is a hole or a trust escalation, and screening is cheap while running
/// Lean is not. `(token, whole_word, why)`; `@[implemented_by` is matched as a
/// bare substring because `[` is not a word character.
const SCREENS: &[(&str, bool, &str)] = &[
    (
        "sorry",
        true,
        "contains `sorry`: an explicit hole, proves nothing",
    ),
    (
        "admit",
        true,
        "contains `admit`: an explicit hole, proves nothing",
    ),
    (
        "axiom",
        true,
        "declares an axiom: adds a trusted assumption",
    ),
    (
        "@[implemented_by",
        false,
        "uses `@[implemented_by]`: replaces a definition with unverified code",
    ),
];

/// Screened unless the objective explicitly opts in.
const NATIVE_DECIDE: (&str, bool, &str) = (
    "native_decide",
    true,
    "uses `native_decide`: trusts the compiler, not the kernel",
);

/// A per-process-unique suffix for a scratch directory.
///
/// Not a hash of the input: two verifications running at once with the same
/// source would collide, and the loser's directory is deleted out from under it
/// on the winner's cleanup. A counter cannot repeat within a process, and the
/// pid separates processes.
fn next_scratch() -> u64 {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
}

/// Whole-word containment, by hand.
///
/// No regex crate here, and that is the right call twice over: this is a
/// second opinion that should share as few dependencies as possible with the
/// primary, and a regex engine pointed at submitter-controlled text is itself
/// an attack surface.
///
/// A word byte is ASCII alphanumeric or `_`; anything above 0x7f counts as
/// *non*-word. That can only make a screen fire more often, never less, which
/// is the safe direction: an over-eager screen rejects a proof that can be
/// rewritten, an under-eager one accepts a `sorry` and mints money.
fn contains_word(text: &str, token: &str) -> bool {
    let (bytes, needle) = (text.as_bytes(), token.as_bytes());
    let word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let mut at = 0;
    while let Some(found) = text[at..].find(token) {
        let start = at + found;
        let end = start + needle.len();
        let before_ok = start == 0 || !word(bytes[start - 1]);
        let after_ok = end == bytes.len() || !word(bytes[end]);
        if before_ok && after_ok {
            return true;
        }
        at = start + 1;
        if at >= text.len() {
            break;
        }
    }
    false
}

/// A Lean kernel accepted the proof.
///
/// The last kind this crate could not check. Spawning a toolchain adds no
/// dependency -- it already spawns `python3` -- so "needs Lean" was never a
/// reason to leave the gap, only a reason a node without Lean answers
/// `Unavailable`, which is correct and now visible rather than silent.
///
/// **No jail here**, as with `replay`, and the warning is the same: Lean
/// elaboration runs arbitrary code through macros and `#eval`, half the input
/// is submitter-controlled, and this crate is an opinion on the rules rather
/// than a hardened node.
///
/// The verdict rules are the format and are all kept. The one that is easy to
/// get backwards: a **non-zero exit is a real `Reject`**, uniquely here,
/// because the exit code *is* the kernel's answer. Everywhere else in this
/// crate a non-zero exit is infrastructure and settles nothing. And a *clean*
/// exit is not sufficient -- Lean warns rather than errors when a declaration
/// depends on `sorryAx`, so the output is searched for it.
fn lean(root: &Path, spec: &Value, artifact: &Value) -> Verdict {
    let binary = std::env::var("PROOFWORK_LEAN").unwrap_or_else(|_| String::from("lean"));
    lean_using(&binary, root, spec, artifact)
}

/// `lean`, with the toolchain named explicitly.
///
/// Split out so the tests can drive every verdict branch -- including "no
/// toolchain" and "the kernel said no" -- without touching a process-global
/// environment variable that a concurrently running test would race on.
fn lean_using(binary: &str, root: &Path, spec: &Value, artifact: &Value) -> Verdict {
    let Some(statement) = spec
        .get("statement")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
    else {
        return Verdict::plain(Status::InvalidSpec, "lean spec needs a 'statement'");
    };
    let Some(proof) = artifact
        .get("proof")
        .and_then(Value::as_str)
        .filter(|p| !p.trim().is_empty())
    else {
        return Verdict::plain(Status::Reject, "artifact has no 'proof' text");
    };

    // Fails closed: only an explicit `true` opts in, so a malformed spec gets
    // the *stricter* treatment rather than a looser one.
    let allow_native_decide = matches!(spec.get("allow_native_decide"), Some(Value::Bool(true)));
    let mut screens: Vec<&(&str, bool, &str)> = SCREENS.iter().collect();
    if !allow_native_decide {
        screens.push(&NATIVE_DECIDE);
    }
    for (token, whole_word, why) in screens {
        let hit = if *whole_word {
            contains_word(proof, token)
        } else {
            proof.contains(token)
        };
        if hit {
            return Verdict::plain(Status::Reject, *why);
        }
    }

    // Attacker-authored, and the primary hands it to the jail as a *writable*
    // bind -- so unconfined, `"/"` would be a pass-through of the filesystem.
    // Screened before the toolchain lookup: a malformed spec is malformed
    // whether or not this node has Lean.
    let canonical_root = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let project_cwd = match spec.get("project_root").and_then(Value::as_str) {
        Some(relative) if !relative.is_empty() => {
            let joined = normalize(&canonical_root.join(relative));
            if !joined.starts_with(&canonical_root) {
                return Verdict::plain(
                    Status::InvalidSpec,
                    format!("project_root escapes the objective root: {relative}"),
                );
            }
            Some(joined)
        }
        _ => None,
    };

    let preamble = spec.get("preamble").and_then(Value::as_str).unwrap_or("");
    let source = format!("{preamble}\n{statement} {proof}\n");

    let dir = std::env::temp_dir().join(format!(
        "proofwork-reference-lean-{}-{}",
        std::process::id(),
        next_scratch()
    ));
    if std::fs::create_dir_all(&dir).is_err() {
        return Verdict::plain(Status::Unavailable, "cannot create a working directory");
    }
    let claim = dir.join("Claim.lean");
    if std::fs::write(&claim, source.as_bytes()).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Verdict::plain(Status::Unavailable, "cannot write the Lean source");
    }
    let cwd = project_cwd.unwrap_or_else(|| dir.clone());

    let output = Command::new(binary).arg(&claim).current_dir(&cwd).output();
    let _ = std::fs::remove_dir_all(&dir);
    let output = match output {
        Ok(output) => output,
        // No toolchain is a fact about this node, never about the proof.
        Err(error) => {
            return Verdict::plain(
                Status::Unavailable,
                format!("'{binary}' not on PATH ({error}); install a Lean toolchain to verify"),
            )
        }
    };

    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let evidence = Value::object([(
        "returncode",
        match output.status.code() {
            Some(code) => Value::Int(i128::from(code)),
            None => Value::Null,
        },
    )]);
    match output.status.code() {
        // The one place a non-zero exit is a verdict: it is the kernel's answer.
        Some(code) if code != 0 => {
            Verdict::new(Status::Reject, "lean rejected the proof", evidence)
        }
        // Killed by a signal -- OOM, or an operator. A fact about this node.
        None => Verdict::new(
            Status::Unavailable,
            "lean was killed by a signal; that is a fact about this node, not the proof",
            evidence,
        ),
        // Lean *warns* rather than errors on a declaration that depends on
        // `sorryAx`, so a clean exit code is not sufficient on its own.
        Some(_) if text.contains("declaration uses 'sorry'") => {
            Verdict::new(Status::Reject, "proof depends on sorryAx", evidence)
        }
        Some(_) => Verdict::new(Status::Accept, "kernel accepted the proof", evidence),
    }
}

/// Fields a `replay` objective may never declare reproducible.
///
/// A timing or a memory figure measures the *host*, not the computation. Two
/// honest nodes replaying the same command get different numbers, so declaring
/// one reproducible turns every re-run into a refutation of work that was fine.
/// Matched as substrings and case-insensitively, so `wall_time_ms` and
/// `PeakRSS` are both caught.
const TIME_LIKE: &[&str] = &[
    "time",
    "seconds",
    "duration",
    "elapsed",
    "latency",
    "throughput",
    "memory",
    "rss",
    "flops",
    "timestamp",
    "date",
];

fn machine_dependent(field: &str) -> bool {
    let lowered = field.to_ascii_lowercase();
    TIME_LIKE.iter().any(|token| lowered.contains(token))
}

/// Re-run a pinned computation and compare its declared fields.
///
/// The third kind this crate could not check, and the third to answer
/// `Unavailable` for every claim while the audit reported full coverage. That
/// composition is now loud rather than silent, but the coverage still has to
/// exist.
///
/// **No jail here, deliberately.** The primary confines this command --
/// bubblewrap or seatbelt, read-only `cwd`, a wall-clock bound -- because it
/// runs objective-authored code on a node that verifies strangers' work. This
/// crate is an independent opinion on the *rules*, not a hardened node, and
/// `verifiers.rs` says so at the top. Do not point it at an objective you have
/// not read.
///
/// What it does keep is every rule that decides a *verdict*, because those are
/// the format:
///
/// * A machine-dependent declared field is a spec defect, not a rejection.
/// * `cwd` resolves against the objective root and may not escape it.
/// * A command that cannot run, times out, exits non-zero, prints
///   non-JSON, or omits a declared field is `Unavailable` -- an infrastructure
///   fact is never evidence about an artifact.
/// * Only a value that *differs* is a `Reject`.
fn replay(root: &Path, spec: &Value, artifact: &Value) -> Verdict {
    let Some(parts) = spec.get("command").and_then(Value::as_array) else {
        return Verdict::plain(Status::InvalidSpec, "command must be a list of strings");
    };
    let mut command_parts: Vec<&str> = Vec::with_capacity(parts.len());
    for part in parts {
        match part.as_str() {
            Some(text) => command_parts.push(text),
            None => {
                return Verdict::plain(Status::InvalidSpec, "command must be a list of strings")
            }
        }
    }
    let Some(program) = command_parts.first().copied() else {
        return Verdict::plain(
            Status::InvalidSpec,
            "command must be a non-empty list of strings",
        );
    };

    let fields = match spec.get("reproducible_fields").and_then(Value::as_array) {
        Some(fields) if !fields.is_empty() => fields,
        _ => return Verdict::plain(Status::InvalidSpec, "reproducible_fields must be non-empty"),
    };
    let mut declared: Vec<&str> = Vec::with_capacity(fields.len());
    let mut bad: Vec<String> = Vec::new();
    for field in fields {
        match field.as_str() {
            Some(name) if !machine_dependent(name) => declared.push(name),
            Some(name) => bad.push(format!("'{name}'")),
            None => bad.push(field.canonical_string()),
        }
    }
    if !bad.is_empty() {
        return Verdict::plain(
            Status::InvalidSpec,
            format!(
                "machine-dependent fields cannot be reproducible: [{}]. \
                 Timings and memory measure the host, not the computation.",
                bad.join(", ")
            ),
        );
    }

    // The same containment the pinned paths get: an objective naming
    // `../../..` would otherwise read any directory the operator can.
    let relative = spec.get("cwd").and_then(Value::as_str).unwrap_or(".");
    let canonical_root = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let cwd = normalize(&canonical_root.join(relative));
    if !cwd.starts_with(&canonical_root) || !cwd.is_dir() {
        return Verdict::plain(
            Status::InvalidSpec,
            format!("cwd escapes the objective root: {relative}"),
        );
    }

    let output = match Command::new(program)
        .args(command_parts.get(1..).unwrap_or(&[]))
        .current_dir(&cwd)
        .output()
    {
        Ok(output) => output,
        Err(error) => {
            return Verdict::plain(
                Status::Unavailable,
                format!("cannot run replay command '{program}': {error}"),
            )
        }
    };
    if !output.status.success() {
        return Verdict::plain(
            Status::Unavailable,
            "replay command exited non-zero; infrastructure failure is not evidence \
             about the artifact",
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let Ok(parsed) = Value::from_json(stdout.trim()) else {
        return Verdict::plain(Status::Unavailable, "replay output is not JSON");
    };
    let Value::Object(observed) = parsed else {
        return Verdict::plain(Status::Unavailable, "replay output is not a JSON object");
    };
    let Some(Value::Object(claimed)) = artifact.get("results") else {
        return Verdict::plain(Status::Reject, "artifact has no 'results' object");
    };

    let mut mismatches = Vec::new();
    let mut reproduced = Vec::new();
    for name in &declared {
        let Some(seen) = observed.get(*name) else {
            // The objective declared a field its own command does not print.
            // Nothing was compared, so nothing is settled.
            return Verdict::plain(
                Status::Unavailable,
                format!("replay output is missing declared field '{name}'"),
            );
        };
        let claim = claimed.get(*name).cloned().unwrap_or(Value::Null);
        if &claim == seen {
            reproduced.push(((*name).to_string(), seen.clone()));
        } else {
            mismatches.push((
                (*name).to_string(),
                Value::object([("claimed", claim), ("observed", seen.clone())]),
            ));
        }
    }

    if !mismatches.is_empty() {
        let mut map = std::collections::BTreeMap::new();
        for (k, v) in mismatches {
            map.insert(k, v);
        }
        return Verdict::new(
            Status::Reject,
            "replay disagrees with the claim",
            Value::object([("mismatches", Value::Object(map))]),
        );
    }
    let mut map = std::collections::BTreeMap::new();
    for (k, v) in reproduced {
        map.insert(k, v);
    }
    Verdict::new(
        Status::Accept,
        format!("replay reproduced {} declared field(s)", declared.len()),
        Value::object([("reproduced", Value::Object(map))]),
    )
}

/// A pinned, seeded test statistic clearing a threshold.
///
/// The kind this crate silently could not check. `run` answered `Unavailable`
/// for it, which is the *correct* answer for a kind an implementation does not
/// implement -- `Unavailable` is never `Reject` -- and the audit skips
/// non-settling statuses, so an objective of this kind settled by the primary
/// passed every cross-implementation check without ever being re-derived.
/// Correct behaviour composing into no coverage at all.
///
/// Two things differ from `evaluator` and both are load-bearing:
///
/// * The pinned file is named by `statistic.path` / `statistic.sha256` rather
///   than a flat pair, because the seed belongs with it.
/// * The seed is passed to the entrypoint as a second parameter and comes from
///   the **objective**, never the artifact. Resampling until a statistic passes
///   is the attack this forecloses, and a submitter who could choose the seed
///   would choose a passing one.
fn statistical(root: &Path, spec: &Value, artifact: &Value) -> Verdict {
    let Some(statistic) = spec.get("statistic") else {
        return Verdict::plain(
            Status::InvalidSpec,
            "statistical spec needs a 'statistic' object with 'path' and 'sha256'",
        );
    };
    let (path_text, declared, entrypoint) = match (
        required(statistic, "path"),
        required(statistic, "sha256"),
        required(spec, "entrypoint"),
    ) {
        (Ok(a), Ok(b), Ok(c)) => (a, b, c),
        (Err(v), _, _) | (_, Err(v), _) | (_, _, Err(v)) => return v,
    };
    let Some(threshold) = spec.get("threshold").and_then(Value::as_i64) else {
        return Verdict::plain(
            Status::InvalidSpec,
            "threshold must be an integer (scale fractional scores)",
        );
    };
    let direction_text = spec
        .get("direction")
        .and_then(Value::as_str)
        .unwrap_or("maximize");
    let Some(direction) = crate::frontier::Direction::parse(direction_text) else {
        return Verdict::plain(
            Status::InvalidSpec,
            format!("unknown direction {direction_text:?}"),
        );
    };
    // Absent means zero, and `"seed": 0` must mean the same thing -- two
    // spellings of one objective would otherwise verify differently. The first
    // version of this treated absent as "no seed" and called a two-parameter
    // entrypoint with one argument, which raised, which became `Unavailable`,
    // which the audit skips. Correct-looking and completely inert.
    let seed = spec.get("seed").and_then(Value::as_i64).unwrap_or(0);
    let path = match pinned(root, path_text, declared) {
        Ok(path) => path,
        Err(verdict) => return verdict,
    };
    let outcome = match run_pinned_seeded(&path, entrypoint, artifact, Some(seed)) {
        Ok(outcome) => outcome,
        Err(verdict) => return verdict,
    };
    let Some(score) = outcome.as_i64() else {
        return Verdict::plain(
            Status::Unavailable,
            "statistic returned a non-integer score",
        );
    };
    let evidence = Value::object([
        ("direction", Value::string(direction_text)),
        ("score", Value::Int(i128::from(score))),
        ("seed", Value::Int(i128::from(seed))),
        ("statistic_sha256", Value::string(declared)),
        ("threshold", Value::Int(i128::from(threshold))),
    ]);
    let detail = format!("score {score} vs threshold {threshold} ({direction_text})");
    if direction.clears(score, threshold) {
        Verdict::new(Status::Accept, detail, evidence)
    } else {
        Verdict::new(Status::Reject, detail, evidence)
    }
}

fn evaluator(root: &Path, spec: &Value, artifact: &Value) -> Verdict {
    let (evaluator, declared, entrypoint) = match (
        required(spec, "evaluator"),
        required(spec, "evaluator_sha256"),
        required(spec, "entrypoint"),
    ) {
        (Ok(a), Ok(b), Ok(c)) => (a, b, c),
        (Err(v), _, _) | (_, Err(v), _) | (_, _, Err(v)) => return v,
    };
    // Integer threshold only: a float threshold is a comparison two honest
    // nodes could answer differently.
    let Some(threshold) = spec.get("threshold").and_then(Value::as_i64) else {
        return Verdict::plain(
            Status::InvalidSpec,
            "threshold must be an integer (scale fractional scores)",
        );
    };
    let direction_text = spec
        .get("direction")
        .and_then(Value::as_str)
        .unwrap_or("maximize");
    let Some(direction) = crate::frontier::Direction::parse(direction_text) else {
        return Verdict::plain(
            Status::InvalidSpec,
            format!("unknown direction {direction_text:?}"),
        );
    };
    let path = match pinned(root, evaluator, declared) {
        Ok(path) => path,
        Err(verdict) => return verdict,
    };
    let outcome = match run_pinned(&path, entrypoint, artifact) {
        Ok(outcome) => outcome,
        Err(verdict) => return verdict,
    };
    let Some(score) = outcome.as_i64() else {
        return Verdict::plain(
            Status::Unavailable,
            "evaluator returned a non-integer score",
        );
    };
    let evidence = Value::object([
        ("direction", Value::string(direction_text)),
        ("evaluator_sha256", Value::string(declared)),
        ("score", Value::Int(i128::from(score))),
        ("threshold", Value::Int(i128::from(threshold))),
    ]);
    let detail = format!("score {score} vs threshold {threshold} ({direction_text})");
    if direction.clears(score, threshold) {
        Verdict::new(Status::Accept, detail, evidence)
    } else {
        Verdict::new(Status::Reject, detail, evidence)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A replay spec whose command prints `json` and declares `fields`.
    fn spec(json: &str, fields: &[&str], cwd: Option<&str>) -> Value {
        let mut pairs = vec![
            ("kind", Value::string("replay")),
            (
                "command",
                Value::Array(vec![
                    Value::string("sh"),
                    Value::string("-c"),
                    Value::string(format!("printf '%s' '{json}'")),
                ]),
            ),
            (
                "reproducible_fields",
                Value::Array(fields.iter().map(|f| Value::string(*f)).collect()),
            ),
        ];
        if let Some(cwd) = cwd {
            pairs.push(("cwd", Value::string(cwd)));
        }
        Value::object(pairs)
    }

    fn artifact(results: Value) -> Value {
        Value::object([("results", results)])
    }

    /// An empty object. `Value::object([])` cannot infer its key type.
    fn empty() -> Value {
        Value::Object(std::collections::BTreeMap::new())
    }

    fn root() -> &'static Path {
        Path::new(".")
    }

    #[test]
    fn a_reproduced_field_accepts_and_a_differing_one_rejects() {
        let s = spec(r#"{"n":42}"#, &["n"], None);
        let good = run(
            root(),
            &s,
            &artifact(Value::object([("n", Value::Int(42))])),
        );
        assert_eq!(good.status, Status::Accept, "{}", good.detail);

        let bad = run(
            root(),
            &s,
            &artifact(Value::object([("n", Value::Int(41))])),
        );
        assert_eq!(bad.status, Status::Reject, "{}", bad.detail);
    }

    #[test]
    fn a_machine_dependent_field_is_a_spec_defect_not_a_rejection() {
        // A timing measures the host, not the computation. Declaring one
        // reproducible would make every honest re-run a refutation, so the
        // objective is broken rather than the artifact.
        for field in ["wall_time_ms", "PeakRSS", "elapsed", "flops", "timestamp"] {
            let s = spec(r#"{"x":1}"#, &[field], None);
            let verdict = run(root(), &s, &artifact(empty()));
            assert_eq!(
                verdict.status,
                Status::InvalidSpec,
                "{field} was accepted as reproducible"
            );
        }
    }

    #[test]
    fn a_missing_declared_field_settles_nothing() {
        // The command did not print what the objective said it would. Nothing
        // was compared, so nothing can be concluded about the artifact.
        let s = spec(r#"{"other":1}"#, &["n"], None);
        let verdict = run(root(), &s, &artifact(Value::object([("n", Value::Int(1))])));
        assert_eq!(verdict.status, Status::Unavailable, "{}", verdict.detail);
    }

    #[test]
    fn output_that_is_not_a_json_object_settles_nothing() {
        for output in ["not json at all", "[1,2,3]", "\"a string\"", ""] {
            let s = spec(output, &["n"], None);
            let verdict = run(root(), &s, &artifact(empty()));
            assert_eq!(
                verdict.status,
                Status::Unavailable,
                "output {output:?} was treated as evidence"
            );
        }
    }

    #[test]
    fn a_cwd_that_escapes_the_root_is_refused() {
        // Unconfined, a record naming `../..` reads any directory the operator
        // can -- and any declared field the command prints lands in public
        // verdict evidence, which is exfiltration with no network needed.
        for escape in ["..", "../..", "/etc"] {
            let s = spec(r#"{"n":1}"#, &["n"], Some(escape));
            let verdict = run(root(), &s, &artifact(empty()));
            assert_eq!(
                verdict.status,
                Status::InvalidSpec,
                "cwd {escape:?} was allowed"
            );
        }
    }

    #[test]
    fn an_empty_or_malformed_command_is_a_spec_defect() {
        let no_command = Value::object([
            ("kind", Value::string("replay")),
            ("command", Value::Array(Vec::new())),
            (
                "reproducible_fields",
                Value::Array(vec![Value::string("n")]),
            ),
        ]);
        assert_eq!(
            run(root(), &no_command, &artifact(empty())).status,
            Status::InvalidSpec
        );

        let not_strings = Value::object([
            ("kind", Value::string("replay")),
            ("command", Value::Array(vec![Value::Int(7)])),
            (
                "reproducible_fields",
                Value::Array(vec![Value::string("n")]),
            ),
        ]);
        assert_eq!(
            run(root(), &not_strings, &artifact(empty())).status,
            Status::InvalidSpec
        );
    }

    #[test]
    fn a_command_that_does_not_exist_settles_nothing() {
        let s = Value::object([
            ("kind", Value::string("replay")),
            (
                "command",
                Value::Array(vec![Value::string("proofwork-no-such-program-anywhere")]),
            ),
            (
                "reproducible_fields",
                Value::Array(vec![Value::string("n")]),
            ),
        ]);
        let verdict = run(root(), &s, &artifact(empty()));
        assert_eq!(verdict.status, Status::Unavailable, "{}", verdict.detail);
    }

    #[test]
    fn every_kind_the_primary_settles_is_implemented_here() {
        // The gap this crate kept having: a kind it does not implement answers
        // `Unavailable` for every claim, which is correct and settles nothing,
        // and the audit used to skip it silently. The list is now empty, and
        // this test is what stops it growing again: a kind added to the primary
        // and not to this crate fails here rather than passing quietly.
        // The control. Without it the loop below is a check that cannot fail:
        // reword the not-registered message and every `assert_ne!` passes
        // whether or not the kind is dispatched.
        let unknown = Value::object([("kind", Value::string("no-such-kind"))]);
        let missing = run(Path::new("."), &unknown, &empty());
        assert_eq!(
            missing.detail, "no verifier registered for kind \"no-such-kind\"",
            "the not-registered message moved; the loop below no longer detects anything"
        );
        assert_eq!(missing.status, Status::Unavailable);

        for kind in KINDS {
            let spec = Value::object([("kind", Value::string(*kind))]);
            let verdict = run(Path::new("."), &spec, &empty());
            assert_ne!(
                verdict.detail,
                format!("no verifier registered for kind {kind:?}"),
                "{kind} is advertised in KINDS but not dispatched"
            );
            assert!(implements(kind));
        }

        // The primary's kinds, spelled out rather than read from `KINDS`.
        // Reading them from the same constant would make the check circular:
        // drop a kind from `KINDS` and from `run` together and it would still
        // pass while the audit went quietly back to skipping that kind.
        for kind in ["certificate", "evaluator", "statistical", "replay", "lean"] {
            assert!(
                implements(kind),
                "the primary settles {kind} and this crate no longer claims to"
            );
        }
    }

    // -- lean ---------------------------------------------------------------

    /// A binary name no PATH lookup can satisfy.
    ///
    /// Every screen that must fire *before* the toolchain is consulted is
    /// tested against this: if the check moved below the lookup, the verdict
    /// would come back `Unavailable` instead, and the assertion fails.
    const NO_LEAN: &str = "proofwork-no-such-lean-anywhere";

    fn lean_spec(pairs: Vec<(&'static str, Value)>) -> Value {
        let mut all = vec![
            ("kind", Value::string("lean")),
            ("statement", Value::string("theorem t : True")),
        ];
        for (key, value) in pairs {
            all.retain(|(existing, _)| *existing != key);
            all.push((key, value));
        }
        Value::object(all)
    }

    fn proof(text: &str) -> Value {
        Value::object([("proof", Value::string(text))])
    }

    #[test]
    fn a_hole_or_an_escalation_is_rejected_before_lean_is_ever_run() {
        // Each of these proves the theorem to a reader who is not looking. The
        // screens are cheap and Lean is not, so they run first -- and because
        // the toolchain here does not exist, an `Unavailable` would mean the
        // screen had silently moved below the lookup.
        for hole in [
            ":= by sorry",
            ":= by admit",
            "axiom cheat : True",
            ":= by decide\n@[implemented_by fastPath] def slow := 1",
        ] {
            let verdict = lean_using(NO_LEAN, root(), &lean_spec(vec![]), &proof(hole));
            assert_eq!(
                verdict.status,
                Status::Reject,
                "{hole:?}: {}",
                verdict.detail
            );
        }
    }

    #[test]
    fn native_decide_is_screened_unless_the_objective_explicitly_opts_in() {
        let native = proof(":= by native_decide");

        let closed = lean_using(NO_LEAN, root(), &lean_spec(vec![]), &native);
        assert_eq!(closed.status, Status::Reject, "{}", closed.detail);

        // Only a real boolean `true` opts in. A truthy-looking `1` or the
        // string "true" must get the *stricter* treatment: a malformed spec is
        // not consent to trust the compiler instead of the kernel.
        for not_true in [Value::Int(1), Value::string("true"), Value::Bool(false)] {
            let spec = lean_spec(vec![("allow_native_decide", not_true.clone())]);
            let verdict = lean_using(NO_LEAN, root(), &spec, &native);
            assert_eq!(
                verdict.status,
                Status::Reject,
                "{} opted in to native_decide",
                not_true.canonical_string()
            );
        }

        // With the opt-in, the screen no longer fires -- so the run gets as far
        // as looking for a toolchain, and stops there.
        let opted_in = lean_using(
            NO_LEAN,
            root(),
            &lean_spec(vec![("allow_native_decide", Value::Bool(true))]),
            &native,
        );
        assert_eq!(opted_in.status, Status::Unavailable, "{}", opted_in.detail);
    }

    #[test]
    fn a_screened_token_inside_a_longer_word_is_not_a_hit() {
        // `sorry` and `admit` are screened as whole words. A lemma named
        // `sorryFree` or a definition about `admittance` is not a hole, and an
        // over-eager screen would make honest proofs unverifiable while
        // teaching submitters to rename around it.
        for innocent in [
            ":= by exact sorryFree",
            ":= by exact unsorry_lemma",
            ":= by exact admittance",
            ":= by exact Nat.axiomatic",
        ] {
            let verdict = lean_using(NO_LEAN, root(), &lean_spec(vec![]), &proof(innocent));
            assert_eq!(
                verdict.status,
                Status::Unavailable,
                "{innocent:?} was screened: {}",
                verdict.detail
            );
        }
    }

    #[test]
    fn a_project_root_that_escapes_the_objective_root_is_refused() {
        // The primary hands `project_root` to the jail as a *writable* bind, so
        // `"/"` unconfined is a pass-through of the filesystem. It is
        // attacker-authored like every other spec field, and a malformed spec
        // is malformed whether or not this node has Lean -- hence checked
        // before the lookup.
        for escape in ["..", "../..", "/etc"] {
            let spec = lean_spec(vec![("project_root", Value::string(escape))]);
            let verdict = lean_using(NO_LEAN, root(), &spec, &proof(":= trivial"));
            assert_eq!(
                verdict.status,
                Status::InvalidSpec,
                "project_root {escape:?} was allowed"
            );
        }
    }

    #[test]
    fn a_missing_statement_is_a_spec_defect_and_a_missing_proof_is_a_rejection() {
        // The asymmetry is the point. The statement belongs to the objective:
        // without it there is nothing to prove and the objective is broken. The
        // proof belongs to the submitter: an empty one is a claim that failed.
        for bad in [Value::string("   "), Value::Int(7)] {
            let spec = lean_spec(vec![("statement", bad)]);
            let verdict = lean_using(NO_LEAN, root(), &spec, &proof(":= trivial"));
            assert_eq!(verdict.status, Status::InvalidSpec, "{}", verdict.detail);
        }
        for bad in [empty(), proof(""), proof("  \n ")] {
            let verdict = lean_using(NO_LEAN, root(), &lean_spec(vec![]), &bad);
            assert_eq!(verdict.status, Status::Reject, "{}", verdict.detail);
        }
    }

    #[test]
    fn no_toolchain_settles_nothing() {
        // A node without Lean has no opinion. Reporting `Reject` here would let
        // anyone refute every proof on the network by uninstalling something.
        let verdict = lean_using(NO_LEAN, root(), &lean_spec(vec![]), &proof(":= trivial"));
        assert_eq!(verdict.status, Status::Unavailable, "{}", verdict.detail);
    }

    /// A stand-in for `lean` that prints `says` and exits `code`.
    ///
    /// Real Lean is not a build dependency of this crate, and waiting on one
    /// would leave the verdict branches -- the part that decides who gets paid
    /// -- untested. What is under test is how an exit code and some output map
    /// to a verdict, and that does not need a kernel.
    #[cfg(unix)]
    fn fake_lean(tag: &str, code: i32, says: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!(
            "proofwork-reference-fakelean-{}-{tag}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let path = dir.join("lean");
        std::fs::write(
            &path,
            format!("#!/bin/sh\nprintf '%s' \"{says}\"\nexit {code}\n"),
        )
        .expect("write the stand-in");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        path
    }

    /// Run the stand-in, retrying past `ETXTBSY`.
    ///
    /// **The race is not in what is being tested, and it cannot be fixed from
    /// here.** `fake_lean` writes a script and then execs it. Every other test
    /// thread in this binary also spawns processes, and a `fork` landing
    /// between our `write` and our `exec` hands the child a duplicate of our
    /// still-open write descriptor. The kernel then refuses to exec a file some
    /// process holds open for writing -- `ETXTBSY`, reported here as
    /// `Text file busy (os error 26)` -- until that child reaches its own
    /// `exec` and `CLOEXEC` closes the copy. The window is microseconds wide
    /// and it fired about one run in five under load, which is how it survived:
    /// nobody ran the reference suite in a loop until `make check` started
    /// running it as part of a longer sequence.
    ///
    /// Retried rather than locked, because a lock here would not help. The fork
    /// that does the damage belongs to a thread that never calls this function,
    /// so the only serialisation that would work is one every `Command::spawn`
    /// in the crate agrees to take.
    ///
    /// Retrying is safe in the direction that matters: an `Unavailable` is
    /// never a verdict about a proof, so this can only turn a non-answer into
    /// an answer, and a genuinely missing toolchain still ends `Unavailable`
    /// after the last attempt.
    #[cfg(unix)]
    fn with_fake_lean(tag: &str, code: i32, says: &str) -> Verdict {
        let binary = fake_lean(tag, code, says);
        let path = binary.to_str().expect("utf-8 path");
        let mut verdict = Verdict::plain(Status::Unavailable, "never ran");
        for attempt in 0..64 {
            verdict = lean_using(path, root(), &lean_spec(vec![]), &proof(":= trivial"));
            if !verdict.detail.contains("Text file busy") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(2 + attempt));
        }
        let _ = std::fs::remove_dir_all(binary.parent().expect("parent"));
        verdict
    }

    #[cfg(unix)]
    #[test]
    fn the_exit_code_is_the_kernels_answer() {
        // Uniquely for this kind, a non-zero exit is a real `Reject` rather
        // than an infrastructure fact: Lean's exit code *is* its answer about
        // this proof. Everywhere else in this file a non-zero exit settles
        // nothing.
        let rejected = with_fake_lean("nonzero", 1, "error: unsolved goals");
        assert_eq!(rejected.status, Status::Reject, "{}", rejected.detail);

        let accepted = with_fake_lean("zero", 0, "");
        assert_eq!(accepted.status, Status::Accept, "{}", accepted.detail);
    }

    #[cfg(unix)]
    #[test]
    fn a_clean_exit_that_warns_about_sorry_is_still_a_rejection() {
        // Lean *warns* rather than errors when a declaration depends on
        // `sorryAx` -- reached through an import or the preamble, where the
        // text screens cannot see it. Trusting the exit code alone would accept
        // a proof of nothing.
        let verdict = with_fake_lean("warns", 0, "warning: declaration uses 'sorry'");
        assert_eq!(verdict.status, Status::Reject, "{}", verdict.detail);
    }
}
