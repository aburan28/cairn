//! Pinned verifiers: certificate and evaluator.
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

/// Resolve a pinned path against the bundle root and check its hash.
///
/// Containment first, then the hash. A pin whose path leaves the bundle is a
/// malformed objective and content-addressing must not rescue it: otherwise an
/// objective could name `../../.ssh/id_rsa` and start resolving the day
/// somebody's node happened to hold a blob at that address.
fn pinned(root: &Path, relative: &str, declared: &str) -> Result<PathBuf, Verdict> {
    let root = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let joined = normalize(&root.join(relative));
    if !joined.starts_with(&root) {
        return Err(Verdict::plain(
            Status::InvalidSpec,
            format!("pinned path escapes the objective root: {relative}"),
        ));
    }
    let source = std::fs::read(&joined).map_err(|error| {
        // Cannot read is a fact about this node, not about the artifact.
        Verdict::plain(
            Status::Unavailable,
            format!("cannot load pinned code {relative}: {error}"),
        )
    })?;
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
    const DRIVER: &str = r#"
import json, sys, importlib.util
spec = importlib.util.spec_from_file_location("pinned", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
artifact = json.loads(sys.stdin.read())
print(json.dumps({"ok": getattr(module, sys.argv[2])(artifact)}))
"#;
    let mut child = Command::new("python3")
        .args(["-c", DRIVER, &path.to_string_lossy(), entrypoint])
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

pub fn run(root: &Path, spec: &Value, artifact: &Value) -> Verdict {
    match spec.get("kind").and_then(Value::as_str) {
        Some("certificate") => certificate(root, spec, artifact),
        Some("evaluator") => evaluator(root, spec, artifact),
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
