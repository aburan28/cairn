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
    run_pinned_seeded(path, entrypoint, artifact, None)
}

fn run_pinned_seeded(
    path: &Path,
    entrypoint: &str,
    artifact: &Value,
    seed: Option<i64>,
) -> Result<Value, Verdict> {
    const DRIVER: &str = r#"
import json, sys, importlib.util
spec = importlib.util.spec_from_file_location("pinned", sys.argv[1])
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

pub fn run(root: &Path, spec: &Value, artifact: &Value) -> Verdict {
    match spec.get("kind").and_then(Value::as_str) {
        Some("certificate") => certificate(root, spec, artifact),
        Some("evaluator") => evaluator(root, spec, artifact),
        Some("statistical") => statistical(root, spec, artifact),
        Some("replay") => replay(root, spec, artifact),
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
        // and the audit used to skip it silently. `lean` is the one that
        // remains -- it needs a proof-assistant toolchain -- and it is named
        // here so the list cannot quietly grow.
        let unimplemented = ["lean"];
        for kind in ["certificate", "evaluator", "statistical", "replay"] {
            let spec = Value::object([("kind", Value::string(kind))]);
            let verdict = run(Path::new("."), &spec, &empty());
            assert_ne!(
                verdict.detail,
                format!("no verifier registered for kind {kind:?}"),
                "{kind} is no longer dispatched"
            );
        }
        for kind in unimplemented {
            let spec = Value::object([("kind", Value::string(kind))]);
            let verdict = run(Path::new("."), &spec, &empty());
            assert_eq!(verdict.status, Status::Unavailable);
        }
    }
}
