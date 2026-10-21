//! One round of a solver, in the jail.
//!
//! On Linux a round runs under gVisor or Kata through the host agent's
//! executor ([`super::executor`]) when either works here, and otherwise in the
//! jail pinned checkers already run in ([`crate::verifiers::sandbox`]):
//! seatbelt on macOS, bubblewrap on Linux. Every executor gives no
//! network, a scrubbed environment, nothing readable outside the package, the
//! system and the interpreter, nothing writable outside a scratch directory
//! that is deleted afterwards, and the process tree held to the threads the
//! contributor offered and the memory the package asked for. A solver is
//! objective-authored code exactly as a checker is, and a stranger's machine
//! runs it for hours rather than seconds, so it gets no less.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::executor;
use super::isolate;
use super::manifest::{self, Platform, Resources, Target};
use crate::canonical::Value;
use crate::verifiers::sandbox::{self, Confinement};
use crate::verifiers::{self, RunFailure, TempDir};

/// Everything a round needs, all of it decided before the jail is built.
pub struct Round<'a> {
    /// The package's own directory: the jail's working directory, read-only.
    pub dir: &'a Path,
    pub platform: Platform,
    pub target: &'a Target,
    pub resources: Resources,
    pub assignment: &'a Value,
    pub objective: &'a str,
    pub worker: &'a str,
    pub round: u64,
    /// Threads offered: `CAIRN_THREADS` for the solver, and the CPU cap the
    /// jail holds its whole process tree to.
    pub threads: u32,
    /// Run with no jail on a host that has none. Development only; the
    /// report and every round's output say `sandbox: none` when it happens.
    pub allow_unjailed: bool,
}

/// A round that ran to exit 0.
#[derive(Debug, Clone)]
pub struct Output {
    pub candidates: Vec<Value>,
    /// Lines that were not candidate objects, with why. The contract says
    /// every line is one; a worker drops them, a conformance check fails on
    /// them.
    pub skipped: Vec<String>,
    pub stderr: String,
    pub sandbox: &'static str,
    pub elapsed: Duration,
}

/// Why a round produced nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// This host cannot run the package: no interpreter, no jail, a jail that
    /// will not start. A fact about the machine, never about the package.
    Unavailable(String),
    /// The solver ran and broke the contract: crashed, overran its round,
    /// printed too much.
    Broke { reason: String, stderr: String },
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Failure::Unavailable(why) => write!(f, "cannot run here: {why}"),
            Failure::Broke { reason, stderr } if stderr.trim().is_empty() => f.write_str(reason),
            Failure::Broke { reason, stderr } => {
                write!(f, "{reason}; its last words:\n{}", tail(stderr, 12))
            }
        }
    }
}

/// The interpreter a `python3` target runs under: the one pinned checkers use,
/// chosen the same way (`CAIRN_PYTHON`, else `python3` on `PATH`), with the
/// same refusal of a version-manager shim the jail cannot follow.
pub(super) fn python(jailed: bool) -> Result<(PathBuf, Option<PathBuf>), String> {
    let wanted = std::env::var(verifiers::PYTHON_ENV)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "python3".to_string());
    let Some(found) = verifiers::which(&wanted) else {
        return Err(format!(
            "'{wanted}' is not on PATH; a python3 solver needs it"
        ));
    };
    let root = std::env::var_os(verifiers::PYTHON_ROOT_ENV)
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty());
    if jailed {
        match sandbox::interpreter_problem(&found, root.as_deref()) {
            None => {}
            Some(sandbox::Unjailable::Shim { found, what }) => {
                return Err(format!(
                    "{} is a version-manager shim ({what}) the sandbox cannot follow; set {} \
                     to the real interpreter (`pyenv which python3`) and {} to its prefix",
                    found.display(),
                    verifiers::PYTHON_ENV,
                    verifiers::PYTHON_ROOT_ENV
                ))
            }
            Some(sandbox::Unjailable::UnderHome { interpreter, .. }) => {
                return Err(format!(
                    "{} is under a home directory the sandbox does not show; set {} to its \
                     prefix or use a python3 installed outside home",
                    interpreter.display(),
                    verifiers::PYTHON_ROOT_ENV
                ))
            }
        }
    }
    Ok((found, root))
}

/// The contract's variables, the same under every executor.
pub(super) fn contract_env(round: &Round<'_>, line: &str) -> Vec<(String, String)> {
    let field = |name: &str| {
        round
            .assignment
            .get(name)
            .and_then(Value::as_u64)
            .unwrap_or(0)
            .to_string()
    };
    let threads = round.threads.max(1).to_string();
    vec![
        ("CAIRN_ABI".into(), manifest::ABI.into()),
        ("CAIRN_ASSIGNMENT".into(), line.into()),
        ("CAIRN_OBJECTIVE".into(), round.objective.into()),
        ("CAIRN_WORKER".into(), round.worker.into()),
        ("CAIRN_EPOCH".into(), field("epoch")),
        ("CAIRN_EPOCH_ENDS_IN".into(), field("epoch_ends_in_seconds")),
        ("CAIRN_ROUND".into(), round.round.to_string()),
        (
            "CAIRN_ROUND_SECONDS".into(),
            round.resources.round_seconds.to_string(),
        ),
        ("CAIRN_THREADS".into(), threads.clone()),
        ("OMP_NUM_THREADS".into(), threads.clone()),
        ("RAYON_NUM_THREADS".into(), threads),
    ]
}

/// Run one round and collect what it printed.
pub fn run(round: &Round<'_>) -> Result<Output, Failure> {
    let selection = executor::select().map_err(Failure::Unavailable)?;
    match &selection.executor {
        executor::Executor::Host => run_host(round),
        isolated => isolate::run(round, isolated),
    }
}

/// Validate and package what a finished round printed.
pub(super) fn finish(
    stdout: &str,
    stderr: String,
    sandbox: &'static str,
    elapsed: Duration,
) -> Result<Output, Failure> {
    let (candidates, skipped) = parse_candidates(stdout);
    if candidates.len() > manifest::MAX_CANDIDATES {
        return Err(Failure::Broke {
            reason: format!(
                "printed {} candidates; one round may print at most {}",
                candidates.len(),
                manifest::MAX_CANDIDATES
            ),
            stderr,
        });
    }
    Ok(Output {
        candidates,
        skipped,
        stderr,
        sandbox,
        elapsed,
    })
}

/// A round under the platform's own jail: bubblewrap or seatbelt.
fn run_host(round: &Round<'_>) -> Result<Output, Failure> {
    let mechanism = sandbox::mechanism();
    if !mechanism.is_jail() && !round.allow_unjailed {
        let why = match &mechanism {
            sandbox::Mechanism::None(why) => *why,
            _ => "no sandbox",
        };
        return Err(Failure::Unavailable(format!(
            "{why}. A published solver only runs in a sandbox: on Linux install bubblewrap \
             (`apt install bubblewrap`); macOS has one built in"
        )));
    }
    let dir = std::fs::canonicalize(round.dir)
        .map_err(|e| Failure::Unavailable(format!("{}: {e}", round.dir.display())))?;
    let entry = dir.join(&round.target.entry);
    let scratch = TempDir::new("cairn-solver")
        .map_err(|e| Failure::Unavailable(format!("cannot create a scratch directory: {e}")))?;

    let (program, mut args, interpreter) = if round.platform == Platform::Python3 {
        let (interpreter, root) = python(mechanism.is_jail()).map_err(Failure::Unavailable)?;
        // -E: no PYTHON* from anywhere; -s: no user site-packages; -B: the
        // package is read-only, so do not try to write bytecode beside it.
        let args = sandbox::argv([
            OsString::from("-E"),
            OsString::from("-s"),
            OsString::from("-B"),
            entry.clone().into_os_string(),
        ]);
        (interpreter.clone(), args, Some((interpreter, root)))
    } else {
        (entry.clone(), Vec::new(), None)
    };
    args.extend(round.target.args.iter().map(OsString::from));

    let threads = round.threads.max(1);
    let seconds = round.resources.round_seconds;
    let line = round.assignment.canonical_string();
    let mut plan = Confinement::new(
        scratch.path(),
        &dir,
        seconds.saturating_mul(u64::from(threads)).saturating_add(5),
    )
    .reading(&dir)
    .scrubbed();
    for (key, value) in contract_env(round, &line) {
        plan = plan.with_env(key, value);
    }
    plan.memory_mb = round.resources.memory_mb;
    plan.cpus = threads;
    if let Some((interpreter, root)) = &interpreter {
        plan = plan.reading(interpreter);
        if let Some(root) = root {
            plan = plan.reading(root);
        }
    }
    let jailed = sandbox::confine(&program, &args, &plan)
        .map_err(|sandbox::Unavailable(why)| Failure::Unavailable(why))?;
    let sandbox_name = jailed.mechanism;
    let mut command = jailed.command;

    let started = Instant::now();
    let input = format!("{line}\n");
    let completed = match verifiers::run_bounded(
        &mut command,
        scratch.path(),
        Some(input.as_bytes()),
        Duration::from_secs(seconds),
        plan.limits(),
    ) {
        Ok(completed) => completed,
        Err(RunFailure::TimedOut(_)) => {
            return Err(Failure::Broke {
                reason: format!(
                    "did not finish within its round_seconds ({seconds} s) and was stopped"
                ),
                stderr: String::new(),
            })
        }
        Err(RunFailure::Spawn(error)) => {
            return Err(Failure::Unavailable(format!(
                "could not start {} under {sandbox_name}: {error}",
                round.target.entry
            )))
        }
        // An output or memory cap it ran into: the solver's doing.
        Err(RunFailure::Io(error)) => {
            return Err(Failure::Broke {
                reason: error.to_string(),
                stderr: String::new(),
            })
        }
    };
    let elapsed = started.elapsed();
    if completed.code != Some(0) {
        let how = match completed.code {
            Some(code) => format!("exited {code}"),
            None => "was killed by a signal".to_string(),
        };
        return Err(Failure::Broke {
            reason: format!("{} {how}; this round is discarded", round.target.entry),
            stderr: completed.stderr,
        });
    }

    finish(&completed.stdout, completed.stderr, sandbox_name, elapsed)
}

/// One JSON object per line; blank lines are nothing.
pub fn parse_candidates(stdout: &str) -> (Vec<Value>, Vec<String>) {
    let mut candidates = Vec::new();
    let mut skipped = Vec::new();
    for (n, line) in stdout.lines().enumerate() {
        let text = line.trim();
        if text.is_empty() {
            continue;
        }
        match Value::from_json(text) {
            Ok(value) if value.as_object().is_some() => candidates.push(value),
            Ok(_) => skipped.push(format!("line {}: not a JSON object", n + 1)),
            // No floats in canonical JSON, on purpose; better said here than
            // by the node refusing the artifact an epoch later.
            Err(error) => skipped.push(format!("line {}: {error}", n + 1)),
        }
    }
    (candidates, skipped)
}

/// The last `lines` lines of `text`, for a message.
pub fn tail(text: &str, lines: usize) -> String {
    let all: Vec<&str> = text.trim_end().lines().collect();
    let start = all.len().saturating_sub(lines);
    all[start..]
        .iter()
        .map(|line| {
            if line.len() > 300 {
                let mut cut = 300;
                while !line.is_char_boundary(cut) {
                    cut -= 1;
                }
                format!("{}…", &line[..cut])
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidates_are_objects_one_per_line() {
        let (found, skipped) = parse_candidates("{\"x\":1}\n\n[1]\n{\"y\":1.5}\n{\"z\":\"2\"}\n");
        assert_eq!(found.len(), 2);
        assert_eq!(skipped.len(), 2);
        assert!(skipped[0].contains("line 3"));
        assert!(skipped[1].contains("line 4"));
    }

    #[test]
    fn a_tail_is_short_and_cut_on_a_character() {
        let text = format!("one\ntwo\n{}\n", "é".repeat(400));
        let cut = tail(&text, 2);
        assert!(cut.starts_with("two\n"));
        assert!(cut.ends_with('…'));
    }
}
