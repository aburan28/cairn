//! A round as an executor job: gVisor over a directory, or Kata over an
//! image, through the host agent's [`crate::agent::job::run`].
//!
//! The solver sees `/pkg` (the package, read-only, its working directory),
//! `/cairn/assignment` (the assignment line, read-only; the program's stdin is
//! redirected from it), `/tmp` (a size-limited tmpfs, `HOME` and `TMPDIR`),
//! `/out` (the job's scratch directory), and the system. Under gVisor the root
//! is a skeleton made here that holds *only* the system directories and the
//! interpreter's prefix, never the host's `/`: no `/home`, no `/etc`, no
//! `/root`, none of the node's keys. Everything is gone when the round ends.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use super::executor::{self, Executor};
use super::manifest::Platform;
use super::run::{self, Failure, Output, Round};
use crate::agent::job::{self, Input, Job};
use crate::agent::sandbox::Preference;
use crate::hardware::CpuRequirements;

/// A fork bomb is stopped here, and by the memory limit before that.
const PIDS: u32 = 4096;
const TMP_MB: u64 = 1024;
/// Where the program reads its assignment inside the sandbox.
const ASSIGNMENT: &str = "/cairn/assignment";

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// The job directory, removed when the round is over.
struct JobDir(PathBuf);

impl Drop for JobDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn unavailable(why: impl Into<String>) -> Failure {
    Failure::Unavailable(why.into())
}

/// The command line inside the sandbox: a shell that redirects stdin from
/// the assignment file and replaces itself with the program.
pub(crate) fn wrap(program: &str, args: &[String]) -> Vec<String> {
    let mut argv = vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        format!("exec \"$0\" \"$@\" < {ASSIGNMENT}"),
        program.to_string(),
    ];
    argv.extend(args.iter().cloned());
    argv
}

/// The root a gVisor round starts from, and the mounts that fill it. Only
/// the system directories: a link where the host has a link, a read-only
/// mount where it has a directory.
pub(crate) fn system_root(root: &Path) -> Result<Vec<Input>, String> {
    fs::create_dir_all(root).map_err(|e| format!("{}: {e}", root.display()))?;
    let mut mounts = Vec::new();
    for top in executor::SYSTEM_TOPS {
        let host = Path::new("/").join(top);
        let Ok(meta) = fs::symlink_metadata(&host) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            let target = fs::read_link(&host).map_err(|e| format!("{}: {e}", host.display()))?;
            link(&target, &root.join(top))?;
        } else if meta.is_dir() {
            mounts.push(Input {
                source: host,
                target: format!("/{top}"),
            });
        }
    }
    Ok(mounts)
}

#[cfg(unix)]
fn link(target: &Path, at: &Path) -> Result<(), String> {
    std::os::unix::fs::symlink(target, at).map_err(|e| format!("{}: {e}", at.display()))
}

#[cfg(not(unix))]
fn link(_: &Path, _: &Path) -> Result<(), String> {
    Err("gVisor rounds need a Unix host".into())
}

/// Mounts for paths the interpreter needs that the system directories do
/// not already show, each at its own host path, none inside another.
pub(crate) fn grants(paths: &[PathBuf]) -> Vec<Input> {
    let mut kept: Vec<PathBuf> = Vec::new();
    let mut sorted: Vec<&PathBuf> = paths
        .iter()
        .filter(|p| !executor::under_system(p))
        .collect();
    sorted.sort_by_key(|p| p.components().count());
    for path in sorted {
        if !kept.iter().any(|k| path.starts_with(k)) {
            kept.push(path.clone());
        }
    }
    kept.into_iter()
        .map(|path| Input {
            target: path.display().to_string(),
            source: path,
        })
        .collect()
}

fn job_dir() -> Result<JobDir, Failure> {
    let id = format!(
        "solver-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let base = executor::state_dir();
    let dir = base.join("jobs").join(&id);
    fs::create_dir_all(&dir)
        .map_err(|e| unavailable(format!("cannot create {}: {e}", dir.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = fs::set_permissions(&base, fs::Permissions::from_mode(0o700));
    }
    Ok(JobDir(dir))
}

pub(super) fn run(round: &Round<'_>, executor: &Executor) -> Result<Output, Failure> {
    let package = fs::canonicalize(round.dir)
        .map_err(|e| unavailable(format!("{}: {e}", round.dir.display())))?;
    let threads = round.threads.max(1);
    let seconds = round.resources.round_seconds;
    let line = round.assignment.canonical_string();
    let dir = job_dir()?;
    let id = dir
        .0
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();

    let incoming = dir.0.join("in");
    fs::create_dir_all(&incoming).map_err(|e| unavailable(e.to_string()))?;
    fs::write(incoming.join("assignment"), format!("{line}\n"))
        .map_err(|e| unavailable(e.to_string()))?;
    let mut inputs = vec![
        Input {
            source: package,
            target: "/pkg".into(),
        },
        Input {
            source: incoming,
            target: "/cairn".into(),
        },
    ];

    let entry = format!("/pkg/{}", round.target.entry);
    let (program, mut args) = if round.platform == Platform::Python3 {
        let interpreter = match executor {
            Executor::Gvisor => {
                let (found, root) = run::python(true).map_err(Failure::Unavailable)?;
                let real = fs::canonicalize(&found).unwrap_or(found);
                let mut needed = vec![real.clone()];
                needed.extend(root);
                inputs.extend(grants(&needed));
                real.display().to_string()
            }
            // The image's own interpreter.
            _ => "python3".to_string(),
        };
        (
            interpreter,
            vec!["-E".to_string(), "-s".into(), "-B".into(), entry],
        )
    } else {
        (entry, Vec::new())
    };
    args.extend(round.target.args.iter().cloned());

    let rootfs = match executor {
        Executor::Gvisor => {
            let root = dir.0.join("rootfs");
            inputs.extend(system_root(&root).map_err(Failure::Unavailable)?);
            Some(root)
        }
        _ => None,
    };

    let mut env = vec![
        (
            "PATH".to_string(),
            "/usr/local/bin:/usr/bin:/bin".to_string(),
        ),
        ("LANG".into(), "C.UTF-8".into()),
        ("LC_ALL".into(), "C.UTF-8".into()),
        ("HOME".into(), "/tmp".into()),
        ("TMPDIR".into(), "/tmp".into()),
        ("PYTHONDONTWRITEBYTECODE".into(), "1".into()),
    ];
    env.extend(run::contract_env(round, &line));

    let (image, sandbox) = match executor {
        Executor::Kata { image } => (Some(image.clone()), Preference::Kata),
        _ => (None, Preference::Runsc),
    };
    let spec = Job {
        id,
        objective_id: None,
        task: None,
        image,
        rootfs,
        argv: wrap(&program, &args),
        cwd: Some("/pkg".into()),
        env,
        inputs,
        cpus: threads,
        memory_mb: round.resources.memory_mb,
        gpus: 0,
        pids: PIDS,
        timeout: Duration::from_secs(seconds),
        network: false,
        sandbox,
        tmp_mb: TMP_MB,
        note: None,
        cpu_requirements: CpuRequirements::default(),
        workload: None,
    };

    let started = Instant::now();
    let receipt = job::run(&spec, executor::sandboxes(), &dir.0, "cairn-solver");
    let elapsed = started.elapsed();
    let read = |path: &Path| {
        fs::read(path)
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_default()
    };
    let stdout = read(&receipt.stdout);
    let stderr = read(&receipt.stderr);
    let name = receipt.sandbox.as_str();

    if let Some(error) = &receipt.error {
        return Err(unavailable(format!(
            "could not run {} under {name}: {error}",
            round.target.entry
        )));
    }
    if receipt.timed_out {
        return Err(Failure::Broke {
            reason: format!(
                "did not finish within its round_seconds ({seconds} s) and was stopped"
            ),
            stderr: String::new(),
        });
    }
    if receipt.limit_exceeded {
        return Err(Failure::Broke {
            reason: "exceeded its memory_mb or printed more than the output cap and was stopped"
                .into(),
            stderr,
        });
    }
    if receipt.exit_status != Some(0) {
        let how = match receipt.exit_status {
            Some(code) => format!("exited {code}"),
            None => "was killed by a signal".to_string(),
        };
        return Err(Failure::Broke {
            reason: format!("{} {how}; this round is discarded", round.target.entry),
            stderr,
        });
    }
    run::finish(&stdout, stderr, receipt.sandbox.as_str(), elapsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stdin_comes_from_the_assignment_file_not_from_the_engine() {
        let argv = wrap("/pkg/solve", &["--fast".to_string()]);
        assert_eq!(argv[..2], ["/bin/sh", "-c"]);
        assert!(argv[2].ends_with("< /cairn/assignment"));
        assert!(argv[2].starts_with("exec \"$0\" \"$@\""));
        assert_eq!(argv[3..], ["/pkg/solve", "--fast"]);
    }

    #[test]
    fn grants_skip_the_system_and_anything_nested() {
        let got = grants(&[
            PathBuf::from("/usr/bin/python3.11"),
            PathBuf::from("/opt/py/bin/python3"),
            PathBuf::from("/opt/py"),
            PathBuf::from("/srv/lib"),
        ]);
        let targets: Vec<&str> = got.iter().map(|i| i.target.as_str()).collect();
        assert_eq!(targets, ["/opt/py", "/srv/lib"]);
    }

    #[cfg(unix)]
    #[test]
    fn the_root_holds_only_the_system_directories() {
        let dir = std::env::temp_dir().join(format!("cairn-iso-root-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let mounts = system_root(&dir).unwrap();
        for input in &mounts {
            assert!(input.source.starts_with("/"));
            let top = input.target.trim_start_matches('/');
            assert!(executor::SYSTEM_TOPS.contains(&top), "{}", input.target);
            assert!(!dir.join(top).exists(), "{top} is mounted, not copied");
        }
        for entry in fs::read_dir(&dir).unwrap() {
            let name = entry.unwrap().file_name().into_string().unwrap();
            assert!(executor::SYSTEM_TOPS.contains(&name.as_str()), "{name}");
        }
        for hidden in ["home", "root", "etc", "Users", "var"] {
            assert!(!dir.join(hidden).exists(), "{hidden} leaked into the root");
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
