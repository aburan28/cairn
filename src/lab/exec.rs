//! Running a command inside an environment, under gVisor or bubblewrap.
//!
//! # Backends, strongest first
//!
//! | backend | what stands between the program and the host |
//! |---|---|
//! | `runsc` (gVisor) | a user-space kernel: the program's syscalls are served by gVisor's Sentry, and only a narrow, filtered set reaches the host kernel |
//! | `bwrap` | Linux namespaces over the host kernel: the program's syscalls reach the host kernel directly |
//! | `none` | nothing; refused unless the caller opts in, and the receipt says so |
//!
//! Every backend gets the same plan: the environment's tree as a **read-only**
//! root, declared inputs mounted read-only, exactly one writable output
//! directory, a tmpfs `/tmp`, **no network** unless asked, a wall-clock
//! deadline, and optional memory, CPU and process limits.
//!
//! # The environment's tree is never the runtime's root
//!
//! A run's root is an empty directory of its own, with the environment's
//! top-level entries bound into it read-only, and every mount point is made in
//! that root. gVisor's gofer creates a missing mount point on the host, in the
//! directory the OCI root names, before that root is made read-only — and it
//! does so through a read-only bind as well. Handed the environment's tree as
//! its root, one run with an input at `/work/x` left an empty `/work/x` behind
//! in it, and the tree stopped matching the digest every later receipt named.
//! For the same reason a mount target that would have to be created *inside*
//! one of the environment's own directories is refused ([`check_targets`]); a
//! new top-level path such as `/work` or `/in` is made in the run's own root.
//!
//! No two mounts share a destination. runsc sorts a config's mounts before
//! mounting them, and not stably: with an environment's `/out` bound read-only
//! and the run's writable output at `/out` too, which one ended up on top
//! changed with the number of mounts, and a Sage run found its output
//! directory read-only. So a mount at a top-level path *replaces* the
//! environment's entry there rather than covering it, and targets may neither
//! repeat nor nest. Bubblewrap gets the identical layout, so a request means
//! the same thing under either backend.
//!
//! # Memory is limited by resident set or cgroup, never `RLIMIT_AS`
//!
//! Computer algebra systems reserve address space far beyond what they touch;
//! an address-space cap kills them while they are well inside any sensible
//! memory budget. The research program this serves wrote that rule down after
//! paying for it. Under gVisor the limit is the sandbox's cgroup; under
//! bubblewrap it is a resident-set watchdog over the process tree.
//!
//! # An infrastructure failure is not a result
//!
//! `runsc run` reports a sandbox that never started as exit status 128 —
//! indistinguishable, by status alone, from a program that exited 128. So the
//! run is given a `--pid-file`, which gVisor writes only once the sandbox is
//! up: no pid file means the sandbox never started, and that is an
//! [`Outcome::error`]; a sandbox that started but could not exec the command
//! (the program is not in the environment) is an error too. Only a status the
//! program itself produced is an [`Outcome::exit_status`]. The same rule as
//! `Unavailable` in the verifiers: a receipt must never present a broken host
//! as a fact about the program.
//!
//! The obvious alternative — `create`, `start`, then `wait` — was tried and
//! measured: a program that exits within milliseconds takes its sandbox down
//! before `wait` attaches, and its status is simply lost, in about one run in
//! eight on the host this was written on.

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use super::LabError;
use crate::canonical::Value;

/// A host directory made visible inside the sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    pub source: PathBuf,
    /// Absolute path inside the sandbox.
    pub target: String,
    pub writable: bool,
}

/// Everything a run needs.
#[derive(Debug, Clone)]
pub struct Spec {
    /// The environment's root filesystem on the host.
    pub rootfs: PathBuf,
    pub argv: Vec<String>,
    /// Absolute working directory inside the sandbox.
    pub cwd: String,
    pub env: Vec<(String, String)>,
    pub mounts: Vec<Mount>,
    pub timeout: Duration,
    /// Memory limit in MiB; `0` for none.
    pub memory_mb: u64,
    /// CPU limit in whole cores; `0` for none.
    pub cpus: u32,
    /// Process limit; `0` for none.
    pub pids: u32,
    /// Size of the tmpfs `/tmp`, MiB.
    pub tmp_mb: u64,
    /// Allow network access. Off by default and recorded either way.
    pub network: bool,
    /// Where the sandbox runtime keeps its state, shared by every run of one
    /// lab. Not a per-run directory: `runsc --network=none` bind-mounts a
    /// `null-netns` file into its state root and never unmounts it, so a
    /// fresh root per run leaks one mount per run and leaves a directory that
    /// cannot be deleted. One root per lab holds exactly one.
    pub runtime_dir: PathBuf,
}

/// Which jail runs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Backend {
    Gvisor { runsc: PathBuf, version: String },
    Bubblewrap { bwrap: PathBuf, version: String },
    Unconfined,
}

impl Backend {
    pub fn name(&self) -> &'static str {
        match self {
            Backend::Gvisor { .. } => "runsc",
            Backend::Bubblewrap { .. } => "bwrap",
            Backend::Unconfined => "none",
        }
    }

    pub fn version(&self) -> &str {
        match self {
            Backend::Gvisor { version, .. } | Backend::Bubblewrap { version, .. } => version,
            Backend::Unconfined => "",
        }
    }
}

/// Which backends were asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preference {
    /// gVisor if it works here, else bubblewrap, else refuse.
    Auto,
    Gvisor,
    Bubblewrap,
    /// No jail. The caller must have been told to allow it.
    Unconfined,
}

impl Preference {
    pub fn parse(text: &str) -> Result<Preference, LabError> {
        match text {
            "auto" => Ok(Preference::Auto),
            "runsc" | "gvisor" => Ok(Preference::Gvisor),
            "bwrap" | "bubblewrap" => Ok(Preference::Bubblewrap),
            "none" | "unconfined" => Ok(Preference::Unconfined),
            other => Err(LabError::Invalid(format!(
                "unknown sandbox {other:?} (auto, runsc, bwrap, none)"
            ))),
        }
    }
}

/// Environment variable naming the sandbox preference.
pub const SANDBOX_ENV: &str = "CAIRN_LAB_SANDBOX";

/// Pick a backend this host can actually use. Probed, not assumed: an
/// installed `runsc` or `bwrap` that cannot create a sandbox here (no user
/// namespaces, no ptrace, an old kernel) is the common failure, and it looks
/// like a spawn error at the worst moment.
pub fn backend(preference: Preference) -> Result<Backend, LabError> {
    match preference {
        Preference::Gvisor => gvisor().map_err(LabError::Unavailable),
        Preference::Bubblewrap => bubblewrap().map_err(LabError::Unavailable),
        Preference::Unconfined => Ok(Backend::Unconfined),
        Preference::Auto => match gvisor() {
            Ok(backend) => Ok(backend),
            Err(gvisor_why) => bubblewrap().map_err(|bwrap_why| {
                LabError::Unavailable(format!(
                    "no sandbox works on this host: runsc: {gvisor_why}; bwrap: {bwrap_why}. \
                     Install gVisor (https://gvisor.dev) or bubblewrap, or pass \
                     --sandbox none to run unconfined"
                ))
            }),
        },
    }
}

fn gvisor() -> Result<Backend, String> {
    static PROBED: OnceLock<Result<Backend, String>> = OnceLock::new();
    PROBED
        .get_or_init(|| {
            let runsc = which("runsc").ok_or("runsc is not on PATH")?;
            let version = Command::new(&runsc)
                .arg("--version")
                .output()
                .map_err(|e| format!("runsc --version: {e}"))?;
            if !version.status.success() {
                return Err("runsc --version failed".into());
            }
            let version = String::from_utf8_lossy(&version.stdout)
                .lines()
                .next()
                .unwrap_or("")
                .trim()
                .to_string();
            // `runsc do` runs a command in a sandbox over the host's root;
            // whether it completes is the whole question.
            let mut probe = Command::new(&runsc);
            probe.args(rootless_flags());
            let ok = probe
                .args(["--network=none", "do", "/bin/true"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map(|status| status.success())
                .unwrap_or(false);
            if !ok {
                return Err("runsc is installed but cannot start a sandbox on this host".into());
            }
            Ok(Backend::Gvisor { runsc, version })
        })
        .clone()
}

fn bubblewrap() -> Result<Backend, String> {
    static PROBED: OnceLock<Result<Backend, String>> = OnceLock::new();
    PROBED
        .get_or_init(|| {
            if !cfg!(target_os = "linux") {
                return Err("bubblewrap is Linux only".into());
            }
            let bwrap = which("bwrap").ok_or("bwrap is not on PATH")?;
            let ok = Command::new(&bwrap)
                .args(["--ro-bind", "/", "/", "--unshare-net", "--", "/bin/true"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map(|status| status.success())
                .unwrap_or(false);
            if !ok {
                return Err("bwrap is installed but cannot create a namespace here".into());
            }
            let version = Command::new(&bwrap)
                .arg("--version")
                .output()
                .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
                .unwrap_or_default();
            Ok(Backend::Bubblewrap { bwrap, version })
        })
        .clone()
}

fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

/// `runsc --rootless` when this process is not root. Read from
/// `/proc/self/status` rather than `geteuid`, which would need `unsafe` or a
/// libc dependency for one integer.
fn rootless_flags() -> Vec<&'static str> {
    let root = fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find(|line| line.starts_with("Uid:"))
                .and_then(|line| line.split_whitespace().nth(2).map(|euid| euid == "0"))
        })
        .unwrap_or(false);
    if root {
        Vec::new()
    } else {
        vec!["--rootless"]
    }
}

/// What happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub backend: String,
    pub backend_version: String,
    /// The status `wait` reported. `128 + n` for a program killed by signal
    /// `n`, as a shell reports it — gVisor gives nothing finer.
    pub exit_status: Option<i64>,
    pub timed_out: bool,
    /// The resident-set watchdog killed the run for its memory limit
    /// (bubblewrap and unconfined runs). Under gVisor the cgroup does the
    /// killing, which reads as exit 137 and is said so in [`Outcome::notes`].
    pub limit_exceeded: bool,
    /// The sandbox could not be created or started. Not a result about the
    /// program.
    pub error: Option<String>,
    pub stdout: PathBuf,
    pub stderr: PathBuf,
    pub started: String,
    pub finished: String,
    pub wall_ms: u64,
    /// Limits that were asked for and could not be enforced here.
    pub unenforced: Vec<String>,
    /// Anything else a reader of the receipt should know about the outcome.
    pub notes: Vec<String>,
}

impl Outcome {
    /// The program ran and exited 0.
    pub fn succeeded(&self) -> bool {
        self.error.is_none()
            && !self.timed_out
            && !self.limit_exceeded
            && self.exit_status == Some(0)
    }

    /// The receipt fields this outcome contributes.
    pub fn to_value(&self) -> Vec<(&'static str, Value)> {
        let mut pairs = vec![
            ("backend", Value::string(&self.backend)),
            ("started", Value::string(&self.started)),
            ("finished", Value::string(&self.finished)),
            ("wall_ms", Value::Int(i128::from(self.wall_ms))),
            ("timed_out", Value::Bool(self.timed_out)),
            ("limit_exceeded", Value::Bool(self.limit_exceeded)),
            (
                "exit_status",
                match self.exit_status {
                    Some(status) => Value::Int(i128::from(status)),
                    None => Value::Null,
                },
            ),
        ];
        if !self.backend_version.is_empty() {
            pairs.push(("backend_version", Value::string(&self.backend_version)));
        }
        if let Some(error) = &self.error {
            pairs.push(("error", Value::string(error)));
        }
        if !self.unenforced.is_empty() {
            pairs.push((
                "unenforced",
                Value::array(self.unenforced.iter().map(Value::string)),
            ));
        }
        if !self.notes.is_empty() {
            pairs.push(("notes", Value::array(self.notes.iter().map(Value::string))));
        }
        pairs
    }
}

/// Run `spec` under `backend`, using `work` (an empty directory this call
/// owns) for the bundle, the sandbox state and the captured streams.
pub fn run(backend: &Backend, spec: &Spec, work: &Path) -> Outcome {
    let stdout = work.join("stdout");
    let stderr = work.join("stderr");
    let mut outcome = Outcome {
        backend: backend.name().to_string(),
        backend_version: backend.version().to_string(),
        exit_status: None,
        timed_out: false,
        limit_exceeded: false,
        error: None,
        stdout: stdout.clone(),
        stderr: stderr.clone(),
        started: crate::time::timestamp(),
        finished: String::new(),
        wall_ms: 0,
        unenforced: Vec::new(),
        notes: Vec::new(),
    };
    let started = Instant::now();
    let result = check_targets(&spec.rootfs, &spec.mounts).and_then(|()| match backend {
        Backend::Gvisor { runsc, .. } => run_gvisor(runsc, spec, work, &mut outcome),
        Backend::Bubblewrap { bwrap, .. } => run_bwrap(bwrap, spec, work, &mut outcome),
        Backend::Unconfined => run_unconfined(spec, work, &mut outcome),
    });
    if let Err(why) = result {
        outcome.error = Some(why);
    }
    outcome.wall_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    outcome.finished = crate::time::timestamp();
    // The capture files exist even when nothing ran, so a receipt can always
    // point at them.
    for path in [&stdout, &stderr] {
        if !path.exists() {
            let _ = File::create(path);
        }
    }
    outcome
}

// -- the run's root --------------------------------------------------------------

/// Top-level names the sandbox supplies itself. The environment's own
/// `/proc`, `/dev` and `/tmp` are never bound: each run gets fresh ones.
const SANDBOX_OWNED: [&str; 3] = ["dev", "proc", "tmp"];

/// One top-level entry of a run's root.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Top {
    /// Bound read-only from the environment's tree.
    Bind { name: String, dir: bool },
    /// Recreated as the same symbolic link.
    Link { name: String, target: PathBuf },
    /// An empty directory for the sandbox to mount its own filesystem on.
    Own { name: String },
}

/// The top-level layout of a run's root, read from the environment's tree, in
/// byte order of name. An entry that one of `mounts` replaces is left out, and
/// so are device nodes, sockets and fifos; nothing a program needs lives there.
fn top_level(rootfs: &Path, mounts: &[Mount]) -> Result<Vec<Top>, String> {
    let mut names = Vec::new();
    for entry in fs::read_dir(rootfs).map_err(|e| format!("{}: {e}", rootfs.display()))? {
        let entry = entry.map_err(|e| format!("{}: {e}", rootfs.display()))?;
        let name = entry.file_name().into_string().map_err(|name| {
            format!(
                "the environment has a top-level entry whose name is not UTF-8: {}",
                name.to_string_lossy()
            )
        })?;
        names.push(name);
    }
    names.sort();
    let mut layout = Vec::new();
    for name in names {
        if SANDBOX_OWNED.contains(&name.as_str())
            || mounts
                .iter()
                .any(|mount| mount.target.strip_prefix('/') == Some(name.as_str()))
        {
            continue;
        }
        let path = rootfs.join(&name);
        let meta = fs::symlink_metadata(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let file_type = meta.file_type();
        if file_type.is_symlink() {
            let target = fs::read_link(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            layout.push(Top::Link { name, target });
        } else if file_type.is_dir() || file_type.is_file() {
            layout.push(Top::Bind {
                name,
                dir: file_type.is_dir(),
            });
        }
    }
    layout.extend(SANDBOX_OWNED.iter().map(|name| Top::Own {
        name: (*name).to_string(),
    }));
    Ok(layout)
}

/// Refuse a mount the runtime would have to create inside the environment's
/// tree, reach through a link in it, or stack on another mount.
///
/// Allowed: a top-level target (it replaces the environment's entry of that
/// name, if any); a deeper target whose first component the environment does
/// not have (made in the run's own root); anything under `/tmp` (the run's own
/// tmpfs); and a deeper target that already exists in the environment as the
/// same kind — a directory over a directory, a file over a file — which a
/// mount covers without creating anything. Targets may not repeat or nest.
/// See the module docs for why the rest is refused.
pub fn check_targets(rootfs: &Path, mounts: &[Mount]) -> Result<(), String> {
    for (n, mount) in mounts.iter().enumerate() {
        check_target(rootfs, &mount.target, mount.source.is_dir())?;
        for other in &mounts[..n] {
            let (a, b) = (other.target.as_str(), mount.target.as_str());
            if a == b {
                return Err(format!("two mounts at {a:?}"));
            }
            let nested = |outer: &str, inner: &str| {
                inner
                    .strip_prefix(outer)
                    .is_some_and(|rest| rest.starts_with('/'))
            };
            if nested(a, b) || nested(b, a) {
                return Err(format!(
                    "mounts at {a:?} and {b:?} nest; mount them side by side"
                ));
            }
        }
    }
    Ok(())
}

fn check_target(rootfs: &Path, target: &str, dir: bool) -> Result<(), String> {
    let Some(relative) = target.strip_prefix('/') else {
        return Err(format!("mount target {target:?} is not absolute"));
    };
    let segments: Vec<&str> = relative.split('/').collect();
    if segments
        .iter()
        .any(|segment| segment.is_empty() || *segment == "." || *segment == "..")
    {
        return Err(format!(
            "mount target {target:?} is not a normal path (empty, `.` or `..` segment)"
        ));
    }
    match segments[0] {
        "dev" | "proc" | "tmp" if segments.len() == 1 => {
            return Err(format!(
                "mount target {target:?} is a filesystem the sandbox provides"
            ))
        }
        "tmp" => return Ok(()),
        "dev" | "proc" => {
            return Err(format!(
                "mount target {target:?} is inside /{}, which the sandbox provides",
                segments[0]
            ))
        }
        // Replaces whatever the environment has there; see `top_level`.
        _ if segments.len() == 1 => return Ok(()),
        _ => {}
    }
    let kind = |is_dir: bool| if is_dir { "directory" } else { "file" };
    let mut path = rootfs.to_path_buf();
    for (depth, segment) in segments.iter().enumerate() {
        path.push(segment);
        let here = segments[..=depth].join("/");
        match fs::symlink_metadata(&path) {
            Err(_) if depth == 0 => return Ok(()),
            Err(_) => {
                return Err(format!(
                    "mount target {target:?} does not exist in the environment, and making it \
                     would write into the environment's /{}; mount it at a path the \
                     environment does not have, such as /work/{}",
                    segments[..depth].join("/"),
                    segments[depth..].join("/")
                ))
            }
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(format!(
                    "mount target {target:?} passes through /{here}, a symbolic link in the \
                     environment; name the path it resolves to"
                ))
            }
            Ok(meta) if depth + 1 == segments.len() => {
                if meta.is_dir() != dir {
                    return Err(format!(
                        "mount target {target:?} is a {} in the environment and the mount is a {}",
                        kind(meta.is_dir()),
                        kind(dir)
                    ));
                }
            }
            Ok(meta) if !meta.is_dir() => {
                return Err(format!(
                    "mount target {target:?} passes through /{here}, a file in the environment"
                ))
            }
            Ok(_) => {}
        }
    }
    Ok(())
}

#[cfg(unix)]
fn symlink(target: &Path, at: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, at)
}

#[cfg(not(unix))]
fn symlink(_target: &Path, _at: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "sandboxed runs need a Unix host",
    ))
}

/// Make the run's own root under `root` and return the read-only binds that
/// fill it from the environment. The run's own `mounts` go on top of these;
/// the mount points they need are made here, by the runtime.
fn scaffold_root(rootfs: &Path, root: &Path, mounts: &[Mount]) -> Result<Vec<Mount>, String> {
    fs::create_dir_all(root).map_err(|e| format!("{}: {e}", root.display()))?;
    let mut binds = Vec::new();
    for entry in top_level(rootfs, mounts)? {
        match entry {
            Top::Bind { name, dir } => {
                let at = root.join(&name);
                let made = if dir {
                    fs::create_dir_all(&at)
                } else {
                    File::create(&at).map(drop)
                };
                made.map_err(|e| format!("{}: {e}", at.display()))?;
                binds.push(Mount {
                    source: rootfs.join(&name),
                    target: format!("/{name}"),
                    writable: false,
                });
            }
            Top::Link { name, target } => {
                let at = root.join(&name);
                symlink(&target, &at).map_err(|e| format!("{}: {e}", at.display()))?;
            }
            Top::Own { name } => {
                let at = root.join(&name);
                fs::create_dir_all(&at).map_err(|e| format!("{}: {e}", at.display()))?;
            }
        }
    }
    Ok(binds)
}

// -- gVisor ------------------------------------------------------------------

fn run_gvisor(runsc: &Path, spec: &Spec, work: &Path, outcome: &mut Outcome) -> Result<(), String> {
    let bundle = work.join("bundle");
    let state = spec.runtime_dir.clone();
    fs::create_dir_all(&bundle).map_err(|e| e.to_string())?;
    fs::create_dir_all(&state).map_err(|e| e.to_string())?;
    let id = format!(
        "cairn-lab-{}-{}",
        std::process::id(),
        crate::hex::encode(&nonce())
    );
    let pid_file = work.join("sandbox.pid");

    let rootless = rootless_flags();
    // Under rootless gVisor there is no cgroup to put a limit in. Say so in
    // the receipt rather than silently running unlimited.
    let use_cgroups = rootless.is_empty();
    if !use_cgroups && (spec.memory_mb > 0 || spec.cpus > 0 || spec.pids > 0) {
        outcome
            .unenforced
            .push("memory/cpu/pids: rootless gVisor has no cgroups here".into());
    }
    let root = work.join("root");
    let binds = scaffold_root(&spec.rootfs, &root, &spec.mounts)?;
    let config = oci_config(spec, &root, &binds, use_cgroups);
    fs::write(bundle.join("config.json"), config.canonical_string()).map_err(|e| e.to_string())?;

    let base = |command: &mut Command| {
        command.arg("--root").arg(&state);
        command.args(&rootless);
        if !use_cgroups {
            command.arg("--ignore-cgroups");
        }
        command.arg(if spec.network {
            "--network=host"
        } else {
            "--network=none"
        });
    };

    let mut run = Command::new(runsc);
    base(&mut run);
    // The program's streams are runsc's: they land in the capture files, and
    // so do runsc's own diagnostics when something goes wrong.
    let child = run
        .arg("run")
        .arg("--pid-file")
        .arg(&pid_file)
        .arg("--bundle")
        .arg(&bundle)
        .arg(&id)
        .stdin(Stdio::null())
        .stdout(File::create(&outcome.stdout).map_err(|e| e.to_string())?)
        .stderr(File::create(&outcome.stderr).map_err(|e| e.to_string())?)
        .spawn()
        .map_err(|e| format!("runsc run: {e}"))?;
    let finished = wait_with_deadline(child, spec.timeout, || {
        let mut kill = Command::new(runsc);
        base(&mut kill);
        let _ = kill
            .args(["kill", "--all", &id, "KILL"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    });
    let mut delete = Command::new(runsc);
    base(&mut delete);
    let _ = delete
        .args(["delete", "--force", &id])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let (output, timed_out) = finished.map_err(|e| format!("runsc run: {e}"))?;
    outcome.timed_out = timed_out;
    let status = output.status.code().map(i64::from);
    let started = pid_file.is_file();
    let last_line = tail_of(&outcome.stderr);
    if !started {
        return Err(format!("the sandbox could not be created: {last_line}"));
    }
    if status == Some(128)
        && !timed_out
        && last_line.contains("running container: starting container")
    {
        return Err(format!(
            "the command could not be started in this environment: {last_line}"
        ));
    }
    outcome.exit_status = status;
    if spec.memory_mb > 0 && status == Some(137) && !timed_out {
        // The cgroup's OOM killer and a program killed by SIGKILL read the
        // same from outside; say which one this could be rather than guess.
        outcome
            .notes
            .push("exit 137 under a memory limit may be the limit's kill".into());
    }
    Ok(())
}

/// The OCI runtime config for a run: `root` is the run's own root, which
/// `binds` fill from the environment before any input or output is mounted.
fn oci_config(spec: &Spec, root: &Path, binds: &[Mount], cgroups: bool) -> Value {
    let mut env: Vec<Value> = vec![Value::string(
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    )];
    for (key, value) in &spec.env {
        if key == "PATH" {
            env[0] = Value::string(format!("PATH={value}"));
        } else {
            env.push(Value::string(format!("{key}={value}")));
        }
    }
    if !spec.env.iter().any(|(key, _)| key == "HOME") {
        env.push(Value::string("HOME=/root"));
    }

    let mut mounts = vec![
        Value::object([
            ("destination", Value::string("/proc")),
            ("type", Value::string("proc")),
            ("source", Value::string("proc")),
        ]),
        Value::object([
            ("destination", Value::string("/tmp")),
            ("type", Value::string("tmpfs")),
            ("source", Value::string("tmpfs")),
            (
                "options",
                Value::array([
                    Value::string("nosuid"),
                    Value::string("nodev"),
                    Value::string("mode=1777"),
                    Value::string(format!("size={}m", spec.tmp_mb.max(1))),
                ]),
            ),
        ]),
    ];
    for mount in binds.iter().chain(&spec.mounts) {
        mounts.push(Value::object([
            ("destination", Value::string(&mount.target)),
            ("type", Value::string("bind")),
            ("source", Value::string(mount.source.display().to_string())),
            (
                "options",
                Value::array([
                    Value::string("rbind"),
                    Value::string(if mount.writable { "rw" } else { "ro" }),
                ]),
            ),
        ]));
    }

    let mut resources: Vec<(&str, Value)> = Vec::new();
    if cgroups && spec.memory_mb > 0 {
        let bytes = i128::from(spec.memory_mb).saturating_mul(1024 * 1024);
        resources.push((
            "memory",
            Value::object([("limit", Value::Int(bytes)), ("swap", Value::Int(bytes))]),
        ));
    }
    if cgroups && spec.cpus > 0 {
        resources.push((
            "cpu",
            Value::object([
                ("quota", Value::Int(i128::from(spec.cpus) * 100_000)),
                ("period", Value::Int(100_000)),
            ]),
        ));
    }
    if cgroups && spec.pids > 0 {
        resources.push((
            "pids",
            Value::object([("limit", Value::Int(i128::from(spec.pids)))]),
        ));
    }
    let mut linux = vec![(
        "namespaces",
        Value::array(
            ["pid", "network", "ipc", "uts", "mount"]
                .into_iter()
                .map(|kind| Value::object([("type", Value::string(kind))])),
        ),
    )];
    if !resources.is_empty() {
        linux.push(("resources", Value::object(resources)));
    }

    Value::object([
        ("ociVersion", Value::string("1.0.2")),
        (
            "process",
            Value::object([
                ("terminal", Value::Bool(false)),
                (
                    "user",
                    Value::object([("uid", Value::Int(0)), ("gid", Value::Int(0))]),
                ),
                ("args", Value::array(spec.argv.iter().map(Value::string))),
                ("env", Value::Array(env)),
                ("cwd", Value::string(&spec.cwd)),
                ("noNewPrivileges", Value::Bool(true)),
                (
                    "rlimits",
                    Value::array([Value::object([
                        ("type", Value::string("RLIMIT_NOFILE")),
                        ("hard", Value::Int(65536)),
                        ("soft", Value::Int(65536)),
                    ])]),
                ),
            ]),
        ),
        (
            "root",
            Value::object([
                ("path", Value::string(root.display().to_string())),
                ("readonly", Value::Bool(true)),
            ]),
        ),
        ("hostname", Value::string("cairn-lab")),
        ("mounts", Value::Array(mounts)),
        ("linux", Value::object(linux)),
    ])
}

// -- bubblewrap ----------------------------------------------------------------

fn run_bwrap(bwrap: &Path, spec: &Spec, work: &Path, outcome: &mut Outcome) -> Result<(), String> {
    let mut command = Command::new(bwrap);
    command.args([
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
    ]);
    if spec.network {
        command.arg("--share-net");
    }
    // The run's own root is a tmpfs, laid out as gVisor's is (see the module
    // docs): binding the tree itself at `/` would leave nowhere to create the
    // mount points for inputs and outputs.
    command.args(["--tmpfs", "/"]);
    for entry in top_level(&spec.rootfs, &spec.mounts)? {
        match entry {
            Top::Bind { name, .. } => {
                command
                    .arg("--ro-bind")
                    .arg(spec.rootfs.join(&name))
                    .arg(format!("/{name}"));
            }
            Top::Link { name, target } => {
                command.arg("--symlink").arg(target).arg(format!("/{name}"));
            }
            // Mounted below, each by its own option.
            Top::Own { .. } => {}
        }
    }
    command.args(["--proc", "/proc", "--dev", "/dev"]);
    command.args([
        "--size",
        &(spec.tmp_mb.max(1) * 1024 * 1024).to_string(),
        "--tmpfs",
        "/tmp",
    ]);
    for mount in &spec.mounts {
        command
            .arg(if mount.writable {
                "--bind"
            } else {
                "--ro-bind"
            })
            .arg(&mount.source)
            .arg(&mount.target);
    }
    let mut path_set = false;
    for (key, value) in &spec.env {
        if key == "PATH" {
            path_set = true;
        }
        command.arg("--setenv").arg(key).arg(value);
    }
    if !path_set {
        command.args([
            "--setenv",
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        ]);
    }
    if !spec.env.iter().any(|(key, _)| key == "HOME") {
        command.args(["--setenv", "HOME", "/root"]);
    }
    command.arg("--chdir").arg(&spec.cwd);
    command.arg("--").args(&spec.argv);
    if spec.cpus > 0 || spec.pids > 0 {
        outcome
            .unenforced
            .push("cpu/pids: bubblewrap has no cgroup here; only memory is watched".into());
    }
    command.current_dir(work);
    let child = command
        .stdin(Stdio::null())
        .stdout(File::create(&outcome.stdout).map_err(|e| e.to_string())?)
        .stderr(File::create(&outcome.stderr).map_err(|e| e.to_string())?)
        .spawn()
        .map_err(|e| format!("bwrap: {e}"))?;
    supervise(child, spec, outcome)?;
    // bwrap reports a program it could not exec as its own exit status 1,
    // which would read as the program failing. It is the environment lacking
    // the program, so it is an error, the same as gVisor's equivalent.
    let last_line = tail_of(&outcome.stderr);
    if outcome.exit_status == Some(1) && last_line.contains("bwrap: execvp") {
        outcome.exit_status = None;
        return Err(format!(
            "the command could not be started in this environment: {last_line}"
        ));
    }
    Ok(())
}

// -- unconfined -----------------------------------------------------------------

fn run_unconfined(spec: &Spec, work: &Path, outcome: &mut Outcome) -> Result<(), String> {
    // No root filesystem swap, no namespaces: the command runs on the host.
    // The only thing honoured is where inputs and outputs are, by exporting
    // their host paths, because a sandbox path does not exist here.
    let program = spec.argv.first().ok_or_else(|| "no command".to_string())?;
    let mut command = Command::new(program);
    command.args(&spec.argv[1..]);
    command.current_dir(work);
    for (key, value) in &spec.env {
        command.env(key, value);
    }
    for mount in &spec.mounts {
        let key = format!(
            "CAIRN_LAB_MOUNT_{}",
            mount
                .target
                .trim_start_matches('/')
                .replace(|c: char| !c.is_ascii_alphanumeric(), "_")
                .to_ascii_uppercase()
        );
        command.env(key, &mount.source);
        // The one writable mount is the output directory. `CAIRN_LAB_OUT`
        // names it inside a sandbox; here it has to name the host path, or a
        // program that writes where it is told writes nowhere.
        if mount.writable {
            command.env("CAIRN_LAB_OUT", &mount.source);
        }
    }
    outcome
        .unenforced
        .push("isolation: unconfined run on the host".into());
    outcome.notes.push(
        "unconfined: mounts are host paths, exported as CAIRN_LAB_MOUNT_<TARGET>; \
         CAIRN_LAB_OUT is the host output directory"
            .into(),
    );
    let child = command
        .stdin(Stdio::null())
        .stdout(File::create(&outcome.stdout).map_err(|e| e.to_string())?)
        .stderr(File::create(&outcome.stderr).map_err(|e| e.to_string())?)
        .spawn()
        .map_err(|e| format!("{program}: {e}"))?;
    supervise(child, spec, outcome)
}

/// Wait for a host child with the deadline and the resident-set watchdog.
fn supervise(mut child: Child, spec: &Spec, outcome: &mut Outcome) -> Result<(), String> {
    let deadline = Instant::now() + spec.timeout;
    let limit_kib = spec.memory_mb.saturating_mul(1024);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                outcome.exit_status = exit_code(&status);
                return Ok(());
            }
            Ok(None) => {}
            Err(e) => return Err(format!("wait: {e}")),
        }
        if Instant::now() >= deadline {
            outcome.timed_out = true;
            kill_tree(child.id());
            let _ = child.kill();
            let _ = child.wait();
            return Ok(());
        }
        if limit_kib > 0 && tree_rss_kib(child.id()) > limit_kib {
            outcome.limit_exceeded = true;
            kill_tree(child.id());
            let _ = child.kill();
            let _ = child.wait();
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(unix)]
fn exit_code(status: &std::process::ExitStatus) -> Option<i64> {
    use std::os::unix::process::ExitStatusExt as _;
    match (status.code(), status.signal()) {
        (Some(code), _) => Some(i64::from(code)),
        // The shell convention, so a signal reads the same as under gVisor.
        (None, Some(signal)) => Some(128 + i64::from(signal)),
        (None, None) => None,
    }
}

#[cfg(not(unix))]
fn exit_code(status: &std::process::ExitStatus) -> Option<i64> {
    status.code().map(i64::from)
}

/// Every descendant of `leader`, by parent pid, from `/proc`.
fn descendants(leader: u32) -> Vec<u32> {
    let mut parents: Vec<(u32, u32)> = Vec::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(stat) = fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        // The command name is in parentheses and may contain spaces or
        // parentheses itself; the fields after the last ')' are fixed.
        let Some(after) = stat.rsplit_once(')').map(|(_, rest)| rest) else {
            continue;
        };
        if let Some(ppid) = after.split_whitespace().nth(1).and_then(|p| p.parse().ok()) {
            parents.push((pid, ppid));
        }
    }
    let mut tree = vec![leader];
    let mut i = 0;
    while i < tree.len() {
        let parent = tree[i];
        for &(pid, ppid) in &parents {
            if ppid == parent && !tree.contains(&pid) {
                tree.push(pid);
            }
        }
        i += 1;
    }
    tree
}

fn tree_rss_kib(leader: u32) -> u64 {
    descendants(leader)
        .into_iter()
        .filter_map(|pid| fs::read_to_string(format!("/proc/{pid}/status")).ok())
        .filter_map(|status| {
            status
                .lines()
                .find(|line| line.starts_with("VmRSS:"))
                .and_then(|line| line.split_whitespace().nth(1))
                .and_then(|kib| kib.parse::<u64>().ok())
        })
        .sum()
}

fn kill_tree(leader: u32) {
    for pid in descendants(leader).into_iter().rev() {
        let _ = Command::new("kill")
            .args(["-KILL", &pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// Wait for `child`, killing it via `kill` past `timeout`. Returns its output
/// and whether the deadline fired.
fn wait_with_deadline(
    mut child: Child,
    timeout: Duration,
    kill: impl Fn(),
) -> std::io::Result<(std::process::Output, bool)> {
    let deadline = Instant::now() + timeout;
    let mut timed_out = false;
    loop {
        if child.try_wait()?.is_some() {
            break;
        }
        if !timed_out && Instant::now() >= deadline {
            timed_out = true;
            kill();
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let output = child.wait_with_output()?;
    Ok((output, timed_out))
}

fn tail_of(path: &Path) -> String {
    let text = fs::read_to_string(path).unwrap_or_default();
    let lines: Vec<&str> = text.lines().rev().take(3).collect();
    lines.into_iter().rev().collect::<Vec<_>>().join(" | ")
}

fn nonce() -> [u8; 6] {
    use rand_core::RngCore as _;
    let mut bytes = [0u8; 6];
    rand_core::OsRng.fill_bytes(&mut bytes);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_oci_config_mounts_inputs_read_only_and_the_output_writable() {
        let spec = Spec {
            rootfs: PathBuf::from("/envs/x/rootfs"),
            argv: vec!["/bin/true".into()],
            cwd: "/work".into(),
            env: vec![("PATH".into(), "/opt/sage/bin:/usr/bin".into())],
            mounts: vec![
                Mount {
                    source: PathBuf::from("/host/in"),
                    target: "/in".into(),
                    writable: false,
                },
                Mount {
                    source: PathBuf::from("/host/out"),
                    target: "/out".into(),
                    writable: true,
                },
            ],
            timeout: Duration::from_secs(5),
            memory_mb: 512,
            cpus: 2,
            pids: 64,
            tmp_mb: 64,
            network: false,
            runtime_dir: PathBuf::from("/var/lib/cairn-lab/runsc"),
        };
        let binds = vec![Mount {
            source: PathBuf::from("/env/usr"),
            target: "/usr".into(),
            writable: false,
        }];
        let config = oci_config(&spec, Path::new("/work/root"), &binds, true);
        let text = config.canonical_string();
        assert!(text.contains(r#""readonly":true"#), "{text}");
        // The runtime is handed the run's own root, never the environment's.
        assert_eq!(
            config
                .get("root")
                .and_then(|r| r.get("path"))
                .and_then(Value::as_str),
            Some("/work/root")
        );
        assert!(text.contains(r#""PATH=/opt/sage/bin:/usr/bin""#), "{text}");
        let mounts = config
            .get("mounts")
            .and_then(Value::as_array)
            .expect("mounts");
        let find = |target: &str| {
            mounts
                .iter()
                .find(|m| m.get("destination").and_then(Value::as_str) == Some(target))
                .and_then(|m| m.get("options"))
                .map(Value::canonical_string)
                .unwrap_or_default()
        };
        assert!(find("/in").contains("\"ro\""));
        assert!(find("/out").contains("\"rw\""));
        assert!(find("/usr").contains("\"ro\""));
        // The environment is mounted before anything is mounted inside it.
        let position = |target: &str| {
            mounts
                .iter()
                .position(|m| m.get("destination").and_then(Value::as_str) == Some(target))
                .expect("mounted")
        };
        assert!(position("/usr") < position("/in"));
        let memory = config
            .get("linux")
            .and_then(|l| l.get("resources"))
            .and_then(|r| r.get("memory"))
            .and_then(|m| m.get("limit"))
            .and_then(Value::as_i128);
        assert_eq!(memory, Some(512 * 1024 * 1024));
        // Without cgroups there is no resources block to pretend with.
        let rootless = oci_config(&spec, Path::new("/work/root"), &binds, false);
        assert!(rootless
            .get("linux")
            .and_then(|l| l.get("resources"))
            .is_none());
    }

    #[test]
    fn a_signal_reads_as_128_plus_its_number_like_a_shell_says_it() {
        #[cfg(unix)]
        {
            let status = Command::new("/bin/sh")
                .args(["-c", "kill -9 $$"])
                .status()
                .expect("spawn");
            assert_eq!(exit_code(&status), Some(137));
        }
    }

    #[test]
    fn an_unconfined_run_honours_the_deadline() {
        let work = std::env::temp_dir().join(format!(
            "cairn-lab-exec-{}-{}",
            std::process::id(),
            crate::hex::encode(&nonce())
        ));
        fs::create_dir_all(&work).expect("mkdir");
        let spec = Spec {
            rootfs: PathBuf::from("/"),
            argv: vec!["/bin/sh".into(), "-c".into(), "sleep 30".into()],
            cwd: "/".into(),
            env: Vec::new(),
            mounts: Vec::new(),
            timeout: Duration::from_millis(300),
            memory_mb: 0,
            cpus: 0,
            pids: 0,
            tmp_mb: 16,
            network: false,
            runtime_dir: std::env::temp_dir().join("cairn-lab-runtime"),
        };
        let outcome = run(&Backend::Unconfined, &spec, &work);
        assert!(outcome.timed_out, "{outcome:?}");
        assert!(outcome.wall_ms < 10_000);
        assert!(!outcome.succeeded());
        let _ = fs::remove_dir_all(&work);
    }

    fn environment(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "cairn-lab-layout-{name}-{}-{}",
            std::process::id(),
            crate::hex::encode(&nonce())
        ));
        fs::create_dir_all(root.join("usr/share/doc")).expect("mkdir");
        fs::create_dir_all(root.join("proc")).expect("mkdir");
        fs::create_dir_all(root.join("out")).expect("mkdir");
        fs::write(root.join(".dockerenv"), b"").expect("write");
        fs::write(root.join("usr/share/motd"), b"hi").expect("write");
        #[cfg(unix)]
        std::os::unix::fs::symlink("usr/bin", root.join("bin")).expect("link");
        root
    }

    #[test]
    fn a_mount_point_the_environment_lacks_is_refused_unless_it_is_new_at_the_top() {
        let env = environment("targets");
        let check = |target: &str, dir: bool| check_target(&env, target, dir);
        // New at the top level: made in the run's own root.
        assert!(check("/work/x", true).is_ok());
        assert!(check("/in/experiments/a.py", false).is_ok());
        // At the top level: replaces the environment's entry, whatever it is.
        assert!(check("/out", true).is_ok());
        assert!(check("/out", false).is_ok());
        assert!(check("/.dockerenv", true).is_ok());
        // Deeper and already there as the same kind: covered, nothing made.
        assert!(check("/usr/share/doc", true).is_ok());
        assert!(check("/usr/share/motd", false).is_ok());
        // The run's own tmpfs.
        assert!(check("/tmp/scratch", true).is_ok());
        // Would be created inside the environment's own directories.
        let inside = check("/usr/share/new", true).expect_err("refused");
        assert!(inside.contains("/work/new"), "{inside}");
        assert!(check("/out/sub", true).is_err());
        // Through a link, a file, or over the wrong kind.
        #[cfg(unix)]
        assert!(check("/bin/x", true).is_err());
        assert!(check("/usr/share/motd/x", true).is_err());
        assert!(check("/usr/share/doc", false).is_err());
        assert!(check("/usr/share/motd", true).is_err());
        // Not a path the sandbox can take.
        assert!(check("/proc/x", true).is_err());
        assert!(check("/tmp", true).is_err());
        assert!(check("relative", true).is_err());
        assert!(check("/a/../b", true).is_err());
        assert!(check("/a//b", true).is_err());

        // Mounts may neither repeat nor nest: runsc orders them itself.
        let at = |target: &str| Mount {
            source: env.join("usr"),
            target: target.into(),
            writable: false,
        };
        assert!(check_targets(&env, &[at("/in/a"), at("/in/b"), at("/out")]).is_ok());
        assert!(check_targets(&env, &[at("/out"), at("/out")]).is_err());
        assert!(check_targets(&env, &[at("/work"), at("/work/sub")]).is_err());
        assert!(check_targets(&env, &[at("/work/sub"), at("/work")]).is_err());
        assert!(check_targets(&env, &[at("/work"), at("/workshop")]).is_ok());
        let _ = fs::remove_dir_all(&env);
    }

    #[test]
    fn a_runs_root_mirrors_the_top_level_and_leaves_the_environment_alone() {
        let env = environment("scaffold");
        let before = super::super::env::tree_digest(&env).expect("digest");
        let root = env.with_extension("root");
        let output = Mount {
            source: root.with_extension("out"),
            target: "/out".into(),
            writable: true,
        };
        let binds = scaffold_root(&env, &root, std::slice::from_ref(&output)).expect("scaffold");
        // The environment's own `/out` is replaced by the run's, not covered.
        let targets: Vec<&str> = binds.iter().map(|b| b.target.as_str()).collect();
        assert_eq!(targets, ["/.dockerenv", "/usr"]);
        assert!(!root.join("out").exists());
        assert!(binds.iter().all(|b| !b.writable));
        assert!(root.join("usr").is_dir() && root.join(".dockerenv").is_file());
        // The sandbox's own mount points exist; the environment's `/proc` is
        // not bound.
        for own in SANDBOX_OWNED {
            assert!(root.join(own).is_dir(), "{own}");
        }
        #[cfg(unix)]
        assert_eq!(
            fs::read_link(root.join("bin")).expect("link"),
            PathBuf::from("usr/bin")
        );
        assert_eq!(
            super::super::env::tree_digest(&env).expect("digest"),
            before
        );
        let _ = fs::remove_dir_all(&env);
        let _ = fs::remove_dir_all(&root);
    }
}
