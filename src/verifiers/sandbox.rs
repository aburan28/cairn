//! An OS jail around every process that runs objective-authored code.
//!
//! The verifier module spawns three kinds of child: pinned checker/evaluator/
//! statistic source, a `replay` command, and `lean` on a submitted proof. All
//! three execute code that somebody other than the node operator wrote, so all
//! three go through here.
//!
//! # What this is and is not
//!
//! It is a *kernel-enforced* boundary: no network, and nothing written to the
//! host outside a scratch directory that is deleted when the check finishes.
//! (Under bubblewrap a write to a path the jail does not show from the host
//! lands on the jail's own tmpfs and goes with it; seatbelt refuses it. Neither
//! reaches the host.) It is not a VM
//! and not a container image. A kernel bug or a sandbox-policy bug is still an
//! escape. See [`super::SANDBOXING`] for the enforced/not-enforced list that is
//! kept honest against the threat model.
//!
//! # Why the mechanism is probed rather than assumed
//!
//! `bwrap` being installed does not mean it works: unprivileged user namespaces
//! are disabled outright on some distributions and inside many container
//! runtimes, and the failure looks like a spawn error at verification time
//! rather than at startup. Probing once and caching the answer means a host
//! where the jail cannot work degrades to the documented fallback instead of
//! reporting every artifact `Unavailable`.
//!
//! # The one rule
//!
//! Nothing in this module may produce a rejection. A jail that will not start,
//! a mechanism that is absent, a limit that cannot be set — every one of those
//! is a fact about this node, and the caller turns it into
//! [`super::Status::Unavailable`]. A sandbox that could reject would hand an
//! attacker a way to fail honest submissions by breaking a host.

use std::ffi::{OsStr, OsString};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use super::which;

/// Set to `1` to refuse to run objective code at all without a working jail.
///
/// The right setting for a node that verifies objectives it did not write. It
/// is not the default because that would turn every macOS/Linux host without a
/// jail mechanism into a node that answers `Unavailable` to everything, and a
/// network of nodes that cannot verify is worse than one that verifies in a
/// documented weaker mode.
pub const REQUIRE_ENV: &str = "CAIRN_REQUIRE_SANDBOX";

/// Address-space cap for pinned pure functions, in MiB. `0` disables it.
pub const MEMORY_ENV: &str = "CAIRN_SANDBOX_MEMORY_MB";

/// Default address-space cap. A pinned `check`/`score`/`statistic` that needs
/// more than this is not a verifier anyone should be running synchronously.
const DEFAULT_MEMORY_MB: u64 = 4096;

/// Which jail this host can actually use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mechanism {
    /// `bwrap`, at the resolved path. Linux.
    Bubblewrap(PathBuf),
    /// `sandbox-exec`, at the resolved path. macOS seatbelt.
    Seatbelt(PathBuf),
    /// Nothing available. Carries why, for the evidence field.
    None(&'static str),
}

impl Mechanism {
    /// The name recorded in verdict evidence. Auditors compare verdicts across
    /// nodes; knowing a disagreeing node ran unjailed is the first question.
    pub fn as_str(&self) -> &'static str {
        match self {
            Mechanism::Bubblewrap(_) => "bwrap",
            Mechanism::Seatbelt(_) => "sandbox-exec",
            Mechanism::None(_) => "none",
        }
    }

    pub fn is_jail(&self) -> bool {
        !matches!(self, Mechanism::None(_))
    }
}

/// What the child is allowed to touch.
pub struct Confinement<'a> {
    /// Scratch directory. Always writable, always the child's `$TMPDIR`.
    pub workdir: &'a Path,
    /// Where the child starts. Must be readable; need not be writable.
    pub cwd: &'a Path,
    /// Extra paths the child must be able to read.
    pub readable: Vec<PathBuf>,
    /// Extra paths the child must be able to write. Empty is the normal case.
    pub writable: Vec<PathBuf>,
    /// Replace the environment with a minimal one. Objective-authored code
    /// must not inherit operator credentials through any verifier path.
    pub scrub_env: bool,
    /// `RLIMIT_CPU`, seconds. Complements the wall-clock kill: a child that
    /// spins in a tight loop hits this first and dies on `SIGXCPU`.
    pub cpu_seconds: u64,
    /// `RLIMIT_AS`, MiB, on Linux; on macOS, which has no `RLIMIT_AS`, the
    /// same number caps the process tree's physical footprint, measured by
    /// [`super::limits::Watch`]. `0` leaves memory unbounded.
    pub memory_mb: u64,
    /// Cores the process tree may keep busy on average, from
    /// [`super::limits::CPUS_ENV`]. `0` is no cap. Every spawn path gets it:
    /// unlike the memory cap it cannot fail a checker that stays inside its
    /// own `RLIMIT_CPU`, so nothing needs to opt out.
    pub cpus: u32,
}

impl<'a> Confinement<'a> {
    pub fn new(workdir: &'a Path, cwd: &'a Path, cpu_seconds: u64) -> Confinement<'a> {
        Confinement {
            workdir,
            cwd,
            readable: Vec::new(),
            writable: Vec::new(),
            scrub_env: false,
            cpu_seconds,
            memory_mb: 0,
            cpus: super::limits::configured_cpus(),
        }
    }

    /// What `run_bounded` holds the running child to.
    pub fn limits(&self) -> super::limits::Limits {
        super::limits::Limits {
            cpus: self.cpus,
            memory_mb: self.memory_mb,
        }
    }

    pub fn reading(mut self, path: impl Into<PathBuf>) -> Confinement<'a> {
        self.readable.push(path.into());
        self
    }

    pub fn writing(mut self, path: impl Into<PathBuf>) -> Confinement<'a> {
        self.writable.push(path.into());
        self
    }

    pub fn scrubbed(mut self) -> Confinement<'a> {
        self.scrub_env = true;
        self
    }

    pub fn capped_memory(mut self) -> Confinement<'a> {
        self.memory_mb = configured_memory_mb();
        self
    }
}

/// A [`Command`] that will run confined, plus the mechanism that confines it.
pub struct Jailed {
    pub command: Command,
    pub mechanism: &'static str,
}

/// Why a jail could not be built. Always becomes `Unavailable`, never a
/// rejection — hence a plain reason string rather than a status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unavailable(pub String);

/// Build the command that runs `program args…` under whatever jail this host
/// has.
///
/// `program` must already be an absolute path: resolving a name through `PATH`
/// inside the jail would pick a different binary than the one the caller
/// checked, and under `bwrap` it would usually not resolve at all.
pub fn confine(
    program: &Path,
    args: &[OsString],
    plan: &Confinement<'_>,
) -> Result<Jailed, Unavailable> {
    let mechanism = mechanism();
    let required = require_sandbox(std::env::var(REQUIRE_ENV).ok().as_deref());
    // Strict mode is a promise about the whole host boundary, not only the
    // availability of a kernel jail. Replay and Lean normally inherit the
    // operator's environment for toolchain discovery, but an objective can
    // print those values into verdict evidence without using the network.
    // Requiring the sandbox therefore also requires a scrubbed environment.
    let scrub_env = effective_scrub_env(plan, required);

    match mechanism {
        Mechanism::None(why) if required => Err(Unavailable(format!(
            "{REQUIRE_ENV} is set and no sandbox mechanism is usable here ({why}); \
             refusing to run objective-authored code unjailed"
        ))),
        Mechanism::None(_) => Ok(Jailed {
            command: bare(program, args, plan, scrub_env),
            mechanism: "none",
        }),
        Mechanism::Bubblewrap(bwrap) => Ok(Jailed {
            command: bubblewrap(bwrap, program, args, plan, scrub_env),
            mechanism: "bwrap",
        }),
        Mechanism::Seatbelt(sandbox_exec) => seatbelt(sandbox_exec, program, args, plan, scrub_env),
    }
}

fn effective_scrub_env(plan: &Confinement<'_>, required: bool) -> bool {
    plan.scrub_env || required
}

/// Whether this process was started with [`REQUIRE_ENV`] asking for a
/// mandatory jail: what `GET /verifiers` reports beside the mechanism, so a
/// node that answers `Unavailable` to everything can say why.
pub fn required() -> bool {
    require_sandbox(std::env::var(REQUIRE_ENV).ok().as_deref())
}

/// Whether [`REQUIRE_ENV`] asks for a mandatory jail.
///
/// Fails closed. This is a security kill-switch, so `=true`, `=yes`, or a typo
/// must not silently mean "off" -- the failure mode of a misread value is
/// objective-authored code running unjailed with nothing printed anywhere.
/// Only unset, empty, and the explicit off spellings leave the requirement
/// off; every other value turns it on.
fn require_sandbox(value: Option<&str>) -> bool {
    match value {
        None => false,
        Some(text) => {
            let normalized = text.trim().to_ascii_lowercase();
            !matches!(normalized.as_str(), "" | "0" | "false" | "no" | "off")
        }
    }
}

/// The jail this host can use, probed once.
pub fn mechanism() -> Mechanism {
    static CACHED: OnceLock<Mechanism> = OnceLock::new();
    CACHED.get_or_init(probe).clone()
}

fn probe() -> Mechanism {
    if cfg!(target_os = "linux") {
        if let Some(bwrap) = which("bwrap") {
            // `bwrap` installs fine on hosts where unprivileged user
            // namespaces are switched off; only running it tells you.
            let ok = Command::new(&bwrap)
                .args(["--ro-bind", "/", "/", "--unshare-net", "--", "/bin/true"])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|status| status.success())
                .unwrap_or(false);
            if ok {
                return Mechanism::Bubblewrap(bwrap);
            }
            return Mechanism::None(
                "bwrap is installed but cannot create a namespace on this host",
            );
        }
        return Mechanism::None("bwrap is not installed");
    }
    if cfg!(target_os = "macos") {
        if let Some(sandbox_exec) = which("sandbox-exec") {
            let ok = Command::new(&sandbox_exec)
                .args(["-p", "(version 1)(allow default)", "/usr/bin/true"])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|status| status.success())
                .unwrap_or(false);
            if ok {
                return Mechanism::Seatbelt(sandbox_exec);
            }
            return Mechanism::None("sandbox-exec is present but refused a trivial profile");
        }
        return Mechanism::None("sandbox-exec is not available");
    }
    Mechanism::None("no jail mechanism is implemented for this platform")
}

/// [`MEMORY_ENV`], or its default. Public so `run` can say at startup which
/// cap its verifiers get.
pub fn configured_memory_mb() -> u64 {
    match std::env::var(MEMORY_ENV) {
        Ok(text) => text.trim().parse::<u64>().unwrap_or(DEFAULT_MEMORY_MB),
        Err(_) => DEFAULT_MEMORY_MB,
    }
}

/// Unjailed fallback: still resource-limited, still on a scratch cwd.
fn bare(program: &Path, args: &[OsString], plan: &Confinement<'_>, scrub_env: bool) -> Command {
    let (bin, argv) = with_limits(program, args, plan);
    let mut command = Command::new(bin);
    command.args(argv).current_dir(plan.cwd);
    apply_env(&mut command, plan, scrub_env);
    command
}

fn bubblewrap(
    bwrap: PathBuf,
    program: &Path,
    args: &[OsString],
    plan: &Confinement<'_>,
    scrub_env: bool,
) -> Command {
    let mut command = Command::new(bwrap);
    command.args([
        // The point of the exercise: objective code cannot phone home, and it
        // cannot see or signal anything else on the box.
        "--unshare-net",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-pid",
        // Without this a child that outlives a killed node keeps running with
        // its jail intact and nobody watching it.
        "--die-with-parent",
        // Detach the controlling terminal so the child cannot inject keystrokes
        // into the operator's shell with TIOCSTI.
        "--new-session",
    ]);
    command.args(["--proc", "/proc"]);
    command.args(["--dev", "/dev"]);
    command.args(["--tmpfs", "/tmp"]);

    let mut view = View::default();
    // System directories, read only. `/bin` and friends are symlinks into
    // `/usr` on merged-usr distributions; binding a symlink source as a
    // directory fails, so recreate the link instead.
    for top in ["/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64"] {
        let path = Path::new(top);
        match std::fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_symlink() => {
                if let Ok(target) = std::fs::read_link(path) {
                    command.arg("--symlink").arg(target).arg(top);
                    view.shown.push(path.to_path_buf());
                }
            }
            Ok(_) => {
                command.arg("--ro-bind").arg(top).arg(top);
                view.shown.push(path.to_path_buf());
            }
            Err(_) => {}
        }
    }

    // What the child executes must be in the jail under the name it is
    // executed by: the shell that sets the limits, and the program that shell
    // hands over to. Callers list the program as readable anyway; the seatbelt
    // profile allows both regardless of the plan, and so does this.
    let (bin, argv) = with_limits(program, args, plan);
    view.read(&mut command, "--ro-bind", Path::new(&bin));
    view.read(&mut command, "--ro-bind", program);
    for path in &plan.readable {
        view.read(&mut command, "--ro-bind", path);
    }
    // After the read-only binds, so an entry in both lists ends up writable.
    view.write(&mut command, plan.workdir);
    for path in &plan.writable {
        view.write(&mut command, path);
    }
    // The cwd only has to be readable, and for two callers it is also writable:
    // a pinned run's cwd *is* its scratch directory, and `workspace` runs its
    // build in a tree it binds writable. Bound read-only unconditionally, as it
    // used to be, that mount landed on top of the writable one above and won (a
    // later bind wins): under bubblewrap, and nowhere else, every pinned
    // checker found its `$TMPDIR` read-only, and a `workspace` build could not
    // write its tree. A read-only bind is now skipped wherever the jail already
    // shows the path, which covers a cwd inside the scratch directory, inside a
    // writable path, or inside anything bound read-only already.
    view.read(&mut command, "--ro-bind-try", plan.cwd);
    view.recreate_links(&mut command);
    command.arg("--chdir").arg(plan.cwd);

    if scrub_env {
        command.arg("--clearenv");
        for (key, value) in minimal_env(plan) {
            command.arg("--setenv").arg(key).arg(value);
        }
    } else {
        command.arg("--setenv").arg("TMPDIR").arg(plan.workdir);
    }

    command.arg("--").arg(bin).args(argv);
    // bwrap itself must start in a directory that exists outside the jail.
    command.current_dir(plan.workdir);
    apply_env(&mut command, plan, scrub_env);
    command
}

/// The host paths a bubblewrap jail shows, and the symlinks that lead to them.
///
/// bwrap creates a bind's destination inside its own scratch root, before
/// that root becomes `/`. A destination running through a symlink the jail
/// already has -- `/usr/local/bin/python3 -> /usr/bin/python3.11`, inside the
/// `/usr` bind -- is followed *there*, where an absolute target names nothing,
/// so binding the interpreter at the name `which` found died with "Can't create
/// file at /usr/local/bin/python3" before the checker started, and every
/// verdict on the host was `Unavailable`. Where the bind did not fail, the name
/// could still be dead inside the jail: Debian's `/usr/bin/python3 ->
/// /etc/alternatives/python3` points out of everything the jail shows.
///
/// So each path is bound where its symlinks end, a destination that by
/// construction runs through none, and the symlinks between the caller's name
/// and that place are recreated inside the jail -- unless it already has them,
/// as it does anything under `/usr`. The child still runs a program by the name
/// it was given. Executing the resolved file instead would be simpler and wrong:
/// argv\[0\] is how busybox and rustup-style proxies (elan's `lean` among them)
/// choose what to be. bwrap's `--argv0` cannot help either: bwrap executes the
/// limits shell, not the program, and the flag only exists from bwrap 0.9.
#[derive(Default)]
struct View {
    /// What the jail shows from the host, with everything beneath it: the
    /// system directories, then each bind as it is made.
    shown: Vec<PathBuf>,
    /// `(link, target)` for each symlink met on the way to a bind.
    links: Vec<(PathBuf, PathBuf)>,
}

impl View {
    fn shows(&self, path: &Path) -> bool {
        self.shown.iter().any(|shown| path.starts_with(shown))
    }

    /// Bind `path` read-only, unless the jail already shows it. Either way it
    /// is readable, and a read-only mount over something already mounted
    /// writable takes the write away: the later mount wins.
    fn read(&mut self, command: &mut Command, flag: &str, path: &Path) {
        if let Some(at) = self.place(path) {
            if !self.shows(&at) {
                self.mount(command, flag, at);
            }
        }
    }

    /// Bind `path` writable, whatever already shows it.
    fn write(&mut self, command: &mut Command, path: &Path) {
        if let Some(at) = self.place(path) {
            self.mount(command, "--bind", at);
        }
    }

    /// Where `path` is bound, noting the symlinks that lead there. `None` when
    /// it does not resolve, the same "nothing to bind" the `exists()` checks
    /// here always gave.
    fn place(&mut self, path: &Path) -> Option<PathBuf> {
        let trace = trace(path)?;
        if trace.links.iter().any(|(link, _)| mounted_by_jail(link)) {
            // A symlink where bwrap mounts something of its own -- a host whose
            // `/tmp` is a link -- cannot be recreated, so the only place this
            // path can appear is where the caller named it, as every bind did
            // before. Under `/tmp` that works: bwrap resolves the source
            // itself, and the destination is in the jail's fresh tmpfs, which
            // holds no host symlinks to follow.
            return Some(path.to_path_buf());
        }
        for link in trace.links {
            if !self.links.contains(&link) {
                self.links.push(link);
            }
        }
        Some(trace.canonical)
    }

    fn mount(&mut self, command: &mut Command, flag: &str, at: PathBuf) {
        command.arg(flag).arg(&at).arg(&at);
        self.shown.push(at);
    }

    /// Recreate the links the jail does not already have. Last, so that
    /// everything the jail will show is known: a link inside a bound directory
    /// is the host's own and already there.
    fn recreate_links(&self, command: &mut Command) {
        for (link, target) in &self.links {
            if !self.shows(link) {
                command.arg("--symlink").arg(target).arg(link);
            }
        }
    }
}

/// Paths bubblewrap mounts for the jail itself, before any bind.
fn mounted_by_jail(path: &Path) -> bool {
    path == Path::new("/tmp") || path.starts_with("/proc") || path.starts_with("/dev")
}

/// How a path reaches its file.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Trace {
    /// The path with every symlink resolved; it runs through none.
    canonical: PathBuf,
    /// `(link, target)` for each symlink followed, in order. A link's parent is
    /// always canonical, so `link` is exactly where the jail needs it.
    links: Vec<(PathBuf, PathBuf)>,
}

/// Resolve `path` a component at a time, as the kernel does, and record each
/// symlink followed. [`std::fs::canonicalize`] gives the same end point and
/// throws away the links the jail has to recreate.
///
/// `None` when the path does not resolve: a missing component, a file used as
/// a directory, or a loop.
fn trace(path: &Path) -> Option<Trace> {
    // Linux's own limit (MAXSYMLINKS) before a lookup fails with ELOOP.
    const MAX_LINKS: usize = 40;

    let mut canonical = if path.is_absolute() {
        PathBuf::from("/")
    } else {
        std::env::current_dir().ok()?
    };
    let mut pending = Vec::new();
    queue_components(&mut pending, path);
    let mut links = Vec::new();
    while let Some(name) = pending.pop() {
        if name == ".." {
            canonical.pop();
            continue;
        }
        let next = canonical.join(&name);
        let meta = std::fs::symlink_metadata(&next).ok()?;
        if !meta.file_type().is_symlink() {
            canonical = next;
            continue;
        }
        if links.len() == MAX_LINKS {
            return None;
        }
        let target = std::fs::read_link(&next).ok()?;
        if target.is_absolute() {
            canonical = PathBuf::from("/");
        }
        queue_components(&mut pending, &target);
        links.push((next, target));
    }
    Some(Trace { canonical, links })
}

/// Push `path`'s components so that popping returns them first to last.
///
/// `..` stays a marker rather than being folded away lexically. It means the
/// parent of what has been resolved so far, and after a symlink that is not the
/// parent of what was written.
fn queue_components(pending: &mut Vec<OsString>, path: &Path) {
    for component in path.components().rev() {
        match component {
            Component::Normal(name) => pending.push(name.to_os_string()),
            Component::ParentDir => pending.push(OsString::from("..")),
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
        }
    }
}

fn seatbelt(
    sandbox_exec: PathBuf,
    program: &Path,
    args: &[OsString],
    plan: &Confinement<'_>,
    scrub_env: bool,
) -> Result<Jailed, Unavailable> {
    // Seatbelt matches on fully resolved paths. `/tmp` is a symlink to
    // `/private/tmp` on macOS and `$TMPDIR` lives under `/var/folders`, which
    // is also symlinked, so an unresolved subpath silently allows nothing and
    // every write fails. Cost of getting this wrong: the jail looks like it
    // works and instead makes the node useless.
    let mut writable = vec![resolve(plan.workdir)];
    for path in &plan.writable {
        writable.push(resolve(path));
    }

    let profile = seatbelt_profile(program, plan, &writable);

    if profile.contains('\0') {
        return Err(Unavailable(
            "sandbox profile contains a NUL byte; refusing to run unjailed".into(),
        ));
    }

    let mut command = Command::new(sandbox_exec);
    command.arg("-p").arg(&profile);
    let (bin, argv) = with_limits(program, args, plan);
    command.arg(bin).args(argv);
    command.current_dir(plan.cwd);
    apply_env(&mut command, plan, scrub_env);
    Ok(Jailed {
        command,
        mechanism: "sandbox-exec",
    })
}

/// A deny-by-default Seatbelt profile with an explicit filesystem allow-list.
///
/// The previous profile used `(allow default)` and denied only writes and the
/// network. On macOS that let objective code read the operator's SSH keys and
/// return them in verdict output. System/runtime files and declared bundle
/// paths remain readable; operator data outside those paths does not.
fn seatbelt_profile(program: &Path, plan: &Confinement<'_>, writable: &[PathBuf]) -> String {
    let mut readable = vec![
        PathBuf::from("/System"),
        PathBuf::from("/Library"),
        PathBuf::from("/usr"),
        resolve(Path::new("/bin/sh")),
        resolve(program),
        resolve(plan.workdir),
        resolve(plan.cwd),
    ];
    readable.extend(plan.readable.iter().map(|path| resolve(path)));
    readable.extend(writable.iter().cloned());

    // A Homebrew, rustup, pyenv, or elan executable normally loads libraries
    // and adjacent resources from the version root two levels above `bin`.
    // Allow that version root, not the whole package manager or home directory.
    if let Some(runtime_root) = narrow_runtime_root(&resolve(program)) {
        // A runtime root is an installation prefix such as
        // `/opt/homebrew/Cellar/python@3.13/3.13.2`, never the filesystem
        // root. In particular, the grandparent of `/bin/sh` is `/`; adding
        // it here turns the deny-by-default profile into a read-everything
        // profile.
        readable.push(runtime_root);
    }
    readable.sort();
    readable.dedup();

    let mut profile = String::from(
        "(version 1)\n(deny default)\n(import \"system.sb\")\n(deny network*)\n\
         (allow process-fork)\n(allow process-exec)\n(allow signal (target self))\n\
         (allow file-read-metadata)\n",
    );
    for path in &readable {
        let text = path.to_string_lossy();
        profile.push_str(&format!(
            "(allow file-read* file-map-executable (subpath \"{}\"))\n",
            escape(&text)
        ));
    }
    for path in writable {
        let text = path.to_string_lossy();
        profile.push_str(&format!(
            "(allow file-write* (subpath \"{}\"))\n",
            escape(&text)
        ));
    }
    // A child that cannot write to /dev/null fails in ways that look like the
    // artifact's fault rather than the jail's.
    profile.push_str("(allow file-write-data (literal \"/dev/null\"))\n");
    profile.push_str("(allow file-write-data (literal \"/dev/dtracehelper\"))\n");
    profile
}

/// The narrow installation prefix needed by a runtime, when its shape is safe.
///
/// `~/bin/tool`, `~/.local/bin/tool`, and versioned rustup/pyenv/elan installs
/// are common, but every one is below the operator's home. Granting any such
/// subtree to objective-authored code can expose unrelated operator data, so a
/// runtime beneath a home directory is refused rather than broadened into a
/// read capability. System installation prefixes remain usable.
fn narrow_runtime_root(executable: &Path) -> Option<PathBuf> {
    let root = executable.parent()?.parent()?.to_path_buf();
    if root == Path::new("/") {
        return None;
    }

    let configured_home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|path| resolve(&path));
    let structural_home = |path: &Path| {
        path == Path::new("/root")
            || path
                .parent()
                .is_some_and(|parent| parent == Path::new("/Users") || parent == Path::new("/home"))
    };
    if configured_home
        .as_deref()
        .is_some_and(|home| root.starts_with(home))
        || root.ancestors().any(structural_home)
    {
        return None;
    }
    Some(root)
}

/// Prefix the child with a shell that sets `ulimit`s, when a shell exists.
///
/// `std::process::Command` has no portable hook for `setrlimit` between fork
/// and exec, and this crate does not depend on `libc`. `sh -c 'ulimit …; exec
/// "$@"'` gets the same limits applied in the same place at the cost of one
/// short-lived process. Each `ulimit` is allowed to fail — macOS has no
/// `RLIMIT_AS` — because a limit that cannot be set is best-effort by
/// specification, not a reason to refuse to verify.
fn with_limits(
    program: &Path,
    args: &[OsString],
    plan: &Confinement<'_>,
) -> (OsString, Vec<OsString>) {
    let shell = Path::new("/bin/sh");
    let wanted = plan.cpu_seconds > 0 || plan.memory_mb > 0;
    if !wanted || !shell.exists() {
        let mut argv = Vec::with_capacity(args.len());
        argv.extend_from_slice(args);
        return (program.as_os_str().to_os_string(), argv);
    }

    let mut script = String::new();
    if plan.cpu_seconds > 0 {
        script.push_str(&format!("ulimit -t {} 2>/dev/null;", plan.cpu_seconds));
    }
    if plan.memory_mb > 0 {
        // `ulimit -v` is in kibibytes. Saturating: an operator who asks for
        // an absurd cap gets no cap rather than an overflow.
        let kib = plan.memory_mb.saturating_mul(1024);
        script.push_str(&format!("ulimit -v {kib} 2>/dev/null;"));
    }
    script.push_str(" exec \"$@\"");

    let mut argv: Vec<OsString> = vec![
        OsString::from("-c"),
        OsString::from(script),
        // `$0` for the shell; `$@` starts at the program.
        OsString::from("cairn-jail"),
        program.as_os_str().to_os_string(),
    ];
    argv.extend_from_slice(args);
    (shell.as_os_str().to_os_string(), argv)
}

fn apply_env(command: &mut Command, plan: &Confinement<'_>, scrub_env: bool) {
    if scrub_env {
        command.env_clear();
        for (key, value) in minimal_env(plan) {
            command.env(key, value);
        }
    } else {
        command.env("TMPDIR", plan.workdir);
    }
}

/// The environment a pinned pure function gets.
///
/// `PATH` survives because interpreters are routinely shims that re-exec
/// themselves through it (pyenv, asdf, `/usr/bin/env`), and losing it turns a
/// working node into one that reports `Unavailable` for everything. Everything
/// else goes: an objective's checker has no business reading the operator's
/// tokens out of the environment, and it is the one exfiltration channel that
/// survives having no network.
fn minimal_env(plan: &Confinement<'_>) -> Vec<(OsString, OsString)> {
    let path =
        std::env::var_os("PATH").unwrap_or_else(|| OsString::from("/usr/local/bin:/usr/bin:/bin"));
    vec![
        (OsString::from("PATH"), path),
        (OsString::from("LANG"), OsString::from("C.UTF-8")),
        (OsString::from("LC_ALL"), OsString::from("C.UTF-8")),
        (
            OsString::from("HOME"),
            plan.workdir.as_os_str().to_os_string(),
        ),
        (
            OsString::from("TMPDIR"),
            plan.workdir.as_os_str().to_os_string(),
        ),
        // Bytecode caching writes next to the source, which is read-only here;
        // Python tolerates the failure but the wasted syscalls are noise.
        (
            OsString::from("PYTHONDONTWRITEBYTECODE"),
            OsString::from("1"),
        ),
    ]
}

fn resolve(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn escape(text: &str) -> String {
    text.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Convenience for callers assembling `argv` out of `&str` and `&Path`.
pub fn argv<I, S>(parts: I) -> Vec<OsString>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    parts
        .into_iter()
        .map(|part| part.as_ref().to_os_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_probe_is_stable_and_names_itself() {
        let first = mechanism();
        assert_eq!(first, mechanism());
        assert!(!first.as_str().is_empty());
        // On the two platforms this crate targets a jail should be reachable.
        // Anywhere else the fallback is expected, so this is not an assertion
        // about the mechanism, only that the answer is one of the three.
        assert!(matches!(
            first,
            Mechanism::Bubblewrap(_) | Mechanism::Seatbelt(_) | Mechanism::None(_)
        ));
        // Except where a run says which jail it installed. A jail that cannot
        // start falls back to running unjailed, and every other test here
        // passes either way, so CI's `jail` job would go green having tested
        // nothing it exists to test.
        if let Ok(expected) = std::env::var("CAIRN_EXPECT_SANDBOX") {
            assert_eq!(first.as_str(), expected, "{first:?}");
        }
    }

    #[test]
    fn a_scrubbed_environment_keeps_path_and_drops_secrets() {
        let dir = PathBuf::from("/tmp/cairn-env-test");
        let plan = Confinement::new(&dir, &dir, 1).scrubbed();
        let env = minimal_env(&plan);
        let keys: Vec<String> = env
            .iter()
            .map(|(k, _)| k.to_string_lossy().into_owned())
            .collect();
        assert!(keys.contains(&"PATH".to_string()));
        assert!(!keys
            .iter()
            .any(|k| k.contains("TOKEN") || k.contains("KEY")));
    }

    #[test]
    fn strict_mode_scrubs_replay_and_lean_even_when_the_plan_does_not() {
        let dir = PathBuf::from("/tmp/proofwork-strict-env-test");
        let inherited = Confinement::new(&dir, &dir, 1);
        assert!(!effective_scrub_env(&inherited, false));
        assert!(effective_scrub_env(&inherited, true));
    }

    #[test]
    fn seatbelt_is_deny_by_default_and_allows_only_declared_reads() {
        let work = PathBuf::from("/private/tmp/proofwork-seatbelt-work");
        let bundle = PathBuf::from("/Volumes/objectives/example");
        let plan = Confinement::new(&work, &bundle, 1).reading(bundle.join("checker.py"));
        let profile = seatbelt_profile(
            Path::new("/usr/bin/python3"),
            &plan,
            std::slice::from_ref(&work),
        );
        assert!(profile.contains("(deny default)"));
        assert!(!profile.contains("(allow default)"));
        assert!(profile.contains("/Volumes/objectives/example"));
        assert!(profile.contains("/private/tmp/proofwork-seatbelt-work"));
        assert!(!profile.contains("/Users/"));
        assert!(!profile.contains("(subpath \"/\")"));
    }

    #[test]
    fn user_runtime_paths_never_allow_their_data_ancestor() {
        assert_eq!(
            narrow_runtime_root(Path::new("/Users/alice/.local/bin/uv")),
            None
        );
        assert_eq!(
            narrow_runtime_root(Path::new("/Users/alice/bin/tool")),
            None
        );
        assert_eq!(
            narrow_runtime_root(Path::new(
                "/Users/alice/.rustup/toolchains/stable-aarch64-apple-darwin/bin/rustc"
            )),
            None
        );
        assert_eq!(
            narrow_runtime_root(Path::new("/Users/alice/Projects/private/bin/python")),
            None
        );
    }

    #[test]
    fn profile_paths_with_quotes_cannot_break_out_of_the_sexp() {
        assert_eq!(escape(r#"a"b\c"#), r#"a\"b\\c"#);
    }

    #[test]
    fn the_require_switch_fails_closed_on_unrecognised_values() {
        // Regression: only the literal "1" used to count, so `=true` -- the
        // spelling half of everyone reaches for first -- silently meant "run
        // objective code unjailed".
        for on in ["1", "true", "TRUE", "yes", "on", " 1 ", "banana"] {
            assert!(require_sandbox(Some(on)), "{on:?} must require the jail");
        }
        for off in [
            None,
            Some(""),
            Some("0"),
            Some("false"),
            Some("no"),
            Some("off"),
            Some("OFF"),
        ] {
            assert!(!require_sandbox(off), "{off:?} must not require the jail");
        }
    }

    #[cfg(unix)]
    fn link(target: impl AsRef<Path>, at: impl AsRef<Path>) {
        std::os::unix::fs::symlink(target, at).expect("symlink");
    }

    /// A scratch directory and its canonical name, so that the links a test
    /// makes are the only ones in play. macOS reaches its temporary directory
    /// through `/var -> private/var`.
    #[cfg(unix)]
    fn scratch(prefix: &str) -> (super::super::TempDir, PathBuf) {
        let dir = super::super::TempDir::new(prefix).expect("temp dir");
        let base = std::fs::canonicalize(dir.path()).expect("canonical");
        (dir, base)
    }

    /// `/usr/local/bin/python3 -> /usr/bin/python3.11`, and Debian's
    /// `/usr/bin/python3 -> /etc/alternatives/python3`, built where a test can
    /// build them: `shown/bin/<name>`, inside a directory the jail is to show,
    /// is an absolute link to `alternatives/<name>`, outside everything it
    /// shows, which is an absolute link to `file`. Returns `(shown, program)`.
    #[cfg(target_os = "linux")]
    fn alternatives(base: &Path, name: &str, file: &Path) -> (PathBuf, PathBuf) {
        let shown = base.join("shown");
        std::fs::create_dir_all(shown.join("bin")).expect("shown/bin");
        std::fs::create_dir_all(base.join("alternatives")).expect("alternatives");
        link(file, base.join("alternatives").join(name));
        link(
            base.join("alternatives").join(name),
            shown.join("bin").join(name),
        );
        let program = shown.join("bin").join(name);
        (shown, program)
    }

    #[cfg(unix)]
    #[test]
    fn a_trace_ends_where_canonicalize_does_and_keeps_every_link() {
        let (_dir, base) = scratch("cairn-trace");
        let real = base.join("real");
        std::fs::create_dir_all(real.join("bin")).expect("real/bin");
        std::fs::write(real.join("bin/tool"), b"").expect("tool");
        link("real", base.join("rel"));
        link("../bin/tool", real.join("bin/up"));
        link(base.join("rel/bin/up"), base.join("entry"));
        link("real/bin", base.join("deep"));
        link("loop-b", base.join("loop-a"));
        link("loop-a", base.join("loop-b"));

        // Absolute into relative into relative-through-`..`, every hop kept,
        // each at a canonical parent, which is where the jail recreates it.
        let traced = trace(&base.join("entry")).expect("resolves");
        assert_eq!(traced.canonical, real.join("bin/tool"));
        assert_eq!(
            traced.links,
            vec![
                (base.join("entry"), base.join("rel/bin/up")),
                (base.join("rel"), PathBuf::from("real")),
                (real.join("bin/up"), PathBuf::from("../bin/tool")),
            ]
        );
        // `..` after a link is the parent of where the link went. Folded away
        // lexically, `deep/../bin/tool` would be `base/bin/tool`, which does
        // not exist.
        let physical = trace(&base.join("deep/../bin/tool")).expect("resolves");
        assert_eq!(physical.canonical, real.join("bin/tool"));
        for path in ["entry", "deep/../bin/tool", "real/bin/tool"] {
            let traced = trace(&base.join(path)).expect("resolves").canonical;
            assert_eq!(
                Some(traced),
                std::fs::canonicalize(base.join(path)).ok(),
                "{path}"
            );
        }
        let plain = trace(&real.join("bin/tool")).expect("resolves");
        assert!(plain.links.is_empty());
        // What does not resolve is not bound, as `exists()` used to decide.
        assert_eq!(trace(&base.join("loop-a")), None);
        assert_eq!(trace(&base.join("missing/tool")), None);
        assert_eq!(trace(&real.join("bin/tool/under-a-file")), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bubblewrap_mounts_where_links_end_and_runs_the_name_it_was_given() {
        let (_dir, base) = scratch("cairn-bwrap-args");
        let real = base.join("real");
        std::fs::write(&real, b"").expect("file");
        let (shown, program) = alternatives(&base, "tool", &real);
        let work = base.join("work");
        std::fs::create_dir(&work).expect("work");
        // As a pinned run: the scratch directory is also the cwd, and limits
        // put the shell in front of the program.
        let plan = Confinement::new(&work, &work, 5)
            .reading(&shown)
            .reading(&program);
        let command = bubblewrap(PathBuf::from("bwrap"), &program, &[], &plan, true);
        let args: Vec<&OsStr> = command.get_args().collect();
        let mounts: Vec<(&OsStr, &Path)> = args
            .windows(3)
            .filter(|op| op[0] == "--bind" || op[0] == "--ro-bind" || op[0] == "--ro-bind-try")
            .map(|op| (op[0], Path::new(op[2])))
            .collect();
        let links: Vec<(&Path, &Path)> = args
            .windows(3)
            .filter(|op| op[0] == "--symlink")
            .map(|op| (Path::new(op[2]), Path::new(op[1])))
            .collect();

        // bwrap cannot mount on a symlink, so no destination may contain one.
        for (_, at) in &mounts {
            assert_eq!(
                std::fs::canonicalize(at).ok().as_deref(),
                Some(*at),
                "mounted on a symlink: {}",
                at.display()
            );
        }
        assert!(mounts.iter().any(|(_, at)| *at == real));
        // The link outside the shown directory is recreated, so the name still
        // leads somewhere; the one inside it is already there.
        let outside = base.join("alternatives/tool");
        assert!(
            links.contains(&(outside.as_path(), real.as_path())),
            "{links:?}"
        );
        assert!(
            !links.iter().any(|(at, _)| at.starts_with(&shown)),
            "{links:?}"
        );
        // The program runs under the name it was given, not the file it is.
        assert_eq!(args.last(), Some(&program.as_os_str()));
        // And the scratch directory's last mount is the writable one.
        let scratch = mounts.iter().rev().find(|(_, at)| *at == work);
        assert_eq!(scratch.map(|(flag, _)| *flag), Some(OsStr::new("--bind")));
    }

    /// `(flag, path)` for each mount a bubblewrap command makes, in the order
    /// it makes them, which is the order that decides who wins.
    #[cfg(target_os = "linux")]
    fn mounts_of(command: &Command) -> Vec<(String, PathBuf)> {
        let args: Vec<&OsStr> = command.get_args().collect();
        args.windows(3)
            .filter(|op| op[0] == "--bind" || op[0] == "--ro-bind" || op[0] == "--ro-bind-try")
            .map(|op| (op[0].to_string_lossy().into_owned(), PathBuf::from(op[2])))
            .collect()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_cwd_the_plan_made_writable_is_not_bound_read_only_on_top() {
        // Two callers run in a directory they also write: a pinned checker in
        // its scratch directory, and `workspace` in the tree it builds. A later
        // bind wins, so a read-only bind of the cwd after the writable one made
        // both read-only, under bubblewrap alone.
        let (_dir, base) = scratch("cairn-bwrap-cwd");
        let (work, tree, inside, plain) = (
            base.join("work"),
            base.join("tree"),
            base.join("tree/pkg"),
            base.join("plain"),
        );
        for dir in [&work, &tree, &inside, &plain] {
            std::fs::create_dir_all(dir).expect("dir");
        }
        let mounts = |plan: &Confinement<'_>| {
            let command = bubblewrap(
                PathBuf::from("bwrap"),
                Path::new("/bin/true"),
                &[],
                plan,
                true,
            );
            mounts_of(&command)
        };
        let last_flag = |mounts: &[(String, PathBuf)], path: &Path| {
            mounts
                .iter()
                .rev()
                .find(|(_, at)| at == path)
                .map(|(flag, _)| flag.clone())
        };

        // The pinned shape: the cwd is the scratch directory.
        let pinned = mounts(&Confinement::new(&work, &work, 5));
        assert_eq!(last_flag(&pinned, &work).as_deref(), Some("--bind"));
        // The workspace shape: the cwd is a separate tree the plan writes.
        let workspace = mounts(&Confinement::new(&work, &tree, 5).writing(&tree));
        assert_eq!(last_flag(&workspace, &tree).as_deref(), Some("--bind"));
        // Inside that tree nothing more is mounted: the jail already shows it.
        let nested = mounts(&Confinement::new(&work, &inside, 5).writing(&tree));
        assert_eq!(last_flag(&nested, &inside), None);
        assert_eq!(last_flag(&nested, &tree).as_deref(), Some("--bind"));
        // A cwd nothing else shows is still bound, read-only: the skip above
        // is for what the jail shows, not a way to drop the cwd.
        let bare = mounts(&Confinement::new(&work, &plain, 5));
        assert_eq!(last_flag(&bare, &plain).as_deref(), Some("--ro-bind-try"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn an_interpreter_named_through_absolute_links_runs_in_the_jail() {
        let Some(python) = which("python3") else {
            return;
        };
        let (_dir, base) = scratch("cairn-bwrap-python");
        let (shown, program) = alternatives(&base, "python3", &python);
        let work = base.join("work");
        std::fs::create_dir(&work).expect("work");
        // Bound like this, the old jail mounted `shown` and then the program at
        // its own name, through the link inside `shown`, and bwrap died with
        // "Can't create file at …/shown/bin/python3" before Python started.
        let plan = Confinement::new(&work, &work, 30)
            .reading(&shown)
            .reading(&program)
            .scrubbed();
        let code = argv(["-c", "import sys; print(sys.executable)"]);
        // Err only when a jail is required and this host has none.
        let Ok(jailed) = confine(&program, &code, &plan) else {
            return;
        };
        let mechanism = jailed.mechanism;
        let mut command = jailed.command;
        let output = command
            .stdin(std::process::Stdio::null())
            .output()
            .expect("spawn");
        assert!(
            output.status.success(),
            "{mechanism}: {:?}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        // `sys.executable` is argv[0]: what a venv, or a busybox-style binary,
        // decides by.
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            program.to_string_lossy()
        );
    }

    #[test]
    fn limits_wrap_through_a_shell_only_when_a_limit_is_asked_for() {
        let dir = PathBuf::from("/tmp/cairn-limit-test");
        let none = Confinement::new(&dir, &dir, 0);
        let (bin, argv) = with_limits(Path::new("/usr/bin/true"), &[], &none);
        assert_eq!(bin, OsString::from("/usr/bin/true"));
        assert!(argv.is_empty());

        let capped = Confinement::new(&dir, &dir, 5);
        let (bin, argv) = with_limits(Path::new("/usr/bin/true"), &[], &capped);
        if Path::new("/bin/sh").exists() {
            assert_eq!(bin, OsString::from("/bin/sh"));
            assert!(argv
                .iter()
                .any(|a| a.to_string_lossy().contains("ulimit -t 5")));
            assert_eq!(argv.last(), Some(&OsString::from("/usr/bin/true")));
        }
    }
}
