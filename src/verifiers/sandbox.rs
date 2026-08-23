//! An OS jail around every process that runs objective-authored code.
//!
//! The verifier module spawns three kinds of child: pinned checker/evaluator/
//! statistic source, a `replay` command, and `lean` on a submitted proof. All
//! three execute code that somebody other than the node operator wrote, so all
//! three go through here.
//!
//! # What this is and is not
//!
//! It is a *kernel-enforced* boundary: no network, and no writes outside a
//! scratch directory that is deleted when the check finishes. It is not a VM
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
use std::path::{Path, PathBuf};
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
    /// `RLIMIT_AS`, MiB. `0` leaves the address space unbounded.
    pub memory_mb: u64,
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

fn configured_memory_mb() -> u64 {
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

    // System directories, read only. `/bin` and friends are symlinks into
    // `/usr` on merged-usr distributions; binding a symlink source as a
    // directory fails, so recreate the link instead.
    for top in ["/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64"] {
        let path = Path::new(top);
        match std::fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_symlink() => {
                if let Ok(target) = std::fs::read_link(path) {
                    command.arg("--symlink").arg(target).arg(top);
                }
            }
            Ok(_) => {
                command.arg("--ro-bind").arg(top).arg(top);
            }
            Err(_) => {}
        }
    }

    for path in &plan.readable {
        if path.exists() {
            command.arg("--ro-bind").arg(path).arg(path);
        }
    }
    // After the read-only binds, so an entry in both lists ends up writable.
    command.arg("--bind").arg(plan.workdir).arg(plan.workdir);
    for path in &plan.writable {
        if path.exists() {
            command.arg("--bind").arg(path).arg(path);
        }
    }
    if plan.cwd.exists() {
        command.arg("--ro-bind-try").arg(plan.cwd).arg(plan.cwd);
    }
    command.arg("--chdir").arg(plan.cwd);

    if scrub_env {
        command.arg("--clearenv");
        for (key, value) in minimal_env(plan) {
            command.arg("--setenv").arg(key).arg(value);
        }
    } else {
        command.arg("--setenv").arg("TMPDIR").arg(plan.workdir);
    }

    let (bin, argv) = with_limits(program, args, plan);
    command.arg("--").arg(bin).args(argv);
    // bwrap itself must start in a directory that exists outside the jail.
    command.current_dir(plan.workdir);
    apply_env(&mut command, plan, scrub_env);
    command
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
    for executable in [resolve(program)] {
        if let Some(runtime_root) = narrow_runtime_root(&executable) {
            // A runtime root is an installation prefix such as
            // `/opt/homebrew/Cellar/python@3.13/3.13.2`, never the filesystem
            // root. In particular, the grandparent of `/bin/sh` is `/`; adding
            // it here turns the deny-by-default profile into a read-everything
            // profile.
            readable.push(runtime_root);
        }
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
/// `~/bin/tool` and `~/.local/bin/tool` are common, but their grandparent is
/// the operator's home or `.local` data tree. Granting either subtree to
/// objective-authored code is a sandbox escape. Versioned rustup/pyenv/elan
/// roots are deeper and remain usable.
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
        .is_some_and(|home| root == home || root.parent() == Some(home))
        || structural_home(&root)
        || root.parent().is_some_and(structural_home)
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
    fn shallow_user_runtime_paths_never_allow_their_data_ancestor() {
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
            Some(PathBuf::from(
                "/Users/alice/.rustup/toolchains/stable-aarch64-apple-darwin"
            ))
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
