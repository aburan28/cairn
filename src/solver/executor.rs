//! Which executor runs a solver round.
//!
//! A solver is a stranger's program that a contributor's machine runs for
//! hours. The design is a user-space or hardware-virtualised kernel between
//! it and the host: gVisor (`runsc`) or Kata Containers, the two the host
//! agent already drives for executor jobs ([`crate::agent`]). A round goes
//! through exactly that code, [`crate::agent::job::run`], so a solver gets the
//! jail an executor job gets and nothing about the jail is written twice.
//!
//! | executor | boundary | chosen when |
//! |---|---|---|
//! | `runsc` | gVisor's Sentry serves the program's syscalls | Linux, `runsc` starts a sandbox here, and this process is root so the sandbox has cgroups to hold memory and CPU |
//! | `kata` | a guest kernel in a lightweight VM | Linux, an engine runs the Kata runtime, and the operator named an image ([`KATA_IMAGE_ENV`]) |
//! | `bwrap` | namespaces over the host kernel | Linux, nothing above works |
//! | `sandbox-exec` | seatbelt | macOS, always |
//!
//! `auto` takes the first that works. [`SANDBOX_ENV`] pins one: a pinned
//! executor that cannot run makes the round `Unavailable` rather than
//! quietly running under a weaker one, because the operator who pinned `kata`
//! did so for the boundary.
//!
//! # Same guarantees, whichever executor
//!
//! No network (the sandbox has no route to the host's network or loopback),
//! a root that shows only the system directories and the interpreter, the
//! package read-only, nothing writable but a scratch directory that is
//! deleted afterwards, a scrubbed environment, and the offered `threads`,
//! the package's `memory_mb` and its `round_seconds` held by the executor.
//! gVisor without cgroups (unprivileged `runsc --rootless`) cannot hold
//! memory or CPU limits, so it is not chosen then: the host falls back to
//! bubblewrap, whose limits are enforced, and the worker log says why.
//!
//! The assignment reaches the solver on stdin through a shell redirect from a
//! read-only file inside the sandbox, so no executor needs a stdin of its own.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::agent::sandbox::{Names, Sandboxes, Via};
use crate::verifiers::sandbox as host;

/// `auto` (default), `strongest`, `runsc` (`gvisor`), `kata`, or `bwrap`.
pub const SANDBOX_ENV: &str = "CAIRN_SOLVER_SANDBOX";

/// An OCI image the Kata executor runs rounds in. It needs `/bin/sh`, and
/// `python3` for python3 targets; a native target must be built for its libc.
pub const KATA_IMAGE_ENV: &str = "CAIRN_SOLVER_KATA_IMAGE";

/// Where per-round job directories and gVisor's state live; default
/// `~/.cairn/solver-run`.
pub const STATE_ENV: &str = "CAIRN_SOLVER_STATE";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Executor {
    /// gVisor over a directory, no container engine.
    Gvisor,
    /// Kata through a container engine, over this image.
    Kata { image: String },
    /// The platform's own jail: bubblewrap, seatbelt, or none.
    Host,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Want {
    Auto,
    Strongest,
    Runsc,
    Kata,
    Bwrap,
}

impl Want {
    pub fn parse(text: &str) -> Result<Want, String> {
        match text.trim().to_ascii_lowercase().as_str() {
            "" | "auto" => Ok(Want::Auto),
            "strongest" => Ok(Want::Strongest),
            "runsc" | "gvisor" => Ok(Want::Runsc),
            "kata" | "kata-containers" => Ok(Want::Kata),
            "bwrap" | "host" => Ok(Want::Bwrap),
            other => Err(format!(
                "{SANDBOX_ENV}={other:?}: expected auto, strongest, runsc, kata or bwrap"
            )),
        }
    }
}

/// What this host offers, gathered once.
pub struct Facts<'a> {
    pub linux: bool,
    /// `None` when the probe was not run (macOS, or bubblewrap pinned).
    pub sandboxes: Option<&'a Sandboxes>,
    /// Whether gVisor here has cgroups to hold memory and CPU.
    pub gvisor_limits: bool,
    pub kata_image: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    pub executor: Executor,
    /// Stronger executors that were considered and why each was not used.
    pub passed_over: Vec<String>,
}

impl Selection {
    /// The name recorded in reports and logs.
    pub fn name(&self) -> &'static str {
        match &self.executor {
            Executor::Gvisor => "runsc",
            Executor::Kata { .. } => "kata",
            Executor::Host => host::mechanism().as_str(),
        }
    }

    /// One line for a worker log: the executor and, if a stronger one was
    /// passed over, why.
    pub fn describe(&self) -> String {
        if self.passed_over.is_empty() {
            self.name().to_string()
        } else {
            format!("{} ({})", self.name(), self.passed_over.join("; "))
        }
    }
}

fn gvisor(facts: &Facts<'_>) -> Result<Executor, String> {
    if !facts.linux {
        return Err("runsc: gVisor is Linux only".into());
    }
    let Some(sandboxes) = facts.sandboxes else {
        return Err("runsc: not probed".into());
    };
    let found = &sandboxes.runsc;
    if !found.usable || !found.via.contains(&Via::Native) {
        return Err(format!(
            "runsc: {}",
            found
                .why
                .clone()
                .unwrap_or_else(|| "no engine-free runsc here".into())
        ));
    }
    if !facts.gvisor_limits {
        return Err(
            "runsc: not root, so gVisor has no cgroups to hold memory and CPU limits; \
             run the worker as root or a service with cgroup delegation"
                .into(),
        );
    }
    Ok(Executor::Gvisor)
}

fn kata(facts: &Facts<'_>) -> Result<Executor, String> {
    if !facts.linux {
        return Err("kata: Linux only".into());
    }
    let Some(sandboxes) = facts.sandboxes else {
        return Err("kata: not probed".into());
    };
    let found = &sandboxes.kata;
    if !found.usable || !found.via.iter().any(|v| matches!(v, Via::Engine { .. })) {
        return Err(format!(
            "kata: {}",
            found
                .why
                .clone()
                .unwrap_or_else(|| "no engine runs it".into())
        ));
    }
    match &facts.kata_image {
        Some(image) => Ok(Executor::Kata {
            image: image.clone(),
        }),
        None => Err(format!(
            "kata: usable, but {KATA_IMAGE_ENV} names no image to run rounds in"
        )),
    }
}

/// Pick the executor. Pure: every input is in `facts`.
pub fn decide(want: Want, facts: &Facts<'_>) -> Result<Selection, String> {
    let mut passed_over = Vec::new();
    let mut try_one = |result: Result<Executor, String>| match result {
        Ok(executor) => Some(executor),
        Err(why) => {
            passed_over.push(why);
            None
        }
    };
    let chosen = match want {
        Want::Auto => try_one(gvisor(facts))
            .or_else(|| try_one(kata(facts)))
            .or(Some(Executor::Host)),
        Want::Strongest => try_one(kata(facts)).or_else(|| try_one(gvisor(facts))),
        Want::Runsc => try_one(gvisor(facts)),
        Want::Kata => try_one(kata(facts)),
        Want::Bwrap => Some(Executor::Host),
    };
    match chosen {
        Some(executor) => {
            // Reasons only matter when a stronger executor lost; a pinned
            // bubblewrap passed nothing over.
            if want == Want::Bwrap || !facts.linux {
                passed_over.clear();
            }
            Ok(Selection {
                executor,
                passed_over,
            })
        }
        None => Err(format!(
            "no executor satisfies {SANDBOX_ENV}: {}",
            passed_over.join("; ")
        )),
    }
}

fn probed() -> &'static Sandboxes {
    static PROBED: OnceLock<Sandboxes> = OnceLock::new();
    PROBED.get_or_init(|| Sandboxes::probe(&Names::from_env()))
}

/// The executor this process will run rounds in, probing the host on first
/// use.
pub fn select() -> Result<Selection, String> {
    let want = match std::env::var(SANDBOX_ENV) {
        Ok(text) => Want::parse(&text)?,
        Err(_) => Want::Auto,
    };
    let linux = cfg!(target_os = "linux");
    let probe = linux && want != Want::Bwrap;
    let kata_image = std::env::var(KATA_IMAGE_ENV)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    if let Some(image) = &kata_image {
        if !crate::agent::job::valid_image_reference(image) {
            return Err(format!(
                "{KATA_IMAGE_ENV}={image:?} is not an image reference"
            ));
        }
    }
    decide(
        want,
        &Facts {
            linux,
            sandboxes: probe.then(probed),
            gvisor_limits: probe && crate::lab::exec::gvisor_enforces_limits(),
            kata_image,
        },
    )
}

/// The executor's name for a report; `none` if it could not be chosen.
pub fn name() -> String {
    select()
        .map(|s| s.name().to_string())
        .unwrap_or_else(|_| "none".to_string())
}

/// For a worker log or `cairn solver add`.
pub fn describe() -> String {
    match select() {
        Ok(selection) => selection.describe(),
        Err(why) => format!("none ({why})"),
    }
}

pub(crate) fn sandboxes() -> &'static Sandboxes {
    probed()
}

/// Directories of the host that a gVisor root shows, read-only, at the same
/// paths. Merged-usr hosts have `/bin` and friends as links, which are
/// recreated as links.
pub(crate) const SYSTEM_TOPS: [&str; 6] = ["usr", "bin", "sbin", "lib", "lib32", "lib64"];

/// Whether `path` is inside a directory [`SYSTEM_TOPS`] already shows.
pub(crate) fn under_system(path: &Path) -> bool {
    SYSTEM_TOPS
        .iter()
        .any(|top| path.starts_with(Path::new("/").join(top)))
}

/// Where a round's job directories live.
pub(crate) fn state_dir() -> PathBuf {
    std::env::var_os(STATE_ENV)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cairn/solver-run")))
        .unwrap_or_else(|| std::env::temp_dir().join("cairn-solver-run"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::sandbox::{Found, Kind};

    fn found(kind: Kind, usable: bool, via: Vec<Via>, why: Option<&str>) -> Found {
        Found {
            kind,
            usable,
            binary: None,
            version: Some("test".into()),
            via,
            why: why.map(str::to_string),
            gpu: false,
        }
    }

    fn engine() -> Via {
        Via::Engine {
            engine: "docker".into(),
            runtime: "kata".into(),
        }
    }

    fn sandboxes(runsc: bool, kata: bool) -> Sandboxes {
        Sandboxes::assembled(
            found(
                Kind::Kata,
                kata,
                if kata { vec![engine()] } else { vec![] },
                (!kata).then_some("no kata"),
            ),
            found(
                Kind::Runsc,
                runsc,
                if runsc { vec![Via::Native] } else { vec![] },
                (!runsc).then_some("runsc is not on PATH"),
            ),
            found(Kind::Bwrap, true, vec![Via::Native], None),
            vec![],
        )
    }

    fn facts<'a>(sandboxes: &'a Sandboxes, limits: bool, image: Option<&str>) -> Facts<'a> {
        Facts {
            linux: true,
            sandboxes: Some(sandboxes),
            gvisor_limits: limits,
            kata_image: image.map(str::to_string),
        }
    }

    #[test]
    fn auto_prefers_gvisor_then_kata_then_the_host_jail() {
        let both = sandboxes(true, true);
        let picked = decide(Want::Auto, &facts(&both, true, Some("img:1"))).unwrap();
        assert_eq!(picked.executor, Executor::Gvisor);
        assert!(picked.passed_over.is_empty());

        let kata_only = sandboxes(false, true);
        let picked = decide(Want::Auto, &facts(&kata_only, true, Some("img:1"))).unwrap();
        assert_eq!(
            picked.executor,
            Executor::Kata {
                image: "img:1".into()
            }
        );
        assert!(picked.passed_over[0].contains("runsc is not on PATH"));

        let neither = sandboxes(false, false);
        let picked = decide(Want::Auto, &facts(&neither, true, None)).unwrap();
        assert_eq!(picked.executor, Executor::Host);
        assert_eq!(picked.passed_over.len(), 2, "{:?}", picked.passed_over);
    }

    #[test]
    fn gvisor_without_cgroups_is_not_chosen_because_it_cannot_hold_limits() {
        let have = sandboxes(true, false);
        let picked = decide(Want::Auto, &facts(&have, false, None)).unwrap();
        assert_eq!(picked.executor, Executor::Host);
        assert!(picked.passed_over[0].contains("cgroups"), "{picked:?}");
        let refused = decide(Want::Runsc, &facts(&have, false, None)).unwrap_err();
        assert!(refused.contains("cgroups"), "{refused}");
    }

    #[test]
    fn kata_needs_an_image_and_a_pinned_executor_never_degrades() {
        let have = sandboxes(true, true);
        let refused = decide(Want::Kata, &facts(&have, true, None)).unwrap_err();
        assert!(refused.contains(KATA_IMAGE_ENV), "{refused}");
        // `strongest` takes gVisor when Kata has no image, and never the host.
        let picked = decide(Want::Strongest, &facts(&have, true, None)).unwrap();
        assert_eq!(picked.executor, Executor::Gvisor);
        let none = sandboxes(false, false);
        assert!(decide(Want::Strongest, &facts(&none, true, None)).is_err());
        assert!(decide(Want::Runsc, &facts(&none, true, None)).is_err());
        assert_eq!(
            decide(Want::Bwrap, &facts(&have, true, None))
                .unwrap()
                .executor,
            Executor::Host
        );
    }

    #[test]
    fn macos_is_always_the_host_jail() {
        let picked = decide(
            Want::Auto,
            &Facts {
                linux: false,
                sandboxes: None,
                gvisor_limits: false,
                kata_image: None,
            },
        )
        .unwrap();
        assert_eq!(picked.executor, Executor::Host);
    }

    #[test]
    fn wants_parse_every_spelling_and_refuse_the_rest() {
        assert_eq!(Want::parse("gVisor").unwrap(), Want::Runsc);
        assert_eq!(Want::parse(" ").unwrap(), Want::Auto);
        assert_eq!(Want::parse("kata").unwrap(), Want::Kata);
        assert!(Want::parse("firejail").is_err());
    }

    #[test]
    fn system_directories_cover_their_children() {
        assert!(under_system(Path::new("/usr/bin/python3")));
        assert!(under_system(Path::new("/lib64/ld-linux.so.2")));
        assert!(!under_system(Path::new("/opt/python/bin/python3")));
        assert!(!under_system(Path::new("/home/a")));
    }
}
