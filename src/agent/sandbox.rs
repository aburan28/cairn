//! Which jails this host can put an executor job in, and how each is driven.
//!
//! Three mechanisms, strongest first:
//!
//! | sandbox | boundary | driven by |
//! |---|---|---|
//! | `kata` | a separate guest kernel in a lightweight VM (Kata Containers) | a container engine with the `kata` runtime configured |
//! | `runsc` | gVisor's user-space kernel; a filtered few syscalls reach the host | the engine with the `runsc` runtime, or `runsc` itself over a root filesystem directory |
//! | `bwrap` | Linux namespaces over the host kernel | `bwrap` over a root filesystem directory |
//!
//! Kata and gVisor both plug into Docker, Podman and nerdctl as OCI runtimes,
//! and that is how a job that names an *image* runs: the engine pulls, the
//! runtime jails. A job that names a *root filesystem directory* instead goes
//! through [`crate::lab::exec`], the same code the lab's `exec` uses, which
//! drives `runsc` or `bwrap` directly and needs no engine at all. Kata has no
//! engine-free path worth offering: its runtime is a containerd shim.
//!
//! # Probed, not assumed
//!
//! Every mechanism here is checked by asking it to do something, once, at
//! startup: `runsc do /bin/true`, `bwrap ... /bin/true`, `docker info` with
//! the runtimes it lists. A binary on `PATH` that cannot start a sandbox is
//! the common case -- no user namespaces in this container, no `/dev/kvm` in
//! this VM, the engine socket owned by a group this process is not in -- and
//! the time to learn that is before the first job, in a line of the probe,
//! not in the receipt of a job that ran nowhere.
//!
//! # GPU
//!
//! Through an engine only, and only as far as the engine takes it: Docker
//! and nerdctl take `--gpus`, Podman takes a CDI device. Under gVisor the
//! runtime additionally needs `--nvproxy` in its daemon configuration, and
//! under Kata the device needs VFIO passthrough set up, neither of which
//! this process can see or do. So the agent reports `gpu: engine` for a
//! sandbox the engine will hand a GPU to, passes the request through, and
//! the receipt carries whatever the engine said if it would not.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use super::AgentError;
use crate::canonical::Value;

/// The three jails, and the absence of one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    None,
    Bwrap,
    Runsc,
    Kata,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Kata => "kata",
            Kind::Runsc => "runsc",
            Kind::Bwrap => "bwrap",
            Kind::None => "none",
        }
    }
}

/// What a job (or the operator) asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preference {
    /// gVisor if it works, else Kata, else bubblewrap, else refuse. gVisor
    /// first because it is what most hosts have and what a rootfs job can
    /// use without an engine.
    Auto,
    /// Kata, else gVisor, else refuse. For a job whose author wants the
    /// furthest it can get from the host kernel.
    Strongest,
    Kata,
    Runsc,
    Bwrap,
    /// No jail. Only ever by explicit request, and the receipt says so.
    None,
}

impl Preference {
    pub fn parse(text: &str) -> Result<Preference, AgentError> {
        Ok(match text.trim().to_ascii_lowercase().as_str() {
            "auto" => Preference::Auto,
            "strongest" | "strong" => Preference::Strongest,
            "kata" | "kata-containers" => Preference::Kata,
            "runsc" | "gvisor" => Preference::Runsc,
            "bwrap" | "bubblewrap" => Preference::Bwrap,
            "none" | "unconfined" => Preference::None,
            other => {
                return Err(AgentError::Invalid(format!(
                    "unknown sandbox {other:?} (auto, strongest, kata, runsc, bwrap, none)"
                )))
            }
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Preference::Auto => "auto",
            Preference::Strongest => "strongest",
            Preference::Kata => "kata",
            Preference::Runsc => "runsc",
            Preference::Bwrap => "bwrap",
            Preference::None => "none",
        }
    }
}

/// A container engine on this host and the OCI runtimes it will run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Engine {
    /// `docker`, `podman` or `nerdctl`.
    pub name: String,
    pub path: PathBuf,
    pub version: Option<String>,
    /// Runtime names the engine reported it has configured. Podman and
    /// nerdctl report none and are given the conventional names instead.
    pub runtimes: Vec<String>,
}

impl Engine {
    fn to_value(&self) -> Value {
        Value::object([
            ("name", Value::string(self.name.clone())),
            ("path", Value::string(self.path.display().to_string())),
            (
                "version",
                match &self.version {
                    Some(v) => Value::string(v.clone()),
                    None => Value::Null,
                },
            ),
            (
                "runtimes",
                Value::array(self.runtimes.iter().map(|r| Value::string(r.clone()))),
            ),
        ])
    }
}

/// How a sandbox is reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Via {
    /// `runsc`/`bwrap` over a directory, through [`crate::lab::exec`].
    Native,
    /// `<engine> run --runtime <runtime>` over an image.
    Engine { engine: String, runtime: String },
}

/// One sandbox as the probe found it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub kind: Kind,
    pub usable: bool,
    pub binary: Option<PathBuf>,
    pub version: Option<String>,
    /// Every way this host can drive it; empty when unusable.
    pub via: Vec<Via>,
    /// Why not, when not.
    pub why: Option<String>,
    /// An engine will pass a GPU to it.
    pub gpu: bool,
}

impl Found {
    fn absent(kind: Kind, why: impl Into<String>) -> Found {
        Found {
            kind,
            usable: false,
            binary: None,
            version: None,
            via: Vec::new(),
            why: Some(why.into()),
            gpu: false,
        }
    }

    pub fn to_value(&self) -> Value {
        let text = |value: &Option<String>| match value {
            Some(s) => Value::string(s.clone()),
            None => Value::Null,
        };
        Value::object([
            ("usable", Value::Bool(self.usable)),
            (
                "binary",
                match &self.binary {
                    Some(p) => Value::string(p.display().to_string()),
                    None => Value::Null,
                },
            ),
            ("version", text(&self.version)),
            (
                "via",
                Value::array(self.via.iter().map(|via| match via {
                    Via::Native => Value::string("native"),
                    Via::Engine { engine, runtime } => Value::string(format!("{engine}:{runtime}")),
                })),
            ),
            ("gpu", Value::Bool(self.gpu)),
            ("why", text(&self.why)),
        ])
    }

    fn engine_via(&self) -> Option<(&str, &str)> {
        self.via.iter().find_map(|via| match via {
            Via::Engine { engine, runtime } => Some((engine.as_str(), runtime.as_str())),
            Via::Native => None,
        })
    }

    fn native(&self) -> bool {
        self.via.contains(&Via::Native)
    }
}

/// Runtime names the operator's engine knows each sandbox by. Docker's
/// `daemon.json` calls them whatever the operator wrote; these are the
/// conventional spellings and the environment overrides them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Names {
    pub kata: String,
    pub runsc: String,
    /// Prefer this engine when several are present.
    pub engine: Option<String>,
}

pub const KATA_RUNTIME_ENV: &str = "CAIRN_AGENT_KATA_RUNTIME";
pub const RUNSC_RUNTIME_ENV: &str = "CAIRN_AGENT_RUNSC_RUNTIME";
pub const ENGINE_ENV: &str = "CAIRN_AGENT_ENGINE";

impl Names {
    pub fn from_env() -> Names {
        let read = |name: &str| std::env::var(name).ok().filter(|v| !v.trim().is_empty());
        Names {
            kata: read(KATA_RUNTIME_ENV).unwrap_or_else(|| "kata".to_string()),
            runsc: read(RUNSC_RUNTIME_ENV).unwrap_or_else(|| "runsc".to_string()),
            engine: read(ENGINE_ENV),
        }
    }
}

impl Default for Names {
    fn default() -> Names {
        Names {
            kata: "kata".to_string(),
            runsc: "runsc".to_string(),
            engine: None,
        }
    }
}

/// Everything the probe found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sandboxes {
    pub kata: Found,
    pub runsc: Found,
    pub bwrap: Found,
    pub engines: Vec<Engine>,
}

impl Sandboxes {
    /// Probe the host. Spawns each tool once.
    pub fn probe(names: &Names) -> Sandboxes {
        let engines = engines(names);
        let runsc = probe_runsc(&engines, &names.runsc);
        let kata = probe_kata(&engines, &names.kata);
        let bwrap = probe_bwrap();
        Sandboxes {
            kata,
            runsc,
            bwrap,
            engines,
        }
    }

    /// Assemble from parts, for tests and for callers that probed elsewhere.
    pub fn assembled(kata: Found, runsc: Found, bwrap: Found, engines: Vec<Engine>) -> Sandboxes {
        Sandboxes {
            kata,
            runsc,
            bwrap,
            engines,
        }
    }

    pub fn found(&self, kind: Kind) -> Option<&Found> {
        match kind {
            Kind::Kata => Some(&self.kata),
            Kind::Runsc => Some(&self.runsc),
            Kind::Bwrap => Some(&self.bwrap),
            Kind::None => None,
        }
    }

    /// The `sandboxes` block of a registration, keyed by name so a node can
    /// read `usable` off each without knowing the rest of the shape.
    pub fn to_value(&self) -> Value {
        Value::object([
            ("kata", self.kata.to_value()),
            ("runsc", self.runsc.to_value()),
            ("bwrap", self.bwrap.to_value()),
            (
                "engines",
                Value::array(self.engines.iter().map(Engine::to_value)),
            ),
        ])
    }

    /// Choose the jail for a job. `image` is whether the job names an image
    /// (needs an engine) rather than a root filesystem (needs the native
    /// path); `gpus` is how many it asked for.
    pub fn choose(
        &self,
        preference: Preference,
        image: bool,
        gpus: u64,
    ) -> Result<Choice, AgentError> {
        let order: &[Kind] = match preference {
            Preference::Auto => &[Kind::Runsc, Kind::Kata, Kind::Bwrap],
            Preference::Strongest => &[Kind::Kata, Kind::Runsc],
            Preference::Kata => &[Kind::Kata],
            Preference::Runsc => &[Kind::Runsc],
            Preference::Bwrap => &[Kind::Bwrap],
            Preference::None => {
                if gpus > 0 {
                    return Err(AgentError::Invalid(
                        "a GPU job needs an engine to pass the device, so it cannot run \
                         unconfined; name a sandbox"
                            .to_string(),
                    ));
                }
                return Ok(Choice {
                    kind: Kind::None,
                    via: Via::Native,
                });
            }
        };
        let mut reasons = Vec::new();
        for kind in order {
            let found = self.found(*kind).expect("never None here");
            if !found.usable {
                reasons.push(format!(
                    "{}: {}",
                    kind.as_str(),
                    found.why.clone().unwrap_or_else(|| "unusable".to_string())
                ));
                continue;
            }
            if image {
                match found.engine_via() {
                    Some((engine, runtime)) => {
                        if gpus > 0 && !found.gpu {
                            reasons.push(format!(
                                "{}: usable through {engine} but it will not pass a GPU to it",
                                kind.as_str()
                            ));
                            continue;
                        }
                        return Ok(Choice {
                            kind: *kind,
                            via: Via::Engine {
                                engine: engine.to_string(),
                                runtime: runtime.to_string(),
                            },
                        });
                    }
                    None => reasons.push(format!(
                        "{}: no container engine on this host runs it, and the job names an image",
                        kind.as_str()
                    )),
                }
            } else {
                if gpus > 0 {
                    reasons.push(format!(
                        "{}: a root filesystem job cannot be handed a GPU; name an image",
                        kind.as_str()
                    ));
                    continue;
                }
                if found.native() {
                    return Ok(Choice {
                        kind: *kind,
                        via: Via::Native,
                    });
                }
                reasons.push(format!(
                    "{}: reachable only through an engine, and the job names a root \
                     filesystem rather than an image",
                    kind.as_str()
                ));
            }
        }
        Err(AgentError::Unavailable(format!(
            "no sandbox on this host fits the job (asked for {}): {}",
            preference.as_str(),
            reasons.join("; ")
        )))
    }
}

/// The jail a job will run in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Choice {
    pub kind: Kind,
    pub via: Via,
}

// -- probing ----------------------------------------------------------------------

fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

fn first_line(output: &std::process::Output) -> Option<String> {
    if !output.status.success() {
        return None;
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .next()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
}

fn engines(names: &Names) -> Vec<Engine> {
    let mut found = Vec::new();
    for name in ["docker", "podman", "nerdctl"] {
        let Some(path) = which(name) else {
            continue;
        };
        let version = Command::new(&path)
            .args(["version", "--format", "{{.Client.Version}}"])
            .stdin(Stdio::null())
            .output()
            .ok()
            .and_then(|out| first_line(&out));
        // The engine must answer `info`: a client with no daemon behind it
        // is a binary, not an engine.
        let info = Command::new(&path)
            .args(["info", "--format", "{{json .Runtimes}}"])
            .stdin(Stdio::null())
            .output();
        let Ok(info) = info else { continue };
        if !info.status.success() {
            continue;
        }
        let listed = parse_runtimes(&String::from_utf8_lossy(&info.stdout));
        let runtimes = if listed.is_empty() {
            conventional_runtimes(name, names)
        } else {
            listed
        };
        found.push(Engine {
            name: name.to_string(),
            path,
            version,
            runtimes,
        });
    }
    if let Some(preferred) = &names.engine {
        found.sort_by_key(|engine| engine.name != *preferred);
    }
    found
}

/// `docker info --format '{{json .Runtimes}}'` is an object keyed by runtime
/// name. Podman prints a bare `null` or an error string there.
pub fn parse_runtimes(text: &str) -> Vec<String> {
    Value::from_json(text.trim())
        .ok()
        .and_then(|value| value.as_object().map(|o| o.keys().cloned().collect()))
        .unwrap_or_default()
}

/// The runtime names an engine that lists none is conventionally configured
/// with: nerdctl's are containerd shim names; podman's are whatever
/// `containers.conf` says, and `runsc` works as a bare path there too.
fn conventional_runtimes(engine: &str, names: &Names) -> Vec<String> {
    match engine {
        "nerdctl" => vec![
            "io.containerd.runc.v2".to_string(),
            "io.containerd.runsc.v1".to_string(),
            "io.containerd.kata.v2".to_string(),
        ],
        _ => vec!["runc".to_string(), names.runsc.clone(), names.kata.clone()],
    }
}

/// The engine route for `kind`, if any engine lists a runtime by its name.
fn engine_route(engines: &[Engine], candidates: &[&str]) -> Option<Via> {
    for engine in engines {
        for candidate in candidates {
            if engine.runtimes.iter().any(|r| r == candidate) {
                return Some(Via::Engine {
                    engine: engine.name.clone(),
                    runtime: candidate.to_string(),
                });
            }
        }
    }
    None
}

fn probe_runsc(engines: &[Engine], runtime_name: &str) -> Found {
    let mut found = match crate::lab::exec::backend(crate::lab::exec::Preference::Gvisor) {
        Ok(crate::lab::exec::Backend::Gvisor { runsc, version }) => Found {
            kind: Kind::Runsc,
            usable: true,
            binary: Some(runsc),
            version: Some(version),
            via: vec![Via::Native],
            why: None,
            gpu: false,
        },
        Ok(_) => unreachable!("asked for gVisor"),
        Err(why) => Found::absent(Kind::Runsc, why.to_string()),
    };
    if let Some(via) = engine_route(engines, &[runtime_name, "io.containerd.runsc.v1"]) {
        if let Via::Engine { engine, .. } = &via {
            found.gpu = engine_passes_gpu(engine);
        }
        found.via.push(via);
        found.usable = true;
        found.why = None;
        if found.binary.is_none() {
            found.binary = which("runsc");
        }
    }
    found
}

fn probe_kata(engines: &[Engine], runtime_name: &str) -> Found {
    let binary = which("containerd-shim-kata-v2").or_else(|| which("kata-runtime"));
    let version = binary.as_ref().and_then(|path| {
        Command::new(path)
            .arg("--version")
            .stdin(Stdio::null())
            .output()
            .ok()
            .and_then(|out| first_line(&out))
    });
    match engine_route(engines, &[runtime_name, "io.containerd.kata.v2"]) {
        Some(via) => {
            let gpu = match &via {
                Via::Engine { engine, .. } => engine_passes_gpu(engine),
                Via::Native => false,
            };
            Found {
                kind: Kind::Kata,
                usable: true,
                binary,
                version,
                via: vec![via],
                why: None,
                gpu,
            }
        }
        None => {
            let why = if binary.is_none() {
                "no containerd-shim-kata-v2 or kata-runtime on PATH".to_string()
            } else if engines.is_empty() {
                "Kata is installed but no container engine answers here; it runs only as an \
                 engine's OCI runtime"
                    .to_string()
            } else {
                format!(
                    "Kata is installed but no engine lists a runtime named {runtime_name:?} \
                     (set {KATA_RUNTIME_ENV} to the name in your engine's configuration)"
                )
            };
            Found {
                kind: Kind::Kata,
                usable: false,
                binary,
                version,
                via: Vec::new(),
                why: Some(why),
                gpu: false,
            }
        }
    }
}

fn probe_bwrap() -> Found {
    match crate::lab::exec::backend(crate::lab::exec::Preference::Bubblewrap) {
        Ok(crate::lab::exec::Backend::Bubblewrap { bwrap, version }) => Found {
            kind: Kind::Bwrap,
            usable: true,
            binary: Some(bwrap),
            version: Some(version),
            via: vec![Via::Native],
            why: None,
            gpu: false,
        },
        Ok(_) => unreachable!("asked for bubblewrap"),
        Err(why) => Found::absent(Kind::Bwrap, why.to_string()),
    }
}

/// Whether an engine on this host will pass a GPU: NVIDIA's container
/// toolkit is registered with Docker/nerdctl as a runtime hook and with
/// Podman as a CDI spec, and either leaves a file behind.
fn engine_passes_gpu(engine: &str) -> bool {
    match engine {
        "podman" => ["/etc/cdi/nvidia.yaml", "/var/run/cdi/nvidia.yaml"]
            .iter()
            .any(|p| fs::metadata(p).is_ok()),
        _ => {
            which("nvidia-container-runtime-hook").is_some()
                || which("nvidia-container-toolkit").is_some()
                || which("nvidia-ctk").is_some()
        }
    }
}

// -- engine command lines ---------------------------------------------------------

/// What an engine run needs to know, independent of the job type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineRun<'a> {
    pub engine: &'a str,
    pub runtime: &'a str,
    pub name: &'a str,
    pub image: &'a str,
    pub argv: &'a [String],
    pub cwd: Option<&'a str>,
    pub env: &'a [(String, String)],
    /// `(host path, container path, writable)`.
    pub mounts: &'a [(PathBuf, String, bool)],
    pub cpus: u32,
    pub memory_mb: u64,
    pub pids: u32,
    pub gpus: u64,
    pub network: bool,
    pub tmp_mb: u64,
}

/// The exact argument vector for `<engine> run …`. A pure function, so the
/// tests pin what each engine is asked for; nothing here spawns.
pub fn engine_argv(run: &EngineRun<'_>) -> Vec<String> {
    let mut argv = vec![
        "run".to_string(),
        "--rm".to_string(),
        "--name".to_string(),
        run.name.to_string(),
        "--runtime".to_string(),
        run.runtime.to_string(),
        // Nothing an executor job does needs the engine to pull a TTY or
        // keep stdin open; both would hang a service.
        "--interactive=false".to_string(),
    ];
    argv.push(format!(
        "--network={}",
        if run.network { "bridge" } else { "none" }
    ));
    if run.cpus > 0 {
        argv.push(format!("--cpus={}", run.cpus));
    }
    if run.memory_mb > 0 {
        argv.push(format!("--memory={}m", run.memory_mb));
        // Swap would turn a memory limit into a slowdown rather than a
        // refusal; the lab's rule is that a limit means the limit.
        argv.push(format!("--memory-swap={}m", run.memory_mb));
    }
    if run.pids > 0 {
        argv.push(format!("--pids-limit={}", run.pids));
    }
    if run.tmp_mb > 0 {
        argv.push(format!("--tmpfs=/tmp:rw,size={}m", run.tmp_mb));
    }
    if run.gpus > 0 {
        match run.engine {
            "podman" => argv.push("--device=nvidia.com/gpu=all".to_string()),
            _ => argv.push("--gpus=all".to_string()),
        }
    }
    for (key, value) in run.env {
        argv.push("--env".to_string());
        argv.push(format!("{key}={value}"));
    }
    for (source, target, writable) in run.mounts {
        argv.push("--volume".to_string());
        argv.push(format!(
            "{}:{}:{}",
            source.display(),
            target,
            if *writable { "rw" } else { "ro" }
        ));
    }
    if let Some(cwd) = run.cwd {
        argv.push("--workdir".to_string());
        argv.push(cwd.to_string());
    }
    argv.push(run.image.to_string());
    argv.extend(run.argv.iter().cloned());
    argv
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usable(kind: Kind, via: Vec<Via>, gpu: bool) -> Found {
        Found {
            kind,
            usable: true,
            binary: None,
            version: Some("test".into()),
            via,
            why: None,
            gpu,
        }
    }

    fn engine(engine: &str, runtime: &str) -> Via {
        Via::Engine {
            engine: engine.into(),
            runtime: runtime.into(),
        }
    }

    #[test]
    fn preferences_parse_every_spelling() {
        assert_eq!(Preference::parse("gvisor").unwrap(), Preference::Runsc);
        assert_eq!(Preference::parse("Kata").unwrap(), Preference::Kata);
        assert_eq!(
            Preference::parse("strongest").unwrap(),
            Preference::Strongest
        );
        assert!(Preference::parse("firejail").is_err());
    }

    #[test]
    fn docker_runtime_listings_parse_and_podmans_do_not_break() {
        let docker = r#"{"io.containerd.runc.v2":{"path":"runc"},"runc":{"path":"runc"},"runsc":{"path":"/usr/local/bin/runsc","runtimeArgs":["--nvproxy"]},"kata":{"path":"/usr/bin/containerd-shim-kata-v2"}}"#;
        assert_eq!(
            parse_runtimes(docker),
            ["io.containerd.runc.v2", "kata", "runc", "runsc"]
        );
        assert!(parse_runtimes("null\n").is_empty());
        assert!(parse_runtimes("template: :1:7: executing").is_empty());
    }

    #[test]
    fn auto_prefers_gvisor_then_kata_then_bubblewrap_and_strongest_prefers_kata() {
        let all = Sandboxes::assembled(
            usable(Kind::Kata, vec![engine("docker", "kata")], true),
            usable(
                Kind::Runsc,
                vec![Via::Native, engine("docker", "runsc")],
                true,
            ),
            usable(Kind::Bwrap, vec![Via::Native], false),
            vec![],
        );
        assert_eq!(
            all.choose(Preference::Auto, true, 0).unwrap().kind,
            Kind::Runsc
        );
        assert_eq!(
            all.choose(Preference::Auto, false, 0).unwrap().via,
            Via::Native
        );
        assert_eq!(
            all.choose(Preference::Strongest, true, 0).unwrap().kind,
            Kind::Kata
        );
        assert_eq!(
            all.choose(Preference::Bwrap, false, 0).unwrap().kind,
            Kind::Bwrap
        );
        assert_eq!(
            all.choose(Preference::None, false, 0).unwrap().kind,
            Kind::None
        );

        // No engine: an image job cannot run under gVisor's native path and
        // falls through to nothing, and the refusal says why per sandbox.
        let native_only = Sandboxes::assembled(
            Found::absent(Kind::Kata, "no kata"),
            usable(Kind::Runsc, vec![Via::Native], false),
            usable(Kind::Bwrap, vec![Via::Native], false),
            vec![],
        );
        assert_eq!(
            native_only.choose(Preference::Auto, false, 0).unwrap().kind,
            Kind::Runsc
        );
        let refused = native_only.choose(Preference::Auto, true, 0).unwrap_err();
        assert!(matches!(refused, AgentError::Unavailable(_)));
        assert!(refused.to_string().contains("names an image"), "{refused}");
        assert!(refused.to_string().contains("no kata"), "{refused}");
    }

    #[test]
    fn a_gpu_job_needs_an_engine_that_passes_one() {
        let no_toolkit = Sandboxes::assembled(
            usable(Kind::Kata, vec![engine("docker", "kata")], false),
            usable(
                Kind::Runsc,
                vec![Via::Native, engine("docker", "runsc")],
                false,
            ),
            usable(Kind::Bwrap, vec![Via::Native], false),
            vec![],
        );
        let refused = no_toolkit.choose(Preference::Auto, true, 1).unwrap_err();
        assert!(
            refused.to_string().contains("will not pass a GPU"),
            "{refused}"
        );
        assert!(no_toolkit.choose(Preference::Auto, false, 1).is_err());
        assert!(no_toolkit.choose(Preference::None, false, 1).is_err());

        let with_toolkit = Sandboxes::assembled(
            usable(Kind::Kata, vec![engine("docker", "kata")], true),
            usable(Kind::Runsc, vec![engine("docker", "runsc")], true),
            Found::absent(Kind::Bwrap, "none"),
            vec![],
        );
        let choice = with_toolkit.choose(Preference::Strongest, true, 2).unwrap();
        assert_eq!(choice.kind, Kind::Kata);
        assert_eq!(choice.via, engine("docker", "kata"));
    }

    #[test]
    fn the_engine_command_line_is_exactly_what_each_engine_takes() {
        let argv_in = vec!["python3".to_string(), "walk.py".to_string()];
        let env = vec![("SEED".to_string(), "7".to_string())];
        let mounts = vec![
            (
                PathBuf::from("/var/lib/cairn-agent/jobs/x/out"),
                "/out".to_string(),
                true,
            ),
            (PathBuf::from("/data/job"), "/in/job".to_string(), false),
        ];
        let run = EngineRun {
            engine: "docker",
            runtime: "kata",
            name: "cairn-job-x",
            image: "ghcr.io/example/walker:1",
            argv: &argv_in,
            cwd: Some("/work"),
            env: &env,
            mounts: &mounts,
            cpus: 4,
            memory_mb: 8192,
            pids: 256,
            gpus: 1,
            network: false,
            tmp_mb: 512,
        };
        let argv = engine_argv(&run);
        assert_eq!(
            argv,
            [
                "run",
                "--rm",
                "--name",
                "cairn-job-x",
                "--runtime",
                "kata",
                "--interactive=false",
                "--network=none",
                "--cpus=4",
                "--memory=8192m",
                "--memory-swap=8192m",
                "--pids-limit=256",
                "--tmpfs=/tmp:rw,size=512m",
                "--gpus=all",
                "--env",
                "SEED=7",
                "--volume",
                "/var/lib/cairn-agent/jobs/x/out:/out:rw",
                "--volume",
                "/data/job:/in/job:ro",
                "--workdir",
                "/work",
                "ghcr.io/example/walker:1",
                "python3",
                "walk.py",
            ]
        );
        let podman = EngineRun {
            engine: "podman",
            runtime: "runsc",
            cpus: 0,
            memory_mb: 0,
            pids: 0,
            tmp_mb: 0,
            network: true,
            cwd: None,
            env: &[],
            mounts: &[],
            ..run
        };
        let argv = engine_argv(&podman);
        assert!(argv.contains(&"--device=nvidia.com/gpu=all".to_string()));
        assert!(argv.contains(&"--network=bridge".to_string()));
        assert!(!argv.iter().any(|a| a.starts_with("--cpus")));
    }
}
