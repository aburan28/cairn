//! An executor job: what runs, where, with what, and the receipt it leaves.
//!
//! A job is a JSON file. It names either an **image** (run through a
//! container engine under Kata or gVisor) or a **root filesystem directory**
//! (run through [`crate::lab::exec`] under gVisor or bubblewrap), the
//! command, and the resources it wants. The agent runs it and writes a
//! receipt beside the captured streams: the jail it got, the exit status,
//! the wall clock, and anything that could not be enforced. The receipt
//! never says whether the output is *right* -- that is a verifier's job.
//!
//! ```json
//! {
//!   "id": "walk-0017",
//!   "objective_id": "sha256:…",
//!   "task": "unit:4017",
//!   "image": "ghcr.io/example/walker:1",
//!   "argv": ["python3", "walk.py", "--unit", "4017"],
//!   "env": {"SEED": "7"},
//!   "inputs": [{"source": "/data/job.json", "target": "/in/job.json"}],
//!   "cpus": 4, "memory_mb": 8192, "gpus": 1, "pids": 256,
//!   "timeout_seconds": 3600, "network": false, "sandbox": "strongest"
//! }
//! ```
//!
//! Whatever the job writes to `/out` is kept in the job's directory under
//! `out/`. The `objective_id` and `task` are optional and advisory: with
//! both, the agent leases the task on its nodes while the job runs and
//! releases it with the outcome, so a roster shows who is on what.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::sandbox::{self, Choice, EngineRun, Kind, Preference, Sandboxes, Via};
use super::AgentError;
use crate::canonical::Value;

/// A job's `timeout_seconds` when it names none: an hour.
pub const DEFAULT_TIMEOUT_SECONDS: u64 = 3600;
/// The longest a job may ask for: a week. A job that needs longer is a
/// service, and should be split so a receipt lands at least weekly.
pub const MAX_TIMEOUT_SECONDS: u64 = 7 * 86_400;
const DEFAULT_PIDS: u32 = 1024;
const DEFAULT_TMP_MB: u64 = 1024;
const MAX_ID_LEN: usize = 96;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Input {
    pub source: PathBuf,
    pub target: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Job {
    pub id: String,
    pub objective_id: Option<String>,
    pub task: Option<String>,
    pub image: Option<String>,
    pub rootfs: Option<PathBuf>,
    pub argv: Vec<String>,
    pub cwd: Option<String>,
    pub env: Vec<(String, String)>,
    pub inputs: Vec<Input>,
    pub cpus: u32,
    pub memory_mb: u64,
    pub gpus: u64,
    pub pids: u32,
    pub timeout: Duration,
    pub network: bool,
    pub sandbox: Preference,
    pub tmp_mb: u64,
    pub note: Option<String>,
}

const FIELDS: [&str; 17] = [
    "id",
    "objective_id",
    "task",
    "image",
    "rootfs",
    "argv",
    "cwd",
    "env",
    "inputs",
    "cpus",
    "memory_mb",
    "gpus",
    "pids",
    "timeout_seconds",
    "network",
    "sandbox",
    "note",
];

/// An OCI image reference as `docker run` takes one: registry, path, tag and
/// digest, and nothing an engine would parse as an option.
pub fn valid_image_reference(image: &str) -> bool {
    !image.is_empty()
        && image.len() <= 255
        && image.starts_with(|c: char| c.is_ascii_alphanumeric())
        && image
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/' | ':' | '@'))
}

impl Job {
    pub fn from_file(path: &Path) -> Result<Job, AgentError> {
        let text = fs::read_to_string(path)
            .map_err(|e| AgentError::Io(format!("{}: {e}", path.display())))?;
        let value = Value::from_json(&text)
            .map_err(|e| AgentError::Invalid(format!("{}: not JSON: {e}", path.display())))?;
        let fallback = path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        Job::from_value(&value, &fallback)
    }

    /// Decode a job. `fallback_id` names it when the spec does not.
    pub fn from_value(value: &Value, fallback_id: &str) -> Result<Job, AgentError> {
        let object = value
            .as_object()
            .ok_or_else(|| AgentError::Invalid("a job is a JSON object".into()))?;
        if let Some(unknown) = object.keys().find(|key| !FIELDS.contains(&key.as_str())) {
            return Err(AgentError::Invalid(format!(
                "unknown job field {unknown:?}; the fields are {}",
                FIELDS.join(", ")
            )));
        }
        let text = |field: &str| -> Result<Option<String>, AgentError> {
            match object.get(field) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::String(s)) if !s.is_empty() => Ok(Some(s.clone())),
                Some(_) => Err(AgentError::Invalid(format!(
                    "job field `{field}` must be a non-empty string"
                ))),
            }
        };
        let int = |field: &str, default: u64| -> Result<u64, AgentError> {
            match object.get(field) {
                None | Some(Value::Null) => Ok(default),
                Some(v) => v.as_u64().ok_or_else(|| {
                    AgentError::Invalid(format!(
                        "job field `{field}` must be a non-negative integer"
                    ))
                }),
            }
        };
        let id = text("id")?.unwrap_or_else(|| fallback_id.to_string());
        if id.is_empty()
            || id.len() > MAX_ID_LEN
            || !id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
            || id.starts_with('.')
        {
            return Err(AgentError::Invalid(format!(
                "job id {id:?} must be 1-{MAX_ID_LEN} characters of [A-Za-z0-9._-] and not start with a dot"
            )));
        }
        let image = text("image")?;
        // The image is a positional argument to `docker run` / `podman run`,
        // after every option this agent sets. A value that starts with `-`
        // is read as one more option -- `--volume=/:/host`, `--privileged`,
        // `--runtime=runc` -- which is the host's root through the engine's
        // daemon. A reference is a name, so it is held to a name's alphabet.
        if let Some(image) = &image {
            if !valid_image_reference(image) {
                return Err(AgentError::Invalid(format!(
                    "image {image:?} is not an image reference: 1-255 characters of \
                     [A-Za-z0-9._/:@-], starting with a letter or digit"
                )));
            }
        }
        let rootfs = text("rootfs")?.map(PathBuf::from);
        match (&image, &rootfs) {
            (None, None) => {
                return Err(AgentError::Invalid(
                    "a job names an `image` (run through a container engine) or a `rootfs` \
                     directory (run through runsc or bwrap directly)"
                        .into(),
                ))
            }
            (Some(_), Some(_)) => {
                return Err(AgentError::Invalid(
                    "a job names `image` or `rootfs`, not both".into(),
                ))
            }
            _ => {}
        }
        if let Some(rootfs) = &rootfs {
            if !rootfs.is_absolute() {
                return Err(AgentError::Invalid(format!(
                    "rootfs {} must be an absolute path",
                    rootfs.display()
                )));
            }
        }
        let argv: Vec<String> = match object.get("argv") {
            Some(Value::Array(items)) if !items.is_empty() => items
                .iter()
                .map(|item| {
                    item.as_str().map(str::to_string).ok_or_else(|| {
                        AgentError::Invalid("job `argv` must be an array of strings".into())
                    })
                })
                .collect::<Result<_, _>>()?,
            _ => {
                return Err(AgentError::Invalid(
                    "job `argv` must be a non-empty array of strings".into(),
                ))
            }
        };
        let cwd = text("cwd")?;
        if let Some(cwd) = &cwd {
            if !cwd.starts_with('/') {
                return Err(AgentError::Invalid(format!(
                    "job `cwd` {cwd:?} must be absolute inside the sandbox"
                )));
            }
        }
        let env: Vec<(String, String)> = match object.get("env") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Object(pairs)) => pairs
                .iter()
                .map(|(key, value)| {
                    let value = value.as_str().ok_or_else(|| {
                        AgentError::Invalid(format!("job env `{key}` must be a string"))
                    })?;
                    if key.is_empty() || key.contains('=') || key.chars().any(char::is_control) {
                        return Err(AgentError::Invalid(format!(
                            "job env name {key:?} is not a valid variable name"
                        )));
                    }
                    Ok((key.clone(), value.to_string()))
                })
                .collect::<Result<_, _>>()?,
            Some(_) => {
                return Err(AgentError::Invalid(
                    "job `env` must be an object of strings".into(),
                ))
            }
        };
        let inputs: Vec<Input> = match object.get("inputs") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(items)) => items
                .iter()
                .map(|item| {
                    let source = item
                        .get("source")
                        .and_then(Value::as_str)
                        .map(PathBuf::from)
                        .filter(|p| p.is_absolute())
                        .ok_or_else(|| {
                            AgentError::Invalid(
                                "each job input needs an absolute `source` path".into(),
                            )
                        })?;
                    let target = item
                        .get("target")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                        .unwrap_or_else(|| {
                            format!(
                                "/in/{}",
                                source
                                    .file_name()
                                    .map(|n| n.to_string_lossy().to_string())
                                    .unwrap_or_default()
                            )
                        });
                    if !target.starts_with('/') || target == "/" || target.starts_with("/out") {
                        return Err(AgentError::Invalid(format!(
                            "job input target {target:?} must be an absolute path other than / and /out"
                        )));
                    }
                    Ok(Input { source, target })
                })
                .collect::<Result<_, _>>()?,
            Some(_) => {
                return Err(AgentError::Invalid(
                    "job `inputs` must be an array of {source, target}".into(),
                ))
            }
        };
        let timeout_seconds = int("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)?;
        if timeout_seconds == 0 || timeout_seconds > MAX_TIMEOUT_SECONDS {
            return Err(AgentError::Invalid(format!(
                "job `timeout_seconds` must be between 1 and {MAX_TIMEOUT_SECONDS}"
            )));
        }
        let network = match object.get("network") {
            None | Some(Value::Null) => false,
            Some(Value::Bool(b)) => *b,
            Some(_) => {
                return Err(AgentError::Invalid(
                    "job `network` must be true or false".into(),
                ))
            }
        };
        let sandbox = match text("sandbox")? {
            Some(name) => Preference::parse(&name)?,
            None => Preference::Auto,
        };
        Ok(Job {
            id,
            objective_id: text("objective_id")?,
            task: text("task")?,
            image,
            rootfs,
            argv,
            cwd,
            env,
            inputs,
            cpus: u32::try_from(int("cpus", 0)?).unwrap_or(u32::MAX),
            memory_mb: int("memory_mb", 0)?,
            gpus: int("gpus", 0)?,
            pids: u32::try_from(int("pids", u64::from(DEFAULT_PIDS))?).unwrap_or(u32::MAX),
            timeout: Duration::from_secs(timeout_seconds),
            network,
            sandbox,
            tmp_mb: DEFAULT_TMP_MB,
            note: text("note")?,
        })
    }

    pub fn to_value(&self) -> Value {
        let opt = |value: &Option<String>| match value {
            Some(s) => Value::string(s.clone()),
            None => Value::Null,
        };
        Value::object([
            ("id", Value::string(self.id.clone())),
            ("objective_id", opt(&self.objective_id)),
            ("task", opt(&self.task)),
            ("image", opt(&self.image)),
            (
                "rootfs",
                match &self.rootfs {
                    Some(p) => Value::string(p.display().to_string()),
                    None => Value::Null,
                },
            ),
            (
                "argv",
                Value::array(self.argv.iter().map(|a| Value::string(a.clone()))),
            ),
            ("cwd", opt(&self.cwd)),
            (
                "env",
                Value::Object(
                    self.env
                        .iter()
                        .map(|(k, v)| (k.clone(), Value::string(v.clone())))
                        .collect::<BTreeMap<_, _>>(),
                ),
            ),
            (
                "inputs",
                Value::array(self.inputs.iter().map(|input| {
                    Value::object([
                        ("source", Value::string(input.source.display().to_string())),
                        ("target", Value::string(input.target.clone())),
                    ])
                })),
            ),
            ("cpus", Value::Int(i128::from(self.cpus))),
            ("memory_mb", Value::Int(i128::from(self.memory_mb))),
            ("gpus", Value::Int(i128::from(self.gpus))),
            ("pids", Value::Int(i128::from(self.pids))),
            (
                "timeout_seconds",
                Value::Int(i128::from(self.timeout.as_secs())),
            ),
            ("network", Value::Bool(self.network)),
            ("sandbox", Value::string(self.sandbox.as_str())),
            ("note", opt(&self.note)),
        ])
    }
}

/// What happened to a job. Written as `receipt.json` in the job's directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    pub job_id: String,
    pub host: String,
    pub sandbox: Kind,
    pub via: String,
    pub sandbox_version: Option<String>,
    pub exit_status: Option<i64>,
    pub timed_out: bool,
    pub limit_exceeded: bool,
    /// The jail could not be set up or the engine could not start the
    /// container. Not a fact about the program.
    pub error: Option<String>,
    pub started: String,
    pub finished: String,
    pub wall_ms: u64,
    pub stdout: PathBuf,
    pub stderr: PathBuf,
    pub out_dir: PathBuf,
    pub gpus_requested: u64,
    pub unenforced: Vec<String>,
    pub notes: Vec<String>,
}

impl Receipt {
    /// The program ran and exited 0 inside its limits.
    pub fn succeeded(&self) -> bool {
        self.error.is_none()
            && !self.timed_out
            && !self.limit_exceeded
            && self.exit_status == Some(0)
    }

    /// `completed` / `failed` / `abandoned`, the lease vocabulary.
    pub fn lease_outcome(&self) -> &'static str {
        if self.succeeded() {
            "completed"
        } else if self.error.is_some() {
            "abandoned"
        } else {
            "failed"
        }
    }

    pub fn to_value(&self) -> Value {
        let opt_text = |value: &Option<String>| match value {
            Some(s) => Value::string(s.clone()),
            None => Value::Null,
        };
        Value::object([
            ("job_id", Value::string(self.job_id.clone())),
            ("host", Value::string(self.host.clone())),
            ("agent", Value::string(super::CLIENT)),
            ("sandbox", Value::string(self.sandbox.as_str())),
            ("via", Value::string(self.via.clone())),
            ("sandbox_version", opt_text(&self.sandbox_version)),
            (
                "exit_status",
                match self.exit_status {
                    Some(s) => Value::Int(i128::from(s)),
                    None => Value::Null,
                },
            ),
            ("succeeded", Value::Bool(self.succeeded())),
            ("timed_out", Value::Bool(self.timed_out)),
            ("limit_exceeded", Value::Bool(self.limit_exceeded)),
            ("error", opt_text(&self.error)),
            ("started", Value::string(self.started.clone())),
            ("finished", Value::string(self.finished.clone())),
            ("wall_ms", Value::Int(i128::from(self.wall_ms))),
            ("stdout", Value::string(self.stdout.display().to_string())),
            ("stderr", Value::string(self.stderr.display().to_string())),
            ("out", Value::string(self.out_dir.display().to_string())),
            (
                "gpus_requested",
                Value::Int(i128::from(self.gpus_requested)),
            ),
            (
                "unenforced",
                Value::array(self.unenforced.iter().map(|s| Value::string(s.clone()))),
            ),
            (
                "notes",
                Value::array(self.notes.iter().map(|s| Value::string(s.clone()))),
            ),
            (
                "note",
                Value::string(
                    "A fact about this host: what ran, in which jail, with what exit status. \
                     Never a verdict on what it produced; a pinned verifier decides that.",
                ),
            ),
        ])
    }
}

/// Run `job` in `dir` (created by the caller; `out/`, `stdout`, `stderr`
/// and `receipt.json` land in it) under the jail `sandboxes` chooses.
pub fn run(job: &Job, sandboxes: &Sandboxes, dir: &Path, host: &str) -> Receipt {
    let out_dir = dir.join("out");
    let stdout = dir.join("stdout");
    let stderr = dir.join("stderr");
    let mut receipt = Receipt {
        job_id: job.id.clone(),
        host: host.to_string(),
        sandbox: Kind::None,
        via: String::new(),
        sandbox_version: None,
        exit_status: None,
        timed_out: false,
        limit_exceeded: false,
        error: None,
        started: crate::time::timestamp(),
        finished: String::new(),
        wall_ms: 0,
        stdout: stdout.clone(),
        stderr: stderr.clone(),
        out_dir: out_dir.clone(),
        gpus_requested: job.gpus,
        unenforced: Vec::new(),
        notes: Vec::new(),
    };
    let started = Instant::now();
    let result = fs::create_dir_all(&out_dir)
        .map_err(|e| format!("{}: {e}", out_dir.display()))
        .and_then(|()| {
            sandboxes
                .choose(job.sandbox, job.image.is_some(), job.gpus)
                .map_err(|e| e.to_string())
        })
        .and_then(|choice| {
            receipt.sandbox = choice.kind;
            receipt.via = match &choice.via {
                Via::Native => "native".to_string(),
                Via::Engine { engine, runtime } => format!("{engine}:{runtime}"),
            };
            receipt.sandbox_version = sandboxes
                .found(choice.kind)
                .and_then(|found| found.version.clone());
            if job.network {
                receipt
                    .notes
                    .push("network: the job asked for it and got it".into());
            }
            match &choice.via {
                Via::Engine { .. } => run_engine(job, &choice, sandboxes, dir, &mut receipt),
                Via::Native => run_native(job, &choice, dir, &mut receipt),
            }
        });
    if let Err(why) = result {
        receipt.error = Some(why);
    }
    receipt.wall_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    receipt.finished = crate::time::timestamp();
    for path in [&stdout, &stderr] {
        if !path.exists() {
            let _ = File::create(path);
        }
    }
    let _ = fs::write(
        dir.join("receipt.json"),
        format!("{}\n", receipt.to_value().canonical_string()),
    );
    receipt
}

/// `<engine> run --rm --runtime <rt> …`, with a wall-clock deadline enforced
/// by `<engine> kill`. The job's `/out` is the directory's `out/`.
fn run_engine(
    job: &Job,
    choice: &Choice,
    sandboxes: &Sandboxes,
    dir: &Path,
    receipt: &mut Receipt,
) -> Result<(), String> {
    let (engine_name, runtime) = match &choice.via {
        Via::Engine { engine, runtime } => (engine.as_str(), runtime.as_str()),
        Via::Native => unreachable!(),
    };
    let engine = sandboxes
        .engines
        .iter()
        .find(|e| e.name == engine_name)
        .ok_or_else(|| format!("engine {engine_name} vanished between probe and run"))?;
    let image = job.image.as_deref().expect("engine runs take an image");
    let name = format!("cairn-job-{}", job.id);
    let mut mounts: Vec<(PathBuf, String, bool)> =
        vec![(dir.join("out"), "/out".to_string(), true)];
    for input in &job.inputs {
        mounts.push((input.source.clone(), input.target.clone(), false));
    }
    let argv = sandbox::engine_argv(&EngineRun {
        engine: engine_name,
        runtime,
        name: &name,
        image,
        argv: &job.argv,
        cwd: job.cwd.as_deref(),
        env: &job.env,
        mounts: &mounts,
        cpus: job.cpus,
        memory_mb: job.memory_mb,
        pids: job.pids,
        gpus: job.gpus,
        network: job.network,
        tmp_mb: job.tmp_mb,
    });
    let _ = fs::write(
        dir.join("command"),
        format!("{} {}\n", engine.path.display(), argv.join(" ")),
    );
    let stdout = File::create(&receipt.stdout).map_err(|e| e.to_string())?;
    let stderr = File::create(&receipt.stderr).map_err(|e| e.to_string())?;
    let mut child = Command::new(&engine.path)
        .args(&argv)
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr)
        .spawn()
        .map_err(|e| format!("{}: {e}", engine.path.display()))?;
    let deadline = Instant::now() + job.timeout;
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            break status;
        }
        if Instant::now() >= deadline {
            receipt.timed_out = true;
            // Kill the container by name rather than the client: the client
            // dying leaves the container running under `--rm`'s promise to
            // nobody.
            let _ = Command::new(&engine.path)
                .args(["kill", &name])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            let _ = child.kill();
            break child.wait().map_err(|e| e.to_string())?;
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    let code = status.code().map(i64::from);
    // An engine reports a container the runtime could not start as 125/126/127
    // and says why on stderr. That is the host failing, not the program.
    match code {
        Some(125) | Some(126) | Some(127) if !receipt.timed_out => {
            let why = fs::read_to_string(&receipt.stderr)
                .ok()
                .and_then(|text| text.lines().last().map(|l| l.trim().to_string()))
                .filter(|l| !l.is_empty())
                .unwrap_or_else(|| format!("{engine_name} exited {}", code.unwrap_or(-1)));
            return Err(format!(
                "{engine_name} could not start the container: {why}"
            ));
        }
        Some(137) if job.memory_mb > 0 => {
            receipt.limit_exceeded = true;
            receipt
                .notes
                .push("exit 137: killed, most likely by the memory limit".into());
        }
        _ => {}
    }
    receipt.exit_status = code;
    if choice.kind == Kind::Runsc && job.gpus > 0 {
        receipt.notes.push(
            "GPU under gVisor needs `--nvproxy` in the runtime's daemon configuration; the \
             engine was asked for the device and this receipt cannot see whether the \
             runtime exposed it"
                .into(),
        );
    }
    Ok(())
}

/// A root filesystem job through the lab's runner, which already knows how
/// to drive `runsc` and `bwrap` over a directory.
fn run_native(job: &Job, choice: &Choice, dir: &Path, receipt: &mut Receipt) -> Result<(), String> {
    use crate::lab::exec::{self as lab, Backend, Mount, Spec};
    let rootfs = job.rootfs.as_deref().expect("native runs take a rootfs");
    if !rootfs.is_dir() {
        return Err(format!("rootfs {} is not a directory", rootfs.display()));
    }
    let backend = match choice.kind {
        Kind::Runsc => lab::backend(lab::Preference::Gvisor),
        Kind::Bwrap => lab::backend(lab::Preference::Bubblewrap),
        Kind::None => Ok(Backend::Unconfined),
        Kind::Kata => return Err("Kata has no engine-free path; name an image".to_string()),
    }
    .map_err(|e| e.to_string())?;
    let mut mounts = vec![Mount {
        source: dir.join("out"),
        target: "/out".to_string(),
        writable: true,
    }];
    for input in &job.inputs {
        mounts.push(Mount {
            source: input.source.clone(),
            target: input.target.clone(),
            writable: false,
        });
    }
    let runtime_dir = dir
        .parent()
        .and_then(Path::parent)
        .map(|agent| agent.join("runsc"))
        .unwrap_or_else(|| dir.join("runsc"));
    let spec = Spec {
        rootfs: rootfs.to_path_buf(),
        argv: job.argv.clone(),
        cwd: job.cwd.clone().unwrap_or_else(|| "/".to_string()),
        env: job.env.clone(),
        mounts,
        timeout: job.timeout,
        memory_mb: job.memory_mb,
        cpus: job.cpus,
        pids: job.pids,
        tmp_mb: job.tmp_mb,
        network: job.network,
        runtime_dir,
    };
    let work = dir.join("work");
    fs::create_dir_all(&work).map_err(|e| format!("{}: {e}", work.display()))?;
    let outcome = lab::run(&backend, &spec, &work);
    // The lab writes its captures in `work`; the receipt names the job's own.
    let _ = fs::rename(&outcome.stdout, &receipt.stdout);
    let _ = fs::rename(&outcome.stderr, &receipt.stderr);
    receipt.exit_status = outcome.exit_status;
    receipt.timed_out = outcome.timed_out;
    receipt.limit_exceeded = outcome.limit_exceeded;
    receipt.unenforced = outcome.unenforced;
    receipt.notes.extend(outcome.notes);
    if !outcome.backend_version.is_empty() {
        receipt.sandbox_version = Some(outcome.backend_version);
    }
    match outcome.error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(json: &str) -> Result<Job, AgentError> {
        Job::from_value(&Value::from_json(json).unwrap(), "fallback")
    }

    #[test]
    fn an_image_that_would_be_read_as_an_engine_option_is_refused() {
        for image in [
            "--volume=/:/host",
            "--privileged",
            "-v/:/host",
            "alpine --privileged",
            "alpine\nx",
            " alpine",
            "",
        ] {
            let spec = Value::object([
                ("image", Value::string(image)),
                ("argv", Value::Array(vec![Value::string("true")])),
            ]);
            assert!(
                Job::from_value(&spec, "x").is_err(),
                "{image:?} reached `docker run` as an image"
            );
        }
        for image in [
            "alpine",
            "ghcr.io/x/y:1",
            "localhost:5000/team/walker:v2.1",
            "alpine@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ] {
            assert!(valid_image_reference(image), "{image} refused");
        }
    }

    #[test]
    fn a_job_decodes_with_defaults_and_refuses_what_it_cannot_run() {
        let j = job(r#"{"image":"ghcr.io/x/y:1","argv":["true"]}"#).unwrap();
        assert_eq!(j.id, "fallback");
        assert_eq!(j.timeout, Duration::from_secs(DEFAULT_TIMEOUT_SECONDS));
        assert_eq!(j.sandbox, Preference::Auto);
        assert_eq!(j.pids, DEFAULT_PIDS);
        assert!(!j.network);

        let full = job(
            r#"{"id":"walk-0017","objective_id":"sha256:o","task":"unit:4017","image":"i","argv":["python3","walk.py"],"env":{"SEED":"7"},"inputs":[{"source":"/data/job.json"}],"cpus":4,"memory_mb":8192,"gpus":1,"timeout_seconds":60,"network":true,"sandbox":"strongest","cwd":"/work"}"#,
        )
        .unwrap();
        assert_eq!(full.inputs[0].target, "/in/job.json");
        assert_eq!(full.sandbox, Preference::Strongest);
        assert_eq!(full.gpus, 1);
        let round = Job::from_value(&full.to_value(), "x").unwrap();
        assert_eq!(round, full);

        for (bad, needle) in [
            (r#"{"argv":["true"]}"#, "image"),
            (r#"{"image":"i","rootfs":"/r","argv":["true"]}"#, "not both"),
            (r#"{"image":"i","argv":[]}"#, "argv"),
            (r#"{"image":"i","argv":["true"],"id":"../x"}"#, "job id"),
            (r#"{"image":"i","argv":["true"],"id":".hidden"}"#, "job id"),
            (r#"{"rootfs":"relative","argv":["true"]}"#, "absolute"),
            (
                r#"{"image":"i","argv":["true"],"timeout_seconds":0}"#,
                "timeout",
            ),
            (
                r#"{"image":"i","argv":["true"],"colour":"blue"}"#,
                "unknown job field",
            ),
            (
                r#"{"image":"i","argv":["true"],"inputs":[{"source":"/a","target":"/out/x"}]}"#,
                "/out",
            ),
            (
                r#"{"image":"i","argv":["true"],"env":{"A=B":"c"}}"#,
                "variable name",
            ),
            (
                r#"{"image":"i","argv":["true"],"sandbox":"firejail"}"#,
                "unknown sandbox",
            ),
        ] {
            let error = job(bad).unwrap_err().to_string();
            assert!(error.contains(needle), "{bad}: {error}");
        }
    }

    #[test]
    fn a_receipt_reports_outcomes_in_the_lease_vocabulary() {
        let mut receipt = Receipt {
            job_id: "j".into(),
            host: "h".into(),
            sandbox: Kind::Runsc,
            via: "native".into(),
            sandbox_version: None,
            exit_status: Some(0),
            timed_out: false,
            limit_exceeded: false,
            error: None,
            started: String::new(),
            finished: String::new(),
            wall_ms: 1,
            stdout: PathBuf::from("o"),
            stderr: PathBuf::from("e"),
            out_dir: PathBuf::from("out"),
            gpus_requested: 0,
            unenforced: vec![],
            notes: vec![],
        };
        assert!(receipt.succeeded());
        assert_eq!(receipt.lease_outcome(), "completed");
        receipt.exit_status = Some(1);
        assert_eq!(receipt.lease_outcome(), "failed");
        receipt.error = Some("no sandbox".into());
        assert_eq!(receipt.lease_outcome(), "abandoned");
        assert_eq!(
            receipt.to_value().get("succeeded"),
            Some(&Value::Bool(false))
        );
    }

    #[test]
    fn an_unconfined_run_leaves_a_receipt_and_its_output() {
        // `sandbox: none` is the one path every CI host can take, and it is
        // explicitly asked for here, as the agent requires. Unconfined, the
        // lab runner does not chroot: `/out` is reached through the
        // `CAIRN_LAB_OUT` variable it exports, as its receipt note says.
        let dir = std::env::temp_dir().join(format!(
            "cairn-agent-job-{}-{}",
            std::process::id(),
            crate::time::unix_seconds()
        ));
        fs::create_dir_all(&dir).unwrap();
        let j = job(
            r#"{"id":"hello","rootfs":"/","argv":["/bin/sh","-c","echo hi > \"$CAIRN_LAB_OUT/hi\" && echo done"],"sandbox":"none","timeout_seconds":30}"#,
        )
        .unwrap();
        let sandboxes = Sandboxes::assembled(
            super::super::sandbox::Found {
                kind: Kind::Kata,
                usable: false,
                binary: None,
                version: None,
                via: vec![],
                why: Some("test".into()),
                gpu: false,
            },
            super::super::sandbox::Found {
                kind: Kind::Runsc,
                usable: false,
                binary: None,
                version: None,
                via: vec![],
                why: Some("test".into()),
                gpu: false,
            },
            super::super::sandbox::Found {
                kind: Kind::Bwrap,
                usable: false,
                binary: None,
                version: None,
                via: vec![],
                why: Some("test".into()),
                gpu: false,
            },
            vec![],
        );
        let receipt = run(&j, &sandboxes, &dir, "test-host");
        assert_eq!(receipt.sandbox, Kind::None);
        assert!(receipt.succeeded(), "{receipt:?}");
        assert_eq!(fs::read_to_string(dir.join("out/hi")).unwrap().trim(), "hi");
        assert!(fs::read_to_string(&receipt.stdout)
            .unwrap()
            .contains("done"));
        let written = fs::read_to_string(dir.join("receipt.json")).unwrap();
        assert!(written.contains("\"sandbox\":\"none\""));
        let _ = fs::remove_dir_all(&dir);
    }
}
