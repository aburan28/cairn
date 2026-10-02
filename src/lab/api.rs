//! The operations the CLI and the MCP server share.
//!
//! One implementation of "write a file", "take a lease" or "run a command in an
//! environment", called by both front ends, so an agent and a person at a shell
//! cannot get different behaviour from the same request.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::env;
use super::exec::{self, Mount, Outcome, Preference, Spec};
use super::op::{self, Body, EntryRef, FileEntry, Op, Outcome as LeaseOutcome, PathMode};
use super::state::{State, TaskView};
use super::store::Lab;
use super::LabError;
use crate::canonical::Value;
use crate::crypto::identity::Identity;

/// How a write relates to what is already there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expect {
    /// Supersede whatever is current now. Right for a person who just read
    /// the file; wrong for anything that read it a while ago.
    Current,
    /// Supersede exactly these versions — the ones the writer saw. A version
    /// that arrived since stays as a sibling and shows as a conflict.
    Seen(Vec<EntryRef>),
    /// Create only: refuse if the path already has a value.
    Absent,
}

/// Write one file.
pub fn write_file(
    lab: &mut Lab,
    identity: &Identity,
    path: &str,
    bytes: &[u8],
    exec: bool,
    expect: Expect,
) -> Result<Op, LabError> {
    let path = op::normalize_path(path)?;
    lab.refresh()?;
    let state = State::of(lab);
    let mode = state.policy.mode(&path);
    if mode == PathMode::Ignored {
        return Err(LabError::Refused(format!(
            "{path} is ignored by this space's policy"
        )));
    }
    let current: Vec<EntryRef> = state
        .files
        .get(&path)
        .map(|values| values.iter().map(|v| v.version.entry.clone()).collect())
        .unwrap_or_default();
    let pred = match expect {
        Expect::Absent if !current.is_empty() => {
            return Err(LabError::Refused(format!("{path} already exists")));
        }
        Expect::Absent => Vec::new(),
        Expect::Current => current.clone(),
        Expect::Seen(seen) => seen,
    };
    if mode == PathMode::WriteOnce && (!pred.is_empty() || !current.is_empty()) {
        return Err(LabError::Refused(format!(
            "{path} is write-once and already exists; an immutable record is never \
             replaced — write a correction under a new path"
        )));
    }
    let blob = lab.blobs().put_bytes(bytes)?;
    lab.append(
        identity,
        Body::Files {
            entries: vec![FileEntry {
                path,
                blob: Some(blob),
                size: bytes.len() as u64,
                exec,
                pred,
            }],
        },
    )
}

/// Delete one file (a tombstone superseding the current values).
pub fn delete_file(lab: &mut Lab, identity: &Identity, path: &str) -> Result<Op, LabError> {
    let path = op::normalize_path(path)?;
    lab.refresh()?;
    let state = State::of(lab);
    if state.policy.mode(&path) == PathMode::WriteOnce {
        return Err(LabError::Refused(format!(
            "{path} is write-once; an immutable record is never deleted"
        )));
    }
    let current: Vec<EntryRef> = state
        .files
        .get(&path)
        .map(|values| values.iter().map(|v| v.version.entry.clone()).collect())
        .ok_or_else(|| LabError::NotFound(path.clone()))?;
    lab.append(
        identity,
        Body::Files {
            entries: vec![FileEntry {
                path,
                blob: None,
                size: 0,
                exec: false,
                pred: current,
            }],
        },
    )
}

/// The bytes a checkout would write for `path`.
pub fn read_file(lab: &Lab, state: &State, path: &str) -> Result<Vec<u8>, LabError> {
    let winner = state
        .winner(path)
        .ok_or_else(|| LabError::NotFound(path.to_string()))?;
    let blob = winner
        .blob
        .as_deref()
        .ok_or_else(|| LabError::NotFound(path.to_string()))?;
    lab.blobs().read(blob)
}

pub fn claim(
    lab: &mut Lab,
    identity: &Identity,
    task: &str,
    holder: &str,
    ttl: u64,
    note: Option<String>,
) -> Result<(Op, TaskView), LabError> {
    let op = lab.append(
        identity,
        Body::Claim {
            task: task.to_string(),
            holder: holder.to_string(),
            ttl,
            note,
        },
    )?;
    let view = State::of(lab).tasks(now()).remove(task).unwrap_or_default();
    Ok((op, view))
}

pub fn release(
    lab: &mut Lab,
    identity: &Identity,
    claim: &str,
    outcome: LeaseOutcome,
    note: Option<String>,
) -> Result<Op, LabError> {
    let claim = op::op_id(claim)?;
    if !State::of(lab).claims.iter().any(|c| c.id == claim) {
        return Err(LabError::NotFound(format!("no lease {claim}")));
    }
    lab.append(
        identity,
        Body::Release {
            claim,
            outcome,
            note,
        },
    )
}

pub fn send(
    lab: &mut Lab,
    identity: &Identity,
    to: Vec<String>,
    from: Option<String>,
    subject: &str,
    body: &str,
    refs: Vec<String>,
) -> Result<Op, LabError> {
    lab.append(
        identity,
        Body::Msg {
            to,
            from,
            subject: subject.to_string(),
            body: body.to_string(),
            refs,
        },
    )
}

pub fn ack(lab: &mut Lab, identity: &Identity, msg: &str, address: &str) -> Result<Op, LabError> {
    lab.append(
        identity,
        Body::Ack {
            msg: op::op_id(msg)?,
            address: address.to_string(),
        },
    )
}

/// Unix seconds now, for evaluating leases. The one clock read in the lab,
/// and only ever on the reader's side.
pub fn now() -> i64 {
    i64::try_from(crate::time::unix_seconds()).unwrap_or(i64::MAX)
}

// -- exec -----------------------------------------------------------------------

/// A lab path prefix checked out read-only into the sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Input {
    pub prefix: String,
    pub target: String,
}

/// What to run, where, and under what limits.
#[derive(Debug, Clone)]
pub struct ExecRequest {
    pub env: String,
    pub argv: Vec<String>,
    pub inputs: Vec<Input>,
    /// Host directories mounted read-only. Recorded in the receipt by tree
    /// digest, since a host path means nothing to anyone else.
    pub mounts: Vec<(PathBuf, String)>,
    /// Lab path the outputs are published under. A fresh `runs/…` when
    /// unset.
    pub publish: Option<String>,
    pub cwd: Option<String>,
    pub env_vars: BTreeMap<String, String>,
    pub timeout: Duration,
    pub memory_mb: u64,
    pub cpus: u32,
    pub pids: u32,
    pub tmp_mb: u64,
    pub network: bool,
    pub sandbox: Preference,
    /// The lease or task this run serves, recorded in the receipt.
    pub task: Option<String>,
    pub note: Option<String>,
    /// Keep the work directory (bundle, captured streams) for inspection.
    pub keep_work: bool,
}

impl ExecRequest {
    pub fn new(env: &str, argv: Vec<String>) -> ExecRequest {
        ExecRequest {
            env: env.to_string(),
            argv,
            inputs: Vec::new(),
            mounts: Vec::new(),
            publish: None,
            cwd: None,
            env_vars: BTreeMap::new(),
            timeout: Duration::from_secs(3600),
            memory_mb: 0,
            cpus: 0,
            pids: 0,
            tmp_mb: 1024,
            network: false,
            sandbox: Preference::Auto,
            task: None,
            note: None,
            keep_work: false,
        }
    }
}

/// What a run produced.
#[derive(Debug, Clone)]
pub struct ExecResult {
    pub op: Op,
    pub outcome: Outcome,
    pub publish: String,
    pub published: Vec<(String, String, u64)>,
    pub stdout: String,
    pub stderr: String,
    pub work: Option<PathBuf>,
}

/// Where outputs are mounted inside the sandbox.
pub const OUTPUT_DIR: &str = "/out";

/// Run a command in an environment and record it.
///
/// The receipt and the output files are one op: a peer never sees outputs
/// without the run that produced them, or a run without its outputs.
pub fn exec(
    lab: &mut Lab,
    identity: &Identity,
    request: &ExecRequest,
) -> Result<ExecResult, LabError> {
    if request.argv.is_empty() {
        return Err(LabError::Invalid("nothing to run".into()));
    }
    lab.refresh()?;
    let state = State::of(lab);
    let environment = env::resolve(lab, &state, &request.env)?;
    let backend = exec::backend(request.sandbox)?;

    let work = lab.root().join("work").join(format!(
        "{}-{}",
        crate::time::unix_seconds(),
        crate::hex::encode(&rand_bytes())
    ));
    fs::create_dir_all(&work)?;
    // Absolute from here on: the OCI bundle's root and mount sources are
    // resolved by the runtime, not relative to wherever this process started.
    let work = fs::canonicalize(&work)?;
    let mut environment = environment;
    environment.rootfs = fs::canonicalize(&environment.rootfs)?;
    let result = exec_in(
        lab,
        identity,
        request,
        &state,
        &environment,
        &backend,
        &work,
    );
    if !request.keep_work || result.is_err() {
        let _ = fs::remove_dir_all(&work);
    }
    result.map(|mut done| {
        done.work = request.keep_work.then_some(work);
        done
    })
}

#[allow(clippy::too_many_arguments)]
fn exec_in(
    lab: &mut Lab,
    identity: &Identity,
    request: &ExecRequest,
    state: &State,
    environment: &env::Resolved,
    backend: &exec::Backend,
    work: &Path,
) -> Result<ExecResult, LabError> {
    let out = work.join("out");
    fs::create_dir_all(&out)?;
    let mut mounts = vec![Mount {
        source: out.clone(),
        target: OUTPUT_DIR.to_string(),
        writable: true,
    }];
    let mut mount_records = vec![Value::object([
        ("target", Value::string(OUTPUT_DIR)),
        ("kind", Value::string("output")),
    ])];

    for (n, input) in request.inputs.iter().enumerate() {
        let prefix = input.prefix.trim_end_matches('/');
        let dir = work.join(format!("in-{n}"));
        fs::create_dir_all(&dir)?;
        let listed = state.list(prefix);
        // A prefix that names one file, and nothing under it, is that file:
        // `--input x/run.py:/work/run.py` puts a file at `/work/run.py`, not
        // a directory there holding `run.py`.
        if let [(path, value)] = listed.as_slice() {
            if *path == prefix {
                let blob = value.blob.as_deref().unwrap_or_default();
                let name = Path::new(path)
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "input".into());
                let file = dir.join(name);
                lab.blobs().copy_to(blob, &file)?;
                mounts.push(Mount {
                    source: file,
                    target: input.target.clone(),
                    writable: false,
                });
                mount_records.push(Value::object([
                    ("target", Value::string(&input.target)),
                    ("kind", Value::string("lab")),
                    ("prefix", Value::string(prefix)),
                    ("blob", Value::string(blob)),
                ]));
                continue;
            }
        }
        if listed.is_empty() {
            return Err(LabError::NotFound(format!(
                "input {prefix:?} matches no file in the space"
            )));
        }
        for (path, value) in listed {
            let relative = if path == prefix {
                Path::new(path)
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_else(|| path.to_string())
            } else {
                path[prefix.len()..].trim_start_matches('/').to_string()
            };
            let Some(blob) = &value.blob else { continue };
            lab.blobs().copy_to(blob, &dir.join(&relative))?;
        }
        let tree = env::tree_digest(&dir)?;
        mounts.push(Mount {
            source: dir,
            target: input.target.clone(),
            writable: false,
        });
        mount_records.push(Value::object([
            ("target", Value::string(&input.target)),
            ("kind", Value::string("lab")),
            ("prefix", Value::string(prefix)),
            ("tree", Value::string(tree.digest)),
            ("files", Value::Int(i128::from(tree.files))),
        ]));
    }
    for (source, target) in &request.mounts {
        let source = fs::canonicalize(source)
            .map_err(|e| LabError::Io(format!("{}: {e}", source.display())))?;
        let tree = env::tree_digest(&source)?;
        mounts.push(Mount {
            source,
            target: target.clone(),
            writable: false,
        });
        mount_records.push(Value::object([
            ("target", Value::string(target)),
            ("kind", Value::string("host")),
            ("tree", Value::string(tree.digest)),
            ("files", Value::Int(i128::from(tree.files))),
        ]));
    }

    let mut env_vars = environment.env();
    env_vars.extend(request.env_vars.clone());
    env_vars.insert("CAIRN_LAB_OUT".into(), OUTPUT_DIR.into());
    let cwd = request
        .cwd
        .clone()
        .or_else(|| environment.workdir())
        .unwrap_or_else(|| OUTPUT_DIR.to_string());
    let spec = Spec {
        rootfs: environment.rootfs.clone(),
        argv: request.argv.clone(),
        cwd: cwd.clone(),
        env: env_vars.clone().into_iter().collect(),
        mounts,
        timeout: request.timeout,
        memory_mb: request.memory_mb,
        cpus: request.cpus,
        pids: request.pids,
        tmp_mb: request.tmp_mb,
        network: request.network,
        runtime_dir: fs::canonicalize(lab.root())?.join("runtime"),
    };
    // A mount the runtime would have to create inside the environment is a
    // mistake in the request: refused before anything runs or is recorded.
    exec::check_targets(&spec.rootfs, &spec.mounts).map_err(LabError::Refused)?;
    let outcome = exec::run(backend, &spec, work);

    // Outputs become write-once entries under the publish prefix.
    let publish = match &request.publish {
        Some(prefix) => op::normalize_path(prefix.trim_end_matches('/'))?,
        None => format!(
            "runs/{}-{}",
            crate::time::timestamp()
                .replace([':', '+'], "")
                .chars()
                .take(17)
                .collect::<String>(),
            crate::hex::encode(&rand_bytes())
        ),
    };
    let mut files = Vec::new();
    let mut published = Vec::new();
    collect_outputs(lab, &out, &out, &publish, &mut files, &mut published)?;
    if files.len() > op::MAX_ENTRIES {
        return Err(LabError::Refused(format!(
            "the run wrote {} files; one run publishes at most {} — write an archive instead",
            files.len(),
            op::MAX_ENTRIES
        )));
    }
    let (stdout_blob, stdout_size) = lab.blobs().put_file(&outcome.stdout)?;
    let (stderr_blob, stderr_size) = lab.blobs().put_file(&outcome.stderr)?;

    let mut receipt = vec![
        ("type", Value::string("cairn.lab.run")),
        (
            "env",
            Value::object([
                ("name", Value::string(&environment.name)),
                ("tree", Value::string(&environment.tree)),
            ]),
        ),
        ("argv", Value::array(request.argv.iter().map(Value::string))),
        ("cwd", Value::string(&cwd)),
        (
            "env_vars",
            Value::Object(
                env_vars
                    .iter()
                    .map(|(k, v)| (k.clone(), Value::string(v)))
                    .collect(),
            ),
        ),
        ("mounts", Value::Array(mount_records)),
        (
            "limits",
            Value::object([
                (
                    "timeout_s",
                    Value::Int(i128::from(request.timeout.as_secs())),
                ),
                ("memory_mb", Value::Int(i128::from(request.memory_mb))),
                ("cpus", Value::Int(i128::from(request.cpus))),
                ("pids", Value::Int(i128::from(request.pids))),
            ]),
        ),
        ("network", Value::Bool(request.network)),
        ("publish", Value::string(&publish)),
        ("stdout", Value::string(&stdout_blob)),
        ("stderr", Value::string(&stderr_blob)),
        ("stdout_bytes", Value::Int(i128::from(stdout_size))),
        ("stderr_bytes", Value::Int(i128::from(stderr_size))),
        (
            "host",
            Value::object([
                ("os", Value::string(std::env::consts::OS)),
                ("arch", Value::string(std::env::consts::ARCH)),
            ]),
        ),
    ];
    receipt.extend(outcome.to_value());
    if let Some(task) = &request.task {
        receipt.push(("task", Value::string(task)));
    }
    if let Some(note) = &request.note {
        receipt.push(("note", Value::string(note)));
    }
    let op = lab.append(
        identity,
        Body::Run {
            receipt: Value::object(receipt),
            files,
        },
    )?;
    let stdout =
        String::from_utf8_lossy(&fs::read(&outcome.stdout).unwrap_or_default()).into_owned();
    let stderr =
        String::from_utf8_lossy(&fs::read(&outcome.stderr).unwrap_or_default()).into_owned();
    Ok(ExecResult {
        op,
        outcome,
        publish,
        published,
        stdout,
        stderr,
        work: None,
    })
}

fn collect_outputs(
    lab: &Lab,
    root: &Path,
    dir: &Path,
    publish: &str,
    files: &mut Vec<FileEntry>,
    published: &mut Vec<(String, String, u64)>,
) -> Result<(), LabError> {
    let mut entries: Vec<_> = fs::read_dir(dir)?.filter_map(Result::ok).collect();
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let meta = fs::symlink_metadata(&path)?;
        if meta.file_type().is_dir() {
            collect_outputs(lab, root, &path, publish, files, published)?;
            continue;
        }
        if !meta.file_type().is_file() {
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|_| LabError::Io("output walked outside its directory".into()))?
            .to_string_lossy()
            .replace(std::path::MAIN_SEPARATOR, "/");
        let lab_path = op::normalize_path(&format!("{publish}/{relative}"))?;
        let (blob, size) = lab.blobs().put_file(&path)?;
        #[cfg(unix)]
        let exec = {
            use std::os::unix::fs::PermissionsExt as _;
            meta.permissions().mode() & 0o111 != 0
        };
        #[cfg(not(unix))]
        let exec = false;
        files.push(FileEntry {
            path: lab_path.clone(),
            blob: Some(blob.clone()),
            size,
            exec,
            pred: Vec::new(),
        });
        published.push((lab_path, blob, size));
    }
    Ok(())
}

fn rand_bytes() -> [u8; 4] {
    use rand_core::RngCore as _;
    let mut bytes = [0u8; 4];
    rand_core::OsRng.fill_bytes(&mut bytes);
    bytes
}
