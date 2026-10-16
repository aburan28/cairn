//! Immutable inputs for runs. Causal observation and scientific inputs are
//! different: a message received during execution did not supply its files.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::api::{ExecRequest, Input};
use super::env;
use super::op::{self, MAX_ENTRIES};
use super::state::State;
use super::store::Lab;
use super::LabError;
use crate::canonical::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Exact,
    Reapply,
}

impl Mode {
    pub fn name(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Reapply => "reapply",
        }
    }
}

#[derive(Debug, Clone)]
pub struct File {
    pub path: String,
    pub blob: Option<String>,
    pub size: u64,
    pub exec: bool,
    pub versions: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Mount {
    pub kind: String,
    pub prefix: String,
    pub target: String,
    pub single: bool,
    pub files: Vec<File>,
    local: Option<(PathBuf, env::Tree)>,
}

impl Mount {
    /// A digest records an observation; it is not permission to replicate
    /// host bytes. Preserve private mounts until the operator opts in.
    pub fn private_host(source: &Path, target: &str) -> Result<Self, LabError> {
        let source = fs::canonicalize(source)?;
        let tree = env::tree_digest(&source)?;
        Ok(Self {
            kind: "host".into(),
            prefix: String::new(),
            target: target.into(),
            single: false,
            files: Vec::new(),
            local: Some((source, tree)),
        })
    }

    pub fn to_value(&self) -> Value {
        if let Some((_, tree)) = &self.local {
            return Value::object([
                ("kind", Value::string("host")),
                ("prefix", Value::string("")),
                ("target", Value::string(&self.target)),
                ("single", Value::Bool(false)),
                ("snapshot", Value::Null),
                ("tree", Value::string(&tree.digest)),
                ("files", Value::Int(tree.files.into())),
            ]);
        }
        Value::object([
            ("kind", Value::string(&self.kind)),
            ("prefix", Value::string(&self.prefix)),
            ("target", Value::string(&self.target)),
            ("single", Value::Bool(self.single)),
            (
                "snapshot",
                Value::array(self.files.iter().map(|file| {
                    Value::object([
                        ("path", Value::string(&file.path)),
                        (
                            "blob",
                            file.blob.as_ref().map(Value::string).unwrap_or(Value::Null),
                        ),
                        ("size", Value::Int(file.size.into())),
                        ("exec", Value::Bool(file.exec)),
                        (
                            "versions",
                            Value::array(file.versions.iter().map(Value::string)),
                        ),
                    ])
                })),
            ),
        ])
    }

    pub fn from_value(value: &Value) -> Result<Self, LabError> {
        let kind = text(value, "kind")?;
        if !matches!(kind, "lab" | "host") {
            return invalid("unrecognized input kind");
        }
        if kind == "host" && !matches!(value.get("snapshot"), Some(Value::Array(_))) {
            return Err(LabError::Unavailable("a host input was kept private and has no replayable bytes; explicitly run exec with --snapshot-hosts to replicate those inputs".into()));
        }
        let entries = array(value, "snapshot")?;
        if entries.len() > MAX_ENTRIES {
            return invalid("too many pinned input files");
        }
        let mut files = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for file in entries {
            let path = op::normalize_path(text(file, "path")?)?;
            if !seen.insert(path.clone()) {
                return invalid("duplicate pinned path");
            }
            let blob = match file.get("blob") {
                Some(Value::Null) => None,
                Some(Value::String(address)) => Some(op::blob_address(address)?),
                _ => return invalid("pinned input has no blob"),
            };
            files.push(File {
                path,
                blob,
                size: number(file, "size")?,
                exec: boolean(file, "exec")?,
                versions: strings(file, "versions")?,
            });
        }
        let single = boolean(value, "single")?;
        if single && (files.len() != 1 || files[0].blob.is_none()) {
            return invalid("invalid single-file input");
        }
        Ok(Self {
            kind: kind.into(),
            prefix: text(value, "prefix")?.into(),
            target: text(value, "target")?.into(),
            single,
            files,
            local: None,
        })
    }

    /// Re-hash before consumption; a missing or damaged blob teaches nothing
    /// about the program that would have consumed it.
    pub fn materialize(&self, lab: &Lab, dir: &Path) -> Result<PathBuf, LabError> {
        if let Some((source, _)) = &self.local {
            return Ok(source.clone());
        }
        fs::create_dir_all(dir)?;
        for file in &self.files {
            let path = dir.join(&file.path);
            if let Some(blob) = &file.blob {
                if !lab.blobs().verify(blob).unwrap_or(false)
                    || lab.blobs().size(blob).ok() != Some(file.size)
                {
                    return Err(LabError::Unavailable(format!("pinned input {blob} is missing or damaged; sync the original blobs before replaying")));
                }
                lab.blobs().copy_to(blob, &path)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(
                        &path,
                        fs::Permissions::from_mode(if file.exec { 0o755 } else { 0o644 }),
                    )?;
                }
            } else {
                fs::create_dir_all(&path)?;
            }
        }
        Ok(if self.single {
            dir.join(&self.files[0].path)
        } else {
            dir.to_path_buf()
        })
    }
}

/// Host mounts are copied into blobs and then mounted from those copies.
/// Recording a tree hash while mounting a changing host directory would lie
/// about what the command actually read. Symlinks and special files are refused.
pub fn capture(
    lab: &Lab,
    state: &State,
    inputs: &[Input],
    hosts: &[(PathBuf, String)],
) -> Result<Vec<Mount>, LabError> {
    let mut mounts = Vec::new();
    for input in inputs {
        let prefix = input.prefix.trim_end_matches('/');
        let listed = state.list_unambiguous(prefix)?;
        if listed.is_empty() {
            return Err(LabError::NotFound(format!(
                "input {prefix:?} matches no file"
            )));
        }
        let single = listed.len() == 1 && listed[0].0 == prefix;
        let mut files = Vec::new();
        for (path, file) in listed {
            let relative = if single {
                Path::new(path)
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            } else {
                path.strip_prefix(prefix)
                    .unwrap()
                    .trim_start_matches('/')
                    .to_string()
            };
            let versions = state.files[path]
                .iter()
                .map(|value| value.version.entry.to_string())
                .collect();
            files.push(File {
                path: op::normalize_path(&relative)?,
                blob: file.blob.clone(),
                size: file.size,
                exec: file.exec,
                versions,
            });
        }
        if files.len() > MAX_ENTRIES {
            return invalid("an input snapshot exceeds 4096 entries; split the input");
        }
        mounts.push(Mount {
            kind: "lab".into(),
            prefix: prefix.into(),
            target: input.target.clone(),
            single,
            files,
            local: None,
        });
    }
    for (source, target) in hosts {
        if !fs::symlink_metadata(source)?.is_dir() {
            return invalid("a host input must be a directory, not a link");
        }
        let mut files = Vec::new();
        capture_host(lab, source, source, &mut files, &mut 0)?;
        mounts.push(Mount {
            kind: "host".into(),
            prefix: String::new(),
            target: target.clone(),
            single: false,
            files,
            local: None,
        });
    }
    Ok(mounts)
}

fn capture_host(
    lab: &Lab,
    root: &Path,
    dir: &Path,
    files: &mut Vec<File>,
    total: &mut u64,
) -> Result<(), LabError> {
    let mut entries = fs::read_dir(dir)?
        .take(MAX_ENTRIES + 1)
        .collect::<Result<Vec<_>, _>>()?;
    if entries.len() + files.len() > MAX_ENTRIES {
        return invalid("a host snapshot exceeds 4096 entries");
    }
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        if files.len() >= MAX_ENTRIES {
            return invalid("a host snapshot exceeds 4096 entries");
        }
        let path = entry.path();
        let meta = fs::symlink_metadata(&path)?;
        if !meta.is_file() && !meta.is_dir() {
            return invalid("host snapshots cannot contain symlinks or special files");
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|_| LabError::Invalid("input escaped its root".into()))?;
        let relative = op::normalize_path(
            relative
                .to_str()
                .ok_or_else(|| LabError::Invalid("input paths must be UTF-8".into()))?,
        )?;
        const MAX_BYTES: u64 = 1024 * 1024 * 1024;
        if meta.is_file() && total.saturating_add(meta.len()) > MAX_BYTES {
            return invalid("a host snapshot exceeds 1 GiB; publish smaller lab inputs");
        }
        #[cfg(unix)]
        let executable = {
            use std::os::unix::fs::PermissionsExt;
            meta.permissions().mode() & 0o111 != 0
        };
        #[cfg(not(unix))]
        let executable = false;
        let (blob, size) = if meta.is_file() {
            // The file may grow after stat. Bound the actual stream as well
            // as the fast preflight, rather than trusting yesterday's size.
            let mut input = fs::File::open(&path)?.take(MAX_BYTES - *total + 1);
            let mut writer = lab.blobs().writer()?;
            let mut size = 0u64;
            let mut buffer = [0u8; 64 * 1024];
            loop {
                let read = input.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                *total += read as u64;
                size += read as u64;
                if *total > MAX_BYTES {
                    return invalid("a host snapshot exceeds 1 GiB; publish smaller lab inputs");
                }
                writer.write(&buffer[..read])?;
            }
            (Some(writer.finish(None)?), size)
        } else {
            (None, 0)
        };
        files.push(File {
            path: relative,
            blob,
            size,
            exec: executable,
            versions: Vec::new(),
        });
        if meta.is_dir() {
            capture_host(lab, root, &path, files, total)?;
        }
    }
    Ok(())
}

pub struct Plan {
    pub request: ExecRequest,
    pub environment: env::Resolved,
    pub mounts: Vec<Mount>,
    pub heads: Vec<String>,
    pub source: String,
    pub mode: Mode,
}

/// Compare immutable output identities, not a claimed score or verifier verdict.
pub fn compare(
    lab: &Lab,
    source: &str,
    publish: &str,
    files: &[op::FileEntry],
    stdout: &str,
    stderr: &str,
) -> Option<Value> {
    let op::Body::Run {
        receipt,
        files: prior,
    } = &lab.get(source)?.body
    else {
        return None;
    };
    let old_publish = receipt.get("publish")?.as_str()?;
    let relative = |files: &[op::FileEntry], prefix: &str| {
        files
            .iter()
            .filter_map(|file| {
                file.path
                    .strip_prefix(&format!("{prefix}/"))
                    .map(|path| (path.to_string(), (file.blob.clone(), file.exec)))
            })
            .collect::<BTreeMap<_, _>>()
    };
    let expected = relative(prior, old_publish);
    let actual = relative(files, publish);
    let paths = expected
        .keys()
        .chain(actual.keys())
        .collect::<std::collections::BTreeSet<_>>();
    let changed = paths
        .into_iter()
        .filter(|path| expected.get(*path) != actual.get(*path))
        .map(Value::string);
    Some(Value::object([
        ("outputs_identical", Value::Bool(expected == actual)), ("changed_paths", Value::array(changed)),
        ("stdout_identical", Value::Bool(receipt.get("stdout").and_then(Value::as_str) == Some(stdout))),
        ("stderr_identical", Value::Bool(receipt.get("stderr").and_then(Value::as_str) == Some(stderr))),
        ("note", Value::string("Byte identities and executable flags only; matching outputs do not verify a claim or settle a result.")),
    ]))
}

/// Planning is inspectable without starting a runtime. Reapply uses today's
/// unambiguous lab files with the old recipe; it does not merge source code or
/// assert that arbitrary algorithm changes commute.
pub fn plan(lab: &mut Lab, run: &str, mode: Mode) -> Result<Plan, LabError> {
    lab.refresh()?;
    let state = State::of(lab);
    let run = op::op_id(run)?;
    let prior = state
        .runs
        .iter()
        .find(|item| item.id == run)
        .ok_or_else(|| LabError::NotFound(format!("no run {run}")))?;
    let receipt = &prior.receipt;
    if receipt.get("replay_version").and_then(Value::as_u64) != Some(1) {
        return Err(LabError::Unavailable(
            "this historical run has no pinned input manifest; it cannot be replayed safely".into(),
        ));
    }
    let host = receipt
        .get("host")
        .ok_or_else(|| LabError::Invalid("run has no host".into()))?;
    if text(host, "os")? != std::env::consts::OS || text(host, "arch")? != std::env::consts::ARCH {
        return Err(LabError::Unavailable(
            "replay needs the recorded host OS and architecture".into(),
        ));
    }
    let environment = receipt
        .get("env")
        .ok_or_else(|| LabError::Invalid("run has no environment".into()))?;
    let tree = op::digest(text(environment, "tree")?)?;
    let manifest_blob = op::blob_address(text(environment, "manifest")?)?;
    if !lab.blobs().verify(&manifest_blob).unwrap_or(false) {
        return Err(LabError::Unavailable(
            "the pinned environment manifest is missing or damaged".into(),
        ));
    }
    let manifest = Value::from_json(&String::from_utf8_lossy(&lab.blobs().read(&manifest_blob)?))
        .map_err(|e| LabError::Invalid(e.to_string()))?;
    let environment = env::Resolved {
        name: text(environment, "name")?.into(),
        rootfs: env::rootfs_path(lab, &tree)?,
        tree,
        manifest,
    };
    if !env::verify(lab, &environment.tree).unwrap_or(false) {
        return Err(LabError::Unavailable(
            "the pinned environment tree is absent or changed; import the original image".into(),
        ));
    }
    let mut request = ExecRequest::new(&environment.tree, strings(receipt, "argv")?);
    request.cwd = Some(text(receipt, "cwd")?.into());
    request.env_vars = receipt
        .get("env_vars")
        .and_then(Value::as_object)
        .ok_or_else(|| LabError::Invalid("run has no variables".into()))?
        .iter()
        .map(|(key, value)| {
            Ok((
                key.clone(),
                value
                    .as_str()
                    .ok_or_else(|| LabError::Invalid("invalid environment value".into()))?
                    .to_string(),
            ))
        })
        .collect::<Result<BTreeMap<_, _>, LabError>>()?;
    let limits = receipt
        .get("limits")
        .ok_or_else(|| LabError::Invalid("run has no limits".into()))?;
    request.timeout = Duration::from_secs(number(limits, "timeout_s")?);
    request.memory_mb = number(limits, "memory_mb")?;
    request.cpus = u32::try_from(number(limits, "cpus")?)
        .map_err(|_| LabError::Invalid("invalid cpu limit".into()))?;
    request.pids = u32::try_from(number(limits, "pids")?)
        .map_err(|_| LabError::Invalid("invalid pid limit".into()))?;
    request.tmp_mb = number(limits, "tmp_mb")?;
    request.network = boolean(receipt, "network")?;
    if mode == Mode::Exact && request.network {
        return Err(LabError::Unavailable("exact replay cannot pin responses from the external network; use reapply for a new experiment".into()));
    }
    request.task = receipt
        .get("task")
        .and_then(Value::as_str)
        .map(str::to_string);
    let mut mounts = array(receipt, "mounts")?
        .iter()
        .filter(|mount| mount.get("kind").and_then(Value::as_str) != Some("output"))
        .map(Mount::from_value)
        .collect::<Result<Vec<_>, _>>()?;
    let heads = if mode == Mode::Exact {
        strings(receipt, "input_heads")?
    } else {
        lab.heads().iter().cloned().collect()
    };
    if mode == Mode::Reapply {
        request.inputs = mounts
            .iter()
            .filter(|mount| mount.kind == "lab")
            .map(|mount| Input {
                prefix: mount.prefix.clone(),
                target: mount.target.clone(),
            })
            .collect();
        let mut fresh = capture(lab, &state, &request.inputs, &[])?;
        fresh.extend(mounts.into_iter().filter(|mount| mount.kind == "host"));
        mounts = fresh;
    }
    Ok(Plan {
        request,
        environment,
        mounts,
        heads,
        source: run,
        mode,
    })
}

fn invalid<T>(message: &str) -> Result<T, LabError> {
    Err(LabError::Invalid(message.into()))
}
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, LabError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| LabError::Invalid(format!("missing {key}")))
}
fn number(value: &Value, key: &str) -> Result<u64, LabError> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| LabError::Invalid(format!("invalid {key}")))
}
fn boolean(value: &Value, key: &str) -> Result<bool, LabError> {
    match value.get(key) {
        Some(Value::Bool(value)) => Ok(*value),
        _ => invalid(&format!("invalid {key}")),
    }
}
fn array<'a>(value: &'a Value, key: &str) -> Result<&'a [Value], LabError> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| LabError::Invalid(format!("missing {key}")))
}
fn strings(value: &Value, key: &str) -> Result<Vec<String>, LabError> {
    array(value, key)?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| LabError::Invalid(format!("invalid {key}")))
        })
        .collect()
}
