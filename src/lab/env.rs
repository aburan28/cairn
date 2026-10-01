//! Execution environments: root filesystems, identified by what is in them.
//!
//! An experiment that needs SageMath, PARI/GP and msolve at particular versions
//! should not depend on whichever machine happens to run it having them — the
//! research program this was built for lost a gate run to exactly that: a
//! comparator that needed Sage, on a host that did not have it. An
//! environment here is a whole root filesystem, imported once, named in the
//! space, and run under gVisor by [`super::exec`].
//!
//! # Identity is the tree, not the build
//!
//! An environment's id is a digest over every path in it: its type, its
//! permission bits, its size, and the sha256 of its bytes (or its link
//! target). Owners and timestamps are left out on purpose — they change on
//! every extraction, differ between a root and a rootless import, and say
//! nothing about what a program computes. Two machines that import the same
//! image get the same id; two builds that differ in one byte do not, and the
//! digest does not pretend to make a build reproducible.
//!
//! The encoding is length-prefixed so a path containing a space or a newline
//! cannot be confused with the field after it.
//!
//! # Trees do not sync
//!
//! A Sage environment is gigabytes. Its name, digest and manifest are ops and
//! blobs like anything else and sync with the space; the tree itself stays on
//! the machine that imported or built it. A peer that wants to run in it
//! imports or builds the same image and gets — or fails to get — the same
//! digest, which is the check that matters.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use sha2::{Digest as _, Sha256};

use super::op::{self, Body, EntryRef};
use super::state::State;
use super::store::Lab;
use super::LabError;
use crate::canonical::Value;
use crate::crypto::identity::Identity;

/// A tree digest, with what it counted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tree {
    pub digest: String,
    pub files: u64,
    pub bytes: u64,
}

/// Digest a directory tree. See the module docs for what it covers.
pub fn tree_digest(root: &Path) -> Result<Tree, LabError> {
    let mut hasher = Sha256::new();
    hasher.update(b"cairn/lab/tree/v1\n");
    let mut files = 0u64;
    let mut bytes = 0u64;
    walk(root, root, &mut |relative, path, meta| {
        let kind;
        let mut content = String::new();
        let mut size = 0u64;
        let file_type = meta.file_type();
        if file_type.is_symlink() {
            kind = "l";
            content = fs::read_link(path)?.to_string_lossy().into_owned();
        } else if file_type.is_dir() {
            kind = "d";
        } else if file_type.is_file() {
            kind = "f";
            size = meta.len();
            content = file_sha256(path)?;
            files += 1;
            bytes = bytes.saturating_add(size);
        } else {
            // Device nodes, sockets and fifos: recorded by name and kind so
            // their presence is part of the identity, never read.
            kind = "o";
        }
        let mode = permission_bits(meta);
        hasher.update(
            format!(
                "{kind} {mode:o} {size} {}:{relative} {}:{content}\n",
                relative.len(),
                content.len()
            )
            .as_bytes(),
        );
        Ok(())
    })?;
    Ok(Tree {
        digest: format!(
            "{}{}",
            crate::canonical::DIGEST_PREFIX,
            crate::hex::encode(&hasher.finalize())
        ),
        files,
        bytes,
    })
}

#[cfg(unix)]
fn permission_bits(meta: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    meta.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
fn permission_bits(meta: &fs::Metadata) -> u32 {
    if meta.permissions().readonly() {
        0o444
    } else {
        0o644
    }
}

fn file_sha256(path: &Path) -> Result<String, LabError> {
    let mut file =
        fs::File::open(path).map_err(|e| LabError::Io(format!("{}: {e}", path.display())))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 20];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|e| LabError::Io(format!("{}: {e}", path.display())))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(crate::hex::encode(&hasher.finalize()))
}

/// Visit every entry under `dir` in byte order of its relative path, without
/// following symlinks.
fn walk(
    root: &Path,
    dir: &Path,
    visit: &mut dyn FnMut(&str, &Path, &fs::Metadata) -> Result<(), LabError>,
) -> Result<(), LabError> {
    let mut entries: Vec<(String, PathBuf)> = fs::read_dir(dir)
        .map_err(|e| LabError::Io(format!("{}: {e}", dir.display())))?
        .filter_map(Result::ok)
        .map(|entry| {
            (
                entry.file_name().to_string_lossy().into_owned(),
                entry.path(),
            )
        })
        .collect();
    entries.sort();
    for (_, path) in entries {
        let meta = fs::symlink_metadata(&path)
            .map_err(|e| LabError::Io(format!("{}: {e}", path.display())))?;
        let relative = path
            .strip_prefix(root)
            .map_err(|_| LabError::Io("walked outside the tree".into()))?
            .to_string_lossy()
            .into_owned();
        visit(&relative, &path, &meta)?;
        if meta.file_type().is_dir() {
            walk(root, &path, visit)?;
        }
    }
    Ok(())
}

/// Where an environment's tree lives on this machine, by digest.
pub fn rootfs_path(lab: &Lab, tree: &str) -> Result<PathBuf, LabError> {
    let tree = op::digest(tree)?;
    let hex = &tree[crate::canonical::DIGEST_PREFIX.len()..];
    Ok(lab.envs_dir().join(hex).join("rootfs"))
}

/// Where an import comes from.
#[derive(Debug, Clone)]
pub enum Source {
    /// A directory, copied.
    Dir(PathBuf),
    /// A tarball of a root filesystem (`docker export` writes one), extracted.
    Tar(PathBuf),
    /// A local container image, exported through `docker` (or `podman`).
    Image { engine: String, image: String },
}

/// What an import is told besides its source.
#[derive(Debug, Clone, Default)]
pub struct ImportOptions {
    /// Environment variables every run in it starts with, e.g. a `PATH` that
    /// includes `/opt/conda-sage/envs/sage/bin`. Merged over what an image
    /// declares.
    pub env: BTreeMap<String, String>,
    /// Working directory a run starts in unless told otherwise.
    pub workdir: Option<String>,
    /// Free text recorded in the manifest.
    pub note: Option<String>,
}

/// An environment as the space names it, resolved on this machine.
#[derive(Debug, Clone)]
pub struct Resolved {
    pub name: String,
    pub tree: String,
    pub rootfs: PathBuf,
    pub manifest: Value,
}

impl Resolved {
    /// The environment variables the manifest declares.
    pub fn env(&self) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        if let Some(Value::Object(map)) = self.manifest.get("env") {
            for (key, value) in map {
                if let Some(text) = value.as_str() {
                    out.insert(key.clone(), text.to_string());
                }
            }
        }
        out
    }

    pub fn workdir(&self) -> Option<String> {
        self.manifest
            .get("workdir")
            .and_then(Value::as_str)
            .map(str::to_string)
    }
}

/// Import an environment: materialise the tree, digest it, move it under its
/// digest, and name it in the space.
pub fn import(
    lab: &mut Lab,
    identity: &Identity,
    name: &str,
    source: &Source,
    options: &ImportOptions,
) -> Result<(Resolved, op::Op), LabError> {
    let staging = lab.envs_dir().join(format!(
        "tmp-{}-{}",
        std::process::id(),
        crate::time::unix_seconds()
    ));
    let _ = fs::remove_dir_all(&staging);
    let rootfs = staging.join("rootfs");
    fs::create_dir_all(&rootfs)?;
    let result = materialise(source, &rootfs);
    let (source_record, image_env, image_workdir) = match result {
        Ok(found) => found,
        Err(e) => {
            let _ = fs::remove_dir_all(&staging);
            return Err(e);
        }
    };
    let tree = tree_digest(&rootfs)?;
    let dest = rootfs_path(lab, &tree.digest)?;
    if dest.exists() {
        let _ = fs::remove_dir_all(&staging);
    } else {
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::rename(&rootfs, &dest)?;
        let _ = fs::remove_dir_all(&staging);
    }

    let mut env = image_env;
    env.extend(options.env.clone());
    let mut pairs: Vec<(&str, Value)> = vec![
        ("type", Value::string("cairn.lab.env")),
        ("name", Value::string(name)),
        ("tree", Value::string(&tree.digest)),
        ("files", Value::Int(i128::from(tree.files))),
        ("bytes", Value::Int(i128::from(tree.bytes))),
        ("source", source_record),
        ("imported_at", Value::string(crate::time::timestamp())),
        ("arch", Value::string(std::env::consts::ARCH)),
    ];
    if !env.is_empty() {
        pairs.push((
            "env",
            Value::Object(
                env.iter()
                    .map(|(k, v)| (k.clone(), Value::string(v)))
                    .collect(),
            ),
        ));
    }
    if let Some(workdir) = options.workdir.clone().or(image_workdir) {
        pairs.push(("workdir", Value::string(workdir)));
    }
    if let Some(note) = &options.note {
        pairs.push(("note", Value::string(note)));
    }
    let manifest = Value::object(pairs);
    let manifest_blob = lab
        .blobs()
        .put_bytes(manifest.canonical_string().as_bytes())?;
    fs::write(
        dest.parent()
            .ok_or_else(|| LabError::Io("environment path has no parent".into()))?
            .join("manifest.json"),
        manifest.canonical_string(),
    )?;

    let state = State::of(lab);
    let pred: Vec<EntryRef> = state
        .envs
        .get(name)
        .map(|values| values.iter().map(|v| v.version.entry.clone()).collect())
        .unwrap_or_default();
    let op = lab.append(
        identity,
        Body::Env {
            name: name.to_string(),
            tree: tree.digest.clone(),
            manifest: manifest_blob,
            pred,
        },
    )?;
    Ok((
        Resolved {
            name: name.to_string(),
            tree: tree.digest,
            rootfs: dest,
            manifest,
        },
        op,
    ))
}

/// What filling a root filesystem learned about its source: a record of it,
/// and the environment variables and working directory an image declares.
type Materialised = (Value, BTreeMap<String, String>, Option<String>);

/// Fill `rootfs` from `source`.
fn materialise(source: &Source, rootfs: &Path) -> Result<Materialised, LabError> {
    match source {
        Source::Dir(dir) => {
            // `cp -a` rather than a copy loop here: it keeps symlinks as links
            // and modes as modes, which is the part of a root filesystem that
            // is easy to get subtly wrong by hand.
            run_tool(
                Command::new("cp")
                    .arg("-a")
                    .arg(format!("{}/.", dir.display()))
                    .arg(rootfs),
                "cp",
            )?;
            Ok((
                Value::object([
                    ("kind", Value::string("dir")),
                    ("path", Value::string(dir.display().to_string())),
                ]),
                BTreeMap::new(),
                None,
            ))
        }
        Source::Tar(tar) => {
            extract_tar(tar, rootfs)?;
            let digest = file_sha256(tar)?;
            Ok((
                Value::object([
                    ("kind", Value::string("tar")),
                    ("path", Value::string(tar.display().to_string())),
                    ("sha256", Value::string(digest)),
                ]),
                BTreeMap::new(),
                None,
            ))
        }
        Source::Image { engine, image } => {
            let inspect = Command::new(engine)
                .args([
                    "image",
                    "inspect",
                    "--format",
                    "{{json .Id}}\t{{json .RepoDigests}}\t{{json .Config.Env}}\t{{json .Config.WorkingDir}}",
                    image,
                ])
                .output()
                .map_err(|e| LabError::Io(format!("{engine} image inspect: {e}")))?;
            if !inspect.status.success() {
                return Err(LabError::NotFound(format!(
                    "{engine} has no image {image:?}: {}",
                    String::from_utf8_lossy(&inspect.stderr).trim()
                )));
            }
            let text = String::from_utf8_lossy(&inspect.stdout).into_owned();
            let mut parts = text.trim().splitn(4, '\t');
            let image_id = parts
                .next()
                .and_then(|p| serde_json::from_str::<String>(p).ok())
                .unwrap_or_default();
            let repo_digests: Vec<String> = parts
                .next()
                .and_then(|p| serde_json::from_str(p).ok())
                .unwrap_or_default();
            let env_list: Vec<String> = parts
                .next()
                .and_then(|p| serde_json::from_str(p).ok())
                .unwrap_or_default();
            let workdir: String = parts
                .next()
                .and_then(|p| serde_json::from_str(p).ok())
                .unwrap_or_default();
            let mut env = BTreeMap::new();
            for pair in env_list {
                if let Some((key, value)) = pair.split_once('=') {
                    env.insert(key.to_string(), value.to_string());
                }
            }

            let created = Command::new(engine)
                .args(["create", image, "/bin/true"])
                .output()
                .map_err(|e| LabError::Io(format!("{engine} create: {e}")))?;
            if !created.status.success() {
                return Err(LabError::Io(format!(
                    "{engine} create {image}: {}",
                    String::from_utf8_lossy(&created.stderr).trim()
                )));
            }
            let container = String::from_utf8_lossy(&created.stdout).trim().to_string();
            let exported = export_container(engine, &container, rootfs);
            let _ = Command::new(engine)
                .args(["rm", &container])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            exported?;
            Ok((
                Value::object([
                    ("kind", Value::string("image")),
                    ("engine", Value::string(engine)),
                    ("image", Value::string(image)),
                    ("image_id", Value::string(image_id)),
                    (
                        "repo_digests",
                        Value::array(repo_digests.into_iter().map(Value::string)),
                    ),
                ]),
                env,
                (!workdir.is_empty()).then_some(workdir),
            ))
        }
    }
}

fn export_container(engine: &str, container: &str, rootfs: &Path) -> Result<(), LabError> {
    let mut export = Command::new(engine)
        .args(["export", container])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| LabError::Io(format!("{engine} export: {e}")))?;
    let stdout = export
        .stdout
        .take()
        .ok_or_else(|| LabError::Io(format!("{engine} export produced no stream")))?;
    let tar = Command::new("tar")
        .args(["-x", "-f", "-", "-C"])
        .arg(rootfs)
        .stdin(stdout)
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| LabError::Io(format!("tar: {e}")))?;
    let status = export
        .wait()
        .map_err(|e| LabError::Io(format!("{engine} export: {e}")))?;
    if !status.success() {
        return Err(LabError::Io(format!("{engine} export {container} failed")));
    }
    if !tar.status.success() {
        return Err(LabError::Io(format!(
            "tar: {}",
            String::from_utf8_lossy(&tar.stderr).trim()
        )));
    }
    Ok(())
}

fn extract_tar(tar: &Path, rootfs: &Path) -> Result<(), LabError> {
    run_tool(
        Command::new("tar")
            .args(["-x", "-f"])
            .arg(tar)
            .arg("-C")
            .arg(rootfs),
        "tar",
    )
}

fn run_tool(command: &mut Command, name: &str) -> Result<(), LabError> {
    let output = command
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| LabError::Io(format!("{name}: {e}")))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(LabError::Io(format!(
            "{name}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

/// Resolve a name (or a tree digest) to an environment on this machine.
///
/// A name the space binds to more than one tree is a conflict and is refused:
/// running under an environment picked by a tie-break would make the receipt
/// name one tree while another was meant.
pub fn resolve(lab: &Lab, state: &State, wanted: &str) -> Result<Resolved, LabError> {
    let (name, tree, manifest_blob) = if let Some(values) = state.envs.get(wanted) {
        let distinct: std::collections::BTreeSet<&String> =
            values.iter().map(|v| &v.tree).collect();
        if distinct.len() > 1 {
            return Err(LabError::Refused(format!(
                "environment {wanted:?} names {} different trees; resolve it with \
                 `cairn lab env import` before running in it",
                distinct.len()
            )));
        }
        let value = &values[0];
        (
            wanted.to_string(),
            value.tree.clone(),
            Some(value.manifest.clone()),
        )
    } else if op::digest(wanted).is_ok() {
        let named = state
            .envs
            .iter()
            .find(|(_, values)| values.iter().any(|v| v.tree == wanted));
        match named {
            Some((name, values)) => (
                name.clone(),
                wanted.to_string(),
                values
                    .iter()
                    .find(|v| v.tree == wanted)
                    .map(|v| v.manifest.clone()),
            ),
            None => (wanted.to_string(), wanted.to_string(), None),
        }
    } else {
        return Err(LabError::NotFound(format!(
            "no environment named {wanted:?}; `cairn lab env ls` lists them"
        )));
    };
    let rootfs = rootfs_path(lab, &tree)?;
    if !rootfs.is_dir() {
        return Err(LabError::NotFound(format!(
            "environment {name:?} ({}) is named in the space but its root filesystem is \
             not on this machine; import or build the same image here \
             (`cairn lab env import {name} --docker IMAGE`)",
            crate::canonical::short(&tree)
        )));
    }
    let manifest = match manifest_blob.and_then(|blob| lab.blobs().read(&blob).ok()) {
        Some(bytes) => Value::from_json(&String::from_utf8_lossy(&bytes))
            .unwrap_or_else(|_| Value::object(Vec::<(&str, Value)>::new())),
        None => fs::read_to_string(rootfs.with_file_name("manifest.json"))
            .ok()
            .and_then(|text| Value::from_json(&text).ok())
            .unwrap_or_else(|| Value::object(Vec::<(&str, Value)>::new())),
    };
    Ok(Resolved {
        name,
        tree,
        rootfs,
        manifest,
    })
}

/// Re-digest an environment's tree on this machine and compare it with its
/// name. What `cairn lab env verify` runs: a tree edited in place would
/// otherwise run under a digest it no longer has.
pub fn verify(lab: &Lab, tree: &str) -> Result<bool, LabError> {
    let rootfs = rootfs_path(lab, tree)?;
    Ok(tree_digest(&rootfs)?.digest == tree)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "cairn-lab-env-{name}-{}-{}",
            std::process::id(),
            crate::time::unix_seconds()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("mkdir");
        dir
    }

    #[test]
    fn the_tree_digest_covers_content_modes_and_links_but_not_timestamps() {
        let a = temp("a");
        fs::create_dir_all(a.join("usr/bin")).expect("mkdir");
        fs::write(a.join("usr/bin/tool"), b"#!/bin/sh\necho hi\n").expect("write");
        #[cfg(unix)]
        std::os::unix::fs::symlink("usr/bin", a.join("bin")).expect("link");
        let first = tree_digest(&a).expect("digest");
        assert_eq!(first.files, 1);

        // Same content written again: a new mtime, the same identity.
        std::thread::sleep(std::time::Duration::from_millis(20));
        fs::write(a.join("usr/bin/tool"), b"#!/bin/sh\necho hi\n").expect("rewrite");
        assert_eq!(tree_digest(&a).expect("digest").digest, first.digest);

        // One byte different: a different identity.
        fs::write(a.join("usr/bin/tool"), b"#!/bin/sh\necho ho\n").expect("edit");
        let edited = tree_digest(&a).expect("digest");
        assert_ne!(edited.digest, first.digest);

        // A mode change is a different identity too: an executable bit decides
        // whether a program runs at all.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(a.join("usr/bin/tool"), fs::Permissions::from_mode(0o755))
                .expect("chmod");
            assert_ne!(tree_digest(&a).expect("digest").digest, edited.digest);
        }
        let _ = fs::remove_dir_all(&a);
    }

    #[test]
    fn a_name_with_a_space_cannot_impersonate_the_next_field() {
        let a = temp("spaces-a");
        let b = temp("spaces-b");
        fs::write(a.join("x 1"), b"").expect("write");
        fs::write(b.join("x"), b"").expect("write");
        fs::write(b.join("1"), b"").expect("write");
        assert_ne!(
            tree_digest(&a).expect("a").digest,
            tree_digest(&b).expect("b").digest
        );
        let _ = fs::remove_dir_all(&a);
        let _ = fs::remove_dir_all(&b);
    }
}
