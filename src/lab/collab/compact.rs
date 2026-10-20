//! Generation rollover, rather than unsafe deletion of RGA anchors. The old
//! signed history stays replayable in a content-addressed bundle and offline
//! agents keep writing to the old space until deliberately moved to the new one.

use std::collections::BTreeSet;
use std::fs;
use std::io::Write as _;
use std::path::Path;

use serde_json::{json, Value as Json};

use super::{create, edit, request_id, Edit, Graph, Snapshot, MAX_EDITS};
use crate::crypto::identity::Identity;
use crate::lab::op::{Body, FileEntry, Member, Policy, Role};
use crate::lab::{state::State, store::Lab, sync, LabError};

const MANIFEST: &str = "archives/generation.json";
const BUNDLE: &str = "archives/source.bundle";

/// Compact one pinned workspace into a NEW space with a fresh character graph.
/// Other workspaces, prior receipts and original authors remain in the archive;
/// nothing is deleted from the source. Requires a current administrator who
/// is also a writer, and retains the current roster without widening roles.
pub fn rollover(
    source: &mut Lab,
    who: &Identity,
    workspace: &str,
    heads: &BTreeSet<String>,
    destination: &Path,
) -> Result<Json, LabError> {
    source.refresh()?;
    let state = State::of(source);
    let me = who.submitter_id();
    if !state.roster.has(&me, Role::Admin) || !state.roster.has(&me, Role::Writer) {
        return Err(LabError::Refused(
            "generation rollover requires a current administrator and writer".into(),
        ));
    }
    let graph = Graph::load(source)?;
    let snapshot = graph.snapshot(workspace, Some(heads))?;
    snapshot.require_clear()?;
    // Missing referenced bytes must not become an apparently complete archive.
    // Opening the source has already reverified every op signature.
    let mut blobs = BTreeSet::new();
    for op in source.ops() {
        for entry in op.body.file_entries() {
            if let Some(blob) = &entry.blob {
                blobs.insert(blob.clone());
            }
        }
        match &op.body {
            Body::Env { manifest, .. } => {
                blobs.insert(manifest.clone());
            }
            Body::Run { receipt, .. } => {
                for key in ["stdout", "stderr"] {
                    if let Some(blob) = receipt.get(key).and_then(crate::canonical::Value::as_str) {
                        blobs.insert(blob.into());
                    }
                }
            }
            _ => {}
        }
    }
    for blob in blobs {
        if !source.blobs().verify(&blob).unwrap_or(false) {
            return Err(LabError::Unavailable(format!(
                "restore missing or damaged archive input {blob} before compacting"
            )));
        }
    }
    // create_dir is exclusive, including dangling symlinks. On error the new
    // directory is kept marked incomplete for inspection; never remove a path
    // another actor might have populated, and never overwrite a user's target.
    fs::create_dir(destination).map_err(|e| {
        LabError::Io(format!(
            "create a NEW generation directory {}: {e}",
            destination.display()
        ))
    })?;
    let marker = destination.join("ROLLOVER_INCOMPLETE");
    fs::write(&marker, b"Do not sync this generation until archives/generation.json is present and rollover completes. The source lab was not changed.\n")?;
    let members = state
        .roster
        .members
        .iter()
        .map(|(key, standing)| Member {
            key: key.clone(),
            roles: standing.roles.clone(),
            peers: standing.peers.clone(),
        })
        .collect();
    let mut next = Lab::init(
        destination,
        who,
        &format!("{} · compacted", state.name),
        members,
        Policy {
            write_once: vec!["**".into()],
            ..Policy::default()
        },
    )?;
    let archive_file = destination.join("source.bundle.tmp");
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&archive_file)?;
    let (ops, blobs) = sync::write_bundle(source, &mut output, None)?;
    output.flush()?;
    output.sync_all()?;
    drop(output);
    let (bundle, size) = next.blobs().put_file(&archive_file)?;
    fs::remove_file(&archive_file)?;
    let lane = create(
        &mut next,
        who,
        "Compacted workspace",
        &BTreeSet::new(),
        &request_id()?,
    )?;
    let mut current = [lane.clone()].into_iter().collect();
    let edits: Vec<_> = snapshot
        .files
        .iter()
        .map(|(path, file)| Edit {
            path: path.clone(),
            start: 0,
            delete: 0,
            insert: file.text.clone(),
            executable: Some(file.executable),
            remove: false,
        })
        .collect();
    for chunk in edits.chunks(MAX_EDITS) {
        let id = edit(&mut next, who, &lane, &current, chunk, &request_id()?)?;
        current = [id].into_iter().collect();
    }
    let baseline = Graph::load(&next)?.snapshot(&lane, Some(&current))?;
    if baseline.files != snapshot.files {
        return Err(LabError::Corrupt(
            "compacted files differ from the source snapshot".into(),
        ));
    }
    let manifest = json!({"type":"cairn.collab.generation","version":1,
        "source":snapshot.to_json(false),"source_lab_heads":source.heads(),
        "archive":{"blob":bundle,"size":size,"ops":ops,"blobs":blobs,"path":BUNDLE},
        "baseline":baseline.to_json(false),"relay_author":me,
        "note":"Original signatures and author history are in the archive. This baseline is an administrator-signed import, not re-authorship or an execution proof. Old-space updates require explicit recovery and integration."});
    let manifest_bytes = manifest.to_string().into_bytes();
    if manifest_bytes.len() > 8 * 1024 * 1024 {
        return Err(LabError::Unavailable("generation manifest exceeds the recovery limit; the incomplete destination is retained and the source is unchanged".into()));
    }
    let manifest_blob = next.blobs().put_bytes(&manifest_bytes)?;
    let published = next.append(
        who,
        Body::Files {
            entries: vec![
                FileEntry {
                    path: BUNDLE.into(),
                    blob: Some(bundle),
                    size,
                    exec: false,
                    pred: Vec::new(),
                },
                FileEntry {
                    path: MANIFEST.into(),
                    blob: Some(manifest_blob),
                    size: manifest_bytes.len() as u64,
                    exec: false,
                    pred: Vec::new(),
                },
            ],
        },
    )?;
    fs::remove_file(marker)?;
    Ok(
        json!({"directory":destination,"space":next.space(),"workspace":lane,"heads":current,
        "revision":baseline.revision,"archive_op":published.id,"manifest":manifest}),
    )
}

/// Recover an archived source into a NEW replica. Bundle parsing verifies every
/// original signature and referenced blob hash. The recovered source is for
/// receiving late old-space work or replaying old receipts, not for ingesting
/// old-space ops into a new generation.
pub fn recover(generation: &Lab, destination: &Path) -> Result<Json, LabError> {
    let state = State::of(generation);
    if state
        .files
        .get(MANIFEST)
        .is_none_or(|values| values.len() != 1 || values[0].size > 8 * 1024 * 1024)
    {
        return Err(LabError::Refused(
            "generation manifest is missing, conflicting or oversized".into(),
        ));
    }
    let bytes = crate::lab::api::read_file(generation, &state, MANIFEST)?;
    let manifest: Json =
        serde_json::from_slice(&bytes).map_err(|e| LabError::Corrupt(e.to_string()))?;
    if manifest["type"] != "cairn.collab.generation" || manifest["version"] != 1 {
        return Err(LabError::Corrupt("unknown generation manifest".into()));
    }
    let author = generation
        .ops()
        .first()
        .ok_or_else(|| LabError::Corrupt("missing genesis".into()))?
        .author
        .as_str();
    // A writer may publish a similarly named file; only the generation
    // founder's immutable publication establishes the archive provenance.
    for path in [MANIFEST, BUNDLE] {
        let values = state
            .files
            .get(path)
            .ok_or_else(|| LabError::NotFound(path.into()))?;
        if values.len() != 1 || values[0].version.author != author {
            return Err(LabError::Refused(
                "generation archive needs one founder-signed publication".into(),
            ));
        }
    }
    let space = manifest["source"]["space"]
        .as_str()
        .ok_or_else(|| LabError::Corrupt("missing source space".into()))?;
    let blob = manifest["archive"]["blob"]
        .as_str()
        .ok_or_else(|| LabError::Corrupt("missing bundle address".into()))?;
    let registered = state.files[BUNDLE][0].blob.as_deref();
    if registered != Some(blob) || !generation.blobs().verify(blob)? {
        return Err(LabError::Corrupt(
            "archive bytes do not match the manifest".into(),
        ));
    }
    fs::create_dir(destination)?;
    Lab::create_empty(destination, space)?;
    let mut recovered = Lab::open(destination)?;
    let report = sync::read_bundle(&mut recovered, &mut generation.blobs().open(blob)?)?;
    if !report.ops_refused.is_empty()
        || recovered.heads() != &super::model::heads(&manifest["source_lab_heads"])?
    {
        return Err(LabError::Corrupt(
            "archive does not reproduce the signed source history".into(),
        ));
    }
    let source: Snapshot = {
        let workspace = manifest["source"]["workspace"]
            .as_str()
            .ok_or_else(|| LabError::Corrupt("missing archived workspace".into()))?;
        let heads = super::model::heads(&manifest["source"]["heads"])?;
        Graph::load(&recovered)?.snapshot(workspace, Some(&heads))?
    };
    if source.to_json(false) != manifest["source"] {
        return Err(LabError::Corrupt(
            "archive does not reproduce the pinned source".into(),
        ));
    }
    Ok(
        json!({"space":recovered.space(),"directory":destination,"source":source.to_json(false),"report":format!("{report:?}")}),
    )
}
