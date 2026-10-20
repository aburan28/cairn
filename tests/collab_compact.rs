use std::collections::BTreeSet;
use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};

use cairn::crypto::identity::Identity;
use cairn::lab::collab::{self, compact, Edit, Graph};
use cairn::lab::op::{Body, Member, Policy, Role};
use cairn::lab::{api, state::State, store::Lab};

struct Temp(std::path::PathBuf);
impl Temp {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "cairn-compaction-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn one(id: &str) -> BTreeSet<String> {
    [id.to_string()].into_iter().collect()
}
fn setup(dir: &Temp) -> (Lab, Identity, Identity, String) {
    let owner = Identity::from_secret_bytes([1; 32]);
    let writer = Identity::from_secret_bytes([2; 32]);
    let mut lab = Lab::init(
        &dir.0.join("source"),
        &owner,
        "Research",
        vec![Member {
            key: writer.submitter_id(),
            roles: [Role::Writer].into_iter().collect(),
            peers: BTreeSet::new(),
        }],
        Policy {
            write_once: vec!["checkpoints/**".into()],
            ..Policy::default()
        },
    )
    .unwrap();
    let ws = collab::create(&mut lab, &owner, "Algorithm", &BTreeSet::new(), "create").unwrap();
    let initial = collab::edit(
        &mut lab,
        &writer,
        &ws,
        &one(&ws),
        &[Edit::splice("algorithm.py", 0, 0, "a🦀éz")],
        "seed",
    )
    .unwrap();
    collab::edit(
        &mut lab,
        &writer,
        &ws,
        &one(&initial),
        &[Edit::splice("algorithm.py", 1, 2, "λ")],
        "edit",
    )
    .unwrap();
    (lab, owner, writer, ws)
}

#[test]
fn rollover_resets_active_history_and_recovers_original_signatures_and_blobs() {
    let dir = Temp::new();
    let (mut source, owner, writer, ws) = setup(&dir);
    let read = Graph::load(&source).unwrap().snapshot(&ws, None).unwrap();
    let checkpoint = collab::checkpoint(&mut source, &owner, &ws, &read.heads).unwrap();
    let original_ops = source.ops().to_vec();
    let result =
        compact::rollover(&mut source, &owner, &ws, &read.heads, &dir.0.join("next")).unwrap();
    assert_eq!(source.ops(), original_ops);
    let next = Lab::open(&dir.0.join("next")).unwrap();
    assert_ne!(next.space(), source.space());
    assert!(!next.root().join("ROLLOVER_INCOMPLETE").exists());
    let graph = Graph::load(&next).unwrap();
    let active = graph
        .snapshot(result["workspace"].as_str().unwrap(), None)
        .unwrap();
    assert_eq!(active.files, read.files);
    assert_eq!(
        graph
            .feed(&active.workspace, &BTreeSet::new(), 256)
            .unwrap()["changes"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert!(State::of(&next)
        .roster
        .has(&writer.submitter_id(), Role::Writer));
    assert!(!State::of(&next)
        .roster
        .has(&writer.submitter_id(), Role::Admin));
    compact::recover(&next, &dir.0.join("recovered")).unwrap();
    let recovered = Lab::open(&dir.0.join("recovered")).unwrap();
    assert_eq!(recovered.ops(), source.ops());
    let restored = Graph::load(&recovered)
        .unwrap()
        .snapshot(&ws, Some(&read.heads))
        .unwrap();
    assert_eq!(restored, read);
    let input = checkpoint["inputs"][0]["prefix"].as_str().unwrap();
    assert_eq!(
        api::read_file(&recovered, &State::of(&recovered), input).unwrap(),
        "aλz".as_bytes()
    );
    assert!(recovered
        .ops()
        .iter()
        .any(|op| op.author == writer.submitter_id() && matches!(op.body, Body::Doc { .. })));
}

#[test]
fn late_offline_work_stays_recoverable_without_rewriting_new_generation() {
    let dir = Temp::new();
    let (mut source, owner, writer, ws) = setup(&dir);
    let read = Graph::load(&source).unwrap().snapshot(&ws, None).unwrap();
    let result =
        compact::rollover(&mut source, &owner, &ws, &read.heads, &dir.0.join("next")).unwrap();
    collab::edit(
        &mut source,
        &writer,
        &ws,
        &read.heads,
        &[Edit::splice("algorithm.py", 3, 0, " offline")],
        "late",
    )
    .unwrap();
    let next = Lab::open(&dir.0.join("next")).unwrap();
    compact::recover(&next, &dir.0.join("recovered")).unwrap();
    let mut recovered = Lab::open(&dir.0.join("recovered")).unwrap();
    let (_, refused) = recovered.ingest_many(source.ops().to_vec()).unwrap();
    assert!(refused.is_empty());
    assert_eq!(
        Graph::load(&recovered)
            .unwrap()
            .snapshot(&ws, None)
            .unwrap()
            .files["algorithm.py"]
            .text,
        "aλz offline"
    );
    assert_eq!(
        Graph::load(&next)
            .unwrap()
            .snapshot(result["workspace"].as_str().unwrap(), None)
            .unwrap()
            .files["algorithm.py"]
            .text,
        "aλz"
    );
}

#[test]
fn rollover_refuses_privilege_escalation_existing_destinations_and_missing_bytes() {
    let dir = Temp::new();
    let (mut source, owner, writer, ws) = setup(&dir);
    let read = Graph::load(&source).unwrap().snapshot(&ws, None).unwrap();
    assert!(compact::rollover(
        &mut source,
        &writer,
        &ws,
        &read.heads,
        &dir.0.join("unauthorized")
    )
    .is_err());
    assert!(!dir.0.join("unauthorized").exists());
    let existing = dir.0.join("existing");
    fs::create_dir(&existing).unwrap();
    fs::write(existing.join("mine"), b"keep").unwrap();
    assert!(compact::rollover(&mut source, &owner, &ws, &read.heads, &existing).is_err());
    assert_eq!(fs::read(existing.join("mine")).unwrap(), b"keep");
    let checkpoint = collab::checkpoint(&mut source, &owner, &ws, &read.heads).unwrap();
    let state = State::of(&source);
    let blob = state.files[checkpoint["manifest"].as_str().unwrap()][0]
        .blob
        .as_ref()
        .unwrap();
    fs::remove_file(source.blobs().path(blob).unwrap()).unwrap();
    assert!(compact::rollover(
        &mut source,
        &owner,
        &ws,
        &read.heads,
        &dir.0.join("missing")
    )
    .is_err());
    assert!(!dir.0.join("missing").exists());
}

#[test]
fn conflicted_sources_are_never_compacted_into_an_apparently_clean_snapshot() {
    let dir = Temp::new();
    let (mut source, owner, writer, ws) = setup(&dir);
    let read = Graph::load(&source).unwrap().snapshot(&ws, None).unwrap();
    collab::edit(
        &mut source,
        &owner,
        &ws,
        &read.heads,
        &[Edit::splice("algorithm.py", 0, 1, "X")],
        "first",
    )
    .unwrap();
    collab::edit(
        &mut source,
        &writer,
        &ws,
        &read.heads,
        &[Edit::splice("algorithm.py", 0, 1, "Y")],
        "second",
    )
    .unwrap();
    let now = Graph::load(&source).unwrap().snapshot(&ws, None).unwrap();
    assert!(!now.conflicts.is_empty());
    assert!(compact::rollover(
        &mut source,
        &owner,
        &ws,
        &now.heads,
        &dir.0.join("conflicted")
    )
    .is_err());
    assert!(!dir.0.join("conflicted").exists());
}
