//! The collaboration protocol's laws, exercised through actual signed replicas.
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use cairn::crypto::identity::Identity;
use cairn::lab::collab::{self, Edit, Graph, Snapshot};
use cairn::lab::op::{Body, Field, Member, Policy, Role};
use cairn::lab::state::State;
use cairn::lab::store::Lab;
use cairn::lab::sync;
use cairn::lab::LabError;
use serde_json::{json, Value as Json};

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "cairn-collab-{}-{}",
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
fn identity(seed: u8) -> Identity {
    Identity::from_secret_bytes([seed; 32])
}
fn one(id: &str) -> BTreeSet<String> {
    [id.to_string()].into_iter().collect()
}
fn space(dir: &Temp, people: &[Identity]) -> Lab {
    let members = people
        .iter()
        .skip(1)
        .map(|p| Member {
            key: p.submitter_id(),
            roles: [Role::Writer].into_iter().collect(),
            peers: BTreeSet::new(),
        })
        .collect();
    Lab::init(
        &dir.0.join("lab"),
        &people[0],
        "live",
        members,
        Policy {
            write_once: vec!["checkpoints/**".into()],
            ..Policy::default()
        },
    )
    .unwrap()
}
fn replica(dir: &Temp, lab: &Lab) -> Lab {
    let root = dir.0.join("lab");
    Lab::create_empty(&root, lab.space()).unwrap();
    let mut copy = Lab::open(&root).unwrap();
    let (_, refused) = copy.ingest_many(lab.ops().to_vec()).unwrap();
    assert!(refused.is_empty(), "{refused:?}");
    copy
}
fn snapshot(lab: &Lab, ws: &str) -> Snapshot {
    Graph::load(lab).unwrap().snapshot(ws, None).unwrap()
}
macro_rules! edit {
    ($lab:expr, $who:expr, $ws:expr, $base:expr, $path:expr, $start:expr, $delete:expr, $insert:expr, $request:expr $(,)?) => {
        collab::edit(
            $lab,
            $who,
            $ws,
            $base,
            &[Edit::splice($path, $start, $delete, $insert)],
            $request,
        )
        .unwrap()
    };
}

fn workspace(lab: &mut Lab, who: &Identity) -> String {
    collab::create(lab, who, "shared", &BTreeSet::new(), "create").unwrap()
}

#[test]
fn unicode_positions_are_pinned_and_retries_do_not_duplicate_a_change() {
    let dir = Temp::new();
    let people = [identity(1)];
    let mut lab = space(&dir, &people);
    let who = &people[0];
    let ws = workspace(&mut lab, who);
    // Independently encoded with Python json.dumps(sort_keys=True,
    // ensure_ascii=False, separators=(',', ':')) and hashlib.sha256. This
    // versioned payload identity must not drift with an outer op's timestamp.
    assert_eq!(
        ws,
        "sha256:a245c2246efbb64e78ae5ff04df1e7bede964a80f26e89202f1fc71a6be5dcb4"
    );
    let first = edit!(
        &mut lab,
        who,
        &ws,
        &one(&ws),
        "algorithm.rs",
        0,
        0,
        "a🦀éz",
        "initial",
    );
    let second = edit!(
        &mut lab,
        who,
        &ws,
        &one(&first),
        "algorithm.rs",
        1,
        2,
        "λ",
        "replace",
    );
    assert_eq!(snapshot(&lab, &ws).files["algorithm.rs"].text, "aλz");
    let count = lab.len();
    assert_eq!(
        edit!(
            &mut lab,
            who,
            &ws,
            &one(&first),
            "algorithm.rs",
            1,
            2,
            "λ",
            "replace"
        ),
        second
    );
    assert_eq!(lab.len(), count);
    let error = collab::edit(
        &mut lab,
        who,
        &ws,
        &one(&first),
        &[Edit::splice("algorithm.rs", 1, 2, "different")],
        "replace",
    )
    .unwrap_err();
    assert!(matches!(error, LabError::Refused(_)));
    let error = collab::edit(
        &mut lab,
        who,
        &ws,
        &one(&second),
        &[Edit::splice("algorithm.rs", 4, 0, "!")],
        "out-of-bounds",
    )
    .unwrap_err();
    assert!(matches!(error, LabError::Invalid(_)));
    assert_eq!(lab.len(), count);
    assert_eq!(
        Graph::load(&lab)
            .unwrap()
            .snapshot(&ws, Some(&one(&first)))
            .unwrap()
            .files["algorithm.rs"]
            .text,
        "a🦀éz"
    );
    let reopened = Lab::open(lab.root()).unwrap();
    assert_eq!(snapshot(&lab, &ws), snapshot(&reopened, &ws));
}

#[test]
fn thirty_agents_converge_after_partition_shuffle_duplicates_and_concurrent_replacements() {
    let dirs = (0..34).map(|_| Temp::new()).collect::<Vec<_>>();
    let people = (1..=30).map(identity).collect::<Vec<_>>();
    let mut origin = space(&dirs[0], &people);
    let ws = workspace(&mut origin, &people[0]);
    let first = edit!(
        &mut origin,
        &people[0],
        &ws,
        &one(&ws),
        "shared.txt",
        0,
        0,
        "base\n",
        "seed",
    );
    let mut replicas = (0..30)
        .map(|i| replica(&dirs[i + 1], &origin))
        .collect::<Vec<_>>();
    for (i, lab) in replicas.iter_mut().enumerate() {
        let token = format!("agent-{i:02}\n");
        let edits = [
            Edit::splice("shared.txt", 5, 0, &token),
            Edit::splice(&format!("tasks/{i:02}.txt"), 0, 0, &token),
        ];
        let change = collab::edit(
            lab,
            &people[i],
            &ws,
            &one(&first),
            &edits,
            &format!("work-{i}"),
        )
        .unwrap();
        edit!(
            lab,
            &people[i],
            &ws,
            &one(&change),
            "shared.txt",
            0,
            4,
            "BASE",
            &format!("replace-{i}"),
        );
    }
    let mut all = replicas
        .iter()
        .flat_map(|r| r.ops().to_vec())
        .collect::<Vec<_>>();
    let mut expected = None;
    for (n, seed) in [1u64, 42, 20261017].into_iter().enumerate() {
        let mut rng = seed;
        for i in (1..all.len()).rev() {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
            let j = (rng % (i as u64 + 1)) as usize;
            all.swap(i, j);
        }
        let root = dirs[31 + n].0.join("lab");
        Lab::create_empty(&root, origin.space()).unwrap();
        let mut merged = Lab::open(&root).unwrap();
        let (_, refused) = merged.ingest_many(all.clone()).unwrap();
        assert!(refused.is_empty(), "seed {seed}: {refused:?}");
        assert_eq!(merged.ingest_many(all.clone()).unwrap().0, 0);
        let graph = Graph::load(&merged).unwrap();
        assert!(graph.issues.is_empty(), "{:?}", graph.issues);
        let current = graph.snapshot(&ws, None).unwrap();
        assert_eq!(
            current.conflicts.len(),
            1,
            "overlapping replacements need explicit resolution"
        );
        assert_eq!(current.heads.len(), 30);
        assert_eq!(current.files.len(), 31);
        let text = &current.files["shared.txt"].text;
        for i in 0..30 {
            assert_eq!(
                text.matches(&format!("agent-{i:02}\n")).count(),
                1,
                "seed {seed}: {text}"
            );
        }
        assert_eq!(
            text.matches("BASE").count(),
            30,
            "concurrent replacement preserves every author's insertion"
        );
        if let Some(expected) = &expected {
            assert_eq!(&current, expected, "seed {seed}");
        } else {
            expected = Some(current);
        }
        let mut cursor = BTreeSet::new();
        let mut delivered = BTreeSet::new();
        loop {
            let page = graph.feed(&ws, &cursor, 7).unwrap();
            for change in page["changes"].as_array().unwrap() {
                assert!(delivered.insert(change["id"].as_str().unwrap().to_string()));
            }
            cursor = serde_json::from_value(page["cursor"].clone()).unwrap();
            if page["more"] == false {
                break;
            }
        }
        assert_eq!(delivered.len(), 62);
        assert_eq!(cursor, graph.heads(&ws).unwrap());
    }
}

#[test]
fn causal_feed_does_not_skip_a_late_arrival_with_an_older_clock() {
    let dirs = [Temp::new(), Temp::new()];
    let people = [identity(1), identity(2)];
    let mut a = space(&dirs[0], &people);
    let ws = workspace(&mut a, &people[0]);
    let mut b = replica(&dirs[1], &a);
    let mut head = ws.clone();
    for i in 0..8 {
        head = edit!(
            &mut a,
            &people[0],
            &ws,
            &one(&head),
            "a",
            i,
            0,
            "A",
            &format!("a-{i}"),
        );
    }
    let page = Graph::load(&a)
        .unwrap()
        .feed(&ws, &BTreeSet::new(), 256)
        .unwrap();
    let cursor = serde_json::from_value(page["cursor"].clone()).unwrap();
    let late = edit!(&mut b, &people[1], &ws, &one(&ws), "b", 0, 0, "B", "late");
    sync::sync(&mut a, &mut b).unwrap();
    let page = Graph::load(&a).unwrap().feed(&ws, &cursor, 1).unwrap();
    assert_eq!(page["changes"][0]["id"], late);
    assert_eq!(page["changes"][0]["clock"], 2);
    assert_eq!(page["more"], false);
    let cursor = serde_json::from_value(page["cursor"].clone()).unwrap();
    assert_eq!(
        Graph::load(&a).unwrap().feed(&ws, &cursor, 1).unwrap()["changes"],
        json!([])
    );
}

#[test]
fn forks_are_isolated_until_an_explicit_pinned_integration_and_authors_survive() {
    let dir = Temp::new();
    let people = [identity(1), identity(2)];
    let mut lab = space(&dir, &people);
    let ws = workspace(&mut lab, &people[0]);
    let initial = edit!(
        &mut lab,
        &people[0],
        &ws,
        &one(&ws),
        "main.txt",
        0,
        0,
        "base\n",
        "seed",
    );
    let fork = collab::create(&mut lab, &people[1], "experiment", &one(&initial), "fork").unwrap();
    let work = edit!(
        &mut lab,
        &people[1],
        &fork,
        &one(&fork),
        "main.txt",
        5,
        0,
        "experiment\n",
        "experiment",
    );
    let target = edit!(
        &mut lab,
        &people[0],
        &ws,
        &one(&initial),
        "main.txt",
        5,
        0,
        "shared\n",
        "target",
    );
    assert!(!snapshot(&lab, &ws).files["main.txt"]
        .text
        .contains("experiment"));
    let joined = collab::integrate(
        &mut lab,
        &people[0],
        &ws,
        &one(&target),
        &one(&work),
        "integrate",
    )
    .unwrap();
    let current = snapshot(&lab, &ws);
    assert!(current.files["main.txt"].text.contains("experiment\n"));
    assert!(current.files["main.txt"].text.contains("shared\n"));
    assert_eq!(current.heads, one(&joined));
    edit!(
        &mut lab,
        &people[1],
        &fork,
        &one(&work),
        "future.txt",
        0,
        0,
        "not integrated",
        "future",
    );
    assert!(!snapshot(&lab, &ws).files.contains_key("future.txt"));
    let feed = Graph::load(&lab)
        .unwrap()
        .feed(&ws, &one(&target), 256)
        .unwrap();
    let imported = feed["changes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == work)
        .unwrap();
    assert_eq!(imported["change"]["author"], people[1].submitter_id());
    let unrelated = collab::create(
        &mut lab,
        &people[0],
        "unrelated",
        &BTreeSet::new(),
        "unrelated",
    )
    .unwrap();
    assert!(collab::integrate(
        &mut lab,
        &people[0],
        &ws,
        &one(&joined),
        &one(&unrelated),
        "bad-join"
    )
    .is_err());
}

#[test]
fn deletion_edit_and_mode_conflicts_require_an_observed_resolution() {
    let dirs = [Temp::new(), Temp::new()];
    let people = [identity(1), identity(2)];
    let mut a = space(&dirs[0], &people);
    let ws = workspace(&mut a, &people[0]);
    let first = edit!(
        &mut a,
        &people[0],
        &ws,
        &one(&ws),
        "tool",
        0,
        0,
        "old",
        "initial",
    );
    let mut b = replica(&dirs[1], &a);
    let remove = Edit {
        remove: true,
        ..Edit::splice("tool", 0, 0, "")
    };
    collab::edit(&mut a, &people[0], &ws, &one(&first), &[remove], "delete").unwrap();
    edit!(
        &mut b,
        &people[1],
        &ws,
        &one(&first),
        "tool",
        3,
        0,
        "new",
        "edit",
    );
    sync::sync(&mut a, &mut b).unwrap();
    let current = snapshot(&a, &ws);
    assert_eq!(current.files["tool"].text, "new");
    assert_eq!(current.conflicts.len(), 1);
    assert!(collab::checkpoint(&mut a, &people[0], &ws, &current.heads).is_err());
    let clear = edit!(
        &mut a,
        &people[0],
        &ws,
        &current.heads,
        "tool",
        0,
        0,
        "kept ",
        "resolve",
    );
    assert!(snapshot(&a, &ws).conflicts.is_empty());
    sync::sync(&mut a, &mut b).unwrap();
    let on = Edit {
        executable: Some(true),
        ..Edit::splice("tool", 0, 0, "")
    };
    let off = Edit {
        executable: Some(false),
        ..Edit::splice("tool", 0, 0, "")
    };
    collab::edit(&mut a, &people[0], &ws, &one(&clear), &[on], "exec-on").unwrap();
    collab::edit(&mut b, &people[1], &ws, &one(&clear), &[off], "exec-off").unwrap();
    sync::sync(&mut a, &mut b).unwrap();
    let current = snapshot(&a, &ws);
    assert_eq!(current.conflicts.len(), 1);
    assert!(current.require_clear().is_err());
    collab::edit(
        &mut a,
        &people[0],
        &ws,
        &current.heads,
        &[Edit {
            executable: Some(false),
            ..Edit::splice("tool", 0, 0, "")
        }],
        "mode-resolution",
    )
    .unwrap();
    assert!(snapshot(&a, &ws).require_clear().is_ok());
}

#[test]
fn checkpoints_remain_pinned_and_offline_publications_do_not_conflict() {
    let dirs = [Temp::new(), Temp::new()];
    let people = [identity(1), identity(2)];
    let mut a = space(&dirs[0], &people);
    let ws = workspace(&mut a, &people[0]);
    let first = edit!(
        &mut a,
        &people[0],
        &ws,
        &one(&ws),
        "main.rs",
        0,
        0,
        "version 1",
        "initial",
    );
    let mut b = replica(&dirs[1], &a);
    let ca = collab::checkpoint(&mut a, &people[0], &ws, &one(&first)).unwrap();
    let cb = collab::checkpoint(&mut b, &people[1], &ws, &one(&first)).unwrap();
    assert_eq!(ca["revision"], cb["revision"]);
    assert_ne!(ca["prefix"], cb["prefix"]);
    let count = a.len();
    let retry = collab::checkpoint(&mut a, &people[0], &ws, &one(&first)).unwrap();
    assert_eq!(retry["prefix"], ca["prefix"]);
    assert_eq!(a.len(), count);
    assert!(retry["op"].is_null());
    edit!(
        &mut a,
        &people[0],
        &ws,
        &one(&first),
        "main.rs",
        8,
        1,
        "2",
        "later",
    );
    sync::sync(&mut a, &mut b).unwrap();
    let state = State::of(&a);
    assert!(state.conflicts().is_empty());
    for c in [&ca, &cb] {
        let path = c["inputs"][0]["prefix"].as_str().unwrap();
        assert_eq!(c["inputs"][0]["target"], "/src/main.rs");
        assert_eq!(
            cairn::lab::api::read_file(&a, &state, path).unwrap(),
            b"version 1"
        );
        assert!(cairn::lab::api::write_file(
            &mut a,
            &people[0],
            path,
            b"overwrite",
            false,
            cairn::lab::api::Expect::Current
        )
        .is_err());
    }
    assert_eq!(snapshot(&a, &ws).files["main.rs"].text, "version 2");
}

#[test]
fn checkout_preserves_existing_work_and_refuses_path_aliases_and_metadata() {
    let dir = Temp::new();
    let people = [identity(1)];
    let mut lab = space(&dir, &people);
    let ws = workspace(&mut lab, &people[0]);
    for (n, path) in [
        "../escape",
        "/absolute",
        "a/../../escape",
        ".git/config",
        "nested/.GIT/config",
        ".cairn-lab/x",
        ".cairn-collab-index.json",
        "C:escape",
        "CON",
        "name.",
    ]
    .iter()
    .enumerate()
    {
        assert!(
            collab::edit(
                &mut lab,
                &people[0],
                &ws,
                &one(&ws),
                &[Edit::splice(path, 0, 0, "bad")],
                &format!("bad-{n}")
            )
            .is_err(),
            "{path}"
        );
    }
    let first = edit!(
        &mut lab,
        &people[0],
        &ws,
        &one(&ws),
        "src/main.txt",
        0,
        0,
        "source",
        "source",
    );
    let current = snapshot(&lab, &ws);
    let target = dir.0.join("checkout");
    collab::checkout(&current, &target).unwrap();
    assert_eq!(
        fs::read_to_string(target.join("src/main.txt")).unwrap(),
        "source"
    );
    fs::write(target.join("local"), "user work").unwrap();
    assert!(collab::checkout(&current, &target).is_err());
    assert_eq!(
        fs::read_to_string(target.join("local")).unwrap(),
        "user work"
    );
    edit!(
        &mut lab,
        &people[0],
        &ws,
        &one(&first),
        "src",
        0,
        0,
        "collision",
        "collision",
    );
    assert!(!snapshot(&lab, &ws).conflicts.is_empty());
    assert!(collab::checkout(&snapshot(&lab, &ws), &dir.0.join("unsafe")).is_err());
    assert!(!dir.0.join("unsafe").exists());
}

#[test]
fn invalid_unobserved_character_references_are_excluded_without_applying_partial_edits() {
    let dir = Temp::new();
    let people = [identity(1)];
    let mut lab = space(&dir, &people);
    let ws = workspace(&mut lab, &people[0]);
    let first = edit!(
        &mut lab,
        &people[0],
        &ws,
        &one(&ws),
        "a",
        0,
        0,
        "valid",
        "valid",
    );
    let value = json!({"type":"cairn.collab.change","version":1,"kind":"edit","author":people[0].submitter_id(),"request":"forged-anchor","workspace":ws,"title":null,"parents":[first],"edits":[{"path":"a","after":format!("sha256:{}/0/0","00".repeat(32)),"delete":[],"insert":"injected","executable":null,"remove":false}]});
    let value = cairn::canonical::Value::from_json(&value.to_string()).unwrap();
    lab.append(
        &people[0],
        Body::Doc {
            doc: "cairn.collab/v1".into(),
            fields: vec![Field {
                key: value.digest(),
                value,
                pred: vec![],
            }],
        },
    )
    .unwrap();
    let graph = Graph::load(&lab).unwrap();
    assert_eq!(graph.issues.len(), 1);
    assert_eq!(graph.snapshot(&ws, None).unwrap().files["a"].text, "valid");
}

#[test]
fn revocation_invalidates_cursors_instead_of_silently_skipping_removed_history() {
    let dirs = [Temp::new(), Temp::new()];
    let people = [identity(1), identity(2)];
    let mut a = space(&dirs[0], &people);
    let ws = workspace(&mut a, &people[0]);
    let mut b = replica(&dirs[1], &a);
    let revoked = edit!(
        &mut b,
        &people[1],
        &ws,
        &one(&ws),
        "a",
        0,
        0,
        "revoked",
        "concurrent",
    );
    a.append(
        &people[0],
        Body::Members {
            admit: vec![],
            revoke: vec![people[1].submitter_id()],
        },
    )
    .unwrap();
    sync::sync(&mut a, &mut b).unwrap();
    let graph = Graph::load(&a).unwrap();
    assert!(matches!(
        graph.feed(&ws, &one(&revoked), 128),
        Err(LabError::Unavailable(_))
    ));
    assert!(matches!(
        graph.snapshot(&ws, Some(&one(&revoked))),
        Err(LabError::Unavailable(_))
    ));
    assert!(!graph.snapshot(&ws, None).unwrap().files.contains_key("a"));
}

#[test]
fn simultaneous_local_retries_append_once_and_checkpoint_once() {
    let dir = Temp::new();
    let people = [identity(1)];
    let mut lab = space(&dir, &people);
    let ws = workspace(&mut lab, &people[0]);
    let root = lab.root().to_path_buf();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
    let handles = (0..8)
        .map(|_| {
            let root = root.clone();
            let ws = ws.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let mut lab = Lab::open(&root).unwrap();
                barrier.wait();
                edit!(
                    &mut lab,
                    &identity(1),
                    &ws,
                    &one(&ws),
                    "shared",
                    0,
                    0,
                    "once",
                    "same-request",
                )
            })
        })
        .collect::<Vec<_>>();
    let changes = handles
        .into_iter()
        .map(|h| h.join().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(changes.len(), 1);
    lab.refresh().unwrap();
    assert_eq!(lab.len(), 3);
    let at = changes;
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
    let handles = (0..8)
        .map(|_| {
            let root = root.clone();
            let ws = ws.clone();
            let at = at.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let mut lab = Lab::open(&root).unwrap();
                barrier.wait();
                collab::checkpoint(&mut lab, &identity(1), &ws, &at).unwrap()["prefix"].clone()
            })
        })
        .collect::<Vec<_>>();
    let prefixes = handles
        .into_iter()
        .map(|h| h.join().unwrap().as_str().unwrap().to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(prefixes.len(), 1);
    lab.refresh().unwrap();
    assert_eq!(lab.len(), 4);
    assert!(State::of(&lab).conflicts().is_empty());
}

#[test]
fn cli_json_and_finite_live_replication_work_without_a_git_repository() {
    let dirs = [Temp::new(), Temp::new()];
    let people = [identity(1)];
    let mut a = space(&dirs[0], &people);
    let ws = workspace(&mut a, &people[0]);
    let b = replica(&dirs[1], &a);
    edit!(
        &mut a,
        &people[0],
        &ws,
        &one(&ws),
        "text",
        0,
        0,
        "not Git",
        "edit",
    );
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_cairn"))
            .args(["lab", "--lab"])
            .arg(b.root())
            .args(args)
            .output()
            .unwrap()
    };
    let result = run(&[
        "sync",
        "--dir",
        a.root().to_str().unwrap(),
        "--watch",
        "--interval-ms",
        "50",
        "--rounds",
        "2",
    ]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let result = run(&["collab", "read", &ws]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let value: Json = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["contents"]["text"], "not Git");
    let result = run(&[
        "collab",
        "feed",
        &ws,
        "--watch",
        "--interval-ms",
        "50",
        "--rounds",
        "2",
    ]);
    assert!(result.status.success());
    assert_eq!(
        String::from_utf8(result.stdout).unwrap().lines().count(),
        1,
        "quiet watches must not emit duplicate frames"
    );
    assert!(!b.root().join(".git").exists());
}

#[test]
fn an_unseen_overlapping_replacement_cannot_be_resolved_by_editing_only_one_branch() {
    let dirs = [Temp::new(), Temp::new()];
    let people = [identity(1), identity(2)];
    let mut a = space(&dirs[0], &people);
    let ws = workspace(&mut a, &people[0]);
    let first = edit!(
        &mut a,
        &people[0],
        &ws,
        &one(&ws),
        "algorithm",
        0,
        0,
        "old",
        "seed"
    );
    let mut b = replica(&dirs[1], &a);
    let left = edit!(
        &mut a,
        &people[0],
        &ws,
        &one(&first),
        "algorithm",
        0,
        3,
        "left",
        "left"
    );
    edit!(
        &mut b,
        &people[1],
        &ws,
        &one(&first),
        "algorithm",
        0,
        3,
        "right",
        "right"
    );
    edit!(
        &mut a,
        &people[0],
        &ws,
        &one(&left),
        "algorithm",
        4,
        0,
        "!",
        "still-unseen"
    );
    sync::sync(&mut a, &mut b).unwrap();
    let current = snapshot(&a, &ws);
    assert_eq!(current.conflicts.len(), 1);
    assert!(collab::checkpoint(&mut a, &people[0], &ws, &current.heads).is_err());
    let size = current.files["algorithm"].text.chars().count();
    edit!(
        &mut a,
        &people[0],
        &ws,
        &current.heads,
        "algorithm",
        0,
        size,
        "chosen",
        "resolve"
    );
    assert!(snapshot(&a, &ws).conflicts.is_empty());
    assert_eq!(snapshot(&a, &ws).files["algorithm"].text, "chosen");
}

#[test]
fn checkpoint_inputs_exclude_later_files_and_capture_the_exact_pinned_bytes() {
    use cairn::lab::api::{self, Expect, Input};
    let dir = Temp::new();
    let people = [identity(1)];
    let mut lab = space(&dir, &people);
    let ws = workspace(&mut lab, &people[0]);
    let first = edit!(
        &mut lab,
        &people[0],
        &ws,
        &one(&ws),
        "main",
        0,
        0,
        "pinned",
        "seed"
    );
    let checkpoint = collab::checkpoint(&mut lab, &people[0], &ws, &one(&first)).unwrap();
    let extra = format!("{}/files/surprise", checkpoint["prefix"].as_str().unwrap());
    api::write_file(
        &mut lab,
        &people[0],
        &extra,
        b"must not execute",
        false,
        Expect::Absent,
    )
    .unwrap();
    let inputs = checkpoint["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| Input {
            prefix: v["prefix"].as_str().unwrap().into(),
            target: v["target"].as_str().unwrap().into(),
        })
        .collect::<Vec<_>>();
    let mounts = cairn::lab::replay::capture(&lab, &State::of(&lab), &inputs, &[]).unwrap();
    assert_eq!(mounts.len(), 1);
    assert_eq!(mounts[0].files.len(), 1);
    assert_eq!(
        mounts[0].files[0].blob.as_deref(),
        Some(cairn::canonical::digest_bytes(b"pinned").as_str())
    );
}

#[test]
fn unsafe_or_oversized_requests_fail_before_appending_and_case_collisions_are_visible() {
    let dir = Temp::new();
    let people = [identity(1)];
    let mut lab = space(&dir, &people);
    let ws = workspace(&mut lab, &people[0]);
    let count = lab.len();
    let oversized = "x".repeat(collab::MAX_TEXT_BYTES + 1);
    assert!(collab::edit(
        &mut lab,
        &people[0],
        &ws,
        &one(&ws),
        &[Edit::splice("big", 0, 0, &oversized)],
        "too-big"
    )
    .is_err());
    let error=collab::call(&mut lab,Some(&people[0]),"edit",&json!({"workspace":ws,"heads":[ws],"request":"unknown","edits":[{"path":"x","start":0,"delete":0,"insert":"x","execute":true}]})).unwrap_err();
    assert!(error.to_string().contains("unknown"));
    assert_eq!(lab.len(), count);
    let first = edit!(
        &mut lab,
        &people[0],
        &ws,
        &one(&ws),
        "Main.rs",
        0,
        0,
        "A",
        "upper"
    );
    edit!(
        &mut lab,
        &people[0],
        &ws,
        &one(&first),
        "main.rs",
        0,
        0,
        "B",
        "lower"
    );
    assert!(!snapshot(&lab, &ws).conflicts.is_empty());
}

#[test]
fn signed_causal_past_is_checked_and_request_equivocations_do_not_choose_an_arrival_winner() {
    use cairn::lab::op::Op;
    let dirs = [Temp::new(), Temp::new(), Temp::new()];
    let people = [identity(1)];
    let mut lab = space(&dirs[0], &people);
    let ws = workspace(&mut lab, &people[0]);
    let first = edit!(
        &mut lab,
        &people[0],
        &ws,
        &one(&ws),
        "a",
        0,
        0,
        "original",
        "seed"
    );
    let make = |request: &str, title: &str, parents: Json| {
        let value = json!({"type":"cairn.collab.change","version":1,"kind":"workspace","author":people[0].submitter_id(),"request":request,"workspace":null,"title":title,"parents":parents,"edits":[]});
        let value = cairn::canonical::Value::from_json(&value.to_string()).unwrap();
        Body::Doc {
            doc: "cairn.collab/v1".into(),
            fields: vec![Field {
                key: value.digest(),
                value,
                pred: vec![],
            }],
        }
    };
    let genesis = lab.ops()[0].clone();
    let forged = Op::sign(
        &people[0],
        Some(lab.space()),
        2,
        vec![genesis.id.clone()],
        "2026-10-17T00:00:00Z".into(),
        make("unobserved-fork", "unobserved", json!([first])),
    )
    .unwrap();
    lab.ingest(forged).unwrap();
    assert!(Graph::load(&lab)
        .unwrap()
        .issues
        .iter()
        .any(|i| i.contains("signed causal past")));
    lab.append(&people[0], make("equivocation", "left", json!([])))
        .unwrap();
    lab.append(&people[0], make("equivocation", "right", json!([])))
        .unwrap();
    let expected = Graph::load(&lab).unwrap().workspaces();
    assert_eq!(expected.as_array().unwrap().len(), 1);
    assert_eq!(Graph::load(&lab).unwrap().issues.len(), 3);
    let count = lab.len();
    assert!(matches!(
        collab::create(
            &mut lab,
            &people[0],
            "left",
            &BTreeSet::new(),
            "equivocation"
        ),
        Err(LabError::Refused(_))
    ));
    assert_eq!(
        lab.len(),
        count,
        "a retry of quarantined work must not report a false success"
    );
    for (i, reverse) in [true, false].into_iter().enumerate() {
        let root = dirs[i + 1].0.join("lab");
        Lab::create_empty(&root, lab.space()).unwrap();
        let mut copy = Lab::open(&root).unwrap();
        let mut ops = lab.ops().to_vec();
        if reverse {
            ops.reverse();
        }
        copy.ingest_many(ops).unwrap();
        assert_eq!(Graph::load(&copy).unwrap().workspaces(), expected);
        assert_eq!(
            Graph::load(&copy).unwrap().issues,
            Graph::load(&lab).unwrap().issues
        );
    }
}

#[test]
fn random_edit_histories_converge_after_interleaved_partitions() {
    for seed in [7u64, 42, 20261017] {
        let dirs = (0..5).map(|_| Temp::new()).collect::<Vec<_>>();
        let people = (1..=4).map(identity).collect::<Vec<_>>();
        let mut origin = space(&dirs[0], &people);
        let ws = workspace(&mut origin, &people[0]);
        let mut replicas = (0..4)
            .map(|i| replica(&dirs[i + 1], &origin))
            .collect::<Vec<_>>();
        let mut rng = seed;
        for step in 0..80 {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
            let who = (rng % 4) as usize;
            let current = snapshot(&replicas[who], &ws);
            let size = current
                .files
                .get("text")
                .map(|f| f.text.chars().count())
                .unwrap_or(0);
            let start = (rng as usize / 4) % (size + 1);
            let delete = usize::from(start < size && step % 3 == 0);
            let content = format!("{who}🦀");
            edit!(
                &mut replicas[who],
                &people[who],
                &ws,
                &current.heads,
                "text",
                start,
                delete,
                &content,
                &format!("seed-{seed}-step-{step}")
            );
            if step % 5 == 0 {
                let peer = (who + 1) % 4;
                let (a, b) = if who < peer {
                    let (a, b) = replicas.split_at_mut(peer);
                    (&mut a[who], &mut b[0])
                } else {
                    let (a, b) = replicas.split_at_mut(who);
                    (&mut b[0], &mut a[peer])
                };
                sync::sync(a, b).unwrap();
            }
        }
        for copy in &mut replicas {
            sync::sync(&mut origin, copy).unwrap();
        }
        let expected = snapshot(&origin, &ws);
        for copy in &mut replicas {
            sync::sync(&mut origin, copy).unwrap();
            assert_eq!(snapshot(copy, &ws), expected, "seed {seed}");
            assert!(Graph::load(copy).unwrap().issues.is_empty());
        }
    }
}

#[test]
fn whole_file_updates_to_different_functions_preserve_unchanged_character_identity() {
    let dirs = [Temp::new(), Temp::new()];
    let people = [identity(1), identity(2)];
    let mut a = space(&dirs[0], &people);
    let ws = workspace(&mut a, &people[0]);
    let original = "fn a() { 1 }\nfn b() { 2 }\n";
    let first = edit!(
        &mut a,
        &people[0],
        &ws,
        &one(&ws),
        "lib.rs",
        0,
        0,
        original,
        "initial"
    );
    let mut b = replica(&dirs[1], &a);
    edit!(
        &mut a,
        &people[0],
        &ws,
        &one(&first),
        "lib.rs",
        0,
        original.chars().count(),
        "fn a() { 3 }\nfn b() { 2 }\n",
        "left"
    );
    edit!(
        &mut b,
        &people[1],
        &ws,
        &one(&first),
        "lib.rs",
        0,
        original.chars().count(),
        "fn a() { 1 }\nfn b() { 4 }\n",
        "right"
    );
    sync::sync(&mut a, &mut b).unwrap();
    let current = snapshot(&a, &ws);
    assert_eq!(current.files["lib.rs"].text, "fn a() { 3 }\nfn b() { 4 }\n");
    assert!(current.conflicts.is_empty());
    collab::checkpoint(&mut a, &people[0], &ws, &current.heads).unwrap();
}

#[test]
fn a_wide_feed_cursor_remains_resumable_when_it_exceeds_the_edit_parent_limit() {
    let dir = Temp::new();
    let people = [identity(1)];
    let mut lab = space(&dir, &people);
    let ws = workspace(&mut lab, &people[0]);
    for i in 0..65 {
        edit!(
            &mut lab,
            &people[0],
            &ws,
            &one(&ws),
            &format!("file-{i}"),
            0,
            0,
            "x",
            &format!("concurrent-{i}")
        );
    }
    let current = snapshot(&lab, &ws);
    assert_eq!(current.heads.len(), 65);
    let response = collab::call(
        &mut lab,
        None,
        "feed",
        &json!({"workspace":ws,"cursor":current.heads,"limit":1}),
    )
    .unwrap();
    assert_eq!(response["changes"], json!([]));
    assert_eq!(response["cursor"].as_array().unwrap().len(), 65);
    let pinned = collab::call(
        &mut lab,
        Some(&people[0]),
        "checkpoint",
        &json!({"workspace":ws,"heads":current.heads}),
    )
    .unwrap();
    assert_eq!(pinned["heads"].as_array().unwrap().len(), 65);
    assert!(collab::edit(
        &mut lab,
        &people[0],
        &ws,
        &current.heads,
        &[Edit::splice("file-0", 0, 0, "!")],
        "over-parent-limit"
    )
    .is_err());
}
