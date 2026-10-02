//! The `workspace` verifier, driven against `examples/workspace-network/`.
//!
//! Every verdict below is one the design in
//! `docs/design/workspace-benchmarks.md` names: an honest tree accepts at its
//! derived score, a lie about the score is a rejection, a path outside the
//! contract is a rejection, a node missing a blob says nothing, and an
//! objective whose contract is incoherent is the objective's fault.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use cairn::blobs::{self, BlobStore};
use cairn::canonical::Value;
use cairn::verifiers::{Status, VerifierRegistry};

const EXAMPLE: &str = "examples/workspace-network";
const MANIFEST: &str = "examples/workspace-network/base.manifest.json";

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> TempDir {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "cairn-workspace-{label}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("temp dir is creatable");
        TempDir { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn repo(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn python_available() -> bool {
    std::process::Command::new("python3")
        .arg("--version")
        .output()
        .is_ok_and(|out| out.status.success())
}

/// A root holding the example's manifest, with every base file in its store.
fn root() -> TempDir {
    let dir = TempDir::new("root");
    let manifest_at = dir.path.join(MANIFEST);
    fs::create_dir_all(manifest_at.parent().unwrap()).unwrap();
    fs::copy(repo(MANIFEST), &manifest_at).unwrap();
    let store = BlobStore::under(&dir.path);
    for path in ["score.py", "solution/build.py"] {
        let bytes = fs::read(repo(&format!("{EXAMPLE}/base/{path}"))).unwrap();
        store.put(&blobs::address(&bytes), &bytes).unwrap();
    }
    dir
}

fn spec_with(edit: impl FnOnce(&mut Vec<(&'static str, Value)>)) -> Value {
    let manifest = fs::read(repo(MANIFEST)).unwrap();
    let mut fields = vec![
        ("kind", Value::string("workspace")),
        ("base", Value::string(MANIFEST)),
        ("base_sha256", Value::string(blobs::address(&manifest))),
        ("editable_paths", Value::array([Value::string("solution")])),
        (
            "score_command",
            Value::array([Value::string("python3"), Value::string("score.py")]),
        ),
        ("score_path", Value::string("score.json")),
        ("timeout_seconds", Value::Int(120)),
    ];
    edit(&mut fields);
    Value::object(fields)
}

fn spec() -> Value {
    spec_with(|_| {})
}

/// Store `files` and build the artifact claiming `score`.
fn artifact(root: &Path, files: &[(&str, &[u8])], score: i64) -> Value {
    let store = BlobStore::under(root);
    let manifest = files.iter().map(|(path, bytes)| {
        let address = blobs::address(bytes);
        store.put(&address, bytes).unwrap();
        (path.to_string(), Value::string(address))
    });
    Value::object([
        ("files", Value::object(manifest.collect::<Vec<_>>())),
        (
            "results",
            Value::object([("score", Value::Int(i128::from(score)))]),
        ),
        (
            "note",
            Value::string("odd-even merge; ignored by the verifier"),
        ),
    ])
}

fn batcher() -> Vec<u8> {
    fs::read(repo(&format!(
        "{EXAMPLE}/submissions/batcher/solution/build.py"
    )))
    .unwrap()
}

fn run(root: &Path, spec: &Value, artifact: &Value) -> cairn::verifiers::Verdict {
    VerifierRegistry::new(root).run(spec, artifact)
}

#[test]
fn an_honest_submission_accepts_at_its_derived_score() {
    if !python_available() {
        return;
    }
    let root = root();
    let batcher = batcher();
    let claim = artifact(&root.path, &[("solution/build.py", &batcher)], 114);
    let verdict = run(&root.path, &spec(), &claim);
    assert_eq!(verdict.status, Status::Accept, "{}", verdict.detail);
    assert_eq!(verdict.score(), Some(114));
}

#[test]
fn the_baseline_scores_what_the_example_says() {
    if !python_available() {
        return;
    }
    let root = root();
    let baseline = fs::read(repo(&format!("{EXAMPLE}/base/solution/build.py"))).unwrap();
    let claim = artifact(&root.path, &[("solution/build.py", &baseline)], 364);
    let verdict = run(&root.path, &spec(), &claim);
    assert_eq!(verdict.status, Status::Accept, "{}", verdict.detail);
    assert_eq!(verdict.score(), Some(364));
}

#[test]
fn a_lie_about_the_score_is_a_rejection() {
    if !python_available() {
        return;
    }
    let root = root();
    let batcher = batcher();
    let claim = artifact(&root.path, &[("solution/build.py", &batcher)], 100);
    let verdict = run(&root.path, &spec(), &claim);
    assert_eq!(verdict.status, Status::Reject, "{}", verdict.detail);
    assert_eq!(
        verdict.evidence.get("observed").and_then(Value::as_i64),
        Some(114)
    );
}

#[test]
fn a_network_that_does_not_sort_is_a_rejection() {
    if !python_available() {
        return;
    }
    let root = root();
    let broken: &[u8] = b"import json\nprint(json.dumps([[0, 1]]))\n";
    let claim = artifact(&root.path, &[("solution/build.py", broken)], 1);
    let verdict = run(&root.path, &spec(), &claim);
    assert_eq!(verdict.status, Status::Reject, "{}", verdict.detail);
}

#[test]
fn a_submission_cannot_bring_its_own_scorer() {
    let root = root();
    let forged: &[u8] = b"open('score.json','w').write('{\"score\": 1}')\n";
    let claim = artifact(&root.path, &[("score.py", forged)], 1);
    let verdict = run(&root.path, &spec(), &claim);
    assert_eq!(verdict.status, Status::Reject, "{}", verdict.detail);
    assert!(
        verdict.detail.contains("outside editable_paths"),
        "{}",
        verdict.detail
    );
}

#[test]
fn a_path_that_leaves_the_tree_is_a_rejection() {
    let root = root();
    for path in ["solution/../score.py", "/solution/x", "solution/.git/hooks"] {
        let claim = artifact(&root.path, &[(path, b"x")], 1);
        let verdict = run(&root.path, &spec(), &claim);
        assert_eq!(verdict.status, Status::Reject, "{path}: {}", verdict.detail);
    }
}

#[test]
fn a_missing_blob_is_this_nodes_problem() {
    let root = root();
    let claim = Value::object([
        (
            "files",
            Value::object([("solution/build.py", Value::string("ab".repeat(32)))]),
        ),
        ("results", Value::object([("score", Value::Int(114))])),
    ]);
    let verdict = run(&root.path, &spec(), &claim);
    assert_eq!(verdict.status, Status::Unavailable, "{}", verdict.detail);
}

#[test]
fn too_many_files_is_a_rejection_before_anything_runs() {
    let root = root();
    let spec = spec_with(|fields| fields.push(("max_files", Value::Int(2))));
    let claim = artifact(
        &root.path,
        &[
            ("solution/a", b"a"),
            ("solution/b", b"b"),
            ("solution/c", b"c"),
        ],
        1,
    );
    let verdict = run(&root.path, &spec, &claim);
    assert_eq!(verdict.status, Status::Reject, "{}", verdict.detail);
}

#[test]
fn too_many_bytes_is_a_rejection() {
    let root = root();
    let spec = spec_with(|fields| fields.push(("max_bytes", Value::Int(4096))));
    let big = vec![b'x'; 4097];
    let claim = artifact(&root.path, &[("solution/build.py", &big)], 1);
    let verdict = run(&root.path, &spec, &claim);
    assert_eq!(verdict.status, Status::Reject, "{}", verdict.detail);
}

#[test]
fn an_incoherent_contract_is_the_objectives_fault() {
    let root = root();
    let cases: Vec<(&str, Value)> = vec![
        (
            "overlapping editable paths",
            spec_with(|fields| {
                fields[3].1 = Value::array([Value::string("solution"), Value::string("solution/x")])
            }),
        ),
        (
            "score_path inside an editable path",
            spec_with(|fields| fields[5].1 = Value::string("solution/score.json")),
        ),
        (
            "a tampered base manifest",
            spec_with(|fields| fields[2].1 = Value::string("cd".repeat(32))),
        ),
        (
            "an editable path into .git",
            spec_with(|fields| fields[3].1 = Value::array([Value::string(".git")])),
        ),
        (
            "an empty score command",
            spec_with(|fields| fields[4].1 = Value::array(Vec::<Value>::new())),
        ),
    ];
    let batcher = batcher();
    let claim = artifact(&root.path, &[("solution/build.py", &batcher)], 114);
    for (case, spec) in cases {
        let verdict = run(&root.path, &spec, &claim);
        assert_eq!(
            verdict.status,
            Status::InvalidSpec,
            "{case}: {}",
            verdict.detail
        );
    }
}

#[test]
fn a_float_score_is_not_a_score() {
    if !python_available() {
        return;
    }
    let root = root();
    // A scorer that writes a float: replace the base's scorer with one, under
    // a new manifest, so the objective itself is what emits it.
    let scorer: &[u8] = b"open('score.json','w').write('{\"score\": 1.5}')\n";
    let store = BlobStore::under(&root.path);
    store.put(&blobs::address(scorer), scorer).unwrap();
    let base = fs::read(repo(&format!("{EXAMPLE}/base/solution/build.py"))).unwrap();
    let manifest = format!(
        "{{\"files\":{{\"score.py\":\"{}\",\"solution/build.py\":\"{}\"}}}}",
        blobs::address(scorer),
        blobs::address(&base)
    );
    fs::write(root.path.join("float.manifest.json"), &manifest).unwrap();
    let spec = spec_with(|fields| {
        fields[1].1 = Value::string("float.manifest.json");
        fields[2].1 = Value::string(blobs::address(manifest.as_bytes()));
    });
    let claim = artifact(&root.path, &[("solution/build.py", &base)], 1);
    let verdict = run(&root.path, &spec, &claim);
    assert_eq!(verdict.status, Status::Reject, "{}", verdict.detail);
}

#[test]
fn a_failing_prepare_says_nothing_about_the_artifact() {
    if !python_available() {
        return;
    }
    let root = root();
    let spec = spec_with(|fields| {
        fields.push((
            "prepare_command",
            Value::array([
                Value::string("python3"),
                Value::string("-c"),
                Value::string("raise SystemExit(3)"),
            ]),
        ))
    });
    let batcher = batcher();
    let claim = artifact(&root.path, &[("solution/build.py", &batcher)], 114);
    let verdict = run(&root.path, &spec, &claim);
    assert_eq!(verdict.status, Status::Unavailable, "{}", verdict.detail);
}

#[test]
fn the_base_manifest_is_reported_as_pinned_code() {
    let pins = cairn::verifiers::pinned_code(&spec());
    assert_eq!(pins.len(), 1);
    assert_eq!(pins[0].path, MANIFEST);
}
