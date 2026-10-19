//! Solver packages: the format holds, the store offers what it should, a
//! changed byte is refused, and a package in the sandbox can do its job and
//! nothing else.
//!
//! The jail tests need a jail (seatbelt on macOS, bubblewrap on Linux) and a
//! python3 it can run; without one they say so and return, because a host
//! that cannot run a package proves nothing about the package either way.

use std::fs;
use std::path::{Path, PathBuf};

use cairn::canonical::Value;
use cairn::records::Objective;
use cairn::solver::check::Outcome;
use cairn::solver::store::{Offers, Store};
use cairn::solver::{cli, package, Package};

const EXAMPLE: &str = "examples/certicom-ecdlp/solvers/ecc2k-23-orbit";
const EXAMPLE_OBJECTIVE: &str = "examples/certicom-ecdlp/objective-ecc2k-23-orbit-batch.json";

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn scratch(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir =
        std::env::temp_dir().join(format!("cairn-solver-{tag}-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

fn objective(path: &Path) -> Objective {
    let text = fs::read_to_string(path).expect("objective file");
    Objective::from_value(&Value::from_json(&text).expect("json")).expect("objective")
}

/// A one-file python package whose solver is `source`.
fn python_package(dir: &Path, source: &str, tests: &str) -> Package {
    fs::create_dir_all(dir).unwrap();
    fs::write(dir.join("solve.py"), source).unwrap();
    fs::write(
        dir.join("solver.json"),
        format!(
            r#"{{"abi":"cairn-solver/v1","name":"probe","version":"1","targets":{{"python3":{{"entry":"solve.py"}}}},
                "files":{{}},"resources":{{"round_seconds":20}},"tests":{tests}}}"#
        ),
    )
    .unwrap();
    package::pack(dir).expect("pack");
    Package::open(dir).expect("open")
}

#[test]
fn the_example_package_is_packed_and_its_copies_have_not_drifted() {
    let dir = repo().join(EXAMPLE);
    let package = Package::open(&dir).expect("the example matches its own solver.json");
    // The package carries copies, because a package is self-contained. A fix
    // to the tool that does not reach the copy would publish yesterday's
    // solver under today's name.
    for (copy, original) in [
        (
            "orbit_solver.py",
            "examples/certicom-ecdlp/tools/orbit_solver.py",
        ),
        ("orbit_dp.py", "examples/certicom-ecdlp/tools/orbit_dp.py"),
        (
            "jobs/ecc2k-23.json",
            "examples/certicom-ecdlp/jobs/ecc2k-23.json",
        ),
    ] {
        assert_eq!(
            fs::read(dir.join(copy)).unwrap(),
            fs::read(repo().join(original)).unwrap(),
            "{copy} differs from {original}: copy it again and `cairn solver pack {EXAMPLE}`"
        );
    }
    // It names the objective the app's practice task posts.
    let objective = objective(&repo().join(EXAMPLE_OBJECTIVE));
    assert_eq!(
        package.manifest.objective.as_deref(),
        Some(objective.id().as_str())
    );
}

#[test]
fn a_changed_byte_or_a_symlink_is_refused_before_anything_runs() {
    let dir = scratch("tamper");
    let package = python_package(
        &dir,
        "print('{}')\n",
        r#"[{"name":"t","assignment":{},"expect":[{}]}]"#,
    );
    let manifest = package.manifest.clone();

    fs::write(dir.join("solve.py"), "print('{} ')\n").unwrap();
    let refused = Package::at(&dir, manifest.clone()).unwrap_err();
    assert!(refused.0.contains("solve.py"), "{refused}");

    // Same length, different bytes: only the hash can tell.
    fs::write(dir.join("solve.py"), "print('[]')\n").unwrap();
    let refused = Package::at(&dir, manifest.clone()).unwrap_err();
    assert!(refused.0.contains("hashes to"), "{refused}");

    #[cfg(unix)]
    {
        fs::remove_file(dir.join("solve.py")).unwrap();
        let elsewhere = dir.join("elsewhere.py");
        fs::write(&elsewhere, "print('{}')\n").unwrap();
        std::os::unix::fs::symlink(&elsewhere, dir.join("solve.py")).unwrap();
        let refused = Package::at(&dir, manifest).unwrap_err();
        assert!(refused.0.contains("not a regular file"), "{refused}");
    }
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn pack_refuses_a_symlink_rather_than_leaving_it_out() {
    let dir = scratch("pack-link");
    let package_dir = dir.join("pkg");
    python_package(
        &package_dir,
        "print('{}')\n",
        r#"[{"name":"t","assignment":{},"expect":[{}]}]"#,
    );
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("/etc/hosts", package_dir.join("hosts")).unwrap();
        let refused = package::pack(&package_dir).unwrap_err();
        assert!(refused.0.contains("symlink"), "{refused}");
    }
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn a_pin_wins_and_a_missing_pin_is_never_replaced_by_an_approach() {
    let root = scratch("offers");
    let store = Store::under(&root);
    let base = objective(&repo().join(EXAMPLE_OBJECTIVE));

    // An approach written for the objective, filed with a passing report.
    let approach_dir = root.join("approach");
    let approach = python_package(
        &approach_dir,
        "print('{}')\n",
        r#"[{"name":"t","assignment":{},"expect":[{}]}]"#,
    );
    let mut value = approach.manifest.to_value().clone();
    if let Value::Object(map) = &mut value {
        map.insert("objective".into(), Value::string(base.id()));
    }
    fs::write(approach_dir.join("solver.json"), value.canonical_string()).unwrap();
    let approach = Package::open(&approach_dir).unwrap();
    let pass = |package: &Package| cairn::solver::check::Report {
        package: package.id(),
        sandbox: "test".into(),
        checked_at: "2026-10-19T00:00:00Z".into(),
        objective: None,
        tests: vec![cairn::solver::check::TestResult {
            name: "t".into(),
            platform: None,
            outcome: Outcome::Pass,
            detail: String::new(),
            candidates: 1,
            millis: 1,
        }],
        not_run: Vec::new(),
    };
    store
        .add(&approach, &pass(&approach))
        .expect("add the approach");

    let offers = Offers::for_objective(&store, &base);
    assert_eq!(offers.pinned, None);
    assert_eq!(offers.recommended, Some(approach.id()));

    // The same objective, pinning a package this store does not hold.
    let mut pinned_value = base.to_value();
    let absent = format!("sha256:{}", "ab".repeat(32));
    if let Value::Object(map) = &mut pinned_value {
        if let Some(Value::Object(verifier)) = map.get_mut("verifier") {
            verifier.insert(
                "capabilities".into(),
                Value::from_json(&format!(
                    r#"{{"worker":{{"mode":"package","package":"{absent}"}}}}"#
                ))
                .unwrap(),
            );
        }
    }
    let pinned = Objective::from_value(&pinned_value).unwrap();
    let offers = Offers::for_objective(&store, &pinned);
    assert_eq!(offers.pinned.as_deref(), Some(absent.as_str()));
    assert_eq!(
        offers.recommended, None,
        "the author pinned a program; a node must not quietly run another"
    );
    assert_eq!(offers.row().get("ready"), Some(&Value::Bool(false)));

    // A failing report is never filed.
    let mut failing = pass(&approach);
    failing.tests[0].outcome = Outcome::Fail;
    assert!(store.add(&approach, &failing).is_err());

    // A filed copy changed on disk is replaced, not vouched for a second time.
    let slot = store.dir().join(&approach.id()["sha256:".len()..]);
    fs::write(slot.join("solve.py"), "print('[]')\n").unwrap();
    store
        .add(&approach, &pass(&approach))
        .expect("add it again");
    Package::at(&slot, approach.manifest.clone()).expect("the slot holds the package again");

    // `cairn post` refuses the pinned objective while the pin is missing.
    assert!(cli::pin_problem(&root, &pinned).is_some());
    assert!(cli::pin_problem(&root, &base).is_none());
    let _ = fs::remove_dir_all(root);
}

/// Whether this host can run a python3 package at all. Prints why not.
fn runnable(report: &cairn::solver::check::Report) -> bool {
    if report.verdict() == Outcome::Unavailable
        && report
            .tests
            .iter()
            .all(|t| t.outcome == Outcome::Unavailable)
    {
        eprintln!(
            "skipping: this host cannot run a jailed python3 package ({})",
            report
                .tests
                .first()
                .map(|t| t.detail.as_str())
                .unwrap_or("")
        );
        return false;
    }
    true
}

#[test]
fn the_example_package_passes_its_tests_in_the_sandbox_and_its_checker_accepts() {
    if !cairn::verifiers::sandbox::mechanism().is_jail() {
        eprintln!("skipping: no sandbox on this host");
        return;
    }
    let package = Package::open(&repo().join(EXAMPLE)).unwrap();
    let objective = objective(&repo().join(EXAMPLE_OBJECTIVE));
    let report = cli::check_package(
        &package,
        Some((&objective.id(), &objective)),
        &repo(),
        false,
        true,
    );
    if !runnable(&report) {
        return;
    }
    assert_eq!(report.verdict(), Outcome::Pass, "{:#?}", report.tests);
}

#[test]
fn a_package_in_the_sandbox_reaches_no_network_no_home_and_no_secrets() {
    if !cairn::verifiers::sandbox::mechanism().is_jail() {
        eprintln!("skipping: no sandbox on this host");
        return;
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    let dir = scratch("probe");
    // A port on the host's loopback that answers. Under bubblewrap the jail
    // has a loopback of its own, so "refused" there is not "reached".
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback port");
    let port = listener.local_addr().unwrap().port();
    // Everything the probe learns goes into its one candidate, and the test
    // expects the answer a contained solver must give.
    let source = format!(
        r##"import json, os, socket
found = {{}}
try:
    socket.create_connection(("1.1.1.1", 80), timeout=2).close(); found["internet"] = "open"
except Exception:
    found["internet"] = "denied"
try:
    socket.create_connection(("127.0.0.1", {port}), timeout=2).close(); found["loopback"] = "open"
except Exception:
    found["loopback"] = "denied"
try:
    os.listdir({home:?}); found["home"] = "readable"
except Exception:
    found["home"] = "denied"
try:
    open("solve.py", "a").write("#"); found["package"] = "writable"
except Exception:
    found["package"] = "read-only"
try:
    open(os.path.join(os.environ["TMPDIR"], "x"), "w").write("x"); found["scratch"] = "writable"
except Exception:
    found["scratch"] = "denied"
found["secret"] = os.environ.get("CAIRN_TEST_SECRET", "absent")
found["abi"] = os.environ.get("CAIRN_ABI", "")
print(json.dumps(found))
"##
    );
    let expected = r#"{"abi":"cairn-solver/v1","home":"denied","internet":"denied","loopback":"denied","package":"read-only","scratch":"writable","secret":"absent"}"#;
    let package = python_package(
        &dir,
        &source,
        &format!(r#"[{{"name":"contained","assignment":{{}},"expect":[{expected}]}}]"#),
    );
    // Set in this process, so a jail that passed its environment through
    // would hand it to the solver.
    std::env::set_var("CAIRN_TEST_SECRET", "hunter2");
    let report = cli::check_package(&package, None, &dir, false, true);
    if !runnable(&report) {
        let _ = fs::remove_dir_all(dir);
        return;
    }
    assert_eq!(report.verdict(), Outcome::Pass, "{:#?}", report.tests);
    drop(listener);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn a_round_that_overruns_is_stopped_and_discarded() {
    if !cairn::verifiers::sandbox::mechanism().is_jail() {
        eprintln!("skipping: no sandbox on this host");
        return;
    }
    let dir = scratch("spin");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("solve.py"), "print('{}')\nwhile True:\n    pass\n").unwrap();
    fs::write(
        dir.join("solver.json"),
        r#"{"abi":"cairn-solver/v1","name":"spin","version":"1","targets":{"python3":{"entry":"solve.py"}},
            "files":{},"resources":{"round_seconds":2},"tests":[{"name":"t","assignment":{},"expect":[{}]}]}"#,
    )
    .unwrap();
    package::pack(&dir).unwrap();
    let package = Package::open(&dir).unwrap();
    let report = cli::check_package(&package, None, &dir, false, true);
    if !runnable(&report) {
        let _ = fs::remove_dir_all(dir);
        return;
    }
    assert_eq!(report.verdict(), Outcome::Fail);
    assert!(
        report.tests[0].detail.contains("round_seconds"),
        "{}",
        report.tests[0].detail
    );
    let _ = fs::remove_dir_all(dir);
}
