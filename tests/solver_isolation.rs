//! A solver round under the executor this host has: gVisor when `runsc` runs
//! here as root, otherwise the platform's jail. The probes are the same
//! program under both; what only gVisor shows (a root with no `/home`) is
//! asserted only when gVisor is what ran.
//!
//! Without `runsc` (or without root, which gVisor needs for cgroups) the
//! gVisor test says so and returns: a host that cannot run it proves nothing
//! about it. CI hosts with gVisor set `CAIRN_EXPECT_RUNSC=1` to make that a
//! failure instead.

use std::fs;
use std::net::TcpListener;
use std::path::PathBuf;

use cairn::canonical::Value;
use cairn::solver::executor::{self, SANDBOX_ENV};
use cairn::solver::manifest::Platform;
use cairn::solver::run::{self, Round};
use cairn::solver::{package, Package};

/// The tests set process-wide environment variables; one at a time.
static ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

const PROBE: &str = r#"
import json, os, socket, sys
assignment = json.loads(sys.stdin.readline())
def attempt(fn):
    try:
        fn()
        return "allowed"
    except Exception:
        return "refused"
def connect():
    socket.create_connection(("127.0.0.1", assignment["port"]), timeout=3).close()
def write(path):
    def go():
        with open(path, "w") as f:
            f.write("x")
    return go
print(json.dumps({
    "stdin": assignment["token"],
    "network": attempt(connect),
    "write_package": attempt(write(os.path.join(os.getcwd(), "x"))),
    "write_scratch": attempt(write(os.path.join(os.environ["TMPDIR"], "x"))),
    "write_etc": attempt(write("/etc/cairn-probe")),
    "secret_env": "yes" if "CAIRN_TEST_SECRET" in os.environ else "no",
    "has_home": "yes" if os.path.exists("/home") else "no",
    "threads": os.environ["CAIRN_THREADS"],
}))
"#;

fn scratch(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("cairn-iso-{tag}-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn package() -> Package {
    let dir = scratch("pkg");
    fs::write(dir.join("solve.py"), PROBE).unwrap();
    fs::write(
        dir.join("solver.json"),
        r#"{"abi":"cairn-solver/v1","name":"probe","version":"1","targets":{"python3":{"entry":"solve.py"}},
            "files":{},"resources":{"round_seconds":30,"memory_mb":512},"tests":[{"name":"t","assignment":{},"expect":[{}]}]}"#,
    )
    .unwrap();
    package::pack(&dir).expect("pack");
    Package::open(&dir).expect("open")
}

/// Run the probe and return what it printed, or `None` when this host cannot
/// run a package at all.
fn probe(listener: &TcpListener) -> Option<(Value, &'static str)> {
    let package = package();
    let assignment = Value::from_json(&format!(
        r#"{{"port":{},"token":"t-{}"}}"#,
        listener.local_addr().unwrap().port(),
        std::process::id()
    ))
    .unwrap();
    let round = Round {
        dir: &package.dir,
        platform: Platform::Python3,
        target: &package.manifest.targets[&Platform::Python3],
        resources: package.manifest.resources,
        assignment: &assignment,
        objective: "obj",
        worker: "probe",
        round: 1,
        threads: 2,
        allow_unjailed: false,
    };
    match run::run(&round) {
        Ok(output) => {
            assert_eq!(
                output.candidates.len(),
                1,
                "{:?} {}",
                output.skipped,
                output.stderr
            );
            Some((output.candidates[0].clone(), output.sandbox))
        }
        Err(run::Failure::Unavailable(why)) => {
            eprintln!("skipped: this host cannot run a package here: {why}");
            None
        }
        Err(other) => panic!("the probe broke: {other}"),
    }
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or("?")
}

#[test]
fn a_round_holds_the_same_guarantees_under_whatever_executor_runs_it() {
    let _serial = ENV.lock().unwrap_or_else(|e| e.into_inner());
    std::env::remove_var(SANDBOX_ENV);
    std::env::set_var("CAIRN_TEST_SECRET", "hunter2");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let Some((got, sandbox)) = probe(&listener) else {
        return;
    };
    eprintln!("executor: {}", executor::describe());
    assert!(
        ["runsc", "kata", "bwrap", "sandbox-exec"].contains(&sandbox),
        "{sandbox}"
    );
    assert!(text(&got, "stdin").starts_with("t-"), "stdin never arrived");
    assert_eq!(
        text(&got, "network"),
        "refused",
        "host loopback was reachable"
    );
    assert_eq!(text(&got, "write_package"), "refused");
    assert_eq!(text(&got, "write_etc"), "refused");
    assert_eq!(text(&got, "write_scratch"), "allowed");
    assert_eq!(text(&got, "secret_env"), "no");
    assert_eq!(text(&got, "threads"), "2");
    if sandbox == "runsc" {
        assert_eq!(text(&got, "has_home"), "no", "gVisor's root showed /home");
    }
}

#[test]
fn gvisor_runs_the_round_when_this_host_can() {
    let _serial = ENV.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var(SANDBOX_ENV, "runsc");
    std::env::set_var("CAIRN_TEST_SECRET", "hunter2");
    let expected = std::env::var("CAIRN_EXPECT_RUNSC").is_ok_and(|v| v == "1");
    if let Err(why) = executor::select() {
        assert!(
            !expected,
            "CAIRN_EXPECT_RUNSC=1 but gVisor is unusable: {why}"
        );
        eprintln!("skipped: gVisor cannot run rounds here: {why}");
        return;
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let (got, sandbox) = probe(&listener).expect("select said gVisor works");
    assert_eq!(sandbox, "runsc");
    assert_eq!(text(&got, "network"), "refused");
    assert_eq!(text(&got, "has_home"), "no");
    assert_eq!(text(&got, "write_package"), "refused");
    assert_eq!(text(&got, "write_scratch"), "allowed");
    assert_eq!(text(&got, "secret_env"), "no");
}

#[test]
fn a_pinned_executor_that_cannot_run_refuses_instead_of_degrading() {
    let _serial = ENV.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var(SANDBOX_ENV, "kata");
    std::env::remove_var(executor::KATA_IMAGE_ENV);
    let why = executor::select().expect_err("kata with no image must not be chosen");
    assert!(why.contains("kata"), "{why}");
    std::env::set_var(SANDBOX_ENV, "firejail");
    assert!(executor::select().is_err());
}
