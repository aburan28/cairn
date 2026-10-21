//! Solver packages between nodes: a package an objective pins crosses the p2p
//! code exchange, is held to its pin byte for byte, and is offered by the node
//! that received it only after that node's own check.
//!
//! The first tests need no jail: their package's only target is a platform
//! this host cannot run, which is the case the store files on format and
//! hashes alone. The last runs packages' tests in the jail on the receiving
//! node and, like `tests/solver.rs`, says so and returns on a host without one.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;

use cairn::blobs::{self, BlobStore};
use cairn::canonical::Value;
use cairn::ledger::Ledger;
use cairn::node::Node;
use cairn::p2p::code::{CodeLimits, PART_BYTES};
use cairn::p2p::discovery::Endpoint;
use cairn::p2p::handshake::PeerIdentity;
use cairn::p2p::service::Service;
use cairn::p2p::{session, transport};
use cairn::records::Objective;
use cairn::solver::check::{Outcome, Report, TestResult};
use cairn::solver::manifest::Platform;
use cairn::solver::store::{Offers, Store};
use cairn::solver::sync::{self, Exchange, Incoming, Settled};
use cairn::solver::{cli, package, Manifest, Package};

const TS: &str = "2026-07-29T00:00:00+00:00";

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Under `target/`, removed and recreated: a package left staged or filed by
/// the last run would make the next one pass without moving a byte.
fn scratch(name: &str) -> PathBuf {
    let dir = repo().join("target").join("solver-sync-tests").join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("destination");
    for entry in fs::read_dir(from).expect("read source") {
        let entry = entry.expect("entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("file type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).expect("copy");
        }
    }
}

/// A node with a bundle root of its own. The author's holds the collatz
/// example, so its pinned checker resolves and is published there; anybody
/// else's starts empty, like a contributor's node that knows only the log.
fn node(dir: &Path, author: bool) -> Node {
    let root = dir.join("root");
    fs::create_dir_all(&root).expect("root");
    if author {
        copy_tree(
            &repo().join("examples/collatz"),
            &root.join("examples/collatz"),
        );
    }
    Node::new(Ledger::open(dir.join("log.jsonl")).expect("ledger"), root)
}

/// The shipped collatz objective, its verifier pinning `package` in the
/// capabilities verifiers ignore, or pinning nothing.
fn objective_pinning(package: Option<&str>) -> Objective {
    let text = fs::read_to_string(repo().join("examples/collatz/objective.json")).unwrap();
    let mut value = Value::from_json(&text).unwrap();
    if let Some(id) = package {
        let Value::Object(top) = &mut value else {
            panic!("an objective is an object")
        };
        let Some(Value::Object(verifier)) = top.get_mut("verifier") else {
            panic!("the collatz objective has a verifier")
        };
        verifier.insert(
            "capabilities".into(),
            Value::object([(
                "worker",
                Value::object([
                    ("mode", Value::string("package")),
                    ("package", Value::string(id)),
                ]),
            )]),
        );
    }
    Objective::from_value(&value).unwrap()
}

/// A platform this host cannot run, and an entry point in its format.
fn foreign() -> (&'static str, Vec<u8>) {
    if Platform::host() == Some(Platform::LinuxX86_64) {
        let mut mach_o = vec![0xcf, 0xfa, 0xed, 0xfe];
        mach_o.extend_from_slice(&0x0100_000c_u32.to_le_bytes());
        mach_o.resize(64, 0);
        ("darwin-arm64", mach_o)
    } else {
        let mut elf = b"\x7fELF".to_vec();
        elf.extend_from_slice(&[2, 1, 1]);
        elf.resize(18, 0);
        elf.extend_from_slice(&0x3e_u16.to_le_bytes());
        elf.resize(64, 0);
        ("linux-x86_64", elf)
    }
}

/// A package for a platform this host cannot run, with a file several parts
/// long (and not a whole number of them) and an empty one, so a transfer has
/// to split, finish on a short part, and carry a zero-length item.
fn foreign_package(dir: &Path, objective: Option<&str>) -> Package {
    let (platform, entry) = foreign();
    fs::create_dir_all(dir.join("bin")).unwrap();
    fs::create_dir_all(dir.join("data")).unwrap();
    fs::write(dir.join("bin/solve"), entry).unwrap();
    let table: Vec<u8> = (0..3 * PART_BYTES + 17)
        .map(|i| (i * 7 % 251) as u8)
        .collect();
    fs::write(dir.join("data/table.bin"), table).unwrap();
    fs::write(dir.join("data/empty"), b"").unwrap();
    let named = objective
        .map(|id| format!(r#""objective":"{id}","#))
        .unwrap_or_default();
    fs::write(
        dir.join("solver.json"),
        format!(
            r#"{{"abi":"cairn-solver/v1","name":"far-away","version":"1",{named}
                "targets":{{"{platform}":{{"entry":"bin/solve"}}}},"files":{{}},
                "tests":[{{"name":"runs","assignment":{{"epoch":1}},"expect":[]}}]}}"#
        ),
    )
    .unwrap();
    package::pack(dir).expect("pack");
    Package::open(dir).expect("open")
}

/// A one-file python package, as in `tests/solver.rs`.
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

/// File `package` in `root`'s store the way `cairn solver add` does.
fn add(root: &Path, package: &Package, objective: &Objective) -> Report {
    let report = cli::check_package(
        package,
        Some((&objective.id(), objective)),
        root,
        false,
        true,
    );
    Store::under(root)
        .add(package, &report)
        .expect("the author's node files it");
    report
}

/// A report that says `package` passed. What a node that lied, or one with a
/// bug, or one on another platform, would have in its store.
fn vouched(package: &Package) -> Report {
    Report {
        package: package.id(),
        sandbox: "seatbelt".into(),
        checked_at: TS.into(),
        objective: None,
        tests: vec![TestResult {
            name: "runs".into(),
            platform: Platform::host(),
            outcome: Outcome::Pass,
            detail: String::new(),
            candidates: 0,
            millis: 0,
        }],
        not_run: Vec::new(),
    }
}

/// One p2p session, as two daemons hold it: `serving` accepts, `dialling`
/// dials. Returns the serving node.
fn sync(serving: Node, dialling: &mut Node) -> Node {
    let identity = Arc::new(PeerIdentity::generate());
    let public = identity.to_public();
    let service = Service::new(identity);
    let listener = service
        .listen("127.0.0.1:0".parse().expect("loopback"))
        .expect("listen");
    let endpoint = Endpoint::new(listener.local_addr().expect("bound"), public);
    let server = thread::spawn(move || {
        let mut serving = serving;
        service
            .accept_node_once(&listener, &mut serving)
            .expect("the serving node's round");
        serving
    });
    Service::new(Arc::new(PeerIdentity::generate()))
        .dial_node_once(&endpoint, dialling)
        .expect("the dialling node's round");
    server.join().expect("server thread")
}

fn hex(id: &str) -> String {
    id.strip_prefix("sha256:").expect("an id").to_string()
}

#[test]
fn a_pinned_package_crosses_p2p_and_is_offered_only_after_its_own_check() {
    let dir = scratch("crosses");
    let mut alice = node(&dir.join("alice"), true);
    let package = foreign_package(&dir.join("package"), None);
    let pin = package.id();
    let objective = objective_pinning(Some(&pin));
    alice.post_objective(&objective, TS).expect("post");
    add(alice.root(), &package, &objective);
    assert!(alice.missing_packages().is_empty(), "the author holds it");

    // Bob is a contributor's node: an empty log and an empty root. It dials
    // the author, which is what every Cairn.app node does at start.
    let mut bob = node(&dir.join("bob"), false);
    let _alice = sync(alice, &mut bob);

    assert!(
        bob.pinned_packages().contains_key(&pin),
        "the objective did not sync"
    );
    let store = Store::under(bob.root());
    // Every byte is here, and none of it is offered: nobody has checked it on
    // this node yet, and the store's rule is that only checked packages are.
    assert!(
        store.get(&pin).is_none(),
        "a package was offered before this node checked it"
    );
    assert_eq!(Offers::for_objective(&store, &objective).recommended, None);
    assert!(
        bob.missing_packages().is_empty(),
        "the whole package fits one session, so nothing should still be wanted"
    );

    let settled = sync::settle(bob.root(), &bob.pinned_packages());
    // `Unavailable`, not `Pass`: no target runs on this host, so what was
    // checked is format and hashes, and the report says so.
    assert_eq!(
        settled,
        vec![Settled::Offered {
            id: pin.clone(),
            verdict: Outcome::Unavailable,
        }]
    );
    let stored = store.get(&pin).expect("filed after its check");
    assert!(!stored.report.not_run.is_empty());
    for path in package.manifest.files.keys() {
        assert_eq!(
            fs::read(stored.dir.join(path)).unwrap(),
            fs::read(package.dir.join(path)).unwrap(),
            "{path} differs from the author's"
        );
    }
    // Now Start works against Bob, and nothing is left staged.
    assert_eq!(
        Offers::for_objective(&store, &objective).recommended,
        Some(pin.clone())
    );
    assert!(!Incoming::under(bob.root()).dir().join(hex(&pin)).exists());
    assert!(bob.missing_packages().is_empty());
}

#[test]
fn only_wanted_bytes_that_hash_to_their_pin_are_staged_and_a_transfer_resumes_by_file() {
    let dir = scratch("admission");
    let package = foreign_package(&dir.join("package"), None);
    let pin = package.id();
    let root = dir.join("root");
    fs::create_dir_all(&root).unwrap();
    let manifest = package.manifest.to_value().canonical_bytes();
    let file = |path: &str| fs::read(package.dir.join(path)).unwrap();
    let address = |path: &str| package.manifest.files[path].hex();

    let mut exchange = Exchange::new(&root, [pin.clone()]);
    assert_eq!(exchange.wants(), BTreeSet::from([hex(&pin)]));
    // A file before its manifest: nothing on this node says what it is yet.
    assert!(!exchange.admit(&file("bin/solve")));
    // Not the manifest the pin names, by one byte.
    let mut forged = manifest.clone();
    forged.push(b' ');
    assert!(!exchange.admit(&forged));
    assert!(
        !Incoming::under(&root).dir().exists(),
        "refused bytes reached the disk"
    );

    assert!(exchange.admit(&manifest));
    // The manifest makes its files wanted, by hash.
    let files: BTreeSet<String> = package.manifest.files.values().map(|e| e.hex()).collect();
    assert_eq!(exchange.wants(), files);
    // A substituted file of exactly the right size.
    let mut substituted = file("data/table.bin");
    substituted[100] ^= 1;
    assert!(!exchange.admit(&substituted));
    assert!(exchange.admit(&file("bin/solve")));
    assert!(exchange.report().complete.is_empty());

    // A new session, as after a dropped connection: the file that arrived is
    // kept, and only the rest is asked for.
    let mut resumed = Exchange::new(&root, [pin.clone()]);
    assert_eq!(
        resumed.wants(),
        BTreeSet::from([address("data/table.bin"), address("data/empty")])
    );
    assert!(resumed.admit(&file("data/table.bin")));
    assert!(resumed.admit(&file("data/empty")));
    assert_eq!(resumed.report().complete, BTreeSet::from([pin.clone()]));
    assert!(resumed.wants().is_empty());

    // A node whose log pins nothing takes nothing, however well it hashes.
    let mut unpinned = Exchange::new(&dir.join("elsewhere"), Vec::<String>::new());
    assert!(!unpinned.admit(&manifest));
    assert!(!unpinned.admit(&file("bin/solve")));
    assert_eq!(exchange.report().refused, 3);
}

#[test]
fn a_package_that_fails_here_is_never_offered_and_never_fetched_again() {
    let dir = scratch("fails");
    // A Linux entry point that is a shell script. Its manifest is well formed
    // and its bytes hash to their pins, so it travels; no Linux host could
    // exec it, so every node's check refuses it, whatever platform it is on.
    let package_dir = dir.join("package");
    fs::create_dir_all(&package_dir).unwrap();
    let script = b"#!/bin/sh\necho '{}'\n";
    fs::write(package_dir.join("solve.sh"), script).unwrap();
    let manifest = Manifest::from_value(&Value::object([
        ("abi", Value::string("cairn-solver/v1")),
        ("name", Value::string("not-an-elf")),
        ("version", Value::string("1")),
        (
            "targets",
            Value::object([(
                "linux-x86_64",
                Value::object([("entry", Value::string("solve.sh"))]),
            )]),
        ),
        (
            "files",
            Value::object([(
                "solve.sh",
                Value::object([
                    ("sha256", Value::string(blobs::address(script))),
                    ("size", Value::Int(script.len() as i128)),
                ]),
            )]),
        ),
        (
            "tests",
            Value::Array(vec![Value::object([
                ("name", Value::string("runs")),
                ("assignment", Value::object([("epoch", Value::Int(1))])),
                ("expect", Value::Array(vec![])),
            ])]),
        ),
    ]))
    .expect("a well-formed manifest");
    // Built around the format check, as a node with a bug, or one that lies,
    // would have it.
    let package = Package {
        dir: package_dir.clone(),
        manifest,
    };
    assert!(Package::at(&package_dir, package.manifest.clone()).is_err());
    let pin = package.id();

    let mut alice = node(&dir.join("alice"), true);
    let objective = objective_pinning(Some(&pin));
    alice.post_objective(&objective, TS).expect("post");
    Store::under(alice.root())
        .add(&package, &vouched(&package))
        .expect("alice's store takes her word");

    let mut bob = node(&dir.join("bob"), false);
    let _alice = sync(alice, &mut bob);
    let settled = sync::settle(bob.root(), &bob.pinned_packages());
    assert!(
        matches!(&settled[..], [Settled::Failed { id, why }] if *id == pin && why.contains("ELF")),
        "{settled:?}"
    );
    assert!(
        Store::under(bob.root()).get(&pin).is_none(),
        "a package that failed here is offered"
    );
    assert!(Incoming::under(bob.root()).failure(&pin).is_some());
    // And it is not asked for again: a pin whose package fails here would
    // otherwise be refetched from every peer, every round, for ever.
    assert!(bob.missing_packages().is_empty());
    assert!(Exchange::new(bob.root(), [pin.clone()]).pins().is_empty());
    assert!(!Incoming::under(bob.root()).dir().join(hex(&pin)).exists());
}

#[test]
fn an_approach_stays_with_the_operator_who_chose_it() {
    // An objective that pins nothing, and a package its author's node offers
    // for it. Which approach runs is that operator's call, so it does not
    // travel: a peer's node offers what *its* operator added, or nothing.
    let dir = scratch("approach");
    let mut alice = node(&dir.join("alice"), true);
    let objective = objective_pinning(None);
    alice.post_objective(&objective, TS).expect("post");
    let package = foreign_package(&dir.join("package"), Some(&objective.id()));
    add(alice.root(), &package, &objective);
    // Listed, not recommended: `auto` takes an approach only once it passed,
    // and this one could be checked here on format alone.
    assert!(
        Offers::for_objective(&Store::under(alice.root()), &objective)
            .packages
            .iter()
            .any(|s| s.id() == package.id()),
        "alice lists her approach"
    );

    let mut bob = node(&dir.join("bob"), false);
    let _alice = sync(alice, &mut bob);
    assert!(bob.objectives().contains_key(&objective.id()));
    assert!(bob.pinned_packages().is_empty());
    assert!(bob.missing_packages().is_empty());
    assert!(
        !Incoming::under(bob.root()).dir().exists(),
        "an approach was staged"
    );
    assert_eq!(
        Offers::for_objective(&Store::under(bob.root()), &objective).recommended,
        None
    );
}

#[test]
fn a_peer_that_predates_packages_still_completes_its_code_round() {
    // A node that has never heard of packages sends a want with no `packages`
    // field and expects the family after code to come next. Both ends must
    // agree the package round is skipped, or the next frame is read under the
    // wrong context and the whole session fails.
    let dir = scratch("older");
    let responder = Arc::new(PeerIdentity::generate());
    let public = responder.to_public();
    let listener = transport::listen("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    let old_store = BlobStore::at(dir.join("old-blobs"));
    let old = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut connection = transport::accept(stream, &responder).unwrap();
        let none = BTreeSet::new();
        session::reconcile_code(&mut connection, &old_store, &none, CodeLimits::default())
            .expect("the old side's round");
        session::reconcile_code(&mut connection, &old_store, &none, CodeLimits::default())
            .expect("the old side is still in step");
    });

    let root = dir.join("new-root");
    let pin = format!(
        "sha256:{}",
        blobs::address(b"a manifest only the new side wants")
    );
    let mut exchange = Exchange::new(&root, [pin]);
    assert!(!exchange.wants().is_empty());
    let mut connection = transport::connect(&public, addr, &PeerIdentity::generate()).unwrap();
    let store = BlobStore::at(root.join("blobs"));
    let none = BTreeSet::new();
    session::reconcile_code_with(
        &mut connection,
        &store,
        &none,
        Some(&mut exchange),
        CodeLimits::default(),
    )
    .expect("the new side's round");
    session::reconcile_code(&mut connection, &store, &none, CodeLimits::default())
        .expect("the new side is still in step");
    old.join().expect("old side");
    assert_eq!(exchange.report(), &sync::Transfer::default());
}

/// Whether this host can run a jailed python3 package. Prints why not.
fn runnable(report: &Report) -> bool {
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
fn a_synced_package_must_pass_its_tests_on_the_node_that_received_it() {
    if !cairn::verifiers::sandbox::mechanism().is_jail() {
        eprintln!("skipping: no sandbox on this host");
        return;
    }
    let dir = scratch("jailed");
    let tests = r#"[{"name":"answers","assignment":{"epoch":1},"expect":[{"n":42}]}]"#;
    let good = python_package(&dir.join("good"), "print('{\"n\": 42}')\n", tests);
    // Prints something other than its own test expects: a package that
    // passed wherever it was added, and does not pass here.
    let bad = python_package(&dir.join("bad"), "print('{\"n\": 41}')\n", tests);
    let good_objective = objective_pinning(Some(&good.id()));
    let bad_objective = objective_pinning(Some(&bad.id()));

    let mut alice = node(&dir.join("alice"), true);
    alice.post_objective(&good_objective, TS).expect("post");
    alice.post_objective(&bad_objective, TS).expect("post");
    let report = cli::check_package(
        &good,
        Some((&good_objective.id(), &good_objective)),
        alice.root(),
        false,
        true,
    );
    if !runnable(&report) {
        return;
    }
    add(alice.root(), &good, &good_objective);
    Store::under(alice.root())
        .add(&bad, &vouched(&bad))
        .expect("alice's store takes her word");

    let mut bob = node(&dir.join("bob"), false);
    let _alice = sync(alice, &mut bob);
    let settled = sync::settle(bob.root(), &bob.pinned_packages());
    assert!(
        settled.contains(&Settled::Offered {
            id: good.id(),
            verdict: Outcome::Pass,
        }),
        "{settled:?}"
    );
    assert!(
        settled
            .iter()
            .any(|s| matches!(s, Settled::Failed { id, .. } if *id == bad.id())),
        "{settled:?}"
    );
    let store = Store::under(bob.root());
    assert_eq!(
        Offers::for_objective(&store, &good_objective).recommended,
        Some(good.id())
    );
    assert_eq!(
        Offers::for_objective(&store, &bad_objective).recommended,
        None,
        "a package that failed here is offered"
    );
}
