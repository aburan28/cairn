//! Real startup with deliberately tempting public discovery settings. Helpers
//! leave a marker if invoked, so an offline-looking startup cannot hide a curl
//! or Tailscale invocation that merely failed.

use std::collections::HashSet;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use cairn::canonical::Value;
use cairn::p2p::handshake::PeerIdentity;

struct Node {
    child: Child,
    dir: PathBuf,
    http: SocketAddr,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Node {
    fn stop(&mut self) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
    }
}

fn scratch() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "cairn-private-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn address() -> SocketAddr {
    static ISSUED: OnceLock<Mutex<HashSet<u16>>> = OnceLock::new();
    let issued = ISSUED.get_or_init(|| Mutex::new(HashSet::new()));
    loop {
        // The child must bind this address after this listener is dropped.
        // Never hand the same released ephemeral port to another parallel
        // fixture while the first child is still starting.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let first_issue = issued.lock().unwrap().insert(address.port());
        drop(listener);
        if first_issue {
            return address;
        }
    }
}

fn command(dir: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cairn"));
    cmd.env_clear()
        .current_dir(dir)
        .env("PATH", dir)
        .env("CAIRN_KEY", dir.join("absent-key"))
        .env("CAIRN_DATA", dir)
        .env("CAIRN_NETWORK", "private")
        .env("CAIRN_TAILSCALE", dir.join("tailscale"))
        .env("CAIRN_PORTMAP", "upnp")
        .env("CAIRN_PORTMAP_HTTP", "on")
        .env("CAIRN_BEACON_PORT", "47396")
        .env("CAIRN_SEEDS_REFRESH", "on")
        .env(
            "CAIRN_SEEDS_URL",
            "https://public-discovery.invalid/seeds.json",
        )
        .stdin(Stdio::null());
    cmd
}

fn daemon_command(dir: &Path) -> Command {
    let mut cmd = command(dir);
    cmd.arg("--log").arg(dir.join("cairn.jsonl"));
    // Default-feature checks exercise the shared daemon through p2p; an
    // embedded build exercises the complete run entry point used by launchers.
    if cairn::serve::embedded_reader_available() {
        cmd.args(["run", "--no-mcp"]);
    } else {
        cmd.arg("p2p");
    }
    cmd.arg("--identity")
        .arg(dir.join("node.identity.json"))
        .arg("--root-key")
        .arg(dir.join("root.key"))
        .arg("--checkpoint")
        .arg(dir.join("checkpoint.json"));
    cmd
}

#[cfg(unix)]
fn helpers(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    for helper in ["curl", "tailscale"] {
        let path = dir.join(helper);
        fs::write(
            &path,
            "#!/bin/sh\nprintf invoked >> helper-invoked\nexit 1\n",
        )
        .unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }
}

fn spawn(dir: PathBuf, p2p: SocketAddr, bootstrap: Option<&Path>) -> Node {
    start(dir, p2p, address(), bootstrap, |_| {})
}

fn start(
    dir: PathBuf,
    p2p: SocketAddr,
    http: SocketAddr,
    bootstrap: Option<&Path>,
    configure: impl FnOnce(&mut Command),
) -> Node {
    assert_ne!(
        p2p.port(),
        http.port(),
        "P2P and HTTP fixtures must not reserve the same port"
    );
    helpers(&dir);
    let mut cmd = daemon_command(&dir);
    cmd.args([
        "--listen",
        &p2p.to_string(),
        "--serve",
        &format!("0.0.0.0:{}", http.port()),
    ]);
    if let Some(file) = bootstrap {
        cmd.arg("--bootstrap").arg(file);
    }
    configure(&mut cmd);
    cmd.stdout(Stdio::null())
        .stderr(fs::File::create(dir.join("stderr")).unwrap());
    Node {
        child: cmd.spawn().unwrap(),
        dir,
        http,
    }
}

fn finishes(mut cmd: Command, dir: &Path) -> Output {
    cmd.stdout(fs::File::create(dir.join("output")).unwrap())
        .stderr(fs::File::create(dir.join("refusal")).unwrap());
    let mut child = cmd.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return Output {
                status,
                stdout: fs::read(dir.join("output")).unwrap(),
                stderr: fs::read(dir.join("refusal")).unwrap(),
            };
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "startup unexpectedly stayed alive; evidence: {}",
                dir.display()
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn get(node: &Node, path: &str) -> Option<serde_json::Value> {
    let mut stream = TcpStream::connect_timeout(&node.http, Duration::from_millis(100)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    serde_json::from_str(response.split_once("\r\n\r\n")?.1).ok()
}

fn wait_for(
    node: &mut Node,
    path: &str,
    ready: impl Fn(&serde_json::Value) -> bool,
) -> serde_json::Value {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if let Some(value) = get(node, path) {
            if ready(&value) {
                return value;
            }
        }
        assert!(
            node.child.try_wait().unwrap().is_none(),
            "node exited: {}",
            fs::read_to_string(node.dir.join("stderr")).unwrap()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!(
        "node did not become ready: {}",
        fs::read_to_string(node.dir.join("stderr")).unwrap()
    );
}

#[test]
fn concurrent_fixture_addresses_are_unique_until_child_spawn() {
    let workers = (0..8)
        .map(|_| std::thread::spawn(|| (0..16).map(|_| address().port()).collect::<Vec<_>>()))
        .collect::<Vec<_>>();
    let ports = workers
        .into_iter()
        .flat_map(|worker| worker.join().unwrap())
        .collect::<HashSet<_>>();
    assert_eq!(ports.len(), 8 * 16);
}

#[test]
fn private_leader_has_zero_peers_and_runs_no_public_discovery_helpers() {
    let p2p = address();
    let mut node = spawn(scratch(), p2p, None);
    let network = wait_for(&mut node, "/network", |_| true);
    assert_eq!(network["node"]["peers_policy"]["policy"], "allowlist");
    assert_eq!(network["node"]["peers_policy"]["allowed"], 0);
    assert_eq!(network["node"]["reach"]["external"]["mode"], "off");
    assert!(network["node"]["reach"].get("tailnet").is_none());
    let seeds = get(&node, "/ui/seeds.json").expect("private reader discovery list");
    assert_eq!(seeds["seeds"], serde_json::json!([]));
    assert!(!node.dir.join("helper-invoked").exists());
    let stderr = fs::read_to_string(node.dir.join("stderr")).unwrap();
    assert!(stderr.contains("CAIRN_NETWORK=private"));
    assert!(!stderr.contains("beacon bound"));
    assert!(!stderr.contains("asking the router"));

    let key: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(node.dir.join("node.identity.json")).unwrap())
            .unwrap();
    let public = cairn::p2p::handshake::PeerPublic::from_bytes(
        &cairn::hex::decode(key["public"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    let stranger = cairn::p2p::service::Service::new(std::sync::Arc::new(PeerIdentity::generate()));
    let dir = scratch();
    let mut stranger_node = cairn::Node::new(cairn::Ledger::open(dir.join("log")).unwrap(), &dir);
    assert!(
        stranger
            .dial_node_once(
                &cairn::p2p::discovery::Endpoint::new(p2p, public),
                &mut stranger_node,
            )
            .is_err(),
        "a private node with no peers admitted a stranger"
    );
    wait_for(&mut node, "/sessions", |value| {
        value["anonymous_inbound_failures"]
            .as_u64()
            .is_some_and(|n| n > 0)
    });
}

fn identity(dir: &Path, p2p: SocketAddr) -> PathBuf {
    let identity = PeerIdentity::generate();
    let value = Value::object([
        (
            "public",
            Value::string(cairn::hex::encode(identity.public_key())),
        ),
        (
            "secret",
            Value::string(cairn::hex::encode(identity.secret_key())),
        ),
    ]);
    cairn::secret_file::write_new(
        &dir.join("node.identity.json"),
        value.canonical_string().as_bytes(),
    )
    .unwrap();
    let bootstrap = dir.join("bootstrap.json");
    fs::write(
        &bootstrap,
        Value::object([
            ("addr", Value::string(p2p.to_string())),
            (
                "public",
                Value::string(cairn::hex::encode(identity.public_key())),
            ),
        ])
        .canonical_string(),
    )
    .unwrap();
    bootstrap
}

#[test]
fn explicitly_bootstrapped_private_nodes_reach_each_other() {
    let (first_dir, second_dir) = (scratch(), scratch());
    let (first_p2p, second_p2p) = (address(), address());
    let first_bootstrap = identity(&first_dir, first_p2p);
    let second_bootstrap = identity(&second_dir, second_p2p);
    let mut first = spawn(first_dir, first_p2p, Some(&second_bootstrap));
    let mut second = spawn(second_dir, second_p2p, Some(&first_bootstrap));
    for node in [&mut first, &mut second] {
        let network = wait_for(node, "/network", |_| true);
        assert_eq!(network["node"]["peers_policy"]["allowed"], 1);
        wait_for(node, "/sessions", |value| {
            value["reached"].as_u64().is_some_and(|n| n > 0)
        });
        assert!(!node.dir.join("helper-invoked").exists());
    }
}

#[test]
fn a_private_bootstrap_ring_makes_progress_without_a_cross_node_lock_cycle() {
    let dirs = [scratch(), scratch(), scratch()];
    let addresses = [address(), address(), address()];
    let bootstraps = [
        identity(&dirs[0], addresses[0]),
        identity(&dirs[1], addresses[1]),
        identity(&dirs[2], addresses[2]),
    ];
    let peers: Vec<_> = bootstraps
        .iter()
        .map(|path| {
            let value: Value = Value::from_json(&fs::read_to_string(path).unwrap()).unwrap();
            let public = cairn::p2p::handshake::PeerPublic::from_bytes(
                &cairn::hex::decode(value.get("public").unwrap().as_str().unwrap()).unwrap(),
            )
            .unwrap();
            cairn::hex::encode(&public.id())
        })
        .collect();
    let mut nodes = Vec::new();
    for i in 0..3 {
        // All three are named members; only the next member is bootstrapped.
        // The predecessor must be authorized to complete its inbound session.
        let allowed = peers
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, id)| id.as_str())
            .collect::<Vec<_>>()
            .join(",");
        nodes.push(start(
            dirs[i].clone(),
            addresses[i],
            address(),
            Some(&bootstraps[(i + 1) % 3]),
            |cmd| {
                cmd.env("CAIRN_PEERS", allowed);
            },
        ));
    }
    for node in &mut nodes {
        wait_for(node, "/sessions", |value| {
            value["reached"].as_u64().is_some_and(|n| n > 0)
        });
        assert!(!node.dir.join("helper-invoked").exists());
    }
}

#[test]
fn incompatible_profiles_and_auth_fail_before_starting() {
    for (variable, value, expected) in [
        ("CAIRN_NETWORK", "privte", "expected public or private"),
        ("CAIRN_PEERS", "open", "refuses CAIRN_PEERS=open"),
        (
            "CAIRN_GOOGLE_CLIENT_ID",
            "example.apps.googleusercontent.com",
            "conflicts with CAIRN_GOOGLE_CLIENT_ID",
        ),
    ] {
        let dir = scratch();
        let mut cmd = daemon_command(&dir);
        cmd.env(variable, value)
            .args(["--listen", "127.0.0.1:0", "--serve", "127.0.0.1:0"]);
        let output = finishes(cmd, &dir);
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(expected),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!String::from_utf8_lossy(&output.stderr).contains("listening on"));
    }
}

#[test]
fn help_advertises_the_native_private_profile() {
    let dir = scratch();
    let mut cmd = command(&dir);
    cmd.args(["run", "--help"]);
    let output = finishes(cmd, &dir);
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("CAIRN_NETWORK=private"));
}

#[test]
fn version_and_run_agree_about_actual_embedded_reader() {
    let dir = scratch();
    let mut cmd = command(&dir);
    cmd.arg("--version");
    let output = finishes(cmd, &dir);
    assert!(output.status.success());
    let version = String::from_utf8_lossy(&output.stdout);
    let available = cairn::serve::embedded_reader_available();
    assert_eq!(
        version
            .lines()
            .any(|line| line.trim_start().starts_with("ui       embedded --")),
        available,
        "{version}"
    );
    if available {
        // The same fixture exercises the complete run entry point for a real
        // embedded build; source-only builds instead verify early refusal.
        let mut node = spawn(dir, address(), None);
        let network = wait_for(&mut node, "/network", |_| true);
        assert_eq!(network["node"]["peers_policy"]["policy"], "allowlist");
    } else {
        helpers(&dir);
        let http = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut cmd = command(&dir);
        cmd.args([
            "--data-dir",
            dir.to_str().unwrap(),
            "run",
            "--no-mcp",
            "--serve",
        ])
        .arg(http.local_addr().unwrap().to_string());
        let output = finishes(cmd, &dir);
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains("requires the embedded UI assets"));
        assert!(!dir.join("node.identity.json").exists());
        assert!(!dir.join("helper-invoked").exists());
    }
}

#[test]
fn private_publisher_refuses_external_auth_and_tailnet_shortcuts() {
    for publisher in [true, false] {
        let dir = scratch();
        helpers(&dir);
        let mut cmd = if publisher {
            command(&dir)
        } else {
            daemon_command(&dir)
        };
        if publisher {
            cmd.args(["serve", "--listen", "tailnet:8080"]);
        } else {
            cmd.args(["--listen", "127.0.0.1:0", "--serve", "tailnet:8080"]);
        }
        let output = finishes(cmd, &dir);
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("explicit internal or WireGuard IP")
        );
        assert!(!dir.join("helper-invoked").exists());
    }
    for (variable, value) in [
        ("CAIRN_NETWORK", "privte"),
        (
            "CAIRN_GOOGLE_CLIENT_ID",
            "example.apps.googleusercontent.com",
        ),
    ] {
        let dir = scratch();
        let mut cmd = command(&dir);
        cmd.env(variable, value)
            .args(["serve", "--listen", "127.0.0.1:0"]);
        let output = finishes(cmd, &dir);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("CAIRN_NETWORK"));
    }
}

#[test]
fn invalid_configuration_is_refused_before_binding_or_running_discovery() {
    for publisher in [false, true] {
        for (variable, value, reason) in [
            (
                "CAIRN_NETWORK",
                "PRIVATE-typo",
                "expected public or private",
            ),
            (
                "CAIRN_GOOGLE_CLIENT_ID",
                "example.apps.googleusercontent.com",
                "conflicts with",
            ),
            ("CAIRN_PEERS", "open", "refuses CAIRN_PEERS=open"),
            ("CAIRN_PEERS", "not-a-key", "not `open`"),
        ] {
            if publisher && variable == "CAIRN_PEERS" {
                continue; // A publisher has no p2p policy to configure.
            }
            let dir = scratch();
            helpers(&dir);
            // Occupied addresses make a premature bind observable as the wrong
            // refusal. No discovery helper may run even when ambient settings
            // and an unreadable seed file invite it to do so.
            let http = TcpListener::bind("127.0.0.1:0").unwrap();
            let p2p = TcpListener::bind("127.0.0.1:0").unwrap();
            let mut cmd = if publisher {
                command(&dir)
            } else {
                daemon_command(&dir)
            };
            if publisher {
                cmd.args(["serve", "--listen", &http.local_addr().unwrap().to_string()]);
            } else {
                cmd.args([
                    "--listen",
                    &p2p.local_addr().unwrap().to_string(),
                    "--serve",
                    &http.local_addr().unwrap().to_string(),
                ]);
            }
            cmd.env(variable, value)
                .env("CAIRN_SEEDS", dir.join("missing-seeds.json"));
            let output = finishes(cmd, &dir);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(!output.status.success());
            assert!(stderr.contains(reason), "{variable}: {stderr}");
            assert!(
                !stderr.contains("cannot bind"),
                "validation happened after a bind: {stderr}"
            );
            assert!(!dir.join("helper-invoked").exists());
        }
    }
}

#[cfg(unix)]
#[test]
fn a_non_unicode_profile_is_not_treated_as_the_public_default() {
    use std::os::unix::ffi::OsStringExt;
    let dir = scratch();
    helpers(&dir);
    let mut cmd = daemon_command(&dir);
    cmd.env("CAIRN_NETWORK", std::ffi::OsString::from_vec(vec![0xff]))
        .args(["--listen", "127.0.0.1:0", "--serve", "127.0.0.1:0"]);
    let output = finishes(cmd, &dir);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not valid Unicode"));
    assert!(!dir.join("helper-invoked").exists());
    assert!(!dir.join("node.identity.json").exists());
}

#[test]
fn an_invalid_local_seed_file_can_be_repaired_without_replacing_identity() {
    let dir = scratch();
    helpers(&dir);
    let seeds = dir.join("private-seeds.json");
    fs::write(&seeds, r#"{"seeds":"not an array"}"#).unwrap();
    let mut cmd = daemon_command(&dir);
    cmd.env("CAIRN_SEEDS", &seeds)
        .args(["--listen", "127.0.0.1:0", "--serve", "127.0.0.1:0"]);
    let output = finishes(cmd, &dir);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("seeds"));
    assert!(!dir.join("helper-invoked").exists());
    let original = fs::read(dir.join("node.identity.json")).unwrap();
    fs::write(&seeds, r#"{"seeds":[]}"#).unwrap();
    let mut node = start(dir.clone(), address(), address(), None, |cmd| {
        cmd.env("CAIRN_SEEDS", &seeds);
    });
    let network = wait_for(&mut node, "/network", |_| true);
    assert_eq!(network["node"]["peers_policy"]["allowed"], 0);
    assert_eq!(fs::read(dir.join("node.identity.json")).unwrap(), original);
    assert!(!dir.join("helper-invoked").exists());
}

#[test]
fn explicit_local_seeds_dial_only_allowed_identities() {
    let (first_dir, second_dir, stranger_dir) = (scratch(), scratch(), scratch());
    let (first_p2p, second_p2p) = (address(), address());
    let first_bootstrap = identity(&first_dir, first_p2p);
    let second_bootstrap = identity(&second_dir, second_p2p);
    let trap = TcpListener::bind("127.0.0.1:0").unwrap();
    trap.set_nonblocking(true).unwrap();
    let stranger_bootstrap = identity(&stranger_dir, trap.local_addr().unwrap());
    let entry = |file: &Path, name: &str| {
        let bootstrap: Value = Value::from_json(&fs::read_to_string(file).unwrap()).unwrap();
        let public = cairn::p2p::handshake::PeerPublic::from_bytes(
            &cairn::hex::decode(bootstrap.get("public").unwrap().as_str().unwrap()).unwrap(),
        )
        .unwrap();
        Value::object([
            ("name", Value::string(name)),
            ("addr", bootstrap.get("addr").unwrap().clone()),
            ("transport", Value::string(cairn::hex::encode(&public.id()))),
        ])
    };
    let allowed = entry(&second_bootstrap, "allowed");
    let seeds = first_dir.join("private-seeds.json");
    fs::write(
        &seeds,
        Value::object([(
            "seeds",
            Value::array([allowed.clone(), entry(&stranger_bootstrap, "excluded")]),
        )])
        .canonical_string(),
    )
    .unwrap();
    let mut second = spawn(second_dir, second_p2p, Some(&first_bootstrap));
    wait_for(&mut second, "/network", |_| true);
    let mut first = start(first_dir, first_p2p, address(), None, |cmd| {
        cmd.env("CAIRN_SEEDS", &seeds).env(
            "CAIRN_PEERS",
            allowed.get("transport").unwrap().as_str().unwrap(),
        );
    });
    for node in [&mut first, &mut second] {
        wait_for(node, "/sessions", |value| {
            value["reached"].as_u64().is_some_and(|n| n > 0)
        });
        assert!(!node.dir.join("helper-invoked").exists());
    }
    assert_eq!(
        trap.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock,
        "excluded seed was contacted before its key was allowed"
    );
}

#[test]
fn pinned_peer_identity_survives_impostor_failure_and_restart() {
    let (first_dir, second_dir, impostor_dir) = (scratch(), scratch(), scratch());
    let (first_p2p, second_p2p, second_http) = (address(), address(), address());
    let first_bootstrap = identity(&first_dir, first_p2p);
    let second_bootstrap = identity(&second_dir, second_p2p);
    identity(&impostor_dir, second_p2p);
    let real_key = fs::read(second_dir.join("node.identity.json")).unwrap();
    let pinned = fs::read(&second_bootstrap).unwrap();
    fs::copy(
        impostor_dir.join("node.identity.json"),
        second_dir.join("node.identity.json"),
    )
    .unwrap();
    let mut impostor = start(
        second_dir.clone(),
        second_p2p,
        second_http,
        Some(&first_bootstrap),
        |_| {},
    );
    wait_for(&mut impostor, "/network", |_| true);
    let mut first = spawn(first_dir.clone(), first_p2p, Some(&second_bootstrap));
    let sessions = wait_for(&mut first, "/sessions", |value| {
        value["peers"].as_array().is_some_and(|peers| {
            peers
                .iter()
                .any(|peer| peer["failures"].as_u64().is_some_and(|n| n > 0))
        })
    });
    assert_eq!(sessions["reached"], 0);
    assert_eq!(get(&impostor, "/sessions").unwrap()["reached"], 0);
    let first_key = fs::read(first_dir.join("node.identity.json")).unwrap();
    impostor.stop();
    fs::write(second_dir.join("node.identity.json"), &real_key).unwrap();
    let mut second = start(
        second_dir.clone(),
        second_p2p,
        second_http,
        Some(&first_bootstrap),
        |_| {},
    );
    wait_for(&mut first, "/sessions", |value| {
        value["reached"].as_u64().is_some_and(|n| n > 0)
    });
    wait_for(&mut second, "/sessions", |value| {
        value["reached"].as_u64().is_some_and(|n| n > 0)
    });
    let first_http = first.http;
    first.stop();
    first = start(
        first_dir.clone(),
        first_p2p,
        first_http,
        Some(&second_bootstrap),
        |_| {},
    );
    wait_for(&mut first, "/sessions", |value| {
        value["reached"].as_u64().is_some_and(|n| n > 0)
    });
    assert_eq!(
        fs::read(first_dir.join("node.identity.json")).unwrap(),
        first_key
    );
    assert_eq!(
        fs::read(second_dir.join("node.identity.json")).unwrap(),
        real_key
    );
    assert_eq!(fs::read(second_bootstrap).unwrap(), pinned);
    assert!(!first.dir.join("helper-invoked").exists());
    assert!(!second.dir.join("helper-invoked").exists());
}

#[test]
fn an_explicit_public_profile_keeps_open_peering() {
    let mut node = start(scratch(), address(), address(), None, |cmd| {
        cmd.env("CAIRN_NETWORK", "public")
            .env("CAIRN_SEEDS", "off")
            .env("CAIRN_BEACON_PORT", "off")
            .env("CAIRN_PORTMAP", "off")
            .env("CAIRN_PORTMAP_HTTP", "off");
    });
    let network = wait_for(&mut node, "/network", |_| true);
    assert_eq!(network["node"]["peers_policy"]["policy"], "open");
    assert!(network["node"]["peers_policy"]["allowed"].is_null());
    assert!(
        node.dir.join("helper-invoked").exists(),
        "the public wildcard listener no longer probes its optional tailnet integration"
    );
}

#[test]
fn private_fleet_credentials_and_revocation_survive_process_restarts() {
    use cairn::agent::http::{post_json_as, NodeUrl};
    use cairn::fleet::auth::{parse_key, MemberFile};
    use cairn::fleet::members::Registry;

    let dir = scratch();
    let signing_path = dir.join("leader.identity.json");
    let mut create_identity = command(&dir);
    create_identity
        .args(["identity", "--out"])
        .arg(&signing_path);
    assert!(finishes(create_identity, &dir).status.success());
    let signing_bytes = fs::read(&signing_path).unwrap();
    let signing = Value::from_json(std::str::from_utf8(&signing_bytes).unwrap()).unwrap();
    let leader = parse_key(signing.get("public").unwrap().as_str().unwrap()).unwrap();
    let (p2p, http) = (address(), address());
    let member = MemberFile {
        node: format!("http://{http}"),
        leader,
        name: "private-worker".into(),
        member: cairn::crypto::identity::Identity::generate(&mut rand_core::OsRng),
        expires_at: None,
    };
    let member_path = dir.join("worker/member.json");
    member.save_new(&member_path).unwrap();
    let member_bytes = fs::read(&member_path).unwrap();
    let registry = Registry::for_log(&dir.join("cairn.jsonl"), leader);
    let member_key = member.member.public().to_bytes();
    registry
        .admit(member_key, &member.name, None, cairn::time::unix_seconds())
        .unwrap();
    let configure = |cmd: &mut Command| {
        cmd.env("CAIRN_FLEET", "enrolled")
            .env("CAIRN_FLEET_IDENTITY", &signing_path);
    };
    let mut node = start(dir.clone(), p2p, http, None, configure);
    wait_for(&mut node, "/network", |_| true);
    let transport_bytes = fs::read(dir.join("node.identity.json")).unwrap();
    let root_bytes = fs::read(dir.join("root.key")).unwrap();
    let url = NodeUrl::parse(&member.node).unwrap();
    let host = Value::object([
        ("host", Value::string(&member.name)),
        ("hardware", Value::object([("cpus", Value::Int(2))])),
        ("sandboxes", Value::Object(Default::default())),
        ("jobs", Value::Object(Default::default())),
    ]);
    let post = |credential: Option<&MemberFile>| {
        post_json_as(&url, "/hosts", &host, credential, Duration::from_secs(3)).unwrap()
    };
    assert_eq!(post(Some(&member)).status, 202);
    assert_eq!(
        post(None).status,
        403,
        "loopback reachability bypassed reserved member identity"
    );
    let mut wrong_leader = member.clone();
    wrong_leader.leader = [0x42; 32];
    assert_eq!(
        post(Some(&wrong_leader)).status,
        401,
        "a request signed for another leader was accepted"
    );
    node.stop();
    node = start(dir.clone(), p2p, http, None, configure);
    wait_for(&mut node, "/network", |_| true);
    let reloaded = MemberFile::load(&member_path).unwrap();
    assert_eq!(
        post(Some(&reloaded)).status,
        202,
        "a restart invalidated the enrolled member's existing credential"
    );
    registry
        .revoke(
            &member_key,
            "restart regression test",
            cairn::time::unix_seconds(),
        )
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let response = post(Some(&reloaded));
        if response.status == 401 {
            assert_eq!(
                response.body.get("reason").and_then(Value::as_str),
                Some("member_revoked")
            );
            break;
        }
        assert!(
            Instant::now() < deadline,
            "live process did not observe member revocation: HTTP {} {}",
            response.status,
            response.body.canonical_string()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    node.stop();
    node = start(dir.clone(), p2p, http, None, configure);
    let network = wait_for(&mut node, "/network", |_| true);
    assert_eq!(
        network["node"]["fleet"]["signs_as"],
        cairn::hex::encode(&leader)
    );
    let refused = post(Some(&reloaded));
    assert_eq!(
        refused.status, 401,
        "a restart resurrected revoked membership"
    );
    assert_eq!(
        refused.body.get("reason").and_then(Value::as_str),
        Some("member_revoked")
    );
    assert_eq!(fs::read(&signing_path).unwrap(), signing_bytes);
    assert_eq!(fs::read(&member_path).unwrap(), member_bytes);
    assert_eq!(
        fs::read(dir.join("node.identity.json")).unwrap(),
        transport_bytes
    );
    assert_eq!(fs::read(dir.join("root.key")).unwrap(), root_bytes);
    assert!(!dir.join("helper-invoked").exists());
}
