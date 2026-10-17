//! Real startup with deliberately tempting public discovery settings. Helpers
//! leave a marker if invoked, so an offline-looking startup cannot hide a curl
//! or Tailscale invocation that merely failed.

use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
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
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
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
        .stdin(Stdio::null());
    cmd
}

fn daemon_command(dir: &Path) -> Command {
    let mut cmd = command(dir);
    cmd.arg("--log").arg(dir.join("cairn.jsonl"));
    // Default-feature checks exercise the shared daemon through p2p; an
    // embedded build exercises the complete run entry point used by launchers.
    if cfg!(feature = "ui") {
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
    helpers(&dir);
    let http = address();
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
    cmd.stdout(Stdio::null())
        .stderr(fs::File::create(dir.join("stderr")).unwrap());
    Node {
        child: cmd.spawn().unwrap(),
        dir,
        http,
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
        let output = daemon_command(&dir)
            .env(variable, value)
            .args(["--listen", "127.0.0.1:0", "--serve", "127.0.0.1:0"])
            .output()
            .unwrap();
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
    let output = command(&scratch())
        .args(["run", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("CAIRN_NETWORK=private"));
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
        let output = cmd.output().unwrap();
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
        let output = command(&scratch())
            .env(variable, value)
            .args(["serve", "--listen", "127.0.0.1:0"])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("CAIRN_NETWORK"));
    }
}
