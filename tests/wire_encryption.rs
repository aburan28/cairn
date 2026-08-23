//! Everything a `p2p` session sends is encrypted, checked by reading the wire.
//!
//! The claim "frames go through an AEAD" is made in several module doc comments
//! and is the kind of claim that stays true until somebody adds a round that
//! writes to the socket directly. `p2p::dht` was such a round. So this test does
//! not read the code: it puts a recording relay between two real nodes, runs a
//! full session through it, and asserts that content the session certainly
//! carried never appears in the bytes.
//!
//! The relay is a plain byte pump. The handshake is end-to-end between the two
//! peers, so relaying does not break it — which is itself the point: an attacker
//! positioned exactly here learns nothing but sizes and timing.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;

use cairn::canonical::Value;
use cairn::ledger::Ledger;
use cairn::node::Node;
use cairn::p2p::discovery::Endpoint;
use cairn::p2p::handshake::PeerIdentity;
use cairn::p2p::service::Service;
use cairn::records::Objective;

const TS: &str = "2026-07-29T00:00:00+00:00";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn scratch(name: &str) -> PathBuf {
    let dir = repo_root().join("target").join("wire-tests");
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let path = dir.join(format!("{name}.jsonl"));
    let _ = std::fs::remove_file(&path);
    path
}

fn capset_objective() -> Objective {
    let text = std::fs::read_to_string(repo_root().join("examples/capset/objective.json"))
        .expect("read the shipped objective");
    Objective::from_value(&Value::from_json(&text).expect("parse")).expect("decode")
}

/// Copy bytes from `from` to `to`, appending everything seen to `log`.
fn relay(mut from: TcpStream, mut to: TcpStream, log: Arc<Mutex<Vec<u8>>>) {
    let mut buffer = [0u8; 8192];
    loop {
        match from.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                log.lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .extend_from_slice(&buffer[..n]);
                if to.write_all(&buffer[..n]).is_err() {
                    break;
                }
            }
        }
    }
    // Half-close so the far side sees the end of the stream rather than hanging.
    let _ = to.shutdown(std::net::Shutdown::Write);
}

/// Accept one connection, splice it to `upstream`, and record both directions.
fn recording_relay(listener: TcpListener, upstream: SocketAddr) -> Arc<Mutex<Vec<u8>>> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&seen);
    thread::spawn(move || {
        let (inbound, _) = listener.accept().expect("relay accept");
        let outbound = TcpStream::connect(upstream).expect("relay dial");
        // Both directions at once. Splicing them in sequence deadlocks: the
        // first reply would have nothing carrying it back while the forward
        // direction is still open, which is every session.
        let forward = {
            let (from, to) = (
                inbound.try_clone().expect("clone"),
                outbound.try_clone().expect("clone"),
            );
            let log = Arc::clone(&recorded);
            thread::spawn(move || relay(from, to, log))
        };
        relay(outbound, inbound, recorded);
        let _ = forward.join();
    });
    seen
}

#[test]
fn nothing_a_session_carries_appears_in_the_bytes_on_the_wire() {
    let objective = capset_objective();

    let bob_identity = Arc::new(PeerIdentity::generate());
    let bob_public = bob_identity.to_public();
    let bob_service = Service::new(bob_identity);
    let bob_listener = bob_service
        .listen("127.0.0.1:0".parse().expect("loopback"))
        .expect("listen");
    let bob_addr = bob_listener.local_addr().expect("bound");

    // The relay stands where a network adversary would.
    let relay_listener = TcpListener::bind("127.0.0.1:0").expect("relay bind");
    let relay_addr = relay_listener.local_addr().expect("bound");
    let captured = recording_relay(relay_listener, bob_addr);

    let bob_objective = objective.clone();
    let bob_thread = thread::spawn(move || {
        let mut bob = Node::new(
            Ledger::open(scratch("bob-wire")).expect("open ledger"),
            repo_root(),
        );
        bob.post_objective(&bob_objective, TS).expect("post");
        assert!(bob.publish_local_code() > 0, "bob has nothing to serve");
        let held = bob.registry().blobs().addresses();
        bob_service
            .accept_node_once(&bob_listener, &mut bob)
            .expect("bob's session");
        held
    });

    // Alice's verifier root is empty, so she genuinely needs the checker: the
    // session carries a want, a blob, and a DHT ask/tell about the same address.
    let empty_root = repo_root()
        .join("target")
        .join("wire-tests")
        .join("no-root");
    let _ = std::fs::remove_dir_all(&empty_root);
    std::fs::create_dir_all(&empty_root).expect("empty root");
    let mut alice = Node::new(
        Ledger::open(scratch("alice-wire")).expect("open ledger"),
        empty_root,
    );
    alice.post_objective(&objective, TS).expect("post");
    assert!(
        !alice.missing_code().is_empty(),
        "alice needs nothing, so the session would carry no blob traffic"
    );

    let alice_identity = Arc::new(PeerIdentity::generate());
    let alice_key_prefix = alice_identity.public_key()[..64].to_vec();
    let alice_service = Service::new(alice_identity);
    alice_service
        .dial_node_once(&Endpoint::new(relay_addr, bob_public), &mut alice)
        .expect("alice's session");

    let held = bob_thread.join().expect("bob's thread");
    let address = held.first().expect("bob holds a blob").clone();

    // Give the relay a moment to drain, then take what it saw.
    let bytes = loop {
        let seen = captured.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if !seen.is_empty() {
            break seen;
        }
        thread::yield_now();
    };

    assert!(
        bytes.len() > 1_000,
        "the relay captured only {} bytes; it was not in the path",
        bytes.len()
    );

    // Positive control, and an honest disclosure in one assertion.
    //
    // The control: without it, every "does not appear" below would also pass on
    // an empty or misdirected capture, and the test would be checking nothing.
    // The disclosure: the handshake prefix genuinely *is* cleartext — an
    // initiator sends its long-term public key so the responder can derive and
    // authenticate its id before any application state is released.
    // Unlinkability is a transport-layer problem this design does not solve;
    // `docs/threat-model.md` says so under topology mapping.
    assert!(
        contains(&bytes, &alice_key_prefix),
        "the initiator's public key should be visible in the handshake -- if it is \
         not, this capture is not the session and the assertions below prove \
         nothing"
    );

    // The blob address travelled at least three times in this session: as a pin
    // inside the objective record, as a `code_want`, and as a `dht_ask`. If any
    // of those reached the socket unencrypted it is in here.
    let haystack = bytes.as_slice();
    assert!(
        !contains(haystack, address.as_bytes()),
        "the blob's content address appears in cleartext on the wire"
    );

    // Message-type tags, one per family. These are the strings a decoder matches
    // on, so finding one means that family's frames are not sealed.
    for tag in [
        &b"dht_ask"[..],
        b"dht_tell",
        b"code_want",
        b"code_blobs",
        b"objective",
        b"capset",
    ] {
        assert!(
            !contains(haystack, tag),
            "{:?} appears in cleartext on the wire",
            std::str::from_utf8(tag).unwrap_or("<bytes>")
        );
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
