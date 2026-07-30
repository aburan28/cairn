//! Long-running p2p node.
//!
//! Identity files and bootstrap files are local configuration. They are never
//! placed in the append-only ledger.

use proofwork::canonical::Value;
use proofwork::ledger::Ledger;
use proofwork::node::Node;
use proofwork::p2p::discovery::Endpoint;
use proofwork::p2p::handshake::{PeerIdentity, PeerPublic};
use proofwork::p2p::service::Service;
use std::env;
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

fn usage() -> ! {
    eprintln!("usage: proofwork-p2p --identity FILE --listen ADDR --log FILE --root DIR [--bootstrap FILE ...]");
    std::process::exit(2);
}

fn hex_decode(text: &str) -> Result<Vec<u8>, String> {
    if text.len() % 2 != 0 {
        return Err("hex has odd length".into());
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    for i in (0..text.len()).step_by(2) {
        out.push(u8::from_str_radix(&text[i..i + 2], 16).map_err(|_| "invalid hex")?);
    }
    Ok(out)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn load_identity(path: &Path) -> Result<PeerIdentity, String> {
    if !path.exists() {
        let identity = PeerIdentity::generate();
        let value = Value::object([
            ("public", Value::string(hex_encode(identity.public_key()))),
            ("secret", Value::string(hex_encode(identity.secret_key()))),
        ]);
        fs::write(path, value.canonical_string()).map_err(|e| e.to_string())?;
        return Ok(identity);
    }
    let value = Value::from_json(&fs::read_to_string(path).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let public = hex_decode(
        value
            .get("public")
            .and_then(Value::as_str)
            .ok_or("identity.public missing")?,
    )?;
    let secret = hex_decode(
        value
            .get("secret")
            .and_then(Value::as_str)
            .ok_or("identity.secret missing")?,
    )?;
    PeerIdentity::from_bytes(&public, &secret).map_err(|e| e.to_string())
}

fn load_endpoint(path: &Path) -> Result<Endpoint, String> {
    let value = Value::from_json(&fs::read_to_string(path).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let addr = value
        .get("addr")
        .and_then(Value::as_str)
        .ok_or("bootstrap.addr missing")?
        .parse::<SocketAddr>()
        .map_err(|e| e.to_string())?;
    let public = hex_decode(
        value
            .get("public")
            .and_then(Value::as_str)
            .ok_or("bootstrap.public missing")?,
    )?;
    let peer = PeerPublic::from_bytes(&public).map_err(|e| e.to_string())?;
    Ok(Endpoint::new(addr, peer))
}

fn main() {
    let mut identity_path = None;
    let mut listen_addr = None;
    let mut log = None;
    let mut root = None;
    let mut bootstrap = Vec::new();
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        let slot = match arg.as_str() {
            "--identity" => &mut identity_path,
            "--listen" => &mut listen_addr,
            "--log" => &mut log,
            "--root" => &mut root,
            "--bootstrap" => {
                bootstrap.push(args.next().unwrap_or_else(|| usage()));
                continue;
            }
            _ => usage(),
        };
        *slot = Some(args.next().unwrap_or_else(|| usage()));
    }
    let identity_path = identity_path.unwrap_or_else(|| usage());
    let listen_addr = listen_addr
        .unwrap_or_else(|| usage())
        .parse::<SocketAddr>()
        .unwrap_or_else(|_| usage());
    let log = log.unwrap_or_else(|| usage());
    let root = root.unwrap_or_else(|| usage());
    let identity = Arc::new(
        load_identity(Path::new(&identity_path)).unwrap_or_else(|e| {
            eprintln!("identity: {e}");
            std::process::exit(2)
        }),
    );
    let mut service = Service::new(Arc::clone(&identity));
    for path in bootstrap {
        match load_endpoint(Path::new(&path)) {
            Ok(endpoint) => service.add_bootstrap(endpoint),
            Err(error) => {
                eprintln!("bootstrap {path}: {error}");
                std::process::exit(2);
            }
        }
    }
    let listener = service.listen(listen_addr).unwrap_or_else(|e| {
        eprintln!("listen: {e}");
        std::process::exit(2)
    });
    let node = Arc::new(Mutex::new(Node::new(
        Ledger::open(log).unwrap_or_else(|e| {
            eprintln!("ledger: {e}");
            std::process::exit(2)
        }),
        root,
    )));
    let service = Arc::new(service);
    let accept_service = Arc::clone(&service);
    let accept_node = Arc::clone(&node);
    thread::spawn(move || loop {
        let mut guard = accept_node
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Err(error) = accept_service.accept_node_once(&listener, &mut guard) {
            eprintln!("inbound session: {error}");
        }
    });

    loop {
        for endpoint in service
            .address_book()
            .endpoints()
            .cloned()
            .collect::<Vec<_>>()
        {
            let mut guard = node.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Err(error) = service.dial_node_once(&endpoint, &mut guard) {
                eprintln!("outbound session: {error}");
            }
        }
        thread::sleep(Duration::from_secs(5));
    }
}
