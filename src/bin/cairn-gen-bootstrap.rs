//! Generate a `--bootstrap` file for `cairn-p2p`.
//!
//! A bootstrap file is canonical JSON of the form
//! `{"addr":"host:port","public":"<hex McEliece public key>"}` (see
//! `docs/p2p.md`). The address is only ever a hint — `p2p::handshake`
//! authenticates the *key*, not the socket it answered on — so this tool
//! cannot make a real remote peer trustworthy. What it can do is produce a
//! structurally valid file for an address you intend to point at, with a
//! freshly generated keypair standing in until you have the peer's real
//! public key to swap in.
//!
//! The matching secret is written alongside so the file pair is a usable
//! identity (e.g. for a second local node acting as a seed), not a public key
//! with no secret anywhere.

use cairn::canonical::Value;
use cairn::p2p::handshake::PeerIdentity;
use std::env;
use std::fs;
use std::path::Path;

/// Print the usage and exit with `code`.
///
/// `--help` exits 0 and a bad or missing argument exits 2, matching
/// `cairn-p2p`. This binary answered 2 to everything including `--help`,
/// and nothing noticed because the packaging check in `.github/workflows/ci.yml`
/// listed the other binaries and not this one. The release workflow now runs
/// `--help` on every binary it ships, which is what caught it.
fn usage(code: i32) -> ! {
    eprintln!("usage: cairn-gen-bootstrap --addr HOST:PORT --out FILE [--identity-out FILE]");
    std::process::exit(code);
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A host and a port, without deciding what the host means.
///
/// `[::1]:9000` splits at the last colon, which is why this uses `rsplit_once`
/// rather than counting them.
fn is_host_port(addr: &str) -> bool {
    match addr.rsplit_once(':') {
        Some((host, port)) => !host.is_empty() && port.parse::<u16>().is_ok_and(|p| p != 0),
        None => false,
    }
}

fn main() {
    let mut addr = None;
    let mut out = None;
    let mut identity_out = None;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--help" || arg == "-h" {
            usage(0);
        }
        let slot = match arg.as_str() {
            "--addr" => &mut addr,
            "--out" => &mut out,
            "--identity-out" => &mut identity_out,
            _ => usage(2),
        };
        *slot = Some(args.next().unwrap_or_else(|| usage(2)));
    }
    let addr = addr.unwrap_or_else(|| usage(2));
    let out = out.unwrap_or_else(|| usage(2));
    // Shape only, and deliberately not `SocketAddr::parse`: this tool writes
    // config for a host that may be down, or not yet built, so resolving here
    // would refuse a perfectly good file for a peer that is merely offline.
    // A hostname is a legal address everywhere it is dialled -- see
    // `p2p::discovery::dialable` -- and the usage line has always said
    // HOST:PORT, so refusing a name here contradicted both the daemon and this
    // program's own help text.
    if !is_host_port(&addr) {
        eprintln!("--addr {addr:?} is not a host:port address");
        std::process::exit(2);
    }

    let identity = PeerIdentity::generate();
    let public_hex = hex_encode(identity.public_key());

    // `placeholder_peer_id` is what lets the *daemon* say this file is not
    // finished yet, rather than only this program saying it once at generation
    // time and scrolling away in build output. A peer id is
    // `sha256(public key)`, so `cairn-p2p` recomputes it from whatever
    // `public` currently holds and warns only while the two still match --
    // which means the warning **clears itself** the moment somebody pastes the
    // real key in, with nothing to remember to delete. Extra fields are
    // ignored by every reader (`load_endpoint` takes `addr` and `public`), and
    // a bootstrap file is local configuration that never enters the log, so
    // this is not a record-format change.
    let bootstrap = Value::object([
        ("addr", Value::string(addr)),
        ("public", Value::string(public_hex.clone())),
        (
            "placeholder_peer_id",
            Value::string(cairn::p2p::discovery::peer_id_string(
                &identity.to_public().id(),
            )),
        ),
    ]);
    fs::write(&out, bootstrap.canonical_string()).unwrap_or_else(|e| {
        eprintln!("{out}: {e}");
        std::process::exit(2)
    });
    eprintln!("wrote bootstrap file: {out}");

    if let Some(identity_out) = identity_out {
        let identity_value = Value::object([
            ("public", Value::string(public_hex)),
            ("secret", Value::string(hex_encode(identity.secret_key()))),
        ]);
        cairn::secret_file::write_new(
            Path::new(&identity_out),
            identity_value.canonical_string().as_bytes(),
        )
        .unwrap_or_else(|e| {
            eprintln!("{identity_out}: {e}");
            std::process::exit(2)
        });
        eprintln!("wrote matching identity file: {identity_out}");
    }

    eprintln!(
        "note: this key is freshly generated, not the real seed peer's -- \
         replace \"public\" in {out} with the seed's actual public key once you have it, \
         or run the seed's own cairn-p2p with --identity {out} pointed here if you \
         control that host."
    );
}
