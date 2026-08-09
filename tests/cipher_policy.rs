//! Two negative claims about the cryptography, checked instead of asserted.
//!
//! > Every node-to-node path is ChaCha20-Poly1305 over a Classic McEliece
//! > handshake. There is no AES anywhere, and no TLS anywhere.
//!
//! That sentence is in `docs/p2p.md`, in `Cargo.toml`, and in the module docs
//! of `p2p::handshake`. It is also the kind of claim that stops being true
//! quietly: nobody adds AES on purpose, they add a crate that wants
//! `aes-gcm` for one field, or a HTTP client that pulls in `rustls`, and the
//! documentation goes on saying what used to be so. A negative property with no
//! test is a negative property with an expiry date.
//!
//! So this reads `Cargo.lock` — the resolved tree, transitive dependencies
//! included, which is the only place the answer actually lives — and fails if a
//! forbidden crate is in it.
//!
//! # Why these two in particular
//!
//! **Not AES**, because without hardware AES-NI it is either slow or a
//! cache-timing side channel, and a research network runs on whatever its
//! participants have: ARM boards, VMs with the instruction masked off, WASM.
//! ChaCha20 is constant-time in software by construction, so there is no
//! deployment in which this crate quietly runs a table-lookup cipher over
//! secret data. One cipher rather than two is the rest of the argument — every
//! AEAD here takes a 32-byte key and a 12-byte nonce and dies the same way on
//! nonce reuse, so that is one rule to enforce rather than one per call site.
//!
//! **Not TLS**, because the peer-to-peer layer authenticates by *key*, not by
//! certificate. A `PeerId` is the SHA-256 of a McEliece public key, so
//! completing a handshake **is** the proof of identity — there is no authority
//! to consult and none to compromise. Adding TLS underneath would add a second
//! trust root (a CA), a second name for a peer (a hostname), and a second
//! handshake to get wrong, in exchange for nothing the transport does not
//! already have. It would also not be post-quantum, which is most of the point.
//!
//! `src/serve.rs` is the deliberate exception and is not node-to-node: it is a
//! local read-only HTTP API whose own docs say to put a reverse proxy in front
//! of it. Terminating TLS there is the operator's business and needs no crate
//! in this tree.

use std::collections::BTreeSet;

/// Crates that would mean an AES implementation is compiled into this binary.
///
/// Names rather than a substring match on "aes": `blake2`, `keccak` and half a
/// dozen others contain the letters, and a check that cries wolf is a check
/// somebody deletes. The list is the RustCrypto AES family plus the modes that
/// only exist to wrap it.
const AES_CRATES: &[&str] = &[
    "aes",
    "aes-gcm",
    "aes-gcm-siv",
    "aes-siv",
    "aes-kw",
    "aesni",
    "aes-soft",
    "aead-aes-gcm",
    "ccm",
    "eax",
    "cmac",
];

/// Crates that would mean a TLS stack is compiled into this binary.
///
/// The three implementations plus the platform bindings, because "we use the
/// system TLS" is still TLS and still a certificate authority this protocol
/// does not want.
const TLS_CRATES: &[&str] = &[
    "rustls",
    "rustls-pemfile",
    "rustls-native-certs",
    "native-tls",
    "openssl",
    "openssl-sys",
    "boring",
    "boring-sys",
    "schannel",
    "security-framework",
    "webpki",
    "webpki-roots",
    "tokio-rustls",
    "tokio-native-tls",
    "hyper-tls",
    "hyper-rustls",
];

/// Every package name in the resolved dependency tree.
///
/// `Cargo.lock` rather than `Cargo.toml`, because a transitive dependency is
/// exactly the way one of these would arrive: nobody writes `aes-gcm` in a
/// manifest, they write something that wants it.
fn locked_packages() -> BTreeSet<String> {
    let lock = include_str!("../Cargo.lock");
    lock.lines()
        .filter_map(|line| line.strip_prefix("name = "))
        .map(|name| name.trim().trim_matches('"').to_string())
        .collect()
}

#[test]
fn no_aes_implementation_is_in_the_dependency_tree() {
    let packages = locked_packages();
    let found: Vec<&str> = AES_CRATES
        .iter()
        .copied()
        .filter(|name| packages.contains(*name))
        .collect();
    assert!(
        found.is_empty(),
        "an AES crate entered the dependency tree: {found:?}\n\
         Every AEAD in this crate is ChaCha20-Poly1305, deliberately -- see the \
         Cargo.toml comment and this file's docs. If AES is genuinely wanted, \
         that is a decision to argue for in the docs and then remove from this \
         list, not a dependency to let in sideways."
    );
}

#[test]
fn no_tls_stack_is_in_the_dependency_tree() {
    let packages = locked_packages();
    let found: Vec<&str> = TLS_CRATES
        .iter()
        .copied()
        .filter(|name| packages.contains(*name))
        .collect();
    assert!(
        found.is_empty(),
        "a TLS crate entered the dependency tree: {found:?}\n\
         The p2p transport authenticates by key -- a PeerId is the SHA-256 of a \
         McEliece public key, so completing a handshake is the proof of \
         identity. TLS would add a certificate authority to trust and a second \
         handshake to get wrong, and would not be post-quantum. `serve.rs` is \
         plain HTTP behind whatever proxy the operator runs."
    );
}

/// The positive control.
///
/// Without it, both tests above would pass on an empty lock file, on a lock
/// file this test failed to parse, and on a build with no cryptography in it at
/// all. A negative assertion that cannot fail is not evidence.
#[test]
fn the_cipher_and_the_kems_that_should_be_there_are() {
    let packages = locked_packages();
    for required in [
        // The one symmetric cipher.
        "chacha20poly1305",
        "chacha20",
        // The mandatory KEM, and the two optional suites.
        "classic-mceliece-rust",
        "ml-kem",
        "hqc-kem",
        // Signatures. Not key exchange -- see `crypto::kem`.
        "ed25519-dalek",
        "ml-dsa",
    ] {
        assert!(
            packages.contains(required),
            "{required} is missing from the lock file, so the negative checks in \
             this file are not proving anything"
        );
    }
    // And the one that was removed on purpose. `x25519-dalek` sealed committee
    // shares until `crypto::kem` replaced it; leaving it in the tree unused
    // would leave it there for the next person to reach for.
    assert!(
        !packages.contains("x25519-dalek"),
        "x25519-dalek is back in the tree. Key exchange in this crate is \
         post-quantum only -- see src/crypto/kem.rs on why a quantum-resistant \
         transport wrapped around an X25519-sealed submission protects nothing."
    );
}
