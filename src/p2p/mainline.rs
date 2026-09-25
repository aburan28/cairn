//! Mainline DHT rendezvous keys.
//!
//! BEP 5 announces under a 20-byte infohash. That hash is a meeting place, not
//! a security boundary: SHA-1 is fine here and is not used for record ids.
//! The announce key rotates with the epoch so one crawler key cannot enumerate
//! the network forever. `CAIRN_DHT_STATIC=1` keeps a fixed key for operators
//! who need a stable rendezvous during a demo.
//!
//! This module derives the key and builds a KRPC `ping` / `find_node` query.
//! It does not open UDP by itself — the daemon does that when
//! `CAIRN_MAINLINE=1`. A hint that comes back is still only a hint: the
//! handshake decides who answered.

use sha2::{Digest, Sha256};

/// Network name mixed into every infohash so this rendezvous is not BitTorrent's.
pub const NETWORK: &[u8] = b"cairn/mainline/v1";

/// 20-byte infohash for `epoch`. `static_key` ignores the epoch.
pub fn infohash(epoch: u64, static_key: bool) -> [u8; 20] {
    let mut hasher = Sha256::new();
    hasher.update(NETWORK);
    if static_key {
        hasher.update(b"static");
    } else {
        hasher.update(epoch.to_be_bytes());
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest[..20]);
    out
}

/// Bencode a KRPC query. `id` is the 20-byte DHT node id (truncated peer id).
pub fn query(
    transaction: &[u8],
    method: &str,
    node_id: &[u8; 20],
    target: Option<&[u8; 20]>,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"d");
    push_kv(&mut out, b"a", |out| {
        out.extend_from_slice(b"d");
        push_bytes_kv(out, b"id", node_id);
        if let Some(target) = target {
            push_bytes_kv(out, b"target", target);
        }
        out.extend_from_slice(b"e");
    });
    push_str_kv(&mut out, b"q", method.as_bytes());
    push_bytes_kv(&mut out, b"t", transaction);
    push_str_kv(&mut out, b"y", b"q");
    out.extend_from_slice(b"e");
    out
}

fn push_kv(out: &mut Vec<u8>, key: &[u8], value: impl FnOnce(&mut Vec<u8>)) {
    push_str(out, key);
    value(out);
}

fn push_str_kv(out: &mut Vec<u8>, key: &[u8], value: &[u8]) {
    push_str(out, key);
    push_str(out, value);
}

fn push_bytes_kv(out: &mut Vec<u8>, key: &[u8], value: &[u8]) {
    push_str(out, key);
    push_str(out, value);
}

fn push_str(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(bytes.len().to_string().as_bytes());
    out.push(b':');
    out.extend_from_slice(bytes);
}

/// First 20 bytes of a peer id, which is what a DHT node id is.
pub fn node_id_from_peer(peer: &[u8; 32]) -> [u8; 20] {
    let mut out = [0u8; 20];
    out.copy_from_slice(&peer[..20]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_announce_key_rotates_with_the_epoch_unless_asked_not_to() {
        assert_ne!(infohash(1, false), infohash(2, false));
        assert_eq!(infohash(1, true), infohash(2, true));
        assert_eq!(infohash(1, false).len(), 20);
    }

    #[test]
    fn a_find_node_query_is_bencoded_and_names_the_method() {
        let id = [1u8; 20];
        let target = [2u8; 20];
        let query = query(b"aa", "find_node", &id, Some(&target));
        let text = String::from_utf8_lossy(&query);
        assert!(text.contains("find_node"), "{text}");
        assert!(query.starts_with(b"d"));
        assert!(query.ends_with(b"e"));
    }
}
