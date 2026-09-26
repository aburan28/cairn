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

/// Send one KRPC datagram and return the reply. This is the live socket: a
/// hint that comes back is still only a hint.
pub fn exchange(
    socket: &std::net::UdpSocket,
    dest: std::net::SocketAddr,
    packet: &[u8],
) -> std::io::Result<Vec<u8>> {
    socket.send_to(packet, dest)?;
    let mut buf = [0u8; 2048];
    let (n, _) = socket.recv_from(&mut buf)?;
    Ok(buf[..n].to_vec())
}

/// BEP 5 compact nodes: 20-byte id, 4-byte IPv4, 2-byte port, repeated.
pub fn parse_compact_nodes(bytes: &[u8]) -> Vec<([u8; 20], std::net::SocketAddr)> {
    let mut out = Vec::new();
    for chunk in bytes.chunks(26) {
        if chunk.len() != 26 {
            break;
        }
        let mut id = [0u8; 20];
        id.copy_from_slice(&chunk[..20]);
        let ip = std::net::Ipv4Addr::new(chunk[20], chunk[21], chunk[22], chunk[23]);
        let port = u16::from_be_bytes([chunk[24], chunk[25]]);
        out.push((id, std::net::SocketAddr::from((ip, port))));
    }
    out
}

/// `CAIRN_MAINLINE=1` asks a public bootstrap. Unset, the daemon does not
/// open this socket: a test must not depend on `router.bittorrent.com`.
pub const MAINLINE_ENV: &str = "CAIRN_MAINLINE";

pub fn enabled_from_env() -> bool {
    matches!(
        std::env::var(MAINLINE_ENV).ok().as_deref().map(str::trim),
        Some("1") | Some("on") | Some("true")
    )
}

/// What a bootstrap reply contained. The addresses are dial hints.
pub struct BootstrapReply {
    pub bytes: usize,
    pub nodes: Vec<std::net::SocketAddr>,
}

/// The compact-node blob after a bencoded `nodes` key, if the packet has one.
pub fn extract_compact_nodes(packet: &[u8]) -> Option<&[u8]> {
    let key = b"5:nodes";
    let pos = packet.windows(key.len()).position(|window| window == key)?;
    let rest = &packet[pos + key.len()..];
    let colon = rest.iter().position(|byte| *byte == b':')?;
    if colon == 0 || colon > 8 {
        return None;
    }
    let len: usize = std::str::from_utf8(&rest[..colon]).ok()?.parse().ok()?;
    let start = colon + 1;
    rest.get(start..start.checked_add(len)?)
}

/// Ask a Mainline bootstrap for nodes near this epoch's announce key.
/// Failure is a missing rendezvous, not a failed handshake.
pub fn find_bootstrap(epoch: u64) -> std::io::Result<BootstrapReply> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(std::time::Duration::from_secs(3)))?;
    let id = [0u8; 20];
    let target = infohash(epoch, false);
    let packet = query(b"cn", "find_node", &id, Some(&target));
    let reply = exchange(
        &socket,
        "router.bittorrent.com:6881".parse().expect("addr"),
        &packet,
    )?;
    let nodes = extract_compact_nodes(&reply)
        .map(parse_compact_nodes)
        .unwrap_or_default()
        .into_iter()
        .map(|(_, addr)| addr)
        .collect();
    Ok(BootstrapReply {
        bytes: reply.len(),
        nodes,
    })
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

    #[test]
    fn two_sockets_exchange_a_krpc_datagram() {
        let left = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let right = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        left.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        right
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let packet = query(b"aa", "ping", &[9u8; 20], None);
        let reply = std::thread::scope(|scope| {
            let right = &right;
            scope.spawn(|| {
                let mut buf = [0u8; 256];
                let (n, from) = right.recv_from(&mut buf).unwrap();
                right.send_to(&buf[..n], from).unwrap();
            });
            exchange(&left, right.local_addr().unwrap(), &packet).unwrap()
        });
        assert_eq!(reply, packet);
    }

    #[test]
    fn a_bencoded_nodes_field_yields_the_compact_blob() {
        let mut packet = b"d1:rd2:id20:".to_vec();
        packet.extend_from_slice(&[b'_'; 20]);
        packet.extend_from_slice(b"5:nodes26:");
        packet.extend_from_slice(&[7u8; 20]);
        packet.extend_from_slice(&[127, 0, 0, 1, 0x23, 0x28]);
        packet.extend_from_slice(b"e1:t2:cn1:y1:re");
        let blob = extract_compact_nodes(&packet).expect("nodes");
        let nodes = parse_compact_nodes(blob);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].1.to_string(), "127.0.0.1:9000");
        assert!(extract_compact_nodes(b"d1:y1:ee").is_none());
    }

    #[test]
    fn compact_nodes_decode_to_addresses() {
        let mut bytes = vec![7u8; 20];
        bytes.extend_from_slice(&[127, 0, 0, 1, 0x23, 0x28]);
        let nodes = parse_compact_nodes(&bytes);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].1.to_string(), "127.0.0.1:9000");
    }
}
