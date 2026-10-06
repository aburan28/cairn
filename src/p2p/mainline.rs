//! Mainline DHT rendezvous keys.
//!
//! BEP 5 announces under a 20-byte infohash. That hash is a meeting place, not
//! a security boundary: SHA-1 is fine here and is not used for record ids.
//! The announce key rotates with the epoch so one crawler key cannot enumerate
//! the network forever. `CAIRN_DHT_STATIC=1` keeps a fixed key for operators
//! who need a stable rendezvous during a demo.
//!
//! [`meet`] asks a bootstrap for peers under this epoch's key and announces
//! the caller's port. What comes back is a dial hint; the handshake decides
//! who answered. The daemon does this only when `CAIRN_MAINLINE=1`. Tests
//! speak the same queries to an in-process rendezvous, so CI does not dial
//! `router.bittorrent.com`.
//!
//! The walk stops at the bootstrap's own neighbourhood. That is enough when
//! the bootstrap stores the key, which is what the in-process rendezvous does.
//! It is not a full iterative lookup, and a green test here is not evidence
//! that two nodes met on the public DHT.

#[cfg(test)]
use std::collections::BTreeMap;
use std::io;
#[cfg(test)]
use std::io::ErrorKind;
#[cfg(test)]
use std::net::IpAddr;
#[cfg(test)]
use std::net::SocketAddrV4;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
#[cfg(test)]
use std::sync::Mutex;
use std::time::Duration;

use sha2::{Digest, Sha256};

/// How many contacts [`meet`] asks. Three is a neighbourhood, not a walk to
/// the closest nodes on the public DHT.
const WALK_WIDTH: usize = 3;

/// Announces kept per infohash. Past this the rendezvous refuses new ones
/// rather than evicting: eviction is how a flood displaces an honest hint.
#[cfg(test)]
const PEERS_PER_KEY: usize = 32;

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

fn push_int_kv(out: &mut Vec<u8>, key: &[u8], value: u64) {
    push_str(out, key);
    out.push(b'i');
    out.extend_from_slice(value.to_string().as_bytes());
    out.push(b'e');
}

fn query_arguments(transaction: &[u8], method: &str, fill: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"d");
    push_kv(&mut out, b"a", |out| {
        out.extend_from_slice(b"d");
        fill(out);
        out.extend_from_slice(b"e");
    });
    push_str_kv(&mut out, b"q", method.as_bytes());
    push_bytes_kv(&mut out, b"t", transaction);
    push_str_kv(&mut out, b"y", b"q");
    out.extend_from_slice(b"e");
    out
}

#[cfg(test)]
fn response(transaction: &[u8], fill: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"d");
    push_kv(&mut out, b"r", |out| {
        out.extend_from_slice(b"d");
        fill(out);
        out.extend_from_slice(b"e");
    });
    push_bytes_kv(&mut out, b"t", transaction);
    push_str_kv(&mut out, b"y", b"r");
    out.extend_from_slice(b"e");
    out
}

/// `get_peers` for `infohash`. Keys inside `a` are sorted, which is what a
/// bencode reader requires of a dict.
pub fn get_peers_query(transaction: &[u8], node_id: &[u8; 20], infohash: &[u8; 20]) -> Vec<u8> {
    query_arguments(transaction, "get_peers", |out| {
        push_bytes_kv(out, b"id", node_id);
        push_bytes_kv(out, b"info_hash", infohash);
    })
}

/// `announce_peer`. `port` is the port to publish; the IP is whatever the
/// rendezvous sees as the source, which is BEP 5 and not something the query
/// can choose.
pub fn announce_query(
    transaction: &[u8],
    node_id: &[u8; 20],
    infohash: &[u8; 20],
    port: u16,
    token: &[u8],
) -> Vec<u8> {
    query_arguments(transaction, "announce_peer", |out| {
        push_bytes_kv(out, b"id", node_id);
        push_bytes_kv(out, b"info_hash", infohash);
        push_int_kv(out, b"port", u64::from(port));
        push_bytes_kv(out, b"token", token);
    })
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

/// `CAIRN_DHT_STATIC=1` keeps one announce key across epochs. The rotating key
/// is the default: a single crawler key would enumerate the network forever.
pub const STATIC_ENV: &str = "CAIRN_DHT_STATIC";

pub fn static_rendezvous(flag: Option<&str>) -> bool {
    matches!(flag.map(str::trim), Some("1") | Some("on") | Some("true"))
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

/// Ask `bootstrap` who has announced under this epoch's key, then announce
/// `port`. `static_key` ignores the epoch, which is what
/// [`STATIC_ENV`] asks for. Returns the addresses the neighbourhood already
/// held. Empty is a rendezvous with nobody else on it, not an error; an error
/// is a bootstrap that did not answer the first `find_node`.
pub fn meet(
    bootstrap: SocketAddr,
    node_id: [u8; 20],
    epoch: u64,
    port: u16,
    static_key: bool,
) -> io::Result<Vec<SocketAddr>> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    let hash = infohash(epoch, static_key);
    let find = query(b"fn", "find_node", &node_id, Some(&hash));
    let reply = exchange(&socket, bootstrap, &find)?;
    let mut contacts: Vec<SocketAddr> = extract_compact_nodes(&reply)
        .map(parse_compact_nodes)
        .unwrap_or_default()
        .into_iter()
        .map(|(_, addr)| addr)
        .filter(|addr| addr.port() != 0 && !addr.ip().is_unspecified())
        .take(WALK_WIDTH)
        .collect();
    if !contacts.contains(&bootstrap) {
        contacts.insert(0, bootstrap);
        contacts.truncate(WALK_WIDTH);
    }
    socket.set_read_timeout(Some(Duration::from_secs(1)))?;
    let mut found = Vec::new();
    for contact in contacts {
        let query = get_peers_query(b"gp", &node_id, &hash);
        let Ok(reply) = exchange(&socket, contact, &query) else {
            continue;
        };
        collect_peers(&reply, &mut found);
        let Some(token) = extract_field(&reply, "token") else {
            continue;
        };
        let announce = announce_query(b"ap", &node_id, &hash, port, token);
        if exchange(&socket, contact, &announce).is_err() {
            continue;
        }
        let again = get_peers_query(b"g2", &node_id, &hash);
        if let Ok(reply) = exchange(&socket, contact, &again) {
            collect_peers(&reply, &mut found);
        }
    }
    found.sort();
    found.dedup();
    Ok(found)
}

/// The public bootstrap. Only the daemon calls this, and only when
/// `CAIRN_MAINLINE` is set. A unit test must call [`meet`] on a local socket.
pub fn meet_public(epoch: u64, port: u16) -> io::Result<Vec<SocketAddr>> {
    let bootstrap: SocketAddr = "router.bittorrent.com:6881"
        .parse()
        .expect("bootstrap address");
    let flag = std::env::var(STATIC_ENV).ok();
    meet(
        bootstrap,
        [7u8; 20],
        epoch,
        port,
        static_rendezvous(flag.as_deref()),
    )
}

fn collect_peers(packet: &[u8], found: &mut Vec<SocketAddr>) {
    for addr in extract_values(packet) {
        if addr.port() == 0 || addr.ip().is_unspecified() {
            continue;
        }
        if !found.contains(&addr) {
            found.push(addr);
        }
    }
}

/// Bytes after a bencode string key. A scanner, not a parser: a hint list is
/// untrusted either way, and the same scanner already reads `nodes`.
fn extract_field<'a>(packet: &'a [u8], key: &str) -> Option<&'a [u8]> {
    let marker = format!("{}:{key}", key.len());
    let pos = packet
        .windows(marker.len())
        .position(|window| window == marker.as_bytes())?;
    let rest = &packet[pos + marker.len()..];
    match rest.first() {
        Some(b'i' | b'l' | b'd') | None => return None,
        Some(_) => {}
    }
    let colon = rest.iter().position(|byte| *byte == b':')?;
    if colon == 0 || colon > 8 {
        return None;
    }
    let len: usize = std::str::from_utf8(&rest[..colon]).ok()?.parse().ok()?;
    let start = colon + 1;
    rest.get(start..start.checked_add(len)?)
}

#[cfg(test)]
fn extract_port(packet: &[u8]) -> Option<u16> {
    let marker = b"4:porti";
    let pos = packet
        .windows(marker.len())
        .position(|window| window == marker)?;
    let rest = &packet[pos + marker.len()..];
    let end = rest.iter().position(|byte| *byte == b'e')?;
    let value: u64 = std::str::from_utf8(&rest[..end]).ok()?.parse().ok()?;
    u16::try_from(value).ok().filter(|port| *port != 0)
}

/// Compact IPv4 peers from a `values` list: `6:` plus 4-byte address and port.
pub fn extract_values(packet: &[u8]) -> Vec<SocketAddr> {
    let marker = b"6:values";
    let Some(pos) = packet
        .windows(marker.len())
        .position(|window| window == marker)
    else {
        return Vec::new();
    };
    let mut rest = &packet[pos + marker.len()..];
    if rest.first() != Some(&b'l') {
        return Vec::new();
    }
    rest = &rest[1..];
    let mut out = Vec::new();
    while !rest.is_empty() && rest.first() != Some(&b'e') {
        if !rest.starts_with(b"6:") || rest.len() < 8 {
            break;
        }
        let ip = Ipv4Addr::new(rest[2], rest[3], rest[4], rest[5]);
        let port = u16::from_be_bytes([rest[6], rest[7]]);
        out.push(SocketAddr::from((ip, port)));
        rest = &rest[8..];
    }
    out
}

#[cfg(test)]
fn token_for(infohash: &[u8; 20], ip: IpAddr) -> [u8; 8] {
    let mut hasher = Sha256::new();
    hasher.update(b"cairn/mainline/token/v1");
    hasher.update(infohash);
    match ip {
        IpAddr::V4(ip) => hasher.update(ip.octets()),
        IpAddr::V6(ip) => hasher.update(ip.octets()),
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

/// A single-node rendezvous that stores `announce_peer` and answers
/// `get_peers`. It exists so two cairn nodes can learn each other's address
/// without a seed list and without the public DHT. It is not a Kademlia
/// routing table.
#[cfg(test)]
struct Rendezvous {
    socket: UdpSocket,
    id: [u8; 20],
    peers: Mutex<BTreeMap<[u8; 20], Vec<SocketAddrV4>>>,
}

#[cfg(test)]
impl Rendezvous {
    fn bind(addr: &str) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr)?;
        socket.set_read_timeout(Some(Duration::from_millis(200)))?;
        Ok(Self {
            socket,
            id: [0xA5; 20],
            peers: Mutex::new(BTreeMap::new()),
        })
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    fn serve_one(&self) -> io::Result<bool> {
        let mut buf = [0u8; 2048];
        let (n, from) = match self.socket.recv_from(&mut buf) {
            Ok(got) => got,
            Err(error)
                if error.kind() == ErrorKind::WouldBlock || error.kind() == ErrorKind::TimedOut =>
            {
                return Ok(false);
            }
            Err(error) => return Err(error),
        };
        if let Some(reply) = self.respond(&buf[..n], from) {
            self.socket.send_to(&reply, from)?;
        }
        Ok(true)
    }

    fn respond(&self, packet: &[u8], from: SocketAddr) -> Option<Vec<u8>> {
        let tx = extract_field(packet, "t")?;
        let method = extract_field(packet, "q")?;
        match method {
            b"ping" => Some(response(tx, |out| push_bytes_kv(out, b"id", &self.id))),
            b"find_node" => {
                let contact = self.contact_addr()?;
                Some(find_node_response(tx, &self.id, contact))
            }
            b"get_peers" => {
                let hash = infohash_of(packet)?;
                let token = token_for(&hash, from.ip());
                let peers = self.peers_for(&hash);
                Some(get_peers_response(tx, &self.id, &token, &peers))
            }
            b"announce_peer" => {
                let hash = infohash_of(packet)?;
                let expected = token_for(&hash, from.ip());
                if extract_field(packet, "token") == Some(expected.as_slice()) {
                    if let Some(peer) = announced_peer(packet, from) {
                        self.remember(hash, peer);
                    }
                }
                Some(response(tx, |out| push_bytes_kv(out, b"id", &self.id)))
            }
            _ => None,
        }
    }

    fn contact_addr(&self) -> Option<SocketAddrV4> {
        let local = self.socket.local_addr().ok()?;
        let ip = match local.ip() {
            IpAddr::V4(ip) if !ip.is_unspecified() => ip,
            IpAddr::V4(_) => Ipv4Addr::LOCALHOST,
            IpAddr::V6(_) => return None,
        };
        Some(SocketAddrV4::new(ip, local.port()))
    }

    fn peers_for(&self, hash: &[u8; 20]) -> Vec<SocketAddrV4> {
        self.peers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(hash)
            .cloned()
            .unwrap_or_default()
    }

    fn remember(&self, hash: [u8; 20], peer: SocketAddrV4) {
        let mut peers = self
            .peers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let slot = peers.entry(hash).or_default();
        if slot.contains(&peer) || slot.len() >= PEERS_PER_KEY {
            return;
        }
        slot.push(peer);
    }
}

#[cfg(test)]
fn infohash_of(packet: &[u8]) -> Option<[u8; 20]> {
    extract_field(packet, "info_hash")?.try_into().ok()
}

#[cfg(test)]
fn announced_peer(packet: &[u8], from: SocketAddr) -> Option<SocketAddrV4> {
    let port = extract_port(packet)?;
    let IpAddr::V4(ip) = from.ip() else {
        return None;
    };
    if ip.is_unspecified() {
        return None;
    }
    Some(SocketAddrV4::new(ip, port))
}

#[cfg(test)]
fn find_node_response(transaction: &[u8], node_id: &[u8; 20], contact: SocketAddrV4) -> Vec<u8> {
    response(transaction, |out| {
        push_bytes_kv(out, b"id", node_id);
        let mut nodes = Vec::with_capacity(26);
        nodes.extend_from_slice(node_id);
        nodes.extend_from_slice(&contact.ip().octets());
        nodes.extend_from_slice(&contact.port().to_be_bytes());
        push_bytes_kv(out, b"nodes", &nodes);
    })
}

#[cfg(test)]
fn get_peers_response(
    transaction: &[u8],
    node_id: &[u8; 20],
    token: &[u8; 8],
    peers: &[SocketAddrV4],
) -> Vec<u8> {
    response(transaction, |out| {
        push_bytes_kv(out, b"id", node_id);
        push_bytes_kv(out, b"token", token);
        push_str(out, b"values");
        out.push(b'l');
        for peer in peers {
            let mut compact = [0u8; 6];
            compact[..4].copy_from_slice(&peer.ip().octets());
            compact[4..].copy_from_slice(&peer.port().to_be_bytes());
            push_str(out, &compact);
        }
        out.push(b'e');
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_static_flag_accepts_the_same_spellings_as_mainline() {
        assert!(static_rendezvous(Some("1")));
        assert!(static_rendezvous(Some(" on ")));
        assert!(static_rendezvous(Some("true")));
        assert!(!static_rendezvous(Some("0")));
        assert!(!static_rendezvous(Some("")));
        assert!(!static_rendezvous(None));
    }

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

    #[test]
    fn an_announce_names_the_port_as_a_bencode_int() {
        let query = announce_query(b"ap", &[1u8; 20], &[2u8; 20], 9001, &[3u8; 8]);
        let text = String::from_utf8_lossy(&query);
        assert!(text.contains("announce_peer"), "{text}");
        assert!(text.contains("4:porti9001e"), "{text}");
        let peers = get_peers_query(b"gp", &[1u8; 20], &[2u8; 20]);
        assert!(peers.windows(9).any(|window| window == b"get_peers"));
        let values = b"d6:valuesl6:\x7f\x00\x00\x01\x23\x28e";
        let decoded = extract_values(values);
        assert_eq!(decoded, vec!["127.0.0.1:9000".parse().unwrap()]);
    }

    #[test]
    fn two_nodes_meet_through_a_rendezvous_neither_was_configured_with() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use std::thread;

        let stop = Arc::new(AtomicBool::new(false));
        let rendezvous = Arc::new(Rendezvous::bind("127.0.0.1:0").unwrap());
        let bootstrap = rendezvous.local_addr().unwrap();
        let flag = Arc::clone(&stop);
        let server = Arc::clone(&rendezvous);
        let handle = thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                let _ = server.serve_one();
            }
        });

        let epoch = 41u64;
        let hash = infohash(epoch, false);
        let bogus = announce_query(b"zz", &[9u8; 20], &hash, 1, &[0u8; 8]);
        let probe = UdpSocket::bind("127.0.0.1:0").unwrap();
        probe
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        probe.send_to(&bogus, bootstrap).unwrap();
        let mut buf = [0u8; 512];
        probe.recv_from(&mut buf).unwrap();

        let first = meet(bootstrap, [1u8; 20], epoch, 9001, false).unwrap();
        assert!(
            first.iter().all(|addr| addr.port() != 1),
            "a token that was not issued must not publish an address: {first:?}"
        );
        let second = meet(bootstrap, [2u8; 20], epoch, 9002, false).unwrap();
        assert!(
            second
                .iter()
                .any(|addr| *addr == "127.0.0.1:9001".parse().unwrap()),
            "the second node did not learn the first: {second:?}"
        );
        let again = meet(bootstrap, [1u8; 20], epoch, 9001, false).unwrap();
        assert!(
            again
                .iter()
                .any(|addr| *addr == "127.0.0.1:9002".parse().unwrap()),
            "the first node did not learn the second: {again:?}"
        );
        let other_epoch = meet(bootstrap, [3u8; 20], epoch + 1, 9003, false).unwrap();
        assert!(
            other_epoch
                .iter()
                .all(|addr| addr.port() != 9001 && addr.port() != 9002),
            "an epoch key must not return another epoch's peers: {other_epoch:?}"
        );
        // The static key is a different meeting place from either epoch above.
        // Two callers in different epochs must still find each other on it.
        let stable = meet(bootstrap, [5u8; 20], 99, 9102, true).unwrap();
        let _ = meet(bootstrap, [4u8; 20], 1, 9101, true).unwrap();
        let stable_again = meet(bootstrap, [5u8; 20], 99, 9102, true).unwrap();
        assert!(
            stable.iter().all(|addr| addr.port() != 9001),
            "the static key must not see a rotating-key announce: {stable:?}"
        );
        assert!(
            stable_again
                .iter()
                .any(|addr| *addr == "127.0.0.1:9101".parse().unwrap()),
            "a static key must meet across epochs: {stable_again:?}"
        );

        stop.store(true, Ordering::Relaxed);
        handle.join().unwrap();
    }
}
