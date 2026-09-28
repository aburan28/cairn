//! Last-known peers, so a node that connected once does not need a seed again.
//!
//! The file is a routing hint, the same class as a bootstrap list. It is not
//! a ledger. `store::exposure` classifies `peers.cache` as plaintext on
//! purpose: the addresses in it are what this node already dials, and sealing
//! them would hide nothing a peer does not already learn by being dialed.

use std::fs;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use crate::p2p::handshake::PeerId;

/// File name under the data directory.
pub const FILE_NAME: &str = "peers.cache";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedPeer {
    pub id: PeerId,
    pub addr: SocketAddr,
}

/// Read a cache. A missing file is an empty cache, not an error: the first
/// run has nothing to remember.
pub fn load(path: &Path) -> io::Result<Vec<CachedPeer>> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err),
    };
    let mut peers = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((id_hex, addr)) = line.split_once(' ') else {
            continue;
        };
        let Some(bytes) = crate::hex::decode(id_hex) else {
            continue;
        };
        if bytes.len() != 32 {
            continue;
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&bytes);
        let Ok(addr) = addr.parse::<SocketAddr>() else {
            continue;
        };
        peers.push(CachedPeer { id, addr });
    }
    Ok(peers)
}

/// Rewrite the cache. Callers pass the peers they actually reached.
pub fn store(path: &Path, peers: &[CachedPeer]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("cache.tmp");
    {
        let mut file = fs::File::create(&tmp)?;
        writeln!(
            file,
            "# peer-id address — routing hints, not a ledger, not sealed"
        )?;
        for peer in peers {
            writeln!(file, "{} {}", crate::hex::encode(&peer.id), peer.addr)?;
        }
        file.flush()?;
    }
    fs::rename(tmp, path)
}

pub fn path_in(data_dir: &Path) -> PathBuf {
    data_dir.join(FILE_NAME)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cache_round_trips_and_a_missing_file_is_empty() {
        let dir = std::env::temp_dir().join(format!("cairn-cache-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = path_in(&dir);
        assert!(load(&path).unwrap().is_empty());
        let peer = CachedPeer {
            id: [7u8; 32],
            addr: "127.0.0.1:9000".parse().unwrap(),
        };
        store(&path, std::slice::from_ref(&peer)).unwrap();
        assert_eq!(load(&path).unwrap(), vec![peer]);
        let _ = fs::remove_dir_all(&dir);
    }
}
