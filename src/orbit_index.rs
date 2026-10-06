//! Distinguished-orbit index.
//!
//! The ECC2K-130 search does not fit in one log. Orbits live here, sharded by
//! the first byte of `sha256(name)`, which is the same function every node
//! can recompute. A second witness for the same name is a collision candidate:
//! both are kept. [`OrbitIndex::collisions`] reports a name once two
//! *distinct* bodies are stored. Identical bytes stored twice are one
//! witness. Nothing here pays: the answer objective is what a collision is
//! claimed against, and this directory is not on the swarm.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Witness {
    pub orbit: String,
    pub body: Vec<u8>,
}

pub struct OrbitIndex {
    root: PathBuf,
}

impl OrbitIndex {
    pub fn open(root: impl Into<PathBuf>) -> std::io::Result<OrbitIndex> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        Ok(OrbitIndex { root })
    }

    /// Orbits filed under a shard store, not in the log. The log would have
    /// every node store the corpus; this directory is the shard that owns
    /// the name.
    pub fn under_shards(shard_root: impl AsRef<Path>) -> std::io::Result<OrbitIndex> {
        OrbitIndex::open(shard_root.as_ref().join("orbits"))
    }

    pub fn put(&self, orbit: &str, body: &[u8]) -> std::io::Result<PathBuf> {
        let dir = self.shard_dir(orbit);
        fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{:016x}", self.count(&dir)?));
        fs::write(&path, body)?;
        let mut name = path.clone();
        name.set_extension("orbit");
        fs::write(&name, orbit.as_bytes())?;
        Ok(path)
    }

    pub fn get(&self, orbit: &str) -> std::io::Result<Vec<Witness>> {
        let dir = self.shard_dir(orbit);
        let mut out = Vec::new();
        if !dir.exists() {
            return Ok(out);
        }
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("orbit") {
                continue;
            }
            let name = fs::read_to_string(&path)?;
            if name != orbit {
                continue;
            }
            let mut body_path = path.clone();
            body_path.set_extension("");
            if body_path.exists() {
                out.push(Witness {
                    orbit: orbit.to_string(),
                    body: fs::read(body_path)?,
                });
            }
        }
        out.sort_by(|a, b| a.body.cmp(&b.body));
        Ok(out)
    }

    /// Orbit names with at least two distinct witness bodies.
    ///
    /// A second copy of the same bytes is not a second arrival. Two different
    /// trails that canonicalise to one name are. The list is sorted so two
    /// nodes holding the same files report the same names in the same order.
    /// Paying the finder is a claim against the answer objective; this index
    /// does not mint.
    pub fn collisions(&self) -> std::io::Result<Vec<String>> {
        let mut names = BTreeSet::new();
        if !self.root.exists() {
            return Ok(Vec::new());
        }
        for shard in fs::read_dir(&self.root)? {
            let shard = shard?;
            if !shard.file_type()?.is_dir() {
                continue;
            }
            for entry in fs::read_dir(shard.path())? {
                let path = entry?.path();
                if path.extension().and_then(|ext| ext.to_str()) != Some("orbit") {
                    continue;
                }
                names.insert(fs::read_to_string(&path)?);
            }
        }
        let mut out = Vec::new();
        for name in names {
            let mut bodies = BTreeSet::new();
            for witness in self.get(&name)? {
                bodies.insert(witness.body);
            }
            if bodies.len() >= 2 {
                out.push(name);
            }
        }
        Ok(out)
    }

    fn shard_dir(&self, orbit: &str) -> PathBuf {
        let mut hasher = Sha256::new();
        hasher.update(orbit.as_bytes());
        let digest = hasher.finalize();
        self.root.join(format!("{:02x}", digest[0]))
    }

    fn count(&self, dir: &Path) -> std::io::Result<u64> {
        if !dir.exists() {
            return Ok(0);
        }
        let mut n = 0u64;
        for entry in fs::read_dir(dir)? {
            if entry?.path().extension().is_none() {
                n += 1;
            }
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_witnesses_of_one_orbit_are_both_kept() {
        let dir = std::env::temp_dir().join(format!("cairn-orbits-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let index = OrbitIndex::open(&dir).unwrap();
        index.put("orbit-a", b"walker-1").unwrap();
        index.put("orbit-a", b"walker-2").unwrap();
        index.put("orbit-b", b"other").unwrap();
        let found = index.get("orbit-a").unwrap();
        assert_eq!(found.len(), 2);
        assert!(index.get("orbit-b").unwrap().len() == 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_shard_directory_is_the_first_byte_of_the_name() {
        let dir = std::env::temp_dir().join(format!("cairn-orbits-shard-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let index = OrbitIndex::under_shards(&dir).unwrap();
        index.put("orbit-a", b"walker-1").unwrap();
        let mut hasher = Sha256::new();
        hasher.update(b"orbit-a");
        let byte = hasher.finalize()[0];
        let shard = dir.join("orbits").join(format!("{byte:02x}"));
        assert!(shard.is_dir(), "{}", shard.display());
        assert_eq!(index.get("orbit-a").unwrap().len(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_collision_is_two_distinct_bodies_and_a_replay_is_not() {
        let dir = std::env::temp_dir().join(format!("cairn-orbits-hit-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let index = OrbitIndex::open(&dir).unwrap();
        assert!(index.collisions().unwrap().is_empty());
        index.put("orbit-a", b"walker-1").unwrap();
        index.put("orbit-a", b"walker-1").unwrap();
        index.put("orbit-b", b"only").unwrap();
        assert!(
            index.collisions().unwrap().is_empty(),
            "re-storing one witness must not look like a collision"
        );
        index.put("orbit-a", b"walker-2").unwrap();
        assert_eq!(index.collisions().unwrap(), vec!["orbit-a".to_string()]);
        let _ = fs::remove_dir_all(&dir);
    }
}
