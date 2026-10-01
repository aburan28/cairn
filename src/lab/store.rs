//! A replica on disk: the op log, the blobs, and the rules for adding to them.
//!
//! # Layout
//!
//! ```text
//! <lab>/space        the space id (its genesis op id), one line
//! <lab>/ops.jsonl    every op this replica holds, one canonical line each,
//!                    in an order where every op follows its dependencies
//! <lab>/blobs/ab/cd… content-addressed file bytes, by sha256
//! <lab>/envs/…       execution environments (see `super::env`)
//! <lab>/lock         taken while appending
//! ```
//!
//! # Many writers, no daemon
//!
//! Several agents on one machine share one lab directory. Appending takes an
//! advisory lock on `lock`, re-reads whatever other processes appended since
//! this handle last looked, and only then picks dependencies and a Lamport
//! number — so two local writers never both think they are the newest, and
//! never write interleaved lines. Readers take no lock: a line is visible to
//! them only once its terminating newline is, so a half-written line from a
//! writer that crashed is skipped rather than misread, and the next append
//! after a crash truncates it away.
//!
//! # Causal closure is the store's invariant
//!
//! [`Lab::ingest`] refuses an op whose dependencies are not already stored.
//! Every replica is therefore a downward-closed set, the file order is a
//! topological order, and "is this op authorised" can be decided once, from
//! the op's own causal past, when it arrives. That decision is the same on
//! every replica forever, because an op's causal past never changes.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use sha2::{Digest as _, Sha256};

use super::op::{self, Body, Member, Op, Role, MAX_DEPS};
use super::LabError;
use crate::crypto::identity::Identity;

const OPS_FILE: &str = "ops.jsonl";
const SPACE_FILE: &str = "space";
const LOCK_FILE: &str = "lock";
const BLOBS_DIR: &str = "blobs";

/// Where environments live under a lab directory.
pub const ENVS_DIR: &str = "envs";

/// How long an append waits for another local writer before giving up.
const LOCK_WAIT: Duration = Duration::from_secs(120);

// -- membership ----------------------------------------------------------------

/// One member's standing in a roster.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Standing {
    pub roles: BTreeSet<Role>,
    pub peers: BTreeSet<String>,
}

/// Who may do what, as some set of membership ops says.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Roster {
    pub members: BTreeMap<String, Standing>,
}

impl Roster {
    pub fn has(&self, key: &str, role: Role) -> bool {
        self.members
            .get(key)
            .is_some_and(|standing| standing.roles.contains(&role))
    }

    pub fn is_member(&self, key: &str) -> bool {
        self.members.contains_key(key)
    }

    /// Apply one membership op. Admits replace a member's roles and peers
    /// wholesale, so an admin narrows somebody's roles by re-admitting them;
    /// revokes follow admits within one op.
    pub fn apply(&mut self, body: &Body) {
        match body {
            Body::Genesis { members, .. } => {
                for member in members {
                    self.admit(member);
                }
            }
            Body::Members { admit, revoke } => {
                for member in admit {
                    self.admit(member);
                }
                for key in revoke {
                    self.members.remove(key);
                }
            }
            _ => {}
        }
    }

    fn admit(&mut self, member: &Member) {
        self.members.insert(
            member.key.clone(),
            Standing {
                roles: member.roles.clone(),
                peers: member.peers.clone(),
            },
        );
    }

    /// Every transport peer id any member lists. What `cairn lab serve`
    /// answers by default.
    pub fn peers(&self) -> BTreeSet<String> {
        self.members
            .values()
            .flat_map(|standing| standing.peers.iter().cloned())
            .collect()
    }
}

/// A set of small integers: which membership ops lie in an op's causal past.
///
/// Membership ops are rare — a genesis and a handful of admits — so this is a
/// few words per op, and folding a roster from one is cheap enough to cache
/// by value: most ops in a space share the same causal membership.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub(crate) struct Bits(Vec<u64>);

impl Bits {
    pub(crate) fn contains(&self, index: usize) -> bool {
        let (word, bit) = (index / 64, index % 64);
        self.0
            .get(word)
            .is_some_and(|bits| bits & (1u64 << bit) != 0)
    }

    /// These bits with every bit of `mask` cleared.
    pub(crate) fn without(&self, mask: &Bits) -> Bits {
        let mut out = self.clone();
        for (mine, theirs) in out.0.iter_mut().zip(&mask.0) {
            *mine &= !*theirs;
        }
        while out.0.last() == Some(&0) {
            out.0.pop();
        }
        out
    }

    pub(crate) fn set(&mut self, index: usize) {
        let (word, bit) = (index / 64, index % 64);
        if self.0.len() <= word {
            self.0.resize(word + 1, 0);
        }
        self.0[word] |= 1u64 << bit;
    }

    fn union(&mut self, other: &Bits) {
        if self.0.len() < other.0.len() {
            self.0.resize(other.0.len(), 0);
        }
        for (mine, theirs) in self.0.iter_mut().zip(&other.0) {
            *mine |= *theirs;
        }
    }

    pub(crate) fn ones(&self) -> impl Iterator<Item = usize> + '_ {
        self.0.iter().enumerate().flat_map(|(word, bits)| {
            (0..64).filter_map(move |bit| (bits & (1u64 << bit) != 0).then_some(word * 64 + bit))
        })
    }
}

// -- blobs -----------------------------------------------------------------------

/// Content-addressed file bytes.
///
/// Separate from [`crate::blobs::BlobStore`] on purpose. That store holds
/// pinned verifier source under a 1 MiB ceiling, because a verifier bigger
/// than that is not one anybody should be running synchronously. A lab blob is
/// a run's output or a protocol's data file and can be gigabytes, so it is
/// streamed, never held in memory whole, and has no ceiling but the disk.
#[derive(Debug, Clone)]
pub struct Blobs {
    dir: PathBuf,
}

impl Blobs {
    pub fn at(dir: impl Into<PathBuf>) -> Blobs {
        Blobs { dir: dir.into() }
    }

    /// Where a blob lives, if `address` is an address. The check is the
    /// security boundary: an address arrives in an op written by somebody
    /// else and becomes a file name here.
    pub fn path(&self, address: &str) -> Result<PathBuf, LabError> {
        let address = op::blob_address(address)?;
        let hex = &address[crate::canonical::DIGEST_PREFIX.len()..];
        Ok(self.dir.join(&hex[..2]).join(&hex[2..]))
    }

    pub fn has(&self, address: &str) -> bool {
        self.path(address)
            .map(|path| path.is_file())
            .unwrap_or(false)
    }

    /// Store bytes, returning their address.
    pub fn put_bytes(&self, bytes: &[u8]) -> Result<String, LabError> {
        let address = crate::canonical::digest_bytes(bytes);
        if self.has(&address) {
            return Ok(address);
        }
        let mut writer = self.writer()?;
        writer.write(bytes)?;
        writer.finish(Some(&address))
    }

    /// Stream a file in, returning its address and size.
    pub fn put_file(&self, source: &Path) -> Result<(String, u64), LabError> {
        let mut input =
            File::open(source).map_err(|e| LabError::Io(format!("{}: {e}", source.display())))?;
        let mut writer = self.writer()?;
        let mut buffer = vec![0u8; 1 << 20];
        loop {
            let read = input
                .read(&mut buffer)
                .map_err(|e| LabError::Io(format!("{}: {e}", source.display())))?;
            if read == 0 {
                break;
            }
            writer.write(&buffer[..read])?;
        }
        let size = writer.written;
        let address = writer.finish(None)?;
        Ok((address, size))
    }

    /// Begin writing a blob whose address is learned at the end. The bytes go
    /// to a temporary file and are renamed into place only after they hash to
    /// the address, so the store never holds a file under a name it does not
    /// hash to — even if the writer crashes, or a peer lies.
    pub fn writer(&self) -> Result<BlobWriter, LabError> {
        let tmp_dir = self.dir.join("tmp");
        fs::create_dir_all(&tmp_dir)?;
        let name = format!(
            "{}-{}",
            std::process::id(),
            crate::canonical::digest_bytes(&random_bytes())
                .trim_start_matches(crate::canonical::DIGEST_PREFIX)
        );
        let path = tmp_dir.join(name);
        let file = File::create(&path)?;
        Ok(BlobWriter {
            store: self.clone(),
            path,
            file: Some(file),
            hasher: Sha256::new(),
            written: 0,
        })
    }

    pub fn read(&self, address: &str) -> Result<Vec<u8>, LabError> {
        let path = self.path(address)?;
        fs::read(&path).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => LabError::NotFound(format!("blob {address}")),
            _ => LabError::Io(format!("{}: {e}", path.display())),
        })
    }

    pub fn open(&self, address: &str) -> Result<File, LabError> {
        let path = self.path(address)?;
        File::open(&path).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => LabError::NotFound(format!("blob {address}")),
            _ => LabError::Io(format!("{}: {e}", path.display())),
        })
    }

    pub fn size(&self, address: &str) -> Result<u64, LabError> {
        let path = self.path(address)?;
        Ok(fs::metadata(&path)
            .map_err(|_| LabError::NotFound(format!("blob {address}")))?
            .len())
    }

    /// Copy a blob to `dest`, replacing it. A copy and not a hard link: a
    /// checked-out file is somebody's working copy, and an edit through a link
    /// would rewrite the stored bytes under their address.
    pub fn copy_to(&self, address: &str, dest: &Path) -> Result<(), LabError> {
        let source = self.path(address)?;
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = dest.with_file_name(format!(
            ".{}.lab-tmp",
            dest.file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default()
        ));
        fs::copy(&source, &tmp).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => LabError::NotFound(format!("blob {address}")),
            _ => LabError::Io(format!("{}: {e}", dest.display())),
        })?;
        fs::rename(&tmp, dest)?;
        Ok(())
    }

    /// Re-hash a stored blob. What `cairn lab verify` runs on every one.
    pub fn verify(&self, address: &str) -> Result<bool, LabError> {
        let mut file = self.open(address)?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; 1 << 20];
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        let actual = format!(
            "{}{}",
            crate::canonical::DIGEST_PREFIX,
            crate::hex::encode(&hasher.finalize())
        );
        Ok(actual == address)
    }

    /// Every address held.
    pub fn addresses(&self) -> Vec<String> {
        let mut out = Vec::new();
        let Ok(top) = fs::read_dir(&self.dir) else {
            return out;
        };
        for shard in top.flatten() {
            let shard_name = shard.file_name().to_string_lossy().into_owned();
            if shard_name.len() != 2 {
                continue;
            }
            let Ok(entries) = fs::read_dir(shard.path()) else {
                continue;
            };
            for entry in entries.flatten() {
                let rest = entry.file_name().to_string_lossy().into_owned();
                let address = format!("{}{shard_name}{rest}", crate::canonical::DIGEST_PREFIX);
                if op::blob_address(&address).is_ok() {
                    out.push(address);
                }
            }
        }
        out.sort();
        out
    }
}

/// A blob being written. See [`Blobs::writer`].
pub struct BlobWriter {
    store: Blobs,
    path: PathBuf,
    file: Option<File>,
    hasher: Sha256,
    written: u64,
}

impl BlobWriter {
    pub fn write(&mut self, bytes: &[u8]) -> Result<(), LabError> {
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| LabError::Io("blob writer already finished".into()))?;
        file.write_all(bytes)?;
        self.hasher.update(bytes);
        self.written = self.written.saturating_add(bytes.len() as u64);
        Ok(())
    }

    pub fn written(&self) -> u64 {
        self.written
    }

    /// Finish: check the bytes against `expected` if one was declared, then
    /// move them under their address. A mismatch deletes them and is refused.
    pub fn finish(mut self, expected: Option<&str>) -> Result<String, LabError> {
        let file = self
            .file
            .take()
            .ok_or_else(|| LabError::Io("blob writer already finished".into()))?;
        file.sync_all()?;
        drop(file);
        let hasher = std::mem::take(&mut self.hasher);
        let address = format!(
            "{}{}",
            crate::canonical::DIGEST_PREFIX,
            crate::hex::encode(&hasher.finalize())
        );
        if let Some(expected) = expected {
            if expected != address {
                let _ = fs::remove_file(&self.path);
                return Err(LabError::Refused(format!(
                    "bytes hash to {address}, not the declared {expected}"
                )));
            }
        }
        let dest = self.store.path(&address)?;
        if dest.is_file() {
            let _ = fs::remove_file(&self.path);
            return Ok(address);
        }
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::rename(&self.path, &dest)?;
        Ok(address)
    }
}

impl Drop for BlobWriter {
    fn drop(&mut self) {
        if self.file.is_some() {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn random_bytes() -> [u8; 16] {
    use rand_core::RngCore as _;
    let mut bytes = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut bytes);
    bytes
}

// -- the replica -------------------------------------------------------------------

/// What [`Lab::ingest`] did with one op.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ingested {
    /// New, valid, now stored.
    Added,
    /// Already held. Union is idempotent; this is not an error.
    Duplicate,
}

/// One replica of one space.
pub struct Lab {
    root: PathBuf,
    space: Option<String>,
    ops: Vec<Op>,
    index: HashMap<String, usize>,
    heads: BTreeSet<String>,
    max_lamport: u64,
    /// Bytes of `ops.jsonl` already read, so [`Lab::refresh`] reads only what
    /// another process appended since.
    consumed: u64,
    /// Op indices of genesis and `members` ops, in file order. A membership
    /// op's *ordinal* is its position here.
    membership: Vec<usize>,
    ordinal: HashMap<usize, usize>,
    /// Per op: the ordinals of membership ops in its strict causal past.
    past: Vec<Bits>,
    rosters: HashMap<Bits, Roster>,
    blobs: Blobs,
}

impl std::fmt::Debug for Lab {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Lab({}, {} ops)", self.root.display(), self.ops.len())
    }
}

impl Lab {
    /// Create a space: write its genesis op into a new lab directory.
    pub fn init(
        root: &Path,
        identity: &Identity,
        name: &str,
        mut members: Vec<Member>,
        policy: op::Policy,
    ) -> Result<Lab, LabError> {
        if root.join(OPS_FILE).exists() || root.join(SPACE_FILE).exists() {
            return Err(LabError::Refused(format!(
                "{} already holds a lab",
                root.display()
            )));
        }
        let me = identity.submitter_id();
        if !members.iter().any(|member| member.key == me) {
            members.insert(
                0,
                Member {
                    key: me.clone(),
                    roles: [Role::Admin, Role::Writer].into_iter().collect(),
                    peers: BTreeSet::new(),
                },
            );
        }
        let genesis = Op::sign(
            identity,
            None,
            1,
            Vec::new(),
            crate::time::timestamp(),
            Body::Genesis {
                name: name.to_string(),
                members,
                policy,
            },
        )?;
        Lab::create_empty(root, &genesis.id)?;
        let mut lab = Lab::open(root)?;
        lab.ingest(genesis)?;
        Ok(lab)
    }

    /// Prepare an empty replica of a space known only by id. The first op it
    /// will accept is the genesis with exactly that id — which is how a
    /// replica cloned from a peer cannot be handed a different space.
    pub fn create_empty(root: &Path, space: &str) -> Result<(), LabError> {
        let space = op::op_id(space)?;
        fs::create_dir_all(root.join(BLOBS_DIR))?;
        if root.join(SPACE_FILE).exists() {
            return Err(LabError::Refused(format!(
                "{} already holds a lab",
                root.display()
            )));
        }
        fs::write(root.join(SPACE_FILE), format!("{space}\n"))?;
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(root.join(OPS_FILE))?;
        Ok(())
    }

    /// Open a replica and read every op it holds.
    pub fn open(root: &Path) -> Result<Lab, LabError> {
        let space_text = fs::read_to_string(root.join(SPACE_FILE)).map_err(|e| {
            LabError::NotFound(format!(
                "no lab at {} ({e}); `cairn lab init` creates one, `cairn lab clone` copies one",
                root.display()
            ))
        })?;
        let space = op::op_id(space_text.trim())?;
        let mut lab = Lab {
            root: root.to_path_buf(),
            space: Some(space),
            ops: Vec::new(),
            index: HashMap::new(),
            heads: BTreeSet::new(),
            max_lamport: 0,
            consumed: 0,
            membership: Vec::new(),
            ordinal: HashMap::new(),
            past: Vec::new(),
            rosters: HashMap::new(),
            blobs: Blobs::at(root.join(BLOBS_DIR)),
        };
        lab.refresh()?;
        Ok(lab)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn space(&self) -> &str {
        self.space.as_deref().unwrap_or("")
    }

    pub fn blobs(&self) -> &Blobs {
        &self.blobs
    }

    pub fn envs_dir(&self) -> PathBuf {
        self.root.join(ENVS_DIR)
    }

    /// Op indices of genesis and `members` ops; a membership op's ordinal is
    /// its position in this slice.
    pub(crate) fn membership_indices(&self) -> &[usize] {
        &self.membership
    }

    /// The membership ordinal of the op at `index`, if it is a membership op.
    pub(crate) fn ordinal_of(&self, index: usize) -> Option<usize> {
        self.ordinal.get(&index).copied()
    }

    /// The membership ops in the strict causal past of the op at `index`.
    pub(crate) fn past_bits(&self, index: usize) -> &Bits {
        &self.past[index]
    }

    /// Every op held, in an order where each follows its dependencies.
    pub fn ops(&self) -> &[Op] {
        &self.ops
    }

    pub fn len(&self) -> usize {
        self.ops.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    pub fn get(&self, id: &str) -> Option<&Op> {
        self.index.get(id).map(|&i| &self.ops[i])
    }

    pub fn position(&self, id: &str) -> Option<usize> {
        self.index.get(id).copied()
    }

    pub fn has(&self, id: &str) -> bool {
        self.index.contains_key(id)
    }

    /// Ops nothing held here depends on.
    pub fn heads(&self) -> &BTreeSet<String> {
        &self.heads
    }

    pub fn max_lamport(&self) -> u64 {
        self.max_lamport
    }

    pub fn genesis(&self) -> Option<&Op> {
        self.ops.first().filter(|op| op.is_genesis())
    }

    /// The roster an op's causal past establishes.
    pub fn roster_before(&mut self, index: usize) -> Roster {
        let bits = self.past[index].clone();
        self.roster_of(&bits)
    }

    /// The roster every membership op held here establishes, ignoring the
    /// sideways reach of revocation (see [`super::state`]).
    pub fn roster_now(&mut self) -> Roster {
        let mut bits = Bits::default();
        for ordinal in 0..self.membership.len() {
            bits.set(ordinal);
        }
        self.roster_of(&bits)
    }

    fn roster_of(&mut self, bits: &Bits) -> Roster {
        if let Some(roster) = self.rosters.get(bits) {
            return roster.clone();
        }
        let mut chosen: Vec<usize> = bits
            .ones()
            .map(|ordinal| self.membership[ordinal])
            .collect();
        chosen.sort_by(|&a, &b| order_key(&self.ops[a]).cmp(&order_key(&self.ops[b])));
        let mut roster = Roster::default();
        for index in chosen {
            roster.apply(&self.ops[index].body);
        }
        self.rosters.insert(bits.clone(), roster.clone());
        roster
    }

    /// Whether `ancestor` is in the causal past of `descendant` (or is it).
    /// A walk over `deps`; only revocations ask, and there are few of them.
    pub fn ancestors_of(&self, index: usize) -> Vec<bool> {
        let mut seen = vec![false; self.ops.len()];
        let mut stack = vec![index];
        while let Some(current) = stack.pop() {
            if std::mem::replace(&mut seen[current], true) {
                continue;
            }
            for dep in &self.ops[current].deps {
                if let Some(&parent) = self.index.get(dep) {
                    if !seen[parent] {
                        stack.push(parent);
                    }
                }
            }
        }
        seen
    }

    /// Read whatever other processes appended since this handle last looked.
    ///
    /// Only complete lines are read. A trailing line with no newline is a write
    /// in progress, or a crash mid-write; either way it is not an op yet.
    pub fn refresh(&mut self) -> Result<usize, LabError> {
        let path = self.root.join(OPS_FILE);
        let mut file = match File::open(&path) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(LabError::Io(format!("{}: {e}", path.display()))),
        };
        file.seek(SeekFrom::Start(self.consumed))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let complete = match bytes.iter().rposition(|&b| b == b'\n') {
            Some(last) => last + 1,
            None => 0,
        };
        let mut added = 0usize;
        let mut offset = 0usize;
        for line in bytes[..complete].split(|&b| b == b'\n') {
            let line_len = line.len() + 1;
            if offset + line_len > complete {
                break;
            }
            offset += line_len;
            if line.is_empty() {
                continue;
            }
            let text = std::str::from_utf8(line).map_err(|_| {
                LabError::Corrupt(format!("{}: a line is not UTF-8", path.display()))
            })?;
            let op = Op::from_line(text).map_err(|e| {
                LabError::Corrupt(format!(
                    "{}: byte {}: {e}",
                    path.display(),
                    self.consumed as usize + offset - line_len
                ))
            })?;
            // Another process validated this before writing it; validating
            // again costs little and means a hand-edited log is caught here
            // rather than producing views no other replica agrees with.
            match self.admit(op) {
                Ok(_) => added += 1,
                Err(e) => {
                    return Err(LabError::Corrupt(format!(
                        "{}: an op this replica stored is not admissible: {e}",
                        path.display()
                    )))
                }
            }
        }
        self.consumed += complete as u64;
        Ok(added)
    }

    /// Add one op received from anywhere: checked, then written.
    pub fn ingest(&mut self, op: Op) -> Result<Ingested, LabError> {
        if self.has(&op.id) {
            return Ok(Ingested::Duplicate);
        }
        let _lock = self.lock()?;
        self.refresh()?;
        if self.has(&op.id) {
            return Ok(Ingested::Duplicate);
        }
        // Checked before it is written: an inadmissible op on disk would make
        // this replica refuse to open.
        self.check(&op)?;
        self.write_lines(std::slice::from_ref(&op))?;
        self.admit_checked(op);
        Ok(Ingested::Added)
    }

    /// Add many ops, in the order given, under one lock and one sync. Ops
    /// whose dependencies arrive later in the same batch are retried, so the
    /// caller need not sort. Returns what was added and what was refused.
    pub fn ingest_many(
        &mut self,
        ops: Vec<Op>,
    ) -> Result<(usize, Vec<(String, LabError)>), LabError> {
        let _lock = self.lock()?;
        self.refresh()?;
        let mut pending: Vec<Op> = ops.into_iter().filter(|op| !self.has(&op.id)).collect();
        let mut added = 0usize;
        let mut refused = Vec::new();
        loop {
            let mut progressed = false;
            let mut waiting = Vec::new();
            let mut batch = Vec::new();
            for op in pending {
                if self.has(&op.id) {
                    continue;
                }
                if op.deps.iter().any(|dep| !self.has(dep)) {
                    waiting.push(op);
                    continue;
                }
                match self.check(&op) {
                    Ok(()) => {
                        // Admitted in memory before the batch is written, because
                        // a later op in this batch may depend on this one. If
                        // the write then fails the error propagates and this
                        // handle must be dropped: it holds ops the disk does not.
                        self.admit_checked(op.clone());
                        batch.push(op);
                        added += 1;
                        progressed = true;
                    }
                    Err(e) => refused.push((op.id.clone(), e)),
                }
            }
            if !batch.is_empty() {
                self.write_lines(&batch)?;
            }
            pending = waiting;
            if pending.is_empty() || !progressed {
                break;
            }
        }
        for op in pending {
            let missing: Vec<&String> = op.deps.iter().filter(|dep| !self.has(dep)).collect();
            refused.push((
                op.id.clone(),
                LabError::Refused(format!(
                    "depends on {} op(s) this replica does not hold, e.g. {}",
                    missing.len(),
                    missing.first().map(|s| s.as_str()).unwrap_or("?")
                )),
            ));
        }
        Ok((added, refused))
    }

    /// Write a new op authored by `identity`, depending on every current head.
    pub fn append(&mut self, identity: &Identity, body: Body) -> Result<Op, LabError> {
        let _lock = self.lock()?;
        self.refresh()?;
        let space = self
            .space
            .clone()
            .ok_or_else(|| LabError::Corrupt("lab has no space id".into()))?;
        let deps = self.chosen_deps();
        let lamport = self
            .max_lamport
            .checked_add(1)
            .ok_or_else(|| LabError::Refused("lamport clock exhausted".into()))?;
        let op = Op::sign(
            identity,
            Some(&space),
            lamport,
            deps,
            crate::time::timestamp(),
            body,
        )?;
        self.check(&op)?;
        self.write_lines(std::slice::from_ref(&op))?;
        self.admit_checked(op.clone());
        Ok(op)
    }

    /// The heads a new op depends on. All of them, up to [`MAX_DEPS`]; past
    /// that the newest, which still reach everything by transitivity once any
    /// later op names the rest.
    fn chosen_deps(&self) -> Vec<String> {
        let mut heads: Vec<&Op> = self.heads.iter().filter_map(|id| self.get(id)).collect();
        heads.sort_by(|a, b| order_key(b).cmp(&order_key(a)));
        heads.truncate(MAX_DEPS);
        heads.into_iter().map(|op| op.id.clone()).collect()
    }

    /// Check and admit an op already on disk (loading) or about to be.
    fn admit(&mut self, op: Op) -> Result<Ingested, LabError> {
        if self.has(&op.id) {
            return Ok(Ingested::Duplicate);
        }
        self.check(&op)?;
        self.admit_checked(op);
        Ok(Ingested::Added)
    }

    /// The admissibility rules. Deterministic in the op and its causal past,
    /// and nothing else — no clock, no file order, no local configuration.
    fn check(&mut self, op: &Op) -> Result<(), LabError> {
        if let Body::Genesis { members, .. } = &op.body {
            if !self.ops.is_empty() {
                return Err(LabError::Refused(
                    "this replica already has a genesis".into(),
                ));
            }
            if self.space.as_deref() != Some(op.id.as_str()) {
                return Err(LabError::Refused(format!(
                    "genesis {} is not this replica's space {}",
                    op.id,
                    self.space()
                )));
            }
            let founder = members
                .iter()
                .find(|member| member.key == op.author)
                .ok_or_else(|| LabError::Refused("genesis author is not a member".into()))?;
            if !founder.roles.contains(&Role::Admin) {
                return Err(LabError::Refused("genesis author is not an admin".into()));
            }
            return Ok(());
        }

        if self.ops.is_empty() {
            return Err(LabError::Refused(
                "the first op of a space is its genesis".into(),
            ));
        }
        if op.space.as_deref() != self.space.as_deref() {
            return Err(LabError::Refused(format!(
                "op belongs to space {}, this replica is {}",
                op.space.as_deref().unwrap_or("?"),
                self.space()
            )));
        }
        let mut past = Bits::default();
        let mut max_dep = 0u64;
        for dep in &op.deps {
            let Some(&parent) = self.index.get(dep) else {
                return Err(LabError::Refused(format!(
                    "depends on {dep}, which this replica does not hold"
                )));
            };
            max_dep = max_dep.max(self.ops[parent].lamport);
            past.union(&self.past[parent]);
            if let Some(&ordinal) = self.ordinal.get(&parent) {
                past.set(ordinal);
            }
        }
        if op.lamport <= max_dep {
            return Err(LabError::Refused(format!(
                "lamport {} does not exceed its dependencies' {max_dep}",
                op.lamport
            )));
        }
        let roster = self.roster_of(&past);
        let allowed = match op.body.required_role() {
            Some(role) => roster.has(&op.author, role),
            None => roster.is_member(&op.author),
        };
        if !allowed {
            return Err(LabError::Refused(format!(
                "author {} may not write a {} op in this space",
                crate::canonical::short(&op.author),
                op.body.kind()
            )));
        }
        Ok(())
    }

    fn admit_checked(&mut self, op: Op) {
        let index = self.ops.len();
        let mut past = Bits::default();
        for dep in &op.deps {
            if let Some(&parent) = self.index.get(dep) {
                past.union(&self.past[parent]);
                if let Some(&ordinal) = self.ordinal.get(&parent) {
                    past.set(ordinal);
                }
                self.heads.remove(dep);
            }
        }
        if matches!(op.body, Body::Genesis { .. } | Body::Members { .. }) {
            self.ordinal.insert(index, self.membership.len());
            self.membership.push(index);
        }
        self.max_lamport = self.max_lamport.max(op.lamport);
        self.heads.insert(op.id.clone());
        self.index.insert(op.id.clone(), index);
        self.past.push(past);
        self.ops.push(op);
    }

    fn write_lines(&mut self, ops: &[Op]) -> Result<(), LabError> {
        let path = self.root.join(OPS_FILE);
        let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
        // A previous writer that crashed mid-line left bytes with no newline.
        // Appending after them would weld two ops into one corrupt line, so cut
        // the fragment off first. Safe under the lock: no live writer owns it.
        let len = file.metadata()?.len();
        if len > self.consumed {
            drop(file);
            let trunc = OpenOptions::new().write(true).open(&path)?;
            trunc.set_len(self.consumed)?;
            trunc.sync_all()?;
            file = OpenOptions::new().append(true).open(&path)?;
        }
        let mut buffer = String::new();
        for op in ops {
            buffer.push_str(&op.to_line());
            buffer.push('\n');
        }
        file.write_all(buffer.as_bytes())?;
        file.sync_data()?;
        self.consumed += buffer.len() as u64;
        Ok(())
    }

    /// Take the append lock, waiting for another local writer if there is one.
    fn lock(&self) -> Result<File, LabError> {
        let path = self.root.join(LOCK_FILE);
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)?;
        let started = Instant::now();
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(file),
                Err(std::fs::TryLockError::WouldBlock) => {
                    if started.elapsed() > LOCK_WAIT {
                        return Err(LabError::Io(format!(
                            "another process has held {} for over {}s",
                            path.display(),
                            LOCK_WAIT.as_secs()
                        )));
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(std::fs::TryLockError::Error(e)) => return Err(e.into()),
            }
        }
    }
}

/// The total order every fold uses: Lamport number, then id. Respects
/// causality because every op's Lamport number exceeds its dependencies'.
pub fn order_key(op: &Op) -> (u64, &str) {
    (op.lamport, op.id.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lab::op::{FileEntry, Policy};

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "cairn-lab-store-{name}-{}-{}",
            std::process::id(),
            crate::hex::encode(&random_bytes())
        ));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn write(lab: &mut Lab, who: &Identity, path: &str, bytes: &[u8]) -> Result<Op, LabError> {
        let blob = lab.blobs().put_bytes(bytes)?;
        lab.append(
            who,
            Body::Files {
                entries: vec![FileEntry {
                    path: path.into(),
                    blob: Some(blob),
                    size: bytes.len() as u64,
                    exec: false,
                    pred: Vec::new(),
                }],
            },
        )
    }

    #[test]
    fn a_stranger_cannot_write_and_an_admitted_writer_can() {
        let root = temp("auth");
        let admin = Identity::from_secret_bytes([1; 32]);
        let other = Identity::from_secret_bytes([2; 32]);
        let mut lab = Lab::init(&root, &admin, "t", Vec::new(), Policy::default()).expect("init");
        let refused = write(&mut lab, &other, "a", b"x").expect_err("stranger");
        assert!(matches!(refused, LabError::Refused(_)), "{refused}");
        lab.append(
            &admin,
            Body::Members {
                admit: vec![Member {
                    key: other.submitter_id(),
                    roles: [Role::Writer].into_iter().collect(),
                    peers: BTreeSet::new(),
                }],
                revoke: Vec::new(),
            },
        )
        .expect("admit");
        write(&mut lab, &other, "a", b"x").expect("member writes");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_reopened_replica_holds_the_same_ops_in_the_same_order() {
        let root = temp("reopen");
        let admin = Identity::from_secret_bytes([3; 32]);
        let mut lab = Lab::init(&root, &admin, "t", Vec::new(), Policy::default()).expect("init");
        for i in 0..5 {
            write(
                &mut lab,
                &admin,
                &format!("f{i}"),
                format!("{i}").as_bytes(),
            )
            .expect("write");
        }
        let ids: Vec<String> = lab.ops().iter().map(|op| op.id.clone()).collect();
        let reopened = Lab::open(&root).expect("reopen");
        let again: Vec<String> = reopened.ops().iter().map(|op| op.id.clone()).collect();
        assert_eq!(ids, again);
        assert_eq!(reopened.heads().len(), 1);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_half_written_line_is_ignored_and_then_cut_away() {
        let root = temp("torn");
        let admin = Identity::from_secret_bytes([4; 32]);
        let mut lab = Lab::init(&root, &admin, "t", Vec::new(), Policy::default()).expect("init");
        let mut file = OpenOptions::new()
            .append(true)
            .open(root.join(OPS_FILE))
            .expect("open");
        file.write_all(b"{\"op\":{\"type\":\"cairn.la")
            .expect("tear");
        drop(file);
        let mut reopened = Lab::open(&root).expect("a torn tail is not corruption");
        assert_eq!(reopened.len(), lab.len());
        write(&mut reopened, &admin, "after", b"ok").expect("append after a tear");
        let again = Lab::open(&root).expect("still readable");
        assert_eq!(again.len(), 2);
        lab.refresh().expect("the other handle catches up");
        assert_eq!(lab.len(), 2);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn an_op_from_another_space_is_refused() {
        let a = temp("space-a");
        let b = temp("space-b");
        let admin = Identity::from_secret_bytes([5; 32]);
        let mut first = Lab::init(&a, &admin, "a", Vec::new(), Policy::default()).expect("a");
        let mut second = Lab::init(&b, &admin, "b", Vec::new(), Policy::default()).expect("b");
        let op = write(&mut first, &admin, "x", b"1").expect("write");
        let refused = second.ingest(op).expect_err("wrong space");
        assert!(matches!(refused, LabError::Refused(_)));
        let _ = fs::remove_dir_all(&a);
        let _ = fs::remove_dir_all(&b);
    }

    #[test]
    fn blob_writes_refuse_bytes_that_do_not_hash_to_the_declared_address() {
        let root = temp("blobs");
        let blobs = Blobs::at(root.join("blobs"));
        let mut writer = blobs.writer().expect("writer");
        writer.write(b"hello").expect("write");
        let wrong = crate::canonical::digest_bytes(b"goodbye");
        assert!(matches!(
            writer.finish(Some(&wrong)),
            Err(LabError::Refused(_))
        ));
        assert!(!blobs.has(&wrong));
        let address = blobs.put_bytes(b"hello").expect("put");
        assert_eq!(blobs.read(&address).expect("read"), b"hello");
        assert!(blobs.verify(&address).expect("verify"));
        assert!(blobs.path("../../etc/passwd").is_err());
        let _ = fs::remove_dir_all(&root);
    }
}
