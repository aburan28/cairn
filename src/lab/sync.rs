//! Moving ops and blobs between replicas.
//!
//! Merging replicas is set union, so sync is set reconciliation: find the ops
//! each side lacks, hand them over, then fetch the blobs the new ops refer to.
//! Written once, against [`Peer`], with three carriers:
//!
//! - **another directory** — `impl Peer for Lab`: a USB stick, an NFS mount, a
//!   cloud-synced folder;
//! - **the network** — [`RemotePeer`] and [`serve`], over the same transport as
//!   `cairn p2p`: Classic McEliece to an AEAD channel, both ends authenticated;
//! - **a bundle file** — [`write_bundle`] / [`read_bundle`]: one direction,
//!   any medium.
//!
//! # Reconciliation
//!
//! Each side sorts its op ids into 256 buckets by the first byte of the
//! digest and hashes each bucket. Buckets whose hashes agree hold the same ids
//! and are skipped; for the rest the ids are exchanged. Ids are uniform, so a
//! difference of `d` ops costs about `min(d, 256)` buckets of ids — for a
//! replica that is a day behind, a small fraction of the id space.
//!
//! Ops are sent in `(lamport, id)` order, which is causal order, so the
//! receiver can ingest them as they arrive. [`Lab::ingest_many`] retries
//! within a batch anyway, so a carrier that reorders loses nothing.
//!
//! # Nothing a peer sends is trusted
//!
//! An op is verified and its authority checked on arrival, whichever peer
//! carried it. A blob is kept only if its bytes hash to its address. A peer
//! that may sync but not write can therefore still relay a writer's ops — and
//! cannot forge one, change one, or slip in bytes under a name they do not
//! hash to.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::sync::{Arc, Mutex};

use super::op::{self, Body, Op};
use super::store::{order_key, Lab};
use super::LabError;
use crate::canonical::Value;
use crate::p2p::handshake::{peer_id_hex, PeerIdentity};
use crate::p2p::transport::{self, Connection};

/// Transport context for every lab sync frame. Distinct from every other
/// context the transport carries, so a frame from another protocol can never
/// be read as one of these.
const CONTEXT: &[u8] = b"cairn/lab/sync/v1";

/// Ids requested per round trip.
const IDS_PER_REQUEST: usize = 512;

/// Soft cap on one response or request carrying op lines. Under the
/// transport's 16 MiB frame with room to spare; an op is at most 8 MiB.
const BATCH_BYTES: usize = 10 * 1024 * 1024;

/// Bytes per blob chunk on the wire.
const CHUNK_BYTES: usize = 4 * 1024 * 1024;

/// What one sync did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncReport {
    pub ops_received: usize,
    pub ops_sent: usize,
    pub ops_refused: Vec<(String, String)>,
    pub blobs_received: usize,
    pub blobs_sent: usize,
    /// Blobs some op here refers to that neither side holds.
    pub blobs_missing: Vec<String>,
}

/// The far side of a sync.
pub trait Peer {
    /// The space the far side holds.
    fn space_id(&mut self) -> Result<String, LabError>;
    /// Hash of each of the 256 id buckets; `""` for an empty bucket.
    fn buckets(&mut self) -> Result<Vec<String>, LabError>;
    /// Every op id in the named buckets.
    fn ids(&mut self, buckets: &[u8]) -> Result<Vec<String>, LabError>;
    /// The stored lines of the named ops it holds. May return a prefix when
    /// the answer would be too large; the caller asks again for the rest.
    fn get_ops(&mut self, ids: &[String]) -> Result<Vec<String>, LabError>;
    /// Offer op lines. Returns how many were added and which were refused.
    fn put_ops(&mut self, lines: &[String]) -> Result<(usize, Vec<(String, String)>), LabError>;
    /// Blobs its ops refer to that it does not hold.
    fn wanted_blobs(&mut self) -> Result<Vec<String>, LabError>;
    /// Stream a blob into `sink`. `Err(NotFound)` when it does not hold it.
    fn get_blob(
        &mut self,
        address: &str,
        sink: &mut dyn FnMut(&[u8]) -> Result<(), LabError>,
    ) -> Result<(), LabError>;
    /// Offer a blob's bytes.
    fn put_blob(&mut self, address: &str, bytes: &mut dyn Read, size: u64) -> Result<(), LabError>;
}

/// Reconcile `local` with `remote`, both directions: ops first, then blobs.
pub fn sync(local: &mut Lab, remote: &mut dyn Peer) -> Result<SyncReport, LabError> {
    local.refresh()?;
    let theirs = remote.space_id()?;
    if theirs != local.space() {
        return Err(LabError::Refused(format!(
            "the peer holds space {theirs}, this replica is {}",
            local.space()
        )));
    }
    let mut report = SyncReport::default();

    // -- ops ------------------------------------------------------------------
    let mine = buckets(local);
    let remote_buckets = remote.buckets()?;
    if remote_buckets.len() != 256 {
        return Err(LabError::Invalid(
            "peer sent a malformed bucket list".into(),
        ));
    }
    let differing: Vec<u8> = (0..=255u8)
        .filter(|&b| mine[b as usize] != remote_buckets[b as usize])
        .collect();
    if !differing.is_empty() {
        let local_ids: BTreeSet<String> = ids_in(local, &differing).into_iter().collect();
        let remote_ids: BTreeSet<String> = remote.ids(&differing)?.into_iter().collect();

        let wanted: Vec<String> = remote_ids.difference(&local_ids).cloned().collect();
        let mut received = Vec::new();
        for chunk in wanted.chunks(IDS_PER_REQUEST) {
            let mut asked: Vec<String> = chunk.to_vec();
            while !asked.is_empty() {
                let lines = remote.get_ops(&asked)?;
                if lines.is_empty() {
                    break;
                }
                let mut got = BTreeSet::new();
                for line in &lines {
                    let op = Op::from_line(line)?;
                    got.insert(op.id.clone());
                    received.push(op);
                }
                asked.retain(|id| !got.contains(id));
            }
        }
        let (added, refused) = local.ingest_many(received)?;
        report.ops_received = added;
        report
            .ops_refused
            .extend(refused.into_iter().map(|(id, e)| (id, e.to_string())));

        let mut offer: Vec<&Op> = local_ids
            .difference(&remote_ids)
            .filter_map(|id| local.get(id))
            .collect();
        offer.sort_by(|a, b| order_key(a).cmp(&order_key(b)));
        let mut batch = Vec::new();
        let mut batch_bytes = 0usize;
        for op in offer {
            let line = op.to_line();
            if batch_bytes + line.len() > BATCH_BYTES && !batch.is_empty() {
                let (added, refused) = remote.put_ops(&batch)?;
                report.ops_sent += added;
                report.ops_refused.extend(refused);
                batch.clear();
                batch_bytes = 0;
            }
            batch_bytes += line.len();
            batch.push(line);
        }
        if !batch.is_empty() {
            let (added, refused) = remote.put_ops(&batch)?;
            report.ops_sent += added;
            report.ops_refused.extend(refused);
        }
    }

    // -- blobs ------------------------------------------------------------------
    for address in wanted_blobs(local) {
        let mut writer = local.blobs().writer()?;
        let mut failed = None;
        let result = remote.get_blob(&address, &mut |chunk| {
            writer
                .write(chunk)
                .inspect_err(|e| failed = Some(e.clone()))
        });
        match result {
            Ok(()) => {
                writer.finish(Some(&address))?;
                report.blobs_received += 1;
            }
            Err(LabError::NotFound(_)) => report.blobs_missing.push(address),
            Err(e) => return Err(failed.unwrap_or(e)),
        }
    }
    for address in remote.wanted_blobs()? {
        if !local.blobs().has(&address) {
            continue;
        }
        let mut file = local.blobs().open(&address)?;
        let size = local.blobs().size(&address)?;
        remote.put_blob(&address, &mut file, size)?;
        report.blobs_sent += 1;
    }
    Ok(report)
}

/// The 256 bucket hashes of a replica.
pub fn buckets(lab: &Lab) -> Vec<String> {
    let mut grouped: Vec<Vec<&str>> = vec![Vec::new(); 256];
    for op in lab.ops() {
        grouped[bucket_of(&op.id) as usize].push(op.id.as_str());
    }
    grouped
        .into_iter()
        .map(|mut ids| {
            if ids.is_empty() {
                return String::new();
            }
            ids.sort_unstable();
            crate::canonical::digest_bytes(ids.join("\n").as_bytes())
        })
        .collect()
}

fn bucket_of(id: &str) -> u8 {
    id.strip_prefix(crate::canonical::DIGEST_PREFIX)
        .and_then(|hex| hex.get(..2))
        .and_then(|byte| u8::from_str_radix(byte, 16).ok())
        .unwrap_or(0)
}

fn ids_in(lab: &Lab, wanted: &[u8]) -> Vec<String> {
    let wanted: BTreeSet<u8> = wanted.iter().copied().collect();
    lab.ops()
        .iter()
        .filter(|op| wanted.contains(&bucket_of(&op.id)))
        .map(|op| op.id.clone())
        .collect()
}

/// Every blob address any held op refers to — history included, because a
/// research record's earlier versions are part of its audit trail.
pub fn referenced_blobs(lab: &Lab) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for op in lab.ops() {
        for entry in op.body.file_entries() {
            if let Some(blob) = &entry.blob {
                out.insert(blob.clone());
            }
        }
        match &op.body {
            Body::Env { manifest, .. } => {
                out.insert(manifest.clone());
            }
            Body::Run { receipt, .. } => {
                for key in ["stdout", "stderr"] {
                    if let Some(address) = receipt.get(key).and_then(Value::as_str) {
                        if op::blob_address(address).is_ok() {
                            out.insert(address.to_string());
                        }
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/// Blobs this replica's ops refer to that it does not hold.
pub fn wanted_blobs(lab: &Lab) -> Vec<String> {
    referenced_blobs(lab)
        .into_iter()
        .filter(|address| !lab.blobs().has(address))
        .collect()
}

// -- a directory is a peer ------------------------------------------------------

impl Peer for Lab {
    fn space_id(&mut self) -> Result<String, LabError> {
        self.refresh()?;
        Ok(self.space().to_string())
    }

    fn buckets(&mut self) -> Result<Vec<String>, LabError> {
        Ok(buckets(self))
    }

    fn ids(&mut self, wanted: &[u8]) -> Result<Vec<String>, LabError> {
        Ok(ids_in(self, wanted))
    }

    fn get_ops(&mut self, ids: &[String]) -> Result<Vec<String>, LabError> {
        let mut out = Vec::new();
        let mut bytes = 0usize;
        for id in ids {
            if let Some(op) = self.get(id) {
                let line = op.to_line();
                if bytes + line.len() > BATCH_BYTES && !out.is_empty() {
                    break;
                }
                bytes += line.len();
                out.push(line);
            }
        }
        Ok(out)
    }

    fn put_ops(&mut self, lines: &[String]) -> Result<(usize, Vec<(String, String)>), LabError> {
        let mut ops = Vec::with_capacity(lines.len());
        let mut refused = Vec::new();
        for line in lines {
            match Op::from_line(line) {
                Ok(op) => ops.push(op),
                Err(e) => refused.push(("?".to_string(), e.to_string())),
            }
        }
        let (added, more) = self.ingest_many(ops)?;
        refused.extend(more.into_iter().map(|(id, e)| (id, e.to_string())));
        Ok((added, refused))
    }

    fn wanted_blobs(&mut self) -> Result<Vec<String>, LabError> {
        Ok(wanted_blobs(self))
    }

    fn get_blob(
        &mut self,
        address: &str,
        sink: &mut dyn FnMut(&[u8]) -> Result<(), LabError>,
    ) -> Result<(), LabError> {
        let mut file = self.blobs().open(address)?;
        let mut buffer = vec![0u8; CHUNK_BYTES];
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                return Ok(());
            }
            sink(&buffer[..read])?;
        }
    }

    fn put_blob(
        &mut self,
        address: &str,
        bytes: &mut dyn Read,
        _size: u64,
    ) -> Result<(), LabError> {
        if self.blobs().has(address) {
            return Ok(());
        }
        let mut writer = self.blobs().writer()?;
        let mut buffer = vec![0u8; CHUNK_BYTES];
        loop {
            let read = bytes.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            writer.write(&buffer[..read])?;
        }
        writer.finish(Some(address))?;
        Ok(())
    }
}

// -- the network ---------------------------------------------------------------

/// A replica on the far side of an encrypted, mutually authenticated session.
pub struct RemotePeer {
    connection: Connection,
}

impl RemotePeer {
    /// Dial `addr` and require the peer there to be `expected` (a transport
    /// peer id, hex). The key is fetched from the peer and checked against the
    /// id before any session is attempted, so a peer at the right address
    /// with the wrong key is refused rather than trusted.
    pub fn connect(
        addr: SocketAddr,
        expected: &str,
        identity: &PeerIdentity,
    ) -> Result<RemotePeer, LabError> {
        let id_bytes = crate::hex::decode(expected)
            .filter(|bytes| bytes.len() == 32)
            .ok_or_else(|| LabError::Invalid(format!("{expected:?} is not a peer id")))?;
        let mut id = [0u8; 32];
        id.copy_from_slice(&id_bytes);
        let public = transport::request_key(addr, id)
            .map_err(|e| LabError::Io(format!("fetching {addr}'s key: {e}")))?;
        let connection = transport::connect(&public, addr, identity)
            .map_err(|e| LabError::Io(format!("connecting to {addr}: {e}")))?;
        Ok(RemotePeer { connection })
    }

    fn call(&mut self, request: Value) -> Result<Value, LabError> {
        self.send(&request)?;
        self.receive()
    }

    fn send(&mut self, value: &Value) -> Result<(), LabError> {
        self.connection
            .send(&value.canonical_bytes(), CONTEXT)
            .map_err(|e| LabError::Io(format!("send: {e}")))
    }

    fn receive(&mut self) -> Result<Value, LabError> {
        let bytes = self
            .connection
            .receive(CONTEXT)
            .map_err(|e| LabError::Io(format!("receive: {e}")))?;
        let text = String::from_utf8(bytes)
            .map_err(|_| LabError::Invalid("peer sent a non-UTF-8 frame".into()))?;
        let value = Value::from_json(&text)
            .map_err(|e| LabError::Invalid(format!("peer sent bad JSON: {e}")))?;
        match value.get("ok") {
            Some(Value::Bool(true)) => Ok(value),
            _ => {
                let why = value
                    .get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("peer refused");
                if value.get("not_found").and_then(Value::as_bool) == Some(true) {
                    Err(LabError::NotFound(why.to_string()))
                } else {
                    Err(LabError::Refused(format!("peer: {why}")))
                }
            }
        }
    }
}

fn strings(value: &Value, key: &str) -> Result<Vec<String>, LabError> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| LabError::Invalid(format!("peer response lacks {key}")))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_string)
                .ok_or_else(|| LabError::Invalid(format!("peer {key} holds a non-string")))
        })
        .collect()
}

fn string_list(items: &[String]) -> Value {
    Value::array(items.iter().map(Value::string))
}

impl Peer for RemotePeer {
    fn space_id(&mut self) -> Result<String, LabError> {
        let answer = self.call(Value::object([("m", Value::string("space"))]))?;
        answer
            .get("space")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| LabError::Invalid("peer did not name its space".into()))
    }

    fn buckets(&mut self) -> Result<Vec<String>, LabError> {
        let answer = self.call(Value::object([("m", Value::string("buckets"))]))?;
        strings(&answer, "buckets")
    }

    fn ids(&mut self, wanted: &[u8]) -> Result<Vec<String>, LabError> {
        let answer = self.call(Value::object([
            ("m", Value::string("ids")),
            (
                "buckets",
                Value::array(wanted.iter().map(|b| Value::Int(i128::from(*b)))),
            ),
        ]))?;
        strings(&answer, "ids")
    }

    fn get_ops(&mut self, ids: &[String]) -> Result<Vec<String>, LabError> {
        let answer = self.call(Value::object([
            ("m", Value::string("get_ops")),
            ("ids", string_list(ids)),
        ]))?;
        strings(&answer, "lines")
    }

    fn put_ops(&mut self, lines: &[String]) -> Result<(usize, Vec<(String, String)>), LabError> {
        let answer = self.call(Value::object([
            ("m", Value::string("put_ops")),
            ("lines", string_list(lines)),
        ]))?;
        let added = answer.get("added").and_then(Value::as_u64).unwrap_or(0) as usize;
        let refused = answer
            .get("refused")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .map(|item| {
                        (
                            item.get("id")
                                .and_then(Value::as_str)
                                .unwrap_or("?")
                                .to_string(),
                            item.get("why")
                                .and_then(Value::as_str)
                                .unwrap_or("?")
                                .to_string(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok((added, refused))
    }

    fn wanted_blobs(&mut self) -> Result<Vec<String>, LabError> {
        let answer = self.call(Value::object([("m", Value::string("wanted_blobs"))]))?;
        strings(&answer, "blobs")
    }

    fn get_blob(
        &mut self,
        address: &str,
        sink: &mut dyn FnMut(&[u8]) -> Result<(), LabError>,
    ) -> Result<(), LabError> {
        let answer = self.call(Value::object([
            ("m", Value::string("get_blob")),
            ("blob", Value::string(address)),
        ]))?;
        let chunks = answer
            .get("chunks")
            .and_then(Value::as_u64)
            .ok_or_else(|| LabError::Invalid("blob answer lacks a chunk count".into()))?;
        for _ in 0..chunks {
            let bytes = self
                .connection
                .receive(CONTEXT)
                .map_err(|e| LabError::Io(format!("receive: {e}")))?;
            sink(&bytes)?;
        }
        Ok(())
    }

    fn put_blob(&mut self, address: &str, bytes: &mut dyn Read, size: u64) -> Result<(), LabError> {
        let chunks = size.div_ceil(CHUNK_BYTES as u64);
        self.send(&Value::object([
            ("m", Value::string("put_blob")),
            ("blob", Value::string(address)),
            ("chunks", Value::Int(i128::from(chunks))),
        ]))?;
        let mut buffer = vec![0u8; CHUNK_BYTES];
        let mut sent = 0u64;
        while sent < chunks {
            let mut filled = 0usize;
            while filled < CHUNK_BYTES {
                let read = bytes.read(&mut buffer[filled..])?;
                if read == 0 {
                    break;
                }
                filled += read;
            }
            if filled == 0 {
                return Err(LabError::Io(format!(
                    "blob {address} ended before its declared size"
                )));
            }
            self.connection
                .send(&buffer[..filled], CONTEXT)
                .map_err(|e| LabError::Io(format!("send: {e}")))?;
            sent += 1;
        }
        self.receive().map(|_| ())
    }
}

/// Who may sync with a server.
#[derive(Debug, Clone, Default)]
pub struct Access {
    /// Transport peer ids allowed besides the ones members list.
    pub allow: BTreeSet<String>,
    /// Ignore membership and allow anyone who completes a handshake. For a
    /// test network; a research space is not public.
    pub open: bool,
}

/// Serve a lab to peers until the listener fails. One thread per session.
pub fn serve(
    lab_root: &Path,
    identity: PeerIdentity,
    listen: SocketAddr,
    access: Access,
) -> Result<(), LabError> {
    let listener = transport::listen(listen).map_err(|e| LabError::Io(e.to_string()))?;
    let identity = Arc::new(identity);
    let lab = Arc::new(Mutex::new(Lab::open(lab_root)?));
    eprintln!(
        "cairn lab: serving {} at {} as peer {}",
        lab.lock()
            .map(|l| l.space().to_string())
            .unwrap_or_default(),
        listen,
        peer_id_hex(&identity.id())
    );
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let identity = Arc::clone(&identity);
        let lab = Arc::clone(&lab);
        let access = access.clone();
        std::thread::spawn(move || {
            if let Err(e) = session(stream, &identity, &lab, &access) {
                eprintln!("cairn lab: session ended: {e}");
            }
        });
    }
    Ok(())
}

fn session(
    stream: TcpStream,
    identity: &PeerIdentity,
    lab: &Mutex<Lab>,
    access: &Access,
) -> Result<(), LabError> {
    let mut connection = match transport::accept(stream, identity) {
        Ok(connection) => connection,
        // A key request is answered inside `accept`; there is no session.
        Err(transport::TransportError::KeyServed) => return Ok(()),
        Err(e) => return Err(LabError::Io(format!("handshake: {e}"))),
    };
    let remote = peer_id_hex(&connection.remote());
    {
        let mut guard = lab
            .lock()
            .map_err(|_| LabError::Io("lab lock poisoned".into()))?;
        guard.refresh()?;
        let allowed = access.open
            || access.allow.contains(&remote)
            || super::state::State::of(&guard)
                .roster
                .peers()
                .contains(&remote);
        if !allowed {
            let refusal = Value::object([
                ("ok", Value::Bool(false)),
                (
                    "error",
                    Value::string(format!(
                        "peer {remote} is not listed by any member of this space"
                    )),
                ),
            ]);
            let _ = connection.send(&refusal.canonical_bytes(), CONTEXT);
            return Err(LabError::Refused(format!("peer {remote} is not allowed")));
        }
    }
    eprintln!(
        "cairn lab: session with {}",
        crate::canonical::short(&remote)
    );
    // What the space's ops refer to, recomputed only when ops arrive: a peer
    // filling in thousands of blobs must not cost a scan of every op per blob.
    let mut referenced: Option<(usize, BTreeSet<String>)> = None;
    loop {
        let request = match connection.receive(CONTEXT) {
            Ok(bytes) => bytes,
            // The client hanging up is how every session ends.
            Err(_) => return Ok(()),
        };
        let request = String::from_utf8(request)
            .ok()
            .and_then(|text| Value::from_json(&text).ok())
            .ok_or_else(|| LabError::Invalid("client sent a malformed request".into()))?;
        let method = request.get("m").and_then(Value::as_str).unwrap_or("");
        let mut guard = lab
            .lock()
            .map_err(|_| LabError::Io("lab lock poisoned".into()))?;
        guard.refresh()?;
        let answer = match handle(
            &mut guard,
            method,
            &request,
            &mut connection,
            &mut referenced,
        ) {
            Ok(Some(answer)) => answer,
            // Streamed responses write their own frames.
            Ok(None) => continue,
            Err(e) => Value::object([
                ("ok", Value::Bool(false)),
                ("error", Value::string(e.to_string())),
                ("not_found", Value::Bool(matches!(e, LabError::NotFound(_)))),
            ]),
        };
        connection
            .send(&answer.canonical_bytes(), CONTEXT)
            .map_err(|e| LabError::Io(format!("send: {e}")))?;
    }
}

fn handle(
    lab: &mut Lab,
    method: &str,
    request: &Value,
    connection: &mut Connection,
    referenced: &mut Option<(usize, BTreeSet<String>)>,
) -> Result<Option<Value>, LabError> {
    let ok = |pairs: Vec<(&str, Value)>| {
        let mut all = vec![("ok", Value::Bool(true))];
        all.extend(pairs);
        Some(Value::object(all))
    };
    match method {
        "space" => Ok(ok(vec![("space", Value::string(lab.space()))])),
        "buckets" => Ok(ok(vec![(
            "buckets",
            Value::array(buckets(lab).into_iter().map(Value::string)),
        )])),
        "ids" => {
            let wanted: Vec<u8> = request
                .get("buckets")
                .and_then(Value::as_array)
                .unwrap_or(&[])
                .iter()
                .filter_map(|b| b.as_u64().and_then(|n| u8::try_from(n).ok()))
                .collect();
            Ok(ok(vec![(
                "ids",
                Value::array(ids_in(lab, &wanted).into_iter().map(Value::string)),
            )]))
        }
        "get_ops" => {
            let ids = strings(request, "ids")?;
            let lines = Peer::get_ops(lab, &ids)?;
            Ok(ok(vec![("lines", string_list(&lines))]))
        }
        "put_ops" => {
            let lines = strings(request, "lines")?;
            let (added, refused) = Peer::put_ops(lab, &lines)?;
            Ok(ok(vec![
                ("added", Value::Int(added as i128)),
                (
                    "refused",
                    Value::array(refused.into_iter().map(|(id, why)| {
                        Value::object([("id", Value::string(id)), ("why", Value::string(why))])
                    })),
                ),
            ]))
        }
        "wanted_blobs" => Ok(ok(vec![("blobs", string_list(&wanted_blobs(lab)))])),
        "get_blob" => {
            let address = request
                .get("blob")
                .and_then(Value::as_str)
                .ok_or_else(|| LabError::Invalid("get_blob needs a blob".into()))?;
            let size = lab.blobs().size(address)?;
            let chunks = size.div_ceil(CHUNK_BYTES as u64);
            let header = Value::object([
                ("ok", Value::Bool(true)),
                ("chunks", Value::Int(i128::from(chunks))),
            ]);
            connection
                .send(&header.canonical_bytes(), CONTEXT)
                .map_err(|e| LabError::Io(format!("send: {e}")))?;
            let mut file = lab.blobs().open(address)?;
            let mut buffer = vec![0u8; CHUNK_BYTES];
            for _ in 0..chunks {
                let mut filled = 0usize;
                while filled < CHUNK_BYTES {
                    let read = file.read(&mut buffer[filled..])?;
                    if read == 0 {
                        break;
                    }
                    filled += read;
                }
                connection
                    .send(&buffer[..filled], CONTEXT)
                    .map_err(|e| LabError::Io(format!("send: {e}")))?;
            }
            Ok(None)
        }
        "put_blob" => {
            let address = request
                .get("blob")
                .and_then(Value::as_str)
                .ok_or_else(|| LabError::Invalid("put_blob needs a blob".into()))?
                .to_string();
            let chunks = request
                .get("chunks")
                .and_then(Value::as_u64)
                .ok_or_else(|| LabError::Invalid("put_blob needs a chunk count".into()))?;
            // Accepted only when some op here refers to it: a peer may fill in
            // what the space is missing, not use this replica as a disk.
            if referenced.as_ref().is_none_or(|(len, _)| *len != lab.len()) {
                *referenced = Some((lab.len(), referenced_blobs(lab)));
            }
            let wanted = referenced
                .as_ref()
                .is_some_and(|(_, set)| set.contains(&address));
            let mut writer = lab.blobs().writer()?;
            for _ in 0..chunks {
                let bytes = connection
                    .receive(CONTEXT)
                    .map_err(|e| LabError::Io(format!("receive: {e}")))?;
                writer.write(&bytes)?;
            }
            if !wanted {
                return Err(LabError::Refused(format!("no op here refers to {address}")));
            }
            writer.finish(Some(&address))?;
            Ok(ok(Vec::new()))
        }
        other => Err(LabError::Invalid(format!("unknown method {other:?}"))),
    }
}

// -- bundles -------------------------------------------------------------------

/// The first line of a bundle file.
const BUNDLE_TYPE: &str = "cairn.lab.bundle";

/// Write every op `lab` holds that is not in `have`, and every blob those ops
/// refer to, to `out`. Returns `(ops, blobs)` written.
///
/// Format: a JSON header line, then for each op `O <line>\n`, then for each
/// blob `B <address> <size>\n` followed by exactly `size` raw bytes and `\n`.
/// Line-oriented so a bundle can be inspected with `head`; raw bytes for blobs
/// so it is not a third larger than what it carries.
pub fn write_bundle(
    lab: &Lab,
    out: &mut dyn Write,
    have: Option<&BTreeSet<String>>,
) -> Result<(usize, usize), LabError> {
    let mut ops: Vec<&Op> = lab
        .ops()
        .iter()
        .filter(|op| have.is_none_or(|have| !have.contains(&op.id)))
        .collect();
    ops.sort_by(|a, b| order_key(a).cmp(&order_key(b)));
    let mut blobs = BTreeSet::new();
    for op in &ops {
        for entry in op.body.file_entries() {
            if let Some(blob) = &entry.blob {
                blobs.insert(blob.clone());
            }
        }
        match &op.body {
            Body::Env { manifest, .. } => {
                blobs.insert(manifest.clone());
            }
            Body::Run { receipt, .. } => {
                for key in ["stdout", "stderr"] {
                    if let Some(address) = receipt.get(key).and_then(Value::as_str) {
                        blobs.insert(address.to_string());
                    }
                }
            }
            _ => {}
        }
    }
    let blobs: Vec<String> = blobs
        .into_iter()
        .filter(|address| lab.blobs().has(address))
        .collect();
    let header = Value::object([
        ("type", Value::string(BUNDLE_TYPE)),
        ("version", Value::Int(1)),
        ("space", Value::string(lab.space())),
        ("ops", Value::Int(ops.len() as i128)),
        ("blobs", Value::Int(blobs.len() as i128)),
    ]);
    writeln!(out, "{}", header.canonical_string())?;
    for op in &ops {
        writeln!(out, "O {}", op.to_line())?;
    }
    for address in &blobs {
        let size = lab.blobs().size(address)?;
        writeln!(out, "B {address} {size}")?;
        let mut file = lab.blobs().open(address)?;
        let copied = std::io::copy(&mut file, out)?;
        if copied != size {
            return Err(LabError::Io(format!(
                "{address} changed size while bundling"
            )));
        }
        out.write_all(b"\n")?;
    }
    out.flush()?;
    Ok((ops.len(), blobs.len()))
}

/// Read a bundle into `lab`. The bundle's space must be the lab's.
pub fn read_bundle(lab: &mut Lab, input: &mut dyn Read) -> Result<SyncReport, LabError> {
    let mut reader = BufReader::new(input);
    let mut header = String::new();
    reader.read_line(&mut header)?;
    let header = Value::from_json(header.trim_end())
        .map_err(|e| LabError::Invalid(format!("not a lab bundle: {e}")))?;
    if header.get("type").and_then(Value::as_str) != Some(BUNDLE_TYPE) {
        return Err(LabError::Invalid("not a lab bundle".into()));
    }
    if header.get("space").and_then(Value::as_str) != Some(lab.space()) {
        return Err(LabError::Refused(format!(
            "bundle is for space {}, this replica is {}",
            header.get("space").and_then(Value::as_str).unwrap_or("?"),
            lab.space()
        )));
    }
    let mut report = SyncReport::default();
    let mut ops = Vec::new();
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let text = line.trim_end_matches('\n');
        if let Some(op_line) = text.strip_prefix("O ") {
            ops.push(Op::from_line(op_line)?);
        } else if let Some(rest) = text.strip_prefix("B ") {
            if !ops.is_empty() {
                let (added, refused) = lab.ingest_many(std::mem::take(&mut ops))?;
                report.ops_received += added;
                report
                    .ops_refused
                    .extend(refused.into_iter().map(|(id, e)| (id, e.to_string())));
            }
            let (address, size) = rest
                .split_once(' ')
                .ok_or_else(|| LabError::Invalid("malformed blob header".into()))?;
            let size: u64 = size
                .parse()
                .map_err(|_| LabError::Invalid("malformed blob size".into()))?;
            let address = op::blob_address(address)?;
            let mut writer = lab.blobs().writer()?;
            let mut remaining = size;
            let mut buffer = vec![0u8; CHUNK_BYTES];
            while remaining > 0 {
                let want = remaining.min(CHUNK_BYTES as u64) as usize;
                reader.read_exact(&mut buffer[..want])?;
                writer.write(&buffer[..want])?;
                remaining -= want as u64;
            }
            let mut newline = [0u8; 1];
            reader.read_exact(&mut newline)?;
            writer.finish(Some(&address))?;
            report.blobs_received += 1;
        } else if !text.is_empty() {
            return Err(LabError::Invalid("malformed bundle line".into()));
        }
    }
    if !ops.is_empty() {
        let (added, refused) = lab.ingest_many(ops)?;
        report.ops_received += added;
        report
            .ops_refused
            .extend(refused.into_iter().map(|(id, e)| (id, e.to_string())));
    }
    Ok(report)
}

/// Every op id a replica holds, for a bundle's `have` set.
pub fn op_ids(lab: &Lab) -> BTreeSet<String> {
    lab.ops().iter().map(|op| op.id.clone()).collect()
}

/// Summaries for status output: ops per author.
pub fn authors(lab: &Lab) -> BTreeMap<String, usize> {
    let mut out = BTreeMap::new();
    for op in lab.ops() {
        *out.entry(op.author.clone()).or_insert(0) += 1;
    }
    out
}
