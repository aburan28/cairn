//! Coordinator-free work assignment, and the settlement beacon.
//!
//! An assignment is a pure function of public inputs, so a node computes its
//! own region and anyone can recompute a peer's. No messages, no scheduler.

use sha2::{Digest as _, Sha256};

/// Ten minutes. Overridable only so a shell demo can cross an epoch boundary
/// and finish; two nodes with different settings disagree about which reveals
/// were legal, so this is policy, not format. It changes no canonical bytes --
/// epochs are derived from record timestamps and never stored.
pub const EPOCH_SECONDS: u64 = 600;

pub fn epoch_seconds() -> u64 {
    match std::env::var("PROOFWORK_EPOCH_SECONDS") {
        Ok(text) => text
            .trim()
            .parse()
            .ok()
            .filter(|n| *n > 0)
            .unwrap_or(EPOCH_SECONDS),
        Err(_) => EPOCH_SECONDS,
    }
}

/// Closed epochs an epoch must wait out before it may settle.
///
/// A batch's anchor is the epoch chain head as it stood when the batch was
/// written, so which epochs had already settled locally decides the payment
/// order -- and two nodes that learn about work in different orders settle in
/// different orders. Delaying eligibility makes it a function of the clock
/// instead: by the time epoch `E` may settle, a node that heard about `E` late
/// is holding every earlier epoch too, and drains them in epoch order.
///
/// Converges only *within* the delay. A record later than that is refused
/// rather than paid out of order -- see `Node::late_epochs` -- because
/// agreeing on the settled set with unbounded message delay is consensus, and
/// this is not a consensus protocol. Policy, like `EPOCH_SECONDS`: two nodes
/// with different settings disagree about which epochs are eligible.
pub const FINALITY_EPOCHS: u64 = 1;

pub fn finality_epochs() -> u64 {
    match std::env::var("PROOFWORK_FINALITY_EPOCHS") {
        Ok(text) => text.trim().parse().unwrap_or(FINALITY_EPOCHS),
        Err(_) => FINALITY_EPOCHS,
    }
}

/// How many peers hold a share of a sealed submission's content key, and how
/// many must publish before it opens.
///
/// Consensus-critical: the committee is a beacon draw over the log's peer
/// records, so two implementations using different sizes draw different
/// committees and disagree about whether a published share answered a seat that
/// exists. They are here, in the second implementation, for exactly that
/// reason — a constant only one side holds is a constant only one side can be
/// wrong about.
pub const COMMITTEE_SIZE: u8 = 5;
pub const COMMITTEE_THRESHOLD: u8 = 3;
pub const MAX_COMMITTEE_SIZE: u8 = 64;

/// A strict majority. Mirrors the primary's `partition::threshold_for`: two
/// crates disagreeing about the threshold disagree about what "sealed" bought.
pub const fn threshold_for(size: u8) -> u8 {
    size / 2 + 1
}

/// The `d` in `V <= t * d * S'`, as `num/den`. Mirrors the primary.
pub const DETECTION_NUM: u128 = 1;
pub const DETECTION_DEN: u128 = 2;

pub fn epoch_of(timestamp_seconds: u64, epoch_seconds: u64) -> u64 {
    timestamp_seconds / epoch_seconds
}

use crate::canonical::hex_lower as hex;

pub fn beacon(epoch: u64, anchor: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("{epoch}:{anchor}").as_bytes());
    hex(&hasher.finalize())
}

/// `H(beacon(epoch, anchor) ‖ key)`, ascending.
///
/// Append order is the sequencer's to choose, and on a progressive objective
/// the order two improvements settle in decides which is paid for the whole
/// span. Sorting by a value derived from a beacon fixed *before the epoch
/// opened* takes that lever away.
pub fn settlement_rank(epoch: u64, anchor: &str, key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(beacon(epoch, anchor).as_bytes());
    hasher.update(key.as_bytes());
    hex(&hasher.finalize())
}

/// `HMAC-SHA256(beacon, "node_id|objective_id")` -- first **eight** bytes,
/// big-endian, mod `partitions`.
///
/// The width is part of the format, not an implementation detail: taking four
/// bytes here instead of eight produces a different, entirely plausible-looking
/// assignment, so two nodes would each believe they were searching their own
/// region while overlapping and leaving gaps. Nothing would ever error.
pub fn assign(
    node_id: &str,
    objective_id: &str,
    epoch_beacon: &str,
    partitions: u64,
) -> Result<u64, String> {
    if partitions == 0 {
        return Err("partitions must be positive".into());
    }
    let mac = hmac_sha256(
        epoch_beacon.as_bytes(),
        format!("{node_id}|{objective_id}").as_bytes(),
    );
    let value = u64::from_be_bytes(mac[..8].try_into().expect("8 bytes"));
    Ok(value % partitions)
}

/// HMAC-SHA256, written out: the crate has no hmac dependency and this is the
/// whole of RFC 2104 for a 64-byte block function.
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut padded = [0u8; BLOCK];
    if key.len() > BLOCK {
        let mut hasher = Sha256::new();
        hasher.update(key);
        padded[..32].copy_from_slice(&hasher.finalize());
    } else {
        padded[..key.len()].copy_from_slice(key);
    }
    let mut inner_key = [0u8; BLOCK];
    let mut outer_key = [0u8; BLOCK];
    for i in 0..BLOCK {
        inner_key[i] = padded[i] ^ 0x36;
        outer_key[i] = padded[i] ^ 0x5c;
    }
    let mut inner = Sha256::new();
    inner.update(inner_key);
    inner.update(message);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_key);
    outer.update(inner);
    outer.finalize().into()
}
