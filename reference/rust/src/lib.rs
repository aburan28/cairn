//! An independent reference implementation of the cairn protocol.
//!
//! Its job is to disagree. The primary implementation and this one are checked
//! against each other by `scripts/interop.sh` and against a frozen set of
//! conformance vectors, and the whole value of that is that neither was
//! written from the other's source. This crate depends on nothing from
//! `cairn` -- it is even its own cargo workspace, so a shared helper
//! cannot leak across by accident.
//!
//! What it covers is the consensus surface: canonical encoding, record
//! identity, the hash-linked ledger, the settlement beacon, and the payout
//! curve. Those are the things two implementations must agree on byte for
//! byte; everything else is local behaviour that can differ without anybody
//! disagreeing about what was settled.

pub mod attribution;
pub mod canonical;
pub mod frontier;
pub mod ledger;
pub mod node;
pub mod partition;
pub mod records;
pub mod sig;
pub mod time;
pub mod verifiers;
