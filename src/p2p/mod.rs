//! Peer-to-peer layer.
//!
//! See `docs/p2p.md` for the design. The short version: records are
//! content-addressed and independently verifiable, so peers need no agreement
//! about *validity* — only about *order*, and only for the frontier.

pub mod code;
pub mod dht;
pub mod discovery;
pub mod handshake;
pub mod pop;
pub mod service;
pub mod session;
pub mod sync;
pub mod transport;
