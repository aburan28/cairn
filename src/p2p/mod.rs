//! Peer-to-peer layer.
//!
//! See `docs/p2p.md` for the design. The short version: records are
//! content-addressed and independently verifiable, so peers need no agreement
//! about *validity* — only about *order*, and only for the frontier.
//!
//! # Why [`swarm`] lives here
//!
//! It used to be `crate::swarm`, a sibling, and the two were described as
//! duplicating each other for long enough that the description outlived the
//! fact. They never did: [`discovery`] caches a 261 KiB McEliece key per peer
//! and can never relay one, while [`swarm::discovery`] holds signed, relayable
//! records with a monotonic sequence. Neither can do the other's job, and
//! `crate::dht` is the one Kademlia both instantiate.
//!
//! What *was* wrong was the dependency graph. Blob transfer runs over
//! [`transport`], asks [`dht`] for keys, and reaches them through
//! [`service::Service`] — which in turn implements [`swarm::tcp::KeySource`], a
//! trait declared in the module that consumes it. Two sibling modules each
//! naming the other is a cycle a reader has to hold in their head, and it was
//! the reason "does `swarm` fold into `p2p`?" kept being deferred rather than
//! answered.
//!
//! Answered by moving it. The dependency runs one way now and the module tree
//! says so: blob transfer is a *consumer* of this layer, the `KeySource` impl
//! is a sibling talking to a sibling, and nothing above `p2p` needs to know
//! either exists.

pub mod code;
pub mod dht;
pub mod discovery;
pub mod handshake;
pub mod multicast;
pub mod pop;
pub mod portmap;
pub mod service;
pub mod session;
pub mod swarm;
pub mod sync;
pub mod transport;
