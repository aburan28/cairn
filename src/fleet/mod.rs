//! A fleet: one leader that is paid, and the machines that work for it.
//!
//! # The arrangement
//!
//! An operator with a Mac in front of them and a rack of Linux boxes behind
//! them wants the rack to do the walking and the Mac to collect the pay. In
//! cairn's terms: one **leader** node holds the signing identity that claims
//! are paid to, and the **workers** -- `cairn agent` hosts, GPU walkers, the
//! reference `orbit_worker.py` -- post heartbeats and hand records to the
//! leader over its HTTP side, which is plaintext on purpose and therefore
//! lives inside the operator's own network or a tunnel they built. Nothing a
//! worker does crosses to the public network except through the leader, and
//! the leader decides whether it peers with that network at all.
//!
//! Two switches make that private, and they are deliberately separate,
//! because they bound different things:
//!
//! - [`Fleet`] (`CAIRN_FLEET`): whose records this node will **sign as
//!   itself**. A worker submits a commitment or a claim whose `submitter` is
//!   the leader's own key and leaves the signature off; the leader adds it
//!   before the record is queued, so the record settles to the leader and the
//!   worker never holds the key. `enrolled` signs for [`members`] -- machines
//!   the operator invited, each with its own key, proving it on every request
//!   ([`auth`]) from any address, which is how a rented GPU joins without a
//!   tunnel. Networks (`private`, `loopback`, CIDRs) sign for any request
//!   from inside them, as before enrollment existed. Anyone else is refused
//!   with `403` rather than queued to fail at drain time, where the worker
//!   would never hear why.
//! - [`PeerPolicy`] (`CAIRN_PEERS`): whom this node will talk to over the
//!   authenticated transport. `open`, the default, is the network as it has
//!   always been; `bootstrap`, or a list of peer ids, makes the node refuse
//!   every other peer after the handshake has named it, dial nobody else, and
//!   never learn a stranger from a beacon or a seed. A fleet of nodes in two
//!   regions peers through that transport -- McEliece handshake, AEAD
//!   channel -- which is the tunnel between them; nothing weaker is offered.
//!
//! # What this does not change
//!
//! The rules. A record the leader signs is admitted or refused by exactly the
//! checks every record meets: the epoch, the schema, the duplicate index, the
//! pinned verifier. Signing says *whose* result it is, not that it is right.
//! The commitment hash binds the submitter, so a worker that wants the leader
//! paid computes its hash with the leader's id as the submitter from the
//! start -- `GET /network` publishes it as `node.fleet.signs_as` -- and asks
//! for its work slice under its own name, because the slice is a function of
//! the name and a fleet of workers under one name would all walk one slice.
//!
//! Money is the network's own unit of account, credited to the submitter the
//! settlement names. No external currency rail exists in this repository;
//! `docs/fleet.md` says so in as many words.

pub mod auth;
pub mod cli;
pub mod members;

use std::collections::BTreeSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::canonical::Value;
use crate::p2p::handshake::PeerId;

/// The networks whose records this node signs as itself.
pub const ENV: &str = "CAIRN_FLEET";
/// The ed25519 identity file the leader signs with, when it is not the
/// node's `--mcp-identity`.
pub const IDENTITY_ENV: &str = "CAIRN_FLEET_IDENTITY";
/// Whom this node will peer with. See [`PeerPolicy`].
pub const PEERS_ENV: &str = "CAIRN_PEERS";

/// Why a value could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FleetError {
    Malformed { text: String, why: String },
}

impl fmt::Display for FleetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FleetError::Malformed { text, why } => write!(f, "{text:?}: {why}"),
        }
    }
}

impl std::error::Error for FleetError {}

// -- addresses --------------------------------------------------------------------

/// A network in CIDR notation, or a single address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cidr {
    V4 { net: Ipv4Addr, bits: u8 },
    V6 { net: Ipv6Addr, bits: u8 },
}

impl Cidr {
    /// `10.0.0.0/8`, `192.168.1.7` (a `/32`), `fd00::/8`, `::1`.
    pub fn parse(text: &str) -> Result<Cidr, FleetError> {
        let text = text.trim();
        let malformed = |why: &str| FleetError::Malformed {
            text: text.to_string(),
            why: why.to_string(),
        };
        let (addr, bits) = match text.split_once('/') {
            Some((addr, bits)) => (
                addr,
                Some(
                    bits.parse::<u8>()
                        .map_err(|_| malformed("the prefix length is not a number"))?,
                ),
            ),
            None => (text, None),
        };
        let ip: IpAddr = addr
            .parse()
            .map_err(|_| malformed("not an IPv4 or IPv6 address"))?;
        match ip {
            IpAddr::V4(v4) => {
                let bits = bits.unwrap_or(32);
                if bits > 32 {
                    return Err(malformed("an IPv4 prefix is at most /32"));
                }
                Ok(Cidr::V4 {
                    net: Ipv4Addr::from(u32::from(v4) & mask32(bits)),
                    bits,
                })
            }
            IpAddr::V6(v6) => {
                let bits = bits.unwrap_or(128);
                if bits > 128 {
                    return Err(malformed("an IPv6 prefix is at most /128"));
                }
                Ok(Cidr::V6 {
                    net: Ipv6Addr::from(u128::from(v6) & mask128(bits)),
                    bits,
                })
            }
        }
    }

    /// Whether `ip` is inside. An IPv4 address arriving as a v4-mapped IPv6
    /// address (a dual-stack listener does that) is judged as IPv4.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Cidr::V4 { net, bits }, IpAddr::V4(v4)) => {
                u32::from(v4) & mask32(*bits) == u32::from(*net)
            }
            (Cidr::V4 { .. }, IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
                Some(v4) => self.contains(IpAddr::V4(v4)),
                None => false,
            },
            (Cidr::V6 { net, bits }, IpAddr::V6(v6)) => {
                u128::from(v6) & mask128(*bits) == u128::from(*net)
            }
            (Cidr::V6 { .. }, IpAddr::V4(_)) => false,
        }
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Cidr::V4 { net, bits } => write!(f, "{net}/{bits}"),
            Cidr::V6 { net, bits } => write!(f, "{net}/{bits}"),
        }
    }
}

fn mask32(bits: u8) -> u32 {
    if bits == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(bits))
    }
}

fn mask128(bits: u8) -> u128 {
    if bits == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(bits))
    }
}

/// Whom a leader signs for: enrolled members, networks, or both.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Fleet {
    /// Networks whose requests are signed for with no further proof.
    pub sources: Vec<Cidr>,
    /// Whether members enrolled in the registry beside the log are signed
    /// for, from any address, on a request that proves the member's key.
    pub enrolled: bool,
}

impl Fleet {
    /// Sources separated by commas or spaces. `enrolled` is the members of
    /// this leader's registry, from anywhere. Two words stand for sets of
    /// networks: `private` is every RFC 1918 block, loopback and IPv6
    /// unique-local, and `loopback` is this host alone -- the case where the
    /// workers are processes beside the node, or arrive through an SSH tunnel
    /// that ends here.
    pub fn parse(text: &str) -> Result<Fleet, FleetError> {
        let mut sources = Vec::new();
        let mut enrolled = false;
        for item in text.split([',', ' ']).filter(|s| !s.trim().is_empty()) {
            match item.trim().to_ascii_lowercase().as_str() {
                "enrolled" => enrolled = true,
                "private" => {
                    for block in [
                        "10.0.0.0/8",
                        "172.16.0.0/12",
                        "192.168.0.0/16",
                        "127.0.0.0/8",
                        "fc00::/7",
                        "::1/128",
                    ] {
                        sources.push(Cidr::parse(block).expect("a fixed block parses"));
                    }
                }
                "loopback" => {
                    sources.push(Cidr::parse("127.0.0.0/8").expect("parses"));
                    sources.push(Cidr::parse("::1/128").expect("parses"));
                }
                _ => sources.push(Cidr::parse(item)?),
            }
        }
        if sources.is_empty() && !enrolled {
            return Err(FleetError::Malformed {
                text: text.to_string(),
                why: "names nobody to sign for; `enrolled` (machines you invite), \
                      `private`, `loopback`, or CIDRs such as 10.0.0.0/8"
                    .to_string(),
            });
        }
        Ok(Fleet { sources, enrolled })
    }

    /// `CAIRN_FLEET`, or `None` when unset or empty.
    pub fn from_env() -> Result<Option<Fleet>, FleetError> {
        Self::from_setting(std::env::var(ENV).ok().as_deref())
    }

    pub fn from_setting(value: Option<&str>) -> Result<Option<Fleet>, FleetError> {
        match value.map(str::trim) {
            None | Some("") => Ok(None),
            Some(text) if text.eq_ignore_ascii_case("off") => Ok(None),
            Some(text) => Fleet::parse(text).map(Some),
        }
    }

    /// Whether a request from `ip` is signed for by its address alone.
    pub fn admits(&self, ip: IpAddr) -> bool {
        self.sources.iter().any(|cidr| cidr.contains(ip))
    }

    /// Whether any address is trusted with no proof: the setting the leader
    /// says out loud at start, because a network is not a credential.
    pub fn trusts_networks(&self) -> bool {
        !self.sources.is_empty()
    }

    /// `enrolled` first when it is on, then the networks: what a worker
    /// reads at `GET /network` before it joins.
    pub fn to_value(&self) -> Value {
        Value::Array(
            self.enrolled
                .then(|| Value::string("enrolled"))
                .into_iter()
                .chain(
                    self.sources
                        .iter()
                        .map(|cidr| Value::string(cidr.to_string())),
                )
                .collect(),
        )
    }

    /// The sources as an operator wrote them, for messages.
    pub fn describe(&self) -> String {
        let mut words: Vec<String> = Vec::new();
        if self.enrolled {
            words.push("enrolled members".to_string());
        }
        words.extend(self.sources.iter().map(|cidr| cidr.to_string()));
        words.join(", ")
    }
}

// -- peers ----------------------------------------------------------------------------

/// Whom this node will peer with over the transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerPolicy {
    /// Anyone who completes the handshake, as always.
    Open,
    /// Only these peers. `bootstrap` adds every peer named by a `--bootstrap`
    /// file, which the daemon resolves once it has loaded them.
    Allow {
        ids: BTreeSet<PeerId>,
        bootstrap: bool,
    },
}

impl PeerPolicy {
    /// `open`; `bootstrap`; or peer ids (64 lowercase hex) separated by commas
    /// or spaces, with `bootstrap` allowed among them.
    pub fn parse(text: &str) -> Result<PeerPolicy, FleetError> {
        let text = text.trim();
        if text.is_empty() || text.eq_ignore_ascii_case("open") {
            return Ok(PeerPolicy::Open);
        }
        let mut ids = BTreeSet::new();
        let mut bootstrap = false;
        for item in text.split([',', ' ']).filter(|s| !s.trim().is_empty()) {
            let item = item.trim();
            if item.eq_ignore_ascii_case("bootstrap") {
                bootstrap = true;
                continue;
            }
            let id = parse_peer_id(item).ok_or_else(|| FleetError::Malformed {
                text: item.to_string(),
                why: "not `open`, `bootstrap`, or a peer id of 64 lowercase hex characters"
                    .to_string(),
            })?;
            ids.insert(id);
        }
        Ok(PeerPolicy::Allow { ids, bootstrap })
    }

    /// `CAIRN_PEERS`, or open when unset.
    pub fn from_env() -> Result<PeerPolicy, FleetError> {
        match std::env::var(PEERS_ENV) {
            Ok(text) => PeerPolicy::parse(&text),
            Err(_) => Ok(PeerPolicy::Open),
        }
    }

    pub fn is_open(&self) -> bool {
        matches!(self, PeerPolicy::Open)
    }

    /// The word a reader sees.
    pub fn as_str(&self) -> &'static str {
        match self {
            PeerPolicy::Open => "open",
            PeerPolicy::Allow { .. } => "allowlist",
        }
    }
}

fn parse_peer_id(text: &str) -> Option<PeerId> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut id = [0u8; 32];
    for (i, slot) in id.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn cidrs_parse_normalise_and_contain() {
        let lan = Cidr::parse("192.168.1.77/24").unwrap();
        assert_eq!(lan.to_string(), "192.168.1.0/24");
        assert!(lan.contains(ip("192.168.1.1")));
        assert!(lan.contains(ip("192.168.1.254")));
        assert!(!lan.contains(ip("192.168.2.1")));
        // A v4-mapped address from a dual-stack listener is the v4 address.
        assert!(lan.contains(ip("::ffff:192.168.1.9")));
        assert!(!lan.contains(ip("fd00::1")));

        let host = Cidr::parse("10.1.2.3").unwrap();
        assert_eq!(host.to_string(), "10.1.2.3/32");
        assert!(host.contains(ip("10.1.2.3")));
        assert!(!host.contains(ip("10.1.2.4")));

        let everything = Cidr::parse("0.0.0.0/0").unwrap();
        assert!(everything.contains(ip("203.0.113.7")));

        let ula = Cidr::parse("fd12:3456::/32").unwrap();
        assert_eq!(ula.to_string(), "fd12:3456::/32");
        assert!(ula.contains(ip("fd12:3456:0:1::9")));
        assert!(!ula.contains(ip("fd12:3457::1")));
        assert!(!ula.contains(ip("10.0.0.1")));
        let one = Cidr::parse("::1").unwrap();
        assert_eq!(one.to_string(), "::1/128");

        for bad in [
            "10.0.0.0/33",
            "fd00::/129",
            "10.0.0/8",
            "10.0.0.0/x",
            "",
            "lan",
        ] {
            assert!(Cidr::parse(bad).is_err(), "{bad:?} must not parse");
        }
    }

    #[test]
    fn a_fleet_is_read_from_cidrs_and_the_two_named_sets() {
        let fleet = Fleet::parse("10.0.0.0/8, 192.168.0.0/16 fd00::/8").unwrap();
        assert_eq!(fleet.sources.len(), 3);
        assert!(fleet.admits(ip("10.200.1.1")));
        assert!(fleet.admits(ip("fd00::7")));
        assert!(!fleet.admits(ip("172.16.0.1")));
        assert!(!fleet.admits(ip("203.0.113.7")));

        let private = Fleet::parse("private").unwrap();
        for inside in [
            "10.0.0.1",
            "172.31.9.9",
            "192.168.4.4",
            "127.0.0.1",
            "fd00::1",
            "::1",
        ] {
            assert!(private.admits(ip(inside)), "{inside}");
        }
        assert!(!private.admits(ip("203.0.113.7")));
        assert!(!private.admits(ip("100.64.0.1")));

        let loopback = Fleet::parse("loopback").unwrap();
        assert!(loopback.admits(ip("127.0.0.1")));
        assert!(loopback.admits(ip("::1")));
        assert!(!loopback.admits(ip("192.168.1.1")));

        let enrolled = Fleet::parse("enrolled").unwrap();
        assert!(enrolled.enrolled);
        assert!(!enrolled.trusts_networks());
        assert!(
            !enrolled.admits(ip("127.0.0.1")),
            "membership is proved, not located"
        );
        assert_eq!(
            enrolled.to_value(),
            Value::Array(vec![Value::string("enrolled")])
        );
        let both = Fleet::parse("Enrolled, loopback").unwrap();
        assert!(both.enrolled && both.admits(ip("127.0.0.1")));
        assert_eq!(both.to_value().as_array().unwrap().len(), 3);
        assert_eq!(both.describe(), "enrolled members, 127.0.0.0/8, ::1/128");
        assert!(!Fleet::parse("private").unwrap().enrolled);

        assert_eq!(Fleet::from_setting(None).unwrap(), None);
        assert_eq!(Fleet::from_setting(Some("")).unwrap(), None);
        assert_eq!(Fleet::from_setting(Some("off")).unwrap(), None);
        assert!(Fleet::from_setting(Some("10.0.0.0/8, lan")).is_err());
        assert!(Fleet::parse(", ,").is_err());
        assert_eq!(
            Fleet::parse("10.0.0.0/8").unwrap().to_value(),
            Value::Array(vec![Value::string("10.0.0.0/8")])
        );
    }

    #[test]
    fn the_peer_policy_is_open_a_bootstrap_set_or_listed_ids() {
        assert_eq!(PeerPolicy::parse("").unwrap(), PeerPolicy::Open);
        assert_eq!(PeerPolicy::parse(" OPEN ").unwrap(), PeerPolicy::Open);
        assert_eq!(
            PeerPolicy::parse("bootstrap").unwrap(),
            PeerPolicy::Allow {
                ids: BTreeSet::new(),
                bootstrap: true
            }
        );
        let id = "ab".repeat(32);
        let other = "cd".repeat(32);
        match PeerPolicy::parse(&format!("{id}, bootstrap {other}")).unwrap() {
            PeerPolicy::Allow { ids, bootstrap } => {
                assert!(bootstrap);
                assert_eq!(ids.len(), 2);
                assert!(ids.contains(&[0xab; 32]));
                assert!(ids.contains(&[0xcd; 32]));
            }
            PeerPolicy::Open => panic!("not open"),
        }
        assert!(
            PeerPolicy::parse("AB".repeat(32).as_str()).is_err(),
            "uppercase is refused"
        );
        assert!(PeerPolicy::parse("abc").is_err());
        assert!(PeerPolicy::parse(&"ab".repeat(31)).is_err());
        assert_eq!(PeerPolicy::Open.as_str(), "open");
        assert!(PeerPolicy::Open.is_open());
    }
}
