//! Asking the router for a port, so a node behind NAT can seed as well as fetch.
//!
//! # The problem, which is not discovery
//!
//! [`super::discovery`] answers *what address does this peer have*. This answers
//! a different question that is routinely confused with it: **can anyone reach
//! that address**. A node behind a home router has a perfectly good address that
//! nobody outside can connect to, so it fetches happily and seeds to nobody —
//! which makes the network more centralised than the protocol suggests, because
//! the only reachable nodes end up being the ones in datacentres.
//!
//! # NAT-PMP, and why this rather than the alternatives
//!
//! Three mechanisms are usually offered:
//!
//! * **NAT-PMP / PCP** (RFC 6886, RFC 6887) — a 12-byte UDP request to the
//!   default gateway. No dependency, no external service, no configuration. It
//!   is what this module implements.
//! * **UPnP-IGD** — the same job over SOAP and XML on HTTP, discovered by
//!   SSDP. It works on more routers and costs an XML parser and an HTTP client
//!   in a crate that has neither, to speak a protocol whose own authors
//!   replaced it.
//! * **STUN, then hole punching** — the only thing that works behind a NAT that
//!   refuses to map at all, and it needs a third party: a reachable server to
//!   reflect your address, and a rendezvous peer to coordinate simultaneous
//!   opens. That is infrastructure this network does not have and should not
//!   require, so it stays out until something reachable exists to host it.
//!
//! NAT-PMP is the one that costs nothing and covers the common case. When it
//! fails the node is exactly where it was: able to fetch, unable to seed, and
//! now able to *say so* rather than silently wondering why nobody dials it.
//!
//! # Nothing here is trusted, and it does not need to be
//!
//! NAT-PMP has no authentication whatsoever. Any device on the segment can ask
//! the router to map a port, and any device can forge a reply to this node's
//! request — the protocol has no session, no nonce, and no signature.
//!
//! That is survivable for the same reason every other hint in this crate is. The
//! external address a router reports is **a claim, checked by use**: a peer that
//! dials it either completes a McEliece handshake with this node or does not.
//! A lie costs a wrong entry in one node's idea of its own address, and the
//! failure is nobody dialling — never a wrong result, never a session with the
//! wrong peer. So this module reports what it heard and marks it as unverified,
//! and nothing downstream treats it as authority.
//!
//! What it must **not** do is act on a reply it did not ask for. A response is
//! matched to a request by opcode, and one that arrives unsolicited is dropped:
//! the router's own "your external address changed" announcement is a real part
//! of the protocol and is exactly the shape an attacker would forge to move a
//! node's advertised address. Renewal on a timer costs one packet and needs no
//! announcement, so the announcement is simply not honoured.
//!
//! # A mapping expires, and that is the interesting failure
//!
//! Mappings are leases. A router reboots, an over-eager NAT table evicts one, a
//! lifetime lapses — and the node keeps advertising an address that stopped
//! working, which looks exactly like being offline. [`Mapping::expires_within`]
//! is what a caller renews on, and renewal is a fresh request rather than a
//! refresh opcode, because the protocol has no refresh and pretending otherwise
//! would mean tracking state the router does not keep either.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

/// The port a NAT-PMP gateway listens on.
pub const GATEWAY_PORT: u16 = 5351;

/// Protocol version. Zero is NAT-PMP; PCP is 2 and is not spoken here.
const VERSION: u8 = 0;

/// Opcodes this module sends.
const OP_EXTERNAL_ADDRESS: u8 = 0;
const OP_MAP_UDP: u8 = 1;
const OP_MAP_TCP: u8 = 2;

/// A response's opcode is the request's with the high bit set.
const RESPONSE_BIT: u8 = 0x80;

/// Lifetime requested for a mapping, in seconds.
///
/// An hour: long enough that renewal is cheap, short enough that a mapping to a
/// node that has gone away does not sit in the router's table all day holding a
/// port some other host on the LAN might want.
pub const LIFETIME_SECONDS: u32 = 3600;

/// How long to wait for the gateway to answer.
///
/// Short on purpose. A host with no NAT-PMP gateway is the common case, not an
/// error, and it announces itself by silence — so this is how long startup is
/// willing to pause for a router that is not there.
pub const TIMEOUT: Duration = Duration::from_millis(250);

/// Which transport a mapping is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Udp,
    Tcp,
}

impl Protocol {
    fn opcode(self) -> u8 {
        match self {
            Protocol::Udp => OP_MAP_UDP,
            Protocol::Tcp => OP_MAP_TCP,
        }
    }
}

/// What a gateway said when asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultCode {
    Success,
    /// The gateway speaks a version this does not.
    UnsupportedVersion,
    /// NAT-PMP is present and switched off. Common, and not an error worth
    /// retrying: the operator has to enable it or forward a port by hand.
    NotAuthorized,
    NetworkFailure,
    OutOfResources,
    UnsupportedOpcode,
    /// Something this version does not have a name for.
    Unknown(u16),
}

impl ResultCode {
    fn from_wire(value: u16) -> ResultCode {
        match value {
            0 => ResultCode::Success,
            1 => ResultCode::UnsupportedVersion,
            2 => ResultCode::NotAuthorized,
            3 => ResultCode::NetworkFailure,
            4 => ResultCode::OutOfResources,
            5 => ResultCode::UnsupportedOpcode,
            other => ResultCode::Unknown(other),
        }
    }

    pub fn is_success(self) -> bool {
        matches!(self, ResultCode::Success)
    }
}

/// A port the gateway says it is forwarding to this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mapping {
    /// The port this node listens on.
    pub internal: u16,
    /// The port the gateway forwards from. Often but not always the same.
    pub external: u16,
    /// Seconds the gateway committed to, which may be less than requested.
    pub lifetime: u32,
}

impl Mapping {
    /// Whether this needs renewing within `window`.
    ///
    /// Renew at half the lifetime, which is what RFC 6886 asks for and is worth
    /// the packet: a mapping that lapses looks precisely like a node that went
    /// offline, and the node itself is the last to notice.
    pub fn expires_within(&self, window: Duration) -> bool {
        u64::from(self.lifetime) <= window.as_secs()
    }

    /// The moment to renew: half the granted lifetime.
    pub fn renew_after(&self) -> Duration {
        Duration::from_secs(u64::from(self.lifetime) / 2)
    }
}

/// Encode a request for the gateway's external address. Two bytes.
pub fn external_address_request() -> [u8; 2] {
    [VERSION, OP_EXTERNAL_ADDRESS]
}

/// Decode an external-address response.
///
/// `None` for anything that is not one: wrong length, wrong version, or an
/// opcode that does not answer the question asked. The last is the important
/// one — a gateway announcement has the same opcode as a solicited reply and
/// arrives unbidden, so a caller that matched on version alone would act on a
/// packet nobody requested.
pub fn parse_external_address(bytes: &[u8]) -> Option<(ResultCode, Ipv4Addr)> {
    if bytes.len() != 12 || bytes[0] != VERSION || bytes[1] != OP_EXTERNAL_ADDRESS | RESPONSE_BIT {
        return None;
    }
    let code = ResultCode::from_wire(u16::from_be_bytes([bytes[2], bytes[3]]));
    // Bytes 4..8 are the gateway's epoch counter, which exists so a client can
    // notice a reboot. Not used here: renewal is on a timer, so a missed reboot
    // costs at most one lifetime of unreachability rather than correctness.
    let addr = Ipv4Addr::new(bytes[8], bytes[9], bytes[10], bytes[11]);
    Some((code, addr))
}

/// Encode a mapping request. Twelve bytes.
pub fn map_request(protocol: Protocol, internal: u16, suggested: u16, lifetime: u32) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[0] = VERSION;
    out[1] = protocol.opcode();
    // out[2..4] is reserved and must be zero.
    out[4..6].copy_from_slice(&internal.to_be_bytes());
    out[6..8].copy_from_slice(&suggested.to_be_bytes());
    out[8..12].copy_from_slice(&lifetime.to_be_bytes());
    out
}

/// Decode a mapping response, checking it answers the protocol asked about.
///
/// A TCP request answered with a UDP mapping is not a mapping this caller can
/// use, and treating the two as interchangeable would advertise a port that
/// forwards the wrong thing.
pub fn parse_map(protocol: Protocol, bytes: &[u8]) -> Option<(ResultCode, Mapping)> {
    if bytes.len() != 16 || bytes[0] != VERSION || bytes[1] != protocol.opcode() | RESPONSE_BIT {
        return None;
    }
    let code = ResultCode::from_wire(u16::from_be_bytes([bytes[2], bytes[3]]));
    let internal = u16::from_be_bytes([bytes[8], bytes[9]]);
    let external = u16::from_be_bytes([bytes[10], bytes[11]]);
    let lifetime = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
    Some((
        code,
        Mapping {
            internal,
            external,
            lifetime,
        },
    ))
}

/// Everything that can go wrong asking a gateway.
#[derive(Debug)]
pub enum PortmapError {
    /// No gateway answered. The ordinary outcome on a host with no NAT-PMP
    /// router, and not an error worth logging loudly.
    NoGateway,
    /// A gateway answered and refused.
    Refused(ResultCode),
    /// A gateway answered with something this does not understand.
    Malformed,
    Io(io::Error),
}

impl std::fmt::Display for PortmapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PortmapError::NoGateway => {
                f.write_str("no NAT-PMP gateway answered; this node can fetch but not seed")
            }
            PortmapError::Refused(ResultCode::NotAuthorized) => f.write_str(
                "the gateway refused: NAT-PMP is present but disabled. Enable it on \
                 the router, or forward a port by hand",
            ),
            PortmapError::Refused(code) => write!(f, "the gateway refused: {code:?}"),
            PortmapError::Malformed => f.write_str("the gateway answered with a malformed packet"),
            PortmapError::Io(e) => write!(f, "port mapping: {e}"),
        }
    }
}

impl std::error::Error for PortmapError {}

impl From<io::Error> for PortmapError {
    fn from(value: io::Error) -> Self {
        PortmapError::Io(value)
    }
}

/// Ask `gateway` to forward `internal` and report the address it forwards from.
///
/// One round trip each for the address and the mapping. Both are needed: the
/// mapping response gives the external *port* and only the address query gives
/// the external *IP*, which is the half a peer actually dials.
///
/// The gateway is a parameter rather than discovered here. Finding a default
/// route is per-platform and belongs to whatever already knows the network
/// layout; [`likely_gateways`] offers the usual guesses for a caller that has
/// nothing better.
pub fn request(
    gateway: Ipv4Addr,
    protocol: Protocol,
    internal: u16,
) -> Result<(Mapping, Ipv4Addr), PortmapError> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    socket.set_read_timeout(Some(TIMEOUT))?;
    let target = SocketAddr::from((gateway, GATEWAY_PORT));

    socket.send_to(&external_address_request(), target)?;
    let mut buffer = [0u8; 32];
    let external_ip = match socket.recv_from(&mut buffer) {
        Ok((read, from)) if from.ip() == gateway => {
            // A reply from somewhere other than the gateway is not this
            // gateway's reply. Cheap to check and it removes the easiest forgery
            // on the segment.
            match parse_external_address(&buffer[..read]) {
                Some((code, _)) if !code.is_success() => return Err(PortmapError::Refused(code)),
                Some((_, addr)) => addr,
                None => return Err(PortmapError::Malformed),
            }
        }
        Ok(_) => return Err(PortmapError::Malformed),
        Err(_) => return Err(PortmapError::NoGateway),
    };

    socket.send_to(
        &map_request(protocol, internal, internal, LIFETIME_SECONDS),
        target,
    )?;
    let (read, from) = socket
        .recv_from(&mut buffer)
        .map_err(|_| PortmapError::NoGateway)?;
    if from.ip() != gateway {
        return Err(PortmapError::Malformed);
    }
    match parse_map(protocol, &buffer[..read]) {
        Some((code, _)) if !code.is_success() => Err(PortmapError::Refused(code)),
        Some((_, mapping)) => Ok((mapping, external_ip)),
        None => Err(PortmapError::Malformed),
    }
}

/// Release a mapping by requesting it with a zero lifetime, as the RFC
/// specifies.
///
/// Best-effort and deliberately ignores the reply: a node shutting down has
/// nothing useful to do with a refusal, and the mapping expires on its own
/// within [`LIFETIME_SECONDS`] anyway. Worth sending because a router's table
/// is finite and a node that leaves quietly holds a port it is not using.
pub fn release(gateway: Ipv4Addr, protocol: Protocol, internal: u16) -> io::Result<()> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    socket.send_to(
        &map_request(protocol, internal, 0, 0),
        SocketAddr::from((gateway, GATEWAY_PORT)),
    )?;
    Ok(())
}

/// The addresses a home gateway is most likely to be at.
///
/// A guess, offered because reading the default route is per-platform and this
/// crate does not link anything that does it. Trying three addresses costs three
/// UDP packets and a quarter of a second, which is cheaper than a dependency and
/// honest about being a heuristic: a gateway somewhere else simply is not found,
/// and the node carries on unable to seed, exactly as it was before.
pub fn likely_gateways() -> [Ipv4Addr; 3] {
    [
        Ipv4Addr::new(192, 168, 1, 1),
        Ipv4Addr::new(192, 168, 0, 1),
        Ipv4Addr::new(10, 0, 0, 1),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address_response(code: u16, addr: [u8; 4]) -> Vec<u8> {
        let mut out = vec![VERSION, OP_EXTERNAL_ADDRESS | RESPONSE_BIT];
        out.extend_from_slice(&code.to_be_bytes());
        out.extend_from_slice(&7u32.to_be_bytes()); // epoch
        out.extend_from_slice(&addr);
        out
    }

    fn map_response(opcode: u8, code: u16, internal: u16, external: u16, life: u32) -> Vec<u8> {
        let mut out = vec![VERSION, opcode | RESPONSE_BIT];
        out.extend_from_slice(&code.to_be_bytes());
        out.extend_from_slice(&7u32.to_be_bytes()); // epoch
        out.extend_from_slice(&internal.to_be_bytes());
        out.extend_from_slice(&external.to_be_bytes());
        out.extend_from_slice(&life.to_be_bytes());
        out
    }

    #[test]
    fn an_external_address_response_round_trips() {
        let bytes = address_response(0, [203, 0, 113, 7]);
        assert_eq!(
            parse_external_address(&bytes),
            Some((ResultCode::Success, Ipv4Addr::new(203, 0, 113, 7)))
        );
    }

    #[test]
    fn a_mapping_response_round_trips() {
        let bytes = map_response(OP_MAP_TCP, 0, 9000, 41234, 3600);
        assert_eq!(
            parse_map(Protocol::Tcp, &bytes),
            Some((
                ResultCode::Success,
                Mapping {
                    internal: 9000,
                    external: 41234,
                    lifetime: 3600,
                }
            ))
        );
    }

    #[test]
    fn a_udp_mapping_does_not_answer_a_tcp_request() {
        // Treating the two as interchangeable would advertise a port that
        // forwards the wrong protocol, which fails in a way that looks like the
        // peer being down.
        let bytes = map_response(OP_MAP_UDP, 0, 9000, 41234, 3600);
        assert_eq!(parse_map(Protocol::Tcp, &bytes), None);
        assert!(parse_map(Protocol::Udp, &bytes).is_some());
    }

    #[test]
    fn a_request_is_never_confused_with_a_response() {
        // The opcode's high bit is the only thing separating them, and a parser
        // that ignored it would read this node's own request, reflected off a
        // hostile host, as the router's answer.
        assert_eq!(
            parse_external_address(&[VERSION, OP_EXTERNAL_ADDRESS]),
            None
        );
        let echoed = map_request(Protocol::Tcp, 9000, 9000, 3600);
        assert_eq!(parse_map(Protocol::Tcp, &echoed), None);
    }

    #[test]
    fn a_refusal_is_reported_rather_than_read_as_an_address() {
        // `NotAuthorized` is the common one: NAT-PMP present and switched off.
        // A parser that returned the address field regardless would hand the
        // caller 0.0.0.0 and call it success.
        let bytes = address_response(2, [0, 0, 0, 0]);
        let (code, _) = parse_external_address(&bytes).expect("parses");
        assert_eq!(code, ResultCode::NotAuthorized);
        assert!(!code.is_success());
    }

    #[test]
    fn junk_and_wrong_versions_are_refused() {
        assert_eq!(parse_external_address(&[]), None);
        assert_eq!(parse_external_address(&[0u8; 11]), None);
        assert_eq!(parse_external_address(&[0u8; 13]), None);
        // PCP (version 2) is a different protocol, not a newer dialect of this
        // one. Refused rather than guessed at.
        let mut pcp = address_response(0, [1, 2, 3, 4]);
        pcp[0] = 2;
        assert_eq!(parse_external_address(&pcp), None);
    }

    #[test]
    fn every_result_code_has_a_meaning_and_unknown_ones_survive() {
        for (wire, want) in [
            (0u16, ResultCode::Success),
            (1, ResultCode::UnsupportedVersion),
            (2, ResultCode::NotAuthorized),
            (3, ResultCode::NetworkFailure),
            (4, ResultCode::OutOfResources),
            (5, ResultCode::UnsupportedOpcode),
        ] {
            assert_eq!(ResultCode::from_wire(wire), want);
        }
        // A code from a later revision must not be read as success.
        assert_eq!(ResultCode::from_wire(99), ResultCode::Unknown(99));
        assert!(!ResultCode::from_wire(99).is_success());
    }

    #[test]
    fn a_release_is_a_zero_lifetime_request() {
        // The RFC's own idiom, and worth pinning: a release that accidentally
        // carried a real lifetime would renew the mapping it meant to drop.
        let bytes = map_request(Protocol::Tcp, 9000, 0, 0);
        assert_eq!(&bytes[8..12], &[0, 0, 0, 0]);
        assert_eq!(&bytes[6..8], &[0, 0], "a release suggests no external port");
        assert_eq!(u16::from_be_bytes([bytes[4], bytes[5]]), 9000);
    }

    #[test]
    fn a_mapping_knows_when_to_renew() {
        let mapping = Mapping {
            internal: 9000,
            external: 9000,
            lifetime: 3600,
        };
        assert_eq!(mapping.renew_after(), Duration::from_secs(1800));
        assert!(!mapping.expires_within(Duration::from_secs(60)));
        let short = Mapping {
            lifetime: 30,
            ..mapping
        };
        assert!(short.expires_within(Duration::from_secs(60)));
    }

    #[test]
    fn the_reserved_field_is_zero_and_the_request_is_the_documented_size() {
        // A gateway may refuse a request with junk in the reserved bytes, and
        // the failure would look like "no NAT-PMP here".
        let bytes = map_request(Protocol::Udp, 1234, 1234, 3600);
        assert_eq!(bytes.len(), 12);
        assert_eq!(&bytes[2..4], &[0, 0]);
        assert_eq!(external_address_request().len(), 2);
    }

    #[test]
    fn asking_an_address_that_hosts_no_gateway_says_so_rather_than_hanging() {
        // The common case on any machine without a NAT-PMP router, including
        // every CI runner. It must be a fast, quiet answer -- a startup that
        // blocked here would be worse than one that never asked.
        let start = std::time::Instant::now();
        let outcome = request(Ipv4Addr::new(127, 0, 0, 1), Protocol::Tcp, 9000);
        assert!(
            matches!(
                outcome,
                Err(PortmapError::NoGateway) | Err(PortmapError::Io(_))
            ),
            "got {outcome:?}"
        );
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "took {:?}, which is long enough to hurt startup",
            start.elapsed()
        );
    }
}
