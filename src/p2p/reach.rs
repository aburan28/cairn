//! Making this node dialable from outside its router, and saying honestly
//! whether that worked.
//!
//! # The problem
//!
//! Two nodes in two homes cannot reach each other. Each sits behind a router
//! that translates addresses on the way out and drops anything inbound that
//! no outbound flow asked for, so each can dial a seed on a public host and
//! neither can be dialled. [`super::portmap`] (NAT-PMP) and [`super::upnp`]
//! (UPnP IGD) each ask a router to forward one port, and until this module
//! neither had a caller: the library spoke two protocols and the daemon spoke
//! none of them. A node behind a home router could fetch and not seed, which
//! `docs/discovery.md` listed as the quiet way the network centralises.
//!
//! # What this module does
//!
//! One thread per daemon, started once the listener is bound:
//!
//! 1. **Decide** whether to try at all ([`decide`]). `CAIRN_PORTMAP=off`, a
//!    loopback listen address (nothing to forward to) and, by default, dials
//!    that go through a proxy (a node hiding from its segment should not ask
//!    its router to advertise it) all mean no. The decision is published, so
//!    a reader sees *why* nothing was mapped rather than a blank.
//! 2. **Find the gateway** ([`candidate_gateways`]). Linux names the default
//!    route in `/proc/net/route`; everywhere else the guess is the `.1` of
//!    this host's own /24, then the three addresses most routers use. UPnP
//!    needs none of this -- its discovery is a multicast question -- which is
//!    one reason it is tried second rather than not at all.
//! 3. **Map** ([`map`]): NAT-PMP first, because it costs a 12-byte datagram
//!    and a quarter-second wait per candidate, then UPnP, which costs a
//!    two-second discovery and two HTTP exchanges. The first protocol that
//!    grants a mapping wins. `CAIRN_PORTMAP=natpmp` or `upnp` tries one only.
//! 4. **Renew** at half the granted lease, forever, and **re-map** from
//!    scratch when a renewal fails: a router that rebooted forgot the
//!    mapping and the node is the last to notice.
//! 5. **Publish** every state change through a callback, which the daemon
//!    points at the session roster so `GET /sessions` and the Network page
//!    carry it as `this_node.external`.
//!
//! # What a mapping proves, which is nothing yet
//!
//! A router's answer is **a claim, checked by use**. The address it reports is
//! published as `mapped` and stays unverified until a peer from outside the
//! LAN completes a handshake inbound -- the roster records that moment as
//! `inbound_from_public_at`, and that record is the only evidence that
//! anybody can actually dial in. A wrong external address costs nobody
//! dialling and never a session with the wrong peer, because the transport
//! authenticates the key and not the address. A mapping whose external
//! address is itself private (carrier-grade NAT, a second router) is
//! published as mapped and *not public*, because that is the common case in
//! which everything here succeeds and nobody can reach the node anyway.
//!
//! # What this is not
//!
//! Not hole punching, not a relay, not AutoNAT. A router with both protocols
//! off, or a carrier that NATs the whole neighbourhood, still needs a port
//! forwarded by hand or a seed on a public host. `docs/two-nodes.md` is the
//! runbook for both.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::time::Duration;

use super::portmap::{self, PortmapError, Protocol};
use super::upnp::{self, UpnpError};
use crate::canonical::Value;
use crate::time::format_iso8601_utc;

/// The environment variable that chooses a mode. See [`Mode::parse`].
pub const ENV: &str = "CAIRN_PORTMAP";

/// The environment variable that forwards the HTTP port as well. Off unless
/// set: a forwarded HTTP side makes this node reachable from the internet, a
/// public seed's surface, which a fleet leader behind a home router wants so
/// that rented machines can join it (`docs/design/fleet-enrollment.md` §12)
/// and nobody else should get by default. See [`decide_http`].
pub const HTTP_ENV: &str = "CAIRN_PORTMAP_HTTP";

/// How long to wait before asking again after nothing granted a mapping.
///
/// Five minutes. A router that is not there will not appear in the next
/// second, and a router that refused will not change its mind; but an
/// operator who turns UPnP on after reading the log should not have to
/// restart the node to find out whether it worked.
pub const RETRY_SECONDS: u64 = 300;

/// The shortest renewal interval, whatever lease the gateway granted. A
/// gateway that grants ten-second leases is asking to be polled, and a node
/// that complied would be a nuisance on its own LAN.
pub const MIN_RENEW_SECONDS: u64 = 60;

/// The address this host's own LAN address is discovered *toward*. No packet
/// is sent: a UDP socket "connected" to it merely picks the interface the
/// routing table would use, which is the interface the gateway is on.
const PROBE_TARGET: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);

// -- deciding -----------------------------------------------------------------

/// What the operator asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// NAT-PMP, then UPnP. The default.
    Auto,
    /// Ask nothing.
    Off,
    /// NAT-PMP only.
    NatPmp,
    /// UPnP IGD only.
    Upnp,
}

impl Mode {
    /// Read a `CAIRN_PORTMAP` value. `None` for a spelling this does not know.
    pub fn parse(raw: &str) -> Option<Mode> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "" | "auto" | "on" | "1" => Some(Mode::Auto),
            "off" | "0" | "none" => Some(Mode::Off),
            "natpmp" | "nat-pmp" | "pmp" => Some(Mode::NatPmp),
            "upnp" => Some(Mode::Upnp),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Auto => "auto",
            Mode::Off => "off",
            Mode::NatPmp => "natpmp",
            Mode::Upnp => "upnp",
        }
    }

    /// The protocols this mode tries, in order.
    pub fn methods(self) -> &'static [Method] {
        match self {
            Mode::Auto => &[Method::NatPmp, Method::Upnp],
            Mode::Off => &[],
            Mode::NatPmp => &[Method::NatPmp],
            Mode::Upnp => &[Method::Upnp],
        }
    }
}

/// Whether to try, and if not, why not -- in words a reader will see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub mode: Mode,
    /// Set when `mode` is [`Mode::Off`]: the reason, for the log and the
    /// roster. Also set when an unknown value was corrected to `auto`.
    pub note: Option<String>,
}

/// Decide whether to forward the HTTP port, from `CAIRN_PORTMAP_HTTP` and the
/// address the HTTP side listens on. The opposite default to [`decide`]:
/// unset, empty or unreadable is off, because this is an opt-in to being
/// reachable and a typo should not open a port.
pub fn decide_http(env: Option<&str>, listen: IpAddr) -> Decision {
    let off = |note: String| Decision {
        mode: Mode::Off,
        note: Some(note),
    };
    let raw = match env.map(str::trim) {
        None | Some("") => {
            return off(format!(
                "off: {HTTP_ENV} is unset; `{HTTP_ENV}=on` forwards the HTTP port, which makes \
                 this node reachable from the internet"
            ))
        }
        Some(raw) => raw,
    };
    let mode = match Mode::parse(raw) {
        Some(Mode::Off) => return off(format!("off ({HTTP_ENV})")),
        Some(mode) => mode,
        None => {
            return off(format!(
                "off: {HTTP_ENV}={raw:?} is not on, off, natpmp or upnp"
            ))
        }
    };
    if listen.is_loopback() {
        return off(format!(
            "off: the HTTP side listens on {listen}, which nothing outside this host can be \
             forwarded to; --serve 0.0.0.0:<port> to be reachable"
        ));
    }
    Decision { mode, note: None }
}

/// Decide from the environment value, the listen address and whether dials
/// go through a proxy. Pure, so the three reasons for `off` are tested
/// rather than read out of a log.
pub fn decide(env: Option<&str>, listen: IpAddr, proxied: bool) -> Decision {
    let (requested, note) = match env {
        None => (None, None),
        Some(raw) => match Mode::parse(raw) {
            Some(mode) => (Some(mode), None),
            None => (
                Some(Mode::Auto),
                Some(format!(
                    "{ENV}={raw:?} is not auto, off, natpmp or upnp; using auto"
                )),
            ),
        },
    };
    if requested == Some(Mode::Off) {
        return Decision {
            mode: Mode::Off,
            note: Some(format!("off ({ENV})")),
        };
    }
    if listen.is_loopback() {
        return Decision {
            mode: Mode::Off,
            note: Some(format!(
                "off: listening on {listen}, which nothing outside this host can be forwarded to; \
                 --listen 0.0.0.0:<port> to be reachable"
            )),
        };
    }
    if requested.is_none() && proxied {
        return Decision {
            mode: Mode::Off,
            note: Some(format!(
                "off: dials go through a proxy, and a node hiding from its segment does not ask \
                 its router to advertise it; {ENV}=auto turns it on"
            )),
        };
    }
    Decision {
        mode: requested.unwrap_or(Mode::Auto),
        note,
    }
}

// -- what came back ---------------------------------------------------------------

/// Which protocol granted a mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    NatPmp,
    Upnp,
}

impl Method {
    pub fn as_str(self) -> &'static str {
        match self {
            Method::NatPmp => "natpmp",
            Method::Upnp => "upnp",
        }
    }
}

/// A mapping a gateway granted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapped {
    pub method: Method,
    /// The gateway that granted it, as seen from this host.
    pub gateway: Ipv4Addr,
    /// The port this node listens on.
    pub internal: u16,
    /// Where a peer outside dials: the gateway's external address and the
    /// port it forwards. A claim until `inbound_from_public_at` says otherwise.
    pub external: SocketAddrV4,
    /// Seconds the gateway committed to. Zero is a permanent mapping, which
    /// only UPnP grants (error 725 asks for it) and only this node deletes.
    pub lease: u32,
    /// The UPnP service that granted it, kept so renewal and deletion go to
    /// the same control URL rather than rediscovering one.
    pub upnp: Option<upnp::Gateway>,
}

impl Mapped {
    /// When to renew: half the lease, never under [`MIN_RENEW_SECONDS`], and
    /// half the default lease for a permanent mapping -- which needs no
    /// renewing but does need re-asserting after a router reboot forgets it.
    pub fn renew_after(&self) -> Duration {
        let lease = if self.lease == 0 {
            upnp::LEASE_SECONDS
        } else {
            self.lease
        };
        Duration::from_secs((u64::from(lease) / 2).max(MIN_RENEW_SECONDS))
    }

    /// Whether the address a peer would dial is one a peer can dial.
    pub fn public(&self) -> bool {
        is_public(IpAddr::V4(*self.external.ip()))
    }
}

/// One protocol's answer when it did not grant a mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Declined {
    pub method: Method,
    pub detail: String,
}

/// Why no mapping was made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// Nothing answered either protocol. The ordinary outcome on a host with
    /// no mapping-capable router, and not an error worth a warning.
    NoGateway,
    /// At least one gateway answered and none granted a mapping.
    Declined(Vec<Declined>),
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Failure::NoGateway => f.write_str(
                "no NAT-PMP or UPnP gateway answered; this node can be dialled from its LAN and \
                 from nowhere else unless a port is forwarded by hand",
            ),
            Failure::Declined(answers) => {
                let parts: Vec<String> = answers
                    .iter()
                    .map(|d| format!("{}: {}", d.method.as_str(), d.detail))
                    .collect();
                write!(f, "a gateway answered and refused ({})", parts.join("; "))
            }
        }
    }
}

// -- finding the gateway -------------------------------------------------------------

/// Addresses to try NAT-PMP against, most likely first and without
/// duplicates: the default route where the OS will say, then the `.1` of
/// this host's own /24, then the usual suspects.
pub fn candidate_gateways() -> Vec<Ipv4Addr> {
    let mut out = Vec::with_capacity(5);
    let mut push = |addr: Ipv4Addr| {
        if !out.contains(&addr) {
            out.push(addr);
        }
    };
    if let Some(gateway) = default_gateway() {
        push(gateway);
    }
    if let Some(local) = local_address(PROBE_TARGET) {
        let [a, b, c, _] = local.octets();
        push(Ipv4Addr::new(a, b, c, 1));
    }
    for addr in portmap::likely_gateways() {
        push(addr);
    }
    out
}

/// The default gateway, where the operating system will say. Linux only;
/// elsewhere `None`, and [`candidate_gateways`] falls back to guessing.
pub fn default_gateway() -> Option<Ipv4Addr> {
    #[cfg(target_os = "linux")]
    {
        let text = std::fs::read_to_string("/proc/net/route").ok()?;
        parse_proc_route(&text)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Read the lowest-metric default route out of `/proc/net/route`.
///
/// Columns are `Iface Destination Gateway Flags RefCnt Use Metric Mask ...`,
/// addresses are eight hex digits in host byte order on a little-endian
/// kernel, and a default route has destination `00000000` with the gateway
/// flag (`0x2`) set. Pure, and tested against the file as the kernel writes it.
pub fn parse_proc_route(text: &str) -> Option<Ipv4Addr> {
    let mut best: Option<(u32, Ipv4Addr)> = None;
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 8 || fields[1] != "00000000" {
            continue;
        }
        let flags = u32::from_str_radix(fields[3], 16).ok()?;
        if flags & 0x2 == 0 {
            continue;
        }
        let raw = u32::from_str_radix(fields[2], 16).ok()?;
        let gateway = Ipv4Addr::from(raw.to_le_bytes());
        if gateway.is_unspecified() {
            continue;
        }
        let metric = fields[6].parse::<u32>().unwrap_or(u32::MAX);
        if best.is_none_or(|(m, _)| metric < m) {
            best = Some((metric, gateway));
        }
    }
    best.map(|(_, gateway)| gateway)
}

/// This host's own address on the interface that reaches `toward`. No packet
/// leaves: a connected UDP socket only consults the routing table.
pub fn local_address(toward: Ipv4Addr) -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    socket.connect((toward, 9)).ok()?;
    match socket.local_addr().ok()? {
        SocketAddr::V4(addr) if !addr.ip().is_unspecified() => Some(*addr.ip()),
        _ => None,
    }
}

/// Whether an address is one a stranger on the internet could dial.
///
/// `Ipv4Addr::is_global` is what this wants and is not stable, so the
/// exclusions are spelled out: unspecified, loopback, link-local, the three
/// private blocks, the carrier-grade block (`100.64/10`, which is what
/// "double NAT" usually looks like from inside), `0/8`, multicast,
/// broadcast and the reserved `240/4`. The documentation ranges are left
/// in, so tests can use `203.0.113.x` as a public-looking address. For
/// IPv6: unspecified, loopback, unique-local and link-local are not public;
/// a v4-mapped address is judged as the v4 address it carries.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, _, _] = v4.octets();
            !(v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_private()
                || v4.is_multicast()
                || v4.is_broadcast()
                || a == 0
                || (a == 100 && (64..=127).contains(&b))
                || a >= 240)
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public(IpAddr::V4(v4));
            }
            let segments = v6.segments();
            !(v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || (segments[0] & 0xfe00) == 0xfc00
                || (segments[0] & 0xffc0) == 0xfe80)
        }
    }
}

// -- mapping ---------------------------------------------------------------------

/// Ask for `internal` to be forwarded, by every protocol `mode` allows, in
/// order, stopping at the first that grants it.
pub fn map(mode: Mode, internal: u16) -> Result<Mapped, Failure> {
    let mut declined = Vec::new();
    let mut heard_anyone = false;
    for method in mode.methods() {
        let attempt = match method {
            Method::NatPmp => map_natpmp(internal),
            Method::Upnp => map_upnp(internal),
        };
        match attempt {
            Ok(mapped) => return Ok(mapped),
            Err(Failure::NoGateway) => {}
            Err(Failure::Declined(answers)) => {
                heard_anyone = true;
                declined.extend(answers);
            }
        }
    }
    if heard_anyone {
        Err(Failure::Declined(declined))
    } else {
        Err(Failure::NoGateway)
    }
}

/// Renew a mapping with the gateway that granted it. A failure here is the
/// caller's cue to [`map`] again from scratch.
pub fn renew(mapped: &Mapped) -> Result<Mapped, Failure> {
    match (mapped.method, &mapped.upnp) {
        (Method::NatPmp, _) => natpmp_at(mapped.gateway, mapped.internal),
        (Method::Upnp, Some(gateway)) => upnp_at(gateway, mapped.internal),
        // Unreachable by construction -- `map_upnp` always fills `upnp` --
        // but a mapping is data, and data is re-mapped rather than trusted.
        (Method::Upnp, None) => map_upnp(mapped.internal),
    }
}

/// Give the mapping back. Best effort on the way out: the lease expires
/// without this, except a permanent UPnP one, which is the case that makes
/// this worth calling.
pub fn release(mapped: &Mapped) {
    let outcome = match (mapped.method, &mapped.upnp) {
        (Method::NatPmp, _) => portmap::release(mapped.gateway, Protocol::Tcp, mapped.internal)
            .map_err(|e| e.to_string()),
        (Method::Upnp, Some(gateway)) => {
            upnp::delete_mapping(gateway, Protocol::Tcp, mapped.external.port())
                .map_err(|e| e.to_string())
        }
        (Method::Upnp, None) => Ok(()),
    };
    if let Err(detail) = outcome {
        log::debug!("portmap: releasing the mapping: {detail}");
    }
}

fn map_natpmp(internal: u16) -> Result<Mapped, Failure> {
    let mut declined = Vec::new();
    for gateway in candidate_gateways() {
        match natpmp_at(gateway, internal) {
            Ok(mapped) => return Ok(mapped),
            Err(Failure::NoGateway) => {}
            Err(Failure::Declined(answers)) => declined.extend(answers),
        }
    }
    if declined.is_empty() {
        Err(Failure::NoGateway)
    } else {
        Err(Failure::Declined(declined))
    }
}

fn natpmp_at(gateway: Ipv4Addr, internal: u16) -> Result<Mapped, Failure> {
    match portmap::request(gateway, Protocol::Tcp, internal) {
        Ok((mapping, external_ip)) => Ok(Mapped {
            method: Method::NatPmp,
            gateway,
            internal,
            external: SocketAddrV4::new(external_ip, mapping.external),
            lease: mapping.lifetime,
            upnp: None,
        }),
        Err(PortmapError::NoGateway) => Err(Failure::NoGateway),
        // A socket that cannot be bound or cannot send is this host's
        // problem, not the gateway's answer; it reads as nobody answering.
        Err(PortmapError::Io(_)) => Err(Failure::NoGateway),
        Err(error) => Err(Failure::Declined(vec![Declined {
            method: Method::NatPmp,
            detail: format!("{gateway}: {error}"),
        }])),
    }
}

fn map_upnp(internal: u16) -> Result<Mapped, Failure> {
    let locations = upnp::discover(upnp::DISCOVERY_TIMEOUT).map_err(|_| Failure::NoGateway)?;
    if locations.is_empty() {
        return Err(Failure::NoGateway);
    }
    let mut declined = Vec::new();
    for location in locations {
        let gateway = match upnp::describe(&location) {
            Ok(gateway) => gateway,
            Err(error) => {
                declined.push(Declined {
                    method: Method::Upnp,
                    detail: format!("{location}: {error}"),
                });
                continue;
            }
        };
        match upnp_at(&gateway, internal) {
            Ok(mapped) => return Ok(mapped),
            Err(Failure::Declined(answers)) => declined.extend(answers),
            Err(Failure::NoGateway) => {}
        }
    }
    if declined.is_empty() {
        Err(Failure::NoGateway)
    } else {
        Err(Failure::Declined(declined))
    }
}

fn upnp_at(gateway: &upnp::Gateway, internal: u16) -> Result<Mapped, Failure> {
    let refused = |error: UpnpError| {
        Failure::Declined(vec![Declined {
            method: Method::Upnp,
            detail: format!("{}: {error}", gateway.host),
        }])
    };
    let client = local_address(gateway.host).ok_or_else(|| {
        Failure::Declined(vec![Declined {
            method: Method::Upnp,
            detail: format!(
                "{}: this host has no IPv4 address on the interface toward the gateway",
                gateway.host
            ),
        }])
    })?;
    let external_ip = upnp::external_address(gateway).map_err(refused)?;
    let lease = upnp::add_mapping(
        gateway,
        Protocol::Tcp,
        client,
        internal,
        internal,
        upnp::LEASE_SECONDS,
    )
    .map_err(refused)?;
    Ok(Mapped {
        method: Method::Upnp,
        gateway: gateway.host,
        internal,
        external: SocketAddrV4::new(external_ip, internal),
        lease,
        upnp: Some(gateway.clone()),
    })
}

// -- the report a reader sees ---------------------------------------------------------

/// Where the attempt stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    /// Not asked, and why.
    Off { reason: String },
    /// Asking.
    Searching,
    /// A gateway granted a mapping. A claim, checked by use.
    Mapped(Mapped),
    /// Nothing granted one; the attempt repeats.
    Failed { detail: String, retry_in: u64 },
}

/// What the daemon publishes about its own reachability: the mode, the
/// state, when it entered it and when it was last renewed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub mode: Mode,
    pub state: State,
    /// When the current state began.
    pub since: u64,
    /// The last successful renewal, for a mapping.
    pub renewed_at: Option<u64>,
    /// Attempts so far, so a reader can tell a first try from a long siege.
    pub attempts: u64,
}

impl Report {
    pub fn off(mode: Mode, reason: String, now: u64) -> Report {
        Report {
            mode,
            state: State::Off { reason },
            since: now,
            renewed_at: None,
            attempts: 0,
        }
    }

    /// The JSON a reader gets as `this_node.external`. Every field present in
    /// every state, so a page can read the shape without reading the status.
    pub fn to_value(&self) -> Value {
        let (status, detail, mapped) = match &self.state {
            State::Off { reason } => ("off", Some(reason.clone()), None),
            State::Searching => ("searching", None, None),
            State::Mapped(mapped) => {
                let detail = if mapped.public() {
                    None
                } else {
                    Some(format!(
                        "the gateway's own address {} is not public: a second router or a \
                         carrier-grade NAT stands in front of it, and nobody outside can dial it",
                        mapped.external.ip()
                    ))
                };
                ("mapped", detail, Some(mapped))
            }
            State::Failed { detail, .. } => ("failed", Some(detail.clone()), None),
        };
        let opt_string = |s: Option<String>| s.map(Value::string).unwrap_or(Value::Null);
        let retry_in = match &self.state {
            State::Failed { retry_in, .. } => Value::Int(i128::from(*retry_in)),
            _ => Value::Null,
        };
        Value::object([
            ("status", Value::string(status)),
            ("mode", Value::string(self.mode.as_str())),
            (
                "method",
                opt_string(mapped.map(|m| m.method.as_str().to_string())),
            ),
            ("gateway", opt_string(mapped.map(|m| m.gateway.to_string()))),
            (
                "address",
                opt_string(mapped.map(|m| m.external.to_string())),
            ),
            (
                "public",
                match mapped {
                    Some(m) => Value::Bool(m.public()),
                    None => Value::Null,
                },
            ),
            (
                "lease_seconds",
                match mapped {
                    Some(m) => Value::Int(i128::from(m.lease)),
                    None => Value::Null,
                },
            ),
            ("detail", opt_string(detail)),
            ("since", Value::string(iso(self.since))),
            ("renewed_at", opt_string(self.renewed_at.map(iso))),
            ("retry_in_seconds", retry_in),
            ("attempts", Value::Int(i128::from(self.attempts))),
        ])
    }
}

fn iso(unix: u64) -> String {
    format_iso8601_utc(i64::try_from(unix).unwrap_or(i64::MAX))
}

// -- the thread ------------------------------------------------------------------------

/// Map, renew and re-map for the life of the process, publishing each state
/// change through `publish`. Never returns; the daemon runs it on a thread of
/// its own, because every call in here waits on a router.
///
/// `publish` is a callback rather than a roster so this module depends on
/// nothing that depends on it; the daemon hands it a closure over the
/// session roster.
pub fn run(mode: Mode, internal: u16, publish: impl Fn(Report)) -> ! {
    let mut attempts: u64 = 0;
    loop {
        attempts += 1;
        publish(Report {
            mode,
            state: State::Searching,
            since: crate::time::unix_seconds(),
            renewed_at: None,
            attempts,
        });
        let mut mapped = match map(mode, internal) {
            Ok(mapped) => mapped,
            Err(failure) => {
                // Silence from every gateway is the common case, not a fault;
                // a refusal is something the operator can act on.
                match &failure {
                    Failure::NoGateway => log::info!("portmap: {failure}"),
                    Failure::Declined(_) => log::warn!("portmap: {failure}"),
                }
                publish(Report {
                    mode,
                    state: State::Failed {
                        detail: failure.to_string(),
                        retry_in: RETRY_SECONDS,
                    },
                    since: crate::time::unix_seconds(),
                    renewed_at: None,
                    attempts,
                });
                std::thread::sleep(Duration::from_secs(RETRY_SECONDS));
                continue;
            }
        };
        announce(&mapped);
        let since = crate::time::unix_seconds();
        publish(Report {
            mode,
            state: State::Mapped(mapped.clone()),
            since,
            renewed_at: None,
            attempts,
        });
        loop {
            std::thread::sleep(mapped.renew_after());
            match renew(&mapped) {
                Ok(renewed) => {
                    if renewed.external != mapped.external {
                        // The router's external address moved -- a DHCP
                        // renewal upstream, usually. Said, because every peer
                        // holding the old address now dials nothing.
                        log::info!(
                            "portmap: external address moved from {} to {}",
                            mapped.external,
                            renewed.external
                        );
                    }
                    mapped = renewed;
                    publish(Report {
                        mode,
                        state: State::Mapped(mapped.clone()),
                        since,
                        renewed_at: Some(crate::time::unix_seconds()),
                        attempts,
                    });
                }
                Err(failure) => {
                    log::warn!(
                        "portmap: renewing the {} mapping failed ({failure}); mapping again",
                        mapped.method.as_str()
                    );
                    break;
                }
            }
        }
    }
}

fn announce(mapped: &Mapped) {
    let lease = if mapped.lease == 0 {
        "permanent".to_string()
    } else {
        format!("{}s", mapped.lease)
    };
    if mapped.public() {
        log::info!(
            "portmap: {} at {} forwards {} to :{} ({lease} lease); a claim until a peer outside \
             dials in -- `GET /sessions` says when one has",
            mapped.method.as_str(),
            mapped.gateway,
            mapped.external,
            mapped.internal
        );
    } else {
        log::warn!(
            "portmap: {} at {} forwards {} to :{} ({lease} lease), but {} is not a public address: \
             a second router or a carrier-grade NAT stands in front of it and nobody outside can \
             dial this node without a port forwarded there too",
            mapped.method.as_str(),
            mapped.gateway,
            mapped.external,
            mapped.internal,
            mapped.external.ip()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_http_port_is_forwarded_only_when_asked_and_only_from_a_reachable_listen() {
        let wildcard: IpAddr = "0.0.0.0".parse().unwrap();
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        for unset in [None, Some(""), Some("  ")] {
            let decision = decide_http(unset, wildcard);
            assert_eq!(decision.mode, Mode::Off, "{unset:?}");
            assert!(decision.note.unwrap().contains(HTTP_ENV));
        }
        assert_eq!(decide_http(Some("on"), wildcard).mode, Mode::Auto);
        assert_eq!(decide_http(Some("upnp"), wildcard).mode, Mode::Upnp);
        assert_eq!(decide_http(Some("off"), wildcard).mode, Mode::Off);
        assert_eq!(
            decide_http(Some("yes please"), wildcard).mode,
            Mode::Off,
            "a typo opens no port"
        );
        let local = decide_http(Some("on"), loopback);
        assert_eq!(local.mode, Mode::Off);
        assert!(local.note.unwrap().contains("--serve"));
    }

    const ROUTE: &str =
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
eth0\t00000000\t010200C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
eth0\t000200C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n\
wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n";

    #[test]
    fn the_default_route_with_the_lowest_metric_is_read_in_the_kernels_byte_order() {
        assert_eq!(parse_proc_route(ROUTE), Some(Ipv4Addr::new(192, 0, 2, 1)));
        // A table with only a connected route has no gateway.
        let connected = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n\
eth0\t000200C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\n";
        assert_eq!(parse_proc_route(connected), None);
        // A default route without the gateway flag is a point-to-point
        // link, not a router to ask.
        let p2p = "hdr\nppp0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\n";
        assert_eq!(parse_proc_route(p2p), None);
        assert_eq!(parse_proc_route(""), None);
        assert_eq!(parse_proc_route("garbage\nmore garbage"), None);
    }

    #[test]
    fn the_mode_is_read_leniently_and_unknown_values_fall_back_to_auto_with_a_note() {
        assert_eq!(Mode::parse("auto"), Some(Mode::Auto));
        assert_eq!(Mode::parse(" UPnP "), Some(Mode::Upnp));
        assert_eq!(Mode::parse("nat-pmp"), Some(Mode::NatPmp));
        assert_eq!(Mode::parse("0"), Some(Mode::Off));
        assert_eq!(Mode::parse("sometimes"), None);

        let lan = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let d = decide(Some("sometimes"), lan, false);
        assert_eq!(d.mode, Mode::Auto);
        assert!(d.note.as_deref().unwrap().contains("using auto"));
        assert_eq!(
            decide(None, lan, false),
            Decision {
                mode: Mode::Auto,
                note: None
            }
        );
        assert_eq!(
            decide(Some("upnp"), lan, false),
            Decision {
                mode: Mode::Upnp,
                note: None
            }
        );
    }

    #[test]
    fn off_is_decided_for_the_three_reasons_and_each_says_which() {
        let lan = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let explicit = decide(Some("off"), lan, false);
        assert_eq!(explicit.mode, Mode::Off);
        assert!(explicit.note.as_deref().unwrap().contains(ENV));

        let loopback = decide(None, IpAddr::V4(Ipv4Addr::LOCALHOST), false);
        assert_eq!(loopback.mode, Mode::Off);
        assert!(
            loopback.note.as_deref().unwrap().contains("loopback")
                || loopback.note.as_deref().unwrap().contains("127.0.0.1")
        );

        let proxied = decide(None, lan, true);
        assert_eq!(proxied.mode, Mode::Off);
        assert!(proxied.note.as_deref().unwrap().contains("proxy"));
        // Asked for explicitly, a proxied node still maps: the operator said so.
        assert_eq!(decide(Some("auto"), lan, true).mode, Mode::Auto);
        // Loopback wins over an explicit request: there is nothing to forward to.
        assert_eq!(
            decide(Some("upnp"), IpAddr::V4(Ipv4Addr::LOCALHOST), false).mode,
            Mode::Off
        );
    }

    #[test]
    fn the_methods_follow_the_mode_in_order() {
        assert_eq!(Mode::Auto.methods(), &[Method::NatPmp, Method::Upnp]);
        assert_eq!(Mode::NatPmp.methods(), &[Method::NatPmp]);
        assert_eq!(Mode::Upnp.methods(), &[Method::Upnp]);
        assert!(Mode::Off.methods().is_empty());
    }

    #[test]
    fn public_addresses_exclude_every_block_a_stranger_cannot_dial() {
        let v4 = |s: &str| IpAddr::V4(s.parse().unwrap());
        for private in [
            "0.0.0.0",
            "0.1.2.3",
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.1.1",
            "169.254.1.1",
            "100.64.0.1",
            "100.127.255.254",
            "224.0.0.1",
            "239.255.255.250",
            "240.0.0.1",
            "255.255.255.255",
        ] {
            assert!(!is_public(v4(private)), "{private} is not public");
        }
        for public in [
            "203.0.113.7",
            "44.251.117.84",
            "100.63.0.1",
            "100.128.0.1",
            "172.32.0.1",
            "8.8.8.8",
        ] {
            assert!(is_public(v4(public)), "{public} is public");
        }
        let v6 = |s: &str| IpAddr::V6(s.parse().unwrap());
        assert!(!is_public(v6("::1")));
        assert!(!is_public(v6("::")));
        assert!(!is_public(v6("fe80::1")));
        assert!(!is_public(v6("fd00::1")));
        assert!(!is_public(v6("fc00::1")));
        assert!(!is_public(v6("ff02::1")));
        assert!(!is_public(v6("::ffff:192.168.1.1")));
        assert!(is_public(v6("::ffff:203.0.113.7")));
        assert!(is_public(v6("2001:db8::1")));
    }

    fn mapped(ip: [u8; 4], lease: u32) -> Mapped {
        Mapped {
            method: Method::Upnp,
            gateway: Ipv4Addr::new(192, 168, 1, 1),
            internal: 9000,
            external: SocketAddrV4::new(Ipv4Addr::from(ip), 9000),
            lease,
            upnp: None,
        }
    }

    #[test]
    fn renewal_is_half_the_lease_floored_and_a_permanent_mapping_is_still_reasserted() {
        assert_eq!(
            mapped([203, 0, 113, 7], 3600).renew_after(),
            Duration::from_secs(1800)
        );
        assert_eq!(
            mapped([203, 0, 113, 7], 10).renew_after(),
            Duration::from_secs(MIN_RENEW_SECONDS)
        );
        assert_eq!(
            mapped([203, 0, 113, 7], 0).renew_after(),
            Duration::from_secs(u64::from(upnp::LEASE_SECONDS) / 2)
        );
    }

    #[test]
    fn the_report_carries_every_field_in_every_state_and_says_when_a_mapping_is_not_public() {
        let fields = [
            "status",
            "mode",
            "method",
            "gateway",
            "address",
            "public",
            "lease_seconds",
            "detail",
            "since",
            "renewed_at",
            "retry_in_seconds",
            "attempts",
        ];
        let get = |value: &Value, key: &str| -> Value {
            match value {
                Value::Object(map) => map.get(key).cloned().expect(key),
                other => panic!("not an object: {other:?}"),
            }
        };

        let off = Report::off(Mode::Off, "off (CAIRN_PORTMAP)".into(), 100).to_value();
        for field in fields {
            get(&off, field);
        }
        assert_eq!(get(&off, "status"), Value::string("off"));
        assert_eq!(get(&off, "address"), Value::Null);
        assert_eq!(get(&off, "detail"), Value::string("off (CAIRN_PORTMAP)"));

        let public = Report {
            mode: Mode::Auto,
            state: State::Mapped(mapped([203, 0, 113, 7], 3600)),
            since: 100,
            renewed_at: Some(1900),
            attempts: 1,
        }
        .to_value();
        assert_eq!(get(&public, "status"), Value::string("mapped"));
        assert_eq!(get(&public, "method"), Value::string("upnp"));
        assert_eq!(get(&public, "address"), Value::string("203.0.113.7:9000"));
        assert_eq!(get(&public, "public"), Value::Bool(true));
        assert_eq!(get(&public, "detail"), Value::Null);
        assert_eq!(get(&public, "lease_seconds"), Value::Int(3600));
        assert_eq!(
            get(&public, "renewed_at"),
            Value::string("1970-01-01T00:31:40+00:00")
        );

        let double_nat = Report {
            mode: Mode::Auto,
            state: State::Mapped(mapped([100, 64, 3, 9], 0)),
            since: 100,
            renewed_at: None,
            attempts: 2,
        }
        .to_value();
        assert_eq!(get(&double_nat, "public"), Value::Bool(false));
        assert!(
            matches!(get(&double_nat, "detail"), Value::String(s) if s.contains("carrier-grade"))
        );
        assert_eq!(get(&double_nat, "lease_seconds"), Value::Int(0));

        let failed = Report {
            mode: Mode::Upnp,
            state: State::Failed {
                detail: Failure::NoGateway.to_string(),
                retry_in: RETRY_SECONDS,
            },
            since: 100,
            renewed_at: None,
            attempts: 3,
        }
        .to_value();
        assert_eq!(get(&failed, "status"), Value::string("failed"));
        assert_eq!(
            get(&failed, "retry_in_seconds"),
            Value::Int(RETRY_SECONDS as i128)
        );
        assert_eq!(get(&failed, "attempts"), Value::Int(3));
        assert!(
            matches!(get(&failed, "detail"), Value::String(s) if s.contains("forwarded by hand"))
        );
    }

    #[test]
    fn a_refusal_names_the_protocol_and_the_gateway_and_silence_names_neither() {
        let declined = Failure::Declined(vec![
            Declined {
                method: Method::NatPmp,
                detail: "192.168.1.1: the gateway refused: NAT-PMP is present but disabled".into(),
            },
            Declined {
                method: Method::Upnp,
                detail: "192.168.1.1: the gateway refused action AddPortMapping (718)".into(),
            },
        ])
        .to_string();
        assert!(declined.contains("natpmp: 192.168.1.1"));
        assert!(declined.contains("upnp: 192.168.1.1"));
        assert!(Failure::NoGateway.to_string().contains("forwarded by hand"));
    }

    #[test]
    fn candidate_gateways_are_distinct_and_include_the_usual_suspects() {
        let candidates = candidate_gateways();
        let mut sorted = candidates.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            candidates.len(),
            "no duplicates: {candidates:?}"
        );
        for usual in portmap::likely_gateways() {
            assert!(candidates.contains(&usual));
        }
    }
}
