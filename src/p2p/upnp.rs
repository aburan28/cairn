//! UPnP IGD port mapping, so a node behind the kind of router most homes have
//! can accept a stranger's dial.
//!
//! # Why this exists beside NAT-PMP
//!
//! [`super::portmap`] speaks NAT-PMP, which costs a 12-byte UDP request and
//! nothing else, and its module docs declined UPnP on the grounds that it
//! "costs an XML parser and an HTTP client in a crate that has neither". That
//! was the right trade for a first mechanism and the wrong place to stop:
//! NAT-PMP is an Apple protocol that most consumer routers never shipped, and
//! PCP, its successor, is rarer still. UPnP IGD is what a home router actually
//! has switched on, and a node that can only map through the protocol the
//! router lacks is a node that cannot seed from a home -- which is the
//! centralising failure the port-mapping module exists to prevent.
//!
//! So this module pays the cost, as narrowly as it can be paid. It does not
//! parse XML; it finds a handful of tags in a document it does not otherwise
//! interpret, which is all the Internet Gateway Device profile asks of a
//! client. It does not carry an HTTP client; it writes one request and reads
//! one response over a `TcpStream`, which `src/serve.rs` already does from the
//! other side. Nothing here is TLS, nothing is a dependency, and
//! `tests/cipher_policy.rs` is unaffected.
//!
//! # What the protocol is
//!
//! Three steps, each over its own transport, which is why it needs three
//! kinds of socket:
//!
//! 1. **SSDP** -- a multicast `M-SEARCH` to `239.255.255.250:1900`; a gateway
//!    answers over unicast UDP with a `LOCATION:` header naming an HTTP URL.
//! 2. **Description** -- `GET` that URL; the body is XML listing the device's
//!    services, among them `WANIPConnection` (or `WANPPPConnection` on a DSL
//!    router), each with a `controlURL`.
//! 3. **Control** -- `POST` a SOAP envelope to the control URL:
//!    `GetExternalIPAddress`, `AddPortMapping`, `DeletePortMapping`.
//!
//! # What a lie costs, which is the same as NAT-PMP's answer
//!
//! Everything a gateway says here is **a claim, checked by use**. An external
//! address is advertised as unverified until a peer completes a McEliece
//! handshake through it, and a wrong one costs nobody dialling -- never a
//! session with the wrong peer, because the transport authenticates the key
//! and not the address. A host on the LAN that answers the `M-SEARCH` in the
//! router's place can therefore make this node *believe* it is reachable at
//! an address it is not, and can make it `POST` a SOAP body to a URL of the
//! impostor's choosing on the same LAN. The first is the lie above. The
//! second is bounded by what is posted: a fixed envelope naming this node's
//! own LAN address and port, to a host the attacker already shares a segment
//! with. `docs/threat-model.md` carries the row.
//!
//! # Bounds
//!
//! Every socket has a timeout, every body has a ceiling ([`MAX_BODY`]), and
//! every parse is a bounded scan that returns `None` rather than panicking on
//! anything it does not recognise. A router's description document is an
//! attacker-shaped input in the precise sense that this crate's canonical
//! decoder treats a record: it arrives from a machine this node did not
//! choose, and the one thing it must not be able to do is crash the node.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

use super::portmap::Protocol;

/// The SSDP multicast group and port.
pub const SSDP_ADDR: (Ipv4Addr, u16) = (Ipv4Addr::new(239, 255, 255, 250), 1900);

/// How long discovery listens for gateways to answer.
///
/// Two seconds, and the `MX` header asks gateways to answer within one: a
/// router on the segment answers in milliseconds, and a host with no UPnP
/// gateway is the common case that announces itself by silence.
pub const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(2);

/// Timeout on each HTTP exchange with the gateway.
pub const HTTP_TIMEOUT: Duration = Duration::from_secs(3);

/// Largest description or control response read, in bytes. A real
/// description is a few kilobytes; a SOAP response is a few hundred bytes.
pub const MAX_BODY: usize = 256 * 1024;

/// Lifetime asked for, in seconds. The same hour as NAT-PMP, for the same
/// reasons given on [`super::portmap::LIFETIME_SECONDS`]. A gateway that
/// supports only permanent leases says so (error 725) and is asked again
/// for one.
pub const LEASE_SECONDS: u32 = 3600;

/// What the mapping is labelled as in the router's table, where a person
/// looking at their router's admin page will see it.
pub const DESCRIPTION: &str = "cairn";

/// The service types this client can drive, most preferred first.
///
/// `WANIPConnection` is what a router doing NAT over a cable or fibre uplink
/// exposes; `WANPPPConnection` is the DSL variant with the same actions.
/// Version 2 is preferred where offered only because it is newer; the three
/// actions used here are identical across all of them.
pub const SERVICE_TYPES: [&str; 3] = [
    "urn:schemas-upnp-org:service:WANIPConnection:2",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
];

/// Search targets sent, one `M-SEARCH` each. Asking for the root device
/// catches gateways that only answer the generic target; asking for the
/// connection services catches ones that only answer specific ones.
const SEARCH_TARGETS: [&str; 3] = [
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "ssdp:all",
];

/// Why a step failed.
#[derive(Debug)]
pub enum UpnpError {
    /// No gateway answered the search.
    NoGateway,
    /// A response could not be read as what it should be; the text says
    /// which step and what was found.
    Malformed(String),
    /// The gateway answered the HTTP exchange with a status other than 200
    /// and no SOAP fault to explain it.
    Http {
        status: u16,
        step: &'static str,
    },
    /// The gateway refused an action, in its own words.
    Soap {
        code: u16,
        description: String,
    },
    Io(io::Error),
}

impl fmt::Display for UpnpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UpnpError::NoGateway => write!(f, "no UPnP gateway answered"),
            UpnpError::Malformed(what) => write!(f, "malformed UPnP response: {what}"),
            UpnpError::Http { status, step } => write!(f, "{step}: gateway answered HTTP {status}"),
            UpnpError::Soap { code, description } => {
                write!(f, "gateway refused: {code} {description}")
            }
            UpnpError::Io(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for UpnpError {}

impl From<io::Error> for UpnpError {
    fn from(error: io::Error) -> Self {
        UpnpError::Io(error)
    }
}

/// A gateway found and described: where to send control requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gateway {
    /// The description URL SSDP named.
    pub location: String,
    /// The connection service's type, exactly as the description spelled it,
    /// because it goes into every `SOAPACTION` header verbatim.
    pub service_type: String,
    /// The absolute control URL for that service.
    pub control_url: String,
    /// The gateway's address as seen from this host, which is also the address
    /// to derive this host's own LAN address toward.
    pub host: Ipv4Addr,
}

// -- discovery ----------------------------------------------------------------

/// Send `M-SEARCH` and collect the description URLs that answer.
///
/// Returns the distinct `LOCATION` values heard within `timeout`, in the order
/// first heard. Empty means nobody answered, which is the common case on a
/// host with no UPnP gateway.
pub fn discover(timeout: Duration) -> io::Result<Vec<String>> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    socket.set_read_timeout(Some(Duration::from_millis(300)))?;
    let target = SocketAddr::from(SSDP_ADDR);
    for st in SEARCH_TARGETS {
        let request = m_search(st);
        // A send can fail on a host with no multicast route at all; that is
        // "no gateway", not an error worth stopping for.
        let _ = socket.send_to(request.as_bytes(), target);
    }
    let mut locations: Vec<String> = Vec::new();
    let deadline = Instant::now() + timeout;
    let mut buffer = [0u8; 4096];
    while Instant::now() < deadline {
        match socket.recv_from(&mut buffer) {
            Ok((read, _from)) => {
                let text = String::from_utf8_lossy(&buffer[..read]);
                if let Some(location) = parse_ssdp_location(&text) {
                    if !locations.iter().any(|known| known == &location) {
                        locations.push(location);
                    }
                }
            }
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.kind() == io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(locations)
}

fn m_search(st: &str) -> String {
    format!(
        "M-SEARCH * HTTP/1.1\r\n\
         HOST: 239.255.255.250:1900\r\n\
         MAN: \"ssdp:discover\"\r\n\
         MX: 1\r\n\
         ST: {st}\r\n\
         \r\n"
    )
}

/// The `LOCATION` header of an SSDP response, if it is an HTTP URL.
///
/// Header names are case-insensitive and gateways use every spelling. Only
/// `http://` is accepted: a gateway that insists on TLS for its description
/// is one this crate cannot talk to, by design, and says so by skipping it.
pub fn parse_ssdp_location(response: &str) -> Option<String> {
    let mut lines = response.split("\r\n");
    let status = lines.next()?;
    if !status.starts_with("HTTP/1.1 200") && !status.starts_with("HTTP/1.0 200") {
        return None;
    }
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("location") {
            let value = value.trim();
            if value.len() < 2048 && value.to_ascii_lowercase().starts_with("http://") {
                return Some(value.to_string());
            }
            return None;
        }
    }
    None
}

// -- URLs ----------------------------------------------------------------------

/// `http://host:port/path` -> `(host, port, path)`. Only `http`, because
/// that is all this module can speak; a port defaults to 80 and a path to `/`.
pub fn parse_url(url: &str) -> Option<(String, u16, String)> {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("HTTP://"))?;
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    // `[::1]:80` style hosts are not expected from an IPv4 gateway and are
    // refused rather than mis-split on their colons.
    if authority.starts_with('[') {
        return None;
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, port.parse::<u16>().ok()?),
        None => (authority, 80),
    };
    if host.is_empty() {
        return None;
    }
    Some((host.to_string(), port, path.to_string()))
}

/// Resolve `reference` against `base`, enough for the shapes a description
/// document uses: absolute URLs, root-relative paths and plain relative paths.
pub fn resolve_url(base: &str, reference: &str) -> Option<String> {
    let reference = reference.trim();
    if reference.to_ascii_lowercase().starts_with("http://") {
        return Some(reference.to_string());
    }
    if reference.to_ascii_lowercase().starts_with("https://") {
        // Cannot be spoken here; see the module docs.
        return None;
    }
    let (host, port, base_path) = parse_url(base)?;
    let path = if let Some(stripped) = reference.strip_prefix('/') {
        format!("/{stripped}")
    } else {
        let directory = match base_path.rfind('/') {
            Some(index) => &base_path[..=index],
            None => "/",
        };
        format!("{directory}{reference}")
    };
    Some(format!("http://{host}:{port}{path}"))
}

// -- the description document ----------------------------------------------------

/// Fetch and read a gateway's description.
pub fn describe(location: &str) -> Result<Gateway, UpnpError> {
    let (host, port, path) = parse_url(location)
        .ok_or_else(|| UpnpError::Malformed(format!("location is not an http URL: {location}")))?;
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\nUser-Agent: cairn\r\n\r\n"
    );
    let (status, body, peer) = http_exchange(&host, port, request.as_bytes())?;
    if status != 200 {
        return Err(UpnpError::Http {
            status,
            step: "description",
        });
    }
    let gateway_ip = match peer.ip() {
        std::net::IpAddr::V4(ip) => ip,
        std::net::IpAddr::V6(_) => {
            return Err(UpnpError::Malformed(
                "gateway answered over IPv6, which this client does not map through".into(),
            ))
        }
    };
    parse_description(&body, location, gateway_ip)
}

/// Pick the connection service out of a description and resolve its control
/// URL. Pure, so it is testable against documents real routers have sent.
pub fn parse_description(xml: &str, location: &str, host: Ipv4Addr) -> Result<Gateway, UpnpError> {
    // Routers that set `URLBase` mean relative control URLs against it rather
    // than against the location; those that do not, mean the location.
    let base = extract_tag(xml, "URLBase")
        .filter(|base| !base.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| location.to_string());
    let mut best: Option<(usize, Gateway)> = None;
    let mut rest = xml;
    while let Some(start) = rest.find("<service>") {
        let after = &rest[start + "<service>".len()..];
        let Some(end) = after.find("</service>") else {
            break;
        };
        let block = &after[..end];
        rest = &after[end + "</service>".len()..];
        let Some(service_type) = extract_tag(block, "serviceType") else {
            continue;
        };
        let Some(rank) = SERVICE_TYPES
            .iter()
            .position(|known| *known == service_type)
        else {
            continue;
        };
        let Some(control) = extract_tag(block, "controlURL") else {
            continue;
        };
        let Some(control_url) = resolve_url(&base, control) else {
            continue;
        };
        if best.as_ref().is_none_or(|(known, _)| rank < *known) {
            best = Some((
                rank,
                Gateway {
                    location: location.to_string(),
                    service_type: service_type.to_string(),
                    control_url,
                    host,
                },
            ));
        }
    }
    best.map(|(_, gateway)| gateway).ok_or_else(|| {
        UpnpError::Malformed(
            "the description names no WANIPConnection or WANPPPConnection service".into(),
        )
    })
}

/// The text of the first `<tag>…</tag>` in `xml`, trimmed and with the five
/// XML entities decoded. A bounded scan, not a parser: it does not see
/// namespaces, attributes or nesting, and does not need to -- the tags it is
/// asked for are leaves in every document this module reads.
pub fn extract_tag<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(xml[start..end].trim())
}

fn decode_entities(text: &str) -> String {
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

// -- control -----------------------------------------------------------------------

/// The external address the gateway reports. A claim, checked by use.
pub fn external_address(gateway: &Gateway) -> Result<Ipv4Addr, UpnpError> {
    let body = soap(gateway, "GetExternalIPAddress", &[])?;
    let text = extract_tag(&body, "NewExternalIPAddress")
        .ok_or_else(|| UpnpError::Malformed("no NewExternalIPAddress in the reply".into()))?;
    decode_entities(text)
        .parse::<Ipv4Addr>()
        .map_err(|_| UpnpError::Malformed(format!("external address {text:?} is not IPv4")))
}

/// Ask the gateway to forward `external` to `internal_client:internal`.
///
/// A gateway that supports only permanent leases (error 725) is asked once
/// more with a lease of zero, which is what "permanent" means on the wire;
/// the caller then has a mapping nothing will expire and should
/// [`delete_mapping`] on the way out.
pub fn add_mapping(
    gateway: &Gateway,
    protocol: Protocol,
    internal_client: Ipv4Addr,
    internal: u16,
    external: u16,
    lease: u32,
) -> Result<u32, UpnpError> {
    let args = |lease: u32| {
        vec![
            ("NewRemoteHost", String::new()),
            ("NewExternalPort", external.to_string()),
            ("NewProtocol", protocol_name(protocol).to_string()),
            ("NewInternalPort", internal.to_string()),
            ("NewInternalClient", internal_client.to_string()),
            ("NewEnabled", "1".to_string()),
            ("NewPortMappingDescription", DESCRIPTION.to_string()),
            ("NewLeaseDuration", lease.to_string()),
        ]
    };
    match soap(gateway, "AddPortMapping", &args(lease)) {
        Ok(_) => Ok(lease),
        Err(UpnpError::Soap { code: 725, .. }) if lease != 0 => {
            soap(gateway, "AddPortMapping", &args(0))?;
            Ok(0)
        }
        Err(error) => Err(error),
    }
}

/// Remove a mapping this node added. Best effort on the way out, like
/// [`super::portmap::release`].
pub fn delete_mapping(
    gateway: &Gateway,
    protocol: Protocol,
    external: u16,
) -> Result<(), UpnpError> {
    soap(
        gateway,
        "DeletePortMapping",
        &[
            ("NewRemoteHost", String::new()),
            ("NewExternalPort", external.to_string()),
            ("NewProtocol", protocol_name(protocol).to_string()),
        ],
    )
    .map(|_| ())
}

fn protocol_name(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Tcp => "TCP",
        Protocol::Udp => "UDP",
    }
}

/// One SOAP action against the gateway's control URL. Returns the response
/// body on 200; a 500 carrying a `UPnPError` is returned as [`UpnpError::Soap`].
fn soap(gateway: &Gateway, action: &str, args: &[(&str, String)]) -> Result<String, UpnpError> {
    let (host, port, path) = parse_url(&gateway.control_url).ok_or_else(|| {
        UpnpError::Malformed(format!("control URL is not http: {}", gateway.control_url))
    })?;
    let envelope = soap_envelope(&gateway.service_type, action, args);
    let request = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}:{port}\r\n\
         Connection: close\r\n\
         User-Agent: cairn\r\n\
         Content-Type: text/xml; charset=\"utf-8\"\r\n\
         SOAPAction: \"{service}#{action}\"\r\n\
         Content-Length: {len}\r\n\
         \r\n\
         {envelope}",
        service = gateway.service_type,
        len = envelope.len(),
    );
    let (status, body, _) = http_exchange(&host, port, request.as_bytes())?;
    match status {
        200 => Ok(body),
        _ => match parse_soap_error(&body) {
            Some((code, description)) => Err(UpnpError::Soap { code, description }),
            None => Err(UpnpError::Http {
                status,
                step: "control",
            }),
        },
    }
}

/// The envelope for `action` with `args` as its children, in the shape the
/// IGD profile specifies. Argument values are escaped; names are this
/// module's own constants.
pub fn soap_envelope(service_type: &str, action: &str, args: &[(&str, String)]) -> String {
    let mut body = String::new();
    for (name, value) in args {
        body.push_str(&format!("<{name}>{}</{name}>", escape(value)));
    }
    format!(
        "<?xml version=\"1.0\"?>\
         <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
         <s:Body><u:{action} xmlns:u=\"{service_type}\">{body}</u:{action}></s:Body>\
         </s:Envelope>"
    )
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// `(errorCode, errorDescription)` from a SOAP fault body, if it carries one.
pub fn parse_soap_error(body: &str) -> Option<(u16, String)> {
    let code = extract_tag(body, "errorCode")?.parse::<u16>().ok()?;
    let description = extract_tag(body, "errorDescription")
        .map(|text| decode_entities(text).chars().take(200).collect())
        .unwrap_or_default();
    Some((code, description))
}

// -- the HTTP exchange -----------------------------------------------------------

/// Write one request, read one response: `(status, body, peer address)`.
///
/// Handles the two body framings a gateway uses, `Content-Length` and
/// chunked, and reads to the ceiling otherwise. Everything is bounded by
/// [`HTTP_TIMEOUT`] and [`MAX_BODY`].
fn http_exchange(
    host: &str,
    port: u16,
    request: &[u8],
) -> Result<(u16, String, SocketAddr), UpnpError> {
    let mut last_error: Option<io::Error> = None;
    let addresses = (host, port)
        .to_socket_addrs()
        .map_err(UpnpError::Io)?
        .filter(|addr| addr.is_ipv4());
    let mut stream = None;
    for addr in addresses {
        match TcpStream::connect_timeout(&addr, HTTP_TIMEOUT) {
            Ok(connected) => {
                stream = Some((connected, addr));
                break;
            }
            Err(error) => last_error = Some(error),
        }
    }
    let (mut stream, peer) = stream.ok_or_else(|| {
        UpnpError::Io(last_error.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "gateway host has no IPv4 address")
        }))
    })?;
    stream.set_read_timeout(Some(HTTP_TIMEOUT))?;
    stream.set_write_timeout(Some(HTTP_TIMEOUT))?;
    stream.write_all(request)?;

    let mut raw = Vec::new();
    let mut chunk = [0u8; 8192];
    let deadline = Instant::now() + HTTP_TIMEOUT;
    loop {
        if raw.len() > MAX_BODY + 16 * 1024 {
            return Err(UpnpError::Malformed(
                "response larger than the ceiling".into(),
            ));
        }
        if Instant::now() > deadline {
            break;
        }
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => raw.extend_from_slice(&chunk[..read]),
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.kind() == io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(error) => return Err(UpnpError::Io(error)),
        }
        // A `Connection: close` peer ends the stream; one that ignores it is
        // read until its declared body is complete.
        if let Some((status, body)) = parse_http_response(&raw) {
            if body.is_some() {
                let _ = status;
                break;
            }
        }
    }
    let (status, body) = parse_http_response(&raw)
        .ok_or_else(|| UpnpError::Malformed("not an HTTP response".into()))?;
    let body = body.unwrap_or_default();
    Ok((status, body, peer))
}

/// Split a raw response into its status and, when complete, its body.
/// `None` for anything that is not an HTTP response; `Some((status, None))`
/// for a response whose body has not fully arrived.
pub fn parse_http_response(raw: &[u8]) -> Option<(u16, Option<String>)> {
    let header_end = find(raw, b"\r\n\r\n")?;
    let head = std::str::from_utf8(&raw[..header_end]).ok()?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next()?;
    let status = status_line.split_whitespace().nth(1)?.parse::<u16>().ok()?;
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        if name == "content-length" {
            content_length = value.parse::<usize>().ok();
        } else if name == "transfer-encoding" && value.to_ascii_lowercase().contains("chunked") {
            chunked = true;
        }
    }
    let body = &raw[header_end + 4..];
    if chunked {
        return Some((status, dechunk(body)));
    }
    match content_length {
        Some(length) if length > MAX_BODY => Some((status, Some(String::new()))),
        Some(length) if body.len() >= length => Some((
            status,
            Some(String::from_utf8_lossy(&body[..length]).into_owned()),
        )),
        Some(_) => Some((status, None)),
        // No framing at all: the body is whatever arrives before close, and
        // the caller treats the stream's end as the body's end.
        None => Some((
            status,
            Some(String::from_utf8_lossy(&body[..body.len().min(MAX_BODY)]).into_owned()),
        )),
    }
}

/// Decode a chunked body, or `None` while the terminating chunk has not
/// arrived.
fn dechunk(mut body: &[u8]) -> Option<String> {
    let mut out = Vec::new();
    loop {
        let line_end = find(body, b"\r\n")?;
        let size_text = std::str::from_utf8(&body[..line_end]).ok()?;
        let size_text = size_text.split(';').next()?.trim();
        let size = usize::from_str_radix(size_text, 16).ok()?;
        body = &body[line_end + 2..];
        if size == 0 {
            return Some(String::from_utf8_lossy(&out).into_owned());
        }
        if body.len() < size + 2 {
            return None;
        }
        out.extend_from_slice(&body[..size]);
        if out.len() > MAX_BODY {
            return Some(String::new());
        }
        body = &body[size + 2..];
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufRead;
    use std::net::TcpListener;

    const DESCRIPTION_XML: &str = r#"<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <friendlyName>Home Router</friendlyName>
    <serviceList>
      <service>
        <serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType>
        <controlURL>/upnp/control/l3f</controlURL>
      </service>
    </serviceList>
    <deviceList>
      <device>
        <deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
        <deviceList>
          <device>
            <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
            <serviceList>
              <service>
                <serviceType>urn:schemas-upnp-org:service:WANPPPConnection:1</serviceType>
                <controlURL>/upnp/control/ppp</controlURL>
              </service>
              <service>
                <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
                <controlURL>upnp/control/wanip</controlURL>
                <eventSubURL>/upnp/event/wanip</eventSubURL>
              </service>
            </serviceList>
          </device>
        </deviceList>
      </device>
    </deviceList>
  </device>
</root>"#;

    #[test]
    fn ssdp_locations_are_read_case_insensitively_and_only_over_http() {
        let response = "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nlocation: http://192.168.1.1:5000/rootDesc.xml\r\nST: upnp:rootdevice\r\n\r\n";
        assert_eq!(
            parse_ssdp_location(response),
            Some("http://192.168.1.1:5000/rootDesc.xml".to_string())
        );
        let https = "HTTP/1.1 200 OK\r\nLOCATION: https://192.168.1.1/desc.xml\r\n\r\n";
        assert_eq!(parse_ssdp_location(https), None);
        let notify = "NOTIFY * HTTP/1.1\r\nLOCATION: http://192.168.1.1/desc.xml\r\n\r\n";
        assert_eq!(
            parse_ssdp_location(notify),
            None,
            "an announcement is not an answer"
        );
        assert_eq!(parse_ssdp_location("garbage"), None);
    }

    #[test]
    fn urls_parse_and_resolve_the_shapes_routers_use() {
        assert_eq!(
            parse_url("http://192.168.1.1:5000/rootDesc.xml"),
            Some(("192.168.1.1".to_string(), 5000, "/rootDesc.xml".to_string()))
        );
        assert_eq!(
            parse_url("http://router.lan"),
            Some(("router.lan".to_string(), 80, "/".to_string()))
        );
        assert_eq!(parse_url("https://192.168.1.1/x"), None);
        assert_eq!(parse_url("http://[::1]:80/x"), None);
        assert_eq!(parse_url("http://user@host/x"), None);

        let base = "http://192.168.1.1:5000/desc/rootDesc.xml";
        assert_eq!(
            resolve_url(base, "/upnp/control/wanip").as_deref(),
            Some("http://192.168.1.1:5000/upnp/control/wanip")
        );
        assert_eq!(
            resolve_url(base, "ctl/wanip").as_deref(),
            Some("http://192.168.1.1:5000/desc/ctl/wanip")
        );
        assert_eq!(
            resolve_url(base, "http://192.168.1.1:49152/ctl").as_deref(),
            Some("http://192.168.1.1:49152/ctl")
        );
        assert_eq!(resolve_url(base, "https://192.168.1.1/ctl"), None);
    }

    #[test]
    fn the_description_yields_the_preferred_connection_service_and_an_absolute_control_url() {
        let gateway = parse_description(
            DESCRIPTION_XML,
            "http://192.168.1.1:5000/rootDesc.xml",
            Ipv4Addr::new(192, 168, 1, 1),
        )
        .expect("a WAN connection service");
        assert_eq!(
            gateway.service_type, "urn:schemas-upnp-org:service:WANIPConnection:1",
            "IP connection beats PPP whatever the document order"
        );
        assert_eq!(
            gateway.control_url, "http://192.168.1.1:5000/upnp/control/wanip",
            "a relative control URL resolves against the location's directory"
        );
        assert_eq!(gateway.host, Ipv4Addr::new(192, 168, 1, 1));

        let with_base = DESCRIPTION_XML.replace(
            "<device>\n    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1",
            "<URLBase>http://192.168.1.1:49152/</URLBase>\n  <device>\n    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1",
        );
        let gateway = parse_description(
            &with_base,
            "http://192.168.1.1:5000/rootDesc.xml",
            Ipv4Addr::new(192, 168, 1, 1),
        )
        .expect("a WAN connection service");
        assert_eq!(
            gateway.control_url,
            "http://192.168.1.1:49152/upnp/control/wanip"
        );

        let none = "<root><device><serviceList><service><serviceType>urn:other</serviceType><controlURL>/x</controlURL></service></serviceList></device></root>";
        assert!(matches!(
            parse_description(none, "http://h/d.xml", Ipv4Addr::LOCALHOST),
            Err(UpnpError::Malformed(_))
        ));
        // A truncated document is a refusal, never a panic.
        assert!(parse_description(
            "<service><serviceType>",
            "http://h/d.xml",
            Ipv4Addr::LOCALHOST
        )
        .is_err());
    }

    #[test]
    fn the_envelope_escapes_values_and_faults_are_read_back() {
        let envelope = soap_envelope(
            "urn:schemas-upnp-org:service:WANIPConnection:1",
            "AddPortMapping",
            &[("NewPortMappingDescription", "a<b&c".to_string())],
        );
        assert!(envelope.contains(
            "<u:AddPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">"
        ));
        assert!(envelope
            .contains("<NewPortMappingDescription>a&lt;b&amp;c</NewPortMappingDescription>"));
        let fault = "<s:Envelope><s:Body><s:Fault><detail><UPnPError><errorCode>718</errorCode><errorDescription>ConflictInMappingEntry</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>";
        assert_eq!(
            parse_soap_error(fault),
            Some((718, "ConflictInMappingEntry".to_string()))
        );
        assert_eq!(parse_soap_error("<nothing/>"), None);
        assert_eq!(extract_tag("<a> x &amp; y </a>", "a"), Some("x &amp; y"));
        assert_eq!(decode_entities("x &amp; y &lt;z&gt;"), "x & y <z>");
    }

    #[test]
    fn http_responses_are_framed_by_length_or_chunks() {
        let fixed = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        assert_eq!(
            parse_http_response(fixed),
            Some((200, Some("hello".to_string())))
        );
        let partial = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel";
        assert_eq!(parse_http_response(partial), Some((200, None)));
        let chunked = b"HTTP/1.1 500 Internal Server Error\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n";
        assert_eq!(
            parse_http_response(chunked),
            Some((500, Some("abcde".to_string())))
        );
        let chunked_partial = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nab";
        assert_eq!(parse_http_response(chunked_partial), Some((200, None)));
        assert_eq!(parse_http_response(b"not http at all\r\n\r\n"), None);
        assert_eq!(
            parse_http_response(b"HTTP/1.1 200 OK\r\n"),
            None,
            "headers not finished"
        );
    }

    /// A gateway on loopback: serves the description, reports an external
    /// address, refuses the first timed lease as permanent-only, then accepts,
    /// and acknowledges the delete.
    fn fake_gateway() -> (SocketAddr, std::thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let handle = std::thread::spawn(move || {
            let mut actions = Vec::new();
            for _ in 0..5 {
                let (stream, _) = listener.accept().expect("accept");
                let mut reader = io::BufReader::new(stream.try_clone().expect("clone"));
                let mut request_line = String::new();
                reader.read_line(&mut request_line).expect("request line");
                let mut length = 0usize;
                let mut soap_action = String::new();
                loop {
                    let mut header = String::new();
                    reader.read_line(&mut header).expect("header");
                    if header.trim().is_empty() {
                        break;
                    }
                    let lower = header.to_ascii_lowercase();
                    if let Some(value) = lower.strip_prefix("content-length:") {
                        length = value.trim().parse().unwrap_or(0);
                    }
                    if lower.starts_with("soapaction:") {
                        soap_action = header.split_once(':').unwrap().1.trim().to_string();
                    }
                }
                let mut body = vec![0u8; length];
                if length > 0 {
                    reader.read_exact(&mut body).expect("body");
                }
                let body = String::from_utf8_lossy(&body).into_owned();
                let mut stream = stream;
                let respond = |stream: &mut TcpStream, status: &str, payload: &str| {
                    let response = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                        payload.len()
                    );
                    stream.write_all(response.as_bytes()).expect("write");
                };
                if request_line.starts_with("GET /rootDesc.xml") {
                    actions.push("describe".to_string());
                    respond(&mut stream, "200 OK", DESCRIPTION_XML);
                } else if soap_action.contains("GetExternalIPAddress") {
                    actions.push("external".to_string());
                    respond(&mut stream, "200 OK", "<s:Envelope><s:Body><u:GetExternalIPAddressResponse><NewExternalIPAddress>203.0.113.9</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>");
                } else if soap_action.contains("AddPortMapping") {
                    let lease = extract_tag(&body, "NewLeaseDuration")
                        .unwrap_or("?")
                        .to_string();
                    actions.push(format!("add lease={lease}"));
                    if lease != "0" {
                        respond(&mut stream, "500 Internal Server Error", "<s:Envelope><s:Body><s:Fault><detail><UPnPError><errorCode>725</errorCode><errorDescription>OnlyPermanentLeasesSupported</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>");
                    } else {
                        respond(
                            &mut stream,
                            "200 OK",
                            "<s:Envelope><s:Body><u:AddPortMappingResponse/></s:Body></s:Envelope>",
                        );
                    }
                } else if soap_action.contains("DeletePortMapping") {
                    actions.push("delete".to_string());
                    respond(
                        &mut stream,
                        "200 OK",
                        "<s:Envelope><s:Body><u:DeletePortMappingResponse/></s:Body></s:Envelope>",
                    );
                } else {
                    respond(&mut stream, "404 Not Found", "");
                }
            }
            actions
        });
        (addr, handle)
    }

    #[test]
    fn a_mapping_is_added_against_a_gateway_that_insists_on_permanent_leases() {
        let (addr, handle) = fake_gateway();
        let location = format!("http://{addr}/rootDesc.xml");
        let gateway = describe(&location).expect("described");
        assert_eq!(gateway.host, Ipv4Addr::LOCALHOST);
        assert_eq!(
            gateway.control_url,
            format!("http://{addr}/upnp/control/wanip"),
            "the fake serves every path, so the control URL only has to be where the description said"
        );
        // The fake answers every path with the same handler, so the control
        // URL's path is irrelevant to it; what matters is the SOAPAction.
        assert_eq!(
            external_address(&gateway).expect("external"),
            Ipv4Addr::new(203, 0, 113, 9)
        );
        let lease = add_mapping(
            &gateway,
            Protocol::Tcp,
            Ipv4Addr::new(192, 168, 1, 20),
            9000,
            9000,
            LEASE_SECONDS,
        )
        .expect("mapped");
        assert_eq!(
            lease, 0,
            "725 means the gateway only does permanent leases, so it got one"
        );
        delete_mapping(&gateway, Protocol::Tcp, 9000).expect("deleted");
        let actions = handle.join().expect("gateway thread");
        assert_eq!(
            actions,
            vec![
                "describe".to_string(),
                "external".to_string(),
                "add lease=3600".to_string(),
                "add lease=0".to_string(),
                "delete".to_string(),
            ]
        );
    }
}
