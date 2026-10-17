//! Reaching a fleet leader over Tailscale, without putting TLS in this crate.
//!
//! # Why this exists
//!
//! A fleet member reaches its leader over the leader's HTTP side, which is
//! plaintext on purpose (`tests/cipher_policy.rs`; [`crate::agent::http`]
//! refuses `https://`). [`docs/fleet.md`] has always said what that means
//! across the internet: the fleet's network *is* a tunnel. The tunnels it
//! named were WireGuard by hand, one `ssh -L` per box, or a forwarded port on a
//! home router, which `CAIRN_PORTMAP_HTTP` asks for and carrier-grade NAT
//! refuses. Tailscale is the WireGuard option without the key distribution: a
//! machine that runs `tailscale up` gets an address on the tailnet, every
//! packet between two tailnet addresses is sealed by WireGuard, and NAT
//! traversal (with a relay when traversal fails) is the daemon's problem.
//!
//! So this module does three small things and nothing else:
//!
//! 1. **Binds to the tailnet and this machine only.** `--serve tailnet:8080`
//!    resolves to this machine's tailnet address ([`resolve_listen`]) and
//!    binds its loopback twin on the same port ([`loopback_twin`]), so a
//!    leader's HTTP side is reachable by tailnet peers and local tools, and by
//!    nobody on the LAN or the internet. That is the difference from
//!    `0.0.0.0`, which also answers on the tailnet but answers the coffee-shop
//!    Wi-Fi too.
//! 2. **Says where it is.** [`Status::to_value`] is `node.reach.tailnet` on
//!    `GET /network`: the MagicDNS name, the addresses, and the URL a member
//!    should be given.
//! 3. **Fills in invites.** `cairn fleet invite --node tailnet` writes the
//!    MagicDNS URL into the join line ([`node_url`]).
//!
//! # What it does not change
//!
//! **Membership.** A tailnet address is not a credential here. Enrolled fleets
//! admit a request by the member key that signed it, wherever it came from,
//! and that stays true on a tailnet: whoever the tailnet's ACLs let in gets
//! exactly what the internet gets from a public leader, which with
//! `CAIRN_FLEET=enrolled` is nothing signed. There is deliberately no
//! `tailnet` keyword for `CAIRN_FLEET`'s trusted networks, which would make
//! the address the credential again.
//!
//! **The cipher policy.** Nothing here links a TLS or WireGuard crate. It runs
//! the `tailscale` command, the way [`crate::deposit`] runs `curl`, and reads
//! `tailscale status --json`. WireGuard runs in `tailscaled`, outside this
//! process; what this process sees is a socket on an address.
//!
//! **Trust in Tailscale.** The coordination server decides which keys are in
//! the tailnet. A compromised Tailscale account, or a Headscale server, can add
//! a machine that then talks to the leader -- and gets what any stranger gets,
//! per the first point. `docs/threat-model.md` carries the row.
//!
//! [`docs/fleet.md`]: https://github.com/aburan28/cairn/blob/main/docs/fleet.md

use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::canonical::Value;

/// The environment variable naming the `tailscale` command, for a binary that
/// is not on `PATH` -- a launchd agent's `PATH` is almost empty, and the Mac
/// App Store build keeps its CLI inside the app bundle.
pub const COMMAND_ENV: &str = "CAIRN_TAILSCALE";

/// The word that stands for "this machine's tailnet address" in a listen
/// address or a `--node` URL.
pub const KEYWORD: &str = "tailnet";

/// Where the CLI usually is when it is not on `PATH`, tried in order: a
/// launchd agent's `PATH` is `/usr/bin:/bin:/usr/sbin:/sbin`, which has none
/// of Homebrew's prefixes, and the Mac App Store and standalone apps keep the
/// CLI inside the bundle.
const FALLBACK_CLIS: [&str; 3] = [
    "/opt/homebrew/bin/tailscale",
    "/usr/local/bin/tailscale",
    "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
];

/// How long `tailscale status` may take. It answers from the local daemon in
/// milliseconds; a daemon that is wedged should cost a node's start seconds,
/// not hang it.
const STATUS_TIMEOUT: Duration = Duration::from_secs(5);

/// Largest `tailscale status --json` read. A tailnet with thousands of peers
/// prints megabytes; this module reads only `Self` and needs none of them,
/// but the peers come first in nothing, so the document is read whole.
const MAX_STATUS_BYTES: u64 = 32 << 20;

/// The default HTTP port when `tailnet` is given without one: the node's own
/// default for `--serve`.
pub const DEFAULT_PORT: u16 = 8080;

/// This machine on its tailnet, as `tailscale status --json` describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    /// The MagicDNS name without its trailing dot, e.g.
    /// `leader.tail1234.ts.net`. Empty when MagicDNS is off.
    pub dns_name: String,
    /// The tailnet addresses, IPv4 first.
    pub addresses: Vec<IpAddr>,
    /// The tailnet's name (`tail1234.ts.net`, or a Headscale domain), when the
    /// daemon reports it.
    pub tailnet: Option<String>,
}

impl Status {
    /// The tailnet IPv4 address, which every member can dial whether or not
    /// its own tailnet has IPv6 on.
    pub fn ipv4(&self) -> Option<Ipv4Addr> {
        self.addresses.iter().find_map(|a| match a {
            IpAddr::V4(v4) => Some(*v4),
            IpAddr::V6(_) => None,
        })
    }

    /// The host a member should be told to dial: the MagicDNS name when there
    /// is one, which survives the machine being re-added, else the IPv4
    /// address.
    pub fn host(&self) -> Option<String> {
        if !self.dns_name.is_empty() {
            return Some(self.dns_name.clone());
        }
        self.ipv4().map(|v4| v4.to_string())
    }

    /// `node.reach.tailnet` on `GET /network`. `port` is the HTTP side's port;
    /// `bound` is whether that side listens on a tailnet address (or on every
    /// address, which includes it), so the URL is only offered when it works.
    pub fn to_value(&self, port: u16, bound: Option<IpAddr>) -> Value {
        let reachable = bound.is_some_and(|ip| ip.is_unspecified() || self.addresses.contains(&ip));
        let only = bound.is_some_and(|ip| self.addresses.contains(&ip));
        let url = match (reachable, self.host()) {
            (true, Some(host)) => Value::string(format!("http://{host}:{port}")),
            _ => Value::Null,
        };
        Value::object([
            ("dns_name", Value::string(self.dns_name.clone())),
            (
                "addresses",
                Value::array(self.addresses.iter().map(|a| Value::string(a.to_string()))),
            ),
            (
                "tailnet",
                self.tailnet
                    .clone()
                    .map(Value::string)
                    .unwrap_or(Value::Null),
            ),
            ("url", url),
            // True when the HTTP side answers on the tailnet and nowhere
            // else, which is what `--serve tailnet` is for.
            ("tailnet_only", Value::Bool(only)),
        ])
    }
}

/// Why this machine has no usable tailnet address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// No `tailscale` command was found.
    NotInstalled,
    /// The command ran and failed, or timed out.
    Command(String),
    /// The daemon answered, but not with a running, logged-in node.
    NotRunning(String),
    /// The answer was not the JSON this module reads.
    Malformed(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::NotInstalled => write!(
                f,
                "Tailscale is not installed (no `tailscale` on PATH; set {COMMAND_ENV} to its \
                 path). Install it from https://tailscale.com/download and run `tailscale up`"
            ),
            Error::Command(why) => write!(f, "`tailscale status` failed: {why}"),
            Error::NotRunning(state) => write!(
                f,
                "Tailscale is installed but not connected (state {state}); run `tailscale up`"
            ),
            Error::Malformed(why) => write!(f, "could not read `tailscale status --json`: {why}"),
        }
    }
}

impl std::error::Error for Error {}

/// Whether `ip` is in the ranges Tailscale assigns: `100.64.0.0/10` (shared
/// with carrier-grade NAT, so this alone is a hint, not proof) and
/// `fd7a:115c:a1e0::/48`.
pub fn is_tailnet_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            a == 100 && (64..128).contains(&b)
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            s[0] == 0xfd7a && s[1] == 0x115c && s[2] == 0xa1e0
        }
    }
}

/// Whether a host as written in a URL looks like it is on a tailnet: a
/// MagicDNS name or a tailnet address. Used to say "run `tailscale up`" when
/// such a host cannot be reached, never to decide anything.
pub fn looks_like_tailnet_host(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.ends_with(".ts.net") {
        return true;
    }
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
        .is_ok_and(is_tailnet_ip)
}

/// Read `tailscale status --json`. Pure, so every refusal is tested.
///
/// Parsed with `serde_json` rather than [`crate::canonical`]: this is a local
/// daemon's answer, never a record, and the canonical parser's refusal of
/// floats (right at the consensus boundary) would fail on any float a future
/// Tailscale adds to a peer entry this module never reads.
pub fn parse_status(json: &[u8]) -> Result<Status, Error> {
    use serde_json::Value as J;
    let value: J =
        serde_json::from_slice(json).map_err(|e| Error::Malformed(format!("not JSON: {e}")))?;
    let J::Object(top) = &value else {
        return Err(Error::Malformed("not a JSON object".into()));
    };
    let state = match top.get("BackendState") {
        Some(J::String(s)) => s.clone(),
        _ => return Err(Error::Malformed("no BackendState".into())),
    };
    if state != "Running" {
        return Err(Error::NotRunning(state));
    }
    let Some(J::Object(me)) = top.get("Self") else {
        return Err(Error::NotRunning("Running, but without a Self node".into()));
    };
    let dns_name = match me.get("DNSName") {
        Some(J::String(s)) => s.trim_end_matches('.').to_string(),
        _ => String::new(),
    };
    // A name that could smuggle anything into a URL is dropped, not escaped:
    // the address still works.
    let dns_name = if dns_name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
        dns_name
    } else {
        String::new()
    };
    let mut addresses: Vec<IpAddr> = match me.get("TailscaleIPs") {
        Some(J::Array(items)) => items
            .iter()
            .filter_map(|v| v.as_str()?.parse::<IpAddr>().ok())
            .filter(|ip| is_tailnet_ip(*ip))
            .collect(),
        _ => Vec::new(),
    };
    addresses.sort_by_key(|a| a.is_ipv6());
    if addresses.is_empty() {
        return Err(Error::NotRunning(
            "Running, but this node has no tailnet address yet".into(),
        ));
    }
    let tailnet = match top.get("CurrentTailnet") {
        Some(J::Object(t)) => t
            .get("MagicDNSSuffix")
            .and_then(J::as_str)
            .filter(|s| !s.is_empty())
            .or_else(|| t.get("Name").and_then(J::as_str).filter(|s| !s.is_empty()))
            .map(|s| s.trim_end_matches('.').to_string()),
        _ => None,
    };
    Ok(Status {
        dns_name,
        addresses,
        tailnet,
    })
}

/// The `tailscale` command to run: `$CAIRN_TAILSCALE`, else `tailscale` on
/// `PATH`, else the usual install locations ([`FALLBACK_CLIS`]).
fn command_path() -> Option<std::path::PathBuf> {
    if let Some(explicit) = std::env::var_os(COMMAND_ENV).filter(|v| !v.is_empty()) {
        return Some(explicit.into());
    }
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join("tailscale");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    FALLBACK_CLIS
        .iter()
        .map(std::path::Path::new)
        .find(|path| path.is_file())
        .map(std::path::Path::to_path_buf)
}

/// Ask the local Tailscale daemon who this machine is.
pub fn status() -> Result<Status, Error> {
    if crate::deployment::Profile::from_env()
        .map_err(Error::Command)?
        .is_private()
    {
        return Err(Error::Command("CAIRN_NETWORK=private does not probe Tailscale; use an explicit internal or WireGuard IP address".into()));
    }
    let path = command_path().ok_or(Error::NotInstalled)?;
    let mut child = Command::new(&path)
        .args(["status", "--json"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => Error::NotInstalled,
            _ => Error::Command(e.to_string()),
        })?;
    // Read on a thread so a daemon that writes more than a pipe holds cannot
    // deadlock the wait below.
    let mut stdout = child.stdout.take().expect("stdout was piped");
    let reader = std::thread::spawn(move || {
        let mut out = Vec::new();
        let _ = (&mut stdout).take(MAX_STATUS_BYTES).read_to_end(&mut out);
        out
    });
    let deadline = Instant::now() + STATUS_TIMEOUT;
    let exit = loop {
        match child.try_wait() {
            Ok(Some(exit)) => break exit,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(Error::Command(format!(
                    "no answer within {}s",
                    STATUS_TIMEOUT.as_secs()
                )));
            }
            Err(e) => return Err(Error::Command(e.to_string())),
        }
    };
    let out = reader.join().unwrap_or_default();
    // `tailscale status --json` exits non-zero when logged out but still
    // prints the document, whose BackendState says why; read it first.
    match parse_status(&out) {
        Ok(status) => Ok(status),
        Err(Error::Malformed(_)) if !exit.success() => {
            Err(Error::Command(format!("exited with {exit}")))
        }
        Err(other) => Err(other),
    }
}

/// Whether a listen address uses the `tailnet` keyword: `tailnet`,
/// `tailnet:8080`, `tailnet6:8080`.
pub fn is_keyword(spec: &str) -> bool {
    let host = spec.trim().split(':').next().unwrap_or("");
    host.eq_ignore_ascii_case(KEYWORD) || host.eq_ignore_ascii_case("tailnet6")
}

/// Turn a listen address into a socket address, resolving `tailnet[:PORT]` to
/// this machine's tailnet IPv4 address (`tailnet6[:PORT]` for IPv6).
/// Anything else must already be `host:port`. `ask` is [`status`] in
/// production and a fixture in tests.
pub fn resolve_listen(
    spec: &str,
    ask: impl FnOnce() -> Result<Status, Error>,
) -> Result<SocketAddr, String> {
    let spec = spec.trim();
    if !is_keyword(spec) {
        return spec
            .parse::<SocketAddr>()
            .map_err(|_| format!("{spec:?} is not host:port (or {KEYWORD}[:PORT])"));
    }
    let (word, port) = match spec.split_once(':') {
        Some((word, port)) => (
            word,
            port.parse::<u16>()
                .map_err(|_| format!("{spec:?}: {port:?} is not a port"))?,
        ),
        None => (spec, DEFAULT_PORT),
    };
    let status = ask().map_err(|e| format!("{spec}: {e}"))?;
    let want_v6 = word.eq_ignore_ascii_case("tailnet6");
    let ip = status
        .addresses
        .iter()
        .copied()
        .find(|a| a.is_ipv6() == want_v6)
        .ok_or_else(|| {
            format!(
                "{spec}: this machine has no tailnet {} address",
                if want_v6 { "IPv6" } else { "IPv4" }
            )
        })?;
    Ok(SocketAddr::new(ip, port))
}

/// The loopback address on the same port as a tailnet listen address, which
/// a `tailnet` listener also binds: this machine's own tools, its window and
/// a systemd unit's `curl 127.0.0.1:8080/network` keep working, and loopback
/// is exempt from the per-address connection cap a busy reader would hit.
pub fn loopback_twin(addr: SocketAddr) -> SocketAddr {
    let ip = if addr.is_ipv6() {
        IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
    } else {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    };
    SocketAddr::new(ip, addr.port())
}

/// Turn a `--node` value into a node URL, resolving `tailnet[:PORT]` to
/// `http://<MagicDNS name>:<PORT>` for this machine. Anything else is
/// returned unchanged.
pub fn node_url(text: &str, ask: impl FnOnce() -> Result<Status, Error>) -> Result<String, String> {
    let trimmed = text.trim();
    if !is_keyword(trimmed) {
        return Ok(trimmed.to_string());
    }
    let port = match trimmed.split_once(':') {
        Some((_, port)) => port
            .parse::<u16>()
            .map_err(|_| format!("--node {trimmed}: {port:?} is not a port"))?,
        None => DEFAULT_PORT,
    };
    let status = ask().map_err(|e| format!("--node {trimmed}: {e}"))?;
    let host = status
        .host()
        .ok_or_else(|| format!("--node {trimmed}: this machine has no tailnet IPv4 address"))?;
    Ok(format!("http://{host}:{port}"))
}

/// What to tell a member that could not reach a leader on a tailnet.
pub fn unreachable_hint(host: &str) -> Option<String> {
    looks_like_tailnet_host(host).then(|| {
        String::from(
            "the leader is on a tailnet: this machine must be on the same tailnet. Run \
             `tailscale up` (on a rented machine, `tailscale up --auth-key <key> \
             --ephemeral` with a key from the tailnet's admin console), check `tailscale \
             status`, and make sure the tailnet's ACLs let this machine reach the leader's port",
        )
    })
}

/// The ranges [`is_tailnet_ip`] accepts, for documentation and tests.
pub const RANGES: (&str, &str) = ("100.64.0.0/10", "fd7a:115c:a1e0::/48");

#[cfg(test)]
mod tests {
    use super::*;

    const RUNNING: &str = r#"{
      "Version": "1.80.0",
      "BackendState": "Running",
      "Self": {
        "HostName": "leader",
        "DNSName": "leader.tail1234.ts.net.",
        "TailscaleIPs": ["fd7a:115c:a1e0::1234", "100.101.102.103"]
      },
      "CurrentTailnet": {"Name": "ops@example.com", "MagicDNSSuffix": "tail1234.ts.net"},
      "Peer": {"nodekey:abc": {"HostName": "gpu-box-1", "TailscaleIPs": ["100.64.0.9"]}}
    }"#;

    fn running() -> Result<Status, Error> {
        parse_status(RUNNING.as_bytes())
    }

    #[test]
    fn a_float_in_a_peer_entry_does_not_break_the_read() {
        let doc = r#"{"BackendState":"Running","Self":{"DNSName":"a.ts.net.","TailscaleIPs":["100.64.0.2"]},"Peer":{"k":{"RxRate":1.5}}}"#;
        assert_eq!(parse_status(doc.as_bytes()).unwrap().dns_name, "a.ts.net");
    }

    #[test]
    fn a_running_node_reads_its_name_and_addresses_ipv4_first() {
        let s = running().unwrap();
        assert_eq!(s.dns_name, "leader.tail1234.ts.net");
        assert_eq!(s.ipv4(), Some(Ipv4Addr::new(100, 101, 102, 103)));
        assert!(s.addresses[0].is_ipv4() && s.addresses[1].is_ipv6());
        assert_eq!(s.tailnet.as_deref(), Some("tail1234.ts.net"));
        assert_eq!(s.host().as_deref(), Some("leader.tail1234.ts.net"));
    }

    #[test]
    fn a_stopped_or_logged_out_node_is_not_running_and_says_its_state() {
        for state in ["Stopped", "NeedsLogin", "Starting"] {
            let doc = format!(r#"{{"BackendState":"{state}","Self":{{"TailscaleIPs":[]}}}}"#);
            assert_eq!(
                parse_status(doc.as_bytes()),
                Err(Error::NotRunning(state.to_string()))
            );
        }
        let no_ip =
            r#"{"BackendState":"Running","Self":{"DNSName":"x.ts.net.","TailscaleIPs":[]}}"#;
        assert!(matches!(
            parse_status(no_ip.as_bytes()),
            Err(Error::NotRunning(_))
        ));
    }

    #[test]
    fn garbage_is_malformed_not_a_panic() {
        for doc in ["", "not json", "[]", r#"{"Self":{}}"#, "\u{0}"] {
            assert!(
                matches!(parse_status(doc.as_bytes()), Err(Error::Malformed(_))),
                "{doc:?}"
            );
        }
    }

    #[test]
    fn a_dns_name_that_could_break_a_url_is_dropped_and_the_address_used() {
        let doc = r#"{"BackendState":"Running","Self":{"DNSName":"evil.ts.net/@x?","TailscaleIPs":["100.64.1.2"]}}"#;
        let s = parse_status(doc.as_bytes()).unwrap();
        assert_eq!(s.dns_name, "");
        assert_eq!(s.host().as_deref(), Some("100.64.1.2"));
    }

    #[test]
    fn tailnet_ranges_are_recognised_and_neighbours_are_not() {
        for yes in ["100.64.0.1", "100.127.255.254", "fd7a:115c:a1e0::1"] {
            assert!(is_tailnet_ip(yes.parse().unwrap()), "{yes}");
        }
        for no in [
            "100.63.255.255",
            "100.128.0.0",
            "10.0.0.1",
            "192.168.1.1",
            "fd7a:115c:a1e1::1",
            "::1",
        ] {
            assert!(!is_tailnet_ip(no.parse().unwrap()), "{no}");
        }
        assert!(looks_like_tailnet_host("leader.tail1234.ts.net"));
        assert!(looks_like_tailnet_host("LEADER.TAIL1234.TS.NET."));
        assert!(looks_like_tailnet_host("100.101.102.103"));
        assert!(looks_like_tailnet_host("[fd7a:115c:a1e0::1]"));
        assert!(!looks_like_tailnet_host("203.0.113.7"));
        assert!(!looks_like_tailnet_host("ts.net.example.com"));
    }

    #[test]
    fn the_keyword_resolves_to_the_tailnet_address_and_nothing_else_asks() {
        assert_eq!(
            resolve_listen("tailnet:9090", running).unwrap(),
            "100.101.102.103:9090".parse().unwrap()
        );
        assert_eq!(
            resolve_listen("tailnet", running).unwrap().port(),
            DEFAULT_PORT
        );
        assert_eq!(
            resolve_listen("tailnet6:9090", running).unwrap(),
            "[fd7a:115c:a1e0::1234]:9090".parse().unwrap()
        );
        // An ordinary address never runs the command.
        let never = || -> Result<Status, Error> { panic!("asked Tailscale for a literal address") };
        assert_eq!(
            resolve_listen("0.0.0.0:8080", never).unwrap(),
            "0.0.0.0:8080".parse().unwrap()
        );
        assert!(resolve_listen("tailnet:http", running).is_err());
        assert!(resolve_listen("nonsense", || Err(Error::NotInstalled)).is_err());
        let err = resolve_listen("tailnet:8080", || Err(Error::NotInstalled)).unwrap_err();
        assert!(err.contains("tailscale up"), "{err}");
    }

    #[test]
    fn the_loopback_twin_keeps_the_port_and_the_family() {
        assert_eq!(
            loopback_twin("100.101.102.103:8080".parse().unwrap()),
            "127.0.0.1:8080".parse().unwrap()
        );
        assert_eq!(
            loopback_twin("[fd7a:115c:a1e0::1234]:9090".parse().unwrap()),
            "[::1]:9090".parse().unwrap()
        );
    }

    #[test]
    fn an_invite_node_of_tailnet_becomes_the_magicdns_url() {
        assert_eq!(
            node_url("tailnet", running).unwrap(),
            "http://leader.tail1234.ts.net:8080"
        );
        assert_eq!(
            node_url("tailnet:9000", running).unwrap(),
            "http://leader.tail1234.ts.net:9000"
        );
        assert_eq!(
            node_url("http://203.0.113.7:8080", || panic!("asked")).unwrap(),
            "http://203.0.113.7:8080"
        );
    }

    #[test]
    fn network_reports_a_url_only_when_the_http_side_is_on_the_tailnet() {
        let s = running().unwrap();
        let on = s.to_value(8080, Some("100.101.102.103".parse().unwrap()));
        let Value::Object(on) = on else { panic!() };
        assert_eq!(
            on["url"],
            Value::string("http://leader.tail1234.ts.net:8080")
        );
        assert_eq!(on["tailnet_only"], Value::Bool(true));

        let Value::Object(any) = s.to_value(8080, Some("0.0.0.0".parse().unwrap())) else {
            panic!()
        };
        assert_eq!(
            any["url"],
            Value::string("http://leader.tail1234.ts.net:8080")
        );
        assert_eq!(any["tailnet_only"], Value::Bool(false));

        let Value::Object(lo) = s.to_value(8080, Some("127.0.0.1".parse().unwrap())) else {
            panic!()
        };
        assert_eq!(lo["url"], Value::Null);
    }

    #[test]
    fn the_hint_is_only_for_tailnet_hosts() {
        assert!(unreachable_hint("leader.tail1234.ts.net")
            .unwrap()
            .contains("tailscale up"));
        assert!(unreachable_hint("203.0.113.7").is_none());
    }
}
