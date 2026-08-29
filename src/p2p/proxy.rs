//! Outbound dialling through a proxy, so a firewall is something to route
//! around rather than something that stops the node.
//!
//! # The problem this is the seam for
//!
//! A node behind a censoring firewall cannot reach its peers, and the reasons
//! are three separate mechanisms that need three separate answers:
//!
//! 1. **IP/port blocking.** The firewall drops packets to the peer's address.
//! 2. **DPI fingerprinting.** The firewall recognises the protocol on the wire
//!    and drops it wherever it goes. cairn is *trivially* fingerprintable: the
//!    initiator's first flight is a fixed 261,216-byte cleartext hello (the
//!    Classic McEliece public key, whose Goppa-matrix bytes are recognisable,
//!    plus a 96-byte ciphertext), sent before any key exists to encrypt under.
//!    See [`super::transport::connect`].
//! 3. **Endpoint enumeration.** The firewall blocks the bootstrap seeds
//!    themselves — the discovery problem [`super::peers`] answers.
//!
//! **This module does not obfuscate the cairn protocol.** Rolling a homegrown
//! obfuscator would be less safe than the alternative and is the wrong layer.
//! Instead it delegates: every dial can be routed through a **SOCKS5 proxy**,
//! which is exactly the interface the entire censorship-circumvention ecosystem
//! already exposes — a Tor client (`127.0.0.1:9050`), a Tor bridge running
//! `obfs4proxy` or `snowflake`, `meek`, `shadowsocks`, or a plain corporate
//! egress. Point cairn at one and:
//!
//! - the **local** censor sees a connection to the proxy, not to the peer, so
//!   the peer's blocked address (mechanism 1) is reached from the proxy's
//!   vantage point instead of this node's;
//! - with an **obfuscating** proxy (obfs4, Snowflake, meek) the bytes on the
//!   local link are the transport the bridge disguises as, so cairn's
//!   fingerprint (mechanism 2) never appears on the censored segment at all.
//!
//! # What it deliberately does not do, stated so it is not discovered later
//!
//! - It does not hide the cairn fingerprint on the **proxy→peer** hop. A Tor
//!   exit, or the peer's own ISP, still sees the McEliece hello. Against a
//!   censor who only controls the local link — the usual threat — that hop is
//!   past the firewall and does not matter; against a global adversary it is
//!   the same residue transport encryption always leaves, named in
//!   [`super::transport`].
//! - It does not make an **unreachable** peer reachable. SOCKS5 CONNECT dials
//!   an address *the proxy* can reach, so a peer behind its own NAT with no
//!   public address is no more reachable through Tor than directly. The fix for
//!   that is an onion-service target — a hostname the proxy resolves inside the
//!   overlay — which this module is shaped for (SOCKS5 carries a domain address
//!   type) but does not yet thread through, because the address book resolves
//!   hints to a [`SocketAddr`] at its edge. That is the honest next step, not a
//!   silent gap.
//! - The proxy is **untrusted**, and that is safe by construction: the McEliece
//!   mutual handshake runs end to end over the tunnelled stream, so a hostile
//!   proxy sees ciphertext and the peer-id fingerprint, can drop or delay
//!   (a liveness power every network hop has), and cannot read, forge, or
//!   redirect — a peer id is `sha256(public key)`, so a substituted endpoint
//!   fails the handshake exactly as a hostile DNS answer does.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

/// How a dial reaches its target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Proxy {
    /// Straight TCP to the peer, as before this module existed.
    Direct,
    /// SOCKS5 CONNECT through an intermediary.
    Socks5 {
        addr: SocketAddr,
        /// RFC 1929 username/password, when the proxy demands it. Most local
        /// circumvention proxies take none; a shared egress may.
        auth: Option<(String, String)>,
    },
}

/// Why a proxy string or a SOCKS negotiation failed.
#[derive(Debug)]
pub enum ProxyError {
    /// The configuration string was not a proxy URL this module understands.
    Malformed { detail: String },
    /// A socket error talking to the proxy.
    Io(io::Error),
    /// The proxy offered no method this client can satisfy (`0xFF`), or one it
    /// did not advertise.
    NoAcceptableAuth,
    /// The proxy rejected the username/password.
    AuthRejected,
    /// The proxy answered CONNECT with a non-zero reply code. The code is
    /// carried so an operator can tell "connection refused" (0x05) from "host
    /// unreachable" (0x04) from "not allowed by ruleset" (0x02).
    ConnectFailed { code: u8 },
    /// The proxy spoke something that was not SOCKS5.
    Protocol { detail: String },
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProxyError::Malformed { detail } => write!(f, "malformed proxy address: {detail}"),
            ProxyError::Io(e) => write!(f, "proxy I/O: {e}"),
            ProxyError::NoAcceptableAuth => {
                f.write_str("proxy accepts no authentication method this client offers")
            }
            ProxyError::AuthRejected => f.write_str("proxy rejected the username/password"),
            ProxyError::ConnectFailed { code } => {
                write!(f, "proxy refused CONNECT with SOCKS reply code {code:#04x}")
            }
            ProxyError::Protocol { detail } => write!(f, "proxy is not SOCKS5: {detail}"),
        }
    }
}

impl std::error::Error for ProxyError {}

impl From<io::Error> for ProxyError {
    fn from(value: io::Error) -> Self {
        ProxyError::Io(value)
    }
}

impl Proxy {
    /// Parse a proxy configuration string.
    ///
    /// Accepted forms:
    ///
    /// - `direct` or the empty string — [`Proxy::Direct`].
    /// - `socks5://host:port`
    /// - `socks5h://host:port` — accepted as a synonym, since this module
    ///   already leaves name resolution of the *target* to whoever built the
    ///   [`SocketAddr`]; the `h` suffix is kept working so a Tor user's habitual
    ///   URL is not rejected.
    /// - `socks5://user:pass@host:port` — with RFC 1929 credentials.
    ///
    /// The scheme is required rather than assumed: a bare `host:port` could be
    /// an HTTP proxy, a peer, or a typo, and guessing SOCKS5 would send a SOCKS
    /// greeting to something that is not one.
    pub fn parse(text: &str) -> Result<Proxy, ProxyError> {
        let text = text.trim();
        if text.is_empty() || text.eq_ignore_ascii_case("direct") {
            return Ok(Proxy::Direct);
        }
        let rest = text
            .strip_prefix("socks5://")
            .or_else(|| text.strip_prefix("socks5h://"))
            .ok_or_else(|| ProxyError::Malformed {
                detail: format!("expected socks5://…, got {text:?}"),
            })?;
        let (auth, hostport) = match rest.rsplit_once('@') {
            Some((creds, hostport)) => {
                let (user, pass) = creds.split_once(':').ok_or_else(|| ProxyError::Malformed {
                    detail: "credentials must be user:pass".into(),
                })?;
                // RFC 1929 caps each field at 255 bytes; a longer one cannot be
                // encoded, so it is refused here rather than truncated into a
                // different credential later.
                if user.is_empty() || user.len() > 255 || pass.len() > 255 {
                    return Err(ProxyError::Malformed {
                        detail: "username 1..=255 bytes, password 0..=255 bytes".into(),
                    });
                }
                (Some((user.to_string(), pass.to_string())), hostport)
            }
            None => (None, rest),
        };
        let addr = hostport
            .parse::<SocketAddr>()
            .map_err(|e| ProxyError::Malformed {
                detail: format!("{hostport:?} is not host:port ({e})"),
            })?;
        Ok(Proxy::Socks5 { addr, auth })
    }

    /// Dial `target`, directly or through the proxy, within `timeout`.
    ///
    /// The returned stream is the tunnel: for [`Proxy::Direct`] it is the peer
    /// connection, for [`Proxy::Socks5`] it is the proxy connection positioned
    /// at the first byte of the tunnelled data, and the caller runs the
    /// McEliece handshake over it either way. The caller sets its own session
    /// timeouts on the result, so the negotiation timeouts this applies do not
    /// outlive the dial.
    pub fn dial(&self, target: SocketAddr, timeout: Duration) -> Result<TcpStream, ProxyError> {
        match self {
            Proxy::Direct => Ok(TcpStream::connect_timeout(&target, timeout)?),
            Proxy::Socks5 { addr, auth } => {
                let mut stream = TcpStream::connect_timeout(addr, timeout)?;
                // The whole negotiation is a handful of tiny messages; one
                // deadline for the round is enough, and the caller replaces it
                // the moment this returns.
                stream.set_read_timeout(Some(timeout))?;
                stream.set_write_timeout(Some(timeout))?;
                socks5_connect(&mut stream, target, auth.as_ref())?;
                Ok(stream)
            }
        }
    }
}

/// SOCKS version byte.
const V5: u8 = 0x05;
/// Method: no authentication required.
const M_NONE: u8 = 0x00;
/// Method: username/password (RFC 1929).
const M_USERPASS: u8 = 0x02;
/// Method: no acceptable methods.
const M_NONE_ACCEPTABLE: u8 = 0xFF;
/// Command: establish a TCP stream.
const CMD_CONNECT: u8 = 0x01;
/// Address type: a 4-byte IPv4 address.
const ATYP_IPV4: u8 = 0x01;
/// Address type: a length-prefixed domain name.
const ATYP_DOMAIN: u8 = 0x03;
/// Address type: a 16-byte IPv6 address.
const ATYP_IPV6: u8 = 0x04;

/// Perform an RFC 1928 CONNECT to `target`, with optional RFC 1929 auth.
///
/// On success the stream is left at the first byte the peer sends, so the
/// caller's handshake reads it directly.
fn socks5_connect(
    stream: &mut TcpStream,
    target: SocketAddr,
    auth: Option<&(String, String)>,
) -> Result<(), ProxyError> {
    // -- method negotiation --------------------------------------------------
    // Offer exactly what this client can do. Offering user/pass when there are
    // no credentials would let a proxy select a method the client cannot then
    // satisfy.
    match auth {
        Some(_) => stream.write_all(&[V5, 0x02, M_NONE, M_USERPASS])?,
        None => stream.write_all(&[V5, 0x01, M_NONE])?,
    }
    stream.flush()?;

    let mut selection = [0u8; 2];
    stream.read_exact(&mut selection)?;
    if selection[0] != V5 {
        return Err(ProxyError::Protocol {
            detail: format!("method reply version {:#04x}", selection[0]),
        });
    }
    match selection[1] {
        M_NONE => {}
        M_USERPASS => authenticate(stream, auth)?,
        M_NONE_ACCEPTABLE => return Err(ProxyError::NoAcceptableAuth),
        other => {
            return Err(ProxyError::Protocol {
                detail: format!("proxy selected method {other:#04x}, which was not offered"),
            })
        }
    }

    // -- CONNECT request -----------------------------------------------------
    let mut request = vec![V5, CMD_CONNECT, 0x00];
    match target {
        SocketAddr::V4(v4) => {
            request.push(ATYP_IPV4);
            request.extend_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(v6) => {
            request.push(ATYP_IPV6);
            request.extend_from_slice(&v6.ip().octets());
        }
    }
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request)?;
    stream.flush()?;

    // -- reply ---------------------------------------------------------------
    let mut head = [0u8; 4];
    stream.read_exact(&mut head)?;
    if head[0] != V5 {
        return Err(ProxyError::Protocol {
            detail: format!("reply version {:#04x}", head[0]),
        });
    }
    if head[1] != 0x00 {
        return Err(ProxyError::ConnectFailed { code: head[1] });
    }
    // The bound address is echoed and must be consumed so the stream is left at
    // the tunnelled data. Its length depends on the address type the *proxy*
    // chose, which need not match the one requested.
    let bound_len = match head[3] {
        ATYP_IPV4 => 4,
        ATYP_IPV6 => 16,
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len)?;
            usize::from(len[0])
        }
        other => {
            return Err(ProxyError::Protocol {
                detail: format!("reply address type {other:#04x}"),
            })
        }
    };
    let mut discard = vec![0u8; bound_len + 2]; // address + 2-byte port
    stream.read_exact(&mut discard)?;
    Ok(())
}

/// RFC 1929 username/password sub-negotiation.
fn authenticate(stream: &mut TcpStream, auth: Option<&(String, String)>) -> Result<(), ProxyError> {
    // The proxy selected user/pass, so credentials are required. A proxy that
    // asks for them from a client that has none is misconfigured for this node,
    // and saying so beats sending empty ones and getting a confusing reject.
    let (user, pass) = auth.ok_or(ProxyError::NoAcceptableAuth)?;
    let mut message = vec![0x01, user.len() as u8];
    message.extend_from_slice(user.as_bytes());
    message.push(pass.len() as u8);
    message.extend_from_slice(pass.as_bytes());
    stream.write_all(&message)?;
    stream.flush()?;

    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply)?;
    // The sub-negotiation version is 0x01, not 0x05.
    if reply[0] != 0x01 {
        return Err(ProxyError::Protocol {
            detail: format!("auth reply version {:#04x}", reply[0]),
        });
    }
    if reply[1] != 0x00 {
        return Err(ProxyError::AuthRejected);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn parse_reads_the_forms_it_documents_and_refuses_the_rest() {
        assert_eq!(Proxy::parse("").unwrap(), Proxy::Direct);
        assert_eq!(Proxy::parse("  direct ").unwrap(), Proxy::Direct);
        assert_eq!(
            Proxy::parse("socks5://127.0.0.1:9050").unwrap(),
            Proxy::Socks5 {
                addr: "127.0.0.1:9050".parse().unwrap(),
                auth: None,
            }
        );
        // socks5h is accepted as a synonym so a Tor user's usual URL works.
        assert_eq!(
            Proxy::parse("socks5h://127.0.0.1:9050").unwrap(),
            Proxy::Socks5 {
                addr: "127.0.0.1:9050".parse().unwrap(),
                auth: None,
            }
        );
        assert_eq!(
            Proxy::parse("socks5://alice:secret@10.0.0.1:1080").unwrap(),
            Proxy::Socks5 {
                addr: "10.0.0.1:1080".parse().unwrap(),
                auth: Some(("alice".into(), "secret".into())),
            }
        );

        // A scheme is required: a bare host:port could be anything, and
        // guessing SOCKS would send a greeting to a non-proxy.
        assert!(matches!(
            Proxy::parse("127.0.0.1:9050"),
            Err(ProxyError::Malformed { .. })
        ));
        // A hostname target for the proxy itself is refused: this module dials
        // the proxy by address, and a name here would need a resolver on the
        // one path that is supposed to have no dependencies.
        assert!(matches!(
            Proxy::parse("socks5://localhost:9050"),
            Err(ProxyError::Malformed { .. })
        ));
        assert!(matches!(
            Proxy::parse("socks5://user@host:1"),
            Err(ProxyError::Malformed { .. })
        ));
    }

    /// A minimal SOCKS5 responder for one connection, asserting the client's
    /// bytes and then playing the given script. Returns the target the client
    /// asked to reach, and echoes one line so the tunnel can be checked.
    fn fake_socks(
        expect_auth: Option<(&'static str, &'static str)>,
    ) -> (SocketAddr, thread::JoinHandle<SocketAddr>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();

            // Greeting.
            let mut head = [0u8; 2];
            stream.read_exact(&mut head).unwrap();
            assert_eq!(head[0], V5);
            let mut methods = vec![0u8; head[1] as usize];
            stream.read_exact(&mut methods).unwrap();

            if let Some((user, pass)) = expect_auth {
                assert!(methods.contains(&M_USERPASS));
                stream.write_all(&[V5, M_USERPASS]).unwrap();
                // Username/password sub-negotiation.
                let mut vhdr = [0u8; 2];
                stream.read_exact(&mut vhdr).unwrap();
                assert_eq!(vhdr[0], 0x01);
                let mut u = vec![0u8; vhdr[1] as usize];
                stream.read_exact(&mut u).unwrap();
                let mut plen = [0u8; 1];
                stream.read_exact(&mut plen).unwrap();
                let mut p = vec![0u8; plen[0] as usize];
                stream.read_exact(&mut p).unwrap();
                assert_eq!(u, user.as_bytes());
                assert_eq!(p, pass.as_bytes());
                stream.write_all(&[0x01, 0x00]).unwrap();
            } else {
                assert!(methods.contains(&M_NONE));
                stream.write_all(&[V5, M_NONE]).unwrap();
            }

            // CONNECT request.
            let mut req = [0u8; 4];
            stream.read_exact(&mut req).unwrap();
            assert_eq!(req[0], V5);
            assert_eq!(req[1], CMD_CONNECT);
            assert_eq!(req[3], ATYP_IPV4, "the fixtures dial an IPv4 target");
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).unwrap();
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).unwrap();
            let target = SocketAddr::from((ip, u16::from_be_bytes(port)));

            // Success, echoing a bound address of a *different* type than the
            // request, to prove the client consumes it by length rather than
            // assuming it matches.
            stream
                .write_all(&[V5, 0x00, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
                .unwrap();
            // Now the tunnel: send a line the client can read to confirm it is
            // positioned at the data.
            stream.write_all(b"tunnelled\n").unwrap();
            stream.flush().unwrap();
            target
        });
        (addr, handle)
    }

    #[test]
    fn a_no_auth_connect_reaches_the_requested_target_and_opens_the_tunnel() {
        let (proxy_addr, server) = fake_socks(None);
        let proxy = Proxy::Socks5 {
            addr: proxy_addr,
            auth: None,
        };
        let target: SocketAddr = "203.0.113.9:9000".parse().unwrap();
        let mut stream = proxy.dial(target, Duration::from_secs(5)).expect("dials");

        let mut line = [0u8; 10];
        stream.read_exact(&mut line).unwrap();
        assert_eq!(&line, b"tunnelled\n");
        assert_eq!(
            server.join().unwrap(),
            target,
            "proxy dialled the wrong host"
        );
    }

    #[test]
    fn credentials_are_offered_and_accepted() {
        let (proxy_addr, server) = fake_socks(Some(("alice", "secret")));
        let proxy = Proxy::Socks5 {
            addr: proxy_addr,
            auth: Some(("alice".into(), "secret".into())),
        };
        let target: SocketAddr = "203.0.113.9:9000".parse().unwrap();
        let mut stream = proxy.dial(target, Duration::from_secs(5)).expect("dials");
        let mut line = [0u8; 10];
        stream.read_exact(&mut line).unwrap();
        assert_eq!(&line, b"tunnelled\n");
        assert_eq!(server.join().unwrap(), target);
    }

    #[test]
    fn a_refused_connect_surfaces_the_reply_code() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut head = [0u8; 2];
            stream.read_exact(&mut head).unwrap();
            let mut methods = vec![0u8; head[1] as usize];
            stream.read_exact(&mut methods).unwrap();
            stream.write_all(&[V5, M_NONE]).unwrap();
            let mut req = [0u8; 10]; // v5 connect + atyp v4 + 4 + 2
            stream.read_exact(&mut req).unwrap();
            // Reply code 0x05: connection refused by the destination.
            stream
                .write_all(&[V5, 0x05, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
                .unwrap();
            stream.flush().unwrap();
        });
        let proxy = Proxy::Socks5 { addr, auth: None };
        let outcome = proxy.dial("203.0.113.9:9000".parse().unwrap(), Duration::from_secs(5));
        assert!(matches!(
            outcome,
            Err(ProxyError::ConnectFailed { code: 0x05 })
        ));
        server.join().unwrap();
    }

    #[test]
    fn a_proxy_that_offers_no_method_is_an_error_not_a_hang() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut head = [0u8; 2];
            stream.read_exact(&mut head).unwrap();
            let mut methods = vec![0u8; head[1] as usize];
            stream.read_exact(&mut methods).unwrap();
            stream.write_all(&[V5, M_NONE_ACCEPTABLE]).unwrap();
            stream.flush().unwrap();
        });
        let proxy = Proxy::Socks5 { addr, auth: None };
        let outcome = proxy.dial("203.0.113.9:9000".parse().unwrap(), Duration::from_secs(5));
        assert!(matches!(outcome, Err(ProxyError::NoAcceptableAuth)));
        server.join().unwrap();
    }

    #[test]
    fn direct_still_dials_straight_through() {
        // The default path is unchanged: a real loopback listener, no proxy.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.write_all(b"hi").unwrap();
            stream.flush().unwrap();
        });
        let mut stream = Proxy::Direct
            .dial(addr, Duration::from_secs(5))
            .expect("dials");
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hi");
        server.join().unwrap();
    }
}
