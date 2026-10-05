//! A minimal HTTP/1.1 client for talking to a cairn node: `GET` and `POST`
//! of JSON over a plain socket, with a deadline on every step.
//!
//! The crate has no HTTP client dependency and does not want one: a node's
//! HTTP side speaks plaintext on purpose (`tests/cipher_policy.rs` keeps TLS
//! out of the tree), so the agent reaches it on a loopback, a LAN, a
//! WireGuard or SSH tunnel, or the p2p transport's own encrypted channel --
//! never over the open internet in the clear, and the docs say so. What
//! remains is a hundred lines of request writing and response framing, which
//! is less than any dependency would cost to audit.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use super::AgentError;
use crate::canonical::Value;
use crate::fleet::auth::MemberFile;

/// Largest answer this client reads from a node, in bytes.
const MAX_RESPONSE_BYTES: u64 = 16 << 20;
/// Longest status or header line read from a node.
const MAX_LINE_BYTES: u64 = 8 * 1024;

/// `http://host:port`, with an optional path prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeUrl {
    pub host: String,
    pub port: u16,
    /// Never ends in `/`; empty for a bare origin.
    pub base: String,
    original: String,
}

impl NodeUrl {
    pub fn parse(text: &str) -> Result<NodeUrl, AgentError> {
        let original = text.trim().trim_end_matches('/').to_string();
        let rest = original.strip_prefix("http://").ok_or_else(|| {
            AgentError::Invalid(format!(
                "node URL {text:?} must start with http:// (a node's HTTP side is plaintext; \
                 put a tunnel in front of it rather than expecting https)"
            ))
        })?;
        let (authority, base) = match rest.find('/') {
            Some(at) => (&rest[..at], rest[at..].to_string()),
            None => (rest, String::new()),
        };
        if authority.is_empty() {
            return Err(AgentError::Invalid(format!(
                "node URL {text:?} names no host"
            )));
        }
        // `[::1]:8080` or `host:port` or `host`.
        let (host, port) = if let Some(end) = authority.strip_prefix('[') {
            let close = end
                .find(']')
                .ok_or_else(|| AgentError::Invalid(format!("node URL {text:?}: unclosed [")))?;
            let host = end[..close].to_string();
            let port = end[close + 1..]
                .strip_prefix(':')
                .map(|p| p.parse::<u16>())
                .transpose()
                .map_err(|_| AgentError::Invalid(format!("node URL {text:?}: bad port")))?
                .unwrap_or(80);
            (host, port)
        } else {
            match authority.rsplit_once(':') {
                Some((host, port)) => (
                    host.to_string(),
                    port.parse::<u16>().map_err(|_| {
                        AgentError::Invalid(format!("node URL {text:?}: bad port {port:?}"))
                    })?,
                ),
                None => (authority.to_string(), 80),
            }
        };
        Ok(NodeUrl {
            host,
            port,
            base: base.trim_end_matches('/').to_string(),
            original,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.original
    }

    fn resolve(&self, timeout: Duration) -> Result<TcpStream, AgentError> {
        let addrs: Vec<SocketAddr> = (self.host.as_str(), self.port)
            .to_socket_addrs()
            .map_err(|e| AgentError::Node(format!("{}: resolve: {e}", self.original)))?
            .collect();
        let mut last = None;
        for addr in addrs {
            match TcpStream::connect_timeout(&addr, timeout) {
                Ok(stream) => return Ok(stream),
                Err(e) => last = Some(e),
            }
        }
        Err(AgentError::Node(format!(
            "{}: connect: {}",
            self.original,
            last.map(|e| e.to_string())
                .unwrap_or_else(|| "no address".to_string())
        )))
    }
}

/// A response: the status and the body, parsed as JSON when there is one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub body: Value,
}

impl Response {
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// The node's `error` field, or the status, for a message.
    pub fn error_text(&self) -> String {
        match self.body.get("error").and_then(Value::as_str) {
            Some(text) => format!("{} ({})", text, self.status),
            None => format!("HTTP {}", self.status),
        }
    }
}

pub fn get(url: &NodeUrl, path: &str, timeout: Duration) -> Result<Response, AgentError> {
    request(url, "GET", path, None, None, timeout)
}

pub fn post_json(
    url: &NodeUrl,
    path: &str,
    body: &Value,
    timeout: Duration,
) -> Result<Response, AgentError> {
    request(url, "POST", path, Some(body), None, timeout)
}

/// [`post_json`], signed as a fleet member when `member` is given: an
/// `Authorization: CairnMember` header over this method, this request-target
/// and these exact body bytes, for the member file's own leader and no other
/// (`docs/design/fleet-enrollment.md` §6). Nothing secret is sent.
pub fn post_json_as(
    url: &NodeUrl,
    path: &str,
    body: &Value,
    member: Option<&MemberFile>,
    timeout: Duration,
) -> Result<Response, AgentError> {
    request(url, "POST", path, Some(body), member, timeout)
}

fn request(
    url: &NodeUrl,
    method: &str,
    path: &str,
    body: Option<&Value>,
    member: Option<&MemberFile>,
    timeout: Duration,
) -> Result<Response, AgentError> {
    let mut stream = url.resolve(timeout)?;
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .map_err(|e| AgentError::Node(format!("{}: {e}", url.original)))?;
    let encoded = body.map(|value| value.canonical_string());
    let mut head = format!(
        "{method} {}{path} HTTP/1.1\r\nhost: {}:{}\r\naccept: application/json\r\nconnection: close\r\nuser-agent: {}\r\n",
        url.base, url.host, url.port, super::CLIENT
    );
    if let Some(encoded) = &encoded {
        head.push_str(&format!(
            "content-type: application/json\r\ncontent-length: {}\r\n",
            encoded.len()
        ));
    }
    if let Some(member) = member {
        // The request-target exactly as the request line above writes it.
        let target = format!("{}{path}", url.base);
        let body = encoded.as_deref().unwrap_or_default().as_bytes();
        head.push_str(&format!(
            "authorization: {}\r\n",
            member.authorize(crate::time::unix_seconds(), method, &target, body)
        ));
    }
    head.push_str("\r\n");
    stream
        .write_all(head.as_bytes())
        .and_then(|()| match &encoded {
            Some(encoded) => stream.write_all(encoded.as_bytes()),
            None => Ok(()),
        })
        .map_err(|e| AgentError::Node(format!("{}: write: {e}", url.original)))?;

    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader
        .by_ref()
        .take(MAX_LINE_BYTES)
        .read_line(&mut status_line)
        .map_err(|e| AgentError::Node(format!("{}: read: {e}", url.original)))?;
    let status = parse_status_line(&status_line).ok_or_else(|| {
        AgentError::Node(format!(
            "{}: not an HTTP response: {:?}",
            url.original,
            status_line.trim()
        ))
    })?;
    let mut length: Option<usize> = None;
    loop {
        let mut line = String::new();
        let read = reader
            .by_ref()
            .take(MAX_LINE_BYTES)
            .read_line(&mut line)
            .map_err(|e| AgentError::Node(format!("{}: read: {e}", url.original)))?;
        if read == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                length = value.trim().parse().ok();
            }
        }
    }
    // A node's word is not an allocation size: `content-length:
    // 99999999999999` from a hostile node, or anyone on the plaintext path,
    // aborted the agent. Nothing a node answers this client is near the cap.
    let mut raw = Vec::new();
    match length {
        Some(n) if n as u64 > MAX_RESPONSE_BYTES => {
            return Err(AgentError::Node(format!(
                "{}: a {n}-byte answer is past this client's {MAX_RESPONSE_BYTES}-byte cap",
                url.original
            )));
        }
        Some(n) => {
            raw.resize(n, 0);
            reader
                .read_exact(&mut raw)
                .map_err(|e| AgentError::Node(format!("{}: body: {e}", url.original)))?;
        }
        None => {
            reader
                .by_ref()
                .take(MAX_RESPONSE_BYTES + 1)
                .read_to_end(&mut raw)
                .map_err(|e| AgentError::Node(format!("{}: body: {e}", url.original)))?;
            if raw.len() as u64 > MAX_RESPONSE_BYTES {
                return Err(AgentError::Node(format!(
                    "{}: answer past this client's {MAX_RESPONSE_BYTES}-byte cap",
                    url.original
                )));
            }
        }
    }
    let text = String::from_utf8_lossy(&raw);
    let body = if text.trim().is_empty() {
        Value::Null
    } else {
        Value::from_json(&text)
            .unwrap_or_else(|_| Value::object([("error", Value::string(text.trim().to_string()))]))
    };
    Ok(Response { status, body })
}

/// `HTTP/1.1 202 Accepted` -> 202.
pub fn parse_status_line(line: &str) -> Option<u16> {
    let mut parts = line.split_whitespace();
    let version = parts.next()?;
    if !version.starts_with("HTTP/") {
        return None;
    }
    parts.next()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_urls_parse_with_and_without_ports_and_prefixes() {
        let url = NodeUrl::parse("http://127.0.0.1:8080/").unwrap();
        assert_eq!(
            (url.host.as_str(), url.port, url.base.as_str()),
            ("127.0.0.1", 8080, "")
        );
        let url = NodeUrl::parse("http://node.lan/cairn/").unwrap();
        assert_eq!(
            (url.host.as_str(), url.port, url.base.as_str()),
            ("node.lan", 80, "/cairn")
        );
        let url = NodeUrl::parse("http://[::1]:9001").unwrap();
        assert_eq!((url.host.as_str(), url.port), ("::1", 9001));
        assert!(NodeUrl::parse("https://node").is_err());
        assert!(NodeUrl::parse("http://").is_err());
        assert!(NodeUrl::parse("http://host:notaport").is_err());
    }

    #[test]
    fn status_lines_parse() {
        assert_eq!(parse_status_line("HTTP/1.1 202 Accepted\r\n"), Some(202));
        assert_eq!(parse_status_line("HTTP/1.0 404 Not Found"), Some(404));
        assert_eq!(parse_status_line("garbage"), None);
    }

    #[test]
    fn a_node_cannot_name_the_size_of_the_buffer_this_client_allocates() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(socket.try_clone().unwrap());
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
            }
            let _ = write!(
                socket,
                "HTTP/1.1 200 OK\r\ncontent-length: 99999999999999\r\n\r\n{{}}"
            );
        });
        let url = NodeUrl::parse(&format!("http://127.0.0.1:{}", addr.port())).unwrap();
        let error = get(&url, "/health", Duration::from_secs(5)).unwrap_err();
        assert!(error.to_string().contains("cap"), "{error}");
    }

    #[test]
    fn a_round_trip_against_a_tiny_server_frames_the_body() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(socket.try_clone().unwrap());
            let mut request = String::new();
            let mut length = 0usize;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = v.trim().parse().unwrap();
                }
                request.push_str(&line);
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            assert!(request.starts_with("POST /x/hosts HTTP/1.1"));
            assert_eq!(String::from_utf8(body).unwrap(), r#"{"host":"a"}"#);
            let reply = r#"{"recorded":true}"#;
            write!(
                socket,
                "HTTP/1.1 202 Accepted\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
                reply.len(),
                reply
            )
            .unwrap();
        });
        let url = NodeUrl::parse(&format!("http://127.0.0.1:{}/x", addr.port())).unwrap();
        let response = post_json(
            &url,
            "/hosts",
            &Value::object([("host", Value::string("a"))]),
            Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(response.status, 202);
        assert_eq!(response.body.get("recorded"), Some(&Value::Bool(true)));
        server.join().unwrap();
    }
}
