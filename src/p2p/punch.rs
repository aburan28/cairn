//! UDP hole punching with a QUIC long-header datagram.
//!
//! A home NAT often forwards a flow only after it has seen a packet leave,
//! and some filters forward UDP only when it looks like QUIC: long header,
//! version 1, at least 1200 bytes. This module sends that shape. The payload
//! is a PATH_CHALLENGE (frame type `0x1a`) plus the address this side
//! observed, which is the STUN role.
//!
//! It is not a QUIC connection. `quinn` and `iroh` both pull a TLS stack, and
//! every Rust TLS stack in reach compiles AES, which [`crate`] refuses in
//! `tests/cipher_policy.rs`. The owner allowed TLS for reachability; that
//! exception does not lift the AES ban, so the punch stays on these bytes.
//! The peer-authentication handshake still runs over whatever path comes
//! back. A punched address is a hint.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

const QUIC_INITIAL: u8 = 0xc0;
const QUIC_VERSION: [u8; 4] = [0x00, 0x00, 0x00, 0x01];
const PATH_CHALLENGE: u8 = 0x1a;
const MIN_DATAGRAM: usize = 1200;

/// What one side tells the other: "I see you at this address."
pub fn observed_message(seen: SocketAddr) -> Vec<u8> {
    format!("cairn-observe {seen}").into_bytes()
}

pub fn parse_observed(bytes: &[u8]) -> Option<SocketAddr> {
    let marker = b"cairn-observe ";
    let pos = bytes
        .windows(marker.len())
        .position(|window| window == marker)?;
    let rest = &bytes[pos + marker.len()..];
    let end = rest
        .iter()
        .position(|byte| *byte == 0 || *byte == b' ')
        .unwrap_or(rest.len());
    let text = std::str::from_utf8(&rest[..end]).ok()?;
    text.parse().ok()
}

/// A 1200-byte QUIC Initial-shaped datagram carrying a path challenge and
/// the observed address. Longer when the address text does not fit.
pub fn quic_observe_packet(seen: SocketAddr, challenge: [u8; 8]) -> Vec<u8> {
    let observe = observed_message(seen);
    let mut header = Vec::with_capacity(24);
    header.push(QUIC_INITIAL);
    header.extend_from_slice(&QUIC_VERSION);
    header.push(8);
    let mut dcid = [0x11u8; 8];
    let port = seen.port().to_be_bytes();
    dcid[6] = port[0];
    dcid[7] = port[1];
    header.extend_from_slice(&dcid);
    header.push(8);
    header.extend_from_slice(&challenge);
    header.push(0x00);

    let min_payload = 1 + challenge.len() + observe.len();
    let mut payload_len = MIN_DATAGRAM.saturating_sub(header.len() + 2 + 1);
    if payload_len < min_payload {
        payload_len = min_payload;
    }
    let mut payload = Vec::with_capacity(payload_len);
    payload.push(PATH_CHALLENGE);
    payload.extend_from_slice(&challenge);
    payload.extend_from_slice(&observe);
    payload.resize(payload_len, 0);

    let length = (1 + payload.len()) as u16;
    debug_assert!(length < 16384);
    let encoded = length | 0x4000;
    let mut packet = header;
    packet.push((encoded >> 8) as u8);
    packet.push((encoded & 0xff) as u8);
    packet.push(0x00);
    packet.extend_from_slice(&payload);
    packet
}

/// Both sockets send a QUIC-shaped datagram to each other and each reports
/// the address it was told it is seen at. On a LAN that is the socket's own
/// address; behind a NAT it is the mapped one, which is what the peer must
/// punch toward.
pub fn punch(left: &UdpSocket, right: &UdpSocket) -> io::Result<(SocketAddr, SocketAddr)> {
    left.set_read_timeout(Some(Duration::from_secs(2)))?;
    right.set_read_timeout(Some(Duration::from_secs(2)))?;
    let left_addr = left.local_addr()?;
    let right_addr = right.local_addr()?;
    left.send_to(&quic_observe_packet(right_addr, [1u8; 8]), right_addr)?;
    right.send_to(&quic_observe_packet(left_addr, [2u8; 8]), left_addr)?;
    let mut buf = [0u8; 2048];
    let (n, from_right) = left.recv_from(&mut buf)?;
    let seen_by_left = parse_observed(&buf[..n]).unwrap_or(from_right);
    let (n, from_left) = right.recv_from(&mut buf)?;
    let seen_by_right = parse_observed(&buf[..n]).unwrap_or(from_left);
    Ok((seen_by_left, seen_by_right))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_datagram_is_a_quic_initial_and_carries_the_observed_address() {
        let seen: SocketAddr = "203.0.113.8:9000".parse().unwrap();
        let packet = quic_observe_packet(seen, [9u8; 8]);
        assert!(packet.len() >= MIN_DATAGRAM);
        assert_eq!(packet[0], QUIC_INITIAL);
        assert_eq!(&packet[1..5], &QUIC_VERSION);
        assert_eq!(parse_observed(&packet), Some(seen));
        assert!(packet
            .windows(9)
            .any(|window| window == [PATH_CHALLENGE, 9, 9, 9, 9, 9, 9, 9, 9]));
    }

    #[test]
    fn two_local_sockets_learn_each_others_address() {
        let left = UdpSocket::bind("127.0.0.1:0").unwrap();
        let right = UdpSocket::bind("127.0.0.1:0").unwrap();
        let (a, b) = punch(&left, &right).unwrap();
        assert_eq!(a, left.local_addr().unwrap());
        assert_eq!(b, right.local_addr().unwrap());
    }
}
