//! Zero-configuration discovery on a local network.
//!
//! # Why this is the cheapest hint source there is
//!
//! [`super::discovery`] makes every source of addresses interchangeable, because
//! none of them is trusted: an address is a hint, and the handshake decides. That
//! design has a payoff, and this module is it. Once a hint source costs nothing
//! to trust, adding one is a hundred lines and no new security argument — so a
//! node on a LAN with peers it has never been told about finds them, with no
//! bootstrap file, no DNS, and no configuration at all.
//!
//! # The address comes from the packet, never from the message
//!
//! An announcement carries a peer id and a port. It does **not** carry an IP
//! address, and that omission is the load-bearing part: an address inside the
//! message is a claim by the sender, while the source address of the datagram is
//! where the packet demonstrably came from. Letting a sender name its own
//! address would turn a beacon into a way to point an entire LAN at a third
//! party — every listener adds the claimed address, every listener dials it. The
//! same rule [`super::dht`] applies to provider answers, for the same reason:
//! attribute to the channel, not to the body.
//!
//! The port is a different case and is carried, because the sending socket's
//! ephemeral port is not the listening port. It is bounded by being a `u16`, and
//! a wrong one costs one failed dial.
//!
//! # Unsigned, and that is not an oversight
//!
//! There is no signature here and none is needed. A false announcement names a
//! transport id its sender cannot dial for: reaching that id requires a McEliece
//! key hashing to it, and the handshake derives the id or yields no session. So
//! the worst a liar achieves is one wasted dial by each listener — the same
//! bound [`crate::records::PeerRecord`] and a DHT routing answer both carry.
//! Signing would add 64 bytes and a key-distribution problem to buy nothing.
//!
//! # Announce-only: no queries, no responses
//!
//! Nothing here answers anything. A protocol that replies to a multicast query
//! is a reflector: an attacker spoofs a victim's source address, sends one
//! query, and every node on the segment replies to the victim. Announce-only
//! removes the amplification primitive rather than trying to rate-limit it, and
//! costs only that a joining node waits one interval instead of asking.
//!
//! # It cannot leave the segment, and it must not say what it holds
//!
//! TTL is 1, so a beacon dies at the first router. That is the intended scope
//! and also the containment: a bug here cannot become traffic on the internet.
//!
//! And an announcement carries **no inventory**. `p2p::code` refuses to publish
//! which blobs a node holds, on the grounds that the set of objectives a node
//! works on is nobody's business; a beacon that helpfully listed them would
//! reintroduce exactly that leak, unauthenticated and broadcast to a whole
//! office. What a listener learns is that *a* cairn node exists here.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};

use super::handshake::PeerId;

/// The multicast group. Inside the IPv4 administratively-scoped block
/// (239.0.0.0/8), which is the range reserved for exactly this: private use
/// within an organization, never routed to the internet.
pub const GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 41, 96);

/// The port beacons are sent to and heard on.
pub const PORT: u16 = 47_396;

/// Hop limit. One means "this segment and no further", which is the whole scope
/// of the feature and the reason a bug here cannot escape onto the internet.
pub const TTL: u32 = 1;

/// How often a node announces itself.
///
/// Thirty seconds: a node joining a LAN is discoverable within half a minute,
/// and a hundred nodes on one segment cost about three packets a second between
/// them. Announcements are idempotent — a repeat refreshes an address the
/// listener already had — so the cost of the interval being wrong is latency,
/// never correctness.
pub const INTERVAL_SECONDS: u64 = 30;

/// Every byte of a beacon: magic, version, peer id, port.
///
/// Fixed-length on purpose. A parser with no variable-length field has no length
/// arithmetic, and a beacon arrives unauthenticated from anyone on the segment —
/// the smallest possible parser is the point.
pub const FRAME_LEN: usize = 4 + 1 + 32 + 2;

/// Frame prefix. Present so a stray datagram on a shared port is discarded by
/// inspection rather than by decoding into a plausible peer id.
const MAGIC: [u8; 4] = *b"PWMC";

/// Wire version. A listener refuses anything else rather than guessing: a format
/// that cannot say which version it is cannot be changed later.
const VERSION: u8 = 1;

/// What one node broadcasts about itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Beacon {
    /// The transport id: `sha256` of this node's McEliece public key.
    pub peer: PeerId,
    /// The port this node accepts sessions on.
    pub port: u16,
}

impl Beacon {
    pub fn new(peer: PeerId, port: u16) -> Beacon {
        Beacon { peer, port }
    }

    /// The exact bytes to put on the wire.
    pub fn encode(&self) -> [u8; FRAME_LEN] {
        let mut out = [0u8; FRAME_LEN];
        out[0..4].copy_from_slice(&MAGIC);
        out[4] = VERSION;
        out[5..37].copy_from_slice(&self.peer);
        out[37..39].copy_from_slice(&self.port.to_be_bytes());
        out
    }

    /// Decode a datagram, or `None` for anything this version does not
    /// understand.
    ///
    /// Every rejection is silent and cheap. This parser is reachable by any host
    /// on the segment without a handshake, so it does the least work that can
    /// possibly answer the question: check the length, check the magic, check
    /// the version, copy 34 bytes.
    ///
    /// A length that is merely *longer* than a frame is refused rather than
    /// truncated to one. Accepting a prefix would let one datagram mean two
    /// things depending on who parsed it, which is the kind of ambiguity that is
    /// harmless here and fatal one layer down.
    pub fn decode(bytes: &[u8]) -> Option<Beacon> {
        if bytes.len() != FRAME_LEN || bytes[0..4] != MAGIC || bytes[4] != VERSION {
            return None;
        }
        let mut peer = [0u8; 32];
        peer.copy_from_slice(&bytes[5..37]);
        let port = u16::from_be_bytes([bytes[37], bytes[38]]);
        Some(Beacon { peer, port })
    }
}

/// What a listener does with a beacon that arrived from `source`.
///
/// Pure, so the policy is testable without a socket — the socket work is a
/// driver around this, and every decision worth arguing about is here.
///
/// The returned address pairs the **source IP of the datagram** with the port
/// from the message. Never the other way round, and never an address from the
/// body: see this module's header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Heard {
    /// A peer worth adding, at this address.
    Peer { peer: PeerId, addr: SocketAddr },
    /// This node's own beacon, looped back. Not an error and not a peer.
    Ourselves,
    /// Not a beacon this version understands.
    Ignored,
}

/// Interpret one received datagram.
///
/// `us` is this node's own transport id, so its own loopback beacons are
/// recognised rather than dialled. A node that added itself would waste a dial
/// on every interval, forever, and the handshake would succeed — which is worse
/// than failing, because nothing would ever flag it.
pub fn hear(bytes: &[u8], source: IpAddr, us: &PeerId) -> Heard {
    let Some(beacon) = Beacon::decode(bytes) else {
        return Heard::Ignored;
    };
    if &beacon.peer == us {
        return Heard::Ourselves;
    }
    // Port zero is not dialable. Refused here rather than by the dial, because a
    // contact that can never be reached still occupies a routing-table slot that
    // an honest peer could have used.
    if beacon.port == 0 {
        return Heard::Ignored;
    }
    Heard::Peer {
        peer: beacon.peer,
        addr: SocketAddr::new(source, beacon.port),
    }
}

// ---------------------------------------------------------------------------
// The socket driver
// ---------------------------------------------------------------------------

/// A bound multicast socket: sends this node's beacon, hears everyone else's.
///
/// Separate from the policy above so that everything worth arguing about is
/// testable without a network and this part is only the syscalls.
///
/// # One beacon socket per host, and what happens when that is not enough
///
/// The port is bound plainly, without `SO_REUSEADDR`. Setting it would need
/// either a new dependency or sixty lines of `sockaddr_in` FFI with a different
/// layout on every platform, and it buys exactly one thing: two nodes on *one
/// host* both hearing beacons. That is a development arrangement, not a
/// deployment. The second node gets an `AddrInUse` from [`Responder::bind`],
/// carries on without LAN discovery, and dials from its bootstrap addresses like
/// every node did before this module existed.
///
/// `port` is therefore a parameter rather than the constant, so two nodes on one
/// host can still each have a beacon socket by agreeing on a different one --
/// and so tests do not fight the machine they run on.
pub struct Responder {
    socket: UdpSocket,
    us: PeerId,
    session_port: u16,
}

impl Responder {
    /// Join the group and bind the beacon port.
    ///
    /// `session_port` is the port this node accepts *sessions* on, which is what
    /// travels in the beacon. `beacon_port` is where beacons themselves are sent
    /// and heard; [`PORT`] is the value every node should use.
    ///
    /// Returns the error rather than panicking, and a caller is expected to
    /// carry on without it. Multicast is unavailable in more ordinary situations
    /// than it is available in exotic ones: containers with no multicast route,
    /// interfaces with it disabled, a port already held. None of those is a
    /// reason a node cannot join the network -- it is a reason it needs a
    /// bootstrap address, which was the only option before this existed.
    pub fn bind(us: PeerId, session_port: u16, beacon_port: u16) -> io::Result<Responder> {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, beacon_port))?;
        socket.join_multicast_v4(&GROUP, &Ipv4Addr::UNSPECIFIED)?;
        socket.set_multicast_ttl_v4(TTL)?;
        // Loopback on, so a node hears its own beacon. Deliberate: it is the
        // cheapest confirmation that the socket really works, and `hear`
        // recognises our own id rather than dialling it.
        socket.set_multicast_loop_v4(true)?;
        socket.set_nonblocking(true)?;
        Ok(Responder {
            socket,
            us,
            session_port,
        })
    }

    /// Broadcast this node's beacon once, to `beacon_port`.
    pub fn announce(&self, beacon_port: u16) -> io::Result<()> {
        let frame = Beacon::new(self.us, self.session_port).encode();
        self.socket
            .send_to(&frame, SocketAddr::new(GROUP.into(), beacon_port))?;
        Ok(())
    }

    /// Drain what is waiting on the socket, returning the peers heard.
    ///
    /// Non-blocking, so a caller polls it from a loop it already has rather than
    /// owning a thread. `limit` bounds one call: this socket is reachable by
    /// anyone on the segment, and a receive loop with no bound is a way for one
    /// host to hold the calling thread for as long as it likes.
    ///
    /// The buffer is one byte longer than a frame so an oversized datagram
    /// arrives *oversized* and is refused by `hear`, rather than being silently
    /// truncated by the kernel into something that parses.
    pub fn poll(&self, limit: usize) -> Vec<(PeerId, SocketAddr)> {
        let mut out = Vec::new();
        let mut buffer = [0u8; FRAME_LEN + 1];
        for _ in 0..limit {
            let Ok((read, from)) = self.socket.recv_from(&mut buffer) else {
                // `WouldBlock` is the ordinary end of the queue. Any other error
                // ends this round and is not fatal to the node.
                break;
            };
            if let Heard::Peer { peer, addr } = hear(&buffer[..read], from.ip(), &self.us) {
                out.push((peer, addr));
            }
        }
        out
    }

    /// The address the beacon socket is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    fn peer(byte: u8) -> PeerId {
        [byte; 32]
    }

    #[test]
    fn a_beacon_round_trips() {
        let beacon = Beacon::new(peer(7), 9000);
        let bytes = beacon.encode();
        assert_eq!(bytes.len(), FRAME_LEN);
        assert_eq!(Beacon::decode(&bytes), Some(beacon));
    }

    #[test]
    fn the_address_comes_from_the_packet_and_the_port_from_the_message() {
        // The rule the whole module turns on. A beacon cannot name an address,
        // so it cannot point a segment at a third party.
        let bytes = Beacon::new(peer(3), 9000).encode();
        let source: IpAddr = "192.168.1.44".parse().expect("addr");
        assert_eq!(
            hear(&bytes, source, &peer(0)),
            Heard::Peer {
                peer: peer(3),
                addr: SocketAddr::new(source, 9000),
            }
        );
        // Same beacon, different sender: a different address, with no way for
        // the sender to influence which.
        let other: IpAddr = "10.1.2.3".parse().expect("addr");
        assert_eq!(
            hear(&bytes, other, &peer(0)),
            Heard::Peer {
                peer: peer(3),
                addr: SocketAddr::new(other, 9000),
            }
        );
    }

    #[test]
    fn our_own_beacon_is_recognised_rather_than_dialled() {
        // Multicast loopback is on, so a node hears itself every interval. A
        // node that dialled itself would succeed, which is worse than failing
        // because nothing would ever flag it.
        let bytes = Beacon::new(peer(5), 9000).encode();
        let source: IpAddr = "192.168.1.9".parse().expect("addr");
        assert_eq!(hear(&bytes, source, &peer(5)), Heard::Ourselves);
    }

    #[test]
    fn junk_on_the_port_is_ignored_without_decoding_into_a_peer() {
        let source: IpAddr = Ipv4Addr::LOCALHOST.into();
        let us = peer(0);
        for junk in [
            &b""[..],
            &b"hello"[..],
            &[0u8; FRAME_LEN][..],      // right length, wrong magic
            &[0xff; FRAME_LEN + 1][..], // longer than a frame
            &[0xff; FRAME_LEN - 1][..], // shorter
        ] {
            assert_eq!(hear(junk, source, &us), Heard::Ignored, "{junk:?}");
        }
        // Right magic, wrong version: refused rather than guessed at.
        let mut wrong_version = Beacon::new(peer(1), 9000).encode();
        wrong_version[4] = VERSION + 1;
        assert_eq!(hear(&wrong_version, source, &us), Heard::Ignored);
    }

    #[test]
    fn a_frame_prefix_is_not_accepted_as_a_frame() {
        // One datagram must not mean two things depending on who parsed it.
        let beacon = Beacon::new(peer(2), 9000).encode();
        let mut padded = beacon.to_vec();
        padded.push(0);
        assert_eq!(Beacon::decode(&padded), None);
        assert_eq!(Beacon::decode(&beacon[..FRAME_LEN - 1]), None);
    }

    #[test]
    fn port_zero_never_becomes_a_contact() {
        let bytes = Beacon::new(peer(4), 0).encode();
        let source: IpAddr = Ipv4Addr::LOCALHOST.into();
        assert_eq!(hear(&bytes, source, &peer(0)), Heard::Ignored);
    }

    #[test]
    fn an_ipv6_source_is_carried_through_unchanged() {
        // The frame has no address in it at all, so it is address-family
        // agnostic for free -- there was never a v4 field to widen.
        let bytes = Beacon::new(peer(6), 9000).encode();
        let source: IpAddr = Ipv6Addr::LOCALHOST.into();
        assert_eq!(
            hear(&bytes, source, &peer(0)),
            Heard::Peer {
                peer: peer(6),
                addr: SocketAddr::new(source, 9000),
            }
        );
    }

    #[test]
    fn the_group_is_administratively_scoped() {
        // 239.0.0.0/8 is the range reserved for private use within an
        // organization. A beacon on a globally-routable group would be a
        // different feature with a different threat model.
        assert_eq!(GROUP.octets()[0], 239);
        assert_eq!(TTL, 1, "a beacon must not survive a router");
    }

    #[test]
    fn a_beacon_carries_nothing_but_an_id_and_a_port() {
        // The privacy property, asserted rather than assumed: `p2p::code`
        // refuses to publish which blobs a node holds, and a beacon that leaked
        // the same set to a whole office would undo that.
        assert_eq!(FRAME_LEN, 39);
        let bytes = Beacon::new(peer(1), 9000).encode();
        assert_eq!(bytes.len(), 39, "the frame has no room for an inventory");
    }

    // -- the socket driver, against real sockets -------------------------
    //
    // Skipped rather than failed where multicast is unavailable: a container
    // with no multicast route is a normal place to run these, and a test that
    // fails there teaches nothing about the code. `bind` returning an error is
    // itself the documented degradation path.

    fn beacon_port() -> u16 {
        // Ports derived from the pid, so concurrent `cargo test` runs on one
        // machine do not collide on a fixed number.
        40_000 + (std::process::id() % 20_000) as u16
    }

    #[test]
    fn a_responder_hears_its_own_beacon_and_knows_it_is_its_own() {
        let port = beacon_port();
        let Ok(responder) = Responder::bind(peer(11), 9000, port) else {
            eprintln!("skipped: multicast unavailable on this host");
            return;
        };
        if responder.announce(port).is_err() {
            eprintln!("skipped: multicast send unavailable on this host");
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
        // Loopback is on, so the datagram came back -- and produced no contact,
        // because a node must never dial itself.
        assert_eq!(responder.poll(8), Vec::new());
    }

    #[test]
    fn a_beacon_from_another_host_becomes_a_contact_at_the_senders_address() {
        // The end-to-end path, with a genuinely separate sender: a bare socket
        // that never binds the beacon port, so no `SO_REUSEADDR` is needed and
        // the datagram really does arrive from somewhere else.
        let port = beacon_port().wrapping_add(1).max(40_000);
        let Ok(responder) = Responder::bind(peer(12), 9000, port) else {
            eprintln!("skipped: multicast unavailable on this host");
            return;
        };
        let Ok(sender) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) else {
            eprintln!("skipped: cannot bind a sender");
            return;
        };
        let _ = sender.set_multicast_ttl_v4(TTL);
        let _ = sender.set_multicast_loop_v4(true);
        let frame = Beacon::new(peer(200), 7777).encode();
        if sender
            .send_to(&frame, SocketAddr::new(GROUP.into(), port))
            .is_err()
        {
            eprintln!("skipped: multicast send unavailable on this host");
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));

        let heard = responder.poll(8);
        if heard.is_empty() {
            eprintln!("skipped: no multicast delivery on this host");
            return;
        }
        assert_eq!(heard.len(), 1, "one beacon, one contact");
        let (id, addr) = heard[0];
        assert_eq!(id, peer(200));
        // The port is the one *in the message*, never the sender's ephemeral
        // source port -- that is the whole reason the port is carried.
        assert_eq!(addr.port(), 7777);
        assert_ne!(
            addr.port(),
            sender.local_addr().expect("addr").port(),
            "the session port was taken from the socket instead of the beacon"
        );
    }

    #[test]
    fn junk_on_the_beacon_port_produces_no_contacts() {
        let port = beacon_port().wrapping_add(2).max(40_000);
        let Ok(responder) = Responder::bind(peer(13), 9000, port) else {
            eprintln!("skipped: multicast unavailable on this host");
            return;
        };
        let Ok(sender) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) else {
            return;
        };
        let _ = sender.set_multicast_loop_v4(true);
        // Something else entirely, and an oversized frame that must not be
        // truncated into a valid one.
        for junk in [&b"not a beacon at all"[..], &[0xffu8; FRAME_LEN + 1][..]] {
            let _ = sender.send_to(junk, SocketAddr::new(GROUP.into(), port));
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert_eq!(responder.poll(8), Vec::new());
    }

    #[test]
    fn poll_stops_at_its_limit() {
        // The bound that stops one host holding the calling thread.
        let port = beacon_port().wrapping_add(3).max(40_000);
        let Ok(responder) = Responder::bind(peer(14), 9000, port) else {
            eprintln!("skipped: multicast unavailable on this host");
            return;
        };
        let Ok(sender) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) else {
            return;
        };
        let _ = sender.set_multicast_loop_v4(true);
        for index in 0..6u8 {
            let frame = Beacon::new(peer(100 + index), 7000 + index as u16).encode();
            let _ = sender.send_to(&frame, SocketAddr::new(GROUP.into(), port));
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
        let heard = responder.poll(2);
        if heard.is_empty() {
            eprintln!("skipped: no multicast delivery on this host");
            return;
        }
        assert!(
            heard.len() <= 2,
            "poll returned {} past its limit",
            heard.len()
        );
    }
}
