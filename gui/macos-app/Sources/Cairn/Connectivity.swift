import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// Whether something accepts a TCP connection at an address: the plainest
/// question about a port, and the one a status word cannot answer. "Waiting
/// for peers" reads the same whether the node's port is open and nobody has
/// dialled yet, or nothing is listening at all.
///
/// A TCP connect proves a listener and nothing more. It does not prove the
/// listener is a cairn node holding the key its id names -- the handshake
/// decides that, and only the node runs it -- so the connectivity sheet
/// shows the node's own log about each peer beside the port result.
enum PortProbe {
    enum Result: Equatable {
        /// Something accepted the connection.
        case open
        /// The host answered that nothing listens on that port.
        case refused
        /// No answer within the deadline: the host is down, or a firewall
        /// dropped the attempt without saying so.
        case noAnswer
        case unresolved(String)
        case failed(String)

        var isOpen: Bool { self == .open }

        var summary: String {
            switch self {
            case .open: return "accepts connections"
            case .refused: return "refused: nothing is listening on that port"
            case .noAnswer: return "no answer: the host is down, or a firewall drops the connection"
            case .unresolved(let why): return "the name does not resolve (\(why))"
            case .failed(let why): return "could not connect (\(why))"
            }
        }
    }

    /// `host:port`, split at the last colon, with `[::1]:9000` unbracketed.
    static func split(_ address: String) -> (host: String, port: UInt16)? {
        guard let colon = address.lastIndex(of: ":") else { return nil }
        var host = String(address[..<colon])
        guard let port = UInt16(address[address.index(after: colon)...]), port != 0, !host.isEmpty else { return nil }
        if host.hasPrefix("["), host.hasSuffix("]") { host = String(host.dropFirst().dropLast()) }
        return (host, port)
    }

    /// Off the calling thread: a dead address takes the whole deadline.
    static func tcp(_ host: String, _ port: UInt16, timeout: TimeInterval = 3) async -> Result {
        await Task.detached(priority: .userInitiated) { connect(host, port, timeout: timeout) }.value
    }

    /// Every address the name resolves to, until one accepts. The best
    /// answer wins, because "refused" from an IPv6 address the host does not
    /// serve on says nothing about its IPv4 one.
    static func connect(_ host: String, _ port: UInt16, timeout: TimeInterval) -> Result {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        #if canImport(Darwin)
        hints.ai_socktype = SOCK_STREAM
        #else
        hints.ai_socktype = Int32(SOCK_STREAM.rawValue)
        #endif
        var list: UnsafeMutablePointer<addrinfo>?
        let rc = getaddrinfo(host, String(port), &hints, &list)
        guard rc == 0, let first = list else {
            return .unresolved(String(cString: gai_strerror(rc)))
        }
        defer { freeaddrinfo(first) }

        var best: Result = .failed("no address")
        var cursor: UnsafeMutablePointer<addrinfo>? = first
        while let info = cursor {
            let result = attempt(info.pointee, timeout: timeout)
            if result == .open { return .open }
            if rank(result) > rank(best) { best = result }
            cursor = info.pointee.ai_next
        }
        return best
    }

    private static func rank(_ r: Result) -> Int {
        switch r {
        case .open: return 4
        case .refused: return 3
        case .noAnswer: return 2
        case .failed: return 1
        case .unresolved: return 0
        }
    }

    /// One non-blocking connect, waited on with `poll` so the deadline is
    /// ours rather than the kernel's (which is over a minute).
    private static func attempt(_ info: addrinfo, timeout: TimeInterval) -> Result {
        let fd = socket(info.ai_family, info.ai_socktype, info.ai_protocol)
        guard fd >= 0 else { return .failed(String(cString: strerror(errno))) }
        defer { close(fd) }
        let flags = fcntl(fd, F_GETFL, 0)
        _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)

        if sysConnect(fd, info.ai_addr, info.ai_addrlen) == 0 { return .open }
        let started = errno
        if started == ECONNREFUSED { return .refused }
        guard started == EINPROGRESS else { return .failed(String(cString: strerror(started))) }

        var poller = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
        let ready = poll(&poller, 1, Int32(max(1, timeout * 1000)))
        guard ready > 0 else { return ready == 0 ? .noAnswer : .failed(String(cString: strerror(errno))) }
        var error: Int32 = 0
        var length = socklen_t(MemoryLayout<Int32>.size)
        guard getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0 else {
            return .failed(String(cString: strerror(errno)))
        }
        switch error {
        case 0: return .open
        case ECONNREFUSED: return .refused
        case ETIMEDOUT, EHOSTUNREACH, ENETUNREACH: return .noAnswer
        default: return .failed(String(cString: strerror(error)))
        }
    }
}

/// The C `connect`, under a name `PortProbe.connect` does not shadow.
private func sysConnect(_ fd: Int32, _ address: UnsafeMutablePointer<sockaddr>!, _ length: socklen_t) -> Int32 {
    connect(fd, address, length)
}

/// What this Mac's own interfaces are, for "reachable on the LAN" checks.
enum LocalNetwork {
    struct Interface: Equatable {
        var name: String
        var address: String
    }

    /// IPv4 addresses on interfaces that are up, loopback and link-local
    /// excluded: the addresses another machine on the network would dial.
    static func ipv4() -> [Interface] {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return [] }
        defer { freeifaddrs(first) }
        var out: [Interface] = []
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let entry = cursor {
            defer { cursor = entry.pointee.ifa_next }
            guard let addr = entry.pointee.ifa_addr, Int32(addr.pointee.sa_family) == AF_INET else { continue }
            let flags = Int32(entry.pointee.ifa_flags)
            guard flags & Int32(IFF_UP) != 0, flags & Int32(IFF_LOOPBACK) == 0 else { continue }
            var host = [CChar](repeating: 0, count: 1025)  // NI_MAXHOST
            guard getnameinfo(addr, socklen_t(MemoryLayout<sockaddr_in>.size), &host, socklen_t(host.count),
                              nil, 0, NI_NUMERICHOST) == 0 else { continue }
            let address = String(cString: host)
            if address.hasPrefix("169.254.") { continue }
            out.append(Interface(name: String(cString: entry.pointee.ifa_name), address: address))
        }
        return out
    }
}

/// What the node's own log says about the peers it dials, read rather than
/// guessed: a TCP connect proves a listener, the handshake proves the node.
enum NetworkLog {
    struct PeerNote: Equatable {
        var name: String
        var address: String
        var ok: Bool
        var detail: String
    }

    /// The latest word on each seed, from the lines `daemon.rs` writes:
    /// `seeds: <name> answered at <addr> with the key its id names; …` and
    /// `seeds: <name> at <addr> did not hand over its key (<error>); …`.
    static func seeds(in lines: [String]) -> [PeerNote] {
        var latest: [String: PeerNote] = [:]
        var order: [String] = []
        for line in lines {
            guard let r = line.range(of: "seeds: ") else { continue }
            let rest = line[r.upperBound...]
            var note: PeerNote?
            if let at = rest.range(of: " answered at "), let end = rest.range(of: " with the key") {
                note = PeerNote(name: String(rest[..<at.lowerBound]),
                                address: String(rest[at.upperBound..<end.lowerBound]),
                                ok: true, detail: "the node completed a handshake with the key its id names")
            } else if let at = rest.range(of: " at "), let end = rest.range(of: " did not hand over its key") {
                // ` (<error>); asking again in 60s. …` -- and the error has
                // parentheses of its own ("os error 111"), so the end is the
                // `); ` after it, not the first `)`.
                var why = String(rest[end.upperBound...])
                if why.hasPrefix(" ("), let close = why.range(of: "); ") ?? why.range(of: ")", options: .backwards) {
                    why = String(why[why.index(why.startIndex, offsetBy: 2)..<close.lowerBound])
                }
                note = PeerNote(name: String(rest[..<at.lowerBound]),
                                address: String(rest[at.upperBound..<end.lowerBound]),
                                ok: false, detail: "the node's handshake failed: \(why)")
            }
            if let note {
                if latest[note.name] == nil { order.append(note.name) }
                latest[note.name] = note
            }
        }
        return order.compactMap { latest[$0] }
    }

    /// The latest failure dialling an address, from
    /// `outbound session to <id> (<addr>): <error>`.
    static func lastDialFailure(to address: String, in lines: [String]) -> String? {
        let marker = "(\(address)): "
        guard let line = lines.last(where: { $0.contains("outbound session to ") && $0.contains(marker) }),
              let r = line.range(of: marker) else { return nil }
        return String(line[r.upperBound...])
    }
}

/// The address in a bootstrap file: `{"addr": "host:port", "public": hex}`,
/// the shape `cairn gen-bootstrap` writes and `--bootstrap` reads.
enum BootstrapFile {
    static func address(_ path: String) -> String? {
        guard let data = FileManager.default.contents(atPath: path),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return nil }
        return json["addr"] as? String
    }
}

/// Whether macOS's application firewall is on. It asks once per program
/// whether to accept incoming connections, and a node set to accept inbound
/// that was denied there looks, from outside, exactly like a closed port.
enum MacFirewall {
    static func isOn() -> Bool? {
        let tool = URL(fileURLWithPath: "/usr/libexec/ApplicationFirewall/socketfilterfw")
        guard FileManager.default.isExecutableFile(atPath: tool.path) else { return nil }
        let p = Process()
        p.executableURL = tool
        p.arguments = ["--getglobalstate"]
        let out = Pipe()
        p.standardOutput = out
        p.standardError = FileHandle.nullDevice
        do { try p.run() } catch { return nil }
        let text = String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self).lowercased()
        p.waitUntilExit()
        if text.contains("enabled") || text.contains("state = 1") { return true }
        if text.contains("disabled") || text.contains("state = 0") { return false }
        return nil
    }
}
