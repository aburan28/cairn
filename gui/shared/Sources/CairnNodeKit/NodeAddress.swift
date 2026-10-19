import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// A listener describes a local socket; only a concrete peer address is useful to share.
public enum NodeAddress {
    /// A wildcard may use a real interface on the computer that owns it, with
    /// the actual bound port. Never substitute a LAN IP for a local-only bind
    /// or borrow this computer's interfaces for an attached remote node.
    public static func forListener(_ listen: String?, localHosts: [String]) -> String? {
        if let address = shareable(listen) { return address }
        guard let listen, let url = URL(string: "tcp://\(listen)"), url.host == "0.0.0.0",
              let port = url.port, port > 0 && port <= 65535 else { return nil }
        for host in localHosts {
            let octets = host.split(separator: ".")
            if octets.count == 4 && octets.allSatisfy({ UInt8($0) != nil }),
               let address = shareable("\(host):\(port)") { return address }
        }
        return nil
    }

    public static func shareable(_ value: String?) -> String? {
        guard let value = value?.trimmingCharacters(in: .whitespacesAndNewlines), !value.isEmpty,
              let url = URL(string: value.contains("://") ? value : "http://\(value)"),
              let rawHost = url.host, url.user == nil, url.password == nil else { return nil }
        let host = rawHost.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "[]."))
        guard !host.isEmpty, restriction(host) == nil,
              ["http", "https", "tcp"].contains(url.scheme?.lowercased() ?? "") else { return nil }
        return value
    }

    public static func label(_ value: String?) -> String {
        if let address = shareable(value) { return address }
        if let value, let url = URL(string: value.contains("://") ? value : "http://\(value)"), let host = url.host,
           let label = restriction(host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "[]."))) {
            return label
        }
        return "Not advertised"
    }

    private static func restriction(_ host: String) -> String? {
        if host == "localhost" || host.hasSuffix(".localhost") || host.range(of: "^127(?:\\.[0-9]+){3}$", options: .regularExpression) != nil {
            return "Local connection"
        }
        if host == "0.0.0.0" { return "Not advertised" }
        #if canImport(Darwin) || canImport(Glibc)
        var address = in6_addr()
        if host.withCString({ inet_pton(AF_INET6, $0, &address) }) == 1 {
            let bytes = withUnsafeBytes(of: address) { Array($0) }
            if bytes.allSatisfy({ $0 == 0 }) { return "Not advertised" }
            if bytes.dropLast().allSatisfy({ $0 == 0 }) && bytes.last == 1 { return "Local connection" }
            if bytes.prefix(10).allSatisfy({ $0 == 0 }) && bytes[10] == 255 && bytes[11] == 255 {
                if bytes[12] == 127 { return "Local connection" }
                if bytes.suffix(4).allSatisfy({ $0 == 0 }) { return "Not advertised" }
            }
        }
        #endif
        return nil
    }
}
