import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Observations from one node's memory, never a claim of ongoing sockets or
/// verified work. Keep wire names so every reader decodes the same contract.
public struct SessionReport: Decodable, Sendable {
    public let available: Bool
    public let peers: [PeerSession]
    public let reached: Int
    public let recent: Int
    public let lost: Int
    public let unreached: Int
    public let note: String
    public let this_node: ThisNode?
    public let address_book: AddressBook?
    public let reached_within_seconds: Int?
    public let recent_within_seconds: Int?
}
public struct PeerSession: Decodable, Identifiable, Sendable {
    public var id: String { peer_id }
    public let peer_id: String
    public let status: String
    public let addr: String?
    public let last_direction: String
    public let inbound_ok: Int
    public let outbound_ok: Int
    public let failures: Int
    public let age_seconds: Int?
    public let last_ok_at: String?
    public let last_error: String?
    public let entries_after: Int?
}
public struct ThisNode: Decodable, Sendable {
    public let peer_id: String?
    public let listen: String?
    public let uptime_seconds: Int
}
public struct AddressBook: Decodable, Sendable {
    public let endpoints: Int
    public let hints: Int
}
public struct NetworkReport: Decodable, Sendable {
    public let node: NodeFacts
    public let compute: ComputeReport
    public let peers: PeerSummary
    public let roles: EvidencedRoles
    public let note: String
    public let generated_at: String
}
public struct PeerSummary: Decodable, Sendable {
    public let reached: Int
    public let recent: Int
    public let lost: Int
    public let unreached: Int
}
public struct NodeFacts: Decodable, Sendable {
    public let roles: DeclaredRoles
    public let warnings: [String]
    public let hardware: NodeHardware
    public let accepts_submissions: Bool
    public let runs_p2p: Bool
}
public struct DeclaredRoles: Decodable, Sendable { public let declared: [String]; public let source: String }
public struct NodeHardware: Decodable, Sendable {
    public let cpus: Int?
    public let memory_mb: Int?
    public let os: String
    public let arch: String
    public let note: String
}
public struct ComputeReport: Decodable, Sendable {
    public let workers: [FleetWorker]
    public let live: Int
    public let stale: Int
    public let gone: Int
    public let steps_per_second: Double
    public let lanes: Int
    public let classes: [DeviceClass]
    public let note: String
}
public struct FleetWorker: Decodable, Identifiable, Sendable {
    public var id: String { "\(objective_id):\(worker)" }
    public let worker: String
    public let objective_id: String
    public let status: String
    public let device: String
    public let age_seconds: Int
    public let lanes: Int?
    public let steps_per_second: Double?
}
public struct DeviceClass: Decodable, Identifiable, Sendable {
    public var id: String { `class` }
    public let `class`: String
    public let workers: Int
    public let live: Int
    public let lanes: Int
    public let steps_per_second: Double
}
public struct EvidencedRoles: Decodable, Sendable {
    public struct Count: Decodable, Sendable { public let total: Int }
    public let coordinators: Count
    public let executors: Count
    public let verifiers: Count
    public let note: String
}

public enum NodeReadError: LocalizedError {
    case invalidURL, status(Int)
    public var errorDescription: String? {
        switch self {
        case .invalidURL: return "Use the node’s HTTP or HTTPS address."
        case .status(404): return "This node predates the session or network report. Update the node to read it here."
        case .status(let status): return "The node answered HTTP \(status). Refresh to try again."
        }
    }
}

/// A reader URL may include /ui/ or sit below a reverse proxy's path. Strip
/// only the UI suffix, preserving its actual node origin and base path.
public enum NodeEndpoint {
    public static func origin(_ url: URL) -> URL? {
        guard ["http", "https"].contains(url.scheme?.lowercased() ?? ""), url.host != nil,
              var parts = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return nil }
        let components = parts.path.split(separator: "/").map(String.init)
        let root = components.firstIndex(of: "ui").map { Array(components[..<$0]) } ?? components
        parts.path = root.isEmpty ? "" : "/" + root.joined(separator: "/")
        parts.query = nil; parts.fragment = nil
        return parts.url
    }
    public static func reader(_ base: URL, page: String, objective: String? = nil) -> URL? {
        guard let base = origin(base), var parts = URLComponents(url: base, resolvingAgainstBaseURL: false) else { return nil }
        parts.path += "/ui/" + page
        parts.queryItems = objective.map { [URLQueryItem(name: "id", value: $0)] }
        return parts.url
    }
    public static func sameOrigin(_ lhs: URL, _ rhs: URL) -> Bool {
        func port(_ url: URL) -> Int? { url.port ?? (url.scheme == "https" ? 443 : url.scheme == "http" ? 80 : nil) }
        return lhs.scheme?.lowercased() == rhs.scheme?.lowercased() && lhs.host?.lowercased() == rhs.host?.lowercased() && port(lhs) == port(rhs)
    }
}

public enum ReaderNavigation {
    public static func staysInReader(_ url: URL, node: URL) -> Bool {
        if ["about", "blob", "data"].contains(url.scheme?.lowercased() ?? "") { return true }
        return NodeEndpoint.sameOrigin(url, node)
    }
    public static func mayOpenExternally(_ url: URL, clicked: Bool, mainFrame: Bool) -> Bool {
        clicked && mainFrame && ["http", "https", "mailto"].contains(url.scheme?.lowercased() ?? "")
    }
}

public enum SecretName {
    public static func isValid(_ name: String) -> Bool {
        let bytes = Array(name.utf8)
        func letter(_ byte: UInt8) -> Bool { (65...90).contains(byte) || (97...122).contains(byte) || byte == 95 }
        guard let first = bytes.first, letter(first), bytes.count <= 128 else { return false }
        return bytes.allSatisfy { letter($0) || (48...57).contains($0) }
    }
}

public struct NodeReportClient: Sendable {
    public let base: URL
    public let session: URLSession
    public init(base: URL, session: URLSession = .shared) { self.base = base; self.session = session }
    public func sessions() async throws -> SessionReport { try await get("sessions") }
    public func network() async throws -> NetworkReport { try await get("network") }
    private func get<T: Decodable>(_ path: String) async throws -> T {
        guard let origin = NodeEndpoint.origin(base) else { throw NodeReadError.invalidURL }
        var request = URLRequest(url: origin.appendingPathComponent(path), cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 10)
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw NodeReadError.invalidURL }
        guard http.statusCode == 200 else { throw NodeReadError.status(http.statusCode) }
        return try JSONDecoder().decode(T.self, from: data)
    }
}
