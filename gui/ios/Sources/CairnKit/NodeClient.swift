import Foundation

/// Talks to one cairn node's HTTP surface.
///
/// Convenience routes only — `/log` is the product. Nothing here re-derives
/// a chain or a settlement. `cachePolicy: .reloadIgnoringLocalCacheData`
/// because a node that just settled has a different frontier, and a cached
/// answer would show a pool that is no longer there.
public struct NodeClient: Sendable {
    public var base: String
    public var session: URLSession
    /// Published seed list, used only when `base` is empty and nothing local
    /// answered. Same file the public site publishes; a seed that lies is
    /// caught by the reader, not by this fetch.
    public var seedsURL: URL?

    public init(
        base: String,
        session: URLSession = .shared,
        seedsURL: URL? = URL(string: "https://aburan28.github.io/cairn/seeds.json")
    ) {
        self.base = trimSlash(base)
        self.session = session
        self.seedsURL = seedsURL
    }

    /// `GET /health` is `text/plain` `ok`. A 200 carrying an HTML error page
    /// is not a node — that is what GitHub Pages serves for a path it does
    /// not have, and mistaking it for live is how a site once labelled a
    /// snapshot as a node that did not exist.
    public func answers(_ base: String) async -> Bool {
        guard let url = URL(string: "\(trimSlash(base))/health") else { return false }
        var request = URLRequest(url: url)
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.timeoutInterval = 4
        do {
            let (data, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
                return false
            }
            let text = String(data: data, encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines)
            return text == "ok"
        } catch {
            return false
        }
    }

    /// Pick a node: the configured URL if it answers, else a published seed,
    /// else nothing. One answer for the whole screen, so `/objectives` and
    /// `/chain` cannot silently come from two hosts.
    public func resolve() async -> String {
        if !base.isEmpty, await answers(base) { return base }
        if !base.isEmpty { return base }
        if let seedsURL {
            if let seeds = try? await fetchSeeds(from: seedsURL) {
                for endpoint in readableEndpoints(seeds.seeds, pageIsHTTPS: true) {
                    if await answers(endpoint) { return endpoint }
                }
            }
        }
        return ""
    }

    public func fetchObjectives(at base: String) async throws -> [Objective] {
        let body: ObjectivesResponse = try await get(base, path: "/objectives")
        return body.objectives
    }

    public func fetchObjective(at base: String, id: String) async throws -> ObjectiveRecord? {
        // Not percent-encoded: the id is `sha256:<hex>`, the colon is legal
        // in a path segment, and the server matches on the raw remainder
        // after `/objective/` without decoding. Encoding it 404s.
        struct Envelope: Decodable { var record: ObjectiveRecord? }
        let body: Envelope = try await get(base, path: "/objective/\(id)")
        return body.record
    }

    public func fetchChain(at base: String) async throws -> Chain {
        try await get(base, path: "/chain")
    }

    public func fetchCheckpoint(at base: String) async throws -> CheckpointResponse {
        try await get(base, path: "/checkpoint")
    }

    public func fetchPeers(at base: String) async throws -> PeersResponse {
        try await get(base, path: "/peers")
    }

    public func fetchLog(at base: String) async throws -> ParsedLog {
        let text = try await getText(base, path: "/log")
        return parseLog(text)
    }

    public func fetchSeeds(from url: URL) async throws -> SeedList {
        var request = URLRequest(url: url)
        request.cachePolicy = .reloadIgnoringLocalCacheData
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            return SeedList(version: 0, seeds: [])
        }
        return try JSONDecoder().decode(SeedList.self, from: data)
    }

    private func get<T: Decodable>(_ base: String, path: String) async throws -> T {
        let data = try await getData(base, path: path)
        do {
            return try JSONDecoder().decode(T.self, from: data)
        } catch {
            throw NodeError.shape("\(display(base))\(path) is not the shape this reader expects: \(error)")
        }
    }

    private func getText(_ base: String, path: String) async throws -> String {
        let data = try await getData(base, path: path)
        return String(data: data, encoding: .utf8) ?? ""
    }

    private func getData(_ base: String, path: String) async throws -> Data {
        let root = trimSlash(base)
        guard let url = URL(string: "\(root)\(path)") else {
            throw NodeError.unreachable(display(base))
        }
        var request = URLRequest(url: url)
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.timeoutInterval = 20
        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            throw NodeError.unreachable(display(base))
        }
        guard let http = response as? HTTPURLResponse else {
            throw NodeError.unreachable(display(base))
        }
        if http.statusCode != 200 {
            throw NodeError.httpStatus(http.statusCode, "\(display(base))\(path)")
        }
        return data
    }
}

private func trimSlash(_ base: String) -> String {
    var out = base.trimmingCharacters(in: .whitespacesAndNewlines)
    while out.hasSuffix("/") { out.removeLast() }
    return out
}

private func display(_ base: String) -> String {
    base.isEmpty ? "this origin" : base
}
