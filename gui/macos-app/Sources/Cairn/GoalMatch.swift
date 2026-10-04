import Foundation

/// A goal the node says a description names -- `GET /goals?q=` (docs/goals.md).
///
/// Asked while the person types, so that "let's solve ECC2K-130" is caught
/// before it is drafted as a second spelling of a goal four objectives
/// already share. A match is a suggestion from the node's alias catalog: the
/// person chooses whether the challenge becomes a new angle on that goal, and
/// the model is told the handle to use.
struct GoalMatch: Equatable, Identifiable {
    var id: String { key }
    let key: String
    let name: String
    /// The handle to post under: `GOAL-certicom-ecc2k130`.
    let handle: String
    /// Every spelling already in use, the handle first.
    let handles: [String]
    let objectives: Int
    let open: Int
    /// The angle paths funded so far, the empty (unnamed) one left out.
    let angles: [String]
    let summary: String?

    /// One line for the banner under the description.
    var summaryLine: String {
        if objectives == 0 {
            return "\(name) is a known goal nobody has funded yet; the first challenge on it is \(handle)."
        }
        let spelled = handles.count > 1 ? " (also written \(handles.dropFirst().joined(separator: ", ")))" : ""
        let approaches = angles.isEmpty
            ? "no angle named yet"
            : "\(angles.count) angle\(angles.count == 1 ? "" : "s"): \(angles.joined(separator: ", "))"
        return "\(name) already has \(objectives) challenge\(objectives == 1 ? "" : "s") (\(open) open) under \(handle)\(spelled), \(approaches)."
    }

    /// The `matches` of a `GET /goals?q=` body. Anything malformed is no match.
    static func parse(_ body: Any) -> [GoalMatch] {
        guard let object = body as? [String: Any], let matches = object["matches"] as? [[String: Any]] else {
            return []
        }
        return matches.compactMap { item in
            guard let key = item["key"] as? String, let name = item["name"] as? String,
                  let handle = item["handle"] as? String else { return nil }
            let angles = (item["angles"] as? [[String: Any]] ?? [])
                .compactMap { $0["path"] as? String }
                .filter { !$0.isEmpty }
            return GoalMatch(
                key: key, name: name, handle: handle,
                handles: item["handles"] as? [String] ?? [handle],
                objectives: item["objectives"] as? Int ?? 0,
                open: item["open"] as? Int ?? 0,
                angles: angles,
                summary: item["summary"] as? String)
        }
    }
}

enum GoalLookup {
    /// Ask the node this window reads which goals `brief` names. The reader
    /// URL is the node's `/ui/`; its HTTP side is the same origin.
    static func find(_ brief: String, reader: URL) async -> [GoalMatch] {
        guard var components = URLComponents(url: reader, resolvingAgainstBaseURL: false) else { return [] }
        components.path = "/goals"
        components.queryItems = [URLQueryItem(name: "q", value: String(brief.prefix(500)))]
        guard let url = components.url else { return [] }
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 3
        guard let (data, response) = try? await URLSession(configuration: config).data(from: url),
              (response as? HTTPURLResponse)?.statusCode == 200,
              let body = try? JSONSerialization.jsonObject(with: data) else { return [] }
        return GoalMatch.parse(body)
    }
}
