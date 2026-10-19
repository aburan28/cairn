import Foundation

/// Which agent is being connected: the three `make mcp-setup` writes for,
/// each with its own config file and shape, and Conductor, which runs them.
enum AgentClient: String, CaseIterable, Identifiable {
    case claudeCode, codex, opencode, conductor

    var id: String { rawValue }

    var title: String {
        switch self {
        case .claudeCode: return "Claude Code"
        case .codex: return "Codex"
        case .opencode: return "OpenCode"
        case .conductor: return "Conductor"
        }
    }

    /// The clients whose config files this one reads. Conductor has no MCP
    /// config of its own: each workspace runs Claude Code or Codex, which
    /// read their user configs there when a session starts
    /// (conductor.build/docs/reference/mcp).
    var targets: [AgentClient] {
        self == .conductor ? [.claudeCode, .codex] : [self]
    }

    func configURLs(home: URL = FileManager.default.homeDirectoryForCurrentUser) -> [URL] {
        switch self {
        case .claudeCode: return [home.appendingPathComponent(".claude.json")]
        case .codex: return [home.appendingPathComponent(".codex/config.toml")]
        case .opencode: return [home.appendingPathComponent(".config/opencode/opencode.json")]
        case .conductor: return targets.flatMap { $0.configURLs(home: home) }
        }
    }

    var file: String {
        switch self {
        case .claudeCode: return "~/.claude.json (user config)"
        case .codex: return "~/.codex/config.toml"
        case .opencode: return "~/.config/opencode/opencode.json"
        case .conductor: return "~/.claude.json and ~/.codex/config.toml, which Conductor's sessions read"
        }
    }

    /// What loads a changed config.
    var reload: String {
        switch self {
        case .conductor: return "Start a new session in Conductor to load it"
        default: return "Restart \(title) to load it"
        }
    }
}

/// How the agent reaches a cairn: the two arrangements docs/agents.md
/// describes.
enum AgentArrangement: String, CaseIterable, Identifiable {
    /// This app keeps running the node and serves MCP beside it on loopback
    /// (`--mcp-http`); the client connects to that URL rather than starting
    /// anything. Each client opens its own session -- its own citation
    /// capabilities -- on the one log, so any number of agents work at once
    /// and what they submit reaches the network live. The arrangement for
    /// Conductor, whose parallel workspaces each start their own MCP client:
    /// were each to spawn `cairn run`, all but the first would be refused
    /// the log's lock.
    case shared
    /// The client launches `cairn run` on this node's data folder and
    /// becomes its supervisor: one process owns the log, syncs with peers,
    /// serves the reader and answers the agent over MCP. This app attaches
    /// to that reader.
    case runNode
    /// The client launches `cairn mcp` on a log of its own, offline from the
    /// network, beside the node this app runs.
    case ownLog

    var id: String { rawValue }

    var title: String {
        switch self {
        case .shared: return "Agents share this node"
        case .runNode: return "The agent runs this node"
        case .ownLog: return "A log of its own, offline"
        }
    }
}

/// The stanza, from this Mac's real paths. Pure, so tests can hold it to
/// the shapes `scripts/mcp-config.sh` writes and `docs/agents.md` shows.
enum AgentStanza {
    struct Inputs: Equatable {
        var binary: String
        var dataDir: String
        var settings: NodeSettings
        var arrangement: AgentArrangement
        var client: AgentClient
        /// `<dataDir>/agent.identity.json` when it exists: the agent signs
        /// its submissions with it, and its public half is the submitter.
        var identity: String?
        /// Where the node answers agents, for `.shared`: the live address
        /// when the node serves one, else the one it will serve on.
        var agentsURL: URL = NodeSettings.agentsURL(port: NodeSettings.agentsPort)

        /// The same, for one of `client.targets`.
        func `for`(_ target: AgentClient) -> Inputs {
            var copy = self
            copy.client = target
            return copy
        }
    }

    /// The command line after the binary. Global flags before the
    /// subcommand, its own after it, as the CLI parses them.
    static func arguments(_ i: Inputs) -> [String] {
        switch i.arrangement {
        case .shared:
            // Nothing to launch: the node this app runs already serves.
            return []
        case .runNode:
            var args = i.settings.arguments + [
                "run",
                "--listen", "\(i.settings.p2pHost):9000",
                "--serve", "127.0.0.1:8080",
            ] + i.settings.runArguments
            if let identity = i.identity { args += ["--mcp-identity", identity] }
            return args
        case .ownLog:
            var args = ["--log", "\(i.dataDir)/agents/\(i.client.rawValue).jsonl", "--root", i.dataDir, "mcp"]
            if let identity = i.identity { args += ["--identity", identity] }
            return args
        }
    }

    /// What the node reads from its environment, so the agent's node keeps
    /// the limits Settings chose. A standalone `cairn mcp` verifies too, so
    /// it gets them as well. The shared node is this app's, started with them
    /// already.
    static func environment(_ i: Inputs) -> [String: String] {
        i.arrangement == .shared ? [:] : i.settings.environment
    }

    static func render(_ i: Inputs) -> String {
        if i.client == .conductor {
            return i.client.targets.map { render(i.for($0)) }.joined(separator: "\n\n")
        }
        if i.arrangement == .shared {
            // The shapes `scripts/mcp-config.sh --url` writes.
            let url = i.agentsURL.absoluteString
            switch i.client {
            case .claudeCode, .conductor: return json(["mcpServers": ["cairn": ["type": "http", "url": url]]])
            case .opencode: return json(["mcp": ["cairn": ["type": "remote", "url": url, "enabled": true] as [String: Any]]])
            case .codex: return "[mcp_servers.cairn]\nurl = \(tomlString(url))\n"
            }
        }
        let args = arguments(i)
        let env = environment(i)
        switch i.client {
        case .claudeCode, .conductor:  // Conductor's two were rendered above
            var server: [String: Any] = ["command": i.binary, "args": args]
            if !env.isEmpty { server["env"] = env }
            return json(["mcpServers": ["cairn": server]])
        case .opencode:
            var server: [String: Any] = ["type": "local", "command": [i.binary] + args, "enabled": true]
            if !env.isEmpty { server["environment"] = env }
            return json(["mcp": ["cairn": server]])
        case .codex:
            var text = "[mcp_servers.cairn]\ncommand = \(tomlString(i.binary))\nargs = ["
                + args.map(tomlString).joined(separator: ", ") + "]\n"
            if !env.isEmpty {
                text += "\n[mcp_servers.cairn.env]\n"
                for key in env.keys.sorted() {
                    text += "\(key) = \(tomlString(env[key] ?? ""))\n"
                }
            }
            return text
        }
    }

    enum InstallResult: Equatable {
        case installed(URL, backup: URL?)
        case alreadyConfigured(URL)
        /// A `cairn` entry is there that says something else -- a `cairn run`
        /// the client would start itself, say, which in Conductor's second
        /// workspace is refused the log's lock. Left alone, since it may be
        /// hand-edited; named so a person can remove it and add this one.
        case conflicting(URL)
    }

    enum InstallError: LocalizedError {
        case malformedJSON(URL, String)
        case unsupportedConfig(URL)

        var errorDescription: String? {
            switch self {
            case let .malformedJSON(url, reason):
                return "Could not read \(url.path): \(reason). The file was left unchanged."
            case let .unsupportedConfig(url):
                return "\(url.path) has an unexpected structure. The file was left unchanged."
            }
        }
    }

    /// Install this client's user-level MCP entry after the UI has obtained
    /// explicit consent: one outcome per file it reads -- Conductor's agents
    /// read two -- each written or refused on its own, so a malformed one
    /// does not stop the other. Existing configuration is preserved;
    /// replacement is refused so a hand-edited entry cannot be silently
    /// changed.
    static func install(
        _ i: Inputs, home: URL = FileManager.default.homeDirectoryForCurrentUser
    ) -> [(url: URL, outcome: Result<InstallResult, Error>)] {
        i.client.targets.map { target in
            let url = target.configURLs(home: home)[0]
            return (url, Result { try installOne(i.for(target), at: url) })
        }
    }

    private static func installOne(_ i: Inputs, at url: URL) throws -> InstallResult {
        try FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(), withIntermediateDirectories: true)

        if i.client == .codex {
            let current = FileManager.default.fileExists(atPath: url.path)
                ? try String(contentsOf: url, encoding: .utf8)
                : ""
            let stanza = render(i).trimmingCharacters(in: .whitespacesAndNewlines)
            if current.contains("[mcp_servers.cairn]") {
                return current.contains(stanza) ? .alreadyConfigured(url) : .conflicting(url)
            }
            let backup = try backupIfPresent(url)
            let separator = current.isEmpty || current.hasSuffix("\n") ? "" : "\n"
            try (current + separator + "\n# cairn -- added by Cairn.app\n" + stanza + "\n")
                .write(to: url, atomically: true, encoding: .utf8)
            return .installed(url, backup: backup)
        }

        var config: [String: Any] = [:]
        if FileManager.default.fileExists(atPath: url.path) {
            do {
                let data = try Data(contentsOf: url)
                guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any]
                else { throw InstallError.unsupportedConfig(url) }
                config = object
            } catch let error as InstallError {
                throw error
            } catch {
                throw InstallError.malformedJSON(url, error.localizedDescription)
            }
        }

        let section = i.client == .claudeCode ? "mcpServers" : "mcp"
        var servers: [String: Any]
        if let existingSection = config[section] {
            guard let object = existingSection as? [String: Any] else {
                throw InstallError.unsupportedConfig(url)
            }
            servers = object
        } else {
            servers = [:]
        }
        let rendered = render(i)
        guard let data = rendered.data(using: .utf8),
              let entryObject = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let entries = entryObject[section] as? [String: Any],
              let entry = entries["cairn"] as? [String: Any] else {
            throw InstallError.unsupportedConfig(url)
        }
        if let existing = servers["cairn"] {
            return matches(existing, entry) ? .alreadyConfigured(url) : .conflicting(url)
        }
        servers["cairn"] = entry
        config[section] = servers
        let encoded = try JSONSerialization.data(
            withJSONObject: config, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
        let backup = try backupIfPresent(url)
        try (encoded + Data([0x0A])).write(to: url, options: .atomic)
        return .installed(url, backup: backup)
    }

    /// Whether an entry already in a file says what this one says. Every
    /// field of ours must be there and equal; fields a client may add when it
    /// writes the entry itself, such as a `type` or an empty `env`, are not a
    /// difference.
    static func matches(_ existing: Any, _ entry: [String: Any]) -> Bool {
        guard let existing = existing as? [String: Any] else { return false }
        return entry.allSatisfy { key, value in
            guard let theirs = existing[key] else { return false }
            return NSDictionary(dictionary: ["v": theirs]).isEqual(to: ["v": value])
        }
    }

    private static func backupIfPresent(_ url: URL) throws -> URL? {
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        let stamp = ISO8601DateFormatter().string(from: Date()).replacingOccurrences(of: ":", with: "-")
        let backup = url.appendingPathExtension("cairn-\(stamp).bak")
        try FileManager.default.copyItem(at: url, to: backup)
        return backup
    }

    /// `claude mcp add`, which writes the Claude Code stanza itself and
    /// cannot drift from the flags the way a hand-edited file can.
    static func claudeAdd(_ i: Inputs) -> String {
        if i.arrangement == .shared {
            return ["claude", "mcp", "add", "--transport", "http", "--scope", "user", "cairn",
                    i.agentsURL.absoluteString].map(shellQuote).joined(separator: " ")
        }
        let env = environment(i)
        var parts = ["claude", "mcp", "add", "cairn", "--scope", "user"]
        for key in env.keys.sorted() {
            parts += ["--env", "\(key)=\(env[key] ?? "")"]
        }
        parts += ["--", i.binary] + arguments(i)
        return parts.map(shellQuote).joined(separator: " ")
    }

    /// `codex mcp add`, the same for Codex, for the shared node.
    static func codexAdd(_ i: Inputs) -> String {
        ["codex", "mcp", "add", "cairn", "--url", i.agentsURL.absoluteString].map(shellQuote).joined(separator: " ")
    }

    static func json(_ object: [String: Any]) -> String {
        guard let data = try? JSONSerialization.data(
            withJSONObject: object, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
        else { return "{}" }
        return String(decoding: data, as: UTF8.self)
    }

    /// A TOML basic string. Control characters are escaped too: a raw
    /// newline in a path would make the whole config.toml unparseable.
    static func tomlString(_ s: String) -> String {
        var out = "\""
        for scalar in s.unicodeScalars {
            switch scalar {
            case "\\": out += "\\\\"
            case "\"": out += "\\\""
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            case _ where scalar.value < 0x20 || scalar.value == 0x7F:
                out += String(format: "\\u%04X", scalar.value)
            default: out.unicodeScalars.append(scalar)
            }
        }
        return out + "\""
    }

    /// Single quotes around anything a shell would read, and nothing around
    /// a plain word, so the command reads the way a person would type it.
    static func shellQuote(_ s: String) -> String {
        let safe = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-_./=:@,+"))
        if !s.isEmpty, s.unicodeScalars.allSatisfy({ safe.contains($0) }) { return s }
        return "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}
