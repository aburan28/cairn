import Foundation

/// Which agent is being connected: the three `make mcp-setup` writes for,
/// each with its own config file and shape.
enum AgentClient: String, CaseIterable, Identifiable {
    case claudeCode, codex, opencode

    var id: String { rawValue }

    var title: String {
        switch self {
        case .claudeCode: return "Claude Code"
        case .codex: return "Codex"
        case .opencode: return "OpenCode"
        }
    }

    var file: String {
        switch self {
        case .claudeCode: return ".mcp.json in the project, or ~/.claude.json through claude mcp add"
        case .codex: return "~/.codex/config.toml"
        case .opencode: return "opencode.json in the project, or ~/.config/opencode/opencode.json"
        }
    }
}

/// How the agent reaches a cairn: the two arrangements docs/agents.md
/// describes.
enum AgentArrangement: String, CaseIterable, Identifiable {
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
    }

    /// The command line after the binary. Global flags before the
    /// subcommand, its own after it, as the CLI parses them.
    static func arguments(_ i: Inputs) -> [String] {
        switch i.arrangement {
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
    /// it gets them as well.
    static func environment(_ i: Inputs) -> [String: String] {
        i.settings.environment
    }

    static func render(_ i: Inputs) -> String {
        let args = arguments(i)
        let env = environment(i)
        switch i.client {
        case .claudeCode:
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

    /// `claude mcp add`, which writes the Claude Code stanza itself and
    /// cannot drift from the flags the way a hand-edited file can.
    static func claudeAdd(_ i: Inputs) -> String {
        let env = environment(i)
        var parts = ["claude", "mcp", "add", "cairn", "--scope", "user"]
        for key in env.keys.sorted() {
            parts += ["--env", "\(key)=\(env[key] ?? "")"]
        }
        parts += ["--", i.binary] + arguments(i)
        return parts.map(shellQuote).joined(separator: " ")
    }

    static func json(_ object: [String: Any]) -> String {
        guard let data = try? JSONSerialization.data(
            withJSONObject: object, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
        else { return "{}" }
        return String(decoding: data, as: UTF8.self)
    }

    static func tomlString(_ s: String) -> String {
        "\"" + s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }

    /// Single quotes around anything a shell would read, and nothing around
    /// a plain word, so the command reads the way a person would type it.
    static func shellQuote(_ s: String) -> String {
        let safe = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-_./=:@,+"))
        if !s.isEmpty, s.unicodeScalars.allSatisfy({ safe.contains($0) }) { return s }
        return "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}
