import Foundation
import XCTest
@testable import Cairn

/// The stanzas Connect an Agent… writes, held to the shapes
/// `scripts/mcp-config.sh` writes and `docs/agents.md` shows.
final class AgentsTests: XCTestCase {
    private let dir = "/Users/x/Library/Application Support/Cairn"
    private let binary = "/usr/local/cairn/bin/cairn"

    private var settings: NodeSettings {
        NodeSettings(dataFolder: URL(fileURLWithPath: dir, isDirectory: true), cpus: 4, memoryMB: 4096, storageGB: 0,
                     p2pHost: "127.0.0.1", bootstrapFiles: [], attachURL: nil)
    }

    private func inputs(_ arrangement: AgentArrangement, _ client: AgentClient, identity: String? = nil) -> AgentStanza.Inputs {
        AgentStanza.Inputs(binary: binary, dataDir: dir, settings: settings, arrangement: arrangement, client: client,
                           identity: identity)
    }

    func testTheAgentRunsTheNodeWithThisWindowsSettings() throws {
        let i = inputs(.runNode, .claudeCode)
        let args = AgentStanza.arguments(i)
        XCTAssertEqual(args, ["--data-dir", dir, "--root", dir, "run", "--listen", "127.0.0.1:9000", "--serve", "127.0.0.1:8080"])

        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(AgentStanza.render(i).utf8)) as? [String: Any])
        let server = try XCTUnwrap((json["mcpServers"] as? [String: Any])?["cairn"] as? [String: Any])
        XCTAssertEqual(server["command"] as? String, binary)
        XCTAssertEqual(server["args"] as? [String], args)
        XCTAssertEqual((server["env"] as? [String: String])?["CAIRN_REQUIRE_SANDBOX"], "1")
        XCTAssertEqual((server["env"] as? [String: String])?["CAIRN_SANDBOX_CPUS"], "4")
        XCTAssertEqual((server["env"] as? [String: String])?["CAIRN_SANDBOX_MEMORY_MB"], "4096")

        let add = AgentStanza.claudeAdd(i)
        XCTAssertTrue(add.hasPrefix("claude mcp add cairn --scope user --env CAIRN_REQUIRE_SANDBOX=1 --env CAIRN_SANDBOX_CPUS=4 --env CAIRN_SANDBOX_MEMORY_MB=4096 -- \(binary) --data-dir '\(dir)' --root '\(dir)' run"), add)
    }

    func testAnOfflineLogIsItsOwnAndSigned() {
        let identity = dir + "/agent.identity.json"
        let i = inputs(.ownLog, .codex, identity: identity)
        XCTAssertEqual(AgentStanza.arguments(i), ["--log", dir + "/agents/codex.jsonl", "--root", dir, "mcp", "--identity", identity])
        let toml = AgentStanza.render(i)
        XCTAssertTrue(toml.hasPrefix("[mcp_servers.cairn]\ncommand = \"\(binary)\"\nargs = [\"--log\", \"\(dir)/agents/codex.jsonl\", "), toml)
        XCTAssertTrue(toml.contains("\n[mcp_servers.cairn.env]\nCAIRN_REQUIRE_SANDBOX = \"1\"\nCAIRN_SANDBOX_CPUS = \"4\"\nCAIRN_SANDBOX_MEMORY_MB = \"4096\"\n"), toml)
        XCTAssertEqual(AgentStanza.arguments(inputs(.runNode, .claudeCode, identity: identity)).suffix(2), ["--mcp-identity", identity])
    }

    func testOpenCodeTakesOneCommandList() throws {
        let i = inputs(.runNode, .opencode)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(AgentStanza.render(i).utf8)) as? [String: Any])
        let server = try XCTUnwrap((json["mcp"] as? [String: Any])?["cairn"] as? [String: Any])
        XCTAssertEqual(server["type"] as? String, "local")
        XCTAssertEqual(server["command"] as? [String], [binary] + AgentStanza.arguments(i))
        XCTAssertEqual(server["enabled"] as? Bool, true)
        XCTAssertEqual((server["environment"] as? [String: String])?["CAIRN_SANDBOX_CPUS"], "4")
    }

    func testTheSharedNodeIsAURLForEveryClient() throws {
        let url = "http://127.0.0.1:8001/mcp"
        let claude = inputs(.shared, .claudeCode)
        XCTAssertEqual(AgentStanza.arguments(claude), [], "nothing to launch: the app's node already serves")
        XCTAssertEqual(AgentStanza.environment(claude), [:])
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(AgentStanza.render(claude).utf8)) as? [String: Any])
        let server = try XCTUnwrap((json["mcpServers"] as? [String: Any])?["cairn"] as? [String: Any])
        XCTAssertEqual(NSDictionary(dictionary: server), NSDictionary(dictionary: ["type": "http", "url": url]))
        XCTAssertEqual(AgentStanza.claudeAdd(claude), "claude mcp add --transport http --scope user cairn \(url)")

        let open = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(AgentStanza.render(inputs(.shared, .opencode)).utf8)) as? [String: Any])
        let remote = try XCTUnwrap((open["mcp"] as? [String: Any])?["cairn"] as? [String: Any])
        XCTAssertEqual(NSDictionary(dictionary: remote), NSDictionary(dictionary: ["type": "remote", "url": url, "enabled": true]))

        let codex = inputs(.shared, .codex)
        XCTAssertEqual(AgentStanza.render(codex), "[mcp_servers.cairn]\nurl = \"\(url)\"\n")
        XCTAssertEqual(AgentStanza.codexAdd(codex), "codex mcp add cairn --url \(url)")

        var moved = codex
        moved.agentsURL = NodeSettings.agentsURL(port: 50123)
        XCTAssertEqual(AgentStanza.render(moved), "[mcp_servers.cairn]\nurl = \"http://127.0.0.1:50123/mcp\"\n",
                       "the live port when 8001 was taken")
    }

    func testConductorIsClaudeCodeAndCodexUserConfigs() throws {
        XCTAssertEqual(AgentClient.conductor.targets, [.claudeCode, .codex])
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("home-\(UUID())", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: home) }
        XCTAssertEqual(AgentClient.conductor.configURLs(home: home).map(\.lastPathComponent), [".claude.json", "config.toml"])

        // Claude Code's file already holds other settings and another server.
        let claudeFile = home.appendingPathComponent(".claude.json")
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        try Data(#"{"numStartups": 3, "mcpServers": {"other": {"command": "x"}}}"#.utf8).write(to: claudeFile)

        let i = inputs(.shared, .conductor)
        let first = AgentStanza.install(i, home: home)
        XCTAssertEqual(first.map(\.url.lastPathComponent), [".claude.json", "config.toml"])
        guard case .success(.installed(_, let backup)) = first[0].outcome else { return XCTFail("\(first[0].outcome)") }
        XCTAssertNotNil(backup, "an existing file is copied before it is rewritten")
        guard case .success(.installed(_, nil)) = first[1].outcome else { return XCTFail("\(first[1].outcome)") }

        let claude = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: claudeFile)) as? [String: Any])
        XCTAssertEqual(claude["numStartups"] as? Int, 3)
        let servers = try XCTUnwrap(claude["mcpServers"] as? [String: Any])
        XCTAssertNotNil(servers["other"], "other servers survive")
        XCTAssertEqual((servers["cairn"] as? [String: Any])?["url"] as? String, "http://127.0.0.1:8001/mcp")
        let toml = try String(contentsOf: home.appendingPathComponent(".codex/config.toml"), encoding: .utf8)
        XCTAssertTrue(toml.contains("[mcp_servers.cairn]\nurl = \"http://127.0.0.1:8001/mcp\"\n"), toml)

        // Again: both already say this.
        for (url, outcome) in AgentStanza.install(i, home: home) {
            guard case .success(.alreadyConfigured) = outcome else { return XCTFail("\(url.path): \(outcome)") }
        }
    }

    func testAnEntryThatStartsItsOwnNodeIsNotOverwritten() throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("home-\(UUID())", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: home) }
        // Last month's stanza: each Conductor workspace would start `cairn run`.
        let stdio = inputs(.runNode, .claudeCode)
        guard case .success(.installed) = AgentStanza.install(stdio, home: home)[0].outcome else { return XCTFail() }
        let file = home.appendingPathComponent(".claude.json")
        let before = try Data(contentsOf: file)
        guard case .success(.conflicting) = AgentStanza.install(inputs(.shared, .claudeCode), home: home)[0].outcome
        else { return XCTFail("a different cairn entry is reported, not replaced") }
        XCTAssertEqual(try Data(contentsOf: file), before)

        guard case .success(.installed) = AgentStanza.install(inputs(.runNode, .codex), home: home)[0].outcome else { return XCTFail() }
        guard case .success(.conflicting) = AgentStanza.install(inputs(.shared, .codex), home: home)[0].outcome
        else { return XCTFail("the same for config.toml") }

        // An entry a client wrote itself, with fields of its own, is the same entry.
        XCTAssertTrue(AgentStanza.matches(["type": "http", "url": "u", "headers": [String: String]()], ["type": "http", "url": "u"]))
        XCTAssertFalse(AgentStanza.matches(["type": "http", "url": "v"], ["type": "http", "url": "u"]))
        XCTAssertFalse(AgentStanza.matches(["command": "/x"], ["type": "http", "url": "u"]))
    }

    func testTheNodeServesAgentsOnlyWhenAsked() {
        var s = settings
        let identity = URL(fileURLWithPath: dir + "/agent.identity.json")
        XCTAssertEqual(s.agentArguments(port: 8001, signedBy: identity), [], "off unless asked: the port acts as this node")
        s.serveAgents = true
        XCTAssertEqual(s.agentArguments(port: 8001, signedBy: nil), ["--mcp-http", "127.0.0.1:8001"])
        XCTAssertEqual(s.agentArguments(port: 8001, signedBy: identity),
                       ["--mcp-http", "127.0.0.1:8001", "--mcp-identity", identity.path])
        s.leadFleet = true
        XCTAssertEqual(s.agentArguments(port: 8001, signedBy: identity), ["--mcp-http", "127.0.0.1:8001"],
                       "a leader's one --mcp-identity is its fleet's, passed by fleetArguments")
        XCTAssertEqual(NodeSettings.agentsURL(port: 8001).absoluteString, "http://127.0.0.1:8001/mcp")
    }

    func testShellAndTomlQuoting() {
        XCTAssertEqual(AgentStanza.shellQuote("--data-dir"), "--data-dir")
        XCTAssertEqual(AgentStanza.shellQuote("CAIRN_SANDBOX_CPUS=4"), "CAIRN_SANDBOX_CPUS=4")
        XCTAssertEqual(AgentStanza.shellQuote(dir), "'\(dir)'")
        XCTAssertEqual(AgentStanza.shellQuote("it's"), "'it'\\''s'")
        XCTAssertEqual(AgentStanza.shellQuote(""), "''")
        XCTAssertEqual(AgentStanza.tomlString("a\"b\\c"), "\"a\\\"b\\\\c\"")
        XCTAssertEqual(AgentStanza.tomlString("a\nb\tc\u{1}"), "\"a\\nb\\tc\\u0001\"")
    }
}
