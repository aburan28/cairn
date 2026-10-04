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
        XCTAssertEqual((server["env"] as? [String: String])?["CAIRN_SANDBOX_CPUS"], "4")
        XCTAssertEqual((server["env"] as? [String: String])?["CAIRN_SANDBOX_MEMORY_MB"], "4096")

        let add = AgentStanza.claudeAdd(i)
        XCTAssertTrue(add.hasPrefix("claude mcp add cairn --scope user --env CAIRN_SANDBOX_CPUS=4 --env CAIRN_SANDBOX_MEMORY_MB=4096 -- \(binary) --data-dir '\(dir)' --root '\(dir)' run"), add)
    }

    func testAnOfflineLogIsItsOwnAndSigned() {
        let identity = dir + "/agent.identity.json"
        let i = inputs(.ownLog, .codex, identity: identity)
        XCTAssertEqual(AgentStanza.arguments(i), ["--log", dir + "/agents/codex.jsonl", "--root", dir, "mcp", "--identity", identity])
        let toml = AgentStanza.render(i)
        XCTAssertTrue(toml.hasPrefix("[mcp_servers.cairn]\ncommand = \"\(binary)\"\nargs = [\"--log\", \"\(dir)/agents/codex.jsonl\", "), toml)
        XCTAssertTrue(toml.contains("\n[mcp_servers.cairn.env]\nCAIRN_SANDBOX_CPUS = \"4\"\nCAIRN_SANDBOX_MEMORY_MB = \"4096\"\n"), toml)
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

    func testShellAndTomlQuoting() {
        XCTAssertEqual(AgentStanza.shellQuote("--data-dir"), "--data-dir")
        XCTAssertEqual(AgentStanza.shellQuote("CAIRN_SANDBOX_CPUS=4"), "CAIRN_SANDBOX_CPUS=4")
        XCTAssertEqual(AgentStanza.shellQuote(dir), "'\(dir)'")
        XCTAssertEqual(AgentStanza.shellQuote("it's"), "'it'\\''s'")
        XCTAssertEqual(AgentStanza.shellQuote(""), "''")
        XCTAssertEqual(AgentStanza.tomlString("a\"b\\c"), "\"a\\\"b\\\\c\"")
    }
}
