import Foundation
import XCTest
@testable import Cairn

/// The launchd agent Settings installs, held to the node the window would
/// have spawned: the same flags, the same environment, the documented ports --
/// and a fleet leader's extra flags when, and only when, it leads one.
final class BackgroundServiceTests: XCTestCase {
    private let binary = URL(fileURLWithPath: "/usr/local/cairn/bin/cairn")
    private let dir = "/Users/x/Library/Application Support/Cairn"

    private func settings(lead: Bool = false) -> NodeSettings {
        NodeSettings(dataFolder: URL(fileURLWithPath: dir, isDirectory: true), cpus: 4, memoryMB: 4096, storageGB: 0,
                     p2pHost: "0.0.0.0", bootstrapFiles: ["/Users/x/seed.json"], attachURL: nil,
                     leadFleet: lead, fleetNetworks: "10.0.0.0/8")
    }

    func testTheAgentRunsTheNodeWithoutMCPOnTheDocumentedPorts() throws {
        let plist = BackgroundService.definition(settings: settings(), binary: binary)
        XCTAssertEqual(plist["Label"] as? String, "org.cairn.node")
        let args = plist["ProgramArguments"] as? [String] ?? []
        XCTAssertEqual(args.first, binary.path)
        XCTAssertTrue(args.contains("run"))
        XCTAssertTrue(args.contains("--no-mcp"), "launchd's stdin is /dev/null; plain run would stop at once")
        XCTAssertTrue(args.contains("--listen") && args.contains("0.0.0.0:9000"))
        XCTAssertTrue(args.contains("--serve") && args.contains("127.0.0.1:8080"))
        XCTAssertTrue(args.contains("--bootstrap") && args.contains("/Users/x/seed.json"))
        XCTAssertFalse(args.contains("--mcp-identity"), "a node that leads no fleet signs for nobody")
        XCTAssertEqual(plist["RunAtLoad"] as? Bool, true)
        XCTAssertEqual(plist["KeepAlive"] as? Bool, true)
        XCTAssertEqual(plist["WorkingDirectory"] as? String, dir)
        XCTAssertEqual(plist["StandardErrorPath"] as? String, dir + "/node.log")

        let data = try BackgroundService.render(settings: settings(), binary: binary)
        let back = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any]
        XCTAssertEqual(back?["Label"] as? String, "org.cairn.node")
        XCTAssertEqual((back?["ProgramArguments"] as? [String])?.count, args.count)
    }

    func testTheEnvironmentIsThePathTheHomeAndEveryCairnVariable() {
        let env = BackgroundService.serviceEnvironment(settings(lead: true))
        XCTAssertNotNil(env["PATH"])
        XCTAssertNotNil(env["HOME"])
        XCTAssertEqual(env["CAIRN_SANDBOX_CPUS"], "4")
        XCTAssertEqual(env["CAIRN_SANDBOX_MEMORY_MB"], "4096")
        XCTAssertEqual(env["CAIRN_FLEET"], "10.0.0.0/8")
        for key in env.keys {
            XCTAssertTrue(key == "PATH" || key == "HOME" || key.hasPrefix("CAIRN_"),
                          "\(key) is this app's business, not the service's")
        }
    }

    func testLeadingAFleetServesEveryInterfaceAndSignsWithTheLeaderIdentity() {
        let leader = settings(lead: true)
        XCTAssertEqual(leader.serveHost, "0.0.0.0")
        XCTAssertEqual(leader.fleetArguments, ["--mcp-identity", dir + "/leader.identity.json"])
        XCTAssertEqual(leader.environment["CAIRN_FLEET"], "10.0.0.0/8")
        let args = BackgroundService.definition(settings: leader, binary: binary)["ProgramArguments"] as? [String] ?? []
        XCTAssertTrue(args.contains("0.0.0.0:8080"), "workers reach the leader over the network")
        XCTAssertTrue(args.contains("--mcp-identity"))

        let plain = settings()
        XCTAssertEqual(plain.serveHost, "127.0.0.1")
        XCTAssertEqual(plain.fleetArguments, [])
        XCTAssertNil(plain.environment["CAIRN_FLEET"])
    }

    func testTheReaderURLAndThePlistPathAreWhereTheDocsSayTheyAre() {
        XCTAssertEqual(BackgroundService.readerURL.absoluteString, "http://127.0.0.1:8080/ui/")
        XCTAssertTrue(BackgroundService.plistURL.path.hasSuffix("/Library/LaunchAgents/org.cairn.node.plist"))
        XCTAssertTrue(BackgroundService.domain.hasPrefix("gui/"))
    }
}
