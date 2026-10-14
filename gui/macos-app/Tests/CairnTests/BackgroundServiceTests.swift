import Foundation
import XCTest
@testable import Cairn

/// The launchd agent Settings installs, held to the node the window would
/// have spawned: the same flags, the same environment, the documented ports --
/// and a fleet leader's extra flags when, and only when, it leads one.
final class BackgroundServiceTests: XCTestCase {
    private let binary = URL(fileURLWithPath: "/usr/local/cairn/bin/cairn")
    private let dir = "/Users/x/Library/Application Support/Cairn"

    private func settings(lead: Bool = false, join: NodeSettings.FleetJoin = .network) -> NodeSettings {
        NodeSettings(dataFolder: URL(fileURLWithPath: dir, isDirectory: true), cpus: 4, memoryMB: 4096, storageGB: 0,
                     p2pHost: "0.0.0.0", bootstrapFiles: ["/Users/x/seed.json"], attachURL: nil,
                     leadFleet: lead, fleetNetworks: "10.0.0.0/8", fleetJoin: join)
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
        XCTAssertEqual(env["TMPDIR"], dir + "/tmp")
        XCTAssertEqual(env["CAIRN_SANDBOX_CPUS"], "4")
        XCTAssertEqual(env["CAIRN_SANDBOX_MEMORY_MB"], "4096")
        XCTAssertEqual(env["CAIRN_FLEET"], "10.0.0.0/8")
        for key in env.keys {
            XCTAssertTrue(key == "PATH" || key == "HOME" || key == "TMPDIR" || key.hasPrefix("CAIRN_"),
                          "\(key) is this app's business, not the service's")
        }
    }

    func testVerifierScratchExistsAndIsPrivateBeforeTheNodeStarts() throws {
        let folder = FileManager.default.temporaryDirectory
            .appendingPathComponent("cairn-scratch-test-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: folder) }
        let local = NodeSettings(dataFolder: folder, cpus: 1, memoryMB: 1024, storageGB: 0,
                                 p2pHost: "127.0.0.1", bootstrapFiles: [], attachURL: nil)
        try Node.prepareScratch(local)
        let scratch = folder.appendingPathComponent("tmp", isDirectory: true)
        // Opening the app again must reuse its scratch directory; a past
        // launch may also have left permissions broader than the policy.
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: scratch.path)
        try Node.prepareScratch(local)
        XCTAssertEqual(Node.childEnvironment(local)["TMPDIR"], scratch.path)
        let attributes = try FileManager.default.attributesOfItem(atPath: scratch.path)
        XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o700)
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

    func testAnInvitedFleetSignsForEnrolledMembersOnly() {
        let invited = settings(lead: true, join: .invited)
        XCTAssertEqual(invited.environment["CAIRN_FLEET"], "enrolled", "the networks are not a credential")
        XCTAssertEqual(BackgroundService.serviceEnvironment(invited)["CAIRN_FLEET"], "enrolled")
        XCTAssertEqual(invited.serveHost, "0.0.0.0", "members still reach the leader over the network")
    }

    func testANewFleetStartsWithInvitationsAndAnOldOneKeepsItsNetworks() throws {
        let fresh = try XCTUnwrap(UserDefaults(suiteName: "cairn-fleet-new-\(UUID().uuidString)"))
        XCTAssertEqual(NodeSettings.current(fresh).fleetJoin, .invited)
        fresh.set(true, forKey: NodeSettings.Key.leadFleet)
        XCTAssertEqual(NodeSettings.current(fresh).fleetJoin, .invited, "decided once, before the fleet was led")

        let upgraded = try XCTUnwrap(UserDefaults(suiteName: "cairn-fleet-old-\(UUID().uuidString)"))
        upgraded.set(true, forKey: NodeSettings.Key.leadFleet)
        upgraded.set("192.168.1.0/24", forKey: NodeSettings.Key.fleetNetworks)
        let kept = NodeSettings.current(upgraded)
        XCTAssertEqual(kept.fleetJoin, .network, "a fleet led before invitations keeps what its operator chose")
        XCTAssertEqual(kept.environment["CAIRN_FLEET"], "192.168.1.0/24")
    }

    func testTheReaderURLAndThePlistPathAreWhereTheDocsSayTheyAre() {
        XCTAssertEqual(BackgroundService.readerURL.absoluteString, "http://127.0.0.1:8080/ui/")
        XCTAssertTrue(BackgroundService.plistURL.path.hasSuffix("/Library/LaunchAgents/org.cairn.node.plist"))
        XCTAssertTrue(BackgroundService.domain.hasPrefix("gui/"))
    }
}
