import Foundation
import XCTest
@testable import Cairn

/// The execution environment, found where the node will look, and handed to
/// the node the way its jail needs it.
final class ToolchainTests: XCTestCase {
    private func scratch() throws -> URL {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("cairn-test-\(UUID())", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    private func executable(_ url: URL, printing text: String) throws {
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data("#!/bin/sh\necho \"\(text)\"\n".utf8).write(to: url)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path)
    }

    func testLocateFindsAnExecutableOnThePathGiven() throws {
        let dir = try scratch()
        defer { try? FileManager.default.removeItem(at: dir) }
        let tool = dir.appendingPathComponent("lean")
        try executable(tool, printing: "Lean (version 4.99.0)")
        XCTAssertEqual(Toolchains.locate("lean", in: ["/nonexistent", dir.path]), tool)
        XCTAssertNil(Toolchains.locate("lean", in: ["/nonexistent"]))
        XCTAssertEqual(Toolchains.version(of: tool, ["PATH": "/usr/bin:/bin"]), "Lean (version 4.99.0)")
        XCTAssertEqual(Toolchains.searchPath(["PATH": "/a::/b"]), ["/a", "/b"])
    }

    func testElanToolchainIsResolvedFromItsSettingsNotByRunningTheProxy() throws {
        let home = try scratch().appendingPathComponent(".elan", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: home.deletingLastPathComponent()) }
        let stable = home.appendingPathComponent("toolchains/leanprover--lean4---stable", isDirectory: true)
        let dated = home.appendingPathComponent("toolchains/leanprover--lean4---v4.22.0", isDirectory: true)
        try executable(stable.appendingPathComponent("bin/lean"), printing: "stable")
        try executable(dated.appendingPathComponent("bin/lean"), printing: "dated")

        XCTAssertEqual(Toolchains.defaultToolchain(in: "version = \"1.0.0\"\ndefault_toolchain = \"leanprover/lean4:stable\"\n"),
                       "leanprover/lean4:stable")
        XCTAssertNil(Toolchains.defaultToolchain(in: "version = \"1.0.0\"\n"))
        XCTAssertEqual(Toolchains.elanDirectoryName("leanprover/lean4:stable"), "leanprover--lean4---stable")

        try Data("default_toolchain = \"leanprover/lean4:stable\"\n".utf8).write(to: home.appendingPathComponent("settings.toml"))
        XCTAssertEqual(Toolchains.elanToolchainPrefix(home)?.standardizedFileURL.path, stable.standardizedFileURL.path)

        // Without a default, whichever toolchain is there, newest name first.
        try FileManager.default.removeItem(at: home.appendingPathComponent("settings.toml"))
        XCTAssertEqual(Toolchains.elanToolchainPrefix(home)?.standardizedFileURL.path, dated.standardizedFileURL.path)

        // A default that names a toolchain not downloaded yet falls back too.
        try Data("default_toolchain = \"leanprover/lean4:nightly\"\n".utf8).write(to: home.appendingPathComponent("settings.toml"))
        XCTAssertEqual(Toolchains.elanToolchainPrefix(home)?.standardizedFileURL.path, dated.standardizedFileURL.path)

        XCTAssertNil(Toolchains.elanToolchainPrefix(home.appendingPathComponent("nowhere")))
    }

    func testTheNodeIsHandedTheRealBinaryAndItsPrefix() {
        let prefix = URL(fileURLWithPath: "/Users/x/.elan/toolchains/leanprover--lean4---stable", isDirectory: true)
        let lean = LeanToolchain(found: URL(fileURLWithPath: "/Users/x/.elan/bin/lean"), prefix: prefix, version: nil)
        XCTAssertEqual(Toolchains.leanEnvironment(lean),
                       ["CAIRN_LEAN": prefix.path + "/bin/lean", "CAIRN_LEAN_ROOT": prefix.path])
        XCTAssertTrue(lean.isElan)
        XCTAssertEqual(Toolchains.leanEnvironment(nil), [:])
        XCTAssertTrue(Toolchains.isShim(URL(fileURLWithPath: "/Users/x/.pyenv/shims/python3")))
        XCTAssertFalse(Toolchains.isShim(URL(fileURLWithPath: "/opt/homebrew/bin/python3")))
    }

    func testTheNodesPathReachesElanHomebrewAndTheSystem() {
        let settings = NodeSettings.current()
        let env = Node.childEnvironment(settings)
        let path = Toolchains.searchPath(env)
        XCTAssertEqual(path.first, NSHomeDirectory() + "/.elan/bin")
        XCTAssertTrue(path.contains("/opt/homebrew/bin"))
        XCTAssertTrue(path.contains("/usr/bin"))
        // Both or neither: a binary without its granted root is one the jail may refuse.
        XCTAssertEqual(env["CAIRN_LEAN"] == nil, env["CAIRN_LEAN_ROOT"] == nil)
        XCTAssertEqual(env["TMPDIR"], settings.dataFolder.appendingPathComponent("tmp").path)
    }

    func testTheNodesVerifierReportIsRead() throws {
        let json = """
        {"kinds":["certificate","lean"],
         "toolchains":{"lean":{"binary":"lean","path":null,"available":false,"version":null,"granted_root":null,"serves":["lean"]},
                       "python3":{"binary":"python3","path":"/usr/bin/python3","available":true,"version":"Python 3.12.1","serves":["certificate"]}},
         "sandbox":{"mechanism":"sandbox-exec","jail":true,"required":false,"path":"/usr/bin/sandbox-exec"},
         "servable":["certificate"],
         "unservable":{"lean":"'lean' not on PATH; install a Lean toolchain to verify"},
         "note":"x","generated_at":"t"}
        """
        let report = try JSONDecoder().decode(NodeVerifiers.self, from: Data(json.utf8))
        XCTAssertFalse(report.servesLean)
        XCTAssertEqual(report.lean?.available, false)
        XCTAssertEqual(report.python?.version, "Python 3.12.1")
        XCTAssertEqual(report.sandbox.mechanism, "sandbox-exec")
        XCTAssertTrue(report.unservable["lean"]?.contains("Lean toolchain") ?? false)
    }
}
