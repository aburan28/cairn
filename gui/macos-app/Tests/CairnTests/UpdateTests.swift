import Foundation
import XCTest
@testable import Cairn

/// What the updater believes about a release, held to the shapes
/// `release.yml` and GitHub actually produce. The fixture is v1.8.1's
/// `releases/latest` answer, cut to the fields read and the assets that
/// matter.
final class UpdateTests: XCTestCase {
    // MARK: versions

    func testVersionsOrderAsSemverDoes() {
        // The precedence example from semver.org, then the case text gets wrong.
        let order = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta",
                     "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.9.0", "1.10.0", "2.0.0"]
        let parsed = order.map { SemVer($0)! }
        for i in parsed.indices {
            for j in parsed.indices {
                XCTAssertEqual(parsed[i] < parsed[j], i < j, "\(order[i]) < \(order[j])")
            }
        }
    }

    func testVersionSpellings() {
        XCTAssertEqual(SemVer("v1.8.1"), SemVer("1.8.1"))
        XCTAssertEqual(SemVer("1.8.1+build.7"), SemVer("1.8.1"))
        for bad in ["1.8", "1.8.x", "1.8.1-", "1.8.1-a..b", "nightly", "", "１.2.3"] {
            XCTAssertNil(SemVer(bad), bad)
        }
        XCTAssertTrue(SemVer("0.0.0")!.isPlaceholder)
        XCTAssertTrue(SemVer("0.0.0-dispatch.123")!.isPlaceholder)
        XCTAssertFalse(SemVer("0.1.0")!.isPlaceholder)
    }

    func testCliVersionComesFromTheFirstLineOfVersionOutput() {
        let out = "cairn 1.8.1\n  ui       embedded -- `cairn run` will start\n"
        XCTAssertEqual(AppVersion.cli(fromVersionOutput: out), "1.8.1")
        XCTAssertNil(AppVersion.cli(fromVersionOutput: "something 1.8.1"))
        XCTAssertNil(AppVersion.cli(fromVersionOutput: ""))
    }

    // MARK: the release

    func testTheInstallerIsFoundWithBothHashes() throws {
        let release = try XCTUnwrap(Release.parse(fixture(), repository: "aburan28/cairn"))
        XCTAssertEqual(release.tag, "v1.8.1")
        XCTAssertEqual(release.version, SemVer("1.8.1"))
        let installer = try XCTUnwrap(release.installer)
        XCTAssertEqual(installer.name, "cairn-v1.8.1-macos-universal.dmg")
        XCTAssertEqual(installer.digest, Self.digest)
        XCTAssertEqual(installer.size, 8_526_677)
        XCTAssertEqual(installer.image.absoluteString,
                       "https://github.com/aburan28/cairn/releases/download/v1.8.1/cairn-v1.8.1-macos-universal.dmg")
    }

    func testTheNotesStopAtTheInstallSection() throws {
        let release = try XCTUnwrap(Release.parse(fixture(), repository: "aburan28/cairn"))
        XCTAssertTrue(release.notes.contains("### Fixes"))
        XCTAssertFalse(release.notes.contains("Install"))
    }

    func testAnAssetAnywhereElseIsNotTheInstaller() throws {
        let elsewhere = fixture { assets in
            assets[0]["browser_download_url"] =
                "https://example.com/aburan28/cairn/releases/download/v1.8.1/cairn-v1.8.1-macos-universal.dmg"
        }
        XCTAssertNil(try Release.parse(elsewhere, repository: "aburan28/cairn")?.installer)
        // The same assets read for a fork name are not that fork's.
        XCTAssertNil(try Release.parse(fixture(), repository: "someone/cairn")?.installer)
    }

    func testAnImageWithoutItsChecksumIsStillUploading() throws {
        let noSum = fixture { assets in assets.remove(at: 1) }
        let release = try XCTUnwrap(Release.parse(noSum, repository: "aburan28/cairn"))
        XCTAssertNil(release.installer)
        let partial = fixture { assets in assets[0]["state"] = "new" }
        XCTAssertNil(try Release.parse(partial, repository: "aburan28/cairn")?.installer)
    }

    func testDraftsPreReleasesAndDryRunsAreNotOffered() throws {
        XCTAssertNil(try Release.parse(fixture(top: ["prerelease": true]), repository: "aburan28/cairn"))
        XCTAssertNil(try Release.parse(fixture(top: ["draft": true]), repository: "aburan28/cairn"))
        XCTAssertNil(try Release.parse(fixture(top: ["tag_name": "v0.0.0-dispatch.9"]), repository: "aburan28/cairn"))
        XCTAssertNil(try Release.parse(fixture(top: ["tag_name": "nightly"]), repository: "aburan28/cairn"))
    }

    func testTheChecksumFileIsReadForItsOwnName() {
        let name = "cairn-v1.8.1-macos-universal.dmg"
        // Byte for byte what `shasum -a 256` wrote for v1.8.1.
        let file = "\(Self.digest)  \(name)\n"
        XCTAssertEqual(Release.checksum(fromFile: file, for: name), Self.digest)
        XCTAssertNil(Release.checksum(fromFile: file, for: "cairn-v1.8.1-x86_64-apple-darwin.tar.gz"))
        XCTAssertNil(Release.checksum(fromFile: "zz  \(name)\n", for: name))
        XCTAssertEqual(Release.checksum(fromFile: Self.digest.uppercased() + " *" + name, for: name), Self.digest)
        XCTAssertNil(Release.sha256(fromDigest: "sha1:" + Self.digest))
    }

    // MARK: what root runs

    /// A Swift escape gone wrong in the embedded script is a syntax error
    /// that would surface as "the installer could not be started", on
    /// somebody else's Mac, at the worst moment.
    func testTheRootScriptsParse() throws {
        XCTAssertTrue(InstallScript.stage1.contains("\nFINISH\n"), "the heredoc's terminator must start its line")
        for script in [InstallScript.stage1, InstallScript.finish] {
            let (status, err) = try run("/bin/sh", ["-n"], stdin: script)
            XCTAssertEqual(status, 0, err)
        }
    }

    func testTheAppleScriptCompiles() throws {
        let out = FileManager.default.temporaryDirectory.appendingPathComponent("cairn-update-\(UUID()).scpt")
        defer { try? FileManager.default.removeItem(at: out) }
        let (status, err) = try run(
            "/usr/bin/osacompile",
            ["-o", out.path] + InstallScript.osascript.flatMap { ["-e", $0] }
        )
        XCTAssertEqual(status, 0, err)
    }

    // MARK: helpers

    private static let digest = "8a6ecd885691d9d3275f9fd4269bbe4d812b89be05d82de037e9ed0ac7596bc3"

    private func fixture(
        top: [String: Any] = [:],
        assets edit: (inout [[String: Any]]) -> Void = { _ in }
    ) -> Data {
        let base = "https://github.com/aburan28/cairn/releases/download/v1.8.1/"
        var assets: [[String: Any]] = [
            ["name": "cairn-v1.8.1-macos-universal.dmg", "state": "uploaded", "size": 8_526_677,
             "digest": "sha256:\(Self.digest)",
             "browser_download_url": base + "cairn-v1.8.1-macos-universal.dmg"],
            ["name": "cairn-v1.8.1-macos-universal.dmg.sha256", "state": "uploaded", "size": 99,
             "browser_download_url": base + "cairn-v1.8.1-macos-universal.dmg.sha256"],
            ["name": "install.sh", "state": "uploaded", "size": 8584,
             "browser_download_url": base + "install.sh"],
        ]
        edit(&assets)
        var json: [String: Any] = [
            "tag_name": "v1.8.1",
            "html_url": "https://github.com/aburan28/cairn/releases/tag/v1.8.1",
            "draft": false,
            "prerelease": false,
            "body": """
                ## [1.8.1](https://github.com/aburan28/cairn/compare/v1.8.0...v1.8.1) (2026-10-02)


                ### Fixes

                * **sandbox:** run symlinked interpreters under bwrap

                <!-- cairn:install-notes -- everything from here down is rewritten by packaging/release-notes.sh each time this tag is built -->

                ## Install
                """,
            "assets": assets,
        ]
        json.merge(top) { _, new in new }
        return try! JSONSerialization.data(withJSONObject: json)
    }

    private func run(_ tool: String, _ args: [String], stdin: String? = nil) throws -> (Int32, String) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: tool)
        p.arguments = args
        let input = Pipe(), err = Pipe()
        p.standardInput = input
        p.standardOutput = FileHandle.nullDevice
        p.standardError = err
        try p.run()
        if let stdin { input.fileHandleForWriting.write(Data(stdin.utf8)) }
        try input.fileHandleForWriting.close()
        let text = String(decoding: err.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        p.waitUntilExit()
        return (p.terminationStatus, text)
    }
}
