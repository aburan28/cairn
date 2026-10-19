import Foundation
import XCTest
@testable import Cairn

final class CoordinationTests: XCTestCase {
    static var reply: [String: Any] { [
        "clarification": "", "goal": "GOAL-squares/exhaustive", "statement": "Compute each square for integers 0 through 15.",
        "unit": "One integer and its exact square.", "units": "16", "unit_price": "10", "reward": "160",
        "unit_key": "unit", "artifact_schema_json": #"{"type":"object","properties":{"unit":{"type":"integer"},"square":{"type":"integer"}},"required":["unit","square"]}"#,
        "good_artifact_json": #"{"unit":3,"square":9}"#, "bad_artifact_json": #"{"unit":3,"square":10}"#,
        "notes": "", "checker_source": """
            def check(a):
                if not isinstance(a, dict) or type(a.get('unit')) is not int or type(a.get('square')) is not int:
                    return False, 'integer fields required'
                n = a['unit']
                return (0 <= n < 16 and a['square'] == n*n), 'recomputed square'
            """,
    ] }

    func root() throws -> URL {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("cairn-coordination-test-\(UUID())")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: root) }
        return root
    }

    func testBudgetPreservesUInt64AndRejectsInvalidValues() throws {
        XCTAssertEqual(try CoordinationWriter.budget(" 18,446,744,073,709,551,615 "), UInt64.max)
        XCTAssertEqual(try CoordinationWriter.budget("9_007_199_254_740_993"), 9_007_199_254_740_993)
        XCTAssertNil(try CoordinationWriter.budget("  "))
        for value in ["0", "-1", "1.5", "1e3", "18446744073709551616", ",", "１２"] {
            XCTAssertThrowsError(try CoordinationWriter.budget(value), value)
        }
        XCTAssertThrowsError(try CoordinationWriter.parse(Self.reply, budget: 100))
    }

    func testMissingInputsAreReturnedWithoutSubstitutingAChallenge() throws {
        XCTAssertThrowsError(try CoordinationWriter.parse(["clarification": "Which exact challenge and target point?"], budget: nil)) {
            guard case CoordinationFailure.needsInput = $0 else { return XCTFail("expected a request for missing inputs") }
        }
    }

    func testMalformedDraftsCannotBecomeLaunchableSpecs() {
        for change: [String: Any] in [
            ["unit_price": "161"], ["units": "0"], ["goal": "../../elsewhere"],
            ["good_artifact_json": #"{"square":9}"#], ["bad_artifact_json": #"{"unit":3,"square":9}"#],
            ["good_artifact_json": #"{"unit":3,"square":9.5}"#], ["artifact_schema_json": #"{"type":"array"}"#],
        ] {
            XCTAssertThrowsError(try CoordinationWriter.parse(Self.reply.merging(change) { _, new in new }, budget: nil))
        }
    }

    func testJSONModeProvidersMayReturnStructuredObjects() throws {
        let expected = try CoordinationWriter.parse(Self.reply, budget: 160)
        var response = Self.reply
        for field in ["artifact_schema_json", "good_artifact_json", "bad_artifact_json"] {
            response[field] = try JSONSerialization.jsonObject(with: Data((response[field] as! String).utf8))
        }
        let actual = try CoordinationWriter.parse(response, budget: 160)
        XCTAssertTrue(NSDictionary(dictionary: actual.artifactSchema).isEqual(to: expected.artifactSchema))
        XCTAssertTrue(NSDictionary(dictionary: actual.good).isEqual(to: expected.good))
        XCTAssertTrue(NSDictionary(dictionary: actual.bad).isEqual(to: expected.bad))
        XCTAssertEqual(actual.reward, expected.reward)
        // A mixed response is common after a provider repairs just one field.
        response["bad_artifact_json"] = Self.reply["bad_artifact_json"]
        XCTAssertNoThrow(try CoordinationWriter.parse(response, budget: 160))
    }

    func testStructuredObjectsKeepTheSameValidationGates() {
        for value: Any in [
            ["unit": 3, "square": 9.5], ["square": 9],
            ["unit": 3, "square": 9, "padding": String(repeating: "x", count: 256_000)],
            ["unit": 3, "square": Double.infinity], [3, 9], NSNull(),
        ] {
            let reply = Self.reply.merging(["good_artifact_json": value]) { _, new in new }
            XCTAssertThrowsError(try CoordinationWriter.parse(reply, budget: 160))
        }
        XCTAssertThrowsError(try CoordinationWriter.parse(Self.reply.merging(["reward": 160]) { _, new in new }, budget: 160))
    }

    func testBuilderPinsCheckerAndPreservesCheckedSpec() throws {
        let draft = try CoordinationWriter.parse(Self.reply, budget: 160)
        let built = try CoordinationBuilder.build(draft, root: root())
        let spec = try XCTUnwrap(JSONSerialization.jsonObject(with: built.objectiveBytes) as? [String: Any])
        let verifier = try XCTUnwrap(spec["verifier"] as? [String: Any])
        XCTAssertEqual(verifier["kind"] as? String, "certificate")
        XCTAssertEqual(verifier["checker_sha256"] as? String, GuiTasks.sha256(Data(draft.checker.utf8)))
        XCTAssertEqual((spec["piecework"] as? [String: Any])?["unit_price"] as? Int, 10)
        XCTAssertNil(spec["ratchet"])
        XCTAssertNoThrow(try built.requireUnchanged())
        try Data("changed".utf8).write(to: built.checkerFile)
        XCTAssertThrowsError(try built.requireUnchanged())
    }

    func testBridgeAcceptsOnlyDescriptionsAmountsAndOpaqueDraftIDs() throws {
        XCTAssertEqual(try PageRequest.parse(["kind": "draft-coordination", "brief": "  compute integer squares  ", "budget": "1,000"]).get(),
                       .draftCoordination(brief: "compute integer squares", budget: "1000"))
        XCTAssertThrowsError(try PageRequest.parse(["kind": "draft-coordination", "brief": "compute integer squares", "budget": 1000]).get())
        XCTAssertThrowsError(try PageRequest.parse(["kind": "launch-coordination", "draftId": "/tmp/objective.json"]).get())
        XCTAssertEqual(try PageRequest.parse(["kind": "coordination-status"]).get(), .coordinationStatus)
    }

    @MainActor
    func testBackgroundOwnershipDoesNotAuthorizeAnUnrelatedRemoteNode() {
        XCTAssertTrue(CoordinationComposer.ownsNode(attachURL: nil, background: false))
        XCTAssertTrue(CoordinationComposer.ownsNode(attachURL: BackgroundService.readerURL, background: true))
        XCTAssertFalse(CoordinationComposer.ownsNode(attachURL: BackgroundService.readerURL, background: false))
        XCTAssertFalse(CoordinationComposer.ownsNode(attachURL: URL(string: "http://remote:8080/ui/"), background: true))
        XCTAssertFalse(CoordinationComposer.ownsNode(attachURL: URL(string: "http://127.0.0.1:9090/ui/"), background: true))
    }

    @MainActor
    func context(_ root: URL) -> CoordinationComposer.Context {
        .init(root: root, binary: URL(fileURLWithPath: "/unused"), environment: [:],
              config: AIConfig(provider: .custom, model: "test", baseURL: "http://127.0.0.1:1/v1"),
              key: "test-key-not-returned-to-page", catalog: "")
    }

    @MainActor
    func waitFor(_ composer: CoordinationComposer, _ phase: String) async throws {
        for _ in 0..<2000 {
            if composer.phase == phase { return }
            try await Task.sleep(nanoseconds: 1_000_000)
        }
        XCTFail("Expected \(phase); got \(composer.snapshot())")
    }

    @MainActor
    func testProviderToCheckedSpecToLaunchAndDuplicateClicks() async throws {
        let context = context(try root())
        var calls = 0
        var checks = 0
        var posts = 0
        let id = "sha256:" + String(repeating: "a", count: 64)
        let composer = CoordinationComposer(services: .init(
            prepare: { _ in context },
            complete: { _, request in
                calls += 1
                XCTAssertTrue(request.contains("compute integer squares"))
                return Self.reply
            },
            check: { _, _, _ in checks += 1; return id },
            post: { built in posts += 1; try built.requireUnchanged() },
            confirm: { _ in true }
        ))
        XCTAssertEqual(try composer.generate(brief: "compute integer squares", budget: "160")["phase"] as? String, "drafting")
        XCTAssertThrowsError(try composer.generate(brief: "compute another problem", budget: "160"))
        try await waitFor(composer, "ready")
        let receipt = composer.snapshot()
        XCTAssertEqual(calls, 1)
        XCTAssertEqual(checks, 1)
        XCTAssertEqual(posts, 0)
        XCTAssertFalse(String(describing: receipt).contains(context.key))
        XCTAssertEqual(receipt["objectiveId"] as? String, id)
        XCTAssertThrowsError(try composer.launch(UUID().uuidString))
        let token = try XCTUnwrap(receipt["draftId"] as? String)
        _ = try composer.launch(token)
        _ = try composer.launch(token)
        try await waitFor(composer, "posted")
        _ = try composer.launch(token)
        XCTAssertEqual(posts, 1)
    }

    @MainActor
    func testFailedCheckIsRepairedAutomaticallyButUnavailableIsNot() async throws {
        let context = context(try root())
        var calls = 0
        var checks = 0
        let composer = CoordinationComposer(services: .init(
            prepare: { _ in context },
            complete: { _, request in
                calls += 1
                if calls == 2 { XCTAssertTrue(request.contains("bad example accepted")) }
                return Self.reply
            },
            check: { _, _, _ in
                checks += 1
                if checks == 1 { throw AIError("bad example accepted") }
                return "sha256:" + String(repeating: "b", count: 64)
            },
            post: { _ in XCTFail("must not publish while generating") }, confirm: { _ in false }
        ))
        _ = try composer.generate(brief: "compute integer squares", budget: "160")
        try await waitFor(composer, "ready")
        XCTAssertEqual(calls, 2)
        let token = try XCTUnwrap(composer.snapshot()["draftId"] as? String)
        XCTAssertThrowsError(try composer.launch(token))
        XCTAssertEqual(composer.phase, "ready")

        calls = 0
        let unavailable = CoordinationComposer(services: .init(
            prepare: { _ in context }, complete: { _, _ in calls += 1; return Self.reply },
            check: { _, _, _ in throw CoordinationFailure.unavailable("sandbox unavailable") },
            post: { _ in XCTFail("must not publish an unchecked spec") }, confirm: { _ in true }
        ))
        _ = try unavailable.generate(brief: "compute integer squares", budget: "160")
        try await waitFor(unavailable, "error")
        XCTAssertEqual(calls, 1)
        XCTAssertNil(unavailable.snapshot()["draftId"])
    }

    @MainActor
    func testCancellationDiscardsProviderResultAndPostingFailureRemainsRetryable() async throws {
        let context = context(try root())
        let composer = CoordinationComposer(services: .init(
            prepare: { _ in context }, complete: { _, _ in
                try await Task.sleep(nanoseconds: 100_000_000)
                return Self.reply
            },
            check: { _, _, _ in XCTFail("cancelled draft must not be checked"); return "" },
            post: { _ in XCTFail("cancelled draft must not be posted") }, confirm: { _ in true }
        ))
        _ = try composer.generate(brief: "compute integer squares", budget: "160")
        _ = try composer.cancel()
        try await Task.sleep(nanoseconds: 150_000_000)
        XCTAssertEqual(composer.phase, "idle")
        XCTAssertNil(composer.snapshot()["spec"])

        let failed = CoordinationComposer(services: .init(
            prepare: { _ in context }, complete: { _, _ in Self.reply },
            check: { _, _, _ in "sha256:" + String(repeating: "c", count: 64) },
            post: { _ in throw AIError("funding refused") }, confirm: { _ in true }
        ))
        _ = try failed.generate(brief: "compute integer squares", budget: "160")
        try await waitFor(failed, "ready")
        _ = try failed.launch(XCTUnwrap(failed.snapshot()["draftId"] as? String))
        try await waitFor(failed, "ready")
        XCTAssertEqual(failed.snapshot()["message"] as? String, "funding refused")
    }

    func testActualNodeChecksPinnedCheckerInDisposableLog() async throws {
        guard let binary = ProcessInfo.processInfo.environment["CAIRN_DRAFT_TEST_BINARY"] else {
            throw XCTSkip("Set CAIRN_DRAFT_TEST_BINARY for the real sandboxed verifier integration")
        }
        let draft = try CoordinationWriter.parse(Self.reply, budget: 160)
        let built = try CoordinationBuilder.build(draft, root: root())
        var environment = ProcessInfo.processInfo.environment
        environment["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin"
        environment["CAIRN_PYTHON"] = "/usr/bin/python3"
        // The generator must require a jail even if the parent opted out.
        environment["CAIRN_REQUIRE_SANDBOX"] = "0"
        let id = try await CoordinationBuilder.check(built, draft: draft, binary: URL(fileURLWithPath: binary), environment: environment)
        XCTAssertTrue(PageRequest.isObjectiveId(id))
        XCTAssertFalse(FileManager.default.fileExists(atPath: built.root.appendingPathComponent("log/cairn.jsonl").path))
    }
}
