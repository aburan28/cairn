import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import XCTest
@testable import Cairn

/// What the app sends to each provider, how it reads what comes back, and the
/// objective it builds. Running a drafted checker through `cairn propose`
/// needs a `cairn` binary this job does not build; the verdict parser is
/// held here to the exact lines that command prints.
final class DraftingTests: XCTestCase {
    private func body(_ config: AIConfig) throws -> (URLRequest, [String: Any]) {
        let request = try AIClient(config: config, apiKey: "k")
            .makeRequest(system: "s", user: "u", schema: ChallengeWriter.schema, schemaName: "cairn_challenge")
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: XCTUnwrap(request.httpBody)) as? [String: Any])
        return (request, json)
    }

    private func config(_ provider: AIProvider, _ model: String) -> AIConfig {
        AIConfig(provider: provider, model: model, baseURL: provider.defaultBaseURL)
    }

    // MARK: requests

    func testClaudeGetsMessagesWithStructuredOutputAndFallbacks() throws {
        let (request, json) = try body(config(.anthropic, "claude-opus-5-5"))
        XCTAssertEqual(request.url?.absoluteString, "https://api.anthropic.com/v1/messages")
        XCTAssertEqual(request.value(forHTTPHeaderField: "x-api-key"), "k")
        XCTAssertEqual(request.value(forHTTPHeaderField: "anthropic-version"), "2023-06-01")
        XCTAssertEqual(request.value(forHTTPHeaderField: "anthropic-beta"), "server-side-fallback-2026-07-01")
        XCTAssertEqual(json["fallbacks"] as? String, "default")
        let output = try XCTUnwrap(json["output_config"] as? [String: Any])
        XCTAssertEqual(output["effort"] as? String, "high")
        XCTAssertEqual((output["format"] as? [String: Any])?["type"] as? String, "json_schema")
        // Both are refused by current models; neither may ride along.
        XCTAssertNil(json["thinking"])
        XCTAssertNil(json["temperature"])
    }

    func testOpenCodeRoutesByModel() throws {
        let (claude, _) = try body(config(.opencode, "claude-opus-5-5"))
        XCTAssertEqual(claude.url?.absoluteString, "https://opencode.ai/zen/v1/messages")
        XCTAssertEqual(claude.value(forHTTPHeaderField: "x-api-key"), "k")
        XCTAssertNil(claude.value(forHTTPHeaderField: "anthropic-beta"), "the fallback beta is Anthropic's own API only")

        let (kimi, json) = try body(config(.opencode, "kimi-k3"))
        XCTAssertEqual(kimi.url?.absoluteString, "https://opencode.ai/zen/v1/chat/completions")
        XCTAssertEqual(kimi.value(forHTTPHeaderField: "Authorization"), "Bearer k")
        XCTAssertEqual((json["response_format"] as? [String: Any])?["type"] as? String, "json_object")

        XCTAssertNotNil(config(.opencode, "gpt-6.1-sol").problem, "Zen serves GPT only on the Responses API")
    }

    func testOpenAIGetsStrictSchemaAndDeveloperRole() throws {
        let (request, json) = try body(config(.openai, "gpt-6.1-sol"))
        XCTAssertEqual(request.url?.absoluteString, "https://api.openai.com/v1/chat/completions")
        let messages = try XCTUnwrap(json["messages"] as? [[String: Any]])
        XCTAssertEqual(messages.first?["role"] as? String, "developer")
        XCTAssertEqual(json["max_completion_tokens"] as? Int, 16000)
        XCTAssertNil(json["max_tokens"])
        XCTAssertNil(json["temperature"])
        let format = try XCTUnwrap((json["response_format"] as? [String: Any])?["json_schema"] as? [String: Any])
        XCTAssertEqual(format["strict"] as? Bool, true)
    }

    func testFireworksAndCustomSpeakChatCompletions() throws {
        let (fireworks, json) = try body(config(.fireworks, "accounts/fireworks/models/kimi-k3"))
        XCTAssertEqual(fireworks.url?.absoluteString, "https://api.fireworks.ai/inference/v1/chat/completions")
        XCTAssertEqual(json["max_tokens"] as? Int, 16000)
        XCTAssertEqual((json["messages"] as? [[String: Any]])?.first?["role"] as? String, "system")

        let local = AIConfig(provider: .custom, model: "m", baseURL: "http://127.0.0.1:11434/v1/")
        XCTAssertNil(local.problem)
        XCTAssertEqual(try body(local).0.url?.absoluteString, "http://127.0.0.1:11434/v1/chat/completions")
        XCTAssertNotNil(AIConfig(provider: .custom, model: "m", baseURL: "http://example.com/v1").problem,
                        "a key is never sent in the clear past this Mac")
    }

    // MARK: replies

    func testRepliesAreReadPastFallbackBlocksAndFences() throws {
        let messages = #"{"stop_reason":"end_turn","content":[{"type":"fallback"},{"type":"text","text":"```json\n{\"a\":1}\n```"}]}"#
        XCTAssertEqual(try AIClient.jsonObject(in: AIClient.text(from: Data(messages.utf8), wire: .messages))["a"] as? Int, 1)
        let chat = #"{"choices":[{"finish_reason":"stop","message":{"content":"Here it is: {\"a\":2}"}}]}"#
        XCTAssertEqual(try AIClient.jsonObject(in: AIClient.text(from: Data(chat.utf8), wire: .chatCompletions))["a"] as? Int, 2)
    }

    func testRefusalsAndTruncationAreSaidAsSuch() {
        let refusal = #"{"stop_reason":"refusal","stop_details":{"explanation":"no"},"content":[]}"#
        XCTAssertThrowsError(try AIClient.text(from: Data(refusal.utf8), wire: .messages)) {
            XCTAssertTrue($0.localizedDescription.contains("declined"))
        }
        let cut = #"{"choices":[{"finish_reason":"length","message":{"content":"{"}}]}"#
        XCTAssertThrowsError(try AIClient.text(from: Data(cut.utf8), wire: .chatCompletions)) {
            XCTAssertTrue($0.localizedDescription.contains("ran out of room"))
        }
        let credits = Data(#"{"type":"error","error":{"type":"CreditsError","message":"x"}}"#.utf8)
        XCTAssertTrue(AIClient.failure(status: 401, body: credits, provider: .opencode).message.contains("out of credits"))
        let badKey = Data(#"{"error":{"message":"Incorrect API key","code":"invalid_api_key"}}"#.utf8)
        XCTAssertTrue(AIClient.failure(status: 401, body: badKey, provider: .openai).message.contains("refused the API key"))
    }

    // MARK: the objective

    private let draftObject: [String: Any] = [
        "goal": "GOAL-factor-a-semiprime",
        "statement": "Find integers p and q above 1 whose product is 1000036000099.",
        "answer_schema": #"{"type":"object","properties":{"p":{"type":"integer"},"q":{"type":"integer"}},"required":["p","q"],"example":{"p":3,"q":5}}"#,
        "checker": "def check(artifact):\n    return False, 'stub'",
        "passing_example": "",
        "failing_example": #"{"p": 1, "q": 1000036000099}"#,
        "notes": "",
    ]

    func testADraftBecomesAPinnedObjectiveUnderTheRoot() throws {
        let draft = try ChallengeWriter.parse(draftObject)
        XCTAssertNil(draft.passing, "an empty passing example means none is known")
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("cairn-test-\(UUID())")
        defer { try? FileManager.default.removeItem(at: root) }

        let built = try ChallengeBuilder.build(draft, reward: 5000, funder: "treasury", root: root,
                                               now: Date(timeIntervalSince1970: 1_790_000_000))
        let source = try Data(contentsOf: root.appendingPathComponent(built.checkerPath))
        XCTAssertEqual(GuiTasks.sha256(source), built.checkerHash)
        XCTAssertTrue(built.checkerPath.hasPrefix("challenges/factor-a-semiprime-"))

        let objective = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: built.objectiveFile)) as? [String: Any])
        let verifier = try XCTUnwrap(objective["verifier"] as? [String: Any])
        XCTAssertEqual(verifier["kind"] as? String, "certificate")
        XCTAssertEqual(verifier["checker"] as? String, built.checkerPath)
        XCTAssertEqual(verifier["checker_sha256"] as? String, built.checkerHash)
        XCTAssertEqual(verifier["entrypoint"] as? String, "check")
        XCTAssertEqual(verifier["timeout_seconds"] as? Int, 60)
        XCTAssertEqual(objective["reward"] as? Int, 5000)
        XCTAssertEqual(objective["created_at"] as? String, "2026-09-21T14:13:20+00:00")
        XCTAssertNotNil(objective["artifact_schema"] as? [String: Any])
    }

    func testFractionsAreRefusedBeforeTheNodeSeesThem() {
        XCTAssertThrowsError(try ChallengeBuilder.requireIntegers(["a": [1, 2.5]], what: "x"))
        XCTAssertNoThrow(try ChallengeBuilder.requireIntegers(["a": [1, 2, true, "1.5"] as [Any]], what: "x"))
    }

    func testVerdictsAreReadFromProposeOutput() {
        // Verbatim shapes of `cairn propose --dry-run` output.
        let accepted = """
              /tmp/x/passing.json: accept
            submitting /tmp/x/passing.json
              --dry-run: nothing was written
            """
        XCTAssertEqual(ChallengeTest.parse(accepted, err: "", artifact: "/tmp/x/passing.json"), .accept("accepted"))
        let rejected = """
              /tmp/x/failing.json: reject  (artifact.n must be an integer)
            nothing passed locally, so nothing was submitted
            """
        XCTAssertEqual(ChallengeTest.parse(rejected, err: "", artifact: "/tmp/x/failing.json"),
                       .reject("artifact.n must be an integer"))
        let crashed = "  /tmp/x/failing.json: unavailable  (pinned checker exited 1; a crashed verifier is unavailable, not a rejection)\n"
        XCTAssertEqual(ChallengeTest.parse(crashed, err: "", artifact: "/tmp/x/failing.json"),
                       .unavailable("pinned checker exited 1; a crashed verifier is unavailable, not a rejection"))
        XCTAssertEqual(ChallengeTest.parse("", err: "refused: objective sha256:ab is not in this log", artifact: "/tmp/x/a.json"),
                       .refused("refused: objective sha256:ab is not in this log"))

        let lax = ChallengeTest.Outcome(passing: .accept("ok"), failing: .accept("ok"))
        XCTAssertFalse(lax.ok)
        XCTAssertEqual(lax.problems.count, 1)
        XCTAssertTrue(ChallengeTest.Outcome(passing: nil, failing: .reject("no")).ok)
    }

    // MARK: tasks

    func testStagingCopiesAPinnedCheckerAndRefusesAWrongOne() throws {
        let base = FileManager.default.temporaryDirectory.appendingPathComponent("cairn-test-\(UUID())")
        defer { try? FileManager.default.removeItem(at: base) }
        let library = base.appendingPathComponent("library"), root = base.appendingPathComponent("root")
        let checker = Data("def check(a):\n    return True\n".utf8)
        try FileManager.default.createDirectory(at: library.appendingPathComponent("ex/checkers"), withIntermediateDirectories: true)
        try checker.write(to: library.appendingPathComponent("ex/checkers/c.py"))
        func objective(_ path: String, _ hash: String) throws {
            let json: [String: Any] = ["verifier": ["kind": "certificate", "checker": path, "checker_sha256": hash, "entrypoint": "check"]]
            try JSONSerialization.data(withJSONObject: json).write(to: library.appendingPathComponent("ex/o.json"))
        }

        try objective("ex/checkers/c.py", GuiTasks.sha256(checker))
        try GuiTasks.stage(objective: "ex/o.json", from: library, into: root)
        XCTAssertEqual(try Data(contentsOf: root.appendingPathComponent("ex/checkers/c.py")), checker)

        try objective("ex/checkers/c.py", String(repeating: "0", count: 64))
        XCTAssertThrowsError(try GuiTasks.stage(objective: "ex/o.json", from: library, into: root))
        try objective("../outside.py", GuiTasks.sha256(checker))
        XCTAssertThrowsError(try GuiTasks.stage(objective: "ex/o.json", from: library, into: root))
    }
}
