import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import XCTest
@testable import Cairn

/// What the app sends to each provider, how it reads what comes back, and the
/// objective it builds. Running a drafted theorem through `cairn propose`
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

    // MARK: served models

    func testModelListsAreReadFromEveryProviderShape() throws {
        let openai = #"{"object":"list","data":[{"id":"gpt-6.1-sol","object":"model"},{"id":"gpt-6.1-sol"},{"id":"o5"}]}"#
        XCTAssertEqual(try AIClient.modelIDs(in: Data(openai.utf8)), ["gpt-6.1-sol", "o5"], "in the provider's order, once each")
        let fireworks = #"{"data":[{"id":"accounts/fireworks/models/kimi-k3","supports_chat":true},{"id":"accounts/fireworks/models/nomic-embed","supports_chat":false}]}"#
        XCTAssertEqual(try AIClient.modelIDs(in: Data(fireworks.utf8)), ["accounts/fireworks/models/kimi-k3"], "an embedder cannot draft")
        let anthropic = #"{"data":[{"type":"model","id":"claude-opus-5-5","display_name":"Claude Opus 5.5"}],"has_more":false}"#
        XCTAssertEqual(try AIClient.modelIDs(in: Data(anthropic.utf8)), ["claude-opus-5-5"])
        let ollama = #"{"models":[{"name":"qwen3:32b","model":"qwen3:32b"}]}"#
        XCTAssertEqual(try AIClient.modelIDs(in: Data(ollama.utf8)), ["qwen3:32b"])
        XCTAssertThrowsError(try AIClient.modelIDs(in: Data(#"{"data":[]}"#.utf8)))
        XCTAssertThrowsError(try AIClient.modelIDs(in: Data("not json".utf8)))
    }

    func testListingNeedsAnEndpointButNoModel() throws {
        XCTAssertNil(AIConfig(provider: .custom, model: "", baseURL: "http://127.0.0.1:11434/v1").endpointProblem,
                     "listing needs an endpoint, not a model")
        XCTAssertNotNil(AIConfig(provider: .custom, model: "", baseURL: "").endpointProblem)
        XCTAssertNotNil(AIConfig(provider: .custom, model: "", baseURL: "http://example.com/v1").endpointProblem)
    }

    func testStaleDefaultsFindTheirServedName() {
        let fireworks = ["accounts/fireworks/models/deepseek-v4", "accounts/fireworks/models/kimi-k3-instruct", "accounts/fireworks/models/qwen3-coder"]
        XCTAssertEqual(AIClient.nearest(to: "accounts/fireworks/models/kimi-k3", in: fireworks), "accounts/fireworks/models/kimi-k3-instruct")
        XCTAssertNil(AIClient.nearest(to: "accounts/fireworks/models/qwen3-coder", in: fireworks), "served as is: nothing to suggest")
        XCTAssertEqual(AIClient.nearest(to: "kimi-k3-0905", in: ["moonshotai/kimi-k3"]), "moonshotai/kimi-k3", "a dated id finds its family")
        XCTAssertEqual(AIClient.nearest(to: "Kimi-K3", in: ["moonshotai/kimi-k3"]), "moonshotai/kimi-k3", "case is the provider's business")
        XCTAssertNil(AIClient.nearest(to: "gpt-6.1-sol", in: fireworks))
        XCTAssertNil(AIClient.nearest(to: "", in: fireworks))
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
        "goal": "GOAL-add-comm-nat",
        "statement": "Prove that addition of natural numbers is commutative.",
        "theorem": "theorem pw_add_comm (a b : Nat) : a + b = b + a",
        "preamble": "",
        "proof": "",
        "timeout_seconds": "120",
        "notes": "",
    ]

    func testADraftBecomesALeanObjectiveUnderTheRoot() throws {
        let draft = try ChallengeWriter.parse(draftObject)
        XCTAssertNil(draft.proof, "an empty proof means the model knows none")
        XCTAssertEqual(draft.timeoutSeconds, 120)
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("cairn-test-\(UUID())")
        defer { try? FileManager.default.removeItem(at: root) }

        let built = try ChallengeBuilder.build(draft, reward: 5000, funder: "treasury", root: root,
                                               now: Date(timeIntervalSince1970: 1_790_000_000))
        XCTAssertTrue(built.directory.path.contains("/challenges/add-comm-nat-"), built.directory.path)
        XCTAssertEqual(try String(contentsOf: built.leanFile, encoding: .utf8),
                       "\ntheorem pw_add_comm (a b : Nat) : a + b = b + a := by sorry\n",
                       "the file a solver starts from: the theorem with a hole")

        let objective = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: built.objectiveFile)) as? [String: Any])
        let verifier = try XCTUnwrap(objective["verifier"] as? [String: Any])
        // The shape of examples/lean/objective.json, which the node settles.
        XCTAssertEqual(verifier["kind"] as? String, "lean")
        XCTAssertEqual(verifier["statement"] as? String, "theorem pw_add_comm (a b : Nat) : a + b = b + a")
        XCTAssertEqual(verifier["preamble"] as? String, "")
        XCTAssertEqual(verifier["timeout_seconds"] as? Int, 120)
        XCTAssertNil(verifier["checker"], "a Lean challenge pins no code; the theorem is the pin")
        XCTAssertEqual(objective["reward"] as? Int, 5000)
        XCTAssertEqual(objective["created_at"] as? String, "2026-09-21T14:13:20+00:00")
        let schema = try XCTUnwrap(objective["artifact_schema"] as? [String: Any])
        XCTAssertEqual(schema["required"] as? [String], ["proof"])
    }

    func testTheTheoremIsHeldToLeanShape() throws {
        func parsed(_ changes: [String: Any]) throws -> ChallengeDraft {
            try ChallengeWriter.parse(draftObject.merging(changes) { _, new in new })
        }
        XCTAssertThrowsError(try parsed(["theorem": "lemma t : True"]), "core Lean has no lemma")
        XCTAssertThrowsError(try parsed(["theorem": "theorem t : True := trivial"]), "the proof is the solver's")
        XCTAssertThrowsError(try parsed(["theorem": "theorem t"]), "no proposition")
        XCTAssertEqual(try parsed(["proof": "by omega"]).proof, ":= by omega", "a proof without := gets one")
        XCTAssertEqual(try parsed(["proof": ":= Nat.add_comm a b"]).proof, ":= Nat.add_comm a b")
        XCTAssertEqual(try parsed(["timeout_seconds": "5"]).timeoutSeconds, 30, "clamped up")
        XCTAssertEqual(try parsed(["timeout_seconds": "99999"]).timeoutSeconds, 3600, "clamped down")
        XCTAssertEqual(try parsed(["timeout_seconds": "soon"]).timeoutSeconds, 120, "unreadable means the default")

        let draft = try parsed(["preamble": "def double (n : Nat) : Nat := 2 * n"])
        XCTAssertEqual(draft.source(proof: ":= rfl"),
                       "def double (n : Nat) : Nat := 2 * n\ntheorem pw_add_comm (a b : Nat) : a + b = b + a := rfl\n",
                       "assembled exactly as src/verifiers/mod.rs assembles it")
    }

    func testScreensMatchTheVerifiers() throws {
        XCTAssertEqual(LeanScreen.hits(in: ":= by sorry"), ["contains `sorry`: an explicit hole, proves nothing"])
        XCTAssertTrue(LeanScreen.hits(in: "theorem sorrying : True").isEmpty, "whole words, as the verifier matches them")
        XCTAssertEqual(LeanScreen.hits(in: "@[implemented_by evil] def f := 1").count, 1)
        XCTAssertEqual(LeanScreen.hits(in: "axiom cheat : False").count, 1)
        XCTAssertEqual(LeanScreen.hits(in: ":= by native_decide").count, 1)
        XCTAssertTrue(LeanScreen.hits(in: "theorem t : 1 + 1 = 2 := by decide").isEmpty)

        let clean = try ChallengeWriter.parse(draftObject)
        XCTAssertTrue(ChallengeWriter.problems(in: clean).isEmpty)
        var holed = clean
        holed.preamble = "theorem helper : False := by sorry"
        XCTAssertEqual(ChallengeWriter.problems(in: holed).count, 1)
        XCTAssertTrue(ChallengeWriter.problems(in: holed)[0].contains("preamble"))
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

        let lax = ChallengeTest.Outcome(hole: .accept("ok"), statement: .elaborates("Lean 4"), proof: nil)
        XCTAssertFalse(lax.ok, "a verifier that takes a hole pays for nothing")
        XCTAssertEqual(lax.problems.count, 1)
        let good = ChallengeTest.Outcome(hole: .reject("contains `sorry`"), statement: .elaborates("Lean 4"), proof: nil)
        XCTAssertTrue(good.ok, "no proof known is fine; the theorem is what is published")
        XCTAssertTrue(good.problems.isEmpty)
        let uncompiled = ChallengeTest.Outcome(hole: .reject("x"), statement: .untested("no Lean here"), proof: nil)
        XCTAssertFalse(uncompiled.ok, "a theorem nobody compiled is not posted")
        XCTAssertTrue(uncompiled.problems.isEmpty, "a missing toolchain is not the model's problem")
        let broken = ChallengeTest.Outcome(hole: .reject("x"), statement: .broken("unknown identifier 'foo'"), proof: nil)
        XCTAssertFalse(broken.ok)
        XCTAssertTrue(broken.problems[0].contains("unknown identifier"))
        let refusedProof = ChallengeTest.Outcome(hole: .reject("x"), statement: .elaborates("Lean 4"), proof: .reject("lean rejected the proof"))
        XCTAssertFalse(refusedProof.ok)
        XCTAssertTrue(refusedProof.problems[0].contains("kernel rejected"))
        let proofUnavailable = ChallengeTest.Outcome(hole: .reject("x"), statement: .elaborates("Lean 4"), proof: .unavailable("no lean"))
        XCTAssertFalse(proofUnavailable.ok)
        XCTAssertTrue(proofUnavailable.problems.isEmpty)
    }

    // MARK: the reader's page

    /// The body `handOff` in ui/lib/draft.ts posts, as WebKit hands it over.
    func testThePagesDescriptionIsReadTrimmed() throws {
        let body: [String: Any] = ["kind": "draft-challenge", "brief": "  find a 16-input sorting network \n"]
        guard case .success(let request) = PageRequest.parse(body) else { return XCTFail("refused a well-formed request") }
        XCTAssertEqual(request, .draftChallenge(brief: "find a 16-input sorting network"))
    }

    func testThePageCanOnlyRequestWhatTheAppDoesFromItsMenus() {
        XCTAssertEqual(try? PageRequest.parse(["kind": "start-dictation"]).get(), .startDictation)
        XCTAssertEqual(try? PageRequest.parse(["kind": "stop-dictation"]).get(), .stopDictation)
        if case .failure = PageRequest.parse(["kind": "listen-forever"]) {} else {
            XCTFail("accepted an unknown page request")
        }
        // Roles and sheets are WorkTests'.
    }

    func testThePageIsHeldToTheSheetsOwnLimits() {
        func refused(_ body: Any) -> Bool {
            if case .failure = PageRequest.parse(body) { return true }
            return false
        }
        XCTAssertTrue(refused("draft-challenge"))
        XCTAssertTrue(refused(["kind": "post-objective", "brief": "find a 16-input sorting network"]))
        XCTAssertTrue(refused(["kind": "draft-challenge"]))
        XCTAssertTrue(refused(["kind": "draft-challenge", "brief": "  too short  "]))
        XCTAssertTrue(refused(["kind": "draft-challenge", "brief": String(repeating: "x", count: 20_001)]))
        XCTAssertFalse(refused(["kind": "draft-challenge", "brief": String(repeating: "x", count: 20_000)]))
        // Counted as JavaScript counts `length`, so the page and the app
        // agree at the boundary: five emoji are ten UTF-16 units.
        XCTAssertTrue(ChallengeWriter.isDraftable(String(repeating: "🧩", count: 5)))
        XCTAssertFalse(ChallengeWriter.isDraftable(String(repeating: "🧩", count: 4)))
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
