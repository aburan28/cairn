import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import XCTest
@testable import Cairn

/// A provider's stream, folded back into the one reply the sheet reads --
/// and the progress a person watches while it arrives.
final class StreamingTests: XCTestCase {
    private func feed(_ raw: String, wire: AIWire) throws -> (String, AIProgress, AIStreamReader) {
        var parser = SSEParser()
        var reader = AIStreamReader(wire: wire)
        var progress = AIProgress()
        for line in raw.split(separator: "\n", omittingEmptySubsequences: false) {
            guard let event = parser.feed(String(line)) else { continue }
            _ = try reader.take(event, into: &progress)
            if reader.finished { break }
        }
        if !reader.finished, let event = parser.flush() {
            _ = try reader.take(event, into: &progress)
        }
        return (try reader.reply(), progress, reader)
    }

    func testSSEFramingJoinsDataLinesAndSkipsComments() {
        var parser = SSEParser()
        XCTAssertNil(parser.feed(": keep-alive"))
        XCTAssertNil(parser.feed("event: content_block_delta"))
        XCTAssertNil(parser.feed("data: {\"a\":"))
        XCTAssertNil(parser.feed("data: 1}"))
        XCTAssertEqual(parser.feed(""), SSEEvent(event: "content_block_delta", data: "{\"a\":\n1}"))
        XCTAssertNil(parser.feed(""), "a second blank line dispatches nothing")
        XCTAssertNil(parser.feed("data:[DONE]"), "no space after the colon is still the field")
        XCTAssertEqual(parser.flush(), SSEEvent(event: nil, data: "[DONE]"))
        XCTAssertNil(parser.flush())
    }

    func testAnthropicStreamFoldsIntoOneReply() throws {
        let raw = """
        event: message_start
        data: {"type":"message_start","message":{"id":"m"}}

        event: content_block_start
        data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}

        event: content_block_delta
        data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"{\\"goal\\": "}}

        event: ping
        data: {"type":"ping"}

        event: content_block_delta
        data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"\\"GOAL-x\\"}"}}

        event: message_delta
        data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":9}}

        event: message_stop
        data: {"type":"message_stop"}

        """
        let (text, progress, reader) = try feed(raw, wire: .messages)
        XCTAssertEqual(try AIClient.jsonObject(in: text)["goal"] as? String, "GOAL-x")
        XCTAssertEqual(progress.stage, .writing)
        XCTAssertEqual(progress.written, text.count)
        XCTAssertEqual(progress.tail, text, "a short answer is its own tail")
        XCTAssertTrue(reader.finished)
    }

    func testChatCompletionsStreamFoldsIntoOneReplyAndCountsReasoning() throws {
        let raw = """
        data: {"id":"c","choices":[{"index":0,"delta":{"role":"assistant","content":""},"finish_reason":null}]}

        data: {"id":"c","choices":[{"index":0,"delta":{"reasoning_content":"let me think"},"finish_reason":null}]}

        data: {"id":"c","choices":[{"index":0,"delta":{"content":"{\\"goal\\":"},"finish_reason":null}]}

        data: {"id":"c","choices":[{"index":0,"delta":{"content":"\\"GOAL-y\\"}"},"finish_reason":"stop"}]}

        data: [DONE]

        """
        let (text, progress, reader) = try feed(raw, wire: .chatCompletions)
        XCTAssertEqual(try AIClient.jsonObject(in: text)["goal"] as? String, "GOAL-y")
        XCTAssertEqual(progress.reasoned, "let me think".count)
        XCTAssertEqual(progress.stage, .writing)
        XCTAssertTrue(reader.finished)
    }

    func testStreamedRefusalsTruncationAndErrorsAreSaidAsSuch() {
        func fails(_ raw: String, wire: AIWire, containing needle: String, line: UInt = #line) {
            XCTAssertThrowsError(try feed(raw, wire: wire), "expected a failure mentioning \(needle)", line: line) {
                XCTAssertTrue($0.localizedDescription.contains(needle), $0.localizedDescription, line: line)
            }
        }
        fails("event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"refusal\",\"stop_details\":{\"explanation\":\"no\"}}}\n\n",
              wire: .messages, containing: "declined")
        fails("event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"max_tokens\"}}\n\n",
              wire: .messages, containing: "ran out of room")
        fails("event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"Overloaded\"}}\n\n",
              wire: .messages, containing: "Overloaded")
        fails("data: {\"choices\":[{\"delta\":{\"content\":\"{\"},\"finish_reason\":\"length\"}]}\n\n",
              wire: .chatCompletions, containing: "ran out of room")
        fails("data: {\"choices\":[{\"delta\":{\"refusal\":\"nope\"},\"finish_reason\":null}]}\n\n",
              wire: .chatCompletions, containing: "declined")
        fails("data: {\"error\":{\"message\":\"model overloaded\"}}\n\n",
              wire: .chatCompletions, containing: "overloaded")
        fails("data: [DONE]\n\n", wire: .chatCompletions, containing: "no text")
    }

    func testStreamingIsAskedForOnBothWiresAndOnlyWhenAsked() throws {
        let configs = [
            AIConfig(provider: .anthropic, model: "claude-opus-5-5", baseURL: AIProvider.anthropic.defaultBaseURL),
            AIConfig(provider: .fireworks, model: "accounts/fireworks/models/kimi-k3", baseURL: AIProvider.fireworks.defaultBaseURL),
        ]
        for config in configs {
            let client = AIClient(config: config, apiKey: "k")
            let streamed = try client.makeRequest(system: "s", user: "u", schema: ChallengeWriter.schema, schemaName: "x", stream: true)
            let json = try XCTUnwrap(JSONSerialization.jsonObject(with: XCTUnwrap(streamed.httpBody)) as? [String: Any])
            XCTAssertEqual(json["stream"] as? Bool, true)
            let plain = try client.makeRequest(system: "s", user: "u", schema: ChallengeWriter.schema, schemaName: "x")
            let plainJSON = try XCTUnwrap(JSONSerialization.jsonObject(with: XCTUnwrap(plain.httpBody)) as? [String: Any])
            XCTAssertNil(plainJSON["stream"])
        }
    }

    func testProgressAdvancesByStageAndByCharacters() {
        var progress = DraftProgress()
        XCTAssertEqual(progress.fraction, 0)
        XCTAssertEqual(progress.current, .connect)
        progress.model = AIProgress(stage: .writing, written: 3_500, reasoned: 0, tail: "x")
        XCTAssertEqual(progress.current, .model)
        XCTAssertTrue(progress.done.contains(.connect))
        XCTAssertEqual(progress.fraction, (1 + 0.5) / 8, accuracy: 1e-9)
        XCTAssertTrue(progress.headline.contains("3,500") || progress.headline.contains("3500"), progress.headline)
        progress.reached(.post)
        XCTAssertEqual(progress.done.count, 4)
        XCTAssertEqual(progress.current, .post)
        progress.stages.removeAll { $0 == .proof }
        progress.finished(ok: true)
        XCTAssertEqual(progress.fraction, 1)
        XCTAssertEqual(progress.headline, "Tested.")
        progress.failed(at: .hole)
        XCTAssertTrue(progress.headline.hasPrefix("Stopped while"))
    }
}
