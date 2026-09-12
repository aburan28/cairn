import XCTest
@testable import CairnKit

private func recordJSON(seq: Int, kind: String, payload: String = "{}", prev: String? = nil) -> String {
    let prevJSON: String
    if seq == 0, prev == nil {
        prevJSON = "null"
    } else {
        prevJSON = "\"\(prev ?? "sha256:entry-\(seq - 1)")\""
    }
    return """
    {"seq":\(seq),"kind":"\(kind)","hash":"sha256:entry-\(seq)","prev":\(prevJSON),"ts":"t","payload":\(payload)}
    """
}

final class LogParseTests: XCTestCase {
    func testParsesOneRecordPerLineAndSkipsBlanks() {
        let text = [recordJSON(seq: 0, kind: "objective"), "", recordJSON(seq: 1, kind: "claim"), ""].joined(separator: "\n")
        let parsed = parseLog(text)
        XCTAssertEqual(parsed.records.map(\.seq), [0, 1])
        XCTAssertTrue(parsed.problems.isEmpty)
    }

    func testReportsAMalformedLineByNumberAndKeepsTheRest() {
        let text = [
            recordJSON(seq: 0, kind: "objective"),
            "{\"seq\": 1, \"kind\": \"claim\", \"hash\": \"sha256:entry-1\", \"prev\": \"sha256:entry-0\", \"ts\": \"t\", \"payload\": {",
            recordJSON(seq: 2, kind: "verdict"),
        ].joined(separator: "\n")
        let parsed = parseLog(text)
        XCTAssertEqual(parsed.records.map(\.seq), [0, 2])
        XCTAssertEqual(parsed.problems.count, 1)
        XCTAssertTrue(parsed.problems[0].hasPrefix("line 2: "))
    }

    func testReportsALineThatParsesButIsNotARecord() {
        let text = [recordJSON(seq: 0, kind: "objective"), "{\"not\": \"a record\"}", "[1, 2, 3]"].joined(separator: "\n")
        let parsed = parseLog(text)
        XCTAssertEqual(parsed.records.count, 1)
        XCTAssertEqual(parsed.problems.count, 2)
        XCTAssertTrue(parsed.problems[0].contains("line 2:"))
        XCTAssertTrue(parsed.problems[1].contains("line 3:"))
    }

    func testAcceptsGenesisWhosePrevIsNull() {
        let parsed = parseLog(recordJSON(seq: 0, kind: "objective"))
        XCTAssertNil(parsed.records[0].prev)
        XCTAssertTrue(parsed.problems.isEmpty)
    }

    func testSummarizeObjective() {
        let parsed = parseLog(recordJSON(
            seq: 0,
            kind: "objective",
            payload: "{\"goal\":\"GOAL-x\",\"verifier\":{\"kind\":\"certificate\"},\"reward\":1000,\"funder\":\"treasury\"}"
        ))
        XCTAssertEqual(summarize(parsed.records[0]), "GOAL-x · certificate · 1,000 by treasury")
    }

    func testKindCountsPreserveFirstSeenOrder() {
        let text = [
            recordJSON(seq: 0, kind: "objective"),
            recordJSON(seq: 1, kind: "claim"),
            recordJSON(seq: 2, kind: "objective"),
        ].joined(separator: "\n")
        let counts = kindCounts(parseLog(text).records)
        XCTAssertEqual(counts.map(\.0), ["objective", "claim"])
        XCTAssertEqual(counts.map(\.1), [2, 1])
    }
}
