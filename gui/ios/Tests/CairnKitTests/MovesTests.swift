import XCTest
@testable import CairnKit

/// Same fixtures as `ui/lib/log.test.ts` so a change to `buildMoves` that
/// disagrees with the site fails here the same way it fails there.
private let objectiveId = "sha256:objective"

private func record(seq: Int, kind: String, payload: [String: JSONValue]) -> LogRecord {
    LogRecord(
        seq: seq,
        kind: kind,
        hash: "sha256:entry-\(seq)",
        prev: seq == 0 ? nil : "sha256:entry-\(seq - 1)",
        ts: String(format: "2026-01-01T00:00:%02d+00:00", seq),
        payload: payload
    )
}

private func frontier(seq: Int, claim: String, score: Int, paid: Int) -> LogRecord {
    record(seq: seq, kind: "frontier", payload: [
        "objective_id": .string(objectiveId),
        "claim_id": .string(claim),
        "holder": .string("holder-of-\(claim)"),
        "score": .int(score),
        "paid_cumulative": .int(paid),
        "pool_remaining": .int(1_000 - paid),
    ])
}

private func settlement(seq: Int, claim: String, reward: Int) -> LogRecord {
    record(seq: seq, kind: "settlement", payload: [
        "objective_id": .string(objectiveId),
        "claim_id": .string(claim),
        "submitter": .string("holder-of-\(claim)"),
        "reward": .int(reward),
    ])
}

final class MovesTests: XCTestCase {
    func testLaysOutSuccessiveStatesOldestFirstWithEachMovesPayout() {
        let records = [
            frontier(seq: 5, claim: "sha256:a", score: 12, paid: 300),
            settlement(seq: 6, claim: "sha256:a", reward: 300),
            frontier(seq: 9, claim: "sha256:b", score: 17, paid: 800),
            settlement(seq: 10, claim: "sha256:b", reward: 500),
        ]
        let moves = buildMoves(records, objectiveId: objectiveId)
        XCTAssertEqual(moves.map(\.claimId), ["sha256:a", "sha256:b"])
        XCTAssertEqual(moves.map(\.paidThisMove), [300, 500])
        XCTAssertEqual(moves.map(\.paidCumulative), [300, 800])
        XCTAssertEqual(moves.map(\.settlementReward), [300, 500])
        XCTAssertTrue(moves.allSatisfy(\.consistent))
    }

    func testOrdersBySeqEvenWhenRecordsArriveOutOfOrder() {
        let records = [
            frontier(seq: 9, claim: "sha256:b", score: 17, paid: 800),
            frontier(seq: 5, claim: "sha256:a", score: 12, paid: 300),
        ]
        XCTAssertEqual(buildMoves(records, objectiveId: objectiveId).map(\.seq), [5, 9])
    }

    func testIgnoresOtherObjectivesFrontierAndSettlement() {
        var other = frontier(seq: 3, claim: "sha256:x", score: 99, paid: 999)
        other.payload["objective_id"] = .string("sha256:other")
        let records = [other, frontier(seq: 5, claim: "sha256:a", score: 12, paid: 300)]
        XCTAssertEqual(buildMoves(records, objectiveId: objectiveId).map(\.claimId), ["sha256:a"])
    }

    func testConsistentWithNoSettlementYet() {
        // The log may not have reached the settlement. Picking "inconsistent"
        // here would paint every live ratchet red until the epoch closed.
        let moves = buildMoves([frontier(seq: 5, claim: "sha256:a", score: 12, paid: 300)], objectiveId: objectiveId)
        XCTAssertNil(moves[0].settlementReward)
        XCTAssertTrue(moves[0].consistent)
    }

    func testFlagsAMoveWhosePayoutDisagreesWithSettlement() {
        // Two records the same node wrote, disagreeing about one payment.
        // The reader renders this red rather than picking one — the same
        // instinct as `overspent`.
        let records = [
            frontier(seq: 5, claim: "sha256:a", score: 12, paid: 300),
            settlement(seq: 6, claim: "sha256:a", reward: 300),
            frontier(seq: 9, claim: "sha256:b", score: 17, paid: 800),
            settlement(seq: 10, claim: "sha256:b", reward: 450),
        ]
        let moves = buildMoves(records, objectiveId: objectiveId)
        XCTAssertTrue(moves[0].consistent)
        XCTAssertEqual(moves[1].paidThisMove, 500)
        XCTAssertEqual(moves[1].settlementReward, 450)
        XCTAssertFalse(moves[1].consistent)
    }

    func testPrettyPrintsTheRecordTheNodeWrote() {
        let parsed = parseLog(
            "{\"seq\":0,\"kind\":\"objective\",\"hash\":\"sha256:entry-0\",\"prev\":null,\"ts\":\"t\",\"payload\":{\"goal\":\"GOAL-x\"}}"
        )
        let text = pretty(parsed.records[0])
        XCTAssertTrue(text.contains("\"kind\" : \"objective\"") || text.contains("\"kind\": \"objective\""))
        XCTAssertTrue(text.contains("GOAL-x"))
        XCTAssertTrue(text.contains("null"))
    }
}