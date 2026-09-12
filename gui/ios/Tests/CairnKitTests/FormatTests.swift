import XCTest
@testable import CairnKit

private func objective(reward: Int, paid: Int, remaining: Int) -> Objective {
    Objective(
        id: "sha256:o",
        goal: "GOAL",
        statement: "",
        reward: reward,
        funder: "treasury",
        verifier_kind: "evaluator",
        settled: false,
        open: true,
        frontier: Frontier(
            claim_id: "sha256:c",
            holder: "carol",
            must_cite: "sha256:c",
            paid_cumulative: paid,
            pool_remaining: remaining,
            score: 1
        )
    )
}

final class FormatTests: XCTestCase {
    func testShortHashKeepsAShortValue() {
        XCTAssertEqual(shortHash("abcd"), "abcd")
    }

    func testShortHashStripsTheSha256Prefix() {
        XCTAssertEqual(shortHash("sha256:0123456789abcdef0123"), "01234567…0123")
    }

    func testOverspentIsFalseWithNoFrontier() {
        var o = objective(reward: 100, paid: 0, remaining: 100)
        o.frontier = nil
        XCTAssertFalse(overspent(o))
    }

    func testOverspentIsFalseWhenPaidPlusRemainingIsTheReward() {
        XCTAssertFalse(overspent(objective(reward: 1_100_000, paid: 1_100_000, remaining: 0)))
        XCTAssertFalse(overspent(objective(reward: 1_000, paid: 300, remaining: 700)))
    }

    func testOverspentIsFalseWhenUnderAccounted() {
        XCTAssertFalse(overspent(objective(reward: 1_000, paid: 300, remaining: 600)))
    }

    func testOverspentIsTrueWhenTheNodePublishedMoreThanFundingCovers() {
        XCTAssertTrue(overspent(objective(reward: 1_000, paid: 300, remaining: 701)))
    }

    func testPoolFractionIsRemainingAgainstWhatWasFunded() {
        XCTAssertEqual(poolFraction(of: objective(reward: 1_000, paid: 250, remaining: 750)), 0.75)
    }

    func testPoolFractionClampsAnOverspentPool() {
        XCTAssertEqual(poolFraction(of: objective(reward: 1_000, paid: 0, remaining: 2_000)), 1)
    }

    func testPoolFractionIsNilWithNoFrontierOrNoReward() {
        var o = objective(reward: 1_000, paid: 0, remaining: 0)
        o.frontier = nil
        XCTAssertNil(poolFraction(of: o))
        XCTAssertNil(poolFraction(of: objective(reward: 0, paid: 0, remaining: 0)))
    }

    func testRatchetProgressCountsUpForMaximize() {
        let ratchet = Ratchet(
            baseline: 9, target: 20, direction: "maximize",
            min_improvement: 3, reward: 1_100_000
        )
        XCTAssertEqual(ratchetProgress(score: 9, ratchet: ratchet), 0)
        XCTAssertEqual(ratchetProgress(score: 20, ratchet: ratchet), 1)
        XCTAssertEqual(ratchetProgress(score: 12, ratchet: ratchet)!, 3.0 / 11.0, accuracy: 1e-9)
    }

    func testRatchetProgressCountsDownForMinimize() {
        let ratchet = Ratchet(
            baseline: 100, target: 40, direction: "minimize",
            min_improvement: 5, reward: 1_000
        )
        XCTAssertEqual(ratchetProgress(score: 100, ratchet: ratchet), 0)
        XCTAssertEqual(ratchetProgress(score: 40, ratchet: ratchet), 1)
        XCTAssertEqual(ratchetProgress(score: 70, ratchet: ratchet)!, 0.5, accuracy: 1e-9)
    }

    func testRatchetProgressIsNilOnADegenerateSpan() {
        let ratchet = Ratchet(
            baseline: 5, target: 5, direction: "maximize",
            min_improvement: 1, reward: 1
        )
        XCTAssertNil(ratchetProgress(score: 5, ratchet: ratchet))
    }
}
