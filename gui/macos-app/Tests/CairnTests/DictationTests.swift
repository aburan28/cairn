import Foundation
import XCTest
@testable import Cairn

/// The parts of dictation and goal matching that need no microphone and no
/// node: how an utterance lands in a field, and how the node's answer reads.
final class DictationTests: XCTestCase {
    func testAnUtteranceIsSpacedAfterTypedTextAndNotBeforeNothing() {
        XCTAssertEqual(Dictation.merge("", "  hello  "), "hello")
        XCTAssertEqual(Dictation.merge("hello", "world"), "hello world")
        XCTAssertEqual(Dictation.merge("hello ", "world"), "hello world")
        XCTAssertEqual(Dictation.merge("line\n", "next"), "line\nnext")
        XCTAssertEqual(Dictation.merge("typed", "   "), "typed")
    }

    func testGoalMatchesAreReadOffTheNodesAnswerAndSummarised() throws {
        let body = try JSONSerialization.jsonObject(with: Data("""
            {"query": "ecc2k130", "matches": [
              {"key": "certicomecc2k130", "name": "ECC2K-130", "handle": "GOAL-certicom-ecc2k130",
               "handles": ["GOAL-certicom-ecc2k130", "GOAL-ecc2k-130"], "objectives": 4, "open": 3,
               "summary": "The Certicom ECC2K-130 challenge.",
               "angles": [{"path": ""}, {"path": "rho/distributed"}, {"path": "rho/gpu-kernel"}]},
              {"key": "certicomeccp131", "name": "ECCp-131", "handle": "GOAL-certicom-eccp131",
               "handles": [], "objectives": 0, "open": 0, "angles": []},
              {"name": "broken: no key or handle"}
            ]}
            """.utf8))
        let matches = GoalMatch.parse(body)
        XCTAssertEqual(matches.map(\.key), ["certicomecc2k130", "certicomeccp131"])
        XCTAssertEqual(matches[0].angles, ["rho/distributed", "rho/gpu-kernel"], "the unnamed angle is left out")
        XCTAssertEqual(
            matches[0].summaryLine,
            "ECC2K-130 already has 4 challenges (3 open) under GOAL-certicom-ecc2k130 (also written GOAL-ecc2k-130), 2 angles: rho/distributed, rho/gpu-kernel.")
        XCTAssertEqual(
            matches[1].summaryLine,
            "ECCp-131 is a known goal nobody has funded yet; the first challenge on it is GOAL-certicom-eccp131.")
        XCTAssertEqual(GoalMatch.parse(["matches": "nonsense"]).count, 0)
    }

    func testTheModelIsToldTheHandleWhenTheChallengeIsAnAngleOnAGoal() {
        let plain = ChallengeWriter.request(describing: "prove something")
        XCTAssertFalse(plain.contains("ANGLE"))
        let angle = ChallengeWriter.request(describing: "a faster kernel", angleOn: "GOAL-certicom-ecc2k130")
        XCTAssertTrue(angle.contains("\"GOAL-certicom-ecc2k130/<angle>\""), angle)
        XCTAssertTrue(angle.contains("Do not invent a different goal name"))
    }
}
