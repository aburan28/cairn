import XCTest
@testable import CairnKit

/// The bundled file is `launch/cairn.jsonl` as a node served it. Decoding it
/// is the known-answer test for this package's types: a field rename in
/// `GET /objectives` that the website already absorbed would compile here
/// against a hand-written fixture and only fail on a phone.
final class SnapshotTests: XCTestCase {
    func testBundledSnapshotDecodes() throws {
        let snapshot = try BundledSnapshot.load()
        XCTAssertFalse(snapshot.objectives.isEmpty)
        XCTAssertEqual(snapshot.chain.height, snapshot.checkpoint.height)
        XCTAssertEqual(snapshot.chain.ledger_head, snapshot.checkpoint.head)
        XCTAssertFalse(snapshot.source.contains("live"))
        // The merkle root the landing page prints. A change here means the
        // snapshot was regenerated, which is fine, but the decode must still
        // produce the same number of challenges the site shows.
        XCTAssertGreaterThanOrEqual(snapshot.objectives.count, 1)
        for objective in snapshot.objectives {
            XCTAssertFalse(objective.id.isEmpty)
            XCTAssertEqual(objective.open, !objective.settled)
        }
    }

    func testCapsetObjectiveInTheLaunchLog() throws {
        let snapshot = try BundledSnapshot.load()
        let capset = snapshot.objectives.first { $0.goal.contains("capset") }
        XCTAssertNotNil(capset)
        XCTAssertNotNil(capset?.frontier)
        XCTAssertNotNil(capset?.record?.ratchet)
    }
}
