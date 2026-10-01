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

    func testPieceworkDecodesFromTheObjectivesRoute() throws {
        // The shape `piecework_value` in src/serve.rs publishes, `key` and
        // `items` included: a field this reader does not use must not fail
        // the whole list.
        let json = """
        {"id":"sha256:p","goal":"g","statement":"s","reward":1000,"funder":"f",
         "verifier_kind":"command","settled":false,"open":true,"settlement":null,
         "piecework":{"unit_price":10,"paid_units":3,"paid_total":30,
                      "pool_remaining":970,"units":100,"key":"orbit","items":"jobs"}}
        """
        let objective = try JSONDecoder().decode(Objective.self, from: Data(json.utf8))
        XCTAssertNil(objective.frontier)
        XCTAssertNil(objective.settlement)
        XCTAssertEqual(objective.piecework?.paid_units, 3)
        XCTAssertEqual(objective.piecework?.paid_total, 30)
        XCTAssertEqual(objective.piecework?.units, 100)
    }

    func testCapsetObjectiveInTheLaunchLog() throws {
        let snapshot = try BundledSnapshot.load()
        let capset = snapshot.objectives.first { $0.goal.contains("capset") }
        XCTAssertNotNil(capset)
        XCTAssertNotNil(capset?.frontier)
        XCTAssertNotNil(capset?.record?.ratchet)
    }
}
