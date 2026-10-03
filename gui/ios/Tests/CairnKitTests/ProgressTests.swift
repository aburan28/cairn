import XCTest
@testable import CairnKit

/// `GET /progress/{id}` as a node sent it, and the arithmetic the screen does
/// on it. The fixture is a real answer from a node holding the ECC2K-130
/// orbit objective with three fleet supervisors reporting, captured the day
/// the route shipped; nothing in it was typed by hand.
final class ProgressTests: XCTestCase {
    private func fixture() throws -> ProgressResponse {
        guard let url = Bundle.module.url(
            forResource: "progress-ecc2k130", withExtension: "json", subdirectory: "Fixtures"
        ) else {
            throw NodeError.shape("Fixtures/progress-ecc2k130.json is missing from the test bundle")
        }
        return try JSONDecoder().decode(ProgressResponse.self, from: Data(contentsOf: url))
    }

    func testTheCapturedAnswerDecodes() throws {
        let p = try fixture()
        XCTAssertEqual(p.kind, "piecework")
        XCTAssertTrue(p.open)
        XCTAssertEqual(p.goal, "GOAL-certicom-ecc2k130")
        XCTAssertEqual(p.piecework?.unit_price, 1000)
        XCTAssertEqual(p.piecework?.units, 281_474_976_710_656)
        // Nothing paid yet: the fleet client uploads to its campaign store,
        // not to the node, and the page must not pretend otherwise.
        XCTAssertEqual(p.derived.units_paid, 0)
        XCTAssertEqual(p.derived.claims_paid, 0)
        XCTAssertEqual(p.derived.steps, 0)
        XCTAssertTrue(p.derived.workers.isEmpty)
        XCTAssertTrue(p.derived.hourly.isEmpty)
        XCTAssertEqual(p.derived.coverage?.bins, 128)
        XCTAssertEqual(p.derived.coverage?.counts.count, 128)
        XCTAssertEqual(p.derived.coverage?.units_touched, 0)
        XCTAssertFalse(p.derived.note.isEmpty)
        XCTAssertFalse(p.note.isEmpty)
    }

    func testTheReportedHalfIsThreeWorkersOneOfThemStale() throws {
        let r = try fixture().reported
        XCTAssertEqual(r.live, 2)
        XCTAssertEqual(r.stale, 1)
        XCTAssertEqual(r.gone, 0)
        XCTAssertEqual(r.workers.count, 3)
        XCTAssertEqual(r.live_within_seconds, 180)
        XCTAssertEqual(r.stale_within_seconds, 1800)
        XCTAssertGreaterThan(r.steps_per_second, 0)
        let stale = r.workers.first { $0.liveness == .stale }
        XCTAssertEqual(stale?.worker, "gpu-2")
        XCTAssertEqual(stale?.status, "stale")
        let live = r.workers.first { $0.worker == "gpu-0" }
        XCTAssertEqual(live?.liveness, .live)
        XCTAssertEqual(live?.client, "ecc2k130-aws-worker/1")
        XCTAssertEqual(live?.device, "cpu/1")
        XCTAssertEqual(live?.lanes, 16384)
        XCTAssertNil(live?.epoch)
        XCTAssertNil(live?.units)
        // The node measured a rate between two heartbeats and it agrees
        // with the worker's own figure to within a few percent.
        let measured = try XCTUnwrap(live?.measured_steps_per_second)
        let reported = try XCTUnwrap(live?.reported_steps_per_second)
        XCTAssertEqual(measured / reported, 1, accuracy: 0.1)
        XCTAssertEqual(workerRate(live), measured)
    }

    func testAnUnknownStatusFailsOneBadgeNotTheDecode() throws {
        let json = """
        {"worker":"w","status":"hibernating","first_seen_at":"t","received_at":"t","age_seconds":3,
         "epoch":null,"units":{"first":1,"end":9},"unit":4,"steps":12,"trails":1,"capped":0,
         "units_pending":0,"units_submitted":0,"reported_steps_per_second":null,
         "measured_steps_per_second":null,"device":null,"lanes":null,"client":null}
        """
        let worker = try JSONDecoder().decode(ReportedWorker.self, from: Data(json.utf8))
        XCTAssertEqual(worker.liveness, .gone)
        XCTAssertEqual(worker.units?.end, 9)
        XCTAssertNil(workerRate(worker))
    }

    func testTheSettledHalfDecodesWithWorkersAndHours() throws {
        let json = """
        {"claims_paid":3,"claims":4,"rejected":1,"in_flight":0,"elements":12,"units_paid":11,
         "reward":1100,"steps":123456,"first_paid_at":"2026-10-03T12:00:10+00:00",
         "last_paid_at":"2026-10-03T12:00:40+00:00",
         "workers":[{"submitter":"alice","claims_paid":1,"claims":1,"rejected":0,"in_flight":0,
                     "elements":4,"units_paid":4,"reward":400,"steps":40000,
                     "first_paid_at":"2026-10-03T12:00:10+00:00","last_paid_at":"2026-10-03T12:00:10+00:00"}],
         "hourly":[{"hour":"2026-10-03T12:00:00+00:00","claims_paid":3,"units_paid":11,"steps":123456}],
         "last_hour":{"claims_paid":3,"units_paid":11,"steps":123456},
         "last_day":{"claims_paid":3,"units_paid":11,"steps":123456},
         "coverage":null,"steps_method":"sum","note":"derived"}
        """
        let derived = try JSONDecoder().decode(Derived.self, from: Data(json.utf8))
        XCTAssertEqual(derived.workers.first?.id, "alice")
        XCTAssertEqual(derived.hourly.first?.units_paid, 11)
        XCTAssertNil(derived.coverage)
        XCTAssertNil(coverageFraction(derived.coverage))
    }

    func testTheRecordCarriesTheCheckerHashTheJobTableKeysOn() throws {
        let json = """
        {"goal":"GOAL-certicom-ecc2k130","created_at":"2026-09-14T00:00:00+00:00",
         "verifier":{"checker":"examples/certicom-ecdlp/checkers/ecc2k130_orbit_batch.py",
                     "checker_sha256":"502F5B58881ED1A83B0F882153F78B724BC4319744853D080E8B2134AEC661A3",
                     "entrypoint":"check","kind":"certificate"}}
        """
        let record = try JSONDecoder().decode(ObjectiveRecord.self, from: Data(json.utf8))
        XCTAssertNil(record.ratchet)
        let job = jobFor(checkerSha256: record.verifier?.checker_sha256)
        XCTAssertEqual(job?.name, "certicom ecc2k-130")
        XCTAssertEqual(job?.unitNoun, "orbits")
        XCTAssertNil(jobFor(checkerSha256: "0000"))
        XCTAssertNil(jobFor(checkerSha256: nil))
    }

    // MARK: - The two halves on one row

    private func derived(_ name: String, paid: Int) -> DerivedWorker {
        let json = """
        {"submitter":"\(name)","claims_paid":1,"claims":1,"rejected":0,"in_flight":0,"elements":\(paid),
         "units_paid":\(paid),"reward":\(paid * 100),"steps":1000,"first_paid_at":null,"last_paid_at":null}
        """
        return try! JSONDecoder().decode(DerivedWorker.self, from: Data(json.utf8))
    }

    private func reported(_ name: String, status: String) -> ReportedWorker {
        let json = """
        {"worker":"\(name)","status":"\(status)","first_seen_at":"t","received_at":"t","age_seconds":1,
         "epoch":null,"units":null,"unit":null,"steps":5,"trails":0,"capped":0,"units_pending":0,
         "units_submitted":0,"reported_steps_per_second":7,"measured_steps_per_second":null,
         "device":null,"lanes":null,"client":null}
        """
        return try! JSONDecoder().decode(ReportedWorker.self, from: Data(json.utf8))
    }

    func testWorkersMergeByNameLiveFirstThenMostPaid() {
        let rows = mergeWorkers(
            derived: [derived("alice", paid: 10), derived("dave", paid: 3), derived("erin", paid: 30)],
            reported: [reported("bob", status: "live"), reported("alice", status: "stale"), reported("carol", status: "gone")]
        )
        XCTAssertEqual(rows.map(\.name), ["bob", "alice", "carol", "erin", "dave"])
        XCTAssertEqual(rows.map(\.standing), [.live, .stale, .gone, .settled, .settled])
        XCTAssertEqual(rows[1].derived?.units_paid, 10)
        XCTAssertEqual(rows[1].reported?.status, "stale")
        XCTAssertNil(rows[0].derived)
        XCTAssertEqual(workerRate(rows[0].reported), 7)
    }

    // MARK: - The search as a whole

    func testCollisionOddsAreTheBirthdayBound() throws {
        let expected = pow(2, 60.81)
        XCTAssertEqual(try XCTUnwrap(collisionOdds(steps: 0, expected: expected)), 0, accuracy: 1e-12)
        XCTAssertEqual(try XCTUnwrap(collisionOdds(steps: expected, expected: expected)), 0.5443, accuracy: 0.001)
        XCTAssertEqual(try XCTUnwrap(workForOdds(0.5, expected: expected)) / expected, 0.9394, accuracy: 0.001)
        XCTAssertEqual(try XCTUnwrap(workForOdds(0.9, expected: expected)) / expected, 1.712, accuracy: 0.01)
        let half = try XCTUnwrap(workForOdds(0.5, expected: expected))
        XCTAssertEqual(try XCTUnwrap(collisionOdds(steps: half, expected: expected)), 0.5, accuracy: 1e-6)
        XCTAssertNil(collisionOdds(steps: 10, expected: 0))
        XCTAssertNil(workForOdds(1, expected: expected))
        XCTAssertNil(shareOfExpected(steps: 10, expected: 0))
        XCTAssertEqual(shareOfExpected(steps: 150, expected: 100), 1.5)
    }

    func testTheEtaIsPlainDivisionAndNothingWithoutARate() {
        XCTAssertEqual(etaSeconds(steps: 0, expected: 100, rate: 10), 10)
        XCTAssertEqual(etaSeconds(steps: 150, expected: 100, rate: 10), -5)
        XCTAssertNil(etaSeconds(steps: 0, expected: 100, rate: nil))
        XCTAssertNil(etaSeconds(steps: 0, expected: 100, rate: 0))
    }

    func testDenseHoursFillTheGapsEndingAtNow() throws {
        let hour = try JSONDecoder().decode(
            ProgressHour.self,
            from: Data(#"{"hour":"2026-10-03T12:00:00+00:00","claims_paid":1,"units_paid":3,"steps":9}"#.utf8)
        )
        let now = try XCTUnwrap(ISO8601DateFormatter().date(from: "2026-10-03T13:30:00Z"))
        let dense = denseHours([hour], hours: 3, now: now)
        XCTAssertEqual(dense.map(\.hour), [
            "2026-10-03T11:00:00+00:00", "2026-10-03T12:00:00+00:00", "2026-10-03T13:00:00+00:00",
        ])
        XCTAssertEqual(dense.map(\.units_paid), [0, 3, 0])
        XCTAssertTrue(denseHours([], hours: 0, now: now).isEmpty)
    }

    func testTheWorkerCommandNamesThisNodeAndThisObjective() {
        let job = searchJobs["502f5b58881ed1a83b0f882153f78b724bc4319744853d080e8b2134aec661a3"]
        let text = workerCommand(origin: "http://127.0.0.1:8080", id: "sha256:abc", job: job)
        XCTAssertTrue(text.contains("--node http://127.0.0.1:8080"))
        XCTAssertTrue(text.contains("--job examples/certicom-ecdlp/jobs/ecc2k130.json"))
        XCTAssertTrue(text.contains("--objective sha256:abc"))
        XCTAssertTrue(workerCommand(origin: "o", id: "i", job: nil).contains("--job <job document>"))
    }

    // MARK: - Expected cost, the same numbers as ui/lib/jobs.ts

    func testEcc2k130IsTheTwoToTheSixtyPointEightSearch() throws {
        let job = try XCTUnwrap(searchJobs["502f5b58881ed1a83b0f882153f78b724bc4319744853d080e8b2134aec661a3"])
        // docs/design/orbit-piecework.md: about 2^60.81 iterations, 2^25.27
        // steps per orbit, about 2^35.54 orbits.
        XCTAssertEqual(log2(try XCTUnwrap(expectedSteps(job))), 60.81, accuracy: 0.05)
        XCTAssertEqual(log2(try XCTUnwrap(stepsPerUnit(job))), 25.27, accuracy: 0.05)
        XCTAssertEqual(log2(try XCTUnwrap(expectedUnits(job))), 35.54, accuracy: 0.05)
    }

    func testTheSmallJobsMatchTheSite() throws {
        let ecc2k23 = try XCTUnwrap(searchJobs["0ba12ff65fbdf7170cbd1f70732fac3ee6cfb222e0f4bdc8712ed0c162079626"])
        XCTAssertEqual(try XCTUnwrap(expectedSteps(ecc2k23)), 267.6, accuracy: 1)
        XCTAssertEqual(try XCTUnwrap(stepsPerUnit(ecc2k23)), 6.99, accuracy: 0.1)
        let nums50 = try XCTUnwrap(searchJobs["9c69e6f201d15d30f34fa7a2d53409c92a456dcec0e529c4081ec7e1b380c01c"])
        XCTAssertEqual(stepsPerUnit(nums50), 65536)
        XCTAssertEqual(log2(try XCTUnwrap(expectedSteps(nums50))), 25.33, accuracy: 0.05)
        XCTAssertEqual(nums50.unitNoun, "points")
    }

    // MARK: - Formatting, spelled as the site spells it

    func testFormatting() {
        XCTAssertEqual(formatLog2(pow(2, 60.81)), "2^60.81")
        XCTAssertEqual(formatLog2(0), "2^−∞")
        XCTAssertEqual(formatRate(1.4e10), "14.0 G it/s")
        XCTAssertEqual(formatRate(12_345_678), "12.3 M it/s")
        XCTAssertEqual(formatRate(950), "950 it/s")
        XCTAssertEqual(formatRate(nil), "—")
        XCTAssertEqual(formatMagnitude(2.5e15), "2.50 P")
        XCTAssertEqual(formatMagnitude(123_456), "123 k")
        XCTAssertEqual(formatDuration(42), "42 s")
        XCTAssertEqual(formatDuration(12 * 60), "12 min")
        XCTAssertEqual(formatDuration(5400), "1 h 30 min")
        XCTAssertEqual(formatDuration(3 * 86_400 + 4 * 3600), "3 d 4 h")
        XCTAssertEqual(formatDuration(2.5 * 365.25 * 86_400), "2.5 y")
        XCTAssertEqual(formatDuration(-90), "past by 2 min")
        XCTAssertEqual(formatDuration(nil), "—")
        XCTAssertEqual(formatPercent(0), "0%")
        XCTAssertEqual(formatPercent(0.00004), "4.0e-3%")
        XCTAssertEqual(formatPercent(0.0042), "0.420%")
        XCTAssertEqual(formatPercent(0.05), "5.00%")
        XCTAssertEqual(formatPercent(0.5443), "54.4%")
        XCTAssertEqual(formatPercent(nil), "—")
        XCTAssertEqual(formatAge(42), "42 s ago")
        XCTAssertEqual(formatAge(180), "3 min ago")
        XCTAssertEqual(formatAge(7200), "2 h ago")
        XCTAssertEqual(formatAge(3 * 86_400), "3 d ago")
    }
}
