import Foundation
import XCTest
@testable import Cairn

/// Work on This Mac…: the `cairn work` line the sheet starts, and what the
/// reader's Contribute page may ask of the app.
final class WorkTests: XCTestCase {
    private let objective = "sha256:" + String(repeating: "ab", count: 32)

    func testThePlanIsTheCommandTheContributePageUsedToPrint() {
        let plan = WorkPlan(node: "http://127.0.0.1:8080", objective: objective, worker: "garage-gpu",
                            identity: "/Users/x/Library/Application Support/Cairn/worker.identity.json",
                            solver: "/Users/x/solver", solverArguments: ["--threads", "8"])
        XCTAssertEqual(plan.arguments, [
            "work", "--node", "http://127.0.0.1:8080", "--objective", objective,
            "--worker", "garage-gpu", "--heartbeat", "5",
            "--identity", "/Users/x/Library/Application Support/Cairn/worker.identity.json",
            "--", "/Users/x/solver", "--threads", "8",
        ])
        XCTAssertFalse(plan.arguments.contains("--submitter"), "a worker on the leader's own Mac is paid to its own key")
        var safelyStopped = plan
        safelyStopped.stopFile = "/tmp/cairn-stop-unique"
        let flag = safelyStopped.arguments.firstIndex(of: "--stop-file")
        XCTAssertNotNil(flag)
        if let flag { XCTAssertEqual(safelyStopped.arguments[flag + 1], "/tmp/cairn-stop-unique") }
        let unsigned = WorkPlan(node: "http://h:1", objective: objective, worker: "w", identity: nil, solver: "/s")
        XCTAssertEqual(unsigned.arguments, ["work", "--node", "http://h:1", "--objective", objective,
                                          "--worker", "w", "--heartbeat", "5", "--", "/s"])
    }

    func testThePlanRefusesWhatCairnWorkWouldRefuse() throws {
        let solver = FileManager.default.temporaryDirectory.appendingPathComponent("cairn-solver-\(UUID())")
        try Data("#!/bin/sh\n".utf8).write(to: solver)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: solver.path)
        defer { try? FileManager.default.removeItem(at: solver) }

        var plan = WorkPlan(node: "http://127.0.0.1:8080", objective: objective, worker: "w", identity: nil, solver: solver.path)
        XCTAssertNil(plan.problem)
        plan.node = "127.0.0.1:8080"
        XCTAssertNotNil(plan.problem, "a node is dialled by URL")
        plan.node = "http://127.0.0.1:8080"
        plan.objective = "ab"
        XCTAssertNotNil(plan.problem, "an objective is its id")
        plan.objective = objective
        plan.worker = ""
        XCTAssertNotNil(plan.problem)
        plan.worker = "w"
        plan.solver = solver.path + ".missing"
        XCTAssertNotNil(plan.problem, "a solver that is not there would fail every round")
    }

    func testNamesAreCleanedAsThePageCleansThem() {
        XCTAssertEqual(WorkPlan.cleanName("garage gpu"), "garage-gpu")
        XCTAssertEqual(WorkPlan.cleanName(" a|b "), "a-b", "`|` separates the fields of a commitment's preimage")
        XCTAssertEqual(WorkPlan.defaultName(host: "Adams-MacBook-Pro.local"), "adams-macbook-pro")
        XCTAssertEqual(WorkPlan.defaultName(host: ""), "this-mac")
    }

    func testSolverArgumentsSplitLikeAShellWouldWithoutBeingOne() {
        XCTAssertEqual(WorkPlan.splitArguments(""), [])
        XCTAssertEqual(WorkPlan.splitArguments("  --threads 8 "), ["--threads", "8"])
        XCTAssertEqual(WorkPlan.splitArguments("--name 'my solver' --x \"a b\""), ["--name", "my solver", "--x", "a b"])
        XCTAssertEqual(WorkPlan.splitArguments("''"), [""], "an empty quoted argument is still an argument")
        XCTAssertEqual(WorkPlan.splitArguments("$HOME/x"), ["$HOME/x"], "nothing is expanded; nothing here goes through a shell")
    }

    func testTheObjectiveListIsTheNodesOpenOnes() {
        let body: [String: Any] = ["objectives": [
            ["id": objective, "goal": "GOAL-ecc2k-130", "statement": "Find the private key for the ECC2K-130 challenge curve. Details follow.", "open": true],
            ["id": "sha256:" + String(repeating: "cd", count: 32), "goal": "GOAL-x", "statement": "", "settled": true],
            ["id": "not-an-id", "statement": "x", "open": true],
        ]]
        let listed = WorkObjective.parse(body)
        XCTAssertEqual(listed.map(\.id), [objective, "sha256:" + String(repeating: "cd", count: 32)])
        XCTAssertEqual(listed[0].title, "Find the private key for the ECC2K-130 challenge curve")
        XCTAssertTrue(listed[0].open)
        XCTAssertEqual(listed[1].title, "x", "a goal slug without its prefix when the statement is empty")
        XCTAssertFalse(listed[1].open, "`settled` is read when a node older than `open` answers")
        XCTAssertEqual(WorkObjective.title(goal: nil, statement: nil, id: objective), "abababab…abab")
    }

    // MARK: the reader's page

    func testThePageCanTurnARoleOnOrOff() throws {
        XCTAssertEqual(try PageRequest.parse(["kind": "set-role", "role": "validator", "on": true]).get(),
                       .setRole(.validator, on: true))
        XCTAssertEqual(try PageRequest.parse(["kind": "set-role", "role": "relay", "on": false]).get(),
                       .setRole(.relay, on: false))
        XCTAssertEqual(try PageRequest.parse(["kind": "set-role", "role": "worker-host", "on": true]).get(),
                       .setRole(.workerHost, on: true))
        func refused(_ body: Any) -> Bool {
            if case .failure = PageRequest.parse(body) { return true }
            return false
        }
        XCTAssertTrue(refused(["kind": "set-role", "role": "coordinator", "on": true]), "no role the page can name that Settings cannot")
        XCTAssertTrue(refused(["kind": "set-role", "role": "validator"]))
        XCTAssertTrue(refused(["kind": "set-role", "role": "validator", "on": "yes"]))
    }

    func testThePageCanOpenASheetOnAnObjectiveItNamesProperly() throws {
        XCTAssertEqual(try PageRequest.parse(["kind": "open", "sheet": "work", "objective": objective]).get(),
                       .open(.work, objective: objective))
        XCTAssertEqual(try PageRequest.parse(["kind": "open", "sheet": "agents"]).get(), .open(.agents, objective: nil))
        XCTAssertEqual(try PageRequest.parse(["kind": "open", "sheet": "new-challenge"]).get(), .open(.newChallenge, objective: nil))
        func refused(_ body: Any) -> Bool {
            if case .failure = PageRequest.parse(body) { return true }
            return false
        }
        XCTAssertTrue(refused(["kind": "open", "sheet": "terminal"]))
        // The objective reaches a command line; only an id gets that far.
        XCTAssertTrue(refused(["kind": "open", "sheet": "work", "objective": "--rounds 1"]))
        XCTAssertTrue(refused(["kind": "open", "sheet": "work", "objective": "sha256:zz"]))
    }

    func testThePageCanOnlyControlASelectedObjectiveThroughTheApp() throws {
        XCTAssertEqual(try PageRequest.parse(["kind": "work-status"]).get(), .workStatus)
        XCTAssertEqual(try PageRequest.parse(["kind": "start-work", "objective": objective]).get(),
                       .startWork(objective: objective))
        XCTAssertEqual(try PageRequest.parse(["kind": "stop-work"]).get(), .stopWork)
        if case .success = PageRequest.parse(["kind": "start-work", "objective": "--solver /tmp/x"]) {
            XCTFail("a page must not choose an executable")
        }
    }

    @MainActor func testWorkerCPUIncludesItsSolverTree() {
        let ps = """
          20   1  5.0
          21  20 92.5
          22  21 50.0
          30   1 80.0
          """
        XCTAssertEqual(Worker.cpuUsage(root: 20, ps: ps), 147.5)
        XCTAssertNil(Worker.cpuUsage(root: 99, ps: ps))
    }
}
