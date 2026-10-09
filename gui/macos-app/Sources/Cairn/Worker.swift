import Foundation

/// What one `cairn work` is started with: the Work on This Mac… sheet's
/// fields, as the command line they become.
///
/// Until this existed the Contribute page's answer to "put this machine to
/// work" was a shell line to copy into a terminal, in a window whose whole
/// point is that there is no terminal. The line is the same; the app now
/// runs it.
struct WorkPlan: Equatable {
    /// The node's HTTP address, `http://host:port`. This node's own by
    /// default; another node's when this Mac works for a node elsewhere.
    var node: String
    /// `sha256:…`
    var objective: String
    /// The name on the roster. Cleaned of `|`, which separates the fields of
    /// a commitment's preimage, so `cairn work` would refuse it.
    var worker: String
    /// A key this Mac holds, so the pay lands on it rather than on a bare
    /// name anyone could use. Nil signs nothing and is paid to `worker`.
    var identity: String?
    /// The solver's path and its own arguments.
    var solver: String
    var solverArguments: [String] = []
    /// This app's per-run request marker. The worker drains committed answers
    /// when it appears; the path changes for every start.
    var stopFile: String? = nil

    /// `cairn work …`, as argv after the binary.
    ///
    /// Never `--submitter`: that names a fleet leader so *it* is paid, and
    /// is for a machine on the leader's trusted network. A worker on the
    /// leader's own Mac is on loopback, which a fleet of invited machines
    /// does not trust (`CAIRN_FLEET=enrolled`), and would be refused every
    /// round. A worker here is paid to its own key.
    var arguments: [String] {
        var args = ["work", "--node", node, "--objective", objective,
                    "--worker", worker, "--heartbeat", "5"]
        if let identity { args += ["--identity", identity] }
        if let stopFile { args += ["--stop-file", stopFile] }
        return args + ["--", solver] + solverArguments
    }

    /// Why this cannot start, in the sheet's words, or nil when it can.
    var problem: String? {
        guard let url = URL(string: node), let scheme = url.scheme?.lowercased(),
              scheme == "http" || scheme == "https", url.host != nil
        else { return "The node's address is http://host:port." }
        guard PageRequest.isObjectiveId(objective) else { return "Choose an objective." }
        guard !worker.isEmpty else { return "Give this machine a name." }
        guard !solver.isEmpty else { return "Choose a solver: the program that searches for answers." }
        guard FileManager.default.isExecutableFile(atPath: solver) else {
            return "\(solver) is not a program this Mac can run."
        }
        return nil
    }

    /// A roster name `cairn work` accepts: whitespace and `|` become dashes,
    /// as the Contribute page cleans it before printing the command.
    static func cleanName(_ text: String) -> String {
        text.trimmingCharacters(in: .whitespacesAndNewlines)
            .components(separatedBy: CharacterSet.whitespacesAndNewlines.union(CharacterSet(charactersIn: "|")))
            .filter { !$0.isEmpty }
            .joined(separator: "-")
    }

    /// This Mac's name, as the roster will show it: the hostname without
    /// the `.local` Bonjour suffix, lowercased.
    static func defaultName(host: String = ProcessInfo.processInfo.hostName) -> String {
        var name = host.lowercased()
        if name.hasSuffix(".local") { name.removeLast(".local".count) }
        let cleaned = cleanName(name)
        return cleaned.isEmpty ? "this-mac" : cleaned
    }

    /// The solver's arguments as typed into one field. Split on whitespace,
    /// with single or double quotes keeping an argument together; no other
    /// shell syntax, because nothing here goes through a shell.
    static func splitArguments(_ text: String) -> [String] {
        var args: [String] = []
        var current = ""
        var quote: Character?
        var open = false
        for ch in text {
            if let q = quote {
                if ch == q { quote = nil } else { current.append(ch) }
            } else if ch == "\"" || ch == "'" {
                quote = ch
                open = true
            } else if ch.isWhitespace {
                if open || !current.isEmpty { args.append(current) }
                current = ""
                open = false
            } else {
                current.append(ch)
            }
        }
        if open || !current.isEmpty { args.append(current) }
        return args
    }
}

/// One objective as the sheet lists it, from the node's `GET /objectives`.
struct WorkObjective: Identifiable, Equatable {
    let id: String
    let title: String
    let open: Bool

    /// The open objectives, as the reader's Objectives page would list
    /// them. Settled ones are left out: a worker on one is refused every
    /// round, and the roster never shows it.
    static func parse(_ body: Any) -> [WorkObjective] {
        guard let object = body as? [String: Any],
              let rows = object["objectives"] as? [[String: Any]] else { return [] }
        return rows.compactMap { row in
            guard let id = row["id"] as? String, PageRequest.isObjectiveId(id) else { return nil }
            let open = (row["open"] as? Bool) ?? !((row["settled"] as? Bool) ?? false)
            return WorkObjective(id: id, title: title(goal: row["goal"] as? String,
                                                      statement: row["statement"] as? String, id: id),
                                 open: open)
        }
    }

    /// What `ui/lib/title.ts` calls the objective, near enough: the
    /// statement's first sentence cut to a headline, else the goal without
    /// its `GOAL-` prefix, else the short id. A display string only.
    static func title(goal: String?, statement: String?, id: String) -> String {
        let text = (statement ?? "").split(whereSeparator: \.isWhitespace).joined(separator: " ")
        if !text.isEmpty {
            var first = text
            if let end = text.range(of: #"[.?!](\s|$)"#, options: .regularExpression) {
                first = String(text[..<end.lowerBound])
            }
            if first.count > 96 {
                first = String(first.prefix(95)).trimmingCharacters(in: .whitespaces) + "…"
            }
            return first
        }
        if let goal, !goal.isEmpty {
            let slug = goal.replacingOccurrences(of: #"^GOAL[-_:]"#, with: "", options: [.regularExpression, .caseInsensitive])
            return slug.replacingOccurrences(of: #"[-_]+"#, with: " ", options: .regularExpression)
        }
        let bare = id.dropFirst("sha256:".count)
        return "\(bare.prefix(8))…\(bare.suffix(4))"
    }
}

/// The one `cairn work` this app runs: started from the sheet, watched,
/// stopped with the app.
///
/// Kept apart from `Node` because it is a different process with a different
/// life: the node is up for as long as the window is, and a worker is
/// started and stopped by hand, against this node or another. What it prints
/// goes to `work.log` beside `node.log`, and the sheet shows the tail.
@MainActor
final class Worker: ObservableObject {
    enum State: Equatable {
        case idle
        case running(WorkPlan, since: Date)
        /// It stopped on its own: a refusal no round can change, a solver
        /// that is not there, or `--rounds` reached. `stop()` never lands
        /// here; the sheet says why it ended from the log.
        case exited(WorkPlan, status: Int32)
    }

    @Published private(set) var state: State = .idle
    @Published private(set) var lines: [String] = []
    @Published private(set) var isDraining = false

    private var process: Process?
    private var sink: Stderr?
    private var stopping = false
    private var roundSamples: [(at: Date, completed: Int)] = []

    var isRunning: Bool {
        if case .running = state { return true }
        return false
    }

    /// The plan the sheet last started, for its fields to come back to.
    var lastPlan: WorkPlan? {
        switch state {
        case .idle: return nil
        case .running(let plan, _), .exited(let plan, _): return plan
        }
    }

    /// A small, local-only snapshot for the reader. The rate and payment
    /// still come from the node: this reports only what this app runs.
    func pageStatus() -> [String: Any] {
        switch state {
        case .idle:
            return ["state": "idle"]
        case .exited(let plan, let code):
            return ["state": "exited", "objective": plan.objective,
                    "worker": plan.worker, "exit_code": Int(code),
                    "activity": activity ?? "The worker stopped."]
        case .running(let plan, let since):
            let cpu = process.map { Self.cpuUsage(root: $0.processIdentifier) }
            let completed = Self.completedRounds(in: lines)
            let roundRate = roundsPerMinute(now: Date(), completed: completed)
            return ["state": isDraining ? "stopping" : "running", "objective": plan.objective,
                    "worker": plan.worker,
                    "started_at": ISO8601DateFormatter().string(from: since),
                    "cpu_percent": cpu.map { $0 as Any } ?? NSNull(),
                    "rounds_completed": completed,
                    "rounds_per_minute": roundRate.map { $0 as Any } ?? NSNull(),
                    "activity": activity ?? "Waiting for the first work round."]
        }
    }

    /// The worker writes a round line for every completed solver run. Its
    /// timestamp is fixed by `say` in `cairn work`.
    private static func completedRounds(in lines: [String]) -> Int {
        for line in lines.reversed() {
            let body = line.dropFirst(9)
            guard body.hasPrefix("round ") else { continue }
            let number = body.dropFirst("round ".count)
            let digits = number.prefix(while: { $0.isNumber })
            if number.dropFirst(digits.count).first == ":", let count = Int(digits) {
                return count
            }
        }
        return 0
    }

    /// A rolling completed-round rate remains available for solvers that do
    /// not count their own search steps. It is labelled separately in the UI.
    private func roundsPerMinute(now: Date, completed: Int) -> Double? {
        if let last = roundSamples.last, completed < last.completed { roundSamples = [] }
        roundSamples.removeAll { now.timeIntervalSince($0.at) > 60 }
        roundSamples.append((now, completed))
        guard let base = roundSamples.first,
              now.timeIntervalSince(base.at) >= 10 else { return nil }
        return Double(completed - base.completed) * 60 / now.timeIntervalSince(base.at)
    }

    private var activity: String? {
        lines.reversed().first { line in
            line.contains("committed a candidate") || line.contains("revealed the candidate")
                || line.contains("round ") || line.contains("done:")
        }?.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// macOS reports %CPU per process, with 100 meaning one busy core. Add
    /// the worker's descendants because the search runs in its solver child.
    private static func cpuUsage(root: Int32) -> Double? {
        let command = Process()
        command.executableURL = URL(fileURLWithPath: "/bin/ps")
        command.arguments = ["-axo", "pid=,ppid=,%cpu="]
        let output = Pipe()
        command.standardOutput = output
        command.standardError = FileHandle.nullDevice
        do { try command.run() } catch { return nil }
        let data = output.fileHandleForReading.readDataToEndOfFile()
        command.waitUntilExit()
        guard command.terminationStatus == 0,
              let text = String(data: data, encoding: .utf8) else { return nil }
        return cpuUsage(root: root, ps: text)
    }

    static func cpuUsage(root: Int32, ps: String) -> Double? {
        struct Row { let parent: Int32; let cpu: Double }
        var rows: [Int32: Row] = [:]
        for line in ps.split(separator: "\n") {
            let parts = line.split(whereSeparator: \.isWhitespace)
            guard parts.count == 3, let pid = Int32(parts[0]),
                  let parent = Int32(parts[1]), let cpu = Double(parts[2]),
                  cpu.isFinite, cpu >= 0 else { continue }
            rows[pid] = Row(parent: parent, cpu: cpu)
        }
        guard rows[root] != nil else { return nil }
        var family: Set<Int32> = [root]
        var previous = -1
        while family.count != previous {
            previous = family.count
            for (pid, row) in rows where family.contains(row.parent) { family.insert(pid) }
        }
        return family.reduce(0) { $0 + (rows[$1]?.cpu ?? 0) }
    }

    /// Start `cairn work` with `plan`, or say why not. One at a time: a
    /// second worker with the same name would take the same slice, and one
    /// with another name is another machine's job.
    func start(_ plan: WorkPlan, binary: URL, environment: [String: String], logFile: URL) -> String? {
        guard process == nil else { return "A worker is already running on this Mac. Stop it first." }
        if let problem = plan.problem { return problem }

        let p = Process()
        p.executableURL = binary
        p.arguments = plan.arguments
        // Beside the solver, so a solver that reads its own files by a
        // relative path finds them, as it would from a terminal there.
        p.currentDirectoryURL = URL(fileURLWithPath: plan.solver).deletingLastPathComponent()
        p.environment = environment
        // Nothing to say to it; closing stdin at once keeps a solver that
        // reads past its assignment from waiting on this app.
        p.standardInput = FileHandle.nullDevice
        let out = Pipe()
        p.standardOutput = out
        p.standardError = out

        let sink = Stderr(file: logFile)
        out.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty else {
                handle.readabilityHandler = nil
                sink.finish()
                return
            }
            sink.write(data)
            Task { @MainActor in self?.refresh() }
        }
        p.terminationHandler = { [weak self] proc in
            Task { @MainActor in self?.exited(proc) }
        }
        stopping = false
        isDraining = false
        lines = []
        roundSamples = []
        do {
            try p.run()
        } catch {
            return "Could not start \(binary.path): \(error.localizedDescription)"
        }
        process = p
        self.sink = sink
        state = .running(plan, since: Date())
        return nil
    }

    /// Request a stop after this round and after all committed answers are
    /// revealed. The process remains alive while it waits for the next epoch.
    func requestStop() -> String? {
        guard case .running(let plan, _) = state, process != nil else {
            return "This Mac is not working right now."
        }
        guard let path = plan.stopFile else {
            return "This worker predates safe stopping. Stop it from the native window."
        }
        if isDraining { return nil }
        do {
            try "stop".write(toFile: path, atomically: true, encoding: .utf8)
            isDraining = true
            return nil
        } catch {
            return "Could not request a safe stop: \(error.localizedDescription)"
        }
    }

    /// Force the worker down at app quit. The visible Stop button uses
    /// `requestStop()` so pending answers can be revealed first.
    func stop() {
        guard let p = process else { return }
        stopping = true
        p.interrupt()
        if !Self.wait(for: p, seconds: 2) {
            p.terminate()
            if !Self.wait(for: p, seconds: 2) {
                kill(p.processIdentifier, SIGKILL)
                _ = Self.wait(for: p, seconds: 1)
            }
        }
        sink?.waitForEnd(seconds: 1)
        refresh()
        process = nil
        sink = nil
        if let path = lastPlan?.stopFile { try? FileManager.default.removeItem(atPath: path) }
        isDraining = false
        roundSamples = []
        state = .idle
    }

    private func exited(_ p: Process) {
        guard p === process, !stopping else { return }
        sink?.waitForEnd(seconds: 1)
        refresh()
        let plan = lastPlan
        process = nil
        sink = nil
        if let path = plan?.stopFile { try? FileManager.default.removeItem(atPath: path) }
        isDraining = false
        roundSamples = []
        if let plan { state = .exited(plan, status: p.terminationStatus) } else { state = .idle }
    }

    private func refresh() {
        if let sink { lines = sink.snapshot() }
    }

    nonisolated private static func wait(for p: Process, seconds: Double) -> Bool {
        let deadline = Date().addingTimeInterval(seconds)
        while p.isRunning && Date() < deadline {
            usleep(50_000)
        }
        return !p.isRunning
    }
}
