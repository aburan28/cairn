import Foundation
import Combine

/// One row of `status.json`: an objective and what the researcher did about it.
struct ObjectiveRow: Identifiable, Decodable, Equatable {
    var id: String
    var goal: String?
    var reward: Int?
    var verifier: String?
    var status: String
    var reason: String?
    var strategy: String?
    var claim: String?
    var verdict: String?
    var settled: Bool?
    var epoch: Int?
    // `reward` above is the objective's pool; the researcher's payout for a
    // solved row is written under the same key by the Python side, so a
    // solved row's `reward` is what was paid and an open row's is the pool.
    var shortId: String { String(id.dropFirst(7).prefix(12)) }
}

/// `status.json`, rewritten by the researcher on every change. Reading one
/// file is simpler and more honest than re-deriving state from the journal.
struct Status: Decodable {
    var updated: String
    var phase: String
    var http: String
    var submitter: String?
    var log: String?
    var epoch_seconds: Int?
    var pid: Int?
    var node_pid: Int?
    var balance: Int?
    var objectives: [ObjectiveRow]
}

/// One journal line.
struct JournalEntry: Identifiable, Equatable {
    let id: Int
    let time: String
    let event: String
    let detail: String
}

/// Owns the researcher process, the settings it runs with, and the files it
/// writes. Everything the views show comes from here.
@MainActor
final class ResearcherModel: ObservableObject {
    // Settings, persisted. `root` is the checkout; everything else is
    // relative to it unless overridden.
    @Published var root: String { didSet { defaults.set(root, forKey: "root") } }
    @Published var httpAddress: String { didSet { defaults.set(httpAddress, forKey: "http") } }
    @Published var p2pAddress: String { didSet { defaults.set(p2pAddress, forKey: "p2p") } }
    @Published var epochSeconds: Int { didSet { defaults.set(epochSeconds, forKey: "epoch") } }
    @Published var budgetMinutes: Int { didSet { defaults.set(budgetMinutes, forKey: "budget") } }
    @Published var intervalSeconds: Int { didSet { defaults.set(intervalSeconds, forKey: "interval") } }

    // Live state.
    @Published private(set) var isRunning = false
    @Published private(set) var isBuilding = false
    @Published private(set) var status: Status?
    @Published private(set) var journal: [JournalEntry] = []
    @Published private(set) var console: String = ""
    @Published private(set) var lastError: String?
    @Published private(set) var nodeReachable = false

    private let defaults = UserDefaults.standard
    private var process: Process?
    private var timer: AnyCancellable?
    private var journalOffset: UInt64 = 0
    private var journalCount = 0

    init() {
        root = defaults.string(forKey: "root") ?? ResearcherModel.guessRoot()
        httpAddress = defaults.string(forKey: "http") ?? "127.0.0.1:8090"
        p2pAddress = defaults.string(forKey: "p2p") ?? "127.0.0.1:9010"
        epochSeconds = defaults.object(forKey: "epoch") as? Int ?? 5
        budgetMinutes = defaults.object(forKey: "budget") as? Int ?? 30
        intervalSeconds = defaults.object(forKey: "interval") as? Int ?? 120
        timer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()
            .sink { [weak self] _ in self?.tick() }
        tick()
    }

    // MARK: paths

    var stateDir: String { root + "/.autoresearcher" }
    var scriptDir: String { root + "/research/crypto-autoresearcher" }
    var cairnBinary: String { root + "/bin/cairn" }
    var hasCheckout: Bool { FileManager.default.fileExists(atPath: scriptDir + "/autoresearcher.py") }
    var hasBinary: Bool { FileManager.default.isExecutableFile(atPath: cairnBinary) }
    var nodeURL: URL { URL(string: "http://\(httpAddress)/")! }
    var readerURL: URL { URL(string: "http://\(httpAddress)/ui/")! }
    var chainURL: URL { URL(string: "http://\(httpAddress)/chain.html")! }

    /// Walk up from the app bundle looking for the checkout it was built in,
    /// so a freshly built app opens on the right repository with no setup.
    static func guessRoot() -> String {
        if let env = ProcessInfo.processInfo.environment["AR_ROOT"] { return env }
        var url = Bundle.main.bundleURL
        for _ in 0..<8 {
            url.deleteLastPathComponent()
            if FileManager.default.fileExists(atPath: url.path + "/research/crypto-autoresearcher/autoresearcher.py") {
                return url.path
            }
        }
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        for candidate in [home + "/cairn", home + "/src/cairn", home + "/code/cairn"] {
            if FileManager.default.fileExists(atPath: candidate + "/Cargo.toml") { return candidate }
        }
        return home + "/cairn"
    }

    // MARK: process control

    private func environment() -> [String: String] {
        var env = ProcessInfo.processInfo.environment
        env["AR_ROOT"] = root
        env["AR_STATE"] = stateDir
        env["AR_HTTP"] = httpAddress
        env["AR_P2P"] = p2pAddress
        env["AR_BUDGET_SECONDS"] = String(budgetMinutes * 60)
        env["AR_INTERVAL"] = String(intervalSeconds)
        env["CAIRN_EPOCH_SECONDS"] = String(epochSeconds)
        env["PYTHONUNBUFFERED"] = "1"
        // An app launched from Finder inherits a minimal PATH; python3, cc
        // and make live in the usual places.
        let path = env["PATH"] ?? ""
        env["PATH"] = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/Library/Frameworks/Python.framework/Versions/Current/bin:" + path
        return env
    }

    func toggle(once: Bool) {
        if isRunning { stop() } else { start(once: once) }
    }

    func start(once: Bool) {
        guard !isRunning, !isBuilding else { return }
        guard hasCheckout else {
            lastError = "No checkout at \(root): choose the cairn repository in Settings."
            return
        }
        guard hasBinary else {
            lastError = "bin/cairn is missing: build it first (Researcher ▸ Build cairn, which runs make ui-build and needs Node)."
            return
        }
        lastError = nil
        console = ""
        var args = [scriptDir + "/autoresearcher.py", "--post", scriptDir + "/objectives.txt"]
        if once { args.append("--once") }
        launch(executable: "/usr/bin/env", arguments: ["python3"] + args, label: once ? "one sweep" : "researcher") { [weak self] in
            self?.isRunning = false
        }
        isRunning = true
    }

    func stop() {
        guard let p = process, p.isRunning else { isRunning = false; return }
        // SIGTERM: the researcher closes the node's stdin, which stops it in turn.
        p.terminate()
    }

    func build() {
        guard !isRunning, !isBuilding, hasCheckout else { return }
        lastError = nil
        console = ""
        isBuilding = true
        launch(executable: "/usr/bin/env", arguments: ["make", "-C", root, "ui-build"], label: "make ui-build") { [weak self] in
            self?.isBuilding = false
        }
    }

    private func launch(executable: String, arguments: [String], label: String, onExit: @escaping () -> Void) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: executable)
        p.arguments = arguments
        p.environment = environment()
        p.currentDirectoryURL = URL(fileURLWithPath: root)
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty, let text = String(data: data, encoding: .utf8) else { return }
            Task { @MainActor in self?.append(console: text) }
        }
        p.terminationHandler = { [weak self] proc in
            pipe.fileHandleForReading.readabilityHandler = nil
            Task { @MainActor in
                self?.append(console: "\n[\(label) exited with status \(proc.terminationStatus)]\n")
                if proc.terminationStatus != 0 && proc.terminationReason == .exit {
                    self?.lastError = "\(label) exited with status \(proc.terminationStatus); see the console."
                }
                self?.process = nil
                onExit()
                self?.tick()
            }
        }
        do {
            try p.run()
            process = p
            append(console: "$ \(arguments.joined(separator: " "))\n")
        } catch {
            lastError = "could not start \(label): \(error.localizedDescription)"
            onExit()
        }
    }

    private func append(console text: String) {
        console += text
        if console.count > 200_000 { console = String(console.suffix(150_000)) }
    }

    /// Quitting must not leave a node holding the port and the lock. Called
    /// on the main thread from the app delegate, synchronously, so the
    /// process is really gone before the app is.
    func terminateChildren() {
        if let p = process, p.isRunning {
            p.terminate()
            p.waitUntilExit()
        }
    }

    // MARK: polling

    private func tick() {
        readStatus()
        readJournal()
        probeNode()
    }

    private func readStatus() {
        guard let data = FileManager.default.contents(atPath: stateDir + "/status.json") else {
            status = nil
            return
        }
        if let s = try? JSONDecoder().decode(Status.self, from: data) {
            status = s
        }
    }

    /// Tail the journal incrementally: read only what was appended since the
    /// last tick, and start over if the file shrank (a fresh state directory).
    private func readJournal() {
        let path = stateDir + "/journal.jsonl"
        guard let handle = FileHandle(forReadingAtPath: path) else {
            if !journal.isEmpty { journal = []; journalOffset = 0; journalCount = 0 }
            return
        }
        defer { try? handle.close() }
        let size = (try? handle.seekToEnd()) ?? 0
        if size < journalOffset { journal = []; journalOffset = 0; journalCount = 0 }
        guard size > journalOffset else { return }
        try? handle.seek(toOffset: journalOffset)
        guard let data = try? handle.readToEnd(), let text = String(data: data, encoding: .utf8) else { return }
        // Only complete lines; a partially written last line waits for the next tick.
        var consumed = 0
        for line in text.split(separator: "\n", omittingEmptySubsequences: false).dropLast() {
            consumed += line.utf8.count + 1
            guard let obj = try? JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any] else { continue }
            let t = (obj["t"] as? String) ?? ""
            let event = (obj["event"] as? String) ?? "?"
            let detail = obj.keys.sorted().filter { $0 != "t" && $0 != "event" }
                .map { "\($0)=\(obj[$0].map { "\($0)" } ?? "")" }.joined(separator: "  ")
            journalCount += 1
            journal.append(JournalEntry(id: journalCount, time: String(t.suffix(8)), event: event, detail: detail))
        }
        journalOffset += UInt64(consumed)
        if journal.count > 2000 { journal.removeFirst(journal.count - 2000) }
    }

    private func probeNode() {
        var request = URLRequest(url: nodeURL.appendingPathComponent("health"))
        request.timeoutInterval = 1
        URLSession.shared.dataTask(with: request) { [weak self] _, response, _ in
            let ok = (response as? HTTPURLResponse)?.statusCode == 200
            Task { @MainActor in
                if self?.nodeReachable != ok { self?.nodeReachable = ok }
            }
        }.resume()
    }

    func clearError() { lastError = nil }

    // MARK: derived

    var solved: [ObjectiveRow] { status?.objectives.filter { $0.status == "solved" } ?? [] }
    var unreachable: [ObjectiveRow] { status?.objectives.filter { $0.status == "unreachable" } ?? [] }
    var open: [ObjectiveRow] { status?.objectives.filter { $0.status != "solved" && $0.status != "unreachable" } ?? [] }
    var earned: Int { solved.reduce(0) { $0 + ($1.reward ?? 0) } }
}
