import Foundation
import Combine
import AppKit
import UserNotifications

// MARK: - files the researcher writes

/// One row of `status.json`: an objective and what the researcher did about it.
struct ObjectiveRow: Identifiable, Decodable, Equatable, Hashable {
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
    var settled_at: String?
    var seconds: Double?
    var epoch: Int?
    var shortId: String { String(id.dropFirst(7).prefix(12)) }
    var title: String { goal ?? shortId }
    /// The Python side writes the researcher's payout under `reward` on a
    /// solved row and the pool on any other row.
    var paid: Int { status == "solved" ? (reward ?? 0) : 0 }
}

/// `status.json`, rewritten by the researcher on every change.
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

/// `progress.json`, rewritten twice a second while a solver runs.
struct Progress: Decodable, Equatable {
    var objective: String
    var engine: String
    var started: Double
    var elapsed: Double
    var line: String
    var done: Bool
}

struct JournalEntry: Identifiable, Equatable {
    let id: Int
    let time: String
    let event: String
    let detail: String
    let fields: [String: String]
    var kind: JournalKind {
        switch event {
        case "settled", "revealed", "rho-solved", "birthday-solved", "posted": return .good
        case "out-of-reach", "no-strategy", "already-posted", "settle-pending": return .muted
        case _ where event.contains("fail") || event.contains("refused") || event.contains("error")
            || event.contains("timeout") || event == "not-submitting": return .bad
        case "committed", "scored", "rho-start", "birthday-start", "compiling": return .active
        default: return .plain
        }
    }
}

enum JournalKind { case good, bad, active, muted, plain }

// MARK: - what the node serves

struct NodeObjective: Decodable, Identifiable {
    var id: String
    var goal: String?
    var statement: String?
    var reward: Int?
    var funder: String?
    var verifier_kind: String?
}

struct ChainInfo: Decodable {
    var height: Int?
    var links: Int?
    var head: String?
    var ledger_head: String?
}

struct FrontierInfo: Decodable, Equatable {
    var claim_id: String?
    var holder: String?
    var score: Int?
    var paid_cumulative: Int?
    var pool_remaining: Int?
}

struct BalanceRow: Identifiable, Equatable {
    var id: String { name }
    var name: String
    var spendable: Int
    var escrowed: Int
}

/// One example objective on disk, a candidate for posting.
struct CatalogItem: Identifiable, Equatable {
    var id: String { path }
    var path: String          // relative to the checkout
    var family: String        // examples/<dir>
    var goal: String
    var reward: Int
    var kind: String
}

/// Free-form JSON leaf, for the peers list.
struct AnyCodable: Decodable {
    init(from decoder: Decoder) throws { _ = try? decoder.singleValueContainer() }
}

/// One row of `autoresearcher.py --plan`: what a sweep would decide for an
/// objective file at the current budget, computed without any compute.
struct PlanRow: Decodable, Equatable {
    var path: String
    var goal: String?
    var strategy: String?
    var decision: String      // solve | decline | none | error
    var reason: String?
    var est_seconds: Double?
}

/// One ledger entry as `/log` serves it.
struct LedgerEntry: Identifiable, Equatable {
    var id: Int { seq }
    var seq: Int
    var kind: String
    var hash: String
    var createdAt: String
    var summary: String
}

struct PeerRow: Identifiable, Equatable {
    var id: String { identity + addr }
    var identity: String
    var addr: String
    var transport: String
    var createdAt: String
}

/// Setup facts the Overview reports before anything can run.
struct SetupCheck: Identifiable {
    var id: String { title }
    var title: String
    var ok: Bool
    var detail: String
}

// MARK: - the model

@MainActor
final class ResearcherModel: ObservableObject {
    // Settings, persisted.
    @Published var root: String { didSet { defaults.set(root, forKey: "root"); rescanCatalog() } }
    @Published var httpAddress: String { didSet { defaults.set(httpAddress, forKey: "http") } }
    @Published var p2pAddress: String { didSet { defaults.set(p2pAddress, forKey: "p2p") } }
    @Published var epochSeconds: Int { didSet { defaults.set(epochSeconds, forKey: "epoch") } }
    @Published var budgetMinutes: Int { didSet { defaults.set(budgetMinutes, forKey: "budget"); replan() } }
    @Published var intervalSeconds: Int { didSet { defaults.set(intervalSeconds, forKey: "interval") } }
    @Published var notifyOnSettle: Bool { didSet { defaults.set(notifyOnSettle, forKey: "notify") } }
    @Published var bootstrapFile: String { didSet { defaults.set(bootstrapFile, forKey: "bootstrap") } }
    @Published var selectedObjectives: Set<String> {
        didSet { defaults.set(Array(selectedObjectives).sorted(), forKey: "selected") }
    }

    // Live state from the researcher's files.
    @Published private(set) var isRunning = false
    @Published private(set) var isBuilding = false
    @Published private(set) var status: Status?
    @Published private(set) var progress: Progress?
    @Published private(set) var journal: [JournalEntry] = []
    @Published private(set) var console: String = ""
    @Published private(set) var lastError: String?
    @Published var infoMessage: String?

    // Live state from the node.
    @Published private(set) var nodeReachable = false
    @Published private(set) var nodeObjectives: [NodeObjective] = []
    @Published private(set) var chain: ChainInfo?
    @Published private(set) var peerCount: Int?
    @Published private(set) var logKinds: [String: Int] = [:]
    @Published private(set) var frontiers: [String: FrontierInfo] = [:]
    @Published private(set) var balances: [BalanceRow] = []

    // The checkout.
    @Published private(set) var catalog: [CatalogItem] = []
    @Published private(set) var checks: [SetupCheck] = []
    @Published private(set) var plan: [String: PlanRow] = [:]     // by catalog path
    @Published private(set) var planning = false

    // More of the node.
    @Published private(set) var ledger: [LedgerEntry] = []
    @Published private(set) var peers: [PeerRow] = []
    @Published private(set) var auditOutput: String?
    @Published private(set) var auditing = false

    // Navigation the panes share: a journal row can open its objective.
    @Published var pane: Pane? = .overview
    @Published var selectedObjective: String?
    @Published var journalFilter: String = ""

    // Wall clock, for the epoch display.
    @Published private(set) var now = Date()

    /// What the node's own log says about finding peers, tailed live.
    struct Discovery: Equatable {
        var multicast: String?          // nil until the node said anything
        var beaconTicks = 0
        var inboundOK = 0
        var outboundOK = 0
        var failures: [String] = []     // last few outbound failures
        var bootstrap: [String] = []    // bootstrap lines, warnings included
        var lines: [String] = []        // last discovery-related lines
    }
    @Published private(set) var discovery = Discovery()
    private var nodeLogOffset: UInt64 = 0

    private let defaults = UserDefaults.standard
    private var process: Process?
    private var timer: AnyCancellable?
    private var journalOffset: UInt64 = 0
    private var journalCount = 0
    private var ticks = 0
    private var binaryProbe: (mtime: Date, hasReader: Bool)?
    private var notifiedClaims = Set<String>()
    private var checking = false

    init() {
        root = defaults.string(forKey: "root") ?? ResearcherModel.guessRoot()
        httpAddress = defaults.string(forKey: "http") ?? "127.0.0.1:8090"
        p2pAddress = defaults.string(forKey: "p2p") ?? "127.0.0.1:9010"
        epochSeconds = defaults.object(forKey: "epoch") as? Int ?? 5
        budgetMinutes = defaults.object(forKey: "budget") as? Int ?? 30
        intervalSeconds = defaults.object(forKey: "interval") as? Int ?? 120
        notifyOnSettle = defaults.object(forKey: "notify") as? Bool ?? true
        bootstrapFile = defaults.string(forKey: "bootstrap") ?? ""
        selectedObjectives = Set(defaults.stringArray(forKey: "selected") ?? [])
        timer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()
            .sink { [weak self] _ in self?.tick() }
        // Nothing here touches the disk: the window must appear before the
        // first file is read, because on an external volume the first read
        // can block on a system consent prompt, and a blocked launch shows
        // the user nothing to consent to. The first tick does the reading.
        rescanCatalog()
        if selectedObjectives.isEmpty {
            Task.detached(priority: .utility) { [scriptDir] in
                let list = ResearcherModel.readList(scriptDir + "/objectives.txt")
                await MainActor.run { if self.selectedObjectives.isEmpty { self.selectedObjectives = Set(list) } }
            }
        }
    }

    nonisolated private static func readList(_ path: String) -> [String] {
        guard let text = try? String(contentsOfFile: path) else { return [] }
        return text.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.hasPrefix("#") }
    }

    // MARK: paths

    var stateDir: String { root + "/.autoresearcher" }
    var scriptDir: String { root + "/research/crypto-autoresearcher" }
    var cairnBinary: String { root + "/bin/cairn" }
    var logPath: String { stateDir + "/cairn.jsonl" }
    var hasCheckout: Bool { FileManager.default.fileExists(atPath: scriptDir + "/autoresearcher.py") }
    var hasBinary: Bool { FileManager.default.isExecutableFile(atPath: cairnBinary) }
    var nodeURL: URL { URL(string: "http://\(httpAddress)/")! }
    var readerURL: URL { URL(string: "http://\(httpAddress)/ui/")! }
    var chainURL: URL { URL(string: "http://\(httpAddress)/chain.html")! }
    func readerURL(for objectiveId: String) -> URL {
        URL(string: "http://\(httpAddress)/ui/challenge/?id=\(objectiveId)")!
    }

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

    // MARK: setup checks

    private func runChecks() {
        guard !checking else { return }
        checking = true
        let root = self.root, scriptDir = self.scriptDir, cairnBinary = self.cairnBinary
        let probe = binaryProbe
        Task.detached(priority: .utility) {
            let fm = FileManager.default
            func tool(_ name: String) -> String? {
                for dir in ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin",
                            "/Library/Frameworks/Python.framework/Versions/Current/bin"] {
                    if fm.isExecutableFile(atPath: dir + "/" + name) { return dir + "/" + name }
                }
                return nil
            }
            var out: [SetupCheck] = []
            let hasCheckout = fm.fileExists(atPath: scriptDir + "/autoresearcher.py")
            out.append(SetupCheck(title: "Checkout", ok: hasCheckout,
                                  detail: hasCheckout ? root : "no research/crypto-autoresearcher under \(root)"))
            let py = tool("python3")
            out.append(SetupCheck(title: "Python 3", ok: py != nil, detail: py ?? "python3 not found on PATH"))
            let cc = tool("cc")
            out.append(SetupCheck(title: "C compiler", ok: cc != nil, detail: cc ?? "install the Command Line Tools"))
            // The binary must carry the embedded reader or `cairn run`
            // refuses to start; its exported site includes this asset
            // path. Read once per modification of the file.
            var newProbe = probe
            if fm.isExecutableFile(atPath: cairnBinary) {
                let mtime = (try? fm.attributesOfItem(atPath: cairnBinary))?[.modificationDate] as? Date ?? .distantPast
                if probe?.mtime != mtime {
                    let has = (try? Data(contentsOf: URL(fileURLWithPath: cairnBinary)))?
                        .range(of: Data("_next/static".utf8)) != nil
                    newProbe = (mtime, has)
                }
                let reader = newProbe?.hasReader ?? false
                out.append(SetupCheck(title: "cairn binary", ok: reader,
                                      detail: reader ? cairnBinary : "built without the embedded reader; cairn run needs make ui-build"))
            } else {
                out.append(SetupCheck(title: "cairn binary", ok: false, detail: "bin/cairn is missing; press Build"))
            }
            let node = tool("node")
            out.append(SetupCheck(title: "Node (for Build)", ok: node != nil, detail: node ?? "needed once, by make ui-build"))
            await MainActor.run {
                self.binaryProbe = newProbe
                self.checks = out
                self.checking = false
            }
        }
    }

    var ready: Bool { checks.prefix(4).allSatisfy { $0.ok } }

    // MARK: catalog

    /// Objective files live at examples/<dir>/objective*.json and, for one
    /// family, examples/<dir>/objectives/*.json. A shallow walk of those two
    /// levels, not a recursive enumeration: examples/ also holds test
    /// corpora, and enumerating them stalled the launch for seconds.
    func rescanCatalog() {
        let base = root + "/examples"
        Task.detached(priority: .utility) {
            let items = ResearcherModel.scanCatalog(base: base)
            await MainActor.run { self.catalog = items; self.replan() }
        }
    }

    /// Ask the researcher what it would decide for every catalog item, at
    /// the current budget. Its own arithmetic, so the Catalog cannot drift
    /// from what a sweep does.
    func replan() {
        guard hasCheckout, !catalog.isEmpty, !planning else { return }
        planning = true
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        p.arguments = ["python3", scriptDir + "/autoresearcher.py", "--plan"] + catalog.map { root + "/" + $0.path }
        p.environment = environment()
        p.currentDirectoryURL = URL(fileURLWithPath: root)
        let pipe = Pipe()
        p.standardOutput = pipe; p.standardError = FileHandle.nullDevice
        p.terminationHandler = { [weak self] _ in
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let rows = (try? JSONDecoder().decode([PlanRow].self, from: data)) ?? []
            Task { @MainActor in
                self?.plan = Dictionary(uniqueKeysWithValues: rows.map { ($0.path, $0) })
                self?.planning = false
            }
        }
        do { try p.run() } catch { planning = false }
    }

    nonisolated private static func scanCatalog(base: String) -> [CatalogItem] {
        let fm = FileManager.default
        var items: [CatalogItem] = []
        for dir in (try? fm.contentsOfDirectory(atPath: base)) ?? [] {
            var candidates: [String] = []
            for name in (try? fm.contentsOfDirectory(atPath: base + "/" + dir)) ?? [] {
                if name.hasPrefix("objective") && name.hasSuffix(".json") { candidates.append(dir + "/" + name) }
                if name == "objectives" {
                    for inner in (try? fm.contentsOfDirectory(atPath: base + "/" + dir + "/objectives")) ?? []
                    where inner.hasPrefix("objective") && inner.hasSuffix(".json") {
                        candidates.append(dir + "/objectives/" + inner)
                    }
                }
            }
            for rel in candidates {
                guard let data = fm.contents(atPath: base + "/" + rel),
                      let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                      let goal = obj["goal"] as? String else { continue }
                let verifier = obj["verifier"] as? [String: Any]
                items.append(CatalogItem(path: "examples/" + rel, family: "examples/" + dir,
                                         goal: goal, reward: obj["reward"] as? Int ?? 0,
                                         kind: verifier?["kind"] as? String ?? "?"))
            }
        }
        return items.sorted { ($0.family, $0.path) < ($1.family, $1.path) }
    }

    /// The list the researcher ships with.
    var researcherDefault: [String] { ResearcherModel.readList(scriptDir + "/objectives.txt") }

    func selectResearcherDefault() { selectedObjectives = Set(researcherDefault) }
    func selectAll() { selectedObjectives = Set(catalog.map(\.path)) }
    func selectNone() { selectedObjectives = [] }

    /// Whether the node already holds this example, by goal.
    func isPosted(_ item: CatalogItem) -> Bool {
        nodeObjectives.contains { $0.goal == item.goal } || rows.contains { $0.goal == item.goal }
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
        if !bootstrapFile.trimmingCharacters(in: .whitespaces).isEmpty { env["AR_BOOTSTRAP"] = bootstrapFile }
        env["PYTHONUNBUFFERED"] = "1"
        let path = env["PATH"] ?? ""
        env["PATH"] = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/Library/Frameworks/Python.framework/Versions/Current/bin:" + path
        return env
    }

    func toggle(once: Bool) {
        if isRunning { stop() } else { start(once: once) }
    }

    func start(once: Bool, only: [String] = []) {
        guard !isRunning, !isBuilding else { return }
        guard ready else {
            lastError = checks.first { !$0.ok }.map { "\($0.title): \($0.detail)" } ?? "not ready"
            return
        }
        // The selection becomes the list the researcher posts. Written to
        // the state directory, not the checkout: the shipped list is code.
        try? FileManager.default.createDirectory(atPath: stateDir, withIntermediateDirectories: true)
        let list = selectedObjectives.sorted().joined(separator: "\n") + "\n"
        try? list.write(toFile: stateDir + "/objectives.txt", atomically: true, encoding: .utf8)
        lastError = nil
        console = ""
        var args = [scriptDir + "/autoresearcher.py", "--post", stateDir + "/objectives.txt"]
        if once { args.append("--once") }
        if !only.isEmpty { args += ["--only"] + only }
        let label = only.isEmpty ? (once ? "one sweep" : "researcher") : "solve \(only.count == 1 ? only[0].prefix(16) : "\(only.count) objectives")"
        launch(executable: "/usr/bin/env", arguments: ["python3"] + args, label: label) { [weak self] in
            self?.isRunning = false
            self?.progress = nil
        }
        isRunning = true
    }

    func stop() {
        guard let p = process, p.isRunning else { isRunning = false; return }
        p.terminate()      // the researcher closes the node's stdin, which stops the node
    }

    func build() {
        guard !isRunning, !isBuilding, hasCheckout else { return }
        lastError = nil
        console = ""
        isBuilding = true
        launch(executable: "/usr/bin/env", arguments: ["make", "-C", root, "ui-build"], label: "make ui-build") { [weak self] in
            self?.isBuilding = false
            self?.binaryProbe = nil
            self?.runChecks()
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
                    self?.lastError = "\(label) exited with status \(proc.terminationStatus); see the Console pane."
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

    func clearConsole() { console = "" }

    /// Quitting must not leave a node holding the port and the lock.
    func terminateChildren() {
        if let p = process, p.isRunning {
            p.terminate()
            p.waitUntilExit()
        }
    }

    func clearError() { lastError = nil }

    // MARK: actions on state

    /// Forget an outcome so the next sweep looks at the objective again.
    /// Only while stopped: the researcher holds its own copy of state.json
    /// while it runs and would write it back over this edit.
    func retry(_ row: ObjectiveRow) {
        guard !isRunning else { lastError = "Stop the researcher first; it owns state.json while it runs."; return }
        let path = stateDir + "/state.json"
        guard let data = FileManager.default.contents(atPath: path),
              var st = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return }
        for key in ["done", "unreachable", "pending"] {
            var section = st[key] as? [String: Any] ?? [:]
            section.removeValue(forKey: row.id)
            st[key] = section
        }
        if let out = try? JSONSerialization.data(withJSONObject: st, options: [.prettyPrinted, .sortedKeys]) {
            try? out.write(to: URL(fileURLWithPath: path))
            infoMessage = "\(row.title) will be looked at again on the next sweep."
            if var s = status, let i = s.objectives.firstIndex(where: { $0.id == row.id }) {
                s.objectives[i].status = "open"; s.objectives[i].reason = nil; s.objectives[i].claim = nil
                status = s
            }
        }
    }

    /// Start over: a fresh log, fresh node keys, no outcomes. The identity
    /// is worth keeping -- it is the name payments went to.
    func resetState(keepIdentity: Bool) {
        guard !isRunning else { lastError = "Stop the researcher first."; return }
        let fm = FileManager.default
        let identity = stateDir + "/researcher.json"
        let saved = keepIdentity ? fm.contents(atPath: identity) : nil
        try? fm.removeItem(atPath: stateDir)
        try? fm.createDirectory(atPath: stateDir, withIntermediateDirectories: true)
        if let saved { fm.createFile(atPath: identity, contents: saved, attributes: [.posixPermissions: 0o600]) }
        status = nil; progress = nil; journal = []; journalOffset = 0; journalCount = 0
        balances = []; frontiers = [:]; discovery = Discovery(); nodeLogOffset = 0
        infoMessage = keepIdentity ? "State cleared; the identity was kept." : "State cleared, identity included."
    }

    /// One sweep restricted to one objective: forget its outcome first so
    /// the sweep looks at it, then run with --only.
    func solveOne(_ row: ObjectiveRow) {
        guard !isRunning else { lastError = "Stop the researcher first."; return }
        if row.status != "open" { retry(row); infoMessage = nil }
        start(once: true, only: [row.id])
    }

    /// Post catalog items to the researcher's log now, with the CLI. Only
    /// while nothing runs: a ledger has one writer, and the node is it.
    func postNow(_ items: [CatalogItem]) {
        guard !isRunning, !isBuilding else { lastError = "Stop the researcher first; the node holds the log's lock."; return }
        guard hasBinary else { lastError = "bin/cairn is missing."; return }
        try? FileManager.default.createDirectory(atPath: stateDir, withIntermediateDirectories: true)
        console = ""
        var argv = ["sh", "-c"]
        let posts = items.map { "\"\(cairnBinary)\" --log \"\(logPath)\" --root \"\(root)\" post \"\(root)/\($0.path)\"" }
        argv.append(posts.joined(separator: "; "))
        isBuilding = true
        launch(executable: "/usr/bin/env", arguments: argv, label: "post \(items.count) objective\(items.count == 1 ? "" : "s")") { [weak self] in
            self?.isBuilding = false
            self?.pollBalances()
            self?.infoMessage = "Posted; the rows appear once a node serves the log."
        }
    }

    /// `cairn audit` re-derives the whole log. Read-only, safe beside the node.
    func audit() {
        guard hasBinary, !auditing else { return }
        auditing = true
        auditOutput = nil
        let p = Process()
        p.executableURL = URL(fileURLWithPath: cairnBinary)
        p.arguments = ["--log", logPath, "--root", root, "audit"]
        p.environment = environment()
        let pipe = Pipe()
        p.standardOutput = pipe; p.standardError = pipe
        p.terminationHandler = { [weak self] proc in
            let text = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            Task { @MainActor in
                self?.auditOutput = text.trimmingCharacters(in: .whitespacesAndNewlines) + (proc.terminationStatus == 0 ? "" : "\n[exit \(proc.terminationStatus)]")
                self?.auditing = false
            }
        }
        do { try p.run() } catch { auditOutput = error.localizedDescription; auditing = false }
    }

    var identityPublic: String? {
        guard let data = FileManager.default.contents(atPath: stateDir + "/researcher.json"),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        return obj["public"] as? String
    }

    func revealIdentityInFinder() {
        NSWorkspace.shared.selectFile(stateDir + "/researcher.json", inFileViewerRootedAtPath: stateDir)
    }

    /// From a journal row to the objective it names.
    func open(objectivePrefix: String) {
        guard let row = rows.first(where: { $0.id.hasPrefix(objectivePrefix) }) else { return }
        selectedObjective = row.id
        pane = .objectives
    }

    func showJournal(for row: ObjectiveRow) {
        journalFilter = String(row.id.prefix(16))
        pane = .journal
    }

    // Epochs are derived from the clock, never stored: epoch = unix / length.
    var epochLength: Int { status?.epoch_seconds ?? epochSeconds }
    var currentEpoch: Int { Int(now.timeIntervalSince1970) / max(1, epochLength) }
    var secondsToNextEpoch: Int { epochLength - Int(now.timeIntervalSince1970) % max(1, epochLength) }
    var pendingReveals: [ObjectiveRow] { rows.filter { $0.status == "committed" } }

    func revealStateInFinder() {
        NSWorkspace.shared.selectFile(nil, inFileViewerRootedAtPath: stateDir)
    }

    /// Score an artifact file against an objective's pinned verifier, via
    /// the CLI's dry run. Read-only, so it is safe while the node runs.
    func score(objectiveId: String, artifact: URL, completion: @escaping (String) -> Void) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: cairnBinary)
        p.arguments = ["--log", logPath, "--root", root, "propose", objectiveId, "--artifact", artifact.path, "--dry-run"]
        p.environment = environment()
        let pipe = Pipe()
        p.standardOutput = pipe; p.standardError = pipe
        p.terminationHandler = { _ in
            let text = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            Task { @MainActor in completion(text) }
        }
        do { try p.run() } catch { completion("could not run cairn: \(error.localizedDescription)") }
    }

    func artifactText(for row: ObjectiveRow) -> String? {
        try? String(contentsOfFile: stateDir + "/artifact-\(row.shortId).json")
    }

    // MARK: polling

    private func tick() {
        ticks += 1
        now = Date()
        readStatus()
        readProgress()
        readJournal()
        readNodeLog()
        probeNode()
        if ticks % 5 == 1 { runChecks() }
        if nodeReachable && ticks % 3 == 0 { pollNode() }
        if ticks % 10 == 2 { pollBalances() }
        if ticks % 5 == 3 { updateDockBadge() }
    }

    private func updateDockBadge() {
        let label = isRunning ? (progress != nil ? "…" : (open.isEmpty ? "" : "\(open.count)")) : ""
        if NSApp.dockTile.badgeLabel != (label.isEmpty ? nil : label) {
            NSApp.dockTile.badgeLabel = label.isEmpty ? nil : label
        }
    }

    private func readStatus() {
        guard let data = FileManager.default.contents(atPath: stateDir + "/status.json") else {
            if status != nil { status = nil }
            return
        }
        if let s = try? JSONDecoder().decode(Status.self, from: data),
           s.updated != status?.updated || s.phase != status?.phase || s.objectives != status?.objectives {
            status = s
        }
    }

    private func readProgress() {
        guard isRunning, let data = FileManager.default.contents(atPath: stateDir + "/progress.json"),
              let p = try? JSONDecoder().decode(Progress.self, from: data), !p.done else {
            if progress != nil { progress = nil }
            return
        }
        if p != progress { progress = p }
    }

    private func readNodeLog() {
        let path = stateDir + "/node.log"
        guard let handle = FileHandle(forReadingAtPath: path) else {
            if discovery != Discovery() { discovery = Discovery(); nodeLogOffset = 0 }
            return
        }
        defer { try? handle.close() }
        let size = (try? handle.seekToEnd()) ?? 0
        if size < nodeLogOffset { discovery = Discovery(); nodeLogOffset = 0 }
        guard size > nodeLogOffset else { return }
        try? handle.seek(toOffset: nodeLogOffset)
        guard let data = try? handle.readToEnd(), let text = String(data: data, encoding: .utf8) else { return }
        var d = discovery
        var consumed = 0
        for line in text.split(separator: "\n", omittingEmptySubsequences: false).dropLast() {
            consumed += line.utf8.count + 1
            let l = String(line)
            if l.contains("cairn node starting") {
                // A fresh node: its discovery starts over, its log does not.
                d = Discovery()
            }
            if l.contains("multicast:") {
                d.multicast = l.contains("Address already in use")
                    ? "beacon port already held by another node on this host; LAN discovery is off for this node"
                    : (l.components(separatedBy: "multicast: ").last ?? l)
            } else if l.contains("listening on") && l.contains("cairn::daemon") && d.multicast == nil {
                d.multicast = "bound; announcing every 30s on 239.255.41.96:47396"
            }
            if l.contains("beacons: heard") { d.beaconTicks += 1 }
            if l.contains("inbound session:") && l.contains(" ok") { d.inboundOK += 1 }
            if l.contains("outbound session:") && l.contains(" ok") { d.outboundOK += 1 }
            if l.contains("outbound session to") || (l.contains("inbound session:") && !l.contains(" ok")) {
                d.failures.append(l); if d.failures.count > 5 { d.failures.removeFirst() }
            }
            if l.contains("bootstrap") { d.bootstrap.append(l); if d.bootstrap.count > 5 { d.bootstrap.removeFirst() } }
            if l.contains("multicast") || l.contains("beacon") || l.contains("session") || l.contains("bootstrap") || l.contains("listening on") {
                d.lines.append(l); if d.lines.count > 40 { d.lines.removeFirst() }
            }
        }
        nodeLogOffset += UInt64(consumed)
        if d != discovery { discovery = d }
    }

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
        var consumed = 0
        for line in text.split(separator: "\n", omittingEmptySubsequences: false).dropLast() {
            consumed += line.utf8.count + 1
            guard let obj = try? JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any] else { continue }
            let t = (obj["t"] as? String) ?? ""
            let event = (obj["event"] as? String) ?? "?"
            var fields: [String: String] = [:]
            for (k, v) in obj where k != "t" && k != "event" { fields[k] = "\(v)" }
            let detail = fields.keys.sorted().map { "\($0)=\(fields[$0]!)" }.joined(separator: "  ")
            journalCount += 1
            let entry = JournalEntry(id: journalCount, time: String(t.suffix(8)), event: event, detail: detail, fields: fields)
            journal.append(entry)
            if event == "settled", isRunning { notifySettled(entry) }
        }
        journalOffset += UInt64(consumed)
        if journal.count > 3000 { journal.removeFirst(journal.count - 3000) }
    }

    private func probeNode() {
        var request = URLRequest(url: nodeURL.appendingPathComponent("health"))
        request.timeoutInterval = 1
        URLSession.shared.dataTask(with: request) { [weak self] _, response, _ in
            let ok = (response as? HTTPURLResponse)?.statusCode == 200
            Task { @MainActor in
                guard let self else { return }
                if self.nodeReachable != ok {
                    self.nodeReachable = ok
                    if ok { self.pollNode() } else { self.nodeObjectives = []; self.chain = nil; self.peerCount = nil; self.logKinds = [:]; self.peers = []; self.ledger = [] }
                }
            }
        }.resume()
    }

    private func fetch<T: Decodable>(_ path: String, as type: T.Type, _ done: @escaping (T) -> Void) {
        var request = URLRequest(url: URL(string: "http://\(httpAddress)\(path)")!)
        request.timeoutInterval = 3
        URLSession.shared.dataTask(with: request) { data, _, _ in
            guard let data, let value = try? JSONDecoder().decode(T.self, from: data) else { return }
            Task { @MainActor in done(value) }
        }.resume()
    }

    private struct ObjectivesDoc: Decodable { var objectives: [NodeObjective] }
    private struct FrontierDoc: Decodable { var frontier: FrontierInfo? }

    private func pollNode() {
        fetch("/objectives", as: ObjectivesDoc.self) { [weak self] doc in
            self?.nodeObjectives = doc.objectives
            for o in doc.objectives {
                self?.fetch("/frontier/\(o.id)", as: FrontierDoc.self) { f in
                    if let fr = f.frontier { self?.frontiers[o.id] = fr } else { self?.frontiers.removeValue(forKey: o.id) }
                }
            }
        }
        fetch("/chain", as: ChainInfo.self) { [weak self] c in self?.chain = c }
        fetch("/peers", as: PeersRawDoc.self) { [weak self] p in
            let rows = p.peers.map { PeerRow(identity: $0.identity ?? "?", addr: $0.addr ?? "", transport: $0.transport ?? "", createdAt: $0.created_at ?? "") }
            self?.peerCount = rows.count
            if rows != self?.peers { self?.peers = rows }
        }
        var request = URLRequest(url: URL(string: "http://\(httpAddress)/log")!)
        request.timeoutInterval = 5
        URLSession.shared.dataTask(with: request) { [weak self] data, _, _ in
            guard let data, let text = String(data: data, encoding: .utf8) else { return }
            var kinds: [String: Int] = [:]
            var entries: [LedgerEntry] = []
            for (i, line) in text.split(separator: "\n").enumerated() {
                guard let obj = try? JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any] else { continue }
                let kind = obj["kind"] as? String ?? "?"
                kinds[kind, default: 0] += 1
                let payload = obj["payload"] as? [String: Any] ?? [:]
                let summary: String
                switch kind {
                case "objective": summary = (payload["goal"] as? String ?? "") + "  reward \(payload["reward"] ?? "")"
                case "commitment": summary = "by \((payload["submitter"] as? String ?? "").prefix(12))  for \((payload["objective_id"] as? String ?? "").prefix(20))"
                case "claim": summary = "by \((payload["submitter"] as? String ?? "").prefix(12))  for \((payload["objective_id"] as? String ?? "").prefix(20))  cites \((payload["cites"] as? [Any])?.count ?? 0)"
                case "verdict": summary = "\(payload["status"] ?? "")  claim \((payload["claim_id"] as? String ?? "").prefix(20))"
                case "settlement": summary = "epoch \(payload["epoch"] ?? "")  paid \(payload["reward"] ?? payload["amount"] ?? "")"
                default: summary = payload.keys.sorted().prefix(4).joined(separator: ", ")
                }
                entries.append(LedgerEntry(seq: obj["seq"] as? Int ?? i + 1, kind: kind,
                                           hash: obj["hash"] as? String ?? "", createdAt: payload["created_at"] as? String ?? "",
                                           summary: summary))
            }
            Task { @MainActor in
                if kinds != self?.logKinds { self?.logKinds = kinds }
                if entries != self?.ledger { self?.ledger = entries }
            }
        }.resume()
    }

    private struct PeerRaw: Decodable { var identity: String?; var addr: String?; var transport: String?; var created_at: String? }
    private struct PeersRawDoc: Decodable { var peers: [PeerRaw] }

    /// `cairn balances` is read-only and takes no lock, so it is safe to run
    /// beside the node. Names come back truncated to eight characters.
    private func pollBalances() {
        guard hasBinary, FileManager.default.fileExists(atPath: logPath) else { if !balances.isEmpty { balances = [] }; return }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: cairnBinary)
        p.arguments = ["--log", logPath, "--root", root, "balances"]
        p.environment = environment()
        let pipe = Pipe()
        p.standardOutput = pipe; p.standardError = FileHandle.nullDevice
        p.terminationHandler = { [weak self] _ in
            let text = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            var rows: [BalanceRow] = []
            for line in text.split(separator: "\n") {
                // "  name  spendable  N  escrowed  M"; tier lines are indented deeper.
                guard line.hasPrefix("  "), !line.hasPrefix("      ") else { continue }
                let parts = line.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
                if parts.count >= 5, parts[1] == "spendable", parts[3] == "escrowed",
                   let s = Int(parts[2]), let e = Int(parts[4]) {
                    rows.append(BalanceRow(name: parts[0], spendable: s, escrowed: e))
                }
            }
            Task { @MainActor in if rows != self?.balances { self?.balances = rows } }
        }
        try? p.run()
    }

    // MARK: notifications

    private func notifySettled(_ e: JournalEntry) {
        guard notifyOnSettle, Bundle.main.bundleIdentifier != nil else { return }
        let key = (e.fields["objective"] ?? "") + (e.fields["reward"] ?? "")
        guard !notifiedClaims.contains(key) else { return }
        notifiedClaims.insert(key)
        let goal = rows.first { $0.id.hasPrefix(e.fields["objective"] ?? "-") }?.goal
        let body = "\(goal ?? e.fields["objective"] ?? "an objective") paid \(e.fields["reward"] ?? "?")"
        let center = UNUserNotificationCenter.current()
        center.requestAuthorization(options: [.alert, .sound]) { granted, _ in
            guard granted else { return }
            let content = UNMutableNotificationContent()
            content.title = "Claim settled"
            content.body = body
            content.sound = .default
            center.add(UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil))
        }
    }

    // MARK: derived

    var rows: [ObjectiveRow] { status?.objectives ?? [] }
    var solved: [ObjectiveRow] { rows.filter { $0.status == "solved" } }
    var unreachable: [ObjectiveRow] { rows.filter { $0.status == "unreachable" } }
    var open: [ObjectiveRow] { rows.filter { $0.status != "solved" && $0.status != "unreachable" } }
    var earned: Int { solved.reduce(0) { $0 + $1.paid } }
    var mySpendable: Int? {
        guard let sub = status?.submitter else { return status?.balance }
        return balances.first { sub.hasPrefix($0.name) }?.spendable ?? status?.balance
    }

    struct EarningPoint: Identifiable { var id: Int; var label: String; var reward: Int; var cumulative: Int }

    /// Cumulative earnings in settlement order, for the chart.
    var earningsSeries: [EarningPoint] {
        var total = 0
        return solved.filter { $0.settled == true }
            .sorted { ($0.settled_at ?? "") < ($1.settled_at ?? "") }
            .enumerated()
            .map { i, r in total += r.paid; return EarningPoint(id: i, label: r.title, reward: r.paid, cumulative: total) }
    }

    func statement(for id: String) -> String? { nodeObjectives.first { $0.id == id }?.statement }
}
