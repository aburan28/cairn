import Foundation
import Darwin

/// The one `cairn run` this app owns: found, started, watched, stopped.
///
/// The app is a window onto a node and nothing more. Everything it shows is
/// the node's own reader, so this type's whole job is the process: which
/// binary, which folder, which ports, is it up yet, and did it die.
@MainActor
final class Node: ObservableObject {
    enum State: Equatable {
        case stopped
        case starting
        case running(URL)
        case failed(String)
    }

    @Published private(set) var state: State = .stopped
    /// The node's stderr, newest last, capped so a long-lived node cannot grow
    /// the app without bound. The whole of it is also in `logFile`.
    @Published private(set) var lines: [String] = []

    /// What this node was last started with: its data folder and the limits
    /// on its work. Read from Settings at each start and kept until the next,
    /// so the window can tell a person that a change they made has not
    /// reached the running node yet.
    @Published private(set) var settings = NodeSettings.current()

    /// Parsed from the node's own log lines as they arrive. Empty until the
    /// node has said so; never invented by the app.
    @Published private(set) var peerId: String?
    @Published private(set) var listenAddress: String?
    /// Recent discovery / session lines, newest last, for the status strip.
    @Published private(set) var networkLines: [String] = []
    @Published private(set) var sessionsOK = 0
    /// The running binary's own version, from the first line of
    /// `cairn --version` ("cairn 1.8.1"). Nil in attach mode, where this app
    /// runs no binary and the reader's page says the node's.
    @Published private(set) var binaryVersion: String?
    /// Drives the Peers sheet from the Node menu and the status popover.
    @Published var presentPeers = false
    @Published var presentTasks = false
    @Published var presentSecrets = false
    @Published var presentNewChallenge = false
    @Published var presentConnectivity = false
    @Published var presentAgents = false
    @Published var presentWork = false
    /// What Work on This Mac… opens on: the objective the reader's page asked
    /// for, or nil from the menu and the toolbar.
    private(set) var workObjective: String?
    /// The one `cairn work` this app runs, against this node or another.
    let worker = Worker()
    /// What New Challenge… opens with: the description the reader's Post a
    /// challenge page handed over, or nil from the Node menu.
    private(set) var challengeBrief: String?

    /// Where the node keeps its log, keys and queue.
    var dataDir: URL { settings.dataFolder }
    var logFile: URL { dataDir.appendingPathComponent("node.log") }
    var workLogFile: URL { dataDir.appendingPathComponent("work.log") }
    /// The node's HTTP side as a worker dials it: the reader's origin
    /// without its path. Nil until the node is up.
    var httpOrigin: String? {
        guard case .running(let url) = state, let host = url.host else { return nil }
        let scheme = url.scheme ?? "http"
        return url.port.map { "\(scheme)://\(host):\($0)" } ?? "\(scheme)://\(host)"
    }
    var identityFile: URL { dataDir.appendingPathComponent("node.identity.json") }
    var hasIdentity: Bool { FileManager.default.fileExists(atPath: identityFile.path) }
    /// True when Settings points at an existing node rather than spawning one.
    var isAttached: Bool { settings.attachURL != nil }

    private(set) var binary: URL?
    private var process: Process?
    /// Held open for the node's whole life. `cairn run` serves MCP on stdio
    /// and stops when stdin closes, so if this app dies without cleaning up --
    /// a crash, a force quit -- the kernel closes the pipe and the node
    /// follows it instead of being left holding the ports and the log's lock.
    private var stdin: Pipe?
    private var sink: Stderr?
    private var stopping = false
    /// The attach-mode probe, so a stop or a second start can cancel it
    /// rather than leave it to set a state nobody asked for.
    private var probe: Task<Void, Never>?

    // MARK: sheets

    /// Open New Challenge…, empty, or with a description to draft from at once.
    func newChallenge(brief: String? = nil) {
        challengeBrief = brief
        presentNewChallenge = true
    }

    /// The reader's way in: open New Challenge… with the description typed
    /// on its Post a challenge page, or return why not, in words the page
    /// shows as they are.
    func draftChallenge(fromPage brief: String) -> String? {
        if isAttached {
            return "This window is showing a node Cairn.app does not run, so there is nowhere here to write its checker. Draft it from the Cairn.app that runs that node."
        }
        guard case .running = state else { return "The node is not running." }
        // SwiftUI shows one sheet at a time; a second is dropped silently.
        if sheetIsOpen { return "Close the sheet that is open in Cairn.app first." }
        newChallenge(brief: brief)
        return nil
    }

    /// Whether any of the window's sheets is up.
    var sheetIsOpen: Bool {
        presentNewChallenge || presentTasks || presentPeers || presentSecrets
            || presentConnectivity || presentAgents || presentWork
    }

    /// Open Work on This Mac…, on `objective` when the page named one.
    func work(on objective: String? = nil) {
        workObjective = objective
        presentWork = true
    }

    /// The reader's Contribute page turning a role on or off: the same
    /// UserDefaults key the Settings toggle writes, then the restart that
    /// Settings would ask for. Returns why not, in words the page shows.
    ///
    /// The page's button has already been confirmed natively by the time
    /// this runs (`PageBridge`), because a page is scriptable and two of
    /// these open a port to the network while the third stakes money.
    func setRole(fromPage role: PageRole, on: Bool) -> String? {
        // Attached to the launchd agent is still this app's node: `restart`
        // rewrites its plist from these settings. Attached to anything else
        // is somebody else's.
        if isAttached, !runsInBackground {
            return "This window is showing a node Cairn.app does not run, so its roles are set where it runs."
        }
        let defaults = UserDefaults.standard
        switch role {
        case .validator:
            defaults.set(on, forKey: NodeSettings.Key.validator)
        case .relay:
            defaults.set(on ? NodeSettings.anyHost : NodeSettings.loopbackHost, forKey: NodeSettings.Key.p2pHost)
        case .workerHost:
            defaults.set(on, forKey: NodeSettings.Key.shareHTTP)
        }
        restart()
        return nil
    }

    /// The reader's pages opening one of this window's sheets. Settings is
    /// the app's own window and is opened by the delegate, not here.
    func open(fromPage sheet: PageSheet, objective: String?) -> String? {
        if sheetIsOpen { return "Close the sheet that is open in Cairn.app first." }
        switch sheet {
        case .agents:
            presentAgents = true
        case .work:
            work(on: objective)
        case .peers:
            presentPeers = true
        case .newChallenge:
            if isAttached {
                return "This window is showing a node Cairn.app does not run, so there is nowhere here to write its checker."
            }
            newChallenge()
        case .settings:
            return "Settings opens from the Cairn menu."
        }
        return nil
    }

    /// Start `cairn work` as the sheet asked, with the key it is paid to
    /// made first if this Mac has none yet. Returns why not, or nil.
    func startWork(_ requested: WorkPlan) -> String? {
        guard let binary = binary ?? Self.locateBinary() else { return "No cairn command was found." }
        do {
            try Self.prepareScratch(settings)
        } catch {
            return "Could not prepare the worker's scratch directory: \(error.localizedDescription)"
        }
        if let identity = requested.identity, !FileManager.default.fileExists(atPath: identity) {
            try? FileManager.default.createDirectory(
                at: URL(fileURLWithPath: identity).deletingLastPathComponent(), withIntermediateDirectories: true)
            let made = Self.runCairn(binary, ["identity", "--out", identity])
            if made.status != 0 {
                return "Could not create the worker's key at \(identity): "
                    + (made.err.isEmpty ? "cairn identity exited \(made.status)" : made.err)
            }
        }
        var plan = requested
        plan.stopFile = dataDir.appendingPathComponent("work-stop-\(UUID().uuidString)").path
        return worker.start(plan, binary: binary, environment: Self.childEnvironment(settings), logFile: workLogFile)
    }

    /// The reader can select an objective, but only the native app chooses
    /// the saved executable and arguments. A page never supplies a command.
    func startWorkFromPage(objective: String) -> String? {
        guard let origin = httpOrigin else { return "The node is not running." }
        guard !worker.isRunning else { return "This Mac is already working. Stop it before changing objectives." }
        let defaults = UserDefaults.standard
        let solver = defaults.string(forKey: "workSolver") ?? ""
        if solver.isEmpty {
            if sheetIsOpen { return "Close the open Cairn window first, then choose a solver." }
            work(on: objective)
            return "Choose a solver in the Work on this Mac window, then press Start."
        }
        let savedName = WorkPlan.cleanName(defaults.string(forKey: "workName") ?? "")
        let plan = WorkPlan(
            node: origin, objective: objective,
            worker: savedName.isEmpty ? WorkPlan.defaultName() : savedName,
            identity: settings.workerIdentity.path, solver: solver,
            solverArguments: WorkPlan.splitArguments(defaults.string(forKey: "workSolverArguments") ?? "")
        )
        return startWork(plan)
    }

    // MARK: finding the binary

    /// The `cairn` to run, in the order a person would expect to win: an
    /// explicit override, then where the installer puts it, then where a
    /// package manager would.
    ///
    /// Deliberately not `$PATH`: an app started from Finder gets a minimal one,
    /// and `~/.local/bin/cairn` from an old install script is the copy most
    /// likely to be stale. And never inside this bundle: its own executable is
    /// `Cairn`, which on the case-insensitive volume nearly every Mac boots
    /// from *is* `cairn`, so a lookup there finds this app, which runs itself,
    /// which runs itself.
    static func locateBinary() -> URL? {
        var candidates: [String] = []
        if let override = ProcessInfo.processInfo.environment["CAIRN_BINARY"], !override.isEmpty {
            candidates.append(override)
        }
        candidates += ["/usr/local/cairn/bin/cairn", "/opt/homebrew/bin/cairn", "/usr/local/bin/cairn"]
        let me = Bundle.main.executableURL?.resolvingSymlinksInPath().standardizedFileURL
        return candidates
            .map { URL(fileURLWithPath: $0).resolvingSymlinksInPath().standardizedFileURL }
            .first { url in
                FileManager.default.isExecutableFile(atPath: url.path) && !Self.sameFile(url, me)
            }
    }

    /// By inode rather than by name, since a name comparison is exactly what
    /// case-insensitivity defeats.
    private static func sameFile(_ a: URL, _ b: URL?) -> Bool {
        guard let b,
              let x = try? FileManager.default.attributesOfItem(atPath: a.path),
              let y = try? FileManager.default.attributesOfItem(atPath: b.path) else { return false }
        return (x[.systemFileNumber] as? UInt64) == (y[.systemFileNumber] as? UInt64)
            && (x[.systemNumber] as? Int) == (y[.systemNumber] as? Int)
    }

    /// `cairn --version`, or nil if it would not run.
    nonisolated static func version(of binary: URL) -> String? {
        let p = Process()
        p.executableURL = binary
        p.arguments = ["--version"]
        let out = Pipe()
        p.standardOutput = out
        p.standardError = FileHandle.nullDevice
        do { try p.run() } catch { return nil }
        let data = out.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        guard p.terminationStatus == 0 else { return nil }
        return String(decoding: data, as: UTF8.self)
    }

    // MARK: lifecycle

    func start() {
        guard process == nil else { return }
        stopping = false
        lines = []
        peerId = nil
        listenAddress = nil
        networkLines = []
        sessionsOK = 0
        binaryVersion = nil
        state = .starting
        settings = NodeSettings.current()

        // Attach mode: no process of our own. Probe the URL and show it, the
        // same way the iOS reader retargets. Resource limits and bootstrap
        // files do not apply — that node already chose them.
        if let attach = settings.attachURL {
            probe?.cancel()
            probe = Task { await waitUntilServing(attach, process: nil) }
            return
        }

        guard let binary = Self.locateBinary() else {
            state = .failed("""
                No cairn command was found. Cairn.app runs the one the installer \
                puts at /usr/local/cairn/bin/cairn; open "Install Cairn.pkg" from \
                the disk image again to put it back.
                """)
            return
        }
        self.binary = binary
        // `cairn run` refuses to start without the embedded reader, with an
        // error that talks about build features. Said here in the app's terms.
        guard let version = Self.version(of: binary) else {
            state = .failed("\(binary.path) does not run.")
            return
        }
        binaryVersion = version.split(separator: "\n").first.map { line in
            var v = String(line).trimmingCharacters(in: .whitespaces)
            if v.hasPrefix("cairn ") { v.removeFirst("cairn ".count) }
            return v
        }
        guard version.range(of: #"(?m)^\s*ui\s+embedded"#, options: .regularExpression) != nil else {
            state = .failed("""
                \(binary.path) was built without the embedded reader, so it has \
                nothing to show in this window. \(version.split(separator: "\n").first ?? "")
                """)
            return
        }

        // Only the default folder is created here. A chosen one that is not
        // there is most likely on a disk that is not connected, and creating
        // it would start a new, empty node on whatever disk the path now
        // lands on -- quietly, and with a new identity.
        if !settings.isDefaultFolder, !FileManager.default.fileExists(atPath: dataDir.path) {
            state = .failed("""
                The data folder \(dataDir.path) is not there. If it is on a disk that \
                is not connected, connect it and try again, or choose another folder \
                in Settings.
                """)
            return
        }
        do {
            try FileManager.default.createDirectory(at: dataDir, withIntermediateDirectories: true)
            try Self.prepareScratch(settings)
        } catch {
            state = .failed("Could not prepare \(dataDir.path): \(error.localizedDescription)")
            return
        }

        // Keys the chosen roles sign with, made before the node starts
        // because it refuses to start naming a key file that is not there.
        if let failure = Self.prepareIdentities(settings, binary: binary) {
            state = .failed(failure)
            return
        }

        // A missing bootstrap file is a dial that never happens, and the node
        // would say so once per file after starting. Refusing here keeps the
        // reason next to the setting that named the path.
        for path in settings.bootstrapFiles {
            guard FileManager.default.fileExists(atPath: path) else {
                state = .failed("""
                    Bootstrap file \(path) is not there. Choose another in Settings, \
                    or remove it from the list.
                    """)
                return
            }
        }

        // The command line's defaults when they are free, so a node started
        // here is where the docs say it is; otherwise any free port, so a
        // second node on this Mac does not stop this one starting. The HTTP
        // half is loopback unless Settings shares the node on the LAN or
        // leads a fleet, which is what lets another machine there run
        // `cairn work` against it; the window reads 127.0.0.1 either way,
        // since 0.0.0.0 includes it. The P2P half uses the host Settings
        // chose -- loopback dials out only; 0.0.0.0 also accepts.
        let http = Self.freePort(preferring: 8080, on: settings.serveHost)
        let p2p = Self.freePort(preferring: 9000, on: settings.p2pHost)
        guard http != 0, p2p != 0 else {
            state = .failed("Could not find a free port for the node to bind.")
            return
        }
        listenAddress = "\(settings.p2pHost):\(p2p)"

        let p = Process()
        p.executableURL = binary
        p.currentDirectoryURL = dataDir
        p.arguments = settings.arguments + [
            "run",
            "--listen", "\(settings.p2pHost):\(p2p)",
            "--serve", "\(settings.serveHost):\(http)",
        ] + settings.runArguments + settings.fleetArguments
        p.environment = Self.childEnvironment(settings)

        let input = Pipe()
        p.standardInput = input
        // stdout is MCP's JSON-RPC channel; this app sends no requests, so the
        // node never writes to it.
        p.standardOutput = FileHandle.nullDevice
        let err = Pipe()
        p.standardError = err

        let sink = Stderr(file: logFile)
        err.fileHandleForReading.readabilityHandler = { [weak self] handle in
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

        do {
            try p.run()
        } catch {
            state = .failed("Could not start \(binary.path): \(error.localizedDescription)")
            return
        }
        process = p
        stdin = input
        self.sink = sink
        let url = URL(string: "http://127.0.0.1:\(http)/ui/")!
        Task { await waitUntilServing(url, process: p) }
    }

    /// Stop the node and wait, briefly, for it to go. Closing stdin is the
    /// node's own "stop" -- the same one `run.sh` and Ctrl-D use -- and the
    /// signals are only for a node that does not listen. Attach mode has no
    /// process to stop.
    ///
    /// This one blocks the main thread for up to seven seconds, which is
    /// right at quit and wrong anywhere a person is looking at the window;
    /// `stop(then:)` is the same stop with the wait on another queue.
    func stop() {
        guard let p = beginStop() else { return }
        Self.reap(p, sink: sink)
        cleanUp()
        state = .stopped
    }

    /// `stop()`, waiting off the main thread, then `next` on it. A second
    /// call while the first is still waiting reaps the same process; only
    /// the first completion to arrive cleans up, and `start()` refuses to
    /// run twice, so two quick Restarts start one node.
    func stop(then next: @escaping () -> Void) {
        guard let p = beginStop() else {
            next()
            return
        }
        let sink = self.sink
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            Node.reap(p, sink: sink)
            DispatchQueue.main.async {
                guard let self else { return }
                if self.process === p {
                    self.cleanUp()
                    self.state = .stopped
                }
                next()
            }
        }
    }

    func restart() {
        if runsInBackground {
            // The service's plist *is* the settings: write it again from what
            // Settings holds now, then start it, then attach.
            guard let binary = binary ?? Self.locateBinary() else {
                state = .failed("No cairn command was found.")
                return
            }
            let settings = NodeSettings.current()
            stop()
            state = .starting
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                let failure: String?
                do {
                    try BackgroundService.stop()
                    if let missing = Self.prepareIdentities(settings, binary: binary) {
                        failure = missing
                    } else {
                        try BackgroundService.install(settings: settings, binary: binary)
                        failure = nil
                    }
                } catch {
                    failure = error.localizedDescription
                }
                DispatchQueue.main.async {
                    guard let self else { return }
                    if let failure { self.state = .failed(failure) } else { self.start() }
                }
            }
            return
        }
        // The spinner, not a frozen window, while the old node goes.
        if process != nil { state = .starting }
        stop { [weak self] in self?.start() }
    }

    // MARK: the background service

    /// True when Settings asked for the launchd agent. This window then
    /// attaches to it and owns no process, so quitting stops nothing.
    var runsInBackground: Bool { NodeSettings.backgroundService }

    /// The log has one writer. Make way for a CLI command that writes it:
    /// stop the child, or stop the service and wait for it to let go.
    private func pauseForWriteLock() {
        stop()
        if runsInBackground { try? BackgroundService.stop() }
    }

    private func resumeAfterWriteLock() {
        if runsInBackground { try? BackgroundService.start() }
        start()
    }

    /// Turn the launchd agent on or off and move this window to the right
    /// side of it: attached to the service, or running a child again.
    /// Completion is on the main actor, with an error or nil.
    func setBackground(_ on: Bool, completion: @escaping (String?) -> Void) {
        let defaults = UserDefaults.standard
        if on {
            guard let binary = binary ?? Self.locateBinary() else {
                completion("No cairn command was found.")
                return
            }
            let settings = NodeSettings.current()
            state = .starting
            stop { [weak self] in
                guard let self else { return }
                do {
                    if let missing = Self.prepareIdentities(settings, binary: binary) {
                        self.start()
                        completion(missing)
                        return
                    }
                    try BackgroundService.install(settings: settings, binary: binary)
                } catch {
                    self.start()
                    completion(error.localizedDescription)
                    return
                }
                defaults.set(true, forKey: NodeSettings.Key.backgroundService)
                defaults.set(BackgroundService.readerURL.absoluteString, forKey: NodeSettings.Key.attachURL)
                self.start()
                completion(nil)
            }
        } else {
            defaults.set(false, forKey: NodeSettings.Key.backgroundService)
            defaults.set("", forKey: NodeSettings.Key.attachURL)
            stop()
            state = .starting
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                let failure: String?
                do {
                    try BackgroundService.uninstall()
                    failure = nil
                } catch {
                    failure = error.localizedDescription
                }
                DispatchQueue.main.async {
                    self?.start()
                    completion(failure)
                }
            }
        }
    }

    /// At launch: the service the person asked for is loaded, or loaded again
    /// if a `launchctl bootout` by hand or a missing plist left it stopped.
    func ensureBackgroundService() {
        guard runsInBackground, let binary = binary ?? Self.locateBinary() else { return }
        if BackgroundService.isInstalled {
            try? BackgroundService.start()
        } else {
            let settings = NodeSettings.current()
            if Self.prepareIdentities(settings, binary: binary) == nil {
                try? BackgroundService.install(settings: settings, binary: binary)
            }
        }
        let attach = UserDefaults.standard.string(forKey: NodeSettings.Key.attachURL) ?? ""
        if attach.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            UserDefaults.standard.set(
                BackgroundService.readerURL.absoluteString, forKey: NodeSettings.Key.attachURL)
        }
    }

    /// The id a fleet is paid to: the public half of the leader identity,
    /// once the node has made it. Workers submit under this.
    var leaderId: String? {
        let path = NodeSettings.current().leaderIdentity
        guard let data = try? Data(contentsOf: path),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return nil }
        return object["public"] as? String
    }

    /// The part of a stop that must happen on the main actor: no more probe,
    /// and the stdin close that asks the node to go.
    private func beginStop() -> Process? {
        probe?.cancel()
        probe = nil
        guard let p = process else {
            state = .stopped
            return nil
        }
        stopping = true
        try? stdin?.fileHandleForWriting.close()
        return p
    }

    /// The waiting part, safe on any queue.
    nonisolated private static func reap(_ p: Process, sink: Stderr?) {
        if !wait(for: p, seconds: 3) {
            p.terminate()
            if !wait(for: p, seconds: 2) {
                kill(p.processIdentifier, SIGKILL)
                _ = wait(for: p, seconds: 1)
            }
        }
        sink?.waitForEnd(seconds: 1)
    }

    /// What every `cairn` this app starts runs with.
    ///
    /// Finder gives an app /usr/bin:/bin:/usr/sbin:/sbin. Verifiers the node
    /// runs want python3 and friends from where people install them. The
    /// limits on its work are the node's own to enforce. One function, so a
    /// checker tested before posting runs under exactly what the node gives
    /// it after.
    nonisolated static func childEnvironment(_ settings: NodeSettings) -> [String: String] {
        var env = ProcessInfo.processInfo.environment
        env["PATH"] = [
            "\(NSHomeDirectory())/.elan/bin", "/opt/homebrew/bin", "/usr/local/bin",
            env["PATH"] ?? "/usr/bin:/bin:/usr/sbin:/sbin",
        ].joined(separator: ":")
        env.merge(settings.environment) { _, chosen in chosen }
        // Installer-launched apps can inherit a PKInstallSandbox TMPDIR that
        // disappears while the node is still running. Every pinned verifier
        // then becomes unavailable before its checker even starts.
        env["TMPDIR"] = settings.dataFolder.appendingPathComponent("tmp", isDirectory: true).path
        // Lean, named the way the node's jail needs it: the toolchain's own
        // binary and its prefix (CAIRN_LEAN, CAIRN_LEAN_ROOT), since elan's
        // proxy and a home-directory toolchain both fail inside the jail.
        // A launcher that set them already (`open --env`) is left alone.
        if env["CAIRN_LEAN"] == nil {
            let (lean, _) = Toolchains.lean(environment: env)
            env.merge(Toolchains.leanEnvironment(lean)) { current, _ in current }
        }
        return env
    }

    /// A stable private parent for verifier workdirs, under the node's data
    /// folder. The child environment only names it; launch paths create it.
    nonisolated static func prepareScratch(_ settings: NodeSettings) throws {
        let dir = settings.dataFolder.appendingPathComponent("tmp", isDirectory: true)
        if !FileManager.default.fileExists(atPath: settings.dataFolder.path) {
            // A chosen folder may be an unmounted disk. Only the default is
            // safe to create on demand for a worker or background service.
            guard settings.isDefaultFolder else { throw CocoaError(.fileNoSuchFile) }
            try FileManager.default.createDirectory(at: settings.dataFolder,
                                                    withIntermediateDirectories: true)
        }
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: dir.path)
    }

    /// `cairn identity --out`: an ed25519 keypair whose public half is the
    /// submitter name, for an agent to sign with. Refuses to overwrite.
    /// Completion is on the main actor.
    func createAgentIdentity(at path: String, completion: @escaping (String?) -> Void) {
        guard let binary = binary ?? Self.locateBinary() else {
            completion("No cairn command was found.")
            return
        }
        DispatchQueue.global(qos: .userInitiated).async {
            let run = Self.runCairn(binary, ["identity", "--out", path])
            DispatchQueue.main.async {
                completion(run.status == 0 ? nil : (run.err.isEmpty ? "cairn identity exited \(run.status)" : run.err))
            }
        }
    }

    // MARK: internals

    private func waitUntilServing(_ url: URL, process p: Process?) async {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 2
        let session = URLSession(configuration: config)
        let attached = p == nil
        let deadline = Date().addingTimeInterval(attached ? 15 : 60)
        while Date() < deadline {
            if Task.isCancelled { return }
            if let p {
                // A spawned node that exited, or was replaced by a restart, is
                // not ours to wait for any more; `exited` has already said why.
                guard process === p, p.isRunning else { return }
            }
            if let (_, response) = try? await session.data(from: url),
               (response as? HTTPURLResponse)?.statusCode == 200 {
                if Task.isCancelled { return }
                if attached || process === p { state = .running(url) }
                return
            }
            try? await Task.sleep(nanoseconds: 250_000_000)
        }
        if Task.isCancelled { return }
        if attached || process === p {
            state = .failed(
                attached
                    ? "Did not reach \(url.absoluteString) within 15s.\n\nIs that node up, and does the URL point at its reader (/ui/)?"
                    : "The node started but did not serve \(url.absoluteString) within a minute."
            )
        }
    }

    private func exited(_ p: Process) {
        // A node `stop` already waited for, or one a restart replaced, has
        // nothing left to say.
        guard p === process, !stopping else { return }
        sink?.waitForEnd(seconds: 1)
        cleanUp()
        let reason = lines.last(where: { !$0.trimmingCharacters(in: .whitespaces).isEmpty })
        state = .failed("The node exited (status \(p.terminationStatus))." + (reason.map { "\n\n\($0)" } ?? ""))
    }

    private func cleanUp() {
        refresh()
        sink = nil
        process = nil
        stdin = nil
    }

    nonisolated private static func wait(for p: Process, seconds: Double) -> Bool {
        let deadline = Date().addingTimeInterval(seconds)
        while p.isRunning && Date() < deadline {
            usleep(50_000)
        }
        return !p.isRunning
    }

    private func refresh() {
        if let sink { lines = sink.snapshot() }
        absorbLog()
    }

    /// Pull peer id, listen confirmation and session counts out of what the
    /// node already wrote. The app never invents a peer id: it is `sha256` of
    /// the transport key the node just loaded, and only the node knows it.
    ///
    /// Rescans the capped tail each time rather than tracking an offset:
    /// `Stderr` drops old lines under load, and an offset into a truncated
    /// buffer would skip the new ones that replaced them.
    private func absorbLog() {
        var id = peerId
        var listen = listenAddress
        var ok = 0
        var net: [String] = []
        for line in lines {
            if id == nil, let r = line.range(of: "peer id ") {
                let rest = line[r.upperBound...].prefix(64)
                if rest.count == 64, rest.allSatisfy(\.isHexDigit) {
                    id = String(rest)
                }
            }
            if line.contains("listening on"),
               let r = line.range(of: "listening on ") {
                let addr = line[r.upperBound...].trimmingCharacters(in: .whitespaces)
                if !addr.isEmpty {
                    listen = String(addr.split(separator: " ").first ?? Substring(addr))
                }
            }
            if (line.contains("inbound session:") || line.contains("outbound session:"))
                && line.contains(" ok") {
                ok += 1
            }
            if line.contains("bootstrap") || line.contains("multicast") || line.contains("beacon")
                || line.contains("session") || line.contains("seeds:") || line.contains("listening on") {
                net.append(line)
            }
        }
        if id != peerId { peerId = id }
        if listen != listenAddress { listenAddress = listen }
        if ok != sessionsOK { sessionsOK = ok }
        if net.count > 40 { net = Array(net.suffix(40)) }
        if net != networkLines { networkLines = net }
    }

    /// `preferred` if nothing on `host` holds it, otherwise a port the kernel
    /// picks; 0 if not even that works. Checked against the same host the
    /// node will bind, so a free loopback port is not mistaken for a free
    /// wildcard one. There is a window between this check and the node
    /// binding, and if something takes it in that window the node says so
    /// and the window shows it.
    nonisolated static func freePort(preferring preferred: UInt16, on host: String) -> UInt16 {
        func bound(_ port: UInt16) -> UInt16 {
            let fd = socket(AF_INET, SOCK_STREAM, 0)
            guard fd >= 0 else { return 0 }
            defer { close(fd) }
            var addr = sockaddr_in()
            addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            addr.sin_family = sa_family_t(AF_INET)
            addr.sin_port = port.bigEndian
            addr.sin_addr.s_addr = inet_addr(host)
            let ok = withUnsafePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) == 0
                }
            }
            guard ok else { return 0 }
            var len = socklen_t(MemoryLayout<sockaddr_in>.size)
            let named = withUnsafeMutablePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    getsockname(fd, $0, &len) == 0
                }
            }
            return named ? UInt16(bigEndian: addr.sin_port) : 0
        }
        let got = bound(preferred)
        return got != 0 ? got : bound(0)
    }

    // MARK: secrets
    //
    // Operator credentials for campaign scripts (AWS keys, DATABASE_URL, …).
    // Outside the node data dir; writing them does not need the log lock.
    // Values go in via `--stdin` so they never appear on argv.

    struct SecretsList {
        var names: [String]
        var dir: String?
    }

    /// One secret's value, from `cairn secret get`, or nil if it is not set.
    /// Held only by the caller, in memory, for as long as it needs it.
    func secretValue(_ name: String) async -> String? {
        guard let binary = binary ?? Self.locateBinary() else { return nil }
        return await Task.detached(priority: .userInitiated) {
            let result = Self.runCairn(binary, ["secret", "get", name])
            return result.status == 0 && !result.out.isEmpty ? result.out : nil
        }.value
    }

    func listSecrets(completion: @escaping (SecretsList?, String?) -> Void) {
        guard let binary = binary ?? Self.locateBinary() else {
            completion(nil, "No cairn command was found.")
            return
        }
        DispatchQueue.global(qos: .userInitiated).async {
            let pathOut = Self.runCairn(binary, ["secret", "path"])
            let listOut = Self.runCairn(binary, ["secret", "list"])
            DispatchQueue.main.async {
                if listOut.status != 0 {
                    completion(nil, listOut.err.isEmpty
                               ? "cairn secret list failed (\(listOut.status))"
                               : listOut.err)
                    return
                }
                let dir = pathOut.status == 0 ? pathOut.out : nil
                let names = listOut.out
                    .split(separator: "\n")
                    .map { String($0).trimmingCharacters(in: .whitespaces) }
                    .filter { !$0.isEmpty && !$0.hasPrefix("(") }
                completion(SecretsList(names: names, dir: dir), nil)
            }
        }
    }

    /// Write a secret by piping the value to `cairn secret set NAME --stdin`.
    func setSecret(name: String, value: String, completion: @escaping (String?) -> Void) {
        guard let binary = binary ?? Self.locateBinary() else {
            completion("No cairn command was found.")
            return
        }
        DispatchQueue.global(qos: .userInitiated).async {
            let p = Process()
            p.executableURL = binary
            p.arguments = ["secret", "set", name, "--stdin"]
            let stdin = Pipe()
            let err = Pipe()
            let out = Pipe()
            p.standardInput = stdin
            p.standardOutput = out
            p.standardError = err
            do { try p.run() } catch {
                DispatchQueue.main.async { completion(error.localizedDescription) }
                return
            }
            // Trailing newline stripped by cairn; send bytes as pasted.
            if let data = value.data(using: .utf8) {
                try? stdin.fileHandleForWriting.write(contentsOf: data)
            }
            try? stdin.fileHandleForWriting.close()
            p.waitUntilExit()
            let text = String(decoding: err.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
                .trimmingCharacters(in: .whitespacesAndNewlines)
            DispatchQueue.main.async {
                if p.terminationStatus == 0 {
                    completion(nil)
                } else {
                    completion(text.isEmpty ? "cairn secret set exited with status \(p.terminationStatus)" : text)
                }
            }
        }
    }

    func deleteSecret(name: String, completion: @escaping (String?) -> Void) {
        guard let binary = binary ?? Self.locateBinary() else {
            completion("No cairn command was found.")
            return
        }
        DispatchQueue.global(qos: .userInitiated).async {
            let result = Self.runCairn(binary, ["secret", "delete", name])
            DispatchQueue.main.async {
                if result.status == 0 {
                    completion(nil)
                } else {
                    completion(result.err.isEmpty
                               ? "cairn secret delete exited with status \(result.status)"
                               : result.err)
                }
            }
        }
    }

    /// Run `cairn fleet ARGS…` against this node's own member registry --
    /// beside its log, in the data folder -- and hand back what it printed,
    /// or why it refused. Membership changes only through these files and the
    /// node's join route, so this works whether or not the node is running.
    /// Completion is on the main actor.
    func fleet(_ args: [String], completion: @escaping (_ output: String?, _ problem: String?) -> Void) {
        guard let binary = binary ?? Self.locateBinary() else {
            completion(nil, "No cairn command was found.")
            return
        }
        let full = ["--data-dir", NodeSettings.current().dataFolder.path, "fleet"] + args
        DispatchQueue.global(qos: .userInitiated).async {
            let run = Self.runCairn(binary, full)
            DispatchQueue.main.async {
                if run.status == 0 {
                    completion(run.out, nil)
                } else {
                    let said = run.err.replacingOccurrences(of: "cairn fleet: ", with: "")
                    completion(nil, said.isEmpty ? "cairn fleet exited with status \(run.status)" : said)
                }
            }
        }
    }

    /// `GET /network` from the node this window runs, or nil when it is not
    /// up. For the Fleet settings: which members are live, and the address a
    /// machine elsewhere would dial.
    func networkFacts() async -> [String: Any]? {
        guard case .running(let reader) = state,
              let url = URL(string: "/network", relativeTo: reader)?.absoluteURL else { return nil }
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 3
        guard let (data, response) = try? await URLSession(configuration: config).data(from: url),
              (response as? HTTPURLResponse)?.statusCode == 200 else { return nil }
        return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
    }

    struct CairnRun: Sendable {
        var status: Int32
        var out: String
        var err: String
    }

    /// Make each key a chosen role signs with, if it is not there yet: the
    /// fleet leader's (paid for its workers' records) and the validator's
    /// (bonded behind every attestation). Made with the same `cairn identity`
    /// a person would run, never overwritten -- each key is the identity the
    /// log's payments, bonds and slashes name. Called before the child starts
    /// *and* before the launch agent is written, because launchd would
    /// otherwise restart a node that refuses to start, forever. Returns what
    /// to tell the person, or nil.
    nonisolated static func prepareIdentities(_ settings: NodeSettings, binary: URL) -> String? {
        let wanted: [(Bool, URL, String, String)] = [
            (settings.leadFleet, settings.leaderIdentity, "the fleet identity", "Lead a fleet"),
            (settings.validator, settings.validatorIdentity, "the validator's key", "the validator role"),
        ]
        for (on, url, what, setting) in wanted where on {
            guard !FileManager.default.fileExists(atPath: url.path) else { continue }
            let made = runCairn(binary, ["identity", "--out", url.path])
            if made.status != 0 {
                return "Could not create \(what) at \(url.path): "
                    + (made.err.isEmpty ? "cairn identity exited \(made.status)" : made.err)
                    + ". Turn off \(setting) in Settings to start without it."
            }
        }
        return nil
    }

    nonisolated static func runCairn(_ binary: URL, _ args: [String]) -> CairnRun {
        let p = Process()
        p.executableURL = binary
        p.arguments = args
        let out = Pipe()
        let err = Pipe()
        p.standardOutput = out
        p.standardError = err
        do { try p.run() } catch {
            return CairnRun(status: -1, out: "", err: error.localizedDescription)
        }
        p.waitUntilExit()
        return CairnRun(
            status: p.terminationStatus,
            out: String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
                .trimmingCharacters(in: .whitespacesAndNewlines),
            err: String(decoding: err.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
                .trimmingCharacters(in: .whitespacesAndNewlines)
        )
    }

    /// Run `cairn gen-bootstrap` against the same binary this app starts.
    /// The file gets a placeholder key; the node warns until the peer's real
    /// one replaces it. Completion is on the main actor.
    func generateBootstrap(addr: String, to url: URL, completion: @escaping (String?) -> Void) {
        guard let binary = binary ?? Self.locateBinary() else {
            completion("No cairn command was found.")
            return
        }
        let p = Process()
        p.executableURL = binary
        p.arguments = ["gen-bootstrap", "--addr", addr, "--out", url.path]
        let err = Pipe()
        p.standardOutput = FileHandle.nullDevice
        p.standardError = err
        DispatchQueue.global(qos: .userInitiated).async {
            do { try p.run() } catch {
                DispatchQueue.main.async { completion(error.localizedDescription) }
                return
            }
            p.waitUntilExit()
            let text = String(decoding: err.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
                .trimmingCharacters(in: .whitespacesAndNewlines)
            DispatchQueue.main.async {
                if p.terminationStatus == 0 {
                    completion(nil)
                } else {
                    completion(text.isEmpty ? "gen-bootstrap exited with status \(p.terminationStatus)" : text)
                }
            }
        }
    }

    /// Post one or more objective JSON files with `cairn post`. Stops a running
    /// node briefly, same as announcing a peer. The files a pin names must
    /// already be under the node's root (`GuiTasks.stage`), or the node admits
    /// an objective it cannot check.
    func postObjectives(at paths: [String], completion: @escaping (String?) -> Void) {
        guard !isAttached || runsInBackground else {
            completion("This window is attached to another node; it cannot write that log.")
            return
        }
        guard let binary = binary ?? Self.locateBinary() else {
            completion("No cairn command was found.")
            return
        }
        for path in paths where !FileManager.default.fileExists(atPath: path) {
            completion("Missing \(path)")
            return
        }
        let wasRunning: Bool = {
            if case .running = state { return true }
            if case .starting = state { return true }
            return false
        }()
        if wasRunning { pauseForWriteLock() }
        let log = dataDir.appendingPathComponent("log/cairn.jsonl")
        let root = dataDir.path
        let posts = paths.map { path in
            ["--log", log.path, "--root", root, "post", path]
        }
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            var lastError: String?
            for args in posts {
                let p = Process()
                p.executableURL = binary
                p.arguments = args
                let err = Pipe()
                p.standardOutput = FileHandle.nullDevice
                p.standardError = err
                do { try p.run() } catch {
                    lastError = error.localizedDescription
                    break
                }
                p.waitUntilExit()
                let text = String(decoding: err.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                if p.terminationStatus != 0 {
                    lastError = text.isEmpty ? "cairn post exited with status \(p.terminationStatus)" : text
                    break
                }
            }
            DispatchQueue.main.async {
                if wasRunning { self?.resumeAfterWriteLock() }
                completion(lastError)
            }
        }
    }

    /// Announce a peer in the log with `cairn peer`. The log has one writer,
    /// so a running node is stopped for the command and started again after.
    func announcePeer(transport: String, addr: String, completion: @escaping (String?) -> Void) {
        guard !isAttached || runsInBackground else {
            completion("This window is attached to another node; it cannot write that log.")
            return
        }
        guard hasIdentity else {
            completion("No identity yet. Start the node once so it can create node.identity.json.")
            return
        }
        guard let binary = binary ?? Self.locateBinary() else {
            completion("No cairn command was found.")
            return
        }
        let wasRunning: Bool = {
            if case .running = state { return true }
            if case .starting = state { return true }
            return false
        }()
        if wasRunning { pauseForWriteLock() }
        let log = dataDir.appendingPathComponent("log/cairn.jsonl")
        let p = Process()
        p.executableURL = binary
        p.arguments = [
            "--log", log.path, "--root", dataDir.path, "peer",
            "--identity", identityFile.path,
            "--transport", transport, "--addr", addr,
        ]
        let err = Pipe()
        p.standardOutput = FileHandle.nullDevice
        p.standardError = err
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            do { try p.run() } catch {
                DispatchQueue.main.async {
                    if wasRunning { self?.resumeAfterWriteLock() }
                    completion(error.localizedDescription)
                }
                return
            }
            p.waitUntilExit()
            let text = String(decoding: err.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
                .trimmingCharacters(in: .whitespacesAndNewlines)
            DispatchQueue.main.async {
                if wasRunning { self?.resumeAfterWriteLock() }
                if p.terminationStatus == 0 {
                    completion(nil)
                } else {
                    completion(text.isEmpty ? "cairn peer exited with status \(p.terminationStatus)" : text)
                }
            }
        }
    }

    /// A transport id is sha256 of a McEliece public key, hex.
    static func isPeerId(_ s: String) -> Bool {
        s.count == 64 && s.allSatisfy(\.isHexDigit)
    }

    /// `host:port`, split at the last colon so `[::1]:9010` works.
    static func isHostPort(_ s: String) -> Bool {
        guard let i = s.lastIndex(of: ":") else { return false }
        let host = s[s.startIndex..<i], port = s[s.index(after: i)...]
        return !host.isEmpty && (UInt16(port).map { $0 != 0 } ?? false)
    }
}

/// The node's stderr, kept off the main actor. Written from the pipe's own
/// queue, straight to `node.log` and a capped tail of lines, so nothing waits
/// on the main actor -- which is blocked in `stop()` exactly when the node
/// says its last words. The window copies the tail; it never owns the text.
final class Stderr: @unchecked Sendable {
    private let lock = NSLock()
    private var handle: FileHandle?
    private var partial = ""
    private var lines: [String] = []
    private var ended = false
    private static let maxLines = 2000

    init(file: URL) {
        // The last run's log is kept beside this one, so the stderr of a node
        // that failed survives the Try Again that starts the next.
        let previous = file.deletingPathExtension().appendingPathExtension("previous.log")
        try? FileManager.default.removeItem(at: previous)
        try? FileManager.default.moveItem(at: file, to: previous)
        FileManager.default.createFile(atPath: file.path, contents: nil)
        handle = try? FileHandle(forWritingTo: file)
    }

    func write(_ data: Data) {
        lock.lock(); defer { lock.unlock() }
        try? handle?.write(contentsOf: data)
        partial += String(decoding: data, as: UTF8.self)
        var parts = partial.components(separatedBy: "\n")
        partial = parts.removeLast()
        lines.append(contentsOf: parts)
        if lines.count > Self.maxLines { lines.removeFirst(lines.count - Self.maxLines) }
    }

    /// End of file: the node, and anything it started, has closed stderr.
    func finish() {
        lock.lock(); defer { lock.unlock() }
        if !partial.isEmpty { lines.append(partial); partial = "" }
        try? handle?.close()
        handle = nil
        ended = true
    }

    /// Once the process has exited its stderr ends promptly, unless a child
    /// it left behind still holds the pipe; then this gives up rather than
    /// hang the app's quit on it.
    func waitForEnd(seconds: Double) {
        let deadline = Date().addingTimeInterval(seconds)
        while Date() < deadline {
            lock.lock(); let done = ended; lock.unlock()
            if done { return }
            usleep(20_000)
        }
    }

    func snapshot() -> [String] {
        lock.lock(); defer { lock.unlock() }
        return partial.isEmpty ? lines : lines + [partial]
    }
}
