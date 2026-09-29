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
    /// Drives the Peers sheet from the Node menu and the toolbar.
    @Published var presentPeers = false

    /// Where the node keeps its log, keys and queue.
    var dataDir: URL { settings.dataFolder }
    var logFile: URL { dataDir.appendingPathComponent("node.log") }
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
        state = .starting
        settings = NodeSettings.current()

        // Attach mode: no process of our own. Probe the URL and show it, the
        // same way the iOS reader retargets. Resource limits and bootstrap
        // files do not apply — that node already chose them.
        if let attach = settings.attachURL {
            Task { await waitUntilServing(attach, process: nil) }
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
        } catch {
            state = .failed("Could not create \(dataDir.path): \(error.localizedDescription)")
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
        // half stays on loopback: the window is the reader, and serving it
        // past this Mac is a different product. The P2P half uses the host
        // Settings chose -- loopback dials out only; 0.0.0.0 also accepts.
        let http = Self.freePort(preferring: 8080, on: NodeSettings.loopbackHost)
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
            "--serve", "\(NodeSettings.loopbackHost):\(http)",
        ]
        // Finder gives an app /usr/bin:/bin:/usr/sbin:/sbin. Verifiers the
        // node runs want python3 and friends from where people install them.
        var env = ProcessInfo.processInfo.environment
        env["PATH"] = ["/opt/homebrew/bin", "/usr/local/bin", env["PATH"] ?? "/usr/bin:/bin:/usr/sbin:/sbin"]
            .joined(separator: ":")
        // The limits on its work, which the node enforces itself.
        env.merge(settings.environment) { _, chosen in chosen }
        p.environment = env

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
    func stop() {
        guard let p = process else {
            state = .stopped
            return
        }
        stopping = true
        try? stdin?.fileHandleForWriting.close()
        if !Self.wait(for: p, seconds: 3) {
            p.terminate()
            if !Self.wait(for: p, seconds: 2) {
                kill(p.processIdentifier, SIGKILL)
                _ = Self.wait(for: p, seconds: 1)
            }
        }
        sink?.waitForEnd(seconds: 1)
        cleanUp()
        state = .stopped
    }

    func restart() {
        stop()
        start()
    }

    // MARK: internals

    private func waitUntilServing(_ url: URL, process p: Process?) async {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 2
        let session = URLSession(configuration: config)
        let attached = p == nil
        let deadline = Date().addingTimeInterval(attached ? 15 : 60)
        while Date() < deadline {
            if let p {
                // A spawned node that exited, or was replaced by a restart, is
                // not ours to wait for any more; `exited` has already said why.
                guard process === p, p.isRunning else { return }
            }
            if let (_, response) = try? await session.data(from: url),
               (response as? HTTPURLResponse)?.statusCode == 200 {
                if attached || process === p { state = .running(url) }
                return
            }
            try? await Task.sleep(nanoseconds: 250_000_000)
        }
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

    private static func wait(for p: Process, seconds: Double) -> Bool {
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

    /// Announce a peer in the log with `cairn peer`. The log has one writer,
    /// so a running node is stopped for the command and started again after.
    func announcePeer(transport: String, addr: String, completion: @escaping (String?) -> Void) {
        guard !isAttached else {
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
        if wasRunning { stop() }
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
                    if wasRunning { self?.start() }
                    completion(error.localizedDescription)
                }
                return
            }
            p.waitUntilExit()
            let text = String(decoding: err.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
                .trimmingCharacters(in: .whitespacesAndNewlines)
            DispatchQueue.main.async {
                if wasRunning { self?.start() }
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
