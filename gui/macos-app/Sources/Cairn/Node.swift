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

    /// Where the node keeps its log, keys and queue.
    var dataDir: URL { settings.dataFolder }
    var logFile: URL { dataDir.appendingPathComponent("node.log") }

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
        state = .starting
        settings = NodeSettings.current()

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

        // The command line's defaults when they are free, so a node started
        // here is where the docs say it is; otherwise any free port, so a
        // second node on this Mac does not stop this one starting.
        let http = Self.freePort(preferring: 8080)
        let p2p = Self.freePort(preferring: 9000)
        guard http != 0, p2p != 0 else {
            state = .failed("Could not find a free port on 127.0.0.1.")
            return
        }

        let p = Process()
        p.executableURL = binary
        p.currentDirectoryURL = dataDir
        p.arguments = settings.arguments + [
            "run",
            "--listen", "127.0.0.1:\(p2p)",
            "--serve", "127.0.0.1:\(http)",
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
    /// signals are only for a node that does not listen.
    func stop() {
        guard let p = process else { return }
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

    private func waitUntilServing(_ url: URL, process p: Process) async {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 2
        let session = URLSession(configuration: config)
        let deadline = Date().addingTimeInterval(60)
        while Date() < deadline {
            // A node that exited, or was replaced by a restart, is not ours
            // to wait for any more; `exited` has already said why.
            guard process === p, p.isRunning else { return }
            if let (_, response) = try? await session.data(from: url),
               (response as? HTTPURLResponse)?.statusCode == 200 {
                if process === p { state = .running(url) }
                return
            }
            try? await Task.sleep(nanoseconds: 250_000_000)
        }
        if process === p {
            state = .failed("The node started but did not serve \(url.absoluteString) within a minute.")
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

    private func refresh() {
        if let sink { lines = sink.snapshot() }
    }

    private static func wait(for p: Process, seconds: Double) -> Bool {
        let deadline = Date().addingTimeInterval(seconds)
        while p.isRunning && Date() < deadline {
            usleep(50_000)
        }
        return !p.isRunning
    }

    /// `preferred` if nothing on 127.0.0.1 holds it, otherwise a port the
    /// kernel picks; 0 if not even that works. There is a window between this
    /// check and the node binding the port, and if something takes it in that
    /// window the node says so and the window shows it.
    nonisolated static func freePort(preferring preferred: UInt16) -> UInt16 {
        func bound(_ port: UInt16) -> UInt16 {
            let fd = socket(AF_INET, SOCK_STREAM, 0)
            guard fd >= 0 else { return 0 }
            defer { close(fd) }
            var addr = sockaddr_in()
            addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            addr.sin_family = sa_family_t(AF_INET)
            addr.sin_port = port.bigEndian
            addr.sin_addr.s_addr = inet_addr("127.0.0.1")
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
