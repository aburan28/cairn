import Foundation

/// The node as a launchd agent, so it keeps running when this window is
/// closed and starts again when the person logs in -- if, and only if, they
/// turned that on in Settings.
///
/// Why a plist in `~/Library/LaunchAgents` driven by `launchctl`, rather than
/// `SMAppService`: the service runs the `cairn` command, which lives outside
/// this bundle at whichever of the installer's, Homebrew's or `CAIRN_BINARY`'s
/// paths this Mac has, and `SMAppService` registers a plist sealed inside the
/// bundle at build time, which cannot name a path chosen on the Mac it runs
/// on. A file the person can open in a text editor, under one label, is also
/// the one thing that is inspectable and removable without this app:
/// `launchctl print gui/$UID/org.cairn.node` shows it running.
///
/// The service runs `cairn run --no-mcp`. No MCP on stdin, because launchd's
/// stdin is `/dev/null` and plain `run` stops when stdin closes -- the app's
/// own child relies on exactly that to die with the app. Same data folder,
/// bootstrap files, limits, fleet settings and environment as the node this
/// app would spawn, from the same `NodeSettings`, so switching modes changes
/// who starts the node and nothing about it. The ports are the documented
/// defaults, 9000 and 8080, and while the service runs the window attaches to
/// `http://127.0.0.1:8080/ui/` -- the existing attach mode, which is why
/// quitting the app then stops nothing.
///
/// On macOS 15 and later a process that is not an app cannot ask for the
/// Local Network permission itself. The node under launchd therefore may be
/// denied the LAN beacon silently; Settings says so beside the toggle, and
/// peers through bootstrap files, seeds and port mapping are unaffected.
enum BackgroundService {
    static let label = "org.cairn.node"
    static let httpPort = 8080
    static let p2pPort = 9000

    /// Where the window attaches while the service runs.
    static var readerURL: URL { URL(string: "http://127.0.0.1:\(httpPort)/ui/")! }

    static var plistURL: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/LaunchAgents/\(label).plist")
    }

    /// launchd's per-user domain for this login session.
    static var domain: String { "gui/\(getuid())" }

    enum Failure: LocalizedError {
        case launchctl(String, String)
        case write(String)

        var errorDescription: String? {
            switch self {
            case .launchctl(let verb, let detail):
                return "launchctl \(verb) failed: \(detail)"
            case .write(let detail):
                return "Could not write the launch agent: \(detail)"
            }
        }
    }

    // MARK: the plist

    /// The property list, as a dictionary. Pure, so a test can read back
    /// exactly what would be written.
    static func definition(settings: NodeSettings, binary: URL) -> [String: Any] {
        var arguments: [String] = [binary.path]
        arguments += settings.arguments
        arguments += [
            "run", "--no-mcp",
            "--listen", "\(settings.p2pHost):\(p2pPort)",
            "--serve", "\(settings.serveHost):\(httpPort)",
        ]
        arguments += settings.runArguments
        arguments += settings.fleetArguments
        return [
            "Label": label,
            "ProgramArguments": arguments,
            "WorkingDirectory": settings.dataFolder.path,
            "EnvironmentVariables": serviceEnvironment(settings),
            // Start at login and again whenever it exits; launchd waits ten
            // seconds between restarts of a job that keeps exiting.
            "RunAtLoad": true,
            "KeepAlive": true,
            // stdout is the MCP channel, which --no-mcp leaves silent; the
            // node's log goes to stderr, into the same file the window shows.
            "StandardOutPath": "/dev/null",
            "StandardErrorPath": settings.dataFolder.appendingPathComponent("node.log").path,
            "ExitTimeOut": 20,
        ]
    }

    /// `definition` as XML.
    static func render(settings: NodeSettings, binary: URL) throws -> Data {
        try PropertyListSerialization.data(
            fromPropertyList: definition(settings: settings, binary: binary),
            format: .xml,
            options: 0
        )
    }

    /// The environment the service gets. Deliberately not this app's whole
    /// environment: the PATH the node's verifiers need, the folder-relative
    /// variables, every `CAIRN_*` the settings produce, and nothing else.
    static func serviceEnvironment(_ settings: NodeSettings) -> [String: String] {
        let full = Node.childEnvironment(settings)
        var env: [String: String] = [:]
        for (key, value) in full where key == "PATH" || key == "HOME" || key.hasPrefix("CAIRN_") {
            env[key] = value
        }
        if env["HOME"] == nil { env["HOME"] = NSHomeDirectory() }
        return env
    }

    // MARK: launchctl

    /// Write the plist and start the service. Replaces one already loaded.
    static func install(settings: NodeSettings, binary: URL) throws {
        let data = try render(settings: settings, binary: binary)
        let url = plistURL
        do {
            try FileManager.default.createDirectory(
                at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            try data.write(to: url, options: .atomic)
        } catch {
            throw Failure.write(error.localizedDescription)
        }
        // A service already loaded under this label keeps its old plist until
        // it is booted out; `bootstrap` over it would be refused.
        _ = launchctl(["bootout", "\(domain)/\(label)"])
        let result = launchctl(["bootstrap", domain, url.path])
        if result.status != 0 {
            throw Failure.launchctl("bootstrap", result.text)
        }
    }

    /// Stop the service and leave the plist: a restart will `start()` it.
    static func stop() throws {
        guard isLoaded() else { return }
        let result = launchctl(["bootout", "\(domain)/\(label)"])
        if result.status != 0 && isLoaded() {
            throw Failure.launchctl("bootout", result.text)
        }
        // bootout returns when launchd has accepted the request, not when the
        // node has exited and released the log's lock. Wait for both, briefly.
        let deadline = Date().addingTimeInterval(10)
        while Date() < deadline,
              isLoaded() || PortProbe.connect("127.0.0.1", UInt16(httpPort), timeout: 0.5).isOpen {
            Thread.sleep(forTimeInterval: 0.25)
        }
    }

    /// Start a service whose plist is already written.
    static func start() throws {
        guard FileManager.default.fileExists(atPath: plistURL.path) else { return }
        if isLoaded() { return }
        let result = launchctl(["bootstrap", domain, plistURL.path])
        if result.status != 0 {
            throw Failure.launchctl("bootstrap", result.text)
        }
    }

    /// Stop the service and remove the plist.
    static func uninstall() throws {
        try stop()
        if FileManager.default.fileExists(atPath: plistURL.path) {
            do {
                try FileManager.default.removeItem(at: plistURL)
            } catch {
                throw Failure.write(error.localizedDescription)
            }
        }
    }

    /// Whether launchd has the service loaded (running or waiting to run).
    static func isLoaded() -> Bool {
        launchctl(["print", "\(domain)/\(label)"]).status == 0
    }

    /// Whether a plist is installed, loaded or not.
    static var isInstalled: Bool { FileManager.default.fileExists(atPath: plistURL.path) }

    private static func launchctl(_ arguments: [String]) -> (status: Int32, text: String) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        p.arguments = arguments
        let out = Pipe()
        p.standardOutput = out
        p.standardError = out
        do { try p.run() } catch { return (-1, error.localizedDescription) }
        let data = out.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return (p.terminationStatus, String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines))
    }
}
