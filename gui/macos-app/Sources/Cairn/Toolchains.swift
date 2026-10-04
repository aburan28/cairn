import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// The execution environment behind the node's verifiers, as this app finds
/// it on the PATH it gives the node -- so what Settings says is available is
/// what the node is given, not what a Terminal sees.
struct ToolchainReport: Equatable {
    var lean: LeanToolchain?
    /// Why no usable Lean was found, when `lean` is nil.
    var leanProblem: String?
    var python: URL?
    var pythonVersion: String?
    /// Something about this python the node would trip on: a version-manager
    /// shim, which the jail cannot follow.
    var pythonProblem: String?
    /// macOS's seatbelt, which every Mac has; nil would mean a very odd Mac.
    var sandbox: URL?
    var checkedAt: Date
}

/// Lean as the node must be told about it.
///
/// elan's `~/.elan/bin/lean` is a proxy: it reads `$HOME/.elan/settings.toml`
/// to find a toolchain and execs that toolchain's own `bin/lean`. The node's
/// jail scrubs `$HOME` and never allow-lists a runtime root under the home
/// directory, so the proxy fails inside it. The node is therefore given the
/// toolchain's real binary and its prefix (`CAIRN_LEAN`, `CAIRN_LEAN_ROOT`),
/// which is what this type carries.
struct LeanToolchain: Equatable {
    /// What PATH found: the proxy, or the binary itself.
    var found: URL
    /// The toolchain's installation prefix: `bin/lean` and `lib/lean` are
    /// under it.
    var prefix: URL
    var version: String?

    var binary: URL { prefix.appendingPathComponent("bin/lean") }
    var isElan: Bool { found.path.contains("/.elan/") }
    /// Under the home directory, where the jail refuses a runtime root on its
    /// own and `CAIRN_LEAN_ROOT` grants it.
    var underHome: Bool { prefix.standardizedFileURL.path.hasPrefix(NSHomeDirectory() + "/") }
}

enum Toolchains {
    static var elanHome: URL {
        URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent(".elan", isDirectory: true)
    }

    /// Lean's own installer, as its documentation gives it: elan into
    /// `~/.elan`, with the stable toolchain. `-y` answers its one question.
    static let elanInstall = "curl -sSf https://elan.lean-lang.org/elan-init.sh | sh -s -- -y --default-toolchain stable"
    /// The other way, for a Mac with Homebrew: a system prefix the jail
    /// allow-lists by itself.
    static let brewInstall = "brew install lean"

    static func searchPath(_ environment: [String: String]) -> [String] {
        (environment["PATH"] ?? "").split(separator: ":").map(String.init).filter { !$0.isEmpty }
    }

    /// The first executable of that name in the directories given, which is
    /// how the node's own `which` finds it.
    static func locate(_ name: String, in directories: [String]) -> URL? {
        for directory in directories {
            let candidate = URL(fileURLWithPath: directory).appendingPathComponent(name)
            if FileManager.default.isExecutableFile(atPath: candidate.path) { return candidate }
        }
        return nil
    }

    /// Lean on the node's PATH, resolved to a toolchain, or why not.
    ///
    /// An elan proxy is resolved from elan's own settings rather than by
    /// running it: asked anything, a proxy whose toolchain is not downloaded
    /// yet downloads it, which is minutes of network nobody asked for.
    static func lean(environment: [String: String]) -> (LeanToolchain?, String?) {
        guard let found = locate("lean", in: searchPath(environment)) else {
            return (nil, "No Lean toolchain was found on the node's PATH.")
        }
        if found.path.hasPrefix(elanHome.path + "/") {
            guard let prefix = elanToolchainPrefix(elanHome) else {
                return (nil, "elan is installed but has no toolchain downloaded yet. In a Terminal: elan toolchain install stable")
            }
            return (LeanToolchain(found: found, prefix: prefix, version: version(of: prefix.appendingPathComponent("bin/lean"), environment)), nil)
        }
        guard let printed = output(of: found, ["--print-prefix"], environment: environment, timeout: 15),
              !printed.isEmpty
        else {
            return (nil, "\(found.path) did not say where its toolchain is (lean --print-prefix).")
        }
        let prefix = URL(fileURLWithPath: printed, isDirectory: true).standardizedFileURL
        guard FileManager.default.isExecutableFile(atPath: prefix.appendingPathComponent("bin/lean").path) else {
            return (nil, "\(found.path) names \(printed) as its prefix, but there is no bin/lean there.")
        }
        return (LeanToolchain(found: found, prefix: prefix, version: version(of: prefix.appendingPathComponent("bin/lean"), environment)), nil)
    }

    /// The toolchain elan would run: the default named in `settings.toml`,
    /// else any toolchain it has, newest name first.
    static func elanToolchainPrefix(_ home: URL) -> URL? {
        let toolchains = home.appendingPathComponent("toolchains", isDirectory: true)
        var candidates: [URL] = []
        if let settings = try? String(contentsOf: home.appendingPathComponent("settings.toml"), encoding: .utf8),
           let name = defaultToolchain(in: settings) {
            candidates.append(toolchains.appendingPathComponent(elanDirectoryName(name), isDirectory: true))
        }
        let installed = (try? FileManager.default.contentsOfDirectory(at: toolchains, includingPropertiesForKeys: nil)) ?? []
        candidates += installed.sorted { $0.lastPathComponent > $1.lastPathComponent }
        return candidates.first { FileManager.default.isExecutableFile(atPath: $0.appendingPathComponent("bin/lean").path) }
    }

    /// `default_toolchain = "leanprover/lean4:stable"`, from elan's settings.
    static func defaultToolchain(in settings: String) -> String? {
        for line in settings.split(separator: "\n") {
            let text = line.trimmingCharacters(in: .whitespaces)
            guard text.hasPrefix("default_toolchain"), let equals = text.firstIndex(of: "=") else { continue }
            let value = text[text.index(after: equals)...]
                .trimmingCharacters(in: .whitespaces)
                .trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
            return value.isEmpty ? nil : value
        }
        return nil
    }

    /// elan's directory for a toolchain name: `/` becomes `--` and `:` becomes
    /// `---`, so `leanprover/lean4:stable` is `leanprover--lean4---stable`.
    static func elanDirectoryName(_ name: String) -> String {
        name.replacingOccurrences(of: "/", with: "--").replacingOccurrences(of: ":", with: "---")
    }

    /// The two variables the node reads for Lean, for the toolchain found.
    /// `CAIRN_LEAN` names the real binary; `CAIRN_LEAN_ROOT` grants the jail
    /// its prefix, which it needs under a home directory and does no harm
    /// elsewhere.
    static func leanEnvironment(_ toolchain: LeanToolchain?) -> [String: String] {
        guard let toolchain else { return [:] }
        return ["CAIRN_LEAN": toolchain.binary.path, "CAIRN_LEAN_ROOT": toolchain.prefix.path]
    }

    /// Whether a python on this path is a version-manager shim, which
    /// re-execs through a directory under `$HOME` the jail denies.
    static func isShim(_ python: URL) -> Bool {
        let path = python.path
        return path.contains("/shims/") || path.contains("/.pyenv/") || path.contains("/.asdf/")
            || path.contains("/.local/share/mise/")
    }

    static func report(environment: [String: String]) -> ToolchainReport {
        let (lean, leanProblem) = self.lean(environment: environment)
        let python = locate("python3", in: searchPath(environment))
        let pythonVersion = python.flatMap { version(of: $0, environment) }
        let pythonProblem = python.flatMap { url -> String? in
            isShim(url)
                ? "\(url.path) is a version-manager shim, which the node's jail cannot follow; every pinned checker would be unavailable. Put a directly installed python3 (Homebrew's, or python.org's) first."
                : nil
        }
        let sandbox = URL(fileURLWithPath: "/usr/bin/sandbox-exec")
        return ToolchainReport(
            lean: lean,
            leanProblem: leanProblem,
            python: python,
            pythonVersion: pythonVersion,
            pythonProblem: pythonProblem,
            sandbox: FileManager.default.isExecutableFile(atPath: sandbox.path) ? sandbox : nil,
            checkedAt: Date()
        )
    }

    static func version(of binary: URL, _ environment: [String: String]) -> String? {
        output(of: binary, ["--version"], environment: environment, timeout: 15)
    }

    /// The first line `binary args` prints, or nil when it would not run,
    /// failed, said nothing, or took longer than `timeout` seconds.
    static func output(of binary: URL, _ args: [String], environment: [String: String],
                       timeout: TimeInterval) -> String? {
        let p = Process()
        p.executableURL = binary
        p.arguments = args
        p.environment = environment
        let out = Pipe()
        p.standardOutput = out
        p.standardError = FileHandle.nullDevice
        p.standardInput = FileHandle.nullDevice
        do { try p.run() } catch { return nil }
        let watchdog = DispatchWorkItem { if p.isRunning { p.terminate() } }
        DispatchQueue.global().asyncAfter(deadline: .now() + timeout, execute: watchdog)
        let data = out.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        watchdog.cancel()
        guard p.terminationStatus == 0 else { return nil }
        let line = String(decoding: data, as: UTF8.self)
            .split(separator: "\n").first.map { $0.trimmingCharacters(in: .whitespaces) } ?? ""
        return line.isEmpty ? nil : line
    }
}

/// What the running node says it can verify: `GET /verifiers`, which it
/// answers from its own PATH and jail probe. The one report that is about
/// the node rather than about this Mac.
struct NodeVerifiers: Decodable, Equatable {
    struct Tool: Decodable, Equatable {
        var binary: String
        var path: String?
        var available: Bool
        var version: String?
        var granted_root: String?
    }

    struct Sandbox: Decodable, Equatable {
        var mechanism: String
        var jail: Bool
        var required: Bool
    }

    var kinds: [String]
    var toolchains: [String: Tool]
    var sandbox: Sandbox
    var servable: [String]
    var unservable: [String: String]

    var lean: Tool? { toolchains["lean"] }
    var python: Tool? { toolchains["python3"] }
    var servesLean: Bool { servable.contains("lean") }

    /// Asked of the node behind a reader URL. Nil when it does not answer,
    /// or predates the route (nodes before 1.16 answer 404).
    static func fetch(readerURL: URL) async -> NodeVerifiers? {
        guard var parts = URLComponents(url: readerURL, resolvingAgainstBaseURL: false) else { return nil }
        parts.path = "/verifiers"
        parts.query = nil
        guard let url = parts.url else { return nil }
        var request = URLRequest(url: url)
        request.timeoutInterval = 5
        guard let answer = try? await URLSession.shared.data(for: request),
              (answer.1 as? HTTPURLResponse)?.statusCode == 200
        else { return nil }
        return try? JSONDecoder().decode(NodeVerifiers.self, from: answer.0)
    }
}
