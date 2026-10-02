import Foundation

/// What the node may take from this Mac, where it keeps its data, and how it
/// reaches the network.
///
/// Read from UserDefaults at each start; the Settings window writes the same
/// keys. The app enforces none of it itself. Every limit and dial hint is one
/// the node already has -- a flag, an environment variable, or a `--bootstrap`
/// any `cairn run` accepts -- so what this window promises is exactly what the
/// command line does, and a limit cannot work here and be missing there.
struct NodeSettings: Equatable {
    enum Key {
        static let dataFolder = "dataFolder"
        static let cpus = "cpuLimit"
        static let limitMemory = "limitMemory"
        static let memoryGB = "memoryLimitGB"
        static let limitStorage = "limitStorage"
        static let storageGB = "storageLimitGB"
        static let p2pHost = "p2pHost"
        static let bootstrap = "bootstrap"
        /// Empty = this app runs the node. Non-empty = open that reader's URL
        /// and do not spawn `cairn run`. Same idea as the iOS reader's
        /// retargetable node URL.
        static let attachURL = "attachURL"
    }

    /// The node's own default cap, 4096 MiB, so a person who never opens
    /// Settings gets what `cairn run` gives.
    static let defaultMemoryGB = 4
    static let defaultStorageGB = 50

    /// Loopback: the node dials out and nothing dials in. The release's
    /// default, because an app that suddenly accepts connections on every
    /// interface is a surprise; Settings is where that becomes a choice.
    static let loopbackHost = "127.0.0.1"
    /// Bind every interface. Put the public or LAN address in a bootstrap
    /// file you hand out -- the listen address is never itself a dial hint
    /// (a cloud public IP is not on any local interface).
    static let anyHost = "0.0.0.0"

    /// Where the data lives unless a person chose somewhere else. One fixed
    /// folder rather than "wherever you started it", because an app has no
    /// working directory a person chose.
    static let defaultDataFolder: URL = FileManager.default
        .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        .appendingPathComponent("Cairn", isDirectory: true)

    static var cores: Int { max(1, ProcessInfo.processInfo.activeProcessorCount) }
    static var physicalMemoryGB: Int { max(1, Int(ProcessInfo.processInfo.physicalMemory >> 30)) }

    var dataFolder: URL
    /// Cores a verifier may keep busy. 0 is every core.
    var cpus: Int
    /// MiB a pinned checker may use. 0 is no cap.
    var memoryMB: Int
    /// GB (10^9, as Finder counts) the data folder may hold. 0 is no cap.
    var storageGB: Int
    /// Host half of `--listen`. Port is chosen at start.
    var p2pHost: String
    /// `--bootstrap` files, in the order given. Dial hints only; the handshake
    /// authenticates the key, not the socket that answered.
    var bootstrapFiles: [String]
    /// When set, the app is a window onto this URL and owns no process.
    var attachURL: URL?

    var isDefaultFolder: Bool {
        dataFolder.standardizedFileURL.path == Self.defaultDataFolder.standardizedFileURL.path
    }

    /// True when the p2p port is loopback: the node can dial peers, and nobody
    /// outside this Mac can dial it.
    var listensLocallyOnly: Bool {
        p2pHost == Self.loopbackHost || p2pHost == "localhost" || p2pHost.hasPrefix("127.")
    }

    var isAttached: Bool { attachURL != nil }

    /// Registered before every read, so an unset key reads as its default
    /// rather than as `false` or `0` -- which for the memory cap would
    /// silently mean "no cap". Registering is an in-memory write and costs
    /// nothing worth caching.
    private static var registeredDefaults: [String: Any] {
        [
            Key.dataFolder: "",
            Key.cpus: 0,
            Key.limitMemory: true,
            Key.memoryGB: defaultMemoryGB,
            Key.limitStorage: false,
            Key.storageGB: defaultStorageGB,
            Key.p2pHost: loopbackHost,
            Key.bootstrap: "",
            Key.attachURL: "",
        ]
    }

    static func current(_ defaults: UserDefaults = .standard) -> NodeSettings {
        defaults.register(defaults: registeredDefaults)
        let path = defaults.string(forKey: Key.dataFolder) ?? ""
        let cpus = defaults.integer(forKey: Key.cpus)
        let host = defaults.string(forKey: Key.p2pHost) ?? loopbackHost
        let attach = (defaults.string(forKey: Key.attachURL) ?? "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return NodeSettings(
            dataFolder: path.isEmpty ? defaultDataFolder : URL(fileURLWithPath: path, isDirectory: true),
            // A count at or past this Mac's cores caps nothing; say so as 0.
            cpus: (1..<cores).contains(cpus) ? cpus : 0,
            memoryMB: defaults.bool(forKey: Key.limitMemory)
                ? max(1, defaults.integer(forKey: Key.memoryGB)) * 1024 : 0,
            storageGB: defaults.bool(forKey: Key.limitStorage)
                ? max(1, defaults.integer(forKey: Key.storageGB)) : 0,
            // Anything other than the two documented choices falls back to
            // loopback: a free-form host that is not on this Mac would refuse
            // to bind at start with a message most people would not expect
            // from typing an address into Settings.
            p2pHost: host == anyHost ? anyHost : loopbackHost,
            bootstrapFiles: Self.parseBootstrap(defaults.string(forKey: Key.bootstrap) ?? ""),
            attachURL: Self.parseAttachURL(attach)
        )
    }

    /// Accept `http://host:port` or `http://host:port/ui/`; store the reader
    /// URL the WebView will load. Reject anything that is not http(s).
    static func parseAttachURL(_ raw: String) -> URL? {
        guard !raw.isEmpty, let url = URL(string: raw),
              let scheme = url.scheme?.lowercased(),
              scheme == "http" || scheme == "https",
              url.host != nil
        else { return nil }
        var parts = URLComponents(url: url, resolvingAgainstBaseURL: false)
        let path = parts?.path ?? ""
        if path.isEmpty || path == "/" {
            parts?.path = "/ui/"
        } else if !path.hasSuffix("/") && !path.contains(".") {
            parts?.path = path + (path.hasSuffix("/ui") ? "/" : "")
        }
        return parts?.url ?? url
    }

    static func parseBootstrap(_ raw: String) -> [String] {
        raw.split(separator: ":").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }

    static func joinBootstrap(_ paths: [String]) -> String {
        paths.joined(separator: ":")
    }

    /// Global flags, which go before the subcommand as with every `cairn`
    /// command.
    var arguments: [String] {
        var args = ["--data-dir", dataFolder.path, "--root", dataFolder.path]
        if storageGB > 0 { args += ["--max-size", "\(storageGB)GB"] }
        return args
    }

    /// Flags of `run` itself, which go after it. `--bootstrap` is one: the
    /// global parser stops at the first flag it does not know, so before
    /// `run` it reads as a command named "--bootstrap" and the node never
    /// starts.
    var runArguments: [String] {
        bootstrapFiles.flatMap { ["--bootstrap", $0] }
    }

    /// Both always set, so the value chosen here is the one that applies and
    /// not one inherited from whatever launched the app.
    var environment: [String: String] {
        ["CAIRN_SANDBOX_CPUS": String(cpus), "CAIRN_SANDBOX_MEMORY_MB": String(memoryMB)]
    }
}

/// The data folder as files: what it holds, whether it holds a node, and
/// copying one somewhere else.
enum DataFolder {
    /// A ledger or a node identity: something a person would lose by starting
    /// over.
    static func holdsNode(_ folder: URL) -> Bool {
        let fm = FileManager.default
        return fm.fileExists(atPath: folder.appendingPathComponent("log/cairn.jsonl").path)
            || fm.fileExists(atPath: folder.appendingPathComponent("node.identity.json").path)
    }

    /// Whether one folder is the other or inside it. Copying a folder into
    /// itself never finishes.
    static func overlaps(_ a: URL, _ b: URL) -> Bool {
        let x = a.resolvingSymlinksInPath().standardizedFileURL.path
        let y = b.resolvingSymlinksInPath().standardizedFileURL.path
        return x == y || x.hasPrefix(y + "/") || y.hasPrefix(x + "/")
    }

    /// Copy everything in `source` into `destination`, creating it if needed.
    /// Nothing in `source` is removed: the ledger is the one file whose loss
    /// cannot be undone by fetching it again, so moving it is left to a
    /// person who has seen the copy work.
    static func copyContents(of source: URL, to destination: URL) throws {
        let fm = FileManager.default
        try fm.createDirectory(at: destination, withIntermediateDirectories: true)
        for item in try fm.contentsOfDirectory(at: source, includingPropertiesForKeys: nil) {
            try fm.copyItem(at: item, to: destination.appendingPathComponent(item.lastPathComponent))
        }
    }

    struct Usage: Equatable {
        var bytes: Int64
        var available: Int64?
        var volume: String?
    }

    /// Counted the way the node counts against `--max-size`: the length of
    /// every file, symbolic links not followed.
    static func usage(of folder: URL) -> Usage {
        var bytes: Int64 = 0
        let keys: [URLResourceKey] = [.fileSizeKey, .isRegularFileKey]
        if let walk = FileManager.default.enumerator(at: folder, includingPropertiesForKeys: keys) {
            for case let url as URL in walk {
                guard let values = try? url.resourceValues(forKeys: Set(keys)),
                      values.isRegularFile == true else { continue }
                bytes += Int64(values.fileSize ?? 0)
            }
        }
        // The folder's volume, or the nearest existing parent's for a folder
        // not created yet.
        var probe = folder
        while !FileManager.default.fileExists(atPath: probe.path), probe.path != "/" {
            probe.deleteLastPathComponent()
        }
        let volume = try? probe.resourceValues(forKeys: [
            .volumeAvailableCapacityForImportantUsageKey, .volumeLocalizedNameKey,
        ])
        return Usage(
            bytes: bytes,
            available: volume?.volumeAvailableCapacityForImportantUsage,
            volume: volume?.volumeLocalizedName
        )
    }
}
