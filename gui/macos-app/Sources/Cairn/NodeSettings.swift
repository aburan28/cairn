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
        /// Serve the node's HTTP side -- its pages and the routes a worker
        /// calls -- on every interface, so another machine on the LAN can
        /// join with `cairn work`. Off by default, like inbound P2P.
        static let shareHTTP = "shareHTTP"
        /// Offer this Mac's configured capacity for compatible challenges.
        static let shareResources = "shareResources"
        static let resourceCPUs = "resourceCPUs"
        static let resourceMemoryGB = "resourceMemoryGB"
        static let resourceStorageGB = "resourceStorageGB"
        static let resourceConcurrency = "resourceConcurrency"
        /// Dial no internet seeds: a node for one building's machines, which
        /// still finds the others by the LAN beacon and any bootstrap file.
        static let offline = "offline"
        /// Run the validator loop: re-run each claim's pinned verifier here
        /// and stand behind what it said, under bond (`--attest-identity`).
        static let validator = "validatorRole"
        static let bootstrap = "bootstrap"
        /// Empty = this app runs the node. Non-empty = open that reader's URL
        /// and do not spawn `cairn run`. Same idea as the iOS reader's
        /// retargetable node URL.
        static let attachURL = "attachURL"
        /// The node runs as a launchd agent and this window attaches to it.
        /// Read by `Node`, never part of the struct: it says who starts the
        /// node, not how the node runs.
        static let backgroundService = "backgroundService"
        static let leadFleet = "leadFleet"
        static let fleetNetworks = "fleetNetworks"
        /// Who may join a fleet this node leads: `invited` or `network`.
        /// See `FleetJoin`. Never registered as a default: its absence is how
        /// `current()` tells a fleet led before invitations existed.
        static let fleetJoin = "fleetJoin"
        /// Serve a fleet this node leads on the tailnet, not every interface:
        /// `--serve tailnet:PORT`. See `fleetTailnet`.
        static let fleetTailnet = "fleetTailnet"
        /// Answer agents on this Mac over MCP, Streamable HTTP on loopback
        /// (`--mcp-http`), so any number of them share this one node. See
        /// `agentArguments`.
        static let serveAgents = "serveAgents"
    }

    /// Who may join a fleet this node leads.
    enum FleetJoin: String {
        /// Machines invited with `cairn fleet invite`, each proving its own
        /// key on every request, from any address: `CAIRN_FLEET=enrolled`.
        case invited
        /// Anything on the networks in `fleetNetworks`, with no proof.
        case network
    }

    /// The node's own default cap, 4096 MiB, so a person who never opens
    /// Settings gets what `cairn run` gives.
    static let defaultMemoryGB = 4
    static let defaultStorageGB = 50
    static let defaultSharedMemoryGB = 1
    static let defaultSharedStorageGB = 10

    /// Loopback: the node dials out and nothing dials in. The release's
    /// default, because an app that suddenly accepts connections on every
    /// interface is a surprise; Settings is where that becomes a choice.
    static let loopbackHost = "127.0.0.1"
    /// Bind every interface. Put the public or LAN address in a bootstrap
    /// file you hand out -- the listen address is never itself a dial hint
    /// (a cloud public IP is not on any local interface).
    static let anyHost = "0.0.0.0"
    /// The node's own word for this Mac's Tailscale address. `cairn run`
    /// resolves it with `tailscale status`, binds that address and its
    /// loopback twin on the same port, and refuses to start, saying why, when
    /// Tailscale is not connected (`src/tailnet.rs`).
    static let tailnetHost = "tailnet"

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
    /// Whether *Share this node on my network* asked for the HTTP side on
    /// every interface. Read through `serveHost`, which leading a fleet also
    /// opens. Defaulted so code that builds a settings value by hand need not
    /// name it.
    var httpHost: String = loopbackHost
    /// Whether this node publishes an operator-approved offer for challenge
    /// work. Publishing capacity does not start a worker or reserve a task.
    var shareResources: Bool = false
    /// Shared CPU capacity; 0 means all active cores.
    var resourceCPUs: Int = 1
    var resourceMemoryGB: Int = defaultSharedMemoryGB
    var resourceStorageGB: Int = defaultSharedStorageGB
    var resourceConcurrency: Int = 1
    /// `CAIRN_SEEDS=off`: no built-in internet seeds.
    var offline: Bool = false
    /// Attest to every claim this node can verify, under the identity in
    /// `validatorIdentity`. Off by default: each attestation stakes a bond.
    var validator: Bool = false
    /// `--bootstrap` files, in the order given. Dial hints only; the handshake
    /// authenticates the key, not the socket that answered.
    var bootstrapFiles: [String]
    /// When set, the app is a window onto this URL and owns no process.
    var attachURL: URL?
    /// Lead a fleet: serve HTTP on every interface so workers on the network
    /// can reach it, and sign their records with `leaderIdentity` so their
    /// work is paid to this node. `docs/fleet.md`.
    var leadFleet: Bool = false
    /// The networks whose unsigned records naming the leader are signed when
    /// `fleetJoin` is `.network`. `private` is every RFC 1918 block, loopback
    /// and IPv6 ULA.
    var fleetNetworks: String = NodeSettings.defaultFleetNetworks
    /// Invitations by default: the setting `docs/design/fleet-enrollment.md`
    /// recommends, and the one a new fleet starts with.
    var fleetJoin: FleetJoin = .invited
    /// Serve the fleet on this Mac's tailnet only: members on the same
    /// tailnet reach it over WireGuard, behind any router and with no port
    /// forwarded, and nothing on the LAN or the internet reaches it at all.
    /// This window still reads 127.0.0.1, which the node binds beside the
    /// tailnet address. Membership is unchanged: being on the tailnet admits
    /// nobody, and an invited fleet still signs only for invited keys.
    var fleetTailnet: Bool = false
    /// Serve MCP over HTTP on loopback beside the node's other work. Off by
    /// default: the endpoint acts as this node's identity for any program on
    /// this Mac that connects, so it opens when a person asks for it.
    var serveAgents: Bool = false

    /// `CAIRN_FLEET` for this fleet.
    var fleetSources: String {
        fleetJoin == .invited ? "enrolled" : fleetNetworks
    }

    static let defaultFleetNetworks = "private"

    /// Host half of `--serve`: loopback unless the node is shared on the
    /// network or leads a fleet -- both exist so another machine there can
    /// reach it; leading also signs that machine's records as this node.
    var serveHost: String {
        if leadFleet && fleetTailnet { return Self.tailnetHost }
        return leadFleet || httpHost == Self.anyHost ? Self.anyHost : Self.loopbackHost
    }

    /// Where to look for a free HTTP port before starting. `tailnet` is not an
    /// address this app can bind; a port free on every interface is free on
    /// the tailnet address and on loopback, the two the node will take.
    var serveProbeHost: String {
        serveHost == Self.tailnetHost ? Self.anyHost : serveHost
    }

    /// The ed25519 identity a fleet is paid to, beside the node's other keys.
    /// Created by the node on first use and never leaves this Mac.
    var leaderIdentity: URL { dataFolder.appendingPathComponent("leader.identity.json") }

    /// Flags of `run` that make this node a fleet leader; empty otherwise.
    /// Kept apart from `runArguments`, which the Connect an Agent stanza
    /// reuses with an identity of its own.
    var fleetArguments: [String] {
        leadFleet ? ["--mcp-identity", leaderIdentity.path] : []
    }

    /// Where agents reach the node unless that port was taken: the address
    /// docs/agents.md uses, fixed so a client's config outlives a restart.
    static let agentsPort: UInt16 = 8001

    static func agentsURL(port: UInt16) -> URL {
        URL(string: "http://127.0.0.1:\(port)/mcp")!
    }

    /// The key Connect an Agent… makes for agents to sign with.
    var agentIdentity: URL { dataFolder.appendingPathComponent("agent.identity.json") }

    /// `agentIdentity`, when it has been made.
    var existingAgentIdentity: URL? {
        FileManager.default.fileExists(atPath: agentIdentity.path) ? agentIdentity : nil
    }

    /// Flags of `run` that answer agents over MCP on loopback `port`; empty
    /// unless `serveAgents`. Every client that connects opens its own
    /// session on the one log, which is what lets several agents -- each
    /// Conductor workspace starts its own -- work at once, where each
    /// spawning a `cairn run` of its own would be refused the log's lock.
    /// Submissions are signed with `identity` when one is given, except on a
    /// fleet leader: the node has one `--mcp-identity`, and a leader's is the
    /// key its fleet is paid to, which `fleetArguments` already passes.
    func agentArguments(port: UInt16, signedBy identity: URL?) -> [String] {
        guard serveAgents else { return [] }
        var args = ["--mcp-http", "127.0.0.1:\(port)"]
        if !leadFleet, let identity { args += ["--mcp-identity", identity.path] }
        return args
    }

    /// Whether Settings asked for the launchd agent.
    static var backgroundService: Bool {
        UserDefaults.standard.bool(forKey: Key.backgroundService)
    }

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
            Key.shareHTTP: false,
            Key.shareResources: false,
            Key.resourceCPUs: 1,
            Key.resourceMemoryGB: defaultSharedMemoryGB,
            Key.resourceStorageGB: defaultSharedStorageGB,
            Key.resourceConcurrency: 1,
            Key.offline: false,
            Key.validator: false,
            Key.bootstrap: "",
            Key.attachURL: "",
            Key.backgroundService: false,
            Key.leadFleet: false,
            Key.fleetNetworks: defaultFleetNetworks,
            Key.fleetTailnet: false,
            Key.serveAgents: false,
        ]
    }

    static func current(_ defaults: UserDefaults = .standard) -> NodeSettings {
        defaults.register(defaults: registeredDefaults)
        // A fleet led before invitations existed keeps trusting the networks
        // its operator chose, as it did; only a new fleet starts with
        // invitations. Written once, so the choice is then a setting like any
        // other and this never runs again.
        if defaults.object(forKey: Key.fleetJoin) == nil {
            defaults.set(
                (defaults.bool(forKey: Key.leadFleet) ? FleetJoin.network : FleetJoin.invited).rawValue,
                forKey: Key.fleetJoin)
        }
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
            httpHost: defaults.bool(forKey: Key.shareHTTP) ? anyHost : loopbackHost,
            shareResources: defaults.bool(forKey: Key.shareResources),
            resourceCPUs: max(1, min(defaults.integer(forKey: Key.resourceCPUs) == 0 ? cores : defaults.integer(forKey: Key.resourceCPUs), cores)),
            resourceMemoryGB: max(1, defaults.integer(forKey: Key.resourceMemoryGB)),
            resourceStorageGB: max(1, defaults.integer(forKey: Key.resourceStorageGB)),
            resourceConcurrency: max(1, defaults.integer(forKey: Key.resourceConcurrency)),
            offline: defaults.bool(forKey: Key.offline),
            validator: defaults.bool(forKey: Key.validator),
            bootstrapFiles: Self.parseBootstrap(defaults.string(forKey: Key.bootstrap) ?? ""),
            attachURL: Self.parseAttachURL(attach),
            leadFleet: defaults.bool(forKey: Key.leadFleet),
            fleetNetworks: {
                let text = (defaults.string(forKey: Key.fleetNetworks) ?? "")
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                return text.isEmpty ? defaultFleetNetworks : text
            }(),
            fleetJoin: FleetJoin(rawValue: defaults.string(forKey: Key.fleetJoin) ?? "") ?? .invited,
            fleetTailnet: defaults.bool(forKey: Key.fleetTailnet),
            serveAgents: defaults.bool(forKey: Key.serveAgents)
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
        var args = bootstrapFiles.flatMap { ["--bootstrap", $0] }
        if validator { args += ["--attest-identity", validatorIdentity.path] }
        return args
    }

    /// The key the validator loop signs and bonds under. Kept in the data
    /// folder, beside the node's own identity, so moving the folder moves
    /// the validator with it; created on first start with the role on.
    var validatorIdentity: URL {
        dataFolder.appendingPathComponent("validator.identity.json")
    }

    /// The key Share this Mac… signs with, so what a worker here earns
    /// lands on a key this Mac holds rather than on a name anyone could
    /// use. Made by `cairn identity` on the first start, never overwritten.
    var workerIdentity: URL {
        dataFolder.appendingPathComponent("worker.identity.json")
    }

    /// The roles this node declares (`CAIRN_ROLES`), read off the settings
    /// that actually give each one a duty, so a declaration here can never
    /// name a role the node is not set up to do. `GET /network` publishes
    /// them as declared -- a hint to readers, never a permission.
    var declaredRoles: [String] {
        var roles: [String] = []
        if sharesOnNetwork { roles.append("executor") }
        if validator { roles.append("verifier") }
        if !listensLocallyOnly { roles.append("relay") }
        return roles
    }

    /// A background preference alone cannot make a remote attachment local:
    /// only the service URL this app owns can use this Mac's repair actions.
    func verifiersRunLocally(backgroundServiceURL: URL?) -> Bool {
        attachURL == nil || attachURL == backgroundServiceURL
    }

    /// The app's chosen limits and required isolation must win over whatever
    /// environment launched it, for foreground and background nodes alike.
    var environment: [String: String] {
        // A desktop node syncs code written by strangers. Losing its jail
        // must make verification unavailable, never silently unconfined.
        var env = ["CAIRN_SANDBOX_CPUS": String(cpus), "CAIRN_SANDBOX_MEMORY_MB": String(memoryMB),
                   "CAIRN_REQUIRE_SANDBOX": "1"]
        if shareResources {
            env["CAIRN_SHARE_RESOURCES"] = "1"
            env["CAIRN_RESOURCE_CPUS"] = String(resourceCPUs)
            env["CAIRN_RESOURCE_MEMORY_MB"] = String(resourceMemoryGB * 1024)
            env["CAIRN_RESOURCE_STORAGE_MB"] = String(resourceStorageGB * 1024)
            env["CAIRN_RESOURCE_CONCURRENCY"] = String(resourceConcurrency)
        }
        // Set only when chosen: a launcher that already pointed the node at
        // its own seed list (`CAIRN_SEEDS=path`) keeps it when this is off.
        if offline { env["CAIRN_SEEDS"] = "off" }
        if !declaredRoles.isEmpty { env["CAIRN_ROLES"] = declaredRoles.joined(separator: ",") }
        if leadFleet { env["CAIRN_FLEET"] = fleetSources }
        return env
    }

    /// True when another machine -- on the LAN, or on the tailnet -- can reach
    /// the node's pages and its worker routes.
    var sharesOnNetwork: Bool { serveHost != Self.loopbackHost }
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
