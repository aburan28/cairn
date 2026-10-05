import AppKit
import SwiftUI
import UniformTypeIdentifiers

/// ⌘, -- how much of this Mac the node's work may use, and where its data
/// lives.
///
/// Everything here is written to UserDefaults as it changes and read by
/// `Node.start()`, so a change applies at the next start. A running node
/// keeps what it started with until then; the window says so, with the
/// button that restarts it.
struct SettingsView: View {
    @ObservedObject var node: Node
    @ObservedObject var updates: Updates

    @AppStorage(NodeSettings.Key.cpus) private var cpus = 0
    @AppStorage(NodeSettings.Key.backgroundService) private var background = false
    @AppStorage(NodeSettings.Key.leadFleet) private var leadFleet = false
    @AppStorage(NodeSettings.Key.fleetNetworks) private var fleetNetworks = NodeSettings.defaultFleetNetworks
    @AppStorage(NodeSettings.Key.fleetJoin) private var fleetJoin = NodeSettings.FleetJoin.invited.rawValue
    @State private var backgroundBusy = false
    @State private var backgroundError: String?
    @AppStorage(NodeSettings.Key.limitMemory) private var limitMemory = true
    @AppStorage(NodeSettings.Key.memoryGB) private var memoryGB = NodeSettings.defaultMemoryGB
    @AppStorage(NodeSettings.Key.limitStorage) private var limitStorage = false
    @AppStorage(NodeSettings.Key.storageGB) private var storageGB = NodeSettings.defaultStorageGB
    @AppStorage(NodeSettings.Key.dataFolder) private var dataFolder = ""
    @AppStorage(NodeSettings.Key.p2pHost) private var p2pHost = NodeSettings.loopbackHost
    @AppStorage(NodeSettings.Key.shareHTTP) private var shareHTTP = false
    @AppStorage(NodeSettings.Key.offline) private var offline = false
    @AppStorage(NodeSettings.Key.validator) private var validator = false
    @AppStorage(NodeSettings.Key.bootstrap) private var bootstrap = ""
    @AppStorage(NodeSettings.Key.attachURL) private var attachURL = ""

    @State private var usage: DataFolder.Usage?
    @State private var pending: FolderChange?
    @State private var copying = false
    @State private var problem: String?
    @State private var bootstrapAddr = ""
    @State private var bootstrapBusy = false

    private var current: NodeSettings { NodeSettings.current() }
    private var bootstrapPaths: [String] { NodeSettings.parseBootstrap(bootstrap) }
    private var attaching: Bool { !attachURL.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }

    var body: some View {
        Form {
            Section {
                attach
            } header: {
                Text("Window")
            } footer: {
                Caption("""
                    By default this app runs a local node and shows its reader. \
                    Attach instead to open any node's reader without starting one \
                    — the same idea as pointing the iPhone app at a URL. Resource \
                    limits, bootstrap files and the data folder then apply only \
                    when you switch back to running a node here.
                    """)
            }

            // Attached to somebody else's node, these do not apply. Attached
            // to our own launchd agent, they do: the agent is this node.
            if !attaching || background {
            Section {
                processor
            } header: {
                Text("Processor")
            } footer: {
                Caption("""
                    Cairn's work on this Mac is checking results: it runs each \
                    objective's verifier, one at a time. A verifier that wants more \
                    cores than this is paused until it is back under the limit, so it \
                    takes longer. One that runs out of time is reported as unavailable, \
                    never as wrong. The node does not use the graphics processor, and \
                    macOS has no way to cap one app's use of it, so there is no GPU \
                    setting.
                    """)
            }

            Section {
                Toggle("Limit memory for each verifier", isOn: $limitMemory)
                if limitMemory {
                    LabeledSlider(
                        title: "Memory",
                        value: $memoryGB,
                        range: 1...max(1, NodeSettings.physicalMemoryGB),
                        text: "\(memoryGB) GB of \(NodeSettings.physicalMemoryGB) GB"
                    )
                }
            } header: {
                Text("Memory")
            } footer: {
                Caption("""
                    Applies to each objective's pinned checker. One that goes past it is \
                    stopped, and its result is reported as unavailable. Replay commands \
                    and Lean proofs are not limited.
                    """)
            }

            Section {
                roles
            } header: {
                Text("Roles")
            } footer: {
                Caption("""
                    Each role is something this node does, and a declaration other \
                    readers see on the Network page. None of them gives this node a say \
                    over what is paid: only an objective's pinned checker decides that. \
                    Solving challenges is done by you or your agent — Node ▸ Connect an \
                    Agent… — and is paid when an answer is accepted. The Contribute page \
                    in the window explains every role and how each one is paid.
                    """)
            }

            Section {
                network
            } header: {
                Text("Network")
            } footer: {
                Caption("""
                    The reader stays on this Mac unless the node is shared on your \
                    network above. Peers on the local segment find each \
                    other without a file. A peer elsewhere needs a bootstrap file with \
                    its address and real transport key; `cairn gen-bootstrap` writes the \
                    shape, and a placeholder key is warned about at every start until \
                    the real one replaces it. A bootstrap is a dial hint, never a trust \
                    decision — the handshake authenticates the key.
                    """)
            }

            Section {
                fleet
            } header: {
                Text("Fleet")
            } footer: {
                Caption("""
                    Lead a fleet and this node serves its HTTP side on every interface and signs \
                    the records its machines hand it with an identity kept here and nowhere \
                    else — their work is paid to this node. Machines I invite each get a token \
                    and their own key, and prove it on every request from wherever they are, \
                    so a rented GPU joins without a tunnel and a stranger on your Wi-Fi gets \
                    nothing signed. Anything on my network is the older way: every address on \
                    the listed networks is a member with no proof, so the list must mean a \
                    network you run. docs/fleet.md has the whole arrangement.
                    """)
            }

            Section {
                folder
                Toggle("Limit storage", isOn: $limitStorage)
                if limitStorage {
                    LabeledContent("Up to") {
                        HStack(spacing: 6) {
                            TextField("Limit", value: $storageGB, format: .number)
                                .labelsHidden()
                                .textFieldStyle(.roundedBorder)
                                .multilineTextAlignment(.trailing)
                                .frame(width: 80)
                                .onChange(of: storageGB) { storageGB = max(1, $0) }
                            Text("GB")
                            Stepper("", value: $storageGB, in: 1...1_000_000, step: 5).labelsHidden()
                        }
                    }
                }
            } header: {
                Text("Storage")
            } footer: {
                Caption("""
                    The folder holds the ledger, this node's keys, and copies of \
                    verifier code it can download again. At the limit, Cairn deletes \
                    those copies first. If the ledger alone outgrows it, the node stops \
                    and tells you. It never deletes the ledger to fit.
                    """)
            }
            } // !attaching

            UpdatesSection(updates: updates, nodeVersion: node.binaryVersion)

            if !attaching {
                VerifiersSection(node: node)
            }

            AISettingsSection(node: node)

            if needsRestart {
                Section {
                    HStack {
                        Label("The node is still using its old settings.", systemImage: "arrow.clockwise.circle")
                        Spacer()
                        Button("Restart Node") { node.restart() }
                    }
                }
            }
        }
        .formStyle(.grouped)
        // Wide enough for a whole peer id on one line. Not sized to its
        // content's height: with every section open that is taller than a
        // laptop screen, and a window past the bottom edge cannot be scrolled.
        // The form scrolls instead, and the window can be dragged taller.
        .frame(width: 640)
        .frame(minHeight: 360, idealHeight: idealHeight, maxHeight: .infinity)
        .disabled(copying || bootstrapBusy)
        .task(id: current.dataFolder) { await measure() }
        .alert(pending?.title ?? "", isPresented: Binding(
            get: { pending != nil }, set: { if !$0 { pending = nil } }
        ), presenting: pending) { change in
            switch change.kind {
            case .adopt:
                Button("Use It") { switchFolder(to: change.to, copying: nil) }
            case .move:
                Button("Copy and Switch") { switchFolder(to: change.to, copying: change.from) }
                Button("Start Empty") { switchFolder(to: change.to, copying: nil) }
            }
            Button("Cancel", role: .cancel) {}
        } message: { change in
            Text(change.message)
        }
        .alert("Something went wrong", isPresented: Binding(
            get: { problem != nil }, set: { if !$0 { problem = nil } }
        )) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(problem ?? "")
        }
    }

    // MARK: sections

    private var fleet: some View {
        VStack(alignment: .leading, spacing: 8) {
            Toggle("Lead a fleet: sign the submissions of machines that work for this Mac", isOn: $leadFleet)
            if leadFleet {
                Picker("Who may join", selection: $fleetJoin) {
                    Text("Machines I invite").tag(NodeSettings.FleetJoin.invited.rawValue)
                    Text("Anything on my network").tag(NodeSettings.FleetJoin.network.rawValue)
                }
                .pickerStyle(.radioGroup)
                if fleetJoin == NodeSettings.FleetJoin.network.rawValue {
                    TextField("Member networks: CIDRs, or private, or loopback", text: $fleetNetworks)
                        .font(.body.monospaced())
                    Text("Anything at these addresses has its records signed as this Mac, with no proof: a guest on the Wi-Fi included.")
                        .font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if let id = node.leaderId {
                    HStack(spacing: 8) {
                        Text("The fleet is paid to").font(.caption).foregroundStyle(.secondary)
                        Text(id)
                            .font(.caption.monospaced())
                            .textSelection(.enabled)
                            .lineLimit(1)
                            .truncationMode(.middle)
                        Button("Copy") {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(id, forType: .string)
                        }
                        .controlSize(.small)
                    }
                } else {
                    Text("The fleet identity is created the next time the node starts. Its id appears here, and as node.fleet.signs_as on GET /network.")
                        .font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if fleetJoin == NodeSettings.FleetJoin.invited.rawValue {
                    FleetMembersView(node: node)
                }
            }
        }
    }

    private var attach: some View {
        VStack(alignment: .leading, spacing: 8) {
            Toggle("Keep the node running in the background", isOn: Binding(
                get: { background },
                set: { on in
                    backgroundBusy = true
                    backgroundError = nil
                    node.setBackground(on) { error in
                        backgroundBusy = false
                        backgroundError = error
                    }
                }
            ))
            .disabled(backgroundBusy)
            if background || backgroundBusy {
                Text("""
                    The node is a launchd agent (\(BackgroundService.label), in ~/Library/LaunchAgents): \
                    it keeps running when this window closes and starts again when you log in, and this \
                    window attaches to it. On macOS 15 and later a process that is not an app cannot ask \
                    for Local Network permission itself, so LAN beacons may be denied silently; bootstrap \
                    files, seeds and port mapping are unaffected.
                    """)
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let backgroundError {
                Text(backgroundError).font(.caption).foregroundStyle(.red)
            }
            Toggle("Attach to an existing node", isOn: Binding(
                get: { attaching },
                set: { on in
                    if on {
                        if attachURL.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                            attachURL = "http://127.0.0.1:8080/ui/"
                        }
                    } else {
                        attachURL = ""
                    }
                }
            ))
            .disabled(background)
            if attaching {
                TextField("Reader URL", text: $attachURL)
                    .font(.body.monospaced())
                    .disabled(background)
                Text("Example: http://192.168.1.10:8080/ui/ — the page this window will show. Nothing is started on this Mac.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    private var processor: some View {
        let all = NodeSettings.cores
        let binding = Binding<Int>(
            get: { cpus == 0 ? all : min(cpus, all) },
            set: { cpus = $0 >= all ? 0 : $0 }
        )
        return LabeledSlider(
            title: "CPU cores",
            value: binding,
            range: 1...max(1, all),
            text: cpus == 0 || cpus >= all ? "All \(all) cores" : "\(cpus) of \(all) cores"
        )
    }

    /// Each role bound to the setting that gives it its duty, so turning a
    /// role on here and turning on its setting in Network are the same act.
    private var roles: some View {
        let relay = Binding<Bool>(
            get: { p2pHost == NodeSettings.anyHost },
            set: { p2pHost = $0 ? NodeSettings.anyHost : NodeSettings.loopbackHost }
        )
        return VStack(alignment: .leading, spacing: 10) {
            Toggle("Validator — re-check other people's answers", isOn: $validator)
            Caption("""
                Re-runs each claim's checker on this Mac and signs what it found. Every \
                attestation stakes 50,000 units, returned after six epochs and lost if \
                a canary shows it was wrong. Not paid yet: a correct check earns nothing \
                today, so this is for people who want results checked. Its key is \
                validator.identity.json in the data folder.
                """)
            Toggle("Worker host — let machines on my network work for this node", isOn: $shareHTTP)
            Caption("""
                Same as "Share this node on my network" below. Each machine runs \
                `cairn work` with its own solver and is paid for what the checker \
                accepts, like any solver.
                """)
            Toggle("Relay — let other nodes connect to this one", isOn: relay)
            Caption("""
                Same as P2P listen on any interface below. Helps the network stay \
                connected. Not paid: nothing in the log can show a relay did its job.
                """)
        }
    }

    private var network: some View {
        VStack(alignment: .leading, spacing: 12) {
            Toggle("Share this node on my network", isOn: $shareHTTP)
            Text(shareHTTP
                 ? "Other machines on your network can open this node's pages and join its work with `cairn work --node http://<this Mac>:8080 …` — the Contribute page shows the exact command. Each machine is paid under its own name; Lead a fleet pays this Mac instead. Anyone on the network can read the log and post answers; nobody can change what has settled."
                 : "Only this Mac can open the node's pages or work on it. Turn this on to add machines on your network as workers.")
                .font(.caption).foregroundStyle(.secondary)
            Toggle("Offline: no internet peers", isOn: $offline)
            Text(offline
                 ? "The node dials no built-in seeds. It still finds nodes on this network by their LAN beacon, and any bootstrap file below."
                 : "The node may dial the built-in internet seeds to sync.")
                .font(.caption).foregroundStyle(.secondary)

            Divider()

            Picker("P2P listen", selection: $p2pHost) {
                Text("This Mac only").tag(NodeSettings.loopbackHost)
                Text("Any interface (accept inbound)").tag(NodeSettings.anyHost)
            }
            if p2pHost == NodeSettings.loopbackHost {
                Text("The node dials peers and nothing dials it. Enough to sync; not enough to be a peer others reach.")
                    .font(.caption).foregroundStyle(.secondary)
            } else {
                Text("Binds 0.0.0.0 on the P2P port. Hand out this Mac's LAN or public address with the peer id below — never put a cloud public IP in the listen field; it is not on any local interface.")
                    .font(.caption).foregroundStyle(.secondary)
            }

            Divider()

            LabeledContent("Peer id") {
                Text(node.peerId ?? "shown once the node has started")
                    .font(.callout.monospaced())
                    .textSelection(.enabled)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .foregroundStyle(node.peerId == nil ? .secondary : .primary)
            }
            if let listen = node.listenAddress {
                LabeledContent("Listening") {
                    Text(listen).font(.callout.monospaced()).textSelection(.enabled)
                }
            } else {
                LabeledContent("Will listen") {
                    Text("\(current.p2pHost):9000 (or next free)")
                        .font(.callout.monospaced())
                        .foregroundStyle(.secondary)
                }
            }
            HStack {
                Button("Copy peer id") {
                    guard let id = node.peerId else { return }
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(id, forType: .string)
                }
                .disabled(node.peerId == nil)
                Button("Copy peer id and listen address") {
                    guard let id = node.peerId else { return }
                    let addr = node.listenAddress ?? "\(current.p2pHost):9000"
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString("\(id) \(addr)", forType: .string)
                }
                .disabled(node.peerId == nil)
            }
            .font(.callout)

            Divider()

            Text("Bootstrap files").font(.headline)
            if bootstrapPaths.isEmpty {
                Text("None. LAN peers only, unless this cairn binary dials built-in seeds on its own.")
                    .font(.callout).foregroundStyle(.secondary)
            } else {
                ForEach(bootstrapPaths, id: \.self) { path in
                    HStack {
                        Image(systemName: FileManager.default.fileExists(atPath: path)
                              ? "doc" : "exclamationmark.triangle.fill")
                            .foregroundStyle(FileManager.default.fileExists(atPath: path)
                                             ? Color.secondary : .gray)
                        Text(path)
                            .font(.caption.monospaced())
                            .lineLimit(1)
                            .truncationMode(.middle)
                            .help(path)
                        Spacer()
                        Button("Remove") { removeBootstrap(path) }
                            .buttonStyle(.link)
                    }
                }
            }
            HStack {
                Button("Choose…") { chooseBootstrap() }
                // A grouped form puts a field's title beside it, which in
                // 160 points left no room for the field.
                TextField("Address to generate for", text: $bootstrapAddr, prompt: Text("host:port"))
                    .labelsHidden()
                    .textFieldStyle(.roundedBorder)
                    .font(.body.monospaced())
                    .frame(width: 160)
                Button("Generate…") { generateBootstrap() }
                    .disabled(!Self.isHostPort(bootstrapAddr.trimmingCharacters(in: .whitespacesAndNewlines))
                              || bootstrapBusy)
            }
            .font(.callout)
        }
    }

    private var folder: some View {
        VStack(alignment: .leading, spacing: 8) {
            LabeledContent("Data folder") {
                Text(current.dataFolder.path)
                    .font(.callout.monospaced())
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .textSelection(.enabled)
                    .help(current.dataFolder.path)
            }
            HStack {
                if copying {
                    ProgressView().controlSize(.small)
                    Text("Copying…").foregroundStyle(.secondary)
                } else if let usage {
                    Text(describe(usage)).foregroundStyle(.secondary)
                }
                Spacer()
                if !current.isDefaultFolder {
                    Button("Use Default") { propose(NodeSettings.defaultDataFolder) }
                }
                Button("Show in Finder") {
                    NSWorkspace.shared.activateFileViewerSelecting([current.dataFolder])
                }
                .disabled(!FileManager.default.fileExists(atPath: current.dataFolder.path))
                Button("Choose…") { choose() }
            }
            .font(.callout)
        }
    }

    // MARK: behaviour

    /// The window's opening height: most of the form at once, with room left
    /// on this screen for the title bar and some desktop around it.
    private var idealHeight: CGFloat {
        let visible = NSScreen.main?.visibleFrame.height ?? 800
        return max(360, min(900, visible - 120))
    }

    /// Settings a restart would change, on a node that is up or coming up. A
    /// stopped or failed node picks them up on its next start anyway.
    private var needsRestart: Bool {
        switch node.state {
        case .running, .starting: return node.settings != current
        case .stopped, .failed: return false
        }
    }

    private func describe(_ usage: DataFolder.Usage) -> String {
        guard FileManager.default.fileExists(atPath: current.dataFolder.path) else {
            return current.isDefaultFolder
                ? "Created when the node starts"
                : "This folder is not there. Is its disk connected?"
        }
        let bytes = ByteCountFormatter.string(fromByteCount: usage.bytes, countStyle: .file)
        var text = "Uses \(bytes)"
        if let available = usage.available {
            let free = ByteCountFormatter.string(fromByteCount: available, countStyle: .file)
            text += ", \(free) free"
            if let volume = usage.volume { text += " on \(volume)" }
        }
        return text
    }

    private func measure() async {
        let folder = current.dataFolder
        let measured = await Task.detached(priority: .utility) { DataFolder.usage(of: folder) }.value
        usage = measured
    }

    private func choose() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.canCreateDirectories = true
        panel.allowsMultipleSelection = false
        panel.prompt = "Use This Folder"
        panel.message = "Choose where Cairn keeps its ledger, keys and cache."
        panel.directoryURL = current.dataFolder.deletingLastPathComponent()
        if panel.runModal() == .OK, let url = panel.url {
            propose(url)
        }
    }

    private func chooseBootstrap() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.allowsMultipleSelection = true
        panel.prompt = "Use as Bootstrap"
        panel.message = "A bootstrap file is an address and a transport key. The handshake authenticates the key."
        if panel.runModal() == .OK {
            var paths = bootstrapPaths
            for url in panel.urls {
                let path = url.path
                if !paths.contains(path) { paths.append(path) }
            }
            bootstrap = NodeSettings.joinBootstrap(paths)
        }
    }

    private func removeBootstrap(_ path: String) {
        bootstrap = NodeSettings.joinBootstrap(bootstrapPaths.filter { $0 != path })
    }

    private func generateBootstrap() {
        let addr = bootstrapAddr.trimmingCharacters(in: .whitespacesAndNewlines)
        guard Self.isHostPort(addr) else { return }
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "bootstrap.json"
        panel.allowedContentTypes = [.json]
        panel.prompt = "Generate"
        panel.message = "Writes a placeholder key. Paste the peer's real transport key into the file before the node can authenticate them."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        bootstrapBusy = true
        node.generateBootstrap(addr: addr, to: url) { error in
            bootstrapBusy = false
            if let error {
                problem = error
            } else {
                var paths = bootstrapPaths
                if !paths.contains(url.path) { paths.append(url.path) }
                bootstrap = NodeSettings.joinBootstrap(paths)
            }
        }
    }

    /// host:port with a non-empty host and a 1…65535 port. Same shape the
    /// Autoresearcher sheet accepts; kept local so this app does not share types.
    private static func isHostPort(_ value: String) -> Bool {
        guard let idx = value.lastIndex(of: ":") else { return false }
        let host = value[..<idx]
        let port = value[value.index(after: idx)...]
        guard !host.isEmpty, let n = UInt16(port), n > 0 else { return false }
        return true
    }

    /// Decide what choosing `target` means, and ask when it could cost
    /// something: a node identity left behind, or a folder that already holds
    /// a different node.
    private func propose(_ target: URL) {
        let from = current.dataFolder
        if from.standardizedFileURL.path == target.standardizedFileURL.path { return }
        if DataFolder.overlaps(from, target) {
            problem = "\(target.path) is inside \(from.path), or the other way round. Choose a folder outside the current one."
            return
        }
        if DataFolder.holdsNode(target) {
            pending = FolderChange(kind: .adopt, from: from, to: target)
        } else if DataFolder.holdsNode(from) {
            pending = FolderChange(kind: .move, from: from, to: target)
        } else {
            switchFolder(to: target, copying: nil)
        }
    }

    /// Stop the node, copy if asked, point the setting at `target`, start.
    /// A failed copy leaves the setting where it was, so the node comes back
    /// on the folder that still holds everything.
    private func switchFolder(to target: URL, copying source: URL?) {
        node.stop()
        let commit = {
            dataFolder = target.standardizedFileURL.path == NodeSettings.defaultDataFolder.standardizedFileURL.path
                ? "" : target.path
            node.start()
        }
        guard let source else {
            commit()
            return
        }
        copying = true
        Task {
            let result = await Task.detached(priority: .userInitiated) {
                Result { try DataFolder.copyContents(of: source, to: target) }
            }.value
            copying = false
            switch result {
            case .success:
                commit()
            case .failure(let error):
                problem = "Copying \(source.path) to \(target.path) failed: \(error.localizedDescription). Nothing was changed; the node is back on the old folder."
                node.start()
            }
        }
    }
}

/// A choice of data folder that needs a person's say-so.
private struct FolderChange: Identifiable {
    enum Kind { case adopt, move }
    let kind: Kind
    let from: URL
    let to: URL
    var id: String { to.path }

    var title: String {
        switch kind {
        case .adopt: return "“\(to.lastPathComponent)” already holds a Cairn node"
        case .move: return "Copy this node to “\(to.lastPathComponent)”?"
        }
    }

    var message: String {
        switch kind {
        case .adopt:
            return """
                Cairn will run the node whose ledger and keys are already in \(to.path). \
                Nothing in \(from.path) is changed.
                """
        case .move:
            return """
                The ledger and this node's keys are in \(from.path). Copying them keeps \
                this node's identity. Starting empty makes a new node, which syncs the \
                ledger from its peers again. Nothing is deleted from the old folder \
                either way.
                """
        }
    }
}

/// A whole-number slider with its title before it and its value after.
private struct LabeledSlider: View {
    let title: String
    @Binding var value: Int
    let range: ClosedRange<Int>
    let text: String

    var body: some View {
        LabeledContent(title) {
            HStack(spacing: 12) {
                Slider(
                    value: Binding(get: { Double(value) }, set: { value = Int($0.rounded()) }),
                    in: Double(range.lowerBound)...Double(max(range.upperBound, range.lowerBound + 1))
                )
                .labelsHidden()
                .frame(minWidth: 180)
                Text(text)
                    .monospacedDigit()
                    .frame(minWidth: 120, alignment: .trailing)
            }
        }
    }
}

struct Caption: View {
    let text: String
    init(_ text: String) { self.text = text }

    var body: some View {
        // Form footers trail-align by default, which reads badly for a
        // paragraph.
        Text(text)
            .font(.caption)
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.leading)
            .frame(maxWidth: .infinity, alignment: .leading)
            .fixedSize(horizontal: false, vertical: true)
    }
}

/// Opens this window. `SettingsLink` is the only way that works from macOS 14
/// on; macOS 13, which this app still supports, predates it and still takes
/// the old selector.
struct OpenSettingsButton: View {
    var iconOnly = false
    var title = "Settings…"

    var body: some View {
        if #available(macOS 14, *) {
            SettingsLink { label }
        } else {
            Button {
                NSApp.sendAction(Selector(("showSettingsWindow:")), to: nil, from: nil)
            } label: { label }
        }
    }

    @ViewBuilder private var label: some View {
        if iconOnly {
            Label("Settings", systemImage: "gearshape")
        } else {
            Text(title)
        }
    }
}
