import AppKit
import SwiftUI

/// ⌘, -- how much of this Mac the node's work may use, and where its data
/// lives.
///
/// Everything here is written to UserDefaults as it changes and read by
/// `Node.start()`, so a change applies at the next start. A running node
/// keeps what it started with until then; the window says so, with the
/// button that restarts it.
struct SettingsView: View {
    @ObservedObject var node: Node

    @AppStorage(NodeSettings.Key.cpus) private var cpus = 0
    @AppStorage(NodeSettings.Key.limitMemory) private var limitMemory = true
    @AppStorage(NodeSettings.Key.memoryGB) private var memoryGB = NodeSettings.defaultMemoryGB
    @AppStorage(NodeSettings.Key.limitStorage) private var limitStorage = false
    @AppStorage(NodeSettings.Key.storageGB) private var storageGB = NodeSettings.defaultStorageGB
    @AppStorage(NodeSettings.Key.dataFolder) private var dataFolder = ""

    @State private var usage: DataFolder.Usage?
    @State private var pending: FolderChange?
    @State private var copying = false
    @State private var problem: String?

    private var current: NodeSettings { NodeSettings.current() }

    var body: some View {
        Form {
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
        .frame(width: 540)
        .fixedSize(horizontal: false, vertical: true)
        .disabled(copying)
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
        .alert("Could not change the data folder", isPresented: Binding(
            get: { problem != nil }, set: { if !$0 { problem = nil } }
        )) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(problem ?? "")
        }
    }

    // MARK: sections

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

private struct Caption: View {
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
            Text("Settings…")
        }
    }
}
