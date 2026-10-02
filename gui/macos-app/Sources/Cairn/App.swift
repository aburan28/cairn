import AppKit
import SwiftUI

@main
struct CairnApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate

    var body: some Scene {
        // `Window`, not `WindowGroup`: there is one node, so there is one
        // window, and ⌘N has nothing to make.
        Window("Cairn", id: "main") {
            ContentView(node: delegate.node, browser: delegate.browser, updater: delegate.updater)
                .frame(minWidth: 720, minHeight: 480)
        }
        .defaultSize(width: 1180, height: 800)
        .commands {
            CommandGroup(replacing: .newItem) {}
            CommandGroup(after: .appInfo) {
                Button("Check for Updates…") { delegate.updater.checkNow() }
            }
            CommandGroup(after: .toolbar) {
                Button("Reload Page") { delegate.browser.reload() }
                    .keyboardShortcut("r")
                Divider()
            }
            CommandMenu("Node") {
                Button("Open in Browser") { delegate.openInBrowser() }
                    .keyboardShortcut("o", modifiers: [.command, .shift])
                Button("Restart / Reconnect") { delegate.node.restart() }
                    .keyboardShortcut("r", modifiers: [.command, .shift])
                Divider()
                Button("Tasks…") { delegate.node.presentTasks = true }
                    .disabled(delegate.node.isAttached)
                Button("Secrets…") { delegate.node.presentSecrets = true }
                Button("Peers…") { delegate.node.presentPeers = true }
                Button("Copy Peer Id") { delegate.copyPeerId() }
                    .disabled(delegate.node.peerId == nil)
                Button("Show Data Folder") {
                    NSWorkspace.shared.activateFileViewerSelecting([delegate.node.dataDir])
                }
                .disabled(delegate.node.isAttached)
                Button("Show Node Log") {
                    NSWorkspace.shared.open(delegate.node.logFile)
                }
                .disabled(delegate.node.isAttached)
            }
        }

        // ⌘, and the app menu's Settings… item come with the scene.
        Settings {
            SettingsView(node: delegate.node, updater: delegate.updater)
        }
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    let node = Node()
    let browser = Browser()
    lazy var updater = Updater(node: node)

    func applicationDidFinishLaunching(_ notification: Notification) {
        // The node first: its start reads the `cairn` binary's version, which
        // the update check compares against.
        node.start()
        updater.start()
    }

    // Closing the window is closing the node: nothing keeps running where
    // nobody can see it. Attach mode has no process; still quit with the window.
    func applicationShouldTerminateAfterLastWindowClosed(_ app: NSApplication) -> Bool { true }

    func applicationWillTerminate(_ notification: Notification) {
        node.stop()
    }

    func openInBrowser() {
        if case .running(let url) = node.state { NSWorkspace.shared.open(url) }
    }

    func copyPeerId() {
        guard let id = node.peerId else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(id, forType: .string)
    }
}

struct ContentView: View {
    @ObservedObject var node: Node
    @ObservedObject var browser: Browser
    @ObservedObject var updater: Updater

    var body: some View {
        Group {
            switch node.state {
            case .running(let url):
                WebView(browser: browser)
                    .onAppear { browser.show(url) }
                    .onChange(of: url) { browser.show($0) }
            case .starting, .stopped:
                Starting(node: node)
            case .failed(let message):
                Failed(node: node, message: message)
            }
        }
        // Under "Cairn" in the title bar, where it is visible without a menu:
        // the first thing anybody asks of a bug report, and the thing to look
        // at after an update.
        .navigationSubtitle(node.versionSubtitle)
        .toolbar {
            ToolbarItemGroup {
                // Not only while running: a node that fails to start is the
                // likeliest to be fixed by a newer release.
                if let release = updater.badge {
                    Button { updater.presentSheet = true } label: {
                        Label("Update to \(release.version.description)", systemImage: "arrow.down.circle.fill")
                            .foregroundStyle(Color.accentColor)
                    }
                    .help("Cairn \(release.version.description) is available")
                }
                if case .running(let url) = node.state {
                    // One status button rather than two raw addresses run
                    // together ("127.0.0.1:8080p2p 127.0.0.1:9000") and a
                    // full-width strip of prose above the page. The addresses
                    // and the explanation are one click away, in its popover.
                    NodeStatusButton(node: node, url: url)
                    Button { node.presentTasks = true } label: {
                        Label("Tasks", systemImage: "target")
                    }
                    .help("Post a curated objective (e.g. ECC2K-130) into this node's log")
                    .disabled(node.isAttached)
                    Button { node.presentPeers = true } label: {
                        Label("Peers", systemImage: "person.badge.plus")
                    }
                    .help("Announce a peer, manage bootstrap, or copy what to give someone adding this node")
                    Button { browser.reload() } label: { Label("Reload", systemImage: "arrow.clockwise") }
                        .help("Reload the page")
                    Button { NSWorkspace.shared.open(url) } label: { Label("Open in Browser", systemImage: "safari") }
                        .help("Open this page in your browser")
                }
                Button { node.presentSecrets = true } label: {
                    Label("Secrets", systemImage: "key.fill")
                }
                .help("Paste AWS keys and other named secrets for campaign scripts")
                OpenSettingsButton(iconOnly: true)
                    .help("How much of this Mac the node may use, where it keeps its data, and how it reaches peers")
            }
        }
        .sheet(isPresented: $node.presentPeers) {
            PeersSheet(node: node, isPresented: $node.presentPeers)
        }
        .sheet(isPresented: $node.presentTasks) {
            TasksSheet(node: node, browser: browser, isPresented: $node.presentTasks)
        }
        .sheet(isPresented: $node.presentSecrets) {
            SecretsSheet(node: node, isPresented: $node.presentSecrets)
        }
        .sheet(isPresented: $updater.presentSheet) {
            UpdateSheet(updater: updater, node: node)
        }
    }
}

/// Whether anyone can dial this node, and whether it has reached anyone, as
/// one toolbar button. Taken from the node's own log, never guessed. It used
/// to be a strip of prose across the top of the window, permanently orange on
/// a default install, which read as a warning about a state that is normal.
private struct NodeStatusButton: View {
    @ObservedObject var node: Node
    let url: URL
    @State private var showing = false

    var body: some View {
        Button { showing.toggle() } label: {
            HStack(spacing: 6) {
                Circle()
                    .fill(node.networkTint)
                    .frame(width: 7, height: 7)
                Text(node.networkLabel)
                    .font(.callout)
            }
        }
        .help(node.networkSummary)
        .popover(isPresented: $showing, arrowEdge: .bottom) {
            NodeDetails(node: node, url: url)
        }
    }
}

private struct NodeDetails: View {
    @ObservedObject var node: Node
    let url: URL
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label(node.networkSummary, systemImage: node.networkIcon)
                .foregroundStyle(node.networkTint)
                .fixedSize(horizontal: false, vertical: true)

            Divider()

            Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 12, verticalSpacing: 8) {
                // Verbatim: as a localized key the port is a number to
                // format, and 8080 reads "8,080".
                row("Reader", url.host.map { "\($0):\(url.port ?? 80)" } ?? url.absoluteString)
                if !node.isAttached, let listen = node.listenAddress {
                    row("P2P", listen)
                }
                if let id = node.peerId {
                    row("Peer id", id)
                }
                GridRow {
                    Text("Sessions").foregroundStyle(.secondary).gridColumnAlignment(.trailing)
                    Text(verbatim: "\(node.sessionsOK)").monospacedDigit()
                }
                GridRow {
                    Text("Version").foregroundStyle(.secondary).gridColumnAlignment(.trailing)
                    Text(verbatim: node.versionDetail)
                }
            }
            .font(.callout)

            HStack {
                Button("Peers…") {
                    // Close the popover first: a sheet presented from under
                    // an open popover leaves the popover floating over it.
                    dismiss()
                    node.presentPeers = true
                }
                OpenSettingsButton()
                Spacer()
                Button("Open in Browser") { NSWorkspace.shared.open(url) }
            }
        }
        .padding(16)
        .frame(width: 380)
    }

    private func row(_ label: String, _ value: String) -> some View {
        GridRow {
            Text(label).foregroundStyle(.secondary).gridColumnAlignment(.trailing)
            HStack(spacing: 4) {
                Text(verbatim: value)
                    .font(.callout.monospaced())
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .textSelection(.enabled)
                Button {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(value, forType: .string)
                } label: {
                    Image(systemName: "doc.on.doc")
                }
                .buttonStyle(.borderless)
                .help("Copy")
            }
        }
    }
}

extension Node {
    /// The title bar's line: the release, and the command's version only
    /// when it says something the release does not -- a checkout's build,
    /// or a `cairn` that is not the one the app was installed with.
    var versionSubtitle: String {
        guard let cli = cliVersion, cli != AppVersion.release?.description else { return AppVersion.label }
        return "\(AppVersion.label) · cairn \(cli)"
    }

    /// Both versions, always, for the popover.
    var versionDetail: String {
        let app = AppVersion.release.map { "Cairn.app \($0)" } ?? "Cairn.app (development build)"
        return app + " · cairn " + (cliVersion ?? (isAttached ? "not run in attach mode" : "not found"))
    }

    /// The toolbar's word for the network state: two at most.
    var networkLabel: String {
        if isAttached { return "Attached" }
        if sessionsOK > 0 { return sessionsOK == 1 ? "1 peer" : "\(sessionsOK) peers" }
        if settings.listensLocallyOnly { return "This Mac only" }
        return "Waiting for peers"
    }

    var networkSummary: String {
        if isAttached {
            return "Attached to an existing node. This app owns no process."
        }
        if settings.listensLocallyOnly {
            if sessionsOK > 0 {
                return "Dialling out from this Mac only, and reached a peer."
            }
            if settings.bootstrapFiles.isEmpty {
                return "Listening on this Mac only. LAN peers may find it; add a bootstrap or accept inbound in Settings to reach further."
            }
            return "Listening on this Mac only. Dialling bootstrap peers…"
        }
        if sessionsOK > 0 {
            return "Accepting inbound, and reached \(sessionsOK) peer session\(sessionsOK == 1 ? "" : "s")."
        }
        if settings.bootstrapFiles.isEmpty {
            return "Accepting inbound. Waiting for a LAN peer, or add a bootstrap in Settings."
        }
        return "Accepting inbound. Dialling bootstrap peers…"
    }

    var networkIcon: String {
        if isAttached { return "link" }
        if sessionsOK > 0 { return "antenna.radiowaves.left.and.right" }
        if settings.listensLocallyOnly { return "lock.laptopcomputer" }
        return "network"
    }

    var networkTint: Color {
        if isAttached { return .blue }
        if sessionsOK > 0 { return .green }
        if settings.listensLocallyOnly { return .orange }
        return .secondary
    }
}

private struct Starting: View {
    @ObservedObject var node: Node

    var body: some View {
        VStack(spacing: 14) {
            ProgressView()
            Text(node.isAttached ? "Connecting…" : "Starting a node…").font(.title3)
            if node.isAttached, let url = node.settings.attachURL {
                Text(url.absoluteString)
                    .font(.callout.monospaced())
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            } else {
                Text(node.dataDir.path)
                    .font(.callout.monospaced())
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
            if let last = node.lines.last(where: { !$0.isEmpty }) {
                Text(last)
                    .font(.caption.monospaced())
                    .foregroundStyle(.tertiary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .frame(maxWidth: 560)
            }
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

private struct Failed: View {
    @ObservedObject var node: Node
    let message: String

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label(node.isAttached ? "Could not reach that node" : "The node is not running",
                  systemImage: "exclamationmark.triangle.fill")
                .font(.title2)
                .foregroundStyle(.orange)
            Text(message)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
            if !node.lines.isEmpty {
                ScrollView {
                    Text(node.lines.suffix(200).joined(separator: "\n"))
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(8)
                }
                .background(Color(nsColor: .textBackgroundColor))
                .clipShape(RoundedRectangle(cornerRadius: 6))
            }
            Text(verbatim: node.versionDetail)
                .font(.caption)
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
            HStack {
                Button("Try Again") { node.restart() }
                    .keyboardShortcut(.defaultAction)
                if !node.isAttached {
                    Button("Show Node Log") { NSWorkspace.shared.open(node.logFile) }
                    Button("Show Data Folder") {
                        NSWorkspace.shared.activateFileViewerSelecting([node.dataDir])
                    }
                }
                // The storage cap, the data folder and the attach URL are all
                // reasons a window shows this page, and all are fixed there.
                OpenSettingsButton()
            }
        }
        .padding(28)
        .frame(maxWidth: 760, maxHeight: .infinity, alignment: .topLeading)
    }
}
