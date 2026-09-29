import AppKit
import SwiftUI

@main
struct CairnApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate

    var body: some Scene {
        // `Window`, not `WindowGroup`: there is one node, so there is one
        // window, and ⌘N has nothing to make.
        Window("Cairn", id: "main") {
            ContentView(node: delegate.node, browser: delegate.browser)
                .frame(minWidth: 720, minHeight: 480)
        }
        .defaultSize(width: 1180, height: 800)
        .commands {
            CommandGroup(replacing: .newItem) {}
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
            SettingsView(node: delegate.node)
        }
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    let node = Node()
    let browser = Browser()

    func applicationDidFinishLaunching(_ notification: Notification) {
        node.start()
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

    var body: some View {
        Group {
            switch node.state {
            case .running(let url):
                VStack(spacing: 0) {
                    NetworkStrip(node: node)
                    WebView(browser: browser)
                        .onAppear { browser.show(url) }
                        .onChange(of: url) { browser.show($0) }
                }
            case .starting, .stopped:
                Starting(node: node)
            case .failed(let message):
                Failed(node: node, message: message)
            }
        }
        .toolbar {
            ToolbarItemGroup {
                if case .running(let url) = node.state {
                    // Verbatim: as a localized key the port is a number to
                    // format, and 8080 reads "8,080".
                    Text(verbatim: url.host.map { "\($0):\(url.port ?? 80)" } ?? "")
                        .font(.callout.monospacedDigit())
                        .foregroundStyle(.secondary)
                        .help(node.isAttached
                              ? "Attached reader URL."
                              : "This node's reader. The same page opens in any browser on this Mac.")
                    if !node.isAttached, let listen = node.listenAddress {
                        Text(verbatim: "p2p \(listen)")
                            .font(.callout.monospacedDigit())
                            .foregroundStyle(.secondary)
                            .help(node.settings.listensLocallyOnly
                                  ? "P2P is on loopback: this node dials out and nothing dials in."
                                  : "P2P listen address. Hand this out with the peer id from Settings.")
                    }
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
    }
}

/// One line above the reader: whether anyone can dial this node, and whether
/// it has reached anyone. Taken from the node's own log, never guessed.
private struct NetworkStrip: View {
    @ObservedObject var node: Node

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: icon)
                .foregroundStyle(tint)
            Text(summary)
                .font(.callout)
                .lineLimit(1)
                .truncationMode(.middle)
            Spacer(minLength: 8)
            if let id = node.peerId {
                Text(verbatim: String(id.prefix(12)) + "…")
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .help("Transport peer id \(id). Copy it from Node → Copy Peer Id or Settings.")
            }
            if node.sessionsOK > 0 {
                Text("\(node.sessionsOK) session\(node.sessionsOK == 1 ? "" : "s")")
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 6)
        .background(Color(nsColor: .windowBackgroundColor))
        .overlay(alignment: .bottom) {
            Divider()
        }
    }

    private var summary: String {
        if node.isAttached {
            return "Attached to an existing node — this app owns no process."
        }
        if node.settings.listensLocallyOnly {
            if node.sessionsOK > 0 {
                return "Dialling out from this Mac only — reached a peer."
            }
            if node.settings.bootstrapFiles.isEmpty {
                return "Listening on this Mac only. LAN peers may find it; set a bootstrap or accept inbound in Settings to reach further."
            }
            return "Listening on this Mac only. Dialling bootstrap peers…"
        }
        if node.sessionsOK > 0 {
            return "Accepting inbound and reached \(node.sessionsOK) peer session\(node.sessionsOK == 1 ? "" : "s")."
        }
        if node.settings.bootstrapFiles.isEmpty {
            return "Accepting inbound. Waiting for a LAN peer, or add a bootstrap in Settings."
        }
        return "Accepting inbound. Dialling bootstrap peers…"
    }

    private var icon: String {
        if node.isAttached { return "link" }
        if node.sessionsOK > 0 { return "antenna.radiowaves.left.and.right" }
        if node.settings.listensLocallyOnly { return "lock.laptopcomputer" }
        return "network"
    }

    private var tint: Color {
        if node.isAttached { return .blue }
        if node.sessionsOK > 0 { return .green }
        if node.settings.listensLocallyOnly { return .orange }
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
