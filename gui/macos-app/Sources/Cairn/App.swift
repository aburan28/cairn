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
            CommandGroup(replacing: .appInfo) {
                Button("About Cairn") { showAboutPanel(node: delegate.node) }
                CheckForUpdatesButton(updates: delegate.updates)
            }
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
                Button("New Challenge…") { delegate.node.newChallenge() }
                    .keyboardShortcut("n", modifiers: [.command, .shift])
                    .disabled(delegate.node.isAttached)
                Button("Tasks…") { delegate.node.presentTasks = true }
                    .disabled(delegate.node.isAttached)
                Button("Connect an Agent…") { delegate.node.presentAgents = true }
                    .keyboardShortcut("a", modifiers: [.command, .shift])
                Button("Work on This Mac…") { delegate.node.work() }
                    .keyboardShortcut("w", modifiers: [.command, .shift])
                Button("Secrets…") { delegate.node.presentSecrets = true }
                Button("Peers…") { delegate.node.presentPeers = true }
                Button("Test Connectivity…") { delegate.node.presentConnectivity = true }
                    .keyboardShortcut("k", modifiers: [.command, .shift])
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
            SettingsView(node: delegate.node, updates: delegate.updates)
        }
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    let node = Node()
    let browser = Browser()
    let updates = Updates()

    func applicationDidFinishLaunching(_ notification: Notification) {
        browser.onDraftChallenge = { [node] brief in node.draftChallenge(fromPage: brief) }
        browser.onSetRole = { [node] role, on in node.setRole(fromPage: role, on: on) }
        browser.onOpen = { [node] sheet, objective in
            // Settings is a scene of the app, not a sheet of the window.
            if sheet == .settings {
                NSApp.sendAction(Selector(("showSettingsWindow:")), to: nil, from: nil)
                return nil
            }
            return node.open(fromPage: sheet, objective: objective)
        }
        browser.onWorkStatus = { [node] in node.worker.pageStatus() }
        browser.onStartWork = { [node] objective in node.startWorkFromPage(objective: objective) }
        browser.onPauseWork = { [node] in node.worker.requestPause() }
        browser.onResumeWork = { [node] in node.worker.resume() }
        browser.onStopWork = { [node] in
            node.worker.requestStop()
        }
        browser.onExitWork = { [node] in node.exitWork() }
        // A node the person asked to keep running is a launchd agent; make
        // sure it is loaded, then attach to it instead of spawning one.
        node.ensureBackgroundService()
        node.start()
    }

    // Closing the window is closing the node: nothing keeps running where
    // nobody can see it -- unless Settings asked for the launchd agent, in
    // which case the window was only attached and the agent carries on.
    // Attach mode has no process; still quit with the window.
    func applicationShouldTerminateAfterLastWindowClosed(_ app: NSApplication) -> Bool { true }

    func applicationWillTerminate(_ notification: Notification) {
        // The worker first: it is talking to the node, and a node that goes
        // mid-round leaves it a refusal to print rather than a last word.
        node.worker.stop()
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
                WebView(browser: browser)
                    .onAppear { browser.show(url) }
                    .onChange(of: url) { browser.show($0) }
            case .starting, .stopped:
                Starting(node: node)
            case .failed(let message):
                Failed(node: node, message: message)
            }
        }
        // The version under the window's title, so "which one am I on" needs
        // no menu. The node's is in the status popover and About Cairn.
        .navigationSubtitle(AppVersion.label)
        .toolbar {
            ToolbarItemGroup {
                if case .running(let url) = node.state {
                    // One status button rather than a strip of actions. New
                    // Challenge, Tasks, Peers, Agent, Secrets, Reload and Open
                    // in Browser used to sit here beside a sidebar that already
                    // listed most of them, so the window had two maps. They
                    // stay in the Node menu, as does Work on This Mac. The
                    // status popover still opens Peers, Test and the browser.
                    NodeStatusButton(node: node, url: url)
                }
                OpenSettingsButton(iconOnly: true)
                    .help("Where this node runs, and who can reach it")
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
        .sheet(isPresented: $node.presentNewChallenge) {
            NewChallengeSheet(node: node, browser: browser, isPresented: $node.presentNewChallenge)
        }
        .sheet(isPresented: $node.presentConnectivity) {
            ConnectivitySheet(node: node, isPresented: $node.presentConnectivity)
        }
        .sheet(isPresented: $node.presentAgents) {
            AgentsSheet(node: node, isPresented: $node.presentAgents)
        }
        .sheet(isPresented: $node.presentWork) {
            WorkSheet(node: node, worker: node.worker, isPresented: $node.presentWork)
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
                    Text("App").foregroundStyle(.secondary).gridColumnAlignment(.trailing)
                    Text(verbatim: AppVersion.label)
                }
                if let v = node.binaryVersion {
                    GridRow {
                        Text("Node").foregroundStyle(.secondary).gridColumnAlignment(.trailing)
                        Text(verbatim: "cairn \(v)")
                    }
                }
            }
            .font(.callout)

            if AppVersion.differs(fromNode: node.binaryVersion) {
                Label("The app and the cairn command are different versions.",
                      systemImage: "exclamationmark.triangle")
                    .font(.callout)
                    .foregroundStyle(.gray)
            }

            HStack {
                Button("Peers…") {
                    // Close the popover first: a sheet presented from under
                    // an open popover leaves the popover floating over it.
                    dismiss()
                    node.presentPeers = true
                }
                // The status word above is read from the log; this tests the
                // ports themselves.
                Button("Test…") {
                    dismiss()
                    node.presentConnectivity = true
                }
                .help("Test whether this node is listening, and whether the peers it dials answer")
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
        if isAttached { return .gray }
        if sessionsOK > 0 { return .green }
        if settings.listensLocallyOnly { return .gray }
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
                .foregroundStyle(.gray)
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
