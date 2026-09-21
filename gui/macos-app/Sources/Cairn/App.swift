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
                Button("Restart Node") { delegate.node.restart() }
                    .keyboardShortcut("r", modifiers: [.command, .shift])
                Divider()
                Button("Show Data Folder") {
                    NSWorkspace.shared.activateFileViewerSelecting([delegate.node.dataDir])
                }
                Button("Show Node Log") {
                    NSWorkspace.shared.open(delegate.node.logFile)
                }
            }
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
    // nobody can see it.
    func applicationShouldTerminateAfterLastWindowClosed(_ app: NSApplication) -> Bool { true }

    func applicationWillTerminate(_ notification: Notification) {
        node.stop()
    }

    func openInBrowser() {
        if case .running(let url) = node.state { NSWorkspace.shared.open(url) }
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
        .toolbar {
            ToolbarItemGroup {
                if case .running(let url) = node.state {
                    Text(url.host.map { "\($0):\(url.port ?? 80)" } ?? "")
                        .font(.callout.monospacedDigit())
                        .foregroundStyle(.secondary)
                        .help("This node's reader. The same page opens in any browser on this Mac.")
                    Button { browser.reload() } label: { Label("Reload", systemImage: "arrow.clockwise") }
                        .help("Reload the page")
                    Button { NSWorkspace.shared.open(url) } label: { Label("Open in Browser", systemImage: "safari") }
                        .help("Open this page in your browser")
                }
            }
        }
    }
}

private struct Starting: View {
    @ObservedObject var node: Node

    var body: some View {
        VStack(spacing: 14) {
            ProgressView()
            Text("Starting a node…").font(.title3)
            Text(node.dataDir.path)
                .font(.callout.monospaced())
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
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
            Label("The node is not running", systemImage: "exclamationmark.triangle.fill")
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
                Button("Show Node Log") { NSWorkspace.shared.open(node.logFile) }
                Button("Show Data Folder") {
                    NSWorkspace.shared.activateFileViewerSelecting([node.dataDir])
                }
            }
        }
        .padding(28)
        .frame(maxWidth: 760, maxHeight: .infinity, alignment: .topLeading)
    }
}
