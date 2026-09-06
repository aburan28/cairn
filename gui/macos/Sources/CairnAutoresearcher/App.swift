import SwiftUI
import AppKit

/// Quitting the app must take the researcher, and through it the node, down
/// with it: a node left behind still holds the port and the ledger's lock.
final class AppDelegate: NSObject, NSApplicationDelegate {
    static var model: ResearcherModel?
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        AppDelegate.model?.terminateChildren()
        return .terminateNow
    }
}

@main
struct CairnAutoresearcherApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    // Not a @Published on the model: `isInserted` is a two-way binding that
    // SwiftUI reads and writes while updating the scene, so backing it with
    // one made every model publish re-enter the scene update and publish
    // again -- a render loop that pegged a core and grew without bound.
    // @AppStorage writes straight to UserDefaults and closes that circle.
    @AppStorage("menubar") private var menuBarItem = true
    @StateObject private var model: ResearcherModel = {
        let m = ResearcherModel()
        AppDelegate.model = m
        return m
    }()

    var body: some Scene {
        WindowGroup("Cairn Autoresearcher", id: "main") {
            ContentView()
                .environmentObject(model)
                .frame(minWidth: 960, minHeight: 600)
        }
        .commands {
            CommandGroup(replacing: .newItem) {}
            CommandMenu("Researcher") {
                Button(model.isRunning ? "Stop" : "Start") { model.toggle(once: false) }
                    .keyboardShortcut("r", modifiers: [.command])
                    .disabled(model.foreignPid != nil || model.isBuilding)
                Button("Run One Sweep") { model.toggle(once: true) }
                    .keyboardShortcut("r", modifiers: [.command, .shift])
                    .disabled(model.isLive || model.isBuilding)
                Button("Sweep Now") { model.sweepNow() }
                    .keyboardShortcut("s", modifiers: [.command, .shift])
                    .disabled(!model.isIdle)
                Divider()
                Button("Build cairn") { model.build() }
                    .keyboardShortcut("b", modifiers: [.command])
                    .disabled(model.isLive || model.isBuilding)
            }
            // ⌘1…⌘6 walk the sidebar, as in Mail and Finder.
            CommandGroup(after: .sidebar) {
                Divider()
                ForEach(Array(Pane.allCases.enumerated()), id: \.element) { i, p in
                    Button(p.rawValue) { model.pane = p }
                        .keyboardShortcut(KeyEquivalent(Character(String(i + 1))), modifiers: .command)
                }
                Divider()
            }
        }
        // A glance without the window: the phase, the counts, Start / Stop /
        // Sweep now. Optional, since a menu bar has only so much room.
        MenuBarExtra(isInserted: $menuBarItem) {
            MenuBarMenu().environmentObject(model)
        } label: {
            Image(systemName: model.isLive ? "square.stack.3d.up.fill" : "square.stack.3d.up")
        }
        Settings {
            SettingsView().environmentObject(model)
        }
    }
}

struct MenuBarMenu: View {
    @EnvironmentObject var model: ResearcherModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Text(model.phaseLine)
        Text("\(model.solved.count) solved · \(model.unreachable.count) declined · \(model.open.count) open")
        if let s = model.mySpendable { Text("\(s.formatted()) spendable") }
        Divider()
        if model.isRunning {
            Button("Stop") { model.stop() }
        } else {
            Button("Start") { model.start(once: false) }.disabled(model.isBuilding || model.foreignPid != nil)
        }
        Button("Sweep now") { model.sweepNow() }.disabled(!model.isIdle)
        Divider()
        Button("Open Cairn Autoresearcher") {
            openWindow(id: "main")
            NSApp.activate(ignoringOtherApps: true)
        }
        Button("Quit") { NSApp.terminate(nil) }.keyboardShortcut("q")
    }
}
