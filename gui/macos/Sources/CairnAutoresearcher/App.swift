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
    @StateObject private var model: ResearcherModel = {
        let m = ResearcherModel()
        AppDelegate.model = m
        return m
    }()

    var body: some Scene {
        WindowGroup("Cairn Autoresearcher") {
            ContentView()
                .environmentObject(model)
                .frame(minWidth: 960, minHeight: 600)
        }
        .commands {
            CommandGroup(replacing: .newItem) {}
            CommandMenu("Researcher") {
                Button(model.isRunning ? "Stop" : "Start") { model.toggle(once: false) }
                    .keyboardShortcut("r", modifiers: [.command])
                Button("Run One Sweep") { model.toggle(once: true) }
                    .keyboardShortcut("r", modifiers: [.command, .shift])
                    .disabled(model.isRunning)
                Divider()
                Button("Build cairn") { model.build() }
                    .keyboardShortcut("b", modifiers: [.command])
                    .disabled(model.isRunning || model.isBuilding)
            }
        }
        Settings {
            SettingsView().environmentObject(model)
        }
    }
}
