import SwiftUI
import CairnKit

/// The chrome. Tabs on iPhone, a sidebar on a wide Mac window — same pages
/// either way, because a second information architecture would be a second
/// place for a label to drift from the site.
public struct RootView: View {
    @EnvironmentObject private var model: AppModel

    public init() {}

    public var body: some View {
        Group {
            #if os(iOS)
            TabView {
                NavigationStack { OverviewView() }
                    .tabItem { Label("Overview", systemImage: "square.stack.3d.up") }
                NavigationStack { ObjectivesView() }
                    .tabItem { Label("Objectives", systemImage: "list.bullet.rectangle") }
                NavigationStack { ChainView() }
                    .tabItem { Label("Chain", systemImage: "link") }
                NavigationStack { LogView() }
                    .tabItem { Label("Log", systemImage: "text.alignleft") }
                NavigationStack { MoreView() }
                    .tabItem { Label("More", systemImage: "ellipsis.circle") }
            }
            #else
            NavigationSplitView {
                List {
                    NavigationLink("Overview") { OverviewView() }
                    NavigationLink("Objectives") { ObjectivesView() }
                    NavigationLink("Chain") { ChainView() }
                    NavigationLink("Log") { LogView() }
                    NavigationLink("Peers") { PeersView() }
                    NavigationLink("How it works") { HowItWorksView() }
                    NavigationLink("Settings") { SettingsView() }
                }
                .navigationTitle("cairn")
            } detail: {
                OverviewView()
            }
            #endif
        }
        .task { await model.refresh() }
    }
}

public struct MoreView: View {
    public init() {}
    public var body: some View {
        List {
            NavigationLink("Peers") { PeersView() }
            NavigationLink("How it works") { HowItWorksView() }
            NavigationLink("Settings") { SettingsView() }
            Section {
                Text("A reader, not a node. Nothing here re-derives a settlement or a chain — it reads what a node published and says where each number came from. The check that means something is `cairn audit` on a copy of the log.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
        .navigationTitle("More")
    }
}
