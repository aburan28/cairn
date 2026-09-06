import SwiftUI

enum Pane: String, CaseIterable, Identifiable {
    case overview = "Overview"
    case objectives = "Objectives"
    case catalog = "Catalog"
    case node = "Node"
    case journal = "Journal"
    case console = "Console"
    var id: String { rawValue }
    var icon: String {
        switch self {
        case .overview: return "gauge.with.dots.needle.33percent"
        case .objectives: return "list.bullet.rectangle.portrait"
        case .catalog: return "shippingbox"
        case .node: return "server.rack"
        case .journal: return "text.book.closed"
        case .console: return "terminal"
        }
    }
}

struct ContentView: View {
    @EnvironmentObject var model: ResearcherModel

    var body: some View {
        NavigationSplitView {
            List(selection: $model.pane) {
                ForEach(Pane.allCases) { p in
                    Label { Text(p.rawValue) } icon: { Image(systemName: p.icon) }
                        .badge(badge(for: p))
                        .tag(p)
                }
            }
            .navigationSplitViewColumnWidth(min: 170, ideal: 190)
            .safeAreaInset(edge: .bottom) { StatusFooter() }
        } detail: {
            switch model.pane ?? .overview {
            case .overview: OverviewView()
            case .objectives: ObjectivesView()
            case .catalog: CatalogView()
            case .node: NodeView()
            case .journal: JournalView()
            case .console: ConsoleView()
            }
        }
        .toolbar {
            ToolbarItem(placement: .navigation) {
                HStack(spacing: 8) {
                    if model.isLive || model.isBuilding { ProgressView().controlSize(.small) }
                    Text(model.phaseLine)
                        .font(.callout).foregroundStyle(.secondary).lineLimit(1)
                    Text("epoch \(model.currentEpoch) · \(model.secondsToNextEpoch)s")
                        .font(.caption.monospacedDigit()).foregroundStyle(.tertiary)
                        .help("Epochs are derived from the clock: unix time divided by the epoch length")
                }
            }
            ToolbarItemGroup(placement: .primaryAction) {
                if model.isIdle {
                    Button { model.sweepNow() } label: { Label("Sweep now", systemImage: "arrow.clockwise") }
                        .help("Cut the wait short and start the next sweep")
                }
                if model.isRunning {
                    Button { model.stop() } label: { Label("Stop", systemImage: "stop.fill") }
                        .help("Stop the researcher; it takes its node down with it")
                } else if model.foreignPid == nil {
                    Button { model.start(once: false) } label: { Label("Start", systemImage: "play.fill") }
                        .disabled(model.isBuilding)
                        .help("Post the selected objectives, start the node, and keep sweeping")
                    Button { model.start(once: true) } label: { Label("One sweep", systemImage: "forward.end.fill") }
                        .disabled(model.isBuilding)
                        .help("One pass over every objective, then stop")
                }
                Button { model.build() } label: { Label("Build", systemImage: "hammer") }
                    .disabled(model.isLive || model.isBuilding)
                    .help("make ui-build: the binary cairn run needs")
                Link(destination: model.readerURL) { Label("Reader", systemImage: "safari") }
                    .disabled(!model.nodeReachable)
                    .help("Open the node's reader in your browser")
            }
        }
        .alert("Autoresearcher", isPresented: Binding(get: { model.lastError != nil }, set: { if !$0 { model.clearError() } })) {
            Button("OK") { model.clearError() }
        } message: { Text(model.lastError ?? "") }
        .overlay(alignment: .bottom) {
            if let info = model.infoMessage {
                Text(info)
                    .padding(.horizontal, 14).padding(.vertical, 8)
                    .background(.regularMaterial, in: Capsule())
                    .padding(.bottom, 16)
                    .transition(.move(edge: .bottom).combined(with: .opacity))
                    .task { try? await Task.sleep(nanoseconds: 4_000_000_000); withAnimation { model.infoMessage = nil } }
            }
        }
        .animation(.default, value: model.infoMessage)
    }

    private func badge(for p: Pane) -> Int {
        switch p {
        case .objectives: return model.open.count + model.pendingReveals.count
        case .catalog: return model.selectedObjectives.count
        default: return 0
        }
    }
}

struct StatusFooter: View {
    @EnvironmentObject var model: ResearcherModel

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            Divider()
            dot(model.isLive ? .green : (model.isBuilding ? .orange : .gray),
                model.foreignPid != nil ? "researcher running elsewhere"
                    : (model.isRunning ? "researcher running" : (model.isBuilding ? "building" : "researcher stopped")))
            dot(model.nodeReachable ? .green : .gray,
                model.nodeReachable ? "node on \(model.httpAddress)" : "no node on \(model.httpAddress)")
            if let s = model.mySpendable {
                dot(.teal, "\(s.formatted()) spendable")
            }
        }
        .padding(.horizontal, 12).padding(.bottom, 10)
    }

    private func dot(_ color: Color, _ text: String) -> some View {
        HStack(spacing: 6) {
            Circle().fill(color).frame(width: 7, height: 7)
            Text(text).font(.caption).foregroundStyle(.secondary).lineLimit(1)
        }
    }
}

// MARK: small shared pieces

/// A counted fact. Given an `action` it becomes a way in to the rows it
/// counted, which is what an operator wants from a number they disagree with.
struct Tile: View {
    var title: String
    var value: String
    var color: Color
    var caption: String? = nil
    var action: (() -> Void)? = nil
    @State private var hovering = false

    var body: some View {
        let face = VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            Text(value).font(.title2.monospacedDigit().bold()).foregroundStyle(color).lineLimit(1).minimumScaleFactor(0.55)
            if let caption { Text(caption).font(.caption2).foregroundStyle(.tertiary).lineLimit(1) }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(color.opacity(hovering && action != nil ? 0.18 : 0.08), in: RoundedRectangle(cornerRadius: 8))

        if let action {
            Button(action: action) { face }
                .buttonStyle(.plain)
                .onHover { hovering = $0 }
                .help("Show these")
        } else {
            face
        }
    }
}

struct KeyValueRow: View {
    var key: String
    var value: String
    var mono = false
    var body: some View {
        GridRow {
            Text(key).foregroundStyle(.secondary).gridColumnAlignment(.trailing)
            Text(value).font(mono ? .body.monospaced() : .body).textSelection(.enabled).lineLimit(1).truncationMode(.middle)
        }
    }
}

extension ObjectiveRow {
    var icon: String {
        switch status {
        case "solved": return settled == true ? "checkmark.seal.fill" : "checkmark.seal"
        case "unreachable": return "hand.raised.fill"
        case "committed": return "lock.fill"
        default: return "circle.dashed"
        }
    }
    var color: Color {
        switch status {
        case "solved": return .green
        case "unreachable": return .orange
        case "committed": return .blue
        default: return .secondary
        }
    }
    var statusLabel: String {
        switch status {
        case "solved": return settled == true ? "paid" : "accepted"
        case "unreachable": return "declined"
        default: return status
        }
    }
}
