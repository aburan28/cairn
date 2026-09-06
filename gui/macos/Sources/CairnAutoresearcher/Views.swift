import SwiftUI

enum Pane: String, CaseIterable, Identifiable {
    case overview = "Overview"
    case objectives = "Objectives"
    case journal = "Journal"
    case console = "Console"
    case reader = "Node reader"
    var id: String { rawValue }
    var icon: String {
        switch self {
        case .overview: return "gauge"
        case .objectives: return "list.bullet.rectangle"
        case .journal: return "text.book.closed"
        case .console: return "terminal"
        case .reader: return "globe"
        }
    }
}

struct ContentView: View {
    @EnvironmentObject var model: ResearcherModel
    @State private var section: Pane? = .overview

    var body: some View {
        NavigationSplitView {
            List(Pane.allCases, selection: $section) { s in
                Label(s.rawValue, systemImage: s.icon).tag(s)
            }
            .navigationSplitViewColumnWidth(min: 160, ideal: 180)
            .safeAreaInset(edge: .bottom) { statusFooter }
        } detail: {
            switch section ?? .overview {
            case .overview: OverviewView()
            case .objectives: ObjectivesView()
            case .journal: JournalView()
            case .console: ConsoleView()
            case .reader: ReaderView()
            }
        }
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                if model.isRunning {
                    Button { model.stop() } label: { Label("Stop", systemImage: "stop.fill") }
                } else {
                    Button { model.start(once: false) } label: { Label("Start", systemImage: "play.fill") }
                        .disabled(model.isBuilding)
                    Button { model.start(once: true) } label: { Label("One sweep", systemImage: "forward.end.fill") }
                        .disabled(model.isBuilding)
                }
                Button { model.build() } label: { Label("Build", systemImage: "hammer") }
                    .disabled(model.isRunning || model.isBuilding)
            }
        }
        .alert("Autoresearcher", isPresented: Binding(
            get: { model.lastError != nil },
            set: { if !$0 { model.clearError() } })) {
            Button("OK") { model.clearError() }
        } message: { Text(model.lastError ?? "") }
    }

    private var statusFooter: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 6) {
                Circle().fill(model.isRunning ? Color.green : (model.isBuilding ? Color.orange : Color.gray))
                    .frame(width: 8, height: 8)
                Text(model.isRunning ? "researching" : (model.isBuilding ? "building" : "stopped"))
                    .font(.caption)
            }
            HStack(spacing: 6) {
                Circle().fill(model.nodeReachable ? Color.green : Color.gray).frame(width: 8, height: 8)
                Text(model.nodeReachable ? "node on \(model.httpAddress)" : "no node").font(.caption)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(10)
    }
}

// MARK: overview

struct OverviewView: View {
    @EnvironmentObject var model: ResearcherModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                Text("Crypto autoresearcher").font(.largeTitle.bold())
                Text("An unattended contributor to a cairn node. It posts the cryptographic objectives in examples/, starts one node over its own log, solves what its repertoire covers, scores every candidate with the objective's pinned verifier, and submits through commit and reveal. Nothing here grades its own work.")
                    .foregroundStyle(.secondary)

                HStack(spacing: 14) {
                    tile("Solved", "\(model.solved.count)", .green)
                    tile("Declined", "\(model.unreachable.count)", .orange)
                    tile("Open", "\(model.open.count)", .blue)
                    tile("Earned", model.earned.formatted(), .purple)
                    tile("Balance", model.status?.balance.map { $0.formatted() } ?? "–", .teal)
                }

                GroupBox("State") {
                    Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 6) {
                        row("Phase", model.status?.phase ?? (model.isRunning ? "starting" : "stopped"))
                        row("Checkout", model.root)
                        row("Binary", model.hasBinary ? model.cairnBinary : "missing – press Build")
                        row("Node", model.nodeReachable ? model.nodeURL.absoluteString : "not running")
                        row("Submitter", model.status?.submitter ?? "–")
                        row("Epoch", "\(model.status?.epoch_seconds ?? model.epochSeconds)s")
                        row("Updated", model.status?.updated ?? "–")
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }

                if !model.solved.isEmpty {
                    GroupBox("Settled results") {
                        VStack(alignment: .leading, spacing: 4) {
                            ForEach(model.solved) { r in
                                HStack {
                                    Image(systemName: "checkmark.seal.fill").foregroundStyle(.green)
                                    Text(r.goal ?? r.shortId).bold()
                                    Spacer()
                                    Text(r.settled == true ? "paid \(r.reward ?? 0)" : "accepted, settling")
                                        .foregroundStyle(.secondary)
                                    Text(r.claim.map { String($0.prefix(20)) } ?? "").font(.caption.monospaced())
                                        .foregroundStyle(.secondary)
                                }
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }

                if model.status == nil {
                    Text("No state yet. Press Start to post the objectives, launch the node and begin the sweep, or One sweep to run once and stop.")
                        .foregroundStyle(.secondary)
                }
            }
            .padding(24)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func tile(_ title: String, _ value: String, _ color: Color) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            Text(value).font(.title2.monospacedDigit().bold()).foregroundStyle(color)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(color.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
    }

    private func row(_ k: String, _ v: String) -> some View {
        GridRow {
            Text(k).foregroundStyle(.secondary)
            Text(v).textSelection(.enabled).lineLimit(1).truncationMode(.middle)
        }
    }
}

// MARK: objectives

struct ObjectivesView: View {
    @EnvironmentObject var model: ResearcherModel
    @State private var selection: ObjectiveRow.ID?

    var rows: [ObjectiveRow] { model.status?.objectives ?? [] }

    var body: some View {
        VStack(spacing: 0) {
            Table(rows, selection: $selection) {
                TableColumn("") { r in
                    Image(systemName: icon(r.status)).foregroundStyle(color(r.status))
                }.width(20)
                TableColumn("Goal") { r in Text(r.goal ?? r.shortId) }
                TableColumn("Status") { r in Text(r.status) }.width(90)
                TableColumn("Pool / paid") { r in
                    Text(r.reward.map { $0.formatted() } ?? "").monospacedDigit()
                }.width(90)
                TableColumn("Verifier") { r in Text(r.verifier ?? "") }.width(80)
                TableColumn("Outcome") { r in
                    Text(r.reason ?? r.claim.map { "claim \($0.prefix(20))…" } ?? "")
                        .foregroundStyle(.secondary)
                }
            }
            Divider()
            detail.frame(height: 120)
        }
    }

    @ViewBuilder private var detail: some View {
        if let r = rows.first(where: { $0.id == selection }) {
            ScrollView {
                VStack(alignment: .leading, spacing: 4) {
                    Text(r.goal ?? "").font(.headline)
                    Text(r.id).font(.caption.monospaced()).textSelection(.enabled)
                    if let reason = r.reason { Text(reason).textSelection(.enabled) }
                    if let claim = r.claim {
                        Text("claim \(claim)").font(.caption.monospaced()).textSelection(.enabled)
                        Text("verdict \(r.verdict ?? "?"), \(r.settled == true ? "settled for \(r.reward ?? 0)" : "not yet settled")")
                    }
                    if let s = r.strategy { Text("strategy \(s)").foregroundStyle(.secondary) }
                }
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            Text(rows.isEmpty ? "No objectives yet: start the researcher." : "Select an objective.")
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    private func icon(_ s: String) -> String {
        switch s {
        case "solved": return "checkmark.seal.fill"
        case "unreachable": return "xmark.octagon"
        case "committed": return "lock.fill"
        default: return "circle.dashed"
        }
    }
    private func color(_ s: String) -> Color {
        switch s {
        case "solved": return .green
        case "unreachable": return .orange
        case "committed": return .blue
        default: return .secondary
        }
    }
}

// MARK: journal and console

struct JournalView: View {
    @EnvironmentObject var model: ResearcherModel

    var body: some View {
        ScrollViewReader { proxy in
            List(model.journal) { e in
                HStack(alignment: .top, spacing: 10) {
                    Text(e.time).font(.caption.monospaced()).foregroundStyle(.secondary)
                    Text(e.event).font(.body.monospaced().bold()).frame(width: 170, alignment: .leading)
                    Text(e.detail).font(.caption.monospaced()).textSelection(.enabled)
                }
                .id(e.id)
            }
            .onChange(of: model.journal.last?.id) { id in
                if let id { proxy.scrollTo(id, anchor: .bottom) }
            }
            .overlay {
                if model.journal.isEmpty {
                    Text("The journal is empty.").foregroundStyle(.secondary)
                }
            }
        }
    }
}

struct ConsoleView: View {
    @EnvironmentObject var model: ResearcherModel

    var body: some View {
        ScrollViewReader { proxy in
            ScrollView {
                Text(model.console.isEmpty ? "Process output appears here." : model.console)
                    .font(.caption.monospaced())
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(12)
                Color.clear.frame(height: 1).id("end")
            }
            .onChange(of: model.console.count) { _ in proxy.scrollTo("end") }
        }
    }
}

// MARK: node reader

struct ReaderView: View {
    @EnvironmentObject var model: ResearcherModel
    @State private var page = 0

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Picker("", selection: $page) {
                    Text("Reader").tag(0)
                    Text("Chain").tag(1)
                    Text("Objectives JSON").tag(2)
                }
                .pickerStyle(.segmented)
                .frame(width: 320)
                Spacer()
                Link("Open in browser", destination: model.readerURL)
            }
            .padding(8)
            Divider()
            if model.nodeReachable {
                WebView(url: [model.readerURL, model.chainURL, model.nodeURL.appendingPathComponent("objectives")][page])
            } else {
                VStack(spacing: 8) {
                    Image(systemName: "network.slash").font(.largeTitle).foregroundStyle(.secondary)
                    Text("No node is answering on \(model.httpAddress).").foregroundStyle(.secondary)
                    Text("Start the researcher; it runs one.").font(.caption).foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
    }
}
