import SwiftUI
import AppKit

struct JournalView: View {
    @EnvironmentObject var model: ResearcherModel
    @State private var onlyImportant = false
    @State private var follow = true

    var entries: [JournalEntry] {
        let q = model.journalFilter
        return model.journal.filter { e in
            (!onlyImportant || e.kind == .good || e.kind == .bad)
            && (q.isEmpty || e.event.localizedCaseInsensitiveContains(q) || e.detail.localizedCaseInsensitiveContains(q))
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                TextField("Filter events, ids, goals", text: $model.journalFilter).textFieldStyle(.roundedBorder).frame(width: 260)
                if !model.journalFilter.isEmpty {
                    Button { model.journalFilter = "" } label: { Image(systemName: "xmark.circle.fill") }.buttonStyle(.plain).foregroundStyle(.secondary)
                }
                Toggle("Outcomes only", isOn: $onlyImportant).toggleStyle(.checkbox)
                    .help("Settlements, reveals, solves, and anything that failed")
                Toggle("Follow", isOn: $follow).toggleStyle(.checkbox)
                Spacer()
                Text("\(entries.count) of \(model.journal.count)").foregroundStyle(.secondary).font(.caption)
                Button { copyAll() } label: { Image(systemName: "doc.on.doc") }.help("Copy the shown lines")
            }
            .padding(8)
            Divider()
            ScrollViewReader { proxy in
                List(entries) { e in
                    HStack(alignment: .top, spacing: 10) {
                        Text(e.time).font(.caption.monospaced()).foregroundStyle(.secondary).frame(width: 60, alignment: .leading)
                        Text(e.event).font(.callout.monospaced().bold()).foregroundStyle(color(e.kind)).frame(width: 160, alignment: .leading)
                        Text(e.detail).font(.callout.monospaced()).textSelection(.enabled)
                        Spacer(minLength: 0)
                        if let oid = e.fields["objective"], model.rows.contains(where: { $0.id.hasPrefix(oid) }) {
                            Button { model.open(objectivePrefix: oid) } label: { Image(systemName: "arrow.right.circle") }
                                .buttonStyle(.plain).foregroundStyle(.blue).help("Open this objective")
                        }
                    }
                    .listRowSeparator(.hidden)
                    .id(e.id)
                    .contextMenu {
                        if let oid = e.fields["objective"] {
                            Button("Show only this objective") { model.journalFilter = oid }
                            Button("Open objective") { model.open(objectivePrefix: oid) }
                        }
                        Button("Copy line") {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString("[\(e.time)] \(e.event)  \(e.detail)", forType: .string)
                        }
                    }
                }
                .onChange(of: model.journal.last?.id) { id in
                    if follow, let id { proxy.scrollTo(id, anchor: .bottom) }
                }
                .onAppear { if let id = entries.last?.id { proxy.scrollTo(id, anchor: .bottom) } }
            }
            .overlay {
                if model.journal.isEmpty {
                    Text("The journal is empty. Every event the researcher records appears here as it happens.").foregroundStyle(.secondary)
                } else if entries.isEmpty {
                    Text("Nothing matches the filter.").foregroundStyle(.secondary)
                }
            }
        }
    }

    private func color(_ k: JournalKind) -> Color {
        switch k {
        case .good: return .green
        case .bad: return .red
        case .active: return .blue
        case .muted: return .orange
        case .plain: return .primary
        }
    }

    private func copyAll() {
        let text = entries.map { "[\($0.time)] \($0.event)  \($0.detail)" }.joined(separator: "\n")
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
        model.infoMessage = "Copied \(entries.count) journal lines"
    }
}

struct ConsoleView: View {
    @EnvironmentObject var model: ResearcherModel
    @State private var follow = true

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("stdout and stderr of the researcher, a post, or make ui-build").font(.caption).foregroundStyle(.secondary)
                Spacer()
                Toggle("Follow", isOn: $follow).toggleStyle(.checkbox)
                Button("Copy") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(model.console, forType: .string)
                    model.infoMessage = "Console copied"
                }
                Button("Clear") { model.clearConsole() }
            }
            .padding(8)
            Divider()
            ScrollViewReader { proxy in
                ScrollView {
                    Text(model.console.isEmpty ? "Process output appears here." : model.console)
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(12)
                    Color.clear.frame(height: 1).id("end")
                }
                .onChange(of: model.console.count) { _ in if follow { proxy.scrollTo("end") } }
            }
        }
    }
}
