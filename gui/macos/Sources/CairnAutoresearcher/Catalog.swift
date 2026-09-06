import SwiftUI

/// Every example objective in the checkout, with a checkbox and the
/// researcher's own verdict on it at the current budget: solve (with an
/// estimate), decline (with the reason), or out of repertoire. The checked
/// ones are posted when the researcher next starts, or now, with Post.
struct CatalogView: View {
    @EnvironmentObject var model: ResearcherModel
    @State private var search = ""
    @State private var onlySolvable = false

    var families: [(String, [CatalogItem])] {
        let items = model.catalog.filter {
            (search.isEmpty || $0.goal.localizedCaseInsensitiveContains(search) || $0.path.localizedCaseInsensitiveContains(search))
            && (!onlySolvable || model.plan[$0.path]?.decision == "solve")
        }
        return Dictionary(grouping: items, by: \.family).sorted { $0.key < $1.key }
    }

    var selectedItems: [CatalogItem] { model.catalog.filter { model.selectedObjectives.contains($0.path) } }
    var solvableSelected: Int { selectedItems.filter { model.plan[$0.path]?.decision == "solve" }.count }
    var selectedUnposted: [CatalogItem] { selectedItems.filter { !model.isPosted($0) } }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("\(model.selectedObjectives.count) of \(model.catalog.count) selected").bold()
                    Text("\(solvableSelected) in repertoire at a \(model.budgetMinutes)-minute budget · \(selectedUnposted.count) not yet posted")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                if model.planning { ProgressView().controlSize(.small) }
                TextField("Filter", text: $search).textFieldStyle(.roundedBorder).frame(width: 170)
                Toggle("Solvable only", isOn: $onlySolvable).toggleStyle(.checkbox)
                Menu("Select") {
                    Button("Researcher default") { model.selectResearcherDefault() }
                    Button("Everything the plan says solve") {
                        model.selectedObjectives = Set(model.catalog.filter { model.plan[$0.path]?.decision == "solve" }.map(\.path))
                    }
                    Button("All") { model.selectAll() }
                    Button("None") { model.selectNone() }
                }
                .frame(width: 90)
                .disabled(model.isLive)
                Button { model.rescanCatalog() } label: { Image(systemName: "arrow.clockwise") }.help("Rescan examples/ and re-plan")
            }
            .padding(8)
            Divider()
            List {
                ForEach(families, id: \.0) { family, items in
                    Section {
                        ForEach(items) { item in CatalogRow(item: item) }
                    } header: {
                        HStack {
                            Text(family)
                            Spacer()
                            Button(items.allSatisfy { model.selectedObjectives.contains($0.path) } ? "none" : "all") {
                                if items.allSatisfy({ model.selectedObjectives.contains($0.path) }) {
                                    items.forEach { model.selectedObjectives.remove($0.path) }
                                } else {
                                    items.forEach { model.selectedObjectives.insert($0.path) }
                                }
                            }
                            .buttonStyle(.plain).foregroundStyle(.blue).font(.caption)
                            .disabled(model.isLive)
                        }
                    }
                }
            }
            .overlay {
                if model.catalog.isEmpty {
                    Text("No examples/**/objective*.json under \(model.root).").foregroundStyle(.secondary)
                }
            }
            Divider()
            HStack {
                Text("Checked objectives are posted at the next Start. A checked objective the log already holds is left alone: re-posting is refused by id.")
                    .font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button {
                    model.postNow(selectedUnposted)
                } label: { Label("Post \(selectedUnposted.count) now", systemImage: "tray.and.arrow.down") }
                    .disabled(selectedUnposted.isEmpty || model.isLive || model.isBuilding)
                    .help("Append the unposted checked objectives to the researcher's log with the CLI. Needs the node stopped: a ledger has one writer.")
            }
            .padding(8)
        }
    }
}

struct CatalogRow: View {
    @EnvironmentObject var model: ResearcherModel
    var item: CatalogItem

    var body: some View {
        HStack(spacing: 10) {
            Toggle("", isOn: Binding(
                get: { model.selectedObjectives.contains(item.path) },
                set: { on in if on { model.selectedObjectives.insert(item.path) } else { model.selectedObjectives.remove(item.path) } }))
            .labelsHidden()
            .disabled(model.isLive)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(item.goal).bold()
                    if model.isPosted(item) {
                        Text("posted").font(.caption2).padding(.horizontal, 5).padding(.vertical, 1)
                            .background(Color.green.opacity(0.15), in: Capsule())
                    }
                }
                Text(item.path).font(.caption.monospaced()).foregroundStyle(.secondary)
                if let p = model.plan[item.path] { planLine(p) }
            }
            Spacer()
            Text(item.kind).font(.caption).foregroundStyle(.secondary).frame(width: 80, alignment: .trailing)
            Text(item.reward.formatted()).font(.body.monospacedDigit()).frame(width: 90, alignment: .trailing)
        }
        .padding(.vertical, 2)
    }

    @ViewBuilder private func planLine(_ p: PlanRow) -> some View {
        switch p.decision {
        case "solve":
            Label("\(p.strategy ?? "") would solve it, about \(estimate(p.est_seconds ?? 0))", systemImage: "bolt.fill")
                .font(.caption).foregroundStyle(.green)
        case "decline":
            Label("\(p.strategy ?? "") declines: \(p.reason ?? "")", systemImage: "hand.raised")
                .font(.caption).foregroundStyle(.orange).lineLimit(2).help(p.reason ?? "")
        case "none":
            Label("no strategy in the repertoire", systemImage: "questionmark.circle")
                .font(.caption).foregroundStyle(.secondary)
        default:
            Label(p.reason ?? "could not read", systemImage: "exclamationmark.triangle")
                .font(.caption).foregroundStyle(.red)
        }
    }

    private func estimate(_ s: Double) -> String {
        if s < 1 { return "a second" }
        if s < 90 { return "\(Int(s.rounded()))s" }
        if s < 5400 { return "\(Int((s / 60).rounded())) min" }
        return String(format: "%.1f h", s / 3600)
    }
}
