import SwiftUI

/// Every example objective in the checkout, with a checkbox: the checked
/// ones are posted when the researcher next starts. Nothing here touches
/// the log; posting happens inside the researcher, before its node starts.
struct CatalogView: View {
    @EnvironmentObject var model: ResearcherModel
    @State private var search = ""

    var families: [(String, [CatalogItem])] {
        let items = model.catalog.filter {
            search.isEmpty || $0.goal.localizedCaseInsensitiveContains(search) || $0.path.localizedCaseInsensitiveContains(search)
        }
        return Dictionary(grouping: items, by: \.family).sorted { $0.key < $1.key }
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("\(model.selectedObjectives.count) of \(model.catalog.count) selected; posted at the next Start")
                    .foregroundStyle(.secondary)
                Spacer()
                TextField("Filter", text: $search).textFieldStyle(.roundedBorder).frame(width: 200)
                Button("Researcher default") { model.selectResearcherDefault() }
                    .help("The crypto set the researcher ships with (objectives.txt)")
                Button("All") { model.selectAll() }
                Button("None") { model.selectNone() }
                Button { model.rescanCatalog() } label: { Image(systemName: "arrow.clockwise") }.help("Rescan examples/")
            }
            .padding(8)
            Divider()
            List {
                ForEach(families, id: \.0) { family, items in
                    Section {
                        ForEach(items) { item in
                            HStack(spacing: 10) {
                                Toggle("", isOn: Binding(
                                    get: { model.selectedObjectives.contains(item.path) },
                                    set: { on in
                                        if on { model.selectedObjectives.insert(item.path) } else { model.selectedObjectives.remove(item.path) }
                                    }))
                                .labelsHidden()
                                .disabled(model.isRunning)
                                VStack(alignment: .leading, spacing: 1) {
                                    Text(item.goal).bold()
                                    Text(item.path).font(.caption.monospaced()).foregroundStyle(.secondary)
                                }
                                Spacer()
                                if model.isPosted(item) {
                                    Text("posted").font(.caption).padding(.horizontal, 6).padding(.vertical, 2)
                                        .background(Color.green.opacity(0.15), in: Capsule())
                                }
                                Text(item.kind).font(.caption).foregroundStyle(.secondary).frame(width: 80, alignment: .trailing)
                                Text(item.reward.formatted()).font(.body.monospacedDigit()).frame(width: 90, alignment: .trailing)
                            }
                        }
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
                            .disabled(model.isRunning)
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
            Text("A checked objective the log already holds is left alone: re-posting is refused by id, which is the right answer. Everything in the researcher's repertoire is solved or declined with a reason; the rest is recorded as out of repertoire.")
                .font(.caption).foregroundStyle(.secondary).padding(8)
        }
    }
}
