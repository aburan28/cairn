import AppKit
import SwiftUI

/// Pick a curated task; the checked objectives in Catalog follow that choice.
struct TasksView: View {
    @EnvironmentObject var model: ResearcherModel

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header.padding(12)
            Divider()
            List(selection: $model.selectedTaskId) {
                ForEach(GuiTasks.all) { task in
                    TaskRow(task: task)
                        .tag(task.id as String?)
                }
            }
            .listStyle(.inset(alternatesRowBackgrounds: true))
            .onChange(of: model.selectedTaskId) { id in
                guard let id, let task = GuiTasks.task(id: id) else { return }
                if Set(task.paths) != model.selectedObjectives {
                    model.selectTask(task)
                }
            }
            Divider()
            footer.padding(12)
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Tasks").font(.title2.bold())
            Text("Choose one task to select its objectives for posting. The researcher does not solve ECC2K-130 automatically — post the task, then work it with your client or the reader.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var footer: some View {
        HStack {
            if let task = model.activeTask {
                Text("Catalog selection: \(task.paths.count) objective\(task.paths.count == 1 ? "" : "s")")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button {
                model.pane = .secrets
            } label: {
                Label("Secrets…", systemImage: "key.fill")
            }
            .help("Paste AWS keys for campaign DP upload")
            Button {
                model.pane = .catalog
            } label: {
                Label("Catalog…", systemImage: "shippingbox")
            }
            .help("See plan lines and post while the researcher is stopped")
            Button {
                model.postNow(model.catalog.filter { model.selectedObjectives.contains($0.path) })
            } label: {
                Label("Post selected", systemImage: "tray.and.arrow.down")
            }
            .disabled(model.isLive || model.isBuilding || model.selectedUnpostedCatalog.isEmpty)
            .help("Append unposted objectives to the log with cairn post")
        }
    }
}

private struct TaskRow: View {
    @EnvironmentObject var model: ResearcherModel
    var task: GuiTask

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline) {
                Text(task.title).font(.headline)
                Spacer()
                if model.selectedTaskId == task.id {
                    Text("selected").font(.caption2.bold())
                        .padding(.horizontal, 6).padding(.vertical, 2)
                        .background(Color.accentColor.opacity(0.15), in: Capsule())
                }
            }
            Text(task.detail).font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            ForEach(task.paths, id: \.self) { path in
                objectiveLine(path: path)
            }
            HStack(spacing: 10) {
                if let doc = task.docPath {
                    Button("Show guide") {
                        let url = URL(fileURLWithPath: model.root + "/" + doc)
                        NSWorkspace.shared.activateFileViewerSelecting([url])
                    }
                    .disabled(!FileManager.default.fileExists(atPath: model.root + "/" + doc))
                }
                if let item = model.catalog.first(where: { task.paths.contains($0.path) }),
                   model.isPosted(item),
                   let row = model.status?.objectives.first(where: { $0.goal == item.goal }) {
                    Link("Open in reader", destination: model.readerURL(for: row.id))
                        .disabled(!model.nodeReachable)
                }
            }
            .font(.caption)
        }
        .padding(.vertical, 6)
        .contentShape(Rectangle())
        .onTapGesture { model.selectTask(task) }
    }

    @ViewBuilder
    private func objectiveLine(path: String) -> some View {
        HStack(spacing: 6) {
            if let item = model.catalog.first(where: { $0.path == path }) {
                if model.isPosted(item) {
                    Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
                } else {
                    Image(systemName: "circle").foregroundStyle(.secondary)
                }
                Text(item.goal).font(.caption.monospaced())
                Text(item.reward.formatted()).font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                if let p = model.plan[path] { planBadge(p) }
            } else {
                Image(systemName: "exclamationmark.triangle").foregroundStyle(.orange)
                Text(path).font(.caption.monospaced()).foregroundStyle(.secondary)
                Text("not in checkout").font(.caption2).foregroundStyle(.orange)
            }
        }
    }

    @ViewBuilder
    private func planBadge(_ p: PlanRow) -> some View {
        switch p.decision {
        case "solve":
            Text("autoresearcher would solve").font(.caption2).foregroundStyle(.green)
        case "decline":
            Text("autoresearcher declines").font(.caption2).foregroundStyle(.orange)
        default:
            Text("not in repertoire").font(.caption2).foregroundStyle(.secondary)
        }
    }
}
