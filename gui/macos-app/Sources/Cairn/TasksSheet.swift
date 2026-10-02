import AppKit
import SwiftUI

/// Post a curated objective into this node's log: pick one, press Post.
///
/// Everything a task needs ships inside the app (`GuiTasks.library`), so
/// there is nothing to locate first. The sheet used to open on a "Checkout
/// folder" field that only a contributor with the repository could fill in.
struct TasksSheet: View {
    @ObservedObject var node: Node
    @ObservedObject var browser: Browser
    @Binding var isPresented: Bool

    @State private var selectedId: String = GuiTasks.all[0].id
    @State private var busy = false
    @State private var error: String?
    @State private var info: String?

    private var selected: GuiTask {
        GuiTasks.all.first { $0.id == selectedId } ?? GuiTasks.all[0]
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            VStack(alignment: .leading, spacing: 4) {
                Label("Post a task", systemImage: "target").font(.headline)
                Text("""
                    A ready-made challenge with its checker. Once posted, its bounty is \
                    listed under Objectives, and whoever solves it is paid when the \
                    checker accepts their answer.
                    """)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            VStack(spacing: 8) {
                ForEach(GuiTasks.all) { task in
                    TaskRow(
                        task: task,
                        payout: GuiTasks.payout(task),
                        available: GuiTasks.isAvailable(task),
                        isSelected: task.id == selectedId
                    )
                    .onTapGesture {
                        selectedId = task.id
                        error = nil
                        info = nil
                    }
                }
            }

            if let error {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .font(.callout)
                    .foregroundStyle(.red)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let info {
                Label(info, systemImage: "checkmark.circle.fill")
                    .font(.callout)
                    .foregroundStyle(.green)
                    .fixedSize(horizontal: false, vertical: true)
            }

            HStack {
                if let path = selected.docPath, let url = GuiTasks.docURL(path) {
                    Link("About this task", destination: url).font(.callout)
                }
                Spacer()
                if busy { ProgressView().controlSize(.small) }
                Button(info == nil ? "Cancel" : "Done") { isPresented = false }
                    .keyboardShortcut(.cancelAction)
                Button("Post") { post() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(busy || node.isAttached || !GuiTasks.isAvailable(selected))
            }
            // Said before the click, because the window reloads after it.
            Text("Posting pauses the node for a moment: its log has one writer.")
                .font(.caption)
                .foregroundStyle(.tertiary)
        }
        .padding(20)
        .frame(width: 560)
    }

    private func post() {
        guard let library = GuiTasks.library else { return }
        let task = selected
        error = nil
        info = nil
        do {
            for objective in task.objectives {
                try GuiTasks.stage(objective: objective, from: library, into: node.dataDir)
            }
        } catch {
            self.error = error.localizedDescription
            return
        }
        busy = true
        let files = task.objectives.map { library.appendingPathComponent($0).path }
        node.postObjectives(at: files) { err in
            busy = false
            guard let err else {
                info = "Posted. It is listed under Objectives once the node is back."
                browser.reload()
                return
            }
            // An objective's id is its content, so posting the same one twice
            // is refused by the node. That is not a failure to show in red.
            if err.contains("already posted") {
                info = "Already in this node's log."
            } else {
                error = err
            }
        }
    }
}

private struct TaskRow: View {
    let task: GuiTask
    let payout: String?
    let available: Bool
    let isSelected: Bool

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: isSelected ? "largecircle.fill.circle" : "circle")
                .foregroundStyle(isSelected ? Color.accentColor : Color.secondary)
                .padding(.top, 1)
            VStack(alignment: .leading, spacing: 4) {
                Text(task.title).font(.body.weight(.medium))
                Text(task.detail)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if !available {
                    Text("Not included in this build of Cairn.")
                        .font(.caption)
                        .foregroundStyle(.orange)
                } else if let payout {
                    Text(payout)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(10)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(isSelected ? Color.accentColor.opacity(0.10) : Color.clear)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .strokeBorder(isSelected ? Color.accentColor : Color.secondary.opacity(0.25))
        )
        .contentShape(Rectangle())
    }
}
