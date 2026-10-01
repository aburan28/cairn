import AppKit
import SwiftUI

/// Post a curated objective from a source checkout into this node's log.
struct TasksSheet: View {
    @ObservedObject var node: Node
    @ObservedObject var browser: Browser
    @Binding var isPresented: Bool

    @AppStorage(NodeSettings.Key.checkoutRoot) private var checkoutRoot = ""
    @State private var selectedId: String = GuiTasks.all[0].id
    @State private var busy = false
    @State private var error: String?
    @State private var info: String?

    private var checkout: URL? {
        let raw = checkoutRoot.trimmingCharacters(in: .whitespacesAndNewlines)
        if !raw.isEmpty { return URL(fileURLWithPath: raw, isDirectory: true) }
        if let env = ProcessInfo.processInfo.environment["CAIRN_REPO"], !env.isEmpty {
            return URL(fileURLWithPath: env, isDirectory: true)
        }
        return nil
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Tasks", systemImage: "target").font(.headline)
            Text("Pick a task and post its objective into this node's log. The reader then shows the bounty; settlement still goes through submit and reveal as usual.")
                .font(.callout).foregroundStyle(.secondary)
            checkoutPicker
            Divider()
            Picker("Task", selection: $selectedId) {
                ForEach(GuiTasks.all) { task in
                    Text(task.title).tag(task.id)
                }
            }
            if let task = GuiTasks.all.first(where: { $0.id == selectedId }) {
                Text(task.detail).font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                ForEach(task.paths, id: \.self) { path in
                    Text(path).font(.caption.monospaced()).foregroundStyle(.tertiary)
                }
            }
            if let error {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .font(.callout).foregroundStyle(.red).textSelection(.enabled)
            }
            if let info {
                Text(info).font(.callout).foregroundStyle(.secondary)
            }
            Text("Campaign DP upload needs AWS credentials in Secrets (Node → Secrets…), not in this sheet.")
                .font(.caption).foregroundStyle(.tertiary)
            Spacer(minLength: 0)
            HStack {
                if busy { ProgressView().controlSize(.small) }
                Button("Secrets…") {
                    isPresented = false
                    node.presentSecrets = true
                }
                Spacer()
                Button("Cancel") { isPresented = false }.keyboardShortcut(.cancelAction)
                Button("Post to log") { postSelected() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(busy || node.isAttached || checkout == nil)
            }
        }
        .padding(18)
        .frame(width: 560, height: 420)
    }

    private var checkoutPicker: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Checkout folder").font(.subheadline.bold())
            HStack {
                TextField("Path to cairn repository", text: $checkoutRoot, prompt: Text("/path/to/cairn"))
                    .font(.body.monospaced())
                Button("Choose…") { chooseCheckout() }
            }
            Text("Must contain examples/certicom-ecdlp. Saved in Settings, or set CAIRN_REPO when launching the app.")
                .font(.caption).foregroundStyle(.tertiary)
            if let root = checkout {
                let ok = FileManager.default.fileExists(
                    atPath: root.appendingPathComponent("examples/certicom-ecdlp").path)
                Label(ok ? "Found certicom examples" : "No examples/certicom-ecdlp here",
                      systemImage: ok ? "checkmark.circle" : "exclamationmark.triangle")
                .font(.caption)
                .foregroundStyle(ok ? .green : .orange)
            }
        }
    }

    private func chooseCheckout() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        panel.message = "Choose the cairn repository checkout"
        if panel.runModal() == .OK, let url = panel.url {
            checkoutRoot = url.path
        }
    }

    private func postSelected() {
        guard let task = GuiTasks.all.first(where: { $0.id == selectedId }),
              let root = checkout else { return }
        error = nil; info = nil; busy = true
        let paths = task.paths.map { root.appendingPathComponent($0).path }
        node.postObjectives(at: paths) { err in
            busy = false
            if let err { error = err }
            else {
                info = "Posted."
                browser.reload()
            }
        }
    }
}
