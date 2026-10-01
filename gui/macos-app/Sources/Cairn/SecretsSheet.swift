import AppKit
import SwiftUI
import UniformTypeIdentifiers

/// Paste named operator secrets into `~/.cairn/secrets` via `cairn secret`.
///
/// Values are written through `--stdin` so they never appear on the process
/// argument list. Names are listed; values are never shown after save — the
/// same rule as MCP `set_secret` / `list_secrets`.
struct SecretsSheet: View {
    @ObservedObject var node: Node
    @Binding var isPresented: Bool

    @State private var names: [String] = []
    @State private var secretsDir: String?
    @State private var name = ""
    @State private var value = ""
    @State private var revealValue = false
    @State private var busy = false
    @State private var error: String?
    @State private var info: String?

    /// Names the ECC2K campaign path and similar ops already read.
    private static let suggestions = [
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "DATABASE_URL",
        "RHO_DB_HOST",
    ]

    private var nameOK: Bool {
        let n = name.trimmed
        guard let first = n.first, first.isLetter || first == "_" else { return false }
        return n.count <= 128 && n.allSatisfy { $0.isLetter || $0.isNumber || $0 == "_" }
    }

    private var canSave: Bool {
        nameOK && !value.isEmpty && !busy
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Secrets", systemImage: "key.fill").font(.headline)
            Text("Paste a credential for scripts such as ECC2K-130 DP upload. Stored under \(secretsDir ?? "~/.cairn/secrets"), never in the log. Values are not shown again after Save.")
                .font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            pasteForm
            Divider()
            storedList

            if let error {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .font(.callout).foregroundStyle(.red).textSelection(.enabled)
            }
            if let info {
                Text(info).font(.callout).foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
            HStack {
                if busy { ProgressView().controlSize(.small) }
                Spacer()
                Button("Done") { isPresented = false }.keyboardShortcut(.cancelAction)
            }
        }
        .padding(18)
        .frame(width: 560, height: 520)
        .onAppear { refresh() }
    }

    private var pasteForm: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Paste a secret").font(.subheadline.bold())
            HStack {
                TextField("Name", text: $name, prompt: Text("AWS_ACCESS_KEY_ID"))
                    .font(.body.monospaced())
                    .textFieldStyle(.roundedBorder)
                Menu("Suggest") {
                    ForEach(Self.suggestions, id: \.self) { s in
                        Button(s) { name = s }
                    }
                }
                .frame(width: 90)
            }
            HStack(alignment: .top) {
                Group {
                    if revealValue {
                        TextEditor(text: $value)
                            .font(.body.monospaced())
                            .frame(minHeight: 72, maxHeight: 96)
                            .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.secondary.opacity(0.35)))
                    } else {
                        SecureField("Value (paste here)", text: $value)
                            .font(.body.monospaced())
                            .textFieldStyle(.roundedBorder)
                    }
                }
                VStack(spacing: 6) {
                    Toggle("Show", isOn: $revealValue).toggleStyle(.checkbox)
                    Button("From file…") { loadFromFile() }.disabled(busy)
                }
            }
            HStack {
                Button {
                    save()
                } label: {
                    Label(names.contains(name.trimmed) ? "Replace" : "Save", systemImage: "square.and.arrow.down")
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!canSave)
                Button("Paste name from clipboard") {
                    if let s = NSPasteboard.general.string(forType: .string)?.trimmed, !s.isEmpty, !s.contains("\n") {
                        name = s
                    }
                }
                .disabled(busy)
                Button("Paste value from clipboard") {
                    if let s = NSPasteboard.general.string(forType: .string) {
                        value = s
                    }
                }
                .disabled(busy)
                .help("Reads the clipboard into the value field, then clear the clipboard yourself when done")
            }
            Text("Save pipes the value into `cairn secret set NAME --stdin` so it never sits on the command line.")
                .font(.caption).foregroundStyle(.tertiary)
        }
    }

    private var storedList: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("Stored names").font(.subheadline.bold())
                Spacer()
                Button { refresh() } label: { Image(systemName: "arrow.clockwise") }
                    .disabled(busy)
                    .help("Refresh the list")
            }
            if names.isEmpty {
                Text("None yet.").font(.callout).foregroundStyle(.secondary)
            } else {
                List {
                    ForEach(names, id: \.self) { n in
                        HStack {
                            Text(n).font(.body.monospaced())
                            Spacer()
                            Button("Delete") { delete(n) }
                                .foregroundStyle(.red)
                                .disabled(busy)
                        }
                    }
                }
                .frame(minHeight: 120, maxHeight: 160)
            }
        }
    }

    private func refresh() {
        busy = true
        error = nil
        node.listSecrets { result in
            busy = false
            switch result {
            case .success(let listed):
                names = listed.names
                secretsDir = listed.dir
            case .failure(let message):
                error = message
            }
        }
    }

    private func save() {
        let n = name.trimmed
        guard nameOK, !value.isEmpty else { return }
        busy = true
        error = nil
        info = nil
        let payload = value
        node.setSecret(name: n, value: payload) { err in
            busy = false
            if let err { error = err; return }
            value = ""
            revealValue = false
            info = "Saved \(n). The value is not shown again."
            refresh()
        }
    }

    private func delete(_ n: String) {
        busy = true
        error = nil
        info = nil
        node.deleteSecret(name: n) { err in
            busy = false
            if let err { error = err; return }
            info = "Deleted \(n)."
            if name.trimmed == n { name = ""; value = "" }
            refresh()
        }
    }

    private func loadFromFile() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.message = "Read the secret value from this file (not stored as a path — contents are written via cairn secret)"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            value = try String(contentsOf: url, encoding: .utf8)
            if name.isEmpty {
                let base = url.deletingPathExtension().lastPathComponent
                if base.range(of: "^[A-Za-z_][A-Za-z0-9_]*$", options: .regularExpression) != nil {
                    name = base
                }
            }
            info = "Loaded from \(url.lastPathComponent). Press Save to store."
        } catch {
            self.error = error.localizedDescription
        }
    }
}

private extension String {
    var trimmed: String { trimmingCharacters(in: .whitespacesAndNewlines) }
}
