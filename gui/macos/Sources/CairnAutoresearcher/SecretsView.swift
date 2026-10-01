import AppKit
import SwiftUI

/// Paste named operator secrets via `bin/cairn secret set --stdin`.
struct SecretsView: View {
    @EnvironmentObject var model: ResearcherModel

    @State private var names: [String] = []
    @State private var secretsDir: String?
    @State private var name = ""
    @State private var value = ""
    @State private var revealValue = false
    @State private var busy = false
    @State private var error: String?
    @State private var info: String?

    private static let suggestions = [
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "DATABASE_URL", "RHO_DB_HOST",
    ]

    private var nameOK: Bool {
        let n = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let first = n.first, first.isLetter || first == "_" else { return false }
        return n.count <= 128 && n.allSatisfy { $0.isLetter || $0.isNumber || $0 == "_" }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header.padding(12)
            Divider()
            Form {
                Section {
                    HStack {
                        TextField("Name", text: $name, prompt: Text("AWS_ACCESS_KEY_ID"))
                            .font(.body.monospaced())
                        Menu("Suggest") {
                            ForEach(Self.suggestions, id: \.self) { s in
                                Button(s) { name = s }
                            }
                        }
                    }
                    if revealValue {
                        TextEditor(text: $value)
                            .font(.body.monospaced())
                            .frame(minHeight: 64)
                    } else {
                        SecureField("Value (paste here)", text: $value)
                            .font(.body.monospaced())
                    }
                    Toggle("Show value while editing", isOn: $revealValue)
                    HStack {
                        Button("Paste value from clipboard") {
                            if let s = NSPasteboard.general.string(forType: .string) { value = s }
                        }
                        Button(names.contains(name.trimmingCharacters(in: .whitespacesAndNewlines)) ? "Replace" : "Save") {
                            save()
                        }
                        .disabled(!nameOK || value.isEmpty || busy || !model.hasBinary)
                        .keyboardShortcut(.defaultAction)
                    }
                } header: {
                    Text("Paste a secret")
                } footer: {
                    Text("Piped into `cairn secret set NAME --stdin`. Values are never listed after Save. Used by scripts/ecc2k-dp.sh and similar.")
                        .font(.caption)
                }

                Section("Stored names") {
                    if names.isEmpty {
                        Text("None yet.").foregroundStyle(.secondary)
                    } else {
                        ForEach(names, id: \.self) { n in
                            HStack {
                                Text(n).font(.body.monospaced())
                                Spacer()
                                Button("Delete", role: .destructive) { delete(n) }.disabled(busy)
                            }
                        }
                    }
                    Button("Refresh") { refresh() }.disabled(busy)
                }

                if let error {
                    Section {
                        Text(error).foregroundStyle(.red).textSelection(.enabled)
                    }
                }
                if let info {
                    Section {
                        Text(info).foregroundStyle(.secondary)
                    }
                }
            }
            .formStyle(.grouped)
        }
        .onAppear { refresh() }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Secrets").font(.title2.bold())
            Text(secretsDir.map { "Directory: \($0)" } ?? "Named credentials for campaign scripts (ECC2K DP upload, …).")
                .font(.callout).foregroundStyle(.secondary)
                .textSelection(.enabled)
        }
    }

    private func refresh() {
        busy = true
        error = nil
        model.listSecrets { result in
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
        let n = name.trimmingCharacters(in: .whitespacesAndNewlines)
        busy = true
        error = nil
        info = nil
        model.setSecret(name: n, value: value) { err in
            busy = false
            if let err { error = err; return }
            value = ""
            revealValue = false
            info = "Saved \(n)."
            refresh()
        }
    }

    private func delete(_ n: String) {
        busy = true
        error = nil
        model.deleteSecret(name: n) { err in
            busy = false
            if let err { error = err; return }
            info = "Deleted \(n)."
            refresh()
        }
    }
}
