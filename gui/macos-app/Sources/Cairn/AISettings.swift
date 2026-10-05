import SwiftUI

/// Settings → AI: which model drafts challenges, and its key.
///
/// The key goes into `~/.cairn/secrets` through `cairn secret set --stdin`,
/// like every other credential this app handles: one store, listed in
/// Node → Secrets…, never on a command line, and under the name the
/// provider's own tools read, so a terminal agent can be handed the same key
/// with `cairn secret run`. The app reads it back only when it needs it.
///
/// The provider and model controls are `ModelPicker`, shared with the New
/// challenge sheet, so the sheet can change them without opening this window.
struct AISettingsSection: View {
    @ObservedObject var node: Node

    @AppStorage(AIConfig.Key.provider) private var providerRaw = AIProvider.anthropic.rawValue
    @State private var pasted = ""
    @State private var hasKey: Bool?
    @State private var status: (ok: Bool, text: String)?
    @State private var busy = false
    /// Bumped when a key is saved or removed, so the picker asks the provider
    /// for its models again.
    @State private var keyEpoch = 0

    private var provider: AIProvider { AIProvider(rawValue: providerRaw) ?? .anthropic }

    var body: some View {
        Section {
            ModelPicker(node: node, keyEpoch: keyEpoch) {
                pasted = ""
                status = nil
            }

            LabeledContent("API key") {
                HStack {
                    SecureField(hasKey == true ? "Saved — paste to replace" : "Paste key", text: $pasted)
                        .frame(minWidth: 180)
                        .onSubmit(save)
                    Button("Save", action: save)
                        .disabled(pasted.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || busy)
                }
            }

            HStack {
                if busy {
                    ProgressView().controlSize(.small)
                } else if let status {
                    Label(status.text, systemImage: status.ok ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                        .foregroundStyle(status.ok ? Color.green : Color.gray)
                        .lineLimit(3)
                } else if hasKey == false {
                    Text("No key saved for \(provider.title).").foregroundStyle(.secondary)
                } else if hasKey == true {
                    Text(verbatim: "Saved as \(provider.secretName).").foregroundStyle(.secondary)
                }
                Spacer()
                if let page = provider.keyPage {
                    Link("Get a key", destination: page)
                }
                Button("Test") { test() }
                    .disabled(hasKey != true || busy)
                Button("Remove") { remove() }
                    .disabled(hasKey != true || busy)
            }
            .font(.callout)
        } header: {
            Text("AI")
        } footer: {
            Text("""
                Node → New Challenge… turns a plain description into a Lean theorem, written \
                by this model and compiled before anything is posted. Requests go from this \
                Mac straight to \(provider.title), streamed, so the sheet shows the draft \
                arriving; the node never sees the key. Keys are kept in ~/.cairn/secrets, \
                readable by your user only, and not encrypted on disk.
                """)
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.leading)
                .frame(maxWidth: .infinity, alignment: .leading)
                .fixedSize(horizontal: false, vertical: true)
        }
        .task(id: providerRaw) { await checkKey() }
    }

    private func checkKey() async {
        hasKey = nil
        hasKey = await node.secretValue(provider.secretName) != nil
    }

    private func save() {
        let key = pasted.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !key.isEmpty else { return }
        busy = true
        status = nil
        node.setSecret(name: provider.secretName, value: key) { err in
            busy = false
            pasted = ""
            if let err {
                status = (false, err)
            } else {
                hasKey = true
                keyEpoch += 1
                test()
            }
        }
    }

    private func test() {
        busy = true
        status = nil
        Task {
            defer { busy = false }
            guard let key = await node.secretValue(provider.secretName) else {
                hasKey = false
                return
            }
            do {
                try await AIClient(config: AIConfig.current(), apiKey: key).test()
                status = (true, "\(provider.title) accepted the key.")
            } catch {
                status = (false, error.localizedDescription)
            }
        }
    }

    private func remove() {
        busy = true
        node.deleteSecret(name: provider.secretName) { err in
            busy = false
            if let err {
                status = (false, err)
            } else {
                hasKey = false
                status = nil
                keyEpoch += 1
            }
        }
    }
}
