import SwiftUI

/// Settings → AI: which model drafts challenges, and its key.
///
/// The key goes into `~/.cairn/secrets` through `cairn secret set --stdin`,
/// like every other credential this app handles: one store, listed in
/// Node → Secrets…, never on a command line, and under the name the
/// provider's own tools read, so a terminal agent can be handed the same key
/// with `cairn secret run`. The app reads it back only when it needs it.
struct AISettingsSection: View {
    @ObservedObject var node: Node

    @AppStorage(AIConfig.Key.provider) private var providerRaw = AIProvider.anthropic.rawValue
    @AppStorage(AIConfig.Key.customBaseURL) private var customBaseURL = ""
    @State private var model = ""
    @State private var pasted = ""
    @State private var hasKey: Bool?
    @State private var status: (ok: Bool, text: String)?
    @State private var busy = false
    /// What the provider said it serves, once a key is there to ask with.
    @State private var served: [String] = []
    @State private var servedProblem: String?

    private var provider: AIProvider { AIProvider(rawValue: providerRaw) ?? .anthropic }

    /// The id a draft would use: the field, or the default behind it.
    private var effectiveModel: String {
        let typed = model.trimmingCharacters(in: .whitespacesAndNewlines)
        return typed.isEmpty ? provider.defaultModel : typed
    }

    /// The menu's rows: everything served, narrowed by what has been typed
    /// so far once that stops matching any id outright.
    private var menuModels: [String] {
        let typed = model.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !typed.isEmpty, !served.contains(where: { $0.lowercased() == typed }) else { return served }
        let narrowed = served.filter { $0.lowercased().contains(typed) }
        return narrowed.isEmpty ? served : narrowed
    }

    var body: some View {
        Section {
            Picker("Provider", selection: $providerRaw) {
                ForEach(AIProvider.allCases) { Text($0.title).tag($0.rawValue) }
            }
            .onChange(of: providerRaw) { _ in reload() }

            LabeledContent("Model") {
                HStack(spacing: 4) {
                    TextField("Model", text: $model, prompt: Text(provider.defaultModel.isEmpty ? "model id" : provider.defaultModel))
                        .labelsHidden()
                        .font(.body.monospaced())
                        .onChange(of: model) { value in
                            UserDefaults.standard.set(value.trimmingCharacters(in: .whitespacesAndNewlines),
                                                      forKey: AIConfig.Key.model(provider))
                        }
                    if !served.isEmpty {
                        Menu {
                            ForEach(menuModels, id: \.self) { id in
                                Button(id) { model = id }
                            }
                        } label: {
                            Image(systemName: "chevron.up.chevron.down")
                        }
                        .menuStyle(.borderlessButton)
                        .menuIndicator(.hidden)
                        .fixedSize()
                        .help("The \(served.count) models \(provider.title) serves this key")
                        .accessibilityLabel("Served models")
                    }
                }
            }

            if provider == .custom {
                TextField("API address", text: $customBaseURL, prompt: Text("https://host/v1"))
                    .font(.body.monospaced())
                    .onSubmit { Task { await discover() } }
            }

            if !served.isEmpty, !served.contains(effectiveModel) {
                HStack {
                    Label("\(provider.title) does not serve \(effectiveModel).", systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                        .lineLimit(2)
                    Spacer()
                    if let nearest = AIClient.nearest(to: effectiveModel, in: served) {
                        Button("Use \(nearest)") { model = nearest }
                            .font(.callout.monospaced())
                    } else {
                        Text("Choose one from the list.").foregroundStyle(.secondary)
                    }
                }
                .font(.callout)
            } else if let servedProblem {
                Label(servedProblem, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                    .font(.callout)
                    .lineLimit(3)
            } else if !served.isEmpty {
                Text("One of \(served.count) models \(provider.title) serves.")
                    .foregroundStyle(.secondary)
                    .font(.callout)
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
                        .foregroundStyle(status.ok ? Color.green : Color.orange)
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
                Node → New Challenge… turns a plain description into a challenge, with a \
                checker written by this model and tested before anything is posted. Requests \
                go from this Mac straight to \(provider.title); the node never sees the key. \
                Keys are kept in ~/.cairn/secrets, readable by your user only, and not \
                encrypted on disk.
                """)
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.leading)
                .frame(maxWidth: .infinity, alignment: .leading)
                .fixedSize(horizontal: false, vertical: true)
        }
        .task(id: providerRaw) {
            await checkKey()
            if hasKey == true { await discover() }
        }
        .onAppear { model = UserDefaults.standard.string(forKey: AIConfig.Key.model(provider)) ?? "" }
    }

    private func reload() {
        model = UserDefaults.standard.string(forKey: AIConfig.Key.model(provider)) ?? ""
        pasted = ""
        status = nil
        served = []
        servedProblem = nil
    }

    private func checkKey() async {
        hasKey = nil
        hasKey = await node.secretValue(provider.secretName) != nil
    }

    /// Ask the provider what it serves, so the model is chosen from that
    /// rather than typed and found wanting at draft time.
    private func discover() async {
        let asked = provider
        guard let key = await node.secretValue(asked.secretName) else { return }
        do {
            let list = try await AIClient(config: AIConfig.current(), apiKey: key).models()
            guard asked == provider else { return }
            served = list
            servedProblem = nil
        } catch {
            guard asked == provider else { return }
            served = []
            servedProblem = "Could not list models: \(error.localizedDescription)"
        }
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
                await discover()
            } catch {
                status = (false, error.localizedDescription)
            }
        }
    }

    private func remove() {
        busy = true
        node.deleteSecret(name: provider.secretName) { err in
            busy = false
            if let err { status = (false, err) } else { hasKey = false; status = nil; served = []; servedProblem = nil }
        }
    }
}
