import SwiftUI

/// Which model drafts: the provider, and a model chosen from what that
/// provider serves this key. One view for Settings → AI and the New
/// challenge sheet, so changing one's mind in the sheet needs no second
/// window.
///
/// Once a key is there, the provider is asked what it serves (`GET /models`,
/// with the key, so an account sees its own deployments) and the answer
/// fills a menu beside the model field. Typing narrows the menu. A model the
/// provider does not list is said so on the spot, with the nearest served id
/// offered, rather than failing when a draft is first asked for. The field
/// still takes any id, for a model the list is behind on.
struct ModelPicker: View {
    @ObservedObject var node: Node
    /// One row, for the sheet; the labelled rows of a settings form otherwise.
    var compact = false
    /// Bumped by whoever saves or removes a key, so the served list is asked
    /// for again.
    var keyEpoch = 0
    /// Called when the provider changes, after the stored model is reloaded.
    var onProviderChange: (() -> Void)? = nil

    @AppStorage(AIConfig.Key.provider) private var providerRaw = AIProvider.anthropic.rawValue
    @AppStorage(AIConfig.Key.customBaseURL) private var customBaseURL = ""
    @State private var model = ""
    @State private var served: [String] = []
    @State private var servedProblem: String?
    @State private var listing = false

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
        Group {
            if compact {
                VStack(alignment: .leading, spacing: 6) {
                    HStack(spacing: 8) {
                        Picker("Provider", selection: $providerRaw) {
                            ForEach(AIProvider.allCases) { Text($0.title).tag($0.rawValue) }
                        }
                        .labelsHidden()
                        .fixedSize()
                        modelField
                    }
                    if provider == .custom { customField }
                    status
                }
            } else {
                Picker("Provider", selection: $providerRaw) {
                    ForEach(AIProvider.allCases) { Text($0.title).tag($0.rawValue) }
                }
                LabeledContent("Model") { modelField }
                if provider == .custom { customField }
                status
            }
        }
        .onChange(of: providerRaw) { _ in
            reload()
            onProviderChange?()
        }
        .task(id: "\(providerRaw)|\(keyEpoch)") {
            model = UserDefaults.standard.string(forKey: AIConfig.Key.model(provider)) ?? ""
            await discover()
        }
    }

    private var modelField: some View {
        HStack(spacing: 4) {
            TextField("Model", text: $model,
                      prompt: Text(provider.defaultModel.isEmpty ? "model id" : provider.defaultModel))
                .labelsHidden()
                .font(.body.monospaced())
                .frame(minWidth: compact ? 200 : 0)
                .onChange(of: model) { value in
                    UserDefaults.standard.set(value.trimmingCharacters(in: .whitespacesAndNewlines),
                                              forKey: AIConfig.Key.model(provider))
                }
            if listing {
                ProgressView().controlSize(.small)
            } else if !served.isEmpty {
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

    private var customField: some View {
        TextField("API address", text: $customBaseURL, prompt: Text("https://host/v1"))
            .font(.body.monospaced())
            .onSubmit { Task { await discover() } }
    }

    @ViewBuilder private var status: some View {
        if !served.isEmpty, !served.contains(effectiveModel) {
            HStack {
                Label("\(provider.title) does not serve \(effectiveModel).", systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.gray)
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
                .foregroundStyle(.gray)
                .font(.callout)
                .lineLimit(3)
        } else if !served.isEmpty {
            Text("One of \(served.count) models \(provider.title) serves.")
                .foregroundStyle(.secondary)
                .font(.callout)
        }
    }

    private func reload() {
        model = UserDefaults.standard.string(forKey: AIConfig.Key.model(provider)) ?? ""
        served = []
        servedProblem = nil
    }

    /// Ask the provider what it serves, so the model is chosen from that
    /// rather than typed and found wanting at draft time. Nothing without a
    /// key: the list is the one call that needs one.
    private func discover() async {
        let asked = provider
        guard let key = await node.secretValue(asked.secretName) else {
            served = []
            servedProblem = nil
            return
        }
        listing = true
        defer { listing = false }
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
}
