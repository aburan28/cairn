import SwiftUI
import CairnKit

public struct SettingsView: View {
    @EnvironmentObject private var model: AppModel
    @State private var draft: String = ""

    public init() {}

    public var body: some View {
        Form {
            Section {
                TextField("http://192.168.1.5:8080", text: $draft)
                    .textContentType(.URL)
                    #if os(iOS)
                    .keyboardType(.URL)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    #endif
                Button("Use this node") {
                    model.nodeURL = draft.trimmingCharacters(in: .whitespacesAndNewlines)
                    Task { await model.refresh() }
                }
                Button("Clear — use the snapshot") {
                    draft = ""
                    model.nodeURL = ""
                    Task { await model.refresh() }
                }
            } header: {
                Text("node")
            } footer: {
                Text("A cairn node publishes GET /objectives, /chain, /log, /checkpoint and /peers. Writes stay on the node's own origin; this app is a reader. Cleartext HTTP is allowed because an operator's node is often on a LAN or an SSH tunnel, and refusing it would make the app unable to read the one thing it exists to read.")
            }

            Section("status") {
                LabeledContent("configured") { Text(model.nodeURL.isEmpty ? "—" : model.nodeURL) }
                LabeledContent("resolved") { Text(model.resolvedBase.isEmpty ? "—" : model.resolvedBase) }
                LabeledContent("health") {
                    switch model.health {
                    case .live: Text("live")
                    case .down: Text("down")
                    case .checking: Text("checking")
                    }
                }
            }

            Section("fallback") {
                Text("When no node answers, the app shows \(model.snapshot.source) — the same settled log the public site uses, signed at the merkle root the Overview prints. It is not simulated.")
                    .font(.footnote)
            }
        }
        .navigationTitle("Settings")
        .onAppear { draft = model.nodeURL }
    }
}
