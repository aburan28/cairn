import SwiftUI
import AppKit

struct SettingsView: View {
    @EnvironmentObject var model: ResearcherModel
    @State private var keepIdentity = true
    @State private var confirmReset = false

    var body: some View {
        Form {
            Section("Checkout") {
                HStack {
                    TextField("cairn repository", text: $model.root).disabled(model.isRunning)
                    Button("Choose…") { choose() }.disabled(model.isRunning)
                }
                Text(model.hasCheckout ? "research/crypto-autoresearcher found" : "no autoresearcher at this path")
                    .font(.caption).foregroundStyle(model.hasCheckout ? Color.secondary : Color.red)
            }
            Section("Node") {
                TextField("HTTP address", text: $model.httpAddress).disabled(model.isRunning)
                TextField("P2P address", text: $model.p2pAddress).disabled(model.isRunning)
                Stepper("Epoch length: \(model.epochSeconds)s", value: $model.epochSeconds, in: 1...600).disabled(model.isRunning)
                HStack {
                    TextField("Bootstrap file(s), colon-separated (optional)", text: $model.bootstrapFile).disabled(model.isRunning)
                    Button("Choose…") { chooseBootstrap() }.disabled(model.isRunning)
                }
                Text("Peers on this LAN are found by themselves. To reach a seed elsewhere, give the node a bootstrap file with the seed's address and real public key; `cairn gen-bootstrap` writes the shape, and a placeholder key is warned about at start.")
                    .font(.caption).foregroundStyle(.secondary)
                Text("Short epochs make a local trial quick; a real round takes 600s. The node, the researcher and the audit all read the same value. 8080/9000 are what an operator's own cairn run binds, which is why the defaults are 8090/9010.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("Researcher") {
                Stepper("Compute budget per objective: \(model.budgetMinutes) min", value: $model.budgetMinutes, in: 1...1440)
                Stepper("Sweep interval: \(model.intervalSeconds)s", value: $model.intervalSeconds, in: 10...3600, step: 10)
                Toggle("Notify when a claim settles", isOn: $model.notifyOnSettle)
                Text("An objective whose estimated work exceeds the budget is declined with its reason rather than attempted.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("State") {
                HStack {
                    Text(model.stateDir).font(.caption.monospaced()).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                    Spacer()
                    Button("Reveal in Finder") { model.revealStateInFinder() }
                }
                Toggle("Keep the identity when resetting", isOn: $keepIdentity)
                Button("Reset state…", role: .destructive) { confirmReset = true }.disabled(model.isRunning)
                Text("Deletes the researcher's log, node keys, journal and outcomes. The identity is the name payments went to; losing it is unrecoverable, so it is kept unless you say otherwise.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .frame(width: 540, height: 600)
        .confirmationDialog("Delete \(model.stateDir)?", isPresented: $confirmReset) {
            Button(keepIdentity ? "Reset, keep identity" : "Reset everything", role: .destructive) {
                model.resetState(keepIdentity: keepIdentity)
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("The log and every outcome go; a fresh node and a fresh log are created on the next Start.")
        }
    }

    private func chooseBootstrap() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = true
        panel.prompt = "Use as bootstrap"
        if panel.runModal() == .OK {
            model.bootstrapFile = panel.urls.map(\.path).joined(separator: ":")
        }
    }

    private func choose() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.prompt = "Use this checkout"
        if panel.runModal() == .OK, let url = panel.url {
            model.root = url.path
        }
    }
}
