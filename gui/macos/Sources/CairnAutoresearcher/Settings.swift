import SwiftUI
import AppKit

struct SettingsView: View {
    @EnvironmentObject var model: ResearcherModel

    var body: some View {
        Form {
            Section("Checkout") {
                HStack {
                    TextField("cairn repository", text: $model.root)
                        .disabled(model.isRunning)
                    Button("Choose…") { choose() }.disabled(model.isRunning)
                }
                Text(model.hasCheckout ? "research/crypto-autoresearcher found" : "no autoresearcher at this path")
                    .font(.caption).foregroundStyle(model.hasCheckout ? Color.secondary : Color.red)
            }
            Section("Node") {
                TextField("HTTP address", text: $model.httpAddress).disabled(model.isRunning)
                TextField("P2P address", text: $model.p2pAddress).disabled(model.isRunning)
                Stepper("Epoch length: \(model.epochSeconds)s", value: $model.epochSeconds, in: 1...600)
                    .disabled(model.isRunning)
                Text("Short epochs make a local trial quick; a real round takes 600s. The node, the researcher and the audit all read the same value.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("Researcher") {
                Stepper("Compute budget per objective: \(model.budgetMinutes) min", value: $model.budgetMinutes, in: 1...1440)
                Stepper("Sweep interval: \(model.intervalSeconds)s", value: $model.intervalSeconds, in: 10...3600, step: 10)
                Text("An objective whose estimated work exceeds the budget is declined with its reason rather than attempted.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .frame(width: 520, height: 420)
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
