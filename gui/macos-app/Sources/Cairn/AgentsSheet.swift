import AppKit
import SwiftUI

/// Node → Connect an Agent…: the stanza that points Claude Code, Codex or
/// OpenCode at cairn, with this Mac's real paths in it.
struct AgentsSheet: View {
    @ObservedObject var node: Node
    @Binding var isPresented: Bool
    @State private var arrangement: AgentArrangement = .runNode
    @State private var client: AgentClient = .claudeCode
    @State private var identityBusy = false
    @State private var message: (ok: Bool, text: String)?

    private var binary: String {
        (node.binary ?? Node.locateBinary())?.path ?? "/usr/local/cairn/bin/cairn"
    }

    private var identityPath: String {
        node.dataDir.appendingPathComponent("agent.identity.json").path
    }

    private var inputs: AgentStanza.Inputs {
        AgentStanza.Inputs(
            binary: binary, dataDir: node.dataDir.path, settings: node.settings,
            arrangement: arrangement, client: client,
            identity: FileManager.default.fileExists(atPath: identityPath) ? identityPath : nil
        )
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("Connect an agent", systemImage: "terminal").font(.headline)
            Text("""
                Claude Code, Codex and OpenCode speak MCP. Point one at cairn and it has the \
                node's tools: list_objectives, get_objective, score_candidate, submit_claim, \
                frontier_status, work_assignment and the rest. The stanza below carries this \
                Mac's real paths and this window's settings.
                """)
                .font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            Picker("Arrangement", selection: $arrangement) {
                ForEach(AgentArrangement.allCases) { Text($0.title).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            Text(explanation)
                .font(.callout)
                .fixedSize(horizontal: false, vertical: true)

            stanza
            identityRow

            if let message {
                Label(message.text, systemImage: message.ok ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                    .font(.callout)
                    .foregroundStyle(message.ok ? Color.green : Color.red)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }

            HStack {
                if arrangement == .runNode, !node.isAttached {
                    Button("Hand the Node to the Agent") { handOver() }
                        .help("Stop this app's node and attach this window to http://127.0.0.1:8080/ui/, where the agent's cairn run will serve it.")
                }
                Spacer()
                Button("Done") { isPresented = false }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 660)
    }

    /// The client, and the stanza for it. Its own view so the sheet's
    /// column stays within what a view builder takes.
    private var stanza: some View {
        VStack(alignment: .leading, spacing: 8) {
            Picker("Client", selection: $client) {
                ForEach(AgentClient.allCases) { Text($0.title).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            Text(verbatim: client.file).font(.caption).foregroundStyle(.secondary)
            codeBox(AgentStanza.render(inputs))
            if client == .claudeCode {
                Text("Or let Claude Code write it, in a Terminal:")
                    .font(.caption).foregroundStyle(.secondary)
                codeBox(AgentStanza.claudeAdd(inputs))
            }
        }
    }

    private var explanation: String {
        switch arrangement {
        case .runNode:
            return """
                The client launches cairn run on this node's data folder and becomes its \
                supervisor: one process owns the log, syncs with peers, serves the reader on \
                127.0.0.1:8080 and answers the agent over MCP, so what the agent does reaches \
                the network live. A log has one writer, so this app must stop its own node \
                first: Hand the Node to the Agent switches this window to attach mode, and the \
                page comes back once the client has started the node. Settings → Window \
                switches back.
                """
        case .ownLog:
            return """
                The client launches cairn mcp on a log of its own under this node's data \
                folder, beside the node this app keeps running. Nothing it writes reaches \
                peers while the client runs, and it sees only objectives in that log; \
                docs/agents.md has the stop, sync, restart sequence. Right for an agent that \
                should work offline; wrong for one that should work this node's challenges.
                """
        }
    }

    private var identityRow: some View {
        HStack(alignment: .firstTextBaseline) {
            if inputs.identity != nil {
                Label("Submissions are signed with agent.identity.json; its public half is the submitter name.",
                      systemImage: "checkmark.seal")
                    .font(.caption).foregroundStyle(.secondary)
            } else {
                Label("Unsigned submissions: anyone can use the same submitter name. Create an identity to sign them.",
                      systemImage: "exclamationmark.triangle")
                    .font(.caption).foregroundStyle(.orange)
                Button("Create Identity") { createIdentity() }
                    .font(.caption)
                    .disabled(identityBusy || node.isAttached)
            }
            Spacer()
        }
    }

    private func createIdentity() {
        identityBusy = true
        message = nil
        node.createAgentIdentity(at: identityPath) { err in
            identityBusy = false
            if let err {
                message = (ok: false, text: err)
            } else {
                message = (ok: true, text: "Created \(identityPath). The stanza now names it.")
            }
        }
    }

    private func handOver() {
        UserDefaults.standard.set("http://127.0.0.1:8080/ui/", forKey: NodeSettings.Key.attachURL)
        node.restart()
        message = (ok: true, text: "This window now attaches to http://127.0.0.1:8080/ui/. Start the agent's client; the page appears once its node serves.")
    }

    private func codeBox(_ text: String) -> some View {
        HStack(alignment: .top, spacing: 6) {
            ScrollView(.horizontal) {
                Text(verbatim: text)
                    .font(.caption.monospaced())
                    .textSelection(.enabled)
                    .padding(8)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .background(Color(nsColor: .textBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 6))
            Button {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(text, forType: .string)
            } label: {
                Image(systemName: "doc.on.doc")
            }
            .buttonStyle(.borderless)
            .help("Copy")
        }
    }
}
