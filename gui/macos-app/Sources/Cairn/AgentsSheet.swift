import AppKit
import SwiftUI

/// Node → Connect an Agent…: the stanza that points Claude Code, Codex,
/// OpenCode or Conductor at cairn, with this Mac's real paths in it.
struct AgentsSheet: View {
    @ObservedObject var node: Node
    @Binding var isPresented: Bool
    @State private var arrangement: AgentArrangement = .shared
    @State private var client: AgentClient
    @State private var identityBusy = false
    @State private var installConfirmation = false
    @State private var message: (ok: Bool, text: String)?

    init(node: Node, isPresented: Binding<Bool>) {
        self.node = node
        self._isPresented = isPresented
        self._client = State(initialValue: node.agentsClient)
    }

    private var binary: String {
        (node.binary ?? Node.locateBinary())?.path ?? "/usr/local/cairn/bin/cairn"
    }

    private var identityPath: String {
        node.dataDir.appendingPathComponent("agent.identity.json").path
    }

    /// Conductor runs several agents at once, each starting its own MCP
    /// client, so only the shared node serves it: the other two would have
    /// each workspace start a writer of its own.
    private var effectiveArrangement: AgentArrangement {
        client == .conductor ? .shared : arrangement
    }

    /// Whether this app can turn the agents endpoint on: it starts the node,
    /// itself or as the background service. Attached elsewhere, that node's
    /// flags are whoever started it.
    private var canServeAgents: Bool { !node.isAttached || node.runsInBackground }

    private var inputs: AgentStanza.Inputs {
        AgentStanza.Inputs(
            binary: binary, dataDir: node.dataDir.path, settings: node.settings,
            arrangement: effectiveArrangement, client: client,
            identity: FileManager.default.fileExists(atPath: identityPath) ? identityPath : nil,
            agentsURL: node.agentsURL ?? NodeSettings.agentsURL(port: NodeSettings.agentsPort)
        )
    }

    /// Every file the install writes, for the question that asks first.
    private var files: String {
        client.configURLs().map(\.path).joined(separator: " and ")
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("Connect an agent", systemImage: "terminal").font(.headline)
            Text("""
                Claude Code, Codex and OpenCode speak MCP, and Conductor runs the first two. \
                Point one at cairn and it has the node's tools: list_objectives, get_objective, \
                score_candidate, submit_claim, frontier_status, work_assignment and the rest. \
                The stanza below carries this Mac's real paths and this window's settings.
                """)
                .font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            Picker("Arrangement", selection: Binding(get: { effectiveArrangement }, set: { arrangement = $0 })) {
                ForEach(AgentArrangement.allCases) { Text($0.title).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .disabled(client == .conductor)
            Text(explanation)
                .font(.callout)
                .fixedSize(horizontal: false, vertical: true)
            if effectiveArrangement == .shared { servingRow }

            stanza
            Button("Add to \(client.title)…") {
                message = nil
                installConfirmation = true
            }
            .disabled(effectiveArrangement == .shared && node.agentsURL == nil && !canServeAgents)
            .confirmationDialog(
                "Allow Cairn to update \(files)?",
                isPresented: $installConfirmation,
                titleVisibility: .visible
            ) {
                Button("Add Cairn to \(client.title)") { installClient() }
                Button("Cancel", role: .cancel) { }
            } message: {
                Text(confirmation)
            }
            identityRow

            if let message {
                Label(message.text, systemImage: message.ok ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                    .font(.callout)
                    .foregroundStyle(message.ok ? Color.green : Color.red)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }

            HStack {
                if effectiveArrangement == .runNode, !node.isAttached {
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
            if client == .conductor {
                Text("""
                    Conductor reads no MCP config of its own: each workspace runs Claude Code or \
                    Codex, which read their user configs when a session starts, so both get the \
                    entry. work_assignment slices the search by the node_id an agent passes: have \
                    each workspace pass its own ($CONDUCTOR_WORKSPACE_NAME), or two search the same slice.
                    """)
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            ForEach(client.targets) { target in
                Text(verbatim: target.file).font(.caption).foregroundStyle(.secondary)
                codeBox(AgentStanza.render(inputs.for(target)))
            }
            if !commands.isEmpty {
                Text("Or let \(client == .conductor ? "Claude Code and Codex" : client.title) write it, in a Terminal:")
                    .font(.caption).foregroundStyle(.secondary)
                codeBox(commands.joined(separator: "\n"))
            }
        }
    }

    /// The clients' own commands for the same entry, where they have one.
    private var commands: [String] {
        var out: [String] = []
        if client.targets.contains(.claudeCode) { out.append(AgentStanza.claudeAdd(inputs.for(.claudeCode))) }
        if effectiveArrangement == .shared, client.targets.contains(.codex) {
            out.append(AgentStanza.codexAdd(inputs.for(.codex)))
        }
        return out
    }

    /// Whether the node answers agents now, and the switch for it.
    private var servingRow: some View {
        HStack(alignment: .firstTextBaseline) {
            if let url = node.agentsURL {
                Label {
                    Text(url.port == Int(NodeSettings.agentsPort)
                         ? "This node answers agents at \(url.absoluteString)."
                         : """
                           Port \(NodeSettings.agentsPort) was taken, so this node answers agents at \
                           \(url.absoluteString) until it restarts; an agent set up for \
                           \(NodeSettings.agentsPort) does not reach it meanwhile.
                           """)
                } icon: {
                    Image(systemName: url.port == Int(NodeSettings.agentsPort)
                          ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                        .foregroundStyle(url.port == Int(NodeSettings.agentsPort) ? Color.green : Color.orange)
                }
                .font(.caption)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
                Spacer()
                Button("Stop Serving") { node.setServeAgents(false) }.font(.caption)
            } else if canServeAgents {
                Label(node.settings.serveAgents
                      ? "Agents are on in Settings; the node starts serving them when it next starts."
                      : "Off. Adding Cairn below turns it on, which restarts the node.",
                      systemImage: "circle.dashed")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer()
                Button("Serve Agents") { node.setServeAgents(true) }.font(.caption)
            } else {
                Label("""
                    This window is attached to a node it did not start. Start that one with \
                    cairn run --mcp-http 127.0.0.1:\(NodeSettings.agentsPort) and the stanza below reaches it.
                    """, systemImage: "info.circle")
                    .font(.caption).foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private var confirmation: String {
        var text = """
            Cairn will add its MCP entry, keep other settings, and save a backup of any file \
            that already exists. It will not change \(client.title)'s sandbox or file permissions.
            """
        if effectiveArrangement == .shared, node.agentsURL == nil, canServeAgents {
            text += """
                 It will also restart this node to answer agents at \
                \(NodeSettings.agentsURL(port: NodeSettings.agentsPort).absoluteString), on this Mac only.
                """
        }
        return text
    }

    private var explanation: String {
        switch effectiveArrangement {
        case .shared:
            return """
                This app keeps running the node and answers agents beside it, over MCP on \
                loopback. Each client that connects gets its own session on the one log, so any \
                number of agents work at once -- every Conductor workspace, Claude Code in three \
                terminals -- and what they submit reaches the network live. Nothing off this Mac \
                can reach the port; any program on it can, and acts as this node when it does.
                """
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
            if effectiveArrangement == .shared, node.settings.leadFleet {
                // One --mcp-identity per node, and a leader's is its fleet's.
                Label("Submissions are signed with leader.identity.json, the key this fleet is paid to.",
                      systemImage: "checkmark.seal")
                    .font(.caption).foregroundStyle(.secondary)
            } else if inputs.identity != nil {
                Label("Submissions are signed with agent.identity.json; its public half is the submitter name.",
                      systemImage: "checkmark.seal")
                    .font(.caption).foregroundStyle(.secondary)
            } else {
                Label("Unsigned submissions: anyone can use the same submitter name. Create an identity to sign them.",
                      systemImage: "exclamationmark.triangle")
                    .font(.caption).foregroundStyle(.gray)
                Button("Create Identity") { createIdentity() }
                    .font(.caption)
                    .disabled(identityBusy || node.isAttached)
            }
            Spacer()
        }
    }

    private func installClient() {
        let serve = effectiveArrangement == .shared && node.agentsURL == nil && canServeAgents
        var ok = true
        var lines: [String] = []
        for (url, outcome) in AgentStanza.install(inputs) {
            switch outcome {
            case let .success(.installed(_, backup)):
                lines.append("Added Cairn to \(url.path)." + (backup.map { " Backup: \($0.path)." } ?? ""))
            case .success(.alreadyConfigured):
                lines.append("\(url.path) already has this entry; left unchanged.")
            case .success(.conflicting):
                ok = false
                lines.append("""
                    \(url.path) already has a cairn entry that says something else; left unchanged. \
                    Remove it (\(Self.removal(for: url))) and add again.
                    """)
            case let .failure(error):
                ok = false
                lines.append(error.localizedDescription.isEmpty ? "Could not update \(url.path)." : error.localizedDescription)
            }
        }
        if ok { lines.append("\(client.reload).") }
        if serve {
            node.setServeAgents(true)
            lines.append("The node is restarting to answer agents.")
        }
        message = (ok: ok, text: lines.joined(separator: " "))
    }

    /// How to take out a cairn entry this sheet will not overwrite.
    private static func removal(for url: URL) -> String {
        switch url.lastPathComponent {
        case ".claude.json": return "claude mcp remove cairn --scope user"
        case "config.toml": return "codex mcp remove cairn"
        default: return "delete its \"cairn\" entry"
        }
    }

    private func createIdentity() {
        identityBusy = true
        message = nil
        node.createAgentIdentity(at: identityPath) { err in
            identityBusy = false
            if let err {
                message = (ok: false, text: err)
            } else if node.agentsURL != nil {
                // The shared node reads its --mcp-identity at start.
                node.restart()
                message = (ok: true, text: "Created \(identityPath). The node is restarting to sign agents' submissions with it.")
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
