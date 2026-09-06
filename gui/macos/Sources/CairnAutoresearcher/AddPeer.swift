import SwiftUI
import AppKit
import UniformTypeIdentifiers

/// Adding a peer, both halves of it.
///
/// A peer record in the log tells every reader of that log where an identity
/// is; a bootstrap file tells *this* node where to dial before it has a log
/// worth reading. They answer different questions, so the sheet does not make
/// the operator guess which one "add a peer" meant -- it does both, labelled.
///
/// Neither is a trust decision. A transport id is `sha256` of the key the
/// handshake proves, so an entry naming the wrong id gets no session: a wrong
/// peer costs a dial, never a wrong result. That is worth saying on screen,
/// because an operator who thinks they are granting something will be far more
/// cautious than the mechanism requires.
struct AddPeerSheet: View {
    @EnvironmentObject var model: ResearcherModel
    @Binding var isPresented: Bool

    @State private var tab = "announce"
    @State private var transport = ""
    @State private var addr = ""
    @State private var busy = false
    @State private var error: String?

    private var transportOK: Bool { ResearcherModel.isPeerId(transport.trimmed) }
    private var addrOK: Bool { ResearcherModel.isHostPort(addr.trimmed) }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Add a peer", systemImage: "person.badge.plus").font(.headline)
            Picker("", selection: $tab) {
                Text("Announce in the log").tag("announce")
                Text("Bootstrap file").tag("bootstrap")
                Text("This node").tag("self")
            }
            .pickerStyle(.segmented)

            Group {
                switch tab {
                case "bootstrap": bootstrapTab
                case "self": selfTab
                default: announceTab
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            if let error {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .font(.callout).foregroundStyle(.red).textSelection(.enabled).lineLimit(4)
            }
            Spacer(minLength: 0)
            HStack {
                if busy { ProgressView().controlSize(.small) }
                Spacer()
                Button("Done") { isPresented = false }.keyboardShortcut(.cancelAction)
            }
        }
        .padding(18)
        .frame(width: 620, height: 460)
    }

    // MARK: announce

    private var announceTab: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Appends a peer record to this node's log: your identity vouching that a transport id is reachable at an address. Every node that replicates the log learns the peer from it, so finding the network becomes part of obtaining the log rather than a second problem.")
                .font(.callout).foregroundStyle(.secondary)
            Form {
                TextField("Transport peer id", text: $transport, prompt: Text("64 hex characters"))
                    .font(.body.monospaced())
                TextField("Address", text: $addr, prompt: Text("host:port, e.g. 198.51.100.7:9000"))
            }
            .formStyle(.columns)
            HStack(spacing: 12) {
                mark(transport.isEmpty ? nil : transportOK,
                     transport.isEmpty ? "The peer id is sha256 of their transport key."
                        : (transportOK ? "A well-formed transport id." : "A transport id is exactly 64 hex characters."))
                Spacer()
            }
            mark(addr.isEmpty ? nil : addrOK,
                 addr.isEmpty ? "The address is only a hint; it is never checked here."
                    : (addrOK ? "A well-formed address." : "Expected host:port."))
            Text("The address is a hint and the id is a promise: a dialler derives the id from the handshake or gets no session. A record that is wrong costs a dial and can never cost a wrong result.")
                .font(.caption).foregroundStyle(.tertiary)
            HStack {
                Button {
                    error = nil; busy = true
                    model.addPeerRecord(transport: transport.trimmed, addr: addr.trimmed) { err in
                        busy = false; error = err
                        if err == nil { transport = ""; addr = "" }
                    }
                } label: { Label("Announce peer", systemImage: "antenna.radiowaves.left.and.right") }
                    .disabled(!transportOK || !addrOK || busy || model.isLive || model.isBuilding)
                if model.isLive {
                    Text("Stop the researcher first: a ledger has one writer, and its node is it.")
                        .font(.caption).foregroundStyle(.orange)
                }
            }
        }
    }

    // MARK: bootstrap

    private var bootstrapTab: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("A bootstrap file is local configuration this node reads at start: an address and the peer's real transport key, which is too large to keep in a log. Peers on this LAN are found without one; a seed elsewhere needs one.")
                .font(.callout).foregroundStyle(.secondary)
            HStack {
                Button("Choose a file…") { chooseBootstrap() }
                Button("Generate one for an address…") { generateBootstrap() }
                    .disabled(!addrOK || busy || !model.hasBinary)
                TextField("host:port", text: $addr).frame(width: 170)
            }
            Text("A generated file carries a placeholder key until you paste the peer's real one in. The node warns on every start while it does, and the warning clears itself once the key is right.")
                .font(.caption).foregroundStyle(.tertiary)
            Divider()
            if model.bootstrapPaths.isEmpty {
                Text("No bootstrap files. This node finds peers on the local segment only.")
                    .foregroundStyle(.secondary)
            } else {
                ForEach(model.bootstrapPaths, id: \.self) { path in
                    HStack {
                        Image(systemName: FileManager.default.fileExists(atPath: path) ? "doc" : "doc.badge.gearshape")
                            .foregroundStyle(FileManager.default.fileExists(atPath: path) ? Color.secondary : .orange)
                        Text(path).font(.caption.monospaced()).lineLimit(1).truncationMode(.middle)
                        Spacer()
                        Button("Remove") { model.removeBootstrap(path) }.buttonStyle(.link)
                    }
                }
                Text(model.isLive ? "The running node read this list at its start; changes apply at the next one."
                        : "Read at the next Start.")
                    .font(.caption).foregroundStyle(.tertiary)
            }
        }
    }

    // MARK: this node

    private var selfTab: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("What to give somebody adding this node. The transport id is printed by the node itself at startup, so it appears once the node has run.")
                .font(.callout).foregroundStyle(.secondary)
            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 6) {
                GridRow {
                    Text("Peer id").foregroundStyle(.secondary).gridColumnAlignment(.trailing)
                    Text(model.discovery.peerId ?? "start the node once to learn it")
                        .font(.caption.monospaced()).textSelection(.enabled).lineLimit(1).truncationMode(.middle)
                }
                GridRow {
                    Text("Address").foregroundStyle(.secondary).gridColumnAlignment(.trailing)
                    Text(model.p2pAddress).font(.body.monospaced()).textSelection(.enabled)
                }
                GridRow {
                    Text("Submitter").foregroundStyle(.secondary).gridColumnAlignment(.trailing)
                    Text(model.identityPublic ?? "–").font(.caption.monospaced())
                        .textSelection(.enabled).lineLimit(1).truncationMode(.middle)
                }
            }
            HStack {
                Button("Copy peer id and address") {
                    guard let id = model.discovery.peerId else { return }
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString("\(id) \(model.p2pAddress)", forType: .string)
                    model.infoMessage = "Copied"
                }
                .disabled(model.discovery.peerId == nil)
            }
            if model.p2pAddress.hasPrefix("127.") || model.p2pAddress.hasPrefix("localhost") {
                Label("This node listens on loopback, so only this Mac can reach it. Give it a LAN or public address in Settings before handing the pair out.",
                      systemImage: "info.circle")
                    .font(.caption).foregroundStyle(.orange)
            }
            Text("Handing these out publishes where this node is. The transport key it proves is never in the log, so an id alone lets somebody dial you and nothing else.")
                .font(.caption).foregroundStyle(.tertiary)
        }
    }

    // MARK: bits

    @ViewBuilder private func mark(_ ok: Bool?, _ text: String) -> some View {
        HStack(spacing: 6) {
            Image(systemName: ok == nil ? "info.circle" : (ok! ? "checkmark.circle.fill" : "xmark.circle.fill"))
                .foregroundStyle(ok == nil ? Color.secondary : (ok! ? .green : .red))
            Text(text).font(.caption).foregroundStyle(.secondary)
        }
    }

    private func chooseBootstrap() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = true
        panel.prompt = "Use as bootstrap"
        if panel.runModal() == .OK {
            panel.urls.forEach { model.useBootstrap($0.path) }
        }
    }

    private func generateBootstrap() {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "bootstrap.json"
        panel.allowedContentTypes = [.json]
        panel.prompt = "Generate"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        error = nil; busy = true
        model.generateBootstrap(addr: addr.trimmed, to: url) { err in
            busy = false; error = err
        }
    }
}

extension String {
    var trimmed: String { trimmingCharacters(in: .whitespacesAndNewlines) }
}
