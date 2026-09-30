import AppKit
import SwiftUI
import UniformTypeIdentifiers

/// Adding a peer, both halves of it, and reading off what to give someone
/// adding this node.
///
/// A peer record in the log tells every reader of that log where an identity
/// answers; a bootstrap file tells *this* node where to dial before it has a
/// log worth reading. Neither is a trust decision: a transport id is
/// `sha256` of the key the handshake proves, so a wrong entry costs a dial
/// and never a wrong result.
struct PeersSheet: View {
    @ObservedObject var node: Node
    @Binding var isPresented: Bool

    @State private var tab = "announce"
    @State private var transport = ""
    @State private var addr = ""
    @State private var busy = false
    @State private var error: String?
    @State private var info: String?

    private var transportOK: Bool { Node.isPeerId(transport.trimmed) }
    private var addrOK: Bool { Node.isHostPort(addr.trimmed) }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Peers", systemImage: "person.badge.plus").font(.headline)
            if node.isAttached {
                Text("This window is attached to an existing node, so it cannot write the log or change that node's bootstrap list. Copy the peer id below if the attached node published one; otherwise use its own Settings.")
                    .font(.callout).foregroundStyle(.secondary)
            }
            Picker("", selection: $tab) {
                Text("Announce in the log").tag("announce")
                Text("Bootstrap file").tag("bootstrap")
                Text("This node").tag("self")
            }
            .pickerStyle(.segmented)
            .disabled(node.isAttached && tab != "self")

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
            if let info {
                Text(info).font(.callout).foregroundStyle(.secondary)
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
            Text("Appends a peer record to this node's log: your identity vouching that a transport id is reachable at an address. Every node that replicates the log learns the peer from it.")
                .font(.callout).foregroundStyle(.secondary)
            Form {
                TextField("Transport peer id", text: $transport, prompt: Text("64 hex characters"))
                    .font(.body.monospaced())
                TextField("Address", text: $addr, prompt: Text("host:port, e.g. 198.51.100.7:9000"))
            }
            .formStyle(.columns)
            Text("The address is a hint and the id is a promise: a dialler derives the id from the handshake or gets no session.")
                .font(.caption).foregroundStyle(.tertiary)
            HStack {
                Button {
                    error = nil; info = nil; busy = true
                    node.announcePeer(transport: transport.trimmed, addr: addr.trimmed) { err in
                        busy = false
                        if let err { error = err } else {
                            info = "Announced \(transport.trimmed.prefix(12))… at \(addr.trimmed)"
                            transport = ""; addr = ""
                        }
                    }
                } label: { Label("Announce peer", systemImage: "antenna.radiowaves.left.and.right") }
                .disabled(!transportOK || !addrOK || busy || node.isAttached || !node.hasIdentity)
                if node.isAttached {
                    Text("Detach in Settings first.")
                        .font(.caption).foregroundStyle(.orange)
                } else if !node.hasIdentity {
                    Text("Start the node once so it can create the identity that signs a peer record.")
                        .font(.caption).foregroundStyle(.orange)
                } else if case .running = node.state {
                    Text("The node will stop briefly: a ledger has one writer.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
        }
    }

    // MARK: bootstrap

    private var bootstrapTab: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Bootstrap files are managed in Settings → Network. They are local dial hints this node reads at start; the seeds built into cairn and LAN peers are found without one.")
                .font(.callout).foregroundStyle(.secondary)
            OpenSettingsButton()
            Text("Generate writes a placeholder key via `cairn gen-bootstrap`. Paste the peer's real key before expecting a session.")
                .font(.caption).foregroundStyle(.tertiary)
        }
    }

    // MARK: this node

    private var selfTab: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("What to give somebody adding this node. The transport id is printed by the node itself at startup.")
                .font(.callout).foregroundStyle(.secondary)
            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 6) {
                GridRow {
                    Text("Peer id").foregroundStyle(.secondary).gridColumnAlignment(.trailing)
                    Text(node.peerId ?? "start the node once to learn it")
                        .font(.caption.monospaced()).textSelection(.enabled)
                        .lineLimit(1).truncationMode(.middle)
                }
                GridRow {
                    Text("Address").foregroundStyle(.secondary).gridColumnAlignment(.trailing)
                    Text(handOutAddress)
                        .font(.body.monospaced()).textSelection(.enabled)
                }
            }
            HStack {
                Button("Copy peer id and address") {
                    guard let id = node.peerId else { return }
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString("\(id) \(handOutAddress)", forType: .string)
                    info = "Copied"
                }
                .disabled(node.peerId == nil)
            }
            if node.settings.listensLocallyOnly && !node.isAttached {
                Label("This node listens on loopback, so only this Mac can reach it. Accept inbound in Settings before handing the pair out.",
                      systemImage: "info.circle")
                    .font(.caption).foregroundStyle(.orange)
            }
        }
    }

    /// Prefer a concrete listen address; fall back to the settings host with
    /// the usual port so a stopped node still has something to copy.
    private var handOutAddress: String {
        if let listen = node.listenAddress, !listen.hasPrefix("0.0.0.0") {
            return listen
        }
        if let listen = node.listenAddress, listen.hasPrefix("0.0.0.0"),
           let port = listen.split(separator: ":").last {
            return "<this-Mac-LAN-or-public>:\(port)"
        }
        return "\(node.settings.p2pHost):9000"
    }
}

private extension String {
    var trimmed: String { trimmingCharacters(in: .whitespacesAndNewlines) }
}
