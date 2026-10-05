import AppKit
import SwiftUI

/// One line of the connectivity report.
struct ConnectivityRow: Identifiable, Equatable {
    enum Status: Equatable { case checking, ok, warning, failed, info }
    let id: String
    var title: String
    var target: String
    var status: Status
    var detail: String
}

/// Node → Test Connectivity…: is this node actually listening, and do the
/// peers it dials answer -- tested now, from this Mac, rather than inferred
/// from a status word.
///
/// Each row is one real attempt: an HTTP request to the reader, a TCP
/// connect to the P2P port (and, when the node accepts inbound, to that port
/// on each of this Mac's LAN addresses), and a TCP connect to every
/// bootstrap peer and every seed the node's log names. A port that answers
/// proves a listener, not a cairn node, so peer rows carry the node's own
/// log about its handshake with them too.
@MainActor
final class ConnectivityCheck: ObservableObject {
    @Published private(set) var rows: [ConnectivityRow] = []
    @Published private(set) var running = false
    /// `nc -vz <lan address> <port>`, for testing from another machine:
    /// the one direction this Mac cannot test for itself.
    @Published private(set) var remoteHint: String?

    let node: Node

    init(node: Node) { self.node = node }

    private typealias Work = @Sendable () async -> (ConnectivityRow.Status, String)

    func run() {
        guard !running else { return }
        running = true
        let jobs = plan()
        rows = jobs.map(\.row)
        Task {
            await withTaskGroup(of: (String, ConnectivityRow.Status, String).self) { group in
                for job in jobs {
                    guard let work = job.work else { continue }
                    let id = job.row.id
                    group.addTask { let (status, detail) = await work(); return (id, status, detail) }
                }
                for await (id, status, detail) in group {
                    if let i = rows.firstIndex(where: { $0.id == id }) {
                        rows[i].status = status
                        rows[i].detail = detail
                    }
                }
            }
            running = false
        }
    }

    var report: String {
        rows.map { row in
            let mark: String
            switch row.status {
            case .ok: mark = "OK  "
            case .warning: mark = "WARN"
            case .failed: mark = "FAIL"
            case .info: mark = "INFO"
            case .checking: mark = "... "
            }
            return "\(mark) \(row.title) \(row.target) — \(row.detail)"
        }.joined(separator: "\n")
    }

    // MARK: what to check

    private func plan() -> [(row: ConnectivityRow, work: Work?)] {
        var jobs: [(row: ConnectivityRow, work: Work?)] = []
        func add(_ id: String, _ title: String, _ target: String, _ work: Work?, status: ConnectivityRow.Status = .checking, detail: String = "checking…") {
            jobs.append((ConnectivityRow(id: id, title: title, target: target, status: work == nil ? status : .checking,
                                         detail: work == nil ? detail : "checking…"), work))
        }
        let settings = node.settings
        let lines = node.lines
        remoteHint = nil

        // The reader.
        if node.isAttached, let url = settings.attachURL {
            add("reader", "Reader", url.absoluteString, { await Self.http(url) })
        } else if case .running(let url) = node.state {
            add("reader", "Reader", "\(url.host ?? "127.0.0.1"):\(url.port ?? 80)", { await Self.http(url) })
        } else {
            add("reader", "Reader", "", nil, status: .failed,
                detail: node.state == .starting ? "the node is still starting" : "the node is not running")
        }
        if node.isAttached {
            add("attached", "P2P", "", nil, status: .info,
                detail: "attached to another node; its listener is that node's, not this Mac's")
            return jobs
        }

        // This node's P2P listener.
        guard let listen = node.listenAddress, let bound = PortProbe.split(listen) else {
            add("p2p", "P2P listener", "", nil, status: .failed, detail: "the node has not said where it listens yet")
            return jobs
        }
        let host = bound.host, port = bound.port
        let wildcard = host == "0.0.0.0" || host == "::"
        let local = wildcard ? "127.0.0.1" : host
        add("p2p", "P2P listener", listen, {
            let r = await PortProbe.tcp(local, port)
            return r.isOpen
                ? (.ok, "accepting connections on this Mac")
                : (.failed, "\(r.summary). The node's log (Node → Show Node Log) says why it did not bind.")
        })

        if settings.listensLocallyOnly {
            add("inbound", "Inbound", "this Mac only", nil, status: .info, detail: """
                P2P listens on loopback, so no other machine can connect. That is enough to sync \
                by dialling out; Settings → Network → Any interface accepts inbound.
                """)
        } else {
            let interfaces = LocalNetwork.ipv4()
            if let first = interfaces.first { remoteHint = "nc -vz \(first.address) \(port)" }
            for iface in interfaces {
                let address = iface.address
                add("lan-\(iface.name)-\(address)", "On \(iface.name)", "\(address):\(port)", {
                    let r = await PortProbe.tcp(address, port)
                    return r.isOpen
                        ? (.ok, "answers at this address from this Mac; another machine also needs the firewall and router to let it through")
                        : (.failed, r.summary)
                })
            }
            if interfaces.isEmpty {
                add("lan", "LAN", "", nil, status: .warning, detail: "this Mac has no network address other than loopback")
            }
            add("firewall", "macOS firewall", "", {
                switch await Task.detached(operation: { MacFirewall.isOn() }).value {
                case .some(true):
                    return (.warning, """
                        on. If cairn was denied incoming connections, peers cannot reach it: System \
                        Settings → Network → Firewall → Options.
                        """)
                case .some(false): return (.ok, "off; it does not block inbound connections")
                case .none: return (.info, "its state could not be read")
                }
            })
        }

        // The peers it dials: bootstrap files, then seeds as the log names them.
        for path in settings.bootstrapFiles {
            let name = (path as NSString).lastPathComponent
            guard let address = BootstrapFile.address(path), let peer = PortProbe.split(address) else {
                add("bootstrap-\(path)", "Bootstrap \(name)", "", nil, status: .failed, detail: "the file holds no host:port address")
                continue
            }
            let failure = NetworkLog.lastDialFailure(to: address, in: lines)
            add("bootstrap-\(path)", "Bootstrap \(name)", address, {
                let r = await PortProbe.tcp(peer.host, peer.port)
                guard r.isOpen else { return (.failed, r.summary) }
                if let failure {
                    return (.warning, "the port answers, but the node's last dial there failed: \(failure)")
                }
                return (.ok, "the port answers")
            })
        }
        let seeds = NetworkLog.seeds(in: lines)
        for seed in seeds {
            guard let at = PortProbe.split(seed.address) else { continue }
            add("seed-\(seed.name)", "Seed \(seed.name)", seed.address, {
                let r = await PortProbe.tcp(at.host, at.port)
                guard r.isOpen else { return (.failed, "\(r.summary); \(seed.detail)") }
                return seed.ok ? (.ok, "the port answers, and \(seed.detail)") : (.warning, "the port answers, but \(seed.detail)")
            })
        }
        if settings.bootstrapFiles.isEmpty && seeds.isEmpty {
            add("peers", "Peers to dial", "", nil, status: .info, detail: """
                no bootstrap files, and the node has not logged a seed yet. Peers on this network \
                are found by beacon; Settings → Network adds a bootstrap file.
                """)
        }

        let sessions = node.sessionsOK
        add("sessions", "Sessions", "", nil, status: sessions > 0 ? .ok : .warning,
            detail: sessions > 0
                ? "\(sessions) peer session\(sessions == 1 ? "" : "s") established, by the node's log"
                : "no peer session yet, by the node's log")
        return jobs
    }

    /// The reader's page, as the window would load it.
    nonisolated static func http(_ url: URL) async -> (ConnectivityRow.Status, String) {
        var request = URLRequest(url: url)
        request.timeoutInterval = 5
        do {
            let (_, response) = try await URLSession(configuration: .ephemeral).data(for: request)
            let status = (response as? HTTPURLResponse)?.statusCode ?? 0
            return status == 200 ? (.ok, "serving the reader") : (.failed, "answered HTTP \(status)")
        } catch {
            return (.failed, error.localizedDescription)
        }
    }
}

struct ConnectivitySheet: View {
    @ObservedObject var node: Node
    @Binding var isPresented: Bool
    @StateObject private var check: ConnectivityCheck

    init(node: Node, isPresented: Binding<Bool>) {
        self.node = node
        self._isPresented = isPresented
        self._check = StateObject(wrappedValue: ConnectivityCheck(node: node))
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("Connectivity", systemImage: "network").font(.headline)
            Text("Whether this node is listening, and whether the peers it dials answer: each tested now, from this Mac.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            VStack(alignment: .leading, spacing: 0) {
                ForEach(check.rows) { row in
                    ConnectivityRowView(row: row)
                    if row.id != check.rows.last?.id { Divider() }
                }
            }
            .padding(.horizontal, 10)
            .background(Color(nsColor: .textBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 8))

            if let hint = check.remoteHint {
                HStack(spacing: 6) {
                    Text("From another machine on this network:").font(.callout).foregroundStyle(.secondary)
                    Text(verbatim: hint).font(.callout.monospaced()).textSelection(.enabled)
                    Button {
                        copy(hint)
                    } label: { Image(systemName: "doc.on.doc") }
                    .buttonStyle(.borderless)
                    .help("Copy")
                }
            }

            if !node.networkLines.isEmpty {
                DisclosureGroup("Recent network log") {
                    ScrollView {
                        Text(verbatim: node.networkLines.suffix(30).joined(separator: "\n"))
                            .font(.caption.monospaced())
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(6)
                    }
                    .frame(maxHeight: 160)
                }
                .font(.callout)
            }

            HStack {
                Button("Copy Report") { copy(check.report) }
                    .disabled(check.rows.isEmpty)
                Spacer()
                if check.running { ProgressView().controlSize(.small) }
                Button("Run Again") { check.run() }
                    .disabled(check.running)
                Button("Done") { isPresented = false }
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 620)
        .onAppear { check.run() }
    }

    private func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }
}

private struct ConnectivityRowView: View {
    let row: ConnectivityRow

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            icon.frame(width: 18)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 8) {
                    Text(row.title).font(.callout.weight(.medium))
                    if !row.target.isEmpty {
                        Text(verbatim: row.target)
                            .font(.callout.monospaced())
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                    }
                }
                Text(row.detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
        .padding(.vertical, 8)
    }

    @ViewBuilder private var icon: some View {
        switch row.status {
        case .checking: ProgressView().controlSize(.small)
        case .ok: Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
        case .warning: Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.gray)
        case .failed: Image(systemName: "xmark.octagon.fill").foregroundStyle(.red)
        case .info: Image(systemName: "info.circle").foregroundStyle(.secondary)
        }
    }
}
