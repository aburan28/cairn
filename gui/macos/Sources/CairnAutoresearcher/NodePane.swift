import SwiftUI
import AppKit

/// The node the researcher runs: what it serves, who holds what, the ledger
/// itself, and the reader it embeds -- the same pages a browser would show.
struct NodeView: View {
    @EnvironmentObject var model: ResearcherModel
    @State private var tab = "ledger"
    @State private var page = 0
    @State private var showAudit = false
    @State private var showAddPeer = false

    var body: some View {
        VSplitView {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    HStack(spacing: 12) {
                        Tile(title: "Node", value: model.nodeReachable ? "up" : "down", color: model.nodeReachable ? .green : .gray,
                             caption: "http \(model.httpAddress) · p2p \(model.p2pAddress)")
                        Tile(title: "Epoch", value: "\(model.currentEpoch)", color: .orange,
                             caption: "next in \(model.secondsToNextEpoch)s · \(model.epochLength)s long")
                        Tile(title: "Ledger height", value: model.chain?.height.map(String.init) ?? "–", color: .blue,
                             caption: model.chain?.ledger_head.map { String($0.prefix(18)) } ?? "entries in the log")
                        Tile(title: "Epoch links", value: model.chain?.links.map(String.init) ?? "–", color: .indigo,
                             caption: model.chain?.head.flatMap { $0.isEmpty ? nil : String($0.prefix(18)) } ?? "settled epochs")
                        Tile(title: "Peers", value: model.peerCount.map(String.init) ?? "–", color: .cyan, caption: "peer records in the log")
                        Tile(title: "Objectives", value: model.nodeReachable ? "\(model.nodeObjectives.count)" : "–", color: .purple,
                             caption: "\(model.frontiers.count) with a frontier")
                    }
                    HStack(alignment: .top, spacing: 14) {
                        VStack(spacing: 14) {
                            discoveryCard
                            balancesCard
                        }
                        .frame(maxWidth: .infinity)
                        VStack(spacing: 14) {
                            identityCard
                            kindsCard
                        }
                        .frame(width: 280)
                    }
                }
                .padding(16)
            }
            .frame(minHeight: 220)
            VStack(spacing: 0) {
                HStack {
                    Picker("", selection: $tab) {
                        Text("Ledger").tag("ledger")
                        Text("Peers").tag("peers")
                        Text("Reader").tag("reader")
                    }
                    .pickerStyle(.segmented).frame(width: 260)
                    if tab == "reader" {
                        Picker("", selection: $page) {
                            Text("Site").tag(0)
                            Text("Chain").tag(1)
                            Text("Objectives JSON").tag(2)
                            Text("Log JSON").tag(3)
                        }
                        .pickerStyle(.segmented).frame(width: 360)
                    }
                    Spacer()
                    Button { showAddPeer = true } label: { Label("Add peer…", systemImage: "person.badge.plus") }
                        .help("Announce a peer in the log, add a bootstrap file, or read off what to give somebody adding this node")
                    Button {
                        model.audit(); showAudit = true
                    } label: { Label(model.auditing ? "Auditing…" : "Audit log", systemImage: "checkmark.shield") }
                        .disabled(model.auditing || !model.hasBinary)
                        .help("cairn audit: re-derive the whole log and re-verify every settled claim. Read-only.")
                    Link("Open in browser", destination: model.readerURL).disabled(!model.nodeReachable)
                }
                .padding(8)
                Divider()
                switch tab {
                case "peers": peersTable
                case "reader": reader
                default: ledgerTable
                }
            }
            .frame(minHeight: 240)
        }
        .sheet(isPresented: $showAudit) { auditSheet }
        .sheet(isPresented: $showAddPeer) { AddPeerSheet(isPresented: $showAddPeer).environmentObject(model) }
    }

    // MARK: cards

    private var balancesCard: some View {
        GroupBox {
            if model.balances.isEmpty {
                Text(model.hasBinary ? "No balances to show: the log is empty or has no holders yet." : "bin/cairn is needed to read balances.")
                    .foregroundStyle(.secondary).frame(maxWidth: .infinity, alignment: .leading)
            } else {
                Grid(alignment: .leading, horizontalSpacing: 18, verticalSpacing: 4) {
                    GridRow {
                        Text("holder").font(.caption).foregroundStyle(.secondary)
                        Text("spendable").font(.caption).foregroundStyle(.secondary).gridColumnAlignment(.trailing)
                        Text("escrowed").font(.caption).foregroundStyle(.secondary).gridColumnAlignment(.trailing)
                    }
                    ForEach(model.balances) { b in
                        GridRow {
                            HStack(spacing: 6) {
                                if let s = model.status?.submitter ?? model.identityPublic, s.hasPrefix(b.name) {
                                    Image(systemName: "person.crop.circle.fill").foregroundStyle(.teal)
                                }
                                Text(b.name).font(.body.monospaced())
                            }
                            Text(b.spendable.formatted()).monospacedDigit()
                            Text(b.escrowed.formatted()).monospacedDigit().foregroundStyle(.secondary)
                        }
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                Text("From cairn balances, read-only, refreshed every ten seconds. Escrow is what funders promised to open pools; this log declares no supply, so rewards are backed by the operator's word.")
                    .font(.caption).foregroundStyle(.secondary).padding(.top, 6)
            }
        } label: { Label("Balances", systemImage: "banknote") }
    }

    /// Discovery, as the node's own log tells it: whether the beacon socket
    /// bound, how often beacons were heard, sessions that worked, and the
    /// last failures verbatim. Nothing here is inferred.
    private var discoveryCard: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 6) {
                let d = model.discovery
                HStack(spacing: 8) {
                    // Green only for a bind the node reported. A failed bind,
                    // `off`, and a binary too old to say all used to get the
                    // green antenna, because anything but "already held" did.
                    let look: (symbol: String, tint: Color) = {
                        switch d.beacon {
                        case .bound: return ("antenna.radiowaves.left.and.right", .green)
                        case .off: return ("antenna.radiowaves.left.and.right.slash", .secondary)
                        case .failed: return ("exclamationmark.triangle.fill", .orange)
                        case .unknown: return ("circle.dashed", .secondary)
                        }
                    }()
                    Image(systemName: look.symbol)
                        .foregroundStyle(look.tint)
                    Text(d.multicast ?? (model.nodeReachable ? "waiting for the node's log" : "no node running"))
                        .textSelection(.enabled)
                }
                HStack(spacing: 14) {
                    stat("beacon ticks", d.beaconTicks)
                    stat("inbound ok", d.inboundOK)
                    stat("outbound ok", d.outboundOK)
                    stat("bootstrap", d.bootstrap.count)
                }
                if let last = d.failures.last {
                    Text(String(last.split(separator: " ", maxSplits: 3).last ?? "")).font(.caption.monospaced()).foregroundStyle(.red).lineLimit(2)
                }
                if let b = d.bootstrap.last, b.contains("PLACEHOLDER") {
                    Text("The bootstrap file still carries the placeholder key; dials to that seed will fail their handshake. Put the seed's real public key in it.")
                        .font(.caption).foregroundStyle(.orange)
                }
                if d.multicast?.contains("already held") == true {
                    Text("Another node on this Mac bound the beacon port first without sharing it. Nodes built after this change share the port; restart the older node on a current build and both will hear each other.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Text(model.bootstrapFile.isEmpty ? "No bootstrap file: LAN peers only. Set one in Settings to reach a seed." : "Bootstrap: \(model.bootstrapFile)")
                    .font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        } label: { Label("Discovery", systemImage: "dot.radiowaves.left.and.right") }
    }

    private func stat(_ label: String, _ n: Int) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("\(n)").font(.title3.monospacedDigit().bold())
            Text(label).font(.caption2).foregroundStyle(.secondary)
        }
    }

    private var identityCard: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 6) {
                if let pub = model.identityPublic {
                    Text(pub).font(.caption.monospaced()).textSelection(.enabled).lineLimit(2)
                    HStack {
                        Button("Copy") {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(pub, forType: .string)
                            model.infoMessage = "Public key copied"
                        }
                        Button("Reveal key file") { model.revealIdentityInFinder() }
                    }
                    Text("The name is the public key; the file beside it holds the secret half. Losing the file loses the name.")
                        .font(.caption).foregroundStyle(.secondary)
                } else {
                    Text("Created on the first Start.").foregroundStyle(.secondary)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        } label: { Label("Identity", systemImage: "person.badge.key") }
    }

    private var kindsCard: some View {
        GroupBox {
            if model.logKinds.isEmpty {
                Text("–").foregroundStyle(.secondary).frame(maxWidth: .infinity, alignment: .leading)
            } else {
                Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 4) {
                    ForEach(model.logKinds.keys.sorted(), id: \.self) { k in
                        GridRow {
                            Text(k).font(.body.monospaced())
                            Text("\(model.logKinds[k] ?? 0)").monospacedDigit().gridColumnAlignment(.trailing)
                        }
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } label: { Label("Records by kind", systemImage: "doc.text") }
    }

    // MARK: tables

    private var ledgerTable: some View {
        Table(model.ledger) {
            TableColumn("#") { e in Text("\(e.seq)").monospacedDigit() }.width(40)
            TableColumn("kind") { e in Text(e.kind).font(.body.monospaced()) }.width(90)
            TableColumn("hash") { e in Text(String(e.hash.prefix(22))).font(.caption.monospaced()).foregroundStyle(.secondary) }.width(170)
            TableColumn("appended") { e in Text(e.ts).font(.caption.monospaced()) }.width(170)
            TableColumn("summary") { e in Text(e.summary).font(.callout) }
        }
        .overlay {
            if model.ledger.isEmpty {
                Text(model.nodeReachable ? "The log is empty." : "No node is answering on \(model.httpAddress). Start the researcher; it runs one.")
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var peersTable: some View {
        Table(model.peers) {
            TableColumn("identity") { p in Text(String(p.identity.prefix(24))).font(.caption.monospaced()) }
            TableColumn("address") { p in Text(p.addr) }
            TableColumn("transport") { p in Text(p.transport) }.width(90)
            TableColumn("since") { p in Text(p.createdAt).font(.caption.monospaced()) }
        }
        .overlay {
            if model.peers.isEmpty {
                VStack(spacing: 8) {
                    Text("No peer records in this log.").foregroundStyle(.secondary)
                    Text("Peers appear when the node is given a bootstrap file or hears one on the LAN; this researcher's node runs alone by default.")
                        .font(.caption).foregroundStyle(.secondary).multilineTextAlignment(.center).frame(maxWidth: 420)
                    Button("Add a peer…") { showAddPeer = true }
                }
            }
        }
    }

    @ViewBuilder private var reader: some View {
        if model.nodeReachable {
            WebView(url: [model.readerURL, model.chainURL,
                          model.nodeURL.appendingPathComponent("objectives"),
                          model.nodeURL.appendingPathComponent("log")][page])
        } else {
            VStack(spacing: 8) {
                Image(systemName: "network.slash").font(.largeTitle).foregroundStyle(.secondary)
                Text("No node is answering on \(model.httpAddress).").foregroundStyle(.secondary)
                Text("Start the researcher; it runs one.").font(.caption).foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    private var auditSheet: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label("cairn audit", systemImage: "checkmark.shield").font(.headline)
            if model.auditing {
                HStack { ProgressView().controlSize(.small); Text("Re-deriving the log and re-running every settled verifier…") }
            } else {
                ScrollView {
                    Text(model.auditOutput ?? "").font(.body.monospaced()).textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(minHeight: 120)
                if let out = model.auditOutput {
                    Label(out.contains("log verified") ? "The log verifies: chain intact, every settled claim re-verified."
                          : "The audit reported problems; read the output above.",
                          systemImage: out.contains("log verified") ? "checkmark.circle.fill" : "xmark.octagon.fill")
                        .foregroundStyle(out.contains("log verified") ? .green : .red)
                }
            }
            HStack { Spacer(); Button("Close") { showAudit = false }.keyboardShortcut(.cancelAction) }
        }
        .padding(16)
        .frame(width: 560, height: 320)
    }
}
