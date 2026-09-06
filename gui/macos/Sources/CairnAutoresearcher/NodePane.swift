import SwiftUI

/// The node the researcher runs: what it serves, who holds what, and the
/// reader it embeds -- the same pages a browser would show.
struct NodeView: View {
    @EnvironmentObject var model: ResearcherModel
    @State private var page = 0

    var body: some View {
        VSplitView {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    HStack(spacing: 12) {
                        Tile(title: "Node", value: model.nodeReachable ? "up" : "down", color: model.nodeReachable ? .green : .gray,
                             caption: "http \(model.httpAddress) · p2p \(model.p2pAddress)")
                        Tile(title: "Ledger height", value: model.chain?.height.map(String.init) ?? "–", color: .blue,
                             caption: model.chain?.ledger_head.map { String($0.prefix(18)) } ?? "entries in the log")
                        Tile(title: "Epoch links", value: model.chain?.links.map(String.init) ?? "–", color: .indigo,
                             caption: model.chain?.head.flatMap { $0.isEmpty ? nil : String($0.prefix(18)) } ?? "settled epochs")
                        Tile(title: "Peers", value: model.peerCount.map(String.init) ?? "–", color: .cyan, caption: "peer records in the log")
                        Tile(title: "Objectives", value: model.nodeReachable ? "\(model.nodeObjectives.count)" : "–", color: .purple,
                             caption: "\(model.frontiers.count) with a frontier")
                    }
                    HStack(alignment: .top, spacing: 14) {
                        balancesCard.frame(maxWidth: .infinity)
                        kindsCard.frame(width: 260)
                    }
                }
                .padding(16)
            }
            .frame(minHeight: 200)
            VStack(spacing: 0) {
                HStack {
                    Picker("", selection: $page) {
                        Text("Reader").tag(0)
                        Text("Chain").tag(1)
                        Text("Objectives JSON").tag(2)
                        Text("Log JSON").tag(3)
                    }
                    .pickerStyle(.segmented).frame(width: 420)
                    Spacer()
                    Link("Open in browser", destination: model.readerURL)
                }
                .padding(8)
                Divider()
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
            .frame(minHeight: 240)
        }
    }

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
                                if let s = model.status?.submitter, s.hasPrefix(b.name) {
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
                Text("From `cairn balances`, read-only, refreshed every ten seconds. Escrow is what funders have promised to open pools; this log declares no supply, so rewards are backed by the operator's word.")
                    .font(.caption).foregroundStyle(.secondary).padding(.top, 6)
            }
        } label: { Label("Balances", systemImage: "banknote") }
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
}
