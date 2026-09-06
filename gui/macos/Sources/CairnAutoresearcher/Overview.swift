import SwiftUI
import Charts

struct OverviewView: View {
    @EnvironmentObject var model: ResearcherModel
    @State private var now = Date()
    private let clock = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                header
                if !model.ready { setupCard }
                activityCard
                HStack(spacing: 12) {
                    Tile(title: "Solved", value: "\(model.solved.count)", color: .green,
                         caption: "\(model.solved.filter { $0.settled == true }.count) paid")
                    Tile(title: "Declined", value: "\(model.unreachable.count)", color: .orange, caption: "with a reason each")
                    Tile(title: "Open", value: "\(model.open.count)", color: .blue, caption: "not yet looked at")
                    Tile(title: "Earned", value: model.earned.formatted(), color: .purple, caption: "this identity, this log")
                    Tile(title: "Spendable", value: model.mySpendable.map { $0.formatted() } ?? "–", color: .teal,
                         caption: "from cairn balances")
                }
                if !model.pendingReveals.isEmpty { pendingCard }
                if model.earningsSeries.count > 0 { earningsCard }
                HStack(alignment: .top, spacing: 14) {
                    settledCard.frame(maxWidth: .infinity)
                    stateCard.frame(width: 360)
                }
                if model.status == nil && model.ready {
                    Text("Nothing has run yet. Choose objectives in Catalog, then press Start to post them, launch the node and begin sweeping, or One sweep to run a single pass and stop.")
                        .foregroundStyle(.secondary)
                }
            }
            .padding(22)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .onReceive(clock) { now = $0 }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Crypto autoresearcher").font(.largeTitle.bold())
            Text("An unattended contributor to a cairn node. It posts the objectives you choose, starts one node over its own log, solves what its repertoire covers, scores every candidate with the objective's pinned verifier, and submits through commit and reveal. Nothing here grades its own work.")
                .foregroundStyle(.secondary)
        }
    }

    private var setupCard: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 6) {
                ForEach(model.checks) { c in
                    HStack(alignment: .top, spacing: 8) {
                        Image(systemName: c.ok ? "checkmark.circle.fill" : "xmark.circle.fill")
                            .foregroundStyle(c.ok ? .green : .red)
                        Text(c.title).bold().frame(width: 130, alignment: .leading)
                        Text(c.detail).foregroundStyle(.secondary).textSelection(.enabled)
                    }
                }
                HStack {
                    Button("Build cairn (make ui-build)") { model.build() }.disabled(model.isBuilding || model.isRunning)
                    if #available(macOS 14, *) {
                        SettingsLink { Text("Settings…") }
                    }
                }
                .padding(.top, 4)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        } label: {
            Label("Before it can run", systemImage: "wrench.and.screwdriver").foregroundStyle(.orange)
        }
    }

    private var activityCard: some View {
        GroupBox {
            HStack(alignment: .center, spacing: 14) {
                if model.isRunning || model.isBuilding {
                    ProgressView().controlSize(.regular)
                } else {
                    Image(systemName: "pause.circle").font(.title).foregroundStyle(.secondary)
                }
                VStack(alignment: .leading, spacing: 4) {
                    if let p = model.progress {
                        let goal = model.rows.first { $0.id == p.objective }?.title ?? p.objective
                        Text("\(p.engine) on \(goal)").font(.headline)
                        Text(p.line.isEmpty ? "starting…" : p.line).font(.callout.monospaced()).foregroundStyle(.secondary)
                        Text("\(Int(max(0, now.timeIntervalSince1970 - p.started)))s elapsed").font(.caption).foregroundStyle(.tertiary)
                    } else if model.isBuilding {
                        Text("Building the cairn binary with the embedded reader").font(.headline)
                        Text("make ui-build — the Console pane has the output").foregroundStyle(.secondary)
                    } else if model.isRunning {
                        Text(model.status?.phase ?? "starting the node").font(.headline)
                        Text(lastEvent).font(.callout.monospaced()).foregroundStyle(.secondary).lineLimit(1)
                    } else {
                        Text("Stopped").font(.headline)
                        Text(model.status.map { "last update \($0.updated)" } ?? "no state directory yet").foregroundStyle(.secondary)
                    }
                }
                Spacer()
                if model.isRunning {
                    Button("Stop") { model.stop() }
                } else {
                    // Not the window's default button: a prominent Start would
                    // answer a stray Return by launching a node.
                    Button("Start") { model.start(once: false) }.disabled(model.isBuilding)
                    Button("One sweep") { model.start(once: true) }.disabled(model.isBuilding)
                }
            }
            .padding(4)
        } label: { Label("Activity", systemImage: "waveform.path.ecg") }
    }

    private var lastEvent: String {
        guard let e = model.journal.last else { return "…" }
        return "\(e.event)  \(e.detail)"
    }

    private var earningsCard: some View {
        GroupBox {
            Chart(model.earningsSeries) { p in
                BarMark(x: .value("Objective", p.label), y: .value("Reward", p.reward))
                    .foregroundStyle(Color.purple.opacity(0.7))
                    .annotation(position: .top) { Text(p.reward.formatted()).font(.caption2).foregroundStyle(.secondary) }
                LineMark(x: .value("Objective", p.label), y: .value("Cumulative", p.cumulative))
                    .foregroundStyle(Color.teal)
                    .interpolationMethod(.monotone)
                PointMark(x: .value("Objective", p.label), y: .value("Cumulative", p.cumulative))
                    .foregroundStyle(Color.teal)
            }
            .chartYAxisLabel("units")
            .frame(height: 160)
            .padding(.top, 4)
        } label: { Label("Earnings, in settlement order (bars per claim, line cumulative)", systemImage: "chart.bar.xaxis") }
    }

    /// A commitment is opened in a strictly later epoch; until then it is
    /// bound but hidden, and the researcher is waiting for the clock.
    private var pendingCard: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 4) {
                ForEach(model.pendingReveals) { r in
                    HStack {
                        Image(systemName: "lock.fill").foregroundStyle(.blue)
                        Text(r.title).bold()
                        Spacer()
                        if let e = r.epoch {
                            Text(model.currentEpoch > e ? "revealable now" : "reveal opens in \(model.secondsToNextEpoch)s")
                                .font(.callout.monospacedDigit()).foregroundStyle(.secondary)
                        }
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        } label: { Label("Committed, waiting for the epoch to turn", systemImage: "clock") }
    }

    private var settledCard: some View {
        GroupBox {
            if model.solved.isEmpty {
                Text("No accepted claims yet.").foregroundStyle(.secondary).frame(maxWidth: .infinity, alignment: .leading)
            } else {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(model.solved) { r in
                        HStack(spacing: 8) {
                            Image(systemName: r.icon).foregroundStyle(r.color)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(r.title).bold()
                                Text("\(r.strategy ?? "?")\(r.seconds.map { ", \(Int($0))s" } ?? "")  ·  \(r.claim.map { String($0.prefix(22)) } ?? "")")
                                    .font(.caption.monospaced()).foregroundStyle(.secondary)
                            }
                            Spacer()
                            Text(r.settled == true ? "paid \(r.paid.formatted())" : "accepted, settling")
                                .foregroundStyle(r.settled == true ? .primary : .secondary)
                            if model.nodeReachable {
                                Link(destination: model.readerURL(for: r.id)) { Image(systemName: "arrow.up.right.square") }
                                    .help("Open in the node's reader")
                            }
                        }
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } label: { Label("Accepted claims", systemImage: "checkmark.seal") }
    }

    private var stateCard: some View {
        GroupBox {
            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 5) {
                KeyValueRow(key: "Phase", value: model.status?.phase ?? (model.isRunning ? "starting" : "stopped"))
                KeyValueRow(key: "Node", value: model.nodeReachable ? model.nodeURL.absoluteString : "not running")
                KeyValueRow(key: "Submitter", value: model.status?.submitter.map { String($0.prefix(16)) + "…" } ?? "–", mono: true)
                KeyValueRow(key: "Epoch", value: "\(model.currentEpoch), next in \(model.secondsToNextEpoch)s (\(model.epochLength)s long)")
                KeyValueRow(key: "Budget", value: "\(model.budgetMinutes) min per objective")
                KeyValueRow(key: "Selected", value: "\(model.selectedObjectives.count) objectives to post")
                KeyValueRow(key: "Updated", value: model.status?.updated ?? "–")
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        } label: { Label("State", systemImage: "info.circle") }
    }
}
