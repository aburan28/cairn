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
                         caption: "\(model.solved.filter { $0.settled == true }.count) paid") { model.showObjectives("solved") }
                    Tile(title: "Declined", value: "\(model.unreachable.count)", color: .orange,
                         caption: "with a reason each") { model.showObjectives("declined") }
                    Tile(title: "Open", value: "\(model.open.count)", color: .blue,
                         caption: "not yet looked at") { model.showObjectives("open") }
                    Tile(title: "Earned", value: model.earned.formatted(), color: .purple, caption: "this identity, this log")
                    Tile(title: "Spendable", value: model.mySpendable.map { $0.formatted() } ?? "–", color: .teal,
                         caption: "from cairn balances") { model.pane = .node }
                }
                if !model.pendingReveals.isEmpty { pendingCard }
                if model.earningsSeries.count > 0 { earningsCard }
                if !model.declineGroups.isEmpty { declinedCard }
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
                Text("Each of these is read from the disk, not assumed. The researcher cannot start until the first four hold.")
                    .font(.caption).foregroundStyle(.secondary)
                ForEach(model.checks) { c in
                    HStack(alignment: .top, spacing: 8) {
                        Image(systemName: c.ok ? "checkmark.circle.fill" : "xmark.circle.fill")
                            .foregroundStyle(c.ok ? .green : .red)
                        Text(c.title).bold().frame(width: 130, alignment: .leading)
                        Text(c.detail).foregroundStyle(.secondary).textSelection(.enabled)
                    }
                }
                HStack {
                    Button("Build cairn (make ui-build)") { model.build() }.disabled(model.isBuilding || model.isLive)
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
            VStack(alignment: .leading, spacing: 8) {
                HStack(alignment: .center, spacing: 14) {
                    if model.isLive || model.isBuilding {
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
                        } else if model.isLive {
                            Text(model.phaseLine).font(.headline)
                            Text(lastEvent).font(.callout.monospaced()).foregroundStyle(.secondary).lineLimit(1)
                        } else {
                            Text("Stopped").font(.headline)
                            Text(model.status.map { "last update \($0.updated)" } ?? "no state directory yet").foregroundStyle(.secondary)
                        }
                    }
                    Spacer()
                    if model.isIdle { Button("Sweep now") { model.sweepNow() } }
                    if model.isRunning {
                        Button("Stop") { model.stop() }
                    } else if model.foreignPid == nil {
                        // Not the window's default button: a prominent Start would
                        // answer a stray Return by launching a node.
                        Button("Start") { model.start(once: false) }.disabled(model.isBuilding)
                        Button("One sweep") { model.start(once: true) }.disabled(model.isBuilding)
                    }
                }
                if let f = model.idleFraction, let s = model.secondsToNextSweep {
                    // The wait is the researcher's own: the bar reads the time
                    // it published, so a Sweep now is visible as the bar jumping.
                    ProgressView(value: f) {
                        Text("Next sweep in \(ResearcherModel.clock(s))")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    .progressViewStyle(.linear)
                } else if let sp = model.sweepProgress {
                    ProgressView(value: Double(sp.index), total: Double(sp.total)) {
                        Text("Sweep \(sp.n): objective \(sp.index) of \(sp.total)")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    .progressViewStyle(.linear)
                }
                if let pid = model.foreignPid {
                    Label("This researcher was started outside the app (pid \(String(pid))); the app is watching it, not running it. Stop it where it was started.",
                          systemImage: "info.circle")
                        .font(.caption).foregroundStyle(.secondary)
                }
                if let sw = model.status?.sweep, let last = sw.seconds, model.progress == nil {
                    Text("Last sweep took \(Int(last))s\(sw.finished.map { ", finished \($0.suffix(8))" } ?? "").")
                        .font(.caption).foregroundStyle(.tertiary)
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

    /// Why the declined objectives were declined. The two kinds mean
    /// different things: over budget is a setting, out of the repertoire is
    /// a strategy nobody has written.
    private var declinedCard: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 8) {
                ForEach(model.declineGroups) { g in
                    HStack(alignment: .top, spacing: 10) {
                        Image(systemName: g.label.hasPrefix("Out of") ? "questionmark.circle" : "hourglass")
                            .foregroundStyle(.orange)
                        VStack(alignment: .leading, spacing: 2) {
                            HStack(spacing: 6) {
                                Text(g.label).bold()
                                Text("\(g.rows.count)").font(.callout.monospacedDigit()).foregroundStyle(.secondary)
                                if g.pool > 0 {
                                    Text("· \(g.pool.formatted()) in pools left on the table")
                                        .font(.caption).foregroundStyle(.tertiary)
                                }
                            }
                            Text(g.example).font(.caption).foregroundStyle(.secondary).lineLimit(2)
                        }
                        Spacer()
                        Button("Show") {
                            model.selectedObjective = g.rows.first?.id
                            model.showObjectives("declined")
                        }
                        .buttonStyle(.link)
                    }
                }
                if model.declineGroups.contains(where: { !$0.label.hasPrefix("Out of") }) {
                    Text("Over-budget declines change with the compute budget in Settings; the Catalog re-plans against it and says which would flip.")
                        .font(.caption).foregroundStyle(.tertiary)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        } label: { Label("Declined, and why", systemImage: "hand.raised") }
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
