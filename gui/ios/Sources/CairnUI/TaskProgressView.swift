import SwiftUI
import CairnKit

/// One divided search as the node sees it: what the log has paid, beside
/// what the workers report. The same page as `/ui/task/?id=` on the site,
/// read from the same route, under the same rule: settled and reported are
/// two kinds of number, and every figure says which it is. Nothing here is
/// recomputed from the log; the node did that, and this screen shows it.
public struct TaskProgressView: View {
    let id: String
    @EnvironmentObject private var model: AppModel
    @State private var progress: ProgressResponse?
    @State private var readAt: Date?
    @State private var origin = ""
    @State private var failure: String?
    @State private var loading = false

    private static let refreshSeconds = 20

    public init(id: String) { self.id = id }

    public var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                if model.health != .live {
                    offline
                } else if let progress {
                    content(progress)
                } else if let failure {
                    failed(failure)
                } else {
                    HStack(spacing: 8) {
                        ProgressView().controlSize(.small)
                        Text("reading /progress…").font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
            .padding()
        }
        .navigationTitle(progress?.goal ?? model.objective(id: id)?.goal ?? shortHash(id))
        #if os(iOS)
        .navigationBarTitleDisplayMode(.inline)
        #endif
        .refreshable { await load() }
        .task(id: "\(id)|\(model.resolvedBase)|\(String(describing: model.health))") {
            await model.fillRecord(for: id)
            while !Task.isCancelled {
                await load()
                try? await Task.sleep(nanoseconds: UInt64(Self.refreshSeconds) * 1_000_000_000)
            }
        }
    }

    private func load() async {
        let base = model.resolvedBase
        guard model.health == .live, !base.isEmpty else { return }
        loading = true
        defer { loading = false }
        do {
            let next = try await NodeClient(base: base).fetchProgress(at: base, id: id)
            guard !Task.isCancelled else { return }
            progress = next
            origin = base
            readAt = Date()
            failure = nil
        } catch let NodeError.httpStatus(code, _) where code == 404 {
            failure = "\(base) answered 404 for /progress. Either it knows no objective \(shortHash(id)), or it was built before this route existed: a node from 1.14.0 on has it."
        } catch {
            failure = error.localizedDescription
        }
    }

    // MARK: - Sections

    @ViewBuilder
    private func content(_ p: ProgressResponse) -> some View {
        let job = jobFor(checkerSha256: model.objective(id: id)?.record?.verifier?.checker_sha256)
        let expected = job.flatMap(expectedSteps)
        let rate: Double? = p.reported.live > 0 ? p.reported.steps_per_second : nil
        let unit = job?.unitNoun ?? "units"
        header(p)
        provenance
        tiles(p, job: job, expected: expected, rate: rate, unit: unit)
        if let expected {
            expectation(p, expected: expected)
        }
        pool(p, unit: unit)
        workers(p)
        coverage(p)
        hourly(p, unit: unit)
        notes(p)
        command(job)
    }

    private func header(_ p: ProgressResponse) -> some View {
        HStack(spacing: 8) {
            StatusBadge(p.open ? "open" : "settled", kind: p.open ? .accent : .neutral)
            StatusBadge(p.kind, kind: .info)
            StatusBadge(roster(p.reported), kind: p.reported.live > 0 ? .accent : .neutral)
            Spacer()
            if loading {
                ProgressView().controlSize(.small)
            }
        }
    }

    private func roster(_ r: Reported) -> String {
        if r.live == 0, r.stale == 0 { return "nobody reporting" }
        var parts = ["\(r.live) live"]
        if r.stale > 0 { parts.append("\(r.stale) stale") }
        return parts.joined(separator: ", ")
    }

    private var provenance: some View {
        let when = readAt.map { $0.formatted(date: .omitted, time: .standard) } ?? "—"
        return Text("Read from \(origin) at \(when), again every \(Self.refreshSeconds) s while this screen is open. Settled figures are recomputed from the node's log; reported ones are what workers posted and nobody checked.")
            .font(.caption)
            .foregroundStyle(.secondary)
    }

    private func tiles(_ p: ProgressResponse, job: SearchJob?, expected: Double?, rate: Double?, unit: String) -> some View {
        let share = expected.flatMap { shareOfExpected(steps: p.derived.steps, expected: $0) }
        let odds = expected.flatMap { collisionOdds(steps: p.derived.steps, expected: $0) }
        let eta = expected.flatMap { etaSeconds(steps: p.derived.steps, expected: $0, rate: rate) }
        let whole = job.flatMap(expectedUnits).map { "of about \(formatMagnitude($0)) the whole search needs" }
        let poolNote = p.piecework.map { "left of \(units($0.pool_remaining + $0.paid_total)); \(units($0.unit_price)) per unit" }
        return LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 10) {
            StatTile("\(unit) paid", value: units(p.derived.units_paid), from: whole ?? "settled, from the log")
            StatTile("steps walked", value: formatMagnitude(p.derived.steps), from: "from the paid witnesses")
            StatTile("share of expected", value: formatPercent(share), from: expected.map { "expected \(formatLog2($0)) ops" } ?? "job not known to this reader")
            StatTile("workers live", value: "\(p.reported.live)", from: "\(p.reported.stale) stale · \(p.reported.gone) gone · reported")
            StatTile("rate, reported", value: formatRate(rate), from: "sum over live workers")
            StatTile("to expected cost", value: formatDuration(eta), from: rate == nil ? "needs a live reported rate" : "at the reported rate, if it holds")
            StatTile("odds a collision happened", value: formatPercent(odds), from: "birthday bound on the settled work")
            StatTile("pool", value: units(p.piecework?.pool_remaining), from: poolNote ?? "not piecework")
        }
    }

    private func expectation(_ p: ProgressResponse, expected: Double) -> some View {
        let share = shareOfExpected(steps: p.derived.steps, expected: expected) ?? 0
        return VStack(alignment: .leading, spacing: 8) {
            Text("Progress against the expected cost").font(.headline)
            ProgressView(value: min(1, max(0, share))).tint(.green)
            Text("Pollard rho has no finish line, only an expectation: about \(formatLog2(expected)) group operations here, with even odds of a collision by 94% of that and nine in ten by 171%. The bar is the settled share; the odds tile is what that share is worth.")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
        .cairnCard()
    }

    private func pool(_ p: ProgressResponse, unit: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Pool").font(.headline)
            LabeledContent("paid out") { Text(units(p.derived.reward)).monospaced() }
            LabeledContent("paid claims") { Text("\(p.derived.claims_paid) of \(p.derived.claims)").monospaced() }
            LabeledContent("rejected") { Text("\(p.derived.rejected)").monospaced() }
            LabeledContent("last hour") { Text("\(p.derived.last_hour.units_paid) \(unit) in \(p.derived.last_hour.claims_paid) claims").monospaced() }
            LabeledContent("last day") { Text("\(p.derived.last_day.units_paid) \(unit)").monospaced() }
            LabeledContent("in flight") { Text("\(p.derived.in_flight) not yet revealed").monospaced() }
        }
        .cairnCard()
    }

    private func workers(_ p: ProgressResponse) -> some View {
        let rows = mergeWorkers(derived: p.derived.workers, reported: p.reported.workers)
        return VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("Workers").font(.headline)
                Text("\(rows.count)").foregroundStyle(.secondary)
                Spacer()
                Text("live within \(p.reported.live_within_seconds) s · stale within \(p.reported.stale_within_seconds) s")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }
            if rows.isEmpty {
                Text("Nobody has been paid and nobody is reporting. A worker that posts a heartbeat appears here within seconds; one that has been paid appears when the log settles its claim.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            ForEach(rows) { row in
                WorkerLine(row: row, total: p.derived.units_paid)
            }
        }
        .cairnCard()
    }

    @ViewBuilder
    private func coverage(_ p: ProgressResponse) -> some View {
        if let coverage = p.derived.coverage {
            VStack(alignment: .leading, spacing: 8) {
                Text("Unit space").font(.headline)
                Text("\(units(coverage.units_touched)) of \(units(coverage.units)) units touched · \(formatPercent(coverageFraction(coverage))) of \(coverage.bins) bins")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                CoverageStrip(counts: coverage.counts)
                Text("Where paid elements came from, by seed, darker with more. \(coverage.unbinned) unbinned.")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }
            .cairnCard()
        }
    }

    private func hourly(_ p: ProgressResponse, unit: String) -> some View {
        let hours = denseHours(p.derived.hourly, hours: 48, now: Date())
        return VStack(alignment: .leading, spacing: 8) {
            Text("\(unit.capitalized) settled per hour, last 48 h").font(.headline)
            HourBars(hours: hours)
            if hours.allSatisfy({ $0.units_paid == 0 }) {
                Text("Nothing settled in this window. An hour with no bar is an hour with no settlement, not missing data.")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }
        }
        .cairnCard()
    }

    private func notes(_ p: ProgressResponse) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Two kinds of number").font(.caption.weight(.semibold))
            Text(p.derived.note).font(.caption)
            Text(p.reported.note).font(.caption)
        }
        .foregroundStyle(.secondary)
        .cairnCard()
    }

    private func command(_ job: SearchJob?) -> some View {
        let text = workerCommand(origin: origin, id: id, job: job)
        return VStack(alignment: .leading, spacing: 8) {
            Text("Run a worker against this node, from a checkout").font(.headline)
            Text(text)
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
                .cairnCard()
            Button("Copy the command") { copyToPasteboard(text) }
                .font(.caption)
        }
    }

    private var offline: some View {
        ContentUnavailableView {
            Label("Needs a live node", systemImage: "antenna.radiowaves.left.and.right.slash")
        } description: {
            Text("Progress is read from a node's /progress route: what its log has paid for, beside what its workers report. The launch snapshot has neither. Point the app at a node in Settings.")
        }
    }

    private func failed(_ message: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(message).font(.footnote).foregroundStyle(.red)
            Button("Try again") { Task { await load() } }
        }
        .cairnCard()
    }
}

/// One worker: the log's figures on the left, the heartbeat's on the right.
private struct WorkerLine: View {
    let row: WorkerRow
    let total: Int

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                Text(row.name)
                    .font(.subheadline.weight(.semibold))
                    .lineLimit(1)
                StatusBadge(label, kind: kind)
                Spacer()
                Text(units(row.derived?.units_paid ?? 0))
                    .font(.system(.subheadline, design: .monospaced))
            }
            HStack(spacing: 12) {
                Text(formatRate(workerRate(row.reported)))
                if let reported = row.reported {
                    if reported.units_pending > 0 {
                        Text("\(reported.units_pending) pending")
                    }
                    Text(formatAge(reported.age_seconds))
                } else if let paid = row.derived?.last_paid_at {
                    Text("last paid \(paid)")
                }
            }
            .font(.caption)
            .foregroundStyle(.secondary)
            if let device = row.reported?.device {
                Text(device)
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                    .lineLimit(1)
            }
            if total > 0, let paid = row.derived?.units_paid, paid > 0 {
                ProgressView(value: Double(paid) / Double(total)).tint(.green)
            }
        }
        .padding(.vertical, 4)
    }

    private var label: String {
        switch row.standing {
        case .live: return "live"
        case .stale: return "stale"
        case .gone: return "gone"
        case .settled: return "settled"
        }
    }

    private var kind: StatusBadge.Kind {
        switch row.standing {
        case .live: return .accent
        case .stale: return .warn
        case .gone: return .neutral
        case .settled: return .info
        }
    }
}

/// The unit space in bins, darker where more paid elements came from.
private struct CoverageStrip: View {
    let counts: [Int]

    var body: some View {
        let top = Double(counts.max() ?? 0)
        HStack(spacing: 0) {
            ForEach(Array(counts.enumerated()), id: \.offset) { _, count in
                Rectangle()
                    .fill(Color.green.opacity(top > 0 && count > 0 ? 0.25 + 0.75 * Double(count) / top : 0.06))
            }
        }
        .frame(height: 14)
        .clipShape(RoundedRectangle(cornerRadius: 4))
    }
}

/// Settled units per hour as bars; a missing hour is a zero-height bar.
private struct HourBars: View {
    let hours: [ProgressHour]

    var body: some View {
        let top = Double(hours.map(\.units_paid).max() ?? 0)
        VStack(alignment: .leading, spacing: 4) {
            HStack(alignment: .bottom, spacing: 1) {
                ForEach(hours) { hour in
                    Rectangle()
                        .fill(Color.green.opacity(hour.units_paid > 0 ? 0.8 : 0.08))
                        .frame(height: top > 0 ? max(2, 56 * Double(hour.units_paid) / top) : 2)
                        .frame(maxWidth: .infinity)
                }
            }
            .frame(height: 56, alignment: .bottom)
            HStack {
                Text(hours.first.map { String($0.hour.prefix(13)) } ?? "")
                Spacer()
                Text(hours.last.map { String($0.hour.prefix(13)) } ?? "")
            }
            .font(.caption2)
            .foregroundStyle(.tertiary)
        }
    }
}
