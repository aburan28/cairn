import SwiftUI
import CairnKit

public struct ObjectivesView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""
    @State private var showSettled = true

    public init() {}

    public var body: some View {
        List {
            Section {
                Toggle("Show settled", isOn: $showSettled)
                ProvenanceLine(model.objectives.provenance)
            }
            ForEach(filtered) { objective in
                NavigationLink {
                    ChallengeView(id: objective.id)
                } label: {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(objective.goal.isEmpty ? shortHash(objective.id) : objective.goal)
                            .font(.subheadline.weight(.semibold))
                        Text("pool \(units(objective.reward)) · \(objective.verifier_kind)")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
        .navigationTitle("Objectives")
        .searchable(text: $query, prompt: "goal, id, funder")
        .refreshable { await model.refresh() }
    }

    private var filtered: [Objective] {
        model.objectives.value.filter { objective in
            if !showSettled && objective.settled { return false }
            let needle = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            if needle.isEmpty { return true }
            return objective.goal.lowercased().contains(needle)
                || objective.id.lowercased().contains(needle)
                || objective.funder.lowercased().contains(needle)
                || objective.statement.lowercased().contains(needle)
        }
        .sorted { $0.reward > $1.reward }
    }
}

public struct ChallengeView: View {
    let id: String
    @EnvironmentObject private var model: AppModel

    public init(id: String) { self.id = id }

    public var body: some View {
        ScrollView {
            if let objective = model.objective(id: id) {
                VStack(alignment: .leading, spacing: 16) {
                    HStack {
                        StatusBadge(objective.settled ? "settled" : "open", kind: objective.settled ? .neutral : .accent)
                        StatusBadge(objective.verifier_kind, kind: .info)
                    }
                    UntrustedStatement(objective.statement)
                    LabeledContent("pool") { Text(units(objective.reward)).monospaced() }
                    LabeledContent("funder") { HashText(objective.funder) }
                    LabeledContent("id") { HashText(objective.id, chars: 10) }
                    if let frontier = objective.frontier {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("Frontier").font(.headline)
                            LabeledContent("score") { Text("\(frontier.score)").monospaced() }
                            LabeledContent("holder") { HashText(frontier.holder) }
                            LabeledContent("must cite") { HashText(frontier.must_cite) }
                            LabeledContent("paid") { Text(units(frontier.paid_cumulative)).monospaced() }
                            LabeledContent("remaining") { Text(units(frontier.pool_remaining)).monospaced() }
                            if let ratchet = objective.record?.ratchet,
                               let fraction = ratchetProgress(score: frontier.score, ratchet: ratchet) {
                                ProgressView(value: fraction) {
                                    Text("frontier across the span")
                                }
                            }
                        }
                    }
                    if let settlement = objective.settlement {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("Settlement").font(.headline)
                            LabeledContent("paid") { Text(units(settlement.reward)).monospaced() }
                            LabeledContent("to") { HashText(settlement.submitter) }
                            LabeledContent("claim") { HashText(settlement.claim_id) }
                        }
                    }
                    FrontierHistory(objective: objective)
                    if overspent(objective) {
                        Text("This node published paid + remaining greater than the reward. That is a bug on one side of the seam, not a display choice.")
                            .font(.footnote)
                            .foregroundStyle(.red)
                    }
                    ProvenanceLine(model.objectives.provenance)
                }
                .padding()
            } else {
                ContentUnavailableView("No such objective", systemImage: "questionmark.circle")
            }
        }
        .navigationTitle(model.objective(id: id)?.goal ?? shortHash(id))
        #if os(iOS)
        .navigationBarTitleDisplayMode(.inline)
        #endif
        .task {
            await model.fillRecord(for: id)
            if model.health == .live {
                await model.loadLogIfNeeded()
            }
        }
    }
}

/// Successive frontier states, newest first — the same pile the site shows
/// at `/frontier?id=`. Built from log records the node already wrote; a
/// missing log is a missing history, not an empty one.
private struct FrontierHistory: View {
    let objective: Objective
    @EnvironmentObject private var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Frontier history").font(.headline)
            Text("Each move is a frontier record. The payout is this record's paid_cumulative minus the previous one — two numbers the node published, compared, not recomputed.")
                .font(.footnote)
                .foregroundStyle(.secondary)

            if let sourced = model.log {
                let moves = buildMoves(sourced.value.records, objectiveId: objective.id)
                if !sourced.value.problems.isEmpty {
                    Text("\(sourced.value.problems.count) line\(sourced.value.problems.count == 1 ? "" : "s") of the log could not be read. A move recorded on one of those would be missing.")
                        .font(.caption)
                        .foregroundStyle(.red)
                }
                if moves.isEmpty {
                    if objective.frontier != nil {
                        Text("This log has no frontier records for this objective.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    } else if objective.settlement != nil {
                        Text("A certificate settles once and moves no frontier, so there are no moves to list.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    } else {
                        Text("The frontier starts at the objective's baseline.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                } else {
                    ForEach(Array(moves.reversed().enumerated()), id: \.element.id) { index, move in
                        VStack(alignment: .leading, spacing: 4) {
                            HStack {
                                Text("\(move.score)")
                                    .font(.title3.weight(.semibold))
                                    .monospacedDigit()
                                if index == 0 {
                                    StatusBadge("current", kind: .accent)
                                }
                                Spacer()
                                Text("+\(units(move.paidThisMove))")
                                    .font(.system(.subheadline, design: .monospaced))
                            }
                            HStack {
                                Text("held by")
                                    .foregroundStyle(.secondary)
                                HashText(move.holder)
                            }
                            .font(.caption)
                            HStack {
                                Text("claim")
                                    .foregroundStyle(.secondary)
                                HashText(move.claimId)
                            }
                            .font(.caption)
                            if !move.consistent {
                                Text("disagrees with settlement (\(units(move.settlementReward)))")
                                    .font(.caption)
                                    .foregroundStyle(.red)
                            }
                            Text(move.ts)
                                .font(.caption2)
                                .foregroundStyle(.tertiary)
                        }
                        .padding(.vertical, 4)
                    }
                    if let frontier = objective.frontier {
                        let parts = moves.map { units($0.paidThisMove) }.joined(separator: " + ")
                        Text("\(parts) = \(units(frontier.paid_cumulative)) paid so far of \(units(objective.reward)) funded.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                ProvenanceLine(sourced.provenance)
            } else if model.health == .live {
                Button("Read the log for this history") {
                    Task { await model.loadLog() }
                }
            } else {
                Text("Point the app at a live node to walk the successive states. The snapshot has the current frontier, not the pile that built it.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
    }
}
