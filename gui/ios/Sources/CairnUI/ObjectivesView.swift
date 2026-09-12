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
        .task { await model.fillRecord(for: id) }
    }
}
