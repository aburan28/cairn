import SwiftUI
import CairnKit

public struct OverviewView: View {
    @EnvironmentObject private var model: AppModel

    public init() {}

    public var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                header
                health
                stats
                notes
                challenges
                checkIt
            }
            .padding()
        }
        .navigationTitle("cairn")
        .refreshable { await model.refresh() }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Verified results are the unit of account.")
                .font(.title2.weight(.semibold))
            Text("Post a question with a pinned checker and a bounty. Anyone who moves the answer forward is paid in proportion to how far they moved it, and every payment is re-derivable from the log.")
                .font(.subheadline)
                .foregroundStyle(.secondary)
        }
    }

    @ViewBuilder
    private var health: some View {
        HStack(spacing: 8) {
            Circle()
                .fill(healthColor)
                .frame(width: 8, height: 8)
            Text(healthLabel)
                .font(.caption)
                .foregroundStyle(.secondary)
            Spacer()
            if model.loading {
                ProgressView()
                    .controlSize(.small)
            }
        }
        .padding(10)
        .background(.background.secondary, in: RoundedRectangle(cornerRadius: 10))
    }

    private var healthColor: Color {
        switch model.health {
        case .live: return .green
        case .down: return .secondary
        case .checking: return .orange
        }
    }

    private var healthLabel: String {
        switch model.health {
        case .live: return "node live · \(model.resolvedBase)"
        case .down: return model.nodeURL.isEmpty
            ? "no node — showing the launch snapshot"
            : "no node at \(model.nodeURL)"
        case .checking: return "checking…"
        }
    }

    private var stats: some View {
        LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 10) {
            StatTile("objectives", value: "\(model.objectives.value.count)", from: model.objectives.provenance)
            StatTile("open", value: "\(model.open.count)", from: model.objectives.provenance)
            StatTile("pool", value: units(model.pool), from: model.objectives.provenance)
            StatTile("paid out", value: units(model.paid), from: model.objectives.provenance)
            if let chain = model.chain {
                StatTile("chain links", value: "\(chain.value.links)", from: chain.provenance)
                StatTile("height", value: "\(chain.value.height)", from: chain.provenance)
            }
        }
    }

    @ViewBuilder
    private var notes: some View {
        let messages = [model.objectives.note, model.chain?.note, model.checkpoint.note].compactMap { $0 }
        if !messages.isEmpty {
            VStack(alignment: .leading, spacing: 6) {
                Text("showing the snapshot for part of this page")
                    .font(.caption.weight(.semibold))
                ForEach(messages, id: \.self) { Text($0).font(.caption) }
            }
            .foregroundStyle(.orange)
            .cairnCard()
        }
    }

    private var challenges: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Challenges")
                .font(.headline)
            ForEach(model.objectives.value) { objective in
                NavigationLink {
                    ChallengeView(id: objective.id)
                } label: {
                    ObjectiveRow(objective: objective)
                }
                .buttonStyle(.plain)
            }
        }
    }

    private var checkIt: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Check it before you trust it")
                .font(.headline)
            Text("Every number above says where it came from: a node that answered, or \(model.snapshot.source) — a real settled log that ships in the repository, not a mock. Re-derive it yourself:")
                .font(.subheadline)
                .foregroundStyle(.secondary)
            Text("cairn --log launch/cairn.jsonl --root . audit")
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
                .cairnCard()
            HStack {
                Text("merkle root")
                    .foregroundStyle(.secondary)
                HashText(model.checkpoint.value.root ?? "—", chars: 10)
            }
            .font(.caption)
            ProvenanceLine(model.checkpoint.provenance)
        }
    }
}

public struct ObjectiveRow: View {
    let objective: Objective

    public var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(objective.goal.isEmpty ? shortHash(objective.id) : objective.goal)
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(.primary)
                Spacer()
                StatusBadge(objective.settled ? "settled" : "open", kind: objective.settled ? .neutral : .accent)
                StatusBadge(objective.verifier_kind, kind: .info)
            }
            UntrustedStatement(objective.statement, limit: 160)
            HStack(spacing: 12) {
                Text("pool \(units(objective.reward))")
                    .font(.system(.caption, design: .monospaced))
                if let frontier = objective.frontier {
                    Text("best \(frontier.score)")
                    HashText(frontier.holder, chars: 6)
                } else if let settlement = objective.settlement {
                    Text("settled — \(units(settlement.reward))")
                } else {
                    Text("no claim yet").foregroundStyle(.tertiary)
                }
            }
            .font(.caption)
            .foregroundStyle(.secondary)
            if overspent(objective) {
                Text("this node published a pool its own reward cannot cover")
                    .font(.caption)
                    .foregroundStyle(.red)
            }
            if let ratchet = objective.record?.ratchet, let frontier = objective.frontier,
               let fraction = ratchetProgress(score: frontier.score, ratchet: ratchet) {
                ProgressView(value: fraction)
                    .tint(.green)
            }
        }
        .cairnCard()
    }
}
