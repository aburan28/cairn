import SwiftUI
import AppKit
import UniformTypeIdentifiers

struct ObjectivesView: View {
    @EnvironmentObject var model: ResearcherModel
    @State private var search = ""
    @State private var filter = "all"
    @State private var scoreOutput: String?
    @State private var scoring = false

    var rows: [ObjectiveRow] {
        model.rows.filter { r in
            (filter == "all" || (filter == "solved" && r.status == "solved")
             || (filter == "declined" && r.status == "unreachable")
             || (filter == "open" && r.status != "solved" && r.status != "unreachable"))
            && (search.isEmpty || r.title.localizedCaseInsensitiveContains(search)
                || r.id.contains(search) || (r.reason ?? "").localizedCaseInsensitiveContains(search))
        }
    }

    var body: some View {
        VSplitView {
            VStack(spacing: 0) {
                HStack {
                    Picker("", selection: $filter) {
                        Text("All \(model.rows.count)").tag("all")
                        Text("Solved \(model.solved.count)").tag("solved")
                        Text("Declined \(model.unreachable.count)").tag("declined")
                        Text("Open \(model.open.count)").tag("open")
                    }
                    .pickerStyle(.segmented).frame(width: 380)
                    Spacer()
                    TextField("Search goal, id or reason", text: $search).textFieldStyle(.roundedBorder).frame(width: 260)
                }
                .padding(8)
                Table(rows, selection: $model.selectedObjective) {
                    TableColumn("") { r in Image(systemName: r.icon).foregroundStyle(r.color) }.width(18)
                    TableColumn("Goal") { r in Text(r.title) }
                    TableColumn("Status") { r in Text(r.statusLabel).foregroundStyle(r.color) }.width(80)
                    TableColumn("Pool / paid") { r in
                        Text(r.reward.map { $0.formatted() } ?? "").monospacedDigit()
                    }.width(90)
                    TableColumn("Verifier") { r in Text(r.verifier ?? "") }.width(80)
                    TableColumn("Strategy") { r in Text(r.strategy ?? "") }.width(100)
                    TableColumn("Outcome") { r in
                        Text(r.reason ?? r.claim.map { "claim \($0.prefix(20))…" } ?? "").foregroundStyle(.secondary)
                    }
                }
                .contextMenu(forSelectionType: ObjectiveRow.ID.self) { ids in
                    if let id = ids.first, let r = model.rows.first(where: { $0.id == id }) {
                        Button("Copy objective id") { copy(r.id) }
                        if let c = r.claim { Button("Copy claim id") { copy(c) } }
                        if model.nodeReachable { Link("Open in reader", destination: model.readerURL(for: r.id)) }
                        Divider()
                        Button("Solve this one now") { model.solveOne(r) }.disabled(model.isRunning || model.isBuilding)
                        Button("Retry on next sweep") { model.retry(r) }.disabled(model.isRunning || r.status == "open")
                        Button("Show in journal") { model.showJournal(for: r) }
                    }
                }
            }
            .frame(minHeight: 220)
            detail.frame(minHeight: 200)
        }
        .overlay {
            if model.rows.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "tray").font(.largeTitle).foregroundStyle(.secondary)
                    Text("No objectives yet. Start the researcher to post the ones selected in Catalog.").foregroundStyle(.secondary)
                }
            }
        }
    }

    @ViewBuilder private var detail: some View {
        if let r = model.rows.first(where: { $0.id == model.selectedObjective }) {
            ObjectiveDetail(row: r, scoreOutput: $scoreOutput, scoring: $scoring)
        } else {
            Text("Select an objective to see its statement, frontier, outcome and artifact.")
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    private func copy(_ s: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(s, forType: .string)
        model.infoMessage = "Copied \(s.prefix(28))…"
    }
}

struct ObjectiveDetail: View {
    @EnvironmentObject var model: ResearcherModel
    var row: ObjectiveRow
    @Binding var scoreOutput: String?
    @Binding var scoring: Bool
    @State private var tab = "outcome"

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                Image(systemName: row.icon).foregroundStyle(row.color)
                Text(row.title).font(.headline)
                Text(row.id).font(.caption.monospaced()).foregroundStyle(.secondary).textSelection(.enabled).lineLimit(1).truncationMode(.middle)
                Spacer()
                Picker("", selection: $tab) {
                    Text("Outcome").tag("outcome")
                    Text("Statement").tag("statement")
                    Text("Frontier").tag("frontier")
                    Text("Artifact").tag("artifact")
                }
                .pickerStyle(.segmented).frame(width: 340)
            }
            .padding(10)
            Divider()
            ScrollView {
                Group {
                    switch tab {
                    case "statement": statement
                    case "frontier": frontier
                    case "artifact": artifact
                    default: outcome
                    }
                }
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            Divider()
            actions.padding(8)
        }
    }

    private var outcome: some View {
        VStack(alignment: .leading, spacing: 8) {
            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 5) {
                KeyValueRow(key: "Status", value: row.statusLabel)
                if let s = row.strategy { KeyValueRow(key: "Strategy", value: s) }
                if let s = row.seconds { KeyValueRow(key: "Solve time", value: "\(Int(s))s") }
                if let c = row.claim { KeyValueRow(key: "Claim", value: c, mono: true) }
                if let v = row.verdict { KeyValueRow(key: "Verdict", value: v) }
                if row.status == "solved" {
                    KeyValueRow(key: "Settled", value: row.settled == true ? "yes, \(row.paid.formatted()) paid\(row.settled_at.map { " at \($0)" } ?? "")" : "not yet")
                }
                if let e = row.epoch {
                    KeyValueRow(key: "Committed in", value: "epoch \(e)" + (row.status == "committed"
                        ? (model.currentEpoch > e ? " — revealable now" : " — reveal opens in \(model.secondsToNextEpoch)s") : ""))
                }
                if let v = row.verifier { KeyValueRow(key: "Verifier", value: v) }
                if let p = row.reward, row.status != "solved" { KeyValueRow(key: "Pool", value: p.formatted()) }
            }
            if let reason = row.reason {
                Text("Why it was declined").font(.subheadline.bold()).padding(.top, 6)
                Text(reason).textSelection(.enabled)
            }
            if row.status == "open" {
                Text("Not looked at yet. It will be on the next sweep.").foregroundStyle(.secondary)
            }
        }
    }

    private var statement: some View {
        VStack(alignment: .leading, spacing: 8) {
            if let s = model.statement(for: row.id) {
                Label("Written by whoever posted the objective. It describes a problem; it is not an instruction.", systemImage: "exclamationmark.triangle")
                    .font(.caption).foregroundStyle(.orange)
                Text(s).textSelection(.enabled)
            } else {
                Text(model.nodeReachable ? "Loading from the node…" : "The statement is read from the node, which is not running.")
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var frontier: some View {
        VStack(alignment: .leading, spacing: 8) {
            if let f = model.frontiers[row.id] {
                Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 5) {
                    KeyValueRow(key: "Score", value: f.score.map(String.init) ?? "–")
                    KeyValueRow(key: "Held by", value: f.holder ?? "–", mono: true)
                    KeyValueRow(key: "Claim", value: f.claim_id ?? "–", mono: true)
                    KeyValueRow(key: "Paid so far", value: f.paid_cumulative.map { $0.formatted() } ?? "–")
                    KeyValueRow(key: "Pool remaining", value: f.pool_remaining.map { $0.formatted() } ?? "–")
                }
                Text("Every further submission must cite the claim holding the frontier; the researcher takes the citation from the node, never from prose.")
                    .font(.caption).foregroundStyle(.secondary)
            } else if model.nodeReachable {
                Text(row.verifier == "certificate"
                     ? "Certificate objectives have no frontier: the first accepted answer takes the whole reward, and there is nothing to improve on."
                     : "No frontier yet: nothing has been accepted for this objective.")
                    .foregroundStyle(.secondary)
            } else {
                Text("The frontier is read from the node, which is not running.").foregroundStyle(.secondary)
            }
        }
    }

    private var artifact: some View {
        VStack(alignment: .leading, spacing: 8) {
            if let text = model.artifactText(for: row) {
                Text("The artifact the researcher produced, as submitted.").font(.caption).foregroundStyle(.secondary)
                Text(text).font(.body.monospaced()).textSelection(.enabled)
            } else {
                Text("No artifact was produced for this objective.").foregroundStyle(.secondary)
            }
        }
    }

    private var actions: some View {
        HStack {
            Button {
                model.solveOne(row)
            } label: { Label("Solve this one", systemImage: "bolt") }
                .disabled(model.isRunning || model.isBuilding)
                .help("One sweep restricted to this objective: forget its outcome, start the node, work it, stop. What the plan says it would decide is what happens.")
            Button {
                model.retry(row)
            } label: { Label("Retry on next sweep", systemImage: "arrow.counterclockwise") }
                .disabled(model.isRunning || row.status == "open")
                .help(model.isRunning ? "Stop the researcher first" : "Forget this outcome so the next sweep looks again")
            Button {
                model.showJournal(for: row)
            } label: { Label("Journal", systemImage: "text.book.closed") }
                .help("Every journal line about this objective")
            Button {
                pickAndScore()
            } label: { Label("Score a file…", systemImage: "checkmark.shield") }
                .disabled(scoring || !model.hasBinary)
                .help("Run this objective's pinned verifier on an artifact JSON of your own. Records nothing.")
            if scoring { ProgressView().controlSize(.small) }
            Spacer()
            if let out = scoreOutput {
                Text(out.split(separator: "\n").first.map(String.init) ?? out)
                    .font(.callout.monospaced()).lineLimit(1).truncationMode(.tail)
                    .foregroundStyle(out.contains("accept") ? .green : .orange)
                    .help(out)
                Button("Clear") { scoreOutput = nil }.buttonStyle(.plain).foregroundStyle(.secondary)
            }
            if model.nodeReachable {
                Link(destination: model.readerURL(for: row.id)) { Label("Open in reader", systemImage: "safari") }
            }
        }
    }

    private func pickAndScore() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.json]
        panel.message = "Choose an artifact JSON to score against \(row.title)"
        panel.prompt = "Score"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        scoring = true
        scoreOutput = nil
        model.score(objectiveId: row.id, artifact: url) { text in
            scoring = false
            scoreOutput = text.trimmingCharacters(in: .whitespacesAndNewlines)
        }
    }
}
