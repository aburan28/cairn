import SwiftUI
import CairnKit

public struct LogView: View {
    @EnvironmentObject private var model: AppModel
    @State private var kind: String = "all"

    public init() {}

    public var body: some View {
        List {
            if let sourced = model.log {
                if !sourced.value.problems.isEmpty {
                    Section("problems") {
                        ForEach(sourced.value.problems, id: \.self) { problem in
                            Text(problem).font(.caption).foregroundStyle(.red)
                        }
                    }
                }
                Section {
                    Picker("kind", selection: $kind) {
                        Text("all (\(sourced.value.records.count))").tag("all")
                        ForEach(kindCounts(sourced.value.records), id: \.0) { pair in
                            Text("\(pair.0) (\(pair.1))").tag(pair.0)
                        }
                    }
                    ProvenanceLine(sourced.provenance)
                }
                Section("records") {
                    ForEach(filtered(sourced.value.records)) { record in
                        VStack(alignment: .leading, spacing: 4) {
                            HStack {
                                Text(record.kind)
                                    .font(.caption.weight(.semibold))
                                Text("#\(record.seq)")
                                    .font(.caption)
                                    .foregroundStyle(.tertiary)
                                Spacer()
                                HashText(record.hash, chars: 6)
                            }
                            Text(summarize(record))
                                .font(.subheadline)
                            Text(record.ts)
                                .font(.caption2)
                                .foregroundStyle(.tertiary)
                        }
                    }
                }
            } else {
                Section {
                    Text("The log is fetched on demand — it is the whole ledger, and a phone that opened on Overview should not pay for it.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                    Button("Load the log") {
                        Task { await model.loadLog() }
                    }
                    .disabled(model.resolvedBase.isEmpty)
                }
            }
        }
        .navigationTitle("Log")
        .refreshable {
            await model.refresh()
            await model.loadLog()
        }
        .task {
            if model.log == nil, !model.resolvedBase.isEmpty {
                await model.loadLog()
            }
        }
    }

    private func filtered(_ records: [LogRecord]) -> [LogRecord] {
        kind == "all" ? records : records.filter { $0.kind == kind }
    }
}
