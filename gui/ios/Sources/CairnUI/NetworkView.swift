import SwiftUI
import CairnKit
import CairnNodeUI

public struct NetworkView: View {
    @EnvironmentObject private var model: AppModel
    public init() {}
    public var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                if let error = model.networkError { Text("Latest read failed. \(error) Any displayed data is from the last successful read.").foregroundStyle(.orange) }
                if let sourced = model.network {
                    NetworkPanel(sourced.value)
                    ProvenanceLine(sourced.provenance)
                } else { Text("Network needs a live node that publishes /network. The launch snapshot contains no sessions or compute fleet.").foregroundStyle(.secondary) }
                Button("Refresh") { Task { await model.refresh() } }.disabled(model.loading)
            }.padding()
        }
        .navigationTitle("Network")
        .refreshable { await model.refresh() }
    }
}
