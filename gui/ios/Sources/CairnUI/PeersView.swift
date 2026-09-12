import SwiftUI
import CairnKit

public struct PeersView: View {
    @EnvironmentObject private var model: AppModel

    public init() {}

    public var body: some View {
        List {
            Section {
                Text("These are peers this node has been told about, not peers it is talking to. A peer record is append-only and nothing retracts it, so an entry here may name a machine that has been gone for months. Live session state is not published over HTTP.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            if let sourced = model.peers {
                if let note = sourced.note {
                    Section { Text(note).font(.caption) }
                }
                Section("announced") {
                    if sourced.value.isEmpty {
                        Text("No peer records in this log.")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(sourced.value) { peer in
                        VStack(alignment: .leading, spacing: 4) {
                            Text(peer.addr)
                                .font(.subheadline.weight(.semibold))
                            HStack {
                                Text("identity")
                                HashText(peer.identity)
                            }
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            HStack {
                                Text("seq \(peer.seq)")
                                Text(peer.created_at)
                            }
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                        }
                    }
                }
                ProvenanceLine(sourced.provenance)
            }
        }
        .navigationTitle("Peers")
        .refreshable { await model.refresh() }
    }
}
