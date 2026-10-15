import SwiftUI
import CairnKit
import CairnNodeUI

public struct PeersView: View {
    @EnvironmentObject private var model: AppModel

    public init() {}

    public var body: some View {
        List {
            Section("Recent sessions · observed by the node") {
                if let error = model.sessionsError { Text("Latest read failed. \(error)").foregroundStyle(.orange) }
                if let sourced = model.sessions {
                    SessionsPanel(sourced.value)
                    ProvenanceLine(sourced.provenance)
                } else { Text("A live node with /sessions is required. The snapshot has no session roster.").foregroundStyle(.secondary) }
            }
            Section {
                Text("Announcements below are addresses in the log. They are append-only and can name machines that are long gone. The session section reports whom this process reached recently.")
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
