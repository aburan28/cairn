#if canImport(SwiftUI)
import SwiftUI
import CairnNodeKit

public struct SecretValueEditor: View {
    @Binding private var value: String
    private let revealed: Bool
    public init(value: Binding<String>, revealed: Bool) { _value = value; self.revealed = revealed }
    public var body: some View {
        Group {
            if revealed { TextEditor(text: $value).font(.body.monospaced()).frame(minHeight: 64, maxHeight: 96) }
            else { SecureField("Value (paste here)", text: $value).font(.body.monospaced()) }
        }
    }
}

public struct SessionsPanel: View {
    public let report: SessionReport
    public init(_ report: SessionReport) { self.report = report }
    public var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            if report.available {
                Text("\(report.reached) reached · \(report.recent) recent · \(report.lost) lost · \(report.unreached) unreached")
                    .font(.callout.weight(.semibold))
                if let seconds = report.reached_within_seconds { Text("Reached within \(seconds) seconds; these are observations, not open sockets.").font(.caption).foregroundStyle(.secondary) }
                ForEach(report.peers) { peer in
                    VStack(alignment: .leading, spacing: 3) {
                        Text("\(peer.status) · \(peer.addr ?? "address not reported")").font(.callout.weight(.medium))
                        Text(peer.peer_id).font(.caption.monospaced()).textSelection(.enabled)
                        Text("\(peer.last_direction) · in \(peer.inbound_ok) · out \(peer.outbound_ok) · failures \(peer.failures) · last success \(peer.age_seconds.map { "\($0)s ago" } ?? "never")")
                            .font(.caption).foregroundStyle(.secondary)
                        if let error = peer.last_error { Text(error).font(.caption).foregroundStyle(.orange) }
                    }.padding(.vertical, 4)
                }
                if report.peers.isEmpty { Text("No peer sessions observed by this process.").foregroundStyle(.secondary) }
            } else { Text("This node is a plain publisher and runs no peer-to-peer service.") }
            Text(report.note).font(.caption).foregroundStyle(.secondary)
        }
    }
}

public struct NetworkPanel: View {
    public let report: NetworkReport
    public init(_ report: NetworkReport) { self.report = report }
    public var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 140), alignment: .leading)], alignment: .leading, spacing: 12) {
                tile("Peers reached", "\(report.peers.reached)", "observed recently")
                tile("Live workers", "\(report.compute.live)", "reported")
                tile("Steps / second", report.compute.steps_per_second.formatted(), "reported, live workers only")
                tile("Lanes", "\(report.compute.lanes)", "reported, live workers only")
                tile("This node", "\(report.node.hardware.cpus.map(String.init) ?? "?") CPUs", "\(report.node.hardware.os) · \(report.node.hardware.arch)")
            }
            Text("Declared roles: \(report.node.roles.declared.isEmpty ? "none" : report.node.roles.declared.joined(separator: ", "))").font(.callout)
            Text("A declaration expresses intent; it grants no authority.").font(.caption).foregroundStyle(.secondary)
            ForEach(report.node.warnings, id: \.self) { Text($0).font(.callout).foregroundStyle(.orange) }
            Text("Hardware by class · reported").font(.headline)
            ForEach(report.compute.classes) { row in
                Text("\(row.class): \(row.live) live of \(row.workers) workers · \(row.lanes) lanes · \(row.steps_per_second.formatted()) steps/s").font(.caption)
            }
            Text("Fleet · reported").font(.headline)
            ForEach(report.compute.workers) { worker in
                VStack(alignment: .leading, spacing: 2) {
                    Text("\(worker.worker) · \(worker.status) · \(worker.device)").font(.callout)
                    Text(worker.objective_id).font(.caption.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
                }
            }
            Text("Evidenced in this node’s log").font(.headline)
            Text("\(report.roles.coordinators.total) funders · \(report.roles.executors.total) accepted submitters · \(report.roles.verifiers.total) attestors").font(.caption)
            Text(report.roles.note).font(.caption).foregroundStyle(.secondary)
            Text(report.compute.note).font(.caption).foregroundStyle(.secondary)
            Text("Read from the live node at \(report.generated_at). \(report.note)").font(.caption).foregroundStyle(.secondary)
        }.textSelection(.enabled)
    }
    private func tile(_ title: String, _ value: String, _ note: String) -> some View {
        VStack(alignment: .leading) { Text(title).font(.caption).foregroundStyle(.secondary); Text(value).font(.title3.weight(.semibold)); Text(note).font(.caption2).foregroundStyle(.secondary) }
    }
}
#endif
