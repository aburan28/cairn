import Combine
import Foundation
import CairnKit
#if canImport(SwiftUI)
import SwiftUI
#endif

/// Everything the reader shows, and where each number came from.
///
/// Three independent loads — objectives, chain, checkpoint — because a node
/// can answer the first and not the third (`cairn checkpoint` is a thing an
/// operator chooses to run). A single request that failed together would
/// hide a live objectives list behind a missing signature.
@MainActor
public final class AppModel: ObservableObject {
    @Published public var nodeURL: String {
        didSet { UserDefaults.standard.set(nodeURL, forKey: Self.urlKey) }
    }
    @Published public var resolvedBase: String = ""
    @Published public var health: Health = .checking
    @Published public var objectives: Sourced<[Objective]>
    @Published public var chain: Sourced<Chain>?
    @Published public var checkpoint: Sourced<CheckpointFacts>
    @Published public var peers: Sourced<[Peer]>?
    @Published public var log: Sourced<ParsedLog>?
    @Published public var loading = false
    @Published public var lastError: String?

    public let snapshot: Snapshot
    private var client: NodeClient { NodeClient(base: nodeURL) }

    private static let urlKey = "cairn.nodeURL"

    public enum Health: Equatable {
        case checking, live, down
    }

    public init(snapshot: Snapshot? = nil, nodeURL: String? = nil) {
        let bundled = snapshot ?? (try? BundledSnapshot.load()) ?? Snapshot(
            source: "missing",
            chain: ChainFacts(head: "", links: 0, height: 0, ledger_head: ""),
            checkpoint: CheckpointFacts(head: nil, height: 0, root: nil, issued_at: "", public_key: ""),
            objectives: []
        )
        self.snapshot = bundled
        self.nodeURL = nodeURL ?? UserDefaults.standard.string(forKey: Self.urlKey) ?? ""
        self.objectives = Sourced(value: bundled.objectives, live: false, origin: bundled.source)
        self.checkpoint = Sourced(value: bundled.checkpoint, live: false, origin: bundled.source)
    }

    public var open: [Objective] { objectives.value.filter(\.open) }
    public var pool: Int { objectives.value.reduce(0) { $0 + $1.reward } }
    public var paid: Int {
        // A ratchet's payouts are summed in its frontier and its settlement
        // is null; a certificate has no frontier and one settlement. Adding
        // both never counts a payment twice, and leaving either out did.
        objectives.value.reduce(0) { sum, o in
            sum + (o.frontier?.paid_cumulative ?? 0) + (o.settlement?.reward ?? 0)
        }
    }

    public func refresh() async {
        loading = true
        lastError = nil
        health = .checking
        defer { loading = false }

        let base = await client.resolve()
        resolvedBase = base
        if base.isEmpty {
            health = .down
            applySnapshot()
            return
        }
        let live = await client.answers(base)
        health = live ? .live : .down
        if !live {
            applySnapshot(note: "Nothing answered at \(base).")
            lastError = "Nothing answered at \(base)."
            return
        }
        await loadAll(from: base)
    }

    public func loadAll(from base: String) async {
        async let objectivesLoad: Void = loadObjectives(from: base)
        async let chainLoad: Void = loadChain(from: base)
        async let checkpointLoad: Void = loadCheckpoint(from: base)
        async let peersLoad: Void = loadPeers(from: base)
        _ = await (objectivesLoad, chainLoad, checkpointLoad, peersLoad)
    }

    public func loadLog(from base: String? = nil) async {
        let at = base ?? resolvedBase
        guard !at.isEmpty else { return }
        do {
            let parsed = try await client.fetchLog(at: at)
            log = Sourced(value: parsed, live: true, origin: at)
        } catch {
            lastError = error.localizedDescription
        }
    }

    public func objective(id: String) -> Objective? {
        objectives.value.first { $0.id == id }
    }

    public func fillRecord(for id: String) async {
        let at = resolvedBase
        guard !at.isEmpty else { return }
        guard let index = objectives.value.firstIndex(where: { $0.id == id }) else { return }
        guard objectives.value[index].record == nil else { return }
        if let record = try? await client.fetchObjective(at: at, id: id) {
            var next = objectives.value
            next[index].record = record
            objectives = Sourced(value: next, live: objectives.live, origin: objectives.origin)
        }
    }

    private func loadObjectives(from base: String) async {
        do {
            var list = try await client.fetchObjectives(at: base)
            if list.isEmpty {
                objectives = Sourced(value: snapshot.objectives, live: false, origin: snapshot.source)
                return
            }
            // Detail is an enhancement: fetch records after the list is on
            // screen. A failure leaves the summary standing.
            for i in list.indices {
                if list[i].record == nil, let record = try? await client.fetchObjective(at: base, id: list[i].id) {
                    list[i].record = record
                }
            }
            objectives = Sourced(value: list, live: true, origin: base)
        } catch {
            objectives = Sourced(
                value: snapshot.objectives, live: false, origin: snapshot.source,
                note: error.localizedDescription
            )
        }
    }

    private func loadChain(from base: String) async {
        do {
            let value = try await client.fetchChain(at: base)
            chain = Sourced(value: value, live: true, origin: base)
        } catch {
            chain = Sourced(
                value: Chain(
                    head: snapshot.chain.head,
                    links: snapshot.chain.links,
                    height: snapshot.chain.height,
                    ledger_head: snapshot.chain.ledger_head
                ),
                live: false,
                origin: snapshot.source,
                note: error.localizedDescription
            )
        }
    }

    private func loadCheckpoint(from base: String) async {
        do {
            let response = try await client.fetchCheckpoint(at: base)
            checkpoint = Sourced(
                value: CheckpointFacts(
                    head: response.checkpoint.head,
                    height: response.checkpoint.height,
                    root: response.checkpoint.root,
                    issued_at: response.checkpoint.issued_at,
                    public_key: response.public_key
                ),
                live: true,
                origin: base
            )
        } catch let NodeError.httpStatus(code, _) where code == 404 {
            checkpoint = Sourced(
                value: snapshot.checkpoint, live: false, origin: snapshot.source,
                note: "\(base) publishes no checkpoint"
            )
        } catch {
            checkpoint = Sourced(
                value: snapshot.checkpoint, live: false, origin: snapshot.source,
                note: error.localizedDescription
            )
        }
    }

    private func loadPeers(from base: String) async {
        do {
            let response = try await client.fetchPeers(at: base)
            peers = Sourced(value: response.peers, live: true, origin: base, note: response.note)
        } catch {
            peers = Sourced(value: [], live: false, origin: base, note: error.localizedDescription)
        }
    }

    private func applySnapshot(note: String? = nil) {
        objectives = Sourced(value: snapshot.objectives, live: false, origin: snapshot.source, note: note)
        chain = Sourced(
            value: Chain(
                head: snapshot.chain.head,
                links: snapshot.chain.links,
                height: snapshot.chain.height,
                ledger_head: snapshot.chain.ledger_head
            ),
            live: false,
            origin: snapshot.source
        )
        checkpoint = Sourced(value: snapshot.checkpoint, live: false, origin: snapshot.source)
    }
}
