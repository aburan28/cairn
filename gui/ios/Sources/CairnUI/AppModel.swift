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
        dropStale(keeping: base)
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
        guard !at.isEmpty else {
            log = nil
            return
        }
        do {
            let parsed = try await client.fetchLog(at: at)
            log = Sourced(value: parsed, live: true, origin: at)
        } catch {
            // A failed fetch must not keep the previous node's log labelled
            // live. Nil drops the table; the error is the reason.
            log = nil
            lastError = error.localizedDescription
        }
    }

    public func objective(id: String) -> Objective? {
        objectives.value.first { $0.id == id }
    }

    public func fillRecord(for id: String) async {
        let at = resolvedBase
        guard !at.isEmpty else { return }
        guard objectives.value.contains(where: { $0.id == id && $0.record == nil }) else { return }
        guard let record = try? await client.fetchObjective(at: at, id: id) else { return }
        // Look up by id *after* the await. A refresh can replace the list
        // while this call is in flight; writing back at a captured index
        // would attach another objective's ratchet or trap out of bounds.
        applyRecord(id: id, record: record, expectedOrigin: at)
    }

    private func loadObjectives(from base: String) async {
        do {
            let list = try await client.fetchObjectives(at: base)
            if list.isEmpty {
                objectives = Sourced(value: snapshot.objectives, live: false, origin: snapshot.source)
                return
            }
            // Publish the summary first. Detail is an enhancement and used
            // to run before this assignment, so Overview stayed on the
            // snapshot and `refresh` held `loading` until every
            // `/objective/{id}` returned.
            objectives = Sourced(value: list, live: true, origin: base)
            for objective in list where objective.record == nil {
                if let record = try? await client.fetchObjective(at: base, id: objective.id) {
                    applyRecord(id: objective.id, record: record, expectedOrigin: base)
                }
            }
        } catch {
            objectives = Sourced(
                value: snapshot.objectives, live: false, origin: snapshot.source,
                note: error.localizedDescription
            )
        }
    }

    private func applyRecord(id: String, record: ObjectiveRecord, expectedOrigin: String) {
        guard objectives.origin == expectedOrigin,
              let index = objectives.value.firstIndex(where: { $0.id == id })
        else { return }
        var next = objectives.value
        next[index].record = record
        objectives = Sourced(value: next, live: objectives.live, origin: objectives.origin, note: objectives.note)
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
        // The snapshot has no log or peer list. Leaving the previous node's
        // here would show them with a live provenance line after a fallback.
        log = nil
        peers = nil
    }

    /// Drop auxiliary pages that still name a different origin.
    private func dropStale(keeping origin: String) {
        if log?.origin != origin { log = nil }
        if peers?.origin != origin { peers = nil }
    }
}
