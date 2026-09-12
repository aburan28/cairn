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
    @Published public var recentNodes: [String]
    @Published public var loading = false
    @Published public var lastError: String?

    public let snapshot: Snapshot
    private var client: NodeClient { NodeClient(base: nodeURL) }
    /// Bumped at the start of every `refresh`. In-flight fetches captured the
    /// previous value and must not write back after a retarget or a fallback —
    /// that is how a late `/log` once restored a live table on a snapshot page.
    private var generation: UInt64 = 0

    private static let urlKey = "cairn.nodeURL"
    private static let recentKey = "cairn.recentNodes"
    private static let recentLimit = 8

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
        self.recentNodes = Self.uniqueNodes(UserDefaults.standard.stringArray(forKey: Self.recentKey) ?? [])
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
        generation += 1
        let token = generation
        // A superseded pass must not clear the spinner the newer one is
        // still holding up — two Settings taps used to do exactly that.
        defer { if token == generation { loading = false } }

        let base = await client.resolve()
        // After the await, not before: a slower earlier resolve once
        // overwrote the origin a newer pass had already loaded, and the
        // log keyed on `resolvedBase` while health was still live, so
        // the table and the objectives named two hosts.
        guard token == generation else { return }
        resolvedBase = base
        if base.isEmpty {
            health = .down
            applySnapshot()
            return
        }
        let live = await client.answers(base)
        guard token == generation else { return }
        health = live ? .live : .down
        if !live {
            applySnapshot(note: "Nothing answered at \(base).")
            lastError = "Nothing answered at \(base)."
            return
        }
        rememberNode(base)
        dropStale(keeping: base)
        await loadAll(from: base, token: token)
    }

    public func loadAll(from base: String) async {
        await loadAll(from: base, token: generation)
    }

    private func loadAll(from base: String, token: UInt64) async {
        async let objectivesLoad: Void = loadObjectives(from: base, token: token)
        async let chainLoad: Void = loadChain(from: base, token: token)
        async let checkpointLoad: Void = loadCheckpoint(from: base, token: token)
        async let peersLoad: Void = loadPeers(from: base, token: token)
        _ = await (objectivesLoad, chainLoad, checkpointLoad, peersLoad)
    }

    public func loadLog(from base: String? = nil) async {
        let at = base ?? resolvedBase
        let token = generation
        guard !at.isEmpty else {
            if token == generation { log = nil }
            return
        }
        do {
            let parsed = try await client.fetchLog(at: at)
            // A refresh can fall back to the snapshot, or retarget, while
            // this call is in flight. Writing back then would put a live
            // log on a page that just said nothing answered.
            guard token == generation, resolvedBase == at, health == .live else { return }
            log = Sourced(value: parsed, live: true, origin: at)
        } catch {
            // Only wipe the table if we still own this origin. A cancelled
            // older failure must not erase a newer log, and a fallback must
            // not be "fixed" by a late 404.
            guard token == generation, resolvedBase == at, health == .live else { return }
            log = nil
            lastError = error.localizedDescription
        }
    }

    /// Fetch the log only when this origin does not already have one.
    /// Challenge history and the Log tab share the same bytes; paying twice
    /// for the ledger is how a phone that opened one objective used to stall.
    public func loadLogIfNeeded() async {
        if let log, log.live, log.origin == resolvedBase, health == .live { return }
        guard health == .live, !resolvedBase.isEmpty else { return }
        await loadLog()
    }

    public func rememberNode(_ url: String) {
        let trimmed = Self.normalizeNode(url)
        guard !trimmed.isEmpty else { return }
        // Dedup the whole list, not only the host being saved. Mapping
        // slash variants and then filtering `!= trimmed` left two
        // `http://other` rows that ForEach identified as one.
        let next = Array(Self.uniqueNodes([trimmed] + recentNodes).prefix(Self.recentLimit))
        recentNodes = next
        UserDefaults.standard.set(next, forKey: Self.recentKey)
    }

    /// Point at a host and refresh. Recents are written only when that host
    /// answers — remembering the typed string here is how a mistype used to
    /// land in the list, and an unstructured `Task` per tap is how two
    /// recents interleaved their resolves.
    public func useNode(_ url: String) async {
        nodeURL = Self.normalizeNode(url)
        await refresh()
    }

    /// Trailing slashes are not part of the identity. `NodeClient` already
    /// strips them to talk to the host; the recents list has to do the same
    /// or the typed URL and the later resolved base both appear.
    private static func normalizeNode(_ url: String) -> String {
        var trimmed = url.trimmingCharacters(in: .whitespacesAndNewlines)
        while trimmed.hasSuffix("/") { trimmed.removeLast() }
        return trimmed
    }

    private static func uniqueNodes(_ urls: [String]) -> [String] {
        var seen = Set<String>()
        var out: [String] = []
        for url in urls {
            let normalized = normalizeNode(url)
            guard !normalized.isEmpty, seen.insert(normalized).inserted else { continue }
            out.append(normalized)
        }
        return out
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

    private func loadObjectives(from base: String, token: UInt64) async {
        do {
            let list = try await client.fetchObjectives(at: base)
            guard token == generation else { return }
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
                guard token == generation else { return }
                if let record = try? await client.fetchObjective(at: base, id: objective.id) {
                    applyRecord(id: objective.id, record: record, expectedOrigin: base)
                }
            }
        } catch {
            guard token == generation else { return }
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

    private func loadChain(from base: String, token: UInt64) async {
        do {
            let value = try await client.fetchChain(at: base)
            guard token == generation else { return }
            chain = Sourced(value: value, live: true, origin: base)
        } catch {
            guard token == generation else { return }
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

    private func loadCheckpoint(from base: String, token: UInt64) async {
        do {
            let response = try await client.fetchCheckpoint(at: base)
            guard token == generation else { return }
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
            guard token == generation else { return }
            checkpoint = Sourced(
                value: snapshot.checkpoint, live: false, origin: snapshot.source,
                note: "\(base) publishes no checkpoint"
            )
        } catch {
            guard token == generation else { return }
            checkpoint = Sourced(
                value: snapshot.checkpoint, live: false, origin: snapshot.source,
                note: error.localizedDescription
            )
        }
    }

    private func loadPeers(from base: String, token: UInt64) async {
        do {
            let response = try await client.fetchPeers(at: base)
            guard token == generation else { return }
            peers = Sourced(value: response.peers, live: true, origin: base, note: response.note)
        } catch {
            guard token == generation else { return }
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
