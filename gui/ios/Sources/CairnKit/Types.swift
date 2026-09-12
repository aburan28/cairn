import Foundation

/// Shapes a cairn node publishes over HTTP.
///
/// Field names match `GET /objectives`, `GET /chain`, `GET /checkpoint` and
/// `GET /peers` in `src/serve.rs`. Nothing here re-derives a frontier, a
/// settlement or a chain — the node decided those, and a second opinion in
/// Swift would be a third place for the rule to drift. The website's
/// `ui/lib/*.ts` is the same contract in another language; the tests pin both
/// to `ui/lib/snapshot.json`.

public struct Frontier: Codable, Hashable, Sendable {
    public var claim_id: String
    public var holder: String
    public var must_cite: String
    public var paid_cumulative: Int
    public var pool_remaining: Int
    public var score: Int

    public init(
        claim_id: String,
        holder: String,
        must_cite: String,
        paid_cumulative: Int,
        pool_remaining: Int,
        score: Int
    ) {
        self.claim_id = claim_id
        self.holder = holder
        self.must_cite = must_cite
        self.paid_cumulative = paid_cumulative
        self.pool_remaining = pool_remaining
        self.score = score
    }
}

/// A certificate's one payment. `null` for a ratchet, whose payouts are many
/// and live on `frontier.paid_cumulative`.
public struct Settlement: Codable, Hashable, Sendable {
    public var claim_id: String
    public var submitter: String
    public var reward: Int
}

public struct Ratchet: Codable, Hashable, Sendable {
    public var baseline: Int
    public var target: Int
    public var direction: String
    public var min_improvement: Int
    public var reward: Int
}

public struct ObjectiveRecord: Codable, Hashable, Sendable {
    public var ratchet: Ratchet?
    public var created_at: String?
}

public struct Objective: Codable, Hashable, Identifiable, Sendable {
    public var id: String
    public var goal: String
    public var statement: String
    public var reward: Int
    public var funder: String
    public var verifier_kind: String
    /// No longer payable, as the node judges it — not "a settlement exists".
    public var settled: Bool
    /// `!settled`, published by the node rather than negated here.
    public var open: Bool
    public var settlement: Settlement?
    public var frontier: Frontier?
    public var record: ObjectiveRecord?

    public init(
        id: String,
        goal: String,
        statement: String,
        reward: Int,
        funder: String,
        verifier_kind: String,
        settled: Bool,
        open: Bool,
        settlement: Settlement? = nil,
        frontier: Frontier? = nil,
        record: ObjectiveRecord? = nil
    ) {
        self.id = id
        self.goal = goal
        self.statement = statement
        self.reward = reward
        self.funder = funder
        self.verifier_kind = verifier_kind
        self.settled = settled
        self.open = open
        self.settlement = settlement
        self.frontier = frontier
        self.record = record
    }
}

public struct ObjectivesResponse: Codable, Sendable {
    public var objectives: [Objective]
}

public struct EpochLink: Codable, Hashable, Sendable {
    public var epoch: Int
    public var claims: [String]
    public var prev: String
    public var link: String
}

public struct Chain: Codable, Sendable {
    public var head: String
    public var links: Int
    public var height: Int
    public var ledger_head: String
    public var chain: [EpochLink]
    public var note: String?

    public init(
        head: String,
        links: Int,
        height: Int,
        ledger_head: String,
        chain: [EpochLink] = [],
        note: String? = nil
    ) {
        self.head = head
        self.links = links
        self.height = height
        self.ledger_head = ledger_head
        self.chain = chain
        self.note = note
    }
}

/// The facts the landing page needs from `/chain` when the full link list
/// is not loaded. Same names as the endpoint.
public struct ChainFacts: Codable, Hashable, Sendable {
    public var head: String
    public var links: Int
    public var height: Int
    public var ledger_head: String

    // Explicit: a public Codable struct only synthesises `init(from:)`,
    // which is useless to CairnUI constructing a labelled fallback.
    public init(head: String, links: Int, height: Int, ledger_head: String) {
        self.head = head
        self.links = links
        self.height = height
        self.ledger_head = ledger_head
    }
}

public struct Checkpoint: Codable, Hashable, Sendable {
    public var head: String?
    public var height: Int
    public var root: String?
    public var issued_at: String
}

public struct CheckpointResponse: Codable, Sendable {
    public var checkpoint: Checkpoint
    public var public_key: String
    public var signature: String?
}

public struct CheckpointFacts: Codable, Hashable, Sendable {
    public var head: String?
    public var height: Int
    public var root: String?
    public var issued_at: String
    public var public_key: String

    public init(
        head: String?,
        height: Int,
        root: String?,
        issued_at: String,
        public_key: String
    ) {
        self.head = head
        self.height = height
        self.root = root
        self.issued_at = issued_at
        self.public_key = public_key
    }
}

public struct Peer: Codable, Hashable, Identifiable, Sendable {
    public var identity: String
    public var transport: String
    public var addr: String
    public var seq: Int
    public var created_at: String
    public var id: String { "\(identity):\(seq)" }
}

public struct PeersResponse: Codable, Sendable {
    public var peers: [Peer]
    public var note: String?
}

public struct Seed: Codable, Hashable, Sendable {
    public var name: String
    public var addr: String?
    public var transport: String?
    public var http: String?
    public var `operator`: String?
    public var note: String?
}

public struct SeedList: Codable, Sendable {
    public var version: Int?
    public var seeds: [Seed]
    public var note: String?
}

/// The committed fallback: `launch/cairn.jsonl` as a node once served it.
///
/// Named `source` so nothing can render it as live by accident. Generated by
/// `scripts/site-snapshot.sh` and copied beside this file; a test requires
/// the copy to decode, which is how a field rename in the node shows up here.
public struct Snapshot: Codable, Sendable {
    public var source: String
    public var chain: ChainFacts
    public var checkpoint: CheckpointFacts
    public var objectives: [Objective]

    public init(
        source: String,
        chain: ChainFacts,
        checkpoint: CheckpointFacts,
        objectives: [Objective]
    ) {
        self.source = source
        self.chain = chain
        self.checkpoint = checkpoint
        self.objectives = objectives
    }
}

/// One value and where it came from. The landing page reads three endpoints
/// and each falls back on its own, so provenance is per value.
public struct Sourced<Value: Sendable>: Sendable {
    public var value: Value
    public var live: Bool
    public var origin: String
    public var note: String?

    public init(value: Value, live: Bool, origin: String, note: String? = nil) {
        self.value = value
        self.live = live
        self.origin = origin
        self.note = note
    }

    public var provenance: String {
        live ? "live from \(origin)" : "from \(origin) snapshot"
    }
}

public struct LogRecord: Hashable, Identifiable, Sendable {
    public var seq: Int
    public var kind: String
    public var hash: String
    public var prev: String?
    public var ts: String
    /// Untyped on purpose: this type's job is parsing NDJSON, not knowing
    /// every record kind the protocol will ever add.
    public var payload: [String: JSONValue]
    public var id: Int { seq }

    public init(
        seq: Int,
        kind: String,
        hash: String,
        prev: String?,
        ts: String,
        payload: [String: JSONValue]
    ) {
        self.seq = seq
        self.kind = kind
        self.hash = hash
        self.prev = prev
        self.ts = ts
        self.payload = payload
    }
}

/// One step in an objective's frontier, as the log recorded it.
///
/// `paidThisMove` is this record's `paid_cumulative` minus the previous
/// frontier record's — arithmetic on two numbers the node published, not a
/// new one. `settlementReward` is the `settlement` naming the same
/// `claim_id`, joined by value, not by re-hashing anything.
public struct FrontierMove: Hashable, Identifiable, Sendable {
    public var seq: Int
    public var ts: String
    public var score: Int
    public var holder: String
    public var claimId: String
    public var paidThisMove: Int
    public var paidCumulative: Int
    public var settlementReward: Int?
    /// Whether this move's own payout matches what `settlement` records for
    /// the same claim. A mismatch means this node published two records that
    /// disagree about one payment. `true` when no settlement has landed yet
    /// — the log may not have reached it.
    public var consistent: Bool
    public var id: Int { seq }

    public init(
        seq: Int,
        ts: String,
        score: Int,
        holder: String,
        claimId: String,
        paidThisMove: Int,
        paidCumulative: Int,
        settlementReward: Int?,
        consistent: Bool
    ) {
        self.seq = seq
        self.ts = ts
        self.score = score
        self.holder = holder
        self.claimId = claimId
        self.paidThisMove = paidThisMove
        self.paidCumulative = paidCumulative
        self.settlementReward = settlementReward
        self.consistent = consistent
    }
}

public enum JSONValue: Hashable, Sendable {
    case string(String)
    case int(Int)
    case double(Double)
    case bool(Bool)
    case object([String: JSONValue])
    case array([JSONValue])
    case null

    public var string: String? {
        if case let .string(value) = self { return value }
        return nil
    }

    public var int: Int? {
        switch self {
        case let .int(value): return value
        case let .double(value) where value.rounded() == value: return Int(value)
        default: return nil
        }
    }

    public subscript(_ key: String) -> JSONValue? {
        if case let .object(object) = self { return object[key] }
        return nil
    }
}

public struct ParsedLog: Sendable {
    public var records: [LogRecord]
    /// One entry per line that did not parse as a record. Never thrown: a
    /// log with one bad line still has every other line.
    public var problems: [String]
}

public enum NodeError: Error, Equatable, LocalizedError {
    case unreachable(String)
    case httpStatus(Int, String)
    case notANode(String)
    case shape(String)

    public var errorDescription: String? {
        switch self {
        case let .unreachable(base):
            return "No node answered at \(base)."
        case let .httpStatus(code, path):
            return "\(path) answered \(code)."
        case let .notANode(base):
            return "\(base) answered, but not as a cairn node."
        case let .shape(detail):
            return detail
        }
    }
}
