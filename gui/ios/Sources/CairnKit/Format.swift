import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// Display helpers that match `ui/lib` so a hash abbreviated on the phone
/// is the same abbreviation as on the site. These are presentation, not
/// consensus: a wrong short form is ugly, a wrong amount would be a lie.

/// `sha256:abcd1234…wxyz` — enough to compare by eye, short enough for a row.
public func shortHash(_ value: String, head: Int = 8, tail: Int = 4) -> String {
    let bare = value.hasPrefix("sha256:") ? String(value.dropFirst(7)) : value
    let limit = head + tail
    if bare.count <= limit { return bare }
    return "\(bare.prefix(head))…\(bare.suffix(tail))"
}

/// Integer amounts, grouped. No currency symbol and no decimal: money here
/// is `u64` with checked arithmetic so nothing renders a fraction of one.
public func units(_ value: Int) -> String {
    value.formatted(.number.grouping(.automatic))
}

public func units(_ value: Int?) -> String {
    guard let value else { return "—" }
    return units(value)
}

/// How much of the funded pool is still payable, as a fraction in [0, 1].
///
/// `pool_remaining` against `reward` rather than against
/// `paid_cumulative + pool_remaining`: the reward is what was funded, and
/// if those two ever disagree the objective has paid out something the
/// funding did not cover, which is worth seeing rather than normalising away.
public func poolFraction(of objective: Objective) -> Double? {
    guard let frontier = objective.frontier, objective.reward > 0 else { return nil }
    let fraction = Double(frontier.pool_remaining) / Double(objective.reward)
    return min(1, max(0, fraction))
}

/// Whether the node published a pool that its own reward cannot account for.
///
/// Rendered rather than hidden. Everything else is the node's word; this is
/// the one arithmetic check a reader can do for itself, same instinct as
/// `firstBrokenLink`.
public func overspent(_ objective: Objective) -> Bool {
    guard let frontier = objective.frontier else { return false }
    return frontier.paid_cumulative + frontier.pool_remaining > objective.reward
}

/// How far a ratchet has travelled from baseline to target, in [0, 1].
///
/// Direction-aware: a `minimize` objective counts *down*, and a bar that
/// filled as the score rose would show a submitter making things worse as
/// progress. `nil` when the span is degenerate rather than dividing by zero.
public func ratchetProgress(score: Int, ratchet: Ratchet) -> Double? {
    let span = Double(ratchet.target - ratchet.baseline)
    if span == 0 { return nil }
    let moved = (Double(score) - Double(ratchet.baseline)) / span
    return min(1, max(0, moved))
}

/// Same as the website's `progress()`: a percentage for a bar, display only.
public func ratchetPercent(score: Int, ratchet: Ratchet) -> Int {
    let span = ratchet.direction == "minimize"
        ? ratchet.baseline - ratchet.target
        : ratchet.target - ratchet.baseline
    if span <= 0 { return 0 }
    let moved = ratchet.direction == "minimize"
        ? ratchet.baseline - score
        : score - ratchet.baseline
    return min(100, max(0, Int((Double(moved) / Double(span) * 100).rounded())))
}

public func totalClaims(_ chain: [EpochLink]) -> Int {
    chain.reduce(0) { $0 + $1.claims.count }
}

/// Epoch lengths this chain appears to have been settled under, largest first.
///
/// A heuristic, and labelled as one wherever it is rendered. The divisor is
/// unrecoverable from the log, so this cannot be a derivation — it notices
/// a discontinuity. See `epochScales` in `ui/lib/chain.ts`.
public func epochScales(_ chain: [EpochLink]) -> [Int] {
    var scales = Set<Int>()
    for link in chain where link.epoch > 0 {
        scales.insert(Int(floor(log10(Double(link.epoch)))))
    }
    return scales.sorted(by: >)
}

public func kindCounts(_ records: [LogRecord]) -> [(String, Int)] {
    var order: [String] = []
    var counts: [String: Int] = [:]
    for record in records {
        if counts[record.kind] == nil { order.append(record.kind) }
        counts[record.kind, default: 0] += 1
    }
    return order.map { ($0, counts[$0] ?? 0) }
}

/// One line describing what a record says. The page's own reading of the
/// payload, not a field the node wrote — unrecognised kinds dump the payload
/// rather than go blank, so a future kind is still legible here.
public func summarize(_ record: LogRecord) -> String {
    let payload = record.payload
    switch record.kind {
    case "objective":
        let goal = payload["goal"]?.string ?? "?"
        let kind = payload["verifier"]?["kind"]?.string ?? "?"
        let reward = payload["reward"]?.int.map(units) ?? "?"
        let funder = payload["funder"]?.string ?? "?"
        return "\(goal) · \(kind) · \(reward) by \(funder)"
    case "commitment":
        return "by \(payload["submitter"]?.string ?? "?")"
    case "claim":
        let who = payload["submitter"]?.string ?? "?"
        if case let .array(cites) = payload["cites"], let first = cites.first?.string {
            let extra = cites.count > 1 ? " +\(cites.count - 1)" : ""
            return "by \(who) · cites \(shortHash(first))\(extra)"
        }
        return "by \(who)"
    case "verdict":
        let status = payload["verdict"]?["status"]?.string ?? "?"
        if let detail = payload["verdict"]?["detail"]?.string, !detail.isEmpty {
            return "\(status): \(detail)"
        }
        return status
    case "settlement":
        let who = payload["submitter"]?.string ?? "?"
        let reward = payload["reward"]?.int.map(units) ?? "?"
        return "\(who) ← \(reward)"
    case "frontier":
        let score = payload["score"]?.int.map(String.init) ?? "?"
        let holder = payload["holder"]?.string ?? "?"
        let paid = payload["paid_cumulative"]?.int.map(units) ?? "?"
        return "\(score) · \(holder) · paid \(paid) so far"
    case "batch":
        let epoch = payload["epoch"]?.int.map(String.init) ?? "?"
        let n: Int
        if case let .array(claims) = payload["claims"] { n = claims.count } else { n = 0 }
        return "epoch \(epoch) · \(n) claim\(n == 1 ? "" : "s")"
    case "peer":
        let identity = payload["identity"]?.string.map { shortHash($0) } ?? "?"
        let addr = payload["addr"]?.string ?? "?"
        return "\(identity) answers at \(addr)"
    default:
        let flat = String(describing: payload)
        return flat.count > 96 ? String(flat.prefix(96)) + "…" : flat
    }
}

/// A pretty-printed record, for the expanded row.
///
/// Two-space JSON rather than anything fancier: this is meant to look like
/// the line the node actually wrote, not like a view's opinion of it. Same
/// job as `pretty` in `ui/lib/log.ts`.
public func pretty(_ record: LogRecord) -> String {
    let object: [String: Any] = [
        "seq": record.seq,
        "kind": record.kind,
        "hash": record.hash,
        "prev": record.prev as Any? ?? NSNull(),
        "ts": record.ts,
        "payload": record.payload.mapValues(\.jsonObject),
    ]
    guard JSONSerialization.isValidJSONObject(object),
          let data = try? JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys]),
          let text = String(data: data, encoding: .utf8)
    else {
        return String(describing: record)
    }
    return text
}

extension JSONValue {
    fileprivate var jsonObject: Any {
        switch self {
        case let .string(value): return value
        case let .int(value): return value
        case let .double(value): return value
        case let .bool(value): return value
        case let .object(value): return value.mapValues(\.jsonObject)
        case let .array(value): return value.map(\.jsonObject)
        case .null: return NSNull()
        }
    }
}
