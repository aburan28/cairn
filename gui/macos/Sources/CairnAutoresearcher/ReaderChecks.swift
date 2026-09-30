import Foundation
import SwiftUI

/// Reader-side checks ported from `gui/ios` / `ui/lib`. They do not re-derive
/// a frontier or a settlement — they only compare numbers the node already
/// published, so a second opinion here cannot disagree with the rules engine.

struct EpochLink: Decodable, Equatable {
    var epoch: Int
    var prev: String
    var link: String
}

struct FrontierMove: Identifiable, Equatable {
    var id: Int { seq }
    var seq: Int
    var ts: String
    var score: Int
    var holder: String
    var claimId: String
    var paidThisMove: Int
    var paidCumulative: Int
    var settlementReward: Int?
    var consistent: Bool
}

/// A ledger line with its payload kept, for `buildMoves`. The table's
/// `LedgerEntry` drops the payload to a summary string; this keeps enough to
/// walk frontier history without a second HTTP fetch.
struct LogRecord: Equatable {
    var seq: Int
    var kind: String
    var ts: String
    var payload: [String: Any]

    static func parse(ndjson text: String) -> [LogRecord] {
        var out: [LogRecord] = []
        for (i, line) in text.split(separator: "\n").enumerated() {
            guard let obj = try? JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any] else { continue }
            out.append(LogRecord(
                seq: obj["seq"] as? Int ?? i,
                kind: obj["kind"] as? String ?? "?",
                ts: obj["ts"] as? String ?? "",
                payload: obj["payload"] as? [String: Any] ?? [:]
            ))
        }
        return out
    }

    // `[String: Any]` is not Equatable; compare the fields moves care about.
    static func == (lhs: LogRecord, rhs: LogRecord) -> Bool {
        lhs.seq == rhs.seq && lhs.kind == rhs.kind && lhs.ts == rhs.ts
    }
}

/// Where a chain stops being a chain. Same as `firstBrokenLink` in
/// `gui/ios` and `ui/lib/chain.ts`.
func firstBrokenLink(_ chain: [EpochLink]) -> Int? {
    var expected = ""
    for link in chain {
        if link.prev != expected { return link.epoch }
        expected = link.link
    }
    return nil
}

/// Whether paid + remaining exceeds the objective's reward. Same as iOS
/// `overspent`.
func overspent(reward: Int, paid: Int?, remaining: Int?) -> Bool {
    guard let paid, let remaining else { return false }
    return paid + remaining > reward
}

/// Successive frontier states for one objective, oldest first. Same function
/// as `buildMoves` in `gui/ios` and `ui/lib/log.ts`.
func buildMoves(_ records: [LogRecord], objectiveId: String) -> [FrontierMove] {
    let frontiers = records
        .filter { $0.kind == "frontier" && ($0.payload["objective_id"] as? String) == objectiveId }
        .sorted { $0.seq < $1.seq }

    var settlementByClaim: [String: Int] = [:]
    for record in records where record.kind == "settlement" {
        guard (record.payload["objective_id"] as? String) == objectiveId,
              let claimId = record.payload["claim_id"] as? String else { continue }
        let reward = record.payload["reward"] as? Int
        if let reward { settlementByClaim[claimId] = reward }
    }

    var moves: [FrontierMove] = []
    var previousPaid = 0
    for record in frontiers {
        let payload = record.payload
        let paidCumulative = payload["paid_cumulative"] as? Int ?? 0
        let paidThisMove = paidCumulative - previousPaid
        let claimId = payload["claim_id"] as? String ?? ""
        let settlementReward = settlementByClaim[claimId]
        moves.append(FrontierMove(
            seq: record.seq,
            ts: record.ts,
            score: payload["score"] as? Int ?? 0,
            holder: payload["holder"] as? String ?? "",
            claimId: claimId,
            paidThisMove: paidThisMove,
            paidCumulative: paidCumulative,
            settlementReward: settlementReward,
            consistent: settlementReward == nil || settlementReward == paidThisMove
        ))
        previousPaid = paidCumulative
    }
    return moves
}

/// Caption naming where a number came from — researcher file, HTTP route, or
/// `cairn balances`. Same role as iOS `ProvenanceLine`.
struct ProvenanceLine: View {
    let sourced: String
    init(_ sourced: String) { self.sourced = sourced }
    var body: some View {
        Text(sourced)
            .font(.caption)
            .foregroundStyle(.secondary)
    }
}
