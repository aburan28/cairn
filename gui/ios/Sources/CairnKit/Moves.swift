import Foundation

/// The successive frontier states for one objective, oldest first.
///
/// Built entirely from `frontier` and `settlement` records already in the
/// log, matched by `objective_id` and `claim_id` — values the node wrote, not
/// anything this file derives. This is deliberately *not* built by walking a
/// claim's `cites` array back to the claim it named: that would mean
/// resolving `claim_id` to the claim record that produced it, and a claim's
/// `claim_id` is a canonical hash of its payload rather than the record's own
/// chained `hash` field. Recomputing that hash here would be a second
/// implementation of a rule this project keeps in exactly one place —
/// `src/canonical.rs` — so this reads the frontier records' own sequence
/// instead, which already *is* the order improvements were admitted in.
///
/// Same function as `buildMoves` in `ui/lib/log.ts`. The tests pin both to
/// the same fixtures.
public func buildMoves(_ records: [LogRecord], objectiveId: String) -> [FrontierMove] {
    let frontiers = records
        .filter { $0.kind == "frontier" && $0.payload["objective_id"]?.string == objectiveId }
        .sorted { $0.seq < $1.seq }

    var settlementByClaim: [String: Int] = [:]
    for record in records {
        guard record.kind == "settlement",
              record.payload["objective_id"]?.string == objectiveId,
              let claimId = record.payload["claim_id"]?.string,
              let reward = record.payload["reward"]?.int
        else { continue }
        settlementByClaim[claimId] = reward
    }

    var moves: [FrontierMove] = []
    var previousPaid = 0
    for record in frontiers {
        let payload = record.payload
        let paidCumulative = payload["paid_cumulative"]?.int ?? 0
        let paidThisMove = paidCumulative - previousPaid
        let claimId = payload["claim_id"]?.string ?? ""
        let settlementReward = settlementByClaim[claimId]
        moves.append(
            FrontierMove(
                seq: record.seq,
                ts: record.ts,
                score: payload["score"]?.int ?? 0,
                holder: payload["holder"]?.string ?? "",
                claimId: claimId,
                paidThisMove: paidThisMove,
                paidCumulative: paidCumulative,
                settlementReward: settlementReward,
                consistent: settlementReward == nil || settlementReward == paidThisMove
            )
        )
        previousPaid = paidCumulative
    }
    return moves
}
