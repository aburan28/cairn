import Foundation

/// What the sheet shows while a draft is made: the stages, the one under
/// way, and how far the model has got. Every number here is measured --
/// stages completed, characters received, seconds elapsed -- except the
/// bar's advance within the model's stage, which is an estimate against a
/// typical draft and says so.
struct DraftProgress: Equatable {
    enum Stage: Int, CaseIterable, Equatable {
        case connect, model, read, write, post, hole, statement, proof

        var title: String {
            switch self {
            case .connect: return "Reaching the provider"
            case .model: return "The model writes the theorem"
            case .read: return "Reading the draft"
            case .write: return "Writing the objective and Challenge.lean"
            case .post: return "Posting into a throwaway log"
            case .hole: return "Refusing a proof that is only a hole"
            case .statement: return "Compiling the theorem on its own"
            case .proof: return "Checking the model's proof with the kernel"
            }
        }
    }

    var stages: [Stage] = Stage.allCases
    var current: Stage = .connect
    var done: Set<Stage> = []
    var failedAt: Stage?
    var finishedOK: Bool?
    var startedAt = Date()
    /// A typical draft, in characters, for the bar's advance within the
    /// model's stage.
    static let typicalDraft = 7_000.0

    var model = AIProgress() {
        didSet {
            if model.stage != .connecting, current == .connect {
                done.insert(.connect)
                current = .model
            }
        }
    }

    /// Everything before `stage` is done; `stage` is under way.
    mutating func reached(_ stage: Stage) {
        guard let target = stages.firstIndex(of: stage) else { return }
        for earlier in stages[..<target] { done.insert(earlier) }
        current = stage
    }

    mutating func finished(ok: Bool) {
        done = Set(stages)
        finishedOK = ok
    }

    mutating func failed(at stage: Stage) {
        failedAt = stage
    }

    /// Completed stages over all stages, the model's stage advancing with
    /// what it has written and stopping short of complete until it is.
    var fraction: Double {
        guard !stages.isEmpty else { return 0 }
        let total = Double(stages.count)
        var value = Double(done.count) / total
        if current == .model, !done.contains(.model) {
            value += min(0.95, Double(model.written) / Self.typicalDraft) / total
        }
        return min(1, value)
    }

    /// One line on the stage under way.
    var headline: String {
        if let failedAt { return "Stopped while \(failedAt.title.lowercased())." }
        if finishedOK != nil { return "Tested." }
        switch current {
        case .model:
            switch model.stage {
            case .connecting:
                return "Waiting for the provider to answer…"
            case .thinking:
                return model.reasoned > 0
                    ? "The model is reasoning: \(model.reasoned.formatted()) characters so far…"
                    : "The model is thinking…"
            case .writing:
                return "The model has written \(model.written.formatted()) characters…"
            }
        default:
            return current.title + "…"
        }
    }
}
