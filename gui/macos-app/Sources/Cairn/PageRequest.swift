import Foundation

/// A role the reader's Contribute page can turn on or off in this app. Each
/// is one toggle in Settings ▸ Roles, named here as `ui/lib/contribute.ts`
/// names it, so the page and the app cannot disagree about which switch a
/// button flips.
enum PageRole: String, CaseIterable {
    /// Settings ▸ Roles ▸ Validator: `--attest-identity`, under bond.
    case validator
    /// Settings ▸ Roles ▸ Relay: the P2P port on every interface.
    case relay
    /// Settings ▸ Roles ▸ Worker host: the HTTP side on every interface, so
    /// machines on the network can work for this node.
    case workerHost = "worker-host"

    /// What the toggle is called in Settings, for the confirmation.
    var title: String {
        switch self {
        case .validator: return "Validator"
        case .relay: return "Relay"
        case .workerHost: return "Worker host"
        }
    }
}

/// A sheet the reader's pages can ask this app to open. The page cannot do
/// any of these itself -- they run commands, hold keys, or change what the
/// node is started with -- and each is already a menu item here.
enum PageSheet: String, CaseIterable {
    case agents
    case work
    case peers
    case settings
    case newChallenge = "new-challenge"
}

/// A request from the reader, in the shape `ui/lib/draft.ts` and
/// `ui/lib/contribute.ts` send it.
enum PageRequest: Equatable {
    case draftChallenge(brief: String)
    case startDictation
    case stopDictation
    /// Turn a role on or off and restart the node with it.
    case setRole(PageRole, on: Bool)
    /// Open a sheet; `objective` is what Work on This Mac… starts on.
    case open(PageSheet, objective: String?)
    /// Local process control stays in the app; the node never accepts it over HTTP.
    case workStatus
    case startWork(objective: String)
    case stopWork

    static func parse(_ body: Any) -> Result<PageRequest, AIError> {
        guard let object = body as? [String: Any], let kind = object["kind"] as? String else {
            return .failure(AIError("The page sent something this app does not read."))
        }
        switch kind {
        case "work-status":
            return .success(.workStatus)
        case "start-work":
            guard let objective = object["objective"] as? String, Self.isObjectiveId(objective) else {
                return .failure(AIError("Choose an objective to work on."))
            }
            return .success(.startWork(objective: objective))
        case "stop-work":
            return .success(.stopWork)
        case "start-dictation":
            return .success(.startDictation)
        case "stop-dictation":
            return .success(.stopDictation)
        case "set-role":
            guard let role = (object["role"] as? String).flatMap(PageRole.init(rawValue:)) else {
                return .failure(AIError("This app has no role called \(object["role"] ?? "nothing")."))
            }
            guard let on = object["on"] as? Bool else {
                return .failure(AIError("A role is turned on or off; the page said neither."))
            }
            return .success(.setRole(role, on: on))
        case "open":
            guard let sheet = (object["sheet"] as? String).flatMap(PageSheet.init(rawValue:)) else {
                return .failure(AIError("This app has no sheet called \(object["sheet"] ?? "nothing")."))
            }
            let objective = object["objective"] as? String
            if let objective, !Self.isObjectiveId(objective) {
                return .failure(AIError("An objective is named by its id, sha256:…."))
            }
            return .success(.open(sheet, objective: objective))
        case "draft-challenge":
            guard let brief = (object["brief"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines),
                  ChallengeWriter.isDraftable(brief)
            else {
                return .failure(AIError("A description is between \(ChallengeWriter.briefLength.lowerBound) and \(ChallengeWriter.briefLength.upperBound) characters."))
            }
            return .success(.draftChallenge(brief: brief))
        default:
            return .failure(AIError("This app does not know the request \(kind)."))
        }
    }

    /// `sha256:` and 64 hex digits: the only shape an objective id has, and
    /// the only thing a page may hand to a command line through this app.
    static func isObjectiveId(_ text: String) -> Bool {
        guard text.hasPrefix("sha256:") else { return false }
        let digest = text.dropFirst("sha256:".count)
        return digest.count == 64 && digest.allSatisfy(\.isHexDigit)
    }
}
