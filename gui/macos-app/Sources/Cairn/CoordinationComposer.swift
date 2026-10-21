import AppKit
import Foundation

/// One app-owned operation survives reader reloads and node restarts. The page gets
/// a receipt and an opaque draft id; it can never supply the files to publish.
@MainActor
final class CoordinationComposer {
    struct Context {
        let root: URL
        let binary: URL
        let environment: [String: String]
        let config: AIConfig
        let key: String
        let catalog: String
    }
    struct Services {
        var prepare: (String) async throws -> Context
        var complete: (Context, String) async throws -> [String: Any]
        var check: (BuiltCoordination, CoordinationDraft, Context) async throws -> String
        var post: (BuiltCoordination) async throws -> Void
        var confirm: (CoordinationDraft) -> Bool
    }
    private struct Prepared {
        let token: String
        let draft: CoordinationDraft
        let built: BuiltCoordination
        let objectiveID: String
    }
    private let services: Services
    private var work: Task<Void, Never>?
    private var generation = UUID()
    private var prepared: Prepared?
    private(set) var phase = "idle"
    private(set) var brief = ""
    private(set) var budget = ""
    private var message = ""
    private var provider = ""

    init(services: Services) { self.services = services }

    convenience init(node: Node) {
        self.init(services: Services(
            prepare: { [weak node] brief in
                guard let node else { throw AIError("The node is no longer available.") }
                try Self.requireLocalNode(node)
                guard case .running(let reader) = node.state else { throw AIError("Wait for the node to finish starting.") }
                let config = AIConfig.current()
                if let problem = config.problem { throw AIError(problem) }
                guard let key = await node.secretValue(config.provider.secretName) else {
                    throw AIError("Add your \(config.provider.title) API key in Settings → AI, then generate the spec again.")
                }
                guard let binary = node.binary ?? Node.locateBinary() else { throw AIError("No cairn command was found.") }
                let settings = node.settings
                let environment = await Task.detached { Node.childEnvironment(settings) }.value
                let goals = await GoalLookup.find(brief, reader: reader)
                let catalog = goals.prefix(8).map { "\($0.handle): \($0.name). \($0.summary ?? "")" }.joined(separator: "\n")
                return Context(root: settings.dataFolder, binary: binary, environment: environment,
                               config: config, key: key, catalog: catalog)
            },
            complete: { context, request in
                try await AIClient(config: context.config, apiKey: context.key).complete(
                    system: CoordinationWriter.system, user: request, schema: CoordinationWriter.schema,
                    schemaName: "cairn_coordinated_challenge")
            },
            check: { built, draft, context in
                try await CoordinationBuilder.check(built, draft: draft, binary: context.binary,
                                                    environment: context.environment)
            },
            post: { [weak node] built in
                guard let node else { throw AIError("The node is no longer available.") }
                try Self.requireLocalNode(node)
                guard node.dataDir.standardizedFileURL == built.root.standardizedFileURL else {
                    throw AIError("The node's data folder changed. Generate a spec for this node first.")
                }
                guard case .running = node.state else { throw AIError("Wait for the node to finish starting.") }
                try built.requireUnchanged()
                // Every objective ships a solver contributors can press Start
                // on; `cairn post --solver` checks it against this spec's
                // checker in the sandbox and refuses the launch unless it passes.
                let solver: String? = await MainActor.run {
                    let panel = NSOpenPanel()
                    panel.canChooseDirectories = true
                    panel.canChooseFiles = false
                    panel.allowsMultipleSelection = false
                    panel.message = "Choose the solver package to publish with this challenge (a folder with solver.json)."
                    panel.prompt = "Publish With This Solver"
                    return panel.runModal() == .OK ? panel.url?.path : nil
                }
                guard let solver else {
                    throw AIError("A challenge launches with its solver package. Choose one to publish with it.")
                }
                guard FileManager.default.fileExists(atPath: (solver as NSString).appendingPathComponent("solver.json")) else {
                    throw AIError("That folder has no solver.json. Run `cairn solver pack` in it first.")
                }
                try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                    node.postObjectives(at: [built.objectiveFile.path], solver: solver) { error in
                        if let error { continuation.resume(throwing: AIError(error)) }
                        else { continuation.resume() }
                    }
                }
            },
            confirm: { draft in
                // Publishing spends the pool. Native confirmation binds the action to the
                // checked spec, not to scriptable preview text supplied by a web page.
                let alert = NSAlert()
                alert.messageText = "Launch this challenge?"
                alert.informativeText = "\(draft.statement)\n\n\(draft.units) pieces · \(draft.price) units per piece\nTotal budget: \(draft.reward) units"
                alert.addButton(withTitle: "Launch challenge")
                alert.addButton(withTitle: "Cancel")
                return alert.runModal() == .alertFirstButtonReturn
            }
        ))
    }

    static func ownsNode(attachURL: URL?, background: Bool) -> Bool {
        guard let attachURL else { return true }
        // A background setting alone does not authorize writing a different attached node.
        return background && attachURL == BackgroundService.readerURL
    }

    static func requireLocalNode(_ node: Node) throws {
        guard ownsNode(attachURL: node.settings.attachURL, background: node.runsInBackground) else {
            throw AIError("Open Coordination in the Cairn app that manages this node to generate and launch its challenge.")
        }
    }

    var busy: Bool { ["drafting", "checking", "launching"].contains(phase) }

    func snapshot() -> [String: Any] {
        var result: [String: Any] = ["phase": phase, "brief": brief, "budget": budget,
                                     "message": message, "provider": provider]
        if let prepared {
            let draft = prepared.draft
            result["draftId"] = prepared.token
            result["objectiveId"] = prepared.objectiveID
            result["spec"] = String(decoding: prepared.built.objectiveBytes, as: UTF8.self)
            result["statement"] = draft.statement
            result["unit"] = draft.unit
            result["units"] = String(draft.units)
            result["unitPrice"] = String(draft.price)
            result["reward"] = String(draft.reward)
            result["notes"] = draft.notes
        }
        return result
    }

    func generate(brief: String, budget: String) throws -> [String: Any] {
        guard !busy else { throw AIError("A challenge is already being prepared or launched.") }
        guard ChallengeWriter.isDraftable(brief) else { throw AIError("Describe the task in 10 to 20,000 characters.") }
        let amount = try CoordinationWriter.budget(budget)
        let token = UUID()
        generation = token
        self.brief = brief.trimmingCharacters(in: .whitespacesAndNewlines)
        self.budget = amount.map(String.init) ?? ""
        prepared = nil
        message = ""
        provider = ""
        phase = "drafting"
        work = Task {
            do {
                let context = try await services.prepare(self.brief)
                try Task.checkCancellation()
                provider = context.config.label
                var request = CoordinationWriter.request(brief: self.brief, budget: amount, catalog: context.catalog)
                for attempt in 0..<2 {
                    phase = "drafting"
                    let object = try await services.complete(context, request)
                    try Task.checkCancellation()
                    do {
                        let draft = try CoordinationWriter.parse(object, budget: amount)
                        let built = try CoordinationBuilder.build(draft, root: context.root)
                        phase = "checking"
                        let objectiveID = try await services.check(built, draft, context)
                        try Task.checkCancellation()
                        guard PageRequest.isObjectiveId(objectiveID) else { throw AIError("The checker returned no objective id.") }
                        try built.requireUnchanged()
                        prepared = Prepared(token: token.uuidString, draft: draft, built: built, objectiveID: objectiveID)
                        phase = "ready"
                        message = "The checker accepted the valid example and rejected the incorrect and empty examples."
                        return
                    } catch let failure as CoordinationFailure {
                        throw failure // Missing inputs and unavailable tools are not errors for the model to repair.
                    } catch is CancellationError {
                        throw CancellationError()
                    } catch {
                        guard attempt == 0 else { throw error }
                        let previous = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
                        request += "\nRepair the previous spec and return the entire JSON again.\nPrevious spec:\n"
                            + String(decoding: previous, as: UTF8.self)
                            + "\nValidation failure:\n" + String(error.localizedDescription.prefix(8000))
                        message = "Revising the spec after checking it…"
                    }
                }
            } catch {
                guard generation == token, !Task.isCancelled else { return }
                phase = "error"
                message = error.localizedDescription
            }
        }
        return snapshot()
    }

    func cancel() throws -> [String: Any] {
        guard phase != "launching" else { throw AIError("The challenge is being posted. Wait for its result.") }
        generation = UUID()
        work?.cancel()
        work = nil
        prepared = nil
        phase = "idle"
        message = ""
        return snapshot()
    }

    func launch(_ token: String) throws -> [String: Any] {
        guard let prepared, prepared.token == token else { throw AIError("Generate and check this spec before launching it.") }
        if phase == "posted" || phase == "launching" { return snapshot() }
        guard phase == "ready" else { throw AIError("The spec is not ready to launch.") }
        try prepared.built.requireUnchanged()
        guard services.confirm(prepared.draft) else { throw AIError("Launch cancelled. Your checked spec is still ready.") }
        phase = "launching"
        message = "Launching the checked challenge…"
        work = Task {
            do {
                try await services.post(prepared.built)
                phase = "posted"
                message = "Challenge launched."
            } catch {
                phase = "ready"
                message = error.localizedDescription
            }
        }
        return snapshot()
    }
}
