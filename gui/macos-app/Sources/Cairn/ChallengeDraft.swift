import Foundation

/// A challenge as a model drafted it from a person's description: the parts
/// of an objective that need judgment, before this app adds the parts that
/// need none (the timestamp, the record's shape, the verifier's fixed
/// fields).
///
/// A drafted challenge is a **Lean 4 theorem**. What is paid for is a proof
/// the Lean kernel accepts, and nothing else: no Python checker, no judgment
/// call, no float. The model writes the theorem and the person reads it,
/// because the theorem is what decides who gets paid.
struct ChallengeDraft: Equatable {
    var goal: String
    /// What solvers read: prose.
    var statement: String
    /// The theorem a proof must close, as one Lean 4 declaration header with
    /// no proof: `theorem name (x : T) : P`. Pinned by the objective; the
    /// verifier appends the submitted proof to it, so a solver cannot prove
    /// something easier.
    var theorem: String
    /// Lean source placed before the theorem: definitions, notation, lemmas
    /// with complete proofs. Empty when the theorem needs none.
    var preamble: String
    /// A complete proof, starting with `:=`, when the model is sure of one;
    /// nil otherwise, which is normal for a problem worth paying for.
    var proof: String?
    /// Seconds the kernel may spend on one proof, as the objective pins it.
    var timeoutSeconds: Int
    var notes: String

    /// The proof text every Lean challenge is tested against first: a hole,
    /// which the verifier screens before any toolchain is looked for.
    static let hole = ":= by sorry"

    /// The file as the verifier assembles it: preamble, then the theorem
    /// with a proof text appended.
    func source(proof: String) -> String {
        "\(preamble)\n\(theorem) \(proof)\n"
    }
}

/// The escape hatches the node's `lean` verifier screens for before Lean
/// ever runs (`src/verifiers/mod.rs`, `FORBIDDEN` and `NATIVE_DECIDE`),
/// applied here to what the model wrote. The verifier screens only the
/// submitted proof -- the preamble is the objective's own -- so a `sorry`'d
/// lemma or an `axiom` in a drafted preamble would let a one-line proof
/// collect the reward. Caught before anything is tested, in the verifier's
/// words.
enum LeanScreen {
    struct Rule: Equatable {
        let token: String
        let wholeWord: Bool
        let why: String
    }

    static let rules: [Rule] = [
        Rule(token: "sorry", wholeWord: true, why: "contains `sorry`: an explicit hole, proves nothing"),
        Rule(token: "admit", wholeWord: true, why: "contains `admit`: an explicit hole, proves nothing"),
        Rule(token: "axiom", wholeWord: true, why: "declares an axiom: adds a trusted assumption"),
        Rule(token: "@[implemented_by", wholeWord: false, why: "replaces an implementation outside the kernel"),
        Rule(token: "native_decide", wholeWord: true, why: "uses `native_decide`: trusts the compiler, not the kernel"),
    ]

    /// The reasons the verifier would give for this text; empty when it passes.
    static func hits(in text: String) -> [String] {
        rules.compactMap { rule in matches(text, rule) ? rule.why : nil }
    }

    static func matches(_ text: String, _ rule: Rule) -> Bool {
        guard rule.wholeWord else { return text.contains(rule.token) }
        let pattern = "\\b" + NSRegularExpression.escapedPattern(for: rule.token) + "\\b"
        return text.range(of: pattern, options: .regularExpression) != nil
    }
}

enum ChallengeWriter {
    /// How long a description may be. Under ten characters there is nothing
    /// to draft from; over twenty thousand it is a document, and every byte
    /// goes to the provider. `ui/lib/draft.ts` holds the page to the same
    /// numbers, counted the way JavaScript counts a string's length.
    static let briefLength = 10...20_000

    static func isDraftable(_ brief: String) -> Bool {
        briefLength.contains(brief.trimmingCharacters(in: .whitespacesAndNewlines).utf16.count)
    }

    /// Seconds the kernel may spend on one proof when the model asks for
    /// nothing else: the verifier's own default.
    static let defaultTimeout = 120
    /// What a draft may ask for. Below it a kernel check of anything real
    /// times out; above it one objective holds a verifier for an hour.
    static let timeoutRange = 30...3600

    /// What the model is told. The theorem it writes decides who gets paid,
    /// so most of this is about the ways a formalisation goes wrong in this
    /// network specifically: the proof is checked by plain `lean` on one
    /// file with no project, the preamble is public and part of the
    /// objective, and five tokens are refused outright.
    static let system = """
        You turn a plain-language description of a problem into a challenge for cairn, \
        a network that pays for machine-checked proofs. You write the challenge as a \
        Lean 4 theorem. A solver submits a proof of exactly that theorem; the Lean \
        kernel decides, alone and automatically, whether it is a proof, and a proof is \
        paid. Write for a stranger who will only ever see the prose statement, the \
        preamble and the theorem.

        Return one JSON object with exactly these fields, every one a string:
        - goal: a short handle, "GOAL-" followed by two to six lowercase words joined \
        by hyphens, e.g. "GOAL-add-comm-nat".
        - statement: what a solver must prove, in plain prose, precise enough to work \
        on, and what makes it worth proving. Do not restate the Lean source.
        - theorem: one Lean 4 declaration header with no proof: "theorem <name> \
        <binders> : <proposition>". No ":=", no "by", nothing after the proposition. \
        The name is lowercase_with_underscores.
        - preamble: Lean 4 source placed before the theorem: definitions, notation, \
        auxiliary lemmas with complete proofs, open namespaces. An empty string when \
        the theorem needs none.
        - proof: a complete proof of the theorem, starting with ":=", as text appended \
        to the theorem, e.g. ":= by omega" or ":= Nat.add_comm a b"; or an empty \
        string if you cannot write one you are confident the kernel accepts. Never \
        guess. A challenge worth paying for usually has no known proof; that is fine.
        - timeout_seconds: seconds the kernel may spend checking one proof, as a \
        decimal integer between 30 and 3600; "120" unless the proposition is \
        decided by heavy computation.
        - notes: one or two sentences for the person paying: how you formalised it, \
        what the theorem does and does not capture, an assumption you made. Empty if \
        none.

        Rules. The file checked is the preamble, a blank line, then the theorem with \
        the solver's proof text appended, compiled by plain `lean` with no project:
        - Core Lean 4 and Std only. No Mathlib, no lake project, no import other than \
        Std. Every name must resolve from the preamble and the core library alone.
        - The verifier rejects any proof containing sorry, admit, axiom, \
        @[implemented_by] or native_decide. Never use those words in the preamble or \
        the theorem either, not even in a comment: an axiom or a sorry'd lemma in the \
        preamble would let a one-line proof collect the reward, and the words alone \
        fail the screen.
        - The theorem must mean what the description asks. For a search problem, state \
        the search space and the property as computable definitions in the preamble \
        and make the theorem an existential, so a found witness is proved by giving it \
        and deciding the property (`⟨w, by decide⟩`, `rfl`). For a claim about all \
        inputs, a universal. Where the problem is finite, make the proposition \
        decidable.
        - Never make the theorem trivially true or vacuous, and never hide the hard \
        part in a definition that assumes the answer.
        - The preamble and the theorem are published with the challenge. Everything \
        in them is given to every solver.

        If the description asks for something a theorem cannot capture (an opinion, \
        "the best" with no measure), choose a precise proposition that captures the \
        checkable part, use it, and say so in notes.
        """

    /// The reply's shape. Every field is a string so one schema works under
    /// the strictest structured-output rules (every object closed, every
    /// field required); the number is parsed afterwards.
    static let schema: [String: Any] = [
        "type": "object",
        "properties": [
            "goal": ["type": "string"],
            "statement": ["type": "string"],
            "theorem": ["type": "string"],
            "preamble": ["type": "string"],
            "proof": ["type": "string"],
            "timeout_seconds": ["type": "string"],
            "notes": ["type": "string"],
        ],
        "required": ["goal", "statement", "theorem", "preamble", "proof", "timeout_seconds", "notes"],
        "additionalProperties": false,
    ]

    /// The person's description, and on a redraft the previous attempt and
    /// what was wrong with it, as one message: a fresh request rather than a
    /// conversation, so nothing about earlier turns has to be replayed.
    static func request(describing description: String, previous: ChallengeDraft? = nil, problems: [String] = [],
                        angleOn: String? = nil) -> String {
        var text = "Problem to pose, as its funder described it:\n\n\(description.trimmingCharacters(in: .whitespacesAndNewlines))\n"
        if let angleOn {
            // Deduplication, from the node's goal catalog (docs/goals.md): the
            // person chose to post this as a new angle on a goal that exists,
            // so the model is told the handle instead of inventing one.
            text += """

                This challenge is a new ANGLE on an existing goal, \(angleOn). Set "goal" to \
                "\(angleOn)/<angle>", where <angle> is one or two lowercase hyphenated words naming \
                the approach this challenge takes (for example rho/gpu-kernel, index-calculus, \
                formal, theory). Do not invent a different goal name.

                """
        }
        if let previous {
            text += """

                An earlier draft of this challenge had problems. Fix them and return the \
                whole challenge again.

                Earlier preamble:
                ```lean
                \(previous.preamble)
                ```
                Earlier theorem:
                ```lean
                \(previous.theorem)
                ```
                Earlier proof: \(previous.proof ?? "(none)")

                Problems:

                """
            text += problems.map { "- \($0)" }.joined(separator: "\n")
            text += "\n"
        }
        return text
    }

    static func parse(_ object: [String: Any]) throws -> ChallengeDraft {
        func field(_ name: String) throws -> String {
            guard let value = object[name] as? String else {
                throw AIError("The model's draft has no \(name).")
            }
            return value.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        let theorem = try field("theorem")
        guard theorem.hasPrefix("theorem ") else {
            throw AIError("The model's theorem does not start with `theorem`.")
        }
        guard !theorem.contains(":=") else {
            throw AIError("The model put a proof inside the theorem; the theorem is pinned and the proof is what solvers submit.")
        }
        guard theorem.contains(":") else {
            throw AIError("The model's theorem states no proposition.")
        }
        var proof = try field("proof")
        if !proof.isEmpty, !proof.hasPrefix(":=") { proof = ":= " + proof }
        let timeoutText = try field("timeout_seconds")
        let timeout = Int(timeoutText) ?? defaultTimeout
        let draft = ChallengeDraft(
            goal: try field("goal"),
            statement: try field("statement"),
            theorem: theorem,
            preamble: try field("preamble"),
            proof: proof.isEmpty ? nil : proof,
            timeoutSeconds: min(max(timeout, timeoutRange.lowerBound), timeoutRange.upperBound),
            notes: try field("notes")
        )
        guard !draft.statement.isEmpty else { throw AIError("The model's draft has an empty statement.") }
        return draft
    }

    /// What is wrong with a draft before anything is run: a screened token
    /// in the theorem or the preamble, which the verifier would never see
    /// (it screens proofs) and which would make the challenge worthless. Sent
    /// back to the model as problems, the way failed tests are.
    static func problems(in draft: ChallengeDraft) -> [String] {
        LeanScreen.hits(in: draft.theorem).map { "The theorem \($0); the verifier refuses that token everywhere." }
            + LeanScreen.hits(in: draft.preamble).map { "The preamble \($0); a hole or an assumption there would pay for nothing." }
    }
}

/// A request from the reader, in the shape `ui/lib/draft.ts` sends it.
enum PageRequest: Equatable {
    case draftChallenge(brief: String)

    static func parse(_ body: Any) -> Result<PageRequest, AIError> {
        guard let object = body as? [String: Any], let kind = object["kind"] as? String else {
            return .failure(AIError("The page sent something this app does not read."))
        }
        guard kind == "draft-challenge" else {
            return .failure(AIError("This app does not know the request \(kind)."))
        }
        guard let brief = (object["brief"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines),
              ChallengeWriter.isDraftable(brief)
        else {
            return .failure(AIError("A description is between \(ChallengeWriter.briefLength.lowerBound) and \(ChallengeWriter.briefLength.upperBound) characters."))
        }
        return .success(.draftChallenge(brief: brief))
    }
}

/// A draft turned into files a node can post: the objective, which carries
/// the theorem and preamble itself, and the Lean file beside it for a person
/// to open.
struct BuiltChallenge {
    /// SHA-256 of the preamble and theorem: what names the folder, so a
    /// redraft never overwrites a challenge already posted.
    let theoremHash: String
    let objectiveFile: URL
    /// `Challenge.lean`: the preamble and theorem with a hole, as a solver
    /// would start from it. Not pinned -- the objective holds the text.
    let leanFile: URL
    let directory: URL
}

enum ChallengeBuilder {
    /// What a solver submits: the proof text, and nothing else.
    static let artifactSchema: [String: Any] = [
        "type": "object",
        "properties": [
            "proof": [
                "type": "string",
                "description": "Lean 4 proof text appended to the pinned theorem, starting with :=",
            ],
        ],
        "required": ["proof"],
        "example": ["proof": ":= by decide"],
    ]

    static func build(_ draft: ChallengeDraft, reward: UInt64, funder: String,
                      root: URL, now: Date = Date()) throws -> BuiltChallenge {
        let theorem = draft.theorem.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !theorem.isEmpty else { throw AIError("The draft has no theorem.") }
        let hash = GuiTasks.sha256(Data("\(draft.preamble)\n\(theorem)\n".utf8))
        let folder = "challenges/\(slug(draft.goal))-\(hash.prefix(8))"
        let directory = root.appendingPathComponent(folder, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let leanFile = directory.appendingPathComponent("Challenge.lean")
        try Data(draft.source(proof: ChallengeDraft.hole).utf8).write(to: leanFile, options: .atomic)

        let verifier: [String: Any] = [
            "kind": "lean",
            "statement": theorem,
            "preamble": draft.preamble,
            "timeout_seconds": min(max(draft.timeoutSeconds, ChallengeWriter.timeoutRange.lowerBound),
                                   ChallengeWriter.timeoutRange.upperBound),
        ]
        let objective: [String: Any] = [
            "goal": draft.goal.isEmpty ? "GOAL-\(slug(draft.statement))" : draft.goal,
            "statement": draft.statement,
            "reward": reward,
            "funder": funder,
            "created_at": timestamp(now),
            "verifier": verifier,
            "artifact_schema": artifactSchema,
        ]
        let data = try JSONSerialization.data(withJSONObject: objective, options: [.prettyPrinted, .sortedKeys])
        let file = directory.appendingPathComponent("objective.json")
        try data.write(to: file, options: .atomic)
        return BuiltChallenge(theoremHash: hash, objectiveFile: file, leanFile: leanFile, directory: directory)
    }

    /// RFC 3339 with an explicit offset, the shape the crate writes itself.
    static func timestamp(_ date: Date) -> String {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        f.dateFormat = "yyyy-MM-dd'T'HH:mm:ss'+00:00'"
        return f.string(from: date)
    }

    /// Lowercase words and hyphens, at most six words, never empty.
    static func slug(_ text: String) -> String {
        var s = text.lowercased()
        if s.hasPrefix("goal-") { s.removeFirst(5) }
        let words = s.split { !($0.isASCII && ($0.isLetter || $0.isNumber)) }.prefix(6)
        let joined = words.joined(separator: "-")
        return joined.isEmpty ? "challenge" : joined
    }

    static func jsonObject(_ text: String, what: String) throws -> [String: Any] {
        guard let data = text.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { throw AIError("\(what) is not a JSON object.") }
        return object
    }

    /// Fractional numbers are refused anywhere in a record: `canonical::Value`
    /// has no float. Caught here, with the value, rather than as a schema
    /// refusal from `cairn post`.
    static func requireIntegers(_ value: Any, what: String) throws {
        switch value {
        case let dict as [String: Any]:
            for v in dict.values { try requireIntegers(v, what: what) }
        case let list as [Any]:
            for v in list { try requireIntegers(v, what: what) }
        // A JSON true or false arrives as 1 or 0, which passes.
        case let number as NSNumber:
            let d = number.doubleValue
            if !d.isFinite || d.rounded() != d {
                throw AIError("\(what) contains the fractional number \(number); cairn allows whole numbers only.")
            }
        default:
            break
        }
    }
}

/// The theorem tested before anything is posted, through the node's own
/// verifier -- the same jail, toolchain and verdict rules settlement uses --
/// rather than a Lean harness of this app's that could disagree with it.
///
/// Three checks, in the order the verifier itself would meet them:
///
/// 1. **The hole is rejected.** `:= by sorry` must come back `reject` from the
///    verifier's screen. Needs no toolchain, so it runs on every Mac.
/// 2. **The theorem compiles on its own.** The preamble and theorem with the
///    hole, compiled by the Lean on this Mac. The node cannot make this check
///    for us (its screen refuses the hole before Lean runs), and a theorem
///    that does not elaborate is a challenge nobody can ever win.
/// 3. **The model's proof, if it wrote one, is accepted** by the node's
///    verifier. Without a toolchain the node answers `unavailable`, which is
///    reported as exactly that.
///
/// No command runs a verifier for an objective that is not in a log, so the
/// objective goes into a throwaway log first and `propose --dry-run` runs
/// against that. The real log is never touched.
enum ChallengeTest {
    enum Verdict: Equatable {
        case accept(String)
        case reject(String)
        /// The verifier could not run: no toolchain, a timeout, a crash.
        case unavailable(String)
        /// The node refused the objective, or the answer, before any check.
        case refused(String)

        var accepted: Bool { if case .accept = self { return true }; return false }
        var rejected: Bool { if case .reject = self { return true }; return false }
    }

    /// Whether the theorem itself compiles, with a hole for its proof.
    enum Statement: Equatable {
        /// It does; the detail names the Lean that said so.
        case elaborates(String)
        /// Lean's first error lines.
        case broken(String)
        /// Not checked, and why: no toolchain here, or it took too long.
        case untested(String)

        var ok: Bool { if case .elaborates = self { return true }; return false }
    }

    /// Which check is running, for the sheet's checklist.
    enum Step: Equatable, Sendable { case posting, hole, statement, proof }

    struct Outcome: Equatable {
        var hole: Verdict
        var statement: Statement
        var proof: Verdict?

        /// Good enough to post: the hole rejected, the theorem compiling, and
        /// the model's proof, when there is one, accepted by the kernel.
        var ok: Bool { hole.rejected && statement.ok && (proof?.accepted ?? true) }

        /// What to tell the model when asking it to fix the draft. A missing
        /// toolchain is not the model's problem and is not sent.
        var problems: [String] {
            var out: [String] = []
            if !hole.rejected {
                out.append("The verifier did not reject a proof that was only a hole: \(Self.describe(hole))")
            }
            if case .broken(let detail) = statement {
                out.append("The preamble and theorem do not compile on their own. Lean said:\n\(detail)")
            }
            if let proof, case .reject(let detail) = proof {
                out.append("The kernel rejected the proof you wrote: \(detail)")
            }
            return out
        }

        static func describe(_ v: Verdict) -> String {
            switch v {
            case .accept(let d): return "accepted (\(d))"
            case .reject(let d): return "rejected (\(d))"
            case .unavailable(let d): return "the verifier could not run: \(d)"
            case .refused(let d): return "refused before checking: \(d)"
            }
        }
    }

    /// Off the main thread: the kernel can take a while. `progress` is
    /// called off it too, before each step.
    static func run(_ built: BuiltChallenge, draft: ChallengeDraft, binary: URL, root: URL,
                    environment: [String: String],
                    progress: @escaping @Sendable (Step) -> Void = { _ in }) async throws -> Outcome {
        try await Task.detached(priority: .userInitiated) {
            let scratch = FileManager.default.temporaryDirectory
                .appendingPathComponent("cairn-challenge-\(UUID().uuidString)", isDirectory: true)
            try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: scratch) }
            // A key file that does not exist keeps the throwaway log plaintext
            // and away from this person's real at-rest key.
            let global = [
                "--log", scratch.appendingPathComponent("scratch.jsonl").path,
                "--root", root.path,
                "--key-file", scratch.appendingPathComponent("no-key").path,
            ]
            progress(.posting)
            let posted = run(binary, global + ["post", built.objectiveFile.path], in: scratch, environment: environment)
            guard posted.status == 0 else {
                let why = posted.err.isEmpty ? "cairn post exited \(posted.status)" : posted.err
                return Outcome(hole: .refused(why), statement: .untested("the objective was refused"), proof: nil)
            }
            func verdict(_ proof: String, named name: String, timeout: TimeInterval) throws -> Verdict {
                let file = scratch.appendingPathComponent("\(name).json")
                try JSONSerialization.data(withJSONObject: ["proof": proof]).write(to: file)
                let r = run(binary, global + ["propose", built.objectiveFile.path, "--artifact", file.path, "--dry-run"],
                            in: scratch, environment: environment, timeout: timeout)
                if r.status == Ran.timedOut {
                    return .unavailable("cairn propose did not finish within \(Int(timeout)) seconds")
                }
                return parse(r.out, err: r.err, artifact: file.path)
            }
            progress(.hole)
            let hole = try verdict(ChallengeDraft.hole, named: "hole", timeout: 60)
            progress(.statement)
            let statement = compile(draft, cairn: binary, in: scratch, environment: environment)
            var proof: Verdict?
            if let text = draft.proof {
                progress(.proof)
                // The verifier's own bound, plus room for the jail and the control run it makes first.
                proof = try verdict(text, named: "proof", timeout: TimeInterval(draft.timeoutSeconds * 2 + 30))
            }
            return Outcome(hole: hole, statement: statement, proof: proof)
        }.value
    }

    /// The preamble and theorem with the hole, compiled by the Lean this Mac
    /// gives the node, inside the node's own jail (`cairn lean-compile`).
    ///
    /// This runs before anyone has read the draft, on text a language model
    /// wrote, and Lean elaboration runs code: `#eval` in a preamble is a
    /// program with this person's files, keys and network. So it is compiled
    /// where a submitter's proof would be -- no network, scratch-only
    /// writes, a scrubbed environment -- and Lean's own words come back for
    /// the redraft.
    static func compile(_ draft: ChallengeDraft, cairn: URL, in scratch: URL,
                        environment: [String: String]) -> Statement {
        let (toolchain, problem) = Toolchains.lean(environment: environment)
        guard let toolchain else {
            return .untested(problem ?? "No Lean toolchain was found on this Mac.")
        }
        let file = scratch.appendingPathComponent("Statement.lean")
        do {
            try Data(draft.source(proof: ChallengeDraft.hole).utf8).write(to: file)
        } catch {
            return .untested(error.localizedDescription)
        }
        let timeout = TimeInterval(max(60, draft.timeoutSeconds))
        let r = run(cairn, ["lean-compile", file.path, "--timeout", String(Int(timeout))],
                    in: scratch, environment: environment, timeout: timeout + 30)
        if r.status == Ran.timedOut {
            return .untested("Lean took longer than \(Int(timeout)) seconds on the theorem alone.")
        }
        switch r.status {
        case 0:
            return .elaborates(toolchain.version ?? toolchain.binary.path)
        case 1:
            let lines = r.out
                .split(separator: "\n")
                .map(String.init)
                .filter { !$0.isEmpty && !$0.contains("declaration uses 'sorry'") }
            return .broken(lines.prefix(8).joined(separator: "\n"))
        default:
            // 3: Lean could not run in the jail; 2: a cairn too old to have
            // the command. Neither is a fact about the theorem.
            let why = r.err.trimmingCharacters(in: .whitespacesAndNewlines)
            return .untested(why.isEmpty ? "cairn lean-compile exited \(r.status)" : why)
        }
    }

    /// `propose` prints one line per artifact, `  <path>: <verdict>  (detail)`
    /// (accept prints no detail), and anything it refused on stderr.
    static func parse(_ out: String, err: String, artifact: String) -> Verdict {
        let marker = "\(artifact): "
        guard let line = out.split(separator: "\n").first(where: { $0.contains(marker) }),
              let range = line.range(of: marker)
        else {
            let reason = err.trimmingCharacters(in: .whitespacesAndNewlines)
            return .refused(reason.isEmpty ? "cairn propose printed no verdict" : reason)
        }
        let rest = line[range.upperBound...].trimmingCharacters(in: .whitespaces)
        let word = rest.prefix { !$0.isWhitespace }
        var detail = rest.dropFirst(word.count).trimmingCharacters(in: .whitespaces)
        if detail.hasPrefix("("), detail.hasSuffix(")") { detail = String(detail.dropFirst().dropLast()) }
        switch word {
        case "accept": return .accept(detail.isEmpty ? "accepted" : detail)
        case "reject": return .reject(detail)
        case "unavailable": return .unavailable(detail)
        default: return .refused("\(word): \(detail)")
        }
    }

    struct Ran {
        /// The status a run that outlived its deadline reports.
        static let timedOut: Int32 = -2
        var status: Int32
        var out: String
        var err: String
    }

    /// A box the watchdog can mark from another queue.
    private final class Flag: @unchecked Sendable {
        var raised = false
    }

    static func run(_ binary: URL, _ args: [String], in directory: URL, environment: [String: String],
                    timeout: TimeInterval? = nil) -> Ran {
        let p = Process()
        p.executableURL = binary
        p.arguments = args
        p.currentDirectoryURL = directory
        p.environment = environment
        // stdout to a file and stderr to a pipe, so neither can fill while
        // this waits on the other: a checker's prints go to stderr, and a
        // full pipe would stall the process being waited for.
        let outFile = directory.appendingPathComponent("\(UUID().uuidString).out")
        guard FileManager.default.createFile(atPath: outFile.path, contents: nil),
              let out = try? FileHandle(forWritingTo: outFile)
        else { return Ran(status: -1, out: "", err: "could not create \(outFile.path)") }
        defer { try? FileManager.default.removeItem(at: outFile) }
        let err = Pipe()
        p.standardOutput = out
        p.standardError = err
        p.standardInput = FileHandle.nullDevice
        do { try p.run() } catch { return Ran(status: -1, out: "", err: error.localizedDescription) }
        let expired = Flag()
        var watchdog: DispatchWorkItem?
        if let timeout {
            let item = DispatchWorkItem {
                if p.isRunning {
                    expired.raised = true
                    p.terminate()
                }
            }
            watchdog = item
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout, execute: item)
        }
        let errData = err.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        watchdog?.cancel()
        try? out.close()
        let outData = (try? Data(contentsOf: outFile)) ?? Data()
        return Ran(status: expired.raised ? Ran.timedOut : p.terminationStatus,
                   out: String(decoding: outData, as: UTF8.self),
                   err: String(decoding: errData, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines))
    }
}
