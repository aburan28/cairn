import Foundation

/// A challenge as a model drafted it from a person's description: the parts
/// of an objective that need judgment, before this app adds the parts that
/// need none (the pin, the timestamp, the record's shape).
struct ChallengeDraft: Equatable {
    var goal: String
    var statement: String
    /// A JSON Schema for the answer, as JSON text.
    var answerSchema: String
    var checker: String
    /// A correct answer, as JSON text, or nil when the model knows none --
    /// which is normal for a problem worth paying for.
    var passing: String?
    /// A plausible wrong answer, as JSON text.
    var failing: String
    var notes: String
}

enum ChallengeWriter {
    /// What the model is told. The checker it writes decides who gets paid,
    /// so most of this is about the ways a checker goes wrong in this
    /// network specifically: its source is public, it runs in a jail with no
    /// network, its input never holds a float, and an exception means
    /// "could not check", never "wrong".
    static let system = """
        You turn a plain-language description of a problem into a challenge for cairn, \
        a network that pays for verified answers. A solver submits an answer as a JSON \
        object; a Python checker you write decides, alone and automatically, whether it \
        is correct, and a correct answer is paid. Write for a stranger who will only \
        ever see the statement and the checker.

        Return one JSON object with exactly these fields:
        - goal: a short handle, "GOAL-" followed by two to six lowercase words joined \
        by hyphens, e.g. "GOAL-sorting-network-16".
        - statement: what a solver must find, in plain prose, precise enough to work \
        on: the exact property a correct answer has, and the exact shape of the answer \
        object, with field names and types. Do not describe the checker's code.
        - answer_schema: a JSON Schema for the answer object, as a JSON string: \
        "type": "object", "properties", "required", and an "example" holding one \
        well-formed (not necessarily correct) answer.
        - checker: the complete source of one Python 3 file that defines \
        check(artifact: dict) -> tuple[bool, str].
        - passing_example: a correct answer as a JSON string, so the checker can be \
        tested; or an empty string if you cannot produce one with certainty. Never \
        guess.
        - failing_example: a plausible but wrong answer as a JSON string, which the \
        checker must reject.
        - notes: one or two sentences for the person paying: assumptions you made, \
        a way the problem might be easier or harder than it sounds. Empty if none.

        Rules for the checker. It runs in a sandbox and the network pays on its verdict:
        - One self-contained file using only the Python standard library. No network, \
        no subprocesses, no files: it cannot read anything but its own source.
        - The answer arrives as a dict parsed from JSON and holds only integers, \
        strings, booleans, null, lists and dicts, never floating-point numbers. If a \
        quantity is fractional, ask for it as a decimal string or as an integer \
        numerator and denominator.
        - Return (True, detail) only when the answer verifiably has the property; \
        otherwise (False, reason). Check every field's presence, type and range first, \
        and return False for anything malformed. Never raise: an exception means the \
        checker crashed, which pays nobody and rejects nobody.
        - Re-derive correctness from the answer itself. Never compare it with a \
        hard-coded solution, secret or list of answers: the checker's source is \
        public, so anything in it is given away to every solver.
        - Checking must be far cheaper than solving and finish within a few seconds; \
        it is stopped after 60 seconds.
        - The detail string is public. Print nothing.

        If the description asks for something code cannot judge (an opinion, an essay, \
        "the best" with no measure), choose a precise criterion code can check, use it, \
        and say so in notes. No floating-point numbers anywhere: not in the schema, \
        not in the examples.
        """

    /// The reply's shape. Every field is a string so one schema works under
    /// the strictest structured-output rules (every object closed, every
    /// field required), and the JSON-valued fields are parsed afterwards.
    static let schema: [String: Any] = [
        "type": "object",
        "properties": [
            "goal": ["type": "string"],
            "statement": ["type": "string"],
            "answer_schema": ["type": "string"],
            "checker": ["type": "string"],
            "passing_example": ["type": "string"],
            "failing_example": ["type": "string"],
            "notes": ["type": "string"],
        ],
        "required": ["goal", "statement", "answer_schema", "checker", "passing_example", "failing_example", "notes"],
        "additionalProperties": false,
    ]

    /// The person's description, and on a redraft the previous attempt and
    /// what was wrong with it, as one message: a fresh request rather than a
    /// conversation, so nothing about earlier turns has to be replayed.
    static func request(describing description: String, previous: ChallengeDraft? = nil, problems: [String] = []) -> String {
        var text = "Problem to pose, as its funder described it:\n\n\(description.trimmingCharacters(in: .whitespacesAndNewlines))\n"
        if let previous {
            text += """

                An earlier draft of this challenge had problems. Fix them and return the \
                whole challenge again.

                Earlier checker:
                ```python
                \(previous.checker)
                ```
                Earlier passing example: \(previous.passing ?? "(none)")
                Earlier failing example: \(previous.failing)

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
        let checker = try field("checker")
        guard checker.contains("def check") else {
            throw AIError("The model's checker defines no check function.")
        }
        let passing = try field("passing_example")
        let draft = ChallengeDraft(
            goal: try field("goal"),
            statement: try field("statement"),
            answerSchema: try field("answer_schema"),
            checker: checker + "\n",
            passing: passing.isEmpty ? nil : passing,
            failing: try field("failing_example"),
            notes: try field("notes")
        )
        guard !draft.statement.isEmpty else { throw AIError("The model's draft has an empty statement.") }
        return draft
    }
}

/// A draft turned into files a node can post: the checker under the node's
/// root, pinned by its hash, and the objective beside it.
struct BuiltChallenge {
    /// The checker's path relative to the root, as the objective pins it.
    let checkerPath: String
    let checkerHash: String
    let objectiveFile: URL
    let directory: URL
}

enum ChallengeBuilder {
    /// A checker that has not finished in a minute is not a cheap check,
    /// and the default would let one hold a verifier for five.
    static let timeoutSeconds = 60

    static func build(_ draft: ChallengeDraft, reward: UInt64, funder: String,
                      root: URL, now: Date = Date()) throws -> BuiltChallenge {
        let schema = try jsonObject(draft.answerSchema, what: "The answer format")
        try requireIntegers(schema, what: "The answer format")

        let source = Data(draft.checker.utf8)
        let hash = GuiTasks.sha256(source)
        // The hash in the folder name, so a redraft never overwrites a
        // checker that an objective already posted still pins.
        let folder = "challenges/\(slug(draft.goal))-\(hash.prefix(8))"
        let checkerPath = "\(folder)/checker.py"
        let directory = root.appendingPathComponent(folder, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try source.write(to: root.appendingPathComponent(checkerPath), options: .atomic)

        let objective: [String: Any] = [
            "goal": draft.goal.isEmpty ? "GOAL-\(slug(draft.statement))" : draft.goal,
            "statement": draft.statement,
            "reward": reward,
            "funder": funder,
            "created_at": timestamp(now),
            "verifier": [
                "kind": "certificate",
                "checker": checkerPath,
                "checker_sha256": hash,
                "entrypoint": "check",
                "timeout_seconds": timeoutSeconds,
            ],
            "artifact_schema": schema,
        ]
        let data = try JSONSerialization.data(withJSONObject: objective, options: [.prettyPrinted, .sortedKeys])
        let file = directory.appendingPathComponent("objective.json")
        try data.write(to: file, options: .atomic)
        return BuiltChallenge(checkerPath: checkerPath, checkerHash: hash, objectiveFile: file, directory: directory)
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

    /// Fractional numbers are refused anywhere in a record, and in an
    /// answer: `canonical::Value` has no float. Caught here, with the value,
    /// rather than as a schema refusal from `cairn post`.
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

/// The checker run against both example answers before anything is posted,
/// through the node's own verifier -- the same jail, interpreter and
/// verdict rules settlement uses -- rather than a Python harness of this
/// app's that could disagree with it.
///
/// No command runs a pinned verifier for an objective that is not in a log,
/// so the objective goes into a throwaway log first and `propose --dry-run`
/// runs against that. The real log is never touched.
enum ChallengeTest {
    enum Verdict: Equatable {
        case accept(String)
        case reject(String)
        /// The checker crashed, timed out, or could not run.
        case unavailable(String)
        /// The node refused the objective, or the answer, before any check.
        case refused(String)

        var accepted: Bool { if case .accept = self { return true }; return false }
        var rejected: Bool { if case .reject = self { return true }; return false }
    }

    struct Outcome: Equatable {
        var passing: Verdict?
        var failing: Verdict

        /// Good enough to post: the wrong answer rejected, and the right one,
        /// when there is one, accepted.
        var ok: Bool { failing.rejected && (passing?.accepted ?? true) }

        /// What to tell the model when asking it to fix the draft.
        var problems: [String] {
            var out: [String] = []
            if let passing, !passing.accepted {
                out.append("The checker did not accept the passing example: \(Self.describe(passing))")
            }
            if !failing.rejected {
                out.append("The checker did not reject the failing example: \(Self.describe(failing))")
            }
            return out
        }

        static func describe(_ v: Verdict) -> String {
            switch v {
            case .accept(let d): return "accepted (\(d))"
            case .reject(let d): return "rejected (\(d))"
            case .unavailable(let d): return "the checker could not run: \(d)"
            case .refused(let d): return "refused before checking: \(d)"
            }
        }
    }

    /// Off the main thread: two checker runs can take a while.
    static func run(_ built: BuiltChallenge, draft: ChallengeDraft, binary: URL, root: URL,
                    environment: [String: String]) async throws -> Outcome {
        try await Task.detached(priority: .userInitiated) {
            let examples: [(String, String?)] = [("passing", draft.passing), ("failing", draft.failing)]
            for (label, text) in examples {
                guard let text else { continue }
                let answer = try ChallengeBuilder.jsonObject(text, what: "The \(label) example")
                try ChallengeBuilder.requireIntegers(answer, what: "The \(label) example")
            }
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
            let posted = run(binary, global + ["post", built.objectiveFile.path], in: scratch, environment: environment)
            guard posted.status == 0 else {
                let why = posted.err.isEmpty ? "cairn post exited \(posted.status)" : posted.err
                return Outcome(passing: nil, failing: .refused(why))
            }
            func verdict(_ text: String, named name: String) throws -> Verdict {
                let file = scratch.appendingPathComponent("\(name).json")
                try Data(text.utf8).write(to: file)
                let r = run(binary, global + ["propose", built.objectiveFile.path, "--artifact", file.path, "--dry-run"],
                            in: scratch, environment: environment)
                return parse(r.out, err: r.err, artifact: file.path)
            }
            let failing = try verdict(draft.failing, named: "failing")
            let passing = try draft.passing.map { try verdict($0, named: "passing") }
            return Outcome(passing: passing, failing: failing)
        }.value
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
        var status: Int32
        var out: String
        var err: String
    }

    static func run(_ binary: URL, _ args: [String], in directory: URL, environment: [String: String]) -> Ran {
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
        let errData = err.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        try? out.close()
        let outData = (try? Data(contentsOf: outFile)) ?? Data()
        return Ran(status: p.terminationStatus,
                   out: String(decoding: outData, as: UTF8.self),
                   err: String(decoding: errData, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines))
    }
}
