import CryptoKit
import Foundation

/// A curated objective this app can post in one click. The same tasks as
/// Cairn Autoresearcher's; `objectives` are repository-relative paths.
struct GuiTask: Identifiable, Equatable {
    var id: String
    var title: String
    var detail: String
    var objectives: [String]
    var docPath: String?
}

enum GuiTasks {
    /// The digest is the posted objective's identity, not a keyword taken
    /// from its untrusted statement. Only this exact objective gets the
    /// bundled search program.
    static let bundledOrbitObjective = "sha256:223a649828de7d0f031a28383b444d29e0481a54a2a26b6b45501ec9ab7f0d44"

    static func bundledWork(for objective: String, python: URL?, count: Int) -> (solver: String, arguments: [String])? {
        guard objective == bundledOrbitObjective, (1...16).contains(count),
              let library, let python, FileManager.default.isExecutableFile(atPath: python.path)
        else { return nil }
        let root = library.appendingPathComponent("examples/certicom-ecdlp")
        let script = root.appendingPathComponent("tools/orbit_solver.py")
        let walker = root.appendingPathComponent("tools/orbit_dp.py")
        let job = root.appendingPathComponent("jobs/ecc2k-23.json")
        guard [script, walker, job].allSatisfy({ FileManager.default.fileExists(atPath: $0.path) }) else { return nil }
        return (python.path, [script.path, "--job", job.path, "--count", String(count)])
    }

    static let all: [GuiTask] = [
        GuiTask(
            id: "ecc2k130-orbit",
            title: "ECC2K-130 — paid orbits",
            detail: """
            Pays for each distinguished orbit contributed to the shared search for \
            Certicom's ECC2K-130 key. Work it with a GPU client and submit batches; \
            uploading campaign points to S3 needs AWS keys in Node → Secrets….
            """,
            objectives: ["examples/certicom-ecdlp/objective-ecc2k130-orbit-batch.json"],
            docPath: "examples/certicom-ecdlp/ECC2K130-CAMPAIGN.md"
        ),
        GuiTask(
            id: "ecc2k130-frontier",
            title: "ECC2K-130 — the key itself",
            detail: """
            The whole discrete log for the same challenge, open since 1997. Not \
            expected to settle soon; the orbit task above is what pays along the way.
            """,
            objectives: ["examples/certicom-ecdlp/objective-ecc2k130.json"],
            docPath: "examples/certicom-ecdlp/README.md"
        ),
        GuiTask(
            id: "ecc2k23-orbit-demo",
            title: "ECC2K-23 — small practice run",
            detail: """
            A 21-bit twin of the orbit task that a laptop solves in seconds: the \
            quickest way to watch a bounty go from posted to settled.
            """,
            objectives: ["examples/certicom-ecdlp/objective-ecc2k-23-orbit-batch.json"],
            docPath: "examples/certicom-ecdlp/README.md"
        ),
    ]

    /// Where the task files are read from: the copy inside this app, which
    /// `build.sh` makes from `examples/` under the same repository-relative
    /// paths. `CAIRN_REPO=<checkout>` at launch reads a checkout instead, so
    /// an edited example can be tried without rebuilding the app.
    ///
    /// The app used to read *only* a checkout, and asked for one in the
    /// sheet. Someone who installed the .dmg has no checkout, so the one
    /// sheet meant to make posting easy opened on a folder picker and a red
    /// "missing" line.
    static var library: URL? {
        if let repo = ProcessInfo.processInfo.environment["CAIRN_REPO"], !repo.isEmpty {
            return URL(fileURLWithPath: repo, isDirectory: true)
        }
        return Bundle.main.resourceURL?.appendingPathComponent("Tasks", isDirectory: true)
    }

    static func isAvailable(_ task: GuiTask) -> Bool {
        guard let library else { return false }
        return task.objectives.allSatisfy {
            FileManager.default.fileExists(atPath: library.appendingPathComponent($0).path)
        }
    }

    /// The task's documentation, as a file in the same library as its
    /// objectives: build.sh copies each `docPath` into the app, and a checkout
    /// has it already. Nil when the library lacks it. This used to be a link
    /// into GitHub's web UI at the release's tag; the app opens nothing there
    /// now, and what it shows is the copy it shipped with.
    static func docURL(_ path: String) -> URL? {
        guard let library else { return nil }
        let url = library.appendingPathComponent(path)
        return FileManager.default.fileExists(atPath: url.path) ? url : nil
    }

    /// One line on what the task pays, read from its own objective rather
    /// than written twice.
    static func payout(_ task: GuiTask) -> String? {
        guard let library, let first = task.objectives.first,
              let data = try? Data(contentsOf: library.appendingPathComponent(first)),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let reward = (json["reward"] as? NSNumber)?.int64Value
        else { return nil }
        let total = reward.formatted()
        if let piece = json["piecework"] as? [String: Any],
           let price = (piece["unit_price"] as? NSNumber)?.int64Value {
            return "\(price.formatted()) units per accepted item, up to \(total) in all"
        }
        return "\(total) units to the first accepted answer"
    }

    /// Put each file an objective pins into the node's root, at the path the
    /// pin names, after checking it hashes to the pin.
    ///
    /// The node runs with `--root` set to its data folder, and an objective
    /// pins its checker by a path relative to that root. Posting the JSON
    /// alone admits the objective, but the node then has no checker to run:
    /// every claim against it comes back `unavailable` until some peer serves
    /// the code. Staged here first, the checker is found when `cairn post`
    /// admits the objective, which copies it into the node's content-addressed
    /// store (`.cairn/blobs`), from where it runs and is served to peers.
    static func stage(objective relative: String, from library: URL, into root: URL) throws {
        let file = library.appendingPathComponent(relative)
        let data = try Data(contentsOf: file)
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let verifier = json["verifier"] as? [String: Any]
        else { throw TaskError("\(relative) is not an objective.") }

        for (pathKey, hashKey) in [("checker", "checker_sha256"), ("evaluator", "evaluator_sha256")] {
            guard let pinned = verifier[pathKey] as? String,
                  let declared = (verifier[hashKey] as? String)?.lowercased() else { continue }
            // The pin is a path inside the root. One that leaves it would be
            // refused by the node anyway; refusing here keeps this function
            // from writing outside the data folder on the way.
            let parts = pinned.split(separator: "/")
            guard !pinned.hasPrefix("/"), !parts.isEmpty, !parts.contains(".."), !parts.contains(".") else {
                throw TaskError("\(relative) pins \(pinned), which is not a path inside the node's folder.")
            }
            let source = library.appendingPathComponent(pinned)
            guard let bytes = try? Data(contentsOf: source) else {
                throw TaskError("This build of Cairn is missing \(pinned), which \(relative) needs.")
            }
            guard sha256(bytes) == declared else {
                throw TaskError("\(pinned) does not match the SHA-256 that \(relative) pins, so the node would refuse it.")
            }
            let destination = root.appendingPathComponent(pinned)
            if let existing = try? Data(contentsOf: destination), sha256(existing) == declared { continue }
            try FileManager.default.createDirectory(
                at: destination.deletingLastPathComponent(), withIntermediateDirectories: true)
            try bytes.write(to: destination, options: .atomic)
        }
    }

    static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}

struct TaskError: LocalizedError {
    let message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}
