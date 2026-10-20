import Foundation

/// One curated catalogue, consumed by both native launchers. Objective bytes
/// remain in the bundled files; display copy never decides their identity.
public struct CuratedTask: Identifiable, Equatable, Sendable {
    public let id: String
    public let title: String
    public let detail: String
    public let objectives: [String]
    public let docPath: String?
    /// Solver package directories (`solver.json` and its files) published
    /// with the objectives, so a person can press Start on them without
    /// choosing a program. Repository-relative, like `objectives`.
    public let solvers: [String]
    public var paths: [String] { objectives }
    public init(id: String, title: String, detail: String, objectives: [String], docPath: String?,
                solvers: [String] = []) {
        self.id = id; self.title = title; self.detail = detail; self.objectives = objectives; self.docPath = docPath
        self.solvers = solvers
    }
}

public enum CuratedTasks {
    public static let all: [CuratedTask] = [
        CuratedTask(
            id: "ecc2k130-orbit",
            title: "ECC2K-130 — paid orbits",
            detail: """
            Pays for each distinguished orbit contributed to the shared search for \
            Certicom's ECC2K-130 key. Share this Mac… walks it on the CPU threads \
            you offer; a GPU client is faster, and uploading campaign points to S3 \
            needs AWS keys in Secrets.
            """,
            objectives: ["examples/certicom-ecdlp/objective-ecc2k130-orbit-batch.json"],
            docPath: "examples/certicom-ecdlp/ECC2K130-CAMPAIGN.md",
            solvers: ["examples/certicom-ecdlp/solvers/ecc2k130-orbit"]
        ),
        CuratedTask(
            id: "ecc2k130-frontier",
            title: "ECC2K-130 — the key itself",
            detail: """
            The whole discrete log for the same challenge, open since 1997. Not \
            expected to settle soon; the orbit task above is what pays along the way.
            """,
            objectives: ["examples/certicom-ecdlp/objective-ecc2k130.json"],
            docPath: "examples/certicom-ecdlp/README.md"
        ),
        CuratedTask(
            id: "ecc2k23-orbit-demo",
            title: "ECC2K-23 — small practice run",
            detail: """
            A 21-bit twin of the orbit task that a laptop solves in seconds: the \
            quickest way to watch a bounty go from posted to settled.
            """,
            objectives: ["examples/certicom-ecdlp/objective-ecc2k-23-orbit-batch.json"],
            docPath: "examples/certicom-ecdlp/README.md",
            solvers: ["examples/certicom-ecdlp/solvers/ecc2k-23-orbit"]
        ),
    ]

}
