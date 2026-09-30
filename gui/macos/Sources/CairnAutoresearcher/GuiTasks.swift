import Foundation

/// Curated work a person picks in **Tasks** instead of hunting through Catalog.
/// Paths are relative to the checkout root, same as [`CatalogItem`].
struct GuiTask: Identifiable, Equatable {
    var id: String
    var title: String
    var detail: String
    /// Objective JSON files this task turns on when selected.
    var paths: [String]
    /// Optional markdown in the checkout (shown in Finder).
    var docPath: String?
}

enum GuiTasks {
    static let all: [GuiTask] = [
        GuiTask(
            id: "ecc2k130-orbit",
            title: "ECC2K-130 — paid orbits",
            detail: """
            Post the piecework objective that pays for witnessed distinguished orbits on \
            Certicom's ECC2K-130 walk. Earn with orbit batches via the GPU client and \
            cairn submit; the campaign DP path (S3 / status site) is separate — see the \
            campaign note in examples/certicom-ecdlp.
            """,
            paths: ["examples/certicom-ecdlp/objective-ecc2k130-orbit-batch.json"],
            docPath: "examples/certicom-ecdlp/ECC2K130-CAMPAIGN.md"
        ),
        GuiTask(
            id: "ecc2k130-frontier",
            title: "ECC2K-130 — frontier (answer)",
            detail: """
            The full discrete-log objective for the same challenge. Posted so the network \
            carries the benchmark; it is not expected to settle. Search pay is on the \
            orbit-batch objective above.
            """,
            paths: ["examples/certicom-ecdlp/objective-ecc2k130.json"],
            docPath: "examples/certicom-ecdlp/README.md"
        ),
        GuiTask(
            id: "ecc2k23-orbit-demo",
            title: "ECC2K-23 — orbit demo twin",
            detail: """
            The 21-bit twin for local testing: same orbit checker shape as ECC2K-130. \
            Run ./scripts/orbit-demo.sh from the checkout after posting.
            """,
            paths: ["examples/certicom-ecdlp/objective-ecc2k-23-orbit-batch.json"],
            docPath: "examples/certicom-ecdlp/README.md"
        ),
    ]

    static func task(matching paths: Set<String>) -> GuiTask? {
        all.first { Set($0.paths) == paths }
    }

    static func task(id: String) -> GuiTask? {
        all.first { $0.id == id }
    }
}
