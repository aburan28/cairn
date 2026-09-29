import Foundation

/// Same curated tasks as Cairn Autoresearcher; paths are relative to a checkout root.
struct GuiTask: Identifiable, Equatable {
    var id: String
    var title: String
    var detail: String
    var paths: [String]
    var docPath: String?
}

enum GuiTasks {
    static let all: [GuiTask] = [
        GuiTask(
            id: "ecc2k130-orbit",
            title: "ECC2K-130 — paid orbits",
            detail: """
            Fund the piecework objective that pays for witnessed distinguished orbits on \
            Certicom's ECC2K-130 walk. Work it with your GPU client and cairn submit; \
            campaign DPs are a separate path (see examples/certicom-ecdlp/ECC2K130-CAMPAIGN.md).
            """,
            paths: ["examples/certicom-ecdlp/objective-ecc2k130-orbit-batch.json"],
            docPath: "examples/certicom-ecdlp/ECC2K130-CAMPAIGN.md"
        ),
        GuiTask(
            id: "ecc2k130-frontier",
            title: "ECC2K-130 — frontier (answer)",
            detail: """
            The full discrete-log objective for the same challenge. Not expected to settle; \
            orbit piecework pays on the batch objective above.
            """,
            paths: ["examples/certicom-ecdlp/objective-ecc2k130.json"],
            docPath: "examples/certicom-ecdlp/README.md"
        ),
        GuiTask(
            id: "ecc2k23-orbit-demo",
            title: "ECC2K-23 — orbit demo twin",
            detail: """
            21-bit twin for local testing. After posting, run ./scripts/orbit-demo.sh from the checkout.
            """,
            paths: ["examples/certicom-ecdlp/objective-ecc2k-23-orbit-batch.json"],
            docPath: "examples/certicom-ecdlp/README.md"
        ),
    ]
}
