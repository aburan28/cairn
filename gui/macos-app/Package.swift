// swift-tools-version:5.9
// Cairn.app: a window onto a local node. A plain SwiftPM executable rather
// than an Xcode project, so it builds with the Command Line Tools alone;
// build.sh wraps the binary into an .app bundle, and the release's .dmg
// installs that bundle beside the `cairn` command it runs.
import PackageDescription

let package = Package(
    name: "Cairn",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(
            name: "Cairn",
            path: "Sources/Cairn",
            swiftSettings: [.unsafeFlags(["-parse-as-library"])]
        )
    ]
)
