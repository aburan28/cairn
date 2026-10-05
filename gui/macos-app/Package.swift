// swift-tools-version:5.9
// Cairn.app: a window onto a local node. A plain SwiftPM executable rather
// than an Xcode project, so it builds with the Command Line Tools alone;
// build.sh wraps the binary into an .app bundle, and the release's .dmg
// installs that bundle beside the `cairn` command it runs.
//
// Sparkle is the one dependency: Check for Updates… and the daily check
// (Sources/Cairn/Updates.swift). It is a prebuilt framework, so it costs no
// Xcode either; build.sh copies it into Contents/Frameworks, where the rpath
// below finds it.
//
// The test target reaches the executable with `@testable import Cairn`. It
// covers what decides the bytes a node is handed: which request goes to
// which provider, how a model's reply is read, the objective built from a
// draft and the pin inside it, and the verdicts read back from `cairn
// propose`. CI's gui-macos job runs it.
import PackageDescription

let package = Package(
    name: "Cairn",
    platforms: [.macOS(.v13)],
    dependencies: [
        // Exact, not `from:`: Sparkle ships inside the signed app and runs
        // the update installer with admin rights, so a new release of it is
        // a change to review, not something the next tag picks up unread.
        .package(url: "https://github.com/sparkle-project/Sparkle", exact: "2.10.0"),
    ],
    targets: [
        .executableTarget(
            name: "Cairn",
            dependencies: [.product(name: "Sparkle", package: "Sparkle")],
            path: "Sources/Cairn",
            swiftSettings: [.unsafeFlags(["-parse-as-library"])],
            linkerSettings: [
                .unsafeFlags(["-Xlinker", "-rpath", "-Xlinker", "@executable_path/../Frameworks"]),
            ]
        ),
        .testTarget(
            name: "CairnTests",
            dependencies: ["Cairn"],
            path: "Tests/CairnTests"
        ),
    ]
)
