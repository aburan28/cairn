// swift-tools-version:5.9
// Cairn.app: a window onto a local node. A plain SwiftPM executable rather
// than an Xcode project, so it builds with the Command Line Tools alone;
// build.sh wraps the binary into an .app bundle, and the release's .dmg
// installs that bundle beside the `cairn` command it runs.
//
// The test target reaches the executable with `@testable import Cairn`. It
// covers what decides which bytes the updater installs as root -- version
// order, which asset is the installer, what it must hash to -- and that the
// shell and AppleScript it hands to root at least parse, since nothing else
// would notice until somebody's update failed.
import PackageDescription

let package = Package(
    name: "Cairn",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(
            name: "Cairn",
            path: "Sources/Cairn",
            swiftSettings: [.unsafeFlags(["-parse-as-library"])]
        ),
        .testTarget(
            name: "CairnTests",
            dependencies: ["Cairn"],
            path: "Tests/CairnTests"
        ),
    ]
)
