// swift-tools-version:5.9
// The macOS launcher for the crypto autoresearcher. A plain SwiftPM
// executable rather than an Xcode project, so it builds with the Command
// Line Tools alone; build.sh wraps the binary into an .app bundle.
import PackageDescription

let package = Package(
    name: "CairnAutoresearcher",
    platforms: [.macOS(.v13)],
    dependencies: [.package(path: "../shared")],
    targets: [
        .executableTarget(
            name: "CairnAutoresearcher",
            dependencies: [.product(name: "CairnNodeKit", package: "shared"), .product(name: "CairnNodeUI", package: "shared")],
            path: "Sources/CairnAutoresearcher",
            swiftSettings: [.unsafeFlags(["-parse-as-library"])]
        )
    ]
)
