// swift-tools-version:5.9
// The cairn reader for iOS (and a macOS window of the same app). A Swift
// package rather than an Xcode-only project so `swift test` on CI can compile
// the decoder and the chain check without a simulator — those are the parts
// that must agree with the website, and a project that only builds under
// xcodebuild would hide a drift until somebody next opened it on a Mac.
//
// The iOS .app itself is Cairn.xcodeproj, which links this package. The
// executable target here is the same SwiftUI scene running as a macOS window,
// so a compile that fails in the views fails this package too.
import PackageDescription

let package = Package(
    name: "Cairn",
    platforms: [
        .iOS(.v17),
        .macOS(.v14),
    ],
    products: [
        .library(name: "CairnKit", targets: ["CairnKit"]),
        .library(name: "CairnUI", targets: ["CairnUI"]),
        .executable(name: "Cairn", targets: ["Cairn"]),
    ],
    targets: [
        .target(
            name: "CairnKit",
            resources: [.copy("Resources/snapshot.json")]
        ),
        .target(
            name: "CairnUI",
            dependencies: ["CairnKit"]
        ),
        .executableTarget(
            name: "Cairn",
            dependencies: ["CairnUI"],
            swiftSettings: [.unsafeFlags(["-parse-as-library"])]
        ),
        .testTarget(
            name: "CairnKitTests",
            dependencies: ["CairnKit"]
        ),
    ]
)
