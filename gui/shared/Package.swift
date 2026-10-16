// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "CairnNode",
    platforms: [.macOS(.v13), .iOS(.v17)],
    products: [
        .library(name: "CairnNodeKit", targets: ["CairnNodeKit"]),
        .library(name: "CairnNodeUI", targets: ["CairnNodeUI"]),
    ],
    targets: [
        .target(name: "CairnNodeKit"),
        .target(name: "CairnNodeUI", dependencies: ["CairnNodeKit"]),
        .testTarget(name: "CairnNodeKitTests", dependencies: ["CairnNodeKit"], resources: [.copy("Fixtures")]),
    ]
)
