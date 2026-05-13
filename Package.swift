// swift-tools-version: 6.3
import PackageDescription

let package = Package(
    name: "Harden",
    platforms: [.macOS(.v14)],
    targets: [
        .executableTarget(
            name: "Harden",
            path: "Harden",
            exclude: [],
            resources: [
                .process("Resources/Assets.xcassets"),
            ],
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        .testTarget(
            name: "HardenTests",
            dependencies: ["Harden"],
            path: "HardenTests"
        ),
    ]
)
