// swift-tools-version: 6.3
import PackageDescription

let package = Package(
    name: "Harden",
    platforms: [.macOS(.v14)],
    dependencies: [
        .package(url: "https://github.com/sparkle-project/Sparkle", from: "2.0.0"),
    ],
    targets: [
        .executableTarget(
            name: "Harden",
            dependencies: ["Sparkle"],
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
