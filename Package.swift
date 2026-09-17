// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "Trailfox",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "TrailfoxCore", targets: ["TrailfoxCore"]),
        .executable(name: "Trailfox", targets: ["TrailfoxApp"]),
        .executable(name: "trailfox-smoke", targets: ["TrailfoxSmoke"])
    ],
    targets: [
        .target(name: "TrailfoxCore"),
        .executableTarget(
            name: "TrailfoxApp",
            dependencies: ["TrailfoxCore"],
            path: "Sources/TrailfoxApp"
        ),
        .executableTarget(name: "TrailfoxSmoke", dependencies: ["TrailfoxCore"]),
        .testTarget(name: "TrailfoxCoreTests", dependencies: ["TrailfoxCore"])
    ]
)
