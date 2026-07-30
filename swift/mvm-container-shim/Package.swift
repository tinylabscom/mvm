// swift-tools-version: 6.2
import PackageDescription

// Dependency pin: apple/containerization 0.6.0. Package.resolved records
// the exact revision; bump both deliberately and rebuild before relying on
// a newer upstream API.
let package = Package(
    name: "mvm-container-shim",
    platforms: [.macOS(.v26)],
    dependencies: [
        .package(url: "https://github.com/apple/containerization.git", from: "0.6.0")
    ],
    targets: [
        .executableTarget(
            name: "mvm-container-shim",
            dependencies: [
                .product(name: "Containerization", package: "containerization")
            ]
        )
    ]
)
