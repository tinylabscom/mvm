// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "MvmContainerBridge",
    platforms: [.macOS(.v26)],
    products: [
        .library(
            name: "MvmContainerBridge",
            type: .static,
            targets: ["MvmContainerBridge"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/containerization.git", from: "0.1.0"),
    ],
    targets: [
        .target(
            name: "MvmContainerBridge",
            dependencies: [
                .product(name: "Containerization", package: "containerization"),
            ],
            swiftSettings: [
                .interoperabilityMode(.C),
            ]
        ),
    ]
)
