// swift-tools-version:5.5
// The swift-tools-version declares the minimum version of Swift required to build this package.
// Swift Package: WalletSdkRs

import PackageDescription;

let package = Package(
    name: "WalletSdkRs",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15)
    ],
    products: [
        .library(
            name: "WalletSdkRs",
            targets: ["WalletSdkRs"]
        )
    ],
    dependencies: [ ],
    targets: [
        .binaryTarget(name: "RustFramework", path: "./WalletSdkRs/RustFramework.xcframework"),
        .target(
            name: "WalletSdkRs",
            dependencies: [
                .target(name: "RustFramework")
            ],
            path: "./WalletSdkRs/Sources/WalletSdkRs"
        )
    ]
)
