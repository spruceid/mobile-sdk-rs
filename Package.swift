// swift-tools-version:5.5
// The swift-tools-version declares the minimum version of Swift required to build this package.
// Swift Package: WalletSdkRs

import PackageDescription;

let package = Package(
    name: "SpruceIDWalletSdkRs",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15)
    ],
    products: [
        .library(
            name: "SpruceIDWalletSdkRs",
            targets: ["SpruceIDWalletSdkRs"]
        )
    ],
    dependencies: [ ],
    targets: [
        .binaryTarget(name: "RustFramework", url: "https://github.com/spruceid/wallet-sdk-rs/releases/download/0.0.12/RustFramework.xcframework.zip", checksum: "29905546cfe7eb1c0f9d898844b0d75a5fc22f4dde98d1019ffa8f668083c6b1"),
        .target(
            name: "SpruceIDWalletSdkRs",
            dependencies: [
                .target(name: "RustFramework")
            ],
            path: "./WalletSdkRs/Sources/WalletSdkRs"
        )
    ]
)
