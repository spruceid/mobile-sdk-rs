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
        .binaryTarget(name: "RustFramework", url: "https://github.com/spruceid/wallet-sdk-rs/releases/download/0.0.19/RustFramework.xcframework.zip", checksum: "64fcf98d847658027741bec576929807a4bfdf883cace0f9b0de226eaebfb62e"),
        .target(
            name: "SpruceIDWalletSdkRs",
            dependencies: [
                .target(name: "RustFramework")
            ],
            path: "./WalletSdkRs/Sources/WalletSdkRs"
        )
    ]
)
