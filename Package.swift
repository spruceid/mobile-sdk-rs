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
        .binaryTarget(name: "RustFramework", url: "https://github.com/spruceid/wallet-sdk-rs/releases/download/0.0.18/RustFramework.xcframework.zip", checksum: "c096e973085dfc1ac173cc0e5b13ead675feb55c10cde98521d8ef8bb75eb232"),
        .target(
            name: "SpruceIDWalletSdkRs",
            dependencies: [
                .target(name: "RustFramework")
            ],
            path: "./WalletSdkRs/Sources/WalletSdkRs"
        )
    ]
)
