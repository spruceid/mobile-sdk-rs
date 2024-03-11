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
        // .binaryTarget(name: "RustFramework", url: "https://github.com/spruceid/wallet-sdk-rs/releases/download/0.0.24/RustFramework.xcframework.zip", checksum: "f8ca19a431e05bfc4275e47b0074895dc85ac7228e54c7fce8679e037e63be31"),
        .binaryTarget(name: "RustFramework", url: "https://github.com/spruceid/wallet-sdk-rs/releases/download/0.0.24/RustFramework.xcframework.zip", checksum: "f8ca19a431e05bfc4275e47b0074895dc85ac7228e54c7fce8679e037e63be31"),
        .target(
            name: "SpruceIDWalletSdkRs",
            dependencies: [
                .target(name: "RustFramework")
            ],
            path: "./WalletSdkRs/Sources/WalletSdkRs"
        )
    ]
)
