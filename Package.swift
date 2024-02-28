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
        .binaryTarget(name: "RustFramework", url: "https://github.com/spruceid/wallet-sdk-rs/releases/download/0.0.7/RustFramework.xcframework.zip", checksum: "77861db98e8c4de6f6bb64eef3cb058a6887939a4d72e4012e011c552a7c9d68"),
        .target(
            name: "WalletSdkRs",
            dependencies: [
                .target(name: "RustFramework")
            ],
            path: "./WalletSdkRs/Sources/WalletSdkRs"
        )
    ]
)
