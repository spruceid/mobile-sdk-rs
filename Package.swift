// swift-tools-version:5.5
// The swift-tools-version declares the minimum version of Swift required to build this package.
// Swift Package: SpruceIDMobileSdkRs

import PackageDescription;

let package = Package(
    name: "SpruceIDMobileSdkRs",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15)
    ],
    products: [
        .library(
            name: "SpruceIDMobileSdkRs",
            targets: ["SpruceIDMobileSdkRs"]
        )
    ],
    dependencies: [ ],
    targets: [
        .binaryTarget(name: "RustFramework", url: "https://github.com/spruceid/mobile-sdk-rs/releases/download/0.0.28/RustFramework.xcframework.zip", checksum: "a783beb8c08aa4c3153aaf84746d5c0c77e234ebd121f10b8aae022e9ad63e52"),
        // .binaryTarget(name: "RustFramework", url: "https://github.com/spruceid/mobile-sdk-rs/releases/download/0.0.28/RustFramework.xcframework.zip", checksum: "a783beb8c08aa4c3153aaf84746d5c0c77e234ebd121f10b8aae022e9ad63e52"),
        .target(
            name: "SpruceIDMobileSdkRs",
            dependencies: [
                .target(name: "RustFramework")
            ],
            path: "./MobileSdkRs/Sources/MobileSdkRs"
        )
    ]
)
