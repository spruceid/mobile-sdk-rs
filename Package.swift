// swift-tools-version:5.5
// The swift-tools-version declares the minimum version of Swift required to build this package.
// Swift Package: SpruceIDMobileSdkRs

import PackageDescription;

let package = Package(
    name: "SpruceIDMobileSdkRs",
    platforms: [
        .iOS(.v14),
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
        .binaryTarget(name: "RustFramework", url: "https://github.com/spruceid/mobile-sdk-rs/releases/download/0.1.0/RustFramework.xcframework.zip", checksum: "aaf2e4f093fbf5f6e3a54d260ad7a450ab55a5c795feca33bbfa7c83402e0e86"),
        //.binaryTarget(name: "RustFramework", url: "https://github.com/spruceid/mobile-sdk-rs/releases/download/0.1.0/RustFramework.xcframework.zip", checksum: "aaf2e4f093fbf5f6e3a54d260ad7a450ab55a5c795feca33bbfa7c83402e0e86"),
        .target(
            name: "SpruceIDMobileSdkRs",
            dependencies: [
                .target(name: "RustFramework")
            ],
            path: "./MobileSdkRs/Sources/MobileSdkRs"
        )
    ]
)
