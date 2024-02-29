Pod::Spec.new do |spec|
  spec.name         = "SpruceIDWalletSdkRsRustFramework"
  spec.version      = "0.0.6"
  spec.summary      = "Rust-generated Framework Swift Wallet SDK."
  spec.description  = <<-DESC
                   Rust layer framework for the Swift Wallet SDK.
                   DESC
  spec.homepage     = "https://github.com/spruceid/wallet-sdk-rs"
  spec.license      = "MIT OR Apache-2.0"
  spec.author       = { "Spruce Systems, Inc." => "hello@spruceid.com" }
  spec.platform     = :ios

  spec.ios.deployment_target  = '13.0'

  spec.static_framework = true
  spec.source = { :http => "https://github.com/spruceid/wallet-sdk-rs/releases/download/#{spec.version}/RustFramework.xcframework.zip" }
  spec.vendored_frameworks = 'WalletSdkRs/RustFramework.xcframework'
end
