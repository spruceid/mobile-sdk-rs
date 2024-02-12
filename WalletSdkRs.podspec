Pod::Spec.new do |spec|
  spec.name         = "WalletSdkRs"
  spec.version      = "0.0.6"
  spec.summary      = "Rust-generated Swift Wallet SDK."
  spec.description  = <<-DESC
                   Rust layer for the Swift Wallet SDK.
                   DESC
  spec.homepage     = "https://github.com/spruceid/wallet-sdk-rs"
  spec.license      = "MIT OR Apache-2.0"
  spec.author       = { "Spruce Systems, Inc." => "hello@spruceid.com" }
  spec.platform     = :ios

  spec.ios.deployment_target  = '13.0'

  spec.static_framework = true
  spec.source        = { :git => "https://spruceid/wallet-sdk-rs.git", :tag => "#{spec.version}" }
  spec.source_files  = "WalletSdkRs"

  spec.dependency 'WalletSdkRsRustFramework' "#{spec.version}"
end
