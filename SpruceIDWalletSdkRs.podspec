Pod::Spec.new do |spec|
  spec.name         = "SpruceIDWalletSdkRs"
  spec.version      = "0.0.13"
  spec.summary      = "Rust-generated Swift Wallet SDK."
  spec.description  = <<-DESC
                   Rust layer for the Swift Wallet SDK.
                   DESC
  spec.homepage     = "https://github.com/spruceid/wallet-sdk-rs"
  spec.license      = { :type => "MIT & Apache License, Version 2.0", :text => <<-LICENSE
                          Refer to LICENSE-MIT and LICENSE-APACHE in the repository.
                        LICENSE
                      }
  spec.author       = { "Spruce Systems, Inc." => "hello@spruceid.com" }
  spec.platform     = :ios

  spec.ios.deployment_target  = '13.0'

  spec.static_framework = true
  spec.source        = { :git => "https://spruceid/wallet-sdk-rs.git", :tag => "#{spec.version}" }
  spec.source_files  = "WalletSdkRs/Sources/WalletSdkRs/*.swift"
  spec.frameworks = 'Foundation'

  spec.dependency 'SpruceIDWalletSdkRsRustFramework', "#{spec.version}"
end
