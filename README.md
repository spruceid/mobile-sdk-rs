# Wallet SDK Uniffi Bindings

## Structure of the Project

```
.               // The Rust crate is at the root
|
├── kotlin      // Contains the Android library project (without the generated
|               // source or dyanmic libraries, these are present in the
|               // published package associated with this repo)
|
└── WalletSdkRs // Contains the iOS library, with all the generated source files
                // and dylibs, as Git is the package manager of Swift
```

## Release

Use the [`release` Github Action](https://github.com/spruceid/wallet-sdk-rs/actions/workflows/release.yml)
which is a manually triggered action.
