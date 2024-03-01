# Wallet SDK Uniffi Bindings

## Structure of the Project

```
.               // The Rust crate is at the root
│
├── kotlin      // Contains the Android library project (without the generated
│               // source or dyanmic libraries, these are present in the
│               // published package associated with this repo)
│
├── WalletSdkRs // Contains the iOS library, with all the generated source files
│               // and dylibs, as Git is the package manager of Swift
│
├── tests       // Contains cargo tests for Kotlin and Swift for the generated
│               // libraries. These tests act as sanity checks to ensure the
│               // generated libraries will be usable, and are not meant to be
│               // full-fledged functional tests.
```

## Release

Use the [`release` Github Action](https://github.com/spruceid/wallet-sdk-rs/actions/workflows/release.yml)
which is a manually triggered action.

## Build

### Kotlin

```bash
cd kotlin
./gradlew build
```

### Swift

```bash
cargo swift package -p ios -n WalletSdkRs
```
> You will need `cargo-swift` which you can install with `cargo install cargo-swift`.
