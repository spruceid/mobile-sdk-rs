# Mobile SDK Uniffi Bindings

## Maturity Disclaimer

In its current version, Mobile SDK has not yet undergone a formal security audit
to desired levels of confidence for suitable use in production systems. This
implementation is currently suitable for exploratory work and experimentation
only. We welcome feedback on the usability, architecture, and security of this
implementation and are committed to a conducting a formal audit with a reputable
security firm before the v1.0 release.

## Structure of the Project

```
.               // The Rust crate is at the root
│
├── kotlin      // Contains the Android library project (without the generated
│               // source or dynamic libraries, these are present in the
│               // published package associated with this repo)
│
├── MobileSdkRs // Contains the iOS library, with all the generated source files
│               // and dylibs, as Git is the package manager of Swift
│
├── tests       // Contains cargo tests for Kotlin and Swift for the generated
│               // libraries. These tests act as sanity checks to ensure the
│               // generated libraries will be usable, and are not meant to be
│               // full-fledged functional tests.
```

## Release

Use the [`release` Github Action](https://github.com/spruceid/mobile-sdk-rs/actions/workflows/release.yml)
which is a manually triggered action.

## Build

### Kotlin

```bash
cd kotlin
./gradlew buildCargoNdkDebug
```

If you get this error:
```
> java.io.FileNotFoundException: .../local.properties (No such file or directory)
```

run:
```bash
touch local.properties
```

and try the build again.

### Swift

```bash
cargo swift package -p ios -n MobileSdkRs --release
```
> **⚠** If you need to call `verify_vcb_qrcode_against_mrz` or `verify_pdf417_barcode` in your iOS app, you **must** build with the `--release` flag to avoid runtime errors when executing these methods.

> You will need `cargo-swift` which you can install with `cargo install cargo-swift`.

## Test
In order to run the tests you'll need to [install the kotlin compiler](https://kotlinlang.org/docs/command-line.html) and download a copy of JNA

```
wget https://repo1.maven.org/maven2/net/java/dev/jna/jna/5.14.0/jna-5.14.0.jar
wget https://repo1.maven.org/maven2/org/jetbrains/kotlinx/kotlinx-coroutines-core-jvm/1.6.4/kotlinx-coroutines-core-jvm-1.6.4.jar
```

JNA will also need to explicitly be on your CLASSPATH.  Simply being in a directory
doesn't necessarily work.  Here is an example of how you might configure this
in your `.bashrc` file

```bash
export CLASSPATH="/path/to/jna-5.14.0.jar:/path/to/kotlinx-coroutines-core-jvm-1.6.4.jar:$CLASSPATH"
```
This lets you just run `cargo test` as normal.


Alternatively, if you don't like the addition to your environment you can
specify it on every invocation of cargo test:

```bash
CLASSPATH="/path/to/jna-5.14.0.jar:/path/to/kotlinx-coroutines-core-jvm-1.6.4.jar" cargo test
```
