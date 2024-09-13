{
  description = "my project description";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  inputs.flake-utils.url = "github:numtide/flake-utils";
  inputs.rust-overlay.url = "github:oxalica/rust-overlay";
  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        #pkgs = nixpkgs.legacyPackages.${system};
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
          config = { 
            android_sdk.accept_license = true;
            allowUnfree = true;
          };
        };
        
        buildToolsVersion = "33.0.1";
        androidComposition = pkgs.androidenv.composeAndroidPackages {
          platformVersions = ["34"];
          includeSources = true;
          useGoogleAPIs = true;
          includeSystemImages = true;
          systemImageTypes = [ "google_apis_playstore" ];
          abiVersions = [ "x86_64" ];
          includeEmulator = true;
          emulatorVersion = "34.2.11";
          includeNDK = true;
          ndkVersion = "25.1.8937393";
          buildToolsVersions = [ "${buildToolsVersion}" ];
        };

        androidSdk = androidComposition.androidsdk;

        myDevTools = with pkgs; [
          #cargo
          cargo-ndk
          #rustc
          zulu17 # OpenJDKo
          jna
          kotlin
          lldb
          pkg-config
          openssl
          openssl.dev
          (rust-bin.stable.latest.default.override { 
            targets = [ 
              "aarch64-linux-android" 
              "armv7-linux-androideabi"
              "i686-linux-android" 
              "x86_64-linux-android"
            ];
            extensions = [ "rust-analyzer" "rustfmt" "rust-src" ];  
          })          
        ];

      in {
        devShells.default = pkgs.mkShell rec {
          buildInputs = [ myDevTools androidSdk ];
          ANDROID_SDK_ROOT = "${androidComposition.androidsdk}/libexec/android-sdk";
          ANDROID_NDK_ROOT = "${ANDROID_SDK_ROOT}/ndk-bundle";
          GRADLE_USER_HOME = "/home/ross/.gradle";
          GRADLE_OPTS = "-Dorg.gradle.project.android.aapt2FromMavenOverride=${ANDROID_SDK_ROOT}/build-tools/${buildToolsVersion}/aapt2";

          shellHook = ''
            cat <<EOF > kotlin/local.properties
            sdk.dir=$ANDROID_SDK_ROOT
            ndk.dir=$ANDROID_NDK_ROOT
            EOF
          '';

          # Make external Nix c libraries like zlib known to GHC, like
          # pkgs.haskell.lib.buildStackProject does
          # https://github.com/NixOS/nixpkgs/blob/d64780ea0e22b5f61cd6012a456869c702a72f20/pkgs/development/haskell-modules/generic-stack-builder.nix#L38
          LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath myDevTools;
        };
      });
}
