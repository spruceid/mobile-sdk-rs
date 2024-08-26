# Makefile

# Get the absolute path to the project root
PROJECT_ROOT := $(shell pwd)

# Variables
CARGO := cargo
GRADLEW := gradlew
UNIFFI_BINDGEN := uniffi-bindgen
KOTLIN_DIR := $(PROJECT_ROOT)/kotlin
KOTLIN_OUT_DIR := $(KOTLIN_DIR)/mobilesdkrs/src/main/java
SWIFT_OUT_DIR := $(PROJECT_ROOT)/MobileSdkRs

# Determine the operating system and set the appropriate library extension
ifeq ($(OS),Windows_NT)
    LIB_EXT := dll
    GRADLEW := $(GRADLEW).bat
else
    UNAME_S := $(shell uname -s)
    ifeq ($(UNAME_S),Linux)
        LIB_EXT := so
    endif
    ifeq ($(UNAME_S),Darwin)
        LIB_EXT := dylib
    endif
    GRADLEW := ./$(GRADLEW)
endif

LIB_NAME := libmobile_sdk_rs.$(LIB_EXT)

# Default target
all: build bindings package_kotlin package_swift test

# Build the Rust library
build:
	$(CARGO) build --release

# Generate Kotlin and Swift bindings
bindings: kotlin swift

# Generate Kotlin bindings
kotlin: build
	$(CARGO) run --features=uniffi/cli --bin $(UNIFFI_BINDGEN) generate \
		--library target/release/$(LIB_NAME) \
		--language kotlin \
		--out-dir $(KOTLIN_OUT_DIR)

# Generate Swift bindings
swift: build
	$(CARGO) run --features=uniffi/cli --bin $(UNIFFI_BINDGEN) generate \
		--library target/release/$(LIB_NAME) \
		--language swift \
		--out-dir $(SWIFT_OUT_DIR)

# Compile Kotlin code
compile_kotlin: kotlin
	cd $(KOTLIN_DIR) && $(GRADLEW) compileDebugKotlin

# Build Kotlin code
package_kotlin: kotlin
	cd $(KOTLIN_DIR) && $(GRADLEW) build

# Package Swift code
package_swift: swift
	$(CARGO) swift package -p ios -n MobileSdkRs

# Package the Swift and Kotlin code
package: package_kotlin package_swift

# Run tests
tests: test_swift test_kotlin

# Run Swift tests
test_swift: swift
	$(CARGO) test

# Run Kotlin tests
test_kotlin: compile_kotlin
	cd $(KOTLIN_DIR) && $(GRADLEW) connectedAndroidTest

# Clean build artifacts
clean:
	$(CARGO) clean
	cd $(KOTLIN_DIR) && $(GRADLEW) clean
	rm -rf $(SWIFT_OUT_DIR)/*.swift $(SWIFT_OUT_DIR)/*.h

.PHONY: all build bindings compile_kotlin package_swift test clean
