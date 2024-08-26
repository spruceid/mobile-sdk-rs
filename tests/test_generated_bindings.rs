uniffi::build_foreign_language_testcases!(
    // Add Swift Binding Unit Tests
    "tests/bindings/test.swift",
    "tests/bindings/test_storage_manager.swift",
    "tests/bindings/test_key_manager.swift",
    "tests/bindings/test_wallet.swift",
    // NOTE: Kotlin tests are written in the
    // androidTest directory of the Android project.
    //
    // The `kotlinx` dependency does not seem to be
    // available in the `uniffi` testing environment,
    // but is available in the android test harness.
    //
    // See: https://developer.android.com/studio/test
    //
    // The following code is commented out to prevent
    // the tests from failing.
    // "tests/bindings/test.kts",
);
