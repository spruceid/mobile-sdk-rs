#[uniffi::export]
fn hello_ffi() -> String {
    "Hello from Rust!".into()
}

uniffi::setup_scaffolding!();
