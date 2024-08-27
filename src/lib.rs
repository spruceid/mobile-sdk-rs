uniffi::setup_scaffolding!();

pub mod common;
pub mod credentials_callback;
pub mod key_manager;
pub mod local_store;
pub mod mdl;
pub mod storage_manager;
pub mod vdc_collection;
pub mod w3c_vc_barcodes;

pub use common::*;
pub use mdl::*;
