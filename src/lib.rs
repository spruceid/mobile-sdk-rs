uniffi::setup_scaffolding!();

pub mod common;
pub mod credentials_callback;
pub mod key_manager;
pub mod local_key_manager;
pub mod local_store;
pub mod mdl;
pub mod oid4vp;
pub mod storage_manager;
pub mod vdc_collection;
pub mod w3c_vc_barcodes;
pub mod wallet;

pub use common::*;
pub use key_manager::*;
pub use mdl::*;
pub use storage_manager::*;
pub use vdc_collection::*;
pub use wallet::*;
