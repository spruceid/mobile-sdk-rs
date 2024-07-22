uniffi::setup_scaffolding!();

pub mod local_store;
pub mod mdl;
pub mod mdl_reader;
pub mod storage_manager;
pub mod vdc_collection;
pub mod w3c_vc_barcodes;

pub use mdl::*;
