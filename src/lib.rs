uniffi::setup_scaffolding!();

pub mod common;
pub mod credential;
pub mod local_store;
pub mod mdl;
pub mod oid4vci;
pub mod storage_manager;
pub mod vdc_collection;
pub mod w3c_vc_barcodes;
// Verifier
pub mod verifier;

pub use common::*;
pub use mdl::reader::*;
pub use mdl::*;

use uniffi::deps::{anyhow, log};