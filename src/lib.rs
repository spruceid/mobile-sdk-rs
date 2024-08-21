uniffi::setup_scaffolding!();

pub mod common;
pub mod key_manager;
pub mod local_store;
pub mod mdl;
pub mod metadata_manager;
pub mod oid4vp;
pub mod storage_manager;
pub mod trust_manager;
pub mod vdc_collection;
pub mod wallet;

pub mod prelude {
    pub use crate::common::*;
    pub use crate::key_manager::*;
    pub use crate::storage_manager::*;
    pub use crate::trust_manager::*;
    pub use crate::vdc_collection::*;
    pub use crate::wallet::*;
}
