use crate::storage_manager::{Key, StorageManagerError, Value};

use super::storage_manager::StorageManagerInterface;

/// Internal prefix for trusted did keys.
const KEY_PREFIX: &str = "TrustedDIDs.";

#[derive(thiserror::Error, Debug, uniffi::Error)]
pub enum MetadataManagerError {
    #[error(transparent)]
    Storage(#[from] StorageManagerError),
}

/// MetadataManager is responsible for managing OID4VP metadata for the wallet.
pub struct MetadataManager;

impl MetadataManager {
    pub fn new() -> Self {
        Self
    }
}
