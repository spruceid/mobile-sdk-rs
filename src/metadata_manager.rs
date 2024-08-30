use std::sync::Arc;

use crate::common::Value;
use crate::storage_manager::{StorageManagerError, StorageManagerInterface};

use oid4vp::core::metadata::WalletMetadata;

/// Internal prefix for the wallet metadata.
const DEFAULT_WALLET_METADATA_KEY: &str = "WalletMetadata.default";

#[derive(thiserror::Error, Debug, uniffi::Error)]
pub enum MetadataManagerError {
    #[error("An unexpected foreign callback error occurred: {0}")]
    UnexpectedUniFFICallbackError(String),
    #[error(transparent)]
    Storage(#[from] StorageManagerError),
    #[error("Failed to serialize metadata: {0}")]
    SerializationError(String),
    #[error("No wallet metadata found")]
    NoMetadataFound,
    #[error("Failed to retrieve or add new request object signing algorithm: {0}")]
    RequestObjectSigningAlgorithm(String),
}

// Handle unexpected errors when calling a foreign callback
impl From<uniffi::UnexpectedUniFFICallbackError> for MetadataManagerError {
    fn from(value: uniffi::UnexpectedUniFFICallbackError) -> Self {
        MetadataManagerError::UnexpectedUniFFICallbackError(value.reason)
    }
}

/// MetadataManager is responsible for managing OID4VP metadata for the wallet.
///
/// Use the [MetadataManager::initialize] method to create a new instance of the metadata manager.
///
/// The metadata manager is responsible for managing the wallet metadata, which includes the supported request object signing algorithms.
///
/// Use the [MetadataManager::cache] method to access a reference to the wallet metadata.
#[derive(Debug)]
pub struct MetadataManager {
    cache: WalletMetadata,
}

impl AsRef<WalletMetadata> for MetadataManager {
    fn as_ref(&self) -> &WalletMetadata {
        &self.cache
    }
}

impl MetadataManager {
    pub fn initialize(
        storage: Arc<dyn StorageManagerInterface>,
    ) -> Result<Self, MetadataManagerError> {
        match Self::get_metadata(storage.clone()) {
            Ok(metadata) => Ok(Self { cache: metadata }),
            Err(MetadataManagerError::NoMetadataFound) => {
                // Add default metadata to the wallet.
                Self::add_metadata(&WalletMetadata::openid4vp_scheme_static(), storage.clone())?;
                Self::initialize(storage.clone())
            }
            Err(e) => Err(e),
        }
    }

    /// Returns a reference to the wallet metadata.
    ///
    /// The metadata manager cache is used to provide a reference to the wallet metadata without having to
    /// retrieve it from storage each time.
    ///
    /// The cache is updated when new metadata is added to the wallet using the [MetadataManager] methods.
    ///
    /// This is an alias for [MetadataManager::as_ref].
    pub fn cache(&self) -> &WalletMetadata {
        self.as_ref()
    }

    // Internal method for adding wallet metadata to the wallet.
    fn add_metadata(
        metadata_value: &WalletMetadata,
        storage: Arc<dyn StorageManagerInterface>,
    ) -> Result<(), MetadataManagerError> {
        let value = serde_json::to_vec(metadata_value)
            .map_err(|e| MetadataManagerError::SerializationError(e.to_string()))?;

        storage
            .add(DEFAULT_WALLET_METADATA_KEY.into(), Value(value))
            .map_err(MetadataManagerError::Storage)
    }

    // Internal method for getting the wallet metadata from the wallet.
    fn get_metadata(
        storage: Arc<dyn StorageManagerInterface>,
    ) -> Result<WalletMetadata, MetadataManagerError> {
        let value = storage
            .get(DEFAULT_WALLET_METADATA_KEY.into())
            .map_err(MetadataManagerError::Storage)?
            .ok_or(MetadataManagerError::NoMetadataFound)?;

        let metadata: WalletMetadata = serde_json::from_slice(&value.0)
            .map_err(|e| MetadataManagerError::SerializationError(e.to_string()))?;

        Ok(metadata)
    }
}
