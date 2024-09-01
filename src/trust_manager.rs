use std::sync::Arc;

use crate::common::{Key, Value};
use crate::storage_manager::{StorageManagerError, StorageManagerInterface};

/// Internal prefix for trusted did keys.
const KEY_PREFIX: &str = "TrustedDIDs.";

#[derive(thiserror::Error, Debug, uniffi::Error)]
pub enum TrustManagerError {
    #[error("An unexpected foreign callback error occurred: {0}")]
    UnexpectedUniFFICallbackError(String),
    #[error(transparent)]
    Storage(#[from] StorageManagerError),
    #[error("The DID key cannot be added because it is blocked, key: {0}")]
    DIDBlocked(String),
}

// Handle unexpected errors when calling a foreign callback
impl From<uniffi::UnexpectedUniFFICallbackError> for TrustManagerError {
    fn from(value: uniffi::UnexpectedUniFFICallbackError) -> Self {
        TrustManagerError::UnexpectedUniFFICallbackError(value.reason)
    }
}

/// TrustManager is responsible for managing trusted DIDs for the wallet.
///
/// Use the [TrustManager::new] method to create a new instance of the trust manager.
///
/// The trust manager does not store a cached state of the trusted dids,
/// but instead accesses and modifies the trusted dids in the storage manager directly.
///
/// In the future, this might change in favor of faster reads.
#[derive(Debug)]
pub struct TrustManager;
// NOTE: Adding a cache to the TrustManager would be a good idea to avoid
// repeated reads from the storage manager. That said, the current implementation
// would need some refactoring to ensure the cache is kept up to date with the
// storage manager. See the MetadataManager for an example of how this could be done.
//
// Given that the trust manager also supports checking for `blocked` DIDs, the cache
// would ultimately only support `trusted_dids` and not `blocked_dids`.

impl TrustManager {
    pub fn new() -> Self {
        Self
    }

    /// Add a trusted DID to the wallet.
    ///
    /// This will internally set the trusted did to true.
    ///
    /// If the DID is already trusted, this will overwrite the existing value.
    ///
    /// # Arguments
    ///
    /// * `did_key` - The DID key to add to the wallet.
    /// * `storage` - The storage manager to use for storing the DID.
    ///
    /// # Errors
    ///
    /// Returns a [TrustManagerError] if the DID could not be
    /// added to the wallet due to a storage error or if the DID is blocked.
    ///
    pub async fn add_did(
        &self,
        did_key: String,
        storage: Arc<dyn StorageManagerInterface>,
    ) -> Result<(), TrustManagerError> {
        if self.is_blocked_key(&did_key, storage.clone()).await? {
            return Err(TrustManagerError::DIDBlocked(did_key));
        }

        storage
            .add(Key::with_prefix(KEY_PREFIX, &did_key), Value::from(true))
            .await
            .map_err(TrustManagerError::Storage)
    }

    /// Remove a trusted DID from the wallet storage.
    ///
    /// # Arguments
    ///
    /// * `did_key` - The DID key to remove from the wallet.
    /// * `storage` - The storage manager to use for removing the DID.
    ///
    /// # Errors
    ///
    /// Returns a [TrustManagerError] if the DID could not be
    /// removed from the wallet due to a storage error.
    ///
    ///
    pub async fn remove_did(
        &self,
        did_key: String,
        storage: Arc<dyn StorageManagerInterface>,
    ) -> Result<(), TrustManagerError> {
        storage
            .remove(Key::with_prefix(KEY_PREFIX, &did_key))
            .await
            .map_err(TrustManagerError::Storage)
    }

    /// Block a trusted DID from the wallet.
    ///
    /// This will internally set the trusted did to false, but will not delete the key.
    ///
    /// If the DID is already blocked, this will overwrite the existing value.
    ///
    /// The motivation for `blocking` a DID is to prevent a removed DID from being added back
    /// to the wallet. This is useful in cases where a DID is desired to be removed from the wallet,
    /// but should not be added back in the future.
    ///
    /// # Arguments
    ///
    /// * `did_key` - The DID key to block from the wallet.
    /// * `storage` - The storage manager to use for storing the DID.
    ///
    /// # Errors
    ///
    /// Returns a [TrustManagerError] if the DID could not be
    /// blocked from the wallet due to a storage error.
    pub async fn block_did(
        &self,
        did_key: String,
        storage: Arc<dyn StorageManagerInterface>,
    ) -> Result<(), TrustManagerError> {
        storage
            .add(Key::with_prefix(KEY_PREFIX, &did_key), Value::from(false))
            .await
            .map_err(TrustManagerError::Storage)
    }

    /// Unblock a DID from the wallet, only if it is blocked.
    ///
    /// This will internally set the trusted did to true, unblocking
    /// the DID key.
    ///
    /// If the DID is not blocked, this will be a no-op.
    ///
    /// # Arguments
    ///
    /// * `did_key` - The DID key to unblock from the wallet.
    /// * `storage` - The storage manager to use for storing the DID.
    ///
    /// # Errors
    ///
    /// Returns a [TrustManagerError] if the DID could not be
    /// unblocked from the wallet due to a storage error.
    pub async fn unblock_did(
        &self,
        did_key: String,
        storage: Arc<dyn StorageManagerInterface>,
    ) -> Result<(), TrustManagerError> {
        if !self.is_blocked_key(&did_key, storage.clone()).await? {
            return Ok(()); // Noop if the key is not blocked.
        }

        storage
            .add(Key::with_prefix(KEY_PREFIX, &did_key), Value::from(true))
            .await
            .map_err(TrustManagerError::Storage)
    }

    /// Get the list of trusted DIDs from the wallet.
    ///
    /// This will return a list of DIDs that are trusted in the wallet.
    ///
    /// # Arguments
    ///
    /// * `storage` - The storage manager to use for storing the DIDs.
    ///
    /// # Errors
    ///
    /// Returns a [TrustManagerError] if the DIDs could not be
    /// retrieved from the wallet due to a storage error.
    pub async fn get_trusted_dids(
        &self,
        storage: Arc<dyn StorageManagerInterface>,
    ) -> Result<Vec<String>, TrustManagerError> {
        let ids: Vec<String> = storage
            .list()
            .await
            .map_err(TrustManagerError::Storage)?
            .into_iter()
            .filter_map(|id| id.strip_prefix(KEY_PREFIX))
            .collect();
        let mut list: Vec<String> = Vec::with_capacity(ids.len());
        for id in ids {
            match self.is_trusted_key(&id, storage.clone()).await {
                Ok(true) => list.push(id),
                _ => (),
            }
        }
        Ok(list)
    }

    /// Get the list of blocked DIDs from the wallet.
    ///
    /// This will return a list of DIDs that are blocked in the wallet.
    ///
    /// # Arguments
    ///
    /// * `storage` - The storage manager to use for storing the DIDs.
    ///
    /// # Errors
    ///
    /// Returns a [TrustManagerError] if the blocked DIDs could not be
    /// retrieved from the wallet due to a storage error.
    pub async fn get_blocked_dids(
        &self,
        storage: Arc<dyn StorageManagerInterface>,
    ) -> Result<Vec<String>, TrustManagerError> {
        let ids: Vec<String> = storage
            .list()
            .await
            .map_err(TrustManagerError::Storage)?
            .into_iter()
            .filter_map(|id| id.strip_prefix(KEY_PREFIX))
            .collect();
        let mut list: Vec<String> = Vec::with_capacity(ids.len());
        for id in ids {
            match self.is_blocked_key(&id, storage.clone()).await {
                Ok(true) => list.push(id),
                _ => (),
            }
        }

        Ok(list)
    }

    /// Check if a DID is trusted.
    ///
    /// Explicitly checks if a DID is trusted.
    ///
    /// # Arguments
    ///
    /// * `did_key` - The DID key to check if it is trusted.
    /// * `storage` - The storage manager to use for storing the DID.
    ///
    /// # Errors
    ///
    /// Returns a [TrustManagerError] if the DID could not be
    /// checked if it is trusted due to a storage error.
    pub async fn is_trusted_did(
        &self,
        did_key: String,
        storage: Arc<dyn StorageManagerInterface>,
    ) -> Result<bool, TrustManagerError> {
        self.is_trusted_key(&did_key, storage).await
    }

    /// Check if a DID is blocked.
    ///
    /// Explicitly checks if a DID is blocked.
    ///
    /// # Arguments
    ///
    /// * `did_key` - The DID key to check if it is blocked.
    /// * `storage` - The storage manager to use for storing the DID.
    ///
    /// # Errors
    ///
    /// Returns a [TrustManagerError] if the DID could not be
    /// checked if it is blocked due to a storage error.
    pub async fn is_blocked_did(
        &self,
        did_key: String,
        storage: Arc<dyn StorageManagerInterface>,
    ) -> Result<bool, TrustManagerError> {
        self.is_blocked_key(&did_key, storage).await
    }

    /// Internal method to check if a key is trusted.
    async fn is_trusted_key(
        &self,
        key: &String,
        storage: Arc<dyn StorageManagerInterface>,
    ) -> Result<bool, TrustManagerError> {
        match storage.get(Key::with_prefix(KEY_PREFIX, key)).await {
            Ok(Some(val)) => Ok(val == Value::from(true)),
            Ok(None) => Ok(false),
            Err(e) => Err(TrustManagerError::Storage(e)),
        }
    }

    /// Internal method to check if a key is blocked.
    ///
    /// This is used internally to check if a key is blocked.
    async fn is_blocked_key(
        &self,
        key: &String,
        storage: Arc<dyn StorageManagerInterface>,
    ) -> Result<bool, TrustManagerError> {
        match storage.get(Key::with_prefix(KEY_PREFIX, key)).await {
            Ok(Some(val)) => Ok(val == Value::from(false)),
            Ok(None) => Ok(false),
            Err(e) => Err(TrustManagerError::Storage(e)),
        }
    }
}
