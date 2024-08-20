use crate::common::*;
use crate::storage_manager::{StorageManagerError, StorageManagerInterface};

/// Internal prefix for trusted did keys.
const KEY_PREFIX: &str = "TrustedDIDs.";

#[derive(thiserror::Error, Debug, uniffi::Error)]
pub enum TrustManagerError {
    #[error(transparent)]
    Storage(#[from] StorageManagerError),
}

pub struct TrustManager;

impl TrustManager {
    pub fn new() -> Self {
        Self
    }

    /// Add a trusted DID to the wallet.
    pub fn add_did(
        &self,
        did_key: String,
        storage: &Box<dyn StorageManagerInterface>,
    ) -> Result<(), TrustManagerError> {
        storage
            .add(Key::with_prefix(KEY_PREFIX, &did_key), Value::from(true))
            .map_err(TrustManagerError::Storage)
    }

    /// Remove a trusted DID from the wallet.
    pub fn remove_did(
        &self,
        did_key: String,
        storage: &Box<dyn StorageManagerInterface>,
    ) -> Result<(), TrustManagerError> {
        storage
            .remove(Key::with_prefix(KEY_PREFIX, &did_key))
            .map_err(TrustManagerError::Storage)
    }

    /// Block a trusted DID from the wallet.
    ///
    /// This will internally set the trusted did to false, but will not delete the key.
    pub fn block_did(
        &self,
        did_key: String,
        storage: &Box<dyn StorageManagerInterface>,
    ) -> Result<(), TrustManagerError> {
        storage
            .add(Key::with_prefix(KEY_PREFIX, &did_key), Value::from(false))
            .map_err(TrustManagerError::Storage)
    }

    /// Get the list of trusted DIDs from the wallet.
    pub fn get_trusted_dids(
        &self,
        storage: &Box<dyn StorageManagerInterface>,
    ) -> Result<Vec<String>, TrustManagerError> {
        let list = storage
            .list()
            .map_err(TrustManagerError::Storage)?
            .into_iter()
            .filter_map(|key| match self.is_trusted_key(key.clone(), storage) {
                Ok(true) => Some(key),
                _ => None,
            })
            .filter_map(|id| id.strip_prefix(KEY_PREFIX))
            .collect::<Vec<String>>();

        Ok(list)
    }

    /// Get the list of blocked DIDs from the wallet.
    pub fn get_blocked_dids(
        &self,
        storage: &Box<dyn StorageManagerInterface>,
    ) -> Result<Vec<String>, TrustManagerError> {
        let list = storage
            .list()
            .map_err(TrustManagerError::Storage)?
            .into_iter()
            .filter_map(|key| match self.is_blocked_key(key.clone(), storage) {
                Ok(true) => Some(key),
                _ => None,
            })
            .filter_map(|id| id.strip_prefix(KEY_PREFIX))
            .collect::<Vec<String>>();

        Ok(list)
    }

    /// Check if a DID is trusted.
    pub fn is_trusted_did(
        &self,
        did_key: String,
        storage: &Box<dyn StorageManagerInterface>,
    ) -> Result<bool, TrustManagerError> {
        self.is_trusted_key(Key::with_prefix(KEY_PREFIX, &did_key), storage)
    }

    /// Check if a DID is blocked.
    ///
    /// Explicitly checks if a DID is blocked.
    pub fn is_blocked_did(
        &self,
        did_key: String,
        storage: &Box<dyn StorageManagerInterface>,
    ) -> Result<bool, TrustManagerError> {
        self.is_blocked_key(Key::with_prefix(KEY_PREFIX, &did_key), storage)
    }

    /// Internal method to check if a key is trusted.
    pub fn is_trusted_key(
        &self,
        key: Key,
        storage: &Box<dyn StorageManagerInterface>,
    ) -> Result<bool, TrustManagerError> {
        match storage.get(key) {
            Ok(Some(val)) => Ok(val == Value::from(true)),
            Ok(None) => Ok(false),
            Err(e) => Err(TrustManagerError::Storage(e)),
        }
    }

    /// Internal method to check if a key is blocked.
    ///
    /// This is used internally to check if a key is blocked.
    pub fn is_blocked_key(
        &self,
        key: Key,
        storage: &Box<dyn StorageManagerInterface>,
    ) -> Result<bool, TrustManagerError> {
        match storage.get(key) {
            Ok(Some(val)) => Ok(val == Value::from(false)),
            Ok(None) => Ok(false),
            Err(e) => Err(TrustManagerError::Storage(e)),
        }
    }
}
