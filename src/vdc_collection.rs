use crate::common::*;
use crate::storage_manager::*;

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{info, info_span};

/// Internal prefix for credential keys.
const KEY_PREFIX: &str = "Credential.";

/// An individual credential.
#[derive(Debug, uniffi::Object, Serialize, Deserialize)]
pub struct Credential {
    id: Uuid,
    format: ClaimFormatDesignation,
    ctype: CredentialType,
    payload: Vec<u8>, // The actual credential.
}

#[uniffi::export]
impl Credential {
    #[uniffi::constructor]
    /// Create a new credential.
    pub fn new(
        id: Uuid,
        format: ClaimFormatDesignation,
        ctype: CredentialType,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            id,
            format,
            ctype,
            payload,
        }
    }

    #[uniffi::constructor]
    pub fn new_as_arc(
        id: Uuid,
        format: ClaimFormatDesignation,
        ctype: CredentialType,
        payload: Vec<u8>,
    ) -> Arc<Self> {
        Arc::new(Self::new(id, format, ctype, payload))
    }

    /// Get the ID of the credential.
    pub fn id(&self) -> Uuid {
        self.id.clone()
    }

    /// Get the format of the credential.
    pub fn format(&self) -> ClaimFormatDesignation {
        self.format.clone()
    }

    /// Get the type of the credential.
    pub fn ctype(&self) -> CredentialType {
        self.ctype.clone()
    }

    /// Get the payload of the credential.
    pub fn payload(&self) -> Vec<u8> {
        self.payload.clone()
    }

    /// Return the credential as a key suitable for storage.
    pub fn as_storage_key(&self) -> Key {
        Key(format!("{}{}", self.as_storage_key_prefix(), self.id))
    }

    /// Return the credential storage key prefix with credential type index as a string.
    pub fn as_storage_key_prefix(&self) -> String {
        format!("{KEY_PREFIX}{}.", self.ctype)
    }
}

/// Verifiable Digital Credential Collection
///
/// This is the main interface to credentials.
#[derive(Debug)]
pub struct VdcCollection;

#[derive(Error, Debug, uniffi::Error)]
pub enum VdcCollectionError {
    /// An unexpected error occurred.
    #[error("An unexpected foreign callback error occurred: {0}")]
    UnexpectedUniFFICallbackError(String),

    /// Attempt to convert the credential to a serialized form suitable for writing to storage failed.
    #[error("Failed to Serialize Value: {0}")]
    SerializeFailed(String),

    /// Attempting to convert the credential to a deserialized form suitable for runtime use failed.
    #[error("Failed to Deserialize Value: {0}")]
    DeserializeFailed(String),

    /// A Storage Manager Error occurred.
    #[error(transparent)]
    Storage(#[from] StorageManagerError),
}

// Handle unexpected errors when calling a foreign callback
impl From<uniffi::UnexpectedUniFFICallbackError> for VdcCollectionError {
    fn from(value: uniffi::UnexpectedUniFFICallbackError) -> Self {
        VdcCollectionError::UnexpectedUniFFICallbackError(value.reason)
    }
}

impl VdcCollection {
    /// Create a new credential set.
    pub fn new() -> VdcCollection {
        Self
    }

    /// Add a credential to the set.
    ///
    /// Internally, the credential is serialized and stored in the storage manager.
    ///
    /// This method returns the key of the credential in the storage manager.
    ///
    /// The storage key can be computed from a credential via the [Credential::as_storage_key] method.
    pub async fn add(
        &self,
        credential: Credential,
        storage: &Arc<dyn StorageManagerInterface>,
    ) -> Result<Key, VdcCollectionError> {
        let val = serde_cbor::to_vec(&credential)
            .map_err(|e| VdcCollectionError::SerializeFailed(e.to_string()))?;

        storage.add(credential.as_storage_key(), Value(val)).await?;

        // Return the key of the credential in the storage manager, in case
        // the caller needs to cache it.
        Ok(credential.as_storage_key())
    }

    /// Get a credential from the store.
    pub async fn get(
        &self,
        key: Key,
        storage: &Arc<dyn StorageManagerInterface>,
    ) -> Result<Option<Credential>, VdcCollectionError> {
        storage
            .get(key)
            .await?
            .map(|x| serde_cbor::de::from_slice(&x.0))
            .transpose()
            .map_err(|e| VdcCollectionError::DeserializeFailed(e.to_string()))
    }

    /// Remove a credential from the store.
    pub async fn delete(
        &self,
        key: Key,
        storage: &Arc<dyn StorageManagerInterface>,
    ) -> Result<(), VdcCollectionError> {
        storage.remove(key).await.map_err(VdcCollectionError::from)
    }

    /// Get a list of all the credentials.
    pub async fn all_entries(
        &self,
        storage: &Arc<dyn StorageManagerInterface>,
    ) -> Result<Vec<Key>, VdcCollectionError> {
        Ok(storage
            .list()
            .await?
            .iter()
            .filter(|key| key.0.contains(KEY_PREFIX))
            .map(ToOwned::to_owned)
            .collect())
    }

    /// Get a list of all the credentials that match a specified type.
    pub async fn all_entries_by_type(
        &self,
        ctype: &CredentialType,
        storage: &Arc<dyn StorageManagerInterface>,
    ) -> Result<Vec<Key>, VdcCollectionError> {
        Ok(self
            .all_entries(storage)
            .await?
            .iter()
            .filter(|key| key.0.contains(&Self::storage_prefix(ctype)))
            .map(ToOwned::to_owned)
            .collect())
    }

    /// Return the storage prefix, given a credential type.
    pub fn storage_prefix(ctype: &CredentialType) -> String {
        format!("{KEY_PREFIX}{}.", ctype)
    }

    pub fn storage_key(ctype: &CredentialType, id: &str) -> Key {
        Key(format!("{}{id}", Self::storage_prefix(ctype)))
    }

    /// Dump the contents of the credential set to the logger.
    pub async fn dump(&self, storage: &Arc<dyn StorageManagerInterface>) {
        //let span = info_span!("All Credentials");
        //span.in_scope(async ||
        match self.all_entries(storage).await {
            Ok(list) => {
                for key in list {
                    if let Ok(x) = self.get(key, storage).await {
                        info!("{:?}", x);
                    }
                }
            }
            Err(e) => info!("Unable to get list: {:?}", e),
        }
        //);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local_store::*;
    use uuid::uuid;

    #[tokio::test]
    async fn test_vdc() {
        let smi: Arc<dyn StorageManagerInterface> = Arc::new(LocalStore);
        let vdc = VdcCollection::new();
        let payload_1: Vec<u8> = "Some random collection of bytes. ⚛".into();
        let payload_2: Vec<u8> = "Some other random collection of bytes. 📯".into();
        let payload_3: Vec<u8> = "Some third random collection of bytes. λ".into();

        let credential_1 = Credential::new(
            uuid!("00000000-0000-0000-0000-000000000001"),
            ClaimFormatDesignation::MsoMDoc,
            CredentialType::Iso18013_5_1mDl,
            payload_1.clone(),
        );
        let credential_2 = Credential::new(
            uuid!("00000000-0000-0000-0000-000000000002"),
            ClaimFormatDesignation::MsoMDoc,
            CredentialType::Iso18013_5_1mDl,
            payload_2.clone(),
        );
        let credential_3 = Credential::new(
            uuid!("00000000-0000-0000-0000-000000000003"),
            ClaimFormatDesignation::MsoMDoc,
            CredentialType::Iso18013_5_1mDl,
            payload_3.clone(),
        );

        let credential_1_key = vdc
            .add(credential_1, &smi)
            .await
            .expect("Unable to add the first value.");

        let credential_2_key = vdc
            .add(credential_2, &smi)
            .await
            .expect("Unable to add the second value.");

        let credential_3_key = vdc
            .add(credential_3, &smi)
            .await
            .expect("Unable to add the third value.");

        vdc.get(credential_1_key.clone(), &smi)
            .await
            .expect("Failed to get the second value");
        vdc.get(credential_2_key.clone(), &smi)
            .await
            .expect("Failed to get the first value");
        vdc.get(credential_3_key.clone(), &smi)
            .await
            .expect("Failed to get the third value");

        assert!(vdc.all_entries(&smi).await.unwrap().len() == 3);

        vdc.delete(credential_2_key.clone(), &smi)
            .await
            .expect("Failed to delete the second value.");

        assert!(vdc.all_entries(&smi).await.unwrap().len() == 2);

        vdc.delete(credential_1_key.clone(), &smi)
            .await
            .expect("Failed to delete the first value.");
        vdc.delete(credential_3_key.clone(), &smi)
            .await
            .expect("Failed to delete the third value.");

        assert!(vdc.all_entries(&smi).await.unwrap().len() == 0);
    }
}
