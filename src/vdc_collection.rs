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
    #[error("Failed to Serialize Value")]
    SerializeFailed,

    /// Attempting to convert the credential to a deserialized form suitable for runtime use failed.
    #[error("Failed to Deserialize Value")]
    DeserializeFailed,

    /// Attempting to write the credential to storage failed.
    #[error("Failed to Write to Storage")]
    StoreFailed(StorageManagerError),

    /// Attempting to read the credential from storage failed.
    #[error("Failed to Read from Storage")]
    LoadFailed(StorageManagerError),

    /// Attempting to delete a credential from storage failed.
    #[error("Failed to Delete from Storage")]
    DeleteFailed(StorageManagerError),
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
    pub fn add(
        &self,
        credential: Credential,
        storage: &Box<dyn StorageManagerInterface>,
    ) -> Result<(), VdcCollectionError> {
        let val = match serde_cbor::to_vec(&credential) {
            Ok(x) => x,
            Err(_) => return Err(VdcCollectionError::SerializeFailed),
        };

        match storage.add(self.id_to_key(credential.id), Value(val)) {
            Ok(()) => Ok(()),
            Err(e) => Err(VdcCollectionError::StoreFailed(e)),
        }
    }

    /// Get a credential from the store.
    pub fn get(
        &self,
        id: &str,
        storage: &Box<dyn StorageManagerInterface>,
    ) -> Result<Option<Credential>, VdcCollectionError> {
        let raw = match storage.get(self.str_to_key(id)) {
            Ok(Some(x)) => x,
            Ok(None) => return Ok(None),
            Err(e) => return Err(VdcCollectionError::LoadFailed(e)),
        };

        match serde_cbor::de::from_slice(&raw.0) {
            Ok(x) => Ok(x),
            Err(_) => Err(VdcCollectionError::DeserializeFailed),
        }
    }

    /// Remove a credential from the store.
    pub fn delete(
        &self,
        id: &str,
        storage: &Box<dyn StorageManagerInterface>,
    ) -> Result<(), VdcCollectionError> {
        match storage.remove(self.str_to_key(id)) {
            Ok(_) => Ok(()),
            Err(e) => Err(VdcCollectionError::DeleteFailed(e)),
        }
    }

    /// Get a list of all the credentials.
    pub fn all_entries(
        &self,
        storage: &Box<dyn StorageManagerInterface>,
    ) -> Result<Vec<String>, VdcCollectionError> {
        let mut r = Vec::new();

        match storage.list() {
            Ok(list) => {
                for key in list {
                    let name = key.0;

                    if name.starts_with(KEY_PREFIX) {
                        if let Some(id) = name.strip_prefix(KEY_PREFIX) {
                            r.push(id.to_string());
                        }
                    }
                }
            }
            Err(e) => return Err(VdcCollectionError::LoadFailed(e)),
        }

        Ok(r)
    }

    /// Get a list of all the credentials that match a specified type.
    pub fn all_entries_by_type(
        &self,
        ctype: CredentialType,
        storage: &Box<dyn StorageManagerInterface>,
    ) -> Result<Vec<String>, VdcCollectionError> {
        let mut r = Vec::new();

        match self.all_entries(storage) {
            Ok(list) => {
                for key in list {
                    let cred = self.get(&key, storage);

                    if let Ok(Some(x)) = cred {
                        if x.ctype == ctype {
                            r.push(key);
                        }
                    }
                }
            }
            Err(e) => return Err(e),
        }

        Ok(r)
    }

    /// Convert a UUID to a storage key.
    fn id_to_key(&self, id: Uuid) -> Key {
        self.str_to_key(&id.to_string())
    }

    /// Convert a string ref to a storage key.
    fn str_to_key(&self, id: &str) -> Key {
        Key(format!("{}{}", KEY_PREFIX, id))
    }

    /// Dump the contents of the credential set to the logger.
    pub fn dump(&self, storage: &Box<dyn StorageManagerInterface>) {
        let span = info_span!("All Credentials");
        span.in_scope(|| match self.all_entries(storage) {
            Ok(list) => {
                for key in list {
                    if let Ok(x) = self.get(&key, storage) {
                        info!("{:?}", x);
                    }
                }
            }
            Err(e) => info!("Unable to get list: {:?}", e),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local_store::*;
    use uuid::uuid;

    #[test]
    fn test_vdc() {
        let smi: Box<dyn StorageManagerInterface> = Box::new(LocalStore);
        let vdc = VdcCollection::new();
        let payload_1: Vec<u8> = "Some random collection of bytes. ⚛".into();
        let payload_2: Vec<u8> = "Some other random collection of bytes. 📯".into();
        let payload_3: Vec<u8> = "Some third random collection of bytes. λ".into();

        vdc.add(
            Credential::new(
                uuid!("00000000-0000-0000-0000-000000000001"),
                ClaimFormatDesignation::MsoMDoc,
                CredentialType::Iso18013_5_1mDl,
                payload_1.clone(),
            ),
            &smi,
        )
        .expect("Unable to add the first value.");

        vdc.add(
            Credential::new(
                uuid!("00000000-0000-0000-0000-000000000002"),
                ClaimFormatDesignation::MsoMDoc,
                CredentialType::Iso18013_5_1mDl,
                payload_2.clone(),
            ),
            &smi,
        )
        .expect("Unable to add the second value.");

        vdc.add(
            Credential::new(
                uuid!("00000000-0000-0000-0000-000000000003"),
                ClaimFormatDesignation::MsoMDoc,
                CredentialType::Iso18013_5_1mDl,
                payload_3.clone(),
            ),
            &smi,
        )
        .expect("Unable to add the third value.");

        vdc.get("00000000-0000-0000-0000-000000000002", &smi)
            .expect("Failed to get the second value");
        vdc.get("00000000-0000-0000-0000-000000000001", &smi)
            .expect("Failed to get the first value");
        vdc.get("00000000-0000-0000-0000-000000000003", &smi)
            .expect("Failed to get the third value");

        assert!(vdc.all_entries(&smi).unwrap().len() == 3);

        vdc.delete("00000000-0000-0000-0000-000000000002", &smi)
            .expect("Failed to delete the second value.");

        assert!(vdc.all_entries(&smi).unwrap().len() == 2);

        vdc.delete("00000000-0000-0000-0000-000000000001", &smi)
            .expect("Failed to delete the first value.");
        vdc.delete("00000000-0000-0000-0000-000000000003", &smi)
            .expect("Failed to delete the third value.");

        assert!(vdc.all_entries(&smi).unwrap().len() == 0);
    }
}
