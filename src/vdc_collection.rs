use super::storage_manager::*;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{info, info_span};
use uuid::Uuid;

/// Internal prefix for credential keys.
const KEY_PREFIX: &str = "Credential.";

/// Supported credential formats.
#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub enum CredentialFormat {
    MsoMdoc,
    JwtVcJson,
    LdpVc,
    Other(String), // For ease of expansion.
}

/// Supported credential types.
#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub enum CredentialType {
    Iso18013_5_1mDl,
    VehicleTitle,
    Other(String), // For ease of expansion.
}

/// An individual credential.
#[derive(Debug, Serialize, Deserialize)]
pub struct Credential {
    id: Uuid,
    format: CredentialFormat,
    ctype: CredentialType,
    payload: Vec<u8>, // The actual credential.
}

impl Credential {
    /// Create a new credential.
    fn new(
        id: Uuid,
        format: CredentialFormat,
        ctype: CredentialType,
        payload: Vec<u8>,
    ) -> Credential {
        Credential {
            id,
            format,
            ctype,
            payload,
        }
    }
}

/// Verifiable Digital Credential Collection
///
/// This is the main interface to credentials.
pub struct VdcCollection {
    storage: Box<dyn StorageManagerInterface>,
}

#[derive(Error, Debug, uniffi::Error)]
pub enum VdcCollectionError {
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

impl VdcCollection {
    /// Create a new credential set.
    pub fn new(engine: Box<dyn StorageManagerInterface>) -> VdcCollection {
        VdcCollection { storage: engine }
    }

    /// Add a credential to the set.
    pub fn add(
        &self,
        id: Uuid,
        format: CredentialFormat,
        ctype: CredentialType,
        payload: Vec<u8>,
    ) -> Result<(), VdcCollectionError> {
        let val = match serde_cbor::to_vec(&Credential::new(id, format, ctype, payload)) {
            Ok(x) => x,
            Err(_) => return Err(VdcCollectionError::SerializeFailed),
        };

        match self.storage.add(self.id_to_key(id), Value(val)) {
            Ok(()) => Ok(()),
            Err(e) => Err(VdcCollectionError::StoreFailed(e)),
        }
    }

    /// Get a credential from the store.
    pub fn get(&self, id: &str) -> Result<Credential, VdcCollectionError> {
        let raw = match self.storage.get(self.str_to_key(id)) {
            Ok(x) => x.0,
            Err(e) => return Err(VdcCollectionError::LoadFailed(e)),
        };

        match serde_cbor::de::from_slice(&raw) {
            Ok(x) => Ok(x),
            Err(_) => Err(VdcCollectionError::DeserializeFailed),
        }
    }

    /// Remove a credential from the store.
    pub fn delete(&self, id: &str) -> Result<(), VdcCollectionError> {
        match self.storage.remove(self.str_to_key(id)) {
            Ok(_) => Ok(()),
            Err(e) => Err(VdcCollectionError::DeleteFailed(e)),
        }
    }

    /// Get a list of all the credentials.
    pub fn all_entries(&self) -> Vec<Key> {
        let mut r = Vec::new();

        for key in self.storage.list() {
            let name = key.0;

            if name.starts_with(KEY_PREFIX) {
                if let Some(id) = name.strip_prefix(KEY_PREFIX) {
                    r.push(Key(id.to_string()));
                }
            }
        }

        r
    }

    /// Get a list of all the credentials that match a specified type.
    pub fn all_entries_by_type(&self, ctype: CredentialType) -> Vec<String> {
        let mut r = Vec::new();

        for key in self.all_entries() {
            let cred = self.get(&key.0);

            if let Ok(x) = cred {
                if x.ctype == ctype {
                    r.push(key.0);
                }
            }
        }

        r
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
    pub fn dump(&self) {
        let span = info_span!("All Credentials");
        span.in_scope(|| {
            for key in self.all_entries() {
                if let Ok(x) = self.get(&key.0) {
                    info!("{:?}", x);
                }
            }
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
        let smi = LocalStore;
        let vdc = VdcCollection::new(Box::new(smi));
        let payload_1: Vec<u8> = "Some random collection of bytes. ⚛".into();
        let payload_2: Vec<u8> = "Some other random collection of bytes. 📯".into();
        let payload_3: Vec<u8> = "Some third random collection of bytes. λ".into();

        match vdc.add(
            uuid!("00000000-0000-0000-0000-000000000001"),
            CredentialFormat::MsoMdoc,
            CredentialType::Iso18013_5_1mDl,
            payload_1.clone(),
        ) {
            Ok(_) => {}
            Err(_) => panic!("Unable to add the first value."),
        }

        match vdc.add(
            uuid!("00000000-0000-0000-0000-000000000002"),
            CredentialFormat::MsoMdoc,
            CredentialType::Iso18013_5_1mDl,
            payload_2.clone(),
        ) {
            Ok(_) => {}
            Err(_) => panic!("Unable to add the second value."),
        }

        match vdc.add(
            uuid!("00000000-0000-0000-0000-000000000003"),
            CredentialFormat::MsoMdoc,
            CredentialType::Iso18013_5_1mDl,
            payload_3.clone(),
        ) {
            Ok(_) => {}
            Err(_) => panic!("Unable to add the third value."),
        }

        match vdc.get("00000000-0000-0000-0000-000000000002") {
            Ok(x) => assert!(x.payload == payload_2.clone()),
            Err(_) => panic!("Failed to get the second value"),
        }

        match vdc.get("00000000-0000-0000-0000-000000000001") {
            Ok(x) => assert!(x.payload == payload_1.clone()),
            Err(_) => panic!("Failed to get the first value"),
        }

        match vdc.get("00000000-0000-0000-0000-000000000003") {
            Ok(x) => assert!(x.payload == payload_3.clone()),
            Err(_) => panic!("Failed to get the third value"),
        }

        let list = vdc.all_entries();

        assert!(list.len() == 3);

        match vdc.delete("00000000-0000-0000-0000-000000000002") {
            Ok(_) => {}
            Err(_) => panic!("Failed to delete the second value."),
        }

        let list = vdc.all_entries();

        assert!(list.len() == 2);

        match vdc.delete("00000000-0000-0000-0000-000000000001") {
            Ok(_) => {}
            Err(_) => panic!("Failed to delete the first value."),
        }

        match vdc.delete("00000000-0000-0000-0000-000000000003") {
            Ok(_) => {}
            Err(_) => panic!("Failed to delete the third value."),
        }

        let list = vdc.all_entries();

        assert!(list.len() == 0);
    }
}
