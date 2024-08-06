use super::storage_manager::*;
use serde::{Deserialize, Serialize};
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

pub enum VdcCollectionError {
    SerializeFailed,
    DeserializeFailed,
    StoreFailed,
    LoadFailed,
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
            Err(_) => Err(VdcCollectionError::StoreFailed),
        }
    }

    /// Get a credential from the store.
    pub fn get(&self, id: &str) -> Result<Credential, VdcCollectionError> {
        let raw = match self.storage.get(self.str_to_key(id)) {
            Ok(x) => x.0,
            Err(_) => return Err(VdcCollectionError::LoadFailed),
        };

        match serde_cbor::de::from_slice(&raw) {
            Ok(x) => Ok(x),
            Err(_) => Err(VdcCollectionError::DeserializeFailed),
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
