use super::storage_manager::*;
use serde_derive::{Deserialize, Serialize};
use tracing::{info_span, info};
use uuid::Uuid;

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
        Credential { id, format, ctype, payload }
    }
}

/// Verifiable Digital Credential Collection
///
/// This is the main interface to credentials.
pub struct VdcCollection {
    storage: Box<dyn StorageManagerInterface>,
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
    ) {
        let val;

        match serde_cbor::to_vec(&Credential::new(id, format, ctype, payload)) {
            Ok(x) => val = x,
            Err(_) => return,
        }

        match self.storage.add(Key(id.to_string()), Value(val)) {
            Ok(()) => {}
            Err(x) => println!("error adding credential: {x}"),
        }
    }

    /// Get a credential from the store.
    pub fn get(&self, id: &str) -> Option<Credential> {
        let raw;

        match self.storage.get(Key(id.to_string())) {
            Ok(x) => raw = x.0,
            Err(_) => return None,
        }

        match serde_cbor::de::from_slice(&raw) {
            Ok(x) => Some(x),
            Err(_) => None,
        }
    }

    /// Get a list of all the credentials.
    pub fn all_entries(&self) -> Vec<Key> {
        self.storage.list()
    }

    /// Get a list of all the credentials that match a specified type.
    pub fn all_entries_by_type(&self, ctype: CredentialType) -> Vec<String> {
        let mut r = Vec::new();

        for key in self.all_entries() {
            let cred = self.get(&key.0);

            match cred {
                Some(x) => {
                    if x.ctype == ctype {
                        r.push(key.0);
                    }
                }
                None => {}
            }
        }

        r
    }

    /// Dump the contents of the credential set to the logger.
    pub fn dump(&self) {
        let span = info_span!("All Credentials");
        span.in_scope(|| {
            for key in self.all_entries() {
                match self.get(&key.0) {
                    Some(x) => info!("{:?}", x),
                    None => {}
                }
            }
        });
    }
}
