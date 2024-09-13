use crate::{CredentialType, KeyAlias, Uuid};
use serde::{Deserialize, Serialize};

/// An individual credential.
#[derive(Debug, Serialize, Deserialize, uniffi::Record)]
pub struct Credential {
    /// The local ID of this credential.
    pub id: Uuid,
    /// The format of this credential.
    pub format: CredentialFormat,
    /// The type of this credential.
    pub r#type: CredentialType,
    /// The raw payload of this credential. The encoding depends on the format.
    pub payload: Vec<u8>,
    /// The alias of the key that is authorized to present this credential.
    pub key_alias: Option<KeyAlias>,
}

/// The format of the credential.
#[derive(uniffi::Enum, PartialEq, Debug, Serialize, Deserialize, Clone)]
pub enum CredentialFormat {
    MsoMdoc,
    JwtVcJson,
    JwtVcJsonLd,
    LdpVc,
    Other(String), // For ease of expansion.
}
