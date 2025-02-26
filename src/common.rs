use crate::UniffiCustomTypeConverter;

use serde::{Deserialize, Serialize};
use ssi::{claims::data_integrity::CryptosuiteString, crypto::Algorithm};
use uniffi::deps::anyhow;
pub use url::Url;
pub use uuid::Uuid;

uniffi::custom_newtype!(CredentialType, String);
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct CredentialType(pub String);

impl From<String> for CredentialType {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<CredentialType> for String {
    fn from(cred_type: CredentialType) -> Self {
        cred_type.0
    }
}

uniffi::custom_type!(Uuid, String);
impl UniffiCustomTypeConverter for Uuid {
    type Builtin = String;
    fn into_custom(uuid: Self::Builtin) -> uniffi::Result<Self> {
        Ok(uuid.parse()?)
    }
    fn from_custom(uuid: Self) -> Self::Builtin {
        uuid.to_string()
    }
}

uniffi::custom_type!(Url, String);
impl UniffiCustomTypeConverter for Url {
    type Builtin = String;
    fn into_custom(url: Self::Builtin) -> uniffi::Result<Self> {
        Ok(Url::parse(&url)?)
    }
    fn from_custom(url: Self) -> Self::Builtin {
        url.to_string()
    }
}

uniffi::custom_newtype!(Key, String);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Key(pub String);

impl Key {
    /// Create a new key with a prefix
    pub fn with_prefix(prefix: &str, key: &str) -> Self {
        Self(format!("{}{}", prefix, key))
    }

    /// Strip the prefix from the key, returning the key without the prefix
    pub fn strip_prefix(&self, prefix: &str) -> Option<String> {
        self.0.strip_prefix(prefix).map(ToOwned::to_owned)
    }
}

impl From<Key> for String {
    fn from(key: Key) -> Self {
        key.0
    }
}

impl From<String> for Key {
    fn from(key: String) -> Self {
        Self(key)
    }
}

impl From<&str> for Key {
    fn from(key: &str) -> Self {
        Self(key.to_string())
    }
}

uniffi::custom_newtype!(Value, Vec<u8>);

#[derive(Debug, PartialEq)]
pub struct Value(pub Vec<u8>);

uniffi::custom_type!(Algorithm, String);
impl UniffiCustomTypeConverter for Algorithm {
    type Builtin = String;

    fn into_custom(alg: Self::Builtin) -> uniffi::Result<Self> {
        match alg.as_ref() {
            "ES256" => Ok(Algorithm::ES256),
            "ES256K" => Ok(Algorithm::ES256K),
            _ => anyhow::bail!("unsupported uniffi custom type for Algorithm mapping: {alg}"),
        }
    }

    fn from_custom(alg: Self) -> Self::Builtin {
        alg.to_string()
    }
}

uniffi::custom_type!(CryptosuiteString, String);
impl UniffiCustomTypeConverter for CryptosuiteString {
    type Builtin = String;

    fn into_custom(suite: Self::Builtin) -> uniffi::Result<Self> {
        Self::new(suite)
            .map_err(|e| uniffi::deps::anyhow::anyhow!("failed to create cryptosuite: {e:?}"))
    }

    fn from_custom(suite: Self) -> Self::Builtin {
        suite.to_string()
    }
}
