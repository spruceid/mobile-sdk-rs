use crate::UniffiCustomTypeConverter;

// Re-export Uuid for common use.
pub use oid4vp::core::credential_format::{ClaimFormatDesignation, CredentialType};
pub use url::Url;
pub use uuid::Uuid;

uniffi::custom_type!(CredentialType, String);
impl UniffiCustomTypeConverter for CredentialType {
    type Builtin = String;
    fn into_custom(credential_type: Self::Builtin) -> uniffi::Result<Self> {
        Ok(CredentialType::from(credential_type.as_str()))
    }
    fn from_custom(credential_type: Self) -> Self::Builtin {
        (&credential_type).into()
    }
}

uniffi::custom_type!(ClaimFormatDesignation, String);
impl UniffiCustomTypeConverter for ClaimFormatDesignation {
    type Builtin = String;
    fn into_custom(claim_format_designation: Self::Builtin) -> uniffi::Result<Self> {
        Ok(ClaimFormatDesignation::from(
            claim_format_designation.as_str(),
        ))
    }
    fn from_custom(claim_format_designation: Self) -> Self::Builtin {
        claim_format_designation.into()
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

/// Generic key type for storage.
///
/// This type is used to store and retrieve values from the storage manager.
///
/// The key is a string, and can be prefixed with a string to group keys together.
#[derive(Debug, Clone, PartialEq)]
pub struct Key(pub(crate) String);

impl Key {
    /// Create a new key with a prefix
    pub fn with_prefix(prefix: &str, key: &str) -> Self {
        Self(format!("{}{}", prefix, key))
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

impl From<&Key> for String {
    fn from(key: &Key) -> Self {
        key.0.to_owned()
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

impl From<bool> for Value {
    fn from(value: bool) -> Self {
        Self(vec![value as u8])
    }
}
