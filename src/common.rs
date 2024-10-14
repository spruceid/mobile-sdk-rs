use std::collections::HashMap;

use crate::UniffiCustomTypeConverter;

use serde::{Deserialize, Serialize};
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

uniffi::custom_newtype!(KeyAlias, String);
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct KeyAlias(pub String);

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

#[derive(Serialize, Deserialize, Debug, Clone, uniffi::Enum)]
pub enum JsonValue {
    Object(HashMap<String, JsonValue>),
    Array(Vec<JsonValue>),
    String(String),
    Boolean(bool),
    Null,
}

impl From<&serde_json::Value> for JsonValue {
    fn from(value: &serde_json::Value) -> Self {
        match value {
            serde_json::Value::Null => Self::Null,
            serde_json::Value::Bool(b) => Self::Boolean(b.to_owned()),
            serde_json::Value::Number(n) => Self::String(n.to_string()),
            serde_json::Value::String(s) => Self::String(s.to_owned()),
            serde_json::Value::Array(a) => {
                Self::Array(a.iter().map(|i| i.into()).collect::<Vec<Self>>())
            }
            serde_json::Value::Object(o) => Self::Object(
                o.iter()
                    .map(|e| (e.0.to_owned(), e.1.into()))
                    .collect::<HashMap<String, Self>>(),
            ),
        }
    }
}

impl From<serde_json::Value> for JsonValue {
    fn from(value: serde_json::Value) -> Self {
        match value {
            serde_json::Value::Null => Self::Null,
            serde_json::Value::Bool(b) => Self::Boolean(b),
            serde_json::Value::Number(n) => Self::String(n.to_string()),
            serde_json::Value::String(s) => Self::String(s),
            serde_json::Value::Array(a) => {
                Self::Array(a.into_iter().map(|i| i.into()).collect::<Vec<Self>>())
            }
            serde_json::Value::Object(o) => Self::Object(
                o.into_iter()
                    .map(|e| (e.0.to_owned(), e.1.into()))
                    .collect::<HashMap<String, Self>>(),
            ),
        }
    }
}
