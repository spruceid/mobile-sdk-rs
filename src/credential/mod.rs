use std::sync::Arc;

use serde::{Deserialize, Serialize};

use json_vc::{JsonVc, JsonVcEncodingError, JsonVcInitError};
use jwt_vc::{JwtVc, JwtVcInitError};
use mdoc::{Mdoc, MdocEncodingError, MdocInitError};

use crate::{CredentialType, KeyAlias, Uuid};

pub mod json_vc;
pub mod jwt_vc;
pub mod mdoc;
pub mod sd_jwt_vc;

/// An unparsed credential, retrieved from storage.
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

/// A credential that has been parsed as a known variant.
#[derive(Debug, Clone, uniffi::Object)]
pub struct ParsedCredential {
    inner: ParsedCredentialInner,
}

/// A credential that has been parsed as a known variant.
#[derive(Debug, Clone)]
enum ParsedCredentialInner {
    MsoMdoc(Arc<Mdoc>),
    JwtVcJson(Arc<JwtVc>),
    JwtVcJsonLd(Arc<JwtVc>),
    LdpVc(Arc<JsonVc>),
    // More to come, for example:
    // SdJwt(...),
    // SdJwtJoseCose(...),
}

#[uniffi::export]
impl ParsedCredential {
    #[uniffi::constructor]
    /// Construct a new `mso_mdoc` credential.
    pub fn new_mso_mdoc(mdoc: Arc<Mdoc>) -> Arc<Self> {
        Arc::new(Self {
            inner: ParsedCredentialInner::MsoMdoc(mdoc),
        })
    }

    #[uniffi::constructor]
    /// Construct a new `jwt_vc_json` credential.
    pub fn new_jwt_vc_json(jwt_vc: Arc<JwtVc>) -> Arc<Self> {
        Arc::new(Self {
            inner: ParsedCredentialInner::JwtVcJson(jwt_vc),
        })
    }

    #[uniffi::constructor]
    /// Construct a new `jwt_vc_json-ld` credential.
    pub fn new_jwt_vc_json_ld(jwt_vc: Arc<JwtVc>) -> Arc<Self> {
        Arc::new(Self {
            inner: ParsedCredentialInner::JwtVcJsonLd(jwt_vc),
        })
    }

    #[uniffi::constructor]
    /// Construct a new `ldp_vc` credential.
    pub fn new_ldp_vc(json_vc: Arc<JsonVc>) -> Arc<Self> {
        Arc::new(Self {
            inner: ParsedCredentialInner::LdpVc(json_vc),
        })
    }

    #[uniffi::constructor]
    /// Parse a credential from the generic form retrieved from storage.
    pub fn parse_from_credential(
        credential: Credential,
    ) -> Result<Arc<Self>, CredentialDecodingError> {
        match credential.format {
            CredentialFormat::MsoMdoc => Ok(Self::new_mso_mdoc(credential.try_into()?)),
            CredentialFormat::JwtVcJson => Ok(Self::new_jwt_vc_json(credential.try_into()?)),
            CredentialFormat::JwtVcJsonLd => Ok(Self::new_jwt_vc_json_ld(credential.try_into()?)),
            CredentialFormat::LdpVc => Ok(Self::new_ldp_vc(credential.try_into()?)),
            _ => Err(CredentialDecodingError::UnsupportedCredentialFormat),
        }
    }

    /// Convert a parsed credential into the generic form for storage.
    pub fn into_generic_form(&self) -> Result<Credential, CredentialEncodingError> {
        match &self.inner {
            ParsedCredentialInner::MsoMdoc(mdoc) => Ok(mdoc.clone().try_into()?),
            ParsedCredentialInner::JwtVcJson(vc) => Ok(Credential {
                id: vc.id(),
                format: CredentialFormat::JwtVcJson,
                r#type: vc.r#type(),
                payload: vc.to_compact_jws_bytes(),
                key_alias: vc.key_alias(),
            }),
            ParsedCredentialInner::JwtVcJsonLd(vc) => Ok(Credential {
                id: vc.id(),
                format: CredentialFormat::JwtVcJsonLd,
                r#type: vc.r#type(),
                payload: vc.to_compact_jws_bytes(),
                key_alias: vc.key_alias(),
            }),
            ParsedCredentialInner::LdpVc(vc) => Ok(Credential {
                id: vc.id(),
                format: CredentialFormat::LdpVc,
                r#type: vc.r#type(),
                payload: vc.to_json_bytes()?,
                key_alias: vc.key_alias(),
            }),
        }
    }

    /// Get the local ID for this credential.
    pub fn id(&self) -> Uuid {
        match &self.inner {
            ParsedCredentialInner::MsoMdoc(arc) => arc.id(),
            ParsedCredentialInner::JwtVcJson(arc) => arc.id(),
            ParsedCredentialInner::JwtVcJsonLd(arc) => arc.id(),
            ParsedCredentialInner::LdpVc(arc) => arc.id(),
        }
    }

    /// Get the key alias for this credential.
    pub fn key_alias(&self) -> Option<KeyAlias> {
        match &self.inner {
            ParsedCredentialInner::MsoMdoc(arc) => Some(arc.key_alias()),
            ParsedCredentialInner::JwtVcJson(arc) => arc.key_alias(),
            ParsedCredentialInner::JwtVcJsonLd(arc) => arc.key_alias(),
            ParsedCredentialInner::LdpVc(arc) => arc.key_alias(),
        }
    }

    /// Return the credential as a JwtVc if it is of that format.
    pub fn as_jwt_vc(&self) -> Option<Arc<JwtVc>> {
        match &self.inner {
            ParsedCredentialInner::JwtVcJson(jwt_vc)
            | ParsedCredentialInner::JwtVcJsonLd(jwt_vc) => Some(jwt_vc.clone()),
            _ => None,
        }
    }

    /// Return the credential as a JsonVc if it is of that format.
    pub fn as_json_vc(&self) -> Option<Arc<JsonVc>> {
        match &self.inner {
            ParsedCredentialInner::LdpVc(ldp_vc) => Some(ldp_vc.clone()),
            _ => None,
        }
    }

    /// Return the credential as an Mdoc if it is of that format.
    pub fn as_mso_mdoc(&self) -> Option<Arc<Mdoc>> {
        match &self.inner {
            ParsedCredentialInner::MsoMdoc(mdoc) => Some(mdoc.clone()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, uniffi::Enum)]
pub enum VcdmVersion {
    V1,
    V2,
}

#[derive(Debug, uniffi::Error, thiserror::Error)]
pub enum CredentialEncodingError {
    #[error(transparent)]
    MsoMdoc(#[from] MdocEncodingError),
    #[error(transparent)]
    JsonVc(#[from] JsonVcEncodingError),
}

#[derive(Debug, uniffi::Error, thiserror::Error)]
pub enum CredentialDecodingError {
    #[error(transparent)]
    MsoMdoc(#[from] MdocInitError),
    #[error(transparent)]
    JsonVc(#[from] JsonVcInitError),
    #[error(transparent)]
    JwtVc(#[from] JwtVcInitError),
    #[error("this credential format is not yet supported")]
    UnsupportedCredentialFormat,
}

/// The format of the credential.
#[derive(uniffi::Enum, PartialEq, Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum CredentialFormat {
    MsoMdoc,
    JwtVcJson,
    #[serde(rename = "jwt_vc_json-ld")]
    JwtVcJsonLd,
    LdpVc,
    #[serde(untagged)]
    Other(String), // For ease of expansion.
}

#[cfg(test)]
mod test {
    use super::*;

    #[rstest::rstest]
    #[case::mso_mdoc(r#""mso_mdoc""#, CredentialFormat::MsoMdoc)]
    #[case::jwt_vc_json(r#""jwt_vc_json""#, CredentialFormat::JwtVcJson)]
    #[case::jwt_vc_json_ld(r#""jwt_vc_json-ld""#, CredentialFormat::JwtVcJsonLd)]
    #[case::ldp_vc(r#""ldp_vc""#, CredentialFormat::LdpVc)]
    #[case::other(r#""something_else""#, CredentialFormat::Other("something_else".into()))]
    fn credential_format_roundtrips(#[case] expected: String, #[case] value: CredentialFormat) {
        let serialized = serde_json::to_string(&value).unwrap();
        assert_eq!(expected, serialized);

        let roundtripped: CredentialFormat = serde_json::from_str(&serialized).unwrap();

        assert_eq!(value, roundtripped);
    }

    #[test]
    fn credential_format_roundtrips_other() {
        let value = CredentialFormat::Other("mso_mdoc".into());

        let serialized = serde_json::to_string(&value).unwrap();
        assert_eq!(r#""mso_mdoc""#, serialized);

        let roundtripped: CredentialFormat = serde_json::from_str(&serialized).unwrap();

        assert_eq!(CredentialFormat::MsoMdoc, roundtripped);
    }
}
