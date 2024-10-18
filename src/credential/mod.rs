pub mod json_vc;
pub mod jwt_vc;
pub mod mdoc;
pub mod sd_jwt;

use std::sync::Arc;

use crate::{oid4vp::permission_request::RequestedField, CredentialType, KeyAlias, Uuid};
use json_vc::{JsonVc, JsonVcEncodingError, JsonVcInitError};
use jwt_vc::{JwtVc, JwtVcInitError};
use mdoc::{Mdoc, MdocEncodingError, MdocInitError};
use openid4vp::core::{
    credential_format::ClaimFormatDesignation, presentation_definition::PresentationDefinition,
};
use sd_jwt::{SdJwt, SdJwtError};
use serde::{Deserialize, Serialize};

/// An unparsed credential, retrieved from storage.
#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
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

// #[uniffi::export]
// impl Credential {
//     /// Create a new credential.
//     #[uniffi::constructor]
//     pub fn new(
//         id: Uuid,
//         format: CredentialFormat,
//         r#type: CredentialType,
//         payload: Vec<u8>,
//         key_alias: Option<KeyAlias>,
//     ) -> Arc<Self> {
//         Arc::new(Self {
//             id,
//             format,
//             r#type,
//             payload,
//             key_alias,
//         })
//     }

//     /// Return the ID of the credential.
//     pub fn id(&self) -> Uuid {
//         self.id
//     }

//     /// Return the format of the credential.
//     pub fn format(&self) -> CredentialFormat {
//         self.format.clone()
//     }

//     /// Return the type of the credential.
//     pub fn r#type(&self) -> CredentialType {
//         self.r#type.clone()
//     }

//     /// Return the raw payload of the credential.
//     pub fn payload(&self) -> Vec<u8> {
//         self.payload.clone()
//     }
// }

// Internal helper methods.
impl Credential {
    /// Convert the parsed credential into a specialized JSON credential.
    pub fn try_into_parsed(&self) -> Result<Arc<ParsedCredential>, CredentialDecodingError> {
        self.to_owned().try_into()
    }
}

/// A credential that has been parsed as a known variant.
#[derive(Debug, Clone, uniffi::Object)]
pub struct ParsedCredential {
    pub(crate) inner: ParsedCredentialInner,
}

/// A credential that has been parsed as a known variant.
#[derive(Debug, Clone)]
pub(crate) enum ParsedCredentialInner {
    MsoMdoc(Arc<Mdoc>),
    JwtVcJson(Arc<JwtVc>),
    JwtVcJsonLd(Arc<JwtVc>),
    SdJwt(Arc<SdJwt>),
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
    /// Construct a new `sd_jwt_vc` credential.
    pub fn new_sd_jwt(sd_jwt_vc: Arc<SdJwt>) -> Arc<Self> {
        Arc::new(Self {
            inner: ParsedCredentialInner::SdJwt(sd_jwt_vc),
        })
    }

    #[uniffi::constructor]
    /// Parse a credential from the generic form retrieved from storage.
    pub fn parse_from_credential(
        credential: Credential,
    ) -> Result<Arc<Self>, CredentialDecodingError> {
        // NOTE: due to the Arc<Credential> type needed in the constructor,
        // given the uniffi::Object trait, we need to have an inner reference
        // to the credential that provided the type conversion, which avoids the
        // TryFrom<Arc<Credential>> that cannot be implemented given the compiler
        // constraints on foreign types.
        credential.try_into_parsed()
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
            ParsedCredentialInner::SdJwt(sd_jwt) => Ok(Credential {
                id: sd_jwt.id(),
                format: CredentialFormat::VCDM2SdJwt,
                r#type: sd_jwt.r#type(),
                payload: sd_jwt.inner.as_bytes().into(),
                key_alias: sd_jwt.key_alias(),
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

    /// Return the format of the credential.
    pub fn format(&self) -> CredentialFormat {
        match &self.inner {
            ParsedCredentialInner::MsoMdoc(_) => CredentialFormat::MsoMdoc,
            ParsedCredentialInner::JwtVcJson(_) => CredentialFormat::JwtVcJson,
            ParsedCredentialInner::JwtVcJsonLd(_) => CredentialFormat::JwtVcJsonLd,
            ParsedCredentialInner::SdJwt(_) => CredentialFormat::VCDM2SdJwt,
            ParsedCredentialInner::LdpVc(_) => CredentialFormat::LdpVc,
        }
    }

    /// Get the local ID for this credential.
    pub fn id(&self) -> Uuid {
        match &self.inner {
            ParsedCredentialInner::MsoMdoc(arc) => arc.id(),
            ParsedCredentialInner::JwtVcJson(arc) => arc.id(),
            ParsedCredentialInner::JwtVcJsonLd(arc) => arc.id(),
            ParsedCredentialInner::LdpVc(arc) => arc.id(),
            ParsedCredentialInner::SdJwt(arc) => arc.id(),
        }
    }

    /// Get the key alias for this credential.
    pub fn key_alias(&self) -> Option<KeyAlias> {
        match &self.inner {
            ParsedCredentialInner::MsoMdoc(arc) => Some(arc.key_alias()),
            ParsedCredentialInner::JwtVcJson(arc) => arc.key_alias(),
            ParsedCredentialInner::JwtVcJsonLd(arc) => arc.key_alias(),
            ParsedCredentialInner::LdpVc(arc) => arc.key_alias(),
            ParsedCredentialInner::SdJwt(arc) => arc.key_alias(),
        }
    }

    /// Return the CredentialType from the parsed credential.
    pub fn r#type(&self) -> CredentialType {
        match &self.inner {
            ParsedCredentialInner::MsoMdoc(arc) => CredentialType(arc.doctype()),
            ParsedCredentialInner::JwtVcJson(arc) => arc.r#type(),
            ParsedCredentialInner::JwtVcJsonLd(arc) => arc.r#type(),
            ParsedCredentialInner::LdpVc(arc) => arc.r#type(),
            ParsedCredentialInner::SdJwt(arc) => arc.r#type(),
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

    /// Return the credential as an SD-JWT, if it is of that format.
    pub fn as_sd_jwt(&self) -> Option<Arc<SdJwt>> {
        match &self.inner {
            ParsedCredentialInner::SdJwt(sd_jwt) => Some(sd_jwt.clone()),
            _ => None,
        }
    }
}

// Intneral Parsed Credential methods
impl ParsedCredential {
    /// Check if the credential satisfies a presentation definition.
    pub fn check_presentation_definition(&self, definition: &PresentationDefinition) -> bool {
        match &self.inner {
            ParsedCredentialInner::JwtVcJson(vc) => vc.check_presentation_definition(definition),
            ParsedCredentialInner::JwtVcJsonLd(vc) => vc.check_presentation_definition(definition),
            ParsedCredentialInner::LdpVc(vc) => vc.check_presentation_definition(definition),
            ParsedCredentialInner::SdJwt(sd_jwt) => {
                sd_jwt.check_presentation_definition(definition)
            }
            ParsedCredentialInner::MsoMdoc(_mdoc) => false,
        }
    }

    /// Return the requested fields for the credential, accordinging to the presentation definition.
    pub fn requested_fields(
        &self,
        definition: &PresentationDefinition,
    ) -> Vec<Arc<RequestedField>> {
        match &self.inner {
            ParsedCredentialInner::SdJwt(sd_jwt) => sd_jwt.requested_fields(definition),
            ParsedCredentialInner::JwtVcJson(vc) => vc.requested_fields(definition),
            ParsedCredentialInner::JwtVcJsonLd(vc) => vc.requested_fields(definition),
            ParsedCredentialInner::LdpVc(vc) => vc.requested_fields(definition),
            ParsedCredentialInner::MsoMdoc(_mdoc) => {
                unimplemented!("Mdoc requested fields not implemented")
            }
        }
    }
}

impl TryFrom<Credential> for Arc<ParsedCredential> {
    type Error = CredentialDecodingError;

    fn try_from(credential: Credential) -> Result<Self, Self::Error> {
        match credential.format {
            CredentialFormat::MsoMdoc => Ok(ParsedCredential::new_mso_mdoc(credential.try_into()?)),
            CredentialFormat::JwtVcJson => {
                Ok(ParsedCredential::new_jwt_vc_json(credential.try_into()?))
            }
            CredentialFormat::JwtVcJsonLd => {
                Ok(ParsedCredential::new_jwt_vc_json_ld(credential.try_into()?))
            }
            CredentialFormat::VCDM2SdJwt => {
                Ok(ParsedCredential::new_sd_jwt(credential.try_into()?))
            }
            CredentialFormat::LdpVc => Ok(ParsedCredential::new_ldp_vc(credential.try_into()?)),
            _ => Err(CredentialDecodingError::UnsupportedCredentialFormat(
                credential.format.to_string(),
            )),
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
    #[error("MsoDoc encoding error: {0}")]
    MsoMdoc(#[from] MdocEncodingError),
    #[error("JsonVc encoding error: {0}")]
    JsonVc(#[from] JsonVcEncodingError),
    #[error("SD-JWT encoding error: {0}")]
    SdJwt(#[from] SdJwtError),
}

#[derive(Debug, uniffi::Error, thiserror::Error)]
pub enum CredentialDecodingError {
    #[error("MsoDoc decoding error: {0}")]
    MsoMdoc(#[from] MdocInitError),
    #[error("JsonVc decoding error: {0}")]
    JsonVc(#[from] JsonVcInitError),
    #[error("JWT VC decoding error: {0}")]
    JwtVc(#[from] JwtVcInitError),
    #[error("SD JWT VC decoding error: {0}")]
    SdJwt(#[from] SdJwtError),
    #[error("Credential format is not yet supported for type: {0}")]
    UnsupportedCredentialFormat(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Deserialization error: {0}")]
    Deserialization(String),
}

#[derive(Debug, uniffi::Error, thiserror::Error)]
pub enum CredentialPresentationError {
    #[error("Credential decoding error: {0}")]
    Decoding(String),
    #[error("JSON path selector error: {0}")]
    JsonPath(String),
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
    #[serde(rename = "vcdm2_sd_jwt")]
    VCDM2SdJwt,
    #[serde(untagged)]
    Other(String), // For ease of expansion.
}

impl From<CredentialFormat> for ClaimFormatDesignation {
    fn from(value: CredentialFormat) -> Self {
        match value {
            CredentialFormat::MsoMdoc => ClaimFormatDesignation::MsoMDoc,
            CredentialFormat::JwtVcJson => ClaimFormatDesignation::JwtVcJson,
            CredentialFormat::VCDM2SdJwt | CredentialFormat::JwtVcJsonLd => {
                ClaimFormatDesignation::Other(value.to_string())
            }
            CredentialFormat::LdpVc => ClaimFormatDesignation::LdpVc,
            CredentialFormat::Other(s) => ClaimFormatDesignation::Other(s.to_owned()),
        }
    }
}

impl std::fmt::Display for CredentialFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredentialFormat::MsoMdoc => write!(f, "mso_mdoc"),
            CredentialFormat::JwtVcJson => write!(f, "jwt_vc_json"),
            CredentialFormat::JwtVcJsonLd => write!(f, "jwt_vc_json-ld"),
            CredentialFormat::LdpVc => write!(f, "ldp_vc"),
            CredentialFormat::VCDM2SdJwt => write!(f, "vcdm2_sd_jwt"),
            CredentialFormat::Other(s) => write!(f, "{s}"),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[rstest::rstest]
    #[case::mso_mdoc(r#""mso_mdoc""#, CredentialFormat::MsoMdoc)]
    #[case::jwt_vc_json(r#""jwt_vc_json""#, CredentialFormat::JwtVcJson)]
    #[case::jwt_vc_json_ld(r#""jwt_vc_json-ld""#, CredentialFormat::JwtVcJsonLd)]
    #[case::ldp_vc(r#""ldp_vc""#, CredentialFormat::LdpVc)]
    #[case::ldp_vc(r#""vcdm2_sd_jwt""#, CredentialFormat::VCDM2SdJwt)]
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
