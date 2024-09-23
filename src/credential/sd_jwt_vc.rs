use base64::prelude::*;
use ssi::{
    claims::{
        jwt::{AnyClaims, JWTClaims},
        sd_jwt::{RevealedSdJwt, SdJwtBuf},
        vc::{v1::Credential as _, v2::Credential as _},
        JwsString,
    },
    prelude::AnyJsonCredential,
};
use uuid::Uuid;

use crate::{CredentialType, KeyAlias};

use super::VcdmVersion;

#[derive(uniffi::Object, Debug, Clone)]
/// A verifiable credential secured as a JWT.
pub struct SdJwtVc {
    id: Uuid,
    sd_jwt: JwsString,
    credential: AnyJsonCredential,
    credential_string: String,
    header_json_string: String,
    payload_json_string: String,
    disclosures: Option<Vec<String>>,
    key_alias: Option<KeyAlias>,
}

#[uniffi::export]
impl SdJwtVc {
    /// The VdcCollection ID for this credential.
    pub fn id(&self) -> Uuid {
        self.id
    }

    /// The version of the Verifiable Credential Data Model that this credential conforms to.
    pub fn vcdm_version(&self) -> VcdmVersion {
        match &self.credential {
            ssi::claims::vc::AnySpecializedJsonCredential::V1(_) => VcdmVersion::V1,
            ssi::claims::vc::AnySpecializedJsonCredential::V2(_) => VcdmVersion::V2,
        }
    }

    /// The type of this credential. Note that if there is more than one type (i.e. `types()`
    /// returns more than one value), then the types will be concatenated with a "+".
    pub fn r#type(&self) -> CredentialType {
        CredentialType(self.types().join("+"))
    }

    /// The types of the credential from the VCDM, excluding the base `VerifiableCredential` type.
    pub fn types(&self) -> Vec<String> {
        match &self.credential {
            ssi::claims::vc::AnySpecializedJsonCredential::V1(vc) => vc.additional_types().to_vec(),
            ssi::claims::vc::AnySpecializedJsonCredential::V2(vc) => vc.additional_types().to_vec(),
        }
    }

    /// Access the W3C VCDM credential as a JSON encoded UTF-8 string.
    pub fn credential_as_json_encoded_utf8_string(&self) -> String {
        self.credential_string.clone()
    }

    /// Access the JWS header as a JSON encoded UTF-8 string.
    pub fn sd_jwt_header_as_json_encoded_utf8_string(&self) -> String {
        self.header_json_string.clone()
    }

    /// Access the JWS payload as a JSON encoded UTF-8 string.
    pub fn sd_jwt_payload_as_json_encoded_utf8_string(&self) -> String {
        self.payload_json_string.clone()
    }

    /// Access the revealed SD-JWT disclosures as a JSON encoded UTF-8 string.
    pub fn sd_jwt_disclosures_as_json_encoded_utf8_string(&self) -> Option<String> {
        self.disclosures
            .as_ref()
            .map(|disclosures| serde_json::to_string(disclosures).unwrap())
    }

    /// The keypair identified in the credential for use in a verifiable presentation.
    pub fn key_alias(&self) -> Option<KeyAlias> {
        self.key_alias.clone()
    }
}

#[uniffi::export]
impl SdJwtVc {
    pub(crate) fn to_compact_sd_jwt_bytes(&self) -> Vec<u8> {
        self.sd_jwt.as_bytes().to_vec()
    }
}

#[uniffi::export]
pub fn decode_reveal_sd_jwt(input: String) -> Result<String, SdJwtVcInitError> {
    let jwt: SdJwtBuf = SdJwtBuf::new(input).map_err(|_| SdJwtVcInitError::InvalidSdJwt)?;
    let revealed_jwt: RevealedSdJwt<AnyClaims> = jwt.decode_reveal_any().map_err(|_| SdJwtVcInitError::JwtDecoding)?;
    let claims: &JWTClaims = revealed_jwt.claims();
    serde_json::to_string(claims).map_err(|_| SdJwtVcInitError::Serialization)
}

#[uniffi::export]
pub fn convert_to_json_string(base64_encoded_bytes: &[u8]) -> Option<String> {
    String::from_utf8(BASE64_STANDARD_NO_PAD.decode(base64_encoded_bytes).ok()?).ok()
}

#[derive(Debug, uniffi::Error, thiserror::Error)]
pub enum SdJwtVcInitError {
    #[error("failed to decode string as an SD-JWT of the form <base64-encoded-header>.<base64-encoded-payload>.<base64-encoded-signature>")]
    CompactSdJwtDecoding,
    #[error("failed to decode claim 'vc' as a W3C VCDM v1 or v2 credential")]
    CredentialClaimDecoding,
    #[error("'vc' is missing from the SD-JWT claims")]
    CredentialClaimMissing,
    #[error("failed to encode the credential as a UTF-8 string")]
    CredentialStringEncoding,
    #[error("failed to decode SD-JWT bytes as UTF-8")]
    SdJwtBytesDecoding,
    #[error("failed to decode SD-JWT as a JWT")]
    JwtDecoding,
    #[error("failed to decode JWT header as base64-encoded JSON")]
    HeaderDecoding,
    #[error("failed to decode JWT payload as base64-encoded JSON")]
    PayloadDecoding,
    #[error("failed to extract concealed claims (disclosures) from SD-JWT")]
    DisclosureExtraction,
    #[error("failed to verify the integrity of the SD-JWT with the disclosed claims")]
    DisclosureVerification,
    #[error("failed to decode disclosures")]
    DisclosureDecoding,
    #[error("invalid SD-JWT")]
    InvalidSdJwt,
    #[error("serialization error")]
    Serialization,
}
