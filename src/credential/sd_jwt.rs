use super::{jwt_vc::JwtVc, Credential, CredentialFormat, ParsedCredential, ParsedCredentialInner};
use crate::{oid4vp::permission_request::RequestedField, CredentialType, KeyAlias};

use std::sync::Arc;

use openid4vp::core::presentation_definition::PresentationDefinition;
use ssi::{
    claims::{
        sd_jwt::SdJwtBuf,
        vc::v2::{Credential as _, JsonCredential},
        vc_jose_cose::SdJwtVc,
    },
    prelude::AnyJsonCredential,
};
use uniffi::deps::log;
use uuid::Uuid;

#[derive(Debug, uniffi::Object)]
pub struct SdJwt {
    pub(crate) id: Uuid,
    pub(crate) key_alias: Option<KeyAlias>,
    pub(crate) credential: JsonCredential,
    pub(crate) inner: SdJwtBuf,
}

// Internal utility methods for decoding a SdJwt.
impl SdJwt {
    /// Decode a SdJwt instance and return the revealed claims as a JSON value.
    pub fn decode_reveal_json(&self) -> Result<serde_json::Value, SdJwtError> {
        serde_json::to_value(&self.credential)
            .map_err(|e| SdJwtError::Serialization(format!("{e:?}")))
    }

    /// The types of the credential from the VCDM, excluding the base `VerifiableCredential` type.
    pub fn types(&self) -> Vec<String> {
        self.credential.additional_types().to_vec()
    }

    /// Returns the SD-JWT credential as an AnyCredential type.
    pub fn credential(&self) -> Result<AnyJsonCredential, SdJwtError> {
        // NOTE: Due to the type constraints on AnyJsonCredential, we're
        // reserializing the type into a V2 credential.
        serde_json::to_value(&self.credential)
            .map_err(|e| SdJwtError::Serialization(format!("{e:?}")))
            .and_then(|v| {
                serde_json::from_value(v).map_err(|e| SdJwtError::Serialization(format!("{e:?}")))
            })
    }

    /// Check if the credential satisfies a presentation definition.
    pub fn check_presentation_definition(&self, definition: &PresentationDefinition) -> bool {
        // If the credential does not match the definition requested format,
        // then return false.
        if !definition.format().is_empty()
            && !definition.contains_format(CredentialFormat::VCDM2SdJwt)
        {
            println!(
                "Credential does not match the requested format: {:?}.",
                definition.format()
            );

            return false;
        }

        let Ok(json) = serde_json::to_value(&self.credential) else {
            // NOTE: if we cannot convert the credential to a JSON value, then we cannot
            // check the presentation definition, so we return false.
            //
            // TODO: add logging to indicate that the credential could not be converted to JSON.
            return false;
        };

        // Check the JSON-encoded credential against the definition.
        definition.check_credential_validation(&json)
    }

    /// Return the requested fields for the SD-JWT credential.
    pub fn requested_fields(
        &self,
        definition: &PresentationDefinition,
    ) -> Vec<Arc<RequestedField>> {
        let Ok(json) = serde_json::to_value(&self.credential) else {
            // NOTE: if we cannot convert the credential to a JSON value, then we cannot
            // check the presentation definition, so we return false.
            log::debug!("credential could not be converted to JSON: {self:?}");
            return Vec::new();
        };

        definition
            .requested_fields_cred(&json)
            .into_iter()
            .map(Into::into)
            .map(Arc::new)
            .collect()
    }
}

#[uniffi::export]
impl SdJwt {
    /// Create a new SdJwt instance from a compact SD-JWS string.
    #[uniffi::constructor]
    pub fn new_from_compact_sd_jwt(input: String) -> Result<Arc<Self>, SdJwtError> {
        let inner: SdJwtBuf =
            SdJwtBuf::new(input).map_err(|e| SdJwtError::InvalidSdJwt(format!("{e:?}")))?;

        let mut sd_jwt = SdJwt::try_from(inner)?;
        sd_jwt.key_alias = None;

        Ok(Arc::new(sd_jwt))
    }

    /// Create a new SdJwt instance from a compact SD-JWS string with a provided key alias.
    #[uniffi::constructor]
    pub fn new_from_compact_sd_jwt_with_key(
        input: String,
        key_alias: KeyAlias,
    ) -> Result<Arc<Self>, SdJwtError> {
        let inner: SdJwtBuf =
            SdJwtBuf::new(input).map_err(|e| SdJwtError::InvalidSdJwt(format!("{e:?}")))?;

        let mut sd_jwt = SdJwt::try_from(inner)?;
        sd_jwt.key_alias = Some(key_alias);

        Ok(Arc::new(sd_jwt))
    }

    /// Return the ID for the SdJwt instance.
    pub fn id(&self) -> Uuid {
        self.id
    }

    /// Return the key alias for the credential
    pub fn key_alias(&self) -> Option<KeyAlias> {
        self.key_alias.clone()
    }

    /// The type of this credential. Note that if there is more than one type (i.e. `types()`
    /// returns more than one value), then the types will be concatenated with a "+".
    pub fn r#type(&self) -> CredentialType {
        CredentialType(self.types().join("+"))
    }

    /// Decode a SdJwt instance and return the revealed claims as a JSON string.
    pub fn decode_reveal_json_string(&self) -> Result<String, SdJwtError> {
        serde_json::to_string(&self.credential)
            .map_err(|e| SdJwtError::Serialization(format!("{e:?}")))
    }

    /// Return the SdJwt as a JwtVc instance.
    pub fn as_jwt_vc(self: Arc<Self>) -> Result<Arc<JwtVc>, SdJwtError> {
        JwtVc::from_compact_jws_bytes(
            self.id,
            self.inner.as_bytes().into(),
            self.key_alias.clone(),
        )
        .map_err(|e| SdJwtError::SdJwtVcInitError(format!("{e:?}")))
    }
}

impl From<SdJwt> for ParsedCredential {
    fn from(value: SdJwt) -> Self {
        ParsedCredential {
            inner: ParsedCredentialInner::SdJwt(Arc::new(value)),
        }
    }
}

impl TryFrom<SdJwt> for Credential {
    type Error = SdJwtError;

    fn try_from(value: SdJwt) -> Result<Self, Self::Error> {
        ParsedCredential::from(value)
            .into_generic_form()
            .map_err(|e| SdJwtError::CredentialEncoding(format!("{e:?}")))
    }
}

impl TryFrom<Arc<SdJwt>> for Credential {
    type Error = SdJwtError;

    fn try_from(value: Arc<SdJwt>) -> Result<Self, Self::Error> {
        ParsedCredential::new_sd_jwt(value)
            .into_generic_form()
            .map_err(|e| SdJwtError::CredentialEncoding(format!("{e:?}")))
    }
}

impl TryFrom<&Credential> for SdJwt {
    type Error = SdJwtError;

    fn try_from(value: &Credential) -> Result<SdJwt, SdJwtError> {
        let inner = SdJwtBuf::new(value.payload.clone())
            .map_err(|_| SdJwtError::InvalidSdJwt(Default::default()))?;

        let mut sd_jwt = SdJwt::try_from(inner)?;
        // Set the ID and key alias from the credential.
        sd_jwt.id = value.id;
        sd_jwt.key_alias = value.key_alias.clone();

        Ok(sd_jwt)
    }
}

impl TryFrom<Credential> for Arc<SdJwt> {
    type Error = SdJwtError;

    fn try_from(value: Credential) -> Result<Arc<SdJwt>, SdJwtError> {
        Ok(Arc::new(SdJwt::try_from(&value)?))
    }
}

impl TryFrom<SdJwtBuf> for SdJwt {
    type Error = SdJwtError;

    fn try_from(value: SdJwtBuf) -> Result<Self, Self::Error> {
        let SdJwtVc(vc) = SdJwtVc::decode_reveal_any(&value)
            .map_err(|e| SdJwtError::SdJwtDecoding(format!("{e:?}")))?
            .into_claims()
            .private;

        Ok(SdJwt {
            id: Uuid::new_v4(),
            key_alias: None,
            inner: value,
            credential: vc,
        })
    }
}

#[uniffi::export]
pub fn decode_reveal_sd_jwt(input: String) -> Result<String, SdJwtError> {
    let jwt: SdJwtBuf =
        SdJwtBuf::new(input).map_err(|e| SdJwtError::InvalidSdJwt(format!("{e:?}")))?;
    let SdJwtVc(vc) = SdJwtVc::decode_reveal_any(&jwt)
        .map_err(|e| SdJwtError::SdJwtDecoding(format!("{e:?}")))?
        .into_claims()
        .private;
    serde_json::to_string(&vc).map_err(|e| SdJwtError::Serialization(format!("{e:?}")))
}

#[derive(Debug, uniffi::Error, thiserror::Error)]
pub enum SdJwtError {
    #[error("failed to initialize SD-JWT: {0}")]
    SdJwtVcInitError(String),
    #[error("failed to decode SD-JWT as a JWT: {0}")]
    SdJwtDecoding(String),
    #[error("invalid SD-JWT: {0}")]
    InvalidSdJwt(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("failed to encode SD-JWT: {0}")]
    CredentialEncoding(String),
    #[error("'vc' is missing from the SD-JWT decoded claims")]
    CredentialClaimMissing,
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use ssi::{claims::sd_jwt::SdAlg, json_pointer, JWK};

    #[test]
    fn test_decode_static() {
        // Example SD-JWT input (you should replace this with a real SD-JWT string for a proper test)
        let sd_jwt_input = include_str!("../../tests/examples/sd_vc.jwt");

        // Call the function with the SD-JWT input
        let output =
            decode_reveal_sd_jwt(sd_jwt_input.to_string()).expect("failed to decode SD-JWT");

        // Check the output JSON string structure
        assert!(output.contains("\"sub\":\"1234567890\""));
        assert!(output.contains("\"awardedDate\":\"2024-09-23T18:12:12+0000\""));
    }

    pub async fn generate_sd_jwt() -> SdJwtBuf {
        // Define the key (this is a private key; for testing purposes you can use this inline or generate one)
        let jwk: JWK = JWK::generate_ed25519().expect("unable to generate sd-jwt");

        // Create the JWT claims
        let registeredclaims = serde_json::json!({"@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json"
          ],
          "awardedDate": "2024-09-23T18:12:12+0000",
          "credentialSubject": {
            "identity": [
              {
                "hashed": false,
                "identityHash": "John Smith",
                "identityType": "name",
                "salt": "not-used",
                "type": "IdentityObject"
              },
              {
                "hashed": false,
                "identityHash": "john.smith@example.com",
                "identityType": "emailAddress",
                "salt": "not-used",
                "type": "IdentityObject"
              }
            ],
            "achievement": {
              "name": "Team Membership",
              "type": "Achievement"
            }
          },
          "issuer": {
            "id": "did:jwk:eyJhbGciOiJFUzI1NiIsImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ4IjoibWJUM2dqOWFvOGNuS280M0prcVRPUmNJQVI4MFgwTUFXQWNGYzZvR1JMYyIsInkiOiJiOFVOY0hDMmFHQ3J1STZ0QlRWSVY0dW5ZWEVyS0M4ZDRnRTFGZ0s0Q05JIn0#0",
            "name": "Workforce Development Council",
            "type": "Profile"
          },
          "name": "TeamMembership",
          "type": ["VerifiableCredential", "OpenBadgeCredential"]
        });

        let claims: SdJwtVc = serde_json::from_value(registeredclaims).unwrap();
        let my_pointer = json_pointer!("/credentialSubject/identity/0");

        claims
            .conceal_and_sign(SdAlg::Sha256, &[my_pointer], &jwk)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_sd_jwt() -> Result<(), SdJwtError> {
        let input = generate_sd_jwt().await;

        assert!(SdJwt::new_from_compact_sd_jwt(input.to_string()).is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn test_decode_gen() -> Result<(), SdJwtError> {
        // Example SD-JWT input (you should replace this with a real SD-JWT string for a proper test)
        let sd_jwt_input = generate_sd_jwt().await;

        // Call the function with the SD-JWT input
        let output =
            decode_reveal_sd_jwt(sd_jwt_input.to_string()).expect("failed to decode SD-JWT");

        // Check the output JSON string structure
        assert!(output.contains("\"sub\":\"1234567890\""));
        assert!(output.contains("\"identityHash\":\"John Smith\""));

        Ok(())
    }
}
