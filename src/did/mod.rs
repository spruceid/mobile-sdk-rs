use ssi::dids::DIDResolver;

mod error;

pub use error::*;

#[derive(uniffi::Enum)]
pub enum DidMethod {
    Jwk,
    Key,
}

impl DidMethod {
    pub fn did_from_jwk(&self, jwk: &str) -> Result<String, DidError> {
        let key: ssi::jwk::JWK = serde_json::from_str(jwk)?;
        let did = match &self {
            DidMethod::Jwk => ssi::dids::DIDJWK::generate(&key),
            DidMethod::Key => ssi::dids::DIDKey::generate(&key)?,
        };
        Ok(did.to_string())
    }

    pub async fn vm_from_jwk(&self, jwk: &str) -> Result<String, DidError> {
        let key: ssi::jwk::JWK = serde_json::from_str(jwk)?;
        let vm = match &self {
            DidMethod::Jwk => {
                let did = ssi::dids::DIDJWK::generate(&key);
                ssi::dids::DIDJWK
                    .resolve_into_any_verification_method(did.as_did())
                    .await?
                    // There will always be a verification method in `did:jwk`
                    .ok_or(DidError::MissingVerificationMethod)
            }
            DidMethod::Key => {
                let did = ssi::dids::DIDKey::generate(&key)?;
                ssi::dids::DIDKey
                    .resolve_into_any_verification_method(did.as_did())
                    .await?
                    // There will always be a verification method in `did:key`
                    .ok_or(DidError::MissingVerificationMethod)
            }
        }?;
        Ok(vm.id.to_string())
    }
}
