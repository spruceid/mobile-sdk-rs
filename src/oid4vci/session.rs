use std::sync::Arc;

use futures::lock::Mutex;
use oid4vci::{
    core::{
        client, metadata,
        profiles::{self},
    },
    credential_offer::CredentialOfferGrants,
    profiles::CredentialConfigurationProfile,
    token,
};

use crate::credential::CredentialFormat;

use super::Oid4vciError;

#[derive(uniffi::Object)]
pub struct Oid4vciSession {
    client: Client,
    metadata: Option<CredentialIssuerMetadata>,
    token_response: Mutex<Option<TokenResponse>>,
    credential_request: Mutex<Option<CredentialRequest>>,
    grants: Mutex<Option<Grants>>,
}

// TODO: some or all of these getters/setters can be converted to macros
impl Oid4vciSession {
    pub fn new(client: Client) -> Self {
        Self {
            client,
            metadata: None,
            token_response: None.into(),
            credential_request: None.into(),
            grants: None.into(),
        }
    }

    pub fn get_client(&self) -> &client::Client {
        &self.client.0
    }

    pub fn get_metadata(&self) -> Result<&metadata::CredentialIssuerMetadata, Oid4vciError> {
        self.metadata
            .as_ref()
            .map(|w| &w.0)
            .ok_or(Oid4vciError::InvalidSession("metadata unset".into()))
    }

    pub fn set_metadata(&mut self, metadata: CredentialIssuerMetadata) {
        self.metadata = Some(metadata);
    }

    pub fn get_token_response(&self) -> Result<token::Response, Oid4vciError> {
        self.token_response
            .try_lock()
            .ok_or(Oid4vciError::LockError("token_response".into()))?
            .as_ref()
            .map(|w| w.0.clone())
            .ok_or(Oid4vciError::InvalidSession("token_response unset".into()))
    }

    pub fn set_token_response(&self, token_response: TokenResponse) -> Result<(), Oid4vciError> {
        *(self
            .token_response
            .try_lock()
            .ok_or(Oid4vciError::LockError("token_response".into()))?) = Some(token_response);

        Ok(())
    }

    pub fn get_credential_requests(
        &self,
    ) -> Result<Vec<profiles::CoreProfilesRequest>, Oid4vciError> {
        self.credential_request
            .try_lock()
            .ok_or(Oid4vciError::LockError("credential_request".into()))?
            .as_ref()
            .map(|w| w.0.clone())
            .ok_or(Oid4vciError::InvalidSession(
                "credential_request unset".into(),
            ))
    }

    pub fn set_credential_request(
        &self,
        credential_request: profiles::CoreProfilesRequest,
    ) -> Result<(), Oid4vciError> {
        *(self
            .credential_request
            .try_lock()
            .ok_or(Oid4vciError::LockError("credential_request".into()))?) =
            Some(vec![credential_request].into());

        Ok(())
    }

    pub fn set_credential_requests(
        &self,
        credential_requests: Vec<profiles::CoreProfilesRequest>,
    ) -> Result<(), Oid4vciError> {
        *(self
            .credential_request
            .try_lock()
            .ok_or(Oid4vciError::LockError("credential_request".into()))?) =
            Some(credential_requests.into());

        Ok(())
    }

    pub fn get_grants(&self) -> Result<CredentialOfferGrants, Oid4vciError> {
        self.grants
            .try_lock()
            .ok_or(Oid4vciError::LockError("grants".into()))?
            .as_ref()
            .map(|w| w.0.clone())
            .ok_or(Oid4vciError::InvalidSession("grants unset".into()))
    }

    pub fn set_grants(&self, grants: Option<CredentialOfferGrants>) -> Result<(), Oid4vciError> {
        *(self
            .grants
            .try_lock()
            .ok_or(Oid4vciError::LockError("grants".into()))?) = grants.map(|g| g.into());

        Ok(())
    }
}

macro_rules! wrap_external_type {
    ($wrap_me:ty, $as:ident) => {
        #[derive(uniffi::Object)]
        pub struct $as($wrap_me);
        impl From<$wrap_me> for $as {
            fn from(value: $wrap_me) -> $as {
                $as(value)
            }
        }
    };
}

wrap_external_type!(client::Client, Client);
wrap_external_type!(metadata::CredentialIssuerMetadata, CredentialIssuerMetadata);
wrap_external_type!(Vec<profiles::CoreProfilesRequest>, CredentialRequest);
wrap_external_type!(token::Response, TokenResponse);
wrap_external_type!(CredentialOfferGrants, Grants);

impl From<profiles::CoreProfilesRequest> for CredentialRequest {
    fn from(value: profiles::CoreProfilesRequest) -> Self {
        CredentialRequest(vec![value])
    }
}

#[derive(uniffi::Record)]
pub struct CredentialResponse {
    pub format: CredentialFormat,
    pub payload: Vec<u8>,
}

#[uniffi::export]
impl Oid4vciSession {
    pub fn get_all_credential_requests(&self) -> Result<Vec<Arc<CredentialRequest>>, Oid4vciError> {
        Ok(self
            .get_metadata()?
            .credential_configurations_supported()
            .iter()
            .map(|c| Arc::new(c.additional_fields().to_request().into()))
            .collect())
    }

    pub fn get_credential_request_by_index(
        &self,
        index: u16,
    ) -> Result<CredentialRequest, Oid4vciError> {
        Ok(self
            .get_metadata()?
            .credential_configurations_supported()
            .get(index as usize)
            .ok_or("invalid credential configuration index".to_string())
            .map_err(Oid4vciError::from)?
            .additional_fields()
            .to_request()
            .into())
    }
}
