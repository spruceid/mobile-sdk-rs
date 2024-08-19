use crate::{common::Url, oid4vp::presentation_exchange::AuthorizationRequestObject};

use std::sync::Arc;

use oid4vp::{
    core::{authorization_request::verification::RequestVerifier, metadata::WalletMetadata},
    wallet::Wallet as OID4VPWallet,
};

use thiserror::Error;

/// The [WalletError] enum represents the errors that can occur
/// when working with the [Wallet] between foreign function interfaces.
#[derive(Error, Debug, uniffi::Error)]
pub enum WalletError {
    #[error("An unexpected foreign callback error occurred: {0}")]
    UnexpectedUniFFICallbackError(String),
    #[error("Failed to initialize HTTP client: {0}")]
    HttpClientInitialization(String),
    #[error("Failed to validate the OID4VP Request: {0}")]
    OID4VPRequestValidation(String),
    #[error("Failed to resolve the presentation definition: {0}")]
    OID4VPPresentationDefinitionResolution(String),
}

// Handle unexpected errors when calling a foreign callback
impl From<uniffi::UnexpectedUniFFICallbackError> for WalletError {
    fn from(value: uniffi::UnexpectedUniFFICallbackError) -> Self {
        WalletError::UnexpectedUniFFICallbackError(value.reason)
    }
}

/// The [Wallet](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-2-3.32) is used by the
/// Holder to receive, store, present, and manage
/// [Verifiable Credentials](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-2-3.4) and key material.
/// There is no single deployment model of a Wallet:
/// [Verifiable Credentials](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-2-3.4) and keys can
/// both be stored/managed locally, or by using a remote self-hosted service, or a remote third-party service.
///
/// In the context of the [OID4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) specification,
/// the Wallet acts as an OAuth 2.0 Authorization Server
/// (see [RFC6749](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#RFC6749))
/// towards the Credential Verifier which acts as the OAuth 2.0 Client.
///
/// # Example
///
/// ```
/// use mobile_sdk_rs::wallet::Wallet;
///
/// let wallet = Wallet::new().unwrap();
/// ```
#[derive(uniffi::Object)]
pub struct Wallet {
    client: oid4vp::core::util::ReqwestClient,
    metadata: WalletMetadata,
}

#[uniffi::export]
impl Wallet {
    /// Initialize a new [Wallet] instance.
    ///
    /// # Returns
    ///
    /// A new [Wallet] instance.
    ///
    /// # Errors
    ///
    /// If the HTTP client fails to initialize.
    #[uniffi::constructor]
    pub fn new() -> Result<Arc<Self>, WalletError> {
        let client = oid4vp::core::util::ReqwestClient::new()
            .map_err(|e| WalletError::HttpClientInitialization(format!("{e}")))?;

        Ok(Arc::new(Self {
            client,
            metadata: WalletMetadata::openid4vp_scheme_static(),
        }))
    }

    /// Handle an OID4VP authorization request provided as a URL.
    ///
    /// This method will validate the request, processing the presentation
    /// exchange request and response.
    pub async fn handle_oid4vp_request(&self, url: Url) -> Result<Option<Url>, WalletError> {
        let request_object = self
            .validate_request(url)
            .await
            .map_err(|e| WalletError::OID4VPRequestValidation(e.to_string()))?;

        // Resolve the presentation definition.
        let presentation_definition = request_object
            .resolve_presentation_definition(self.http_client())
            .await
            .map_err(|e| WalletError::OID4VPPresentationDefinitionResolution(e.to_string()))?;

        Ok(None)
    }
}

impl RequestVerifier for Wallet {}

impl OID4VPWallet for Wallet {
    type HttpClient = oid4vp::core::util::ReqwestClient;

    fn http_client(&self) -> &Self::HttpClient {
        &self.client
    }

    fn metadata(&self) -> &WalletMetadata {
        &self.metadata
    }
}

// /// The [Wallet] trait defines the presentation exchange
// /// methods a holder must implement to perform the presentation exchange
// /// in the oid4vp protocol.
// #[uniffi::export]
// #[async_trait::async_trait]
// pub trait Wallet: Send + Sync {
//     /// Handle an authorization request sent by a verifier.
//     async fn handle_authorization_request(
//         &self,
//         request: &AuthorizationRequest,
//     ) -> Result<(), OID4VPError> {
//         Ok(())
//     }
// }
