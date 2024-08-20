use crate::{
    common::Url,
    key_manager::KeyManager,
    storage_manager::{self, StorageManagerInterface},
    trust_manager::TrustManager,
    vdc_collection::{VdcCollection, VdcCollectionError},
};

use std::sync::Arc;

use anyhow::bail;
use oid4vp::{
    core::{
        authorization_request::{
            verification::{did::verify_with_resolver, RequestVerifier},
            AuthorizationRequestObject,
        },
        metadata::WalletMetadata,
    },
    presentation_exchange::{DescriptorMap, PresentationSubmission},
    wallet::Wallet as OID4VPWallet,
};

use ssi_dids::{DIDKey, VerificationMethodDIDResolver};
use ssi_verification_methods::AnyJwkMethod;
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
    #[error(transparent)]
    Storage(#[from] storage_manager::StorageManagerError),
    #[error(transparent)]
    VdcCollection(#[from] VdcCollectionError),
    #[error("Required credential not found for input descriptor id: {0}")]
    RequiredCredentialNotFound(String),
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
    vdc_collection: VdcCollection,
    trust_manager: TrustManager,
    key_manager: Box<dyn KeyManager>,
    storage_manager: Box<dyn StorageManagerInterface>,
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
    pub fn new(
        storage_manager: Box<dyn StorageManagerInterface>,
        key_manager: Box<dyn KeyManager>,
    ) -> Result<Arc<Self>, WalletError> {
        let client = oid4vp::core::util::ReqwestClient::new()
            .map_err(|e| WalletError::HttpClientInitialization(format!("{e}")))?;

        Ok(Arc::new(Self {
            client,
            // TODO: The wallet metadata should be retrieved from the device storage manager
            // or fallback to the default oid4vp scheme.
            // TODO: There should be an interface to support updated the wallet metadata
            // dynamically. Replace with MetadataManager once ready.
            metadata: WalletMetadata::openid4vp_scheme_static(),
            vdc_collection: VdcCollection::new(),
            trust_manager: TrustManager::new(),
            key_manager,
            storage_manager,
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

        // Check if the verifiable credential(s) exists in the storage.
        let credentials = presentation_definition
            .parsed()
            .input_descriptors()
            .iter()
            .map(|input_descriptor| {
                match self
                    .vdc_collection
                    .get(input_descriptor.id(), &self.storage_manager)
                {
                    Ok(Some(credential)) => Ok(Some(credential)),
                    Ok(None) => {
                        // Check if the input descriptor contains required constraints.
                        if input_descriptor.constraints().is_required() {
                            Err(WalletError::RequiredCredentialNotFound(
                                input_descriptor.id().to_string(),
                            ))
                        } else {
                            Ok(None)
                        }
                    }
                    Err(e) => Err(WalletError::VdcCollection(e)),
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Create a descriptor map for the presentation submission based on the credentials
        // returned from the VDC collection.
        let descriptor_map = credentials
            .into_iter()
            .enumerate()
            .filter_map(|(index, credential)| match credential {
                None => return None,
                // Only create descriptor maps for credentials that exist in the storage.
                Some(credential) => {
                    // Create a descriptor map for the presentation submission.
                    DescriptorMap::new(*credential.id(), credential.format().to_owned(), "$".into())
                        // TODO: Determine if the nested path should be set.
                        // For example:
                        .set_path_nested(DescriptorMap::new(
                            *credential.id(),
                            credential.format().to_owned(),
                            format!("$.vp.verifiableCredential[{index}]"),
                        ))
                        .ok()
                }
            })
            .collect::<Vec<DescriptorMap>>();

        // Create a presentation submission.
        let presentation_submission = PresentationSubmission::new(
            uuid::Uuid::new_v4(),
            presentation_definition.parsed().id().clone(),
            descriptor_map,
        );

        // Create a VP Token response.

        Ok(None)
    }
}

impl RequestVerifier for Wallet {
    fn did<'life0, 'life1, 'async_trait>(
        &'life0 self,
        decoded_request: &'life1 AuthorizationRequestObject,
        request_jwt: String,
    ) -> ::core::pin::Pin<
        Box<
            dyn ::core::future::Future<Output = anyhow::Result<(), anyhow::Error>>
                + ::core::marker::Send
                + 'async_trait,
        >,
    >
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: ::core::marker::Sync + 'async_trait,
    {
        let trusted_dids = self
            .trust_manager
            .get_trusted_dids(&self.storage_manager)
            .ok();

        let wallet_metadata = self.metadata.clone();

        let resolver: VerificationMethodDIDResolver<DIDKey, AnyJwkMethod> =
            VerificationMethodDIDResolver::new(DIDKey);

        Box::pin(async move {
            verify_with_resolver(
                &wallet_metadata,
                decoded_request,
                request_jwt,
                trusted_dids.as_ref().map(|did| did.as_slice()),
                resolver,
            )
            .await?;

            Ok(())
        })
    }
}

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
