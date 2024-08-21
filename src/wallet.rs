use crate::{
    common::Url,
    key_manager::{KeyManager, DEFAULT_KEY_INDEX, KEY_MANAGER_PREFIX},
    storage_manager::{self, Key, StorageManagerInterface},
    trust_manager::TrustManager,
    vdc_collection::{Credential, VdcCollection, VdcCollectionError},
};

use std::sync::Arc;

use anyhow::Result;
use oid4vp::{
    core::{
        authorization_request::{
            parameters::PresentationDefinition,
            verification::{did::verify_with_resolver, RequestVerifier},
            AuthorizationRequestObject,
        },
        metadata::WalletMetadata,
        response::{parameters::VpToken, AuthorizationResponse, UnencodedAuthorizationResponse},
    },
    presentation_exchange::{ClaimFormatDesignation, DescriptorMap, PresentationSubmission},
    wallet::Wallet as OID4VPWallet,
};
use serde_json::json;
use ssi_dids::DIDMethod;
use ssi_vc::{LinkedDataProofOptions, Presentation, URI};
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
    #[error("Key not found for ID: {0}")]
    KeyNotFound(String),
    #[error("Failed to deserialize JSON: {0}")]
    Deserialization(String),
    #[error("Failed to submit OID4VP response: {0}")]
    OID4VPResponseSubmission(String),
    #[error("Failed to create presentation submission: {0}")]
    PresentationSubmissionCreation(String),
    #[error("Failed to create presentation: {0}")]
    VerifiablePresentation(String),
    #[error("Failed to create JWT: {0}")]
    GenerateJwt(String),
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
            // TODO: There should be an interface to support updating the wallet metadata
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
        let request = self
            .validate_request(url)
            .await
            .map_err(|e| WalletError::OID4VPRequestValidation(e.to_string()))?;

        // Resolve the presentation definition.
        let presentation_definition = request
            .resolve_presentation_definition(self.http_client())
            .await
            .map_err(|e| WalletError::OID4VPPresentationDefinitionResolution(e.to_string()))?;

        // TODO: Handle request using a selected key index.
        let key_index = None;

        // Create an unencoded authorization response.
        let response = self
            .create_unencoded_authorization_response(presentation_definition, key_index)
            .await?;

        self.submit_response(request, AuthorizationResponse::Unencoded(response))
            .await
            .map_err(|e| WalletError::OID4VPResponseSubmission(e.to_string()))
    }

    /// Returns the JWK DID of the wallet's public JWK encoded key.
    ///
    /// An optional `key_index` can be provided to specify the key index to use.
    /// If no `key_index` is provided, the default key index (i.e. `0`) is used.
    pub fn jwk_did(&self, key_index: Option<u8>) -> Result<String, WalletError> {
        let key_id = key_index
            .map(|index| Key::with_prefix(KEY_MANAGER_PREFIX, &format!("{index}")))
            // Use a default key id if no did_key is provided.
            .unwrap_or(Key::with_prefix(
                KEY_MANAGER_PREFIX,
                &format!("{DEFAULT_KEY_INDEX}"),
            ));

        let did_key = self
            .key_manager
            .get_jwk(key_id.clone())
            .map(|jwk| serde_json::from_str(&jwk))
            .transpose()
            .map_err(|e| WalletError::Deserialization(e.to_string()))?
            .map(|jwk| DIDJWK::generate(&jwk))
            .ok_or(WalletError::KeyNotFound(key_id.into()))?;

        Ok(did_key.to_string())
    }

    /// Returns the verification method of the wallet's public JWK encoded key.
    pub fn jwk_verification_method(&self, key_index: Option<u8>) -> Result<String, WalletError> {
        let did_key = self.jwk_did(key_index)?;
        let index = key_index.unwrap_or(DEFAULT_KEY_INDEX);
        Ok(format!("{}#{}", did_key, index))
    }
}

// Internal Wallet Methods for OID4VP
impl Wallet {
    /// Retrieves the credentials from the wallet
    /// storage based on the presentation definition.
    fn retrieve_credentials(
        &self,
        presentation_definition: &PresentationDefinition,
    ) -> Result<Vec<Option<Credential>>, WalletError> {
        presentation_definition
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
            .collect::<Result<Vec<_>, _>>()
    }

    // Construct a DescriptorMap for the presentation submission based on the
    // credentials returned from the VDC collection.
    fn create_descriptor_maps(
        &self,
        credentials: Vec<Option<Credential>>,
    ) -> Vec<(DescriptorMap, Credential)> {
        credentials
            .into_iter()
            // Filter out the credentials that are not found in the storage.
            .filter_map(|credential| credential)
            // Enumerate over the existing credentials to create a descriptor map.
            .enumerate()
            .map(|(index, credential)| {
                (
                    DescriptorMap::new(
                        *credential.id(),
                        ClaimFormatDesignation::JwtVpJson,
                        "$.vp".into(),
                    )
                    // TODO: Determine if the nested path should be set.
                    // For example: `$.vc` or `$.verifiableCredential`
                    .set_path_nested(DescriptorMap::new(
                        *credential.id(),
                        credential.format().to_owned(),
                        // NOTE: The path is set to the index of the credential
                        // in the presentation submission.
                        format!("$.verifiableCredential[{index}]"),
                    )),
                    // Return the credential for the presentation submission.
                    // This is used to construct the `verifiableCredentials` array
                    // in the presentation submission. The index position
                    // of the credential in the array must match the index position
                    // of the descriptor in the descriptor map.
                    credential,
                )
            })
            .collect::<Vec<(DescriptorMap, Credential)>>()
    }

    // Internal method for creating a verifiable presentation object.
    async fn create_unencoded_authorization_response(
        &self,
        presentation_definition: PresentationDefinition,
        key_index: Option<u8>,
    ) -> Result<UnencodedAuthorizationResponse, WalletError> {
        let presentation_submission_id = uuid::Uuid::new_v4();
        let presentation_definition_id = presentation_definition.parsed().id().clone();

        // Check if the verifiable credential(s) exists in the storage.
        let credentials = self.retrieve_credentials(&presentation_definition)?;

        // Create a descriptor map for the presentation submission based on the credentials
        // returned from the VDC collection.
        //
        // NOTE: The order of the descriptor map is important as the index of the descriptor
        // in the presentation submission must match the index of the credential in the
        // presentation submission.
        //
        // For example, when adding to the `verifiableCredentials` array in the presentation
        // submission, the order of the credentials must match the order of the descriptors
        // in the descriptor map where there paths are index-based.
        let credential_descriptor_map = self.create_descriptor_maps(credentials);

        // Create a presentation submission.
        let presentation_submission = PresentationSubmission::new(
            presentation_submission_id,
            presentation_definition_id,
            // Use the descriptor map to create the submission.
            credential_descriptor_map
                .iter()
                .map(|(descriptor, _)| descriptor.clone())
                .collect(),
        )
        .try_into()
        .map_err(|e: anyhow::Error| WalletError::PresentationSubmissionCreation(e.to_string()))?;

        let vp_token = self
            .create_verifiable_presentation_jwt(credential_descriptor_map, key_index)
            .await?;

        // Create a verifiable presentation object.
        Ok(UnencodedAuthorizationResponse(
            Default::default(),
            VpToken(vp_token),
            presentation_submission,
        ))
    }

    // Internation method for creating a verifiable presentation JWT.
    async fn create_verifiable_presentation_jwt(
        &self,
        credential_descriptor_map: Vec<(DescriptorMap, Credential)>,
        key_index: Option<u8>,
    ) -> Result<String, WalletError> {
        let verifiable_credential = credential_descriptor_map
            .into_iter()
            .map(|(_, credential)| credential)
            .collect::<Vec<Credential>>();

        let vp_json = json!({
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1"
            ],
            "type": [
                "VerifiablePresentation"
            ],
            "verifiableCredential": verifiable_credential
        });

        let vp: Presentation = serde_json::from_value(vp_json)
            .map_err(|e| WalletError::VerifiablePresentation(e.to_string()))?;

        let ldp_options = self.new_linked_data_proof_options(key_index)?;

        // Constuct unsigned JWT, then sign it with the key manager.
        let unsigned_jwt_vp = vp
            .generate_jwt(None, &ldp_options, did_jwk::DIDJWK.to_resolver())
            .await
            .map_err(|e| WalletError::GenerateJwt(e.to_string()))?;

        unimplemented!()
    }

    // Internal method for creating new linked data proof options.
    //
    // This method is not intended to be used by external callers.
    fn new_linked_data_proof_options(
        &self,
        key_index: Option<u8>,
    ) -> Result<LinkedDataProofOptions, WalletError> {
        Ok(LinkedDataProofOptions {
            verification_method: self
                .jwk_verification_method(key_index)
                .ok()
                .map(|vm| URI::String(vm)),
            // NOTE: The ldp options are defaulted for the user
            // to override if needed.
            ..LinkedDataProofOptions::default()
        })
    }
}

#[async_trait::async_trait]
impl RequestVerifier for Wallet {
    /// Performs verification on Authorization Request Objects when `client_id_scheme` is `did`.
    async fn did(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> Result<()> {
        let trusted_dids = self
            .trust_manager
            .get_trusted_dids(&self.storage_manager)
            .ok();

        let wallet_metadata = self.metadata.clone();

        verify_with_resolver(
            &wallet_metadata,
            decoded_request,
            request_jwt,
            trusted_dids.as_ref().map(|did| did.as_slice()),
            DIDKey.to_resolver(),
        )
        .await?;

        Ok(())
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
