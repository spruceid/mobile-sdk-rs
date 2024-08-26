use crate::{
    common::{Key, Url},
    credentials_callback::{CredentialCallbackError, CredentialCallbackInterface},
    key_manager::{KeyManagerError, KeyManagerInterface, DEFAULT_KEY_INDEX, KEY_MANAGER_PREFIX},
    // metadata_manager::{MetadataManager, MetadataManagerError},
    storage_manager::{self, StorageManagerInterface},
    // trust_manager::TrustManager,
    vdc_collection::{Credential, VdcCollection, VdcCollectionError},
};

use std::sync::{Arc, RwLock};

use anyhow::{bail, Result};
use oid4vp::{
    core::{authorization_request::parameters::ResponseMode, metadata::WalletMetadata},
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
    #[error(transparent)]
    Storage(#[from] storage_manager::StorageManagerError),
    #[error(transparent)]
    VdcCollection(#[from] VdcCollectionError),
    // #[error(transparent)]
    // MetadataManager(#[from] MetadataManagerError),
    #[error(transparent)]
    KeyManager(#[from] KeyManagerError),
    #[error("Required credential not found for input descriptor id: {0}")]
    RequiredCredentialNotFound(String),
    #[error("Key not found for index: {0}")]
    KeyNotFound(u8),
    #[error("Failed to deserialize JSON: {0}")]
    Deserialization(String),
    #[error("Serde JSON Error: {0}")]
    SerdeJson(String),
    #[error("Failed to submit OID4VP response: {0}")]
    OID4VPResponseSubmission(String),
    #[error("Failed to create presentation submission: {0}")]
    PresentationSubmissionCreation(String),
    #[error("Failed to create presentation: {0}")]
    VerifiablePresentation(String),
    #[error("Failed to create JWT: {0}")]
    GenerateJwt(String),
    #[error("Failed to acquire read/write lock for active key index: {0}")]
    ActiveKeyIndexReadWriteError(String),
    #[error("Failed to parse JSON encoded JWK: {0}")]
    JWKParseError(String),
    #[error("Failed to generate DID Key from JWK: {0}")]
    DIDKeyGenerateUrl(String),
    #[error("Invalid DID URL: {0}")]
    InvalidDIDUrl(String),
    #[error("Unsupported Response Mode for OID4VP Request: {0}")]
    OID4VPUnsupportedResponseMode(String),
    #[error("Signing Algorithm Not Found: {0}")]
    SigningAlgorithmNotFound(String),
    #[error("Failed to sign JWT: {0}")]
    SigningError(String),
    #[error("Failed to save reference to credential.")]
    InvalidCredentialReference,
    #[error(transparent)]
    CredentialCallback(#[from] CredentialCallbackError),
    #[error("Unknown error occurred.")]
    Unknown,
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
#[derive(uniffi::Object, Debug)]
pub struct Wallet {
    pub(crate) client: oid4vp::core::util::ReqwestClient,
    pub(crate) metadata: WalletMetadata,
    // TODO: Use `MetadataManager` once merged.
    // pub(crate) metadata: MetadataManager,
    pub(crate) vdc_collection: VdcCollection,
    // NOTE: The wallet has internal access to the trust manager APIs, but
    // is currently not exposing them to the foreign function interface.
    // This is because the trust manager is intended to be used internally by the wallet.
    // The [TrustManager] does not implement uniffi bindings.
    // pub(crate) trust_manager: TrustManager,
    // TODO: Use the `TrustManager` once merged.
    pub(crate) trust_manager: Vec<String>,
    pub(crate) key_manager: Arc<dyn KeyManagerInterface>,
    pub(crate) storage_manager: Arc<dyn StorageManagerInterface>,
    // // The active key index is used to determine which key to used for signing.
    // // By default, this is set to the 0-index key.
    // pub(crate) active_key_index: Arc<RwLock<u8>>,
}

#[uniffi::export]
impl Wallet {
    /// Initialize a new [Wallet] instance provides a storage manager and key manager.
    ///
    /// The storage and key managers are foreign callback interfaces that are implemented
    /// in the native language of the foreign environment, e.g. Kotlin, Swift, etc.
    ///
    /// # Arguments
    ///
    /// * `storage_manager` - A foreign callback interface that implements the [StorageManagerInterface].
    ///
    /// * `key_manager` - A foreign callback interface that implements the [KeyManagerInterface].
    ///
    /// # Returns
    ///
    /// A new [Wallet] instance.
    ///
    /// # Errors
    ///
    /// * If the HTTP client fails to initialize;
    /// * If there is a storage error when initializing the metadata manager.
    #[uniffi::constructor]
    pub fn new(
        storage_manager: Arc<dyn StorageManagerInterface>,
        key_manager: Arc<dyn KeyManagerInterface>,
    ) -> Result<Arc<Self>, WalletError> {
        let client = oid4vp::core::util::ReqwestClient::new()
            .map_err(|e| WalletError::HttpClientInitialization(format!("{e}")))?;

        // Initalized the metdata manager with the device storage.
        // This will load any existing metadata from storage, otherwise
        // it will create a new metadata instance.
        // let metadata = MetadataManager::initialize(&storage_manager)?;

        Ok(Arc::new(Self {
            client,
            // TODO: Replace with `MetadataManager` once merged.
            metadata: WalletMetadata::openid4vp_scheme_static(),
            key_manager,
            storage_manager,
            vdc_collection: VdcCollection::new(),
            trust_manager: Vec::new(),
            // trust_manager: TrustManager::new(),
            // TODO: Remove the key should be determined by the
            // requested credential to be presented.
            // active_key_index: Arc::new(RwLock::new(DEFAULT_KEY_INDEX)),
        }))
    }

    /// Add a credential to the wallet.
    ///
    /// This method will add a verifiable credential to the wallet.
    pub fn add_credential(&self, credential: Arc<Credential>) -> Result<Key, WalletError> {
        // NOTE: This will fail if there is more than one strong reference to the credential.
        let credential =
            Arc::into_inner(credential).ok_or(WalletError::InvalidCredentialReference)?;

        self.vdc_collection
            .add(credential, &self.storage_manager)
            .map_err(Into::into)
    }

    /// Handle an OID4VP authorization request provided as a URL.
    ///
    /// This method will validate and process the request, returning a
    /// redirect URL with the encoded verifiable presentation token,
    /// if the presentation exchange was successful.
    ///
    /// If the request is invalid or cannot be processed, an error will be returned.
    ///
    /// # Arguments
    ///
    /// * `url` - The URL containing the OID4VP authorization request.
    ///
    /// # Returns
    ///
    /// An optional URL containing the OID4VP response.
    ///
    /// # Errors
    ///
    /// * If the request is invalid;
    /// * If the response mode is not supported;
    /// * If the response submission fails.
    ///
    pub async fn handle_oid4vp_request(
        &self,
        url: Url,
        callback: &Box<dyn CredentialCallbackInterface>,
    ) -> Result<Option<Url>, WalletError> {
        let request = self
            .validate_request(url)
            .await
            .map_err(|e| WalletError::OID4VPRequestValidation(e.to_string()))?;

        let response = match request.response_mode() {
            ResponseMode::DirectPost => {
                self.handle_unencoded_authorization_request(&request, callback)
                    .await?
            }
            // TODO: Implement support for other response modes?
            mode => return Err(WalletError::OID4VPUnsupportedResponseMode(mode.to_string())),
        };

        self.submit_response(request, response)
            .await
            .map_err(|e| WalletError::OID4VPResponseSubmission(e.to_string()))
    }
}
