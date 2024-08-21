use crate::{
    common::Url,
    key_manager::{KeyManagerInterface, DEFAULT_KEY_INDEX, KEY_MANAGER_PREFIX},
    metadata_manager::{MetadataManager, MetadataManagerError},
    storage_manager::{self, Key, StorageManagerInterface},
    trust_manager::TrustManager,
    vdc_collection::{VdcCollection, VdcCollectionError},
};

use std::sync::{Arc, RwLock};

use anyhow::Result;
use oid4vp::{
    core::authorization_request::parameters::ResponseMode, verifier::request_signer::RequestSigner,
    wallet::Wallet as OID4VPWallet,
};
use ssi_dids::DIDKey;
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
    #[error(transparent)]
    MetadataManagerError(#[from] MetadataManagerError),
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
/// #[ignore]
/// ```
/// use mobile_sdk_rs::prelude::*;
///
/// let storage_manager = Box::new(MyStorageManager::new());
/// let key_manager = Box::new(MyKeyManager::new());
///
/// fn main() -> Result<(), WalletError> {
///  let wallet = Wallet::new(storage_manager, key_manager)?;
///
/// }
///
///
/// ```
#[derive(uniffi::Object, Debug)]
pub struct Wallet {
    pub(crate) client: oid4vp::core::util::ReqwestClient,
    pub(crate) metadata: MetadataManager,
    pub(crate) vdc_collection: VdcCollection,
    // NOTE: The wallet has internal access to the trust manager APIs, but
    // is currently not exposing them to the foreign function interface.
    // This is because the trust manager is intended to be used internally by the wallet.
    // The [TrustManager] does not implement uniffi bindings.
    pub(crate) trust_manager: TrustManager,
    pub(crate) key_manager: Box<dyn KeyManagerInterface>,
    pub(crate) storage_manager: Box<dyn StorageManagerInterface>,
    // The active key index is used to determine which key to used for signing.
    // By default, this is set to the 0-index key.
    pub(crate) active_key_index: Arc<RwLock<u8>>,
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
        storage_manager: Box<dyn StorageManagerInterface>,
        key_manager: Box<dyn KeyManagerInterface>,
    ) -> Result<Arc<Self>, WalletError> {
        let client = oid4vp::core::util::ReqwestClient::new()
            .map_err(|e| WalletError::HttpClientInitialization(format!("{e}")))?;

        // Initalized the metdata manager with the device storage.
        // This will load any existing metadata from storage, otherwise
        // it will create a new metadata instance.
        let metadata = MetadataManager::initialize(&storage_manager)?;

        Ok(Arc::new(Self {
            client,
            metadata,
            key_manager,
            storage_manager,
            vdc_collection: VdcCollection::new(),
            trust_manager: TrustManager::new(),
            active_key_index: Arc::new(RwLock::new(DEFAULT_KEY_INDEX)),
        }))
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
    pub async fn handle_oid4vp_request(&self, url: Url) -> Result<Option<Url>, WalletError> {
        let request = self
            .validate_request(url)
            .await
            .map_err(|e| WalletError::OID4VPRequestValidation(e.to_string()))?;

        let response = match request.response_mode() {
            ResponseMode::DirectPost => {
                self.handle_unencoded_authorization_request(&request)
                    .await?
            }
            // TODO: Implement support for other response modes?
            mode => return Err(WalletError::OID4VPUnsupportedResponseMode(mode.to_string())),
        };

        self.submit_response(request, response)
            .await
            .map_err(|e| WalletError::OID4VPResponseSubmission(e.to_string()))
    }

    /// Returns the JSON-encoded JWK of the wallet's public JWK encoded key.
    ///
    /// An optional `key_index` can be provided to specify the key index to use.
    ///
    /// If no key index is provided, the active key index is used.
    ///
    /// # Arguments
    ///
    /// # Returns
    ///
    /// The JSON-encoded JWK of the wallet's public JWK encoded key.
    ///
    /// # Errors
    ///
    /// * If the key index is not found.
    /// * If the key is not found.
    /// * If the JWK cannot be encoded.
    ///
    pub fn get_jwk(&self) -> Result<String, WalletError> {
        let index = self.get_active_key_index()?;
        let key_id = Key::with_prefix(KEY_MANAGER_PREFIX, &format!("{index}"));

        self.key_manager
            .get_jwk(key_id.clone())
            .ok_or(WalletError::KeyNotFound(index))
    }

    /// Returns the verification method of the wallet's public JWK encoded key.
    ///
    /// The verification method is a DID URL that can be used to reference the key.
    ///
    /// The active key index is used as the fragment of the DID URL.
    ///
    /// # Arguments
    ///
    /// # Returns
    ///
    /// The verification method of the wallet's public JWK encoded key.
    ///
    /// # Errors
    ///
    /// * If the key index is not found.
    /// * If the key is not found.
    /// * If the JWK cannot be encoded.
    /// * If the JWK cannot be converted to a DID Key.
    ///
    pub fn jwk_verification_method(&self) -> Result<String, WalletError> {
        let index = self.get_active_key_index()?;
        // Convert JWK into DID Key format.
        let did_key = DIDKey::generate_url(&self.jwk()?)
            .map_err(|e| WalletError::DIDKeyGenerateUrl(e.to_string()))?;

        Ok(format!("{did_key}#{index}"))
    }

    /// Set the Active Key Index of the Wallet.
    /// This is used as the default key index for signing.
    /// By default, this is set to the 0-index key.
    ///
    /// This will error if the key index does not exist.
    ///
    /// # Arguments
    ///
    /// * `key_index` - The key index to set as the active key index.
    ///
    /// # Returns
    ///
    /// A result indicating success or failure.
    ///
    /// # Errors
    ///
    /// * If the key index does not exist.
    /// * If the active key index cannot be written due to a write lock guard error.
    ///
    pub fn set_active_key_index(&self, key_index: u8) -> Result<(), WalletError> {
        if !self.key_manager.key_exists(Key::with_prefix(
            KEY_MANAGER_PREFIX,
            &format!("{key_index}"),
        )) {
            return Err(WalletError::KeyNotFound(key_index));
        }

        let mut active_key_index = self
            .active_key_index
            .write()
            .map_err(|e| WalletError::ActiveKeyIndexReadWriteError(e.to_string()))?;

        *active_key_index = key_index;

        Ok(())
    }

    /// Get the Active Key Index of the Wallet.
    /// This is used as the default key index for signing.
    ///
    /// # Returns
    ///
    /// The active key index.
    ///
    /// # Errors
    ///
    /// * If the active key index cannot be read due to a read lock guard failure;
    ///
    pub fn get_active_key_index(&self) -> Result<u8, WalletError> {
        let key_index = self
            .active_key_index
            .read()
            .map_err(|e| WalletError::ActiveKeyIndexReadWriteError(e.to_string()))?;

        Ok(*key_index)
    }
}
