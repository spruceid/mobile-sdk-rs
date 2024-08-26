use crate::common::Key;

use std::{fmt::Debug, sync::Arc};

/// This is the prefix for all key manager keys.
pub const KEY_MANAGER_PREFIX: &str = "SSIKeyManager.";

/// This is the default index for a key in the key manager.
pub const DEFAULT_KEY_INDEX: u8 = 0;

#[uniffi::export(callback_interface)]
pub trait SecretKeyInterface: Send + Sync {
    // TODO: Review available methods in android and cryptokit to implement here
}

#[derive(uniffi::Error, thiserror::Error, Debug)]
pub enum KeyManagerError {
    #[error("An unexpected foreign callback error occurred: {0}")]
    UnexpectedUniFFICallbackError(String),
    #[error("Failed to generate key")]
    FailedToGenerateKey,
    #[error("Failed to encrypt")]
    FailedToEncrypt,
    #[error("Failed to decrypt")]
    FailedToDecrypt,
    #[error("Failed to sign")]
    FailedToSign,
    #[error("Failed to verify")]
    FailedToVerify,
    #[error("Failed to reset")]
    FailedToReset,
    #[error("Key not found")]
    KeyNotFound,
    #[error("Key already exists")]
    KeyAlreadyExists,
    #[error("Key invalid")]
    KeyInvalid,
}

// Handle unexpected errors when calling a foreign callback
impl From<uniffi::UnexpectedUniFFICallbackError> for KeyManagerError {
    fn from(value: uniffi::UnexpectedUniFFICallbackError) -> Self {
        KeyManagerError::UnexpectedUniFFICallbackError(value.reason)
    }
}

/// EncryptedPayload is a struct that holds the IV and ciphertext
/// of an encrypted payload.
#[derive(uniffi::Object, Debug, Clone)]
pub struct EncryptedPayload {
    iv: Vec<u8>,
    ciphertext: Vec<u8>,
}

#[uniffi::export]
impl EncryptedPayload {
    #[uniffi::constructor]
    pub fn new(iv: Vec<u8>, ciphertext: Vec<u8>) -> Self {
        Self { iv, ciphertext }
    }

    /// Get the initialization vector (IV) for the encrypted payload.
    pub fn iv(&self) -> Vec<u8> {
        self.iv.clone()
    }

    /// Get the ciphertext for the encrypted payload.
    pub fn ciphertext(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }
}

/// KeyManager for interacting with the device's
/// cryptographic device APIs for signing and encrypting
/// messages.
#[uniffi::export(callback_interface)]
pub trait KeyManagerInterface: Send + Sync + Debug {
    /// Reset the key manager, removing all keys.
    fn reset(&self) -> bool;

    /// Check if a key exists in the key manager.
    fn key_exists(&self, id: Key) -> bool;

    // /// Get a secret key from the key manager.
    // fn get_secret_key(&self, id: Key) -> Option<Box<dyn SecretKeyInterface>>;

    /// Generate a signing key in the key manager.
    fn generate_signing_key(&self, id: Key) -> bool;

    /// Return a JWK for a given key ID as a JSON-encoded string.
    fn get_jwk(&self, id: Key) -> Result<String, KeyManagerError>;

    /// Sign a payload with a key in the key manager.
    fn sign_payload(&self, id: Key, payload: Vec<u8>) -> Result<Vec<u8>, KeyManagerError>;

    /// Generate an encryption key in the key manager.
    fn generate_encryption_key(&self, id: Key) -> bool;

    // /// Encrypt a payload with a key in the key manager.
    fn encrypt_payload(
        &self,
        id: Key,
        payload: Vec<u8>,
    ) -> Result<Arc<EncryptedPayload>, KeyManagerError>;

    /// Decrypt a ciphertext with a key in the key manager. Returns a
    /// plaintext payload, if the ID exists and the decryption is successful.
    fn decrypt_payload(
        &self,
        id: Key,
        encrypted_payload: Arc<EncryptedPayload>,
    ) -> Result<Vec<u8>, KeyManagerError>;
}
