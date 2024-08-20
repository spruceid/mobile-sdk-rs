#[uniffi::export(callback_interface)]
pub trait SecretKeyInterface: Send + Sync {
    // TODO: Review available methods in android and cryptokit to implement here
}

/// EncryptedPayload is a struct that holds the IV and ciphertext
/// of an encrypted payload.
#[derive(uniffi::Record)]
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
}

/// KeyManager for interacting with the device's
/// cryptographic device APIs for signing and encrypting
/// messages.
#[uniffi::export(callback_interface)]
pub trait KeyManager: Send + Sync {
    /// Reset the key manager, removing all keys.
    fn reset(&self) -> bool;

    /// Check if a key exists in the key manager.
    fn key_exists(&self, id: String) -> bool;

    /// Get a secret key from the key manager.
    fn get_secret_key(&self, id: String) -> Option<Box<dyn SecretKeyInterface>>;

    /// Generate a signing key in the key manager.
    fn generate_signing_key(&self, id: String) -> bool;

    /// Return a JWK for a given key ID as a JSON-encoded string.
    fn get_jwk(&self, id: String) -> Option<String>;

    /// Sign a payload with a key in the key manager.
    fn sign_payload(&self, id: String, payload: Vec<u8>) -> Option<Vec<u8>>;

    /// Generate an encryption key in the key manager.
    fn generate_encryption_key(&self, id: String) -> bool;

    /// Encrypt a payload with a key in the key manager.
    fn encrypt_payload(&self, id: String, payload: Vec<u8>) -> Option<EncryptedPayload>;

    /// Decrypt a ciphertext with a key in the key manager. Returns a
    /// plaintext payload, if the ID exists and the decryption is successful.
    fn decrypt_payload(&self, id: String, ciphertext: Vec<u8>) -> Option<Vec<u8>>;
}
