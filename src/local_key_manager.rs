use std::{
    collections::HashMap,
    ops::Deref,
    sync::{Arc, Mutex},
};

use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    elliptic_curve::rand_core::{OsRng, RngCore},
    SecretKey,
};

use crate::{EncryptedPayload, Key, KeyManagerError, KeyManagerInterface};

#[derive(Debug)]
pub struct LocalKeyManager {
    keys: Mutex<HashMap<Key, p256::SecretKey>>,
}

impl LocalKeyManager {
    pub fn new() -> Self {
        Self {
            keys: Mutex::new(HashMap::new()),
        }
    }

    pub fn new_with_key(id: Key, key: p256::SecretKey) -> Self {
        Self {
            keys: Mutex::new(HashMap::from([(id, key)])),
        }
    }
}

impl KeyManagerInterface for LocalKeyManager {
    #[doc = " Reset the key manager, removing all keys."]
    fn reset(&self) -> bool {
        true
    }

    #[doc = " Check if a key exists in the key manager."]
    fn key_exists(&self, id: Key) -> bool {
        self.keys.lock().unwrap().contains_key(&id)
    }

    #[doc = " Generate a signing key in the key manager."]
    fn generate_signing_key(&self, id: Key) -> bool {
        let mut keys = self.keys.lock().unwrap();
        keys.insert(id, SecretKey::random(&mut OsRng));
        true
    }

    #[doc = " Return a JWK for a given key ID as a JSON-encoded string."]
    fn get_jwk(&self, id: Key) -> Result<String, KeyManagerError> {
        let keys = self.keys.lock().unwrap();
        let key = keys.get(&id).ok_or(KeyManagerError::KeyNotFound)?;
        Ok(key.to_jwk_string().deref().to_string())
    }

    #[doc = " Sign a payload with a key in the key manager."]
    fn sign_payload(&self, id: Key, payload: Vec<u8>) -> Result<Vec<u8>, KeyManagerError> {
        let key = self
            .keys
            .lock()
            .unwrap()
            .get(&id)
            .ok_or(KeyManagerError::KeyNotFound)?
            .clone();
        let signature: Signature = SigningKey::from(key).sign(&payload);
        Ok(signature.to_vec())
    }

    #[doc = " Generate an encryption key in the key manager."]
    fn generate_encryption_key(&self, id: Key) -> bool {
        let mut keys = self.keys.lock().unwrap();
        keys.insert(id, SecretKey::random(&mut OsRng));
        true
    }

    fn encrypt_payload(
        &self,
        id: Key,
        payload: Vec<u8>,
    ) -> Result<Arc<EncryptedPayload>, KeyManagerError> {
        let _key = self
            .keys
            .lock()
            .unwrap()
            .get(&id)
            .ok_or(KeyManagerError::KeyNotFound)?
            .clone();

        // Generating a random IV and XORing the paylod.
        // DO NOT USE IN PRODUCTION
        // FOR TESTING PURPOSES ONLY
        let mut iv: Vec<u8> = Vec::with_capacity(payload.len());
        OsRng.fill_bytes(&mut iv);
        let ciphertext = payload.iter().zip(iv.clone()).map(|(p, i)| p ^ i).collect();
        Ok(Arc::new(EncryptedPayload::new(iv, ciphertext)))
    }

    #[doc = " Decrypt a ciphertext with a key in the key manager. Returns a"]
    #[doc = " plaintext payload, if the ID exists and the decryption is successful."]
    fn decrypt_payload(
        &self,
        id: Key,
        encrypted_payload: Arc<EncryptedPayload>,
    ) -> Result<Vec<u8>, KeyManagerError> {
        let _key = self
            .keys
            .lock()
            .unwrap()
            .get(&id)
            .ok_or(KeyManagerError::KeyNotFound)?
            .clone();

        Ok(encrypted_payload
            .ciphertext()
            .iter()
            .zip(encrypted_payload.iv())
            .map(|(c, i)| c ^ i)
            .collect())
    }
}
