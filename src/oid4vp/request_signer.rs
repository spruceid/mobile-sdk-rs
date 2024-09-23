#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum RequestSignerError {
    #[error("Unsupported algorithm")]
    UnsupportedAlgorithm,
    #[error("Failed to sign the request")]
    SigningError,
}

#[uniffi::export(with_foreign)]
pub trait RequestSignerInterface: Send + Sync + std::fmt::Debug {
    /// Return the algorithm used to sign the request
    fn alg(&self) -> Result<String, RequestSignerError>;

    /// Return the JWK public key
    fn jwk(&self) -> Result<String, RequestSignerError>;

    /// Sign the request
    fn try_sign(&self, payload: Vec<u8>) -> Result<Vec<u8>, RequestSignerError>;
}
