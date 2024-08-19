pub mod presentation_exchange;

use thiserror::Error;

/// The [OID4VPError] enum represents the errors that can occur
/// when using the oid4vp foreign library.
#[derive(Error, Debug, uniffi::Error)]
pub enum OID4VPError {
    #[error("An unexpected foreign callback error occurred: {0}")]
    UnexpectedUniFFICallbackError(String),
}

// Handle unexpected errors when calling a foreign callback
impl From<uniffi::UnexpectedUniFFICallbackError> for OID4VPError {
    fn from(value: uniffi::UnexpectedUniFFICallbackError) -> Self {
        OID4VPError::UnexpectedUniFFICallbackError(value.reason)
    }
}
