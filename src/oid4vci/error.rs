use oid4vci::{
    credential::RequestError,
    openidconnect::{DiscoveryError, ErrorResponse, RequestTokenError},
};

use super::HttpClientError;

#[derive(thiserror::Error, uniffi::Error, Debug)]
#[uniffi(flat_error)]
pub enum Oid4vciError {
    #[error("Serde error")]
    SerdeJsonError(String),

    #[error("HTTP request error: {0}")]
    RequestError(String),

    #[error("Unsupported grant type")]
    UnsupportedGrantType,

    #[error("Invalid session: {0}")]
    InvalidSession(String),

    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    #[error("Failed to acquire lock for {0}")]
    LockError(String),

    #[error("{0}")]
    Generic(String),
}

// TODO: some or all of these trait implementations can be converted to macros
impl From<String> for Oid4vciError {
    fn from(value: String) -> Self {
        Self::Generic(value)
    }
}

impl<RE> From<DiscoveryError<RE>> for Oid4vciError
where
    RE: std::error::Error + 'static,
{
    fn from(value: DiscoveryError<RE>) -> Self {
        if let DiscoveryError::Parse(e) = &value {
            Oid4vciError::RequestError(format!("{value}: {e}"))
        } else {
            Oid4vciError::RequestError(value.to_string())
        }
    }
}

impl From<serde_json::Error> for Oid4vciError {
    fn from(_: serde_json::Error) -> Self {
        Oid4vciError::SerdeJsonError("".into())
    }
}

impl<RE> From<RequestError<RE>> for Oid4vciError
where
    RE: std::error::Error + 'static,
{
    fn from(value: RequestError<RE>) -> Self {
        if let RequestError::Parse(e) = &value {
            Oid4vciError::RequestError(format!("{value}: {e}"))
        } else {
            Oid4vciError::RequestError(value.to_string())
        }
    }
}

impl<RE, T> From<RequestTokenError<RE, T>> for Oid4vciError
where
    RE: std::error::Error + 'static,
    T: ErrorResponse + 'static,
{
    fn from(value: RequestTokenError<RE, T>) -> Self {
        Oid4vciError::RequestError(value.to_string())
    }
}

impl From<oid4vci::client::Error> for Oid4vciError {
    fn from(value: oid4vci::client::Error) -> Self {
        Oid4vciError::RequestError(value.to_string())
    }
}

impl From<HttpClientError> for Oid4vciError {
    fn from(value: HttpClientError) -> Self {
        Oid4vciError::RequestError(value.to_string())
    }
}
