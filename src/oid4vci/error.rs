use oid4vci::{
    credential::RequestError,
    openidconnect::{DiscoveryError, ErrorResponse, RequestTokenError},
};

#[derive(thiserror::Error, uniffi::Error, Debug)]
#[uniffi(flat_error)]
pub enum OID4VCIError {
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
impl From<String> for OID4VCIError {
    fn from(value: String) -> Self {
        Self::Generic(value)
    }
}

impl<RE> From<DiscoveryError<RE>> for OID4VCIError
where
    RE: std::error::Error + 'static,
{
    fn from(value: DiscoveryError<RE>) -> Self {
        if let DiscoveryError::Parse(e) = &value {
            OID4VCIError::RequestError(format!("{value}: {e}"))
        } else {
            OID4VCIError::RequestError(value.to_string())
        }
    }
}

impl From<serde_json::Error> for OID4VCIError {
    fn from(_: serde_json::Error) -> Self {
        OID4VCIError::SerdeJsonError("".into())
    }
}

impl<RE> From<RequestError<RE>> for OID4VCIError
where
    RE: std::error::Error + 'static,
{
    fn from(value: RequestError<RE>) -> Self {
        if let RequestError::Parse(e) = &value {
            OID4VCIError::RequestError(format!("{value}: {e}"))
        } else {
            OID4VCIError::RequestError(value.to_string())
        }
    }
}

impl<RE, T> From<RequestTokenError<RE, T>> for OID4VCIError
where
    RE: std::error::Error + 'static,
    T: ErrorResponse + 'static,
{
    fn from(value: RequestTokenError<RE, T>) -> Self {
        OID4VCIError::RequestError(value.to_string())
    }
}
impl From<oid4vci::client::Error> for OID4VCIError {
    fn from(value: oid4vci::client::Error) -> Self {
        OID4VCIError::RequestError(value.to_string())
    }
}
