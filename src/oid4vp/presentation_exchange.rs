use super::*;
use crate::common::*;

use std::sync::Arc;

use oid4vp::core::authorization_request;

#[derive(uniffi::Object)]
pub struct AuthorizationRequestObject(pub(crate) authorization_request::AuthorizationRequestObject);

/// The [AuthorizationRequest] struct represents an authorization request
/// sent by a verifier to a holder.
#[derive(uniffi::Object)]
pub struct AuthorizationRequest(authorization_request::AuthorizationRequest);

#[uniffi::export]
impl AuthorizationRequest {
    /// Construct a new authorization request from an url-encoded string.
    #[uniffi::constructor]
    pub fn from_url(url: Url, authorization_endpoint: &Url) -> Result<Arc<Self>, OID4VPError> {
        let request =
            authorization_request::AuthorizationRequest::from_url(url, authorization_endpoint)
                .map_err(|e| {
                    OID4VPError::UnexpectedUniFFICallbackError(format!(
                        "Failed to parse authorization: {e}"
                    ))
                })?;
        Ok(Arc::new(Self(request)))
    }

    #[uniffi::constructor]
    pub fn from_query_params(params: &str) -> Result<Arc<Self>, OID4VPError> {
        let request = authorization_request::AuthorizationRequest::from_query_params(params)
            .map_err(|e| {
                OID4VPError::UnexpectedUniFFICallbackError(format!(
                    "Failed to parse authorization: {e}"
                ))
            })?;
        Ok(Arc::new(Self(request)))
    }

    // #[uniffi::method]
    // pub fn validate(&self) -> Result<(), OID4VPError> {
    //     self.0.validate().map_err(|e| {
    //         OID4VPError::UnexpectedUniFFICallbackError(format!(
    //             "Failed to validate authorization request: {e}"
    //         ))
    //     })
    // }
}
