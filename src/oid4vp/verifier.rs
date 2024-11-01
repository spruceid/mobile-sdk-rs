use crate::common::Url;

use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum Oid4vpVerifierError {
    #[error("HTTP client error: {0}")]
    HttpClient(String),
    #[error("Invalid URL: {0}")]
    Url(String),
}

#[derive(Debug, uniffi::Object)]
pub struct DelegatedVerifier {
    base_url: Url,
    /// HTTP Request Client
    pub(crate) client: openid4vp::core::util::ReqwestClient,
}

#[derive(Debug, Serialize, Deserialize, uniffi::Enum, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DelegatedVerifierStatus {
    Initiated,
    Pending,
    Failure,
    Success,
}

#[derive(Debug, Serialize, Deserialize, uniffi::Record)]
pub struct DelegatedVerifierStatusResponse {
    /// The status of the verification request.
    pub status: DelegatedVerifierStatus,
    /// OID4VP presentation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oid4vp: Option<DelegatedVerifierOid4vpResponse>,
}

#[derive(Debug, Serialize, Deserialize, uniffi::Record)]
pub struct DelegatedVerifierOid4vpResponse {
    /// Presented SD-JWT.
    pub vp_token: String,
    // TODO: add presentation_submission
    // pub presentation_submission: PresentationSubmission
}

#[derive(Debug, Serialize, Deserialize, uniffi::Record)]
pub struct DelegateInitializationResponse {
    /// This is the authorization request URL to be presented in
    /// a QR code to the holder.
    pub auth_query: String,
    /// This is the status URL to check the presentation status
    /// from the delegated verifier.
    pub uri: String,
}

#[uniffi::export(async_runtime = "tokio")]
impl DelegatedVerifier {
    #[uniffi::constructor]
    pub async fn new_client(base_url: Url) -> Result<Arc<Self>, Oid4vpVerifierError> {
        let client = openid4vp::core::util::ReqwestClient::new()
            .map_err(|e| Oid4vpVerifierError::HttpClient(format!("{e:?}")))?;

        Ok(Arc::new(Self { base_url, client }))
    }

    /// Initialize a delegated verification request.
    ///
    /// This method will respond with a uniffi::Record object that contains the
    /// `auth_query` to be presented via QR code to the holder, and a `uri` to
    /// check the status of the presentation from the delegated verifier.
    ///
    /// Provide the `uri` to the [Verifier::poll_verification_status] method to
    /// check the status of the presentation.
    pub async fn request_delegated_verification(
        &self,
        url: &str,
    ) -> Result<DelegateInitializationResponse, Oid4vpVerifierError> {
        let uri = self
            .base_url
            .join(url)
            .map_err(|e| Oid4vpVerifierError::Url(format!("{e:?}")))?;

        self.client
            .as_ref()
            .get(uri)
            .send()
            .await
            .map_err(|e| Oid4vpVerifierError::HttpClient(format!("{e:?}")))?
            .json()
            .await
            .map_err(|e| Oid4vpVerifierError::HttpClient(format!("{e:?}")))
    }

    pub async fn poll_verification_status(
        &self,
        url: &str,
    ) -> Result<DelegatedVerifierStatusResponse, Oid4vpVerifierError> {
        let uri = self
            .base_url
            .join(url)
            .map_err(|e| Oid4vpVerifierError::Url(format!("{e:?}")))?;

        self.client
            .as_ref()
            .get(uri)
            .send()
            .await
            .map_err(|e| Oid4vpVerifierError::HttpClient(format!("{e:?}")))?
            .json()
            .await
            .map_err(|e| Oid4vpVerifierError::HttpClient(format!("{e:?}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::vcdm2_sd_jwt::VCDM2SdJwt;
    use crate::credential::*;
    use crate::oid4vp::holder::*;

    // NOTE: This requires an instance of credible to be accessible
    const BASE_URL: &str = "http://localhost:3003";
    const DELEGATED_VERIFIER_URL: &str = "/api2/verifier/1/delegate";

    #[tokio::test]
    #[ignore]
    async fn test_delegated_verification() -> Result<(), Oid4vpVerifierError> {
        let verifier =
            DelegatedVerifier::new_client(BASE_URL.parse().expect("Failed to parse Base URL"))
                .await
                .expect("Failed to create verifier");

        let DelegateInitializationResponse { uri, auth_query } = verifier
            .request_delegated_verification(DELEGATED_VERIFIER_URL)
            .await
            .expect("Failed to request delegated verification");

        let DelegatedVerifierStatusResponse { status, .. } =
            verifier.poll_verification_status(&uri).await?;

        assert_eq!(status, DelegatedVerifierStatus::Initiated);

        // Create a Holder instance to complete the verification
        let example_sd_jwt = include_str!("../../tests/examples/sd_vc.jwt");
        let sd_jwt = VCDM2SdJwt::new_from_compact_sd_jwt(example_sd_jwt.into())
            .expect("failed to parse sd_jwt");
        let credential = ParsedCredential::new_sd_jwt(sd_jwt);

        let trusted_dids = vec!["did:web:localhost%3A3003:colofwd_signer_service".to_string()];

        let holder = Holder::new_with_credentials(vec![credential], trusted_dids)
            .await
            .expect("failed to create oid4vp holder");

        let url = format!("openid4vp://?{auth_query}")
            .parse()
            .expect("failed to parse auth_query");

        let request = holder
            .authorization_request(url)
            .await
            .expect("authorization request failed");

        request.credentials().iter().for_each(|c| {
            println!("Credential: {:?}", c);
        });

        let response = request.create_permission_response(request.credentials());

        let url = holder.submit_permission_response(response).await;

        println!("Received URL: {url:?}");

        // Sleep for 5 seconds
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

        let DelegatedVerifierStatusResponse { status, oid4vp } =
            verifier.poll_verification_status(&uri).await?;

        assert_eq!(status, DelegatedVerifierStatus::Success);
        assert!(oid4vp.is_some());

        println!("Presentation: {:?}", oid4vp);

        Ok(())
    }
}