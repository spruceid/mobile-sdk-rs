use super::error::OID4VPError;
use super::permission_request::*;
use crate::common::*;
use crate::credential::*;
use crate::vdc_collection::VdcCollection;

use std::sync::Arc;

use futures::StreamExt;
use openid4vp::core::authorization_request::parameters::ClientIdScheme;
use openid4vp::core::credential_format::{ClaimFormatDesignation, ClaimFormatPayload};
use openid4vp::core::presentation_definition::PresentationDefinition;
use openid4vp::core::response::parameters::VpTokenItem;
use openid4vp::{
    core::{
        authorization_request::{
            parameters::ResponseMode,
            verification::{did::verify_with_resolver, RequestVerifier},
            AuthorizationRequestObject,
        },
        metadata::WalletMetadata,
        presentation_submission::{DescriptorMap, PresentationSubmission},
        response::{parameters::VpToken, AuthorizationResponse, UnencodedAuthorizationResponse},
    },
    wallet::Wallet as OID4VPWallet,
};
use ssi::claims::vc::{self, syntax::IdOr};
use ssi::dids::DIDWeb;
use ssi::dids::VerificationMethodDIDResolver;
use ssi::json_ld::iref::UriBuf;
use ssi::prelude::AnyJsonCredential;
use ssi::prelude::AnyJwkMethod;
use uniffi::deps::{anyhow, log};

/// A Holder is an entity that possesses one or more Verifiable Credentials.
/// The Holder is typically the subject of the credentials, but not always.
/// The Holder has the ability to generate Verifiable Presentations from
/// these credentials and share them with Verifiers.
#[derive(Debug, uniffi::Object)]
pub struct Holder {
    /// An atomic reference to the VDC collection.
    pub(crate) vdc_collection: Option<Arc<VdcCollection>>,

    /// Metadata about the holder.
    pub(crate) metadata: WalletMetadata,

    /// HTTP Request Client
    pub(crate) client: openid4vp::core::util::ReqwestClient,

    /// A list of trusted DIDs.
    pub(crate) trusted_dids: Vec<String>,

    /// Provide optional credentials to the holder instance.
    pub(crate) provided_credentials: Option<Vec<Arc<ParsedCredential>>>,
}

#[uniffi::export(async_runtime = "tokio")]
impl Holder {
    /// Uses VDC collection to retrieve the credentials for a given presentation definition.
    #[uniffi::constructor]
    pub async fn new(
        vdc_collection: Arc<VdcCollection>,
        trusted_dids: Vec<String>,
    ) -> Result<Arc<Self>, OID4VPError> {
        let client = openid4vp::core::util::ReqwestClient::new()
            .map_err(|e| OID4VPError::HttpClientInitialization(e.to_string()))?;

        Ok(Arc::new(Self {
            client,
            vdc_collection: Some(vdc_collection),
            metadata: Self::metadata()?,
            trusted_dids,
            provided_credentials: None,
        }))
    }

    /// Construct a new holder with provided credentials
    /// instead of a VDC collection.
    ///
    /// This constructor will use the provided credentials for the presentation,
    /// instead of searching for credentials in the VDC collection.
    #[uniffi::constructor]
    pub async fn new_with_credentials(
        provided_credentials: Vec<Arc<ParsedCredential>>,
        trusted_dids: Vec<String>,
    ) -> Result<Arc<Self>, OID4VPError> {
        let client = openid4vp::core::util::ReqwestClient::new()
            .map_err(|e| OID4VPError::HttpClientInitialization(e.to_string()))?;

        Ok(Arc::new(Self {
            client,
            vdc_collection: None,
            metadata: Self::metadata()?,
            trusted_dids,
            provided_credentials: Some(provided_credentials),
        }))
    }

    /// Given an authorization request URL, return a permission request,
    /// which provides a list of requested credentials and requested fields
    /// that align with the presentation definition of the request.
    ///
    /// This will fetch the presentation definition from the verifier.
    pub async fn authorization_request(
        &self,
        url: Url,
    ) -> Result<Arc<PermissionRequest>, OID4VPError> {
        let request = self
            .validate_request(url)
            .await
            .map_err(|e| OID4VPError::RequestValidation(format!("{e:?}")))?;

        match request.response_mode() {
            ResponseMode::DirectPost | ResponseMode::DirectPostJwt => {
                self.permission_request(request).await
            }
            // TODO: Implement support for other response modes.
            mode => Err(OID4VPError::UnsupportedResponseMode(mode.to_string())),
        }
    }

    pub async fn submit_permission_response(
        &self,
        response: Arc<PermissionResponse>,
    ) -> Result<Option<Url>, OID4VPError> {
        // Create a descriptor map for the presentation submission based on the credentials
        // returned from the selection response.
        let Some(input_descriptor_id) = response
            .presentation_definition
            .input_descriptors()
            // TODO: Handle multiple input descriptors.
            // Currently only supporting a single input descriptor
            // mapped to a single credential in the verifiable presentation
            // submission.
            .first()
            .map(|d| d.id().to_owned())
        else {
            // NOTE: We may wish to add a more generic `BadRequest` error type
            // we should always expect to have at least one input descriptor.
            return Err(OID4VPError::InputDescriptorNotFound);
        };

        let descriptor_map =
            self.create_descriptor_map(&response.selected_credential, input_descriptor_id)?;

        let presentation_submission_id = uuid::Uuid::new_v4();
        let presentation_definition_id = response.presentation_definition.id().clone();

        // // Create a presentation submission.
        let presentation_submission = PresentationSubmission::new(
            presentation_submission_id,
            presentation_definition_id,
            // NOTE: we're only supporting a single descriptor map for now.
            // TODO: support multiple descriptor maps.
            vec![descriptor_map],
        );

        let vp_token = self
            .create_unencoded_verifiable_presentation(
                &response.authorization_request,
                &response.selected_credential,
            )
            .await?;

        let response = self
            .submit_response(
                response.authorization_request.clone(),
                AuthorizationResponse::Unencoded(UnencodedAuthorizationResponse(
                    Default::default(),
                    vp_token,
                    presentation_submission,
                )),
            )
            .await
            .map_err(|e| OID4VPError::ResponseSubmission(e.to_string()))?;

        Ok(response)
    }
}

// Internal methods for the Holder.
impl Holder {
    /// Return the static metadata for the holder.
    ///
    /// This method is used to initialize the metadata for the holder.
    pub(crate) fn metadata() -> Result<WalletMetadata, OID4VPError> {
        let mut metadata = WalletMetadata::openid4vp_scheme_static();

        // Insert support for the VCDM2 SD JWT format.
        metadata.vp_formats_supported_mut().0.insert(
            ClaimFormatDesignation::Other("vcdm2_sd_jwt".into()),
            ClaimFormatPayload::AlgValuesSupported(vec!["ES256".into()]),
        );

        metadata
            // Insert support for the DID client ID scheme.
            .add_client_id_schemes_supported(ClientIdScheme::Did)
            .map_err(|e| OID4VPError::MetadataInitialization(format!("{e:?}")))?;

        Ok(metadata)
    }

    /// This will return all the credentials that match the presentation definition.
    async fn search_credentials_vs_presentation_definition(
        &self,
        definition: &PresentationDefinition,
    ) -> Result<Vec<Arc<ParsedCredential>>, OID4VPError> {
        let credentials = match &self.provided_credentials {
            // Use a pre-selected list of credentials if provided.
            Some(credentials) => credentials.to_owned(),
            None => match &self.vdc_collection {
                None => vec![],
                Some(vdc_collection) => {
                    let credential_ids = vdc_collection.all_entries().await?;

                    futures_util::stream::iter(credential_ids)
                        .filter_map(|id| async move {
                            vdc_collection
                                .get(id)
                                .await
                                .ok()
                                .flatten()
                                .and_then(|cred| cred.try_into_parsed().ok())
                        })
                        .collect::<Vec<Arc<ParsedCredential>>>()
                        .await
                }
            },
        }
        .into_iter()
        .filter_map(
            |cred| match cred.check_presentation_definition(definition) {
                true => Some(cred),
                false => None,
            },
        )
        .collect::<Vec<Arc<ParsedCredential>>>();

        Ok(credentials)
    }

    // Construct a DescriptorMap for the presentation submission based on the
    // credentials returned from the VDC collection.
    fn create_descriptor_map(
        &self,
        credential: &Arc<ParsedCredential>,
        input_descriptor_id: String,
    ) -> Result<DescriptorMap, OID4VPError> {
        Ok(DescriptorMap::new(
            input_descriptor_id,
            ClaimFormatDesignation::JwtVpJson,
            "$".into(),
        )
        // Credentials will be nested within a `vp` JSON object.
        .set_path_nested(DescriptorMap::new(
            credential.id().to_string(),
            ClaimFormatDesignation::from(credential.format()),
            "$.verifiableCredential".into(),
        )))
    }

    // Internal method for returning the `PermissionRequest` for an oid4vp request.
    async fn permission_request(
        &self,
        request: AuthorizationRequestObject,
    ) -> Result<Arc<PermissionRequest>, OID4VPError> {
        // Resolve the presentation definition.
        let presentation_definition = request
            .resolve_presentation_definition(self.http_client())
            .await
            .map_err(|e| OID4VPError::PresentationDefinitionResolution(e.to_string()))?
            .into_parsed();

        let credentials = self
            .search_credentials_vs_presentation_definition(&presentation_definition)
            .await?;

        Ok(PermissionRequest::new(
            presentation_definition.clone(),
            credentials.clone(),
            request,
        ))
    }

    // Internal method for creating a verifiable presentation.
    async fn create_unencoded_verifiable_presentation(
        &self,
        request: &AuthorizationRequestObject,
        credential: &Arc<ParsedCredential>,
    ) -> Result<VpToken, OID4VPError> {
        match request.client_id_scheme() {
            ClientIdScheme::Did => self.verifiable_presentation_did(request, credential).await,
            _ => Err(OID4VPError::InvalidClientIdScheme(
                "Only DID client ID scheme is supported.".to_string(),
            )),
        }
    }

    async fn verifiable_presentation_did(
        &self,
        request: &AuthorizationRequestObject,
        credential: &Arc<ParsedCredential>,
    ) -> Result<VpToken, OID4VPError> {
        match &credential.inner {
            ParsedCredentialInner::SdJwt(sd_jwt) => {
                let compact: &str = sd_jwt.inner.as_ref();
                Ok(VpTokenItem::from(compact.to_string()).into())
            }
            ParsedCredentialInner::JwtVcJson(vc) => match vc.credential() {
                AnyJsonCredential::V1(v1) => {
                    let id =
                        UriBuf::new(format!("urn:uuid:{}", Uuid::new_v4()).as_bytes().to_vec())
                            .ok();

                    let id_or =
                        UriBuf::new(request.client_id().0.as_bytes().to_vec()).map_err(|e| {
                            OID4VPError::VpTokenCreate(format!("Error creating URI: {:?}", e))
                        })?;

                    let presentation =
                        vc::v1::syntax::JsonPresentation::new(id, Some(id_or), vec![v1]);

                    // NOTE: There is some conflict between `NonEmptyObject` and `Object` inner
                    // types for the JsonPresentation types that restricts the direct use of the VpTokenItem
                    // `From<T>` conversations. This is not ideal, but as a short-term solution, using a conversion to `Object`
                    // to `VpTokenItem`. In the future, this may require changes to the `ssi` library.
                    let serde_json::Value::Object(obj) = serde_json::to_value(presentation)
                        // SAFETY: by definition a VCDM1.1 presentation is a JSON object.
                        .unwrap()
                    else {
                        // SAFETY: by definition a VCDM1.1 presentation is a JSON object.
                        unreachable!()
                    };

                    Ok(VpTokenItem::JsonObject(obj).into())
                }
                AnyJsonCredential::V2(v2) => {
                    let id =
                        UriBuf::new(format!("urn:uuid:{}", Uuid::new_v4()).as_bytes().to_vec())
                            .ok();

                    let id_or =
                        UriBuf::new(request.client_id().0.as_bytes().to_vec()).map_err(|e| {
                            OID4VPError::VpTokenCreate(format!("Error creating URI: {:?}", e))
                        })?;

                    let presentation =
                        vc::v2::syntax::JsonPresentation::new(id, vec![IdOr::Id(id_or)], vec![v2]);

                    let serde_json::Value::Object(obj) = serde_json::to_value(presentation)
                        // SAFETY: by definition a VCDM1.1 presentation is a JSON object.
                        .unwrap()
                    else {
                        // SAFETY: by definition a VCDM1.1 presentation is a JSON object.
                        unreachable!()
                    };

                    Ok(VpTokenItem::JsonObject(obj).into())
                }
            },
            _ => Err(OID4VPError::VpTokenParse(format!(
                "Credential parsing for VP Token is not implemented for {:?}.",
                credential,
            ))),
        }
    }
}

#[async_trait::async_trait]
impl RequestVerifier for Holder {
    /// Performs verification on Authorization Request Objects when `client_id_scheme` is `did`.
    async fn did(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> anyhow::Result<()> {
        log::debug!("Verifying DID request.");

        let resolver: VerificationMethodDIDResolver<DIDWeb, AnyJwkMethod> =
            VerificationMethodDIDResolver::new(DIDWeb);

        verify_with_resolver(
            &self.metadata,
            decoded_request,
            request_jwt,
            Some(self.trusted_dids.as_slice()),
            &resolver,
        )
        .await?;

        Ok(())
    }
}

impl OID4VPWallet for Holder {
    type HttpClient = openid4vp::core::util::ReqwestClient;

    fn http_client(&self) -> &Self::HttpClient {
        &self.client
    }

    fn metadata(&self) -> &WalletMetadata {
        &self.metadata
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // use crate::openid4vp::request_signer::ExampleRequestSigner;
    use sd_jwt::SdJwt;

    // NOTE: This test requires the `companion` service to be running and
    // available at localhost:3000.
    //
    // See: https://github.com/spruceid/companion/pull/1
    #[ignore]
    #[tokio::test]
    async fn test_oid4vp_url() -> Result<(), Box<dyn std::error::Error>> {
        let example_sd_jwt = include_str!("../../tests/examples/sd_vc.jwt");
        let sd_jwt = SdJwt::new_from_compact_sd_jwt(example_sd_jwt.into())?;
        let credential = ParsedCredential::new_sd_jwt(sd_jwt);

        let initiate_api = "http://localhost:3000/api/oid4vp/initiate";

        // Make a request to the OID4VP initiate API.
        // provide a url-encoded `format` parameter to specify the format of the presentation.
        let response: (String, String) = reqwest::Client::new()
            .post(initiate_api)
            .form(&[("format", "sd_jwt")])
            .send()
            .await?
            .json()
            .await?;

        let _id = response.0;
        let url = Url::parse(&response.1).expect("failed to parse url");

        // Make a request to the OID4VP URL.
        let holder = Holder::new_with_credentials(
            vec![credential],
            vec![
                "did:web:localhost%3A3000:oid4vp:client".into(),
                "did:web:1741-24-113-196-42.ngrok-free.app:oid4vp:client".into(),
            ],
        )
        .await?;

        let permission_request = holder.authorization_request(url).await?;

        let mut parsed_credentials = permission_request.credentials();

        assert_eq!(parsed_credentials.len(), 1);

        let selected_credential = parsed_credentials
            .pop()
            .expect("failed to retrieve a parsed credential matching the presentation definition");

        let requested_fields = permission_request.requested_fields(&selected_credential);

        assert!(requested_fields.len() > 0);

        let response = permission_request.create_permission_response(selected_credential);

        holder.submit_permission_response(response).await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_vehicle_title() -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }
}
