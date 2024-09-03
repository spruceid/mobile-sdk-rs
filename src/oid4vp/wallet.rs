use crate::{
    common::*,
    credentials_callback::{
        CredentialCallbackError, CredentialCallbackInterface, InputDescriptorCredentialMapRef,
        PermissionRequest, RequestedField, SelectCredentialRequest,
    },
    vdc_collection::Credential,
    wallet::{Wallet, WalletError},
};

use std::{collections::HashMap, str::FromStr, sync::Arc};

use anyhow::Result;
use oid4vp::{
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
    holder::verifiable_presentation_builder::{
        VerifiablePresentationBuilder, VerifiablePresentationBuilderOptions,
    },
    verifier::request_signer::RequestSigner,
    wallet::Wallet as OID4VPWallet,
};
use ssi::claims::jws::JWSSigner;
use ssi::dids::{ssi_json_ld::syntax::Value, DIDKey, DIDURLBuf};
use ssi::jwk::JWK;
use uniffi::deps::log;

// 5 minute default expiration.
const DEFAULT_EXPIRATION_IN_SECONDS: u64 = 60 * 5;

#[uniffi::export]
impl Wallet {
    /// Handle an OID4VP authorization request provided as a URL.
    ///
    /// This method will validate and process the request, returning a
    /// redirect URL with the encoded verifiable presentation token,
    /// if the presentation exchange was successful.
    ///
    /// If the request is invalid or cannot be processed, an error will be returned.
    ///
    /// # Arguments
    ///
    /// * `url` - The URL containing the OID4VP authorization request.
    ///
    /// # Returns
    ///
    /// An optional URL containing the OID4VP response.
    ///
    /// # Errors
    ///
    /// * If the request is invalid;
    /// * If the response mode is not supported;
    /// * If the response submission fails.
    ///
    pub async fn handle_oid4vp_request(
        &self,
        url: Url,
        // NOTE: The callback handles UI interactions.
        callback: &Arc<dyn CredentialCallbackInterface>,
    ) -> Result<Option<Url>, WalletError> {
        let request = self
            .validate_request(url)
            .await
            .map_err(|e| WalletError::OID4VPRequestValidation(e.to_string()))?;

        let response = match request.response_mode() {
            ResponseMode::DirectPost => {
                self.handle_unencoded_authorization_request(&request, callback)
                    .await?
            }
            // TODO: Implement support for other response modes?
            mode => return Err(WalletError::OID4VPUnsupportedResponseMode(mode.to_string())),
        };

        self.submit_response(request, response)
            .await
            .map_err(|e| WalletError::OID4VPResponseSubmission(e.to_string()))
    }
}

// Internal wallet methods implementing the OID4VP specification.
impl Wallet {
    /// Retrieves the credentials from the wallet
    /// storage based on the presentation definition.
    ///
    /// Returns a HashMap where the Key is the input descriptor ID,
    /// and the value is a vector of credentials that match the input descriptor.
    fn retrieve_credentials(
        &self,
        requested_fields: &[Arc<RequestedField>],
    ) -> Result<HashMap<String, Vec<Arc<Credential>>>, WalletError> {
        let mut map = HashMap::with_capacity(requested_fields.len());

        for field in requested_fields.iter() {
            if let Some(input_descriptor_id) = field.input_descriptor_id() {
                match field.credential_type() {
                    None => {
                        // TODO: Handle the case where the credential type cannot be parsed.
                        // Currently this is not a hard error, and only a warning will be logged
                        // that the credential type could not be parsed from the input descriptor
                        // when the requested field was created.
                        log::warn!(
                            "Credential type could not be parsed from the input descriptor."
                        );
                    }
                    Some(credential_type) => {
                        let keys = self
                            .vdc_collection
                            .entries_by_type(&credential_type, &self.storage_manager)?;

                        let credentials = keys
                            .into_iter()
                            .filter_map(|key| {
                                self.vdc_collection
                                    .get(key, &self.storage_manager)
                                    .map_err(WalletError::from)
                                    .transpose()
                            })
                            .collect::<Result<Vec<Arc<Credential>>, WalletError>>()?;

                        // Insert or update the map with the credentials. There may already be credentials
                        // mapped for the input descriptor ID, therefore need to append the new credentials.
                        map.entry(input_descriptor_id.clone())
                            .and_modify(|v: &mut Vec<Arc<Credential>>| {
                                v.extend(credentials.clone())
                            })
                            .or_insert(credentials);
                    }
                }
            }
        }

        Ok(map)
    }

    // Construct a DescriptorMap for the presentation submission based on the
    // credentials returned from the VDC collection.
    fn create_descriptor_maps(
        &self,
        selected_credentials: InputDescriptorCredentialMapRef,
    ) -> Result<Vec<(DescriptorMap, Arc<Credential>)>, WalletError> {
        let mut index = 0;

        Ok(selected_credentials
            .read()
            .map_err(|_| WalletError::from(CredentialCallbackError::RwLockError))?
            .iter()
            .flat_map(|(input_descriptor_id, credentials)| {
                credentials
                    .iter()
                    .map(move |credential| {
                        let credential_descriptor_tuple = (
                            DescriptorMap::new(
                                input_descriptor_id,
                                ClaimFormatDesignation::JwtVpJson,
                                "$".into(),
                            )
                            // Credentials will be nested within a `vp` JSON object.
                            .set_path_nested(DescriptorMap::new(
                                credential.id().to_string(),
                                credential.format(),
                                format!("$.verifiableCredential[{index}]"),
                            )),
                            credential.to_owned(),
                        );

                        // Increment the index for the next descriptor.
                        index += 1;

                        credential_descriptor_tuple
                    })
                    .collect::<Vec<(DescriptorMap, Arc<Credential>)>>()
            })
            .collect::<Vec<_>>())
    }

    // Internal method for creating a verifiable presentation object.
    pub(crate) async fn handle_unencoded_authorization_request(
        &self,
        request: &AuthorizationRequestObject,
        callback: &Arc<dyn CredentialCallbackInterface>,
    ) -> Result<AuthorizationResponse, WalletError> {
        // Resolve the presentation definition.
        let presentation_definition = request
            .resolve_presentation_definition(self.http_client())
            .await
            .map_err(|e| WalletError::OID4VPPresentationDefinitionResolution(e.to_string()))?;

        let presentation_submission_id = uuid::Uuid::new_v4();
        let presentation_definition_id = presentation_definition.parsed().id().clone();

        // NOTE: This is a callback method to alert the client the information requested.
        // The user can deny the request or permit the presentation.
        let permission_response = callback
            .permit_presentation(PermissionRequest::new(presentation_definition.parsed()))?;

        // Check if the verifiable credential(s) exists in the storage.
        let credential_map = self.retrieve_credentials(permission_response.requested_fields())?;

        // TODO: Show the user the credentials, and then request a selection from the credentials.
        let selected_credentials =
            callback.select_credentials(SelectCredentialRequest::new(credential_map.clone()));

        // filter the credential_map to only include the selected credentials.

        // Create a descriptor map for the presentation submission based on the credentials
        // returned from the selection response.
        let credential_descriptor_map =
            self.create_descriptor_maps(selected_credentials.inner.clone())?;

        // Create a presentation submission.
        let presentation_submission = PresentationSubmission::new(
            presentation_submission_id,
            presentation_definition_id,
            // Use the descriptor map to create the submission.
            credential_descriptor_map
                .iter()
                .map(|(descriptor_map, _)| descriptor_map.clone())
                .collect(),
        )
        .try_into()
        .map_err(|e: anyhow::Error| WalletError::PresentationSubmissionCreation(e.to_string()))?;

        let vp_token = self
            .create_unencoded_verifiable_presentation(
                request,
                credential_descriptor_map
                    .into_iter()
                    .map(|(_, credential)| credential)
                    .collect(),
            )
            .await?;

        // Create a verifiable presentation object.
        Ok(AuthorizationResponse::Unencoded(
            UnencodedAuthorizationResponse(Default::default(), vp_token, presentation_submission),
        ))
    }

    // Internation method for creating a verifiable presentation JWT.
    async fn create_unencoded_verifiable_presentation(
        &self,
        request: &AuthorizationRequestObject,
        credential_descriptor_map: Vec<Arc<Credential>>,
    ) -> Result<VpToken, WalletError> {
        // NOTE: This assumes the client id scheme is DID URL.
        let client_id = DIDURLBuf::from_str(&request.client_id().0)
            .map_err(|e| WalletError::InvalidDIDUrl(e.to_string()))?;

        let verifiable_credential = credential_descriptor_map
            .into_iter()
            .map(|credential| credential.to_json().map_err(WalletError::from))
            .collect::<Result<Vec<Value>, WalletError>>()?;

        let did_key = DIDKey::generate_url(&self.jwk()?)
            .map_err(|e| WalletError::DIDKeyGenerateUrl(e.to_string()))?;

        let verifiable_presentation =
            VerifiablePresentationBuilder::from_options(VerifiablePresentationBuilderOptions {
                issuer: did_key.clone(),
                subject: did_key,
                audience: client_id,
                nonce: request.nonce().clone(),
                // Pull from the VDC collection
                credentials: verifiable_credential.into(),
                expiration_secs: DEFAULT_EXPIRATION_IN_SECONDS,
            });

        let token = verifiable_presentation
            .as_base64_encoded_vp_token()
            .map_err(|e| WalletError::OID4VPToken(e.to_string()))?;

        Ok(token)
    }
}

#[async_trait::async_trait]
impl RequestVerifier for Wallet {
    /// Performs verification on Authorization Request Objects when `client_id_scheme` is `did`.
    async fn did(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> Result<()> {
        // let trusted_dids =
        // .get_trusted_dids(&self.storage_manager)
        // .ok();

        verify_with_resolver(
            &self.metadata,
            decoded_request,
            request_jwt,
            // trusted_dids.as_ref().map(|did| did.as_slice()),
            Some(self.trust_manager.as_slice()),
            &self.jwk()?,
        )
        .await?;

        Ok(())
    }
}

// TODO: The wallet should provide a `factory` for wallet instances
// that implement the protocol-sepecific traits, e.g. `Wallet` in OID4VP.

impl OID4VPWallet for Wallet {
    type HttpClient = oid4vp::core::util::ReqwestClient;

    fn http_client(&self) -> &Self::HttpClient {
        &self.client
    }

    fn metadata(&self) -> &WalletMetadata {
        &self.metadata
    }
}

#[async_trait::async_trait]
impl RequestSigner for Wallet {
    type Error = WalletError;

    fn alg(&self) -> Result<String, Self::Error> {
        Ok(self
            .jwk()?
            .algorithm
            .ok_or(WalletError::SigningAlgorithmNotFound(
                "JWK algorithm not found.".into(),
            ))?
            .to_string())
    }

    fn jwk(&self) -> Result<JWK, Self::Error> {
        unimplemented!()

        // let jwk = self.get_jwk()?;

        // serde_json::from_str(&jwk).map_err(|e| WalletError::JWKParseError(e.to_string()))
    }

    async fn sign(&self, _payload: &[u8]) -> Vec<u8> {
        tracing::warn!("WARNING: use `try_sign` method instead.");

        Vec::with_capacity(0)
    }

    async fn try_sign(&self, _payload: &[u8]) -> Result<Vec<u8>, Self::Error> {
        unimplemented!()
        // let index = self.get_active_key_index()?;
        // let key_id = Key::with_prefix(KEY_MANAGER_PREFIX, &format!("{index}"));

        // self.key_manager
        //     .sign_payload(key_id, payload.to_vec())
        //     .map_err(Into::into)
    }
}

impl JWSSigner for Wallet {
    async fn fetch_info(
        &self,
    ) -> Result<ssi::claims::jws::JWSSignerInfo, ssi::claims::SignatureError> {
        let jwk = self
            .jwk()
            .map_err(|e| ssi::claims::SignatureError::Other(e.to_string()))?;

        let algorithm = jwk.algorithm.ok_or(ssi::claims::SignatureError::Other(
            "JWK algorithm not found.".into(),
        ))?;

        let key_id = jwk.key_id.clone();

        Ok(ssi::claims::jws::JWSSignerInfo { algorithm, key_id })
    }

    async fn sign_bytes(
        &self,
        signing_bytes: &[u8],
    ) -> Result<Vec<u8>, ssi::claims::SignatureError> {
        self.try_sign(signing_bytes)
            .await
            .map_err(|e| ssi::claims::SignatureError::Other(format!("Failed to sign bytes: {}", e)))
    }
}
