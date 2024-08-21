use crate::{
    key_manager::KEY_MANAGER_PREFIX,
    storage_manager::Key,
    vdc_collection::Credential,
    wallet::{Wallet, WalletError},
};

use std::{
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use oid4vp::{
    core::{
        authorization_request::{
            parameters::PresentationDefinition,
            verification::{did::verify_with_resolver, RequestVerifier},
            AuthorizationRequestObject,
        },
        metadata::WalletMetadata,
        response::{parameters::VpToken, AuthorizationResponse, UnencodedAuthorizationResponse},
    },
    presentation_exchange::{ClaimFormatDesignation, DescriptorMap, PresentationSubmission},
    verifier::request_signer::RequestSigner,
    wallet::Wallet as OID4VPWallet,
};
use ssi_claims::{jws::JWSSigner, jwt::VerifiablePresentation, JWSPayload, JWTClaims};
use ssi_dids::{
    ssi_json_ld::{
        syntax::{Object, Value},
        CREDENTIALS_V1_CONTEXT,
    },
    DIDKey, DIDURLBuf,
};
use ssi_jwk::JWK;
use ssi_vc::v2::syntax::VERIFIABLE_PRESENTATION_TYPE;

// 5 minute default expiration.
const DEFAULT_EXPIRATION_IN_SECONDS: u64 = 60 * 5;

// Internal wallet methods implementing the OID4VP specification.
impl Wallet {
    /// Retrieves the credentials from the wallet
    /// storage based on the presentation definition.
    fn retrieve_credentials(
        &self,
        presentation_definition: &PresentationDefinition,
    ) -> Result<Vec<Option<Credential>>, WalletError> {
        presentation_definition
            .parsed()
            .input_descriptors()
            .iter()
            .map(|input_descriptor| {
                match self
                    .vdc_collection
                    .get(input_descriptor.id(), &self.storage_manager)
                {
                    Ok(Some(credential)) => Ok(Some(credential)),
                    Ok(None) => {
                        // Check if the input descriptor contains required constraints.
                        if input_descriptor.constraints().is_required() {
                            Err(WalletError::RequiredCredentialNotFound(
                                input_descriptor.id().to_string(),
                            ))
                        } else {
                            Ok(None)
                        }
                    }
                    Err(e) => Err(WalletError::VdcCollection(e)),
                }
            })
            .collect::<Result<Vec<_>, _>>()
    }

    // Construct a DescriptorMap for the presentation submission based on the
    // credentials returned from the VDC collection.
    fn create_descriptor_maps(
        &self,
        credentials: Vec<Option<Credential>>,
    ) -> Vec<(DescriptorMap, Credential)> {
        credentials
            .into_iter()
            // Filter out the credentials that are not found in the storage.
            .filter_map(|credential| credential)
            // Enumerate over the existing credentials to create a descriptor map.
            .enumerate()
            .map(|(index, credential)| {
                (
                    DescriptorMap::new(
                        *credential.id(),
                        ClaimFormatDesignation::JwtVpJson,
                        "$.vp".into(),
                    )
                    // TODO: Determine if the nested path should be set.
                    // For example: `$.vc` or `$.verifiableCredential`
                    .set_path_nested(DescriptorMap::new(
                        *credential.id(),
                        credential.format().to_owned(),
                        // NOTE: The path is set to the index of the credential
                        // in the presentation submission.
                        format!("$.verifiableCredential[{index}]"),
                    )),
                    // Return the credential for the presentation submission.
                    // This is used to construct the `verifiableCredentials` array
                    // in the presentation submission. The index position
                    // of the credential in the array must match the index position
                    // of the descriptor in the descriptor map.
                    credential,
                )
            })
            .collect::<Vec<(DescriptorMap, Credential)>>()
    }

    // Internal method for creating a verifiable presentation object.
    pub(crate) async fn handle_unencoded_authorization_request(
        &self,
        request: &AuthorizationRequestObject,
    ) -> Result<AuthorizationResponse, WalletError> {
        // Resolve the presentation definition.
        let presentation_definition = request
            .resolve_presentation_definition(self.http_client())
            .await
            .map_err(|e| WalletError::OID4VPPresentationDefinitionResolution(e.to_string()))?;

        let presentation_submission_id = uuid::Uuid::new_v4();
        let presentation_definition_id = presentation_definition.parsed().id().clone();

        // Check if the verifiable credential(s) exists in the storage.
        let credentials = self.retrieve_credentials(&presentation_definition)?;

        // Create a descriptor map for the presentation submission based on the credentials
        // returned from the VDC collection.
        //
        // NOTE: The order of the descriptor map is important as the index of the descriptor
        // in the presentation submission must match the index of the credential in the
        // presentation submission.
        //
        // For example, when adding to the `verifiableCredentials` array in the presentation
        // submission, the order of the credentials must match the order of the descriptors
        // in the descriptor map where there paths are index-based.
        let credential_descriptor_map = self.create_descriptor_maps(credentials);

        // Create a presentation submission.
        let presentation_submission = PresentationSubmission::new(
            presentation_submission_id,
            presentation_definition_id,
            // Use the descriptor map to create the submission.
            credential_descriptor_map
                .iter()
                .map(|(descriptor, _)| descriptor.clone())
                .collect(),
        )
        .try_into()
        .map_err(|e: anyhow::Error| WalletError::PresentationSubmissionCreation(e.to_string()))?;

        let vp_token = self
            .create_verifiable_presentation_jwt(request, credential_descriptor_map)
            .await?;

        // Create a verifiable presentation object.
        Ok(AuthorizationResponse::Unencoded(
            UnencodedAuthorizationResponse(
                Default::default(),
                VpToken(vp_token),
                presentation_submission,
            ),
        ))
    }

    // Internation method for creating a verifiable presentation JWT.
    async fn create_verifiable_presentation_jwt(
        &self,
        request: &AuthorizationRequestObject,
        credential_descriptor_map: Vec<(DescriptorMap, Credential)>,
    ) -> Result<String, WalletError> {
        // NOTE: This assumes the client id scheme is DID URL.
        let client_id = DIDURLBuf::from_str(&request.client_id().0)
            .map_err(|e| WalletError::InvalidDIDUrl(e.to_string()))?;

        let verifiable_credential = credential_descriptor_map
            .into_iter()
            .map(|(_, credential)| credential)
            .map(|credential| {
                serde_json::from_slice::<Value>(credential.payload())
                    .map_err(|e| WalletError::SerdeJson(e.to_string()))
            })
            .collect::<Result<Vec<Value>, WalletError>>()?;

        let did_key = DIDKey::generate_url(&self.jwk()?)
            .map_err(|e| WalletError::DIDKeyGenerateUrl(e.to_string()))?;

        let mut verifiable_presentation = VerifiablePresentation(Value::Object(Object::new()));

        verifiable_presentation.0.as_object_mut().map(|obj| {
            // The issuer is the holder of the verifiable credential (subject of the verifiable credential).
            obj.insert("iss".into(), Value::String(did_key.as_str().into()));

            // The audience is the verifier of the verifiable credential.
            obj.insert("aud".into(), Value::String(client_id.as_str().into()));

            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .map(|dur| {
                    // The issuance date is the current time.
                    obj.insert("iat".into(), Value::Number(dur.as_secs().into()));

                    obj.insert(
                        "exp".into(),
                        // TODO: Determine if the expiration time should be configurable.
                        Value::Number((dur.as_secs() + DEFAULT_EXPIRATION_IN_SECONDS).into()),
                    );
                });

            obj.insert(
                "nonce".into(),
                // The response nonce should use the request nonce.
                Value::String(request.nonce().to_string().into()),
            );

            let mut verifiable_credential_field = Value::Object(Object::new());

            verifiable_credential_field.as_object_mut().map(|cred| {
                cred.insert(
                    "@context".into(),
                    Value::String(CREDENTIALS_V1_CONTEXT.to_string().into()),
                );

                cred.insert(
                    "type".into(),
                    Value::String(VERIFIABLE_PRESENTATION_TYPE.to_string().into()),
                );

                cred.insert(
                    "verifiableCredential".into(),
                    Value::Array(verifiable_credential),
                );
            });

            // Insert the verifiable credentials into the verifiable presentation
            // `vp` field.
            obj.insert("vp".into(), verifiable_credential_field);
        });

        let claim = JWTClaims::from_private_claims(verifiable_presentation);

        let jwt = claim
            .sign(&self)
            .await
            .map_err(|e| WalletError::SigningError(e.to_string()))?;

        Ok(jwt.to_string())
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
        let trusted_dids = self
            .trust_manager
            .get_trusted_dids(&self.storage_manager)
            .ok();

        let wallet_metadata = self.metadata.clone();

        verify_with_resolver(
            &wallet_metadata,
            decoded_request,
            request_jwt,
            trusted_dids.as_ref().map(|did| did.as_slice()),
            &self.jwk()?,
        )
        .await?;

        Ok(())
    }
}

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
        let jwk = self.get_jwk()?;

        serde_json::from_str(&jwk).map_err(|e| WalletError::JWKParseError(e.to_string()))
    }

    async fn sign(&self, _payload: &[u8]) -> Vec<u8> {
        tracing::warn!("WARNING: use `try_sign` method instead.");

        Vec::with_capacity(0)
    }

    async fn try_sign(&self, payload: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let index = self.get_active_key_index()?;
        let key_id = Key::with_prefix(KEY_MANAGER_PREFIX, &format!("{index}"));

        self.key_manager
            .sign_payload(key_id, payload.to_vec())
            .ok_or(WalletError::SigningError(
                "key manager failed to sign payload".into(),
            ))
    }
}

impl JWSSigner for Wallet {
    async fn fetch_info(
        &self,
    ) -> Result<ssi_claims::jws::JWSSignerInfo, ssi_claims::SignatureError> {
        let jwk = self
            .jwk()
            .map_err(|e| ssi_claims::SignatureError::Other(e.to_string()))?;

        let algorithm = jwk.algorithm.ok_or(ssi_claims::SignatureError::Other(
            "JWK algorithm not found.".into(),
        ))?;

        let key_id = jwk.key_id.clone();

        Ok(ssi_claims::jws::JWSSignerInfo { algorithm, key_id })
    }

    async fn sign_bytes(
        &self,
        signing_bytes: &[u8],
    ) -> Result<Vec<u8>, ssi_claims::SignatureError> {
        self.try_sign(signing_bytes).await.map_err(|e| {
            ssi_claims::SignatureError::Other(format!("Failed to sign bytes: {}", e).into())
        })
    }
}
