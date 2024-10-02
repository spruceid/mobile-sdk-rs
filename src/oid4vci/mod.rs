mod error;
mod http_client;
mod metadata;
mod proof_of_possession;
mod session;
mod wrapper;

pub use error::*;
pub use http_client::*;
pub use metadata::*;
pub use proof_of_possession::*;
pub use session::*;
use url::Url;
pub use wrapper::*;

use std::sync::Arc;

use either::Either;
use oid4vci::{
    client,
    core::{
        metadata::CredentialIssuerMetadata as ICredentialIssuerMetadata,
        profiles::{
            jwt_vc_json_ld, ldp_vc, CoreProfilesCredentialConfiguration,
            CoreProfilesCredentialRequest, CredentialRequestWithFormat,
        },
    },
    credential::ResponseEnum,
    credential_offer::CredentialOffer,
    metadata::{authorization_server::GrantType, AuthorizationServerMetadata, MetadataDiscovery},
    oauth2::{ClientId, RedirectUrl, TokenResponse as ITokenResponse},
    proof_of_possession::Proof,
    types::{CredentialOfferRequest, IssuerUrl, PreAuthorizedCode},
};
use ssi::{
    claims::{
        jwt::ToDecodedJwt, vc::v1::data_integrity::any_credential_from_json_str,
        VerificationParameters,
    },
    dids::{AnyDidMethod, DIDResolver},
};

use crate::credential::CredentialFormat;

#[uniffi::export]
pub async fn oid4vci_initiate_with_offer(
    credential_offer: String,
    client_id: String,
    redirect_url: String,
    http_client: Arc<IHttpClient>,
) -> Result<Oid4vciSession, Oid4vciError> {
    let credential_offer = Url::parse(&credential_offer).map_err(|_| {
        Oid4vciError::InvalidParameter("invalid credential_offer: failed to parse url".into())
    })?;

    let credential_offer = CredentialOffer::from_request(
        CredentialOfferRequest::from_url_checked(credential_offer).map_err(|_| {
            Oid4vciError::InvalidParameter("invalid credential_offer: failed to parse offer".into())
        })?,
    )
    .map_err(|_| {
        Oid4vciError::InvalidParameter("invalid credential_offer: failed to decode offer".into())
    })?;

    let credential_offer = match &http_client.0 {
        Either::Left(sync_client) => credential_offer.resolve(sync_client),
        Either::Right(async_client) => credential_offer.resolve_async(async_client).await,
    }
    .map_err(|_| {
        Oid4vciError::InvalidParameter("invalid credential_offer: failed to resolve offer".into())
    })?;

    let base_url = credential_offer.issuer();

    let issuer_metadata = match &http_client.0 {
        Either::Left(sync_client) => ICredentialIssuerMetadata::discover(base_url, sync_client),
        Either::Right(async_client) => {
            ICredentialIssuerMetadata::discover_async(base_url, async_client).await
        }
    }
    .map_err(|_| {
        Oid4vciError::RequestError("failed to discover credential issuer metadata".into())
    })?;

    let grants = credential_offer.grants().map(|g| g.to_owned());

    let authorization_metadata =
        if let Some(grant) = credential_offer.pre_authorized_code_grant() {
            // TODO: maybe offer a way for the wallet to pick grant ordering
            // when multiple options are present

            let authorization_server = grant.authorization_server();

            match &http_client.0 {
                Either::Left(sync_client) => {
                    AuthorizationServerMetadata::discover_from_credential_issuer_metadata(
                        sync_client,
                        &issuer_metadata,
                        Some(&GrantType::PreAuthorizedCode),
                        authorization_server,
                    )
                }
                Either::Right(async_client) => {
                    AuthorizationServerMetadata::discover_from_credential_issuer_metadata_async(
                        async_client,
                        &issuer_metadata,
                        Some(&GrantType::PreAuthorizedCode),
                        authorization_server,
                    )
                    .await
                }
            }
        } else {
            // TODO: if grants isn't present in the credential offer
            // we must determine the grant type by using the metadata.
            // Potentially defer to caller using a ForeignTrait after
            // obtaining `grant_types_supported` from authorization server
            // metadata. Future solution must keep in mind that the
            // `authorization_servers` field is an array, so multiple
            // grant options from different servers may be available.
            todo!("determine grant type with metadata")
        }
        .map_err(|_| {
            Oid4vciError::RequestError("failed to discover authorization server metadata".into())
        })?;

    let credential_requests: Vec<CoreProfilesCredentialRequest> = issuer_metadata
        .credential_configurations_supported()
        .iter()
        .filter(|config| {
            credential_offer
                .credential_configuration_ids()
                .contains(config.id())
        })
        .map(|config| match config.profile_specific_fields() {
            CoreProfilesCredentialConfiguration::LdpVc(config) => {
                let credential_definition =
                    ldp_vc::authorization_detail::CredentialDefinition::default()
                        .set_context(config.credential_definition().context().clone())
                        .set_type(config.credential_definition().r#type().clone());
                CredentialRequestWithFormat::LdpVc(ldp_vc::CredentialRequestWithFormat::new(
                    credential_definition,
                ))
            }
            CoreProfilesCredentialConfiguration::JwtVcJsonLd(config) => {
                let credential_definition =
                    ldp_vc::authorization_detail::CredentialDefinition::default()
                        .set_context(config.credential_definition().context().clone())
                        .set_type(config.credential_definition().r#type().clone());
                CredentialRequestWithFormat::JwtVcJsonLd(
                    jwt_vc_json_ld::CredentialRequestWithFormat::new(credential_definition),
                )
            }
            x => unimplemented!("{x:?}"),
        })
        .map(|req| CoreProfilesCredentialRequest::WithFormat {
            inner: req,
            _credential_identifier: (),
        })
        .collect();

    let client = client::Client::from_issuer_metadata(
        ClientId::new(client_id),
        RedirectUrl::new(redirect_url).unwrap(),
        issuer_metadata.clone(),
        authorization_metadata,
    );

    let mut session = Oid4vciSession::new(client.into());
    session.set_metadata(issuer_metadata.into());
    session.set_credential_requests(credential_requests)?;
    session.set_grants(grants)?;

    Ok(session)
}

#[uniffi::export]
pub async fn oid4vci_initiate(
    base_url: String,
    client_id: String,
    redirect_url: String,
    http_client: Arc<IHttpClient>,
) -> Result<Oid4vciSession, Oid4vciError> {
    let base_url = IssuerUrl::new(base_url)
        .map_err(|e| e.to_string())
        .map_err(Oid4vciError::from)?;

    let issuer_metadata = match &http_client.0 {
        Either::Left(sync_client) => ICredentialIssuerMetadata::discover(&base_url, sync_client),
        Either::Right(async_client) => {
            ICredentialIssuerMetadata::discover_async(&base_url, async_client).await
        }
    }
    .map_err(|_| {
        Oid4vciError::RequestError("failed to discover credential issuer metadata".into())
    })?;

    let authorization_metadata = match &http_client.0 {
        Either::Left(sync_client) => AuthorizationServerMetadata::discover(&base_url, sync_client),
        Either::Right(async_client) => {
            AuthorizationServerMetadata::discover_async(&base_url, async_client).await
        }
    }
    .map_err(|_| {
        Oid4vciError::RequestError("failed to discover authorization server metadata".into())
    })?;

    let client = client::Client::from_issuer_metadata(
        ClientId::new(client_id),
        RedirectUrl::new(redirect_url).unwrap(),
        issuer_metadata.clone(),
        authorization_metadata,
    );

    let mut session = Oid4vciSession::new(client.into());
    session.set_metadata(issuer_metadata.into());

    Ok(session)
}

#[uniffi::export]
pub async fn oid4vci_exchange_token(
    session: Arc<Oid4vciSession>,
    http_client: Arc<IHttpClient>,
) -> Result<Option<String>, Oid4vciError> {
    // TODO: refactor with `try {}` once it stabilizes.
    let code = (|| -> Result<PreAuthorizedCode, Oid4vciError> {
        if let Some(pre_auth) = session.get_grants()?.pre_authorized_code() {
            return Ok(pre_auth.pre_authorized_code().clone());
        }

        Err(Oid4vciError::UnsupportedGrantType)
    })()?;

    let token_response = match &http_client.0 {
        Either::Left(sync_client) => session
            .get_client()
            .exchange_pre_authorized_code(code)
            .set_anonymous_client()
            .request(sync_client),
        Either::Right(async_client) => {
            session
                .get_client()
                .exchange_pre_authorized_code(code)
                .set_anonymous_client()
                .request_async(async_client)
                .await
        }
    }
    .map_err(|_| Oid4vciError::RequestError("failed to exchange code".into()))?;

    let nonce = token_response
        .extra_fields()
        .c_nonce
        .clone()
        .map(|v| v.secret().to_owned());

    session.set_token_response(token_response.into())?;

    Ok(nonce)
}

#[uniffi::export]
pub async fn oid4vci_exchange_credential(
    session: Arc<Oid4vciSession>,
    proofs_of_possession: Vec<String>,
    http_client: Arc<IHttpClient>,
) -> Result<Vec<CredentialResponse>, Oid4vciError> {
    let credential_requests = session.get_credential_requests()?.clone();

    if credential_requests.is_empty() {
        return Err(Oid4vciError::InvalidSession(
            "credential_requests unset".to_string(),
        ));
    }

    if proofs_of_possession.len() != credential_requests.len() {
        return Err(Oid4vciError::InvalidParameter(
            "invalid number of proofs received, must match credential request count".into(),
        ));
    }

    let credential_responses = if credential_requests.len() == 1 {
        let request = session
            .get_client()
            .request_credential(
                session.get_token_response()?.access_token().clone(),
                credential_requests.first().unwrap().to_owned(),
            )
            .set_proof(Some(Proof::Jwt {
                jwt: proofs_of_possession.first().unwrap().to_owned(),
            }));

        let response = match &http_client.0 {
            Either::Left(sync_client) => request.request(sync_client),
            Either::Right(async_client) => request.request_async(async_client).await,
        }?;

        match response.response_kind() {
            ResponseEnum::Immediate { credential } => vec![credential.to_owned()],
            ResponseEnum::ImmediateMany { credentials } => credentials.to_owned(),
            ResponseEnum::Deferred { .. } => todo!(),
        }
    } else {
        let request = session
            .get_client()
            .batch_request_credential(
                session.get_token_response()?.access_token().clone(),
                credential_requests.to_vec(),
            )?
            .set_proofs::<Oid4vciError>(
                proofs_of_possession
                    .into_iter()
                    .map(|p| Proof::Jwt { jwt: p })
                    .collect(),
            )?;

        let response = match &http_client.0 {
            Either::Left(sync_client) => request.request(sync_client)?,
            Either::Right(async_client) => request.request_async(async_client).await?,
        };

        response
            .credential_responses()
            .iter()
            .flat_map(|r| match r {
                ResponseEnum::Immediate { credential } => vec![credential.to_owned()],
                ResponseEnum::ImmediateMany { credentials } => credentials.to_owned(),
                ResponseEnum::Deferred { .. } => todo!(),
            })
            .collect()
    };

    futures::future::try_join_all(credential_responses.into_iter().map(
        move |credential_response| async {
            let vm_resolver = AnyDidMethod::default().into_vm_resolver();
            let params = VerificationParameters::from_resolver(vm_resolver);

            use oid4vci::core::profiles::CoreProfilesCredentialResponseType::*;

            match credential_response {
                JwtVcJson(response) => Ok(CredentialResponse {
                    format: CredentialFormat::JwtVcJson,
                    payload: response
                        .verify_jwt(&params)
                        .await
                        .map_err(|e| e.to_string())
                        .map_err(Oid4vciError::from)
                        .map(|_| response.as_bytes().to_vec())?,
                }),
                JwtVcJsonLd(response) => Ok(CredentialResponse {
                    format: CredentialFormat::JwtVcJsonLd,
                    payload: any_credential_from_json_str(
                        &serde_json::to_string(&response).unwrap(),
                    )
                    .unwrap()
                    .verify(&params)
                    .await
                    .map_err(|e| e.to_string())
                    .map_err(Oid4vciError::from)
                    .map(|_| serde_json::to_vec(&response).unwrap())?,
                }),
                LdpVc(response) => Ok(CredentialResponse {
                    format: CredentialFormat::JwtVcJson,
                    payload: any_credential_from_json_str(
                        &serde_json::to_string(&response).unwrap(),
                    )
                    .unwrap()
                    .verify(&params)
                    .await
                    .map_err(|e| e.to_string())
                    .map_err(Oid4vciError::from)
                    .map(|_| serde_json::to_vec(&response).unwrap())?,
                }),
                MsoMdoc(_) => todo!(),
            }
        },
    ))
    .await
}
