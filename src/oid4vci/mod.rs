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
pub use wrapper::*;

use std::sync::Arc;

use either::Either;
use oid4vci::{
    core::{
        client,
        metadata::CredentialIssuerMetadata as ICredentialIssuerMetadata,
        profiles::{
            self,
            w3c::{CredentialDefinition, CredentialDefinitionLD},
            CoreProfilesConfiguration, CoreProfilesOffer, CoreProfilesResponse,
        },
    },
    credential::ResponseEnum,
    credential_offer::CredentialOfferParameters,
    metadata::AuthorizationMetadata,
    openidconnect::{AuthorizationCode, ClientId, IssuerUrl, OAuth2TokenResponse, RedirectUrl},
    profiles::CredentialConfigurationProfile,
    proof_of_possession::Proof,
};
use ssi::{
    claims::{
        jwt::ToDecodedJWT, vc::v1::data_integrity::any_credential_from_json_str,
        VerificationParameters,
    },
    dids::{AnyDidMethod, DIDResolver},
};

use crate::vdc_collection::CredentialFormat;

#[uniffi::export]
pub async fn oid4vci_initiate_with_offer(
    credential_offer: String,
    client_id: String,
    redirect_url: String,
    http_client: Arc<IHttpClient>,
) -> Result<Oid4vciSession, Oid4vciError> {
    let credential_offer =
        serde_json::from_str::<CredentialOfferParameters<CoreProfilesOffer>>(&credential_offer)
            .map_err(|_| Oid4vciError::SerdeJsonError("".into()))?;

    let base_url = match &credential_offer {
        CredentialOfferParameters::Value {
            credential_issuer, ..
        } => credential_issuer,
        CredentialOfferParameters::Reference {
            credential_issuer, ..
        } => credential_issuer,
    };

    let issuer_metadata = match &http_client.0 {
        Either::Left(sync_client) => ICredentialIssuerMetadata::discover(base_url, sync_client),
        Either::Right(async_client) => {
            ICredentialIssuerMetadata::discover_async(base_url.to_owned(), async_client).await
        }
    }?;

    let authorization_metadata = match &http_client.0 {
        Either::Left(sync_client) => {
            AuthorizationMetadata::discover(&issuer_metadata, None, sync_client)
        }
        Either::Right(async_client) => {
            AuthorizationMetadata::discover_async(&issuer_metadata, None, async_client).await
        }
    }?;

    let credential_requests: Vec<profiles::CoreProfilesRequest> = match &credential_offer {
        CredentialOfferParameters::Value { credentials, .. } => credentials
            .iter()
            .map(|c| {
                use oid4vci::core::profiles::w3c;
                use oid4vci::core::profiles::CoreProfilesOffer::*;
                use oid4vci::credential_offer::CredentialOfferFormat::*;
                match c {
                    Reference(_scope) => todo!(),
                    Value(JWTVC(offer)) => CoreProfilesConfiguration::JWTVC(
                        w3c::jwt::Configuration::new(CredentialDefinition::new(
                            offer.credential_definition().r#type().to_owned(),
                        )),
                    )
                    .to_request(),
                    Value(JWTLDVC(offer)) => CoreProfilesConfiguration::JWTLDVC(
                        w3c::jwtld::Configuration::new(CredentialDefinitionLD::new(
                            CredentialDefinition::new(
                                offer
                                    .credential_definition()
                                    .credential_offer_definition()
                                    .r#type()
                                    .to_owned(),
                            ),
                            offer.credential_definition().context().to_owned(),
                        )),
                    )
                    .to_request(),
                    Value(LDVC(offer)) => {
                        CoreProfilesConfiguration::LDVC(w3c::ldp::Configuration::new(
                            offer.credential_definition().context().to_owned(),
                            CredentialDefinitionLD::new(
                                CredentialDefinition::new(
                                    offer
                                        .credential_definition()
                                        .credential_offer_definition()
                                        .r#type()
                                        .to_owned(),
                                ),
                                offer.credential_definition().context().to_owned(),
                            ),
                        ))
                        .to_request()
                    }
                    Value(ISOmDL(_)) => todo!(),
                }
            })
            .collect(),
        CredentialOfferParameters::Reference {
            credential_configuration_ids,
            ..
        } => issuer_metadata
            .credential_configurations_supported()
            .iter()
            .filter_map(|c| {
                if credential_configuration_ids
                    .iter()
                    .any(|cid| *cid == *c.name())
                {
                    return Some(c.additional_fields().to_request());
                }
                None
            })
            .collect(),
    };

    let grants = match &credential_offer {
        CredentialOfferParameters::Value { grants, .. } => grants,
        CredentialOfferParameters::Reference { grants, .. } => grants,
    }
    .clone()
    .ok_or("missing grants".to_string())
    .map_err(Oid4vciError::from)?;

    let client = client::Client::from_issuer_metadata(
        issuer_metadata.clone(),
        authorization_metadata,
        ClientId::new(client_id),
        RedirectUrl::new(redirect_url).unwrap(),
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
            ICredentialIssuerMetadata::discover_async(base_url.to_owned(), async_client).await
        }
    }?;

    let authorization_metadata = match &http_client.0 {
        Either::Left(sync_client) => {
            AuthorizationMetadata::discover(&issuer_metadata, None, sync_client)
        }
        Either::Right(async_client) => {
            AuthorizationMetadata::discover_async(&issuer_metadata, None, async_client).await
        }
    }?;

    let client = client::Client::from_issuer_metadata(
        issuer_metadata.clone(),
        authorization_metadata,
        ClientId::new(client_id),
        RedirectUrl::new(redirect_url).unwrap(),
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
    let authorization_code = (|| -> Result<String, Oid4vciError> {
        if let Some(pre_auth) = session.get_grants()?.pre_authorized_code() {
            return Ok(pre_auth.pre_authorized_code().to_owned());
        }

        Err(Oid4vciError::UnsupportedGrantType)
    })()?;

    let token_response = match &http_client.0 {
        Either::Left(sync_client) => session
            .get_client()
            .exchange_code(AuthorizationCode::new(authorization_code))
            .request(sync_client),
        Either::Right(async_client) => {
            session
                .get_client()
                .exchange_code(AuthorizationCode::new(authorization_code))
                .request_async(async_client)
                .await
        }
    }?;

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
            .set_proof(Some(Proof::JWT {
                jwt: proofs_of_possession.first().unwrap().to_owned(),
            }));

        vec![match &http_client.0 {
            Either::Left(sync_client) => request
                .request(sync_client)?
                .additional_profile_fields()
                .to_owned(),
            Either::Right(async_client) => request
                .request_async(async_client)
                .await?
                .additional_profile_fields()
                .to_owned(),
        }]
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
                    .map(|p| Proof::JWT { jwt: p })
                    .collect(),
            )?;

        match &http_client.0 {
            Either::Left(sync_client) => request
                .request(sync_client)?
                .credential_responses()
                .to_owned(),
            Either::Right(async_client) => request
                .request_async(async_client)
                .await?
                .credential_responses()
                .to_owned(),
        }
    };

    futures::future::try_join_all(credential_responses.into_iter().map(
        move |credential_response| async {
            let vm_resolver = AnyDidMethod::default().into_vm_resolver();
            let params = VerificationParameters::from_resolver(vm_resolver);

            match credential_response {
                ResponseEnum::Immediate(imm) => match imm {
                    CoreProfilesResponse::JWTVC(response) => Ok(CredentialResponse {
                        format: CredentialFormat::JwtVcJson,
                        payload: response
                            .credential()
                            .verify_jwt(&params)
                            .await
                            .map_err(|e| e.to_string())
                            .map_err(Oid4vciError::from)
                            .map(|_| response.credential().as_bytes().to_vec())?,
                    }),
                    CoreProfilesResponse::JWTLDVC(response) => Ok(CredentialResponse {
                        format: CredentialFormat::JwtVcJsonLd,
                        payload: any_credential_from_json_str(
                            &serde_json::to_string(response.credential()).unwrap(),
                        )
                        .unwrap()
                        .verify(&params)
                        .await
                        .map_err(|e| e.to_string())
                        .map_err(Oid4vciError::from)
                        .map(|_| serde_json::to_vec(response.credential()).unwrap())?,
                    }),
                    CoreProfilesResponse::LDVC(response) => Ok(CredentialResponse {
                        format: CredentialFormat::JwtVcJson,
                        payload: any_credential_from_json_str(
                            &serde_json::to_string(response.credential()).unwrap(),
                        )
                        .unwrap()
                        .verify(&params)
                        .await
                        .map_err(|e| e.to_string())
                        .map_err(Oid4vciError::from)
                        .map(|_| serde_json::to_vec(response.credential()).unwrap())?,
                    }),
                    CoreProfilesResponse::ISOmDL(_) => todo!(),
                },
                ResponseEnum::Deferred { .. } => todo!(),
            }
        },
    ))
    .await
}
