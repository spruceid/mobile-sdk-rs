mod error;
mod http_client;
mod proof_of_possession;

pub use error::*;
pub use http_client::*;
pub use proof_of_possession::*;

use std::sync::Arc;

use futures::lock::Mutex;
use oid4vci::{
    core::{
        client, metadata,
        profiles::{
            self,
            w3c::{CredentialDefinition, CredentialDefinitionLD},
            CoreProfilesMetadata, CoreProfilesOffer, CoreProfilesResponse,
        },
    },
    credential::ResponseEnum,
    credential_offer::{CredentialOfferGrants, CredentialOfferParameters},
    metadata::AuthorizationMetadata,
    openidconnect::{AuthorizationCode, ClientId, IssuerUrl, OAuth2TokenResponse, RedirectUrl},
    profiles::CredentialMetadataProfile,
    proof_of_possession::Proof,
    token,
};
use serde::{Deserialize, Serialize};
use ssi_claims::{
    jwt::ToDecodedJWT, vc::v1::data_integrity::any_credential_from_json_str, VerificationParameters,
};
use ssi_dids::{AnyDidMethod, DIDResolver};

use crate::vdc_collection::CredentialFormat;

#[derive(uniffi::Object)]
pub struct OID4VCISession {
    client: Client,
    metadata: Option<CredentialIssuerMetadata>,
    token_response: Mutex<Option<TokenResponse>>,
    credential_request: Mutex<Option<CredentialRequest>>,
    grants: Mutex<Option<Grants>>,
}

// TODO: some or all of these getters/setters can be converted to macros
impl OID4VCISession {
    fn new(client: Client) -> Self {
        Self {
            client,
            metadata: None,
            token_response: None.into(),
            credential_request: None.into(),
            grants: None.into(),
        }
    }

    fn get_client(&self) -> &client::Client {
        &self.client.0
    }

    fn get_metadata(&self) -> Result<&metadata::CredentialIssuerMetadata, OID4VCIError> {
        self.metadata
            .as_ref()
            .map(|w| &w.0)
            .ok_or(OID4VCIError::InvalidSession("metadata unset".into()))
    }

    pub fn set_metadata(&mut self, metadata: CredentialIssuerMetadata) {
        self.metadata = Some(metadata);
    }

    fn get_token_response(&self) -> Result<token::Response, OID4VCIError> {
        self.token_response
            .try_lock()
            .ok_or(OID4VCIError::LockError("token_response".into()))?
            .as_ref()
            .map(|w| w.0.clone())
            .ok_or(OID4VCIError::InvalidSession("token_response unset".into()))
    }

    pub fn set_token_response(&self, token_response: TokenResponse) -> Result<(), OID4VCIError> {
        *(self
            .token_response
            .try_lock()
            .ok_or(OID4VCIError::LockError("token_response".into()))?) = Some(token_response);

        Ok(())
    }

    fn get_credential_requests(&self) -> Result<Vec<profiles::CoreProfilesRequest>, OID4VCIError> {
        self.credential_request
            .try_lock()
            .ok_or(OID4VCIError::LockError("credential_request".into()))?
            .as_ref()
            .map(|w| w.0.clone())
            .ok_or(OID4VCIError::InvalidSession(
                "credential_request unset".into(),
            ))
    }

    pub fn set_credential_request(
        &self,
        credential_request: profiles::CoreProfilesRequest,
    ) -> Result<(), OID4VCIError> {
        *(self
            .credential_request
            .try_lock()
            .ok_or(OID4VCIError::LockError("credential_request".into()))?) =
            Some(vec![credential_request].into());

        Ok(())
    }

    fn set_credential_requests(
        &self,
        credential_requests: Vec<profiles::CoreProfilesRequest>,
    ) -> Result<(), OID4VCIError> {
        *(self
            .credential_request
            .try_lock()
            .ok_or(OID4VCIError::LockError("credential_request".into()))?) =
            Some(credential_requests.into());

        Ok(())
    }

    fn get_grants(&self) -> Result<CredentialOfferGrants, OID4VCIError> {
        self.grants
            .try_lock()
            .ok_or(OID4VCIError::LockError("grants".into()))?
            .as_ref()
            .map(|w| w.0.clone())
            .ok_or(OID4VCIError::InvalidSession("token_response unset".into()))
    }

    fn set_grants(&self, grants: CredentialOfferGrants) -> Result<(), OID4VCIError> {
        *(self
            .grants
            .try_lock()
            .ok_or(OID4VCIError::LockError("grants".into()))?) = Some(grants.into());

        Ok(())
    }
}

// TODO: some or all of these uniffi object wrappers can be converted to macros
#[derive(uniffi::Object)]
pub struct Client(client::Client);
impl From<client::Client> for Client {
    fn from(value: client::Client) -> Self {
        Client(value)
    }
}

#[derive(uniffi::Object)]
pub struct CredentialIssuerMetadata(metadata::CredentialIssuerMetadata);
impl From<metadata::CredentialIssuerMetadata> for CredentialIssuerMetadata {
    fn from(value: metadata::CredentialIssuerMetadata) -> Self {
        CredentialIssuerMetadata(value)
    }
}

#[derive(uniffi::Object)]
pub struct CredentialRequest(Vec<profiles::CoreProfilesRequest>);
impl From<profiles::CoreProfilesRequest> for CredentialRequest {
    fn from(value: profiles::CoreProfilesRequest) -> Self {
        CredentialRequest(vec![value])
    }
}
impl From<Vec<profiles::CoreProfilesRequest>> for CredentialRequest {
    fn from(value: Vec<profiles::CoreProfilesRequest>) -> Self {
        CredentialRequest(value)
    }
}

#[derive(uniffi::Object)]
pub struct TokenResponse(token::Response);
impl From<token::Response> for TokenResponse {
    fn from(value: token::Response) -> Self {
        TokenResponse(value)
    }
}

#[derive(uniffi::Object)]
pub struct Grants(CredentialOfferGrants);
impl From<CredentialOfferGrants> for Grants {
    fn from(value: CredentialOfferGrants) -> Self {
        Grants(value)
    }
}

#[derive(uniffi::Record)]
pub struct CredentialResponse {
    pub format: CredentialFormat,
    pub payload: Vec<u8>,
}

#[uniffi::export]
impl OID4VCISession {
    pub fn get_all_credential_requests(&self) -> Result<Vec<Arc<CredentialRequest>>, OID4VCIError> {
        Ok(self
            .get_metadata()?
            .credential_configurations_supported()
            .iter()
            .map(|c| Arc::new(c.additional_fields().to_request().into()))
            .collect())
    }

    pub fn get_credential_request_by_index(
        &self,
        index: u16,
    ) -> Result<CredentialRequest, OID4VCIError> {
        Ok(self
            .get_metadata()?
            .credential_configurations_supported()
            .get(index as usize)
            .ok_or("invalid credential configuration index".to_string())
            .map_err(OID4VCIError::from)?
            .additional_fields()
            .to_request()
            .into())
    }
}

#[derive(uniffi::Object, Clone, Debug, Serialize, Deserialize)]
pub struct Oid4vciMetadata {
    issuer: String,
    credential_endpoint: String,
    authorization_servers: Option<Vec<String>>,
    batch_credential_endpoint: Option<String>,
    deferred_credential_endpoint: Option<String>,
    notification_endpoint: Option<String>,
}

// TODO: some or all of these getters/setters can be converted to macros
#[uniffi::export]
impl Oid4vciMetadata {
    pub fn to_json(&self) -> Result<String, OID4VCIError> {
        Ok(serde_json::to_string(self)?)
    }

    pub fn issuer(&self) -> String {
        self.issuer.to_owned()
    }

    pub fn credential_endpoint(&self) -> String {
        self.credential_endpoint.to_owned()
    }

    pub fn authorization_servers(&self) -> Option<Vec<String>> {
        self.authorization_servers.to_owned()
    }

    pub fn batch_credential_endpoint(&self) -> Option<String> {
        self.batch_credential_endpoint.to_owned()
    }

    pub fn deferred_credential_endpoint(&self) -> Option<String> {
        self.deferred_credential_endpoint.to_owned()
    }

    pub fn notification_endpoint(&self) -> Option<String> {
        self.notification_endpoint.to_owned()
    }
}

#[uniffi::export]
async fn oid4vci_get_metadata(
    session: Arc<OID4VCISession>,
) -> Result<Oid4vciMetadata, OID4VCIError> {
    let issuer = session
        .get_metadata()?
        .credential_issuer()
        .url()
        .to_string();

    let credential_endpoint = session
        .get_metadata()?
        .credential_endpoint()
        .url()
        .to_string();

    let authorization_servers = session
        .get_metadata()?
        .authorization_servers()
        .map(|v| v.iter().cloned().map(|v| v.url().to_string()).collect());

    let batch_credential_endpoint = session
        .get_metadata()?
        .batch_credential_endpoint()
        .map(|v| v.url().to_string());

    let deferred_credential_endpoint = session
        .get_metadata()?
        .deferred_credential_endpoint()
        .map(|v| v.url().to_string());

    let notification_endpoint = session
        .get_metadata()?
        .notification_endpoint()
        .map(|v| v.url().to_string());

    Ok(Oid4vciMetadata {
        issuer,
        credential_endpoint,
        authorization_servers,
        batch_credential_endpoint,
        deferred_credential_endpoint,
        notification_endpoint,
    })
}

#[uniffi::export]
async fn oid4vci_initiate_with_offer(
    credential_offer: String,
    client_id: String,
    redirect_url: String,
    http_client: Arc<dyn HttpClient>,
) -> Result<OID4VCISession, OID4VCIError> {
    let credential_offer =
        serde_json::from_str::<CredentialOfferParameters<CoreProfilesOffer>>(&credential_offer)
            .map_err(|_| OID4VCIError::SerdeJsonError("".into()))?;

    let base_url = match &credential_offer {
        CredentialOfferParameters::Value {
            credential_issuer, ..
        } => credential_issuer,
        CredentialOfferParameters::Reference {
            credential_issuer, ..
        } => credential_issuer,
    };

    let issuer_metadata = metadata::CredentialIssuerMetadata::discover(
        base_url,
        wrap_http_client(http_client.clone()),
    )?;

    let authorization_metadata = AuthorizationMetadata::discover(
        &issuer_metadata,
        None,
        wrap_http_client(http_client.clone()),
    )?;

    let credential_requests: Vec<profiles::CoreProfilesRequest> = match &credential_offer {
        CredentialOfferParameters::Value { credentials, .. } => credentials
            .iter()
            .map(|c| {
                use oid4vci::core::profiles::w3c;
                use oid4vci::core::profiles::CoreProfilesOffer::*;
                use oid4vci::credential_offer::CredentialOfferFormat::*;
                match c {
                    Reference(_scope) => todo!(),
                    Value(JWTVC(offer)) => CoreProfilesMetadata::JWTVC(w3c::jwt::Metadata::new(
                        CredentialDefinition::new(
                            offer.credential_definition().r#type().to_owned(),
                        ),
                    ))
                    .to_request(),
                    Value(JWTLDVC(offer)) => CoreProfilesMetadata::JWTLDVC(
                        w3c::jwtld::Metadata::new(CredentialDefinitionLD::new(
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
                    Value(LDVC(offer)) => CoreProfilesMetadata::LDVC(w3c::ldp::Metadata::new(
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
                    .to_request(),
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
                if let Some(name) = c.name() {
                    if credential_configuration_ids.iter().any(|cid| *cid == *name) {
                        return Some(c.additional_fields().to_request());
                    }
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
    .map_err(OID4VCIError::from)?;

    let client = client::Client::from_issuer_metadata(
        issuer_metadata.clone(),
        authorization_metadata,
        ClientId::new(client_id),
        RedirectUrl::new(redirect_url).unwrap(),
    );

    let mut session = OID4VCISession::new(client.into());
    session.set_metadata(issuer_metadata.into());
    session.set_credential_requests(credential_requests)?;
    session.set_grants(grants)?;

    Ok(session)
}

#[uniffi::export]
async fn oid4vci_initiate(
    base_url: String,
    client_id: String,
    redirect_url: String,
    http_client: Arc<dyn HttpClient>,
) -> Result<OID4VCISession, OID4VCIError> {
    let issuer_metadata = metadata::CredentialIssuerMetadata::discover(
        &IssuerUrl::new(base_url).unwrap(),
        wrap_http_client(http_client.clone()),
    )?;

    let authorization_metadata = AuthorizationMetadata::discover(
        &issuer_metadata,
        None,
        wrap_http_client(http_client.clone()),
    )?;

    let client = client::Client::from_issuer_metadata(
        issuer_metadata.clone(),
        authorization_metadata,
        ClientId::new(client_id),
        RedirectUrl::new(redirect_url).unwrap(),
    );

    let mut session = OID4VCISession::new(client.into());
    session.set_metadata(issuer_metadata.into());

    Ok(session)
}

#[uniffi::export]
fn oid4vci_exchange_token(
    session: Arc<OID4VCISession>,
    http_client: Arc<dyn HttpClient>,
) -> Result<Option<String>, OID4VCIError> {
    // TODO: refactor with `try {}` once it stabilizes.
    let authorization_code = (|| -> Result<String, OID4VCIError> {
        if let Some(pre_auth) = session.get_grants()?.pre_authorized_code() {
            return Ok(pre_auth.pre_authorized_code().to_owned());
        }

        Err(OID4VCIError::UnsupportedGrantType)
    })()?;

    let token_response = session
        .get_client()
        .exchange_code(AuthorizationCode::new(authorization_code))
        .request(wrap_http_client(http_client.clone()))?;

    let nonce = token_response
        .extra_fields()
        .c_nonce
        .clone()
        .map(|v| v.secret().to_owned());

    session.set_token_response(token_response.into())?;

    Ok(nonce)
}

#[uniffi::export]
async fn oid4vci_exchange_credential(
    session: Arc<OID4VCISession>,
    proofs_of_possession: Vec<String>,
    http_client: Arc<dyn HttpClient>,
) -> Result<Vec<CredentialResponse>, OID4VCIError> {
    let credential_requests = session.get_credential_requests()?.clone();

    if credential_requests.is_empty() {
        return Err(OID4VCIError::InvalidSession(
            "credential_requests unset".to_string(),
        ));
    }

    if proofs_of_possession.len() != credential_requests.len() {
        return Err(OID4VCIError::InvalidParameter(
            "invalid number of proofs received, must match credential request count".into(),
        ));
    }

    let credential_responses = if credential_requests.len() == 1 {
        vec![session
            .get_client()
            .request_credential(
                session.get_token_response()?.access_token().clone(),
                credential_requests.first().unwrap().to_owned(),
            )
            .set_proof(Some(Proof::JWT {
                jwt: proofs_of_possession.first().unwrap().to_owned(),
            }))
            .request(wrap_http_client(http_client))?
            .additional_profile_fields()
            .to_owned()]
    } else {
        session
            .get_client()
            .batch_request_credential(
                session.get_token_response()?.access_token().clone(),
                credential_requests.to_vec(),
            )?
            .set_proofs::<OID4VCIError>(
                proofs_of_possession
                    .into_iter()
                    .map(|p| Proof::JWT { jwt: p })
                    .collect(),
            )?
            .request(wrap_http_client(http_client))?
            .credential_responses()
            .to_owned()
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
                            .map_err(OID4VCIError::from)
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
                        .map_err(OID4VCIError::from)
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
                        .map_err(OID4VCIError::from)
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
