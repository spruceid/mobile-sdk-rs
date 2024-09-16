use crate::{common::*, credential::mdoc::Mdoc};
pub mod reader;

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use isomdl::{
    definitions::{
        device_engagement::{CentralClientMode, DeviceRetrievalMethods},
        helpers::NonEmptyMap,
        session, BleOptions, DeviceRetrievalMethod, SessionEstablishment,
    },
    presentation::device::{self, SessionManagerInit},
};
use ssi::{
    claims::vc::v1::{data_integrity::any_credential_from_json_str, ToJwtClaims},
    dids::{AnyDidMethod, DIDResolver},
};

#[derive(thiserror::Error, uniffi::Error, Debug)]
pub enum SessionError {
    #[error("{value}")]
    Generic { value: String },
}

#[derive(uniffi::Object)]
pub struct SessionManagerEngaged(device::SessionManagerEngaged);

#[derive(uniffi::Record)]
struct SessionData {
    state: Arc<SessionManagerEngaged>,
    qr_code_uri: String,
    ble_ident: Vec<u8>,
}

#[derive(thiserror::Error, uniffi::Error, Debug)]
pub enum VCVerificationError {
    #[error("{value}")]
    Generic { value: String },
}

#[uniffi::export]
pub async fn verify_json_vc_string(json: String) -> Result<(), VCVerificationError> {
    use ssi::prelude::VerificationParameters;

    let vc = any_credential_from_json_str(&json).map_err(|e| VCVerificationError::Generic {
        value: e.to_string(),
    })?;

    let vm_resolver = AnyDidMethod::default().into_vm_resolver();
    let params = VerificationParameters::from_resolver(vm_resolver);

    vc.verify(&params)
        .await
        .map_err(|e| VCVerificationError::Generic {
            value: e.to_string(),
        })?
        .map_err(|e| VCVerificationError::Generic {
            value: e.to_string(),
        })
}

#[derive(thiserror::Error, uniffi::Error, Debug)]
pub enum VPError {
    #[error("verification failed")]
    Verification,
    #[error("failed signing jwt")]
    Signing,
    #[error("{value}")]
    Parsing { value: String },
    #[error("{value}")]
    Generic { value: String },
}

#[uniffi::export]
pub async fn vc_to_signed_vp(vc: String, key_str: String) -> Result<String, VPError> {
    use ssi::prelude::*;

    let vp = ssi::claims::vc::v1::JsonPresentation::new(None, None, vec![vc]);

    let mut key: ssi::jwk::JWK = serde_json::from_str(&key_str).map_err(|e| VPError::Parsing {
        value: e.to_string(),
    })?;
    let did = DIDJWK::generate_url(&key.to_public());
    key.key_id = Some(did.into());

    let jwt = vp
        .to_jwt_claims()
        .map_err(|e| VPError::Parsing {
            value: e.to_string(),
        })?
        .sign(&key)
        .await
        .map_err(|_| VPError::Signing)?;
    Ok(jwt.into_string())
}

#[uniffi::export]
pub async fn verify_jwt_vp(jwt_vp: String) -> Result<(), VPError> {
    use ssi::prelude::*;

    let jwt = CompactJWSString::from_string(jwt_vp.to_string()).map_err(|e| VPError::Parsing {
        value: e.to_string(),
    })?;

    let vm_resolver: ssi::dids::VerificationMethodDIDResolver<AnyDidMethod, AnyMethod> =
        AnyDidMethod::default().into_vm_resolver();
    let params = VerificationParameters::from_resolver(vm_resolver);

    jwt.verify(params)
        .await
        .map_err(|e| VPError::Generic {
            value: format!("something went wrong: {e}"),
        })?
        .map_err(|_| VPError::Verification)
}

#[uniffi::export]
fn initialise_session(document: Arc<Mdoc>, uuid: Uuid) -> Result<SessionData, SessionError> {
    let drms = DeviceRetrievalMethods::new(DeviceRetrievalMethod::BLE(BleOptions {
        peripheral_server_mode: None,
        central_client_mode: Some(CentralClientMode { uuid }),
    }));
    let session = SessionManagerInit::initialise(
        NonEmptyMap::new("org.iso.18013.5.1.mDL".into(), document.document().clone()),
        Some(drms),
        None,
    )
    .map_err(|e| SessionError::Generic {
        value: format!("Could not initialize session: {e:?}"),
    })?;
    let ble_ident = session
        .ble_ident()
        .map_err(|e| SessionError::Generic {
            value: format!("Could not get BLE ident: {e:?}"),
        })?
        .to_vec();
    let (engaged_state, qr_code_uri) =
        session.qr_engagement().map_err(|e| SessionError::Generic {
            value: format!("Could not generate qr engagement: {e:?}"),
        })?;
    Ok(SessionData {
        state: Arc::new(SessionManagerEngaged(engaged_state)),
        qr_code_uri,
        ble_ident,
    })
}

#[derive(thiserror::Error, uniffi::Error, Debug)]
pub enum RequestError {
    #[error("{value}")]
    Generic { value: String },
}

#[derive(uniffi::Record)]
struct ItemsRequest {
    doc_type: String,
    namespaces: HashMap<String, HashMap<String, bool>>,
}

#[derive(uniffi::Object)]
pub struct SessionManager {
    inner: Mutex<device::SessionManager>,
    items_requests: device::RequestedItems,
}

#[derive(uniffi::Record)]
struct RequestData {
    session_manager: Arc<SessionManager>,
    items_requests: Vec<ItemsRequest>,
}

#[uniffi::export]
fn handle_request(
    state: Arc<SessionManagerEngaged>,
    request: Vec<u8>,
) -> Result<RequestData, RequestError> {
    let (session_manager, items_requests) = {
        let session_establishment: SessionEstablishment = serde_cbor::from_slice(&request)
            .map_err(|e| RequestError::Generic {
                value: format!("Could not deserialize request: {e:?}"),
            })?;
        state
            .0
            .clone()
            .process_session_establishment(session_establishment)
            .map_err(|e| RequestError::Generic {
                value: format!("Could not process process session establishment: {e:?}"),
            })?
    };
    Ok(RequestData {
        session_manager: Arc::new(SessionManager {
            inner: Mutex::new(session_manager),
            items_requests: items_requests.clone(),
        }),
        items_requests: items_requests
            .into_iter()
            .map(|req| ItemsRequest {
                doc_type: req.doc_type,
                namespaces: req
                    .namespaces
                    .into_inner()
                    .into_iter()
                    .map(|(ns, es)| {
                        let items_request = es.into_inner().into_iter().collect();
                        (ns, items_request)
                    })
                    .collect(),
            })
            .collect(),
    })
}

#[derive(thiserror::Error, uniffi::Error, Debug)]
pub enum ResponseError {
    #[error("no signature payload received from session manager")]
    MissingSignature,
    #[error("{value}")]
    Generic { value: String },
}

#[uniffi::export]
pub fn submit_response(
    session_manager: Arc<SessionManager>,
    permitted_items: HashMap<String, HashMap<String, Vec<String>>>,
) -> Result<Vec<u8>, ResponseError> {
    let permitted = permitted_items
        .into_iter()
        .map(|(doc_type, namespaces)| {
            let ns = namespaces.into_iter().collect();
            (doc_type, ns)
        })
        .collect();
    let mut session_manager_inner = session_manager.inner.lock().unwrap();
    session_manager_inner.prepare_response(&session_manager.items_requests, permitted);
    Ok(session_manager_inner
        .get_next_signature_payload()
        .map(|(_, payload)| payload)
        .ok_or(ResponseError::MissingSignature)?
        .to_vec())
}

#[derive(thiserror::Error, uniffi::Error, Debug)]
pub enum SignatureError {
    #[error("Invalid DER signature: {value}")]
    InvalidSignature { value: String },
    #[error("there were more documents to sign, but we only expected to sign 1!")]
    TooManyDocuments,
    #[error("{value}")]
    Generic { value: String },
}

#[uniffi::export]
pub fn submit_signature(
    session_manager: Arc<SessionManager>,
    der_signature: Vec<u8>,
) -> Result<Vec<u8>, SignatureError> {
    let signature = p256::ecdsa::Signature::from_der(&der_signature).map_err(|e| {
        SignatureError::InvalidSignature {
            value: e.to_string(),
        }
    })?;
    let mut session_manager = session_manager.inner.lock().unwrap();
    session_manager
        .submit_next_signature(signature.to_bytes().to_vec())
        .map_err(|e| SignatureError::Generic {
            value: format!("Could not submit next signature: {e:?}"),
        })?;
    session_manager
        .retrieve_response()
        .ok_or(SignatureError::TooManyDocuments)
}

#[derive(thiserror::Error, uniffi::Error, Debug)]
pub enum TerminationError {
    #[error("{value}")]
    Generic { value: String },
}

#[uniffi::export]
fn terminate_session() -> Result<Vec<u8>, TerminationError> {
    let msg = session::SessionData {
        data: None,
        status: Some(session::Status::SessionTermination),
    };
    let msg_bytes = serde_cbor::to_vec(&msg).map_err(|e| TerminationError::Generic {
        value: format!("Could not serialize message bytes: {e:?}"),
    })?;
    Ok(msg_bytes)
}

#[derive(thiserror::Error, uniffi::Error, Debug)]
pub enum KeyTransformationError {
    #[error("{value}")]
    ToPKCS8 { value: String },
    #[error("{value}")]
    FromPKCS8 { value: String },
    #[error("{value}")]
    FromSEC1 { value: String },
    #[error("{value}")]
    ToSEC1 { value: String },
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use base64::prelude::*;
    use isomdl::{
        definitions::{
            device_request::{self, DataElements},
            x509::trust_anchor::TrustAnchorRegistry,
        },
        presentation::reader,
    };
    use p256::ecdsa::signature::{SignatureEncoding, Signer};

    use super::*;

    #[tokio::test]
    async fn verify_vc() {
        let json_vc = include_str!("../../tests/res/vc");
        verify_json_vc_string(json_vc.into()).await.unwrap()
    }

    #[tokio::test]
    async fn verify_vp() {
        let json_vc = include_str!("../../tests/res/vc");
        let key_str = include_str!("../../tests/res/ed25519-2020-10-18.json");
        let jwt_vp = vc_to_signed_vp(json_vc.to_string(), key_str.to_string())
            .await
            .unwrap();
        verify_jwt_vp(jwt_vp).await.unwrap()
    }

    #[test]
    fn end_to_end_ble_presentment_holder() {
        let mdoc_b64 = include_str!("../../tests/res/mdoc.b64");
        let mdoc_bytes = BASE64_STANDARD.decode(mdoc_b64).unwrap();
        let mdoc = Mdoc::from_cbor_encoded_document(mdoc_bytes, KeyAlias("unused".into())).unwrap();
        let key: p256::ecdsa::SigningKey =
            p256::SecretKey::from_sec1_pem(include_str!("../../tests/res/sec1.pem"))
                .unwrap()
                .into();
        let session_data = initialise_session(mdoc, Uuid::new_v4()).unwrap();
        let namespaces: device_request::Namespaces = [(
            "org.iso.18013.5.1".to_string(),
            [
                ("given_name".to_string(), true),
                ("family_name".to_string(), false),
            ]
            .into_iter()
            .collect::<BTreeMap<String, bool>>()
            .try_into()
            .unwrap(),
        )]
        .into_iter()
        .collect::<BTreeMap<String, DataElements>>()
        .try_into()
        .unwrap();
        let trust_anchor = TrustAnchorRegistry::iaca_registry_from_str(vec![include_str!(
            "../../tests/res/root-cert.pem"
        )
        .to_string()])
        .unwrap();
        let (mut reader_session_manager, request, _ble_ident) =
            reader::SessionManager::establish_session(
                session_data.qr_code_uri,
                namespaces.clone(),
                Some(trust_anchor),
            )
            .unwrap();
        // let request = reader_session_manager.new_request(namespaces).unwrap();
        let request_data = handle_request(session_data.state, request).unwrap();
        let permitted_items = [(
            "org.iso.18013.5.1.mDL".to_string(),
            [(
                "org.iso.18013.5.1".to_string(),
                vec!["given_name".to_string()],
            )]
            .into_iter()
            .collect(),
        )]
        .into_iter()
        .collect();
        let signing_payload =
            submit_response(request_data.session_manager.clone(), permitted_items).unwrap();
        let signature: p256::ecdsa::Signature = key.sign(&signing_payload);
        let response =
            submit_signature(request_data.session_manager, signature.to_der().to_vec()).unwrap();
        let res = reader_session_manager.handle_response(&response);
        assert_eq!(res.errors, BTreeMap::new());
    }

    #[test]
    fn end_to_end_ble_presentment_holder_reader() {
        let mdoc_b64 = include_str!("../../tests/res/mdoc.b64");
        let mdoc_bytes = BASE64_STANDARD.decode(mdoc_b64).unwrap();
        let mdoc = Mdoc::from_cbor_encoded_document(mdoc_bytes, KeyAlias("unused".into())).unwrap();
        let key: p256::ecdsa::SigningKey =
            p256::SecretKey::from_sec1_pem(include_str!("../../tests/res/sec1.pem"))
                .unwrap()
                .into();
        let holder_session_data = initialise_session(mdoc, Uuid::new_v4()).unwrap();
        let namespaces = [(
            "org.iso.18013.5.1".to_string(),
            [
                ("given_name".to_string(), true),
                ("family_name".to_string(), false),
            ]
            .into_iter()
            .collect(),
        )]
        .into_iter()
        .collect();
        let reader_session_data = super::reader::establish_session(
            holder_session_data.qr_code_uri,
            namespaces,
            Some(vec![
                include_str!("../../tests/res/root-cert.pem").to_string()
            ]),
        )
        .unwrap();
        // let request = reader_session_manager.new_request(namespaces).unwrap();
        let request_data =
            handle_request(holder_session_data.state, reader_session_data.request).unwrap();
        let permitted_items = [(
            "org.iso.18013.5.1.mDL".to_string(),
            [(
                "org.iso.18013.5.1".to_string(),
                vec!["given_name".to_string()],
            )]
            .into_iter()
            .collect(),
        )]
        .into_iter()
        .collect();
        let signing_payload =
            submit_response(request_data.session_manager.clone(), permitted_items).unwrap();
        let signature: p256::ecdsa::Signature = key.sign(&signing_payload);
        let response =
            submit_signature(request_data.session_manager, signature.to_der().to_vec()).unwrap();
        let _ = super::reader::handle_response(reader_session_data.state, response).unwrap();
    }
}
