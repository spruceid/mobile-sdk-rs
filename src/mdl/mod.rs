use crate::Wallet;

use super::common::*;

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use anyhow::Result;
use isomdl::{
    definitions::{
        device_engagement::{CentralClientMode, DeviceRetrievalMethods},
        helpers::NonEmptyMap,
        session, BleOptions, DeviceRetrievalMethod, SessionEstablishment,
    },
    presentation::device::{self, Document, SessionManagerInit},
};
use ssi_claims::ResourceProvider;

#[uniffi::export]
impl Wallet {
    /// Begin the mDL presentation process for the holder.
    ///
    /// Initializes the presentation session for an ISO 18013-5 mDL and stores
    /// the session state object in the device storage_manager.
    ///
    /// Arguments:
    /// mdoc_id: unique identifier for the credential to present, to be looked up
    ///          in the VDC collection
    /// uuid:    the Bluetooth Low Energy Client Central Mode UUID to be used
    ///
    /// Returns:
    /// A Result, with the `Ok` containing a tuple consisting of an enum representing
    /// the state of the presentation, a String containing the QR code URI, and a
    /// String containing the BLE ident.
    pub fn initialize_mdl_presentation(
        &self,
        mdoc_id: &str,
        uuid: Uuid,
    ) -> Result<(MdlPresentationSession, String, String)> {
        let document = self
            .vdc_collection
            .get(mdoc_id, &self.storage_manager)?
            .ok_or(Err("No credential with that ID in the VDC collection."))?;

        let mdoc = MDoc::from_cbor(document.payload());
        let drms = DeviceRetrievalMethods::new(DeviceRetrievalMethod::BLE(BleOptions {
            peripheral_server_mode: None,
            central_client_mode: Some(CentralClientMode { uuid }),
        }));
        let session = SessionManagerInit::initialise(
            NonEmptyMap::new("org.iso.18013.5.1.mDL".into(), mdoc),
            Some(drms),
            None,
        )
        .map_err(|e| SessionError::Generic {
            value: format!("Could not initialize session: {e:?}"),
        })?;
        let mut ble_ident =
            session
                .ble_ident()
                .map(hex::encode)
                .map_err(|e| SessionError::Generic {
                    value: format!("Could not encode hex BLE ident: {e:?}"),
                })?;
        ble_ident.insert_str(0, "0x");
        let (engaged_state, qr_code_uri) =
            session.qr_engagement().map_err(|e| SessionError::Generic {
                value: format!("Could not generate qr engagement: {e:?}"),
            })?;
        Ok((
            MdlPresentationSession::Engaged(engaged_state),
            qr_code_uri,
            ble_ident,
        ))
    }
}

#[derive(uniffi::Enum)]
pub enum MdlPresentationSession {
    Engaged(device::SessionManagerEngaged),
    InProcess(InProcessRecord),
}

struct InProcessRecord {
    session: Mutex<device::SessionManager>,
    items_request: Vec<ItemsRequest>,
}

#[uniffi::export]
impl MdlPresentationSession {
    pub fn handle_request(self, request: Vec<u8>) -> Result<RequestData, RequestError> {
        let (session_manager, items_requests) = {
            let session_establishment: SessionEstablishment = serde_cbor::from_slice(&request)
                .map_err(|e| RequestError::Generic {
                    value: format!("Could not deserialize request: {e:?}"),
                })?;
            if let MdlPresentationSession::Engaged(session) = self {
                session
                    .clone()
                    .process_session_establishment(session_establishment)
                    .map_err(|e| RequestError::Generic {
                        value: format!("Could not process process session establishment: {e:?}"),
                    })?
            }
        };

        self = MdlPresentationSession::InProcess(Mutex::new(session_manager));
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
}

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
    ble_ident: String,
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
#[derive(thiserror::Error, uniffi::Error, Debug)]
pub enum ResponseError {
    #[error("no signature payload received from session manager")]
    MissingSignature,
    #[error("{value}")]
    Generic { value: String },
}

#[uniffi::export]
fn submit_response(
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
fn submit_signature(
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

#[derive(uniffi::Object)]
pub struct MDoc(Document);

#[derive(thiserror::Error, uniffi::Error, Debug)]
pub enum MDocInitError {
    #[error("Could not initialize mDoc: {value}")]
    Generic { value: String },
}

#[uniffi::export]
impl MDoc {
    #[uniffi::constructor]
    fn from_cbor(value: Vec<u8>) -> Arc<Self> {
        let mdoc = MDoc(
            serde_cbor::from_slice(&value)
                .map_err(|e| MDocInitError::Generic {
                    value: e.to_string(),
                })
                .expect("Failed construct mdoc presentation."),
        );

        Arc::new(mdoc)
    }

    fn id(&self) -> Uuid {
        self.0.id
    }
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

    #[test]
    fn end_to_end_ble_presentment() {
        let mdoc_b64 = include_str!("../../tests/res/mdoc.b64");
        let mdoc_bytes = BASE64_STANDARD.decode(mdoc_b64).unwrap();
        let mdoc = MDoc::from_cbor(mdoc_bytes);
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
            "../../tests/res/issuer-cert.pem"
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
        // Root cert is expired
        let mut errors = reader_session_manager.handle_response(&response).errors;
        let (k, v) = errors.pop_first().unwrap();
        assert_eq!(k, "certificate_errors");
        assert_eq!(v.as_array().unwrap().len(), 1);
        assert_eq!(errors, BTreeMap::default());
    }
}
