uniffi::setup_scaffolding!();

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
    presentation::device::{self, Document, SessionManagerInit},
};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use uuid::Uuid;

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

uniffi::custom_type!(Uuid, String);
impl UniffiCustomTypeConverter for Uuid {
    type Builtin = String;
    fn into_custom(uuid: Self::Builtin) -> uniffi::Result<Self> {
        Ok(uuid.parse()?)
    }
    fn from_custom(uuid: Self) -> Self::Builtin {
        uuid.to_string()
    }
}

#[uniffi::export]
fn initialise_session(document: Arc<MDoc>, uuid: Uuid) -> Result<SessionData, SessionError> {
    let drms = DeviceRetrievalMethods::new(DeviceRetrievalMethod::BLE(BleOptions {
        peripheral_server_mode: None,
        central_client_mode: Some(CentralClientMode { uuid }),
    }));
    let session = SessionManagerInit::initialise(
        NonEmptyMap::new("org.iso.18013.5.1.mDL".into(), document.0.clone()),
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
    fn from_cbor(value: Vec<u8>) -> Result<Arc<Self>, MDocInitError> {
        Ok(Arc::new(MDoc(serde_cbor::from_slice(&value).map_err(
            |e| MDocInitError::Generic {
                value: e.to_string(),
            },
        )?)))
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

#[uniffi::export]
fn sec1_to_pkcs8(pem: String) -> Result<String, KeyTransformationError> {
    let key =
        p256::SecretKey::from_sec1_pem(&pem).map_err(|e| KeyTransformationError::FromSEC1 {
            value: e.to_string(),
        })?;
    Ok(key
        .to_pkcs8_pem(LineEnding::default())
        .map_err(|e| KeyTransformationError::ToPKCS8 {
            value: e.to_string(),
        })?
        .to_string())
}

#[uniffi::export]
fn pkcs8_to_sec1(pem: String) -> Result<String, KeyTransformationError> {
    let key =
        p256::SecretKey::from_pkcs8_pem(&pem).map_err(|e| KeyTransformationError::FromPKCS8 {
            value: e.to_string(),
        })?;
    Ok(key
        .to_sec1_pem(LineEnding::default())
        .map_err(|e| KeyTransformationError::ToSEC1 {
            value: e.to_string(),
        })?
        .to_string())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use base64::prelude::*;
    use isomdl::{
        definitions::device_request::{self, DataElements},
        presentation::reader,
    };
    use p256::ecdsa::signature::{SignatureEncoding, Signer};

    use super::*;

    #[test]
    fn sec1_to_pkcs8_() {
        let sec1 = include_str!("../tests/res/sec1.pem").to_string();
        let pkcs8 = include_str!("../tests/res/pkcs8.pem").to_string();
        assert_eq!(sec1_to_pkcs8(sec1).unwrap(), pkcs8);
    }

    #[test]
    fn pkcs8_to_sec1_() {
        let sec1 = include_str!("../tests/res/sec1.pem").to_string();
        let pkcs8 = include_str!("../tests/res/pkcs8.pem").to_string();
        assert_eq!(pkcs8_to_sec1(pkcs8).unwrap(), sec1);
    }

    #[test]
    fn end_to_end_ble_presentment() {
        let mdoc_b64 = include_str!("../tests/res/mdoc.b64");
        let mdoc_bytes = BASE64_STANDARD.decode(mdoc_b64).unwrap();
        let mdoc = MDoc::from_cbor(mdoc_bytes).unwrap();
        let key: p256::ecdsa::SigningKey =
            p256::SecretKey::from_sec1_pem(include_str!("../tests/res/sec1.pem"))
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
        let (mut reader_session_manager, request, _ble_ident) =
            reader::SessionManager::establish_session(session_data.qr_code_uri, namespaces.clone())
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
        reader_session_manager.handle_response(&response).unwrap();
    }
}
