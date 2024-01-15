use isomdl::{
    definitions::{
        device_engagement::{CentralClientMode, DeviceRetrievalMethods},
        helpers::NonEmptyMap,
        BleOptions, DeviceRetrievalMethod,
    },
    presentation::{
        device::{Document, SessionManagerInit},
        Stringify,
    },
};
use uuid::Uuid;

#[uniffi::export]
fn hello_ffi() -> String {
    "Hello from Rust!".into()
}

#[derive(thiserror::Error, uniffi::Error, Debug)]
pub enum SessionError {
    #[error("{value}")]
    Generic { value: String },
}

#[derive(uniffi::Record)]
struct SessionData {
    state: String,
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
fn initialise_session(document: String, uuid: Uuid) -> Result<SessionData, SessionError> {
    let drms = DeviceRetrievalMethods::new(DeviceRetrievalMethod::BLE(BleOptions {
        peripheral_server_mode: None,
        central_client_mode: Some(CentralClientMode { uuid }),
    }));
    let document = Document::parse(document).map_err(|e| SessionError::Generic {
        value: format!("Could not parse document: {e:?}"),
    })?;
    let session = SessionManagerInit::initialise(
        NonEmptyMap::new("org.iso.18013.5.1.mDL".into(), document),
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
    let state = engaged_state
        .stringify()
        .map_err(|e| SessionError::Generic {
            value: format!("Could not strigify state: {e:?}"),
        })?;
    Ok(SessionData {
        state,
        qr_code_uri,
        ble_ident,
    })
}

#[derive(thiserror::Error, uniffi::Error, Debug)]
pub enum RequestError {
    #[error("no signature payload received from session manager")]
    MissingSignature,
    #[error("{value}")]
    Generic { value: String },
}

#[derive(uniffi::Record)]
struct RequestData {
    state: String,
    payload: String,
    requested_values: String,
}

#[uniffi::export]
fn handle_request(state: String, request: String) -> Result<RequestData, RequestError> {
    use isomdl::definitions::session::SessionEstablishment;
    use isomdl::presentation::device::{SessionManager, SessionManagerEngaged};

    let request = request.strip_prefix("0x").unwrap_or(&request);
    let request: Vec<u8> = hex::decode(request).map_err(|e| RequestError::Generic {
        value: format!("Could not decode request: {e:?}"),
    })?;
    let (mut session, requested) = match SessionManagerEngaged::parse(state.to_string()) {
        Ok(sme) => {
            let session_establishment: SessionEstablishment = serde_cbor::from_slice(&request)
                .map_err(|e| RequestError::Generic {
                    value: format!("Could not deserialize request: {e:?}"),
                })?;
            sme.process_session_establishment(session_establishment)
                .map_err(|e| RequestError::Generic {
                    value: format!("Could not process process session establishment: {e:?}"),
                })?
        }
        Err(_) => {
            let mut sm =
                SessionManager::parse(state.to_string()).map_err(|e| RequestError::Generic {
                    value: format!("Could not parse session manager state: {e:?}"),
                })?;
            let req = sm
                .handle_request(&request)
                .map_err(|e| RequestError::Generic {
                    value: format!("Could not handle request: {e:?}"),
                })?;
            (sm, req)
        }
    };
    let permitted = requested
        .clone()
        .into_iter()
        .map(|req| {
            let namespaces = req
                .namespaces
                .into_inner()
                .into_iter()
                .map(|(ns, es)| {
                    let ids = es.into_inner().into_keys().collect();
                    (ns, ids)
                })
                .collect();
            (req.doc_type, namespaces)
        })
        .collect();
    session.prepare_response(&requested, permitted);
    let payload = session
        .get_next_signature_payload()
        .map(|(_, payload)| payload)
        .ok_or(RequestError::MissingSignature)?;
    let mut payload = hex::encode(payload);
    payload.insert_str(0, "0x");
    let state = session.stringify().map_err(|e| RequestError::Generic {
        value: format!("Could not stringify session: {e:?}"),
    })?;

    let requested_values = requested
        .into_iter()
        .map(|req| (req.doc_type, req.namespaces))
        .collect::<std::collections::BTreeMap<_, _>>();
    Ok(RequestData {
        state,
        payload,
        requested_values: serde_json::to_string(&requested_values).map_err(|e| {
            RequestError::Generic {
                value: format!("Could not serialize requested values: {e:?}"),
            }
        })?,
    })
}

#[derive(thiserror::Error, uniffi::Error, Debug)]
pub enum SignatureError {
    #[error("there were more documents to sign, but we only expected to sign 1!")]
    TooManyDocuments,
    #[error("{value}")]
    Generic { value: String },
}

#[derive(uniffi::Record)]
struct SignatureData {
    state: String,
    response: String,
}

#[uniffi::export]
fn submit_signature(state: String, signature: String) -> Result<SignatureData, SignatureError> {
    use isomdl::presentation::device::SessionManager;

    let sig = signature.strip_prefix("0x").unwrap_or(&signature);
    let sig: Vec<u8> = hex::decode(sig).map_err(|e| SignatureError::Generic {
        value: format!("Could not decode signature: {e:?}"),
    })?;
    let mut session =
        SessionManager::parse(state.to_string()).map_err(|e| SignatureError::Generic {
            value: format!("Could not parse session manager state: {e:?}"),
        })?;
    session
        .submit_next_signature(sig)
        .map_err(|e| SignatureError::Generic {
            value: format!("Could not submit next signature: {e:?}"),
        })?;

    let response = session
        .retrieve_response()
        .ok_or(SignatureError::TooManyDocuments)?;
    let mut response = hex::encode(response);
    response.insert_str(0, "0x");

    let state = session.stringify().map_err(|e| SignatureError::Generic {
        value: format!("Could not stringify session: {e:?}"),
    })?;
    Ok(SignatureData { state, response })
}

#[derive(thiserror::Error, uniffi::Error, Debug)]
pub enum TerminationError {
    #[error("{value}")]
    Generic { value: String },
}

#[uniffi::export]
fn terminate_session() -> Result<String, TerminationError> {
    use isomdl::definitions::session::{SessionData, Status};

    let msg = SessionData {
        data: None,
        status: Some(Status::SessionTermination),
    };
    let msg_bytes = serde_cbor::to_vec(&msg).map_err(|e| TerminationError::Generic {
        value: format!("Could not serialize message bytes: {e:?}"),
    })?;
    let mut response = hex::encode(msg_bytes);
    response.insert_str(0, "0x");
    Ok(response)
}

uniffi::setup_scaffolding!();
