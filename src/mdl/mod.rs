//! A module to handle presentation of an ISO 18013-5 mobile driving license (mDL).
//!
//! This module manages the session for presentation of an mDL, including generating
//! the QR code and BLE parameters, as well as managing the types of information requested
//! by the reader.
//!
//! The presentation process is begun by calling [`initialize_mdl_presentation`] on the
//! [`Wallet`] and passing the id of the mdoc to be used as well as a UUID that the client
//! will use for the BLE central client:
//!
//! ```rust
//! let ble_uuid = Uuid::new_v4();
//! let presentation_session = wallet.initialize_mdl_presentation("test_mdoc", ble_uuid);
//! // Presenting software then creates a QR code with presentation_session.qr_code_uri
//! // and sets up a BLE session using presentation_session.ble_ident. It will then
//! // receive a list of requested fields from the reader.
//! let requested_items = presentation_session.handle_request(request_bytes)?;
//! // Presenting software should then confirm with the user that they wish to present
//! // the requested information. If so...
//! let signed_response_bytes = presentation_session.submit_response(user_permitted_items, key_id)?;
//! // Presenting software then sends response_bytes over BLE to the reader, completing the exchange.
use crate::{vdc_collection::VdcCollection, KeyManagerInterface, Wallet};

use super::common::*;

use std::{
    collections::HashMap,
    ops::DerefMut,
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
    ) -> Result<MdlPresentationSession, SessionError> {
        let key = VdcCollection::storage_key(&CredentialType::Iso18013_5_1mDl, mdoc_id);

        let document = self
            .vdc_collection
            .get(key, &self.storage_manager)
            .map_err(|_| SessionError::Generic {
                value: "Error in VDC Collection".to_string(),
            })?
            .ok_or(SessionError::Generic {
                value: "No credential with that ID in the VDC collection.".to_string(),
            })?;

        let mdoc = MDoc::from_cbor(document.payload());
        let drms = DeviceRetrievalMethods::new(DeviceRetrievalMethod::BLE(BleOptions {
            peripheral_server_mode: None,
            central_client_mode: Some(CentralClientMode { uuid }),
        }));
        let session = SessionManagerInit::initialise(
            NonEmptyMap::new("org.iso.18013.5.1.mDL".into(), mdoc.0.clone()),
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
        Ok(MdlPresentationSession {
            state: Mutex::new(MdlPresentationState::Engaged),
            key_manager: self.key_manager.clone(),
            engaged: Some(engaged_state),
            in_process: Mutex::new(None),
            qr_code_uri,
            ble_ident,
        })
    }
}

#[derive(uniffi::Object)]
pub struct MdlPresentationSession {
    state: Mutex<MdlPresentationState>,
    engaged: Option<device::SessionManagerEngaged>,
    in_process: Mutex<Option<InProcessRecord>>,
    pub qr_code_uri: String,
    pub ble_ident: String,
    key_manager: Arc<dyn KeyManagerInterface>,
}

#[derive(uniffi::Enum)]
pub enum MdlPresentationState {
    Engaged,
    InProcess,
}

#[derive(uniffi::Object, Clone)]
struct InProcessRecord {
    session: device::SessionManager,
    items_request: device::RequestedItems,
}

#[uniffi::export]
impl MdlPresentationSession {
    /// Handle a request from a reader that is seeking information from the mDL holder.
    ///
    /// Takes the raw bytes received from the reader by the holder over the transmission
    /// technology. Returns a Vector of information items requested by the reader, or an
    /// error.
    pub fn handle_request(&self, request: Vec<u8>) -> Result<Vec<ItemsRequest>, RequestError> {
        // Mutexes only return Err if another thread has panicked while holding the mutex
        // If that has happened, its probably better to just crash. This is what the standard documentation recommends.
        // See https://doc.rust-lang.org/std/sync/struct.Mutex.html
        let mut state = self.state.lock().unwrap();
        let (session_manager, items_requests) = {
            let session_establishment: SessionEstablishment = serde_cbor::from_slice(&request)
                .map_err(|e| RequestError::Generic {
                    value: format!("Could not deserialize request: {e:?}"),
                })?;
            if let MdlPresentationState::Engaged = *state {
                // If the state is `Engaged`, then self.engaged must have been set at the same time, so safe to unwrap
                self.engaged
                    .as_ref()
                    .unwrap()
                    .clone()
                    .process_session_establishment(session_establishment)
                    .map_err(|e| RequestError::Generic {
                        value: format!("Could not process process session establishment: {e:?}"),
                    })?
            } else {
                return Err(RequestError::Generic {
                    value: "Not in the correct state to handle request".to_string(),
                });
            }
        };

        *state = MdlPresentationState::InProcess;
        let mut in_process = self.in_process.lock().unwrap();
        *in_process = Some(InProcessRecord {
            session: session_manager,
            items_request: items_requests.clone(),
        });
        Ok(in_process
            .as_ref()
            .unwrap()
            .items_request
            .clone()
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
            .collect())
    }

    /// Constructs the response to be sent from the holder to the reader containing
    /// the items of information the user has consented to share.
    ///
    /// Takes a HashMap of items the user has authorized the app to share, as well
    /// as the id of a key stored in the key manager to be used to sign the response.
    /// Returns a byte array containing the signed response to be returned to the
    /// reader.
    pub fn submit_response(
        &self,
        permitted_items: HashMap<String, HashMap<String, Vec<String>>>,
        key_id: Key,
    ) -> Result<Vec<u8>, SignatureError> {
        let permitted = permitted_items
            .into_iter()
            .map(|(doc_type, namespaces)| {
                let ns = namespaces.into_iter().collect();
                (doc_type, ns)
            })
            .collect();
        if let Some(ref mut in_process) = self.in_process.lock().unwrap().deref_mut() {
            in_process
                .session
                .prepare_response(&in_process.items_request, permitted);
            let response = in_process
                .session
                .get_next_signature_payload()
                .map(|(_, payload)| payload)
                .ok_or(SignatureError::MissingSignature)?
                .to_vec();
            let signed_response = self
                .key_manager
                .sign_payload(key_id, response)
                .map_err(|e| SignatureError::Generic {
                    value: format!("Error signing payload: {e:?}"),
                })?;
            in_process
                .session
                .submit_next_signature(signed_response)
                .map_err(|e| SignatureError::Generic {
                    value: format!("Could not submit next signature: {e:?}"),
                })?;
            in_process
                .session
                .retrieve_response()
                .ok_or(SignatureError::TooManyDocuments)
        } else {
            Err(SignatureError::Generic {
                value: "Could not get lock on session".to_string(),
            })
        }
    }

    /// Terminates the mDL exchange session.
    ///
    /// Returns the termination message to be transmitted to the reader.
    pub fn terminate_session(&self) -> Result<Vec<u8>, TerminationError> {
        let msg = session::SessionData {
            data: None,
            status: Some(session::Status::SessionTermination),
        };
        let msg_bytes = serde_cbor::to_vec(&msg).map_err(|e| TerminationError::Generic {
            value: format!("Could not serialize message bytes: {e:?}"),
        })?;
        Ok(msg_bytes)
    }
}

#[derive(thiserror::Error, uniffi::Error, Debug)]
pub enum SessionError {
    #[error("{value}")]
    Generic { value: String },
}

#[derive(thiserror::Error, uniffi::Error, Debug)]
pub enum RequestError {
    #[error("{value}")]
    Generic { value: String },
}

#[derive(uniffi::Record, Clone)]
pub struct ItemsRequest {
    doc_type: String,
    namespaces: HashMap<String, HashMap<String, bool>>,
}

#[derive(thiserror::Error, uniffi::Error, Debug)]
pub enum ResponseError {
    #[error("{value}")]
    Generic { value: String },
}

#[derive(thiserror::Error, uniffi::Error, Debug)]
pub enum SignatureError {
    #[error("Invalid DER signature: {value}")]
    InvalidSignature { value: String },
    #[error("there were more documents to sign, but we only expected to sign 1!")]
    TooManyDocuments,
    #[error("{value}")]
    Generic { value: String },
    #[error("no signature payload received from session manager")]
    MissingSignature,
}

#[derive(thiserror::Error, uniffi::Error, Debug)]
pub enum TerminationError {
    #[error("{value}")]
    Generic { value: String },
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

    use crate::{
        local_key_manager::LocalKeyManager, local_store::LocalStore, Credential,
        KeyManagerInterface, StorageManagerInterface,
    };

    use super::*;

    #[test]
    fn end_to_end_ble_presentment() {
        let mdoc_b64 = include_str!("../../tests/res/mdoc.b64");
        let mdoc_bytes = BASE64_STANDARD.decode(mdoc_b64).unwrap();
        let mdoc_id = Uuid::new_v4();
        let smi: Arc<dyn StorageManagerInterface> = Arc::new(LocalStore);
        let key = p256::SecretKey::from_sec1_pem(include_str!("../../tests/res/sec1.pem")).unwrap();
        let kmi: Arc<dyn KeyManagerInterface> =
            Arc::new(LocalKeyManager::new_with_key("test_key".into(), key));

        let wallet = Wallet::new(smi, kmi).unwrap();

        let second_smi: Arc<dyn StorageManagerInterface> = Arc::new(LocalStore);

        // Store the mdoc in the VDC Collection
        wallet
            .vdc_collection
            .add(
                Credential::new(
                    mdoc_id,
                    ClaimFormatDesignation::MsoMDoc,
                    CredentialType::Iso18013_5_1mDl,
                    mdoc_bytes,
                ),
                &second_smi,
            )
            .unwrap();

        // Start a new presentation session
        let session = wallet
            .initialize_mdl_presentation(&mdoc_id.to_string(), Uuid::new_v4())
            .unwrap();

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
                session.qr_code_uri.clone(),
                namespaces.clone(),
                Some(trust_anchor),
            )
            .unwrap();
        // let request = reader_session_manager.new_request(namespaces).unwrap();
        let _request_data = session.handle_request(request).unwrap();
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
        let response = session
            .submit_response(permitted_items, "test_key".into())
            .unwrap();

        // Root cert is expired
        let mut errors = reader_session_manager.handle_response(&response).errors;
        let (k, v) = errors.pop_first().unwrap();
        assert_eq!(k, "certificate_errors");
        assert_eq!(v.as_array().unwrap().len(), 1);
        assert_eq!(errors, BTreeMap::default());
    }
}
