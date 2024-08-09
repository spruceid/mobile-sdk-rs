uniffi::setup_scaffolding!();

pub mod local_store;
pub mod storage_manager;
pub mod vdc_collection;

use std::{ collections::HashMap, io::Cursor, sync::{Arc, Mutex} };

use isomdl::{
    definitions::{
        device_engagement::{CentralClientMode, DeviceRetrievalMethods},
        helpers::NonEmptyMap,
        session, BleOptions, DeviceRetrievalMethod, SessionEstablishment,
    },
    presentation::device::{self, Document, SessionManagerInit},
};
use ssi::{claims::vc::v1::{data_integrity::any_credential_from_json_str, ToJwtClaims}, dids::{AnyDidMethod, DIDResolver}, json_ld::iref::Uri, status::{bitstring_status_list::{BitstringStatusListCredential, StatusList, StatusPurpose, TimeToLive}, client::{MaybeCached, ProviderError, TypedStatusMapProvider}}};
use uuid::Uuid;
use w3c_vc_barcodes::{aamva::{dlid::{pdf_417, DlSubfile}, ZZSubfile}, optical_barcode_credential::{decode_from_bytes, VerificationParameters}, terse_bitstring_status_list_entry::{ConstTerseStatusListProvider, StatusListInfo}, verify, MRZ, MachineReadableZone};


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

pub struct StatusLists;

impl TypedStatusMapProvider<Uri, BitstringStatusListCredential> for StatusLists {
    async fn get_typed(&self, id: &Uri) -> Result<MaybeCached<StatusList>, ProviderError> {
        eprintln!("fetch <{id}>");
        Ok(MaybeCached::NotCached(StatusList::from_bytes(
            1.try_into().unwrap(),
            vec![0u8; 125],
            TimeToLive::DEFAULT,
        )))
    }
}

#[uniffi::export]
pub async fn verify_pdf417_barcode(payload: String) -> Result<(), VCBVerificationError> {
    let mut cursor = Cursor::new(payload);
    let mut file = pdf_417::File::new(&mut cursor)
        .map_err(|e| VCBVerificationError::Generic { value: e.to_string() })?;
    let dl: DlSubfile = file.read_subfile(b"DL")
        .map_err(|e| VCBVerificationError::Generic { value: e.to_string() })?
        .ok_or(VCBVerificationError::Generic { value: "Invalid DLSubfile".to_string() })?;
    let zz: ZZSubfile = file.read_subfile(b"ZZ")
        .map_err(|e| VCBVerificationError::Generic { value: e.to_string() })?
        .ok_or(VCBVerificationError::Generic { value: "Invalid ZZSubfile".to_string() })?;
    let vc = zz.decode_credential()
        .await
        .map_err(|e| VCBVerificationError::Generic { value: e.to_string() })?;

    let status_list_client = ConstTerseStatusListProvider::new(
        StatusLists,
        StatusListInfo::new(1000, StatusPurpose::Revocation),
    );

    let params = VerificationParameters::new_with(
        AnyDidMethod::default().into_vm_resolver(),
        status_list_client,
    );

    verify(&vc, &dl.mandatory, params)
        .await
        .map_err(|e| VCBVerificationError::Generic { value: e.to_string() })?
        .map_err(|e| VCBVerificationError::Generic { value: e.to_string() })
}

fn convert_to_mrz_entry(s: &[u8]) -> &[u8; 30] {
    s.try_into().expect("slice with incorrect length")
}

#[derive(thiserror::Error, uniffi::Error, Debug)]
pub enum VCBVerificationError {
    #[error("{value}")]
    Generic { value: String },
}

#[uniffi::export]
pub async fn verify_vcb_qrcode_against_mrz(mrz_payload: String, qr_payload: String) -> Result<(), VCBVerificationError> {
    let mrz: MRZ = mrz_payload
                .lines()
                .map(|x| *convert_to_mrz_entry(x.as_bytes()))
                .collect::<Vec<[u8;30]>>()
                .try_into()
                .map_err(|_| VCBVerificationError::Generic { value: "Invalid MRZ string".to_string() })?;

    // First we decode the QR-code payload to get the VCB in CBOR-LD form.
    let input = MachineReadableZone::decode_qr_code_payload(qr_payload.as_str())
        .map_err(|e| VCBVerificationError::Generic { value: e.to_string() })?;

    // Then we decompress the CBOR-LD VCB to get a regular JSON-LD VCB.
    let vc = decode_from_bytes::<MachineReadableZone>(&input)
        .await
        .map_err(|e| VCBVerificationError::Generic { value: e.to_string() })?;

    // Finally we verify the VCB against the MRZ data.
    let params = VerificationParameters::new(AnyDidMethod::default().into_vm_resolver());
    verify(&vc, &mrz, params)
        .await
        .map_err(|e| VCBVerificationError::Generic { value: e.to_string() })?
        .map_err(|e| VCBVerificationError::Generic { value: e.to_string() })
}

#[derive(thiserror::Error, uniffi::Error, Debug)]
pub enum VCVerificationError {
    #[error("{value}")]
    Generic { value: String },
}

#[uniffi::export]
pub async fn verify_json_vc_string(json: String) -> Result<(), VCVerificationError> {
    use ssi::prelude::VerificationParameters;

    let vc = any_credential_from_json_str(&json)
        .map_err(|e| VCVerificationError::Generic { value: e.to_string() })?;

    let vm_resolver = AnyDidMethod::default().into_vm_resolver();
    let params = VerificationParameters::from_resolver(vm_resolver);

    vc.verify(&params)
        .await
        .map_err(|e| VCVerificationError::Generic { value: e.to_string() })?
        .map_err(|e| VCVerificationError::Generic { value: e.to_string() })
}

#[derive(thiserror::Error, uniffi::Error, Debug)]
pub enum VPError {
    #[error("{value}")]
    Verification { value: String },
    #[error("{value}")]
    Parsing { value: String },
}

#[uniffi::export]
pub async fn vc_to_signed_vp(vc: String, key_str: String) -> Result<String, VPError> {
    use ssi::prelude::*;

    let vp = ssi::claims::vc::v1::JsonPresentation::new(
        None,
        None,
        vec![vc],
    );

    let mut key: ssi::jwk::JWK = serde_json::from_str(&key_str)
            .map_err(|e| VPError::Parsing { value: e.to_string() })?;
    let did = DIDJWK::generate_url(&key.to_public());
    key.key_id = Some(did.into());
    
    let jwt = vp.to_jwt_claims()
        .map_err(|e| VPError::Parsing { value: e.to_string() })?
        .sign(&key)
        .await
        .map_err(|e| VPError::Parsing { value: e.to_string() })?;
    Ok(jwt.into_string())
}

#[uniffi::export]
pub async fn verify_jwt_vp(jwt_vp: String) -> Result<(), VPError> {
    use ssi::prelude::*;

    let jwt = CompactJWSString::from_string(jwt_vp.to_string())
        .map_err(|e| VPError::Parsing { value: e.to_string() })?;

    let vm_resolver: ssi::dids::VerificationMethodDIDResolver<AnyDidMethod, AnyMethod> = AnyDidMethod::default().into_vm_resolver();
    let params = VerificationParameters::from_resolver(vm_resolver);

    jwt
        .verify(params)
        .await
        .map_err(|e| VPError::Verification { value: e.to_string() })?
        .map_err(|e| VPError::Verification { value: e.to_string() })
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
        let json_vc = include_str!("../tests/res/vc");
        let result = verify_json_vc_string(json_vc.into()).await.is_ok();
        assert_eq!(result, true);
    }

    #[tokio::test]
    async fn verify_vp() {
        let json_vc = include_str!("../tests/res/vc");
        let key_str = include_str!("../tests/res/ed25519-2020-10-18.json");
        let jwt_vp = vc_to_signed_vp(json_vc.to_string(), key_str.to_string()).await.unwrap();
        let result = verify_jwt_vp(jwt_vp).await.is_ok();
        assert_eq!(result, true);
    }

    #[tokio::test]
    async fn verify_vcb_dl() {
        let pdf417 = "@\n\x1e\rANSI 000000090002DL00410234ZZ02750202DLDAQF987654321\nDCSSMITH\nDDEN\nDACJOHN\nDDFN\nDADNONE\nDDGN\nDCAC\nDCBNONE\nDCDNONE\nDBD01012024\nDBB04191988\nDBA04192030\nDBC1\nDAU069 IN\nDAYBRO\nDAG123 MAIN ST\nDAIANYVILLE\nDAJUTO\nDAKF87P20000  \nDCFUTODOCDISCRIM\nDCGUTO\nDAW158\nDCK1234567890\nDDAN\rZZZZA2QZkpgGDGYAAGYABGYACGJ2CGHYYpBi4oxicGKYYzhiyGNAa5ZIggRi6ohicGKAYqER1ggAgGL4YqhjApRicGGwY1gQY4BjmGOJYQXq3wuVrSeLM5iGEziaBjhWosXMWRAG107uT_9bSteuPasCXFQKuPdSdF-xmUoFkA0yRJoW4ERvATNyewT263ZHMGOQYrA==\r";
        let result = verify_pdf417_barcode(pdf417.into()).await.is_ok();
        assert_eq!(result, true);
    }

    #[tokio::test]
    async fn verify_vcb_employment_authorization() {
        let mrz = include_str!("../tests/res/mrz-vcb");
        let ead = include_str!("../tests/res/ead-vcb");
        let result = verify_vcb_qrcode_against_mrz(mrz.into(), ead.into()).await.is_ok();
        assert_eq!(result, true);
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
        let trust_anchor = TrustAnchorRegistry::iaca_registry_from_str(vec![include_str!(
            "../tests/res/issuer-cert.pem"
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
