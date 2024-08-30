use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use isomdl::{
    definitions::{
        device_request,
        helpers::{non_empty_map, NonEmptyMap},
        validated_response,
        x509::{
            self,
            trust_anchor::{RuleSetType, TrustAnchor, TrustAnchorRegistry, ValidationRuleSet},
            x5chain::X509,
        },
    },
    presentation::reader,
};
use uuid::Uuid;

#[derive(thiserror::Error, uniffi::Error, Debug)]
pub enum MDLReaderSessionError {
    #[error("{value}")]
    Generic { value: String },
}

#[derive(uniffi::Object)]
pub struct MDLSessionManager(reader::SessionManager);

impl std::fmt::Debug for MDLSessionManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Debug for SessionManager not implemented")
    }
}

#[derive(uniffi::Record)]
pub struct MDLReaderSessionData {
    pub state: Arc<MDLSessionManager>,
    uuid: Uuid,
    pub request: Vec<u8>,
    ble_ident: Vec<u8>,
}

#[uniffi::export]
pub fn establish_session(
    uri: String,
    requested_items: HashMap<String, HashMap<String, bool>>,
    trust_anchor_registry: Option<Vec<String>>,
) -> Result<MDLReaderSessionData, MDLReaderSessionError> {
    let namespaces: Result<BTreeMap<_, NonEmptyMap<_, _>>, non_empty_map::Error> = requested_items
        .into_iter()
        .map(|(doc_type, namespaces)| {
            let namespaces: BTreeMap<_, _> = namespaces.into_iter().collect();
            match namespaces.try_into() {
                Ok(n) => Ok((doc_type, n)),
                Err(e) => Err(e),
            }
        })
        .collect();
    let namespaces = namespaces.map_err(|e| MDLReaderSessionError::Generic {
        value: format!("Unable to build data elements: {e:?}"),
    })?;
    let namespaces: device_request::Namespaces =
        namespaces
            .try_into()
            .map_err(|e| MDLReaderSessionError::Generic {
                value: format!("Unable to build namespaces: {e:?}"),
            })?;

    let registry = if let Some(r) = trust_anchor_registry {
        let trust_anchors = r
            .iter()
            .map(|s| names_only_registry_from_pem(s))
            .collect::<Result<Vec<TrustAnchor>, x509::error::Error>>()
            .map_err(|e| MDLReaderSessionError::Generic {
                value: format!("unable to parse trust anchors: {e:?}"),
            })?;
        let registry = TrustAnchorRegistry {
            certificates: trust_anchors,
        };
        Some(registry)
    } else {
        None
    };

    let (manager, request, ble_ident) =
        reader::SessionManager::establish_session(uri.to_string(), namespaces, registry).map_err(
            |e| MDLReaderSessionError::Generic {
                value: format!("unable to establish session: {e:?}"),
            },
        )?;
    let manager2 = manager.clone();
    let uuid =
        manager2
            .first_central_client_uuid()
            .ok_or_else(|| MDLReaderSessionError::Generic {
                value: "the device did not transmit a central client uuid".to_string(),
            })?;

    Ok(MDLReaderSessionData {
        state: Arc::new(MDLSessionManager(manager)),
        request,
        ble_ident: ble_ident.to_vec(),
        uuid: *uuid,
    })
}

fn names_only_registry_from_pem(pem: &str) -> Result<TrustAnchor, x509::error::Error> {
    let ruleset = ValidationRuleSet {
        distinguished_names: vec!["2.5.4.6".to_string(), "2.5.4.8".to_string()],
        typ: RuleSetType::NamesOnly,
    };
    let anchor: TrustAnchor = match pem_rfc7468::decode_vec(pem.as_bytes()) {
        Ok(b) => TrustAnchor::Custom(X509 { bytes: b.1 }, ruleset),
        Err(e) => {
            return Err(x509::error::Error::DecodingError(format!(
                "unable to parse pem: {:?}",
                e
            )))
        }
    };
    Ok(anchor)
}

// TODO what was this for? Reusing the same reader?
#[derive(thiserror::Error, uniffi::Error, Debug)]
pub enum MDLReaderRequestBuildError {
    #[error("{value}")]
    Generic { value: String },
}

#[derive(uniffi::Record)]
struct MDLReaderRequest {
    state: Arc<MDLSessionManager>,
    request: Vec<u8>,
}

#[uniffi::export]
fn new_request(
    state: Arc<MDLSessionManager>,
    requested_items: HashMap<String, HashMap<String, bool>>,
) -> Result<MDLReaderRequest, MDLReaderRequestBuildError> {
    let namespaces: Result<BTreeMap<_, NonEmptyMap<_, _>>, non_empty_map::Error> = requested_items
        .into_iter()
        .map(|(doc_type, namespaces)| {
            let namespaces: BTreeMap<_, _> = namespaces.into_iter().collect();
            match namespaces.try_into() {
                Ok(n) => Ok((doc_type, n)),
                Err(e) => Err(e),
            }
        })
        .collect();
    let namespaces = namespaces.map_err(|e| MDLReaderRequestBuildError::Generic {
        value: format!("Unable to build data elements: {e:?}"),
    })?;
    let namespaces: device_request::Namespaces =
        namespaces
            .try_into()
            .map_err(|e| MDLReaderRequestBuildError::Generic {
                value: format!("Unable to build namespaces: {e:?}"),
            })?;
    let mut state = state.0.clone();
    let request =
        state
            .new_request(namespaces)
            .map_err(|e| MDLReaderRequestBuildError::Generic {
                value: format!("unable to build request: {e:?}"),
            })?;
    Ok(MDLReaderRequest {
        state: Arc::new(MDLSessionManager(state)),
        request,
    })
}

#[derive(thiserror::Error, uniffi::Error, Debug, PartialEq)]
pub enum MDLReaderResponseError {
    #[error("Invalid decryption")]
    InvalidDecryption,
    #[error("Invalid parsing")]
    InvalidParsing,
    #[error("Invalid issuer authentication")]
    InvalidIssuerAuthentication,
    #[error("Invalid device authentication")]
    InvalidDeviceAuthentication,
    #[error("{value}")]
    Generic { value: String },
}

#[derive(uniffi::Enum, Debug)]
pub enum MDocItem {
    Text(String),
    Bool(bool),
    Integer(i64),
    // Bytes(Vec<u8>), // already converted in string
    ItemMap(HashMap<String, MDocItem>),
    Array(Vec<MDocItem>),
    // Image(Vec<u8>) maybe?
}

impl From<serde_json::Value> for MDocItem {
    fn from(value: serde_json::Value) -> Self {
        match value {
            serde_json::Value::Null => unreachable!("No null allowed in namespaces"),
            serde_json::Value::Bool(b) => Self::Bool(b),
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Self::Integer(i)
                } else {
                    unreachable!("Only integers allowed in namespaces")
                }
            }
            serde_json::Value::String(s) => Self::Text(s),
            serde_json::Value::Array(a) => {
                Self::Array(a.iter().map(|o| Into::<Self>::into(o.clone())).collect())
            }
            serde_json::Value::Object(m) => Self::ItemMap(
                m.iter()
                    .map(|(k, v)| (k.clone(), Into::<Self>::into(v.clone())))
                    .collect(),
            ),
        }
    }
}
#[derive(uniffi::Record, Debug)]
pub struct MDLReaderResponseData {
    state: Arc<MDLSessionManager>,
    verified_response: HashMap<String, HashMap<String, HashMap<String, MDocItem>>>,
}

#[uniffi::export]
pub fn handle_response(
    state: Arc<MDLSessionManager>,
    response: Vec<u8>,
) -> Result<MDLReaderResponseData, MDLReaderResponseError> {
    let mut state = state.0.clone();
    let validated_response = state.handle_response(&response);
    if let validated_response::Status::Invalid = validated_response.decryption {
        return Err(MDLReaderResponseError::InvalidDecryption);
    }
    if let validated_response::Status::Invalid = validated_response.parsing {
        return Err(MDLReaderResponseError::InvalidParsing);
    }
    if let validated_response::Status::Invalid = validated_response.issuer_authentication {
        return Err(MDLReaderResponseError::InvalidIssuerAuthentication);
    }
    if let validated_response::Status::Invalid = validated_response.device_authentication {
        return Err(MDLReaderResponseError::InvalidDeviceAuthentication);
    }
    if !validated_response.errors.is_empty() {
        return Err(MDLReaderResponseError::Generic {
            value: serde_json::to_string(&validated_response.errors).map_err(|e| {
                MDLReaderResponseError::Generic {
                    value: format!("Could not serialze errors: {e:?}"),
                }
            })?,
        });
    }
    let verified_response: Result<_, _> = validated_response
        .response
        .into_iter()
        .map(|(doc_type, namespaces)| {
            if let Some(namespaces) = namespaces.as_object() {
                let namespaces: Result<_, _> = namespaces
                    .into_iter()
                    .map(|(namespace, items)| {
                        if let Some(items) = items.as_object() {
                            let items = items
                                .iter()
                                .map(|(item, value)| (item.clone(), value.clone().into()))
                                .collect();
                            Ok((namespace.to_string(), items))
                        } else {
                            Err(MDLReaderResponseError::Generic {
                                value: "Items not array".to_string(),
                            })
                        }
                    })
                    .collect();
                let namespaces = namespaces.map_err(|e| MDLReaderResponseError::Generic {
                    value: format!("Unable to parse response: {e:?}"),
                })?;
                Ok((doc_type, namespaces))
            } else {
                Err(MDLReaderResponseError::Generic {
                    value: "Non-hashmap namespaces".to_string(),
                })
            }
        })
        .collect();
    let verified_response = verified_response.map_err(|e| MDLReaderResponseError::Generic {
        value: format!("Unable to parse response: {e:?}"),
    })?;
    Ok(MDLReaderResponseData {
        state: Arc::new(MDLSessionManager(state)),
        verified_response,
    })
}
