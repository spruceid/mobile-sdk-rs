use std::collections::HashMap;

use thiserror::Error;

use isomdl::{
    definitions::x509::{
        error::Error as X509Error,
        trust_anchor::{RuleSetType, TrustAnchor, ValidationRuleSet},
        x5chain::X509,
    },
    presentation::Stringify,
};

#[derive(Error, Debug, uniffi::Error)]
pub enum BleError {
    #[error("{value}")]
    Generic { value: String },
}

#[derive(uniffi::Record)]
pub struct ReaderSessionData {
    state: String,
    uuid: String,
    request: String,
    ble_ident: String,
}

#[derive(uniffi::Record)]
pub struct ReaderResponseData {
    state: String,
    validated_response: String,
}

#[uniffi::export]
fn establish_session(
    uri: &str,
    elements: &str,
    trust_anchor_registry: &str,
) -> Result<ReaderSessionData, BleError> {
    use anyhow::Context;
    use isomdl::definitions::device_request::Namespaces;
    use isomdl::definitions::x509::trust_anchor::TrustAnchorRegistry;
    use isomdl::presentation::reader::SessionManager;

    let namespaces: Namespaces = serde_json::from_str::<Namespaces>(elements)
        .context("Unable to parse namespaces from json.")
        .map_err(|e| BleError::Generic {
            value: format!("Unable to parse namespaces from json: {e:?}"),
        })?;

    let trust_anchors = serde_json::from_str::<Vec<String>>(trust_anchor_registry)
        .context("unable to parse trust_anchor_registry as an array of strings")
        .map_err(|e| BleError::Generic {
            value: format!("Unable to parse trust_anchor_registry as an array of strings: {e:?}"),
        })?
        .iter()
        .map(|s| names_only_registry_from_pem(s))
        .collect::<Result<Vec<TrustAnchor>, X509Error>>()
        .map_err(|e| BleError::Generic {
            value: format!("X509 error: {e:?}"),
        })?;

    let registry = TrustAnchorRegistry {
        certificates: trust_anchors,
    };

    let (manager, request, ble_ident) =
        SessionManager::establish_session(uri.to_string(), namespaces, Some(registry))
            .context("unable to establish session")
            .map_err(|e| BleError::Generic {
                value: format!("Unable to establish session: {e:?}"),
            })?;
    let uuid = manager
        .first_central_client_uuid()
        .ok_or_else(|| anyhow::anyhow!("the device did not transmit a central client uuid"))
        .map_err(|e| BleError::Generic {
            value: format!("The device did not transmit a central client uuid: {e:?}"),
        })?
        .to_string();

    let mut request = hex::encode(request);
    request.insert_str(0, "0x");

    let mut ble_ident = hex::encode(ble_ident);
    ble_ident.insert_str(0, "0x");

    let state = manager.stringify().map_err(|e| BleError::Generic {
        value: format!("Could not stringify session state: {e:?}"),
    })?;

    let reader_session_data = ReaderSessionData {
        state: state.into(),
        uuid: uuid.into(),
        request: request.into(),
        ble_ident: ble_ident.into(),
    };

    Ok(reader_session_data)
}

fn names_only_registry_from_pem(pem: &str) -> Result<TrustAnchor, X509Error> {
    let ruleset = ValidationRuleSet {
        distinguished_names: vec!["2.5.4.6".to_string(), "2.5.4.8".to_string()],
        typ: RuleSetType::NamesOnly,
    };
    let anchor: TrustAnchor = match pem_rfc7468::decode_vec(pem.as_bytes()) {
        Ok(b) => TrustAnchor::Custom(X509 { bytes: b.1 }, ruleset),
        Err(e) => {
            return Err(X509Error::DecodingError(format!(
                "unable to parse pem: {:?}",
                e
            )))
        }
    };

    Ok(anchor)
}

#[uniffi::export]
fn decrypt_response(state: &str, response: &str) -> Result<ReaderResponseData, BleError> {
    use isomdl::presentation::reader::SessionManager;

    let response = response.strip_prefix("0x").unwrap_or(response);
    let response: Vec<u8> = hex::decode(response).map_err(|e| BleError::Generic {
        value: format!("Could not encode hex in the BLE response: {e:?}"),
    })?;
    let mut session = SessionManager::parse(state.to_string()).map_err(|e| BleError::Generic {
        value: format!("Could not parse encoded state in session manager: {e:?}"),
    })?;
    let validated_response = session.handle_response(&response);

    let state = session.stringify().map_err(|e| BleError::Generic {
        value: format!("Could not stringify session state: {e:?}"),
    })?;

    let validated_response_json =
        serde_json::to_value(validated_response).map_err(|e| BleError::Generic {
            value: format!("Could not convert validated response to value: {e:?}"),
        })?;

    let reader_response_data = ReaderResponseData {
        state: state.into(),
        validated_response: validated_response_json.to_string(),
    };

    Ok(reader_response_data)
}

#[uniffi::export]
fn build_request(state: &str) -> Result<HashMap<String, String>, BleError> {
    use isomdl::definitions::device_request::{DataElements, Namespaces};
    use isomdl::presentation::reader::SessionManager;

    let mut session = SessionManager::parse(state.to_string()).map_err(|e| BleError::Generic {
        value: format!("Could not: {e:?}"),
    })?;
    let mut elems = DataElements::new("family_name".into(), false);

    elems.insert("given_name".into(), false);
    elems.insert("document_number".into(), false);

    let namespaces = Namespaces::new("org.iso.18013.5.1".into(), elems);
    let request = session
        .new_request(namespaces)
        .map_err(|e| BleError::Generic {
            value: format!("Could generate new request: {e:?}"),
        })?;

    let mut request = hex::encode(request);
    request.insert_str(0, "0x");

    let state = session.stringify().map_err(|e| BleError::Generic {
        value: format!("Could not stringify session state: {e:?}"),
    })?;

    let mut map = HashMap::new();

    map.insert("state".into(), state.into());
    map.insert("request".into(), request.into());

    Ok(map)
}
