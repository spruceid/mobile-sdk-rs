use std::collections::{BTreeMap, HashMap};

use isomdl::definitions::{
    helpers::NonEmptyMap,
    x509::{
        error::Error as X509Error,
        trust_anchor::{RuleSetType, TrustAnchor, TrustAnchorRegistry, ValidationRuleSet},
        x5chain::X509,
    },
};
use isomdl::presentation::reader::SessionManager;
use uuid::Uuid;

use crate::SessionError;

#[derive(uniffi::Object)]
struct ReaderSessionData {
    state: SessionManager,
    uuid: Uuid,
    request: Vec<u8>,
    ble_ident: Vec<u8>,
}

#[uniffi::export]
fn initialise_reader_session(
    uri: &str,
    elements: HashMap<String, HashMap<String, bool>>,
    trust_anchor_registry: Vec<String>,
) -> Result<ReaderSessionData, crate::SessionError> {
    let trust_anchors = trust_anchor_registry
        .iter()
        .map(|s| names_only_registry_from_pem(s))
        .collect::<Result<Vec<TrustAnchor>, X509Error>>()
        .or(Err(SessionError::Generic {
            value: "could not retrieve trust anchors from registry".to_string(),
        }))?;

    let registry = TrustAnchorRegistry {
        certificates: trust_anchors,
    };

    let new_elements: NonEmptyMap<String, NonEmptyMap<String, bool>> = elements
        .into_iter()
        .collect::<BTreeMap<String, BTreeMap<String, bool>>>()
        .try_into()
        .unwrap();

    let (manager, request, ble_ident) =
        SessionManager::establish_session(uri.to_string(), elements.into(), Some(registry)).or(
            Err(SessionError::Generic {
                value: "Could not establish reader session".to_string(),
            }),
        )?;

    let uuid = manager
        .first_central_client_uuid()
        .ok_or(SessionError::Generic {
            value: "the device did not transmit a central client uuid".to_string(),
        })?;

    Ok(ReaderSessionData {
        state: manager,
        uuid: uuid.clone(),
        request,
        ble_ident: ble_ident.into(),
    })
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
