use std::str::FromStr;

use oid4vci::{
    proof_of_possession::{
        ProofOfPossession, ProofOfPossessionController, ProofOfPossessionParams,
    },
    types::Nonce,
};
use ssi::{dids::DIDURLBuf, jwk::JWK};
use url::Url;

use crate::oid4vci::Oid4vciError;

// TODO: consider unifying prepare and complete fns by using a trait for
// signing/crypto functions similar to `HttpClient` for requests
#[uniffi::export]
fn generate_pop_prepare(
    audience: String,
    issuer: String,
    nonce: Option<String>,
    vm: String,
    public_jwk: String,
    duration_in_secs: Option<i64>,
) -> Result<Vec<u8>, Oid4vciError> {
    let pop_params = ProofOfPossessionParams {
        audience: Url::from_str(&audience)
            .map_err(|e| e.to_string())
            .map_err(Oid4vciError::from)?,
        issuer,
        controller: ProofOfPossessionController {
            vm: Some(
                DIDURLBuf::from_string(vm)
                    .map_err(|e| e.to_string())
                    .map_err(Oid4vciError::from)?,
            ),
            jwk: JWK::from_str(&public_jwk)
                .map_err(|e| e.to_string())
                .map_err(Oid4vciError::from)?,
        },
        nonce: nonce.map(Nonce::new),
    };

    let signing_input = ProofOfPossession::generate(
        &pop_params,
        duration_in_secs
            .map(time::Duration::seconds)
            .unwrap_or(time::Duration::minutes(5)),
    )
    .to_jwt_signing_input()
    .map_err(|e| e.to_string())
    .map_err(Oid4vciError::from)?;

    Ok(signing_input)
}

#[uniffi::export]
fn generate_pop_complete(
    signing_input: Vec<u8>,
    signature: Vec<u8>,
) -> Result<String, Oid4vciError> {
    Ok([
        String::from_utf8(signing_input)
            .map_err(|e| e.to_string())
            .map_err(Oid4vciError::from)?,
        String::from_utf8(signature)
            .map_err(|e| e.to_string())
            .map_err(Oid4vciError::from)?,
    ]
    .join("."))
}
