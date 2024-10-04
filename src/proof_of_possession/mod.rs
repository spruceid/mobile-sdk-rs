use std::str::FromStr;

use oid4vci::{
    proof_of_possession::{
        ProofOfPossession, ProofOfPossessionController, ProofOfPossessionParams,
    },
    types::Nonce,
};
use ssi::{dids::DIDURLBuf, jwk::JWK};
use url::Url;

pub use error::*;

use crate::{did, oid4vci::Oid4vciError};

mod error;

// TODO: consider unifying prepare and complete fns by using a trait for
// signing/crypto functions similar to `HttpClient` for requests
#[uniffi::export]
async fn generate_pop_prepare(
    audience: String,
    nonce: Option<String>,
    did_method: did::DidMethod,
    public_jwk: String,
    duration_in_secs: Option<i64>,
) -> Result<Vec<u8>, PopError> {
    let issuer = did_method.did_from_jwk(&public_jwk)?;
    let vm = did_method.vm_from_jwk(&public_jwk).await?;

    let pop_params = ProofOfPossessionParams {
        audience: Url::from_str(&audience).map_err(PopError::from)?,
        issuer,
        controller: ProofOfPossessionController {
            vm: Some(DIDURLBuf::from_string(vm).map_err(PopError::from)?),
            jwk: JWK::from_str(&public_jwk).map_err(PopError::from)?,
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
    .map_err(PopError::from)?;

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
