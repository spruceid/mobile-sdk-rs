use ssi::claims::{
    jwt::{AnyClaims, JWTClaims},
    sd_jwt::{RevealedSdJwt, SdJwtBuf},
};

#[uniffi::export]
pub fn decode_reveal_sd_jwt(input: String) -> Result<String, SdJwtVcError> {
    let jwt: SdJwtBuf = SdJwtBuf::new(input).map_err(|_| SdJwtVcError::InvalidSdJwt)?;
    let revealed_jwt: RevealedSdJwt<AnyClaims> = jwt
        .decode_reveal_any()
        .map_err(|_| SdJwtVcError::JwtDecoding)?;
    let claims: &JWTClaims = revealed_jwt.claims();
    serde_json::to_string(claims).map_err(|_| SdJwtVcError::Serialization)
}

#[derive(Debug, uniffi::Error, thiserror::Error)]
pub enum SdJwtVcError {
    #[error("failed to decode SD-JWT as a JWT")]
    JwtDecoding,
    #[error("invalid SD-JWT")]
    InvalidSdJwt,
    #[error("serialization error")]
    Serialization,
}

#[cfg(test)]
mod tests {
    use super::*;

    use ssi::{
        claims::sd_jwt::{ConcealJwtClaims, SdAlg},
        json_pointer, JWK,
    };

    #[test]
    fn test_decode_static() {
        // Example SD-JWT input (you should replace this with a real SD-JWT string for a proper test)
        let sd_jwt_input = include_str!("../../tests/examples/sd_vc.jwt");

        // Call the function with the SD-JWT input
        let output =
            decode_reveal_sd_jwt(sd_jwt_input.to_string()).expect("failed to decode SD-JWT");

        // Check the output JSON string structure
        assert!(output.contains("\"sub\":\"user_42\""));
        assert!(output.contains("\"birthdate\":\"1940-01-01\""));
    }

    async fn generate_sd_jwt() -> SdJwtBuf {
        // Define the key (this is a private key; for testing purposes you can use this inline or generate one)
        let jwk: JWK = JWK::generate_ed25519().expect("unable to generate sd-jwt");

        // Create the JWT claims
        let registeredclaims = serde_json::json!({
            "iss": "https://issuer.example.com",
            "sub": "1234567890",
            "vc": {
                "type": ["VerifiableCredential", "UniversityDegreeCredential"],
                "credentialSubject": {
                    "id": "did:example:abcdef1234567890",
                    "name": "John Doe",
                    "degree": {
                        "type": "BachelorDegree",
                        "name": "Bachelor of Science and Arts"
                    }
                }
            }
        });

        let claims: JWTClaims = serde_json::from_value(registeredclaims).unwrap();
        let my_pointer = json_pointer!("/vc");

        claims
            .conceal_and_sign(SdAlg::Sha256, &[my_pointer], &jwk)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_decode_gen() -> Result<(), SdJwtVcError> {
        // Example SD-JWT input (you should replace this with a real SD-JWT string for a proper test)
        let sd_jwt_input = generate_sd_jwt().await;

        // Call the function with the SD-JWT input
        let output =
            decode_reveal_sd_jwt(sd_jwt_input.to_string()).expect("failed to decode SD-JWT");

        // Check the output JSON string structure
        assert!(output.contains("\"sub\":\"1234567890\""));
        assert!(output.contains("\"name\":\"John Doe\""));

        Ok(())
    }
}
