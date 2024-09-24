use ssi::claims::{
    jwt::{AnyClaims, JWTClaims},
    sd_jwt::{RevealedSdJwt, SdJwtBuf},
};

#[uniffi::export]
pub fn decode_reveal_sd_jwt(input: String) -> Result<String, SdJwtVcInitError> {
    let jwt: SdJwtBuf = SdJwtBuf::new(input).map_err(|_| SdJwtVcInitError::InvalidSdJwt)?;
    let revealed_jwt: RevealedSdJwt<AnyClaims> = jwt
        .decode_reveal_any()
        .map_err(|_| SdJwtVcInitError::JwtDecoding)?;
    let claims: &JWTClaims = revealed_jwt.claims();
    serde_json::to_string(claims).map_err(|_| SdJwtVcInitError::Serialization)
}

#[derive(Debug, uniffi::Error, thiserror::Error)]
pub enum SdJwtVcInitError {
    #[error("failed to decode string as an SD-JWT of the form <base64-encoded-header>.<base64-encoded-payload>.<base64-encoded-signature>")]
    CompactSdJwtDecoding,
    #[error("failed to decode claim 'vc' as a W3C VCDM v1 or v2 credential")]
    CredentialClaimDecoding,
    #[error("'vc' is missing from the SD-JWT claims")]
    CredentialClaimMissing,
    #[error("failed to encode the credential as a UTF-8 string")]
    CredentialStringEncoding,
    #[error("failed to decode SD-JWT bytes as UTF-8")]
    SdJwtBytesDecoding,
    #[error("failed to decode SD-JWT as a JWT")]
    JwtDecoding,
    #[error("failed to decode JWT header as base64-encoded JSON")]
    HeaderDecoding,
    #[error("failed to decode JWT payload as base64-encoded JSON")]
    PayloadDecoding,
    #[error("failed to extract concealed claims (disclosures) from SD-JWT")]
    DisclosureExtraction,
    #[error("failed to verify the integrity of the SD-JWT with the disclosed claims")]
    DisclosureVerification,
    #[error("failed to decode disclosures")]
    DisclosureDecoding,
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
        let result = decode_reveal_sd_jwt(sd_jwt_input.to_string());

        // Check if the function returns Ok with a valid JSON string
        assert!(result.is_ok());

        // Check the output JSON string structure
        match result {
            Ok(output) => {
                println!("Output: {}", output);
                // Check the output JSON string structure
                assert!(output.contains("\"sub\":\"user_42\""));
                assert!(output.contains("\"birthdate\":\"1940-01-01\""));
            }
            Err(e) => {
                panic!("Test failed with error: {:?}", e);
            }
        }
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
    async fn test_decode_gen() -> Result<(), SdJwtVcInitError> {
        // Example SD-JWT input (you should replace this with a real SD-JWT string for a proper test)
        let sd_jwt_input = generate_sd_jwt().await;

        // Call the function with the SD-JWT input
        let result = decode_reveal_sd_jwt(sd_jwt_input.to_string());

        println!("TESTING GEN {:?}", result);

        // Check if the function returns Ok with a valid JSON string
        assert!(result.is_ok());

        // Check the output JSON string structure
        match result {
            Ok(output) => {
                println!("Output: {}", output);
                // Check the output JSON string structure
                assert!(output.contains("\"sub\":\"1234567890\""));
                assert!(output.contains("\"name\":\"John Doe\""));
            }
            Err(e) => {
                panic!("Test failed with error: {:?}", e);
            }
        }
        Ok(())
    }
}
